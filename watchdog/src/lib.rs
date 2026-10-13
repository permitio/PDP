//! `CommandWatchdog` spawns a command as a subprocess and monitors it ensuring it stays alive.
//!
//! When the subprocess terminates, the watchdog starts a new instance of the subprocess. While
//! it keeps failing, the watchdog backs off: the shortest time between starts doubles with each
//! failure in a row, up to a cap.
//! The watchdog gracefully shuts down the subprocess when it is dropped.
//!
//! `ServiceWatchdog` builds on top of `CommandWatchdog` to add health checking capabilities
//! to restart services that become unhealthy or unresponsive.

use backoff::RestartBackoff;
use log::{debug, error, info, warn};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use stats::CommandWatchdogStats;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

mod backoff;
mod health;
mod output;
mod service;
mod stats;

/// Compiles and runs the README's examples as doctests, so they keep matching the API.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

// Re-export health checkers and service watchdog
pub use health::{HealthCheck, HttpHealthChecker};
pub use output::{ChildOutputHandler, ChildStream, MAX_LINE_BYTES, TRUNCATION_MARKER};
pub use service::{ServiceWatchdog, ServiceWatchdogOptions};

#[derive(Debug, Clone)]
pub struct CommandWatchdog {
    /// A cancellation token to signal shutdown.
    shutdown_token: CancellationToken,
    /// A channel sender to signal restart.
    restart_tx: Sender<()>,
    /// The program name of the subprocess (for logging).
    pub(crate) program_name: String,
    /// The command line string of the subprocess (for logging).
    pub(crate) cmd_line: String,
    /// Statistics about the subprocess
    stats: Arc<CommandWatchdogStats>,
}

#[derive(Clone)]
pub struct CommandWatchdogOptions {
    /// Shortest time from a start to the next one once the process has failed: exited, failed to
    /// start, or been restarted by a [`ServiceWatchdog`] for failing its health checks. Each
    /// further failure in a row doubles it, up to `max_restart_interval` (default: 1 s)
    pub restart_interval: Duration,
    /// The most that time between starts grows to, never less than `restart_interval`. It is also
    /// how long the process has to stay up, or under a [`ServiceWatchdog`] pass its health
    /// checks, before its earlier failures stop counting (default: 60 s)
    pub max_restart_interval: Duration,
    /// Maximum time to wait for a process to terminate after kill signal (default: 60 s)
    pub termination_timeout: Duration,
    /// Where the child's stdout and stderr go.
    ///
    /// `None` (the default) leaves both streams inheriting the parent's file
    /// descriptors, which is what a watched process has always done. Supplying
    /// a handler switches both to pipes the watchdog drains, delivering one
    /// line at a time to [`ChildOutputHandler::on_line`] — which is how a
    /// caller attributes a child's output to the process that produced it.
    ///
    /// Note the obligations on the trait: the handler must not perform
    /// unbounded blocking work or panic, because it runs on the task that
    /// keeps the child's pipes drained. See [`ChildOutputHandler`]'s own doc
    /// for what that does and does not rule out.
    pub output_handler: Option<Arc<dyn ChildOutputHandler>>,
}

// Hand-written rather than derived: `Arc<dyn ChildOutputHandler>` is not
// `Debug`, and requiring `Debug` of every implementor is a worse trade than
// printing whether one is installed.
impl std::fmt::Debug for CommandWatchdogOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandWatchdogOptions")
            .field("restart_interval", &self.restart_interval)
            .field("max_restart_interval", &self.max_restart_interval)
            .field("termination_timeout", &self.termination_timeout)
            .field(
                "output_handler",
                &if self.output_handler.is_some() {
                    "Some(<handler>)"
                } else {
                    "None"
                },
            )
            .finish()
    }
}

impl Default for CommandWatchdogOptions {
    fn default() -> Self {
        Self {
            restart_interval: Duration::from_secs(1),
            max_restart_interval: Duration::from_secs(60),
            termination_timeout: Duration::from_secs(60),
            output_handler: None,
        }
    }
}

/// What shows that a failing process has recovered, so its earlier failures stop counting.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Recovery {
    /// It stays up for `max_restart_interval`.
    StaysUp,
    /// It passes its health checks for `max_restart_interval`. The [`ServiceWatchdog`] that runs
    /// them resets the count.
    PassesHealthChecks,
}

/// How a run of the process ended, short of the watchdog shutting down.
enum RunEnd {
    /// The process exited by itself.
    Exited,
    /// A restart was asked for, and the watchdog stopped the process.
    RestartRequested,
}

impl CommandWatchdog {
    /// Starts a process and continuously monitors it for shutdown or failure.
    /// When the process terminates, it is restarted, backing off while it keeps failing.
    ///
    /// When the `Watchdog` is dropped, the process will be terminated gracefully.
    ///
    /// # Arguments
    /// * `command` - The command to run the subprocess.
    pub fn start(command: Command) -> Self {
        Self::start_with_opt(command, Default::default())
    }

    /// Starts a process and continuously monitors it for shutdown or failure.
    /// When the process terminates, it is restarted, backing off while it keeps failing.
    ///
    /// When the `Watchdog` is dropped, the process will be terminated gracefully.
    ///
    /// # Arguments
    /// * `command` - The command to run the subprocess.
    /// * `opt` - Additional options for the watchdog.
    pub fn start_with_opt(command: Command, opt: CommandWatchdogOptions) -> Self {
        Self::start_with_recovery(command, opt, Recovery::StaysUp)
    }

    /// Starts and monitors a process whose earlier failures stop counting once `recovery` says so.
    pub(crate) fn start_with_recovery(
        mut command: Command,
        opt: CommandWatchdogOptions,
        recovery: Recovery,
    ) -> Self {
        let shutdown_token = CancellationToken::new();
        command.kill_on_drop(true);

        // Configure stdio ONCE, before the command is moved into the
        // supervising task: the same `Command` is reused for every respawn, so
        // this applies to each generation, and each `spawn()` creates its own
        // fresh pair of pipes.
        if opt.output_handler.is_some() {
            command.stdout(std::process::Stdio::piped());
            command.stderr(std::process::Stdio::piped());
        }

        // For logging purposes, we extract the program name and command line string
        let program_name = command.as_std().get_program().to_string_lossy().to_string();
        let cmd_line = get_command_line(&command);

        // Create a channel for restart signals
        let (restart_tx, restart_rx) = mpsc::channel(1);

        let mut handle = Self {
            shutdown_token,
            restart_tx,
            program_name,
            cmd_line,
            stats: Arc::new(CommandWatchdogStats::default()),
        };

        // Spawn the watchdog process
        handle.spawn(command, restart_rx, opt, recovery);
        handle
    }

    /// Gets the number of times the process has been started
    pub fn start_counter(&self) -> usize {
        self.stats.start_counter()
    }

    /// Gets the last exit code of the subprocess
    pub fn last_exit_code(&self) -> i32 {
        self.stats.last_exit_code()
    }

    /// Gets how many times in a row the process has failed: exited, failed to start, or been
    /// restarted for failing its health checks. It drops to 0 once the process stays up, or
    /// passes its health checks, for `max_restart_interval`.
    pub fn consecutive_failures(&self) -> u32 {
        self.stats.consecutive_failures()
    }

    /// Whether a started process is running, rather than the watchdog waiting to start it
    pub(crate) fn is_running(&self) -> bool {
        self.stats.is_running()
    }

    /// Counts a failure the watchdog cannot see itself, such as failed health checks
    pub(crate) fn record_failure(&self) {
        self.stats.record_failure();
    }

    /// Forgets the failures in a row once the process has recovered. Returns how many there were.
    pub(crate) fn reset_failures(&self) -> u32 {
        self.stats.reset_failures()
    }

    /// Requests a restart of the process
    pub async fn restart(&self) -> Result<(), mpsc::error::SendError<()>> {
        info!("Restart requested for process '{}'", self.program_name);
        self.restart_tx.send(()).await
    }

    /// Starts the watchdog process.
    fn spawn(
        &mut self,
        mut command: Command,
        restart_rx: Receiver<()>,
        opt: CommandWatchdogOptions,
        recovery: Recovery,
    ) {
        let shutdown_token = self.shutdown_token.clone();
        let program_name = self.program_name.clone();
        let cmd_line = self.cmd_line.clone();
        let stats = self.stats.clone();
        let termination_timeout = opt.termination_timeout;
        let backoff = RestartBackoff::new(opt.restart_interval, opt.max_restart_interval);

        // Spawn a new task to monitor the process
        tokio::spawn(async move {
            let mut restart_rx = restart_rx;
            let mut previous_start: Option<Instant> = None;

            loop {
                let failures = stats.consecutive_failures();
                if failures > 0
                    && let Some(previous_start) = previous_start
                {
                    let next_start = previous_start + backoff.delay(failures);
                    let wait = next_start.saturating_duration_since(Instant::now());
                    warn!(
                        "Process '{program_name}' has failed {failures} time(s) in a row; \
                         starting it again in {:.1}s",
                        wait.as_secs_f64()
                    );
                    tokio::select! {
                        _ = shutdown_token.cancelled() => break,
                        _ = tokio::time::sleep_until(next_start) => {}
                    }
                }
                // The start below answers a restart asked for while no process was running
                while restart_rx.try_recv().is_ok() {
                    debug!("Process '{program_name}' was not running when a restart was asked for");
                }

                let count = stats.increment_start_counter();
                info!(
                    "Starting process '{}' with command line '{}' (start count: {})",
                    program_name,
                    cmd_line,
                    count + 1
                );
                let started = Instant::now();
                previous_start = Some(started);
                let mut child = match command.spawn() {
                    Ok(mut child) => {
                        // Attach a reader to each piped stream for THIS
                        // generation. Both must always be read: once a piped
                        // stream stops being drained, the child either blocks
                        // in `write` on a full pipe (while the read end is
                        // still open but nothing is taking from it) or, once
                        // that read end actually closes, takes `SIGPIPE` and
                        // dies — restart-looping either way, which looks
                        // exactly like a hang until it does. Each reader task
                        // ends at EOF — i.e. when this generation exits — so
                        // nothing accumulates across restarts.
                        if let Some(handler) = opt.output_handler.clone() {
                            if let Some(stdout) = child.stdout.take() {
                                tokio::spawn(crate::output::pump(
                                    stdout,
                                    crate::ChildStream::Stdout,
                                    handler.clone(),
                                ));
                            }
                            if let Some(stderr) = child.stderr.take() {
                                tokio::spawn(crate::output::pump(
                                    stderr,
                                    crate::ChildStream::Stderr,
                                    handler,
                                ));
                            }
                        }
                        child
                    }
                    Err(e) => {
                        info!("Failed to start process '{program_name}': {e}");
                        stats.record_failure();
                        continue;
                    }
                };
                stats.set_running(true);
                let run_end = tokio::select! {
                    _ = shutdown_token.cancelled() => {
                        info!("Watchdog received shutdown signal, terminating process '{cmd_line}'");
                        match terminate_process_with_timeout(&mut child, &program_name, termination_timeout).await {
                            Ok(_) => {
                                info!("Process '{program_name}' terminated successfully");
                            }
                            Err(e) => {
                                error!("Failed to terminate process '{program_name}': {e}");
                            }
                        };
                        stats.set_running(false);
                        break;
                    }
                    _ = restart_rx.recv() => {
                        info!("Watchdog received restart signal, restarting process '{cmd_line}'");
                        match terminate_process_with_timeout(&mut child, &program_name, termination_timeout).await {
                            Ok(_) => {
                                debug!("Process '{program_name}' terminated for restart");
                            }
                            Err(e) => {
                                error!("Failed to terminate process '{program_name}' for restart: {e}");
                            }
                        };
                        RunEnd::RestartRequested
                    }
                    result = child.wait() => {
                        match result {
                            Ok(status) => {
                                let exit_code = status.code().unwrap_or(-1);
                                stats.set_last_exit_code(exit_code);
                                info!("Process '{program_name}' exited with status: {status} (code: {exit_code})");
                            }
                            Err(e) => {
                                info!("Failed to wait for process '{program_name}': {e}");
                            }
                        }
                        RunEnd::Exited
                    }
                };
                stats.set_running(false);

                match recovery {
                    Recovery::StaysUp => {
                        let ran_for = started.elapsed();
                        if ran_for >= backoff.reset_after() {
                            let forgotten = stats.reset_failures();
                            if forgotten > 0 {
                                info!(
                                    "Process '{program_name}' ran for {}s; its {forgotten} \
                                     earlier failure(s) no longer count",
                                    ran_for.as_secs()
                                );
                            }
                        }
                    }
                    Recovery::PassesHealthChecks => {}
                }
                match run_end {
                    RunEnd::Exited => {
                        stats.record_failure();
                    }
                    // A restart for failed health checks is counted by the service watchdog
                    // that asked for it
                    RunEnd::RestartRequested => {}
                }
            }
        });
    }
}

impl Drop for CommandWatchdog {
    fn drop(&mut self) {
        self.shutdown_token.cancel();
    }
}

/// Get the full command line string for a given command.
fn get_command_line(command: &Command) -> String {
    let command = command.as_std();
    let mut command_line = command.get_program().to_string_lossy().to_string();
    for arg in command.get_args() {
        command_line.push(' ');
        command_line.push_str(&arg.to_string_lossy());
    }
    command_line
}

/// Reusable function to kill a child process with timeout
async fn terminate_process_with_timeout(
    child: &mut tokio::process::Child,
    program_name: &str,
    timeout: Duration,
) -> Result<(), std::io::Error> {
    // Try to terminate the process gracefully first
    if let Some(id) = child.id() {
        #[cfg(unix)]
        {
            // On Unix systems, use SIGTERM via nix
            match signal::kill(Pid::from_raw(id as i32), Signal::SIGTERM) {
                Ok(_) => debug!("Sent SIGTERM to process '{program_name}' (pid: {id})"),
                Err(e) => {
                    error!("Failed to send SIGTERM to process '{program_name}': {e}");
                    // If SIGTERM fails, attempt SIGKILL immediately
                    return child.kill().await;
                }
            }
        }

        #[cfg(not(unix))]
        {
            // On non-Unix platforms, we use the kill() method directly
            // which usually maps to TerminateProcess on Windows
            return child.kill().await;
        }
    } else {
        // If we can't get the process ID, fall back to SIGKILL/TerminateProcess
        return child.kill().await;
    }

    // Wait for the process to exit with timeout
    match tokio::time::timeout(timeout, child.wait()).await {
        Ok(result) => match result {
            Ok(status) => {
                info!("Process '{program_name}' terminated with status: {status}");
                Ok(())
            }
            Err(e) => {
                error!("Error waiting for process '{program_name}' termination: {e}");
                Err(e)
            }
        },
        Err(_) => {
            error!(
                "Process '{program_name}' did not terminate gracefully within timeout, using SIGKILL"
            );
            // Process didn't exit within timeout, use SIGKILL/TerminateProcess
            child.kill().await?;

            // Note: We don't wait again after SIGKILL as this is expected to be immediate
            // If it's not, there's not much else we can do
            Ok(())
        }
    }
}
