//! `CommandWatchdog` spawns a command as a subprocess and monitors it ensuring it stays alive.
//!
//! When the subprocess terminates, the watchdog starts a new instance of the subprocess.
//! The watchdog gracefully shuts down the subprocess when it is dropped.

use log::{debug, error, info};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use stats::WatchdogStats;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio_util::sync::CancellationToken;

mod stats;

#[derive(Debug)]
pub struct CommandWatchdog {
    /// A cancellation token to signal shutdown.
    shutdown_token: CancellationToken,
    /// A channel sender to signal restart.
    restart_tx: Sender<()>,
    /// The program name of the subprocess (for logging).
    program_name: String,
    /// The command line string of the subprocess (for logging).
    cmd_line: String,
    /// Statistics about the subprocess
    stats: Arc<WatchdogStats>,
}

#[derive(Debug, Clone)]
pub struct CommandWatchdogOptions {
    /// Maximum duration between restarts from exits or failed boot (default: 1 s)
    pub restart_interval: Duration,
    /// Maximum time to wait for a process to terminate after kill signal (default: 60 s)
    pub termination_timeout: Duration,
}

impl Default for CommandWatchdogOptions {
    fn default() -> Self {
        Self {
            restart_interval: Duration::from_secs(1),
            termination_timeout: Duration::from_secs(60),
        }
    }
}

impl CommandWatchdog {
    /// Starts a process and continuously monitors it for shutdown or failure.
    /// When the process terminates, it will be restarted immediately.
    ///
    /// When the `Watchdog` is dropped, the process will be terminated gracefully.
    ///
    /// # Arguments
    /// * `command` - The command to run the subprocess.
    pub fn start(command: Command) -> Self {
        Self::start_with_opt(command, Default::default())
    }

    /// Starts a process and continuously monitors it for shutdown or failure.
    /// When the process terminates, it will be restarted immediately.
    ///
    /// When the `Watchdog` is dropped, the process will be terminated gracefully.
    ///
    /// # Arguments
    /// * `command` - The command to run the subprocess.
    /// * `opt` - Additional options for the watchdog.
    pub fn start_with_opt(mut command: Command, opt: CommandWatchdogOptions) -> Self {
        let shutdown_token = CancellationToken::new();
        command.kill_on_drop(true);

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
            stats: Arc::new(WatchdogStats::new()),
        };

        // Spawn the watchdog process
        handle.spawn(command, restart_rx, opt);
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
    ) {
        let shutdown_token = self.shutdown_token.clone();
        let program_name = self.program_name.clone();
        let cmd_line = self.cmd_line.clone();
        let stats = self.stats.clone();
        let termination_timeout = opt.termination_timeout;

        // Spawn a new task to monitor the process
        tokio::spawn(async move {
            let mut last_start_time;
            let mut restart_rx = restart_rx;

            loop {
                let count = stats.increment_start_counter();
                info!(
                    "Starting process '{}' with command line '{}' (start count: {})",
                    program_name,
                    cmd_line,
                    count + 1
                );
                last_start_time = std::time::Instant::now();
                let mut child = match command.spawn() {
                    Ok(child) => child,
                    Err(e) => {
                        info!("Failed to start process '{}': {}", program_name, e);
                        tokio::time::sleep(opt.restart_interval).await;
                        continue;
                    }
                };
                tokio::select! {
                    _ = shutdown_token.cancelled() => {
                        info!("Watchdog received shutdown signal, terminating process '{}'", cmd_line);
                        match terminate_process_with_timeout(&mut child, &program_name, termination_timeout).await {
                            Ok(_) => {
                                info!("Process '{}' terminated successfully", program_name);
                            }
                            Err(e) => {
                                error!("Failed to terminate process '{}': {}", program_name, e);
                            }
                        };
                        break;
                    }
                    _ = restart_rx.recv() => {
                        info!("Watchdog received restart signal, restarting process '{}'", cmd_line);
                        match terminate_process_with_timeout(&mut child, &program_name, termination_timeout).await {
                            Ok(_) => {
                                info!("Process '{}' terminated for restart", program_name);
                            }
                            Err(e) => {
                                error!("Failed to terminate process '{}' for restart: {}", program_name, e);
                            }
                        };
                        // Continue immediately without delay to restart
                        continue;
                    }
                    result = child.wait() => {
                        match result {
                            Ok(status) => {
                                let exit_code = status.code().unwrap_or(-1);
                                stats.set_last_exit_code(exit_code);
                                info!("Process '{}' exited with status: {} (code: {})", program_name, status, exit_code);
                            }
                            Err(e) => {
                                info!("Failed to wait for process '{}': {}", program_name, e);
                            }
                        }
                    }
                }

                // Check if we need to wait before restarting
                let elapsed = last_start_time.elapsed();
                if elapsed < opt.restart_interval {
                    let delay = opt.restart_interval - elapsed;
                    info!(
                        "Detected crash loop. Waiting {}ms before restarting process",
                        delay.as_millis()
                    );
                    tokio::time::sleep(delay).await;
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
                Ok(_) => debug!("Sent SIGTERM to process '{}' (pid: {})", program_name, id),
                Err(e) => {
                    error!(
                        "Failed to send SIGTERM to process '{}': {}",
                        program_name, e
                    );
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
                info!(
                    "Process '{}' terminated with status: {}",
                    program_name, status
                );
                Ok(())
            }
            Err(e) => {
                error!(
                    "Error waiting for process '{}' termination: {}",
                    program_name, e
                );
                Err(e)
            }
        },
        Err(_) => {
            error!(
                "Process '{}' did not terminate gracefully within timeout, using SIGKILL",
                program_name
            );
            // Process didn't exit within timeout, use SIGKILL/TerminateProcess
            child.kill().await?;

            // Note: We don't wait again after SIGKILL as this is expected to be immediate
            // If it's not, there's not much else we can do
            Ok(())
        }
    }
}
