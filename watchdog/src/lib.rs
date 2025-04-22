//! `CommandWatchdog` spawns a command as a subprocess and monitors it ensuring it stays alive.
//!
//! When the subprocess terminates, the watchdog starts a new instance of the subprocess.
//! The watchdog gracefully shuts down the subprocess when it is dropped.

use log::{error, info};
use stats::WatchdogStats;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;
use tokio_util::sync::CancellationToken;

mod stats;

#[derive(Debug)]
pub struct CommandWatchdog {
    /// A cancellation token to signal shutdown.
    shutdown_token: CancellationToken,
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
}

impl Default for CommandWatchdogOptions {
    fn default() -> Self {
        Self {
            restart_interval: Duration::from_secs(1),
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

        let mut handle = Self {
            shutdown_token,
            program_name,
            cmd_line,
            stats: Arc::new(WatchdogStats::new()),
        };

        // Spawn the watchdog process
        handle.spawn(command, opt);
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

    /// Starts the watchdog process.
    fn spawn(&mut self, mut command: Command, opt: CommandWatchdogOptions) {
        let shutdown_token = self.shutdown_token.clone();
        let program_name = self.program_name.clone();
        let cmd_line = self.cmd_line.clone();
        let stats = self.stats.clone();

        // Spawn a new task to monitor the process
        tokio::spawn(async move {
            let mut last_start_time;
            loop {
                let count = stats.increment_start_counter();
                info!(
                    "Starting process '{}' with command line {} (start count: {})",
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
                        info!("Watchdog received shutdown signal, terminating process {}", cmd_line);
                        match child.kill().await {
                            Ok(_) => {
                                info!("Process '{}' terminated successfully", program_name);
                            }
                            Err(e) => {
                                error!("Failed to terminate process '{}': {}", program_name, e);
                            }
                        };
                        break;
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
        info!("Watchdog is dropping, terminating process");
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
