use crate::backoff::RestartBackoff;
use crate::health::HealthCheck;
use crate::stats::ServiceWatchdogStats;
use crate::{CommandWatchdog, CommandWatchdogOptions, Recovery};
use log::{debug, error, info, log, warn};
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::watch;
use tokio::time::{Instant, interval, timeout};
use tokio_util::sync::CancellationToken;

/// Configuration for the service watchdog
#[derive(Debug, Clone)]
pub struct ServiceWatchdogOptions {
    /// How often to check service health
    pub health_check_interval: Duration,
    /// How many consecutive health check failures before restarting
    pub health_check_failure_threshold: u32,
    /// How many consecutive health check failures before the service is reported unhealthy.
    /// One passing check reports it healthy again. A service that is not running, or a new run
    /// that has not passed a check yet, is reported unhealthy at once. 0 and 1 both report the
    /// first failure (default: 1)
    pub health_check_unhealthy_threshold: u32,
    /// How long to wait before starting health checks after a restart
    pub initial_startup_delay: Duration,
    /// Options for the command watchdog
    pub command_options: CommandWatchdogOptions,
}

impl Default for ServiceWatchdogOptions {
    fn default() -> Self {
        Self {
            health_check_interval: Duration::from_secs(10),
            health_check_failure_threshold: 3,
            health_check_unhealthy_threshold: 1,
            initial_startup_delay: Duration::from_secs(5),
            command_options: CommandWatchdogOptions::default(),
        }
    }
}

/// Service watchdog that monitors the health of a service and restarts it when necessary
#[derive(Debug)]
pub struct ServiceWatchdog {
    /// The underlying command watchdog
    command_watchdog: CommandWatchdog,
    /// Statistics about the service
    stats: Arc<ServiceWatchdogStats>,
    /// Cancellation token for shutdown
    shutdown_token: CancellationToken,
    /// Channel to track and notify of health status changes
    health_status: watch::Sender<bool>,
    /// Receiver for the current health status
    health_receiver: watch::Receiver<bool>,
}

impl ServiceWatchdog {
    /// Starts a service and continuously monitors its health.
    /// When the health checks fail, it will restart the service using the command watchdog.
    ///
    /// # Arguments
    /// * `command` - The command to run the service.
    /// * `health_checker` - The health checker to monitor the service.
    pub fn start<H: HealthCheck>(command: Command, health_checker: H) -> Self {
        Self::start_with_opt(command, health_checker, ServiceWatchdogOptions::default())
    }

    /// Starts a service with custom configuration and continuously monitors its health.
    /// When the health checks fail, it will restart the service using the command watchdog.
    ///
    /// # Arguments
    /// * `command` - The command to run the service.
    /// * `health_checker` - The health checker to monitor the service.
    /// * `config` - The configuration for the service watchdog.
    pub fn start_with_opt<H: HealthCheck>(
        command: Command,
        health_checker: H,
        opt: ServiceWatchdogOptions,
    ) -> Self {
        let command_watchdog = CommandWatchdog::start_with_recovery(
            command,
            opt.command_options.clone(),
            Recovery::PassesHealthChecks,
        );
        let stats = Arc::new(ServiceWatchdogStats::default());
        let shutdown_token = CancellationToken::new();
        let (health_status, health_receiver) = watch::channel(false);

        let mut watchdog = Self {
            command_watchdog,
            stats: Arc::clone(&stats),
            shutdown_token,
            health_status,
            health_receiver,
        };

        // Start the health check monitoring in a background task
        // We don't need to keep the health checker in the struct since it's only used here
        watchdog.spawn(health_checker, opt);
        watchdog
    }

    // Spawn the health monitoring task
    fn spawn<H: HealthCheck>(&mut self, health_checker: H, opt: ServiceWatchdogOptions) {
        let command_watchdog = self.command_watchdog.clone();
        let stats = Arc::clone(&self.stats);
        let shutdown_token = self.shutdown_token.clone();
        let health_status = self.health_status.clone();
        let reset_after = RestartBackoff::new(
            opt.command_options.restart_interval,
            opt.command_options.max_restart_interval,
        )
        .reset_after();

        tokio::spawn(async move {
            // Wait initial startup delay
            tokio::time::sleep(opt.initial_startup_delay).await;
            info!(
                "Starting health checks watchdog for '{}' in {:?}",
                command_watchdog.program_name, opt.initial_startup_delay
            );

            let mut check_interval = interval(opt.health_check_interval);
            // Skip the first tick which happens immediately
            check_interval.tick().await;
            let mut consecutive_failures = 0;
            // When the current run of passing health checks began
            let mut healthy_since: Option<Instant> = None;
            // The run of the process the counts above are about
            let mut checked_run = command_watchdog.start_counter();

            loop {
                tokio::select! {
                    _ = shutdown_token.cancelled() => {
                        info!("Service watchdog for '{}' shutting down", command_watchdog.program_name);
                        break;
                    }
                    _ = check_interval.tick() => {
                        // A restart can fall between two checks. A new run starts afresh either
                        // way, and is unhealthy until it passes a check.
                        let run = command_watchdog.start_counter();
                        if run != checked_run {
                            checked_run = run;
                            consecutive_failures = 0;
                            healthy_since = None;
                            broadcast_health(&health_status, false);
                        }
                        if !command_watchdog.is_running() {
                            // The command watchdog is between runs and starts the next one at
                            // its own pace. A failed check here would only ask to restart a
                            // process that is not running.
                            debug!(
                                "Service '{}' is not running; skipping its health check",
                                command_watchdog.program_name
                            );
                            broadcast_health(&health_status, false);
                            continue;
                        }

                        // Increment health checks counter and perform health check
                        stats.increment_health_checks();

                        // Check health
                        match health_checker.check_health().await {
                            Ok(_) => {
                                // Service is healthy
                                broadcast_health(&health_status, true);

                                if consecutive_failures > 0 {
                                    log!(
                                        if consecutive_failures < opt.health_check_failure_threshold / 2 {
                                            log::Level::Debug
                                        } else {
                                            log::Level::Info
                                        },
                                        "Service '{}' health restored after {} failures",
                                        command_watchdog.program_name, consecutive_failures
                                    );
                                }
                                consecutive_failures = 0;

                                let since = *healthy_since.get_or_insert_with(Instant::now);
                                if since.elapsed() >= reset_after {
                                    let forgotten = command_watchdog.reset_failures();
                                    if forgotten > 0 {
                                        info!(
                                            "Service '{}' has been healthy for {}s; its {} \
                                             earlier failure(s) no longer count",
                                            command_watchdog.program_name,
                                            since.elapsed().as_secs(),
                                            forgotten
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                // Health check failed
                                healthy_since = None;

                                stats.increment_failed_health_checks();
                                consecutive_failures += 1;

                                // One slow or failed check under load is not an outage
                                if consecutive_failures >= opt.health_check_unhealthy_threshold {
                                    let was_healthy = health_status.send_replace(false);
                                    if was_healthy {
                                        warn!(
                                            "Service '{}' failed {} health checks in a row; \
                                             reporting it unhealthy",
                                            command_watchdog.program_name, consecutive_failures
                                        );
                                    }
                                }

                                log!(
                                    if consecutive_failures < opt.health_check_failure_threshold / 2 {
                                        log::Level::Debug
                                    } else {
                                        log::Level::Warn
                                    },
                                    "Service '{}' health check failed: {} (consecutive failures: {}/{})",
                                    command_watchdog.program_name,
                                    e,
                                    consecutive_failures,
                                    opt.health_check_failure_threshold
                                );
                            }
                        }

                        // Check if we need to restart
                        if consecutive_failures >= opt.health_check_failure_threshold {
                            warn!(
                                "Service '{}' is unhealthy, restarting after {} consecutive failures",
                                command_watchdog.program_name, consecutive_failures
                            );

                            // Counted before the restart, so the command watchdog paces it
                            command_watchdog.record_failure();
                            // Restart the command watchdog process
                            match command_watchdog.restart().await {
                                Ok(_) => {
                                    info!("Service process restart requested");

                                    // Wait for initial startup before checking health again
                                    tokio::time::sleep(opt.initial_startup_delay).await;
                                    consecutive_failures = 0;
                                }
                                Err(e) => {
                                    error!("Failed to send restart signal: {e}");
                                }
                            }
                        }
                    }
                }
            }
        });
    }

    /// Wait until the service becomes healthy or the timeout elapses
    ///
    /// # Arguments
    /// * `wait_timeout` - Maximum duration to wait for the service to become healthy
    ///
    /// # Returns
    /// * `Ok(())` - If the service became healthy within the timeout
    /// * `Err(tokio::time::error::Elapsed)` - If the timeout was reached
    pub async fn wait_for_healthy(
        &self,
        wait_timeout: Duration,
    ) -> Result<(), tokio::time::error::Elapsed> {
        let mut receiver = self.health_receiver.clone();
        timeout(wait_timeout, async move {
            receiver.mark_unchanged();
            loop {
                // Wait for the next change
                if receiver.changed().await.is_ok() && *receiver.borrow() {
                    return;
                }
            }
        })
        .await
    }

    /// Whether the service is reported healthy: after a passing check, until it fails
    /// `health_check_unhealthy_threshold` checks in a row, stops running, or is restarted
    pub fn is_healthy(&self) -> bool {
        *self.health_receiver.borrow()
    }

    /// Get the underlying command watchdog
    pub fn command_watchdog(&self) -> &CommandWatchdog {
        &self.command_watchdog
    }

    /// Request a manual restart of the service
    pub async fn restart(&self) -> Result<(), tokio::sync::mpsc::error::SendError<()>> {
        info!("Manual restart requested for service");
        self.command_watchdog.restart().await
    }

    /// Gets the number of times the process has been started
    pub fn start_counter(&self) -> usize {
        self.command_watchdog.start_counter()
    }

    /// Gets the last exit code of the subprocess
    pub fn last_exit_code(&self) -> i32 {
        self.command_watchdog.last_exit_code()
    }

    /// Gets how many times in a row the service has failed: exited, failed to start, or been
    /// restarted for failing its health checks. It drops to 0 once the service passes its health
    /// checks for `max_restart_interval`.
    pub fn consecutive_failures(&self) -> u32 {
        self.command_watchdog.consecutive_failures()
    }

    /// Get the total number of health checks performed
    pub fn health_checks(&self) -> usize {
        self.stats.health_checks()
    }

    /// Get the total number of failed health checks
    pub fn failed_health_checks(&self) -> usize {
        self.stats.failed_health_checks()
    }
}

/// Tells `is_healthy` and `wait_for_healthy` what the latest health check found.
fn broadcast_health(health_status: &watch::Sender<bool>, healthy: bool) {
    if let Err(e) = health_status.send(healthy) {
        warn!("Failed to broadcast health status: {e}");
    }
}

impl Drop for ServiceWatchdog {
    fn drop(&mut self) {
        debug!("Service watchdog dropping, terminating process");
        self.shutdown_token.cancel();
    }
}
