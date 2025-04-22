use crate::CommandWatchdog;
use crate::health::HealthCheck;
use crate::stats::ServiceWatchdogStats;
use log::{debug, error, info, warn};
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::watch;
use tokio::time::{interval, timeout};
use tokio_util::sync::CancellationToken;

/// Configuration for the service watchdog
#[derive(Debug, Clone)]
pub struct ServiceWatchdogOptions {
    /// How often to check service health
    pub health_check_interval: Duration,
    /// How many consecutive health check failures before restarting
    pub health_check_failure_threshold: u32,
    /// How long to wait before starting health checks after a restart
    pub initial_startup_delay: Duration,
}

impl Default for ServiceWatchdogOptions {
    fn default() -> Self {
        Self {
            health_check_interval: Duration::from_secs(10),
            health_check_failure_threshold: 3,
            initial_startup_delay: Duration::from_secs(5),
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
        let command_watchdog = CommandWatchdog::start(command);
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

        tokio::spawn(async move {
            // Wait initial startup delay
            tokio::time::sleep(opt.initial_startup_delay).await;
            info!(
                "Starting health checks watchdog for '{}' in {:?}",
                command_watchdog.program_name, opt.initial_startup_delay
            );

            let mut check_interval = interval(opt.health_check_interval);
            let mut consecutive_failures = 0;

            loop {
                tokio::select! {
                    _ = shutdown_token.cancelled() => {
                        info!("Service watchdog for '{}' shutting down", command_watchdog.program_name);
                        break;
                    }
                    _ = check_interval.tick() => {
                        stats.increment_health_checks();
                    }
                }

                // Check health
                match health_checker.check_health().await {
                    Ok(_) => {
                        // Service is healthy
                        if let Err(e) = health_status.send(true) {
                            warn!("Failed to broadcast health status: {}", e);
                        }

                        if consecutive_failures > 0 {
                            info!(
                                "Service '{}' health restored after {} failures",
                                command_watchdog.program_name, consecutive_failures
                            );
                        }
                        consecutive_failures = 0;
                        continue;
                    }
                    Err(e) => {
                        // Health check failed
                        if let Err(e) = health_status.send(false) {
                            warn!("Failed to broadcast health status: {}", e);
                        }

                        stats.increment_failed_health_checks();
                        consecutive_failures += 1;

                        warn!(
                            "Service '{}' health check failed: {} (consecutive failures: {})",
                            command_watchdog.program_name, e, consecutive_failures
                        );
                    }
                }

                // Check if we need to restart
                if consecutive_failures >= opt.health_check_failure_threshold {
                    warn!(
                        "Service '{}' is unhealthy, restarting after {} consecutive failures",
                        command_watchdog.program_name, consecutive_failures
                    );

                    // Restart the command watchdog process
                    match command_watchdog.restart().await {
                        Ok(_) => {
                            info!("Service process restart requested");

                            // Wait for initial startup before checking health again
                            tokio::time::sleep(opt.initial_startup_delay).await;
                            consecutive_failures = 0;
                            continue;
                        }
                        Err(e) => {
                            error!("Failed to send restart signal: {}", e);
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

    /// Check if the service is currently healthy
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

    /// Get the total number of health checks performed
    pub fn health_checks(&self) -> usize {
        self.stats.health_checks()
    }

    /// Get the total number of failed health checks
    pub fn failed_health_checks(&self) -> usize {
        self.stats.failed_health_checks()
    }
}

impl Drop for ServiceWatchdog {
    fn drop(&mut self) {
        debug!("Service watchdog dropping, terminating process");
        self.shutdown_token.cancel();
    }
}
