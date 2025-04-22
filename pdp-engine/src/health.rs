use crate::error::PDPError;
use crate::runner::PDPRunner;
use log::{debug, error, info};
use reqwest::Client;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use url::Url;

/// Helper function to check if PDP is healthy at the given URL
pub async fn is_healthy(base_url: &Url, client: &Client) -> bool {
    let url = match base_url.join("healthy") {
        Ok(url) => url,
        Err(e) => {
            error!("Failed to create health URL: {}", e);
            return false;
        }
    };

    match client.get(url).send().await {
        Ok(resp) => resp.status().is_success(),
        Err(e) => {
            debug!("Health check error: {}", e);
            false
        }
    }
}

/// Sleep for the given duration or until cancellation occurs.
/// Returns true if cancelled, false if sleep completed.
pub async fn sleep_or_cancel(
    duration: Duration,
    token: &CancellationToken,
    cancel_msg: &str,
) -> bool {
    tokio::select! {
        _ = sleep(duration) => false,
        _ = token.cancelled() => {
            info!("{}", cancel_msg);
            true
        }
    }
}

/// Helper function that waits for PDP to become healthy with timeout and cancellation support.
/// Returns Ok(()) if PDP became healthy, or Err with the reason for failure (timeout or cancelled).
pub async fn wait_for_healthy(
    base_url: &Url,
    client: &Client,
    timeout: Duration,
    token: &CancellationToken,
) -> Result<(), PDPError> {
    let start = std::time::Instant::now();
    let check_interval = Duration::from_millis(500);

    while start.elapsed() < timeout {
        // Check if cancelled
        if token.is_cancelled() {
            return Err(PDPError::ShutdownTriggered);
        }

        // Check health
        if is_healthy(base_url, client).await {
            return Ok(());
        }

        // Wait before next check
        if sleep_or_cancel(check_interval, token, "").await {
            return Err(PDPError::ShutdownTriggered);
        }
    }

    Err(PDPError::HealthCheckTimeout(
        "PDP failed to become healthy within the timeout period".into(),
    ))
}

/// Main health monitoring loop that checks PDP's health and handles recovery
pub async fn run_health_monitor(
    base_url: Url,
    client: Client,
    runner: Arc<PDPRunner>,
    token: CancellationToken,
    check_interval: Duration,
    timeout: Duration,
) {
    info!("Health monitor started");

    loop {
        if token.is_cancelled() {
            info!("Health monitor shutting down");
            break;
        }

        if check_health_and_wait(&base_url, &client, &token, check_interval).await {
            continue;
        }

        // PDP is unhealthy - attempt recovery
        if let Some(()) =
            try_recover_unhealthy_pdp(&base_url, &client, &runner, &token, timeout).await
        {
            continue;
        }

        // Whether recovery was successful or not, wait before next health check cycle
        if sleep_or_cancel(check_interval, &token, "Health monitor shutting down").await {
            break;
        }
    }
}

/// Checks PDP's health and waits for the next interval if healthy
/// Returns true if monitoring should continue, false if PDP is unhealthy
pub async fn check_health_and_wait(
    base_url: &Url,
    client: &Client,
    token: &CancellationToken,
    check_interval: Duration,
) -> bool {
    debug!("Performing health check");
    if !is_healthy(base_url, client).await {
        info!("PDP is unhealthy, attempting recovery");
        return false;
    }

    debug!("PDP is healthy");

    // Wait until next check or exit if cancelled
    !sleep_or_cancel(check_interval, token, "Health monitor shutting down").await
}

/// Attempts to recover an unhealthy PDP instance
/// Returns Some(()) if recovery was successful and monitoring should continue
/// Returns None if recovery failed or shutdown was triggered
pub async fn try_recover_unhealthy_pdp(
    base_url: &Url,
    client: &Client,
    runner: &Arc<PDPRunner>,
    token: &CancellationToken,
    timeout: Duration,
) -> Option<()> {
    // Try waiting for self-recovery
    match wait_for_healthy(base_url, client, timeout, token).await {
        Ok(()) => {
            info!("PDP recovered health on its own");
            return Some(());
        }
        Err(PDPError::ShutdownTriggered) => {
            info!("Health monitor shutting down during recovery");
            return None;
        }
        Err(PDPError::HealthCheckTimeout(_)) => {
            info!("PDP failed to recover, restarting process");
        }
        Err(e) => {
            error!("Unexpected error during health check: {}", e);
            info!("Attempting process restart");
        }
    }

    // If not recovered, try restarting
    match runner.restart().await {
        Ok(_) => {
            info!("PDP process restarted, waiting for health");

            // Wait for health after restart
            match wait_for_healthy(base_url, client, timeout, token).await {
                Ok(()) => {
                    info!("PDP is healthy after restart");
                    return Some(());
                }
                Err(PDPError::ShutdownTriggered) => {
                    info!("Health monitor shutting down after restart");
                    return None;
                }
                Err(PDPError::HealthCheckTimeout(msg)) => {
                    error!("Failed to restore PDP health after restart: {}", msg);
                }
                Err(e) => {
                    error!("Unexpected error checking health after restart: {}", e);
                }
            }
        }
        Err(e) => error!("Failed to restart PDP: {}", e),
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PDPEngine;
    use crate::args::Arg;
    use crate::builder::PDPEngineBuilder;
    use log::LevelFilter;

    /// Test the health check and monitoring functionality
    async fn setup_test_engine(with_monitoring: bool) -> Result<impl PDPEngine, PDPError> {
        let _ = env_logger::builder()
            .filter_level(LevelFilter::Debug)
            .is_test(true)
            .try_init();

        let mut builder = PDPEngineBuilder::new()
            .with_located_python()?
            .with_pdp_dir("./PDP")?
            .with_base_url("http://localhost:7001/")
            .with_args(vec![
                Arg::Module("uvicorn".to_string()),
                Arg::App("horizon.main:app".to_string()),
                Arg::Port(7001),
                Arg::Reload,
            ])
            .add_env("PDP_DEBUG".to_string(), "true".to_string());

        if !with_monitoring {
            builder = builder.with_health_check_interval(Duration::from_secs(0));
        }

        builder.start().await
    }

    #[tokio::test]
    #[ignore] // Requires actual PDP server
    async fn test_health_monitoring() -> Result<(), PDPError> {
        let engine = setup_test_engine(true).await?;
        assert!(engine.health().await);
        engine.stop().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_zero_interval_disables_monitoring() -> Result<(), PDPError> {
        let engine = setup_test_engine(false).await?;
        engine.stop().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_wait_for_healthy_timeout() -> Result<(), PDPError> {
        let url = Url::parse("http://localhost:9999/")?; // Non-existent server
        let client = Client::new();
        let token = CancellationToken::new();
        let timeout = Duration::from_millis(500);

        let result = wait_for_healthy(&url, &client, timeout, &token).await;
        assert!(matches!(result, Err(PDPError::HealthCheckTimeout(_))));
        Ok(())
    }

    #[tokio::test]
    async fn test_wait_for_healthy_cancellation() -> Result<(), PDPError> {
        let url = Url::parse("http://localhost:9999/")?; // Non-existent server
        let client = Client::new();
        let token = CancellationToken::new();
        let timeout = Duration::from_secs(10);

        // Spawn a task to cancel the token after a short delay
        let token_clone = token.clone();
        tokio::spawn(async move {
            sleep(Duration::from_millis(100)).await;
            token_clone.cancel();
        });

        let result = wait_for_healthy(&url, &client, timeout, &token).await;
        assert!(matches!(result, Err(PDPError::ShutdownTriggered)));
        Ok(())
    }

    #[tokio::test]
    async fn test_sleep_or_cancel() -> Result<(), PDPError> {
        let token = CancellationToken::new();
        let duration = Duration::from_millis(500);

        // Test without cancellation
        let result = sleep_or_cancel(duration, &token, "Test cancel").await;
        assert!(!result);

        // Test with cancellation
        let token2 = CancellationToken::new();
        let token2_clone = token2.clone();
        let duration2 = Duration::from_secs(10);

        tokio::spawn(async move {
            sleep(Duration::from_millis(100)).await;
            token2_clone.cancel();
        });

        let result2 = sleep_or_cancel(duration2, &token2, "Test cancel").await;
        assert!(result2);

        Ok(())
    }
}
