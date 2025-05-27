use async_trait::async_trait;
use log::debug;
use std::fmt::Debug;
use std::fmt::Write;
use std::time::Duration;

/// Trait for health checkers to monitor service health
#[async_trait]
pub trait HealthCheck: Send + Sync + Debug + 'static {
    /// Check the health of the service
    /// Returns Ok(()) if healthy, Err otherwise
    ///
    /// Each implementation should handle its own timeout
    async fn check_health(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// HTTP-based health checker
#[derive(Debug, Clone)]
pub struct HttpHealthChecker {
    client: reqwest::Client,
    url: String,
    expected_status: u16,
}

impl HttpHealthChecker {
    /// Create a new HTTP health checker
    pub fn new(url: String) -> Self {
        Self::with_options(url, 200, Duration::from_secs(5))
    }

    /// Create a new HTTP health checker with a specific expected status code
    pub fn with_status(url: String, expected_status: u16) -> Self {
        Self::with_options(url, expected_status, Duration::from_secs(5))
    }

    /// Create a new HTTP health checker with custom options
    pub fn with_options(url: String, expected_status: u16, timeout: Duration) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(timeout)
                .build()
                .unwrap_or_default(),
            url,
            expected_status,
        }
    }
}

fn report(mut err: &dyn std::error::Error) -> String {
    let mut s = format!("{}", err);
    while let Some(src) = err.source() {
        let _ = write!(s, "\n\nCaused by: {}", src);
        err = src;
    }
    s
}

#[async_trait]
impl HealthCheck for HttpHealthChecker {
    async fn check_health(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        debug!("Checking health at URL: {}", self.url);
        let response = match self.client.get(&self.url).send().await {
            Ok(resp) => resp,
            Err(e) => {
                return Err(format!("HTTP request failed: {}", report(&e)).into());
            }
        };
        let status_code = response.status().as_u16();
        if status_code == self.expected_status {
            Ok(())
        } else {
            Err(format!(
                "Unhealthy status code: {} (expected {})",
                status_code, self.expected_status
            )
            .into())
        }
    }
}
