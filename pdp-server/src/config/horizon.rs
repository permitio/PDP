use serde::Deserialize;

/// Configuration for the Horizon service
#[derive(Debug, Deserialize, Clone)]
pub struct HorizonConfig {
    /// Horizon service hostname (default: 0.0.0.0)
    #[serde(default)]
    pub host: String,

    /// Horizon service port (default: 7001)
    #[serde(default)]
    pub port: u16,

    /// The timeout for Horizon client queries in seconds (default: 60)
    #[serde(default)]
    pub client_timeout: u64,

    /// Python interpreter path for running Horizon (default: python3)
    #[serde(default)]
    pub python_path: String,

    /// Health check endpoint timeout in seconds (default: 1)
    #[serde(default)]
    pub health_check_timeout: u64,

    /// Interval between health checks in seconds (default: 5)
    #[serde(default)]
    pub health_check_interval: u64,

    /// Number of consecutive health check failures before restarting (default: 12)
    #[serde(default)]
    pub health_check_failure_threshold: u32,

    /// Initial delay before starting health checks in seconds (default: 5)
    #[serde(default)]
    pub startup_delay: u64,

    /// Interval between service restart attempts in seconds (default: 1)
    #[serde(default)]
    pub restart_interval: u64,

    /// Service termination timeout in seconds (default: 30)
    #[serde(default)]
    pub termination_timeout: u64,
}

impl Default for HorizonConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 7001,
            client_timeout: 60,
            python_path: "python3".to_string(),
            health_check_timeout: 1,
            health_check_interval: 5,
            health_check_failure_threshold: 12,
            startup_delay: 5,
            restart_interval: 1,
            termination_timeout: 30,
        }
    }
}

impl HorizonConfig {
    /// Returns a properly formatted URL to the Horizon service with the given path
    pub fn get_url<S: Into<String>>(&self, path: S) -> String {
        let path = path.into();
        if path.starts_with("/") {
            format!("http://{}:{}{}", self.host, self.port, path)
        } else {
            format!("http://{}:{}/{}", self.host, self.port, path)
        }
    }
}
