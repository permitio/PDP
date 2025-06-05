use confique::Config;

/// Configuration for the Horizon service
#[derive(Debug, Config, Clone, Default)]
pub struct HorizonConfig {
    /// Horizon service hostname (default: 0.0.0.0)
    #[config(env = "PDP_HORIZON_HOST", default = "0.0.0.0")]
    pub host: String,

    /// Horizon service port (default: 7001)
    #[config(env = "PDP_HORIZON_PORT", default = 7001)]
    pub port: u16,

    /// The timeout for Horizon client queries in seconds (default: 60)
    #[config(env = "PDP_HORIZON_CLIENT_TIMEOUT", default = 60)]
    pub client_timeout: u64,

    /// Python interpreter path for running Horizon (default: python3)
    #[config(env = "PDP_HORIZON_PYTHON_PATH", default = "python3")]
    pub python_path: String,

    /// Health check endpoint timeout in seconds (default: 1)
    #[config(env = "PDP_HORIZON_HEALTH_CHECK_TIMEOUT", default = 1)]
    pub health_check_timeout: u64,

    /// Interval between health checks in seconds (default: 5)
    #[config(env = "PDP_HORIZON_HEALTH_CHECK_INTERVAL", default = 5)]
    pub health_check_interval: u64,

    /// Number of consecutive health check failures before restarting (default: 12)
    #[config(env = "PDP_HORIZON_HEALTH_CHECK_FAILURE_THRESHOLD", default = 12)]
    pub health_check_failure_threshold: u32,

    /// Initial delay before starting health checks in seconds (default: 5)
    #[config(env = "PDP_HORIZON_STARTUP_DELAY", default = 5)]
    pub startup_delay: u64,

    /// Interval between service restart attempts in seconds (default: 1)
    #[config(env = "PDP_HORIZON_RESTART_INTERVAL", default = 1)]
    pub restart_interval: u64,

    /// Service termination timeout in seconds (default: 30)
    #[config(env = "PDP_HORIZON_TERMINATION_TIMEOUT", default = 30)]
    pub termination_timeout: u64,
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
