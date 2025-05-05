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
}

impl Default for HorizonConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 7001,
            client_timeout: 60,
            python_path: "python3".to_string(),
        }
    }
}
