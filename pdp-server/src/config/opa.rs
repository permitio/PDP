use serde::Deserialize;

/// Configuration for the OPA service
#[derive(Debug, Deserialize, Clone)]
pub struct OpaConfig {
    /// The URL of the OPA service (default: http://localhost:8181)
    #[serde(default)]
    pub url: String,

    /// The timeout for OPA client queries in seconds (default: 1)
    #[serde(default)]
    pub query_timeout: u64,
}

impl Default for OpaConfig {
    fn default() -> Self {
        Self {
            url: "http://localhost:8181".to_string(),
            query_timeout: 1, // 1 second
        }
    }
}

impl OpaConfig {
    /// Creates a new configuration from environment variables
    pub fn from_env(config: &Self) -> Self {
        // Start with the provided configuration
        let mut result = config.clone();

        // Apply environment variable overrides for OPA configuration
        if let Ok(url) = std::env::var("PDP_OPA_URL") {
            result.url = url;
        }

        if let Ok(timeout) = std::env::var("PDP_OPA_QUERY_TIMEOUT") {
            if let Ok(parsed) = timeout.parse::<u64>() {
                result.query_timeout = parsed;
            }
        }

        result
    }
}
