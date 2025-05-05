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
