use confique::Config;

/// Configuration for the OPA service
#[derive(Debug, Config, Clone, Default)]
pub struct OpaConfig {
    /// The URL of the OPA service (default: http://localhost:8181)
    #[config(env = "PDP_OPA_URL", default = "http://localhost:8181")]
    pub url: String,

    /// The timeout for OPA client queries in seconds (default: 1)
    #[config(env = "PDP_OPA_CLIENT_QUERY_TIMEOUT", default = 1)]
    pub client_query_timeout: u64,
}
