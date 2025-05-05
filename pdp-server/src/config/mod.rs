pub(crate) use crate::config::cache::{CacheConfig, CacheStore};
use crate::config::horizon::HorizonConfig;
use crate::config::opa::OpaConfig;
use config::{Config as ConfigCrate, ConfigError};
use serde::Deserialize;

pub mod cache;
pub mod horizon;
pub mod opa;

/// Main configuration structure for the PDP server
#[derive(Debug, Deserialize, Clone)]
pub struct PDPConfig {
    /// API Key for authentication - mandatory for all API calls
    #[serde(default)]
    pub api_key: String,

    /// Debug mode (injects debug attributes to OPA requests)
    #[serde(default)]
    pub debug: Option<bool>,

    /// The port the PDP server will listen to (default: 7766)
    #[serde(default)]
    pub port: u16,

    /// Feature flag for new authorized users implementation
    #[serde(default)]
    pub use_new_authorized_users: bool,

    /// Horizon service configuration
    #[serde(default)]
    pub horizon: HorizonConfig,

    /// OPA service configuration
    #[serde(default)]
    pub opa: OpaConfig,

    /// Cache configuration
    #[serde(default)]
    pub cache: CacheConfig,
}

impl Default for PDPConfig {
    fn default() -> Self {
        Self {
            api_key: "".to_string(),
            debug: None,
            port: 7766,
            use_new_authorized_users: false,
            horizon: HorizonConfig::default(),
            opa: OpaConfig::default(),
            cache: CacheConfig::default(),
        }
    }
}

impl PDPConfig {
    /// Creates a new Config instance from environment variables
    pub fn new() -> Result<Self, String> {
        ConfigCrate::builder()
            .add_source(
                config::Environment::with_prefix("PDP")
                    .prefix_separator("_")
                    .separator("_")
                    .convert_case(config::Case::Snake),
            )
            .build()
            .map_err(|e: ConfigError| e.to_string())?
            .try_deserialize()
            .map_err(|e| e.to_string())
    }

    #[cfg(test)]
    pub fn for_test_with_mocks(
        horizon_mock: &wiremock::MockServer,
        opa_mock: &wiremock::MockServer,
    ) -> Self {
        Self {
            api_key: "test_api_key".to_string(),
            debug: Some(true),
            port: 0, // Let the OS choose a port
            use_new_authorized_users: false,
            // Use the mock server addresses for testing
            horizon: HorizonConfig {
                host: horizon_mock.address().ip().to_string(),
                port: horizon_mock.address().port(),
                python_path: "python3".to_string(),
                client_timeout: 60,
                health_check_timeout: 1,
                health_check_interval: 5,
                health_check_failure_threshold: 12,
                startup_delay: 5,
                restart_interval: 1,
                termination_timeout: 30,
            },
            opa: OpaConfig {
                url: opa_mock.uri(),
                query_timeout: 5,
            },
            cache: CacheConfig {
                ttl: 60,
                store: CacheStore::None,
                ..Default::default()
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        // Clear any existing environment variables
        for (name, _value) in std::env::vars() {
            if name.starts_with("PDP_") {
                std::env::remove_var(name);
            }
        }
        // Set environment variables for testing
        std::env::set_var("PDP_API_KEY", "test-api-key");
        std::env::set_var("PDP_PORT", "7766");

        let config = PDPConfig::new().unwrap();
        assert_eq!(config.port, 7766);
        assert_eq!(config.cache.ttl, 3600);
        assert_eq!(config.horizon.host, "0.0.0.0");
        assert_eq!(config.horizon.port, 7001);
        assert_eq!(config.horizon.python_path, "python3");
        assert_eq!(config.opa.url, "http://localhost:8181");
        assert_eq!(config.opa.query_timeout, 1);
        assert_eq!(config.horizon.client_timeout, 60);
        assert_eq!(config.cache.store, CacheStore::None);
        assert_eq!(config.cache.memory.capacity, 128);
        assert_eq!(config.cache.redis.url, "");
        assert_eq!(config.api_key, "test-api-key");

        // Clean up
        std::env::remove_var("PDP_API_KEY");
        std::env::remove_var("PDP_PORT");
    }

    #[test]
    fn test_default_cache_store() {
        std::env::remove_var("PDP_CACHE_STORE");
        std::env::remove_var("PDP_CACHE_REDIS_URL");
        std::env::remove_var("PDP_CACHE_MEMORY_CAPACITY");
        std::env::set_var("PDP_API_KEY", "test-api-key");

        let config = PDPConfig::new().unwrap();
        assert_eq!(config.cache.store, CacheStore::None);

        std::env::remove_var("PDP_API_KEY");
    }

    #[test]
    fn test_in_memory_cache_store() {
        std::env::set_var("PDP_CACHE_STORE", "in-memory");
        std::env::set_var("PDP_CACHE_MEMORY_CAPACITY", "256");

        let config = PDPConfig::new().unwrap();
        assert_eq!(config.cache.store, CacheStore::InMemory);
        assert_eq!(config.cache.memory.capacity, 256);

        std::env::remove_var("PDP_CACHE_STORE");
        std::env::remove_var("PDP_CACHE_MEMORY_CAPACITY");
    }

    #[test]
    fn test_redis_cache_store() {
        std::env::set_var("PDP_CACHE_STORE", "redis");
        std::env::set_var("PDP_CACHE_REDIS_URL", "redis://localhost:6379");

        let config = PDPConfig::new().unwrap();
        assert_eq!(config.cache.store, CacheStore::Redis);
        assert_eq!(config.cache.redis.url, "redis://localhost:6379");

        std::env::remove_var("PDP_CACHE_STORE");
        std::env::remove_var("PDP_CACHE_REDIS_URL");
    }
}
