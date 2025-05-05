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
        let config_builder = ConfigCrate::builder()
            .add_source(
                config::Environment::with_prefix("PDP")
                    .prefix_separator("_")
                    .separator("_")
                    .convert_case(config::Case::Snake),
            )
            .build()
            .map_err(|e: ConfigError| e.to_string())?;

        // Debug during tests
        #[cfg(test)]
        {
            println!("Config builder debug: {:?}", config_builder);
        }

        // Try to extract key values directly from environment variables
        let api_key = std::env::var("PDP_API_KEY").unwrap_or_else(|_| String::new());

        // Parse port from environment variable
        let port = std::env::var("PDP_PORT")
            .ok()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(7766);

        // Parse cache TTL from environment variable
        let cache_ttl = std::env::var("PDP_CACHE_TTL")
            .ok()
            .and_then(|ttl| ttl.parse::<u32>().ok())
            .unwrap_or(3600);

        // Parse cache store type
        let cache_store = match std::env::var("PDP_CACHE_STORE").as_deref() {
            Ok("in-memory") => CacheStore::InMemory,
            Ok("redis") => CacheStore::Redis,
            Ok("none") | _ => CacheStore::None,
        };

        let mut config: Self = config_builder
            .try_deserialize()
            .map_err(|e| e.to_string())?;

        // Apply the direct environment variable values
        config.api_key = api_key;
        config.port = port;
        config.cache.ttl = cache_ttl;
        config.cache.store = cache_store;

        Ok(config)
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
    use std::sync::Mutex;

    // This mutex ensures tests don't interfere with each other's environment variables
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    // Helper to set environment variables for testing
    fn with_env_vars<F, R>(vars: &[(&str, &str)], test_fn: F) -> R
    where
        F: FnOnce() -> R,
    {
        // Acquire the mutex to prevent other tests from modifying the environment
        let _lock = ENV_MUTEX.lock().unwrap();

        // Save the original values
        let mut old_values = Vec::new();
        for (key, _) in vars {
            old_values.push((*key, std::env::var(*key).ok()));
        }

        // Clear any PDP_ environment variables
        for (name, _value) in std::env::vars() {
            if name.starts_with("PDP_") {
                std::env::remove_var(name);
            }
        }

        // Set the new values
        for (key, value) in vars {
            std::env::set_var(key, value);
        }

        // Debug - print all environment variables
        println!("Environment variables for test:");
        for (name, value) in std::env::vars() {
            if name.starts_with("PDP_") {
                println!("  {}: {}", name, value);
            }
        }

        // Run the test function
        let result = test_fn();

        // Restore the original environment
        for (name, _value) in std::env::vars() {
            if name.starts_with("PDP_") {
                std::env::remove_var(name);
            }
        }

        // Restore original values
        for (key, maybe_value) in old_values {
            if let Some(val) = maybe_value {
                std::env::set_var(key, val);
            }
        }

        result
    }

    #[test]
    fn test_default_config() {
        with_env_vars(
            &[
                ("PDP_API_KEY", "test-api-key"),
                ("PDP_PORT", "7766"),
                ("PDP_CACHE_TTL", "3600"),
                ("PDP_CACHE_STORE", "none"),
            ],
            || {
                let config = PDPConfig::new().unwrap();
                println!("Config loaded: api_key='{}'", config.api_key);
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
            },
        );
    }

    #[test]
    fn test_default_cache_store() {
        with_env_vars(&[("PDP_API_KEY", "test-api-key")], || {
            let config = PDPConfig::new().unwrap();
            assert_eq!(config.cache.store, CacheStore::None);
        });
    }

    #[test]
    fn test_in_memory_cache_store() {
        with_env_vars(
            &[
                ("PDP_API_KEY", "test-api-key"),
                ("PDP_CACHE_STORE", "in-memory"),
                ("PDP_CACHE_MEMORY_CAPACITY", "256"),
            ],
            || {
                let config = PDPConfig::new().unwrap();
                assert_eq!(config.cache.store, CacheStore::InMemory);
                assert_eq!(config.cache.memory.capacity, 256);
            },
        );
    }

    #[test]
    fn test_redis_cache_store() {
        with_env_vars(
            &[
                ("PDP_API_KEY", "test-api-key"),
                ("PDP_CACHE_STORE", "redis"),
                ("PDP_CACHE_REDIS_URL", "redis://localhost:6379"),
            ],
            || {
                let config = PDPConfig::new().unwrap();
                assert_eq!(config.cache.store, CacheStore::Redis);
                assert_eq!(config.cache.redis.url, "redis://localhost:6379");
            },
        );
    }
}
