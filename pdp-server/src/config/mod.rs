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

    /// Timeout in seconds for health checks (default: 1.0 second)
    #[serde(default)]
    pub healthcheck_timeout: f64,

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
            healthcheck_timeout: 1.0, // 1 second timeout for health checks
            horizon: HorizonConfig::default(),
            opa: OpaConfig::default(),
            cache: CacheConfig::default(),
        }
    }
}

impl PDPConfig {
    /// Creates a new Config instance from environment variables
    pub fn new() -> Result<Self, String> {
        // Create a config builder with environment source
        let config_builder = ConfigCrate::builder()
            .build()
            .map_err(|e: ConfigError| e.to_string())?;

        // Deserialize the basic configuration
        let base_config: Self = config_builder
            .try_deserialize()
            .map_err(|e| e.to_string())?;

        // Create a new configuration with environment variables
        Ok(Self::from_env(&base_config))
    }

    /// Creates a new configuration from environment variables
    pub fn from_env(config: &Self) -> Self {
        // Apply environment variables to main config
        let mut result = config.clone();

        // Apply API key from environment
        if let Ok(api_key) = std::env::var("PDP_API_KEY") {
            result.api_key = api_key;
        }

        // Apply port from environment
        if let Ok(port) = std::env::var("PDP_PORT") {
            if let Ok(parsed) = port.parse::<u16>() {
                result.port = parsed;
            }
        }

        // Apply debug flag from environment
        if let Ok(debug) = std::env::var("PDP_DEBUG") {
            if let Ok(parsed) = debug.parse::<bool>() {
                result.debug = Some(parsed);
            }
        }

        // Apply use_new_authorized_users flag from environment
        if let Ok(use_new) = std::env::var("PDP_USE_NEW_AUTHORIZED_USERS") {
            if let Ok(parsed) = use_new.parse::<bool>() {
                result.use_new_authorized_users = parsed;
            }
        }

        // Apply health check timeout from environment
        if let Ok(timeout) = std::env::var("PDP_HEALTHCHECK_TIMEOUT") {
            if let Ok(parsed) = timeout.parse::<f64>() {
                result.healthcheck_timeout = parsed;
            }
        }

        // Apply sub-configurations
        result.horizon = HorizonConfig::from_env(&result.horizon);
        result.opa = OpaConfig::from_env(&result.opa);
        result.cache = CacheConfig::from_env(&result.cache);

        result
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
            healthcheck_timeout: 1.0,
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
                client_query_timeout: 5,
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
        let lock = ENV_MUTEX
            .lock()
            .expect("Failed to acquire environment mutex");

        // Save the original values
        let mut old_values = Vec::new();
        for (key, _) in vars {
            old_values.push((*key, std::env::var(*key).ok()));
        }

        // Clear any PDP_ environment variables
        for (name, _) in std::env::vars() {
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
        for (name, _) in std::env::vars() {
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

        // Release the lock explicitly (though it would happen automatically at the end of scope)
        drop(lock);

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
                assert_eq!(config.opa.client_query_timeout, 1);
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

    #[test]
    fn test_comprehensive_env_vars() {
        with_env_vars(
            &[
                // Top level config
                ("PDP_API_KEY", "env-test-api-key"),
                ("PDP_PORT", "7777"),
                ("PDP_DEBUG", "true"),
                ("PDP_USE_NEW_AUTHORIZED_USERS", "true"),
                ("PDP_HEALTHCHECK_TIMEOUT", "2.5"),
                // Cache config
                ("PDP_CACHE_TTL", "1800"),
                ("PDP_CACHE_STORE", "in-memory"),
                ("PDP_CACHE_MEMORY_CAPACITY", "256"),
                ("PDP_CACHE_REDIS_URL", "redis://test-host:6379"),
                // OPA config
                ("PDP_OPA_URL", "http://test-opa:8181"),
                ("PDP_OPA_CLIENT_QUERY_TIMEOUT", "3"),
                // Horizon config
                ("PDP_HORIZON_HOST", "test-horizon-host"),
                ("PDP_HORIZON_PORT", "7002"),
                ("PDP_HORIZON_PYTHON_PATH", "/usr/bin/python3"),
                ("PDP_HORIZON_CLIENT_TIMEOUT", "30"),
                ("PDP_HORIZON_HEALTH_CHECK_TIMEOUT", "2"),
                ("PDP_HORIZON_HEALTH_CHECK_INTERVAL", "10"),
                ("PDP_HORIZON_HEALTH_CHECK_FAILURE_THRESHOLD", "5"),
                ("PDP_HORIZON_STARTUP_DELAY", "3"),
                ("PDP_HORIZON_RESTART_INTERVAL", "2"),
                ("PDP_HORIZON_TERMINATION_TIMEOUT", "15"),
            ],
            || {
                let config = PDPConfig::new().unwrap();

                // Test top level config
                assert_eq!(config.api_key, "env-test-api-key");
                assert_eq!(config.port, 7777);
                assert_eq!(config.debug, Some(true));
                assert!(config.use_new_authorized_users);
                assert_eq!(config.healthcheck_timeout, 2.5);

                // Test cache config
                assert_eq!(config.cache.ttl, 1800);
                assert_eq!(config.cache.store, CacheStore::InMemory);
                assert_eq!(config.cache.memory.capacity, 256);
                assert_eq!(config.cache.redis.url, "redis://test-host:6379");

                // Test OPA config
                assert_eq!(config.opa.url, "http://test-opa:8181");
                assert_eq!(config.opa.client_query_timeout, 3);

                // Test Horizon config
                assert_eq!(config.horizon.host, "test-horizon-host");
                assert_eq!(config.horizon.port, 7002);
                assert_eq!(config.horizon.python_path, "/usr/bin/python3");
                assert_eq!(config.horizon.client_timeout, 30);
                assert_eq!(config.horizon.health_check_timeout, 2);
                assert_eq!(config.horizon.health_check_interval, 10);
                assert_eq!(config.horizon.health_check_failure_threshold, 5);
                assert_eq!(config.horizon.startup_delay, 3);
                assert_eq!(config.horizon.restart_interval, 2);
                assert_eq!(config.horizon.termination_timeout, 15);
            },
        );
    }
}
