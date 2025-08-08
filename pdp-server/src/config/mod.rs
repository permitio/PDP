pub(crate) use crate::config::cache::{CacheConfig, CacheStore};
use crate::config::horizon::HorizonConfig;
use crate::config::opa::OpaConfig;
use confique::Config;

pub mod cache;
pub mod horizon;
pub mod opa;

/// Main configuration structure for the PDP server
#[derive(Debug, Config, Clone, Default)]
pub struct PDPConfig {
    /// API Key for authentication - mandatory for all API calls
    #[config(env = "PDP_API_KEY", default = "")]
    pub api_key: String,

    /// Debug mode (injects debug attributes to OPA requests)
    #[config(env = "PDP_DEBUG")]
    pub debug: Option<bool>,

    /// Enable IPv6 binding (default: false for IPv4 0.0.0.0, true for IPv6 ::)
    #[config(env = "PDP_IPV6_ENABLED", default = false)]
    pub ipv6_enabled: bool,

    /// The port the PDP server will listen to (default: 7766)
    #[config(env = "PDP_PORT", default = 7766)]
    pub port: u16,

    /// Feature flag for new authorized users implementation
    #[config(env = "PDP_USE_NEW_AUTHORIZED_USERS", default = false)]
    pub use_new_authorized_users: bool,

    /// Timeout in seconds for health checks (default: 3 second)
    #[config(env = "PDP_HEALTHCHECK_TIMEOUT", default = 3.0)]
    pub healthcheck_timeout: f64,

    /// Horizon service configuration
    #[config(nested)]
    pub horizon: HorizonConfig,

    /// OPA service configuration
    #[config(nested)]
    pub opa: OpaConfig,

    /// Cache configuration
    #[config(nested)]
    pub cache: CacheConfig,
}

impl PDPConfig {
    /// Creates a new Config instance from environment variables
    pub fn new() -> Result<Self, String> {
        // Use confique's builder to load configuration from environment
        Self::builder().env().load().map_err(|e| e.to_string())
    }

    #[cfg(test)]
    pub fn for_test_with_mocks(
        horizon_mock: &wiremock::MockServer,
        opa_mock: &wiremock::MockServer,
    ) -> Self {
        use crate::config::cache::{InMemoryConfig, RedisConfig};

        // Create a base configuration and override specific values for testing
        let mut config = Self::builder().env().load().unwrap_or_else(|_| {
            // Create a minimal config if loading fails
            Self {
                api_key: "test_api_key".to_string(),
                debug: Some(true),
                ipv6_enabled: false,
                port: 0,
                use_new_authorized_users: false,
                healthcheck_timeout: 3.0,
                horizon: HorizonConfig::builder()
                    .env()
                    .load()
                    .unwrap_or_else(|_| HorizonConfig {
                        host: "0.0.0.0".to_string(),
                        port: 7001,
                        python_path: "python3".to_string(),
                        client_timeout: 60,
                        health_check_timeout: 1,
                        health_check_interval: 5,
                        health_check_failure_threshold: 12,
                        startup_delay: 5,
                        restart_interval: 1,
                        termination_timeout: 30,
                    }),
                opa: OpaConfig::builder()
                    .env()
                    .load()
                    .unwrap_or_else(|_| OpaConfig {
                        url: "http://localhost:8181".to_string(),
                        client_query_timeout: 5,
                    }),
                cache: CacheConfig::builder()
                    .env()
                    .load()
                    .unwrap_or_else(|_| CacheConfig {
                        ttl: 60,
                        store: CacheStore::None,
                        memory: InMemoryConfig { capacity: 128 },
                        redis: RedisConfig {
                            url: "".to_string(),
                        },
                    }),
            }
        });

        if config.api_key.is_empty() {
            config.api_key = "default-test-api-key".to_string();
        }

        // Override with mock server addresses
        config.horizon.host = horizon_mock.address().ip().to_string();
        config.horizon.port = horizon_mock.address().port();
        config.opa.url = opa_mock.uri();

        config
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
                println!("  {name}: {value}");
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
                ("PDP_IPV6_ENABLED", "false"),
                ("PDP_PORT", "7766"),
                ("PDP_CACHE_TTL", "3600"),
                ("PDP_CACHE_STORE", "none"),
            ],
            || {
                let config = PDPConfig::new().unwrap();
                println!("Config loaded: api_key='{}'", config.api_key);
                assert!(!config.ipv6_enabled);
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
                ("PDP_IPV6_ENABLED", "true"),
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
                assert!(config.ipv6_enabled);
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

    #[test]
    fn test_ipv6_enabled() {
        with_env_vars(
            &[
                ("PDP_API_KEY", "test-api-key"),
                ("PDP_IPV6_ENABLED", "true"),
                ("PDP_PORT", "7766"),
            ],
            || {
                let config = PDPConfig::new().unwrap();
                assert!(config.ipv6_enabled);
                assert_eq!(config.port, 7766);
            },
        );
    }

    #[test]
    fn test_ipv6_disabled_default() {
        with_env_vars(
            &[
                ("PDP_API_KEY", "test-api-key"),
                ("PDP_PORT", "7766"),
            ],
            || {
                let config = PDPConfig::new().unwrap();
                assert!(!config.ipv6_enabled); // Should default to false
                assert_eq!(config.port, 7766);
            },
        );
    }

    #[test]
    fn test_confique_template_generation() {
        // Test that we can generate configuration templates
        // This is a new feature we get from confique
        let toml_template =
            confique::toml::template::<PDPConfig>(confique::toml::FormatOptions::default());

        // Verify that the template contains our configuration fields
        assert!(toml_template.contains("PDP_API_KEY"));
        assert!(toml_template.contains("PDP_IPV6_ENABLED"));
        assert!(toml_template.contains("PDP_PORT"));
        assert!(toml_template.contains("PDP_DEBUG"));
        assert!(toml_template.contains("PDP_CACHE_TTL"));
        assert!(toml_template.contains("PDP_CACHE_STORE"));
        assert!(toml_template.contains("PDP_OPA_URL"));
        assert!(toml_template.contains("PDP_HORIZON_HOST"));

        // Verify default values are documented
        assert!(toml_template.contains("7766"));
        assert!(toml_template.contains("3600"));
        assert!(toml_template.contains("http://localhost:8181"));
        assert!(toml_template.contains("0.0.0.0"));

        println!("Generated TOML template:\n{toml_template}");
    }

    #[test]
    fn test_confique_builder_pattern() {
        with_env_vars(
            &[("PDP_API_KEY", "builder-test-key"), ("PDP_IPV6_ENABLED", "false"), ("PDP_PORT", "8080")],
            || {
                // Test the builder pattern directly
                let config = PDPConfig::builder()
                    .env()
                    .load()
                    .expect("Failed to load config");

                assert_eq!(config.api_key, "builder-test-key");
                assert!(!config.ipv6_enabled);
                assert_eq!(config.port, 8080);
                assert_eq!(config.cache.ttl, 3600); // Default value
                assert_eq!(config.opa.url, "http://localhost:8181"); // Default value
            },
        );
    }
}
