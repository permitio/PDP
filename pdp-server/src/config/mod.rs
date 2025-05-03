use config::{Config, ConfigError};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone, PartialEq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum CacheStore {
    InMemory,
    Redis,
    #[serde(other)]
    #[default]
    None,
}

#[derive(Debug, Deserialize, Clone)]
pub struct InMemoryCacheConfig {
    /// Maximum capacity in MiB (default: 128)
    #[serde(default = "default_in_memory_capacity")]
    pub capacity_mib: usize,
}

impl Default for InMemoryCacheConfig {
    fn default() -> Self {
        Self {
            capacity_mib: default_in_memory_capacity(),
        }
    }
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct RedisCacheConfig {
    /// Redis connection string
    #[serde(default)]
    pub url: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CacheConfig {
    /// Cache TTL in seconds
    #[serde(default = "default_cache_ttl")]
    pub ttl_secs: u32,

    /// Cache store type: "in-memory", "redis", or null (default)
    #[serde(default)]
    pub store: CacheStore,

    /// In-memory cache specific configuration
    #[serde(default)]
    pub in_memory: InMemoryCacheConfig,

    /// Redis cache specific configuration
    #[serde(default)]
    pub redis: RedisCacheConfig,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            ttl_secs: default_cache_ttl(),
            store: CacheStore::None,
            in_memory: InMemoryCacheConfig::default(),
            redis: RedisCacheConfig::default(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    /// The port the server will listen on
    #[serde(default = "default_port")]
    pub port: u16,

    /// Horizon fallback host
    #[serde(default = "default_horizon_host")]
    pub horizon_host: String,

    /// Horizon fallback port
    #[serde(default = "default_horizon_port")]
    pub horizon_port: u16,

    /// Python interpreter path for running Horizon
    #[serde(default = "default_python_path")]
    pub python_path: String,

    /// The URL of the OPA service
    #[serde(default = "default_opa_url")]
    pub opa_url: String,

    /// The timeout for OPA client queries
    #[serde(default = "default_opa_client_query_timeout")]
    pub opa_client_query_timeout: u64,

    /// Cache configuration
    #[serde(default)]
    pub cache: CacheConfig,

    /// API Key for authentication - mandatory for all API calls
    pub api_key: String,

    /// Debug mode
    #[serde(default)]
    pub debug: Option<bool>,

    /// Use new authorized users flag (controlled by Permit via environment settings)
    #[serde(default)]
    pub use_new_authorized_users: bool,
}

fn default_port() -> u16 {
    7766
}

pub fn default_cache_ttl() -> u32 {
    3600
}

fn default_in_memory_capacity() -> usize {
    128
}

fn default_opa_client_query_timeout() -> u64 {
    1
}

pub fn default_horizon_host() -> String {
    "0.0.0.0".to_string()
}

pub fn default_horizon_port() -> u16 {
    7001
}

fn default_opa_url() -> String {
    "http://localhost:8181".to_string()
}

fn default_python_path() -> String {
    "python3".to_string()
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            port: default_port(),
            horizon_host: default_horizon_host(),
            horizon_port: default_horizon_port(),
            python_path: default_python_path(),
            opa_url: default_opa_url(),
            opa_client_query_timeout: default_opa_client_query_timeout(),
            cache: CacheConfig::default(),
            api_key: String::new(),
            debug: None,
            use_new_authorized_users: false,
        }
    }
}

impl Settings {
    pub fn new() -> Result<Self, String> {
        Config::builder()
            .add_source(
                config::Environment::with_prefix("PDP")
                    .prefix_separator("_")
                    .separator("__")
                    .convert_case(config::Case::Snake),
            )
            .build()
            .map_err(|e: ConfigError| e.to_string())?
            .try_deserialize()
            .map_err(|e| e.to_string())
    }

    pub fn get_horizon_url<S: Into<String>>(&self, path: S) -> String {
        let path = path.into();
        if path.starts_with("/") {
            format!("http://{}:{}{}", self.horizon_host, self.horizon_port, path,)
        } else {
            format!(
                "http://{}:{}/{}",
                self.horizon_host, self.horizon_port, path,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_settings() -> Settings {
        Settings {
            api_key: "test-api-key".to_string(),
            port: 0, // Let the OS choose a port
            ..Default::default()
        }
    }

    #[test]
    fn test_default_settings() {
        // Clear any existing environment variables
        std::env::remove_var("PDP_PORT");
        std::env::remove_var("PDP_CACHE__TTL_SECS");
        std::env::remove_var("PDP_LEGACY_FALLBACK_URL");
        std::env::remove_var("PDP_OPA_URL");
        std::env::remove_var("PDP_PYTHON_PATH");
        std::env::remove_var("PDP_CACHE__STORE");
        std::env::remove_var("PDP_CACHE__REDIS__URL");
        std::env::remove_var("PDP_CACHE__IN_MEMORY__CAPACITY_MIB");
        std::env::set_var("PDP_API_KEY", "test-api-key");

        let settings = Settings::new().unwrap();
        assert_eq!(settings.port, 7766); // Default value
        assert_eq!(settings.cache.ttl_secs, 3600); // Default value
        assert_eq!(settings.horizon_host, "0.0.0.0"); // Default value
        assert_eq!(settings.horizon_port, 7001); // Default value
        assert_eq!(settings.python_path, "python3"); // Default value
        assert_eq!(settings.opa_url, "http://localhost:8181"); // Default value
        assert_eq!(settings.cache.store, CacheStore::None); // Default value
        assert_eq!(settings.cache.in_memory.capacity_mib, 128); // Default value
        assert_eq!(settings.cache.redis.url, ""); // Default value
        assert_eq!(settings.api_key, "test-api-key"); // Default value
    }

    #[test]
    fn test_cache_store_settings() {
        // Clear any existing environment variables that might affect the test
        std::env::remove_var("PDP_CACHE__STORE");
        std::env::remove_var("PDP_CACHE__REDIS_URL");
        std::env::remove_var("PDP_CACHE__IN_MEMORY__CAPACITY_MIB");
        std::env::set_var("PDP_API_KEY", "test-api-key");
        // Test default value (should be None)
        let settings = Settings::new().unwrap();
        assert_eq!(settings.cache.store, CacheStore::None);

        // Test in-memory cache store with custom capacity
        std::env::set_var("PDP_CACHE__STORE", "in-memory");
        std::env::set_var("PDP_CACHE__IN_MEMORY__CAPACITY_MIB", "256");
        let settings = Settings::new().unwrap();
        assert_eq!(settings.cache.store, CacheStore::InMemory);
        assert_eq!(settings.cache.in_memory.capacity_mib, 256);

        // Test redis cache store
        std::env::set_var("PDP_CACHE__STORE", "redis");
        std::env::set_var("PDP_CACHE__REDIS__URL", "redis://localhost:6379");
        let settings = Settings::new().unwrap();
        assert_eq!(settings.cache.store, CacheStore::Redis);
        assert_eq!(settings.cache.redis.url, "redis://localhost:6379");

        // Reset environment variables
        std::env::remove_var("PDP_CACHE__STORE");
        std::env::remove_var("PDP_CACHE__REDIS__URL");
        std::env::remove_var("PDP_CACHE__IN_MEMORY__CAPACITY_MIB");
        std::env::remove_var("PDP_API_KEY");
    }
}
