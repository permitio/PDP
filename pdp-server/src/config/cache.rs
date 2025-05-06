use serde::Deserialize;

/// Specifies which cache store implementation to use
#[derive(Debug, Deserialize, Clone, PartialEq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum CacheStore {
    InMemory,
    Redis,
    #[serde(other)]
    #[default]
    None,
}

/// Configuration for the caching subsystem
#[derive(Debug, Deserialize, Clone)]
pub struct CacheConfig {
    /// Cache TTL in seconds (default: 1 hour)
    #[serde(default)]
    pub ttl: u32,

    /// Cache store type: "in-memory", "redis", or null (default)
    #[serde(default)]
    pub store: CacheStore,

    /// In-memory cache specific configuration
    #[serde(default)]
    pub memory: InMemoryConfig,

    /// Redis cache specific configuration
    #[serde(default)]
    pub redis: RedisConfig,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            ttl: 3600, // 1 hour
            store: CacheStore::None,
            memory: InMemoryConfig::default(),
            redis: RedisConfig::default(),
        }
    }
}

impl CacheConfig {
    /// Creates a new configuration from environment variables
    pub fn from_env(config: &Self) -> Self {
        // Start with the provided configuration
        let mut result = config.clone();

        // Apply TTL environment variable
        if let Ok(ttl) = std::env::var("PDP_CACHE_TTL") {
            if let Ok(parsed) = ttl.parse::<u32>() {
                result.ttl = parsed;
            }
        }

        // Apply store type from environment
        result.store = match std::env::var("PDP_CACHE_STORE").as_deref() {
            Ok("in-memory") => CacheStore::InMemory,
            Ok("redis") => CacheStore::Redis,
            Ok("none") => CacheStore::None,
            _ => result.store.clone(), // Keep existing value if not specified
        };

        // Apply sub-configurations from environment
        result.memory = InMemoryConfig::from_env(&result.memory);
        result.redis = RedisConfig::from_env(&result.redis);

        result
    }
}

/// In-memory cache configuration options
#[derive(Debug, Deserialize, Clone)]
pub struct InMemoryConfig {
    /// Maximum capacity in MiB (default: 128 MiB)
    #[serde(default)]
    pub capacity: usize,
}

impl Default for InMemoryConfig {
    fn default() -> Self {
        Self {
            capacity: 128, // 128 MiB
        }
    }
}

impl InMemoryConfig {
    /// Creates a new configuration from environment variables
    pub fn from_env(config: &Self) -> Self {
        // Start with the provided configuration
        let mut result = config.clone();

        if let Ok(capacity) = std::env::var("PDP_CACHE_MEMORY_CAPACITY") {
            if let Ok(parsed) = capacity.parse::<usize>() {
                result.capacity = parsed;
            }
        }

        result
    }
}

/// Redis cache configuration options
#[derive(Debug, Deserialize, Clone, Default)]
pub struct RedisConfig {
    /// Redis connection string
    #[serde(default)]
    pub url: String,
}

impl RedisConfig {
    /// Creates a new configuration from environment variables
    pub fn from_env(config: &Self) -> Self {
        // Start with the provided configuration
        let mut result = config.clone();

        if let Ok(url) = std::env::var("PDP_CACHE_REDIS_URL") {
            result.url = url;
        }

        result
    }
}
