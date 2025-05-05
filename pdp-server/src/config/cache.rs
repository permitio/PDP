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

/// Redis cache configuration options
#[derive(Debug, Deserialize, Clone, Default)]
pub struct RedisConfig {
    /// Redis connection string
    #[serde(default)]
    pub url: String,
}
