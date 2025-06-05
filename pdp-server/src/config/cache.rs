use confique::Config;
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
#[derive(Debug, Config, Clone, Default)]
pub struct CacheConfig {
    /// Cache TTL in seconds (default: 1 hour)
    #[config(env = "PDP_CACHE_TTL", default = 3600)]
    pub ttl: u32,

    /// Cache store type: "in-memory", "redis", or null (default)
    #[config(env = "PDP_CACHE_STORE", default = "none")]
    pub store: CacheStore,

    /// In-memory cache specific configuration
    #[config(nested)]
    pub memory: InMemoryConfig,

    /// Redis cache specific configuration
    #[config(nested)]
    pub redis: RedisConfig,
}

/// In-memory cache configuration options
#[derive(Debug, Config, Clone, Default)]
pub struct InMemoryConfig {
    /// Maximum capacity in MiB (default: 128 MiB)
    #[config(env = "PDP_CACHE_MEMORY_CAPACITY", default = 128)]
    pub capacity: usize,
}

/// Redis cache configuration options
#[derive(Debug, Config, Clone, Default)]
pub struct RedisConfig {
    /// Redis connection string
    #[config(env = "PDP_CACHE_REDIS_URL", default = "")]
    pub url: String,
}
