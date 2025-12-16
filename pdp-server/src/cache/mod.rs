use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

pub mod memory;
pub mod null;
pub mod redis;

/// Errors that can occur during cache operations
#[derive(Debug, Error)]
pub enum CacheError {
    #[error("Failed to serialize value: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Failed to parse value: {0}")]
    Deserialization(String),
    #[error("Redis error: {0}")]
    Redis(String),
    #[error("Configuration error: {0}")]
    Config(String),
}

/// Cache trait defining the interface for all cache implementations.
///
/// This trait represents the contract that all cache backends must fulfill.
/// It provides a uniform interface for performing common cache operations
/// regardless of the underlying implementation (in-memory, Redis, etc.).
///
/// Implementations of this trait should be thread-safe (Send + Sync)
/// and cloneable to support sharing across multiple handlers.
#[async_trait::async_trait]
#[allow(dead_code)]
pub trait CacheBackend: Send + Sync {
    /// Store a value in the cache with default TTL
    async fn set<T: Serialize + Send + Sync>(&self, key: &str, value: &T)
        -> Result<(), CacheError>;

    /// Retrieve a value from the cache
    async fn get<T: DeserializeOwned + Send + Sync>(
        &self,
        key: &str,
    ) -> Result<Option<T>, CacheError>;

    /// Performs a deep health check on the cache backend
    ///
    /// This method performs a more thorough health check than `health_check`,
    /// potentially testing actual connectivity to the backend.
    /// For Redis, this will ping the server. For memory cache, this will
    /// check if the cache is initialized.
    ///
    /// Returns Ok(()) if healthy, or Err with a descriptive message if unhealthy.
    async fn health_check(&self) -> Result<(), String>;

    /// Delete a value from the cache
    async fn delete(&self, key: &str) -> Result<(), CacheError>;
}

/// Cache implementation that provides a uniform interface regardless of backend.
///
/// This enum serves as a type-safe wrapper around different cache implementations.
/// It allows the application to use different cache backends through a common interface.
/// The concrete implementation is chosen at runtime based on the application configuration.
///
/// This design follows the Strategy Pattern, where different caching strategies
/// can be swapped without changing the client code that uses the cache.
#[derive(Clone)]
pub enum Cache {
    /// In-memory cache implementation using Moka
    InMemory(memory::InMemoryCache),
    /// Redis-based cache implementation
    Redis(redis::RedisCache),
    /// No-op cache implementation that doesn't actually cache anything
    Null(null::NullCache),
}

#[async_trait::async_trait]
impl CacheBackend for Cache {
    async fn set<T: Serialize + Send + Sync>(
        &self,
        key: &str,
        value: &T,
    ) -> Result<(), CacheError> {
        match self {
            Self::InMemory(cache) => cache.set(key, value).await,
            Self::Redis(cache) => cache.set(key, value).await,
            Self::Null(cache) => cache.set(key, value).await,
        }
    }

    async fn get<T: DeserializeOwned + Send + Sync>(
        &self,
        key: &str,
    ) -> Result<Option<T>, CacheError> {
        match self {
            Self::InMemory(cache) => cache.get(key).await,
            Self::Redis(cache) => cache.get(key).await,
            Self::Null(cache) => cache.get(key).await,
        }
    }

    async fn health_check(&self) -> Result<(), String> {
        match self {
            Self::InMemory(cache) => cache.health_check().await,
            Self::Redis(cache) => cache.health_check().await,
            Self::Null(cache) => cache.health_check().await,
        }
    }

    async fn delete(&self, key: &str) -> Result<(), CacheError> {
        match self {
            Self::InMemory(cache) => cache.delete(key).await,
            Self::Redis(cache) => cache.delete(key).await,
            Self::Null(cache) => cache.delete(key).await,
        }
    }
}

/// Factory function to create the appropriate cache implementation based on configuration.
///
/// This function implements the Factory Pattern, creating the appropriate cache
/// implementation at runtime based on the provided configuration.
///
/// # Factory Pattern
///
/// The factory pattern encapsulates the creation logic of cache implementations, allowing:
/// - Selection of the appropriate implementation based on configuration
/// - Initialization with the correct parameters
/// - Validation of configuration parameters before creation
/// - Centralized error handling during initialization
///
/// # Returns
///
/// Returns a `Result` containing either:
/// - A `Cache` enum wrapping the selected cache implementation
/// - A `CacheError` if initialization fails
///
/// # Example
///
/// ```
/// let config = Config::new().expect("Failed to load configuration");
/// let cache = create_cache(&config).await.expect("Failed to create cache");
/// ```
pub async fn create_cache(config: &crate::config::PDPConfig) -> Result<Cache, CacheError> {
    match config.cache.store {
        crate::config::CacheStore::InMemory => {
            let cache =
                memory::InMemoryCache::new(config.cache.ttl as u64, config.cache.memory.capacity)
                    .map_err(CacheError::Config)?;
            Ok(Cache::InMemory(cache))
        }
        crate::config::CacheStore::Redis => {
            if config.cache.redis.url.is_empty() {
                return Err(CacheError::Config(
                    "Redis URL is required for Redis cache".to_string(),
                ));
            }
            let cache = redis::RedisCache::new(&config.cache.redis.url, config.cache.ttl as u64)
                .await
                .map_err(CacheError::Config)?;
            Ok(Cache::Redis(cache))
        }
        crate::config::CacheStore::None => {
            let cache = null::NullCache::new();
            Ok(Cache::Null(cache))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::cache::memory::InMemoryCache;
    use serde::{Deserialize, Serialize};
    use std::time::Duration;

    #[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
    struct TestValue {
        field: String,
    }

    #[tokio::test]
    async fn test_cache_basic_operations() {
        let memory_cache = InMemoryCache::new(60, 128).expect("Failed to create cache");
        let cache = Cache::InMemory(memory_cache);

        // Test set and get
        let test_value = TestValue {
            field: "test_value".to_string(),
        };
        cache
            .set("test_key", &test_value)
            .await
            .expect("Failed to set value");
        let value: Option<TestValue> = cache.get("test_key").await.expect("Failed to get value");
        assert_eq!(value, Some(test_value));

        // Test non-existent key
        let value: Option<TestValue> = cache
            .get("non_existent")
            .await
            .expect("Failed to get value");
        assert_eq!(value, None);

        // Test delete
        cache
            .delete("test_key")
            .await
            .expect("Failed to delete value");
        let value: Option<TestValue> = cache.get("test_key").await.expect("Failed to get value");
        assert_eq!(value, None);
    }

    #[tokio::test]
    async fn test_cache_ttl() {
        let memory_cache = InMemoryCache::new(1, 128).expect("Failed to create cache"); // 1 second TTL
        let cache = Cache::InMemory(memory_cache);

        // Set a value
        let test_value = TestValue {
            field: "ttl_value".to_string(),
        };
        cache
            .set("ttl_key", &test_value)
            .await
            .expect("Failed to set value");

        // Verify value exists
        let value: Option<TestValue> = cache.get("ttl_key").await.expect("Failed to get value");
        assert_eq!(value, Some(test_value));

        // Wait for TTL to expire
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Verify value is gone
        let value: Option<TestValue> = cache.get("ttl_key").await.expect("Failed to get value");
        assert_eq!(value, None);
    }

    #[tokio::test]
    async fn test_cache_persistence() {
        let test_value = TestValue {
            field: "persist_value".to_string(),
        };

        // Create first cache instance and set value
        let memory_cache =
            InMemoryCache::new(60, 128).expect("Failed to create first cache instance");
        let cache = Cache::InMemory(memory_cache);
        cache
            .set("persist_key", &test_value)
            .await
            .expect("Failed to set value");

        // Verify value exists in the same instance
        let value: Option<TestValue> = cache.get("persist_key").await.expect("Failed to get value");
        assert_eq!(value, Some(test_value.clone()));

        // Create second cache instance and verify value does not persist (since Moka is in-memory)
        let memory_cache2 =
            InMemoryCache::new(60, 128).expect("Failed to create second cache instance");
        let cache2 = Cache::InMemory(memory_cache2);
        let value: Option<TestValue> = cache2
            .get("persist_key")
            .await
            .expect("Failed to get value");
        assert_eq!(
            value, None,
            "Value should not persist in a new cache instance since Moka is an in-memory cache"
        );
    }

    #[tokio::test]
    async fn test_cache_concurrent_operations() {
        let memory_cache = InMemoryCache::new(60, 128).expect("Failed to create cache");
        let cache = Cache::InMemory(memory_cache);
        let cache_clone = cache.clone();

        // Spawn task to set values
        let set_task = tokio::spawn(async move {
            for i in 0..100 {
                let test_value = TestValue {
                    field: format!("value_{i}"),
                };
                cache_clone
                    .set(&format!("key_{i}"), &test_value)
                    .await
                    .expect("Failed to set value");
            }
        });

        // Spawn task to get values
        let get_task = tokio::spawn(async move {
            for i in 0..100 {
                if let Ok(Some(value)) = cache.get::<TestValue>(&format!("key_{i}")).await {
                    assert_eq!(value.field, format!("value_{i}"));
                }
            }
        });

        // Wait for both tasks to complete
        tokio::try_join!(set_task, get_task).expect("Tasks failed");
    }
}
