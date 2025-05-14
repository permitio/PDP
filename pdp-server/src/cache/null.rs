use super::{CacheBackend, CacheError};
use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};

/// NullCache is a cache implementation that does nothing.
/// It can be used when caching is disabled but the cache interface is still required.
#[derive(Clone, Debug)]
pub struct NullCache;

impl NullCache {
    /// Create a new NullCache instance
    pub fn new() -> Self {
        NullCache
    }
}

impl Default for NullCache {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CacheBackend for NullCache {
    async fn set<T: Serialize + Send + Sync>(
        &self,
        _key: &str,
        _value: &T,
    ) -> Result<(), CacheError> {
        // Do nothing
        Ok(())
    }

    async fn get<T: DeserializeOwned + Send + Sync>(
        &self,
        _key: &str,
    ) -> Result<Option<T>, CacheError> {
        // Always return None
        Ok(None)
    }

    async fn health_check(&self) -> Result<(), String> {
        // NullCache is always healthy as it doesn't interact with any external systems
        Ok(())
    }

    async fn delete(&self, _key: &str) -> Result<(), CacheError> {
        // Do nothing
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestData {
        field: String,
    }

    #[tokio::test]
    async fn test_null_cache_operations() {
        let cache = NullCache::new();

        let data = TestData {
            field: "test".to_string(),
        };

        // Test set (should do nothing)
        assert!(cache.set("test_key", &data).await.is_ok());

        // Test get (should always return None)
        let result: Option<TestData> = cache.get("test_key").await.unwrap();
        assert!(result.is_none());

        // Test delete (should do nothing)
        assert!(cache.delete("test_key").await.is_ok());
    }

    #[tokio::test]
    async fn test_health_check() {
        let cache = NullCache::new();
        let result = cache.health_check().await;
        assert!(result.is_ok(), "health check failed: {:?}", result);
    }
}
