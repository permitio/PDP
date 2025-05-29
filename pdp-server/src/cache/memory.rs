use super::{CacheBackend, CacheError};
use async_trait::async_trait;
use moka::future::Cache as MokaCache;
use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration;

#[derive(Clone)]
pub struct InMemoryCache {
    cache: MokaCache<String, String>,
    _ttl_secs: u64,
}

impl InMemoryCache {
    /// Initialize a new in-memory cache instance
    pub fn new(ttl_secs: u64, capacity_mib: usize) -> Result<Self, String> {
        // Convert MiB to bytes for max_capacity (1 MiB = 1024 * 1024 bytes)
        let max_capacity_bytes: u64 = (capacity_mib * 1024 * 1024)
            .try_into()
            .expect("Capacity overflow");

        let cache = MokaCache::builder()
            .time_to_live(Duration::from_secs(ttl_secs))
            .weigher(|_key, value: &String| -> u32 {
                //let size = size_of_val(&*value.data) as u32;
                value.len().try_into().unwrap_or(u32::MAX)
            })
            .max_capacity(max_capacity_bytes)
            .build();

        Ok(Self {
            cache,
            _ttl_secs: ttl_secs,
        })
    }
}

#[async_trait]
impl CacheBackend for InMemoryCache {
    async fn set<T: Serialize + Send + Sync>(
        &self,
        key: &str,
        value: &T,
    ) -> Result<(), CacheError> {
        let serialized = serde_json::to_string(value)?;
        self.cache.insert(key.to_string(), serialized).await;
        Ok(())
    }

    async fn get<T: DeserializeOwned + Send + Sync>(
        &self,
        key: &str,
    ) -> Result<Option<T>, CacheError> {
        if let Some(value) = self.cache.get(key).await {
            serde_json::from_str(&value)
                .map_err(|e| CacheError::Deserialization(e.to_string()))
                .map(Some)
        } else {
            Ok(None)
        }
    }

    async fn health_check(&self) -> Result<(), String> {
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), CacheError> {
        self.cache.remove(key).await;
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
    async fn test_cache_operations() {
        let cache = InMemoryCache::new(1, 128).unwrap();

        let data = TestData {
            field: "test".to_string(),
        };

        // Test set and get
        cache.set("test_key", &data).await.unwrap();
        let retrieved: TestData = cache.get("test_key").await.unwrap().unwrap();
        assert_eq!(data, retrieved);

        // Test expiration
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        assert!(cache.get::<TestData>("test_key").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_health_check() {
        let cache = InMemoryCache::new(1, 128).unwrap();
        let result = cache.health_check().await;
        assert!(result.is_ok(), "health check failed: {:?}", result);
    }

    #[tokio::test]
    async fn test_capacity_limit() {
        // Create a cache with a very small capacity (1 MiB) for testing
        let cache = InMemoryCache::new(60, 1).unwrap();

        // Make the data larger to ensure we exceed capacity
        // 300 KiB string * 10 entries = 3 MiB total (exceeds 1 MiB limit)
        let data = "x".repeat(1024 * 300);

        // Insert entries to fill the cache beyond capacity
        for i in 0..10 {
            let key = format!("key_{}", i);
            cache.set(&key, &data).await.unwrap();
            // Sleep for 100ms to allow moka to process the insertion
            // and the eviction to happen
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        // sleep to let moka do its eviction maintenance
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Verify that at least some items were evicted due to capacity limits
        let mut found_items = 0;
        for i in 0..10 {
            let key = format!("key_{}", i);
            if cache.get::<String>(&key).await.unwrap().is_some() {
                found_items += 1;
            }
        }

        // With a 1 MiB cache and entries totaling more than 1 MiB,
        // we expect some items to be evicted, but we can't guarantee exactly how many
        assert!(
            found_items < 10,
            "Expected some items to be evicted, but found {} items",
            found_items
        );
    }
}
