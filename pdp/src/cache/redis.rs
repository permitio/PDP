use super::{CacheBackend, CacheError};
use async_trait::async_trait;
use log::error;
use redis::{aio::ConnectionManager, AsyncCommands, Client};
use serde::{de::DeserializeOwned, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const HEALTH_CHECK_INTERVAL_SECONDS: u64 = 10;

// TODO derive Debug - https://stackoverflow.com/questions/78870773/skip-struct-field-when-deriving-debug
#[derive(Clone)]
pub struct RedisCache {
    _client: Client,
    conn_manager: ConnectionManager,
    ttl_secs: u64,
    // Health status cache to avoid doing a Redis ping on every health check
    healthy: Arc<AtomicBool>,
    last_health_check: Arc<std::sync::Mutex<Instant>>,
}

impl RedisCache {
    /// Initialize a new Redis cache instance
    pub async fn new(redis_url: &str, ttl_secs: u64) -> Result<Self, String> {
        let client = match Client::open(redis_url) {
            Ok(client) => client,
            Err(err) => {
                return Err(format!("Failed to connect to Redis: {}", err));
            }
        };

        let conn_manager = match ConnectionManager::new(client.clone()).await {
            Ok(manager) => manager,
            Err(err) => {
                return Err(format!(
                    "Failed to create Redis connection manager: {}",
                    err
                ));
            }
        };

        // Test the connection to ensure it's working
        let mut conn = conn_manager.clone();
        if let Err(err) = redis::cmd("PING").query_async::<String>(&mut conn).await {
            return Err(format!("Failed to ping Redis: {}", err));
        }

        Ok(Self {
            conn_manager,
            ttl_secs,
            _client: client,
            healthy: Arc::new(AtomicBool::new(true)), // Initially assume healthy
            last_health_check: Arc::new(std::sync::Mutex::new(Instant::now())),
        })
    }

    // Updates the health status asynchronously without blocking
    async fn update_health_status(&self) {
        let mut conn = self.conn_manager.clone();
        let health_result = redis::cmd("PING").query_async::<String>(&mut conn).await;
        let is_healthy = health_result.is_ok();

        if !is_healthy {
            if let Err(err) = health_result {
                error!("Redis health check failed: {}", err);
            }
        }

        self.healthy.store(is_healthy, Ordering::Relaxed);

        // Update last health check time
        if let Ok(mut last_check) = self.last_health_check.lock() {
            *last_check = Instant::now();
        }
    }
}

#[async_trait]
impl CacheBackend for RedisCache {
    async fn set<T: Serialize + Send + Sync>(
        &self,
        key: &str,
        value: &T,
    ) -> Result<(), CacheError> {
        let serialized = serde_json::to_string(value)?;
        let mut conn = self.conn_manager.clone();

        match conn
            .set_ex::<_, _, ()>(key, serialized, self.ttl_secs)
            .await
        {
            Ok(_) => Ok(()),
            Err(err) => {
                // Mark as unhealthy on error
                self.healthy.store(false, Ordering::Relaxed);
                error!("Redis error while setting key {}: {}", key, err);
                Err(CacheError::RedisError(err.to_string()))
            }
        }
    }

    async fn get<T: DeserializeOwned + Send + Sync>(
        &self,
        key: &str,
    ) -> Result<Option<T>, CacheError> {
        let mut conn = self.conn_manager.clone();

        let result: Option<String> = match conn.get(key).await {
            Ok(value) => value,
            Err(err) => {
                if err.kind() == redis::ErrorKind::TypeError {
                    // Key doesn't exist
                    return Ok(None);
                }
                // Mark as unhealthy on error
                self.healthy.store(false, Ordering::Relaxed);
                error!("Redis error while getting key {}: {}", key, err);
                return Err(CacheError::RedisError(err.to_string()));
            }
        };

        if let Some(value) = result {
            serde_json::from_str(&value)
                .map_err(|e| CacheError::DeserializationError(e.to_string()))
                .map(Some)
        } else {
            Ok(None)
        }
    }

    fn health_check(&self) -> bool {
        // Check if we need to update the health status
        let should_check = {
            if let Ok(last_check) = self.last_health_check.lock() {
                last_check.elapsed() > Duration::from_secs(HEALTH_CHECK_INTERVAL_SECONDS)
            } else {
                // If we can't get the lock, assume we should check
                true
            }
        };

        // Spawn a task to update health status in the background if needed
        if should_check {
            let self_clone = self.clone();
            tokio::spawn(async move {
                self_clone.update_health_status().await;
            });
        }

        // Return the cached health status
        self.healthy.load(Ordering::Relaxed)
    }

    async fn delete(&self, key: &str) -> Result<(), CacheError> {
        let mut conn = self.conn_manager.clone();

        match conn.del::<_, ()>(key).await {
            Ok(_) => Ok(()),
            Err(err) => {
                // Mark as unhealthy on error
                self.healthy.store(false, Ordering::Relaxed);
                error!("Redis error while deleting key {}: {}", key, err);
                Err(CacheError::RedisError(err.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use redis_test::server::RedisServer;
    use serde::{Deserialize, Serialize};
    use std::time::Duration;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestData {
        field: String,
    }

    fn get_redis_url(server: &RedisServer) -> String {
        match &server.addr {
            redis::ConnectionAddr::Tcp(host, port) => {
                format!("redis://{}:{}/", host, port)
            }
            _ => format!("redis://127.0.0.1:6379/"),
        }
    }

    #[tokio::test]
    async fn test_redis_cache_operations() {
        // Start a Redis server for testing
        let server = RedisServer::new();
        let redis_url = get_redis_url(&server);

        // Initialize the cache with the test server
        let cache = RedisCache::new(&redis_url, 1).await.unwrap();

        let data = TestData {
            field: "test".to_string(),
        };

        // Test set and get
        cache.set("test_key", &data).await.unwrap();
        let retrieved: TestData = cache.get("test_key").await.unwrap().unwrap();
        assert_eq!(data, retrieved);

        // Test expiration
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(cache.get::<TestData>("test_key").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_redis_health_check() {
        // Start a Redis server for testing
        let server = RedisServer::new();
        let redis_url = get_redis_url(&server);

        // Initialize the cache with the test server
        let cache = RedisCache::new(&redis_url, 1).await.unwrap();

        // Test the health check - this should now be almost instant
        assert!(cache.health_check());

        // Also test the async health update
        cache.update_health_status().await;
        assert!(cache.health_check());
    }
}
