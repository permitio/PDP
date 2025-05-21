use super::{CacheBackend, CacheError};
use async_trait::async_trait;
use log::error;
use redis::{aio::ConnectionManager, AsyncCommands, Client};
use serde::{de::DeserializeOwned, Serialize};

// TODO derive Debug - https://stackoverflow.com/questions/78870773/skip-struct-field-when-deriving-debug
#[derive(Clone)]
pub struct RedisCache {
    _client: Client,
    conn_manager: ConnectionManager,
    ttl_secs: u64,
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
        })
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
                error!("Redis error while setting key {}: {}", key, err);
                Err(CacheError::Redis(err.to_string()))
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
                error!("Redis error while getting key {}: {}", key, err);
                return Err(CacheError::Redis(err.to_string()));
            }
        };

        if let Some(value) = result {
            serde_json::from_str(&value)
                .map_err(|e| CacheError::Deserialization(e.to_string()))
                .map(Some)
        } else {
            Ok(None)
        }
    }

    async fn health_check(&self) -> Result<(), String> {
        let mut conn = self.conn_manager.clone();
        match redis::cmd("PING").query_async::<String>(&mut conn).await {
            Ok(_) => Ok(()),
            Err(err) => Err(format!("Redis health check failed: {}", err)),
        }
    }

    async fn delete(&self, key: &str) -> Result<(), CacheError> {
        let mut conn = self.conn_manager.clone();

        match conn.del::<_, ()>(key).await {
            Ok(_) => Ok(()),
            Err(err) => {
                error!("Redis error while deleting key {}: {}", key, err);
                Err(CacheError::Redis(err.to_string()))
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
    #[ignore]
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
    #[ignore]
    async fn test_redis_health_check() {
        // Arrange
        let server = RedisServer::new();
        let redis_url = get_redis_url(&server);
        let cache = RedisCache::new(&redis_url, 1).await.unwrap();

        // Act
        let result = cache.health_check().await;

        // Assert
        assert!(result.is_ok(), "health check failed: {:?}", result);
    }
}
