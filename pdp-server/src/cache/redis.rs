use super::circuit_breaker::{Admission, BreakerState, CircuitBreaker, Cooldowns};
use super::{CacheBackend, CacheError};
use async_trait::async_trait;
use redis::{aio::ConnectionManager, AsyncCommands, Client, Pipeline, RedisResult};
use serde::{de::DeserializeOwned, Serialize};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{timeout, Instant};

/// The longest a cache operation may wait on Redis. It matches the redis client's default
/// response timeout, which bounds a command on a live connection. This bound also covers a
/// command queued behind a reconnect, which the client otherwise lets wait through all of its
/// connection retries (six, each allowed one second to connect).
pub(crate) const OPERATION_TIMEOUT: Duration = Duration::from_millis(500);

/// One second after the first failure, so a brief interruption such as a failover or restart
/// costs about a second of cache misses. Doubling per failed probe to 30 seconds, so a long
/// outage costs one PING every 30 seconds and caching resumes within 30 seconds of recovery.
const COOLDOWNS: Cooldowns = Cooldowns {
    initial: Duration::from_secs(1),
    max: Duration::from_secs(30),
};

// TODO derive Debug - https://stackoverflow.com/questions/78870773/skip-struct-field-when-deriving-debug
#[derive(Clone)]
pub struct RedisCache {
    _client: Client,
    conn_manager: ConnectionManager,
    ttl_secs: u64,
    breaker: Arc<CircuitBreaker>,
}

impl RedisCache {
    /// Initialize a new Redis cache instance
    pub async fn new(redis_url: &str, ttl_secs: u64) -> Result<Self, String> {
        let client = match Client::open(redis_url) {
            Ok(client) => client,
            Err(err) => {
                return Err(format!("Failed to connect to Redis: {err}"));
            }
        };

        let conn_manager = match ConnectionManager::new(client.clone()).await {
            Ok(manager) => manager,
            Err(err) => {
                return Err(format!("Failed to create Redis connection manager: {err}"));
            }
        };

        // Test the connection to ensure it's working
        let mut conn = conn_manager.clone();
        if let Err(err) = redis::cmd("PING").query_async::<String>(&mut conn).await {
            return Err(format!("Failed to ping Redis: {err}"));
        }

        Ok(Self {
            conn_manager,
            ttl_secs,
            _client: client,
            breaker: Arc::new(CircuitBreaker::new(COOLDOWNS)),
        })
    }

    pub(crate) fn breaker_state(&self) -> BreakerState {
        self.breaker.state()
    }

    #[cfg(test)]
    pub(crate) fn breaker(&self) -> &CircuitBreaker {
        &self.breaker
    }

    /// Starts probes, skipping each cooldown, until one closes the breaker.
    ///
    /// # Panics
    ///
    /// Panics if the breaker has not closed after ten seconds.
    #[cfg(test)]
    pub(crate) async fn probe_until_closed(&self) {
        let probes = async {
            let mut states = self.breaker.subscribe();
            while self.breaker.state() != BreakerState::Closed {
                self.breaker.expire_cooldown();
                if self.redis_available() {
                    continue;
                }
                let probe_done = |state: &BreakerState| match state {
                    BreakerState::HalfOpen { cooldown: _ } => false,
                    BreakerState::Closed
                    | BreakerState::Open {
                        retry_at: _,
                        cooldown: _,
                    } => true,
                };
                let _ = states.wait_for(probe_done).await;
                // Lets the probe and the timeout below run even when nothing above waited.
                tokio::task::yield_now().await;
            }
        };
        let finished = timeout(Duration::from_secs(10), probes).await;
        assert!(
            finished.is_ok(),
            "breaker stuck at {:?}",
            self.breaker.state()
        );
    }

    /// Asks the breaker whether to use Redis now, starting the probe when one is due.
    fn redis_available(&self) -> bool {
        match self.breaker.admit(Instant::now()) {
            Admission::Allow => true,
            Admission::Skip => false,
            Admission::SkipAndProbe => {
                self.spawn_probe();
                false
            }
        }
    }

    /// Runs one Redis command within [`OPERATION_TIMEOUT`], reporting a failure to the breaker.
    async fn execute<T>(
        &self,
        command: impl Future<Output = RedisResult<T>>,
    ) -> Result<T, CacheError> {
        let error = match timeout(OPERATION_TIMEOUT, command).await {
            Ok(Ok(value)) => return Ok(value),
            Ok(Err(err)) => err.to_string(),
            Err(_) => format!("no reply within {OPERATION_TIMEOUT:?}"),
        };
        self.breaker.record_failure(Instant::now(), &error);
        Err(CacheError::Redis(error))
    }

    fn spawn_probe(&self) {
        let cache = self.clone();
        tokio::spawn(async move {
            let mut conn = cache.conn_manager.clone();
            let ping = conn.ping::<String>();
            match timeout(OPERATION_TIMEOUT, ping).await {
                Ok(Ok(_)) => cache.breaker.record_probe_success(),
                Ok(Err(err)) => cache.breaker.record_probe_failure(Instant::now(), &err),
                Err(_) => {
                    let error = format!("no reply within {OPERATION_TIMEOUT:?}");
                    cache.breaker.record_probe_failure(Instant::now(), &error);
                }
            }
        });
    }

    /// Sends `pipeline` in the background, so a slow or unreachable Redis never holds up the
    /// response that produced the values. Skipped while the breaker is open.
    fn spawn_write(&self, pipeline: Pipeline) -> Result<(), CacheError> {
        if !self.redis_available() {
            return Err(CacheError::Unavailable);
        }
        let cache = self.clone();
        tokio::spawn(async move {
            let mut conn = cache.conn_manager.clone();
            // A failure has already reached the breaker, which logs the outage.
            let _ = cache.execute(pipeline.exec_async(&mut conn)).await;
        });
        Ok(())
    }
}

fn decode<T: DeserializeOwned>(value: &str) -> Result<T, CacheError> {
    serde_json::from_str(value).map_err(|e| CacheError::Deserialization(e.to_string()))
}

#[async_trait]
impl CacheBackend for RedisCache {
    async fn set<T: Serialize + Send + Sync>(
        &self,
        key: &str,
        value: &T,
    ) -> Result<(), CacheError> {
        self.set_many(&[(key, value)]).await
    }

    async fn get<T: DeserializeOwned + Send + Sync>(
        &self,
        key: &str,
    ) -> Result<Option<T>, CacheError> {
        if !self.redis_available() {
            return Err(CacheError::Unavailable);
        }
        let mut conn = self.conn_manager.clone();
        let value: Option<String> = self.execute(conn.get(key)).await?;
        match value {
            Some(value) => decode(&value).map(Some),
            None => Ok(None),
        }
    }

    async fn get_many<T: DeserializeOwned + Send + Sync>(
        &self,
        keys: &[String],
    ) -> Result<Vec<Option<T>>, CacheError> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        if !self.redis_available() {
            return Err(CacheError::Unavailable);
        }
        let mut conn = self.conn_manager.clone();
        let values: Vec<Option<String>> = self.execute(conn.mget(keys)).await?;
        if values.len() != keys.len() {
            return Err(CacheError::Redis(format!(
                "MGET returned {} values for {} keys",
                values.len(),
                keys.len()
            )));
        }
        let mut decoded = Vec::with_capacity(values.len());
        for value in values {
            decoded.push(match value {
                Some(value) => Some(decode(&value)?),
                None => None,
            });
        }
        Ok(decoded)
    }

    async fn set_many<T: Serialize + Send + Sync>(
        &self,
        entries: &[(&str, &T)],
    ) -> Result<(), CacheError> {
        if entries.is_empty() {
            return Ok(());
        }
        let mut pipeline = redis::pipe();
        for (key, value) in entries {
            let serialized = serde_json::to_string(value)?;
            pipeline.set_ex(*key, serialized, self.ttl_secs).ignore();
        }
        self.spawn_write(pipeline)
    }

    async fn health_check(&self) -> Result<(), String> {
        let mut conn = self.conn_manager.clone();
        let ping = conn.ping::<String>();
        match self.execute(ping).await {
            Ok(_) => Ok(()),
            Err(err) => Err(format!("Redis health check failed: {err}")),
        }
    }

    async fn delete(&self, key: &str) -> Result<(), CacheError> {
        if !self.redis_available() {
            return Err(CacheError::Unavailable);
        }
        let mut conn = self.conn_manager.clone();
        self.execute(conn.del::<_, ()>(key)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::fake_redis::{FakeRedis, Mode};
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
                format!("redis://{host}:{port}/")
            }
            _ => "redis://127.0.0.1:6379/".to_string(),
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

        // Test set and get. The write is sent in the background, so wait for it to land.
        cache.set("test_key", &data).await.unwrap();
        let mut retrieved = None;
        for _ in 0..100 {
            retrieved = cache.get::<TestData>("test_key").await.unwrap();
            if retrieved.is_some() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(retrieved, Some(data));

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
        assert!(result.is_ok(), "health check failed: {result:?}");
    }

    fn data(field: &str) -> TestData {
        TestData {
            field: field.to_string(),
        }
    }

    /// Waits until the breaker reaches a state that `done` accepts.
    async fn wait_for_breaker(cache: &RedisCache, done: impl FnMut(&BreakerState) -> bool) {
        let mut states = cache.breaker().subscribe();
        let waited = tokio::time::timeout(Duration::from_secs(5), states.wait_for(done)).await;
        assert!(
            matches!(waited, Ok(Ok(_))),
            "breaker stuck at {:?}",
            cache.breaker_state()
        );
    }

    /// Pauses `redis`, makes one lookup fail, and checks that the breaker opened.
    async fn trip_breaker(redis: &FakeRedis, cache: &RedisCache) {
        redis.set_mode(Mode::Paused);
        let lookup = cache.get::<TestData>("k1").await;
        assert!(matches!(lookup, Err(CacheError::Redis(_))), "{lookup:?}");
        assert_eq!(cache.breaker_state().name(), "open");
    }

    #[tokio::test]
    async fn test_get_many_reads_a_batch_with_one_mget() {
        let redis = FakeRedis::start().await;
        let cache = RedisCache::new(&redis.url(), 60).await.unwrap();
        let (a, c) = (data("a"), data("c"));
        cache.set_many(&[("k1", &a), ("k3", &c)]).await.unwrap();
        redis.wait_for_commands("SETEX", 2).await;

        let keys = ["k1", "k2", "k3"].map(String::from);
        let values = cache.get_many::<TestData>(&keys).await.unwrap();

        assert_eq!(values, [Some(a), None, Some(c)]);
        assert_eq!(redis.command_count("MGET"), 1);
        assert_eq!(redis.command_count("GET"), 0);
    }

    #[tokio::test]
    async fn test_empty_batches_send_nothing() {
        let redis = FakeRedis::start().await;
        let cache = RedisCache::new(&redis.url(), 60).await.unwrap();
        let commands_after_connect = redis.total_commands();

        assert!(cache.get_many::<TestData>(&[]).await.unwrap().is_empty());
        cache.set_many::<TestData>(&[]).await.unwrap();

        assert_eq!(redis.total_commands(), commands_after_connect);
    }

    #[tokio::test]
    async fn test_a_write_returns_before_redis_answers() {
        let redis = FakeRedis::start().await;
        let cache = RedisCache::new(&redis.url(), 60).await.unwrap();
        redis.set_mode(Mode::Paused);

        // Redis holds the write, yet set returns without waiting for it.
        let value = data("a");
        let write = tokio::time::timeout(OPERATION_TIMEOUT / 5, cache.set("k1", &value));
        assert!(matches!(write.await, Ok(Ok(()))));

        // The unanswered write still counts as a failure, and opens the breaker.
        wait_for_breaker(&cache, |state| state.name() == "open").await;
    }

    #[tokio::test]
    async fn test_open_breaker_skips_redis() {
        let redis = FakeRedis::start().await;
        let cache = RedisCache::new(&redis.url(), 60).await.unwrap();
        trip_breaker(&redis, &cache).await;
        let commands_when_opened = redis.total_commands();

        let keys = ["k1".to_string()];
        assert!(matches!(
            cache.get::<TestData>("k1").await,
            Err(CacheError::Unavailable)
        ));
        assert!(matches!(
            cache.get_many::<TestData>(&keys).await,
            Err(CacheError::Unavailable)
        ));
        assert!(matches!(
            cache.set("k1", &data("a")).await,
            Err(CacheError::Unavailable)
        ));
        assert!(matches!(
            cache.delete("k1").await,
            Err(CacheError::Unavailable)
        ));
        assert_eq!(redis.total_commands(), commands_when_opened);
    }

    #[tokio::test]
    async fn test_breaker_reopens_on_a_failed_probe_and_closes_after_recovery() {
        let redis = FakeRedis::start().await;
        let cache = RedisCache::new(&redis.url(), 60).await.unwrap();
        trip_breaker(&redis, &cache).await;

        // Redis is still paused: the probe fails and the cooldown doubles.
        cache.breaker().expire_cooldown();
        assert!(matches!(
            cache.get::<TestData>("k1").await,
            Err(CacheError::Unavailable)
        ));
        assert_eq!(cache.breaker_state().name(), "half_open");
        wait_for_breaker(&cache, |state| state.name() == "open").await;
        let BreakerState::Open {
            retry_at: _,
            cooldown,
        } = cache.breaker_state()
        else {
            panic!("expected an open breaker");
        };
        assert_eq!(cooldown, COOLDOWNS.initial * 2);

        // Redis is back: a probe closes the breaker, and operations reach Redis again.
        redis.set_mode(Mode::Serving);
        cache.probe_until_closed().await;
        cache.set("k1", &data("a")).await.unwrap();
        redis.wait_for_commands("SETEX", 1).await;
        assert_eq!(cache.get::<TestData>("k1").await.unwrap(), Some(data("a")));
    }

    #[tokio::test]
    async fn test_a_command_that_never_answers_fails_at_the_operation_timeout() {
        let redis = FakeRedis::start().await;
        let cache = RedisCache::new(&redis.url(), 60).await.unwrap();
        // A command queued behind a reconnect waits on the connection, which the client's own
        // response timeout does not bound. A future that never completes stands in for it.
        tokio::time::pause();
        let started = Instant::now();

        let stuck = cache.execute(std::future::pending::<RedisResult<()>>());
        let outcome = timeout(OPERATION_TIMEOUT * 10, stuck).await;

        assert!(
            matches!(outcome, Ok(Err(CacheError::Redis(_)))),
            "{outcome:?}"
        );
        let waited = started.elapsed();
        assert!(
            waited >= OPERATION_TIMEOUT && waited < OPERATION_TIMEOUT * 2,
            "{waited:?}"
        );
        assert_eq!(cache.breaker_state().name(), "open");
    }

    #[tokio::test]
    async fn test_stopped_redis_opens_the_breaker() {
        let redis = FakeRedis::start().await;
        let cache = RedisCache::new(&redis.url(), 60).await.unwrap();
        redis.set_mode(Mode::Stopped);

        let lookup = cache.get::<TestData>("k1").await;

        assert!(matches!(lookup, Err(CacheError::Redis(_))), "{lookup:?}");
        assert_eq!(cache.breaker_state().name(), "open");
    }

    #[tokio::test]
    async fn test_failed_health_check_opens_the_breaker() {
        let redis = FakeRedis::start().await;
        let cache = RedisCache::new(&redis.url(), 60).await.unwrap();
        assert!(cache.health_check().await.is_ok());
        redis.set_mode(Mode::Paused);

        assert!(cache.health_check().await.is_err());
        assert_eq!(cache.breaker_state().name(), "open");
    }
}
