use crate::{
    cache::{Cache, CacheBackend, create_cache},
    config::{Settings, default_legacy_fallback_host, default_legacy_fallback_port},
};
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{HeaderMap, HeaderValue};
use pdp_engine::{Arg, EngineType, MockEngine, PDPEngine, PDPEngineBuilder};
use reqwest::Client;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

#[derive(Clone)]
pub struct AppState {
    pub settings: Arc<Settings>,
    pub cache: Arc<Cache>,
    pub engine: Arc<EngineType>,
    pub opa_client: Arc<Client>,
}

impl AppState {
    fn create_opa_client(token: String, timeout: u64) -> reqwest::Client {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            format!("Bearer {}", token)
                .parse()
                .expect("Failed to parse API token"),
        );
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        // Create a specialized client for OPA with appropriate configurations
        Client::builder()
            // Set reasonable timeouts
            .timeout(Duration::from_secs(timeout)) // 5 seconds timeout for requests
            .connect_timeout(Duration::from_secs(2)) // 2 seconds timeout for connections
            .default_headers(headers)
            // Configure connection pool
            .pool_max_idle_per_host(10) // Keep up to 10 idle connections per host
            .pool_idle_timeout(Some(Duration::from_secs(90))) // Keep idle connections for 90 seconds
            // Build the client
            .build()
            .expect("Failed to create OPA client")
    }

    pub async fn new(settings: Settings) -> Result<Self, std::io::Error> {
        let state = Self {
            settings: Arc::new(settings.clone()),
            cache: Arc::new(create_cache(&settings).await.map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to create cache: {}", e),
                )
            })?),
            engine: Arc::new(EngineType::Mock(MockEngine::new(
                Url::parse(&settings.legacy_fallback_url).unwrap(),
                settings.api_key.clone(),
            ))),
            opa_client: Arc::new(AppState::create_opa_client(
                settings.api_key,
                settings.opa_client_query_timeout,
            )),
        };
        Ok(state)
    }

    pub async fn new_python_based(
        settings: Settings,
        cache: Cache,
    ) -> Result<Self, std::io::Error> {
        let state = Self {
            settings: Arc::new(settings.clone()),
            cache: Arc::new(cache),
            engine: Arc::new(AppState::init_python_engine(settings.clone()).await?),
            opa_client: Arc::new(AppState::create_opa_client(
                settings.api_key,
                settings.opa_client_query_timeout,
            )),
        };
        Ok(state)
    }

    /// Initialize the PDPEngine
    async fn init_python_engine(settings: Settings) -> Result<EngineType, std::io::Error> {
        // Parse legacy server URL for host and port
        let legacy_url = Url::parse(&settings.legacy_fallback_url).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid legacy fallback URL: {}", e),
            )
        })?;

        let legacy_host = legacy_url
            .host_str()
            .unwrap_or(&default_legacy_fallback_host())
            .to_string();
        let legacy_port = legacy_url
            .port()
            .unwrap_or_else(default_legacy_fallback_port);

        // Create PDP Engine builder
        let builder = PDPEngineBuilder::new()
            // Set Python path to use the system python
            .with_located_python()
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to set Python path: {}", e),
                )
            })?
            // Set PDP directory to the current directory
            .with_cwd_as_pdp_dir()
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to set PDP directory: {}", e),
                )
            })?
            .with_base_url(&settings.legacy_fallback_url)
            .with_args(vec![
                Arg::Module("uvicorn".to_string()),
                Arg::App("horizon.main:app".to_string()),
                Arg::Host(legacy_host),
                Arg::Port(legacy_port),
            ])
            .with_health_timeout(Duration::from_secs(120));

        // Start the PDP engine
        match builder.start().await {
            Ok(engine) => Ok(EngineType::Python(engine)),
            Err(e) => {
                log::error!("Failed to start PDPEngine: {}", e);
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to start PDPEngine: {}", e),
                ))
            }
        }
    }

    /// Stop the PDPEngine
    pub async fn stop_engine(&self) -> i32 {
        // Clone the Arc first, then get a reference to the inner value
        let engine = Arc::clone(&self.engine);
        match (*engine).clone().stop().await {
            Ok(()) => 0,
            Err(e) => {
                log::error!("Failed to stop PDPEngine: {}", e);
                1
            }
        }
    }

    /// Check if all components are healthy
    pub async fn health_check(&self) -> bool {
        let is_cache_healthy = self.cache.health_check();
        let is_engine_healthy = self.engine.health().await;
        is_cache_healthy && is_engine_healthy
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::cache::null::NullCache;
    use crate::config::{CacheConfig, CacheStore, InMemoryCacheConfig, RedisCacheConfig};
    use pdp_engine::MockEngine;
    use std::sync::Arc as StdArc;
    use tokio::sync::Mutex;

    pub(crate) fn create_test_state(settings: Settings) -> AppState {
        AppState {
            settings: Arc::new(settings.clone()),
            cache: Arc::new(Cache::Null(NullCache::new())),
            engine: Arc::new(EngineType::Mock(MockEngine::new(
                Url::parse(&settings.legacy_fallback_url).unwrap(),
                settings.api_key.clone(),
            ))),
            opa_client: Arc::new(AppState::create_opa_client(
                settings.api_key,
                settings.opa_client_query_timeout,
            )),
        }
    }

    #[tokio::test]
    async fn test_app_state_new() {
        let settings = Settings {
            legacy_fallback_url: "http://test".to_string(),
            opa_url: "http://localhost:8181".to_string(),
            port: 3000,
            opa_client_query_timeout: 5,
            cache: CacheConfig {
                ttl_secs: 60,
                store: CacheStore::InMemory,
                in_memory: InMemoryCacheConfig { capacity_mib: 128 },
                redis: RedisCacheConfig::default(),
            },
            api_key: "test-api-key".to_string(),
            debug: None,
            use_new_authorized_users: false,
        };

        let state = create_test_state(settings.clone());

        assert_eq!(
            state.settings.legacy_fallback_url,
            settings.legacy_fallback_url
        );
        assert_eq!(state.settings.cache.ttl_secs, settings.cache.ttl_secs);
        assert_eq!(state.settings.port, settings.port);
    }

    #[tokio::test]
    async fn test_app_state_thread_safety() {
        let settings = Settings {
            legacy_fallback_url: "http://test".to_string(),
            opa_url: "http://localhost:8181".to_string(),
            port: 3000,
            opa_client_query_timeout: 5,
            cache: CacheConfig {
                ttl_secs: 60,
                store: CacheStore::InMemory,
                in_memory: InMemoryCacheConfig { capacity_mib: 128 },
                redis: RedisCacheConfig::default(),
            },
            api_key: "test-api-key".to_string(),
            debug: None,
            use_new_authorized_users: false,
        };

        let state = create_test_state(settings);
        let state = StdArc::new(Mutex::new(state));

        let mut handles = vec![];

        // Spawn multiple tasks that try to access the state concurrently
        for _i in 0..10 {
            let state = state.clone();
            handles.push(tokio::spawn(async move {
                let state = state.lock().await;
                state.settings.cache.ttl_secs == 60
            }));
        }

        // Make sure all tasks complete successfully
        for handle in handles {
            assert!(handle.await.unwrap());
        }
    }

    #[test]
    fn test_app_state_clone() {
        let settings = Settings {
            legacy_fallback_url: "http://test".to_string(),
            opa_url: "http://localhost:8181".to_string(),
            port: 3000,
            opa_client_query_timeout: 5,
            cache: CacheConfig {
                ttl_secs: 60,
                store: CacheStore::InMemory,
                in_memory: InMemoryCacheConfig { capacity_mib: 128 },
                redis: RedisCacheConfig::default(),
            },
            api_key: "test-api-key".to_string(),
            debug: None,
            use_new_authorized_users: false,
        };

        let state = create_test_state(settings);
        let state2 = state.clone();

        // After cloning, both instances should point to the same data
        assert_eq!(Arc::as_ptr(&state.settings), Arc::as_ptr(&state2.settings));
        assert_eq!(Arc::as_ptr(&state.cache), Arc::as_ptr(&state2.cache));
    }
}
