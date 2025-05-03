use crate::{
    cache::{create_cache, Cache, CacheBackend},
    config::Settings,
};
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{HeaderMap, HeaderValue};
use reqwest::Client;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;
use watchdog::{
    CommandWatchdogOptions, HttpHealthChecker, ServiceWatchdog, ServiceWatchdogOptions,
};

/// Represents the application state containing shared resources and configurations
#[derive(Clone)]
pub struct AppState {
    pub settings: Arc<Settings>,
    pub cache: Arc<Cache>,
    pub watchdog: Option<Arc<ServiceWatchdog>>,
    pub opa_client: Arc<Client>,
    pub horizon_client: Arc<Client>,
}

impl AppState {
    /// Create a new application state with all components initialized
    pub async fn new(settings: &Settings) -> Result<Self, std::io::Error> {
        let watchdog = Self::setup_horizon_watchdog(settings).await;
        let cache = Arc::new(create_cache(settings).await.map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to create cache: {}", e),
            )
        })?);

        Ok(Self {
            settings: Arc::new(settings.clone()),
            cache,
            watchdog: Some(Arc::new(watchdog)),
            opa_client: Arc::new(create_http_client(
                settings.api_key.clone(),
                settings.opa_client_query_timeout,
            )),
            horizon_client: Arc::new(create_http_client(
                settings.api_key.clone(),
                settings.horizon_client_timeout,
            )),
        })
    }

    /// Create a new application state with a pre-initialized cache
    pub async fn with_existing_cache(
        settings: &Settings,
        cache: Cache,
    ) -> Result<Self, std::io::Error> {
        let watchdog = Self::setup_horizon_watchdog(settings).await;

        Ok(Self {
            settings: Arc::new(settings.clone()),
            cache: Arc::new(cache),
            watchdog: Some(Arc::new(watchdog)),
            opa_client: Arc::new(create_http_client(
                settings.api_key.clone(),
                settings.opa_client_query_timeout,
            )),
            horizon_client: Arc::new(create_http_client(
                settings.api_key.clone(),
                settings.horizon_client_timeout,
            )),
        })
    }

    /// Create a minimal state for testing without watchdogs or real services
    #[cfg(test)]
    pub fn for_testing(settings: &Settings) -> Self {
        Self {
            settings: Arc::new(settings.clone()),
            cache: Arc::new(Cache::Null(crate::cache::null::NullCache::new())),
            watchdog: None,
            opa_client: Arc::new(create_http_client(
                settings.api_key.clone(),
                settings.opa_client_query_timeout,
            )),
            horizon_client: Arc::new(create_http_client(
                settings.api_key.clone(),
                settings.horizon_client_timeout,
            )),
        }
    }

    /// Check if all components are healthy
    pub async fn health_check(&self) -> bool {
        let is_cache_healthy = self.cache.health_check();
        let is_watchdog_healthy = match &self.watchdog {
            Some(watchdog) => watchdog.is_healthy(),
            None => true, // If no watchdog is running (e.g. in tests), consider it healthy
        };
        is_cache_healthy && is_watchdog_healthy
    }

    /// Set up and initialize the Horizon service watchdog
    async fn setup_horizon_watchdog(settings: &Settings) -> ServiceWatchdog {
        let mut command = Command::new(&settings.python_path);

        // First, check if /app/horizon exists (Docker container case)
        if Path::new("/app/horizon").exists() {
            command.current_dir("/app");
        } else {
            // Use the original relative path for development
            command.current_dir("../horizon");
        }

        command.arg("-m");
        command.arg("uvicorn");
        command.arg("horizon.main:app");
        command.arg("--host");
        command.arg(&settings.horizon_host);
        command.arg("--port");
        command.arg(settings.horizon_port.to_string());

        let health_endpoint = format!(
            "http://{}:{}/healthy",
            settings.horizon_host, settings.horizon_port,
        );
        let health_checker = HttpHealthChecker::with_options(
            health_endpoint,
            200,
            Duration::from_secs(1), // TODO: Expose via settings
        );

        let options = ServiceWatchdogOptions {
            health_check_interval: Duration::from_secs(5), // TODO: Expose via settings
            health_check_failure_threshold: 12,            // TODO: Expose via settings
            initial_startup_delay: Duration::from_secs(5), // TODO: Expose via settings
            command_options: CommandWatchdogOptions {
                restart_interval: Duration::from_secs(1), // TODO: Expose via settings
                termination_timeout: Duration::from_secs(30), // TODO: Expose via settings
            },
        };

        ServiceWatchdog::start_with_opt(command, health_checker, options)
    }
}

/// Creates a configured HTTP client with default headers and timeouts
fn create_http_client(token: String, timeout_secs: u64) -> Client {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        format!("Bearer {}", token)
            .parse()
            .expect("Failed to parse API token"),
    );
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    // Create a client with appropriate configurations
    Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .connect_timeout(Duration::from_secs(5))
        .default_headers(headers)
        .pool_max_idle_per_host(10)
        .pool_idle_timeout(Some(Duration::from_secs(90)))
        .build()
        .expect("Failed to create HTTP client")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CacheConfig, CacheStore, InMemoryCacheConfig, RedisCacheConfig};
    use std::sync::Arc as StdArc;
    use tokio::sync::Mutex;

    fn create_test_settings() -> Settings {
        Settings {
            horizon_host: "localhost".to_string(),
            horizon_port: 3000,
            python_path: "python3".to_string(),
            opa_url: "http://localhost:8181".to_string(),
            port: 3000,
            opa_client_query_timeout: 5,
            horizon_client_timeout: 60,
            cache: CacheConfig {
                ttl_secs: 60,
                store: CacheStore::InMemory,
                in_memory: InMemoryCacheConfig { capacity_mib: 128 },
                redis: RedisCacheConfig::default(),
            },
            api_key: "test-api-key".to_string(),
            debug: None,
            use_new_authorized_users: false,
        }
    }

    #[tokio::test]
    async fn test_app_state_creation() {
        let settings = create_test_settings();
        let state = AppState::for_testing(&settings);

        assert_eq!(state.settings.horizon_host, settings.horizon_host);
        assert_eq!(state.settings.horizon_port, settings.horizon_port);
        assert_eq!(state.settings.cache.ttl_secs, settings.cache.ttl_secs);
        assert_eq!(state.settings.port, settings.port);
    }

    #[tokio::test]
    async fn test_app_state_thread_safety() {
        let settings = create_test_settings();
        let state = AppState::for_testing(&settings);
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
        let settings = create_test_settings();
        let state = AppState::for_testing(&settings);
        let state2 = state.clone();

        // After cloning, both instances should point to the same data
        assert_eq!(Arc::as_ptr(&state.settings), Arc::as_ptr(&state2.settings));
        assert_eq!(Arc::as_ptr(&state.cache), Arc::as_ptr(&state2.cache));
    }
}
