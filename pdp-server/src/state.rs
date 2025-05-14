use crate::{
    cache::{create_cache, Cache, CacheBackend},
    config::PDPConfig,
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
    pub config: Arc<PDPConfig>,
    pub cache: Arc<Cache>,
    pub watchdog: Option<Arc<ServiceWatchdog>>,
    pub opa_client: Arc<Client>,
    pub horizon_client: Arc<Client>,
}

impl AppState {
    /// Create a new application state with all components initialized
    pub async fn new(config: &PDPConfig) -> Result<Self, std::io::Error> {
        let watchdog = Self::setup_horizon_watchdog(config).await;
        let cache = Arc::new(create_cache(config).await.map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to create cache: {}", e),
            )
        })?);

        Ok(Self {
            config: Arc::new(config.clone()),
            cache,
            watchdog: Some(Arc::new(watchdog)),
            opa_client: Arc::new(create_http_client(
                config.api_key.clone(),
                config.opa.client_query_timeout,
            )),
            horizon_client: Arc::new(create_http_client(
                config.api_key.clone(),
                config.horizon.client_timeout,
            )),
        })
    }

    /// Create a new application state with a pre-initialized cache
    pub async fn with_existing_cache(
        config: &PDPConfig,
        cache: Cache,
    ) -> Result<Self, std::io::Error> {
        let watchdog = Self::setup_horizon_watchdog(config).await;

        Ok(Self {
            config: Arc::new(config.clone()),
            cache: Arc::new(cache),
            watchdog: Some(Arc::new(watchdog)),
            opa_client: Arc::new(create_http_client(
                config.api_key.clone(),
                config.opa.client_query_timeout,
            )),
            horizon_client: Arc::new(create_http_client(
                config.api_key.clone(),
                config.horizon.client_timeout,
            )),
        })
    }

    /// Create a minimal state for testing without watchdogs or real services
    #[cfg(test)]
    pub fn for_testing(config: &PDPConfig) -> Self {
        Self {
            config: Arc::new(config.clone()),
            cache: Arc::new(Cache::Null(crate::cache::null::NullCache::new())),
            watchdog: None,
            opa_client: Arc::new(create_http_client(
                config.api_key.clone(),
                config.opa.client_query_timeout,
            )),
            horizon_client: Arc::new(create_http_client(
                config.api_key.clone(),
                config.horizon.client_timeout,
            )),
        }
    }

    /// Set up and initialize the Horizon service watchdog
    async fn setup_horizon_watchdog(config: &PDPConfig) -> ServiceWatchdog {
        let mut command = Command::new(&config.horizon.python_path);

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
        command.arg(&config.horizon.host);
        command.arg("--port");
        command.arg(config.horizon.port.to_string());

        let health_endpoint = format!(
            "http://{}:{}/healthy",
            config.horizon.host, config.horizon.port,
        );
        let health_checker = HttpHealthChecker::with_options(
            health_endpoint,
            200,
            Duration::from_secs(config.horizon.health_check_timeout),
        );

        let options = ServiceWatchdogOptions {
            health_check_interval: Duration::from_secs(config.horizon.health_check_interval),
            health_check_failure_threshold: config.horizon.health_check_failure_threshold,
            initial_startup_delay: Duration::from_secs(config.horizon.startup_delay),
            command_options: CommandWatchdogOptions {
                restart_interval: Duration::from_secs(config.horizon.restart_interval),
                termination_timeout: Duration::from_secs(config.horizon.termination_timeout),
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
    use crate::config::cache::{InMemoryConfig, RedisConfig};
    use crate::config::{CacheConfig, CacheStore};

    fn create_test_config() -> PDPConfig {
        PDPConfig {
            api_key: "test-api-key".to_string(),
            debug: Some(true),
            port: 3000,
            use_new_authorized_users: false,
            horizon: crate::config::horizon::HorizonConfig {
                host: "localhost".to_string(),
                port: 3000,
                python_path: "python3".to_string(),
                client_timeout: 60,
                health_check_timeout: 1,
                health_check_interval: 5,
                health_check_failure_threshold: 12,
                startup_delay: 5,
                restart_interval: 1,
                termination_timeout: 30,
            },
            opa: crate::config::opa::OpaConfig {
                url: "http://localhost:8181".to_string(),
                client_query_timeout: 5,
            },
            cache: CacheConfig {
                ttl: 60,
                store: CacheStore::InMemory,
                memory: InMemoryConfig { capacity: 128 },
                redis: RedisConfig::default(),
            },
        }
    }

    #[tokio::test]
    async fn test_app_state_creation() {
        let config = create_test_config();
        let state = AppState::for_testing(&config);

        // Verify that state was created correctly
        assert!(state.cache.health_check().await.is_ok());
        assert!(state.watchdog.is_none()); // No watchdog in test mode
    }

    #[tokio::test]
    async fn test_app_state_thread_safety() {
        let config = create_test_config();
        let state = AppState::for_testing(&config);
        let state_arc = Arc::new(state);
        let mutex = Arc::new(tokio::sync::Mutex::new(0));

        // Spawn multiple tasks to access the state concurrently
        let handles: Vec<_> = (0..10)
            .map(|_| {
                let state_clone = state_arc.clone();
                let mutex_clone = mutex.clone();
                tokio::spawn(async move {
                    // Access state members concurrently
                    let _cache = &state_clone.cache;
                    let _config = &state_clone.config;

                    // Synchronize to ensure we're actually testing concurrency
                    let mut counter = mutex_clone.lock().await;
                    *counter += 1;
                })
            })
            .collect();

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.unwrap();
        }

        // Check that all tasks completed
        let counter = mutex.lock().await;
        assert_eq!(*counter, 10);
    }

    #[test]
    fn test_app_state_clone() {
        let config = create_test_config();
        let state = AppState::for_testing(&config);

        // Test that we can clone the state
        let cloned_state = state.clone();

        // Verify the clone is valid
        assert!(Arc::ptr_eq(&state.config, &cloned_state.config));
        assert!(Arc::ptr_eq(&state.cache, &cloned_state.cache));
    }
}
