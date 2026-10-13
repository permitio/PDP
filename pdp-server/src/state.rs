use crate::{
    api_key::{handoff, ApiKeySource, CurrentApiKey},
    cache::Cache,
    config::{trino_authz::TrinoAuthzConfig, PDPConfig},
};
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{HeaderMap, HeaderValue};
use reqwest::{Client, RequestBuilder};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;
use watchdog::{
    ChildOutputHandler, ChildStream, CommandWatchdogOptions, HttpHealthChecker, ServiceWatchdog,
    ServiceWatchdogOptions,
};

/// Represents the application state containing shared resources and configurations
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<PDPConfig>,
    pub api_key: CurrentApiKey,
    pub cache: Arc<Cache>,
    pub watchdog: Option<Arc<ServiceWatchdog>>,
    pub opa_client: Arc<Client>,
    pub horizon_client: Arc<Client>,
    pub trino_authz_config: Option<Arc<TrinoAuthzConfig>>,
}

/// Re-emits the supervised Horizon child's output on this process's logger,
/// tagged so a reader can tell the child's lines from the server's own.
///
/// Both streams are logged at `info`. Uvicorn writes its ordinary startup and
/// access lines to stderr, so treating stderr as a warning would misreport
/// every healthy line as a problem; the stream name is recorded instead and
/// left for the reader to interpret.
struct HorizonOutput;

impl ChildOutputHandler for HorizonOutput {
    fn on_line(&self, stream: ChildStream, line: &str) {
        // Under the crate's own module path, not a bare "horizon": a
        // target-scoped directive such as `RUST_LOG=pdp_server=debug`
        // matches a target by prefix, so a bare "horizon" falls outside it
        // and this output would silently vanish whenever verbosity is scoped
        // to the crate rather than left global.
        log::info!(target: "pdp_server::horizon", "[{stream}] {line}");
    }
}

impl AppState {
    /// Create a new application state with a pre-initialized cache
    pub async fn with_existing_cache(
        config: &PDPConfig,
        cache: Cache,
    ) -> Result<Self, std::io::Error> {
        let (api_key, api_key_handoff_file) = init_api_key(config)?;
        let watchdog = Self::setup_horizon_watchdog(config, api_key_handoff_file.as_deref()).await;

        // Load Trino authz config if available
        let trino_authz_config =
            TrinoAuthzConfig::load_from_file(&config.trino_authz_config_path).map(Arc::new);

        Ok(Self {
            config: Arc::new(config.clone()),
            api_key,
            cache: Arc::new(cache),
            watchdog: Some(Arc::new(watchdog)),
            opa_client: Arc::new(create_http_client(config.opa.client_query_timeout)),
            horizon_client: Arc::new(create_http_client(config.horizon.client_timeout)),
            trino_authz_config,
        })
    }

    /// Create a minimal state for testing without watchdogs or real services
    #[cfg(test)]
    pub fn for_testing(config: &PDPConfig) -> Self {
        Self {
            config: Arc::new(config.clone()),
            api_key: CurrentApiKey::new(config.api_key.env_key()),
            cache: Arc::new(Cache::Null(crate::cache::null::NullCache::new())),
            watchdog: None,
            opa_client: Arc::new(create_http_client(config.opa.client_query_timeout)),
            horizon_client: Arc::new(create_http_client(config.horizon.client_timeout)),
            trino_authz_config: None,
        }
    }

    /// Starts a GET to one of horizon's public routes (health, API docs). It presents the API key
    /// when there is one; before there is one it goes without, as those routes do not ask for it.
    pub fn get_public_horizon_route(&self, url: &str) -> RequestBuilder {
        let request = self.horizon_client.get(url);
        match self.api_key.bearer() {
            Some(bearer) => request.header(AUTHORIZATION, bearer),
            None => request,
        }
    }

    /// Set up and initialize the Horizon service watchdog
    pub(crate) async fn setup_horizon_watchdog(
        config: &PDPConfig,
        api_key_handoff_file: Option<&Path>,
    ) -> ServiceWatchdog {
        let command = horizon_command(config, api_key_handoff_file);

        let health_endpoint = format!(
            "http://{}:{}/healthy",
            config.horizon.host, config.horizon.port,
        );
        let health_checker = HttpHealthChecker::with_options(
            health_endpoint,
            200,
            Duration::from_secs(config.horizon.health_check_timeout),
        );

        ServiceWatchdog::start_with_opt(command, health_checker, horizon_watchdog_options(config))
    }
}

/// How the watchdog checks and restarts horizon, from the `PDP_HORIZON_*` settings.
fn horizon_watchdog_options(config: &PDPConfig) -> ServiceWatchdogOptions {
    ServiceWatchdogOptions {
        health_check_interval: Duration::from_secs(config.horizon.health_check_interval),
        health_check_failure_threshold: config.horizon.health_check_failure_threshold,
        initial_startup_delay: Duration::from_secs(config.horizon.startup_delay),
        command_options: CommandWatchdogOptions {
            restart_interval: Duration::from_secs(config.horizon.restart_interval),
            max_restart_interval: Duration::from_secs(config.horizon.max_restart_interval),
            termination_timeout: Duration::from_secs(config.horizon.termination_timeout),
            output_handler: Some(Arc::new(HorizonOutput)),
        },
    }
}

/// The key in force at startup. Without one in `PDP_API_KEY`, also starts taking the key horizon
/// derives, and returns the file horizon hands it over in.
fn init_api_key(config: &PDPConfig) -> std::io::Result<(CurrentApiKey, Option<PathBuf>)> {
    let api_key = CurrentApiKey::new(config.api_key.env_key());
    let handoff_file = match config.api_key {
        ApiKeySource::Env(_) => None,
        ApiKeySource::Horizon => Some(handoff::start(api_key.clone())?),
    };
    Ok((api_key, handoff_file))
}

/// The command that runs horizon, told where to write the key it derives when the PDP has none of
/// its own.
fn horizon_command(config: &PDPConfig, api_key_handoff_file: Option<&Path>) -> Command {
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

    match api_key_handoff_file {
        Some(file) => command.env(handoff::FILE_ENV, file),
        // One inherited from the container's environment would have horizon write the key to a
        // file nothing reads or removes
        None => command.env_remove(handoff::FILE_ENV),
    };
    command
}

/// Creates a configured HTTP client with default headers and timeouts. The API key is not among
/// them: it can change while the PDP runs, so each request that needs it adds it.
fn create_http_client(timeout_secs: u64) -> Client {
    let mut headers = HeaderMap::new();
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
    use crate::cache::CacheBackend;
    use crate::config::cache::{InMemoryConfig, RedisConfig};
    use crate::config::{CacheConfig, CacheStore};

    fn create_test_config() -> PDPConfig {
        PDPConfig {
            api_key: ApiKeySource::from_env_value("test-api-key").unwrap(),
            host: "0.0.0.0".to_string(),
            debug: Some(true),
            port: 3000,
            use_new_authorized_users: false,
            allow_unauthenticated_trino: false,
            healthcheck_timeout: 1.0,
            trino_authz_config_path: "/tmp/trino-authz.yaml".to_string(),
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
                max_restart_interval: 60,
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

    #[test]
    fn test_horizon_restarts_back_off_as_configured() {
        let mut config = create_test_config();
        config.horizon.restart_interval = 2;
        config.horizon.max_restart_interval = 120;

        let options = horizon_watchdog_options(&config).command_options;

        assert_eq!(options.restart_interval, Duration::from_secs(2));
        assert_eq!(options.max_restart_interval, Duration::from_secs(120));
    }

    /// What the command does with PDP_API_KEY_HANDOFF_FILE: `Inherit` leaves the child whatever
    /// this process has.
    #[derive(Debug, PartialEq)]
    enum HandoffFileEnv {
        Inherit,
        Remove,
        Set(String),
    }

    fn handoff_file_env(command: &Command) -> HandoffFileEnv {
        let found = command
            .as_std()
            .get_envs()
            .find(|(name, _)| *name == handoff::FILE_ENV);
        match found {
            None => HandoffFileEnv::Inherit,
            Some((_, None)) => HandoffFileEnv::Remove,
            Some((_, Some(value))) => HandoffFileEnv::Set(value.to_string_lossy().into_owned()),
        }
    }

    /// With a key in PDP_API_KEY horizon gets no handoff file, not even one this process inherited.
    #[tokio::test]
    async fn test_key_from_env_needs_no_handoff() {
        let config = create_test_config();

        let (api_key, handoff_file) = init_api_key(&config).unwrap();

        assert_eq!(api_key.get().unwrap().as_str(), "test-api-key");
        assert_eq!(handoff_file, None);
        let command = horizon_command(&config, handoff_file.as_deref());
        assert_eq!(handoff_file_env(&command), HandoffFileEnv::Remove);
    }

    #[tokio::test]
    async fn test_without_a_key_horizon_is_told_where_to_hand_it_over() {
        let mut config = create_test_config();
        config.api_key = ApiKeySource::Horizon;

        let (api_key, handoff_file) = init_api_key(&config).unwrap();

        assert!(api_key.get().is_none());
        let handoff_file = handoff_file.expect("a handoff file without a key in PDP_API_KEY");
        assert!(handoff_file.is_absolute());
        let command = horizon_command(&config, Some(&handoff_file));
        assert_eq!(
            handoff_file_env(&command),
            HandoffFileEnv::Set(handoff_file.display().to_string())
        );
    }

    /// The handler must survive whatever the child writes: it runs on the task
    /// that keeps the child's pipes drained, so a panic here ends that task —
    /// the child then either blocks on a full pipe or, once the read end
    /// closes, dies on `SIGPIPE` and restart-loops.
    #[test]
    fn horizon_output_handler_survives_hostile_lines() {
        let handler = HorizonOutput;
        for line in [
            "",
            "INFO:     Uvicorn running on http://0.0.0.0:7001",
            "{\"not\":\"a log line\"}",
            "  \t  ",
            &"x".repeat(64 * 1024),
        ] {
            handler.on_line(ChildStream::Stdout, line);
            handler.on_line(ChildStream::Stderr, line);
        }
    }
}
