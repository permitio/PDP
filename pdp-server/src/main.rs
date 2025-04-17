mod api;
mod cache;
mod config;
mod errors;
mod headers;
mod models;
mod openapi;
mod state;

use crate::state::AppState;
use axum::Router;
use log::{error, info};
use std::net::SocketAddr;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_scalar::{Scalar, Servable};

#[tokio::main]
async fn main() {
    // Initialize logging
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    // Load configuration
    let settings = match config::Settings::new() {
        Ok(settings) => settings,
        Err(e) => {
            error!("Configuration error: {}", e);
            std::process::exit(1);
        }
    };

    // Initialize cache asynchronously without using block_in_place
    let cache = match cache::create_cache(&settings).await {
        Ok(cache) => cache,
        Err(e) => {
            error!("Failed to initialize cache: {}", e);
            std::process::exit(1);
        }
    };

    // Initialize application state
    let state: AppState = AppState::new_python_based(settings.clone(), cache)
        .await
        .expect("Failed to initialize application state");

    // Create application & Initialize PDPEngine
    let app = create_app(state.clone()).await;

    // Build server address
    let addr = SocketAddr::from(([0, 0, 0, 0], settings.port));
    info!("Starting server on {}", addr);

    // Start server
    let server = match tokio::net::TcpListener::bind(&addr).await {
        Ok(listener) => {
            info!("Listening on {}", addr);
            listener
        }
        Err(e) => {
            error!("Failed to bind to {}: {}", addr, e);
            std::process::exit(1);
        }
    };

    // Start the server and wait for it to finish
    info!("Server running, press Ctrl+C to stop");
    axum::serve(server, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap_or_else(|err| {
            error!("Server error: {}", err);
        });

    // Stop the PDPEngine
    let exit_code = state.stop_engine().await;
    info!("PDPEngine exited with code {}", exit_code);
    info!("Server shutdown complete");
}

/// Create a new application instance with a given state
pub async fn create_app(state: AppState) -> Router {
    // Create OpenAPI documentation
    let (openapi_router, api_doc) =
        OpenApiRouter::with_openapi(openapi::ApiDoc::openapi()).split_for_parts();

    // Create base router with routes
    Router::new()
        .merge(api::router(&state))
        .merge(openapi_router)
        .merge(Scalar::with_url("/scalar", api_doc.clone()))
        .with_state(state)
}

// Simple signal handler that works on all platforms
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C, shutting down");
        },
        _ = terminate => {
            info!("Received SIGTERM, shutting down");
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    use crate::config::{CacheConfig, CacheStore, Settings};
    use crate::create_app;
    use axum::body::Body;

    pub(crate) use crate::state::tests::create_test_state;
    use crate::state::AppState;
    use axum::Router;
    use http::{Method, Request, StatusCode};
    use http_body_util::BodyExt;
    use log::LevelFilter;
    use tower::ServiceExt;
    use wiremock::MockServer;

    /// Set up a test server
    pub(crate) async fn setup_test_app_with_state(app_state: AppState) -> Router {
        // Setup logger
        let _ = env_logger::builder()
            .filter_level(LevelFilter::Debug)
            .is_test(true)
            .try_init();

        create_app(app_state).await
    }

    /// Set up a test server
    pub(crate) async fn setup_test_app() -> Router {
        let settings = setup_test_settings().await;
        let state = create_test_state(settings);
        setup_test_app_with_state(state).await
    }

    /// Set up test settings with given mock server
    pub(crate) fn setup_test_settings_with_mock(mock_server: &MockServer) -> Settings {
        // TODO move to a method on Settings
        // Create test settings
        Settings {
            port: 0, // Let the OS choose a port
            cache: CacheConfig {
                ttl_secs: 60,
                store: CacheStore::None,
                ..CacheConfig::default()
            },
            api_key: "test_api_key".to_string(),
            legacy_fallback_url: mock_server.uri(),
            opa_url: mock_server.uri(),
            ..Settings::default()
        }
    }

    /// Set up test settings
    pub(crate) async fn setup_test_settings() -> Settings {
        // Create a mock server
        let mock_server = MockServer::start().await;
        setup_test_settings_with_mock(&mock_server)
    }

    pub(crate) async fn get_request(app: &Router, uri: &str) -> serde_json::Value {
        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Body::empty())
            .expect("Failed to build request");

        let resp = app
            .clone()
            .oneshot(request)
            .await
            .expect("Failed to send request");
        assert_eq!(resp.status(), StatusCode::OK);
        let raw_body = resp
            .into_body()
            .collect()
            .await
            .expect("Failed to read response body")
            .to_bytes();
        serde_json::from_slice(&raw_body).expect("Failed to deserialize response body")
    }
}
