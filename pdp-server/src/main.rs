mod api;
mod cache;
mod config;
mod errors;
mod headers;
mod models;
mod opa_client;
mod openapi;
mod state;
#[cfg(test)]
mod test_utils;

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
    let config = match config::PDPConfig::new() {
        Ok(config) => config,
        Err(e) => {
            error!("Configuration error: {}", e);
            std::process::exit(1);
        }
    };

    // Initialize cache asynchronously without using block_in_place
    let cache = match cache::create_cache(&config).await {
        Ok(cache) => cache,
        Err(e) => {
            error!("Failed to initialize cache: {}", e);
            std::process::exit(1);
        }
    };

    // Initialize application state
    let state: AppState = AppState::with_existing_cache(&config, cache)
        .await
        .expect("Failed to initialize application state");

    // Create application & Initialize PDPEngine
    let app = create_app(state).await;

    // Build server address
    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));

    // Start server
    let server = match tokio::net::TcpListener::bind(&addr).await {
        Ok(listener) => listener,
        Err(e) => {
            error!("Failed to bind to {}: {}", addr, e);
            std::process::exit(1);
        }
    };

    // Start the server and wait for it to finish
    info!("Server running on {}, press Ctrl+C to stop", addr);
    let serve = axum::serve(server, app)
        .with_graceful_shutdown(shutdown_signal())
        .await;
    if let Err(e) = serve {
        error!("Server error: {}", e);
        std::process::exit(1);
    }

    // Drop state to ensure clean shutdown of watchdog
    drop(serve);
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
