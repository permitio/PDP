use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{Method, Request, Response, StatusCode},
    response::IntoResponse,
};
use http::header::HeaderName;
use pdp_engine::error::PDPError;
use reqwest::header::HeaderValue;

use crate::state::AppState;
use pdp_engine::PDPEngine;

/// Forward unmatched requests to the legacy Horizon PDP service (Python-based PDP)
pub(super) async fn fallback_to_horizon(
    State(state): State<AppState>,
    req: Request<Body>,
) -> impl IntoResponse {
    // Get path for forwarding
    let path = req.uri().path_and_query().map(|x| x.as_str()).unwrap_or("");

    // Convert method to reqwest method
    let method = match *req.method() {
        Method::GET => Method::GET,
        Method::POST => Method::POST,
        Method::PUT => Method::PUT,
        Method::DELETE => Method::DELETE,
        Method::PATCH => Method::PATCH,
        Method::HEAD => Method::HEAD,
        Method::OPTIONS => Method::OPTIONS,
        _ => {
            log::error!("Unsupported HTTP method: {}", req.method());
            return (
                StatusCode::METHOD_NOT_ALLOWED,
                format!("Unsupported HTTP method: {}", req.method()),
            )
                .into_response();
        }
    };

    // Prepare request builder
    let req_builder = match state.engine.request(method, path) {
        Ok(builder) => builder,
        Err(e) => {
            log::error!("Failed to create request: {}", e);
            return (
                StatusCode::BAD_GATEWAY,
                format!("Failed to create request: {}", e),
            )
                .into_response();
        }
    };

    // Forward headers
    let mut req_builder = req_builder;
    for (key, value) in req.headers() {
        if let Ok(header_value) = HeaderValue::from_bytes(value.as_bytes()) {
            req_builder = req_builder.header(key.as_str(), header_value);
        }
    }

    // Forward body if present
    let body_bytes = match to_bytes(req.into_body(), usize::MAX).await {
        Ok(bytes) => bytes,
        Err(_) => return (StatusCode::BAD_GATEWAY, "Failed to read request body").into_response(),
    };

    if !body_bytes.is_empty() {
        req_builder = req_builder.body(body_bytes);
    }

    // Send request using PDPEngine's low-level send_raw method
    match state.engine.send_raw(req_builder).await {
        Ok(response) => {
            // Get response details
            let status = response.status();
            let headers = response.headers().clone();
            let bytes = match response.bytes().await {
                Ok(bytes) => bytes,
                Err(_) => {
                    return (StatusCode::BAD_GATEWAY, "Failed to read response body")
                        .into_response()
                }
            };

            // Build response
            let mut resp = Response::new(Body::from(bytes));
            *resp.status_mut() = status;

            // Forward response headers
            for (key, value) in headers {
                if let Some(key) = key {
                    if let Ok(name) = HeaderName::from_bytes(key.as_ref()) {
                        resp.headers_mut().insert(name, value);
                    }
                }
            }

            resp
        }
        Err(PDPError::ResponseError(status, _)) => {
            // For status errors, we want to forward the status code
            let status_code = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
            (status_code, "Error response from fallback server").into_response()
        }
        Err(e) => {
            log::error!("Failed to send request: {}", e);
            (
                StatusCode::BAD_GATEWAY,
                format!("Failed to send request: {}", e),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api;
    use crate::config::{CacheStore, Settings};
    use axum::http::Method;
    use axum::response::IntoResponse;
    use axum::{serve, Router};
    use std::net::SocketAddr;
    use tokio::net::TcpListener;
    use wiremock::matchers::{any, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // TODO refactor this to use a common test setup

    pub async fn create_test_app(settings: Settings) -> (Router, AppState) {
        // Initialize application state
        let state = AppState::new(settings).await.unwrap();

        // Create health routes
        let health_routes = api::health::router();

        // Clone state for auth middleware
        let auth_state = state.clone();

        // API key authentication middleware
        let auth_middleware = move |req: axum::http::Request<axum::body::Body>,
                                    next: axum::middleware::Next| {
            let state = auth_state.clone();
            async move {
                // Token validation logic from lib.rs
                let auth_header = req
                    .headers()
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|header| header.to_str().ok())
                    .and_then(|auth_value| {
                        if auth_value.starts_with("Bearer ") {
                            Some(auth_value[7..].to_string())
                        } else {
                            None
                        }
                    });

                let token = match auth_header {
                    Some(token) => token,
                    None => {
                        return Err(crate::auth::AuthError::MissingToken);
                    }
                };

                if token != state.settings.api_key {
                    return Err(crate::auth::AuthError::InvalidToken);
                }

                Ok(next.run(req).await)
            }
        };

        // Protected routes
        let protected_routes = Router::new()
            .merge(api::authz::router())
            .fallback(axum::routing::any(fallback_to_horizon))
            .route_layer(axum::middleware::from_fn(auth_middleware));

        // Create base router with routes
        let app = Router::new()
            .merge(health_routes)
            .merge(protected_routes)
            .with_state(state.clone());
        (app, state)
    }

    pub async fn setup_test_server(cache_store: CacheStore) -> (AppState, MockServer, Settings) {
        let mock_server = MockServer::start().await;
        // Create test settings
        let mut settings = Settings::default();
        settings.port = 0; // Let the OS choose a port
        settings.cache.ttl_secs = 60;
        settings.api_key = "test_api_key".to_string();
        settings.cache.store = cache_store;
        settings.legacy_fallback_url = mock_server.uri(); // Set mock server URL as fallback

        // Create the app with temporary cache directory
        let (app, state) = create_test_app(settings.clone()).await;

        // Create test server
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let listener = TcpListener::bind(addr)
            .await
            .expect("Failed to bind to address");
        let _server_addr = listener.local_addr().expect("Failed to get local address");

        // Spawn the server
        tokio::spawn(async move {
            serve(listener, app).await.expect("Server error");
        });

        (state, mock_server, settings)
    }

    #[tokio::test]
    async fn test_forward_unmatched_basic() {
        let (state, mock_server, _settings) = setup_test_server(CacheStore::None).await;
        // Setup mock response
        Mock::given(method("GET"))
            .and(path("/test"))
            .and(header("X-Test", "value"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("test response")
                    .insert_header("X-Response", "test"),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        // Create test request
        let req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .header("X-Test", "value")
            .body(Body::empty())
            .unwrap();

        // Forward request
        let response = fallback_to_horizon(State(state), req).await;
        let response = response.into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("X-Response").unwrap(), "test");

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"test response");
    }

    #[tokio::test]
    async fn test_forward_unmatched_with_body() {
        let (state, mock_server, _settings) = setup_test_server(CacheStore::None).await;

        // Setup mock to echo request body
        Mock::given(method("POST"))
            .and(path("/echo"))
            .respond_with(|req: &wiremock::Request| {
                ResponseTemplate::new(200).set_body_bytes(req.body.clone())
            })
            .expect(1)
            .mount(&mock_server)
            .await;

        // Create test request with body
        let req = Request::builder()
            .method(Method::POST)
            .uri("/echo")
            .body(Body::from("test body"))
            .unwrap();

        // Forward request
        let response = fallback_to_horizon(State(state), req).await;
        let response = response.into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"test body");
    }

    #[tokio::test]
    async fn test_forward_unmatched_error() {
        let (state, mock_server, _settings) = setup_test_server(CacheStore::None).await;

        // Setup mock to return error
        Mock::given(any())
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Create test request
        let req = Request::builder()
            .method(Method::GET)
            .uri("/error")
            .body(Body::empty())
            .unwrap();

        // Forward request
        let response = fallback_to_horizon(State(state), req).await;
        let response = response.into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
