use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{Method, Request, Response, StatusCode},
    response::IntoResponse,
};
use http::header::HeaderName;
use reqwest::header::HeaderValue;

use crate::state::AppState;

/// Forward unmatched requests to the legacy Horizon PDP service (Python-based PDP)
pub(super) async fn fallback_to_horizon(
    State(state): State<AppState>,
    req: Request<Body>,
) -> impl IntoResponse {
    // Get the path for forwarding
    let path = req.uri().path_and_query();
    let path = match path {
        Some(path) => path.to_string(),
        None => "".to_string(),
    };

    // Convert method to reqwest method
    let method = match *req.method() {
        Method::GET => reqwest::Method::GET,
        Method::POST => reqwest::Method::POST,
        Method::PUT => reqwest::Method::PUT,
        Method::DELETE => reqwest::Method::DELETE,
        Method::PATCH => reqwest::Method::PATCH,
        Method::HEAD => reqwest::Method::HEAD,
        Method::OPTIONS => reqwest::Method::OPTIONS,
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
    let url = state.settings.get_horizon_url(path);
    let req_builder = state.horizon_client.request(method, &url);

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

    // Send request using horizon_client's send method
    match req_builder.send().await {
        Ok(response) => {
            // Get response details
            let status = response.status();
            let headers = response.headers().clone();
            let bytes = match response.bytes().await {
                Ok(bytes) => bytes,
                Err(_) => {
                    return (StatusCode::BAD_GATEWAY, "Failed to read response body")
                        .into_response();
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
        Err(e) => {
            if let Some(status) = e.status() {
                // For status errors, we want to forward the status code
                let status_code =
                    StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
                (status_code, "Error response from fallback server").into_response()
            } else {
                log::error!("Failed to send request: {} ({:?})", e, e.status());
                (
                    StatusCode::BAD_GATEWAY,
                    format!("Failed to send request: {}", e),
                )
                    .into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestFixture;
    use axum::response::IntoResponse;
    use http::{Method, StatusCode};
    use wiremock::{matchers, Mock, ResponseTemplate};

    #[tokio::test]
    async fn test_forward_unmatched_basic() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Setup mock response on horizon_mock instead of a separate mock server
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/test"))
            .and(matchers::header("X-Test", "value"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("test response")
                    .insert_header("X-Response", "test"),
            )
            .expect(1)
            .mount(&fixture.horizon_mock)
            .await;

        // Create test request
        let req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .header("X-Test", "value")
            .body(Body::empty())
            .unwrap();

        // Forward request using the state from the fixture
        let response =
            fallback_to_horizon(State(AppState::for_testing(&fixture.settings)), req).await;
        let response = response.into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("X-Response").unwrap(), "test");

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"test response");

        // Verify mock expectations
        fixture.horizon_mock.verify().await;
    }

    #[tokio::test]
    async fn test_forward_unmatched_with_body() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Setup mock to echo request body
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/echo"))
            .respond_with(|req: &wiremock::Request| {
                ResponseTemplate::new(200).set_body_bytes(req.body.clone())
            })
            .expect(1)
            .mount(&fixture.horizon_mock)
            .await;

        // Create test request with body
        let req = Request::builder()
            .method(Method::POST)
            .uri("/echo")
            .body(Body::from("test body"))
            .unwrap();

        // Forward request using the state from the fixture
        let response =
            fallback_to_horizon(State(AppState::for_testing(&fixture.settings)), req).await;
        let response = response.into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"test body");

        // Verify mock expectations
        fixture.horizon_mock.verify().await;
    }

    #[tokio::test]
    async fn test_forward_unmatched_not_found() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Setup mock to return 404
        Mock::given(matchers::any())
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&fixture.horizon_mock)
            .await;

        // Create test request
        let req = Request::builder()
            .method(Method::GET)
            .uri("/not-found")
            .body(Body::empty())
            .unwrap();

        // Forward request using the state from the fixture
        let response =
            fallback_to_horizon(State(AppState::for_testing(&fixture.settings)), req).await;
        let response = response.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Verify mock expectations
        fixture.horizon_mock.verify().await;
    }

    #[tokio::test]
    async fn test_forward_unmatched_error() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Setup mock to return error
        Mock::given(matchers::any())
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&fixture.horizon_mock)
            .await;

        // Create test request
        let req = Request::builder()
            .method(Method::GET)
            .uri("/error")
            .body(Body::empty())
            .unwrap();

        // Forward request using the state from the fixture
        let response =
            fallback_to_horizon(State(AppState::for_testing(&fixture.settings)), req).await;
        let response = response.into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        // Verify mock expectations
        fixture.horizon_mock.verify().await;
    }
}
