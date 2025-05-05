use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{Method, Request, Response, StatusCode},
    response::IntoResponse,
};
use http::header::HeaderName;
use reqwest::header::HeaderValue;
use std::error::Error as StdError;

use crate::{create_app, state::AppState};

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
    let url = state.config.get_horizon_url(path);
    log::debug!("Forwarding request to Horizon: {} {}", req.method(), url);
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
                Err(e) => {
                    log::error!("Failed to read response body: {}", e);
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
                log::error!(
                    "Failed to send request: {} ({:?})\nURL: {}\nError details: {:?}\nSource error: {:?}",
                    e, e.status(), url, e, e.source()
                );
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
    use serde_json::json;
    use std::time::Duration;
    use wiremock::{matchers, Mock, ResponseTemplate};

    #[tokio::test]
    async fn test_forward_unmatched_basic() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Setup mock response on horizon_mock instead of a separate mock server
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/test"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("test response")
                    .insert_header("X-Response", "test"),
            )
            .expect(1)
            .mount(&fixture.horizon_mock)
            .await;

        // Forward request using the state from the fixture
        let response = fixture.get("/test").await;
        response.assert_status(StatusCode::OK);
        response.assert_header("X-Response", "test");
        assert_eq!(response.json(), "test response");

        // Verify mock expectations
        fixture.horizon_mock.verify().await;
    }

    #[tokio::test]
    async fn test_forward_unmatched_with_body() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Setup mock with more lenient body matching
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/echo"))
            // Use any body matcher instead of specific bytes
            .respond_with(|req: &wiremock::Request| {
                println!(
                    "Received request body: {:?}",
                    String::from_utf8_lossy(&req.body)
                );
                ResponseTemplate::new(200).set_body_bytes(req.body.clone())
            })
            .expect(1)
            .mount(&fixture.horizon_mock)
            .await;

        // Forward request using the state from the fixture
        let response = fixture.post("/echo", &"test body").await;
        response.assert_status(StatusCode::OK);
        assert_eq!(response.json(), "test body");

        // Verify mock expectations
        fixture.horizon_mock.verify().await;
    }

    #[tokio::test]
    async fn test_forward_unmatched_not_found() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Setup mock to return 404
        Mock::given(matchers::any())
            .and(matchers::path_regex(".*not-found$"))
            .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
            .expect(1)
            .mount(&fixture.horizon_mock)
            .await;

        // Forward request using the state from the fixture
        let response = fixture.get("/not-found").await;
        response.assert_status(StatusCode::NOT_FOUND);
        assert_eq!(response.json(), "Not Found");

        // Verify mock expectations
        fixture.horizon_mock.verify().await;
    }

    #[tokio::test]
    async fn test_forward_unmatched_error() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Setup mock to return error
        Mock::given(matchers::any())
            .and(matchers::path_regex(".*error$"))
            .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
            .expect(1)
            .mount(&fixture.horizon_mock)
            .await;

        // Forward request using the state from the fixture
        let response = fixture.get("/error").await;
        response.assert_status(StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.json(), "Service Unavailable");

        // Verify mock expectations
        fixture.horizon_mock.verify().await;
    }

    #[tokio::test]
    async fn test_forward_with_query_parameters() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Setup mock to verify query parameters
        Mock::given(matchers::method("GET"))
            .and(matchers::path_regex(".*query$"))
            .and(matchers::query_param("param1", "value1"))
            .and(matchers::query_param("param2", "value2"))
            .respond_with(ResponseTemplate::new(200).set_body_string("query params received"))
            .expect(1)
            .mount(&fixture.horizon_mock)
            .await;

        // Forward request
        let response = fixture.get("/query?param1=value1&param2=value2").await;
        response.assert_status(StatusCode::OK);
        assert_eq!(response.json(), "query params received");

        // Verify mock expectations
        fixture.horizon_mock.verify().await;
    }

    #[tokio::test]
    async fn test_http_method_get() {
        test_specific_http_method(Method::GET).await;
    }

    #[tokio::test]
    async fn test_http_method_post() {
        test_specific_http_method(Method::POST).await;
    }

    #[tokio::test]
    async fn test_http_method_put() {
        test_specific_http_method(Method::PUT).await;
    }

    #[tokio::test]
    async fn test_http_method_delete() {
        test_specific_http_method(Method::DELETE).await;
    }

    #[tokio::test]
    async fn test_http_method_patch() {
        test_specific_http_method(Method::PATCH).await;
    }

    #[tokio::test]
    async fn test_http_method_head() {
        test_specific_http_method(Method::HEAD).await;
    }

    #[tokio::test]
    async fn test_http_method_options() {
        test_specific_http_method(Method::OPTIONS).await;
    }

    async fn test_specific_http_method(method: Method) {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Setup mock for this method
        Mock::given(matchers::method(method.as_str()))
            .and(matchers::path_regex(".*method-test$"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(format!("{} method works", method.as_str())),
            )
            .expect(1)
            .mount(&fixture.horizon_mock)
            .await;

        // Create test request
        let req = Request::builder()
            .method(method.clone())
            .uri("/method-test")
            .body(Body::empty())
            .unwrap();

        // Forward request
        let response = fixture.send(req).await;
        assert_eq!(response.status, StatusCode::OK);

        // For HEAD, there shouldn't be a body
        if method != Method::HEAD {
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            assert_eq!(
                &body[..],
                format!("{} method works", method.as_str()).as_bytes()
            );
        }

        fixture.horizon_mock.verify().await;
    }

    #[tokio::test]
    async fn test_unsupported_http_method() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Create test request with CONNECT method (not supported in our implementation)
        let req = Request::builder()
            .method(Method::CONNECT)
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        // Forward request
        let response = fixture.send(req).await;
        response.assert_status(StatusCode::METHOD_NOT_ALLOWED);
        // No need to verify mock as request should not be forwarded
    }

    #[tokio::test]
    async fn test_complex_headers() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Create response headers
        let response_headers = [
            ("Content-Type", "text/plain"),
            ("Cache-Control", "no-cache, must-revalidate"),
            ("X-Rate-Limit", "100"),
            ("X-Server", "Test-Server"),
            ("Vary", "Accept-Encoding"),
        ];

        // Setup mock that demonstrates header forwarding
        // We use multiple headers in the request and in the response
        Mock::given(matchers::method("GET"))
            .and(matchers::path_regex(".*headers.*"))
            // Use header matchers to verify headers are forwarded correctly
            .and(matchers::header("Content-Type", "application/json"))
            .and(matchers::header("Authorization", "Bearer token123"))
            .and(matchers::header("X-Custom-Header", "custom value"))
            .respond_with({
                let mut template =
                    ResponseTemplate::new(200).set_body_string("{\"status\":\"success\"}");

                for (name, value) in &response_headers {
                    template = template.insert_header(*name, *value);
                }

                template
            })
            .expect(1)
            .mount(&fixture.horizon_mock)
            .await;

        // Create test request with multiple headers
        let request_headers = [
            ("Content-Type", "application/json"),
            ("Authorization", "Bearer token123"),
            ("X-Custom-Header", "custom value"),
            ("Accept-Language", "en-US,en;q=0.9"),
            ("Cache-Control", "no-cache"),
        ];

        let mut request_builder = Request::builder().method(Method::GET).uri("/headers");

        for (name, value) in &request_headers {
            request_builder = request_builder.header(*name, *value);
        }

        let req = request_builder.body(Body::empty()).unwrap();

        // Forward request
        let response = fixture.send(req).await;
        assert_eq!(response.json(), json!({"status": "success"}));
        response.assert_status(StatusCode::OK);
        for (name, value) in &response_headers {
            response.assert_header(name, value);
        }

        // When this verification succeeds, it confirms that our mock received
        // the expected headers that we specified in the matchers above
        fixture.horizon_mock.verify().await;
        let requests = fixture.horizon_mock.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.method, Method::GET);
        for (name, value) in request_headers {
            assert_eq!(request.headers.get(name).unwrap(), value);
        }
    }

    #[tokio::test]
    async fn test_empty_body_post() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Setup mock to verify empty body POST
        Mock::given(matchers::method("POST"))
            .and(matchers::path_regex(".*empty-body$"))
            .and(matchers::body_bytes(""))
            .respond_with(ResponseTemplate::new(200).set_body_string("Empty body received"))
            .expect(1)
            .mount(&fixture.horizon_mock)
            .await;

        // Create test request with empty body
        let req = Request::builder()
            .method(Method::POST)
            .uri("/empty-body")
            .body(Body::empty())
            .unwrap();

        // Forward request
        let response = fixture.send(req).await;
        response.assert_status(StatusCode::OK);
        assert_eq!(response.json(), "Empty body received");

        fixture.horizon_mock.verify().await;
    }

    #[tokio::test]
    async fn test_connection_error() {
        // Setup test fixture with invalid horizon URL to force connection error
        let mut fixture = TestFixture::new().await;

        // Update settings to point to non-existent server
        fixture.config.horizon.host = "invalid-server".to_string();
        fixture.config.horizon.port = 12345;

        // Override the horizon client timeout to be very short (1 sec)
        fixture.config.horizon.client_timeout = 1; // 1 second for test speed

        // Need to recreate the app state with the new timeout settings
        let state = AppState::for_testing(&fixture.config);
        fixture.app = create_app(state).await;

        // Create test request
        let req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        // Forward request with modified state
        let response =
            fallback_to_horizon(State(AppState::for_testing(&fixture.config)), req).await;
        let response = response.into_response();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(body.len() > 0); // Should contain error message
    }

    #[tokio::test]
    async fn test_horizon_request_timeout() {
        // Setup test fixture with a very short timeout for horizon client
        let mut fixture = TestFixture::new().await;

        // Override the horizon client timeout to be very short (1 sec)
        fixture.config.horizon.client_timeout = 1; // 1 second for test speed

        // Need to recreate the app state with the new timeout settings
        let state = AppState::for_testing(&fixture.config);
        fixture.app = create_app(state).await;

        // Setup mock that delays longer than the timeout
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/timeout-test"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(3))) // 3 second delay
            .expect(1)
            .mount(&fixture.horizon_mock)
            .await;

        // Create test request
        let req = Request::builder()
            .method(Method::GET)
            .uri("/timeout-test")
            .body(Body::empty())
            .expect("Failed to build request");

        // Forward request directly using the fallback handler to ensure the timeout is used
        let response =
            fallback_to_horizon(State(AppState::for_testing(&fixture.config)), req).await;
        let response = response.into_response();

        // Assert timeout error (502 Bad Gateway)
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

        // Read the body
        let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body_str = String::from_utf8_lossy(&body_bytes);

        // The body should contain timeout error message
        assert!(
            body_str.contains("timeout") || body_str.contains("timed out"),
            "Expected timeout error message, got: {}",
            body_str
        );

        // Verify mock expectations
        fixture.horizon_mock.verify().await;
    }

    #[tokio::test]
    async fn test_horizon_slow_but_within_timeout() {
        // Setup test fixture
        let mut fixture = TestFixture::new().await;

        // Set a 2 second timeout
        fixture.config.horizon.client_timeout = 2;

        // Setup mock that responds slower but within the timeout
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/slow-response"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(500)) // 500ms delay - within timeout
                    .set_body_string("slow but successful response"),
            )
            .expect(1)
            .mount(&fixture.horizon_mock)
            .await;

        // Forward request - should succeed despite being slow
        let response = fixture.get("/slow-response").await;

        // Assert success
        response.assert_status(StatusCode::OK);
        assert_eq!(response.json(), "slow but successful response");

        // Verify mock expectations
        fixture.horizon_mock.verify().await;
    }
}
