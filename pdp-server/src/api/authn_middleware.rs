use crate::state::AppState;
use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use log::warn;
use subtle::ConstantTimeEq;

pub(super) async fn authentication_middleware(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // Extract the authorization header
    let auth_header = match request.headers().get(http::header::AUTHORIZATION) {
        Some(header) => header,
        None => {
            warn!("Missing Authorization header");
            // TODO avoid this expect panic (maybe using IntoResponse)
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body("Missing Authorization header".into())
                .expect("Failed to create response");
        }
    };

    // Extract the token from the authorization header
    let api_key = match auth_header.to_str() {
        Ok(header_str) if header_str.to_lowercase().starts_with("bearer ") => {
            // Remove the "Bearer " prefix
            header_str[7..].to_string()
        }
        Ok(_) => {
            warn!("Invalid Authorization header format, missing 'Bearer ' prefix");
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(
                    "You are not authorized to access this resource, please check your API key."
                        .into(),
                )
                .expect("Failed to create response");
        }
        Err(e) => {
            warn!("Failed to parse Authorization header to string: {e}");
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(
                    "You are not authorized to access this resource, please check your API key."
                        .into(),
                )
                .expect("Failed to create response");
        }
    };

    // Verify the API key
    let key_matches: bool = api_key
        .as_bytes()
        .ct_eq(state.config.api_key.as_bytes())
        .into();
    if !key_matches {
        warn!("Authentication failed: Invalid API key");
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(
                "You are not authorized to access this resource, please check your API key.".into(),
            )
            .expect("Failed to create response");
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{LogCapture, TestFixture};
    use axum::routing::get;
    use axum::Router;
    use http::HeaderValue;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const TEST_ROUTE: &str = "/test";

    /// Helper function to set up a mock app with authentication middleware
    async fn setup_authn_mock_app(api_key: &str) -> Router {
        // Create a TestFixture and get settings from it, but customize the API key
        let fixture = TestFixture::new().await;
        let mut config = fixture.config.clone();
        config.api_key = api_key.to_string();
        let state = AppState::for_testing(&config);

        Router::new()
            .route(TEST_ROUTE, get(async || (StatusCode::OK, "Authenticated")))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                authentication_middleware,
            ))
            .with_state(state)
    }

    /// Helper function to build a request with optional authorization header
    async fn send_request(app: &Router, auth_header: Option<&str>) -> (StatusCode, String) {
        let auth_header =
            auth_header.map(|auth| HeaderValue::from_str(auth).expect("Invalid header value"));
        send_request_with_header(app, auth_header).await
    }

    async fn send_request_with_header(
        app: &Router,
        auth_header: Option<HeaderValue>,
    ) -> (StatusCode, String) {
        let mut request_builder = Request::builder().uri(TEST_ROUTE);

        if let Some(auth) = auth_header {
            request_builder = request_builder.header("Authorization", auth);
        }

        let request = request_builder
            .body(Body::empty())
            .expect("Failed to build request");

        let response = app
            .clone()
            .oneshot(request)
            .await
            .expect("Failed to send request");

        let status = response.status();
        let body_bytes = response
            .into_body()
            .collect()
            .await
            .expect("Failed to read response body")
            .to_bytes();

        let body = String::from_utf8(body_bytes.to_vec())
            .expect("Failed to convert response body to string");

        (status, body)
    }

    #[tokio::test]
    async fn test_authentication_middleware() {
        let app = setup_authn_mock_app("test_api_key").await;
        let (status, body) = send_request(&app, Some("Bearer test_api_key")).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "Authenticated");
    }

    #[tokio::test]
    async fn test_missing_authorization_header() {
        let app = setup_authn_mock_app("test_api_key").await;
        let (status, body) = send_request(&app, None).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, "Missing Authorization header");
    }

    #[tokio::test]
    async fn test_invalid_authorization_format() {
        let app = setup_authn_mock_app("test_api_key").await;
        let (status, body) = send_request(&app, Some("test_api_key")).await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            body,
            "You are not authorized to access this resource, please check your API key."
        );
    }

    #[tokio::test]
    async fn test_invalid_api_key() {
        let app = setup_authn_mock_app("test_api_key").await;
        let (status, body) = send_request(&app, Some("Bearer wrong_api_key")).await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            body,
            "You are not authorized to access this resource, please check your API key."
        );
    }

    #[tokio::test]
    async fn test_lowercase_bearer_scheme_is_accepted() {
        let app = setup_authn_mock_app("test_api_key").await;
        let (status, body) = send_request(&app, Some("bearer test_api_key")).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "Authenticated");
    }

    #[tokio::test]
    async fn test_right_key_with_another_scheme_is_rejected() {
        let app = setup_authn_mock_app("test_api_key").await;
        let (status, _) = send_request(&app, Some("Basic test_api_key")).await;

        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_key_that_differs_only_in_length_is_rejected() {
        let app = setup_authn_mock_app("test_api_key").await;

        for header in [
            "Bearer ",
            "Bearer test_api_ke",
            "Bearer test_api_key2",
            "Bearer test_api_key ",
        ] {
            let (status, _) = send_request(&app, Some(header)).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "header {header:?}");
        }
    }

    /// The Authorization header the caller sent appears in no log line, at any level, whatever
    /// the reason the middleware rejects it for.
    #[tokio::test]
    async fn test_rejected_authorization_header_is_not_logged() {
        const PRESENTED: &str = "presented_key_7f3a9c";
        let app = setup_authn_mock_app("test_api_key").await;
        let cases = [
            (
                HeaderValue::from_str(&format!("Basic {PRESENTED}")).expect("Invalid header value"),
                "Invalid Authorization header format",
            ),
            (
                HeaderValue::from_str(&format!("Bearer {PRESENTED}"))
                    .expect("Invalid header value"),
                "Authentication failed",
            ),
            (
                HeaderValue::from_bytes(format!("Bearer {PRESENTED}\u{e9}").as_bytes())
                    .expect("Invalid header value"),
                "Failed to parse Authorization header",
            ),
        ];

        for (header, expected_warning) in cases {
            let logs = LogCapture::start();

            let (status, _) = send_request_with_header(&app, Some(header)).await;

            assert_eq!(status, StatusCode::FORBIDDEN);
            let lines = logs.lines();
            assert!(
                lines
                    .iter()
                    .any(|line| line.starts_with("WARN") && line.contains(expected_warning)),
                "expected a WARN line containing {expected_warning:?}, got {lines:?}"
            );
            assert!(
                lines.iter().all(|line| !line.contains(PRESENTED)),
                "a log line repeats the Authorization header: {lines:?}"
            );
        }
    }
}
