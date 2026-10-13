use crate::api_key::NO_KEY_YET;
use crate::state::AppState;
use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use log::{debug, warn};
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

    // Debug, not warn: one line per request would flood the log, and the handoff warns already
    let Some(expected) = state.api_key.get() else {
        debug!("Rejecting a request: the PDP has no API key yet");
        return Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .body(NO_KEY_YET.into())
            .expect("Failed to create response");
    };

    // Verify the API key
    let key_matches: bool = api_key
        .as_bytes()
        .ct_eq(expected.as_str().as_bytes())
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
    use crate::api_key::{ApiKey, ApiKeySource, CurrentApiKey, PLACEHOLDER};
    use crate::test_utils::{LogCapture, TestFixture};
    use axum::routing::get;
    use axum::Router;
    use http::HeaderValue;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const TEST_ROUTE: &str = "/test";

    /// Helper function to set up a mock app with authentication middleware
    async fn setup_authn_mock_app(api_key: &str) -> Router {
        let (app, _) = setup_authn_mock_app_with_key(api_key).await;
        app
    }

    /// Sets up the app as `PDP_API_KEY=<api_key>` would, and returns the key it holds, to hand a
    /// key over to it the way horizon does.
    async fn setup_authn_mock_app_with_key(api_key: &str) -> (Router, CurrentApiKey) {
        // Create a TestFixture and get settings from it, but customize the API key
        let fixture = TestFixture::new().await;
        let mut config = fixture.config.clone();
        config.api_key = ApiKeySource::from_env_value(api_key).expect("Invalid API key");
        let state = AppState::for_testing(&config);
        let current = state.api_key.clone();

        let app = Router::new()
            .route(TEST_ROUTE, get(async || (StatusCode::OK, "Authenticated")))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                authentication_middleware,
            ))
            .with_state(state);
        (app, current)
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

    /// `PDP_API_KEY` left at the image's placeholder, and horizon has not handed a key over: the
    /// placeholder is no key, so nothing gets in, and the caller learns the PDP is still starting.
    #[tokio::test]
    async fn test_without_a_key_every_bearer_token_gets_503() {
        for env_value in ["", PLACEHOLDER] {
            let app = setup_authn_mock_app(env_value).await;

            for header in ["Bearer MUST BE DEFINED", "Bearer ", "Bearer test_api_key"] {
                let logs = LogCapture::start();

                let (status, body) = send_request(&app, Some(header)).await;

                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{header:?}");
                assert_eq!(
                    body,
                    "The PDP has no API key yet: it is still starting, or it could not get one. \
                     See the PDP logs."
                );
                let lines = logs.lines();
                assert_eq!(
                    lines,
                    ["DEBUG Rejecting a request: the PDP has no API key yet"],
                    "one debug line per request; the handoff does the warning"
                );
                assert!(
                    lines.iter().all(|line| !line.contains("test_api_key")),
                    "{lines:?}"
                );
            }

            let (status, _) = send_request(&app, None).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn test_key_handed_over_later_is_the_only_key_accepted() {
        let (app, current) = setup_authn_mock_app_with_key(PLACEHOLDER).await;

        current.replace(ApiKey::new("derived_key").unwrap());

        let (status, body) = send_request(&app, Some("Bearer derived_key")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "Authenticated");
        for header in ["Bearer MUST BE DEFINED", "Bearer ", "Bearer derived_ke"] {
            let (status, _) = send_request(&app, Some(header)).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{header:?}");
        }
    }

    #[tokio::test]
    async fn test_rotated_key_replaces_the_old_one() {
        let (app, current) = setup_authn_mock_app_with_key("").await;
        current.replace(ApiKey::new("first_key").unwrap());

        current.replace(ApiKey::new("second_key").unwrap());

        let (status, _) = send_request(&app, Some("Bearer second_key")).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = send_request(&app, Some("Bearer first_key")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
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
