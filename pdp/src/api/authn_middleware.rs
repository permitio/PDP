use crate::state::AppState;
use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use log::warn;

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
        Ok(header_str) => {
            warn!(
                "Invalid Authorization header format, missing 'Bearer ' prefix: {}",
                header_str
            );
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(
                    "You are not authorized to access this resource, please check your API key."
                        .into(),
                )
                .expect("Failed to create response");
        }
        Err(e) => {
            warn!("Failed to parse Authorization header to string: {}", e);
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
    if api_key != state.settings.api_key {
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
    use crate::test::{create_test_state, setup_test_settings};
    use axum::routing::get;
    use axum::Router;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const TEST_ROUTE: &'static str = "/test";

    /// Helper function to set up a mock app with authentication middleware
    async fn setup_authn_mock_app(api_key: &str) -> Router {
        let mut settings = setup_test_settings().await;
        settings.api_key = api_key.to_string();
        let state = create_test_state(settings);

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
}
