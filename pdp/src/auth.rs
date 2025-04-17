use axum::{
    body::Body,
    http::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use log::warn;
use serde_json::json;

use crate::state::AppState;

#[derive(Debug)]
pub struct ApiKeyAuth;

#[derive(Debug)]
pub enum AuthError {
    MissingToken,
    InvalidToken,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::MissingToken => (StatusCode::UNAUTHORIZED, "Missing API token"),
            AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid API token"),
        };
        let body = axum::Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

// API key authentication middleware
pub async fn require_auth(
    state: AppState,
    req: Request<Body>,
    next: Next,
) -> Result<Response, AuthError> {
    // Extract the token from the authorization header
    let auth_header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .and_then(|auth_value| {
            if auth_value.to_lowercase().starts_with("bearer ") {
                // Remove the "Bearer " prefix
                Some(auth_value[7..].to_string())
            } else {
                None
            }
        });

    let token = match auth_header {
        Some(token) => token,
        None => {
            warn!("Attempt to access protected resource without providing 'Authorization' header");
            return Err(AuthError::MissingToken);
        }
    };

    // Verify the API key
    if token != state.settings.api_key {
        warn!("Attempt to access protected resource with invalid API key");
        return Err(AuthError::InvalidToken);
    }

    // Token is valid, proceed with request
    Ok(next.run(req).await)
}
