use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// AuthZen error codes as defined in the specification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthZenErrorCode {
    InvalidRequest,
    Unauthorized,
    Forbidden,
    InternalError,
}

impl AuthZenErrorCode {
    /// Get the corresponding HTTP status code
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidRequest => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// AuthZen error response - compliant with spec section 12.1.11
/// The spec requires error responses to be plain strings, not structured JSON
#[derive(Debug, Clone)]
pub struct AuthZenError {
    pub code: AuthZenErrorCode,
    pub message: String,
}

/// AuthZen error details for OpenAPI documentation only
/// This is NOT used in actual responses, only for OpenAPI schema generation
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AuthZenErrorDetails {
    pub code: String,
    pub message: String,
}

impl AuthZenError {
    /// Create a new AuthZen error
    pub fn new(code: AuthZenErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Create an invalid_request error (400)
    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(AuthZenErrorCode::InvalidRequest, message)
    }

    /// Create an unauthorized error (401)
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(AuthZenErrorCode::Unauthorized, message)
    }

    /// Create a forbidden error (403)
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(AuthZenErrorCode::Forbidden, message)
    }

    /// Create an internal_error (500)
    pub fn internal_error(message: impl Into<String>) -> Self {
        Self::new(AuthZenErrorCode::InternalError, message)
    }
}

impl IntoResponse for AuthZenError {
    fn into_response(self) -> Response {
        // AuthZen spec section 12.1.11 requires error responses to be plain strings
        (self.code.status_code(), self.message).into_response()
    }
}

/// Convert internal errors to AuthZen format
impl From<crate::errors::ApiError> for AuthZenError {
    fn from(err: crate::errors::ApiError) -> Self {
        match err.status_code {
            StatusCode::UNAUTHORIZED => AuthZenError::unauthorized("Authentication required"),
            StatusCode::FORBIDDEN => AuthZenError::forbidden("Access denied"),
            StatusCode::BAD_REQUEST => AuthZenError::invalid_request(err.detail),
            _ => {
                log::error!("Internal error converted to AuthZen format: {err:?}");
                AuthZenError::internal_error("Internal server error")
            }
        }
    }
}

/// Convert OPA forwarding errors to AuthZen format
impl From<crate::opa_client::ForwardingError> for AuthZenError {
    fn from(err: crate::opa_client::ForwardingError) -> Self {
        log::error!("OPA forwarding error: {err:?}");
        // Use generic message to avoid leaking internal implementation details
        AuthZenError::internal_error("Internal server error")
    }
}
