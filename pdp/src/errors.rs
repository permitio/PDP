use axum::response::IntoResponse;
use axum::Json;
use http::StatusCode;
use serde_json::json;

#[derive(Debug, Clone)]
pub struct ApiError {
    pub detail: String,
    pub status_code: StatusCode,
}

impl ApiError {
    /// Create a new ApiError with a detail message and status code
    pub fn new<S: ToString>(detail: S, status_code: StatusCode) -> Self {
        Self {
            detail: detail.to_string(),
            status_code,
        }
    }

    /// Create new Internal Server Error (500) with a detail message
    pub fn internal<S: ToString>(detail: S) -> Self {
        Self::new(detail, StatusCode::INTERNAL_SERVER_ERROR)
    }

    /// Create new Bad Request Error (400) with a detail message
    #[allow(dead_code)]
    pub fn bad_request<S: ToString>(detail: S) -> Self {
        Self::new(detail, StatusCode::BAD_REQUEST)
    }

    /// Create new Bad Gateway (502) with a detail message
    pub fn bad_gateway<S: ToString>(detail: S) -> Self {
        Self::new(detail, StatusCode::BAD_GATEWAY)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let status_code = self.status_code;
        let body = json!({
            "detail": self.detail,
        });
        (status_code, Json(body)).into_response()
    }
}
