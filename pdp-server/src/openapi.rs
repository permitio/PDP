use crate::state::AppState;
use axum::body::Body;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{extract::State, routing::get, Router};
use http::HeaderValue;
use utoipa::OpenApi;

pub(crate) const HEALTH_TAG: &str = "Health API";
pub(crate) const AUTHZ_TAG: &str = "Authorization API";
pub(crate) const AUTHZEN_TAG: &str = "AuthZen API";
pub(crate) const TRINO_TAG: &str = "Trino API";

#[derive(OpenApi)]
#[openapi(
    tags(
        (name = HEALTH_TAG, description = "Health check endpoints"),
        (name = AUTHZ_TAG, description = "Authorization endpoints"),
        (name = AUTHZEN_TAG, description = "AuthZen endpoints"),
        (name = TRINO_TAG, description = "Trino integration endpoints"),
    ),
    info(
        title = "Permit.io PDP API",
        description = "Authorization microservice",
        version = "2.0.0"
    )
)]
pub(crate) struct ApiDoc;

/// Handler for the OpenAPI JSON specification endpoint
async fn openapi_json_handler(State(state): State<AppState>) -> impl IntoResponse {
    let openapi_url = state.config.horizon.get_url("/openapi.json");

    match state.horizon_client.get(&openapi_url).send().await {
        Ok(response) => match response.bytes().await {
            Ok(bytes) => match serde_json::from_slice::<serde_json::Value>(&bytes) {
                Ok(json) => axum::Json(json).into_response(),
                Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Invalid JSON").into_response(),
            },
            Err(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Failed to read response").into_response()
            }
        },
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Horizon service unavailable",
        )
            .into_response(),
    }
}

/// Handler for the ReDoc documentation endpoint
async fn redoc_handler(State(state): State<AppState>) -> impl IntoResponse {
    let redoc_url = state.config.horizon.get_url("/redoc");

    match state.horizon_client.get(&redoc_url).send().await {
        Ok(response) => {
            // Extract content-type header before consuming the response
            let content_type = response
                .headers()
                .get("content-type")
                .unwrap_or(&HeaderValue::from_static("text/html"))
                .clone();

            match response.text().await {
                Ok(text) => Response::builder()
                    .header("content-type", content_type)
                    .body(Body::from(text))
                    .unwrap(),
                Err(_) => {
                    (StatusCode::INTERNAL_SERVER_ERROR, "Failed to read response").into_response()
                }
            }
        }
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Horizon service unavailable",
        )
            .into_response(),
    }
}

/// Handler for the Scalar documentation endpoint
async fn scalar_handler(State(state): State<AppState>) -> impl IntoResponse {
    let scalar_url = state.config.horizon.get_url("/scalar");

    match state.horizon_client.get(&scalar_url).send().await {
        Ok(response) => {
            // Extract content-type header before consuming the response
            let content_type = response
                .headers()
                .get("content-type")
                .unwrap_or(&HeaderValue::from_static("text/html"))
                .clone();

            match response.text().await {
                Ok(res_text) => Response::builder()
                    .header("content-type", content_type)
                    .body(Body::from(res_text))
                    .unwrap(),
                Err(_) => {
                    (StatusCode::INTERNAL_SERVER_ERROR, "Failed to read response").into_response()
                }
            }
        }
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Horizon service unavailable",
        )
            .into_response(),
    }
}

/// Creates a router for OpenAPI documentation routes
pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/openapi.json", get(openapi_json_handler))
        .route("/redoc", get(redoc_handler))
        .route("/scalar", get(scalar_handler))
}
