use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::{IntoParams, ToSchema};

/// Represents the health status of a component or the overall service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum HealthStatusType {
    #[serde(rename = "ok")]
    Ok,
    #[serde(rename = "error")]
    Error,
}

/// Health check query parameters
#[derive(Debug, Deserialize, ToSchema, IntoParams)]
pub struct HealthQuery {
    /// Whether to include cache health check
    #[serde(default)]
    pub check_cache: bool,
}

/// Health check response
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct HealthResponse {
    pub status: HealthStatusType,
    pub components: ComponentHealth,
    #[serde(skip)]
    pub status_code: StatusCode,
}

/// Health status of individual components
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ComponentHealth {
    pub horizon: ComponentStatus,
    pub opa: ComponentStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache: Option<ComponentStatus>,
}

/// Status of an individual component
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ComponentStatus {
    pub status: HealthStatusType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl IntoResponse for HealthResponse {
    fn into_response(self) -> Response {
        let mut body = json!({
            "status": self.status,
            "components": {
                "horizon": {
                    "status": self.components.horizon.status,
                    "error": self.components.horizon.error,
                    "details": self.components.horizon.details
                },
                "opa": {
                    "status": self.components.opa.status,
                    "error": self.components.opa.error
                }
            }
        });

        // Include cache component in response if present
        if let Some(cache_status) = &self.components.cache {
            if let Some(components_map) = body["components"].as_object_mut() {
                components_map.insert(
                    "cache".to_string(),
                    json!({
                        "status": cache_status.status,
                        "error": cache_status.error
                    }),
                );
            }
        }

        (
            self.status_code,
            serde_json::to_string(&body).unwrap_or_default(),
        )
            .into_response()
    }
}
