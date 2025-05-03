use crate::openapi::HEALTH_TAG;
use crate::state::AppState;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

/// Basic health check response
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct Health {
    status: &'static str,
    details: Option<Value>,
    #[serde(skip)]
    status_code: StatusCode,
}

impl IntoResponse for Health {
    fn into_response(self) -> Response {
        let mut body = serde_json::json!({
            "status": self.status
        });

        if let Some(Value::Object(obj)) = self.details {
            for (key, value) in obj {
                body[key] = value;
            }
        }

        (
            self.status_code,
            serde_json::to_string(&body).unwrap_or_default(),
        )
            .into_response()
    }
}

/// Basic health check handler
#[utoipa::path(
    get,
    path = "/health",
    tag = HEALTH_TAG,
    responses(
        (status = 200, description = "Service is healthy", body = Health)
    )
)]
async fn health_check() -> impl IntoResponse {
    Health {
        status: "ok",
        details: None,
        status_code: StatusCode::OK,
    }
}

/// Readiness check handler
#[utoipa::path(
    get,
    path = "/ready",
    tag = HEALTH_TAG,
    responses(
        (status = 200, description = "Service is ready", body = Health),
        (status = 503, description = "Service is not ready", body = Health)
    )
)]
async fn ready_check(State(state): State<AppState>) -> impl IntoResponse {
    if state.health_check().await {
        Health {
            status: "ok",
            details: Some(serde_json::json!({
                "cache_status": "healthy",
                "engine_status": "healthy"
            })),
            status_code: StatusCode::OK,
        }
    } else {
        Health {
            status: "error",
            details: Some(serde_json::json!({
                "error": "One or more components are not healthy"
            })),
            status_code: StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

/// Startup check handler
#[utoipa::path(
    get,
    path = "/startup",
    tag = HEALTH_TAG,
    responses(
        (status = 200, description = "Service has started", body = Health),
        (status = 503, description = "Service is still starting", body = Health)
    )
)]
async fn startup_check(State(state): State<AppState>) -> impl IntoResponse {
    if state.health_check().await {
        Health {
            status: "ok",
            details: Some(serde_json::json!({
                "initialized": true
            })),
            status_code: StatusCode::OK,
        }
    } else {
        Health {
            status: "error",
            details: Some(serde_json::json!({
                "error": "Service initialization incomplete"
            })),
            status_code: StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

pub fn router() -> Router<AppState> {
    // TODO add /healthy endpoint to check if the service is healthy on top of PDP's /healthy
    Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(ready_check))
        .route("/startup", get(startup_check))
}

#[cfg(test)]
mod test {
    use crate::test_utils::TestFixture;
    use log::LevelFilter;
    use serde_json::json;

    #[tokio::test]
    async fn test_health_endpoint() {
        // Set custom log level for this test
        TestFixture::setup_logger(LevelFilter::Info);

        let fixture = TestFixture::new().await;
        let response = fixture.get("/health").await;

        response.assert_ok();
        assert_eq!(
            response.json,
            json!({
                "status": "ok",
            })
        );
    }

    #[tokio::test]
    async fn test_ready_endpoint() {
        let fixture = TestFixture::new().await;
        let response = fixture.get("/ready").await;

        response.assert_ok();
        assert_eq!(
            response.json,
            json!({
                "cache_status": "healthy",
                "engine_status": "healthy",
                "status": "ok",
            })
        );
    }

    #[tokio::test]
    async fn test_startup_endpoint() {
        let fixture = TestFixture::new().await;
        let response = fixture.get("/startup").await;

        response.assert_ok();
        assert_eq!(
            response.json,
            json!({
                "initialized": true,
                "status": "ok",
            })
        );
    }
}
