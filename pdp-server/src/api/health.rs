use crate::cache::CacheBackend;
use crate::openapi::HEALTH_TAG;
use crate::state::AppState;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;
use tokio::time::timeout;
use utoipa::{IntoParams, ToSchema};

/// Health check query parameters
#[derive(Debug, Deserialize, ToSchema, IntoParams)]
pub struct HealthQuery {
    /// Whether to include cache health check
    #[serde(default)]
    check_cache: bool,
}

/// Health check response
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct HealthResponse {
    status: String,
    components: ComponentHealth,
    #[serde(skip)]
    status_code: StatusCode,
}

/// Health status of individual components
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ComponentHealth {
    horizon: ComponentStatus,
    opa: ComponentStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache: Option<ComponentStatus>,
}

/// Status of an individual component
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ComponentStatus {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
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
        if let Some(cache) = &self.components.cache {
            if let Some(components) = body["components"].as_object_mut() {
                components.insert(
                    "cache".to_string(),
                    json!({
                        "status": cache.status,
                        "error": cache.error
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

/// Check the health of all components
async fn check_all_health(state: &AppState, check_cache: bool) -> HealthResponse {
    // Check Horizon health (including watchdog)
    let horizon_status = check_horizon_and_watchdog_health(state).await;

    // Check OPA health directly
    let opa_status = match timeout(
        Duration::from_secs_f64(state.config.healthcheck_timeout),
        check_opa_health(state),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => ComponentStatus {
            status: "unhealthy".to_string(),
            error: Some("OPA health check timed out".to_string()),
            details: None,
        },
    };

    // Check Cache health if requested
    let cache_status = if check_cache {
        Some(
            match timeout(
                Duration::from_secs_f64(state.config.healthcheck_timeout),
                check_cache_health(state),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => ComponentStatus {
                    status: "unhealthy".to_string(),
                    error: Some("Cache health check timed out".to_string()),
                    details: None,
                },
            },
        )
    } else {
        None
    };

    // Determine overall status
    let components = ComponentHealth {
        horizon: horizon_status,
        opa: opa_status,
        cache: cache_status,
    };

    let all_healthy = components.horizon.status == "healthy"
        && components.opa.status == "healthy"
        && components
            .cache
            .as_ref()
            .is_none_or(|c| c.status == "healthy");

    HealthResponse {
        status: if all_healthy {
            "healthy".to_string()
        } else {
            "unhealthy".to_string()
        },
        components,
        status_code: if all_healthy {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
    }
}

/// Check Horizon and watchdog health
async fn check_horizon_and_watchdog_health(state: &AppState) -> ComponentStatus {
    // Check watchdog status
    let watchdog_status = match &state.watchdog {
        Some(watchdog) => {
            if watchdog.is_healthy() {
                "healthy"
            } else {
                "unhealthy"
            }
        }
        None => "unknown",
    };

    // Check Horizon health via direct HTTP call
    let horizon_health = match timeout(
        Duration::from_secs_f64(state.config.healthcheck_timeout),
        check_direct_horizon_health(state),
    )
    .await
    {
        Ok(response) => response,
        Err(_) => {
            return ComponentStatus {
                status: "unhealthy".to_string(),
                error: Some("Horizon health check timed out".to_string()),
                details: Some(json!({
                    "watchdog": watchdog_status,
                    "direct_check": "timeout"
                })),
            };
        }
    };

    // Combine the results
    if horizon_health.status == "healthy" {
        // If HTTP check is healthy, the service is healthy regardless of watchdog
        ComponentStatus {
            status: "healthy".to_string(),
            error: None,
            details: Some(json!({
                "watchdog": watchdog_status,
                "direct_check": "success"
            })),
        }
    } else {
        // HTTP check failed, report unhealthy with details about watchdog
        ComponentStatus {
            status: "unhealthy".to_string(),
            error: horizon_health.error,
            details: Some(json!({
                "watchdog": watchdog_status,
                "direct_check": "failed"
            })),
        }
    }
}

/// Check Horizon's health directly through HTTP
async fn check_direct_horizon_health(state: &AppState) -> ComponentStatus {
    // Use the configured Horizon URL from the config
    let horizon_url = state.config.horizon.get_url("/healthy");

    // Use the pre-configured HTTP client for horizon requests
    match state.horizon_client.get(&horizon_url).send().await {
        Ok(response) => {
            if response.status().is_success() {
                ComponentStatus {
                    status: "healthy".to_string(),
                    error: None,
                    details: None,
                }
            } else {
                ComponentStatus {
                    status: "unhealthy".to_string(),
                    error: Some(format!("Horizon returned status {}", response.status())),
                    details: None,
                }
            }
        }
        Err(err) => ComponentStatus {
            status: "unhealthy".to_string(),
            error: Some(format!("Failed to connect to Horizon: {}", err)),
            details: None,
        },
    }
}

/// Check OPA's health by making an HTTP request to its /health endpoint
async fn check_opa_health(state: &AppState) -> ComponentStatus {
    // Use the configured OPA URL from the config
    let opa_url = format!("{}/health", state.config.opa.url);

    // Use the pre-configured HTTP client for OPA requests
    match state.opa_client.get(&opa_url).send().await {
        Ok(response) => {
            if response.status().is_success() {
                ComponentStatus {
                    status: "healthy".to_string(),
                    error: None,
                    details: None,
                }
            } else {
                ComponentStatus {
                    status: "unhealthy".to_string(),
                    error: Some(format!("OPA returned status {}", response.status())),
                    details: None,
                }
            }
        }
        Err(err) => ComponentStatus {
            status: "unhealthy".to_string(),
            error: Some(format!("Failed to connect to OPA: {}", err)),
            details: None,
        },
    }
}

/// Check cache health by performing a deep health check
async fn check_cache_health(state: &AppState) -> ComponentStatus {
    match state.cache.as_ref().health_check().await {
        Ok(_) => ComponentStatus {
            status: "healthy".to_string(),
            error: None,
            details: None,
        },
        Err(err) => ComponentStatus {
            status: "unhealthy".to_string(),
            error: Some(format!("Cache health check failed: {}", err)),
            details: None,
        },
    }
}

/// Health check handler - used for all health check endpoints
#[utoipa::path(
    get,
    path = "/health",
    tag = HEALTH_TAG,
    params(
        HealthQuery
    ),
    responses(
        (status = 200, description = "Service is healthy", body = HealthResponse),
        (status = 503, description = "Service is not healthy", body = HealthResponse)
    )
)]
async fn health_check(
    State(state): State<AppState>,
    Query(params): Query<HealthQuery>,
) -> impl IntoResponse {
    check_all_health(&state, params.check_cache).await
}

/// Ready check handler - alias to health check
#[utoipa::path(
    get,
    path = "/ready",
    tag = HEALTH_TAG,
    params(
        HealthQuery
    ),
    responses(
        (status = 200, description = "Service is ready", body = HealthResponse),
        (status = 503, description = "Service is not ready", body = HealthResponse)
    )
)]
async fn ready_check(state: State<AppState>, params: Query<HealthQuery>) -> impl IntoResponse {
    check_all_health(&state, params.check_cache).await
}

/// Healthy check handler - alias to health check
#[utoipa::path(
    get,
    path = "/healthy",
    tag = HEALTH_TAG,
    params(
        HealthQuery
    ),
    responses(
        (status = 200, description = "Service is healthy", body = HealthResponse),
        (status = 503, description = "Service is not healthy", body = HealthResponse)
    )
)]
async fn healthy_check(state: State<AppState>, params: Query<HealthQuery>) -> impl IntoResponse {
    check_all_health(&state, params.check_cache).await
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(ready_check))
        .route("/healthy", get(healthy_check))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::TestFixture;
    use log::LevelFilter;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn setup_healthy_mocks() -> (MockServer, MockServer) {
        // Setup mock servers for Horizon and OPA
        let horizon_mock = MockServer::start().await;
        let opa_mock = MockServer::start().await;

        // Configure mocks to return healthy responses
        Mock::given(method("GET"))
            .and(path("/healthy"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&horizon_mock)
            .await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&opa_mock)
            .await;

        (horizon_mock, opa_mock)
    }

    async fn setup_unhealthy_horizon_mock() -> (MockServer, MockServer) {
        // Setup mock servers with error responses
        let horizon_mock = MockServer::start().await;
        let opa_mock = MockServer::start().await;

        // Configure Horizon to return unhealthy
        Mock::given(method("GET"))
            .and(path("/healthy"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&horizon_mock)
            .await;

        // Configure OPA to return healthy
        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&opa_mock)
            .await;

        (horizon_mock, opa_mock)
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        // Arrange
        TestFixture::setup_logger(LevelFilter::Info);
        let (horizon_mock, opa_mock) = setup_healthy_mocks().await;
        let config = crate::config::PDPConfig::for_test_with_mocks(&horizon_mock, &opa_mock);
        let fixture = TestFixture::with_config(config, opa_mock, horizon_mock).await;

        // Act
        let response = fixture.get("/health").await;

        // Assert
        response.assert_ok();
    }

    #[tokio::test]
    async fn test_ready_endpoint() {
        // Arrange
        TestFixture::setup_logger(LevelFilter::Info);
        let (horizon_mock, opa_mock) = setup_healthy_mocks().await;
        let config = crate::config::PDPConfig::for_test_with_mocks(&horizon_mock, &opa_mock);
        let fixture = TestFixture::with_config(config, opa_mock, horizon_mock).await;

        // Act
        let response = fixture.get("/ready").await;

        // Assert
        response.assert_ok();
    }

    #[tokio::test]
    async fn test_healthy_endpoint() {
        // Arrange
        TestFixture::setup_logger(LevelFilter::Info);
        let (horizon_mock, opa_mock) = setup_healthy_mocks().await;
        let config = crate::config::PDPConfig::for_test_with_mocks(&horizon_mock, &opa_mock);
        let fixture = TestFixture::with_config(config, opa_mock, horizon_mock).await;

        // Act
        let response = fixture.get("/healthy").await;

        // Assert
        response.assert_ok();
    }

    #[tokio::test]
    async fn test_health_with_cache_check() {
        // Arrange
        TestFixture::setup_logger(LevelFilter::Info);
        let (horizon_mock, opa_mock) = setup_healthy_mocks().await;
        let config = crate::config::PDPConfig::for_test_with_mocks(&horizon_mock, &opa_mock);
        let fixture = TestFixture::with_config(config, opa_mock, horizon_mock).await;

        // Act
        let response = fixture.get("/health?check_cache=true").await;

        // Assert
        response.assert_ok();
        let json_response = response.json();
        assert!(json_response["components"]
            .as_object()
            .unwrap()
            .contains_key("cache"));
        assert_eq!(json_response["components"]["cache"]["status"], "healthy");
    }

    #[tokio::test]
    async fn test_unhealthy_horizon() {
        // Arrange
        let (horizon_mock, opa_mock) = setup_unhealthy_horizon_mock().await;
        let config = crate::config::PDPConfig::for_test_with_mocks(&horizon_mock, &opa_mock);
        let fixture = TestFixture::with_config(config, opa_mock, horizon_mock).await;

        // Act
        let response = fixture.get("/health").await;

        // Assert
        assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
        let json_response = response.json();
        assert_eq!(json_response["status"], "unhealthy");
        assert_eq!(
            json_response["components"]["horizon"]["status"],
            "unhealthy"
        );
        assert_eq!(json_response["components"]["opa"]["status"], "healthy");
    }

    #[tokio::test]
    async fn test_unhealthy_horizon_with_cache_check() {
        // Arrange
        let (horizon_mock, opa_mock) = setup_unhealthy_horizon_mock().await;
        let config = crate::config::PDPConfig::for_test_with_mocks(&horizon_mock, &opa_mock);
        let fixture = TestFixture::with_config(config, opa_mock, horizon_mock).await;

        // Act
        let response = fixture.get("/health?check_cache=true").await;

        // Assert
        assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
        let json_response = response.json();
        assert!(json_response["components"]
            .as_object()
            .unwrap()
            .contains_key("cache"));
        // Cache should be healthy since we're using a NullCache in tests
        assert_eq!(json_response["components"]["cache"]["status"], "healthy");
    }
}
