use super::checkers::{
    check_cache_health, check_horizon_health, check_opa_health, run_health_check,
};
use super::models::{
    ComponentHealth, ComponentStatus, HealthQuery, HealthResponse, HealthStatusType,
};
use crate::openapi::HEALTH_TAG;
use crate::state::AppState;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Router,
};
use log::{debug, info};

/// Check the health of all components
async fn check_all_health(state: &AppState, check_cache: bool) -> HealthResponse {
    let horizon_handle = tokio::spawn(run_health_check(
        "Horizon",
        check_horizon_health,
        state.clone(),
    ));
    let opa_handle = tokio::spawn(run_health_check("OPA", check_opa_health, state.clone()));

    let cache_handle_opt = if check_cache {
        Some(tokio::spawn(run_health_check(
            "Cache",
            check_cache_health,
            state.clone(),
        )))
    } else {
        None
    };

    let horizon_status = horizon_handle.await.unwrap_or_else(|e| {
        log::error!("Horizon check task panicked: {e:?}");
        ComponentStatus {
            status: HealthStatusType::Error,
            error: Some("Horizon check task failed".to_string()),
            details: None,
        }
    });

    let opa_status = opa_handle.await.unwrap_or_else(|e| {
        log::error!("OPA check task panicked: {e:?}");
        ComponentStatus {
            status: HealthStatusType::Error,
            error: Some("OPA check task failed".to_string()),
            details: None,
        }
    });

    let cache_status = if let Some(cache_handle) = cache_handle_opt {
        Some(cache_handle.await.unwrap_or_else(|e| {
            log::error!("Cache check task panicked: {e:?}");
            ComponentStatus {
                status: HealthStatusType::Error,
                error: Some("Cache check task failed".to_string()),
                details: None,
            }
        }))
    } else {
        None
    };

    // Determine overall status
    let components = ComponentHealth {
        horizon: horizon_status,
        opa: opa_status,
        cache: cache_status,
    };

    let all_healthy = components.horizon.status == HealthStatusType::Ok
        && components.opa.status == HealthStatusType::Ok
        && components
            .cache
            .as_ref()
            .is_none_or(|c| c.status == HealthStatusType::Ok);

    if !all_healthy {
        let mut issues = Vec::new();

        if components.horizon.status != HealthStatusType::Ok {
            issues.push(format!(
                "horizon: {}",
                components
                    .horizon
                    .error
                    .as_deref()
                    .unwrap_or("unknown error")
            ));
        }

        if components.opa.status != HealthStatusType::Ok {
            issues.push(format!(
                "opa: {}",
                components.opa.error.as_deref().unwrap_or("unknown error")
            ));
        }

        if let Some(cache) = &components.cache {
            if cache.status != HealthStatusType::Ok {
                issues.push(format!(
                    "cache: {}",
                    cache.error.as_deref().unwrap_or("unknown error")
                ));
            }
        }

        info!("Health check failed: {}", issues.join(", "));
    } else {
        debug!("Health check passed for all components");
    }
    HealthResponse {
        status: if all_healthy {
            HealthStatusType::Ok
        } else {
            HealthStatusType::Error
        },
        components,
        status_code: if all_healthy {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
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
async fn ready_check(
    State(state): State<AppState>,
    Query(params): Query<HealthQuery>,
) -> impl IntoResponse {
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
async fn healthy_check(
    State(state): State<AppState>,
    Query(params): Query<HealthQuery>,
) -> impl IntoResponse {
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
    use std::time::{Duration, Instant};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn setup_healthy_mocks() -> (MockServer, MockServer) {
        let horizon_mock = MockServer::start().await;
        let opa_mock = MockServer::start().await;

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
        let horizon_mock = MockServer::start().await;
        let opa_mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/healthy"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&horizon_mock)
            .await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&opa_mock)
            .await;

        (horizon_mock, opa_mock)
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        TestFixture::setup_logger(LevelFilter::Info);
        let (horizon_mock, opa_mock) = setup_healthy_mocks().await;
        let config = crate::config::PDPConfig::for_test_with_mocks(&horizon_mock, &opa_mock);
        let fixture = TestFixture::with_config(config, opa_mock, horizon_mock).await;
        let response = fixture.get("/health").await;
        response.assert_ok();
        let json_response = response.json();
        assert_eq!(json_response["status"].as_str().unwrap(), "ok");
        assert_eq!(
            json_response["components"]["horizon"]["status"]
                .as_str()
                .unwrap(),
            "ok"
        );
        assert_eq!(
            json_response["components"]["opa"]["status"]
                .as_str()
                .unwrap(),
            "ok"
        );
    }

    #[tokio::test]
    async fn test_ready_endpoint() {
        TestFixture::setup_logger(LevelFilter::Info);
        let (horizon_mock, opa_mock) = setup_healthy_mocks().await;
        let config = crate::config::PDPConfig::for_test_with_mocks(&horizon_mock, &opa_mock);
        let fixture = TestFixture::with_config(config, opa_mock, horizon_mock).await;
        let response = fixture.get("/ready").await;
        response.assert_ok();
        let json_response = response.json();
        assert_eq!(json_response["status"].as_str().unwrap(), "ok");
    }

    #[tokio::test]
    async fn test_healthy_endpoint() {
        TestFixture::setup_logger(LevelFilter::Info);
        let (horizon_mock, opa_mock) = setup_healthy_mocks().await;
        let config = crate::config::PDPConfig::for_test_with_mocks(&horizon_mock, &opa_mock);
        let fixture = TestFixture::with_config(config, opa_mock, horizon_mock).await;
        let response = fixture.get("/healthy").await;
        response.assert_ok();
        let json_response = response.json();
        assert_eq!(json_response["status"].as_str().unwrap(), "ok");
    }

    #[tokio::test]
    async fn test_health_with_cache_check() {
        TestFixture::setup_logger(LevelFilter::Info);
        let (horizon_mock, opa_mock) = setup_healthy_mocks().await;
        let config = crate::config::PDPConfig::for_test_with_mocks(&horizon_mock, &opa_mock);
        let fixture = TestFixture::with_config(config, opa_mock, horizon_mock).await;
        let response = fixture.get("/health?check_cache=true").await;
        response.assert_ok();
        let json_response = response.json();
        assert_eq!(json_response["status"].as_str().unwrap(), "ok");
        assert!(json_response["components"]
            .as_object()
            .unwrap()
            .contains_key("cache"));
        assert_eq!(
            json_response["components"]["cache"]["status"]
                .as_str()
                .unwrap(),
            "ok"
        );
    }

    #[tokio::test]
    async fn test_unhealthy_horizon() {
        TestFixture::setup_logger(LevelFilter::Info);
        let (horizon_mock, opa_mock) = setup_unhealthy_horizon_mock().await;
        let config = crate::config::PDPConfig::for_test_with_mocks(&horizon_mock, &opa_mock);
        let fixture = TestFixture::with_config(config, opa_mock, horizon_mock).await;
        let response = fixture.get("/health").await;
        assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
        let json_response = response.json();
        assert_eq!(json_response["status"].as_str().unwrap(), "error");
        assert_eq!(
            json_response["components"]["horizon"]["status"]
                .as_str()
                .unwrap(),
            "error"
        );
        assert_eq!(
            json_response["components"]["opa"]["status"]
                .as_str()
                .unwrap(),
            "ok"
        );
    }

    #[tokio::test]
    async fn test_unhealthy_horizon_with_cache_check() {
        TestFixture::setup_logger(LevelFilter::Info);
        let (horizon_mock, opa_mock) = setup_unhealthy_horizon_mock().await;
        let config = crate::config::PDPConfig::for_test_with_mocks(&horizon_mock, &opa_mock);
        let fixture = TestFixture::with_config(config, opa_mock, horizon_mock).await;
        let response = fixture.get("/health?check_cache=true").await;
        assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
        let json_response = response.json();
        assert_eq!(json_response["status"].as_str().unwrap(), "error");
        assert!(json_response["components"]
            .as_object()
            .unwrap()
            .contains_key("cache"));
        assert_eq!(
            json_response["components"]["cache"]["status"]
                .as_str()
                .unwrap(),
            "ok"
        );
        assert_eq!(
            json_response["components"]["horizon"]["status"]
                .as_str()
                .unwrap(),
            "error"
        );
    }

    #[tokio::test]
    async fn test_health_check_concurrency_and_timeout() {
        TestFixture::setup_logger(LevelFilter::Info);
        let horizon_mock = MockServer::start().await;
        let opa_mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/healthy"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(1)))
            .mount(&horizon_mock)
            .await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(1)))
            .mount(&opa_mock)
            .await;

        let mut config = crate::config::PDPConfig::for_test_with_mocks(&horizon_mock, &opa_mock);
        config.healthcheck_timeout = 0.5;
        let fixture = TestFixture::with_config(config, opa_mock, horizon_mock).await;

        let start_time = Instant::now();
        let response_with_cache = fixture.get("/health?check_cache=true").await;
        let duration_with_cache = start_time.elapsed();

        assert_eq!(response_with_cache.status, StatusCode::SERVICE_UNAVAILABLE);
        let json_response_with_cache = response_with_cache.json();
        assert_eq!(
            json_response_with_cache["status"].as_str().unwrap(),
            "error"
        );
        assert_eq!(
            json_response_with_cache["components"]["horizon"]["status"]
                .as_str()
                .unwrap(),
            "error"
        );
        assert!(json_response_with_cache["components"]["horizon"]["error"]
            .as_str()
            .unwrap()
            .contains("timed out"));
        assert_eq!(
            json_response_with_cache["components"]["opa"]["status"]
                .as_str()
                .unwrap(),
            "error"
        );
        assert!(json_response_with_cache["components"]["opa"]["error"]
            .as_str()
            .unwrap()
            .contains("timed out"));
        assert_eq!(
            json_response_with_cache["components"]["cache"]["status"]
                .as_str()
                .unwrap(),
            "ok"
        );

        assert!(
            duration_with_cache < Duration::from_millis(750),
            "Concurrent check took too long: {duration_with_cache:?}"
        );
    }

    #[tokio::test]
    async fn test_health_check_success_timing() {
        TestFixture::setup_logger(LevelFilter::Info);
        let (horizon_mock_success, opa_mock_success) = setup_healthy_mocks().await;

        let mut config =
            crate::config::PDPConfig::for_test_with_mocks(&horizon_mock_success, &opa_mock_success);
        config.healthcheck_timeout = 2.0;
        let fixture_success =
            TestFixture::with_config(config, opa_mock_success, horizon_mock_success).await;

        let start_time_success = Instant::now();
        let response_success = fixture_success.get("/health?check_cache=true").await;
        let duration_success = start_time_success.elapsed();

        response_success.assert_ok();
        let json_success = response_success.json();
        assert_eq!(json_success["status"].as_str().unwrap(), "ok");
        assert_eq!(
            json_success["components"]["horizon"]["status"]
                .as_str()
                .unwrap(),
            "ok"
        );
        assert_eq!(
            json_success["components"]["opa"]["status"]
                .as_str()
                .unwrap(),
            "ok"
        );
        assert_eq!(
            json_success["components"]["cache"]["status"]
                .as_str()
                .unwrap(),
            "ok"
        );

        assert!(
            duration_success < Duration::from_millis(1500),
            "Concurrent successful check took too long: {duration_success:?}"
        );
    }

    /*
    #[tokio::test]
    async fn test_health_check_reports_panics_gracefully() {
        TestFixture::setup_logger(LevelFilter::Info);
        let (horizon_mock, opa_mock) = setup_healthy_mocks().await; // All external deps are healthy
        let mut config = crate::config::PDPConfig::for_test_with_mocks(&horizon_mock, &opa_mock);
        config.healthcheck_timeout = 0.5; // 500ms timeout

        let app_state = AppState::new_with_custom_components(
            Arc::new(config.clone()), // Clone config for AppState
            Arc::new(reqwest::Client::new()), // For OPA
            Arc::new(reqwest::Client::new()), // For Horizon
            Arc::new(crate::cache::Cache::Null(crate::cache::null::NullCache::new())), // For Cache
            None, // No watchdog
        ).await;

        // This function will intentionally panic
        async fn panic_check_fn(_state: &AppState) -> ComponentStatus {
            panic!("Intentional panic in health checker");
        }

        let horizon_status_fut = run_health_check("Horizon", check_horizon_health, app_state.clone());
        // Use the new panic_check_fn
        let panic_checker_status_fut = run_health_check("PanicChecker", panic_check_fn, app_state.clone());
        let cache_status_fut = run_health_check("Cache", check_cache_health, app_state.clone());

        let (horizon_status, panic_status, cache_status_opt) = tokio::join!(
            horizon_status_fut,
            panic_checker_status_fut,
            async { Some(cache_status_fut.await) } // Wrap in Some for consistency
        );

        let components = ComponentHealth {
            horizon: horizon_status,
            opa: panic_status, // This is the result from PanicChecker
            cache: cache_status_opt,
        };

        let all_healthy = components.horizon.status == HealthStatusType::Ok
            && components.opa.status == HealthStatusType::Ok
            && components.cache.as_ref().map_or(true, |c| c.status == HealthStatusType::Ok);

        let health_response = HealthResponse {
            status: if all_healthy { HealthStatusType::Ok } else { HealthStatusType::Error },
            components,
            status_code: if all_healthy { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE },
        };

        assert_eq!(health_response.status, HealthStatusType::Error);
        assert_eq!(health_response.components.horizon.status, HealthStatusType::Ok);
        assert_eq!(health_response.components.opa.status, HealthStatusType::Error); // OPA (PanicChecker) should be error
        // The error message now comes from run_health_check for panics
        assert!(health_response.components.opa.error.as_ref().unwrap().contains("PanicChecker check task failed"));
        assert_eq!(health_response.components.cache.as_ref().unwrap().status, HealthStatusType::Ok);

        // fixture.shutdown().await; // fixture is not created in this test setup, remove if not needed or adapt
    }
    */
}
