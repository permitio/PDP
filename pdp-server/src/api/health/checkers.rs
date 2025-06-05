use super::models::ComponentStatus;
use super::models::HealthStatusType;
use crate::cache::CacheBackend;
use crate::state::AppState;
use serde_json::json;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;
use tokio::time::timeout;

pub fn check_horizon_health<'a>(
    state: &'a AppState,
) -> Pin<Box<dyn Future<Output = ComponentStatus> + Send + 'a>> {
    let app_state_for_async = state.clone();

    Box::pin(async move {
        let watchdog_status = match &app_state_for_async.watchdog {
            Some(watchdog) => {
                if watchdog.is_healthy() {
                    HealthStatusType::Ok
                } else {
                    HealthStatusType::Error
                }
            }
            None => HealthStatusType::Error,
        };

        let horizon_direct_health = check_horizon_health_directly(&app_state_for_async).await;

        if horizon_direct_health.status == HealthStatusType::Ok {
            ComponentStatus {
                status: HealthStatusType::Ok,
                error: None,
                details: Some(json!({
                    "watchdog": watchdog_status,
                    "direct_check": "success"
                })),
            }
        } else {
            ComponentStatus {
                status: horizon_direct_health.status,
                error: horizon_direct_health.error,
                details: Some(json!({
                    "watchdog": {
                        "status": watchdog_status,
                        "message": "Watchdog status when direct Horizon health check was not Ok."
                    }
                })),
            }
        }
    })
}

pub fn check_opa_health<'a>(
    state: &'a AppState,
) -> Pin<Box<dyn Future<Output = ComponentStatus> + Send + 'a>> {
    let opa_url_owned = format!("{}/health", state.config.opa.url);
    let opa_client_clone = state.opa_client.clone();

    Box::pin(async move {
        match opa_client_clone.get(&opa_url_owned).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    ComponentStatus {
                        status: HealthStatusType::Ok,
                        error: None,
                        details: None,
                    }
                } else {
                    ComponentStatus {
                        status: HealthStatusType::Error,
                        error: Some(format!("OPA returned status {}", response.status())),
                        details: None,
                    }
                }
            }
            Err(err) => ComponentStatus {
                status: HealthStatusType::Error,
                error: Some(format!("Failed to connect to OPA: {}", err)),
                details: None,
            },
        }
    })
}

pub fn check_cache_health<'a>(
    state: &'a AppState,
) -> Pin<Box<dyn Future<Output = ComponentStatus> + Send + 'a>> {
    let cache_clone = state.cache.clone();
    Box::pin(async move {
        match cache_clone.as_ref().health_check().await {
            Ok(_) => ComponentStatus {
                status: HealthStatusType::Ok,
                error: None,
                details: None,
            },
            Err(err) => ComponentStatus {
                status: HealthStatusType::Error,
                error: Some(format!("Cache health check failed: {}", err)),
                details: None,
            },
        }
    })
}

pub async fn run_health_check<F>(
    checker_name: &'static str,
    check_fn: F,
    state: AppState,
) -> ComponentStatus
where
    F: for<'a> FnOnce(&'a AppState) -> Pin<Box<dyn Future<Output = ComponentStatus> + Send + 'a>>
        + Send
        + 'static,
{
    let timeout_duration = Duration::from_secs_f64(state.config.healthcheck_timeout);
    match timeout(timeout_duration, check_fn(&state)).await {
        Ok(status) => status,
        Err(_) => ComponentStatus {
            status: HealthStatusType::Error,
            error: Some(format!(
                "{} health check timed out after {} seconds",
                checker_name, state.config.healthcheck_timeout
            )),
            details: None,
        },
    }
}

/// Check Horizon's health directly through HTTP
async fn check_horizon_health_directly(state: &AppState) -> ComponentStatus {
    let horizon_url = state.config.horizon.get_url("/healthy");
    match state.horizon_client.get(&horizon_url).send().await {
        Ok(response) => {
            if response.status().is_success() {
                ComponentStatus {
                    status: HealthStatusType::Ok,
                    error: None,
                    details: None,
                }
            } else {
                ComponentStatus {
                    status: HealthStatusType::Error,
                    error: Some(format!("Horizon returned status {}", response.status())),
                    details: None,
                }
            }
        }
        Err(err) => ComponentStatus {
            status: HealthStatusType::Error,
            error: Some(format!("Failed to connect to Horizon: {}", err)),
            details: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::health::models::HealthStatusType;
    use crate::cache::null::NullCache;
    use crate::cache::Cache;
    use crate::config::opa::OpaConfig;
    use crate::config::PDPConfig;
    use crate::state::AppState;
    use reqwest::Client;
    use std::sync::Arc;
    use tokio::time::sleep;

    async fn create_test_app_state(health_timeout_secs: f64) -> AppState {
        let pdp_config = PDPConfig {
            healthcheck_timeout: health_timeout_secs,
            opa: OpaConfig {
                url: "http://localhost:1234".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };

        AppState {
            config: Arc::new(pdp_config),
            opa_client: Arc::new(Client::new()),
            horizon_client: Arc::new(Client::new()),
            cache: Arc::new(Cache::Null(NullCache::new())),
            watchdog: None,
        }
    }

    #[tokio::test]
    async fn test_run_health_check_successful_within_timeout() {
        let app_state = create_test_app_state(0.1).await;

        fn successful_check<'a>(
            _state: &'a AppState,
        ) -> Pin<Box<dyn Future<Output = ComponentStatus> + Send + 'a>> {
            Box::pin(async move {
                sleep(Duration::from_millis(50)).await;
                ComponentStatus {
                    status: HealthStatusType::Ok,
                    error: None,
                    details: None,
                }
            })
        }

        let result = run_health_check("FastSuccess", successful_check, app_state).await;
        assert_eq!(result.status, HealthStatusType::Ok);
        assert!(result.error.is_none());
    }

    #[tokio::test]
    async fn test_run_health_check_times_out() {
        let app_state = create_test_app_state(0.1).await;

        fn slow_check<'a>(
            _state: &'a AppState,
        ) -> Pin<Box<dyn Future<Output = ComponentStatus> + Send + 'a>> {
            Box::pin(async move {
                sleep(Duration::from_millis(200)).await;
                ComponentStatus {
                    status: HealthStatusType::Ok,
                    error: None,
                    details: None,
                }
            })
        }

        let result = run_health_check("SlowChecker", slow_check, app_state).await;
        assert_eq!(result.status, HealthStatusType::Error);
        assert_eq!(
            result.error,
            Some("SlowChecker health check timed out after 0.1 seconds".to_string())
        );
    }

    #[tokio::test]
    async fn test_run_health_check_fails_within_timeout() {
        let app_state = create_test_app_state(0.1).await;

        fn failing_check<'a>(
            _state: &'a AppState,
        ) -> Pin<Box<dyn Future<Output = ComponentStatus> + Send + 'a>> {
            Box::pin(async move {
                sleep(Duration::from_millis(50)).await;
                ComponentStatus {
                    status: HealthStatusType::Error,
                    error: Some("mock failure".to_string()),
                    details: None,
                }
            })
        }

        let result = run_health_check("FastFailure", failing_check, app_state).await;
        assert_eq!(result.status, HealthStatusType::Error);
        assert_eq!(result.error, Some("mock failure".to_string()));
    }
}
