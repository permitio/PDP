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

    match state.get_public_horizon_route(&openapi_url).send().await {
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

    match state.get_public_horizon_route(&redoc_url).send().await {
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

    match state.get_public_horizon_route(&scalar_url).send().await {
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

#[cfg(test)]
mod tests {
    use crate::api_key::ApiKeySource;
    use crate::test_utils::TestFixture;
    use http::header::AUTHORIZATION;
    use serde_json::json;
    use wiremock::{matchers, Mock, ResponseTemplate};

    async fn mount_docs(fixture: &TestFixture) {
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/openapi.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"openapi": "3.1.0"})))
            .mount(&fixture.horizon_mock)
            .await;
        for path in ["/redoc", "/scalar"] {
            Mock::given(matchers::method("GET"))
                .and(matchers::path(path))
                .respond_with(ResponseTemplate::new(200).set_body_string("<html></html>"))
                .mount(&fixture.horizon_mock)
                .await;
        }
    }

    async fn authorization_horizon_received(fixture: &TestFixture) -> Vec<Option<String>> {
        let requests = fixture.horizon_mock.received_requests().await.unwrap();
        requests
            .iter()
            .map(|request| {
                let header = request.headers.get(AUTHORIZATION)?;
                Some(String::from_utf8_lossy(header.as_bytes()).into_owned())
            })
            .collect()
    }

    #[tokio::test]
    async fn test_docs_are_served_before_the_pdp_has_a_key() {
        let fixture = TestFixture::with_config_modifier(|config| {
            config.api_key = ApiKeySource::Horizon;
        })
        .await;
        mount_docs(&fixture).await;

        for path in ["/openapi.json", "/redoc", "/scalar"] {
            fixture.get(path).await.assert_ok();
        }

        assert_eq!(
            authorization_horizon_received(&fixture).await,
            [None, None, None]
        );
    }

    #[tokio::test]
    async fn test_docs_requests_present_the_key_when_there_is_one() {
        let fixture = TestFixture::new().await;
        mount_docs(&fixture).await;

        let response = fixture.get("/openapi.json").await;

        response.assert_ok();
        assert_eq!(
            authorization_horizon_received(&fixture).await,
            [Some(fixture.auth_header())]
        );
    }
}
