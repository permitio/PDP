use crate::errors::ApiError;
use crate::headers::ClientCacheControl;
use crate::opa_client::cached::{query_allowed_bulk_cached, AllowedQuery, BulkAuthorizationResult};
use crate::openapi::AUTHZ_TAG;
use crate::state::AppState;
use axum::{
    extract::{Json, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use http::{header::CACHE_CONTROL, StatusCode};

#[utoipa::path(
    post,
    path = "/allowed/bulk",
    tag = AUTHZ_TAG,
    request_body = Vec<AllowedQuery>,
    params(
        ("Authorization" = String, Header, description = "Authorization header"),
        ("Cache-Control" = String, Header, description = "Cache control directives"),
    ),
    responses(
        (status = 200, description = "Bulk authorization check completed successfully", body = BulkAuthorizationResult),
        (status = 422, description = "Invalid request payload"),
        (status = 500, description = "Internal server error")
    )
)]
pub(super) async fn allowed_bulk_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(queries): Json<Vec<AllowedQuery>>,
) -> Response {
    // Parse client cache control headers
    let cache_control = ClientCacheControl::from_header_value(headers.get(CACHE_CONTROL));

    match query_allowed_bulk_cached(&state, &queries, &cache_control).await {
        Ok(result) => (StatusCode::OK, Json(result)).into_response(),
        Err(err) => {
            log::error!("Failed to send request to OPA: {err}");
            ApiError::from(err).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestFixture;
    use http::{Method, StatusCode};
    use serde_json::json;

    #[tokio::test]
    async fn test_handle_allowed_bulk_success() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Create test queries
        let test_queries = json!([
            {
                "user": {
                    "key": "test-user-1",
                    "first_name": "Test",
                    "last_name": "User",
                    "email": "test1@example.com",
                    "attributes": {}
                },
                "action": "read",
                "resource": {
                    "type": "document",
                    "key": "test-resource-1",
                    "tenant": "test-tenant",
                    "attributes": {},
                    "context": {}
                },
                "context": {}
            },
            {
                "user": {
                    "key": "test-user-2",
                    "first_name": "Test",
                    "last_name": "User",
                    "email": "test2@example.com",
                    "attributes": {}
                },
                "action": "write",
                "resource": {
                    "type": "document",
                    "key": "test-resource-2",
                    "tenant": "test-tenant",
                    "attributes": {},
                    "context": {}
                },
                "context": {}
            }
        ]);

        // Setup mock OPA response
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/bulk",
                json!({
                    "result": {
                        "allow": [
                            { "allow": true, "result": true },
                            { "allow": false, "result": false }
                        ]
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        // Send request to the API
        let response = fixture.post("/allowed/bulk", &test_queries).await;

        // Verify response status and body
        response.assert_ok();
        let result: BulkAuthorizationResult = response.json_as();
        assert_eq!(result.allow.len(), 2);
        assert!(result.allow[0].allow);
        assert!(!result.allow[1].allow);

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_handle_allowed_bulk_empty_list() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Create empty queries list
        let empty_queries = json!([]);

        // Setup mock OPA response
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/bulk",
                json!({
                    "result": {
                        "allow": []
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        // Send request to the API
        let response = fixture.post("/allowed/bulk", &empty_queries).await;

        // Verify response status and body
        response.assert_ok();
        let result: BulkAuthorizationResult = response.json_as();
        assert_eq!(result.allow.len(), 0);

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_handle_allowed_bulk_opa_error() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Create test queries
        let test_queries = json!([
            {
                "user": {
                    "key": "test-user",
                    "first_name": "Test",
                    "last_name": "User",
                    "email": "test@example.com",
                    "attributes": {}
                },
                "action": "read",
                "resource": {
                    "type": "document",
                    "key": "test-resource",
                    "tenant": "test-tenant",
                    "attributes": {},
                    "context": {}
                },
                "context": {}
            }
        ]);

        // Setup mock OPA response with error
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/bulk",
                "Internal Server Error",
                StatusCode::INTERNAL_SERVER_ERROR,
                1,
            )
            .await;

        // Send request to the API
        let response = fixture.post("/allowed/bulk", &test_queries).await;

        // Verify response - should be a 502 Bad Gateway when OPA returns 5xx
        response.assert_status(StatusCode::BAD_GATEWAY);

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }
}
