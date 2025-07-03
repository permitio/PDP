use crate::errors::ApiError;
use crate::headers::ClientCacheControl;
use crate::opa_client::cached::{
    query_authorized_users_cached, AuthorizedUsersQuery, AuthorizedUsersResult,
};
use crate::openapi::AUTHZ_TAG;
use crate::state::AppState;
use axum::extract::State;
use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use http::header::CACHE_CONTROL;

#[utoipa::path(
    post,
    path = "/authorized_users",
    tag = AUTHZ_TAG,
    request_body = AuthorizedUsersQuery,
    params(
        ("Authorization" = String, Header, description = "Authorization header"),
        ("Cache-Control" = String, Header, description = "Cache control directives"),
    ),
    responses(
        (status = 200, description = "Authorized users retrieved successfully", body = AuthorizedUsersResult),
        (status = 422, description = "Invalid request payload"),
        (status = 500, description = "Internal server error")
    )
)]
pub(super) async fn authorized_users_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(query): Json<AuthorizedUsersQuery>,
) -> Response {
    // Parse client cache control headers
    let cache_control = ClientCacheControl::from_header_value(headers.get(CACHE_CONTROL));

    match query_authorized_users_cached(&state, &query, &cache_control).await {
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
    async fn test_authorized_users_success() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Setup mock OPA response using the helper method
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/authorized_users/authorized_users",
                json!({
                    "result": {
                        "result": {
                            "resource": "document:doc-123",
                            "tenant": "test_tenant",
                            "users": {
                            "user1": [
                                {
                                    "user": "user1",
                                    "tenant": "test_tenant",
                                    "resource": "document:doc-123",
                                    "role": "viewer"
                                }
                            ],
                            "user2": [
                                {
                                    "user": "user2",
                                    "tenant": "test_tenant",
                                    "resource": "document:doc-123",
                                    "role": "editor"
                                }
                            ]
                        }
                        },
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        // Send request to the API
        let response = fixture
            .post(
                "/authorized_users",
                &json!({
                    "action": "view",
                    "resource": {
                        "type": "document",
                        "key": "doc-123",
                        "tenant": "test_tenant",
                        "attributes": {},
                        "context": {}
                    },
                    "context": {}
                }),
            )
            .await;

        // Verify response status and body
        response.assert_ok();
        let result: AuthorizedUsersResult = response.json_as();

        // Verify key fields in response
        assert_eq!(result.resource, "document:doc-123");
        assert_eq!(result.tenant, "test_tenant");
        assert_eq!(result.users.len(), 2);
        assert_eq!(result.users.get("user1").unwrap()[0].role, "viewer");
        assert_eq!(result.users.get("user2").unwrap()[0].role, "editor");

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_authorized_users_empty_result() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Setup mock OPA response using the helper method
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/authorized_users/authorized_users",
                json!({
                    "result": {
                        "result": {
                            "resource": "document:doc-123",
                            "tenant": "test_tenant",
                            "users": {}
                        }
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        // Send request
        let response = fixture
            .post(
                "/authorized_users",
                &json!({
                    "action": "view",
                    "resource": {
                        "type": "document",
                        "key": "doc-123",
                        "tenant": "test_tenant",
                        "attributes": {},
                        "context": {}
                    },
                    "context": {}
                }),
            )
            .await;

        // Verify response - should still be 200 OK with empty users map
        response.assert_ok();
        let result: AuthorizedUsersResult = response.json_as();
        assert_eq!(result.resource, "document:doc-123");
        assert_eq!(result.tenant, "test_tenant");
        assert_eq!(result.users.len(), 0);

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_authorized_users_opa_error() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Setup mock OPA response using the helper method
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/authorized_users/authorized_users",
                "Internal Server Error",
                StatusCode::INTERNAL_SERVER_ERROR,
                1,
            )
            .await;

        // Send request
        let response = fixture
            .post(
                "/authorized_users",
                &json!({
                    "action": "view",
                    "resource": {
                        "type": "document",
                        "key": "doc-123",
                        "tenant": "test_tenant",
                        "attributes": {},
                        "context": {}
                    },
                    "context": {}
                }),
            )
            .await;

        // Verify response - should be a 502 Bad Gateway when OPA returns 5xx
        response.assert_status(StatusCode::BAD_GATEWAY);

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_authorized_users_new_endpoint() {
        // Setup test fixture
        let fixture = TestFixture::with_config_modifier(|config| {
            config.use_new_authorized_users = true;
        })
        .await;

        // Setup mock OPA response using the helper method
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/authorized_users_new/authorized_users",
                "Internal Server Error",
                StatusCode::INTERNAL_SERVER_ERROR,
                1,
            )
            .await;

        // Send request
        let response = fixture
            .post(
                "/authorized_users",
                &json!({
                    "action": "view",
                    "resource": {
                        "type": "document",
                        "key": "doc-123",
                        "tenant": "test_tenant",
                        "attributes": {},
                        "context": {}
                    },
                    "context": {}
                }),
            )
            .await;

        // Verify response - should be a 502 Bad Gateway when OPA returns 5xx
        response.assert_status(StatusCode::BAD_GATEWAY);

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }
}
