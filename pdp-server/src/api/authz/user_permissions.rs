use crate::errors::ApiError;
use crate::headers::ClientCacheControl;
use crate::opa_client::cached::{
    query_user_permissions_cached, UserPermissionsQuery, UserPermissionsResult,
};
use crate::openapi::AUTHZ_TAG;
use crate::{headers::presets, state::AppState};
use axum::{
    extract::{Json, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use http::header::CACHE_CONTROL;
use std::collections::HashMap;

// Wrapper type for proper response serialization
#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq, utoipa::ToSchema)]
pub struct UserPermissionsResults(pub HashMap<String, UserPermissionsResult>);

impl IntoResponse for UserPermissionsResults {
    fn into_response(self) -> Response {
        axum::Json(self.0).into_response()
    }
}

impl From<HashMap<String, UserPermissionsResult>> for UserPermissionsResults {
    fn from(map: HashMap<String, UserPermissionsResult>) -> Self {
        UserPermissionsResults(map)
    }
}

#[utoipa::path(
    post,
    path = "/user-permissions",
    tag = AUTHZ_TAG,
    request_body = UserPermissionsQuery,
    params(
        ("Authorization" = String, Header, description = "Authorization header"),
        ("Cache-Control" = String, Header, description = "Cache control directives"),
    ),
    responses(
        (status = 200, description = "User permissions retrieved successfully", body = UserPermissionsResults),
        (status = 422, description = "Invalid request payload"),
        (status = 500, description = "Internal server error")
    )
)]
pub(super) async fn user_permissions_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(query): Json<UserPermissionsQuery>,
) -> Response {
    // Parse client cache control headers
    let cache_control = ClientCacheControl::from_header_value(headers.get(CACHE_CONTROL));

    // Use the cached OPA client function which handles caching internally
    let permissions = match query_user_permissions_cached(&state, &query, &cache_control).await {
        Ok(permissions) => permissions,
        Err(err) => {
            log::error!("Failed to send request to OPA: {err}");
            return ApiError::from(err).into_response();
        }
    };

    // Create response using the map
    let response = UserPermissionsResults::from(permissions);

    // Create response with appropriate cache headers
    let mut http_response = Json(response).into_response();
    presets::private_cache(state.config.cache.ttl).apply(&mut http_response);
    http_response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestFixture;
    use http::{Method, StatusCode};
    use serde_json::json;

    #[tokio::test]
    async fn test_user_permissions_success() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Setup mock OPA response using the helper method
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/user_permissions",
                json!({
                    "result": {
                        "permissions": {
                            "resource1": {
                                "tenant": {
                                    "key": "tenant1",
                                    "attributes": {}
                                },
                                "resource": {
                                    "key": "resource1",
                                    "type": "document",
                                    "attributes": {}
                                },
                                "permissions": ["document:read", "document:write"],
                                "roles": ["editor"]
                            }
                        }
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        // Send request to the API
        let response = fixture
            .post(
                "/user-permissions",
                &json!({
                    "user": {
                        "key": "test-user",
                        "first_name": "Test",
                        "last_name": "User",
                        "email": "test@example.com",
                        "attributes": {}
                    },
                    "tenants": ["tenant1"],
                    "resources": ["resource1"],
                    "resource_types": ["document"]
                }),
            )
            .await;

        // Verify response status and body
        response.assert_ok();
        let result_map: UserPermissionsResults = response.json_as();

        // Check the response structure
        assert_eq!(result_map.0.len(), 1);
        assert!(result_map.0.contains_key("resource1"));

        let resource_result = &result_map.0["resource1"];
        assert_eq!(resource_result.permissions.len(), 2);
        assert!(resource_result
            .permissions
            .contains(&"document:read".to_string()));
        assert!(resource_result
            .permissions
            .contains(&"document:write".to_string()));
        assert_eq!(resource_result.roles.as_ref().unwrap()[0], "editor");

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_user_permissions_empty_result() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Setup mock OPA response using the helper method
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/user_permissions",
                json!({
                    "result": {
                        "permissions": {}
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        // Send request
        let response = fixture
            .post(
                "/user-permissions",
                &json!({
                    "user": {
                        "key": "test-user",
                        "attributes": {}
                    },
                    "tenants": ["tenant1"]
                }),
            )
            .await;

        // Verify response - should still be 200 OK with empty results
        response.assert_ok();
        let result_map: UserPermissionsResults = response.json_as();
        assert_eq!(result_map.0.len(), 0, "Expected empty permissions map");

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_user_permissions_opa_error() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Create request JSON directly
        let request_json = json!({
            "user": {
                "key": "test-user",
                "attributes": {}
            }
        });

        // Setup mock OPA response with error (500 status code)
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/user_permissions",
                "Internal Server Error",
                StatusCode::INTERNAL_SERVER_ERROR,
                1,
            )
            .await;

        // Send request
        let response = fixture.post("/user-permissions", &request_json).await;

        // Verify response - should be a 502 Bad Gateway when OPA returns 5xx
        response.assert_status(StatusCode::BAD_GATEWAY);

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_user_permissions_no_cache_control() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Create request JSON directly
        let request_json = json!({
            "user": {
                "key": "test-user",
                "attributes": {}
            },
            "resource_types": ["document"]
        });

        // Create response JSON directly
        let response_json = json!({
            "result": {
                "permissions": {
                    "resource1": {
                        "tenant": {
                            "key": "tenant1",
                            "attributes": {}
                        },
                        "resource": {
                            "key": "resource1",
                            "type": "document",
                            "attributes": {}
                        },
                        "permissions": ["document:read"]
                    }
                }
            }
        });

        // Setup mock OPA response using the helper method
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/user_permissions",
                response_json,
                StatusCode::OK,
                1,
            )
            .await;

        // Send request to the API
        let response = fixture.post("/user-permissions", &request_json).await;

        // Simply verify the request was successful
        response.assert_ok();
        let result_map: UserPermissionsResults = response.json_as();
        assert_eq!(result_map.0.len(), 1);

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_user_permissions_with_no_store_header() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Create request JSON directly
        let request_json = json!({
            "user": {
                "key": "test-user-cache",
                "attributes": {}
            },
            "resource_types": ["document"]
        });

        // Create response JSON directly
        let response_json = json!({
            "result": {
                "permissions": {
                    "resource1": {
                        "tenant": {
                            "key": "tenant1",
                            "attributes": {}
                        },
                        "resource": {
                            "key": "resource1",
                            "type": "document",
                            "attributes": {}
                        },
                        "permissions": ["document:read"]
                    }
                }
            }
        });

        // Setup mock OPA response using the helper method
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/user_permissions",
                response_json,
                StatusCode::OK,
                1,
            )
            .await;

        // Send request with no-store cache header
        let custom_headers = &[(CACHE_CONTROL.as_str(), "no-store")];
        let response = fixture
            .post_with_headers("/user-permissions", &request_json, custom_headers)
            .await;

        // Verify response is successful
        response.assert_ok();
        let result_map: UserPermissionsResults = response.json_as();
        assert_eq!(
            result_map.0.len(),
            1,
            "Should have one resource in permissions"
        );
        assert!(
            result_map.0.contains_key("resource1"),
            "Should contain resource1 entry"
        );

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }
}
