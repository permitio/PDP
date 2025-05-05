use std::collections::HashMap;

use crate::api::authz::forward_to_opa::send_request_to_opa;
use crate::errors::ApiError;
use crate::openapi::AUTHZ_TAG;
use crate::{
    cache::CacheBackend,
    headers::{presets, ClientCacheControl},
    models::{UserPermissionsQuery, UserPermissionsResult},
    state::AppState,
};
use axum::{
    extract::{Json, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use http::header::CACHE_CONTROL;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use utoipa::ToSchema;

#[utoipa::path(
    post,
    path = "/user-permissions",
    tag = AUTHZ_TAG,
    request_body = UserPermissionsQuery,
    params(
        ("Authorization" = String, Header, description = "Authorization header"),
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
    let client_cache = ClientCacheControl::from_header_value(headers.get(CACHE_CONTROL));

    // Generate cache key
    let cache_key = match generate_cache_key(&query) {
        Ok(key) => key,
        Err(err) => {
            log::error!("Failed to generate cache key: {}", err);
            return ApiError::internal("Failed to generate cache key".to_string()).into_response();
        }
    };

    // Check cache if allowed by client
    if client_cache.should_use_cache() {
        if let Ok(Some(cached)) = state.cache.get::<UserPermissionsResults>(&cache_key).await {
            let mut response = Response::new(Json(cached).into_response().into_body());
            presets::private_cache(state.config.cache.ttl).apply(&mut response);
            return StatusCode::OK.into_response();
        }
    }

    // Forward to OPA service
    let full_result: serde_json::Value = match send_request_to_opa::<serde_json::Value, _>(
        &state,
        "/v1/data/permit/user_permissions",
        &query,
    )
    .await
    {
        Ok(result) => result,
        Err(err) => {
            log::error!("Failed to send request to OPA: {}", err);
            return ApiError::from(err).into_response();
        }
    };

    // Extract "permissions" field from the response
    let result = match &full_result {
        serde_json::Value::Object(map) => {
            if let Some(permissions) = map.get("permissions") {
                permissions.clone()
            } else {
                log::warn!(
                    "OPA response did not contain 'permissions' field: got {:?}",
                    full_result
                );
                // If the response does not contain the "permissions" field, we return an empty result
                return (StatusCode::OK, Json(json!({}))).into_response();
            }
        }
        _ => {
            log::warn!(
                "Invalid response from OPA: expected an object, got {:?}",
                full_result
            );
            // If the response is not an object, we return an empty result
            return (StatusCode::OK, Json(json!({}))).into_response();
        }
    };

    let response: UserPermissionsResults = match serde_json::from_value(result) {
        Ok(response) => response,
        Err(err) => {
            log::error!("Failed to deserialize OPA response: {}", err);
            return ApiError::internal("Invalid response from OPA".to_string()).into_response();
        }
    };

    // Cache the result if allowed
    if !client_cache.no_store {
        if let Err(e) = state.cache.set(&cache_key, &response).await {
            log::error!("Failed to cache permissions result: {}", e);
        }
    }

    // Create response using the map directly
    let mut http_response = Json(response).into_response();
    presets::private_cache(state.config.cache.ttl).apply(&mut http_response);
    (StatusCode::OK, http_response).into_response()
}

// Define a newtype wrapper for HashMap<String, UserPermissionsResult>
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, ToSchema)]
struct UserPermissionsResults(HashMap<String, UserPermissionsResult>);

// Implement IntoResponse for our newtype
impl IntoResponse for UserPermissionsResults {
    fn into_response(self) -> Response {
        Json(self.0).into_response()
    }
}

// Implement conversion from HashMap to our newtype
impl From<HashMap<String, UserPermissionsResult>> for UserPermissionsResults {
    fn from(map: HashMap<String, UserPermissionsResult>) -> Self {
        UserPermissionsResults(map)
    }
}

/// Generate a cache key specifically for user permissions
pub fn generate_cache_key(query: &UserPermissionsQuery) -> Result<String, serde_json::Error> {
    let mut hasher = Sha256::new();

    // Add query to hash
    hasher.update(serde_json::to_string(query)?.as_bytes());

    // Return as Result
    Ok(format!(
        "pdp:user_permissions:{}:{:x}",
        query.user.key,
        hasher.finalize()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestFixture;
    use http::Method;
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
        let result_map: HashMap<String, UserPermissionsResult> = response.json_as();

        // Check the response structure
        assert_eq!(result_map.len(), 1);
        assert!(result_map.contains_key("resource1"));

        let resource_result = &result_map["resource1"];
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
        let result_map: HashMap<String, UserPermissionsResult> = response.json_as();
        assert_eq!(result_map.len(), 0, "Expected empty permissions map");

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
        let result_map: HashMap<String, UserPermissionsResult> = response.json_as();
        assert_eq!(result_map.len(), 1);

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
        let result_map: HashMap<String, UserPermissionsResult> = response.json_as();
        assert_eq!(
            result_map.len(),
            1,
            "Should have one resource in permissions"
        );
        assert!(
            result_map.contains_key("resource1"),
            "Should contain resource1 entry"
        );

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[test]
    fn test_cache_key_generation() {
        // Create test query directly as a struct since we're testing the function
        let query = UserPermissionsQuery {
            user: crate::models::User {
                key: "test_user".to_string(),
                first_name: None,
                last_name: None,
                email: None,
                attributes: HashMap::new(),
            },
            tenants: Some(vec!["tenant1".to_string()]),
            resources: Some(vec!["resource1".to_string()]),
            resource_types: Some(vec!["type1".to_string()]),
            context: None,
        };

        // Generate key and ensure it's consistent
        let key1 = generate_cache_key(&query).unwrap();
        let key2 = generate_cache_key(&query).unwrap();
        assert_eq!(key1, key2, "Same input should generate same key");

        // Verify the key contains expected user key
        assert!(
            key1.contains("test_user"),
            "Cache key should contain user key"
        );
    }
}
