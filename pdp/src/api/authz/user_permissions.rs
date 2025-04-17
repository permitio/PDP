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
            presets::private_cache(state.settings.cache.ttl_secs).apply(&mut response);
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
    presets::private_cache(state.settings.cache.ttl_secs).apply(&mut http_response);
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
    use crate::models::User;

    #[test]
    fn test_cache_key_generation() {
        let query = UserPermissionsQuery {
            user: User {
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
    //
    // #[tokio::test]
    // async fn test_forward_to_opa_minimal_payload() {
    //     let mock_server = MockServer::start().await;
    //     let settings = Settings {
    //         legacy_fallback_url: mock_server.uri(),
    //         opa_url: mock_server.uri(),
    //         port: 3000,
    //         opa_client_query_timeout: 5,
    //         cache: CacheConfig {
    //             ttl_secs: 60,
    //             store: CacheStore::None,
    //             in_memory: InMemoryCacheConfig::default(),
    //             redis: RedisCacheConfig::default(),
    //         },
    //         api_key: "test-api-key".to_string(),
    //     };
    //
    //     let state = AppState::new(settings).await.unwrap();
    //
    //     // Create a minimal query with only required fields
    //     let minimal_query = UserPermissionsQuery {
    //         user: User {
    //             key: "test_user".to_string(),
    //             attributes: HashMap::new(),
    //             first_name: None,
    //             last_name: None,
    //             email: None,
    //         },
    //         tenants: None,
    //         resources: None,
    //         resource_types: None,
    //         context: None,
    //     };
    //     let minimal_query_str = r#"{"user":{"key":"test_user"}}"#;
    //
    //     // Create a test result
    //     let permission_result = UserPermissionsResult {
    //         tenant: Some(TenantDetails {
    //             key: "test".to_string(),
    //             attributes: HashMap::new(),
    //         }),
    //         resource: Some(ResourceDetails {
    //             key: "test".to_string(),
    //             r#type: "test".to_string(),
    //             attributes: HashMap::new(),
    //         }),
    //         permissions: vec!["test:read".to_string()],
    //         roles: Some(vec!["viewer".to_string()]),
    //     };
    //
    //     // Create a HashMap for the response
    //     let mut response_map = HashMap::new();
    //     response_map.insert("test_resource".to_string(), permission_result);
    //
    //     // Setup mock to verify exact JSON payload sent to OPA
    //     Mock::given(method("POST"))
    //         .and(path("/user-permissions"))
    //         .and(body_json(&minimal_query))
    //         .respond_with(
    //             ResponseTemplate::new(200).set_body_json(response_map)
    //         )
    //         .expect(1)
    //         .mount(&mock_server)
    //         .await;
    //
    //     let headers = HeaderMap::new();
    //     let json_value = forward_to_opa::create_opa_request(&minimal_query).unwrap();
    //     let _ = forward_to_opa::send_request_to_opa(&state, "user-permissions", &headers, &json_value).await;
    //     let requests = mock_server.received_requests().await.unwrap();
    //     assert_eq!(requests.len(), 1);
    //     assert_eq!(requests[0].method, Method::POST);
    //     assert_eq!(requests[0].url.path(), "/user-permissions");
    //     assert_eq!(
    //         String::from_utf8(requests[0].body.clone()).unwrap(),
    //         minimal_query_str
    //     );
    //     mock_server.verify().await;
    // }
}
