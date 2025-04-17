use crate::api::authz::forward_to_opa::send_request_to_opa;
use crate::errors::ApiError;
use crate::openapi::AUTHZ_TAG;
use crate::{models::Resource, state::AppState};
use axum::extract::State;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::Value::Object;
use std::collections::HashMap;
use std::os::macos::raw::stat;
use utoipa::ToSchema;

#[utoipa::path(
    post,
    path = "/authorized_users",
    tag = AUTHZ_TAG,
    request_body = AuthorizedUsersAuthorizationQuery,
    params(
        ("Authorization" = String, Header, description = "Authorization header"),
    ),
    responses(
        (status = 200, description = "Authorized users retrieved successfully", body = AuthorizedUsersResult),
        (status = 422, description = "Invalid request payload"),
        (status = 500, description = "Internal server error")
    )
)]
pub(super) async fn authorized_users_handler(
    State(state): State<AppState>,
    Json(query): Json<AuthorizedUsersAuthorizationQuery>,
) -> Response {
    let endpoint = if state.settings.use_new_authorized_users {
        "/v1/data/permit/authorized_users_new/authorized_users"
    } else {
        "/v1/data/permit/authorized_users/authorized_users"
    };
    let result: serde_json::Value =
        match send_request_to_opa::<serde_json::Value, _>(&state, endpoint, &query).await {
            Ok(result) => result,
            Err(err) => {
                log::error!("Failed to send request to OPA: {}", err);
                return ApiError::from(err).into_response();
            }
        };

    // Attempt to extract the "result" field from the response
    if let Object(map) = result {
        if let Some(result) = map.get("result") {
            // Deserialize the inner result into the AuthorizedUsersResult struct
            let result: AuthorizedUsersResult = match serde_json::from_value(result.clone()) {
                Ok(result) => result,
                Err(err) => {
                    log::error!("Failed to deserialize OPA response: {}", err);
                    return ApiError::internal("Invalid response from OPA".to_string())
                        .into_response();
                }
            };
            return (StatusCode::OK, Json(result)).into_response();
        }
    }

    // If the result field is not present, return an empty result
    let resource_key = query.resource.key.unwrap_or("*".to_string());
    let result = AuthorizedUsersResult {
        resource: format!("{}:{}", query.resource.r#type, resource_key),
        tenant: query.resource.tenant.unwrap_or("default".to_string()),
        users: HashMap::new(),
    };
    (StatusCode::OK, Json(result)).into_response()
}

/// Query parameters for the authorized users endpoint
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub(crate) struct AuthorizedUsersAuthorizationQuery {
    /// The action to check
    action: String,
    /// The resource to check access for
    resource: Resource,
    /// Additional context for permission evaluation
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    context: HashMap<String, serde_json::Value>,
    /// SDK identifier
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sdk: Option<String>,
}

/// User assignment details in the authorized users response
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
struct AuthorizedUserAssignment {
    /// User key
    user: String,
    /// Tenant key
    tenant: String,
    /// Resource identifier
    resource: String,
    /// Role assigned to the user
    role: String,
}

/// Response type for the authorized users endpoint
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
struct AuthorizedUsersResult {
    /// Resource identifier
    resource: String,
    /// Tenant identifier
    tenant: String,
    /// Map of user keys to their assignments
    users: HashMap<String, Vec<AuthorizedUserAssignment>>,
}

#[cfg(test)]
mod tests {
    // use super::*;
    // use crate::{
    //     config::{CacheConfig, CacheStore, InMemoryCacheConfig, RedisCacheConfig, Settings},
    // };
    // use wiremock::{
    //     matchers::{body_json, method, path},
    //     Mock, MockServer, ResponseTemplate,
    // };
    //
    // #[tokio::test]
    // #[ignore = "This test requires a mock OPA server"]
    // async fn test_handle_authorized_users() {
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
    //         debug: Some(true),
    //     };
    //
    //     let state = AppState::new(settings).await.unwrap();
    //
    //     // Create a test payload
    //     let test_query = AuthorizedUsersAuthorizationQuery {
    //         action: "view".to_string(),
    //         resource: Resource {
    //             r#type: "document".to_string(),
    //             key: Some("doc-123".to_string()),
    //             tenant: Some("test_tenant".to_string()),
    //             attributes: HashMap::new(),
    //             context: HashMap::new(),
    //         },
    //         context: HashMap::new(),
    //         sdk: None,
    //     };
    //
    //     // Create user assignments
    //     let mut user_assignments = HashMap::new();
    //     let assignments = vec![
    //         AuthorizedUserAssignment {
    //             user: "user1".to_string(),
    //             tenant: "test_tenant".to_string(),
    //             resource: "document:doc-123".to_string(),
    //             role: "viewer".to_string(),
    //         },
    //         AuthorizedUserAssignment {
    //             user: "user2".to_string(),
    //             tenant: "test_tenant".to_string(),
    //             resource: "document:doc-123".to_string(),
    //             role: "editor".to_string(),
    //         },
    //         AuthorizedUserAssignment {
    //             user: "user3".to_string(),
    //             tenant: "test_tenant".to_string(),
    //             resource: "document:doc-123".to_string(),
    //             role: "viewer".to_string(),
    //         },
    //     ];
    //
    //     user_assignments.insert("user1".to_string(), vec![assignments[0].clone()]);
    //     user_assignments.insert("user2".to_string(), vec![assignments[1].clone()]);
    //     user_assignments.insert("user3".to_string(), vec![assignments[2].clone()]);
    //
    //     // Expected response with user assignments
    //     let expected_response = AuthorizedUsersResult {
    //         resource: "document:doc-123".to_string(),
    //         tenant: "test_tenant".to_string(),
    //         users: user_assignments,
    //     };
    //
    //     // Setup mock server
    //     Mock::given(method("POST"))
    //         .and(path("/authorized-users"))
    //         .and(body_json(&test_query))
    //         .respond_with(
    //             ResponseTemplate::new(200).set_body_json(expected_response.clone()),
    //         )
    //         .expect(1)
    //         .mount(&mock_server)
    //         .await;
    //
    //     // Forward request and check response
    //     let headers = HeaderMap::new();
    //     let json_value = forward_to_opa::create_opa_request(&test_query).unwrap();
    //     if let Ok(response) = forward_to_opa::send_request_to_opa(&state, "authorized-users", &headers, &json_value).await {
    //         let typed_response: AuthorizedUsersResult = serde_json::from_value(response.0).unwrap();
    //         assert_eq!(typed_response.resource, expected_response.resource);
    //         assert_eq!(typed_response.tenant, expected_response.tenant);
    //         assert_eq!(typed_response.users.len(), expected_response.users.len());
    //     } else {
    //         panic!("Expected successful response from authorized-users endpoint");
    //     }
    //
    //     mock_server.verify().await;
    // }
}
