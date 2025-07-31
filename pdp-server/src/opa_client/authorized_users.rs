use crate::opa_client::send_request_to_opa;
use crate::opa_client::ForwardingError;
use crate::state::AppState;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;

use super::allowed::Resource;

/// Send an authorized users query to OPA and get the result
pub async fn query_authorized_users(
    state: &AppState,
    query: &AuthorizedUsersQuery,
) -> Result<AuthorizedUsersResult, ForwardingError> {
    let endpoint = if state.config.use_new_authorized_users {
        "/v1/data/permit/authorized_users_new/authorized_users"
    } else {
        "/v1/data/permit/authorized_users/authorized_users"
    };

    // First, send the request to OPA and get the raw JSON result
    let result: serde_json::Value = send_request_to_opa(state, endpoint, query).await?;

    // Process the result to extract the nested 'result' field if it exists
    if let serde_json::Value::Object(map) = &result {
        if let Some(inner_result) = map.get("result") {
            let authorized_result: AuthorizedUsersResult =
                serde_json::from_value(inner_result.clone())?;

            // Add debug logging if enabled
            if state.config.debug.unwrap_or(false) {
                log::info!(
                    "permit.authorized_users(\"{}\", \"{}\") -> {} users",
                    query.action,
                    query.resource,
                    authorized_result.users.len()
                );
                log::debug!(
                    "Query: {}\nResult: {:?}",
                    serde_json::to_string_pretty(query)?,
                    serde_json::to_string_pretty(&authorized_result)?
                );
            }

            return Ok(authorized_result);
        }
    }

    // If no users data found, return an empty result
    let resource_key = query
        .resource
        .key
        .clone()
        .unwrap_or_else(|| "*".to_string());
    let tenant = query
        .resource
        .tenant
        .clone()
        .unwrap_or_else(|| "default".to_string());

    let empty_result = AuthorizedUsersResult {
        resource: format!("{}:{}", query.resource.r#type, resource_key),
        tenant,
        users: HashMap::new(),
    };

    // Add debug logging if enabled
    if state.config.debug.unwrap_or(false) {
        log::info!(
            "permit.authorized_users(\"{}\", \"{}\") -> 0 users",
            query.action,
            query.resource
        );
        log::debug!(
            "Query: {}\nResult: empty",
            serde_json::to_string_pretty(query)?
        );
    }

    Ok(empty_result)
}

/// Query parameters for the authorized users endpoint
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct AuthorizedUsersQuery {
    /// The action to check
    pub action: String,
    /// The resource to check access for
    pub resource: Resource,
    /// Additional context for permission evaluation
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub context: HashMap<String, serde_json::Value>,
    /// SDK identifier
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdk: Option<String>,
}

/// User assignment details in the authorized users response
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct AuthorizedUserAssignment {
    /// User key
    pub user: String,
    /// Tenant key
    pub tenant: String,
    /// Resource identifier
    pub resource: String,
    /// Role assigned to the user
    pub role: String,
}

/// Response type for the authorized users endpoint
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct AuthorizedUsersResult {
    /// Resource identifier
    pub resource: String,
    /// Tenant identifier
    pub tenant: String,
    /// Map of user keys to their assignments
    pub users: HashMap<String, Vec<AuthorizedUserAssignment>>,
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

        // Setup mock OPA response
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

        let query: AuthorizedUsersQuery = serde_json::from_value(json!({
            "action": "view",
            "resource": {
                "type": "document",
                "key": "doc-123",
                "tenant": "test_tenant",
                "attributes": {},
                "context": {},
            },
            "context": {},
            "sdk": null,
        }))
        .unwrap();
        let result = query_authorized_users(&fixture.state, &query)
            .await
            .expect("Failed to query authorized users");

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
    async fn test_authorized_users_empty() {
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
        let query: AuthorizedUsersQuery = serde_json::from_value(json!({
            "action": "view",
            "resource": {
                "type": "document",
                "key": "doc-123",
                "tenant": "test_tenant",
                "attributes": {},
                "context": {},
            },
            "context": {},
            "sdk": null,
        }))
        .expect("Failed to create AuthorizedUsersQuery");
        let result = query_authorized_users(&fixture.state, &query)
            .await
            .expect("Failed to query authorized users");

        // Verify key fields in response
        assert_eq!(result.resource, "document:doc-123");
        assert_eq!(result.tenant, "test_tenant");
        assert_eq!(result.users.len(), 0);

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn authorized_users_returns_empty_when_no_result_field() {
        let fixture = TestFixture::new().await;

        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/authorized_users/authorized_users",
                json!({
                    "result": {},
                }),
                StatusCode::OK,
                1,
            )
            .await;

        let query: AuthorizedUsersQuery = serde_json::from_value(json!({
            "action": "view",
            "resource": {
                "type": "document",
                "key": "doc-123",
                "tenant": "test_tenant",
                "attributes": {},
                "context": {},
            },
            "context": {},
            "sdk": null,
        }))
        .unwrap();

        let result = query_authorized_users(&fixture.state, &query)
            .await
            .expect("Failed to query authorized users");

        assert_eq!(result.resource, "document:doc-123");
        assert_eq!(result.tenant, "test_tenant");
        assert_eq!(result.users.len(), 0);

        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn authorized_users_handles_invalid_json_response() {
        let fixture = TestFixture::new().await;

        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/authorized_users/authorized_users",
                "Invalid JSON",
                StatusCode::OK,
                1,
            )
            .await;

        let query: AuthorizedUsersQuery = serde_json::from_value(json!({
            "action": "view",
            "resource": {
                "type": "document",
                "key": "doc-123",
                "tenant": "test_tenant",
                "attributes": {},
                "context": {},
            },
            "context": {},
            "sdk": null,
        }))
        .unwrap();

        let result = query_authorized_users(&fixture.state, &query).await;

        assert!(result.is_err());
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn authorized_users_uses_new_endpoint_when_configured() {
        let fixture = TestFixture::with_config_modifier(|config| {
            config.use_new_authorized_users = true;
        })
        .await;

        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/authorized_users_new/authorized_users",
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
                                ]
                            }
                        }
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        let query: AuthorizedUsersQuery = serde_json::from_value(json!({
            "action": "view",
            "resource": {
                "type": "document",
                "key": "doc-123",
                "tenant": "test_tenant",
                "attributes": {},
                "context": {},
            },
            "context": {},
            "sdk": null,
        }))
        .unwrap();

        let result = query_authorized_users(&fixture.state, &query)
            .await
            .expect("Failed to query authorized users");

        assert_eq!(result.resource, "document:doc-123");
        assert_eq!(result.tenant, "test_tenant");
        assert_eq!(result.users.len(), 1);
        assert_eq!(result.users.get("user1").unwrap()[0].role, "viewer");

        fixture.opa_mock.verify().await;
    }
}
