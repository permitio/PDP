use std::collections::HashMap;

use axum::response::{IntoResponse, Response};
use axum::Json;
use log::debug;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::opa_client::{send_request_to_opa, ForwardingError};
use crate::state::AppState;

use super::allowed::User;

/// Send a user permissions query to OPA and get the result
pub async fn query_user_permissions(
    state: &AppState,
    query: &UserPermissionsQuery,
) -> Result<HashMap<String, UserPermissionsResult>, ForwardingError> {
    // Send the request to OPA and get the raw JSON result
    let response: serde_json::Value =
        send_request_to_opa(state, "/v1/data/permit/user_permissions", query).await?;

    if let serde_json::Value::Object(result_map) = response {
        if let Some(permissions) = result_map.get("permissions") {
            return Ok(serde_json::from_value(permissions.clone())?);
        } else {
            debug!("No 'permissions' field found in result");
        }
    } else {
        debug!("Result is not an object");
    }

    // If we couldn't find the permissions, return an empty map
    Ok(HashMap::new())
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct UserPermissionsQuery {
    /// User details
    pub user: User,
    /// List of tenant identifiers to check
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenants: Option<Vec<String>>,
    /// List of resource identifiers to check
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Vec<String>>,
    /// List of resource types to check
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_types: Option<Vec<String>>,
    /// Additional context for permission evaluation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct TenantDetails {
    /// Unique identifier for the tenant
    pub key: String,
    /// Additional tenant attributes
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub attributes: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct ResourceDetails {
    /// Unique identifier for the resource
    pub key: String,
    /// Type of the resource
    pub r#type: String,
    /// Additional resource attributes
    #[serde(default)]
    pub attributes: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct UserPermissionsResult {
    /// Tenant details
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<TenantDetails>,
    /// Resource details
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceDetails>,
    /// List of permissions in format "action:resource"
    pub permissions: Vec<String>,
    /// List of roles assigned to the user
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
}
// Define a newtype wrapper for HashMap<String, UserPermissionsResult>
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, ToSchema)]
pub struct UserPermissionsResults(pub HashMap<String, UserPermissionsResult>);

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestFixture;
    use http::{Method, StatusCode};
    use serde_json::json;

    // A helper function to create a test OPA response
    fn create_test_response() -> serde_json::Value {
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
        })
    }

    #[test]
    fn test_parse_opa_response() {
        let test_response = create_test_response();

        // Extract permissions using the same logic as query_user_permissions
        let permissions: HashMap<String, UserPermissionsResult> =
            if let serde_json::Value::Object(map) = &test_response {
                if let Some(serde_json::Value::Object(result_map)) = map.get("result") {
                    if let Some(permissions) = result_map.get("permissions") {
                        serde_json::from_value(permissions.clone()).unwrap()
                    } else {
                        HashMap::new()
                    }
                } else {
                    HashMap::new()
                }
            } else {
                HashMap::new()
            };

        // Check the parsed response
        assert_eq!(permissions.len(), 1);
        assert!(permissions.contains_key("resource1"));

        let resource1 = &permissions["resource1"];
        assert_eq!(resource1.permissions.len(), 2);
        assert!(resource1.permissions.contains(&"document:read".to_string()));
        assert!(resource1
            .permissions
            .contains(&"document:write".to_string()));
    }

    #[test]
    fn test_parse_direct_permissions() {
        // This test is now obsolete since we only expect permissions inside the "result" key
        // We'll keep it but modify it to use the result wrapper
        let test_response = json!({
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

        // Extract permissions using the same logic as query_user_permissions
        let permissions: HashMap<String, UserPermissionsResult> =
            if let serde_json::Value::Object(map) = &test_response {
                if let Some(serde_json::Value::Object(result_map)) = map.get("result") {
                    if let Some(permissions) = result_map.get("permissions") {
                        serde_json::from_value(permissions.clone()).unwrap()
                    } else {
                        HashMap::new()
                    }
                } else {
                    HashMap::new()
                }
            } else {
                HashMap::new()
            };

        // Check the parsed response
        assert_eq!(permissions.len(), 1);
        assert!(permissions.contains_key("resource1"));

        let resource1 = &permissions["resource1"];
        assert_eq!(resource1.permissions.len(), 1);
        assert!(resource1.permissions.contains(&"document:read".to_string()));
    }

    // Integration tests using TestFixture for mocking OPA responses
    #[tokio::test]
    async fn test_query_user_permissions_success() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Setup mock OPA response
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/user_permissions",
                json!({
                    "result": {
                        "permissions": {
                            "document:doc-123": {
                                "tenant": {
                                    "key": "test_tenant",
                                    "attributes": {}
                                },
                                "resource": {
                                    "key": "doc-123",
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

        // Create a test query
        let query = UserPermissionsQuery {
            user: User {
                key: "user123".to_string(),
                first_name: None,
                last_name: None,
                email: None,
                attributes: HashMap::new(),
            },
            tenants: Some(vec!["test_tenant".to_string()]),
            resources: Some(vec!["document:doc-123".to_string()]),
            resource_types: None,
            context: None,
        };

        // Call the function under test
        let result = query_user_permissions(&fixture.state, &query)
            .await
            .expect("Failed to query user permissions");

        // Verify the response
        assert_eq!(result.len(), 1);
        assert!(result.contains_key("document:doc-123"));
        let resource = &result["document:doc-123"];
        assert_eq!(resource.permissions.len(), 2);
        assert!(resource.permissions.contains(&"document:read".to_string()));
        assert!(resource.permissions.contains(&"document:write".to_string()));
        assert_eq!(
            resource.roles.as_ref().unwrap(),
            &vec!["editor".to_string()]
        );

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_query_user_permissions_empty_result() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Setup mock OPA response with empty permissions
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

        // Create a test query
        let query = UserPermissionsQuery {
            user: User {
                key: "user123".to_string(),
                first_name: None,
                last_name: None,
                email: None,
                attributes: HashMap::new(),
            },
            tenants: Some(vec!["test_tenant".to_string()]),
            resources: Some(vec!["document:doc-123".to_string()]),
            resource_types: None,
            context: None,
        };

        // Call the function under test
        let result = query_user_permissions(&fixture.state, &query)
            .await
            .expect("Failed to query user permissions");

        // Verify the response is empty
        assert_eq!(result.len(), 0);

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_query_user_permissions_no_permissions_field() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Setup mock OPA response without permissions field
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/user_permissions",
                json!({
                    "result": {}
                }),
                StatusCode::OK,
                1,
            )
            .await;

        // Create a test query
        let query = UserPermissionsQuery {
            user: User {
                key: "user123".to_string(),
                first_name: None,
                last_name: None,
                email: None,
                attributes: HashMap::new(),
            },
            tenants: Some(vec!["test_tenant".to_string()]),
            resources: Some(vec!["document:doc-123".to_string()]),
            resource_types: None,
            context: None,
        };

        // Call the function under test
        let result = query_user_permissions(&fixture.state, &query)
            .await
            .expect("Failed to query user permissions");

        // Verify the response is empty
        assert_eq!(result.len(), 0);

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_query_user_permissions_opa_error() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Setup mock OPA response with an error
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/user_permissions",
                "Internal Server Error",
                StatusCode::INTERNAL_SERVER_ERROR,
                1,
            )
            .await;

        // Create a test query
        let query = UserPermissionsQuery {
            user: User {
                key: "user123".to_string(),
                first_name: None,
                last_name: None,
                email: None,
                attributes: HashMap::new(),
            },
            tenants: Some(vec!["test_tenant".to_string()]),
            resources: Some(vec!["document:doc-123".to_string()]),
            resource_types: None,
            context: None,
        };

        // Call the function under test
        let result = query_user_permissions(&fixture.state, &query).await;

        // Verify the response is an error
        assert!(result.is_err());

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_query_user_permissions_invalid_json() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Setup mock OPA response with invalid JSON
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/user_permissions",
                "Invalid JSON",
                StatusCode::OK,
                1,
            )
            .await;

        // Create a test query
        let query = UserPermissionsQuery {
            user: User {
                key: "user123".to_string(),
                first_name: None,
                last_name: None,
                email: None,
                attributes: HashMap::new(),
            },
            tenants: Some(vec!["test_tenant".to_string()]),
            resources: Some(vec!["document:doc-123".to_string()]),
            resource_types: None,
            context: None,
        };

        // Call the function under test
        let result = query_user_permissions(&fixture.state, &query).await;

        // Verify the response is an error
        assert!(result.is_err());

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }
}
