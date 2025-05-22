use crate::opa_client::{send_request_to_opa, ForwardingError};
use crate::state::AppState;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;

/// Send an allowed query to OPA and get the result
pub async fn query_allowed(
    state: &AppState,
    query: &AllowedQuery,
) -> Result<AllowedResult, ForwardingError> {
    send_request_to_opa::<AllowedResult, _>(state, "/v1/data/permit/root", query).await
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct User {
    /// Unique identifier for the user
    pub key: String,
    /// User's first name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    /// User's last name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    /// User's email address
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Additional user attributes
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub attributes: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct Resource {
    /// Type of the resource
    pub r#type: String,
    /// Unique identifier for the resource (optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Tenant for this resource (optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// Additional resource attributes
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub attributes: HashMap<String, serde_json::Value>,
    /// Resource context
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub context: HashMap<String, serde_json::Value>,
}

/// Authorization query parameters for the allowed endpoint
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct AllowedQuery {
    /// User making the request
    pub user: User,
    /// The action the user wants to perform
    pub action: String,
    /// The resource the user wants to access
    pub resource: Resource,
    /// Additional context for permission evaluation
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub context: HashMap<String, serde_json::Value>,
    /// SDK identifier
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdk: Option<String>,
}

/// Response type for the allowed endpoint
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct AllowedResult {
    /// Whether the action is allowed
    pub allow: bool,
    /// Query details for debugging
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<HashMap<String, serde_json::Value>>,
    /// Debug information
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub debug: Option<HashMap<String, serde_json::Value>>,
    /// Result (deprecated field for backward compatibility)
    #[serde(default)]
    pub result: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestFixture;
    use http::{Method, StatusCode};
    use serde_json::json;

    #[tokio::test]
    async fn test_allowed_success() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Setup mock OPA response
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/root",
                json!({
                    "result": {
                        "allow": true,
                        "result": true
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        let query = AllowedQuery {
            user: User {
                key: "user-123".to_string(),
                first_name: Some("Test".to_string()),
                last_name: Some("User".to_string()),
                email: Some("test@example.com".to_string()),
                attributes: HashMap::new(),
            },
            action: "view".to_string(),
            resource: Resource {
                r#type: "document".to_string(),
                key: Some("doc-123".to_string()),
                tenant: Some("test_tenant".to_string()),
                attributes: HashMap::new(),
                context: HashMap::new(),
            },
            context: HashMap::new(),
            sdk: None,
        };

        let result = query_allowed(&fixture.state, &query)
            .await
            .expect("Failed to query allowed");

        // Verify key fields in response
        assert!(result.allow);
        assert!(result.result);
        assert!(result.debug.is_none());
        assert!(result.query.is_none());

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_allowed_denied() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Setup mock OPA response
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/root",
                json!({
                    "result": {
                        "allow": false,
                        "result": false
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        let query = AllowedQuery {
            user: User {
                key: "user-123".to_string(),
                first_name: Some("Test".to_string()),
                last_name: Some("User".to_string()),
                email: Some("test@example.com".to_string()),
                attributes: HashMap::new(),
            },
            action: "delete".to_string(),
            resource: Resource {
                r#type: "document".to_string(),
                key: Some("doc-123".to_string()),
                tenant: Some("test_tenant".to_string()),
                attributes: HashMap::new(),
                context: HashMap::new(),
            },
            context: HashMap::new(),
            sdk: None,
        };

        let result = query_allowed(&fixture.state, &query)
            .await
            .expect("Failed to query allowed");

        // Verify key fields in response
        assert!(!result.allow);
        assert!(!result.result);

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_allowed_with_debug_info() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Setup mock OPA response
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/root",
                json!({
                    "result": {
                        "allow": true,
                        "result": true,
                        "debug": {
                            "matching_policy": "admin_policy",
                            "roles": ["admin", "editor"]
                        }
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        let query = AllowedQuery {
            user: User {
                key: "user-123".to_string(),
                first_name: Some("Test".to_string()),
                last_name: Some("User".to_string()),
                email: Some("test@example.com".to_string()),
                attributes: HashMap::new(),
            },
            action: "view".to_string(),
            resource: Resource {
                r#type: "document".to_string(),
                key: Some("doc-123".to_string()),
                tenant: Some("test_tenant".to_string()),
                attributes: HashMap::new(),
                context: HashMap::new(),
            },
            context: HashMap::new(),
            sdk: None,
        };

        let result = query_allowed(&fixture.state, &query)
            .await
            .expect("Failed to query allowed");

        // Verify key fields in response
        assert!(result.allow);
        assert!(result.result);
        assert!(result.debug.is_some());
        let debug = result.debug.as_ref().unwrap();
        assert_eq!(debug.get("matching_policy").unwrap(), "admin_policy");

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_allowed_handles_invalid_json_response() {
        let fixture = TestFixture::new().await;

        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/root",
                "Invalid JSON",
                StatusCode::OK,
                1,
            )
            .await;

        let query = AllowedQuery {
            user: User {
                key: "user-123".to_string(),
                first_name: None,
                last_name: None,
                email: None,
                attributes: HashMap::new(),
            },
            action: "view".to_string(),
            resource: Resource {
                r#type: "document".to_string(),
                key: Some("doc-123".to_string()),
                tenant: Some("test_tenant".to_string()),
                attributes: HashMap::new(),
                context: HashMap::new(),
            },
            context: HashMap::new(),
            sdk: None,
        };

        let result = query_allowed(&fixture.state, &query).await;

        assert!(result.is_err());
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_allowed_handles_server_error() {
        let fixture = TestFixture::new().await;

        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/root",
                json!({ "error": "Internal server error" }),
                StatusCode::INTERNAL_SERVER_ERROR,
                1,
            )
            .await;

        let query = AllowedQuery {
            user: User {
                key: "user-123".to_string(),
                first_name: None,
                last_name: None,
                email: None,
                attributes: HashMap::new(),
            },
            action: "view".to_string(),
            resource: Resource {
                r#type: "document".to_string(),
                key: Some("doc-123".to_string()),
                tenant: Some("test_tenant".to_string()),
                attributes: HashMap::new(),
                context: HashMap::new(),
            },
            context: HashMap::new(),
            sdk: None,
        };

        let result = query_allowed(&fixture.state, &query).await;

        assert!(result.is_err());
        fixture.opa_mock.verify().await;
    }
}
