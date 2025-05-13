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
