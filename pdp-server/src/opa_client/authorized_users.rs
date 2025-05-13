use crate::models::Resource;
use crate::opa_client::send_request_to_opa;
use crate::opa_client::ForwardingError;
use crate::state::AppState;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;

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
            return Ok(serde_json::from_value(inner_result.clone())?);
        }
    }

    // If the result field is not present, return an empty result
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

    Ok(AuthorizedUsersResult {
        resource: format!("{}:{}", query.resource.r#type, resource_key),
        tenant,
        users: HashMap::new(),
    })
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
