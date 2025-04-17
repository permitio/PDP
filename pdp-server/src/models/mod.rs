use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;

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
pub struct TenantDetails {
    /// Unique identifier for the tenant
    pub key: String,
    /// Additional tenant attributes
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
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

// Implement IntoResponse for UserPermissionsResult
impl axum::response::IntoResponse for UserPermissionsResult {
    fn into_response(self) -> axum::response::Response {
        axum::extract::Json(self).into_response()
    }
}

// Define a newtype wrapper for HashMap<String, UserPermissionsResult>
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, ToSchema)]
pub struct UserPermissionsResults(pub HashMap<String, UserPermissionsResult>);

// Implement IntoResponse for our newtype
impl axum::response::IntoResponse for UserPermissionsResults {
    fn into_response(self) -> axum::response::Response {
        axum::extract::Json(self.0).into_response()
    }
}

// Implement conversion from HashMap to our newtype
impl From<HashMap<String, UserPermissionsResult>> for UserPermissionsResults {
    fn from(map: HashMap<String, UserPermissionsResult>) -> Self {
        UserPermissionsResults(map)
    }
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
pub struct ValidationError {
    /// Location of the validation error
    pub loc: Vec<String>,
    /// Error message
    pub msg: String,
    /// Type of error
    pub r#type: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct HTTPValidationError {
    /// List of validation errors
    pub detail: Vec<ValidationError>,
}

// Updated models for the /allowed endpoint to match Python schemas
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct AuthorizationQuery {
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

// For backward compatibility - rename to better reflect API endpoint
#[allow(dead_code)]
pub type AllowedQuery = AuthorizationQuery;

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct AuthorizationResult {
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

// For backward compatibility - rename to better reflect API endpoint
#[allow(dead_code)]
pub type AllowedResponse = AuthorizationResult;

// Models for bulk authorization
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct BulkAuthorizationQuery {
    /// List of authorization checks to perform
    pub checks: Vec<AuthorizationQuery>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct BulkAuthorizationResult {
    /// Results of the authorization checks
    pub allow: Vec<AuthorizationResult>,
}

// Models for all-tenants authorization
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct TenantAuthorizationResult {
    /// Whether the action is allowed for this tenant
    pub allow: bool,
    /// Tenant details
    pub tenant: TenantDetails,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct AllTenantsAuthorizationResult {
    /// List of tenants where the action is allowed
    pub allowed_tenants: Vec<TenantAuthorizationResult>,
}

// Models for the /authorized-users endpoint
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct AuthorizedUsersAuthorizationQuery {
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

// For backward compatibility
#[allow(dead_code)]
pub type AuthorizedUsersQuery = AuthorizedUsersAuthorizationQuery;

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

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct AuthorizedUsersResult {
    /// Resource identifier
    pub resource: String,
    /// Tenant identifier
    pub tenant: String,
    /// Map of user keys to their assignments
    pub users: HashMap<String, Vec<AuthorizedUserAssignment>>,
}

// For backward compatibility
#[allow(dead_code)]
pub type AuthorizedUsersResponse = AuthorizedUsersResult;

// Models for user tenants
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct UserTenantsQuery {
    /// User details
    pub user: User,
    /// Additional context for permission evaluation
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub context: HashMap<String, serde_json::Value>,
}

#[allow(dead_code)]
pub type UserTenantsResult = Vec<TenantDetails>;
