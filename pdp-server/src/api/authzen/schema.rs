use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;

// Import the OPA client types for conversion
use crate::opa_client::allowed::{Resource, User};

/// AuthZen Subject - represents the user in AuthZen protocol
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct AuthZenSubject {
    /// Type of the subject
    pub r#type: String,
    /// Unique identifier of the subject
    pub id: String,
    /// Optional properties of the subject
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<HashMap<String, serde_json::Value>>,
}

/// AuthZen Resource - represents the resource in AuthZen protocol
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct AuthZenResource {
    /// Type of the resource
    pub r#type: String,
    /// Unique identifier of the resource
    pub id: String,
    /// Optional properties of the resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<HashMap<String, serde_json::Value>>,
}

/// AuthZen Action - represents the action in AuthZen protocol
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct AuthZenAction {
    /// Name of the action
    pub name: String,
    /// Optional properties of the action
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<HashMap<String, serde_json::Value>>,
}

// Common conversion implementations to reduce duplication across search handlers

/// Convert AuthZenSubject to OPA User type
impl From<AuthZenSubject> for User {
    fn from(val: AuthZenSubject) -> Self {
        User {
            key: val.id,
            first_name: None,
            last_name: None,
            email: None,
            attributes: val.properties.unwrap_or_default(),
        }
    }
}

/// Convert AuthZenResource to OPA Resource type
impl From<AuthZenResource> for Resource {
    fn from(val: AuthZenResource) -> Self {
        Resource {
            r#type: val.r#type,
            key: Some(val.id),
            tenant: None,
            attributes: val.properties.unwrap_or_default(),
            context: HashMap::new(),
        }
    }
}
