use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;

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
