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
    #[serde(default)] // default empty because it's optional on Search Subject API
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    // default empty because it's optional on Search Resource API
    pub id: Option<String>,
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
        let mut properties = val.properties.unwrap_or_default();
        let first_name = properties.remove("first_name").and_then(|v| match v {
            serde_json::Value::String(s) => Some(s),
            _ => None,
        });
        let last_name = properties.remove("last_name").and_then(|v| match v {
            serde_json::Value::String(s) => Some(s),
            _ => None,
        });
        let email = properties.remove("email").and_then(|v| match v {
            serde_json::Value::String(s) => Some(s),
            _ => None,
        });

        User {
            key: val.id,
            first_name,
            last_name,
            email,
            attributes: properties,
        }
    }
}

/// Convert AuthZenResource to OPA Resource type
impl From<AuthZenResource> for Resource {
    fn from(val: AuthZenResource) -> Self {
        let mut properties = val.properties.unwrap_or_default();
        let tenant = properties.remove("tenant").and_then(|v| match v {
            serde_json::Value::String(s) => Some(s),
            _ => None,
        });
        Resource {
            r#type: val.r#type,
            key: val.id,
            tenant,
            attributes: properties,
            context: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_authzen_resource_conversion_with_attributes() {
        // Create an AuthZen resource with complex attributes
        let authzen_resource = serde_json::from_value::<AuthZenResource>(json!({
            "type": "document",
            "id": "doc-123",
            "properties": {
                "tenant": "acme-corp",
                "department": "sales",
                "classification": "confidential",
                "owner": "bob@example.com",
                "created_at": "2023-01-01T00:00:00Z",
                "tags": ["financial", "customer-data"],
                "metadata": {
                    "version": 1,
                    "locked": true
                },
            }
        }))
        .unwrap();

        // Convert to OPA Resource type
        let opa_resource: Resource = authzen_resource.into();

        // Convert to JSON for comparison
        let result_json = serde_json::to_value(&opa_resource).unwrap();

        // Expected JSON structure
        let expected_json = json!({
            "type": "document",
            "key": "doc-123",
            "tenant": "acme-corp",
            "attributes": {
                "department": "sales",
                "classification": "confidential",
                "owner": "bob@example.com",
                "created_at": "2023-01-01T00:00:00Z",
                "tags": ["financial", "customer-data"],
                "metadata": {
                    "version": 1,
                    "locked": true
                }
            },
        });

        assert_eq!(result_json, expected_json);
    }

    #[test]
    fn test_authzen_resource_conversion_minimal() {
        // Test with minimal resource (no properties)
        let authzen_resource = AuthZenResource {
            r#type: "document".to_string(),
            id: Some("doc-456".to_string()),
            properties: None,
        };

        let opa_resource: Resource = authzen_resource.into();
        let result_json = serde_json::to_value(&opa_resource).unwrap();

        let expected_json = json!({
            "type": "document",
            "key": "doc-456"
        });

        assert_eq!(result_json, expected_json);
    }

    #[test]
    fn test_authzen_resource_conversion_tenant_only() {
        // Test with only tenant property
        let authzen_resource = AuthZenResource {
            r#type: "file".to_string(),
            id: Some("file-789".to_string()),
            properties: Some({
                let mut props = HashMap::new();
                props.insert("tenant".to_string(), json!("other-corp"));
                props
            }),
        };

        let opa_resource: Resource = authzen_resource.into();
        let result_json = serde_json::to_value(&opa_resource).unwrap();

        let expected_json = json!({
            "type": "file",
            "key": "file-789",
            "tenant": "other-corp"
        });

        assert_eq!(result_json, expected_json);
    }

    #[test]
    fn test_authzen_subject_conversion_with_attributes() {
        // Create an AuthZen subject with attributes
        let authzen_subject = serde_json::from_value::<AuthZenSubject>(json!({
            "type": "user",
            "id": "alice@example.com",
            "properties": {
                "first_name": "Alice",
                "last_name": "Smith",
                "email": "alice@example.com",
                "department": "engineering",
                "role": "senior",
                "clearance_level": 3,
                "active": true,
            }
        }))
        .unwrap();

        let opa_user: User = authzen_subject.into();
        let result_json = serde_json::to_value(&opa_user).unwrap();

        let expected_json = json!({
            "key": "alice@example.com",
            "first_name": "Alice",
            "last_name": "Smith",
            "email": "alice@example.com",
            "attributes": {
                "department": "engineering",
                "role": "senior",
                "clearance_level": 3,
                "active": true
            }
        });

        assert_eq!(result_json, expected_json);
    }

    #[test]
    fn test_authzen_subject_conversion_minimal() {
        // Test with minimal subject (no properties)
        let authzen_subject = AuthZenSubject {
            r#type: "user".to_string(),
            id: "bob@example.com".to_string(),
            properties: None,
        };

        let opa_user: User = authzen_subject.into();
        let result_json = serde_json::to_value(&opa_user).unwrap();

        let expected_json = json!({
            "key": "bob@example.com"
        });

        assert_eq!(result_json, expected_json);
    }

    #[test]
    fn test_authzen_resource_conversion_without_id() {
        // Test resource without id field (should default to empty string)
        let authzen_resource = serde_json::from_value::<AuthZenResource>(json!({
            "type": "document",
            "id": "doc-123",
            "properties": {
                "tenant": "test-corp",
                "category": "public",
                "size": 1024,
            }
        }))
        .unwrap();

        // Convert to OPA Resource type
        let opa_resource: Resource = authzen_resource.into();
        let result_json = serde_json::to_value(&opa_resource).unwrap();

        // Expected JSON structure - id should default to empty string, key should be empty string
        let expected_json = json!({
            "type": "document",
            "key": "doc-123",
            "tenant": "test-corp",
            "attributes": {
                "category": "public",
                "size": 1024
            }
        });

        assert_eq!(result_json, expected_json);
    }

    #[test]
    fn test_python_test_payload_deserialization() {
        // Test the exact payload from the Python test case to validate schema compliance
        let json_payload = json!({
            "subject": {
                "type": "user",
                "id": "test-user-123"
            },
            "action": {
                "name": "create"
            },
            "resource": {
                "type": "File",
                "id": "file-123",
                "properties": {
                    "tenant": "default",
                    "public": true,
                }
            }
        });

        // Try to deserialize the payload - this should fail if the id field is missing
        let result = serde_json::from_value::<
            crate::api::authzen::evaluation::AccessEvaluationRequest,
        >(json_payload.clone());

        match result {
            Ok(request) => {
                // If successful, verify the resource id defaults correctly
                assert_eq!(request.resource.id, Some("file-123".to_string())); // Should default to empty string
                assert_eq!(request.resource.r#type, "File");
                assert_eq!(request.action.name, "create");
                assert_eq!(request.subject.id, "test-user-123");

                // Verify properties are parsed correctly
                if let Some(properties) = request.resource.properties {
                    assert_eq!(properties.get("tenant").unwrap(), &json!("default"));
                    if let Some(attributes) = properties.get("attributes") {
                        assert_eq!(attributes.get("public").unwrap(), &json!(true));
                    }
                }
            }
            Err(e) => {
                panic!(
                    "Failed to deserialize payload that matches Python test: {}\nPayload: {}",
                    e,
                    serde_json::to_string_pretty(&json_payload).unwrap()
                );
            }
        }
    }

    #[test]
    fn test_python_test_payload_missing_resource_id() {
        // Test the exact payload from the original failing Python test (without explicit id)
        let json_payload = json!({
            "subject": {
                "type": "user",
                "id": "test-user-123"
            },
            "action": {
                "name": "create"
            },
            "resource": {
                "type": "File",
                "id": "file-123",
                "properties": {
                    "tenant": "default",
                    "public": true,
                }
            }
        });

        // Try to deserialize the payload
        let result = serde_json::from_value::<
            crate::api::authzen::evaluation::AccessEvaluationRequest,
        >(json_payload.clone());

        match result {
            Ok(request) => {
                // Verify the resource id defaults to empty string
                assert_eq!(request.resource.id, Some("file-123".to_string()));
                println!("✅ Deserialization successful - resource.id defaulted to empty string");
            }
            Err(e) => {
                println!("❌ Deserialization failed: {}", e);
                println!(
                    "Payload: {}",
                    serde_json::to_string_pretty(&json_payload).unwrap()
                );
                panic!("This is likely the root cause of the 422 error in the Python test");
            }
        }
    }
}
