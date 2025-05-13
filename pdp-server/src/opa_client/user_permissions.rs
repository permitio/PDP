use std::collections::HashMap;

use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::models::{UserPermissionsQuery, UserPermissionsResult};
use crate::opa_client::{send_request_to_opa, ForwardingError};
use crate::state::AppState;

// Define a newtype wrapper for HashMap<String, UserPermissionsResult>
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, ToSchema)]
pub struct UserPermissionsResults(pub HashMap<String, UserPermissionsResult>);

// Implement IntoResponse for our newtype
impl IntoResponse for UserPermissionsResults {
    fn into_response(self) -> Response {
        Json(self.0).into_response()
    }
}

/// Send a user permissions query to OPA and get the result
pub async fn query_user_permissions(
    state: &AppState,
    query: &UserPermissionsQuery,
) -> Result<HashMap<String, UserPermissionsResult>, ForwardingError> {
    // Send the request to OPA and get the raw JSON result
    let response: serde_json::Value =
        send_request_to_opa(state, "/v1/data/permit/user_permissions", query).await?;

    // Extract the permissions from the response
    // The structure can be either {"result": {"permissions": {...}}} or just {"permissions": {...}}
    if let serde_json::Value::Object(map) = &response {
        // First try to get the "result" field, then the "permissions" field
        if let Some(result) = map.get("result") {
            if let serde_json::Value::Object(result_map) = result {
                if let Some(permissions) = result_map.get("permissions") {
                    return Ok(serde_json::from_value(permissions.clone())?);
                }
            }
        }

        // If there's no "result" field, try to get the "permissions" field directly
        if let Some(permissions) = map.get("permissions") {
            return Ok(serde_json::from_value(permissions.clone())?);
        }
    }

    // If we couldn't find the permissions, return an empty map
    Ok(HashMap::new())
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
                if let Some(result) = map.get("result") {
                    if let serde_json::Value::Object(result_map) = result {
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
        // Test with a response that has permissions directly at the top level
        let direct_response = json!({
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
        });

        // Extract permissions using the same logic as query_user_permissions
        let permissions: HashMap<String, UserPermissionsResult> =
            if let serde_json::Value::Object(map) = &direct_response {
                if let Some(permissions) = map.get("permissions") {
                    serde_json::from_value(permissions.clone()).unwrap()
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
}
