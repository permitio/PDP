use crate::api::authzen::schema::{AuthZenAction, AuthZenResource, AuthZenSubject};
use crate::errors::ApiError;
use crate::opa_client::allowed::User as OpaUser;
use crate::opa_client::{ForwardingError, OpaRequest};
use crate::openapi::AUTHZEN_TAG;
use crate::state::AppState;
use axum::{
    extract::{Json, State},
    response::{IntoResponse, Response},
};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;

// Helper function to send a request to OPA
async fn send_to_opa<T: Serialize>(
    state: &AppState,
    endpoint: &str,
    body: &T,
) -> Result<serde_json::Value, ForwardingError> {
    // Create a new OPA request
    let request = OpaRequest {
        input: serde_json::to_value(body)?,
    };

    // Send the request to OPA
    let client = &state.opa_client;
    let endpoint = endpoint.strip_prefix("/").unwrap_or(endpoint);
    let opa_url = format!("{}/{}", state.config.opa.url, endpoint);

    // Send the request
    let response = client.post(&opa_url).json(&request).send().await?;

    // Check if the request was successful
    if !response.status().is_success() {
        let status = response.status();
        return Err(ForwardingError::InvalidStatus(status));
    }

    // Parse the response body
    let body = response.bytes().await?;
    let full_response: serde_json::Value = serde_json::from_slice(&body)?;

    // Extract the result field
    if let serde_json::Value::Object(map) = &full_response {
        if let Some(result) = map.get("result") {
            return Ok(result.clone());
        }
    }

    Ok(serde_json::Value::Null)
}

/// AuthZen Resource Search Request - to find resources a subject can access
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct ResourceSearchRequest {
    /// Subject making the request
    pub subject: AuthZenSubject,
    /// Action being performed
    pub action: Option<AuthZenAction>,
    /// Resource type to filter by
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    /// Context for the evaluation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<HashMap<String, serde_json::Value>>,
    /// Pagination parameters
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<PageRequest>,
}

/// Pagination request parameters
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct PageRequest {
    /// Token for retrieving the next page of results
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_token: Option<String>,
    /// Maximum number of results to return per page
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<i32>,
}

/// Pagination response parameters
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct PageResponse {
    /// Token for retrieving the next page of results, empty if no more results
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_token: Option<String>,
}

/// Resource action pair representing a permission
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct ResourceAction {
    /// Resource that can be accessed
    pub resource: AuthZenResource,
    /// Action that can be performed
    pub action: AuthZenAction,
}

/// AuthZen Resource Search Response - contains list of resources a subject can access
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct ResourceSearchResponse {
    /// List of resources the subject can access
    pub results: Vec<AuthZenResource>,
    /// Pagination information
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<PageResponse>,
    /// Optional additional context
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<HashMap<String, serde_json::Value>>,
}

// Internal structure to interface with OPA
#[derive(Debug, Serialize, Deserialize, Clone)]
struct OpaResourceSearchRequest {
    user: OpaUser,
    action: Option<String>,
    resource_type: Option<String>,
    context: HashMap<String, serde_json::Value>,
    sdk: Option<String>,
}

// Internal structure to receive OPA response
#[derive(Debug, Serialize, Deserialize, Clone)]
struct OpaResourceSearchResponse {
    permissions: HashMap<String, UserPermission>,
}

// Structure to receive user permission data from OPA
#[derive(Debug, Serialize, Deserialize, Clone)]
struct UserPermission {
    tenant: Option<TenantInfo>,
    resource: ResourceInfo,
    permissions: Vec<String>,
    roles: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct TenantInfo {
    key: String,
    attributes: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ResourceInfo {
    key: String,
    r#type: String,
    attributes: HashMap<String, serde_json::Value>,
}

// Convert AuthZen request to OPA request
impl From<ResourceSearchRequest> for OpaResourceSearchRequest {
    fn from(req: ResourceSearchRequest) -> Self {
        let user = OpaUser {
            key: req.subject.id.clone(),
            first_name: None,
            last_name: None,
            email: None,
            attributes: req.subject.properties.unwrap_or_default(),
        };

        let action = req.action.map(|a| a.name);

        OpaResourceSearchRequest {
            user,
            action,
            resource_type: req.resource_type,
            context: req.context.unwrap_or_default(),
            sdk: Some("authzen".to_string()),
        }
    }
}

// Convert OPA response to AuthZen response
impl From<OpaResourceSearchResponse> for ResourceSearchResponse {
    fn from(res: OpaResourceSearchResponse) -> Self {
        // Extract unique resources from permissions
        let mut unique_resources = HashMap::new();

        // Process each permission and extract the resources
        for (_, perm) in res.permissions {
            let resource = AuthZenResource {
                r#type: perm.resource.r#type.clone(),
                id: perm.resource.key.clone(),
                properties: if perm.resource.attributes.is_empty() {
                    None
                } else {
                    Some(perm.resource.attributes)
                },
            };

            // Use the resource ID as key to ensure uniqueness
            unique_resources.insert(resource.id.clone(), resource);
        }

        // Convert the unique resources HashMap to a Vec
        let results = unique_resources
            .into_iter()
            .map(|(_, resource)| resource)
            .collect();

        ResourceSearchResponse {
            results,
            page: Some(PageResponse {
                next_token: None, // Pagination not yet fully implemented
            }),
            context: None,
        }
    }
}

#[utoipa::path(
    post,
    path = "/access/v1/search/resource",
    tag = AUTHZEN_TAG,
    request_body = ResourceSearchRequest,
    params(
        ("Authorization" = String, Header, description = "Authorization header"),
        ("X-Request-ID" = String, Header, description = "Request Identifier"),
    ),
    responses(
        (status = 200, description = "Resource search completed successfully", body = ResourceSearchResponse),
        (status = 400, description = "Bad Request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn search_resource_handler(
    State(state): State<AppState>,
    Json(request): Json<ResourceSearchRequest>,
) -> Response {
    // Convert AuthZen request to OPA format
    let opa_request: OpaResourceSearchRequest = request.into();

    // Send request to OPA - get the raw JSON response first
    match send_to_opa(&state, "/v1/data/permit/user_permissions", &opa_request).await {
        Ok(result) => {
            // Extract the "permissions" field from the result
            if let serde_json::Value::Object(map) = result {
                if let Some(permissions_value) = map.get("permissions") {
                    // Try to deserialize the permissions map
                    match serde_json::from_value::<HashMap<String, UserPermission>>(
                        permissions_value.clone(),
                    ) {
                        Ok(permissions) => {
                            // Create the OPA response structure
                            let opa_response = OpaResourceSearchResponse { permissions };

                            // Convert to AuthZen response
                            let authzen_response: ResourceSearchResponse = opa_response.into();

                            // Return the response
                            return (StatusCode::OK, Json(authzen_response)).into_response();
                        }
                        Err(err) => {
                            log::error!("Failed to deserialize permissions map: {}", err);
                            return ApiError::internal("Invalid permissions in OPA response")
                                .into_response();
                        }
                    }
                }
            }

            // If we get here, we didn't find the permissions field or it wasn't valid
            // Return an empty result
            let empty_response = ResourceSearchResponse {
                results: Vec::new(),
                page: Some(PageResponse { next_token: None }),
                context: None,
            };

            (StatusCode::OK, Json(empty_response)).into_response()
        }
        Err(err) => {
            log::error!("Failed to process AuthZen resource search request: {}", err);
            ApiError::from(err).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestFixture;
    use serde_json::json;

    #[tokio::test]
    async fn test_resource_search_with_permissions() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Test AuthZen request
        let test_request = json!({
            "subject": {
                "type": "user",
                "id": "alice@acmecorp.com"
            }
        });

        // Mock OPA response with permissions
        let mock_response = json!({
            "result": {
                "permissions": {
                    "resource1": {
                        "tenant": {
                            "key": "tenant1",
                            "attributes": {}
                        },
                        "resource": {
                            "key": "doc1",
                            "type": "document",
                            "attributes": {
                                "title": "Important Document"
                            }
                        },
                        "permissions": ["can_read", "can_edit"],
                        "roles": ["editor"]
                    },
                    "resource2": {
                        "tenant": {
                            "key": "tenant1",
                            "attributes": {}
                        },
                        "resource": {
                            "key": "doc2",
                            "type": "document",
                            "attributes": {
                                "title": "Another Document"
                            }
                        },
                        "permissions": ["can_read"],
                        "roles": ["viewer"]
                    }
                }
            }
        });

        // Set up the mock response
        fixture
            .add_opa_mock(
                http::Method::POST,
                "/v1/data/permit/user_permissions",
                mock_response,
                http::StatusCode::OK,
                1,
            )
            .await;

        // Send the request using the fixture's post method
        let response = fixture
            .post("/access/v1/search/resource", &test_request)
            .await;

        // Assert the response
        response.assert_ok();

        // Parse the response body
        let search_response: ResourceSearchResponse = response.json_as();

        // Check the response - should have 2 unique resources
        assert_eq!(search_response.results.len(), 2);

        // Find the first document
        let doc1 = search_response
            .results
            .iter()
            .find(|res| res.id == "doc1")
            .unwrap();
        assert_eq!(doc1.r#type, "document");
        assert!(doc1.properties.is_some());
        assert_eq!(
            doc1.properties.as_ref().unwrap().get("title").unwrap(),
            "Important Document"
        );

        // Find the second document
        let doc2 = search_response
            .results
            .iter()
            .find(|res| res.id == "doc2")
            .unwrap();
        assert_eq!(doc2.r#type, "document");
        assert!(doc2.properties.is_some());
        assert_eq!(
            doc2.properties.as_ref().unwrap().get("title").unwrap(),
            "Another Document"
        );

        // Verify page is present
        assert!(search_response.page.is_some());
    }

    #[tokio::test]
    async fn test_resource_search_without_permissions() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Test AuthZen request
        let test_request = json!({
            "subject": {
                "type": "user",
                "id": "bob@acmecorp.com"
            }
        });

        // Mock OPA response with no permissions
        let mock_response = json!({
            "result": {
                "permissions": {}
            }
        });

        // Set up the mock response
        fixture
            .add_opa_mock(
                http::Method::POST,
                "/v1/data/permit/user_permissions",
                mock_response,
                http::StatusCode::OK,
                1,
            )
            .await;

        // Send the request using the fixture's post method
        let response = fixture
            .post("/access/v1/search/resource", &test_request)
            .await;

        // Assert the response
        response.assert_ok();

        // Parse the response body
        let search_response: ResourceSearchResponse = response.json_as();

        // Check the response (should be empty)
        assert_eq!(search_response.results.len(), 0);

        // Verify page is present
        assert!(search_response.page.is_some());
    }

    #[tokio::test]
    async fn test_resource_search_with_action_filter() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Test AuthZen request with action filter
        let test_request = json!({
            "subject": {
                "type": "user",
                "id": "alice@acmecorp.com"
            },
            "action": {
                "name": "can_read"
            }
        });

        // Mock OPA response with permissions
        let mock_response = json!({
            "result": {
                "permissions": {
                    "resource1": {
                        "tenant": {
                            "key": "tenant1",
                            "attributes": {}
                        },
                        "resource": {
                            "key": "doc1",
                            "type": "document",
                            "attributes": {
                                "title": "Important Document"
                            }
                        },
                        "permissions": ["can_read"],
                        "roles": ["viewer"]
                    }
                }
            }
        });

        // Set up the mock response
        fixture
            .add_opa_mock(
                http::Method::POST,
                "/v1/data/permit/user_permissions",
                mock_response,
                http::StatusCode::OK,
                1,
            )
            .await;

        // Send the request using the fixture's post method
        let response = fixture
            .post("/access/v1/search/resource", &test_request)
            .await;

        // Assert the response
        response.assert_ok();

        // Parse the response body
        let search_response: ResourceSearchResponse = response.json_as();

        // Check the response (should have 1 resource)
        assert_eq!(search_response.results.len(), 1);

        // Verify resource details
        let doc = &search_response.results[0];
        assert_eq!(doc.id, "doc1");
        assert_eq!(doc.r#type, "document");

        // Verify page is present
        assert!(search_response.page.is_some());
    }

    #[tokio::test]
    async fn test_resource_search_with_pagination() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Test AuthZen request with pagination
        let test_request = json!({
            "subject": {
                "type": "user",
                "id": "alice@acmecorp.com"
            },
            "page": {
                "size": 10,
                "next_token": null
            }
        });

        // Mock OPA response with permissions
        let mock_response = json!({
            "result": {
                "permissions": {
                    "resource1": {
                        "tenant": {
                            "key": "tenant1",
                            "attributes": {}
                        },
                        "resource": {
                            "key": "doc1",
                            "type": "document",
                            "attributes": {
                                "title": "Important Document"
                            }
                        },
                        "permissions": ["can_read", "can_edit"],
                        "roles": ["editor"]
                    }
                }
            }
        });

        // Set up the mock response
        fixture
            .add_opa_mock(
                http::Method::POST,
                "/v1/data/permit/user_permissions",
                mock_response,
                http::StatusCode::OK,
                1,
            )
            .await;

        // Send the request using the fixture's post method
        let response = fixture
            .post("/access/v1/search/resource", &test_request)
            .await;

        // Assert the response
        response.assert_ok();

        // Parse the response body
        let search_response: ResourceSearchResponse = response.json_as();

        // Check the response
        assert_eq!(search_response.results.len(), 1);

        // Verify page is present
        assert!(search_response.page.is_some());
    }
}
