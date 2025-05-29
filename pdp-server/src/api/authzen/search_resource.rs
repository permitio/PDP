use crate::api::authzen::common::{PageRequest, PageResponse};
use crate::api::authzen::errors::AuthZenError;
use crate::api::authzen::schema::{AuthZenAction, AuthZenResource, AuthZenSubject};
use crate::opa_client::user_permissions::{query_user_permissions, UserPermissionsQuery};
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

// Convert AuthZen request to UserPermissionsQuery
impl From<ResourceSearchRequest> for UserPermissionsQuery {
    fn from(req: ResourceSearchRequest) -> Self {
        UserPermissionsQuery {
            user: req.subject.into(),
            tenants: None,
            resources: None,
            resource_types: req.resource_type.map(|rt| vec![rt]),
            context: Some(req.context.unwrap_or_default()),
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
        (status = 400, description = "Bad Request", body = String),
        (status = 401, description = "Unauthorized", body = String),
        (status = 403, description = "Forbidden", body = String),
        (status = 500, description = "Internal server error", body = String)
    )
)]
pub async fn search_resource_handler(
    State(state): State<AppState>,
    Json(request): Json<ResourceSearchRequest>,
) -> Response {
    // Convert AuthZen request to UserPermissionsQuery
    let query: UserPermissionsQuery = request.into();

    // Query OPA using the existing function
    let permissions = match query_user_permissions(&state, &query).await {
        Ok(permissions) => permissions,
        Err(err) => {
            log::error!(
                "Failed to process AuthZen resource search request: {:?}",
                err
            );
            let authzen_error = AuthZenError::from(err);
            return authzen_error.into_response();
        }
    };

    // Extract unique resources from permissions
    let mut unique_resources = HashMap::new();

    // Process each permission and extract the resources
    for (_, perm) in permissions {
        if let Some(resource_details) = perm.resource {
            let resource = AuthZenResource {
                r#type: resource_details.r#type.clone(),
                id: resource_details.key.clone(),
                properties: if resource_details.attributes.is_empty() {
                    None
                } else {
                    Some(resource_details.attributes)
                },
            };

            // Use the resource ID as key to ensure uniqueness
            unique_resources.insert(resource.id.clone(), resource);
        }
    }

    // Convert the unique resources HashMap to a Vec
    let results = unique_resources.into_values().collect();

    // Create the response
    let response = ResourceSearchResponse {
        results,
        page: Some(PageResponse {
            next_token: None, // Pagination not yet fully implemented
        }),
        context: None,
    };

    (StatusCode::OK, Json(response)).into_response()
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
                "id": "alice@example.com"
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
                "id": "bob@example.com"
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
                "id": "alice@example.com"
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
                "id": "alice@example.com"
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
