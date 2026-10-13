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
use std::collections::{BTreeMap, HashMap};
use utoipa::ToSchema;

/// AuthZen Resource Search Request - to find resources a subject can access
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct ResourceSearchRequest {
    /// Subject making the request
    pub subject: AuthZenSubject,
    /// Action being performed
    pub action: AuthZenAction,
    /// Resource type to filter by
    pub resource: AuthZenResource,
    /// Context for the evaluation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<HashMap<String, serde_json::Value>>,
    /// Pagination parameters
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<PageRequest>,
}

/// AuthZen Resource Search Response - contains list of resources a subject can access
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct ResourceSearchResponse {
    /// Resources on which the subject can perform the action, one per type and id, sorted by
    /// type, then id, comparing strings by code point
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
        let mut properties = req.resource.properties.unwrap_or_default();
        let tenant = properties.remove("tenant").map(|v| v.to_string());
        UserPermissionsQuery {
            user: req.subject.into(),
            tenants: tenant.map(|v| vec![v]),
            resources: None,
            resource_types: Some(vec![req.resource.r#type.clone()]),
            context: req.context,
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
    let action = request.action.name.clone();
    let query: UserPermissionsQuery = request.into();

    // Query OPA using the existing function
    let permissions = match query_user_permissions(&state, &query).await {
        Ok(permissions) => permissions,
        Err(err) => {
            log::error!("Failed to process AuthZen resource search request: {err:?}");
            let authzen_error = AuthZenError::from(err);
            return authzen_error.into_response();
        }
    };

    // `permissions` is a HashMap, so it iterates in a different order on every call. Reading it
    // in OPA key order means that when several entries describe the same resource, the same
    // one (the first by OPA key) supplies the properties every time.
    let permissions: BTreeMap<_, _> = permissions.into_iter().collect();

    // Keyed by (type, id): one result per resource, sorted by type, then id.
    let mut unique_resources = BTreeMap::new();
    for perm in permissions.into_values() {
        let Some(resource_details) = perm.resource else {
            continue;
        };
        // OPA lists the permissions on a resource as `<resource type>:<action>`.
        let required_permission = format!("{}:{action}", resource_details.r#type);
        if !perm.permissions.contains(&required_permission) {
            continue;
        }
        let resource_key = (
            resource_details.r#type.clone(),
            resource_details.key.clone(),
        );
        unique_resources
            .entry(resource_key)
            .or_insert_with(|| AuthZenResource {
                r#type: resource_details.r#type,
                id: Some(resource_details.key),
                properties: if resource_details.attributes.is_empty() {
                    None
                } else {
                    Some(resource_details.attributes)
                },
            });
    }
    let results = unique_resources.into_values().collect();

    // Create the response
    let response = ResourceSearchResponse {
        results,
        page: Some(PageResponse {
            next_token: String::new(),
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
            },
            "action": {
                "name": "can_read"
            },
            "resource": {
                "type": "document",
            }
        });

        // Mock OPA response with permissions
        let mock_response = json!({
            "result": {
                "permissions": {
                    "document:doc1": {
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
                        "permissions": ["document:can_read", "document:can_edit"],
                        "roles": ["editor"]
                    },
                    "document:doc2": {
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
                        "permissions": ["document:can_read"],
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
            .find(|res| res.id == Some("doc1".to_string()))
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
            .find(|res| res.id == Some("doc2".to_string()))
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
            },
            "action": {
                "name": "can_read"
            },
            "resource": {
                "type": "document",
                "id": ""
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
            },
            "resource": {
                "type": "document",
                "id": ""
            }
        });

        // Mock OPA response with permissions
        let mock_response = json!({
            "result": {
                "permissions": {
                    "document:doc1": {
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
                        "permissions": ["document:can_read"],
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
        assert_eq!(doc.id, Some("doc1".to_string()));
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
            "action": {
                "name": "can_read"
            },
            "resource": {
                "type": "document",
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
                    "document:doc1": {
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
                        "permissions": ["document:can_read", "document:can_edit"],
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

    /// One `user_permissions` entry for a resource instance, in the shape OPA returns.
    fn instance_entry(
        resource_type: &str,
        resource_key: &str,
        attributes: serde_json::Value,
        permissions: &[&str],
    ) -> serde_json::Value {
        json!({
            "permissions": permissions,
            "resource": {"attributes": attributes, "key": resource_key, "type": resource_type},
            "roles": ["viewer"],
            "tenant": {"attributes": {}, "key": "tenant1", "type": "__tenant"}
        })
    }

    /// An instance entry that grants `can_read` on the resource.
    fn permission_entry(
        resource_type: &str,
        resource_key: &str,
        attributes: serde_json::Value,
    ) -> serde_json::Value {
        let can_read = format!("{resource_type}:can_read");
        instance_entry(resource_type, resource_key, attributes, &[&can_read])
    }

    /// A `user_permissions` OPA result whose entries are in no particular order. Ids such as
    /// `doc-10` and `Doc-9` sort by code point, not by number or case. `document:shared`
    /// appears under three OPA keys with different attributes. The tenant-level entry has no
    /// resource and grants an action other than `can_read`.
    fn unordered_permissions_response() -> serde_json::Value {
        json!({
            "result": {
                "permissions": {
                    "document:doc-2": permission_entry("document", "doc-2", json!({})),
                    "folder:doc-1": permission_entry("folder", "doc-1", json!({})),
                    "document:doc-10": permission_entry("document", "doc-10", json!({})),
                    "shared-copy-b": permission_entry("document", "shared", json!({"copy": "b"})),
                    "document:Doc-9": permission_entry("document", "Doc-9", json!({})),
                    "document:doc-1": permission_entry("document", "doc-1", json!({})),
                    "shared-copy-c": permission_entry("document", "shared", json!({"copy": "c"})),
                    "document:doc-3": permission_entry("document", "doc-3", json!({})),
                    "shared-copy-a": permission_entry("document", "shared", json!({"copy": "a"})),
                    "document:doc-11": permission_entry("document", "doc-11", json!({})),
                    "__tenant:tenant1": {
                        "permissions": ["document:can_share"],
                        "roles": ["sharer"],
                        "tenant": {"attributes": {}, "key": "tenant1", "type": "__tenant"}
                    }
                }
            }
        })
    }

    async fn mock_user_permissions(
        fixture: &TestFixture,
        response: serde_json::Value,
        expected_calls: u64,
    ) {
        fixture
            .add_opa_mock(
                http::Method::POST,
                "/v1/data/permit/user_permissions",
                response,
                http::StatusCode::OK,
                expected_calls,
            )
            .await;
    }

    fn resource_search_request() -> serde_json::Value {
        json!({
            "subject": {"type": "user", "id": "alice@example.com"},
            "action": {"name": "can_read"},
            "resource": {"type": "document"}
        })
    }

    #[tokio::test]
    async fn test_resource_search_sorts_results_by_type_then_id() {
        let fixture = TestFixture::new().await;
        mock_user_permissions(&fixture, unordered_permissions_response(), 1).await;

        let response = fixture
            .post("/access/v1/search/resource", &resource_search_request())
            .await;

        response.assert_ok();
        let search_response: ResourceSearchResponse = response.json_as();
        let mut results = Vec::new();
        for resource in &search_response.results {
            results.push((resource.r#type.as_str(), resource.id.as_deref()));
        }
        assert_eq!(
            results,
            vec![
                ("document", Some("Doc-9")),
                ("document", Some("doc-1")),
                ("document", Some("doc-10")),
                ("document", Some("doc-11")),
                ("document", Some("doc-2")),
                ("document", Some("doc-3")),
                ("document", Some("shared")),
                ("folder", Some("doc-1")),
            ]
        );
    }

    #[tokio::test]
    async fn test_resource_search_returns_one_result_per_resource() {
        let fixture = TestFixture::new().await;
        mock_user_permissions(&fixture, unordered_permissions_response(), 1).await;

        let response = fixture
            .post("/access/v1/search/resource", &resource_search_request())
            .await;

        response.assert_ok();
        let search_response: ResourceSearchResponse = response.json_as();
        let mut shared = Vec::new();
        for resource in &search_response.results {
            if resource.id.as_deref() == Some("shared") {
                shared.push(resource);
            }
        }
        assert_eq!(shared.len(), 1, "expected one `shared` result: {shared:?}");
        let expected_properties = HashMap::from([("copy".to_string(), json!("a"))]);
        assert_eq!(
            shared[0].properties.as_ref(),
            Some(&expected_properties),
            "the entry whose OPA key sorts first supplies the properties"
        );
    }

    #[tokio::test]
    async fn test_resource_search_repeated_calls_return_identical_bodies() {
        const CALLS: u64 = 10;
        let fixture = TestFixture::new().await;
        mock_user_permissions(&fixture, unordered_permissions_response(), CALLS).await;

        let first = fixture
            .post("/access/v1/search/resource", &resource_search_request())
            .await;
        first.assert_ok();
        for call in 2..=CALLS {
            let response = fixture
                .post("/access/v1/search/resource", &resource_search_request())
                .await;
            response.assert_ok();
            assert_eq!(
                response.text(),
                first.text(),
                "call {call} returned a different body than call 1"
            );
        }
    }

    #[tokio::test]
    async fn test_resource_search_ignores_page_and_returns_empty_next_token() {
        let fixture = TestFixture::new().await;
        mock_user_permissions(&fixture, unordered_permissions_response(), 1).await;
        let mut request = resource_search_request();
        request["page"] = json!({"size": 1, "next_token": null});

        let response = fixture.post("/access/v1/search/resource", &request).await;

        response.assert_ok();
        let body = response.json();
        assert_eq!(body["page"], json!({"next_token": ""}));
        assert_eq!(body["results"].as_array().map(Vec::len), Some(8));
    }

    /// `user_permissions` as OPA returns it for frank with `resource_types: ["file"]`: a reader
    /// on a1 and b1, an owner of a2, and an auditor on c1, whose only action starts with `read`.
    fn frank_file_permissions_response() -> serde_json::Value {
        json!({
            "result": {
                "permissions": {
                    "file:a1": instance_entry("file", "a1", json!({}), &["file:read"]),
                    "file:a2": instance_entry("file", "a2", json!({}), &["file:read", "file:delete"]),
                    "file:b1": instance_entry("file", "b1", json!({}), &["file:read"]),
                    "file:c1": instance_entry("file", "c1", json!({}), &["file:read_all"])
                }
            }
        })
    }

    async fn search_file_ids(fixture: &TestFixture, action: &str) -> Vec<String> {
        let request = json!({
            "subject": {"type": "user", "id": "frank"},
            "action": {"name": action},
            "resource": {"type": "file"}
        });
        let response = fixture.post("/access/v1/search/resource", &request).await;
        response.assert_ok();
        let search_response: ResourceSearchResponse = response.json_as();
        let mut ids = Vec::new();
        for resource in search_response.results {
            ids.push(resource.id.unwrap_or_default());
        }
        ids
    }

    #[tokio::test]
    async fn test_resource_search_returns_only_resources_that_allow_the_action() {
        let fixture = TestFixture::new().await;
        mock_user_permissions(&fixture, frank_file_permissions_response(), 2).await;

        assert_eq!(search_file_ids(&fixture, "delete").await, vec!["a2"]);
        assert_eq!(
            search_file_ids(&fixture, "read").await,
            vec!["a1", "a2", "b1"]
        );
    }

    #[tokio::test]
    async fn test_resource_search_returns_nothing_when_no_resource_allows_the_action() {
        let fixture = TestFixture::new().await;
        let reader_only = json!({
            "result": {
                "permissions": {
                    "file:a1": instance_entry("file", "a1", json!({}), &["file:read"]),
                    "file:a2": instance_entry("file", "a2", json!({}), &["file:read"]),
                    "file:b1": instance_entry("file", "b1", json!({}), &["file:read"])
                }
            }
        });
        mock_user_permissions(&fixture, reader_only, 1).await;

        assert_eq!(
            search_file_ids(&fixture, "delete").await,
            Vec::<String>::new()
        );
    }
}
