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

/// AuthZen Action Search Request - to find what actions a subject can perform on a resource
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct ActionSearchRequest {
    /// Subject making the request
    pub subject: AuthZenSubject,
    /// Resource being accessed
    pub resource: AuthZenResource,
    /// Context for the evaluation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<HashMap<String, serde_json::Value>>,
    /// Pagination parameters
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<PageRequest>,
}

/// AuthZen Action Search Response - contains list of actions the subject can perform on the resource
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct ActionSearchResponse {
    /// Actions the subject can perform on the resource, by name (`read`, not `document:read`),
    /// sorted by name, comparing strings by code point
    pub results: Vec<AuthZenAction>,
    /// Pagination information
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<PageResponse>,
    /// Optional additional context
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<HashMap<String, serde_json::Value>>,
}

// Direct conversion from ActionSearchRequest to UserPermissionsQuery
impl From<ActionSearchRequest> for UserPermissionsQuery {
    fn from(req: ActionSearchRequest) -> Self {
        // Convert AuthZenSubject to User using the common Into implementation
        let user = req.subject.into();
        let tenant = req
            .resource
            .properties
            .unwrap_or_default()
            .get("tenant")
            .map(|v| v.to_string());

        let resources = req.resource.id.map(|id| vec![id]);

        // Create the query with SDK field included for AuthZen compatibility
        let context = req.context.unwrap_or_default();
        UserPermissionsQuery {
            user,
            tenants: tenant.map(|v| vec![v]),
            // No need to create a resource string - the user_permissions API expects resources as array of strings
            resources,
            resource_types: Some(vec![req.resource.r#type.clone()]),
            context: Some(context),
        }
    }
}

#[utoipa::path(
    post,
    path = "/access/v1/search/action",
    tag = AUTHZEN_TAG,
    request_body = ActionSearchRequest,
    params(
        ("Authorization" = String, Header, description = "Authorization header"),
        ("X-Request-ID" = String, Header, description = "Request Identifier"),
    ),
    responses(
        (status = 200, description = "Action search completed successfully", body = ActionSearchResponse),
        (status = 400, description = "Bad Request", body = String),
        (status = 401, description = "Unauthorized", body = String),
        (status = 403, description = "Forbidden", body = String),
        (status = 500, description = "Internal server error", body = String)
    )
)]
pub async fn search_action_handler(
    State(state): State<AppState>,
    Json(request): Json<ActionSearchRequest>,
) -> Response {
    let resource_type = request.resource.r#type.clone();
    let user_permissions_query: UserPermissionsQuery = request.into();

    // Query user permissions using the existing client
    let permissions_map = match query_user_permissions(&state, &user_permissions_query).await {
        Ok(permissions_map) => permissions_map,
        Err(err) => {
            log::error!("Failed to process AuthZen action search request: {err:?}");
            let authzen_error = AuthZenError::from(err);
            return authzen_error.into_response();
        }
    };
    // OPA lists permissions as `<resource type>:<action>`. The results are the actions on the
    // requested resource type.
    let mut action_names = Vec::new();
    for result in permissions_map.values() {
        for permission in &result.permissions {
            let Some((permission_type, action_name)) = permission.split_once(':') else {
                log::warn!(
                    "Ignoring permission {permission:?} from OPA user_permissions: \
                     expected <resource type>:<action>"
                );
                continue;
            };
            if permission_type == resource_type {
                action_names.push(action_name.to_string());
            }
        }
    }
    action_names.sort();
    action_names.dedup();

    let results = action_names
        .into_iter()
        .map(|name| AuthZenAction {
            name,
            properties: None,
        })
        .collect();

    // Create and return the AuthZen response
    let authzen_response = ActionSearchResponse {
        results,
        page: Some(PageResponse {
            next_token: String::new(),
        }),
        context: None,
    };

    // Return the response
    (StatusCode::OK, Json(authzen_response)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestFixture;
    use serde_json::json;

    #[tokio::test]
    async fn test_action_search_with_permissions() {
        let fixture = TestFixture::new().await;
        // Set up the mock response
        fixture
            .add_opa_mock(
                http::Method::POST,
                "/v1/data/permit/user_permissions",
                json!({
                    "result": {
                        "permissions": {
                            "document:doc1": {
                                "tenant": null,
                                "resource": null,
                                "permissions": ["document:can_read", "document:can_edit"],
                                "roles": ["editor"]
                            }
                        }
                    }
                }),
                http::StatusCode::OK,
                1,
            )
            .await;

        // Send the request using the fixture's post method
        let response = fixture
            .post(
                "/access/v1/search/action",
                &json!({
                    "subject": {
                        "type": "user",
                        "id": "alice@example.com"
                    },
                    "resource": {
                        "type": "document",
                        "id": "doc1"
                    }
                }),
            )
            .await;

        // Assert the response
        response.assert_ok();

        // Parse the response body
        let search_response: ActionSearchResponse = response.json_as();

        // Print the search response for debugging
        println!("Search response: {search_response:?}");

        // Check the response - should have 2 actions
        assert_eq!(search_response.results.len(), 2);

        // Find the read permission
        let read_action = search_response
            .results
            .iter()
            .find(|action| action.name == "can_read")
            .unwrap();
        assert!(read_action.properties.is_none());

        // Find the edit permission
        let edit_action = search_response
            .results
            .iter()
            .find(|action| action.name == "can_edit")
            .unwrap();
        assert!(edit_action.properties.is_none());

        // Verify page is present
        assert!(search_response.page.is_some());
    }

    #[tokio::test]
    async fn test_action_search_without_permissions() {
        let fixture = TestFixture::new().await;
        fixture
            .add_opa_mock(
                http::Method::POST,
                "/v1/data/permit/user_permissions",
                json!({
                    "result": {
                        "permissions": {}
                    }
                }),
                http::StatusCode::OK,
                1,
            )
            .await;

        // Send the request using the fixture's post method
        let response = fixture
            .post(
                "/access/v1/search/action",
                &json!({
                    "subject": {
                        "type": "user",
                        "id": "bob@example.com"
                    },
                    "resource": {
                        "type": "document",
                        "id": "doc1"
                    }
                }),
            )
            .await;

        // Assert the response
        response.assert_ok();
        let search_response: ActionSearchResponse = response.json_as();
        assert_eq!(search_response.results.len(), 0);
        assert!(search_response.page.is_some());
    }

    #[tokio::test]
    async fn test_action_search_with_pagination() {
        let fixture = TestFixture::new().await;
        fixture
            .add_opa_mock(
                http::Method::POST,
                "/v1/data/permit/user_permissions",
                json!({
                    "result": {
                        "permissions": {
                            "document:doc1": {
                                "tenant": null,
                                "resource": null,
                                "permissions": ["document:can_read"],
                                "roles": ["viewer"]
                            }
                        }
                    }
                }),
                http::StatusCode::OK,
                1,
            )
            .await;

        // Send the request using the fixture's post method
        let response = fixture
            .post(
                "/access/v1/search/action",
                &json!({
                    "subject": {
                        "type": "user",
                        "id": "alice@example.com"
                    },
                    "resource": {
                        "type": "document",
                        "id": "doc1"
                    },
                    "page": {
                        "size": 10,
                        "next_token": null
                    }
                }),
            )
            .await;

        // Assert the response
        response.assert_ok();

        // Parse the response body
        let search_response: ActionSearchResponse = response.json_as();

        // Print the search response for debugging
        println!("Search response: {search_response:?}");

        // Check the response (should have 1 action)
        assert_eq!(search_response.results.len(), 1);
        assert_eq!(search_response.results[0].name, "can_read");

        // Verify page is present
        assert!(search_response.page.is_some());
    }

    /// A `user_permissions` OPA result with overlapping permission lists in no particular
    /// order. `Can_admin` shows that names compare by code point.
    fn overlapping_permissions_response() -> serde_json::Value {
        json!({
            "result": {
                "permissions": {
                    "document:doc1": {
                        "permissions": ["document:can_write", "document:can_read", "document:can_delete"],
                        "roles": ["editor"]
                    },
                    "document:doc2": {
                        "permissions": ["document:can_read", "document:can_archive", "document:Can_admin"],
                        "roles": ["admin"]
                    },
                    "document:doc3": {
                        "permissions": ["document:can_share", "document:can_write", "document:can_comment"],
                        "roles": ["editor"]
                    },
                    "document:doc4": {
                        "permissions": ["document:can_read", "document:can_export", "document:can_print"],
                        "roles": ["viewer"]
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

    fn action_search_request() -> serde_json::Value {
        json!({
            "subject": {"type": "user", "id": "alice@example.com"},
            "resource": {"type": "document", "id": "doc1"}
        })
    }

    #[tokio::test]
    async fn test_action_search_sorts_and_deduplicates_results_by_name() {
        let fixture = TestFixture::new().await;
        mock_user_permissions(&fixture, overlapping_permissions_response(), 1).await;

        let response = fixture
            .post("/access/v1/search/action", &action_search_request())
            .await;

        response.assert_ok();
        let search_response: ActionSearchResponse = response.json_as();
        let mut names = Vec::new();
        for action in &search_response.results {
            names.push(action.name.as_str());
        }
        assert_eq!(
            names,
            vec![
                "Can_admin",
                "can_archive",
                "can_comment",
                "can_delete",
                "can_export",
                "can_print",
                "can_read",
                "can_share",
                "can_write",
            ]
        );
    }

    #[tokio::test]
    async fn test_action_search_repeated_calls_return_identical_bodies() {
        const CALLS: u64 = 10;
        let fixture = TestFixture::new().await;
        mock_user_permissions(&fixture, overlapping_permissions_response(), CALLS).await;

        let first = fixture
            .post("/access/v1/search/action", &action_search_request())
            .await;
        first.assert_ok();
        for call in 2..=CALLS {
            let response = fixture
                .post("/access/v1/search/action", &action_search_request())
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
    async fn test_action_search_ignores_page_and_returns_empty_next_token() {
        let fixture = TestFixture::new().await;
        mock_user_permissions(&fixture, overlapping_permissions_response(), 1).await;
        let mut request = action_search_request();
        request["page"] = json!({"size": 1, "next_token": null});

        let response = fixture.post("/access/v1/search/action", &request).await;

        response.assert_ok();
        let body = response.json();
        assert_eq!(body["page"], json!({"next_token": ""}));
        assert_eq!(body["results"].as_array().map(Vec::len), Some(9));
    }

    /// One `user_permissions` entry for `file:a1`, in the shape OPA returns.
    fn file_a1_permissions_response(permissions: &[&str]) -> serde_json::Value {
        json!({
            "result": {
                "permissions": {
                    "file:a1": {
                        "permissions": permissions,
                        "resource": {"attributes": {}, "key": "a1", "type": "file"},
                        "roles": ["owner"],
                        "tenant": {"attributes": {}, "key": "t1", "type": "__tenant"}
                    }
                }
            }
        })
    }

    async fn search_file_a1_actions(fixture: &TestFixture) -> Vec<String> {
        let request = json!({
            "subject": {"type": "user", "id": "frank"},
            "resource": {"type": "file", "id": "a1"}
        });
        let response = fixture.post("/access/v1/search/action", &request).await;
        response.assert_ok();
        let search_response: ActionSearchResponse = response.json_as();
        let mut names = Vec::new();
        for action in search_response.results {
            names.push(action.name);
        }
        names
    }

    #[tokio::test]
    async fn test_action_search_returns_action_names_not_permission_keys() {
        let fixture = TestFixture::new().await;
        mock_user_permissions(
            &fixture,
            file_a1_permissions_response(&["file:read", "file:delete"]),
            1,
        )
        .await;

        assert_eq!(
            search_file_a1_actions(&fixture).await,
            vec!["delete", "read"]
        );
    }

    #[tokio::test]
    async fn test_action_search_skips_permissions_on_other_types_and_without_a_type() {
        let fixture = TestFixture::new().await;
        mock_user_permissions(
            &fixture,
            file_a1_permissions_response(&["file:read", "folder:delete", "share"]),
            1,
        )
        .await;

        assert_eq!(search_file_a1_actions(&fixture).await, vec!["read"]);
    }
}
