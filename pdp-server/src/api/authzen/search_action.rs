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
    /// List of actions the subject can perform
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

        // Create the query with SDK field included for AuthZen compatibility
        let context = req.context.unwrap_or_default();
        UserPermissionsQuery {
            user,
            tenants: tenant.map(|v| vec![v]),
            // No need to create a resource string - the user_permissions API expects resources as array of strings
            resources: Some(vec![req.resource.id.clone()]),
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
    // Convert directly to UserPermissionsQuery
    let user_permissions_query: UserPermissionsQuery = request.into();

    // Query user permissions using the existing client
    let permissions_map = match query_user_permissions(&state, &user_permissions_query).await {
        Ok(permissions_map) => permissions_map,
        Err(err) => {
            log::error!("Failed to process AuthZen action search request: {:?}", err);
            let authzen_error = AuthZenError::from(err);
            return authzen_error.into_response();
        }
    };
    // Extract permissions and roles from all results
    let mut all_permissions = Vec::new();

    for (_, result) in permissions_map.iter() {
        all_permissions.extend(result.permissions.clone());
    }

    // Remove duplicates
    all_permissions.sort();
    all_permissions.dedup();

    // Convert directly to AuthZen response format
    let results = all_permissions
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
            next_token: None, // Pagination not yet fully implemented
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
                                "permissions": ["can_read", "can_edit"],
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
        println!("Search response: {:?}", search_response);

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
                                "permissions": ["can_read"],
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
        println!("Search response: {:?}", search_response);

        // Check the response (should have 1 action)
        assert_eq!(search_response.results.len(), 1);
        assert_eq!(search_response.results[0].name, "can_read");

        // Verify page is present
        assert!(search_response.page.is_some());
    }
}
