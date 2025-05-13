use crate::api::authzen::schema::{AuthZenAction, AuthZenResource, AuthZenSubject};
use crate::errors::ApiError;
use crate::opa_client::allowed::{Resource as OpaResource, User as OpaUser};
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

// Internal structure to interface with OPA
#[derive(Debug, Serialize, Deserialize, Clone)]
struct OpaActionSearchRequest {
    user: OpaUser,
    resource: OpaResource,
    context: HashMap<String, serde_json::Value>,
    sdk: Option<String>,
}

// Internal structure to receive OPA response
#[derive(Debug, Serialize, Deserialize, Clone)]
struct OpaActionSearchResponse {
    permissions: Vec<String>,
    roles: Option<Vec<String>>,
}

// Convert AuthZen request to OPA request
impl From<ActionSearchRequest> for OpaActionSearchRequest {
    fn from(req: ActionSearchRequest) -> Self {
        let user = OpaUser {
            key: req.subject.id.clone(),
            first_name: None,
            last_name: None,
            email: None,
            attributes: req.subject.properties.unwrap_or_default(),
        };

        let resource = OpaResource {
            r#type: req.resource.r#type.clone(),
            key: Some(req.resource.id.clone()),
            tenant: None,
            attributes: req.resource.properties.unwrap_or_default(),
            context: HashMap::new(),
        };

        OpaActionSearchRequest {
            user,
            resource,
            context: req.context.unwrap_or_default(),
            sdk: Some("authzen".to_string()),
        }
    }
}

// Convert OPA response to AuthZen response
impl From<OpaActionSearchResponse> for ActionSearchResponse {
    fn from(res: OpaActionSearchResponse) -> Self {
        let results = res
            .permissions
            .into_iter()
            .map(|name| AuthZenAction {
                name,
                properties: None,
            })
            .collect();

        ActionSearchResponse {
            results,
            page: Some(PageResponse {
                next_token: None, // Pagination not yet fully implemented
            }),
            context: None,
        }
    }
}

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
        (status = 400, description = "Bad Request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn search_action_handler(
    State(state): State<AppState>,
    Json(request): Json<ActionSearchRequest>,
) -> Response {
    // Convert AuthZen request to OPA format
    let opa_request: OpaActionSearchRequest = request.into();

    // Send request to OPA - get the raw JSON response first
    match send_to_opa(&state, "/v1/data/permit/user_permissions", &opa_request).await {
        Ok(result) => {
            // Process the OPA response to extract permissions and roles
            let mut permissions: Vec<String> = Vec::new();
            let mut roles: Option<Vec<String>> = None;

            if let serde_json::Value::Object(map) = &result {
                // Extract permissions
                if let Some(perms_value) = map.get("permissions") {
                    if let Some(perms_array) = perms_value.as_array() {
                        permissions = perms_array
                            .iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect();
                    }
                }

                // Extract roles
                if let Some(roles_value) = map.get("roles") {
                    if let Some(roles_array) = roles_value.as_array() {
                        let extracted_roles: Vec<String> = roles_array
                            .iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect();

                        if !extracted_roles.is_empty() {
                            roles = Some(extracted_roles);
                        }
                    }
                }
            }

            // Create the OPA response structure
            let opa_response = OpaActionSearchResponse { permissions, roles };

            // Convert to AuthZen response
            let authzen_response: ActionSearchResponse = opa_response.into();

            // Return the response
            (StatusCode::OK, Json(authzen_response)).into_response()
        }
        Err(err) => {
            log::error!("Failed to process AuthZen action search request: {}", err);
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
    async fn test_action_search_with_permissions() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Test AuthZen request
        let test_request = json!({
            "subject": {
                "type": "user",
                "id": "alice@acmecorp.com"
            },
            "resource": {
                "type": "document",
                "id": "doc1"
            }
        });

        // Mock OPA response with permissions
        let mock_response = json!({
            "result": {
                "permissions": ["can_read", "can_edit"],
                "roles": ["editor"]
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
            .post("/access/v1/search/action", &test_request)
            .await;

        // Assert the response
        response.assert_ok();

        // Parse the response body
        let search_response: ActionSearchResponse = response.json_as();

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
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Test AuthZen request
        let test_request = json!({
            "subject": {
                "type": "user",
                "id": "bob@acmecorp.com"
            },
            "resource": {
                "type": "document",
                "id": "doc1"
            }
        });

        // Mock OPA response with no permissions
        let mock_response = json!({
            "result": {
                "permissions": [],
                "roles": []
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
            .post("/access/v1/search/action", &test_request)
            .await;

        // Assert the response
        response.assert_ok();

        // Parse the response body
        let search_response: ActionSearchResponse = response.json_as();

        // Check the response (should be empty)
        assert_eq!(search_response.results.len(), 0);

        // Verify page is present
        assert!(search_response.page.is_some());
    }

    #[tokio::test]
    async fn test_action_search_with_pagination() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Test AuthZen request with pagination
        let test_request = json!({
            "subject": {
                "type": "user",
                "id": "alice@acmecorp.com"
            },
            "resource": {
                "type": "document",
                "id": "doc1"
            },
            "page": {
                "size": 10,
                "next_token": null
            }
        });

        // Mock OPA response with permissions
        let mock_response = json!({
            "result": {
                "permissions": ["can_read"],
                "roles": ["viewer"]
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
            .post("/access/v1/search/action", &test_request)
            .await;

        // Assert the response
        response.assert_ok();

        // Parse the response body
        let search_response: ActionSearchResponse = response.json_as();

        // Check the response (should have 1 action)
        assert_eq!(search_response.results.len(), 1);
        assert_eq!(search_response.results[0].name, "can_read");

        // Verify page is present
        assert!(search_response.page.is_some());
    }
}
