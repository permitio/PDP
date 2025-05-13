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

/// Resource type specification for Resource Search API
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct ResourceType {
    /// Type of the resource
    pub r#type: String,
    /// Optional properties of the resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<HashMap<String, serde_json::Value>>,
}

/// AuthZen Resource Search Request - to find resources that a subject can access
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct ResourceSearchRequest {
    /// Subject making the request
    pub subject: AuthZenSubject,
    /// Action being performed
    pub action: AuthZenAction,
    /// Resource type to search for (without ID as per spec)
    pub resource: ResourceType,
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
    action: String,
    resource_type: String,
    context: HashMap<String, serde_json::Value>,
    sdk: Option<String>,
}

// Internal structure to receive OPA response
#[derive(Debug, Serialize, Deserialize, Clone)]
struct OpaResourceSearchResponse {
    resources: HashMap<String, OpaResource>,
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

        OpaResourceSearchRequest {
            user,
            action: req.action.name,
            resource_type: req.resource.r#type,
            context: req.context.unwrap_or_default(),
            sdk: Some("authzen".to_string()),
        }
    }
}

// Convert OPA response to AuthZen response
impl From<OpaResourceSearchResponse> for ResourceSearchResponse {
    fn from(res: OpaResourceSearchResponse) -> Self {
        let results = res
            .resources
            .into_iter()
            .map(|(_, resource)| AuthZenResource {
                r#type: resource.r#type,
                id: resource.key.unwrap_or_default(),
                properties: if resource.attributes.is_empty() {
                    None
                } else {
                    Some(resource.attributes)
                },
            })
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

/// AuthZen Subject Search Request - to find subjects with access to a resource
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct SubjectSearchRequest {
    /// Resource being accessed
    pub resource: AuthZenResource,
    /// Action being performed
    pub action: AuthZenAction,
    /// Context for the evaluation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<HashMap<String, serde_json::Value>>,
    /// Pagination token for subsequent pages
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<PageRequest>,
}

/// AuthZen Subject Search Response - contains list of subjects with access to a resource
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct SubjectSearchResponse {
    /// List of subjects with access
    pub results: Vec<AuthZenSubject>,
    /// Pagination information
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<PageResponse>,
    /// Optional additional context
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<HashMap<String, serde_json::Value>>,
}

// Internal structure to interface with OPA for subject search
#[derive(Debug, Serialize, Deserialize, Clone)]
struct OpaSubjectSearchRequest {
    action: String,
    resource: OpaResource,
    context: HashMap<String, serde_json::Value>,
    sdk: Option<String>,
}

// Internal structure to receive OPA response for subject search
#[derive(Debug, Serialize, Deserialize, Clone)]
struct OpaSubjectSearchResponse {
    subjects: HashMap<String, OpaUser>,
}

// Convert AuthZen request to OPA request for subject search
impl From<SubjectSearchRequest> for OpaSubjectSearchRequest {
    fn from(req: SubjectSearchRequest) -> Self {
        let resource = OpaResource {
            r#type: req.resource.r#type.clone(),
            key: Some(req.resource.id.clone()),
            tenant: None,
            attributes: req.resource.properties.unwrap_or_default(),
            context: HashMap::new(),
        };

        OpaSubjectSearchRequest {
            action: req.action.name,
            resource,
            context: req.context.unwrap_or_default(),
            sdk: Some("authzen".to_string()),
        }
    }
}

// Convert OPA response to AuthZen response for subject search
impl From<OpaSubjectSearchResponse> for SubjectSearchResponse {
    fn from(res: OpaSubjectSearchResponse) -> Self {
        let results = res
            .subjects
            .into_iter()
            .map(|(_, user)| {
                AuthZenSubject {
                    r#type: "user".to_string(), // Default type for subjects
                    id: user.key,
                    properties: if user.attributes.is_empty() {
                        None
                    } else {
                        Some(user.attributes)
                    },
                }
            })
            .collect();

        SubjectSearchResponse {
            results,
            page: Some(PageResponse {
                next_token: None, // Pagination not yet fully implemented
            }),
            context: None,
        }
    }
}

/// Subject search endpoint - finds subjects that can access a resource
#[utoipa::path(
    post,
    path = "/access/v1/search/subject",
    tag = AUTHZEN_TAG,
    request_body = SubjectSearchRequest,
    params(
        ("Authorization" = String, Header, description = "Authorization header"),
        ("X-Request-ID" = String, Header, description = "Request Identifier"),
    ),
    responses(
        (status = 200, description = "Subject search completed successfully", body = SubjectSearchResponse),
        (status = 400, description = "Bad Request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn search_subject_handler(
    State(state): State<AppState>,
    Json(request): Json<SubjectSearchRequest>,
) -> Response {
    // Convert AuthZen request to OPA format
    let opa_request: OpaSubjectSearchRequest = request.into();

    // Select the appropriate endpoint based on configuration
    let endpoint = if state.config.use_new_authorized_users {
        "/v1/data/permit/authorized_users_new/authorized_users"
    } else {
        "/v1/data/permit/authorized_users/authorized_users"
    };

    // Send request to OPA - we're receiving a raw JSON response first
    match send_to_opa(&state, endpoint, &opa_request).await {
        Ok(result) => {
            // Extract the subjects from the result
            if let serde_json::Value::Object(map) = result {
                if let Some(subjects_value) = map.get("subjects") {
                    // Try to deserialize the subjects map
                    match serde_json::from_value::<HashMap<String, OpaUser>>(subjects_value.clone())
                    {
                        Ok(subjects) => {
                            // Create the OPA response structure
                            let opa_response = OpaSubjectSearchResponse { subjects };

                            // Convert to AuthZen response
                            let authzen_response: SubjectSearchResponse = opa_response.into();

                            // Return the response
                            return (StatusCode::OK, Json(authzen_response)).into_response();
                        }
                        Err(err) => {
                            log::error!("Failed to deserialize subjects map: {}", err);
                            return ApiError::internal("Invalid subjects in OPA response")
                                .into_response();
                        }
                    }
                }
            }

            // If we get here, we didn't find the subjects field or it wasn't valid
            // Return an empty result
            let empty_response = SubjectSearchResponse {
                results: Vec::new(),
                page: Some(PageResponse { next_token: None }),
                context: None,
            };

            (StatusCode::OK, Json(empty_response)).into_response()
        }
        Err(err) => {
            log::error!("Failed to process AuthZen subject search request: {}", err);
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
    async fn test_subject_search_with_access() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Test AuthZen request
        let test_request = json!({
            "resource": {
                "type": "document",
                "id": "123"
            },
            "action": {
                "name": "can_read"
            }
        });

        // Mock OPA response with two users
        let mock_response = json!({
            "result": {
                "subjects": {
                    "alice": {
                        "key": "alice@acmecorp.com",
                        "attributes": {
                            "department": "Engineering"
                        }
                    },
                    "bob": {
                        "key": "bob@acmecorp.com",
                        "attributes": {
                            "department": "Sales"
                        }
                    }
                }
            }
        });

        // Set up the mock response
        fixture
            .add_opa_mock(
                http::Method::POST,
                "/v1/data/permit/authorized_users/authorized_users",
                mock_response,
                http::StatusCode::OK,
                1,
            )
            .await;

        // Send the request using the fixture's post method
        let response = fixture
            .post("/access/v1/search/subject", &test_request)
            .await;

        // Assert the response
        response.assert_ok();

        // Parse the response body
        let search_response: SubjectSearchResponse = response.json_as();

        // Check the response
        assert_eq!(search_response.results.len(), 2);

        // Find Alice in the response
        let alice = search_response
            .results
            .iter()
            .find(|subject| subject.id == "alice@acmecorp.com")
            .unwrap();
        assert_eq!(alice.r#type, "user");
        assert!(alice.properties.is_some());
        assert_eq!(
            alice
                .properties
                .as_ref()
                .unwrap()
                .get("department")
                .unwrap(),
            "Engineering"
        );

        // Find Bob in the response
        let bob = search_response
            .results
            .iter()
            .find(|subject| subject.id == "bob@acmecorp.com")
            .unwrap();
        assert_eq!(bob.r#type, "user");
        assert!(bob.properties.is_some());
        assert_eq!(
            bob.properties.as_ref().unwrap().get("department").unwrap(),
            "Sales"
        );

        // Verify page is present
        assert!(search_response.page.is_some());
    }

    #[tokio::test]
    async fn test_subject_search_without_access() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Test AuthZen request
        let test_request = json!({
            "resource": {
                "type": "document",
                "id": "456"
            },
            "action": {
                "name": "can_write"
            }
        });

        // Mock OPA response with no users (empty map)
        let mock_response = json!({
            "result": {
                "subjects": {}
            }
        });

        // Set up the mock response
        fixture
            .add_opa_mock(
                http::Method::POST,
                "/v1/data/permit/authorized_users/authorized_users",
                mock_response,
                http::StatusCode::OK,
                1,
            )
            .await;

        // Send the request using the fixture's post method
        let response = fixture
            .post("/access/v1/search/subject", &test_request)
            .await;

        // Assert the response
        response.assert_ok();

        // Parse the response body
        let search_response: SubjectSearchResponse = response.json_as();

        // Check the response (should be empty)
        assert_eq!(search_response.results.len(), 0);

        // Verify page is present
        assert!(search_response.page.is_some());
    }

    #[tokio::test]
    async fn test_subject_search_with_pagination() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Test AuthZen request with pagination
        let test_request = json!({
            "resource": {
                "type": "document",
                "id": "123"
            },
            "action": {
                "name": "can_read"
            },
            "page": {
                "size": 10,
                "next_token": null
            }
        });

        // Mock OPA response with users
        let mock_response = json!({
            "result": {
                "subjects": {
                    "alice": {
                        "key": "alice@acmecorp.com",
                        "attributes": {
                            "department": "Engineering"
                        }
                    }
                }
            }
        });

        // Set up the mock response
        fixture
            .add_opa_mock(
                http::Method::POST,
                "/v1/data/permit/authorized_users/authorized_users",
                mock_response,
                http::StatusCode::OK,
                1,
            )
            .await;

        // Send the request using the fixture's post method
        let response = fixture
            .post("/access/v1/search/subject", &test_request)
            .await;

        // Assert the response
        response.assert_ok();

        // Parse the response body
        let search_response: SubjectSearchResponse = response.json_as();

        // Check the response
        assert_eq!(search_response.results.len(), 1);

        // Verify page is present
        assert!(search_response.page.is_some());
    }
}
