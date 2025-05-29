use crate::api::authzen::common::{PageRequest, PageResponse};
use crate::api::authzen::schema::{AuthZenAction, AuthZenResource, AuthZenSubject};
use crate::errors::ApiError;
use crate::opa_client::authorized_users::{query_authorized_users, AuthorizedUsersQuery};
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

impl From<SubjectSearchRequest> for AuthorizedUsersQuery {
    fn from(req: SubjectSearchRequest) -> Self {
        AuthorizedUsersQuery {
            action: req.action.name,
            resource: req.resource.into(),
            context: req.context.unwrap_or_default(),
            sdk: Some("authzen".to_string()),
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
    let query: AuthorizedUsersQuery = request.into();
    let result = match query_authorized_users(&state, &query).await {
        Ok(result) => result,
        Err(err) => {
            log::error!("Failed to process AuthZen subject search request: {}", err);
            return ApiError::from(err).into_response();
        }
    };

    // Convert the result to AuthZen format
    let subjects = result
        .users
        .iter()
        .filter(|(_, assignments)| !assignments.is_empty())
        .map(|(user_key, _)| AuthZenSubject {
            r#type: "user".to_string(),
            id: user_key.clone(),
            properties: None,
        })
        .collect();

    // Create the AuthZen response
    let response = SubjectSearchResponse {
        results: subjects,
        page: Some(PageResponse { next_token: None }),
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
    async fn test_subject_search_with_access() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Set up the mock response
        fixture
            .add_opa_mock(
                http::Method::POST,
                "/v1/data/permit/authorized_users/authorized_users",
                json!({
                    "result": {
                        "result": {
                            "resource": "document:123",
                            "tenant": "default",
                            "users": {
                                "alice@example.com": [
                                    {
                                        "user": "alice@example.com",
                                        "tenant": "default",
                                        "resource": "document:123",
                                        "role": "reader"
                                    }
                                ],
                                "bob@example.com": [
                                    {
                                        "user": "bob@example.com",
                                        "tenant": "default",
                                        "resource": "document:123",
                                        "role": "reader"
                                    }
                                ]
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
                "/access/v1/search/subject",
                &json!({
                    "resource": {
                        "type": "document",
                        "id": "123"
                    },
                    "action": {
                        "name": "can_read"
                    }
                }),
            )
            .await;

        // Assert the response
        response.assert_ok();

        // Parse the response body
        let search_response: SubjectSearchResponse = response.json_as();

        // Check the response
        assert_eq!(
            search_response.results.len(),
            2,
            "Expected 2 users, found: {}",
            search_response.results.len()
        );

        // Find Alice in the response
        let alice = search_response
            .results
            .iter()
            .find(|subject| subject.id == "alice@example.com")
            .unwrap();
        assert_eq!(alice.r#type, "user");

        // Find Bob in the response
        let bob = search_response
            .results
            .iter()
            .find(|subject| subject.id == "bob@example.com")
            .unwrap();
        assert_eq!(bob.r#type, "user");

        // Verify page is present
        assert!(search_response.page.is_some());
    }

    #[tokio::test]
    async fn test_subject_search_without_access() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Set up the mock response
        fixture
            .add_opa_mock(
                http::Method::POST,
                "/v1/data/permit/authorized_users/authorized_users",
                json!({
                    "result": {
                        "result": {
                            "resource": "document:456",
                            "tenant": "default",
                            "users": {}
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
                "/access/v1/search/subject",
                &json!({
                    "resource": {
                        "type": "document",
                        "id": "456"
                    },
                    "action": {
                        "name": "can_write"
                    }
                }),
            )
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

        // Set up the mock response
        fixture
            .add_opa_mock(
                http::Method::POST,
                "/v1/data/permit/authorized_users/authorized_users",
                json!({
                    "result": {
                        "result": {
                            "resource": "document:123",
                            "tenant": "default",
                            "users": {
                                "alice@example.com": [
                                    {
                                        "user": "alice@example.com",
                                        "tenant": "default",
                                        "resource": "document:123",
                                        "role": "reader"
                                    }
                                ]
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
                "/access/v1/search/subject",
                &json!({
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
                }),
            )
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
