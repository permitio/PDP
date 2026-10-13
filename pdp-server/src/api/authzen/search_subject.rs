use crate::api::authzen::common::{PageRequest, PageResponse};
use crate::api::authzen::errors::AuthZenError;
use crate::api::authzen::schema::{AuthZenAction, AuthZenResource, AuthZenSubject};
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
    /// Subject being searched for
    pub subject: AuthZenSubject,
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
    /// Subjects with access, sorted by type, then id, comparing strings by code point
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
        (status = 400, description = "Bad Request", body = String),
        (status = 401, description = "Unauthorized", body = String),
        (status = 403, description = "Forbidden", body = String),
        (status = 500, description = "Internal server error", body = String)
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
            log::error!("Failed to process AuthZen subject search request: {err:?}");
            let authzen_error = AuthZenError::from(err);
            return authzen_error.into_response();
        }
    };

    // `users` is a HashMap, so it iterates in a different order on every call.
    let mut subjects = Vec::new();
    for (user_key, assignments) in result.users {
        if assignments.is_empty() {
            continue;
        }
        subjects.push(AuthZenSubject {
            r#type: "user".to_string(),
            id: user_key,
            properties: None,
        });
    }
    subjects.sort_by(|a, b| (&a.r#type, &a.id).cmp(&(&b.r#type, &b.id)));

    // Create the AuthZen response
    let response = SubjectSearchResponse {
        results: subjects,
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
                    "subject": {
                        "type": "user",
                    },
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
                    "subject": {
                        "type": "user",
                    },
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
                    "subject": {
                        "type": "user",
                    },
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

    /// User keys in no particular order. `Zoe` shows that ids compare by code point, so an
    /// uppercase letter sorts before every lowercase one.
    const UNSORTED_USER_KEYS: [&str; 12] = [
        "mallory@example.com",
        "alice@example.com",
        "trent@example.com",
        "Zoe@example.com",
        "bob@example.com",
        "peggy@example.com",
        "carol@example.com",
        "victor@example.com",
        "dave@example.com",
        "erin@example.com",
        "frank@example.com",
        "oscar@example.com",
    ];

    /// An `authorized_users` OPA result that gives each user in `with_access` a reader role
    /// and each user in `without_access` an empty assignment list.
    fn authorized_users_response(
        with_access: &[&str],
        without_access: &[&str],
    ) -> serde_json::Value {
        let mut users = serde_json::Map::new();
        for user_key in with_access {
            let assignment = json!({
                "user": user_key,
                "tenant": "default",
                "resource": "document:123",
                "role": "reader"
            });
            users.insert((*user_key).to_string(), json!([assignment]));
        }
        for user_key in without_access {
            users.insert((*user_key).to_string(), json!([]));
        }
        json!({
            "result": {
                "result": {
                    "resource": "document:123",
                    "tenant": "default",
                    "users": users
                }
            }
        })
    }

    async fn mock_authorized_users(
        fixture: &TestFixture,
        response: serde_json::Value,
        expected_calls: u64,
    ) {
        fixture
            .add_opa_mock(
                http::Method::POST,
                "/v1/data/permit/authorized_users/authorized_users",
                response,
                http::StatusCode::OK,
                expected_calls,
            )
            .await;
    }

    fn subject_search_request() -> serde_json::Value {
        json!({
            "subject": {"type": "user"},
            "resource": {"type": "document", "id": "123"},
            "action": {"name": "can_read"}
        })
    }

    #[tokio::test]
    async fn test_subject_search_sorts_results_by_type_then_id() {
        let fixture = TestFixture::new().await;
        mock_authorized_users(
            &fixture,
            authorized_users_response(&UNSORTED_USER_KEYS, &[]),
            1,
        )
        .await;

        let response = fixture
            .post("/access/v1/search/subject", &subject_search_request())
            .await;

        response.assert_ok();
        let search_response: SubjectSearchResponse = response.json_as();
        let mut results = Vec::new();
        for subject in &search_response.results {
            results.push((subject.r#type.as_str(), subject.id.as_str()));
        }
        assert_eq!(
            results,
            vec![
                ("user", "Zoe@example.com"),
                ("user", "alice@example.com"),
                ("user", "bob@example.com"),
                ("user", "carol@example.com"),
                ("user", "dave@example.com"),
                ("user", "erin@example.com"),
                ("user", "frank@example.com"),
                ("user", "mallory@example.com"),
                ("user", "oscar@example.com"),
                ("user", "peggy@example.com"),
                ("user", "trent@example.com"),
                ("user", "victor@example.com"),
            ]
        );
    }

    #[tokio::test]
    async fn test_subject_search_repeated_calls_return_identical_bodies() {
        const CALLS: u64 = 10;
        let fixture = TestFixture::new().await;
        mock_authorized_users(
            &fixture,
            authorized_users_response(&UNSORTED_USER_KEYS, &[]),
            CALLS,
        )
        .await;

        let first = fixture
            .post("/access/v1/search/subject", &subject_search_request())
            .await;
        first.assert_ok();
        for call in 2..=CALLS {
            let response = fixture
                .post("/access/v1/search/subject", &subject_search_request())
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
    async fn test_subject_search_omits_users_without_assignments() {
        let fixture = TestFixture::new().await;
        mock_authorized_users(
            &fixture,
            authorized_users_response(
                &["carol@example.com", "alice@example.com"],
                &["bob@example.com"],
            ),
            1,
        )
        .await;

        let response = fixture
            .post("/access/v1/search/subject", &subject_search_request())
            .await;

        response.assert_ok();
        let search_response: SubjectSearchResponse = response.json_as();
        let mut ids = Vec::new();
        for subject in &search_response.results {
            ids.push(subject.id.as_str());
        }
        assert_eq!(ids, vec!["alice@example.com", "carol@example.com"]);
    }

    #[tokio::test]
    async fn test_subject_search_ignores_page_and_returns_empty_next_token() {
        let fixture = TestFixture::new().await;
        mock_authorized_users(
            &fixture,
            authorized_users_response(&UNSORTED_USER_KEYS, &[]),
            1,
        )
        .await;
        let mut request = subject_search_request();
        request["page"] = json!({"size": 1, "next_token": null});

        let response = fixture.post("/access/v1/search/subject", &request).await;

        response.assert_ok();
        let body = response.json();
        assert_eq!(body["page"], json!({"next_token": ""}));
        assert_eq!(
            body["results"].as_array().map(Vec::len),
            Some(UNSORTED_USER_KEYS.len())
        );
    }
}
