use crate::api::authz::forward_to_opa::send_request_to_opa;
use crate::errors::ApiError;
use crate::openapi::AUTHZ_TAG;
use crate::{
    models::{Resource, User},
    state::AppState,
};
use axum::{
    extract::{Json, State},
    response::{IntoResponse, Response},
};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;

#[utoipa::path(
    post,
    path = "/allowed",
    tag = AUTHZ_TAG,
    request_body = AllowedQuery,
    params(
        ("Authorization" = String, Header, description = "Authorization header"),
    ),
    responses(
        (status = 200, description = "Allowed check completed successfully", body = AllowedResult),
        (status = 422, description = "Invalid request payload"),
        (status = 500, description = "Internal server error")
    )
)]
pub(super) async fn allowed_handler(
    State(state): State<AppState>,
    Json(query): Json<AllowedQuery>,
) -> Response {
    match send_request_to_opa::<AllowedResult, _>(&state, "/v1/data/permit/root", &query).await {
        Ok(result) => (StatusCode::OK, Json(result)).into_response(),
        Err(err) => {
            log::error!("Failed to send request to OPA: {}", err);
            ApiError::from(err).into_response()
        }
    }
}

/// Authorization query parameters for the allowed endpoint
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub(crate) struct AllowedQuery {
    /// User making the request
    user: User,
    /// The action the user wants to perform
    action: String,
    /// The resource the user wants to access
    resource: Resource,
    /// Additional context for permission evaluation
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    context: HashMap<String, serde_json::Value>,
    /// SDK identifier
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sdk: Option<String>,
}

/// Response type for the allowed endpoint
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
struct AllowedResult {
    /// Whether the action is allowed
    allow: bool,
    /// Query details for debugging
    #[serde(default, skip_serializing_if = "Option::is_none")]
    query: Option<HashMap<String, serde_json::Value>>,
    /// Debug information
    #[serde(default, skip_serializing_if = "Option::is_none")]
    debug: Option<HashMap<String, serde_json::Value>>,
    /// Result (deprecated field for backward compatibility)
    #[serde(default)]
    result: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestFixture;
    use axum::body::Body;
    use http::{Method, StatusCode};
    use serde_json::json;

    #[tokio::test]
    async fn test_handle_allowed_success() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Use explicit JSON instead of helper function
        let test_query = json!({
            "user": {
                "key": "test-user",
                "first_name": "Test",
                "last_name": "User",
                "email": "test@example.com",
                "attributes": {}
            },
            "action": "read",
            "resource": {
                "type": "document",
                "key": "test-resource",
                "tenant": "test-tenant",
                "attributes": {},
                "context": {}
            },
            "context": {}
        });

        // Setup mock OPA response using the helper method
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/root",
                json!({
                    "result": {
                        "allow": true,
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        // Send request to the API
        let response = fixture.post("/allowed", &test_query).await;

        // Verify response status and body
        response.assert_ok();
        let result: AllowedResult = response.json_as();
        assert!(result.allow);

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_handle_allowed_with_debug_info() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Setup mock OPA response using the helper method
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/root",
                json!({
                    "result": {
                        "allow": true,
                        "debug": {
                            "test": "value",
                            "policy": "test-policy"
                        }
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        // Send request with custom trace header
        let custom_headers = &[("X-Test-Header", "test-value")];

        let response = fixture
            .post_with_headers(
                "/allowed",
                &json!({
                    "user": {
                        "key": "test-user",
                        "first_name": "Test",
                        "last_name": "User",
                        "email": "test@example.com",
                        "attributes": {}
                    },
                    "action": "read",
                    "resource": {
                        "type": "document",
                        "key": "test-resource",
                        "tenant": "test-tenant",
                        "attributes": {},
                        "context": {}
                    },
                    "context": {}
                }),
                custom_headers,
            )
            .await;

        // Verify response
        response.assert_ok();
        let result: AllowedResult = response.json_as();
        assert!(result.allow);
        assert_eq!(result.debug.as_ref().unwrap().get("test").unwrap(), "value");
        assert_eq!(
            result.debug.as_ref().unwrap().get("policy").unwrap(),
            "test-policy"
        );

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_handle_allowed_denied_response() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Setup mock OPA response using the helper method
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/root",
                json!({
                    "result": {
                        "allow": false
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        // Send request
        let response = fixture
            .post(
                "/allowed",
                &json!({
                    "user": {
                        "key": "test-user",
                        "first_name": "Test",
                        "last_name": "User",
                        "email": "test@example.com",
                        "attributes": {}
                    },
                    "action": "read",
                    "resource": {
                        "type": "document",
                        "key": "test-resource",
                        "tenant": "test-tenant",
                        "attributes": {},
                        "context": {}
                    },
                    "context": {}
                }),
            )
            .await;

        // Verify response - should still be 200 OK with allow=false
        response.assert_ok();
        let result: AllowedResult = response.json_as();
        assert!(!result.allow);

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_handle_allowed_opa_error() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Setup mock OPA response using the helper method
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/root",
                "Internal Server Error",
                StatusCode::INTERNAL_SERVER_ERROR,
                1,
            )
            .await;

        // Send request
        let response = fixture
            .post(
                "/allowed",
                &json!({
                    "user": {
                        "key": "test-user",
                        "first_name": "Test",
                        "last_name": "User",
                        "email": "test@example.com",
                        "attributes": {}
                    },
                    "action": "read",
                    "resource": {
                        "type": "document",
                        "key": "test-resource",
                        "tenant": "test-tenant",
                        "attributes": {},
                        "context": {}
                    },
                    "context": {}
                }),
            )
            .await;

        // Verify response - should be a 502 Bad Gateway when OPA returns 5xx
        response.assert_status(StatusCode::BAD_GATEWAY);

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_handle_allowed_invalid_request() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Create an invalid query (missing required fields)
        let invalid_query = json!({
            "action": "read",
            // Missing user and resource
        });

        // Build the request with invalid body
        let request = fixture
            .request_builder(Method::POST, "/allowed")
            .body(Body::from(serde_json::to_vec(&invalid_query).unwrap()))
            .expect("Failed to build request");

        // Send request
        let response = fixture.send(request).await;

        // Should get a 422 Unprocessable Entity for invalid request
        response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }
}
