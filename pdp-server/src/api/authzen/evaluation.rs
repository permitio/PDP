use crate::api::authzen::schema::{AuthZenAction, AuthZenResource, AuthZenSubject};
use crate::errors::ApiError;
use crate::opa_client::allowed::{
    query_allowed, AllowedQuery, AllowedResult, Resource as OpaResource, User as OpaUser,
};
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

/// AuthZen Evaluation Request - the main request object for the Authorization API
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct AccessEvaluationRequest {
    /// Subject (user) making the request
    pub subject: AuthZenSubject,
    /// Resource being accessed
    pub resource: AuthZenResource,
    /// Action being performed
    pub action: AuthZenAction,
    /// Context for the evaluation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<HashMap<String, serde_json::Value>>,
}

/// AuthZen Evaluation Response - the main response object for the Authorization API
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct AccessEvaluationResponse {
    /// The decision whether to allow or deny the action
    pub decision: bool,
    /// Optional additional context
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<HashMap<String, serde_json::Value>>,
}

// Convert AuthZen request to AllowedQuery
impl From<AccessEvaluationRequest> for AllowedQuery {
    fn from(req: AccessEvaluationRequest) -> Self {
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
            tenant: req
                .resource
                .properties
                .clone()
                .unwrap_or_default()
                .get("tenant")
                .cloned()
                .map(|v| v.to_string()),
            attributes: req.resource.properties.unwrap_or_default(),
            context: HashMap::new(),
        };

        AllowedQuery {
            user,
            action: req.action.name,
            resource,
            context: req.context.unwrap_or_default(),
            sdk: Some("authzen".to_string()),
        }
    }
}

// Convert AllowedResult to AuthZen response
impl From<AllowedResult> for AccessEvaluationResponse {
    fn from(res: AllowedResult) -> Self {
        let mut context: Option<HashMap<String, serde_json::Value>> = None;

        if let Some(debug) = res.debug {
            context = Some(debug);
        } else if let Some(query) = res.query {
            context = Some(query);
        }

        AccessEvaluationResponse {
            decision: res.allow,
            context,
        }
    }
}

#[utoipa::path(
    post,
    path = "/access/v1/evaluation",
    tag = AUTHZEN_TAG,
    request_body = AccessEvaluationRequest,
    params(
        ("Authorization" = String, Header, description = "Authorization header"),
        ("X-Request-ID" = String, Header, description = "Request Identifier"),
    ),
    responses(
        (status = 200, description = "Access evaluation completed successfully", body = AccessEvaluationResponse),
        (status = 400, description = "Bad Request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn access_evaluation_handler(
    State(state): State<AppState>,
    Json(request): Json<AccessEvaluationRequest>,
) -> Response {
    // Convert AuthZen request to AllowedQuery
    let allowed_query: AllowedQuery = request.into();

    // Send request to OPA using query_allowed
    match query_allowed(&state, &allowed_query).await {
        Ok(allowed_result) => {
            // Convert AllowedResult to AuthZen format
            let authzen_response: AccessEvaluationResponse = allowed_result.into();

            // Return the response
            (StatusCode::OK, Json(authzen_response)).into_response()
        }
        Err(err) => {
            log::error!("Failed to process AuthZen request: {}", err);
            ApiError::from(err).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestFixture;
    use axum::body::Body;
    use http::{Method, StatusCode};
    use serde_json::json;
    // The wiremock imports are directly referred to through the namespace

    #[tokio::test]
    async fn test_access_evaluation_allowed() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Test AuthZen request
        let test_request = json!({
            "subject": {
                "type": "user",
                "id": "alice@example.com"
            },
            "resource": {
                "type": "document",
                "id": "123"
            },
            "action": {
                "name": "can_read"
            }
        });

        // Setup mock OPA response using the fixture helper method
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/root",
                json!({
                    "result": {
                        "allow": true
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        // Send request to the AuthZen endpoint
        let response = fixture.post("/access/v1/evaluation", &test_request).await;

        // Print response for debugging
        println!("Response status: {}", response.status);
        println!("Response body: {}", String::from_utf8_lossy(&response.body));

        // Verify response
        response.assert_ok();
        let result: AccessEvaluationResponse = response.json_as();
        assert!(result.decision);

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_access_evaluation_denied() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Test AuthZen request
        let test_request = json!({
            "subject": {
                "type": "user",
                "id": "alice@example.com"
            },
            "resource": {
                "type": "document",
                "id": "123"
            },
            "action": {
                "name": "can_write"
            }
        });

        // Setup mock OPA response using the fixture helper method
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

        // Send request to the AuthZen endpoint
        let response = fixture.post("/access/v1/evaluation", &test_request).await;

        // Verify response
        response.assert_ok();
        let result: AccessEvaluationResponse = response.json_as();
        assert!(!result.decision);

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_access_evaluation_with_context() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Test AuthZen request with context
        let test_request = json!({
            "subject": {
                "type": "user",
                "id": "alice@example.com",
                "properties": {
                    "department": "Sales"
                }
            },
            "resource": {
                "type": "document",
                "id": "123",
                "properties": {
                    "sensitivity": "confidential"
                }
            },
            "action": {
                "name": "can_read"
            },
            "context": {
                "time": "2023-01-01T12:00:00Z"
            }
        });

        // Setup mock OPA response with debug info using the fixture helper method
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/root",
                json!({
                    "result": {
                        "allow": true,
                        "debug": {
                            "policy_id": "doc_access_policy",
                            "reason": "User department has access to document"
                        }
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        // Send request to the AuthZen endpoint
        let response = fixture.post("/access/v1/evaluation", &test_request).await;

        // Verify response
        response.assert_ok();
        let result: AccessEvaluationResponse = response.json_as();
        assert!(result.decision);

        // Verify context was passed through
        assert!(result.context.is_some());
        let context = result.context.unwrap();
        assert_eq!(
            context.get("policy_id").unwrap().as_str().unwrap(),
            "doc_access_policy"
        );

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_access_evaluation_with_query_context() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Test AuthZen request with context
        let test_request = json!({
            "subject": {
                "type": "user",
                "id": "alice@example.com",
                "properties": {
                    "department": "Sales"
                }
            },
            "resource": {
                "type": "document",
                "id": "123",
                "properties": {
                    "sensitivity": "confidential"
                }
            },
            "action": {
                "name": "can_read"
            },
            "context": {
                "time": "2023-01-01T12:00:00Z"
            }
        });

        // Setup mock OPA response with query info using the fixture helper method
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/root",
                json!({
                    "result": {
                        "allow": true,
                        "query": {
                            "matched_rules": ["rule1", "rule2"],
                            "evaluation_time_ms": 5
                        }
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        // Send request to the AuthZen endpoint
        let response = fixture.post("/access/v1/evaluation", &test_request).await;

        // Verify response
        response.assert_ok();
        let result: AccessEvaluationResponse = response.json_as();
        assert!(result.decision);

        // Verify query context was passed through
        assert!(result.context.is_some());
        let context = result.context.unwrap();
        let matched_rules = context.get("matched_rules").unwrap().as_array().unwrap();
        assert_eq!(matched_rules[0].as_str().unwrap(), "rule1");
        assert_eq!(matched_rules[1].as_str().unwrap(), "rule2");

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_access_evaluation_with_complex_context() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Test AuthZen request with complex context
        let test_request = json!({
            "subject": {
                "type": "user",
                "id": "alice@example.com"
            },
            "resource": {
                "type": "document",
                "id": "123"
            },
            "action": {
                "name": "can_read"
            },
            "context": {
                "time": "2023-01-01T12:00:00Z",
                "location": {
                    "latitude": 37.7749,
                    "longitude": -122.4194,
                    "accuracy": 10.5
                },
                "device_info": {
                    "is_trusted": true,
                    "fingerprint": "abc123",
                    "last_scanned": null
                },
                "request_metrics": [10, 20, 30],
                "auth_level": 2
            }
        });

        // Setup mock OPA response using the fixture helper method
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/root",
                json!({
                    "result": {
                        "allow": true
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        // Send request to the AuthZen endpoint
        let response = fixture.post("/access/v1/evaluation", &test_request).await;

        // Verify response
        response.assert_ok();
        let result: AccessEvaluationResponse = response.json_as();
        assert!(result.decision);

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_access_evaluation_with_action_properties() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Test AuthZen request
        let test_request = json!({
            "subject": {
                "type": "user",
                "id": "alice@example.com"
            },
            "resource": {
                "type": "document",
                "id": "123"
            },
            "action": {
                "name": "can_access",
                "properties": {
                    "method": "GET",
                    "headers": {
                        "content-type": "application/json",
                        "accept-language": "en-US"
                    },
                    "path_params": ["documents", "123"],
                    "query_params": {
                        "version": "latest"
                    }
                }
            }
        });

        // Setup mock OPA response using the fixture helper method
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/root",
                json!({
                    "result": {
                        "allow": true
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        // Send request to the AuthZen endpoint
        let response = fixture.post("/access/v1/evaluation", &test_request).await;

        // Verify response
        response.assert_ok();
        let result: AccessEvaluationResponse = response.json_as();
        assert!(result.decision);

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_access_evaluation_opa_error() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Test AuthZen request
        let test_request = json!({
            "subject": {
                "type": "user",
                "id": "alice@example.com"
            },
            "resource": {
                "type": "document",
                "id": "123"
            },
            "action": {
                "name": "can_read"
            }
        });

        // Setup mock OPA response with error using the fixture helper method
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/root",
                "Internal Server Error",
                StatusCode::INTERNAL_SERVER_ERROR,
                1,
            )
            .await;

        // Send request to the AuthZen endpoint
        let response = fixture.post("/access/v1/evaluation", &test_request).await;

        // Verify we get a BAD_GATEWAY error when OPA fails
        response.assert_status(StatusCode::BAD_GATEWAY);

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_access_evaluation_invalid_subject_missing_type() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Missing type field in subject
        let invalid_request = json!({
            "subject": {
                "id": "alice@example.com"
                // Missing type field
            },
            "resource": {
                "type": "document",
                "id": "123"
            },
            "action": {
                "name": "can_read"
            }
        });

        // Build and send request with invalid subject
        let request = fixture
            .request_builder(Method::POST, "/access/v1/evaluation")
            .body(Body::from(serde_json::to_vec(&invalid_request).unwrap()))
            .expect("Failed to build request");

        let response = fixture.send(request).await;
        response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_access_evaluation_missing_resource() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Missing resource field completely
        let invalid_request = json!({
            "subject": {
                "type": "user",
                "id": "alice@example.com"
            },
            // Missing resource
            "action": {
                "name": "can_read"
            }
        });

        // Build and send request with missing resource
        let request = fixture
            .request_builder(Method::POST, "/access/v1/evaluation")
            .body(Body::from(serde_json::to_vec(&invalid_request).unwrap()))
            .expect("Failed to build request");

        let response = fixture.send(request).await;
        response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_access_evaluation_empty_resource_id() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Empty id string in resource
        let request_with_empty_id = json!({
            "subject": {
                "type": "user",
                "id": "alice@example.com"
            },
            "resource": {
                "type": "document",
                "id": ""  // Empty id
            },
            "action": {
                "name": "can_read"
            }
        });

        // Empty id is valid per the AuthZen spec (which requires a string but doesn't specify non-empty)
        // So this request should actually succeed at the validation stage
        let request = fixture
            .request_builder(Method::POST, "/access/v1/evaluation")
            .body(Body::from(
                serde_json::to_vec(&request_with_empty_id).unwrap(),
            ))
            .expect("Failed to build request");

        // Setup mock OPA response for this case
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/root",
                json!({
                    "result": { "allow": false }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        let response = fixture.send(request).await;
        response.assert_ok(); // Empty strings are valid per AuthZen spec

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_access_evaluation_invalid_action_missing_name() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Missing name in action
        let invalid_request = json!({
            "subject": {
                "type": "user",
                "id": "alice@example.com"
            },
            "resource": {
                "type": "document",
                "id": "123"
            },
            "action": {
                // Missing name field
                "properties": {
                    "method": "GET"
                }
            }
        });

        // Build and send request with invalid action
        let request = fixture
            .request_builder(Method::POST, "/access/v1/evaluation")
            .body(Body::from(serde_json::to_vec(&invalid_request).unwrap()))
            .expect("Failed to build request");

        let response = fixture.send(request).await;
        response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
    }
}
