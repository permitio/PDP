use crate::api::authzen::evaluation::AccessEvaluationRequest;
use crate::api::authzen::schema::{AuthZenAction, AuthZenResource, AuthZenSubject};
use crate::errors::ApiError;
use crate::opa_client::allowed::{AllowedQuery, AllowedResult};
use crate::opa_client::allowed_bulk::query_allowed_bulk;
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

/// AuthZen Evaluations Request - for batch evaluation of multiple access requests
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct AccessEvaluationsRequest {
    /// Subject (user) making the request - used as default for all evaluations
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<AuthZenSubject>,

    /// Resource being accessed - used as default for all evaluations
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<AuthZenResource>,

    /// Action being performed - used as default for all evaluations
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<AuthZenAction>,

    /// Context for the evaluation - used as default for all evaluations
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<HashMap<String, serde_json::Value>>,

    /// List of individual evaluations to perform
    pub evaluations: Vec<IndividualEvaluation>,

    /// Options for controlling evaluation behavior
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<HashMap<String, serde_json::Value>>,
}

/// Individual evaluation in a batch request
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct IndividualEvaluation {
    /// Subject (user) making the request - overrides the default
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<AuthZenSubject>,

    /// Resource being accessed - overrides the default
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<AuthZenResource>,

    /// Action being performed - overrides the default
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<AuthZenAction>,

    /// Context for the evaluation - overrides the default
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<HashMap<String, serde_json::Value>>,
}

/// AuthZen Evaluations Response - contains decisions for all requests
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct AccessEvaluationsResponse {
    /// List of evaluation results
    pub evaluations: Vec<EvaluationResult>,
}

/// Individual evaluation result
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct EvaluationResult {
    /// The decision whether to allow or deny the action
    pub decision: bool,

    /// Optional additional context
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<HashMap<String, serde_json::Value>>,
}

// Convert an IndividualEvaluation to AllowedQuery, using defaults when needed
fn convert_to_allowed_query(
    evaluation: &IndividualEvaluation,
    defaults: &AccessEvaluationsRequest,
) -> Option<AllowedQuery> {
    // Get subject from evaluation or default
    let subject = match (&evaluation.subject, &defaults.subject) {
        (Some(s), _) => Some(s),
        (None, Some(s)) => Some(s),
        _ => None,
    };

    // Get resource from evaluation or default
    let resource = match (&evaluation.resource, &defaults.resource) {
        (Some(r), _) => Some(r),
        (None, Some(r)) => Some(r),
        _ => None,
    };

    // Get action from evaluation or default
    let action = match (&evaluation.action, &defaults.action) {
        (Some(a), _) => Some(a),
        (None, Some(a)) => Some(a),
        _ => None,
    };

    // Merge context from evaluation and default
    let mut context = defaults.context.clone().unwrap_or_default();
    if let Some(eval_context) = &evaluation.context {
        context.extend(eval_context.clone());
    }

    // Return None if any required field is missing
    if subject.is_none() || resource.is_none() || action.is_none() {
        return None;
    }

    // Create a complete AccessEvaluationRequest
    let req = AccessEvaluationRequest {
        subject: subject.unwrap().clone(),
        resource: resource.unwrap().clone(),
        action: action.unwrap().clone(),
        context: Some(context),
    };

    // Convert to AllowedQuery
    Some(AllowedQuery::from(req))
}

// Convert AllowedResult to EvaluationResult
fn convert_to_evaluation_result(allowed_result: AllowedResult) -> EvaluationResult {
    let mut context: Option<HashMap<String, serde_json::Value>> = None;

    if let Some(debug) = allowed_result.debug {
        context = Some(debug);
    } else if let Some(query) = allowed_result.query {
        context = Some(query);
    }

    EvaluationResult {
        decision: allowed_result.allow,
        context,
    }
}

#[utoipa::path(
    post,
    path = "/access/v1/evaluations",
    tag = AUTHZEN_TAG,
    request_body = AccessEvaluationsRequest,
    params(
        ("Authorization" = String, Header, description = "Authorization header"),
        ("X-Request-ID" = String, Header, description = "Request Identifier"),
    ),
    responses(
        (status = 200, description = "Access evaluations completed successfully", body = AccessEvaluationsResponse),
        (status = 400, description = "Bad Request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn access_evaluations_handler(
    State(state): State<AppState>,
    Json(request): Json<AccessEvaluationsRequest>,
) -> Response {
    // Handle the case with no evaluations (backward compatibility)
    if request.evaluations.is_empty() {
        return ApiError::bad_request("No evaluations provided").into_response();
    }

    // Convert each evaluation to an AllowedQuery
    let queries: Vec<AllowedQuery> = request
        .evaluations
        .iter()
        .filter_map(|eval| convert_to_allowed_query(eval, &request))
        .collect();

    // If any conversion failed, return an error
    if queries.len() != request.evaluations.len() {
        return ApiError::bad_request("One or more evaluations is missing required fields")
            .into_response();
    }

    // Send bulk request to OPA
    match query_allowed_bulk(&state, &queries).await {
        Ok(bulk_result) => {
            // Convert each AllowedResult to an EvaluationResult
            let results: Vec<EvaluationResult> = bulk_result
                .allow
                .into_iter()
                .map(convert_to_evaluation_result)
                .collect();

            // Return the response with evaluations wrapper
            let response = AccessEvaluationsResponse {
                evaluations: results,
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(err) => {
            log::error!("Failed to process AuthZen evaluations request: {}", err);
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
    async fn test_access_evaluations_multiple_requests() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Test AuthZen request with multiple evaluations
        let test_request = json!({
            "subject": {
                "type": "user",
                "id": "alice@acmecorp.com"
            },
            "evaluations": [
                {
                    "action": {
                        "name": "can_read"
                    },
                    "resource": {
                        "type": "document",
                        "id": "doc1"
                    }
                },
                {
                    "action": {
                        "name": "can_write"
                    },
                    "resource": {
                        "type": "document",
                        "id": "doc1"
                    }
                }
            ]
        });

        // Mock OPA response
        fixture
            .add_opa_mock(
                http::Method::POST,
                "/v1/data/permit/bulk",
                json!({
                    "result": {
                        "allow": [
                            {
                                "allow": true,
                                "debug": {"reason": "User has read permission"}
                            },
                            {
                                "allow": false,
                                "debug": {"reason": "User lacks write permission"}
                            }
                        ]
                    }
                }),
                http::StatusCode::OK,
                1,
            )
            .await;

        // Send the request
        let response = fixture.post("/access/v1/evaluations", &test_request).await;

        // Assert response
        response.assert_ok();
        let eval_response: AccessEvaluationsResponse = response.json_as();

        // Check the evaluation results
        assert_eq!(eval_response.evaluations.len(), 2);
        assert!(eval_response.evaluations[0].decision);
        assert!(!eval_response.evaluations[1].decision);
    }

    #[tokio::test]
    async fn test_access_evaluations_with_defaults_override() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Test with defaults and one override
        let test_request = json!({
            "subject": {
                "type": "user",
                "id": "alice@acmecorp.com"
            },
            "action": {
                "name": "can_read"
            },
            "context": {
                "time": "2023-09-15T14:30:00Z"
            },
            "evaluations": [
                {
                    "resource": {
                        "type": "document",
                        "id": "doc1"
                    }
                },
                {
                    "resource": {
                        "type": "document",
                        "id": "doc2"
                    },
                    "action": {
                        "name": "can_write"
                    }
                }
            ]
        });

        // Mock OPA response
        fixture
            .add_opa_mock(
                http::Method::POST,
                "/v1/data/permit/bulk",
                json!({
                    "result": {
                        "allow": [
                            { "allow": true },
                            { "allow": false }
                        ]
                    }
                }),
                http::StatusCode::OK,
                1,
            )
            .await;

        // Send the request
        let response = fixture.post("/access/v1/evaluations", &test_request).await;

        // Assert response
        response.assert_ok();
        let eval_response: AccessEvaluationsResponse = response.json_as();

        // Check the evaluation results
        assert_eq!(eval_response.evaluations.len(), 2);
        assert!(eval_response.evaluations[0].decision);
        assert!(!eval_response.evaluations[1].decision);
    }

    #[tokio::test]
    async fn test_access_evaluations_missing_required_fields() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Test with missing required fields
        let test_request = json!({
            "subject": {
                "type": "user",
                "id": "alice@acmecorp.com"
            },
            "evaluations": [
                {
                    // Missing resource and action
                }
            ]
        });

        // Send the request
        let response = fixture.post("/access/v1/evaluations", &test_request).await;

        // Assert response is a bad request
        response.assert_status(http::StatusCode::BAD_REQUEST);
    }
}
