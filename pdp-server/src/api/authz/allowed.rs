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
    //
    // #[tokio::test]
    // #[ignore = "This test requires a mock OPA server"]
    // async fn test_handle_allowed() {
    //     let mock_server = MockServer::start().await;
    //     let settings = setup_test_settings_with_mock(&mock_server);
    //     let state = create_test_state(settings);
    //     let app = setup_test_app_with_state(state.clone()).await;
    //
    //
    //     // Create a test payload
    //     let test_query = json!({
    //
    //     });
    //
    //     // Setup mock server
    //     Mock::given(method("POST"))
    //         .and(path("/v1/data/permit/root"))
    //         .respond_with(
    //             ResponseTemplate::new(200).set_body_json(json!({
    //                 "result": {
    //                     "allow": true,
    //                 }
    //             })),
    //         )
    //         .expect(1)
    //         .mount(&mock_server)
    //         .await;
    //
    //     // Forward request and check response
    //     let headers = HeaderMap::new();
    //     let json_value = forward_to_opa::create_opa_request(&test_query).unwrap();
    //     if let Ok(response) = forward_to_opa::send_request_to_opa(&state, "allowed", &headers, &json_value).await {
    //         let typed_response: AuthorizationResult = serde_json::from_value(response.0).unwrap();
    //         assert_eq!(typed_response.allow, true);
    //     } else {
    //         panic!("Expected successful response from allowed endpoint");
    //     }
    //
    //     mock_server.verify().await;
    // }
}
