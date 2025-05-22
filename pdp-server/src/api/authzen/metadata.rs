use crate::openapi::AUTHZEN_TAG;
use axum::{
    body::Body,
    extract::Request,
    response::{IntoResponse, Json, Response},
};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// AuthZen PDP Metadata Response - provides information about the PDP capabilities
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct AuthZenMetadataResponse {
    pub policy_decision_point: String,
    pub access_evaluation_endpoint: String,
    pub access_evaluations_endpoint: String,
    pub search_subject_endpoint: String,
    pub search_action_endpoint: String,
    pub search_resource_endpoint: String,
}

#[utoipa::path(
    get,
    path = "/.well-known/authzen-configuration",
    tag = AUTHZEN_TAG,
    responses(
        (status = 200, description = "PDP metadata retrieved successfully", body = AuthZenMetadataResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn authzen_metadata_handler(request: Request<Body>) -> Response {
    // Get the base URL from the request
    let parts = request.uri().clone().into_parts();
    let base_url = format!(
        "{}://{}",
        parts
            .scheme
            .map(|s| s.to_string())
            .unwrap_or("http".to_string()),
        parts
            .authority
            .map(|a| a.to_string())
            .unwrap_or("localhost:7766".to_string())
    );
    let metadata = AuthZenMetadataResponse {
        policy_decision_point: base_url.clone(),
        access_evaluation_endpoint: format!("{}/access/v1/evaluation", base_url),
        access_evaluations_endpoint: format!("{}/access/v1/evaluations", base_url),
        search_subject_endpoint: format!("{}/access/v1/search/subject", base_url),
        search_resource_endpoint: format!("{}/access/v1/search/resource", base_url),
        search_action_endpoint: format!("{}/access/v1/search/action", base_url),
    };
    (StatusCode::OK, Json(metadata)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestFixture;
    use axum::body::Body;
    use http::{Request as HttpRequest, StatusCode, Uri};

    #[tokio::test]
    async fn test_authzen_metadata_handler() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Send request to the metadata endpoint
        let response = fixture.get("/.well-known/authzen-configuration").await;

        // Verify response status
        response.assert_status(StatusCode::OK);

        // Parse the response body
        let metadata: AuthZenMetadataResponse = response.json_as();

        // Verify the response contains expected fields
        assert_eq!(metadata.policy_decision_point, "http://localhost:7766");
        assert_eq!(
            metadata.access_evaluation_endpoint,
            "http://localhost:7766/access/v1/evaluation"
        );
        assert_eq!(
            metadata.access_evaluations_endpoint,
            "http://localhost:7766/access/v1/evaluations"
        );
        assert_eq!(
            metadata.search_subject_endpoint,
            "http://localhost:7766/access/v1/search/subject"
        );
        assert_eq!(
            metadata.search_action_endpoint,
            "http://localhost:7766/access/v1/search/action"
        );
        assert_eq!(
            metadata.search_resource_endpoint,
            "http://localhost:7766/access/v1/search/resource"
        );
    }

    #[tokio::test]
    async fn test_authzen_metadata_handler_with_custom_host() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Create a custom URI with a specific scheme, host and port
        let uri_string = "https://custom-host.example.com:8443/.well-known/authzen-configuration";
        let uri = Uri::try_from(uri_string).expect("Failed to create URI");

        // Build a request manually
        let request = HttpRequest::builder()
            .uri(uri)
            .method("GET")
            .header(
                "Authorization",
                format!("Bearer {}", fixture.config.api_key),
            )
            .header("Content-Type", "application/json")
            .body(Body::empty())
            .expect("Failed to build request");

        // Send the request
        let response = fixture.send(request).await;

        // Verify response status
        response.assert_status(StatusCode::OK);

        // Parse the response body
        let metadata: AuthZenMetadataResponse = response.json_as();

        // Verify the response contains the custom scheme, host and port
        let expected_base = "https://custom-host.example.com:8443";
        assert_eq!(metadata.policy_decision_point, expected_base);
        assert_eq!(
            metadata.access_evaluation_endpoint,
            format!("{}/access/v1/evaluation", expected_base)
        );
        assert_eq!(
            metadata.access_evaluations_endpoint,
            format!("{}/access/v1/evaluations", expected_base)
        );
        assert_eq!(
            metadata.search_subject_endpoint,
            format!("{}/access/v1/search/subject", expected_base)
        );
        assert_eq!(
            metadata.search_action_endpoint,
            format!("{}/access/v1/search/action", expected_base)
        );
        assert_eq!(
            metadata.search_resource_endpoint,
            format!("{}/access/v1/search/resource", expected_base)
        );
    }
}
