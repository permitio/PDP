use crate::opa_client::allowed::AllowedQuery;
use crate::opa_client::allowed::AllowedResult;
use crate::opa_client::{send_request_to_opa, ForwardingError};
use crate::state::AppState;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Request type for bulk authorization checks
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct BulkAuthorizationQuery {
    /// List of individual authorization queries
    pub checks: Vec<AllowedQuery>,
}

/// Response type for bulk authorization checks
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct BulkAuthorizationResult {
    /// List of authorization results, one for each check
    pub allow: Vec<AllowedResult>,
}

/// Send a bulk allowed query to OPA and get the result
pub async fn query_allowed_bulk(
    state: &AppState,
    queries: &[AllowedQuery],
) -> Result<BulkAuthorizationResult, ForwardingError> {
    let bulk_query = BulkAuthorizationQuery {
        checks: queries.to_vec(),
    };
    let result = send_request_to_opa::<BulkAuthorizationResult, _>(
        state,
        "/v1/data/permit/bulk",
        &bulk_query,
    )
    .await;

    // Add debug logging if enabled
    if let Ok(response) = &result {
        if state.config.debug.unwrap_or(false) {
            let allowed_count = response.allow.iter().filter(|r| r.allow).count();
            log::info!(
                "permit.bulk_check({} queries) -> {} allowed, {} denied",
                queries.len(),
                allowed_count,
                response.allow.len() - allowed_count
            );
            log::debug!(
                "Query: {}\nResult: {}",
                serde_json::to_string_pretty(&bulk_query)
                    .unwrap_or("Serialization error".to_string()),
                serde_json::to_string_pretty(response).unwrap_or("Serialization error".to_string()),
            );
        }
    }

    result
}
