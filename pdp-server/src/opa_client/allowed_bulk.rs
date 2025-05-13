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
    send_request_to_opa::<BulkAuthorizationResult, _>(state, "/v1/data/permit/bulk", &bulk_query)
        .await
}
