use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Pagination request parameters. Search results are not paged: the PDP accepts this object,
/// ignores it, and returns every result in one response.
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
    /// Token for retrieving the next page of results. An empty string means there are no more
    /// results, which is always the case because every result is returned in one response.
    pub next_token: String,
}
