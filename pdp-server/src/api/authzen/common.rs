use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Pagination request parameters
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
    /// Token for retrieving the next page of results, empty if no more results
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_token: Option<String>,
}
