use crate::api::authzen::errors::AuthZenError;
use crate::api::authzen::schema::AuthZenResource;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Reads a search request's `resource.properties.tenant` as the tenant filter for OPA.
///
/// Returns `None` when the property is absent.
///
/// # Errors
///
/// Returns an `invalid_request` (400) error when the property is not a JSON string.
pub fn tenant_filter(resource: &AuthZenResource) -> Result<Option<Vec<String>>, AuthZenError> {
    let Some(tenant) = resource
        .properties
        .as_ref()
        .and_then(|properties| properties.get("tenant"))
    else {
        return Ok(None);
    };
    let serde_json::Value::String(tenant) = tenant else {
        return Err(AuthZenError::invalid_request(
            "resource.properties.tenant must be a string",
        ));
    };
    Ok(Some(vec![tenant.clone()]))
}

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
