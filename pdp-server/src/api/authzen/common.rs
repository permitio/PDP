use crate::api::authzen::errors::AuthZenError;
use crate::api::authzen::schema::AuthZenResource;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// The resource type of tenant-level roles in OPA's user_permissions. Their entries are keyed
/// `__tenant:<tenant key>` and have no `resource`. OPA returns them only when this type is in
/// the query's `resource_types`.
pub const TENANT_TYPE: &str = "__tenant";

/// Reads a search request's `resource.properties.tenant`.
///
/// Returns `None` when the property is absent.
///
/// # Errors
///
/// Returns an `invalid_request` (400) error when the property is not a JSON string.
pub fn tenant_property(resource: &AuthZenResource) -> Result<Option<String>, AuthZenError> {
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
    Ok(Some(tenant.clone()))
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
