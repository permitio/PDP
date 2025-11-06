use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

// ============================================================================
// Context and Identity Structures
// ============================================================================

/// Who is asking, plus Trino version
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TrinoContext {
    pub identity: TrinoIdentity,
    #[serde(rename = "softwareStack")]
    pub software_stack: TrinoStackContext,
}

/// User and groups taken from the Trino session
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TrinoIdentity {
    pub user: String,
    pub groups: Vec<String>,
}

/// Holds the running Trino version (e.g. "448")
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TrinoStackContext {
    #[serde(rename = "trinoVersion")]
    pub trino_version: String,
}
