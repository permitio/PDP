use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{action::TrinoAllowAction, context::TrinoContext};

// ============================================================================
// Core Request/Response Structures
// ============================================================================

/// Top-level wrapper sent to every /v1/data/… endpoint
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TrinoAuthzQuery {
    pub context: TrinoContext,
    pub action: TrinoAllowAction,
}
