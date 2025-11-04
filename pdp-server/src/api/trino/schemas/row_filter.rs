use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{action::TrinoOperation, context::TrinoContext, resource::TrinoResource};

// ============================================================================
// Row Filter Structures
// ============================================================================

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TrinoRowFilterQuery {
    pub context: TrinoContext,
    pub action: TrinoRowFilterAction,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TrinoRowFilterAction {
    pub operation: TrinoOperation,
    pub resource: TrinoResource,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TrinoRowFilterResponse {
    pub expression: String,
}
