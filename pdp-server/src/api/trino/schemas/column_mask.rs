use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{action::TrinoOperation, context::TrinoContext};

// ============================================================================
// Column Mask Structures
// ============================================================================

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TrinoColumnMaskQuery {
    pub context: TrinoContext,
    pub action: TrinoColumnMaskAction,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TrinoColumnMaskAction {
    pub operation: TrinoOperation,
    #[serde(rename = "filterResources")]
    pub filter_resources: Vec<TrinoColumnMaskResource>,
}

/// Column resource in column mask requests (flat structure as per Trino spec)
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct TrinoColumnMaskResource {
    pub column: TrinoColumnMaskColumn,
}

/// Column details in column mask requests
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct TrinoColumnMaskColumn {
    #[serde(rename = "catalogName")]
    pub catalog_name: String,
    #[serde(rename = "schemaName")]
    pub schema_name: String,
    #[serde(rename = "tableName")]
    pub table_name: String,
    #[serde(rename = "columnName")]
    pub column_name: String,
    #[serde(rename = "columnType")]
    pub column_type: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TrinoColumnMaskResponse {
    pub index: usize,
    #[serde(rename = "viewExpression")]
    pub view_expression: ViewExpression,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ViewExpression {
    pub expression: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
}
