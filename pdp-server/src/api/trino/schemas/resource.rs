use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;

// ============================================================================
// Resource Structures
// ============================================================================

/// All possible resource kinds
/// This uses untagged serialization to match the actual JSON structure
/// where resources are direct objects with specific field names
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(untagged)]
#[allow(non_snake_case)]
pub enum TrinoResource {
    User {
        user: TrinoUser,
    },
    SystemSessionProperty {
        systemSessionProperty: NamedEntity,
    },
    CatalogSessionProperty {
        catalogSessionProperty: TrinoCatalogSessionProperty,
    },
    Function {
        function: TrinoFunction,
    },
    Catalog {
        catalog: NamedEntity,
    },
    Schema {
        schema: TrinoSchema,
    },
    Table {
        table: TrinoTable,
    },
    Column {
        column: TrinoColumn,
    },
}

impl TrinoResource {
    pub fn get_name(&self) -> String {
        match self {
            TrinoResource::Table { table } => format!(
                "{}.{}.{}",
                table.catalog_name, table.schema_name, table.table_name
            ),
            TrinoResource::Schema { schema } => {
                format!("{}.{}", schema.catalog_name, schema.schema_name)
            }
            TrinoResource::Catalog { catalog } => catalog.name.clone(),
            TrinoResource::User { user } => user.name.clone(),
            TrinoResource::SystemSessionProperty {
                systemSessionProperty,
            } => systemSessionProperty.name.clone(),
            TrinoResource::CatalogSessionProperty {
                catalogSessionProperty,
            } => format!(
                "{}.{}",
                catalogSessionProperty.catalog, catalogSessionProperty.property
            ),
            TrinoResource::Function { function } => format!(
                "{}.{}.{}",
                function.schema.catalog_name, function.schema.schema_name, function.function_name
            ),
            TrinoResource::Column { column } => format!(
                "{}.{}.{}",
                column.table.catalog_name, column.table.schema_name, column.name
            ),
        }
    }

    pub fn get_type(&self) -> String {
        match self {
            TrinoResource::Table { .. } => "table".to_string(),
            TrinoResource::Schema { .. } => "schema".to_string(),
            TrinoResource::Catalog { .. } => "catalog".to_string(),
            TrinoResource::User { .. } => "user".to_string(),
            TrinoResource::SystemSessionProperty { .. } => "systemSessionProperty".to_string(),
            TrinoResource::CatalogSessionProperty { .. } => "catalogSessionProperty".to_string(),
            TrinoResource::Function { .. } => "function".to_string(),
            TrinoResource::Column { .. } => "column".to_string(),
        }
    }

    pub fn to_debug_string(&self) -> String {
        format!("{}={}", self.get_type(), self.get_name())
    }
}

/// Simple wrapper for single-string entities
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct NamedEntity {
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct TrinoUser {
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct TrinoCatalogSessionProperty {
    pub catalog: String,
    pub property: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct TrinoSchema {
    #[serde(rename = "catalogName")]
    pub catalog_name: String,
    #[serde(rename = "schemaName")]
    pub schema_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<HashMap<String, Option<String>>>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct TrinoTable {
    #[serde(rename = "catalogName")]
    pub catalog_name: String,
    #[serde(rename = "schemaName")]
    pub schema_name: String,
    #[serde(rename = "tableName")]
    pub table_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub columns: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<HashMap<String, Option<String>>>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct TrinoTableRef {
    #[serde(rename = "catalogName")]
    pub catalog_name: String,
    #[serde(rename = "schemaName")]
    pub schema_name: String,
    #[serde(rename = "tableName")]
    pub table_name: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct TrinoColumn {
    pub table: TrinoTableRef,
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct TrinoFunction {
    pub schema: TrinoSchema,
    #[serde(rename = "functionName")]
    pub function_name: String,
}
