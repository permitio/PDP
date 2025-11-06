use serde::{Deserialize, Serialize};
use std::fmt;
use utoipa::ToSchema;

use super::resource::TrinoResource;

// ============================================================================
// Action and Operation Structures
// ============================================================================

/// The actual decision request
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TrinoAllowAction {
    pub operation: TrinoOperation,
    pub resource: Option<TrinoResource>,
    #[serde(rename = "filterResources")]
    pub filter_resources: Option<Vec<TrinoResource>>,
    #[serde(rename = "targetResource")]
    pub target_resource: Option<TrinoResource>,
    pub grantee: Option<TrinoGrantPrincipal>,
}

/// Trino operations
// source: https://github.com/trinodb/trino/blob/af38a3c0f14f572ca8a63ca688d96996955ef6d2/plugin/trino-opa/src/main/java/io/trino/plugin/opa/OpaAccessControl.java#L440
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq, Eq, Hash)]
#[serde(rename_all = "PascalCase")]
pub enum TrinoOperation {
    // User / query management
    ImpersonateUser,
    ExecuteQuery,
    ViewQueryOwnedBy,
    FilterViewQueryOwnedBy,
    KillQueryOwnedBy,
    ReadSystemInformation,
    WriteSystemInformation,
    SetSystemSessionProperty,
    // Catalog
    AccessCatalog,
    CreateCatalog,
    DropCatalog,
    FilterCatalogs,
    // Schema
    CreateSchema,
    DropSchema,
    RenameSchema,
    SetSchemaAuthorization,
    ShowSchemas,
    FilterSchemas,
    ShowCreateSchema,
    // Table
    ShowCreateTable,
    CreateTable,
    DropTable,
    RenameTable,
    SetTableProperties,
    SetTableComment,
    AddColumn,
    AlterColumn,
    DropColumn,
    RenameColumn,
    SelectFromColumns,
    InsertIntoTable,
    DeleteFromTable,
    TruncateTable,
    UpdateTableColumns,
    ShowTables,
    FilterTables,
    ShowColumns,
    FilterColumns,
    SetTableAuthorization,
    // View / Materialized View
    CreateView,
    RenameView,
    DropView,
    SetViewAuthorization,
    SetViewComment,
    CreateViewWithSelectFromColumns,
    CreateMaterializedView,
    RefreshMaterializedView,
    SetMaterializedViewProperties,
    DropMaterializedView,
    RenameMaterializedView,
    // Session properties
    SetCatalogSessionProperty,
    // Functions / procedures
    ShowFunctions,
    FilterFunctions,
    ExecuteFunction,
    ExecuteProcedure,
    ExecuteTableProcedure,
    CreateFunction,
    DropFunction,
    ShowCreateFunction,
    CreateViewWithExecuteFunction,
    // Row & column security
    GetRowFilters,
    GetColumnMask,
}

impl fmt::Display for TrinoOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let operation = match self {
            Self::ImpersonateUser => "ImpersonateUser",
            Self::ExecuteQuery => "ExecuteQuery",
            Self::ViewQueryOwnedBy => "ViewQueryOwnedBy",
            Self::FilterViewQueryOwnedBy => "FilterViewQueryOwnedBy",
            Self::KillQueryOwnedBy => "KillQueryOwnedBy",
            Self::ReadSystemInformation => "ReadSystemInformation",
            Self::WriteSystemInformation => "WriteSystemInformation",
            Self::SetSystemSessionProperty => "SetSystemSessionProperty",
            Self::AccessCatalog => "AccessCatalog",
            Self::CreateCatalog => "CreateCatalog",
            Self::DropCatalog => "DropCatalog",
            Self::FilterCatalogs => "FilterCatalogs",
            Self::CreateSchema => "CreateSchema",
            Self::DropSchema => "DropSchema",
            Self::RenameSchema => "RenameSchema",
            Self::SetSchemaAuthorization => "SetSchemaAuthorization",
            Self::ShowSchemas => "ShowSchemas",
            Self::FilterSchemas => "FilterSchemas",
            Self::ShowCreateSchema => "ShowCreateSchema",
            Self::ShowCreateTable => "ShowCreateTable",
            Self::CreateTable => "CreateTable",
            Self::DropTable => "DropTable",
            Self::RenameTable => "RenameTable",
            Self::SetTableProperties => "SetTableProperties",
            Self::SetTableComment => "SetTableComment",
            Self::AddColumn => "AddColumn",
            Self::AlterColumn => "AlterColumn",
            Self::DropColumn => "DropColumn",
            Self::RenameColumn => "RenameColumn",
            Self::SelectFromColumns => "SelectFromColumns",
            Self::InsertIntoTable => "InsertIntoTable",
            Self::DeleteFromTable => "DeleteFromTable",
            Self::TruncateTable => "TruncateTable",
            Self::UpdateTableColumns => "UpdateTableColumns",
            Self::ShowTables => "ShowTables",
            Self::FilterTables => "FilterTables",
            Self::ShowColumns => "ShowColumns",
            Self::FilterColumns => "FilterColumns",
            Self::SetTableAuthorization => "SetTableAuthorization",
            Self::CreateView => "CreateView",
            Self::RenameView => "RenameView",
            Self::DropView => "DropView",
            Self::SetViewAuthorization => "SetViewAuthorization",
            Self::SetViewComment => "SetViewComment",
            Self::CreateViewWithSelectFromColumns => "CreateViewWithSelectFromColumns",
            Self::CreateMaterializedView => "CreateMaterializedView",
            Self::RefreshMaterializedView => "RefreshMaterializedView",
            Self::SetMaterializedViewProperties => "SetMaterializedViewProperties",
            Self::DropMaterializedView => "DropMaterializedView",
            Self::RenameMaterializedView => "RenameMaterializedView",
            Self::SetCatalogSessionProperty => "SetCatalogSessionProperty",
            Self::ShowFunctions => "ShowFunctions",
            Self::FilterFunctions => "FilterFunctions",
            Self::ExecuteFunction => "ExecuteFunction",
            Self::ExecuteProcedure => "ExecuteProcedure",
            Self::ExecuteTableProcedure => "ExecuteTableProcedure",
            Self::CreateFunction => "CreateFunction",
            Self::DropFunction => "DropFunction",
            Self::ShowCreateFunction => "ShowCreateFunction",
            Self::CreateViewWithExecuteFunction => "CreateViewWithExecuteFunction",
            Self::GetRowFilters => "GetRowFilters",
            Self::GetColumnMask => "GetColumnMask",
        };

        f.write_str(operation)
    }
}

/// Grant principal type
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(tag = "principalType")]
pub enum TrinoGrantPrincipal {
    #[serde(rename = "USER")]
    User { name: String },
    #[serde(rename = "ROLE")]
    Role { name: String },
}
