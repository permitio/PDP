use crate::api::trino::schemas::{
    core::TrinoAuthzQuery,
    resource::{NamedEntity, TrinoFunction, TrinoResource, TrinoSchema, TrinoTable},
};
use crate::headers::ClientCacheControl;
use crate::opa_client::allowed::{AllowedQuery, Resource, User};
use crate::opa_client::cached::{query_allowed_bulk_cached, query_allowed_cached};
use crate::state::AppState;
use std::collections::HashMap;

pub async fn check_trino_allowed(
    state: &AppState,
    query: &TrinoAuthzQuery,
    cache_control: &ClientCacheControl,
) -> bool {
    match &query.action.resource {
        // Table resources
        Some(TrinoResource::Table { table }) => {
            let table_allowed = check_trino_table_allowed(state, query, table, cache_control).await;
            if table_allowed {
                // If user has table permissions, allow access regardless of column permissions
                true
            } else {
                // If user doesn't have table permissions, check if they have all column permissions
                check_trino_table_all_columns_allowed(state, query, table, cache_control).await
            }
        }
        Some(TrinoResource::Schema { schema }) => {
            check_trino_schema_allowed(state, query, schema, cache_control).await
        }
        Some(TrinoResource::Catalog { catalog }) => {
            check_trino_catalog_allowed(state, query, catalog, cache_control).await
        }
        Some(TrinoResource::Function { function }) => {
            check_trino_function_allowed(state, query, function, cache_control).await
        }
        // System resources
        Some(TrinoResource::User { user: _ }) => {
            check_trino_system_allowed(state, query, cache_control).await
        }
        Some(TrinoResource::SystemSessionProperty {
            systemSessionProperty: _,
        }) => check_trino_system_allowed(state, query, cache_control).await,
        Some(TrinoResource::CatalogSessionProperty {
            catalogSessionProperty: _,
        }) => check_trino_system_allowed(state, query, cache_control).await,
        None => {
            // Trino System authz request does not have a resource
            check_trino_system_allowed(state, query, cache_control).await
        }
        _ => {
            log::warn!("Trino authz request is not supported, returning false");
            false
        }
    }
}

async fn check_trino_system_allowed(
    state: &AppState,
    query: &TrinoAuthzQuery,
    cache_control: &ClientCacheControl,
) -> bool {
    let allowed = query_allowed_cached(
        state,
        &build_allowed_query(query, "trino_sys"),
        cache_control,
    )
    .await;
    match allowed {
        Ok(allowed) => allowed.allow,
        Err(e) => {
            log::error!("Error checking trino system allowed: {e}");
            false
        }
    }
}

async fn check_trino_table_allowed(
    state: &AppState,
    query: &TrinoAuthzQuery,
    table: &TrinoTable,
    cache_control: &ClientCacheControl,
) -> bool {
    let allowed = query_allowed_cached(
        state,
        &build_allowed_query(
            query,
            format!(
                "trino_table_{catalog_name}_{schema_name}_{table_name}",
                catalog_name = table.catalog_name,
                schema_name = table.schema_name,
                table_name = table.table_name,
            ),
        ),
        cache_control,
    )
    .await;
    match allowed {
        Ok(allowed) => allowed.allow,
        Err(e) => {
            log::error!("Error checking trino table allowed: {e}");
            false
        }
    }
}

async fn check_trino_table_all_columns_allowed(
    state: &AppState,
    query: &TrinoAuthzQuery,
    table: &TrinoTable,
    cache_control: &ClientCacheControl,
) -> bool {
    let columns = match &table.columns {
        Some(columns) if !columns.is_empty() => columns,
        _ => return true,
    };
    let queries = columns
        .iter()
        .map(|column| {
            build_allowed_query(
                query,
                format!(
                    "trino_column_{catalog_name}_{schema_name}_{table_name}_{column_name}",
                    catalog_name = table.catalog_name,
                    schema_name = table.schema_name,
                    table_name = table.table_name,
                    column_name = column,
                ),
            )
        })
        .collect::<Vec<_>>();
    let allowed = query_allowed_bulk_cached(state, &queries, cache_control).await;
    match allowed {
        Ok(allowed) => allowed.allow.iter().all(|allowed| allowed.allow),
        Err(e) => {
            log::error!("Error checking trino table all columns allowed: {e}");
            false
        }
    }
}

async fn check_trino_schema_allowed(
    state: &AppState,
    query: &TrinoAuthzQuery,
    schema: &TrinoSchema,
    cache_control: &ClientCacheControl,
) -> bool {
    let allowed = query_allowed_cached(
        state,
        &build_allowed_query(
            query,
            format!(
                "trino_schema_{catalog_name}_{schema_name}",
                catalog_name = schema.catalog_name,
                schema_name = schema.schema_name
            ),
        ),
        cache_control,
    )
    .await;
    match allowed {
        Ok(allowed) => allowed.allow,
        Err(e) => {
            log::error!("Error checking trino schema allowed: {e}");
            false
        }
    }
}

async fn check_trino_catalog_allowed(
    state: &AppState,
    query: &TrinoAuthzQuery,
    catalog: &NamedEntity,
    cache_control: &ClientCacheControl,
) -> bool {
    let allowed = query_allowed_cached(
        state,
        &build_allowed_query(
            query,
            format!("trino_catalog_{catalog_name}", catalog_name = catalog.name),
        ),
        cache_control,
    )
    .await;
    match allowed {
        Ok(allowed) => allowed.allow,
        Err(e) => {
            log::error!("Error checking trino catalog allowed: {e}");
            false
        }
    }
}

async fn check_trino_function_allowed(
    state: &AppState,
    query: &TrinoAuthzQuery,
    function: &TrinoFunction,
    cache_control: &ClientCacheControl,
) -> bool {
    let allowed = query_allowed_cached(
        state,
        &build_allowed_query(
            query,
            format!(
                "trino_function_{catalog_name}_{schema_name}_{function_name}",
                catalog_name = function.schema.catalog_name,
                schema_name = function.schema.schema_name,
                function_name = function.function_name,
            ),
        ),
        cache_control,
    )
    .await;
    match allowed {
        Ok(allowed) => allowed.allow,
        Err(e) => {
            log::error!("Error checking trino function allowed: {e}");
            false
        }
    }
}

fn build_allowed_query(query: &TrinoAuthzQuery, resource: impl Into<String>) -> AllowedQuery {
    AllowedQuery {
        user: User {
            key: query.context.identity.user.clone(),
            first_name: None,
            last_name: None,
            email: None,
            attributes: HashMap::new(),
        },
        action: query.action.operation.to_string(),
        resource: Resource {
            r#type: resource.into(),
            key: None,
            tenant: Some("default".to_string()), // TODO: Add tenant based on the user's groups
            attributes: HashMap::new(),
            context: HashMap::new(),
        },
        context: HashMap::new(),
        sdk: Some(format!(
            "trino/{}",
            query.context.software_stack.trino_version
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::trino::schemas::{
        action::{TrinoAllowAction, TrinoOperation},
        context::{TrinoContext, TrinoIdentity, TrinoStackContext},
        resource::{
            TrinoCatalogSessionProperty, TrinoColumn, TrinoFunction, TrinoSchema, TrinoTable,
            TrinoTableRef, TrinoUser,
        },
    };
    use crate::test_utils::TestFixture;
    use http::{Method, StatusCode};
    use serde_json::json;

    #[tokio::test]
    async fn test_check_trino_system_allowed_success() {
        let fixture = TestFixture::new().await;

        // Setup mock OPA response
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/root",
                json!({
                    "result": {
                        "allow": true,
                        "result": true
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        let query = TrinoAuthzQuery {
            context: TrinoContext {
                identity: TrinoIdentity {
                    user: "admin".to_string(),
                    groups: vec!["admins".to_string()],
                },
                software_stack: TrinoStackContext {
                    trino_version: "435".to_string(),
                },
            },
            action: TrinoAllowAction {
                operation: TrinoOperation::ReadSystemInformation,
                resource: None,
                filter_resources: None,
                target_resource: None,
                grantee: None,
            },
        };

        let cache_control = ClientCacheControl::default();
        let result = check_trino_system_allowed(&fixture.state, &query, &cache_control).await;

        assert!(result);
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_check_trino_system_allowed_denied() {
        let fixture = TestFixture::new().await;

        // Setup mock OPA response
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/root",
                json!({
                    "result": {
                        "allow": false,
                        "result": false
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        let query = TrinoAuthzQuery {
            context: TrinoContext {
                identity: TrinoIdentity {
                    user: "user".to_string(),
                    groups: vec!["users".to_string()],
                },
                software_stack: TrinoStackContext {
                    trino_version: "435".to_string(),
                },
            },
            action: TrinoAllowAction {
                operation: TrinoOperation::ReadSystemInformation,
                resource: None,
                filter_resources: None,
                target_resource: None,
                grantee: None,
            },
        };

        let cache_control = ClientCacheControl::default();
        let result = check_trino_system_allowed(&fixture.state, &query, &cache_control).await;

        assert!(!result);
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_check_trino_system_allowed_opa_error() {
        let fixture = TestFixture::new().await;

        // Setup mock OPA response that returns an error
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/root",
                json!({
                    "error": "Internal server error"
                }),
                StatusCode::INTERNAL_SERVER_ERROR,
                1,
            )
            .await;

        let query = TrinoAuthzQuery {
            context: TrinoContext {
                identity: TrinoIdentity {
                    user: "admin".to_string(),
                    groups: vec!["admins".to_string()],
                },
                software_stack: TrinoStackContext {
                    trino_version: "435".to_string(),
                },
            },
            action: TrinoAllowAction {
                operation: TrinoOperation::ReadSystemInformation,
                resource: None,
                filter_resources: None,
                target_resource: None,
                grantee: None,
            },
        };

        let cache_control = ClientCacheControl::default();
        let result = check_trino_system_allowed(&fixture.state, &query, &cache_control).await;

        // Should return false on OPA error
        assert!(!result);
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_check_trino_table_allowed_success() {
        let fixture = TestFixture::new().await;

        // Setup mock OPA response
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/root",
                json!({
                    "result": {
                        "allow": true,
                        "result": true
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        let table = TrinoTable {
            catalog_name: "test_catalog".to_string(),
            schema_name: "test_schema".to_string(),
            table_name: "test_table".to_string(),
            columns: None,
            properties: None,
        };

        let query = TrinoAuthzQuery {
            context: TrinoContext {
                identity: TrinoIdentity {
                    user: "analyst".to_string(),
                    groups: vec!["analysts".to_string()],
                },
                software_stack: TrinoStackContext {
                    trino_version: "434".to_string(),
                },
            },
            action: TrinoAllowAction {
                operation: TrinoOperation::SelectFromColumns,
                resource: Some(TrinoResource::Table {
                    table: table.clone(),
                }),
                filter_resources: None,
                target_resource: None,
                grantee: None,
            },
        };

        let cache_control = ClientCacheControl::default();
        let result =
            check_trino_table_allowed(&fixture.state, &query, &table, &cache_control).await;

        assert!(result);
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_check_trino_table_allowed_denied() {
        let fixture = TestFixture::new().await;

        // Setup mock OPA response
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/root",
                json!({
                    "result": {
                        "allow": false,
                        "result": false
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        let table = TrinoTable {
            catalog_name: "restricted_catalog".to_string(),
            schema_name: "restricted_schema".to_string(),
            table_name: "restricted_table".to_string(),
            columns: None,
            properties: None,
        };

        let query = TrinoAuthzQuery {
            context: TrinoContext {
                identity: TrinoIdentity {
                    user: "user".to_string(),
                    groups: vec!["users".to_string()],
                },
                software_stack: TrinoStackContext {
                    trino_version: "434".to_string(),
                },
            },
            action: TrinoAllowAction {
                operation: TrinoOperation::SelectFromColumns,
                resource: Some(TrinoResource::Table {
                    table: table.clone(),
                }),
                filter_resources: None,
                target_resource: None,
                grantee: None,
            },
        };

        let cache_control = ClientCacheControl::default();
        let result =
            check_trino_table_allowed(&fixture.state, &query, &table, &cache_control).await;

        assert!(!result);
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_check_trino_table_all_columns_allowed_success() {
        let fixture = TestFixture::new().await;

        // Setup mock OPA response for bulk column checks
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/bulk",
                json!({
                    "result": {
                        "allow": [
                            {"allow": true, "result": true},
                            {"allow": true, "result": true},
                            {"allow": true, "result": true}
                        ]
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        let table = TrinoTable {
            catalog_name: "test_catalog".to_string(),
            schema_name: "test_schema".to_string(),
            table_name: "test_table".to_string(),
            columns: Some(vec![
                "column1".to_string(),
                "column2".to_string(),
                "column3".to_string(),
            ]),
            properties: None,
        };

        let query = TrinoAuthzQuery {
            context: TrinoContext {
                identity: TrinoIdentity {
                    user: "analyst".to_string(),
                    groups: vec!["analysts".to_string()],
                },
                software_stack: TrinoStackContext {
                    trino_version: "434".to_string(),
                },
            },
            action: TrinoAllowAction {
                operation: TrinoOperation::SelectFromColumns,
                resource: Some(TrinoResource::Table {
                    table: table.clone(),
                }),
                filter_resources: None,
                target_resource: None,
                grantee: None,
            },
        };

        let cache_control = ClientCacheControl::default();
        let result =
            check_trino_table_all_columns_allowed(&fixture.state, &query, &table, &cache_control)
                .await;

        assert!(result);
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_check_trino_table_all_columns_allowed_partial_denial() {
        let fixture = TestFixture::new().await;

        // Setup mock OPA response for bulk column checks - one column denied
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/bulk",
                json!({
                    "result": {
                        "allow": [
                            {"allow": true, "result": true},
                            {"allow": false, "result": false}, // This column is denied
                            {"allow": true, "result": true}
                        ]
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        let table = TrinoTable {
            catalog_name: "test_catalog".to_string(),
            schema_name: "test_schema".to_string(),
            table_name: "test_table".to_string(),
            columns: Some(vec![
                "column1".to_string(),
                "sensitive_column".to_string(),
                "column3".to_string(),
            ]),
            properties: None,
        };

        let query = TrinoAuthzQuery {
            context: TrinoContext {
                identity: TrinoIdentity {
                    user: "analyst".to_string(),
                    groups: vec!["analysts".to_string()],
                },
                software_stack: TrinoStackContext {
                    trino_version: "434".to_string(),
                },
            },
            action: TrinoAllowAction {
                operation: TrinoOperation::SelectFromColumns,
                resource: Some(TrinoResource::Table {
                    table: table.clone(),
                }),
                filter_resources: None,
                target_resource: None,
                grantee: None,
            },
        };

        let cache_control = ClientCacheControl::default();
        let result =
            check_trino_table_all_columns_allowed(&fixture.state, &query, &table, &cache_control)
                .await;

        // Should be denied because one column is not allowed
        assert!(!result);
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_check_trino_table_all_columns_allowed_no_columns() {
        let fixture = TestFixture::new().await;

        let table = TrinoTable {
            catalog_name: "test_catalog".to_string(),
            schema_name: "test_schema".to_string(),
            table_name: "test_table".to_string(),
            columns: None, // No columns specified
            properties: None,
        };

        let query = TrinoAuthzQuery {
            context: TrinoContext {
                identity: TrinoIdentity {
                    user: "analyst".to_string(),
                    groups: vec!["analysts".to_string()],
                },
                software_stack: TrinoStackContext {
                    trino_version: "434".to_string(),
                },
            },
            action: TrinoAllowAction {
                operation: TrinoOperation::SelectFromColumns,
                resource: Some(TrinoResource::Table {
                    table: table.clone(),
                }),
                filter_resources: None,
                target_resource: None,
                grantee: None,
            },
        };

        let cache_control = ClientCacheControl::default();
        let result =
            check_trino_table_all_columns_allowed(&fixture.state, &query, &table, &cache_control)
                .await;

        // Should return true when no columns are specified
        assert!(result);
    }

    #[tokio::test]
    async fn test_check_trino_table_all_columns_allowed_empty_columns() {
        let fixture = TestFixture::new().await;

        let table = TrinoTable {
            catalog_name: "test_catalog".to_string(),
            schema_name: "test_schema".to_string(),
            table_name: "test_table".to_string(),
            columns: Some(vec![]), // Empty columns list
            properties: None,
        };

        let query = TrinoAuthzQuery {
            context: TrinoContext {
                identity: TrinoIdentity {
                    user: "analyst".to_string(),
                    groups: vec!["analysts".to_string()],
                },
                software_stack: TrinoStackContext {
                    trino_version: "434".to_string(),
                },
            },
            action: TrinoAllowAction {
                operation: TrinoOperation::SelectFromColumns,
                resource: Some(TrinoResource::Table {
                    table: table.clone(),
                }),
                filter_resources: None,
                target_resource: None,
                grantee: None,
            },
        };

        let cache_control = ClientCacheControl::default();
        let result =
            check_trino_table_all_columns_allowed(&fixture.state, &query, &table, &cache_control)
                .await;

        // Should return true when columns list is empty
        assert!(result);
    }

    #[tokio::test]
    async fn test_check_trino_schema_allowed_success() {
        let fixture = TestFixture::new().await;

        // Setup mock OPA response
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/root",
                json!({
                    "result": {
                        "allow": true,
                        "result": true
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        let schema = TrinoSchema {
            catalog_name: "test_catalog".to_string(),
            schema_name: "test_schema".to_string(),
            properties: None,
        };

        let query = TrinoAuthzQuery {
            context: TrinoContext {
                identity: TrinoIdentity {
                    user: "admin".to_string(),
                    groups: vec!["admins".to_string()],
                },
                software_stack: TrinoStackContext {
                    trino_version: "435".to_string(),
                },
            },
            action: TrinoAllowAction {
                operation: TrinoOperation::CreateSchema,
                resource: Some(TrinoResource::Schema {
                    schema: schema.clone(),
                }),
                filter_resources: None,
                target_resource: None,
                grantee: None,
            },
        };

        let cache_control = ClientCacheControl::default();
        let result =
            check_trino_schema_allowed(&fixture.state, &query, &schema, &cache_control).await;

        assert!(result);
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_check_trino_catalog_allowed_success() {
        let fixture = TestFixture::new().await;

        // Setup mock OPA response
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/root",
                json!({
                    "result": {
                        "allow": true,
                        "result": true
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        let catalog = NamedEntity {
            name: "test_catalog".to_string(),
        };

        let query = TrinoAuthzQuery {
            context: TrinoContext {
                identity: TrinoIdentity {
                    user: "admin".to_string(),
                    groups: vec!["admins".to_string()],
                },
                software_stack: TrinoStackContext {
                    trino_version: "435".to_string(),
                },
            },
            action: TrinoAllowAction {
                operation: TrinoOperation::AccessCatalog,
                resource: Some(TrinoResource::Catalog {
                    catalog: catalog.clone(),
                }),
                filter_resources: None,
                target_resource: None,
                grantee: None,
            },
        };

        let cache_control = ClientCacheControl::default();
        let result =
            check_trino_catalog_allowed(&fixture.state, &query, &catalog, &cache_control).await;

        assert!(result);
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_check_trino_function_allowed_success() {
        let fixture = TestFixture::new().await;

        // Setup mock OPA response
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/root",
                json!({
                    "result": {
                        "allow": true,
                        "result": true
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        let function = TrinoFunction {
            schema: TrinoSchema {
                catalog_name: "test_catalog".to_string(),
                schema_name: "functions".to_string(),
                properties: None,
            },
            function_name: "custom_function".to_string(),
        };

        let query = TrinoAuthzQuery {
            context: TrinoContext {
                identity: TrinoIdentity {
                    user: "developer".to_string(),
                    groups: vec!["developers".to_string()],
                },
                software_stack: TrinoStackContext {
                    trino_version: "435".to_string(),
                },
            },
            action: TrinoAllowAction {
                operation: TrinoOperation::ExecuteFunction,
                resource: Some(TrinoResource::Function {
                    function: function.clone(),
                }),
                filter_resources: None,
                target_resource: None,
                grantee: None,
            },
        };

        let cache_control = ClientCacheControl::default();
        let result =
            check_trino_function_allowed(&fixture.state, &query, &function, &cache_control).await;

        assert!(result);
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_check_trino_allowed_table_resource() {
        let fixture = TestFixture::new().await;

        // Setup mock OPA response for table access
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/root",
                json!({
                    "result": {
                        "allow": true,
                        "result": true
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        let table = TrinoTable {
            catalog_name: "test_catalog".to_string(),
            schema_name: "test_schema".to_string(),
            table_name: "test_table".to_string(),
            columns: None,
            properties: None,
        };

        let query = TrinoAuthzQuery {
            context: TrinoContext {
                identity: TrinoIdentity {
                    user: "analyst".to_string(),
                    groups: vec!["analysts".to_string()],
                },
                software_stack: TrinoStackContext {
                    trino_version: "434".to_string(),
                },
            },
            action: TrinoAllowAction {
                operation: TrinoOperation::SelectFromColumns,
                resource: Some(TrinoResource::Table { table }),
                filter_resources: None,
                target_resource: None,
                grantee: None,
            },
        };

        let cache_control = ClientCacheControl::default();
        let result = check_trino_allowed(&fixture.state, &query, &cache_control).await;

        assert!(result);
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_check_trino_allowed_schema_resource() {
        let fixture = TestFixture::new().await;

        // Setup mock OPA response for schema access
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/root",
                json!({
                    "result": {
                        "allow": true,
                        "result": true
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        let schema = TrinoSchema {
            catalog_name: "test_catalog".to_string(),
            schema_name: "test_schema".to_string(),
            properties: None,
        };

        let query = TrinoAuthzQuery {
            context: TrinoContext {
                identity: TrinoIdentity {
                    user: "admin".to_string(),
                    groups: vec!["admins".to_string()],
                },
                software_stack: TrinoStackContext {
                    trino_version: "435".to_string(),
                },
            },
            action: TrinoAllowAction {
                operation: TrinoOperation::CreateSchema,
                resource: Some(TrinoResource::Schema { schema }),
                filter_resources: None,
                target_resource: None,
                grantee: None,
            },
        };

        let cache_control = ClientCacheControl::default();
        let result = check_trino_allowed(&fixture.state, &query, &cache_control).await;

        assert!(result);
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_check_trino_allowed_catalog_resource() {
        let fixture = TestFixture::new().await;

        // Setup mock OPA response for catalog access
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/root",
                json!({
                    "result": {
                        "allow": true,
                        "result": true
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        let catalog = NamedEntity {
            name: "test_catalog".to_string(),
        };

        let query = TrinoAuthzQuery {
            context: TrinoContext {
                identity: TrinoIdentity {
                    user: "admin".to_string(),
                    groups: vec!["admins".to_string()],
                },
                software_stack: TrinoStackContext {
                    trino_version: "435".to_string(),
                },
            },
            action: TrinoAllowAction {
                operation: TrinoOperation::AccessCatalog,
                resource: Some(TrinoResource::Catalog { catalog }),
                filter_resources: None,
                target_resource: None,
                grantee: None,
            },
        };

        let cache_control = ClientCacheControl::default();
        let result = check_trino_allowed(&fixture.state, &query, &cache_control).await;

        assert!(result);
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_check_trino_allowed_function_resource() {
        let fixture = TestFixture::new().await;

        // Setup mock OPA response for function access
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/root",
                json!({
                    "result": {
                        "allow": true,
                        "result": true
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        let function = TrinoFunction {
            schema: TrinoSchema {
                catalog_name: "test_catalog".to_string(),
                schema_name: "functions".to_string(),
                properties: None,
            },
            function_name: "custom_function".to_string(),
        };

        let query = TrinoAuthzQuery {
            context: TrinoContext {
                identity: TrinoIdentity {
                    user: "developer".to_string(),
                    groups: vec!["developers".to_string()],
                },
                software_stack: TrinoStackContext {
                    trino_version: "435".to_string(),
                },
            },
            action: TrinoAllowAction {
                operation: TrinoOperation::ExecuteFunction,
                resource: Some(TrinoResource::Function { function }),
                filter_resources: None,
                target_resource: None,
                grantee: None,
            },
        };

        let cache_control = ClientCacheControl::default();
        let result = check_trino_allowed(&fixture.state, &query, &cache_control).await;

        assert!(result);
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_check_trino_allowed_system_session_property() {
        let fixture = TestFixture::new().await;

        // Setup mock OPA response for system operation
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/root",
                json!({
                    "result": {
                        "allow": true,
                        "result": true
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        let system_property = NamedEntity {
            name: "system_property".to_string(),
        };

        let query = TrinoAuthzQuery {
            context: TrinoContext {
                identity: TrinoIdentity {
                    user: "admin".to_string(),
                    groups: vec!["admins".to_string()],
                },
                software_stack: TrinoStackContext {
                    trino_version: "435".to_string(),
                },
            },
            action: TrinoAllowAction {
                operation: TrinoOperation::SetSystemSessionProperty,
                resource: Some(TrinoResource::SystemSessionProperty {
                    systemSessionProperty: system_property,
                }),
                filter_resources: None,
                target_resource: None,
                grantee: None,
            },
        };

        let cache_control = ClientCacheControl::default();
        let result = check_trino_allowed(&fixture.state, &query, &cache_control).await;

        assert!(result);
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_check_trino_allowed_catalog_session_property() {
        let fixture = TestFixture::new().await;

        // Setup mock OPA response for system operation
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/root",
                json!({
                    "result": {
                        "allow": true,
                        "result": true
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        let catalog_property = TrinoCatalogSessionProperty {
            catalog: "test_catalog".to_string(),
            property: "session_property".to_string(),
        };

        let query = TrinoAuthzQuery {
            context: TrinoContext {
                identity: TrinoIdentity {
                    user: "admin".to_string(),
                    groups: vec!["admins".to_string()],
                },
                software_stack: TrinoStackContext {
                    trino_version: "435".to_string(),
                },
            },
            action: TrinoAllowAction {
                operation: TrinoOperation::SetCatalogSessionProperty,
                resource: Some(TrinoResource::CatalogSessionProperty {
                    catalogSessionProperty: catalog_property,
                }),
                filter_resources: None,
                target_resource: None,
                grantee: None,
            },
        };

        let cache_control = ClientCacheControl::default();
        let result = check_trino_allowed(&fixture.state, &query, &cache_control).await;

        assert!(result);
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_check_trino_allowed_user_resource() {
        let fixture = TestFixture::new().await;

        // Setup mock OPA response for system operation
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/root",
                json!({
                    "result": {
                        "allow": true,
                        "result": true
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        let user = TrinoUser {
            name: "target_user".to_string(),
        };

        let query = TrinoAuthzQuery {
            context: TrinoContext {
                identity: TrinoIdentity {
                    user: "admin".to_string(),
                    groups: vec!["admins".to_string()],
                },
                software_stack: TrinoStackContext {
                    trino_version: "435".to_string(),
                },
            },
            action: TrinoAllowAction {
                operation: TrinoOperation::ImpersonateUser,
                resource: Some(TrinoResource::User { user }),
                filter_resources: None,
                target_resource: None,
                grantee: None,
            },
        };

        let cache_control = ClientCacheControl::default();
        let result = check_trino_allowed(&fixture.state, &query, &cache_control).await;

        assert!(result);
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_check_trino_allowed_no_resource() {
        let fixture = TestFixture::new().await;

        // Setup mock OPA response for system operation
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/root",
                json!({
                    "result": {
                        "allow": true,
                        "result": true
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        let query = TrinoAuthzQuery {
            context: TrinoContext {
                identity: TrinoIdentity {
                    user: "admin".to_string(),
                    groups: vec!["admins".to_string()],
                },
                software_stack: TrinoStackContext {
                    trino_version: "435".to_string(),
                },
            },
            action: TrinoAllowAction {
                operation: TrinoOperation::ReadSystemInformation,
                resource: None,
                filter_resources: None,
                target_resource: None,
                grantee: None,
            },
        };

        let cache_control = ClientCacheControl::default();
        let result = check_trino_allowed(&fixture.state, &query, &cache_control).await;

        assert!(result);
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_check_trino_allowed_unsupported_resource() {
        let fixture = TestFixture::new().await;

        // Create a query with an unsupported resource type
        let query = TrinoAuthzQuery {
            context: TrinoContext {
                identity: TrinoIdentity {
                    user: "user".to_string(),
                    groups: vec!["users".to_string()],
                },
                software_stack: TrinoStackContext {
                    trino_version: "435".to_string(),
                },
            },
            action: TrinoAllowAction {
                operation: TrinoOperation::SelectFromColumns,
                resource: Some(TrinoResource::Column {
                    column: TrinoColumn {
                        table: TrinoTableRef {
                            catalog_name: "test_catalog".to_string(),
                            schema_name: "test_schema".to_string(),
                            table_name: "test_table".to_string(),
                        },
                        name: "test_column".to_string(),
                        ty: "varchar".to_string(),
                    },
                }),
                filter_resources: None,
                target_resource: None,
                grantee: None,
            },
        };

        let cache_control = ClientCacheControl::default();
        let result = check_trino_allowed(&fixture.state, &query, &cache_control).await;

        // Should return false for unsupported resources
        assert!(!result);
    }

    #[test]
    fn test_build_allowed_query() {
        let query = TrinoAuthzQuery {
            context: TrinoContext {
                identity: TrinoIdentity {
                    user: "test-user".to_string(),
                    groups: vec!["group1".to_string(), "group2".to_string()],
                },
                software_stack: TrinoStackContext {
                    trino_version: "434".to_string(),
                },
            },
            action: TrinoAllowAction {
                operation: TrinoOperation::SelectFromColumns,
                resource: None,
                filter_resources: None,
                target_resource: None,
                grantee: None,
            },
        };

        let allowed_query = build_allowed_query(&query, "test_resource");

        assert_eq!(allowed_query.user.key, "test-user");
        assert_eq!(allowed_query.action, "SelectFromColumns");
        assert_eq!(allowed_query.resource.r#type, "test_resource");
        assert_eq!(allowed_query.resource.tenant, Some("default".to_string()));
        assert_eq!(allowed_query.sdk, Some("trino/434".to_string()));
        assert!(allowed_query.user.first_name.is_none());
        assert!(allowed_query.user.last_name.is_none());
        assert!(allowed_query.user.email.is_none());
        assert!(allowed_query.user.attributes.is_empty());
        assert!(allowed_query.resource.attributes.is_empty());
        assert!(allowed_query.resource.context.is_empty());
        assert!(allowed_query.context.is_empty());
    }
}
