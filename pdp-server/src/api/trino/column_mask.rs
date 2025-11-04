use crate::api::trino::schemas::column_mask::{
    TrinoColumnMaskColumn, TrinoColumnMaskQuery, TrinoColumnMaskResponse, ViewExpression,
};
use crate::headers::ClientCacheControl;
use crate::opa_client::allowed::{AllowedQuery, Resource, User};
use crate::opa_client::cached::query_allowed_bulk_cached;
use crate::opa_client::{OpaRequest, OpaResponse};
use crate::openapi::TRINO_TAG;
use crate::state::AppState;
use axum::{
    extract::{Json, State},
    response::{IntoResponse, Response},
};
use http::header::CACHE_CONTROL;
use http::{HeaderMap, StatusCode};
use std::collections::HashMap;

#[utoipa::path(
    post,
    path = "/trino/batch-column-masking",
    tag = TRINO_TAG,
    request_body = OpaRequest<TrinoColumnMaskQuery>,
    responses(
        (status = 200, description = "Trino column mask check completed successfully", body = OpaResponse<Vec<TrinoColumnMaskResponse>>),
        (status = 422, description = "Invalid request payload"),
        (status = 500, description = "Internal server error")
    )
)]
pub(super) async fn column_mask_handler(
    state: State<AppState>,
    headers: HeaderMap,
    Json(request): Json<OpaRequest<TrinoColumnMaskQuery>>,
) -> Response {
    let query = request.input;
    let cache_control = ClientCacheControl::from_header_value(headers.get(CACHE_CONTROL));

    // Log the request for debugging
    log::info!(
        "Trino column mask request: user={}, {} column(s)",
        query.context.identity.user,
        query.action.filter_resources.len(),
    );

    // Get column mask expressions based on user permissions
    let masks = get_column_mask_expressions(&state, &query, &cache_control).await;

    let response = OpaResponse { result: masks };
    (StatusCode::OK, Json(response)).into_response()
}

/// Get the column mask expressions for a given query
async fn get_column_mask_expressions(
    state: &AppState,
    query: &TrinoColumnMaskQuery,
    cache_control: &ClientCacheControl,
) -> Vec<TrinoColumnMaskResponse> {
    // Check if we have a config loaded
    let config = match &state.trino_authz_config {
        Some(config) => config,
        None => {
            log::info!("No Trino authz config loaded, returning empty mask list");
            return vec![];
        }
    };

    // Extract columns from filter_resources
    let column_requests: Vec<(usize, &TrinoColumnMaskColumn)> = query
        .action
        .filter_resources
        .iter()
        .enumerate()
        .map(|(index, resource)| (index, &resource.column))
        .collect();

    if column_requests.is_empty() {
        log::info!("No column resources in request");
        return vec![];
    }

    // Group columns by table to optimize config lookups
    let mut table_groups: HashMap<String, Vec<(usize, &str)>> = HashMap::new();
    for (index, column) in &column_requests {
        let table_resource_name = format!(
            "trino_table_{catalog_name}_{schema_name}_{table_name}",
            catalog_name = column.catalog_name,
            schema_name = column.schema_name,
            table_name = column.table_name,
        );
        table_groups
            .entry(table_resource_name)
            .or_default()
            .push((*index, &column.column_name));
    }

    // Process each table group
    let mut all_queries = Vec::new();
    let mut query_metadata = Vec::new();

    for (table_resource_name, columns) in &table_groups {
        // Get masks for this table
        let mask_config = match config.get_column_masks(table_resource_name) {
            Some(config) => config,
            None => {
                log::debug!(
                    "No column masks configured for table: {} (user: {})",
                    table_resource_name,
                    query.context.identity.user
                );
                continue;
            }
        };

        // For each requested column, check if it has a mask configured
        for (request_index, column_name) in columns {
            if let Some(column_config) = mask_config
                .columns
                .iter()
                .find(|c| c.column_name == *column_name)
            {
                // Get the action to use (column-specific or table-level default)
                let action = column_config.action.as_ref().unwrap_or(&mask_config.action);

                // Create TWO queries: one for table-level, one for column-level
                // Table-level permission check
                let table_query = build_column_mask_query(query, table_resource_name, action);
                all_queries.push(table_query);

                // Column-level permission check
                let column_resource_name = format!(
                    "trino_column_{catalog_name}_{schema_name}_{table_name}_{column_name}",
                    catalog_name = column_requests[*request_index].1.catalog_name,
                    schema_name = column_requests[*request_index].1.schema_name,
                    table_name = column_requests[*request_index].1.table_name,
                    column_name = column_name,
                );

                let column_query = build_column_mask_query(query, &column_resource_name, action);
                all_queries.push(column_query);

                // Store metadata for later
                query_metadata.push((
                    *request_index,
                    column_config.view_expression.clone(),
                    column_config.identity.clone(),
                ));
            }
        }
    }

    if all_queries.is_empty() {
        log::info!(
            "No configured column masks match requested columns for user: {}",
            query.context.identity.user
        );
        return vec![];
    }

    // Check permissions for all queries in bulk
    let allowed_results = match query_allowed_bulk_cached(state, &all_queries, cache_control).await
    {
        Ok(results) => results,
        Err(e) => {
            log::error!(
                "Error checking column mask permissions for user {}: {}",
                query.context.identity.user,
                e
            );
            return vec![];
        }
    };

    // Build response: include mask if EITHER table-level OR column-level permission is granted
    let mut masks = Vec::new();
    for (i, (request_index, view_expression, identity)) in query_metadata.iter().enumerate() {
        let table_check_idx = i * 2;
        let column_check_idx = i * 2 + 1;

        let table_allowed = allowed_results
            .allow
            .get(table_check_idx)
            .map(|r| r.allow)
            .unwrap_or(false);
        let column_allowed = allowed_results
            .allow
            .get(column_check_idx)
            .map(|r| r.allow)
            .unwrap_or(false);

        if table_allowed || column_allowed {
            masks.push(TrinoColumnMaskResponse {
                index: *request_index,
                view_expression: ViewExpression {
                    expression: view_expression.clone(),
                    identity: identity.clone(),
                },
            });
        }
    }

    log::info!(
        "Returning {} column mask(s) for user {} out of {} requested columns",
        masks.len(),
        query.context.identity.user,
        column_requests.len()
    );

    masks
}

/// Build an AllowedQuery for column mask permission checks
fn build_column_mask_query(
    query: &TrinoColumnMaskQuery,
    resource_name: &str,
    action: &str,
) -> AllowedQuery {
    AllowedQuery {
        user: User {
            key: query.context.identity.user.clone(),
            first_name: None,
            last_name: None,
            email: None,
            attributes: HashMap::new(),
        },
        action: action.to_string(),
        resource: Resource {
            r#type: resource_name.to_string(),
            key: None,
            tenant: Some("default".to_string()),
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
    use crate::config::trino_authz::{ColumnConfig, ColumnMaskConfig, TrinoAuthzConfig};
    use crate::test_utils::TestFixture;
    use http::{Method, StatusCode};
    use serde_json::json;
    use std::collections::HashMap;

    fn create_test_trino_authz_config() -> TrinoAuthzConfig {
        let mut column_masks = HashMap::new();

        // Users table with multiple columns
        column_masks.insert(
            "trino_table_postgres_demo_users".to_string(),
            ColumnMaskConfig {
                action: "AddColumnMask".to_string(),
                columns: vec![
                    ColumnConfig {
                        column_name: "ssn".to_string(),
                        view_expression: "'***-**-****'".to_string(),
                        identity: None,
                        action: None,
                    },
                    ColumnConfig {
                        column_name: "email".to_string(),
                        view_expression: "CONCAT(SUBSTRING(email, 1, 2), '***@***.com')"
                            .to_string(),
                        identity: Some("admin".to_string()),
                        action: None,
                    },
                    ColumnConfig {
                        column_name: "phone".to_string(),
                        view_expression: "'XXX-XXX-XXXX'".to_string(),
                        identity: None,
                        action: Some("ViewPhone".to_string()),
                    },
                ],
            },
        );

        // Projects table with custom action
        column_masks.insert(
            "trino_table_postgres_demo_projects".to_string(),
            ColumnMaskConfig {
                action: "ViewSensitiveData".to_string(),
                columns: vec![ColumnConfig {
                    column_name: "budget".to_string(),
                    view_expression: "NULL".to_string(),
                    identity: None,
                    action: None,
                }],
            },
        );

        TrinoAuthzConfig {
            row_filters: HashMap::new(),
            column_masks,
        }
    }

    #[tokio::test]
    async fn test_trino_column_mask_no_config() {
        // Test when no config is loaded
        let fixture = TestFixture::new().await;

        let test_request = json!({
            "input": {
                "context": {
                    "identity": {
                        "user": "charlie",
                        "groups": []
                    },
                    "softwareStack": {
                        "trinoVersion": "476"
                    }
                },
                "action": {
                    "operation": "GetColumnMask",
                    "filterResources": [
                        {
                            "column": {
                                "catalogName": "postgres",
                                "schemaName": "demo",
                                "tableName": "users",
                                "columnName": "ssn",
                                "columnType": "VARCHAR"
                            }
                        }
                    ]
                }
            }
        });

        let response = fixture
            .post("/trino/batch-column-masking", &test_request)
            .await;

        response.assert_ok();
        let result: OpaResponse<Vec<TrinoColumnMaskResponse>> = response.json_as();
        assert_eq!(result.result.len(), 0);
    }

    #[tokio::test]
    async fn test_trino_column_mask_no_masks_for_table() {
        // Test when config is loaded but no masks for this specific table
        let fixture = TestFixture::new()
            .await
            .with_trino_authz_config(create_test_trino_authz_config())
            .await;

        let test_request = json!({
            "input": {
                "context": {
                    "identity": {
                        "user": "alice",
                        "groups": ["engineers"]
                    },
                    "softwareStack": {
                        "trinoVersion": "476"
                    }
                },
                "action": {
                    "operation": "GetColumnMask",
                    "filterResources": [
                        {
                            "column": {
                                "catalogName": "postgres",
                                "schemaName": "demo",
                                "tableName": "nonexistent_table",
                                "columnName": "some_column",
                                "columnType": "VARCHAR"
                            }
                        }
                    ]
                }
            }
        });

        let response = fixture
            .post("/trino/batch-column-masking", &test_request)
            .await;

        response.assert_ok();
        let result: OpaResponse<Vec<TrinoColumnMaskResponse>> = response.json_as();
        assert_eq!(result.result.len(), 0);
    }

    #[tokio::test]
    async fn test_trino_column_mask_user_has_all_permissions() {
        // Test when user has permissions for all masks
        let fixture = TestFixture::new()
            .await
            .with_trino_authz_config(create_test_trino_authz_config())
            .await;

        // Setup mock OPA response - user has permissions for all masks (table and column checks)
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/bulk",
                json!({
                    "result": {
                        "allow": [
                            {"allow": true, "result": true},  // ssn table-level
                            {"allow": true, "result": true},  // ssn column-level
                            {"allow": true, "result": true},  // email table-level
                            {"allow": true, "result": true},  // email column-level
                        ]
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        let test_request = json!({
            "input": {
                "context": {
                    "identity": {
                        "user": "admin",
                        "groups": ["admins"]
                    },
                    "softwareStack": {
                        "trinoVersion": "476"
                    }
                },
                "action": {
                    "operation": "GetColumnMask",
                    "filterResources": [
                        {
                            "column": {
                                "catalogName": "postgres",
                                "schemaName": "demo",
                                "tableName": "users",
                                "columnName": "ssn",
                                "columnType": "VARCHAR"
                            }
                        },
                        {
                            "column": {
                                "catalogName": "postgres",
                                "schemaName": "demo",
                                "tableName": "users",
                                "columnName": "email",
                                "columnType": "VARCHAR"
                            }
                        }
                    ]
                }
            }
        });

        let response = fixture
            .post("/trino/batch-column-masking", &test_request)
            .await;

        response.assert_ok();
        let result: OpaResponse<Vec<TrinoColumnMaskResponse>> = response.json_as();
        assert_eq!(result.result.len(), 2);
        assert_eq!(result.result[0].index, 0);
        assert_eq!(result.result[0].view_expression.expression, "'***-**-****'");
        assert!(result.result[0].view_expression.identity.is_none());
        assert_eq!(result.result[1].index, 1);
        assert_eq!(
            result.result[1].view_expression.expression,
            "CONCAT(SUBSTRING(email, 1, 2), '***@***.com')"
        );
        assert_eq!(
            result.result[1].view_expression.identity,
            Some("admin".to_string())
        );

        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_trino_column_mask_user_has_partial_permissions() {
        // Test when user has permissions for only some masks
        let fixture = TestFixture::new()
            .await
            .with_trino_authz_config(create_test_trino_authz_config())
            .await;

        // Setup mock OPA response - user has permission for first mask only
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/bulk",
                json!({
                    "result": {
                        "allow": [
                            {"allow": true, "result": true},   // ssn table-level
                            {"allow": false, "result": false}, // ssn column-level
                            {"allow": false, "result": false}, // email table-level
                            {"allow": false, "result": false}, // email column-level
                        ]
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        let test_request = json!({
            "input": {
                "context": {
                    "identity": {
                        "user": "user1",
                        "groups": ["users"]
                    },
                    "softwareStack": {
                        "trinoVersion": "476"
                    }
                },
                "action": {
                    "operation": "GetColumnMask",
                    "filterResources": [
                        {
                            "column": {
                                "catalogName": "postgres",
                                "schemaName": "demo",
                                "tableName": "users",
                                "columnName": "ssn",
                                "columnType": "VARCHAR"
                            }
                        },
                        {
                            "column": {
                                "catalogName": "postgres",
                                "schemaName": "demo",
                                "tableName": "users",
                                "columnName": "email",
                                "columnType": "VARCHAR"
                            }
                        }
                    ]
                }
            }
        });

        let response = fixture
            .post("/trino/batch-column-masking", &test_request)
            .await;

        response.assert_ok();
        let result: OpaResponse<Vec<TrinoColumnMaskResponse>> = response.json_as();
        assert_eq!(result.result.len(), 1);
        assert_eq!(result.result[0].index, 0);
        assert_eq!(result.result[0].view_expression.expression, "'***-**-****'");

        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_trino_column_mask_user_has_no_permissions() {
        // Test when user has no permissions for any masks
        let fixture = TestFixture::new()
            .await
            .with_trino_authz_config(create_test_trino_authz_config())
            .await;

        // Setup mock OPA response - user has no permissions
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/bulk",
                json!({
                    "result": {
                        "allow": [
                            {"allow": false, "result": false}, // ssn table-level
                            {"allow": false, "result": false}, // ssn column-level
                        ]
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        let test_request = json!({
            "input": {
                "context": {
                    "identity": {
                        "user": "restricted_user",
                        "groups": ["restricted"]
                    },
                    "softwareStack": {
                        "trinoVersion": "476"
                    }
                },
                "action": {
                    "operation": "GetColumnMask",
                    "filterResources": [
                        {
                            "column": {
                                "catalogName": "postgres",
                                "schemaName": "demo",
                                "tableName": "users",
                                "columnName": "ssn",
                                "columnType": "VARCHAR"
                            }
                        }
                    ]
                }
            }
        });

        let response = fixture
            .post("/trino/batch-column-masking", &test_request)
            .await;

        response.assert_ok();
        let result: OpaResponse<Vec<TrinoColumnMaskResponse>> = response.json_as();
        assert_eq!(result.result.len(), 0);

        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_trino_column_mask_table_level_permission() {
        // Test when user has table-level permission grants access to all column masks
        let fixture = TestFixture::new()
            .await
            .with_trino_authz_config(create_test_trino_authz_config())
            .await;

        // Setup mock OPA response - user has table-level permission only
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/bulk",
                json!({
                    "result": {
                        "allow": [
                            {"allow": true, "result": true},   // ssn table-level
                            {"allow": false, "result": false}, // ssn column-level
                        ]
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        let test_request = json!({
            "input": {
                "context": {
                    "identity": {
                        "user": "table_user",
                        "groups": ["table_users"]
                    },
                    "softwareStack": {
                        "trinoVersion": "476"
                    }
                },
                "action": {
                    "operation": "GetColumnMask",
                    "filterResources": [
                        {
                            "column": {
                                "catalogName": "postgres",
                                "schemaName": "demo",
                                "tableName": "users",
                                "columnName": "ssn",
                                "columnType": "VARCHAR"
                            }
                        }
                    ]
                }
            }
        });

        let response = fixture
            .post("/trino/batch-column-masking", &test_request)
            .await;

        response.assert_ok();
        let result: OpaResponse<Vec<TrinoColumnMaskResponse>> = response.json_as();
        assert_eq!(result.result.len(), 1);
        assert_eq!(result.result[0].index, 0);

        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_trino_column_mask_column_level_permission() {
        // Test when user has column-level permission grants access to specific mask
        let fixture = TestFixture::new()
            .await
            .with_trino_authz_config(create_test_trino_authz_config())
            .await;

        // Setup mock OPA response - user has column-level permission only
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/bulk",
                json!({
                    "result": {
                        "allow": [
                            {"allow": false, "result": false}, // ssn table-level
                            {"allow": true, "result": true},   // ssn column-level
                        ]
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        let test_request = json!({
            "input": {
                "context": {
                    "identity": {
                        "user": "column_user",
                        "groups": ["column_users"]
                    },
                    "softwareStack": {
                        "trinoVersion": "476"
                    }
                },
                "action": {
                    "operation": "GetColumnMask",
                    "filterResources": [
                        {
                            "column": {
                                "catalogName": "postgres",
                                "schemaName": "demo",
                                "tableName": "users",
                                "columnName": "ssn",
                                "columnType": "VARCHAR"
                            }
                        }
                    ]
                }
            }
        });

        let response = fixture
            .post("/trino/batch-column-masking", &test_request)
            .await;

        response.assert_ok();
        let result: OpaResponse<Vec<TrinoColumnMaskResponse>> = response.json_as();
        assert_eq!(result.result.len(), 1);
        assert_eq!(result.result[0].index, 0);

        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_trino_column_mask_custom_action() {
        // Test column with custom action override
        let fixture = TestFixture::new()
            .await
            .with_trino_authz_config(create_test_trino_authz_config())
            .await;

        // Setup mock OPA response
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/bulk",
                json!({
                    "result": {
                        "allow": [
                            {"allow": true, "result": true},  // phone table-level (ViewPhone action)
                            {"allow": true, "result": true},  // phone column-level
                        ]
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        let test_request = json!({
            "input": {
                "context": {
                    "identity": {
                        "user": "phone_user",
                        "groups": ["phone_users"]
                    },
                    "softwareStack": {
                        "trinoVersion": "476"
                    }
                },
                "action": {
                    "operation": "GetColumnMask",
                    "filterResources": [
                        {
                            "column": {
                                "catalogName": "postgres",
                                "schemaName": "demo",
                                "tableName": "users",
                                "columnName": "phone",
                                "columnType": "VARCHAR"
                            }
                        }
                    ]
                }
            }
        });

        let response = fixture
            .post("/trino/batch-column-masking", &test_request)
            .await;

        response.assert_ok();
        let result: OpaResponse<Vec<TrinoColumnMaskResponse>> = response.json_as();
        assert_eq!(result.result.len(), 1);
        assert_eq!(result.result[0].index, 0);
        assert_eq!(
            result.result[0].view_expression.expression,
            "'XXX-XXX-XXXX'"
        );

        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_trino_column_mask_opa_error() {
        // Test when OPA returns an error
        let fixture = TestFixture::new()
            .await
            .with_trino_authz_config(create_test_trino_authz_config())
            .await;

        // Setup mock OPA response that returns an error
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/bulk",
                json!({
                    "error": "Internal server error"
                }),
                StatusCode::INTERNAL_SERVER_ERROR,
                1,
            )
            .await;

        let test_request = json!({
            "input": {
                "context": {
                    "identity": {
                        "user": "user1",
                        "groups": ["users"]
                    },
                    "softwareStack": {
                        "trinoVersion": "476"
                    }
                },
                "action": {
                    "operation": "GetColumnMask",
                    "filterResources": [
                        {
                            "column": {
                                "catalogName": "postgres",
                                "schemaName": "demo",
                                "tableName": "users",
                                "columnName": "ssn",
                                "columnType": "VARCHAR"
                            }
                        }
                    ]
                }
            }
        });

        let response = fixture
            .post("/trino/batch-column-masking", &test_request)
            .await;

        // Should return empty list on OPA error
        response.assert_ok();
        let result: OpaResponse<Vec<TrinoColumnMaskResponse>> = response.json_as();
        assert_eq!(result.result.len(), 0);

        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_trino_column_mask_invalid_request() {
        let fixture = TestFixture::new().await;

        let invalid_request = json!({
            "input": {
                "context": {
                    "identity": {
                        "user": "foo"
                        // Missing groups
                    }
                    // Missing softwareStack
                }
                // Missing action
            }
        });

        let response = fixture
            .post("/trino/batch-column-masking", &invalid_request)
            .await;

        response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_trino_column_mask_with_cache_headers() {
        let fixture = TestFixture::new()
            .await
            .with_trino_authz_config(create_test_trino_authz_config())
            .await;

        // Setup mock OPA response
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/bulk",
                json!({
                    "result": {
                        "allow": [
                            {"allow": true, "result": true},  // ssn table-level
                            {"allow": true, "result": true},  // ssn column-level
                        ]
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        let test_request = json!({
            "input": {
                "context": {
                    "identity": {
                        "user": "charlie",
                        "groups": []
                    },
                    "softwareStack": {
                        "trinoVersion": "476"
                    }
                },
                "action": {
                    "operation": "GetColumnMask",
                    "filterResources": [
                        {
                            "column": {
                                "catalogName": "postgres",
                                "schemaName": "demo",
                                "tableName": "users",
                                "columnName": "ssn",
                                "columnType": "VARCHAR"
                            }
                        }
                    ]
                }
            }
        });

        let custom_headers = &[
            ("Cache-Control", "max-age=300"),
            ("Authorization", "Bearer test-token"),
        ];

        let response = fixture
            .post_with_headers("/trino/batch-column-masking", &test_request, custom_headers)
            .await;

        response.assert_ok();
        let result: OpaResponse<Vec<TrinoColumnMaskResponse>> = response.json_as();
        assert_eq!(result.result.len(), 1);

        fixture.opa_mock.verify().await;
    }
}
