use crate::api::trino::schemas::resource::TrinoResource;
use crate::api::trino::schemas::row_filter::{TrinoRowFilterQuery, TrinoRowFilterResponse};
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
    path = "/trino/row-filter",
    tag = TRINO_TAG,
    request_body = OpaRequest<TrinoRowFilterQuery>,
    responses(
        (status = 200, description = "Trino row filter check completed successfully", body = OpaResponse<Vec<TrinoRowFilterResponse>>),
        (status = 422, description = "Invalid request payload"),
        (status = 500, description = "Internal server error")
    )
)]
pub(super) async fn row_filter_handler(
    state: State<AppState>,
    headers: HeaderMap,
    Json(request): Json<OpaRequest<TrinoRowFilterQuery>>,
) -> Response {
    let query = request.input;
    let cache_control = ClientCacheControl::from_header_value(headers.get(CACHE_CONTROL));

    // Log the request for debugging
    log::info!(
        "Trino row filter request: user={}, {}",
        query.context.identity.user,
        query.action.resource.to_debug_string(),
    );

    // Get row filter expressions based on user permissions
    let expressions = get_row_filter_expressions(&state, &query, &cache_control).await;

    let response = OpaResponse {
        result: expressions,
    };
    (StatusCode::OK, Json(response)).into_response()
}

/// Get the row filter expressions for a given query
async fn get_row_filter_expressions(
    state: &AppState,
    query: &TrinoRowFilterQuery,
    cache_control: &ClientCacheControl,
) -> Vec<TrinoRowFilterResponse> {
    // Extract table from resource, return empty if not a table resource
    let table = match &query.action.resource {
        TrinoResource::Table { table } => table,
        _ => {
            log::warn!(
                "Row filter request for non-table resource: {}",
                query.action.resource.to_debug_string()
            );
            return vec![];
        }
    };

    // Build resource name using same format as checks.rs
    let resource_name = format!(
        "trino_table_{catalog_name}_{schema_name}_{table_name}",
        catalog_name = table.catalog_name,
        schema_name = table.schema_name,
        table_name = table.table_name,
    );

    // Check if we have a config loaded
    let config = match &state.trino_authz_config {
        Some(config) => config,
        None => {
            log::info!("No Trino authz config loaded, returning empty filter list");
            return vec![];
        }
    };

    // Get filters for this resource
    let filters = match config.get_filters(&resource_name) {
        Some(filters) => filters,
        None => {
            log::info!(
                "No row filters configured for resource: {} (user: {})",
                resource_name,
                query.context.identity.user
            );
            return vec![];
        }
    };

    if filters.is_empty() {
        log::info!(
            "Empty filter list for resource: {} (user: {})",
            resource_name,
            query.context.identity.user
        );
        return vec![];
    }

    // Build permission check queries for all filter actions
    let action_names: Vec<String> = filters.iter().map(|f| f.action.clone()).collect();
    log::debug!(
        "Checking for row filters of table {} for user {} with actions {:?}",
        resource_name,
        query.context.identity.user,
        action_names,
    );

    let queries: Vec<AllowedQuery> = filters
        .iter()
        .map(|filter| build_row_filter_query(query, &resource_name, &filter.action))
        .collect();

    // Check permissions for all filters in bulk
    let allowed_results = match query_allowed_bulk_cached(state, &queries, cache_control).await {
        Ok(results) => results,
        Err(e) => {
            log::error!(
                "Error checking row filter permissions for user {}: {}",
                query.context.identity.user,
                e
            );
            return vec![];
        }
    };

    // Collect expressions for allowed filters
    let mut expressions = Vec::new();
    for (i, filter) in filters.iter().enumerate() {
        if let Some(result) = allowed_results.allow.get(i) {
            if result.allow {
                expressions.push(TrinoRowFilterResponse {
                    expression: filter.expression.clone(),
                });
            }
        }
    }

    log::info!(
        "Adding {} row filter expression(s) on table {} for user {}: {}",
        expressions.len(),
        resource_name,
        query.context.identity.user,
        expressions
            .iter()
            .map(|e| e.expression.clone())
            .collect::<Vec<String>>()
            .join(" AND ")
    );

    expressions
}

/// Build an AllowedQuery for row filter permission checks
fn build_row_filter_query(
    query: &TrinoRowFilterQuery,
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
    use crate::config::trino_authz::{RowFilterConfig, TrinoAuthzConfig};
    use crate::test_utils::TestFixture;
    use http::{Method, StatusCode};
    use serde_json::json;
    use std::collections::HashMap;

    fn create_test_trino_authz_config() -> TrinoAuthzConfig {
        let mut row_filters = HashMap::new();
        row_filters.insert(
            "trino_table_postgres_demo_users".to_string(),
            vec![
                RowFilterConfig {
                    action: "view_active".to_string(),
                    expression: "status = 'active'".to_string(),
                },
                RowFilterConfig {
                    action: "view_public".to_string(),
                    expression: "is_public = TRUE".to_string(),
                },
            ],
        );
        row_filters.insert(
            "trino_table_postgres_demo_projects".to_string(),
            vec![RowFilterConfig {
                action: "only_small".to_string(),
                expression: "size = 'small'".to_string(),
            }],
        );
        TrinoAuthzConfig { row_filters }
    }

    #[tokio::test]
    async fn test_trino_row_filter_no_config() {
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
                    "operation": "GetRowFilters",
                    "resource": {
                        "table": {
                            "catalogName": "postgres",
                            "schemaName": "demo",
                            "tableName": "users"
                        }
                    }
                }
            }
        });

        let response = fixture.post("/trino/row-filter", &test_request).await;

        response.assert_ok();
        let result: OpaResponse<Vec<TrinoRowFilterResponse>> = response.json_as();
        assert_eq!(result.result.len(), 0);
    }

    #[tokio::test]
    async fn test_trino_row_filter_no_filters_for_table() {
        // Test when config is loaded but no filters for this specific table
        let fixture = TestFixture::new()
            .await
            .with_trino_authz_config(create_test_trino_authz_config())
            .await;

        let test_request = json!({
            "input": {
                "context": {
                    "identity": {
                        "user": "alice",
                        "groups": ["engineers", "analysts"]
                    },
                    "softwareStack": {
                        "trinoVersion": "476"
                    }
                },
                "action": {
                    "operation": "GetRowFilters",
                    "resource": {
                        "table": {
                            "catalogName": "postgres",
                            "schemaName": "demo",
                            "tableName": "nonexistent_table"
                        }
                    }
                }
            }
        });

        let response = fixture.post("/trino/row-filter", &test_request).await;

        response.assert_ok();
        let result: OpaResponse<Vec<TrinoRowFilterResponse>> = response.json_as();
        assert_eq!(result.result.len(), 0);
    }

    #[tokio::test]
    async fn test_trino_row_filter_user_has_all_permissions() {
        // Test when user has permissions for all filters
        let fixture = TestFixture::new()
            .await
            .with_trino_authz_config(create_test_trino_authz_config())
            .await;

        // Setup mock OPA response - user has permissions for both filters
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/bulk",
                json!({
                    "result": {
                        "allow": [
                            {"allow": true, "result": true},
                            {"allow": true, "result": true}
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
                    "operation": "GetRowFilters",
                    "resource": {
                        "table": {
                            "catalogName": "postgres",
                            "schemaName": "demo",
                            "tableName": "users"
                        }
                    }
                }
            }
        });

        let response = fixture.post("/trino/row-filter", &test_request).await;

        response.assert_ok();
        let result: OpaResponse<Vec<TrinoRowFilterResponse>> = response.json_as();
        assert_eq!(result.result.len(), 2);
        assert_eq!(result.result[0].expression, "status = 'active'");
        assert_eq!(result.result[1].expression, "is_public = TRUE");

        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_trino_row_filter_user_has_partial_permissions() {
        // Test when user has permissions for only some filters
        let fixture = TestFixture::new()
            .await
            .with_trino_authz_config(create_test_trino_authz_config())
            .await;

        // Setup mock OPA response - user has permission for first filter only
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/bulk",
                json!({
                    "result": {
                        "allow": [
                            {"allow": true, "result": true},
                            {"allow": false, "result": false}
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
                    "operation": "GetRowFilters",
                    "resource": {
                        "table": {
                            "catalogName": "postgres",
                            "schemaName": "demo",
                            "tableName": "users"
                        }
                    }
                }
            }
        });

        let response = fixture.post("/trino/row-filter", &test_request).await;

        response.assert_ok();
        let result: OpaResponse<Vec<TrinoRowFilterResponse>> = response.json_as();
        assert_eq!(result.result.len(), 1);
        assert_eq!(result.result[0].expression, "status = 'active'");

        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_trino_row_filter_user_has_no_permissions() {
        // Test when user has no permissions for any filters
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
                            {"allow": false, "result": false},
                            {"allow": false, "result": false}
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
                    "operation": "GetRowFilters",
                    "resource": {
                        "table": {
                            "catalogName": "postgres",
                            "schemaName": "demo",
                            "tableName": "users"
                        }
                    }
                }
            }
        });

        let response = fixture.post("/trino/row-filter", &test_request).await;

        response.assert_ok();
        let result: OpaResponse<Vec<TrinoRowFilterResponse>> = response.json_as();
        assert_eq!(result.result.len(), 0);

        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_trino_row_filter_single_filter() {
        // Test with a table that has only one filter
        let fixture = TestFixture::new()
            .await
            .with_trino_authz_config(create_test_trino_authz_config())
            .await;

        // Setup mock OPA response - user has permission for the single filter
        fixture
            .add_opa_mock(
                Method::POST,
                "/v1/data/permit/bulk",
                json!({
                    "result": {
                        "allow": [
                            {"allow": true, "result": true}
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
                        "user": "project_user",
                        "groups": ["users"]
                    },
                    "softwareStack": {
                        "trinoVersion": "476"
                    }
                },
                "action": {
                    "operation": "GetRowFilters",
                    "resource": {
                        "table": {
                            "catalogName": "postgres",
                            "schemaName": "demo",
                            "tableName": "projects"
                        }
                    }
                }
            }
        });

        let response = fixture.post("/trino/row-filter", &test_request).await;

        response.assert_ok();
        let result: OpaResponse<Vec<TrinoRowFilterResponse>> = response.json_as();
        assert_eq!(result.result.len(), 1);
        assert_eq!(result.result[0].expression, "size = 'small'");

        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_trino_row_filter_opa_error() {
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
                    "operation": "GetRowFilters",
                    "resource": {
                        "table": {
                            "catalogName": "postgres",
                            "schemaName": "demo",
                            "tableName": "users"
                        }
                    }
                }
            }
        });

        let response = fixture.post("/trino/row-filter", &test_request).await;

        // Should return empty list on OPA error
        response.assert_ok();
        let result: OpaResponse<Vec<TrinoRowFilterResponse>> = response.json_as();
        assert_eq!(result.result.len(), 0);

        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_trino_row_filter_invalid_request() {
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

        let response = fixture.post("/trino/row-filter", &invalid_request).await;

        response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_trino_row_filter_with_cache_headers() {
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
                            {"allow": true, "result": true},
                            {"allow": true, "result": true}
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
                    "operation": "GetRowFilters",
                    "resource": {
                        "table": {
                            "catalogName": "postgres",
                            "schemaName": "demo",
                            "tableName": "users"
                        }
                    }
                }
            }
        });

        let custom_headers = &[
            ("Cache-Control", "max-age=300"),
            ("Authorization", "Bearer test-token"),
        ];

        let response = fixture
            .post_with_headers("/trino/row-filter", &test_request, custom_headers)
            .await;

        response.assert_ok();
        let result: OpaResponse<Vec<TrinoRowFilterResponse>> = response.json_as();
        assert_eq!(result.result.len(), 2);

        fixture.opa_mock.verify().await;
    }
}
