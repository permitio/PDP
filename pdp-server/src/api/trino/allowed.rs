use crate::api::trino::checks;
use crate::api::trino::schemas::core::TrinoAuthzQuery;
use crate::headers::ClientCacheControl;
use crate::opa_client::{OpaRequest, OpaResponse};
use crate::openapi::TRINO_TAG;
use crate::state::AppState;
use axum::{
    extract::{Json, State},
    response::{IntoResponse, Response},
};
use http::header::CACHE_CONTROL;
use http::{HeaderMap, StatusCode};

#[utoipa::path(
    post,
    path = "/trino/allowed",
    tag = TRINO_TAG,
    request_body = OpaRequest<TrinoAuthzQuery>,
    responses(
        (status = 200, description = "Trino access check completed successfully", body = OpaResponse<bool>),
        (status = 422, description = "Invalid request payload"),
        (status = 500, description = "Internal server error")
    )
)]
pub(super) async fn allowed_handler(
    state: State<AppState>,
    headers: HeaderMap,
    Json(request): Json<OpaRequest<TrinoAuthzQuery>>,
) -> Response {
    let cache_control = ClientCacheControl::from_header_value(headers.get(CACHE_CONTROL));
    let query = request.input;
    // Log the request for debugging
    if let Some(resource) = &query.action.resource {
        log::info!(
            "Trino allowed request: user={}, operation={:?}, {}",
            query.context.identity.user,
            query.action.operation,
            resource.to_debug_string(),
        );
    } else {
        log::info!(
            "Trino allowed request: user={}, operation={:?}",
            query.context.identity.user,
            query.action.operation
        );
    }

    let allowed = checks::check_trino_allowed(&state, &query, &cache_control).await;
    let response = OpaResponse { result: allowed };
    (StatusCode::OK, Json(response)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestFixture;
    use http::{Method, StatusCode};
    use serde_json::json;

    #[tokio::test]
    async fn test_trino_allowed_table_success() {
        // Setup test fixture
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

        // Create test request for table access
        let test_request = json!({
            "input": {
                "context": {
                    "identity": {
                        "user": "test-user",
                        "groups": ["analysts", "readers"]
                    },
                    "softwareStack": {
                        "trinoVersion": "434"
                    }
                },
                "action": {
                    "operation": "SelectFromColumns",
                    "resource": {
                        "table": {
                            "catalogName": "example_catalog",
                            "schemaName": "example_schema",
                            "tableName": "example_table",
                            "columns": [
                                "column1",
                                "column2",
                                "column3"
                            ]
                        }
                    }
                }
            }
        });

        // Send request to the API
        let response = fixture.post("/trino/allowed", &test_request).await;

        // Verify response status and body
        response.assert_ok();
        let result: OpaResponse<bool> = response.json_as();
        assert!(result.result);

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_trino_allowed_table_denied() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Setup mock OPA response for denied table access
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

        // Create test request for table access
        let test_request = json!({
            "input": {
                "context": {
                    "identity": {
                        "user": "restricted-user",
                        "groups": ["readers"]
                    },
                    "softwareStack": {
                        "trinoVersion": "434"
                    }
                },
                "action": {
                    "operation": "SelectFromColumns",
                    "resource": {
                        "table": {
                            "catalogName": "restricted_catalog",
                            "schemaName": "restricted_schema",
                            "tableName": "restricted_table",
                            "columns": ["sensitive_column"]
                        }
                    }
                }
            }
        });

        // Send request to the API
        let response = fixture.post("/trino/allowed", &test_request).await;

        // Verify response status and body
        response.assert_ok();
        let result: OpaResponse<bool> = response.json_as();
        assert!(!result.result);

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_trino_allowed_schema_success() {
        // Setup test fixture
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

        // Create test request for schema access
        let test_request = json!({
            "input": {
                "context": {
                    "identity": {
                        "user": "admin-user",
                        "groups": ["admins", "developers"]
                    },
                    "softwareStack": {
                        "trinoVersion": "435"
                    }
                },
                "action": {
                    "operation": "CreateSchema",
                    "resource": {
                        "schema": {
                            "catalogName": "test_catalog",
                            "schemaName": "new_schema"
                        }
                    }
                }
            }
        });

        // Send request to the API
        let response = fixture.post("/trino/allowed", &test_request).await;

        // Verify response status and body
        response.assert_ok();
        let result: OpaResponse<bool> = response.json_as();
        assert!(result.result);

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_trino_allowed_catalog_success() {
        // Setup test fixture
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

        // Create test request for catalog access
        let test_request = json!({
            "input": {
                "context": {
                    "identity": {
                        "user": "admin-user",
                        "groups": ["admins"]
                    },
                    "softwareStack": {
                        "trinoVersion": "435"
                    }
                },
                "action": {
                    "operation": "AccessCatalog",
                    "resource": {
                        "catalog": {
                            "name": "test_catalog"
                        }
                    }
                }
            }
        });

        // Send request to the API
        let response = fixture.post("/trino/allowed", &test_request).await;

        // Verify response status and body
        response.assert_ok();
        let result: OpaResponse<bool> = response.json_as();
        assert!(result.result);

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_trino_allowed_function_success() {
        // Setup test fixture
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

        // Create test request for function access
        let test_request = json!({
            "input": {
                "context": {
                    "identity": {
                        "user": "developer",
                        "groups": ["developers"]
                    },
                    "softwareStack": {
                        "trinoVersion": "435"
                    }
                },
                "action": {
                    "operation": "ExecuteFunction",
                    "resource": {
                        "function": {
                            "schema": {
                                "catalogName": "test_catalog",
                                "schemaName": "functions"
                            },
                            "functionName": "custom_function"
                        }
                    }
                }
            }
        });

        // Send request to the API
        let response = fixture.post("/trino/allowed", &test_request).await;

        // Verify response status and body
        response.assert_ok();
        let result: OpaResponse<bool> = response.json_as();
        assert!(result.result);

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_trino_allowed_system_operation() {
        // Setup test fixture
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

        // Create test request for system operation (no resource)
        let test_request = json!({
            "input": {
                "context": {
                    "identity": {
                        "user": "admin",
                        "groups": ["admins"]
                    },
                    "softwareStack": {
                        "trinoVersion": "435"
                    }
                },
                "action": {
                    "operation": "ReadSystemInformation"
                }
            }
        });

        // Send request to the API
        let response = fixture.post("/trino/allowed", &test_request).await;

        // Verify response status and body
        response.assert_ok();
        let result: OpaResponse<bool> = response.json_as();
        assert!(result.result);

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_trino_allowed_table_with_column_checks() {
        // Setup test fixture
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
                            {"allow": false, "result": false}
                        ]
                    }
                }),
                StatusCode::OK,
                1,
            )
            .await;

        // Create test request for table access with columns
        let test_request = json!({
            "input": {
                "context": {
                    "identity": {
                        "user": "analyst",
                        "groups": ["analysts"]
                    },
                    "softwareStack": {
                        "trinoVersion": "434"
                    }
                },
                "action": {
                    "operation": "SelectFromColumns",
                    "resource": {
                        "table": {
                            "catalogName": "data_catalog",
                            "schemaName": "analytics",
                            "tableName": "user_data",
                            "columns": [
                                "user_id",
                                "email",
                                "sensitive_info"
                            ]
                        }
                    }
                }
            }
        });

        // Send request to the API
        let response = fixture.post("/trino/allowed", &test_request).await;

        // Verify response status and body - should be denied due to column access
        response.assert_ok();
        let result: OpaResponse<bool> = response.json_as();
        assert!(!result.result);

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_trino_allowed_invalid_request() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Create an invalid request (missing required fields)
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

        // Send request
        let response = fixture.post("/trino/allowed", &invalid_request).await;

        // Should get a 422 Unprocessable Entity for invalid request
        response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_trino_allowed_opa_error() {
        // Setup test fixture
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

        // Create test request
        let test_request = json!({
            "input": {
                "context": {
                    "identity": {
                        "user": "test-user",
                        "groups": ["users"]
                    },
                    "softwareStack": {
                        "trinoVersion": "434"
                    }
                },
                "action": {
                    "operation": "SelectFromColumns",
                    "resource": {
                        "table": {
                            "catalogName": "test_catalog",
                            "schemaName": "test_schema",
                            "tableName": "test_table",
                            "columns": ["column1"]
                        }
                    }
                }
            }
        });

        // Send request to the API
        let response = fixture.post("/trino/allowed", &test_request).await;

        // Should get a 200 OK with allowed=false when OPA returns an error
        response.assert_ok();
        let result: OpaResponse<bool> = response.json_as();
        assert!(!result.result);

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_trino_allowed_unsupported_resource() {
        // Setup test fixture
        let fixture = TestFixture::new().await;

        // Create test request with unsupported resource type
        let test_request = json!({
            "input": {
                "context": {
                    "identity": {
                        "user": "test-user",
                        "groups": ["users"]
                    },
                    "softwareStack": {
                        "trinoVersion": "434"
                    }
                },
                "action": {
                    "operation": "SelectFromColumns",
                    "resource": {
                        "column": {
                            "table": {
                                "catalogName": "test_catalog",
                                "schemaName": "test_schema",
                                "tableName": "test_table"
                            },
                            "name": "test_column",
                            "type": "varchar"
                        }
                    }
                }
            }
        });

        // Send request to the API
        let response = fixture.post("/trino/allowed", &test_request).await;

        // Should return 200 with allowed=false for unsupported resources
        response.assert_ok();
        let result: OpaResponse<bool> = response.json_as();
        assert!(!result.result);
    }

    #[tokio::test]
    async fn test_trino_allowed_with_cache_headers() {
        // Setup test fixture
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

        // Create test request
        let test_request = json!({
            "input": {
                "context": {
                    "identity": {
                        "user": "test-user",
                        "groups": ["users"]
                    },
                    "softwareStack": {
                        "trinoVersion": "434"
                    }
                },
                "action": {
                    "operation": "SelectFromColumns",
                    "resource": {
                        "table": {
                            "catalogName": "test_catalog",
                            "schemaName": "test_schema",
                            "tableName": "test_table",
                            "columns": ["column1"]
                        }
                    }
                }
            }
        });

        // Send request with cache control headers
        let custom_headers = &[
            ("Cache-Control", "max-age=300"),
            ("Authorization", "Bearer test-token"),
        ];

        let response = fixture
            .post_with_headers("/trino/allowed", &test_request, custom_headers)
            .await;

        // Verify response
        response.assert_ok();
        let result: OpaResponse<bool> = response.json_as();
        assert!(result.result);

        // Verify mock expectations
        fixture.opa_mock.verify().await;
    }
}
