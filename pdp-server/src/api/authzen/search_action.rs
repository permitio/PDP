use crate::api::authzen::common::{tenant_property, PageRequest, PageResponse, TENANT_TYPE};
use crate::api::authzen::errors::AuthZenError;
use crate::api::authzen::schema::{AuthZenAction, AuthZenResource, AuthZenSubject};
use crate::opa_client::resource_instances::query_resource_instance_tenant;
use crate::opa_client::user_permissions::{query_user_permissions, UserPermissionsQuery};
use crate::openapi::AUTHZEN_TAG;
use crate::state::AppState;
use axum::{
    extract::{Json, State},
    response::{IntoResponse, Response},
};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;

/// AuthZen Action Search Request - to find what actions a subject can perform on a resource
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct ActionSearchRequest {
    /// Subject making the request
    pub subject: AuthZenSubject,
    /// Resource being accessed. `properties.tenant`, when set, must be a string and limits
    /// the search to that tenant.
    pub resource: AuthZenResource,
    /// Context for the evaluation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<HashMap<String, serde_json::Value>>,
    /// Pagination parameters
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<PageRequest>,
}

/// AuthZen Action Search Response - contains list of actions the subject can perform on the resource
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub struct ActionSearchResponse {
    /// Actions the subject can perform on the resource, by name (`read`, not `document:read`),
    /// sorted by name, comparing strings by code point.
    ///
    /// The resource's tenant is `resource.properties.tenant` when given, otherwise the tenant
    /// of the resource instance synced to the PDP. When the tenant is known, only grants in
    /// that tenant count, and they include the actions a tenant-level role grants on the
    /// resource type. For a resource that is not a synced instance and has no
    /// `properties.tenant`, only grants on the instance itself (ReBAC and ABAC) are returned.
    pub results: Vec<AuthZenAction>,
    /// Pagination information
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<PageResponse>,
    /// Optional additional context
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<HashMap<String, serde_json::Value>>,
}

/// The tenant of the searched resource: `resource.properties.tenant` when it is given,
/// otherwise the tenant of the resource instance synced to the PDP. `None` when neither is
/// known.
async fn resource_tenant(
    state: &AppState,
    resource: &AuthZenResource,
) -> Result<Option<String>, AuthZenError> {
    if let Some(tenant) = tenant_property(resource)? {
        return Ok(Some(tenant));
    }
    let Some(resource_key) = &resource.id else {
        return Ok(None);
    };
    query_resource_instance_tenant(state, &resource.r#type, resource_key)
        .await
        .map_err(|err| {
            // AuthZenError::from logs the error itself.
            log::error!(
                "Failed to look up the tenant of {}:{resource_key} for an AuthZen action search",
                resource.r#type
            );
            AuthZenError::from(err)
        })
}

fn user_permissions_query(
    req: ActionSearchRequest,
    tenant: Option<String>,
) -> UserPermissionsQuery {
    let mut resource_types = vec![req.resource.r#type];
    if tenant.is_some() {
        resource_types.push(TENANT_TYPE.to_string());
    }
    UserPermissionsQuery {
        user: req.subject.into(),
        tenants: tenant.map(|tenant| vec![tenant]),
        // user_permissions takes resources as bare instance keys.
        resources: req.resource.id.map(|id| vec![id]),
        resource_types: Some(resource_types),
        context: Some(req.context.unwrap_or_default()),
    }
}

#[utoipa::path(
    post,
    path = "/access/v1/search/action",
    tag = AUTHZEN_TAG,
    request_body = ActionSearchRequest,
    params(
        ("Authorization" = String, Header, description = "Authorization header"),
        ("X-Request-ID" = String, Header, description = "Request Identifier"),
    ),
    responses(
        (status = 200, description = "Action search completed successfully", body = ActionSearchResponse),
        (status = 400, description = "Bad Request", body = String),
        (status = 401, description = "Unauthorized", body = String),
        (status = 403, description = "Forbidden", body = String),
        (status = 500, description = "Internal server error", body = String)
    )
)]
pub async fn search_action_handler(
    State(state): State<AppState>,
    Json(request): Json<ActionSearchRequest>,
) -> Response {
    let resource_type = request.resource.r#type.clone();
    let tenant = match resource_tenant(&state, &request.resource).await {
        Ok(tenant) => tenant,
        Err(authzen_error) => return authzen_error.into_response(),
    };
    let user_permissions_query = user_permissions_query(request, tenant.clone());

    // Query user permissions using the existing client
    let permissions_map = match query_user_permissions(&state, &user_permissions_query).await {
        Ok(permissions_map) => permissions_map,
        Err(err) => {
            log::error!("Failed to process AuthZen action search request: {err:?}");
            let authzen_error = AuthZenError::from(err);
            return authzen_error.into_response();
        }
    };
    // OPA lists permissions as `<resource type>:<action>`. The results are the actions on the
    // requested resource type.
    let mut action_names = Vec::new();
    let mut untyped_permissions = 0_usize;
    for result in permissions_map.values() {
        // OPA applies the tenant filter to role grants, not to ABAC grants.
        if let Some(tenant) = &tenant {
            let in_tenant = result
                .tenant
                .as_ref()
                .is_some_and(|entry_tenant| &entry_tenant.key == tenant);
            if !in_tenant {
                continue;
            }
        }
        for permission in &result.permissions {
            let Some((permission_type, action_name)) = permission.split_once(':') else {
                untyped_permissions += 1;
                continue;
            };
            if permission_type == resource_type {
                action_names.push(action_name.to_string());
            }
        }
    }
    // Counted rather than listed: values from OPA's response are not written to the log.
    if untyped_permissions > 0 {
        log::warn!(
            "Ignoring {untyped_permissions} permission(s) from OPA user_permissions that are \
             not <resource type>:<action>"
        );
    }
    action_names.sort();
    action_names.dedup();

    let results = action_names
        .into_iter()
        .map(|name| AuthZenAction {
            name,
            properties: None,
        })
        .collect();

    // Create and return the AuthZen response
    let authzen_response = ActionSearchResponse {
        results,
        page: Some(PageResponse {
            next_token: String::new(),
        }),
        context: None,
    };

    // Return the response
    (StatusCode::OK, Json(authzen_response)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{TestFixture, TestResponse};
    use serde_json::json;
    use wiremock::{matchers, Mock, ResponseTemplate};

    #[tokio::test]
    async fn test_action_search_with_permissions() {
        let fixture = TestFixture::new().await;
        mock_unsynced_instance(&fixture).await;
        // Set up the mock response
        fixture
            .add_opa_mock(
                http::Method::POST,
                "/v1/data/permit/user_permissions",
                json!({
                    "result": {
                        "permissions": {
                            "document:doc1": {
                                "tenant": null,
                                "resource": null,
                                "permissions": ["document:can_read", "document:can_edit"],
                                "roles": ["editor"]
                            }
                        }
                    }
                }),
                http::StatusCode::OK,
                1,
            )
            .await;

        // Send the request using the fixture's post method
        let response = fixture
            .post(
                "/access/v1/search/action",
                &json!({
                    "subject": {
                        "type": "user",
                        "id": "alice@example.com"
                    },
                    "resource": {
                        "type": "document",
                        "id": "doc1"
                    }
                }),
            )
            .await;

        // Assert the response
        response.assert_ok();

        // Parse the response body
        let search_response: ActionSearchResponse = response.json_as();

        // Print the search response for debugging
        println!("Search response: {search_response:?}");

        // Check the response - should have 2 actions
        assert_eq!(search_response.results.len(), 2);

        // Find the read permission
        let read_action = search_response
            .results
            .iter()
            .find(|action| action.name == "can_read")
            .unwrap();
        assert!(read_action.properties.is_none());

        // Find the edit permission
        let edit_action = search_response
            .results
            .iter()
            .find(|action| action.name == "can_edit")
            .unwrap();
        assert!(edit_action.properties.is_none());

        // Verify page is present
        assert!(search_response.page.is_some());
    }

    #[tokio::test]
    async fn test_action_search_without_permissions() {
        let fixture = TestFixture::new().await;
        mock_unsynced_instance(&fixture).await;
        fixture
            .add_opa_mock(
                http::Method::POST,
                "/v1/data/permit/user_permissions",
                json!({
                    "result": {
                        "permissions": {}
                    }
                }),
                http::StatusCode::OK,
                1,
            )
            .await;

        // Send the request using the fixture's post method
        let response = fixture
            .post(
                "/access/v1/search/action",
                &json!({
                    "subject": {
                        "type": "user",
                        "id": "bob@example.com"
                    },
                    "resource": {
                        "type": "document",
                        "id": "doc1"
                    }
                }),
            )
            .await;

        // Assert the response
        response.assert_ok();
        let search_response: ActionSearchResponse = response.json_as();
        assert_eq!(search_response.results.len(), 0);
        assert!(search_response.page.is_some());
    }

    #[tokio::test]
    async fn test_action_search_with_pagination() {
        let fixture = TestFixture::new().await;
        mock_unsynced_instance(&fixture).await;
        fixture
            .add_opa_mock(
                http::Method::POST,
                "/v1/data/permit/user_permissions",
                json!({
                    "result": {
                        "permissions": {
                            "document:doc1": {
                                "tenant": null,
                                "resource": null,
                                "permissions": ["document:can_read"],
                                "roles": ["viewer"]
                            }
                        }
                    }
                }),
                http::StatusCode::OK,
                1,
            )
            .await;

        // Send the request using the fixture's post method
        let response = fixture
            .post(
                "/access/v1/search/action",
                &json!({
                    "subject": {
                        "type": "user",
                        "id": "alice@example.com"
                    },
                    "resource": {
                        "type": "document",
                        "id": "doc1"
                    },
                    "page": {
                        "size": 10,
                        "next_token": null
                    }
                }),
            )
            .await;

        // Assert the response
        response.assert_ok();

        // Parse the response body
        let search_response: ActionSearchResponse = response.json_as();

        // Print the search response for debugging
        println!("Search response: {search_response:?}");

        // Check the response (should have 1 action)
        assert_eq!(search_response.results.len(), 1);
        assert_eq!(search_response.results[0].name, "can_read");

        // Verify page is present
        assert!(search_response.page.is_some());
    }

    /// A `user_permissions` OPA result with overlapping permission lists in no particular
    /// order. `Can_admin` shows that names compare by code point.
    fn overlapping_permissions_response() -> serde_json::Value {
        json!({
            "result": {
                "permissions": {
                    "document:doc1": {
                        "permissions": ["document:can_write", "document:can_read", "document:can_delete"],
                        "roles": ["editor"]
                    },
                    "document:doc2": {
                        "permissions": ["document:can_read", "document:can_archive", "document:Can_admin"],
                        "roles": ["admin"]
                    },
                    "document:doc3": {
                        "permissions": ["document:can_share", "document:can_write", "document:can_comment"],
                        "roles": ["editor"]
                    },
                    "document:doc4": {
                        "permissions": ["document:can_read", "document:can_export", "document:can_print"],
                        "roles": ["viewer"]
                    }
                }
            }
        })
    }

    async fn mock_user_permissions(
        fixture: &TestFixture,
        response: serde_json::Value,
        expected_calls: u64,
    ) {
        fixture
            .add_opa_mock(
                http::Method::POST,
                "/v1/data/permit/user_permissions",
                response,
                http::StatusCode::OK,
                expected_calls,
            )
            .await;
    }

    /// Answers the instance-tenant lookup the way OPA does for a key it has no instance for.
    async fn mock_unsynced_instance(fixture: &TestFixture) {
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/query"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&fixture.opa_mock)
            .await;
    }

    fn action_search_request() -> serde_json::Value {
        json!({
            "subject": {"type": "user", "id": "alice@example.com"},
            "resource": {"type": "document", "id": "doc1"}
        })
    }

    #[tokio::test]
    async fn test_action_search_sorts_and_deduplicates_results_by_name() {
        let fixture = TestFixture::new().await;
        mock_unsynced_instance(&fixture).await;
        mock_user_permissions(&fixture, overlapping_permissions_response(), 1).await;

        let response = fixture
            .post("/access/v1/search/action", &action_search_request())
            .await;

        response.assert_ok();
        let search_response: ActionSearchResponse = response.json_as();
        let mut names = Vec::new();
        for action in &search_response.results {
            names.push(action.name.as_str());
        }
        assert_eq!(
            names,
            vec![
                "Can_admin",
                "can_archive",
                "can_comment",
                "can_delete",
                "can_export",
                "can_print",
                "can_read",
                "can_share",
                "can_write",
            ]
        );
    }

    #[tokio::test]
    async fn test_action_search_repeated_calls_return_identical_bodies() {
        const CALLS: u64 = 10;
        let fixture = TestFixture::new().await;
        mock_unsynced_instance(&fixture).await;
        mock_user_permissions(&fixture, overlapping_permissions_response(), CALLS).await;

        let first = fixture
            .post("/access/v1/search/action", &action_search_request())
            .await;
        first.assert_ok();
        for call in 2..=CALLS {
            let response = fixture
                .post("/access/v1/search/action", &action_search_request())
                .await;
            response.assert_ok();
            assert_eq!(
                response.text(),
                first.text(),
                "call {call} returned a different body than call 1"
            );
        }
    }

    #[tokio::test]
    async fn test_action_search_ignores_page_and_returns_empty_next_token() {
        let fixture = TestFixture::new().await;
        mock_unsynced_instance(&fixture).await;
        mock_user_permissions(&fixture, overlapping_permissions_response(), 1).await;
        let mut request = action_search_request();
        request["page"] = json!({"size": 1, "next_token": null});

        let response = fixture.post("/access/v1/search/action", &request).await;

        response.assert_ok();
        let body = response.json();
        assert_eq!(body["page"], json!({"next_token": ""}));
        assert_eq!(body["results"].as_array().map(Vec::len), Some(9));
    }

    /// One `user_permissions` entry for `file:a1`, in the shape OPA returns.
    fn file_a1_permissions_response(permissions: &[&str]) -> serde_json::Value {
        json!({
            "result": {
                "permissions": {
                    "file:a1": {
                        "permissions": permissions,
                        "resource": {"attributes": {}, "key": "a1", "type": "file"},
                        "roles": ["owner"],
                        "tenant": {"attributes": {}, "key": "t1", "type": "__tenant"}
                    }
                }
            }
        })
    }

    async fn search_file_a1_actions(fixture: &TestFixture) -> Vec<String> {
        let request = json!({
            "subject": {"type": "user", "id": "frank"},
            "resource": {"type": "file", "id": "a1"}
        });
        let response = fixture.post("/access/v1/search/action", &request).await;
        response.assert_ok();
        let search_response: ActionSearchResponse = response.json_as();
        let mut names = Vec::new();
        for action in search_response.results {
            names.push(action.name);
        }
        names
    }

    #[tokio::test]
    async fn test_action_search_returns_action_names_not_permission_keys() {
        let fixture = TestFixture::new().await;
        mock_unsynced_instance(&fixture).await;
        mock_user_permissions(
            &fixture,
            file_a1_permissions_response(&["file:read", "file:delete"]),
            1,
        )
        .await;

        assert_eq!(
            search_file_a1_actions(&fixture).await,
            vec!["delete", "read"]
        );
    }

    #[tokio::test]
    async fn test_action_search_skips_permissions_on_other_types_and_without_a_type() {
        let fixture = TestFixture::new().await;
        mock_unsynced_instance(&fixture).await;
        mock_user_permissions(
            &fixture,
            file_a1_permissions_response(&["file:read", "folder:delete", "share"]),
            1,
        )
        .await;

        assert_eq!(search_file_a1_actions(&fixture).await, vec!["read"]);
    }

    #[tokio::test]
    async fn test_action_search_filters_by_the_tenant_property() {
        let fixture = TestFixture::new().await;
        mock_unsynced_instance(&fixture).await;
        // Answers like the policy: entries for the tenant filter ["t1"], none for any other.
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/data/permit/user_permissions"))
            .and(matchers::body_partial_json(
                json!({"input": {"tenants": ["t1"]}}),
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(file_a1_permissions_response(&["file:read", "file:delete"])),
            )
            .with_priority(1)
            .mount(&fixture.opa_mock)
            .await;
        mock_user_permissions(&fixture, json!({"result": {"permissions": {}}}), 0).await;
        let request = json!({
            "subject": {"type": "user", "id": "frank"},
            "resource": {"type": "file", "id": "a1", "properties": {"tenant": "t1"}}
        });

        let response = fixture.post("/access/v1/search/action", &request).await;

        response.assert_ok();
        let search_response: ActionSearchResponse = response.json_as();
        let mut names = Vec::new();
        for action in search_response.results {
            names.push(action.name);
        }
        assert_eq!(names, vec!["delete", "read"]);
    }

    #[tokio::test]
    async fn test_action_search_rejects_a_tenant_that_is_not_a_string() {
        let fixture = TestFixture::new().await;
        mock_unsynced_instance(&fixture).await;
        mock_user_permissions(&fixture, json!({"result": {"permissions": {}}}), 0).await;

        for tenant in [json!(7), json!(null), json!(["t1"]), json!({"key": "t1"})] {
            let request = json!({
                "subject": {"type": "user", "id": "frank"},
                "resource": {"type": "file", "id": "a1", "properties": {"tenant": tenant}}
            });

            let response = fixture.post("/access/v1/search/action", &request).await;

            response.assert_status(http::StatusCode::BAD_REQUEST);
            assert_eq!(
                response.text(),
                "resource.properties.tenant must be a string",
                "tenant {tenant}"
            );
        }
    }

    fn tenant_role_entry(tenant: &str, permissions: &[&str]) -> serde_json::Value {
        json!({
            "permissions": permissions,
            "roles": ["editor"],
            "tenant": {"attributes": {}, "key": tenant, "type": "__tenant"}
        })
    }

    /// Mounts a mock OPA lookup of the synced instance `key`'s tenant.
    async fn mock_instance_tenant_lookup(
        fixture: &TestFixture,
        key: &str,
        response: ResponseTemplate,
        expected_calls: u64,
    ) {
        use crate::opa_client::resource_instances::RESOURCE_INSTANCE_TENANT_QUERY;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/query"))
            .and(matchers::body_json(json!({
                "query": RESOURCE_INSTANCE_TENANT_QUERY,
                "input": {"key": key}
            })))
            .respond_with(response)
            .with_priority(1)
            .expect(expected_calls)
            .mount(&fixture.opa_mock)
            .await;
    }

    /// Mounts a mock OPA `user_permissions` for alice, an editor in tenant t1, that answers an
    /// action search on doc `resource_key` like the policy: the t1 tenant role when the input
    /// filters by tenant t1 and asks for `__tenant`, and no entries otherwise.
    async fn mock_alice_editor_in_t1(fixture: &TestFixture, resource_key: &str) {
        let editor = tenant_role_entry("t1", &["doc:read", "doc:write", "file:read"]);
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/data/permit/user_permissions"))
            .and(matchers::body_partial_json(json!({"input": {
                "tenants": ["t1"],
                "resources": [resource_key],
                "resource_types": ["doc", "__tenant"]
            }})))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"result": {"permissions": {"__tenant:t1": editor}}})),
            )
            .with_priority(1)
            .mount(&fixture.opa_mock)
            .await;
        mock_user_permissions(fixture, json!({"result": {"permissions": {}}}), 0).await;
    }

    async fn search_alice_actions(
        fixture: &TestFixture,
        resource: serde_json::Value,
    ) -> TestResponse {
        let request = json!({"subject": {"type": "user", "id": "alice"}, "resource": resource});
        fixture.post("/access/v1/search/action", &request).await
    }

    fn action_names(response: &TestResponse) -> Vec<String> {
        response.assert_ok();
        let search_response: ActionSearchResponse = response.json_as();
        let mut names = Vec::new();
        for action in search_response.results {
            names.push(action.name);
        }
        names
    }

    #[tokio::test]
    async fn test_action_search_includes_tenant_role_actions_for_a_synced_instance() {
        let fixture = TestFixture::new().await;
        let in_t1 = ResponseTemplate::new(200).set_body_json(json!({"result": [{"tenant": "t1"}]}));
        mock_instance_tenant_lookup(&fixture, "doc:d-secret", in_t1, 1).await;
        mock_alice_editor_in_t1(&fixture, "d-secret").await;

        let response =
            search_alice_actions(&fixture, json!({"type": "doc", "id": "d-secret"})).await;

        assert_eq!(action_names(&response), vec!["read", "write"]);
    }

    #[tokio::test]
    async fn test_action_search_takes_the_tenant_from_the_tenant_property() {
        let fixture = TestFixture::new().await;
        let in_t2 = ResponseTemplate::new(200).set_body_json(json!({"result": [{"tenant": "t2"}]}));
        mock_instance_tenant_lookup(&fixture, "doc:d-secret", in_t2, 0).await;
        mock_alice_editor_in_t1(&fixture, "d-secret").await;

        let resource = json!({"type": "doc", "id": "d-secret", "properties": {"tenant": "t1"}});
        let response = search_alice_actions(&fixture, resource).await;

        assert_eq!(action_names(&response), vec!["read", "write"]);
    }

    #[tokio::test]
    async fn test_action_search_without_a_known_tenant_skips_tenant_roles() {
        let fixture = TestFixture::new().await;
        // OPA answers `{}` when it has no instance for the key.
        let unknown = ResponseTemplate::new(200).set_body_json(json!({}));
        mock_instance_tenant_lookup(&fixture, "doc:ghost", unknown, 1).await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/data/permit/user_permissions"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"result": {"permissions": {}}})),
            )
            .expect(1)
            .mount(&fixture.opa_mock)
            .await;

        let response = search_alice_actions(&fixture, json!({"type": "doc", "id": "ghost"})).await;

        assert_eq!(action_names(&response), Vec::<String>::new());
        let requests = fixture
            .opa_mock
            .received_requests()
            .await
            .unwrap_or_default();
        let mut user_permissions_inputs = Vec::new();
        for request in &requests {
            if request.url.path() == "/v1/data/permit/user_permissions" {
                let body: serde_json::Value = serde_json::from_slice(&request.body)
                    .expect("user_permissions request body is JSON");
                user_permissions_inputs.push(body["input"].clone());
            }
        }
        assert_eq!(user_permissions_inputs.len(), 1);
        let input = &user_permissions_inputs[0];
        assert_eq!(input["resource_types"], json!(["doc"]));
        assert_eq!(input.get("tenants"), None, "input: {input}");
    }

    #[tokio::test]
    async fn test_action_search_counts_only_grants_in_the_known_tenant() {
        let fixture = TestFixture::new().await;
        // OPA filters role grants by tenant but returns ABAC grants from any tenant.
        let permissions = json!({"result": {"permissions": {
            "__tenant:t1": tenant_role_entry("t1", &["doc:read"]),
            "doc:d-secret": {
                "permissions": ["doc:delete"],
                "roles": [],
                "tenant": {"attributes": {}, "key": "t2"}
            }
        }}});
        mock_user_permissions(&fixture, permissions, 1).await;

        let resource = json!({"type": "doc", "id": "d-secret", "properties": {"tenant": "t1"}});
        let response = search_alice_actions(&fixture, resource).await;

        assert_eq!(action_names(&response), vec!["read"]);
    }

    #[tokio::test]
    async fn test_action_search_fails_when_the_tenant_lookup_fails() {
        let fixture = TestFixture::new().await;
        mock_instance_tenant_lookup(&fixture, "doc:d-secret", ResponseTemplate::new(500), 1).await;
        mock_user_permissions(&fixture, json!({"result": {"permissions": {}}}), 0).await;

        let response =
            search_alice_actions(&fixture, json!({"type": "doc", "id": "d-secret"})).await;

        response.assert_status(http::StatusCode::INTERNAL_SERVER_ERROR);
    }
}
