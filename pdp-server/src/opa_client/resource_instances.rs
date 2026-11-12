use crate::opa_client::{send_raw_request_to_opa, ForwardingError};
use crate::state::AppState;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// OPA ad-hoc query for the instances of one resource type in a set of tenants.
///
/// `data.resource_instances` maps `<type>:<key>` to the instance's tenant and attributes. It
/// holds the instances synced from Permit, and the policy reads an instance's tenant from it.
pub(crate) const RESOURCE_INSTANCES_QUERY: &str = "instance := data.resource_instances[key]; \
     startswith(key, input.key_prefix); \
     instance.tenant == input.tenants[_]";

/// OPA ad-hoc query for the tenant of one synced resource instance, by its `<type>:<key>`.
pub(crate) const RESOURCE_INSTANCE_TENANT_QUERY: &str =
    "tenant := data.resource_instances[input.key].tenant";

#[derive(Serialize)]
struct QueryRequest<I> {
    query: &'static str,
    input: I,
}

#[derive(Serialize)]
struct InstancesQueryInput<'a> {
    key_prefix: &'a str,
    tenants: &'a BTreeSet<String>,
}

#[derive(Serialize)]
struct TenantQueryInput<'a> {
    key: &'a str,
}

#[derive(Deserialize)]
struct QueryResponse<R> {
    /// OPA leaves `result` out when nothing matches.
    #[serde(default = "Vec::new")]
    result: Vec<R>,
}

#[derive(Deserialize)]
struct InstanceRow {
    key: String,
    instance: InstanceData,
}

#[derive(Deserialize)]
struct TenantRow {
    tenant: Option<String>,
}

#[derive(Deserialize)]
struct InstanceData {
    #[serde(default)]
    attributes: HashMap<String, serde_json::Value>,
}

/// Lists the synced instances of `resource_type` whose tenant is one of `tenants`.
///
/// Returns each instance's attributes, keyed by the instance key (without the type prefix).
///
/// # Errors
///
/// Returns a [`ForwardingError`] when the query to OPA fails or its response can't be parsed.
pub async fn query_resource_instances(
    state: &AppState,
    resource_type: &str,
    tenants: &BTreeSet<String>,
) -> Result<BTreeMap<String, HashMap<String, serde_json::Value>>, ForwardingError> {
    let key_prefix = format!("{resource_type}:");
    let request = QueryRequest {
        query: RESOURCE_INSTANCES_QUERY,
        input: InstancesQueryInput {
            key_prefix: &key_prefix,
            tenants,
        },
    };
    let response: QueryResponse<InstanceRow> =
        send_raw_request_to_opa(state, "/v1/query", &request).await?;

    let mut instances = BTreeMap::new();
    let mut unprefixed_keys = 0_usize;
    for row in response.result {
        let Some(instance_key) = row.key.strip_prefix(&key_prefix) else {
            unprefixed_keys += 1;
            continue;
        };
        instances.insert(instance_key.to_string(), row.instance.attributes);
    }
    // Counted rather than listed: keys from OPA's response are not written to the log.
    if unprefixed_keys > 0 {
        log::warn!(
            "Ignoring {unprefixed_keys} resource instance(s) from OPA whose key does not start \
             with {key_prefix:?}"
        );
    }
    Ok(instances)
}

/// Returns the tenant of the synced instance `<resource_type>:<resource_key>`.
///
/// Returns `None` when the PDP has no such instance, or the instance has no tenant.
///
/// # Errors
///
/// Returns a [`ForwardingError`] when the query to OPA fails or its response can't be parsed.
pub async fn query_resource_instance_tenant(
    state: &AppState,
    resource_type: &str,
    resource_key: &str,
) -> Result<Option<String>, ForwardingError> {
    let key = format!("{resource_type}:{resource_key}");
    let request = QueryRequest {
        query: RESOURCE_INSTANCE_TENANT_QUERY,
        input: TenantQueryInput { key: &key },
    };
    let response: QueryResponse<TenantRow> =
        send_raw_request_to_opa(state, "/v1/query", &request).await?;
    Ok(response
        .result
        .into_iter()
        .next()
        .and_then(|row| row.tenant))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{LogCapture, TestFixture};
    use serde_json::json;

    #[tokio::test]
    async fn test_instances_with_an_unexpected_key_are_counted_in_one_warning() {
        let fixture = TestFixture::new().await;
        fixture
            .add_opa_mock(
                http::Method::POST,
                "/v1/query",
                json!({"result": [
                    {"instance": {"attributes": {}, "tenant": "t1"}, "key": "doc:d-public"},
                    {"instance": {"attributes": {}, "tenant": "t1"}, "key": "docx:secret-x"},
                    {"instance": {"attributes": {}, "tenant": "t1"}, "key": "doc:d-secret"},
                    {"instance": {"attributes": {}, "tenant": "t1"}, "key": "file:secret-y"}
                ]}),
                http::StatusCode::OK,
                1,
            )
            .await;
        let tenants = BTreeSet::from(["t1".to_string()]);
        let logs = LogCapture::start();

        let instances = query_resource_instances(&fixture.state, "doc", &tenants)
            .await
            .expect("the query succeeds");

        let mut keys = Vec::new();
        for key in instances.keys() {
            keys.push(key.as_str());
        }
        assert_eq!(keys, vec!["d-public", "d-secret"]);
        let mut warnings = Vec::new();
        for line in logs.lines() {
            if line.starts_with("WARN") {
                warnings.push(line);
            }
        }
        assert_eq!(
            warnings,
            vec![
                "WARN Ignoring 2 resource instance(s) from OPA whose key does not start with \
                 \"doc:\""
            ]
        );
        for line in logs.lines() {
            assert!(
                !line.contains("secret-"),
                "an OPA key reached the log: {line}"
            );
        }
    }
}
