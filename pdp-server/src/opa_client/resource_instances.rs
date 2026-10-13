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

#[derive(Serialize)]
struct QueryRequest<'a> {
    query: &'static str,
    input: QueryInput<'a>,
}

#[derive(Serialize)]
struct QueryInput<'a> {
    key_prefix: &'a str,
    tenants: &'a BTreeSet<String>,
}

#[derive(Deserialize)]
struct QueryResponse {
    /// OPA leaves `result` out when nothing matches.
    #[serde(default)]
    result: Vec<QueryRow>,
}

#[derive(Deserialize)]
struct QueryRow {
    key: String,
    instance: InstanceData,
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
        input: QueryInput {
            key_prefix: &key_prefix,
            tenants,
        },
    };
    let response: QueryResponse = send_raw_request_to_opa(state, "/v1/query", &request).await?;

    let mut instances = BTreeMap::new();
    for row in response.result {
        let Some(instance_key) = row.key.strip_prefix(&key_prefix) else {
            log::warn!(
                "Ignoring resource instance {:?} from OPA: expected the prefix {key_prefix:?}",
                row.key
            );
            continue;
        };
        instances.insert(instance_key.to_string(), row.instance.attributes);
    }
    Ok(instances)
}
