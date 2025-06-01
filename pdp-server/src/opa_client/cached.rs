use crate::cache::CacheBackend;
use crate::headers::ClientCacheControl;
use crate::opa_client::ForwardingError;
use crate::state::AppState;
use log::{debug, warn};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[cfg(test)]
use std::sync::Arc;

// Re-export types for convenience
pub use super::allowed::{AllowedQuery, AllowedResult};
pub use super::allowed_bulk::BulkAuthorizationResult;
pub use super::authorized_users::{AuthorizedUsersQuery, AuthorizedUsersResult};
pub use super::user_permissions::{UserPermissionsQuery, UserPermissionsResult};

/// Common cache handling logic
async fn handle_cache_get<T: serde::de::DeserializeOwned + Send + Sync>(
    state: &AppState,
    cache_key: &str,
    cache_control: &ClientCacheControl,
) -> Option<T> {
    // Skip cache if client requested no-cache or no-store
    if !cache_control.should_use_cache() {
        debug!(
            "Skipping cache lookup due to cache control directives: {:?}",
            cache_control
        );
        return None;
    }

    match state.cache.get::<T>(cache_key).await {
        Ok(Some(cached_result)) => {
            debug!("Cache hit for key: {}", cache_key);
            Some(cached_result)
        }
        Ok(None) => {
            debug!("Cache miss for key: {}", cache_key);
            None
        }
        Err(cache_err) => {
            warn!("Cache error for key {}: {}", cache_key, cache_err);
            None
        }
    }
}

/// Common cache storage logic
async fn handle_cache_set<T: serde::Serialize + Send + Sync>(
    state: &AppState,
    cache_key: &str,
    value: &T,
    cache_control: &ClientCacheControl,
) {
    // Skip caching if client requested no-store
    if cache_control.no_store {
        debug!("Skipping cache storage due to no-store directive");
        return;
    }

    if let Err(cache_err) = state.cache.set(cache_key, value).await {
        warn!("Failed to cache result for {}: {}", cache_key, cache_err);
    }
}

/// Generate a cache key for allowed queries
fn generate_allowed_cache_key(query: &AllowedQuery) -> Result<String, String> {
    let mut hasher = Sha256::new();
    let serialized = serde_json::to_string(query)
        .map_err(|e| format!("Failed to serialize AllowedQuery for cache key: {}", e))?;
    hasher.update(serialized.as_bytes());
    let hash = format!("{:x}", hasher.finalize());
    Ok(format!("opa:allowed:{}", &hash[..16]))
}

/// Generate a cache key for user permissions queries
fn generate_user_permissions_cache_key(query: &UserPermissionsQuery) -> Result<String, String> {
    let mut hasher = Sha256::new();
    let serialized = serde_json::to_string(query).map_err(|e| {
        format!(
            "Failed to serialize UserPermissionsQuery for cache key: {}",
            e
        )
    })?;
    hasher.update(serialized.as_bytes());
    let hash = format!("{:x}", hasher.finalize());
    Ok(format!("opa:user_permissions:{}", &hash[..16]))
}

/// Generate a cache key for authorized users queries
fn generate_authorized_users_cache_key(query: &AuthorizedUsersQuery) -> Result<String, String> {
    let mut hasher = Sha256::new();
    let serialized = serde_json::to_string(query).map_err(|e| {
        format!(
            "Failed to serialize AuthorizedUsersQuery for cache key: {}",
            e
        )
    })?;
    hasher.update(serialized.as_bytes());
    let hash = format!("{:x}", hasher.finalize());
    Ok(format!("opa:authorized_users:{}", &hash[..16]))
}

/// Cached version of query_allowed with cache control support
pub async fn query_allowed_cached(
    state: &AppState,
    query: &AllowedQuery,
    cache_control: &ClientCacheControl,
) -> Result<AllowedResult, ForwardingError> {
    let cache_key = generate_allowed_cache_key(query)?;

    // Try to get from cache first
    if let Some(cached_result) =
        handle_cache_get::<AllowedResult>(state, &cache_key, cache_control).await
    {
        return Ok(cached_result);
    }

    // Cache miss or disabled - query OPA
    let result = super::allowed::query_allowed(state, query).await?;

    // Store in cache if allowed
    handle_cache_set(state, &cache_key, &result, cache_control).await;

    Ok(result)
}

/// Cached version of query_allowed_bulk with cache control support
/// This function leverages the shared cache with individual allowed queries
pub async fn query_allowed_bulk_cached(
    state: &AppState,
    queries: &[AllowedQuery],
    cache_control: &ClientCacheControl,
) -> Result<BulkAuthorizationResult, ForwardingError> {
    // Handle empty queries list - for consistency with non-cached version,
    // we should still call OPA even with empty input
    if queries.is_empty() {
        return super::allowed_bulk::query_allowed_bulk(state, queries).await;
    }

    let mut results = Vec::with_capacity(queries.len());
    let mut cache_misses = Vec::new();
    let mut cache_miss_indices = Vec::new();

    // Check cache for each individual query
    for (index, query) in queries.iter().enumerate() {
        let cache_key = generate_allowed_cache_key(query)?;

        if let Some(cached_result) =
            handle_cache_get::<AllowedResult>(state, &cache_key, cache_control).await
        {
            debug!("Cache hit for bulk allowed query {}: {}", index, cache_key);
            results.push(Some(cached_result));
        } else {
            debug!("Cache miss for bulk allowed query {}: {}", index, cache_key);
            results.push(None);
            cache_misses.push(query.clone());
            cache_miss_indices.push(index);
        }
    }

    // If we have cache misses, query OPA for them
    if !cache_misses.is_empty() {
        debug!(
            "Querying OPA for {} cache misses out of {} total queries",
            cache_misses.len(),
            queries.len()
        );

        let bulk_result = super::allowed_bulk::query_allowed_bulk(state, &cache_misses).await?;

        // Store individual results in cache and update our results array
        for (miss_index, opa_result) in cache_miss_indices.iter().zip(bulk_result.allow.iter()) {
            let query = &queries[*miss_index];
            let cache_key = generate_allowed_cache_key(query)?;

            // Store in cache if allowed
            handle_cache_set(state, &cache_key, opa_result, cache_control).await;

            results[*miss_index] = Some(opa_result.clone());
        }
    }

    // Convert Option<AllowedResult> to AllowedResult (should all be Some at this point)
    let final_results: Vec<AllowedResult> = results
        .into_iter()
        .map(|opt| opt.expect("All results should be populated by now"))
        .collect();

    Ok(BulkAuthorizationResult {
        allow: final_results,
    })
}

/// Cached version of query_user_permissions with cache control support
pub async fn query_user_permissions_cached(
    state: &AppState,
    query: &UserPermissionsQuery,
    cache_control: &ClientCacheControl,
) -> Result<HashMap<String, UserPermissionsResult>, ForwardingError> {
    let cache_key = generate_user_permissions_cache_key(query)?;

    // Try to get from cache first
    if let Some(cached_result) =
        handle_cache_get::<HashMap<String, UserPermissionsResult>>(state, &cache_key, cache_control)
            .await
    {
        return Ok(cached_result);
    }

    // Cache miss or disabled - query OPA
    let result = super::user_permissions::query_user_permissions(state, query).await?;

    // Store in cache if allowed
    handle_cache_set(state, &cache_key, &result, cache_control).await;

    Ok(result)
}

/// Cached version of query_authorized_users with cache control support
pub async fn query_authorized_users_cached(
    state: &AppState,
    query: &AuthorizedUsersQuery,
    cache_control: &ClientCacheControl,
) -> Result<AuthorizedUsersResult, ForwardingError> {
    let cache_key = generate_authorized_users_cache_key(query)?;

    // Try to get from cache first
    if let Some(cached_result) =
        handle_cache_get::<AuthorizedUsersResult>(state, &cache_key, cache_control).await
    {
        return Ok(cached_result);
    }

    // Cache miss or disabled - query OPA
    let result = super::authorized_users::query_authorized_users(state, query).await?;

    // Store in cache if allowed
    handle_cache_set(state, &cache_key, &result, cache_control).await;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opa_client::allowed::{Resource, User};
    use crate::test_utils::TestFixture;
    use http::{Method, StatusCode};
    use serde_json::json;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_allowed_cache_respects_no_cache() {
        let fixture = TestFixture::new().await;

        let query = AllowedQuery {
            user: User {
                key: "user-123".to_string(),
                first_name: Some("Test".to_string()),
                last_name: Some("User".to_string()),
                email: Some("test@example.com".to_string()),
                attributes: HashMap::new(),
            },
            action: "view".to_string(),
            resource: Resource {
                r#type: "document".to_string(),
                key: Some("doc-123".to_string()),
                tenant: Some("test_tenant".to_string()),
                attributes: HashMap::new(),
                context: HashMap::new(),
            },
            context: HashMap::new(),
            sdk: None,
        };

        // Setup mock for two calls (since cache should be bypassed)
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
                2, // Expect two calls
            )
            .await;

        let no_cache_control = ClientCacheControl {
            no_cache: true,
            no_store: false,
            max_age: None,
        };

        // First call should hit OPA
        let result1 = query_allowed_cached(&fixture.state, &query, &no_cache_control)
            .await
            .unwrap();
        assert!(result1.allow);

        // Second call should also hit OPA (cache bypassed)
        let result2 = query_allowed_cached(&fixture.state, &query, &no_cache_control)
            .await
            .unwrap();
        assert!(result2.allow);

        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_allowed_cache_respects_no_store() {
        let fixture = TestFixture::new().await;

        let query = AllowedQuery {
            user: User {
                key: "user-456".to_string(),
                first_name: Some("Test".to_string()),
                last_name: Some("User".to_string()),
                email: Some("test@example.com".to_string()),
                attributes: HashMap::new(),
            },
            action: "view".to_string(),
            resource: Resource {
                r#type: "document".to_string(),
                key: Some("doc-456".to_string()),
                tenant: Some("test_tenant".to_string()),
                attributes: HashMap::new(),
                context: HashMap::new(),
            },
            context: HashMap::new(),
            sdk: None,
        };

        // Setup mock for two calls
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
                2, // Expect two calls since result won't be stored
            )
            .await;

        let no_store_control = ClientCacheControl {
            no_cache: false,
            no_store: true,
            max_age: None,
        };

        // First call should hit OPA and not store in cache
        let result1 = query_allowed_cached(&fixture.state, &query, &no_store_control)
            .await
            .unwrap();
        assert!(result1.allow);

        // Second call should hit OPA again (not stored in cache)
        let result2 = query_allowed_cached(&fixture.state, &query, &no_store_control)
            .await
            .unwrap();
        assert!(result2.allow);

        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_allowed_cache_default_behavior() {
        let mut fixture = TestFixture::new().await;

        // Replace the null cache with an in-memory cache for this test
        use crate::cache::{memory::InMemoryCache, Cache};
        fixture.state.cache = Arc::new(Cache::InMemory(InMemoryCache::new(60, 128).unwrap()));

        let query = AllowedQuery {
            user: User {
                key: "user-789".to_string(),
                first_name: Some("Test".to_string()),
                last_name: Some("User".to_string()),
                email: Some("test@example.com".to_string()),
                attributes: HashMap::new(),
            },
            action: "view".to_string(),
            resource: Resource {
                r#type: "document".to_string(),
                key: Some("doc-789".to_string()),
                tenant: Some("test_tenant".to_string()),
                attributes: HashMap::new(),
                context: HashMap::new(),
            },
            context: HashMap::new(),
            sdk: None,
        };

        // Setup mock for one call only (cache should work)
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
                1, // Only expect one call
            )
            .await;

        let default_control = ClientCacheControl::default();

        // First call should hit OPA
        let result1 = query_allowed_cached(&fixture.state, &query, &default_control)
            .await
            .unwrap();
        assert!(result1.allow);

        // Second call should hit cache
        let result2 = query_allowed_cached(&fixture.state, &query, &default_control)
            .await
            .unwrap();
        assert!(result2.allow);
        assert_eq!(result1, result2);

        fixture.opa_mock.verify().await;
    }

    #[test]
    fn test_cache_key_generation() {
        let query1 = AllowedQuery {
            user: User {
                key: "user-123".to_string(),
                first_name: Some("Test".to_string()),
                last_name: Some("User".to_string()),
                email: Some("test@example.com".to_string()),
                attributes: HashMap::new(),
            },
            action: "view".to_string(),
            resource: Resource {
                r#type: "document".to_string(),
                key: Some("doc-123".to_string()),
                tenant: Some("test_tenant".to_string()),
                attributes: HashMap::new(),
                context: HashMap::new(),
            },
            context: HashMap::new(),
            sdk: None,
        };

        let query2 = query1.clone();
        let mut query3 = query1.clone();
        query3.action = "edit".to_string();

        let key1 = generate_allowed_cache_key(&query1).unwrap();
        let key2 = generate_allowed_cache_key(&query2).unwrap();
        let key3 = generate_allowed_cache_key(&query3).unwrap();

        // Same queries should generate same keys
        assert_eq!(key1, key2);

        // Different queries should generate different keys
        assert_ne!(key1, key3);

        // Keys should have the correct prefix
        assert!(key1.starts_with("opa:allowed:"));
        assert!(key3.starts_with("opa:allowed:"));
    }

    #[test]
    fn test_cache_key_collision_resistance() {
        // Test that similar but different queries generate different cache keys
        let base_query = AllowedQuery {
            user: User {
                key: "user".to_string(),
                first_name: None,
                last_name: None,
                email: None,
                attributes: HashMap::new(),
            },
            action: "read".to_string(),
            resource: Resource {
                r#type: "document".to_string(),
                key: Some("doc".to_string()),
                tenant: Some("tenant".to_string()),
                attributes: HashMap::new(),
                context: HashMap::new(),
            },
            context: HashMap::new(),
            sdk: None,
        };

        let mut query_with_different_user = base_query.clone();
        query_with_different_user.user.key = "user2".to_string();

        let mut query_with_different_action = base_query.clone();
        query_with_different_action.action = "write".to_string();

        let mut query_with_context = base_query.clone();
        query_with_context
            .context
            .insert("key".to_string(), serde_json::json!("value"));

        // Generate cache keys
        let key_base = generate_allowed_cache_key(&base_query).unwrap();
        let key_user = generate_allowed_cache_key(&query_with_different_user).unwrap();
        let key_action = generate_allowed_cache_key(&query_with_different_action).unwrap();
        let key_context = generate_allowed_cache_key(&query_with_context).unwrap();

        // All keys should be different
        let keys = [&key_base, &key_user, &key_action, &key_context];
        for (i, key1) in keys.iter().enumerate() {
            for (j, key2) in keys.iter().enumerate() {
                if i != j {
                    assert_ne!(key1, key2, "Cache keys should be unique");
                }
            }
        }
    }

    #[tokio::test]
    async fn test_bulk_cache_efficiency() {
        let mut fixture = TestFixture::new().await;

        // Replace with in-memory cache to test actual caching
        use crate::cache::{memory::InMemoryCache, Cache};
        fixture.state.cache = Arc::new(Cache::InMemory(InMemoryCache::new(60, 128).unwrap()));

        // Create three queries where we'll cache the first two
        let query1 = AllowedQuery {
            user: User {
                key: "user-1".to_string(),
                first_name: None,
                last_name: None,
                email: None,
                attributes: HashMap::new(),
            },
            action: "read".to_string(),
            resource: Resource {
                r#type: "document".to_string(),
                key: Some("doc-1".to_string()),
                tenant: Some("tenant".to_string()),
                attributes: HashMap::new(),
                context: HashMap::new(),
            },
            context: HashMap::new(),
            sdk: None,
        };

        let mut query2 = query1.clone();
        query2.user.key = "user-2".to_string();
        query2.resource.key = Some("doc-2".to_string());

        let mut query3 = query1.clone();
        query3.user.key = "user-3".to_string();
        query3.resource.key = Some("doc-3".to_string());

        let default_control = ClientCacheControl::default();

        // Set up a universal mock for individual caching requests
        use wiremock::{matchers, Mock, ResponseTemplate};
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/data/permit/root"))
            .respond_with(|req: &wiremock::Request| {
                let body_str = String::from_utf8_lossy(&req.body);
                if body_str.contains("user-1") {
                    ResponseTemplate::new(200)
                        .set_body_json(json!({"result": {"allow": true, "result": true}}))
                } else if body_str.contains("user-2") {
                    ResponseTemplate::new(200)
                        .set_body_json(json!({"result": {"allow": false, "result": false}}))
                } else {
                    ResponseTemplate::new(500).set_body_string("Unexpected individual query")
                }
            })
            .expect(2) // Expect exactly 2 individual calls for caching query1 and query2
            .mount(&fixture.opa_mock)
            .await;

        // Cache first two queries individually
        let _ = query_allowed_cached(&fixture.state, &query1, &default_control)
            .await
            .unwrap();
        let _ = query_allowed_cached(&fixture.state, &query2, &default_control)
            .await
            .unwrap();

        // Now test bulk operation - should only query OPA for query3
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/data/permit/bulk"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"result": {"allow": [{"allow": true, "result": true}]}})),
            )
            .expect(1) // Only one bulk call for the uncached query
            .mount(&fixture.opa_mock)
            .await;

        let bulk_result = query_allowed_bulk_cached(
            &fixture.state,
            &[query1.clone(), query2.clone(), query3.clone()],
            &default_control,
        )
        .await
        .unwrap();

        // Verify results
        assert_eq!(bulk_result.allow.len(), 3);
        assert!(bulk_result.allow[0].allow); // From cache (query1)
        assert!(!bulk_result.allow[1].allow); // From cache (query2)
        assert!(bulk_result.allow[2].allow); // From OPA (query3)

        fixture.opa_mock.verify().await;
    }

    #[tokio::test]
    async fn test_bulk_preserves_query_order() {
        let mut fixture = TestFixture::new().await;

        // Replace with in-memory cache to test actual caching
        use crate::cache::{memory::InMemoryCache, Cache};
        fixture.state.cache = Arc::new(Cache::InMemory(InMemoryCache::new(60, 128).unwrap()));

        // Create five queries with distinct identifiable results
        let query_a = AllowedQuery {
            user: User {
                key: "user-a".to_string(),
                first_name: None,
                last_name: None,
                email: None,
                attributes: HashMap::new(),
            },
            action: "read".to_string(),
            resource: Resource {
                r#type: "document".to_string(),
                key: Some("doc-a".to_string()),
                tenant: Some("tenant".to_string()),
                attributes: HashMap::new(),
                context: HashMap::new(),
            },
            context: HashMap::new(),
            sdk: None,
        };

        let mut query_b = query_a.clone();
        query_b.user.key = "user-b".to_string();
        query_b.resource.key = Some("doc-b".to_string());

        let mut query_c = query_a.clone();
        query_c.user.key = "user-c".to_string();
        query_c.resource.key = Some("doc-c".to_string());

        let mut query_d = query_a.clone();
        query_d.user.key = "user-d".to_string();
        query_d.resource.key = Some("doc-d".to_string());

        let mut query_e = query_a.clone();
        query_e.user.key = "user-e".to_string();
        query_e.resource.key = Some("doc-e".to_string());

        let default_control = ClientCacheControl::default();

        // Set up a universal mock that responds differently based on the request content
        use wiremock::{matchers, Mock, ResponseTemplate};
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/data/permit/root"))
            .respond_with(|req: &wiremock::Request| {
                let body_str = String::from_utf8_lossy(&req.body);
                if body_str.contains("user-a") {
                    ResponseTemplate::new(200)
                        .set_body_json(json!({"result": {"allow": true, "result": true}}))
                } else if body_str.contains("user-c") {
                    ResponseTemplate::new(200)
                        .set_body_json(json!({"result": {"allow": false, "result": false}}))
                } else if body_str.contains("user-e") {
                    ResponseTemplate::new(200)
                        .set_body_json(json!({"result": {"allow": true, "result": true}}))
                } else {
                    ResponseTemplate::new(500).set_body_string("Unexpected query")
                }
            })
            .expect(3) // Expect exactly 3 individual calls
            .mount(&fixture.opa_mock)
            .await;

        // Pre-cache queries A, C, and E
        let result_a = query_allowed_cached(&fixture.state, &query_a, &default_control)
            .await
            .unwrap();
        assert!(result_a.allow, "Query A should be cached as true");

        let result_c = query_allowed_cached(&fixture.state, &query_c, &default_control)
            .await
            .unwrap();
        assert!(!result_c.allow, "Query C should be cached as false");

        let result_e = query_allowed_cached(&fixture.state, &query_e, &default_control)
            .await
            .unwrap();
        assert!(result_e.allow, "Query E should be cached as true");

        // Now test bulk operation with order: A(cached=true), B(uncached), C(cached=false), D(uncached), E(cached=true)
        // Should only query OPA for B and D
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/data/permit/bulk"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": {
                    "allow": [
                        {"allow": false, "result": false}, // Result for B
                        {"allow": true, "result": true}    // Result for D
                    ]
                }
            })))
            .expect(1) // Only one bulk call for the uncached queries B and D
            .mount(&fixture.opa_mock)
            .await;

        let bulk_result = query_allowed_bulk_cached(
            &fixture.state,
            &[
                query_a.clone(),
                query_b.clone(),
                query_c.clone(),
                query_d.clone(),
                query_e.clone(),
            ],
            &default_control,
        )
        .await
        .unwrap();

        // Verify results are in the exact same order as input queries
        assert_eq!(bulk_result.allow.len(), 5);

        // Query A (index 0): cached result should be true
        assert!(
            bulk_result.allow[0].allow,
            "Query A result should be true (from cache)"
        );

        // Query B (index 1): OPA result should be false (first result from bulk response)
        assert!(
            !bulk_result.allow[1].allow,
            "Query B result should be false (from OPA)"
        );

        // Query C (index 2): cached result should be false
        assert!(
            !bulk_result.allow[2].allow,
            "Query C result should be false (from cache)"
        );

        // Query D (index 3): OPA result should be true (second result from bulk response)
        assert!(
            bulk_result.allow[3].allow,
            "Query D result should be true (from OPA)"
        );

        // Query E (index 4): cached result should be true
        assert!(
            bulk_result.allow[4].allow,
            "Query E result should be true (from cache)"
        );

        fixture.opa_mock.verify().await;
    }
}
