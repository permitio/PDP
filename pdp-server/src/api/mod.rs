mod authn_middleware;
pub(crate) mod authz;
pub(crate) mod authzen;
pub(crate) mod health;
mod horizon_fallback;
pub(crate) mod oauth;

use crate::api::authn_middleware::authentication_middleware;
use crate::api::horizon_fallback::fallback_to_horizon;
use crate::state::AppState;
use axum::{middleware, routing::any, Router};

/// Combines all API routes into a single router
pub(super) fn router(state: &AppState) -> Router<AppState> {
    Router::new()
        .merge(health::router())
        .merge(oauth::router()) // OAuth endpoints don't require API key auth
        .merge(protected_routes(state))
}

/// Creates a router for protected routes that require API key authentication
fn protected_routes(state: &AppState) -> Router<AppState> {
    // Protected routes that require API key authentication
    Router::new()
        .merge(authz::router())
        .merge(authzen::router())
        // Add fallback route to handle any unmatched requests
        .fallback(any(fallback_to_horizon))
        // we must use layer here and not route_layer because, route_layer only
        // affects routes that are defined on the router which doesn't affect fallback
        .layer(middleware::from_fn_with_state(
            state.clone(),
            authentication_middleware,
        ))
}
