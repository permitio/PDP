//! OAuth 2.0 Authorization Server implementation integrated with Permit.io
//!
//! This module provides OAuth 2.0 endpoints that integrate with Permit.io's Fine-Grained
//! Authorization (FGA) system to provide a unified authorization stack.
//!
//! ## Supported OAuth 2.0 Flows
//! - Client Credentials Grant (RFC 6749 Section 4.4)
//! - Token Introspection (RFC 7662)
//!
//! ## Architecture
//! - Uses Permit.io as the single source of truth for client credentials and permissions
//! - Converts Permit permissions to OAuth scopes using `resource:action` format
//! - Stores tokens in cache (Redis/memory) with configurable TTL
//! - Performs real-time authorization checks during token introspection

pub mod handlers;
pub mod models;
pub mod permit_client;
pub mod token_manager;

use crate::state::AppState;
use axum::{
    routing::{get, post, Router},
};

/// Creates OAuth 2.0 routes
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/authorize", get(handlers::authorize))
        .route("/oauth/authenticate", post(handlers::authenticate))
        .route("/token", post(handlers::token))
        .route("/introspect", post(handlers::introspect))
}