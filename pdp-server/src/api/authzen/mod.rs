pub mod evaluation;
pub mod evaluations;
pub mod metadata;
mod schema;
pub mod search_action;
pub mod search_resource;
pub mod search_subject;

use crate::state::AppState;
use axum::routing::{get, post};
use axum::Router;

/// Combines all AuthZen-related routes into a single router
pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/.well-known/authzen-configuration",
            get(metadata::authzen_metadata_handler),
        )
        .route(
            "/access/v1/evaluation",
            post(evaluation::access_evaluation_handler),
        )
        .route(
            "/access/v1/evaluations",
            post(evaluations::access_evaluations_handler),
        )
        .route(
            "/access/v1/search/subject",
            post(search_subject::search_subject_handler),
        )
        .route(
            "/access/v1/search/resource",
            post(search_resource::search_resource_handler),
        )
        .route(
            "/access/v1/search/action",
            post(search_action::search_action_handler),
        )
}
