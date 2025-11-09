pub mod allowed;
mod checks;
pub mod column_mask;
pub mod row_filter;
pub mod schemas;

use crate::state::AppState;
use axum::routing::post;
use axum::Router;

/// Combines all Trino-related routes into a single router
pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/trino/allowed", post(allowed::allowed_handler))
        .route("/trino/row-filter", post(row_filter::row_filter_handler))
        .route(
            "/trino/batch-column-masking",
            post(column_mask::column_mask_handler),
        )
}
