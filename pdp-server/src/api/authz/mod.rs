pub mod allowed;
pub mod allowed_bulk;
pub mod authorized_users;
pub mod user_permissions;

use crate::state::AppState;
use axum::routing::post;
use axum::Router;

/// Combines all authorization-related routes into a single router
pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/allowed", post(allowed::allowed_handler))
        .route("/allowed/bulk", post(allowed_bulk::allowed_bulk_handler))
        .route(
            "/authorized_users",
            post(authorized_users::authorized_users_handler),
        )
        .route(
            "/user-permissions",
            post(user_permissions::user_permissions_handler),
        )
}
