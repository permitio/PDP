pub mod allowed;
pub mod authorized_users;
pub mod forward_to_opa;
pub mod user_permissions;

use crate::state::AppState;
use axum::routing::post;
use axum::Router;

/// Combines all authorization-related routes into a single router
pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/allowed", post(allowed::allowed_handler))
        .route(
            "/authorized_users",
            post(authorized_users::authorized_users_handler),
        )
        .route(
            "/user-permissions",
            post(user_permissions::user_permissions_handler),
        )
}
