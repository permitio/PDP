use utoipa::OpenApi;

pub(crate) const HEALTH_TAG: &str = "Health API";
pub(crate) const AUTHZ_TAG: &str = "Authorization API";
pub(crate) const AUTHZEN_TAG: &str = "AuthZen API";

#[derive(OpenApi)]
#[openapi(
    tags(
        (name = HEALTH_TAG, description = "Health check endpoints"),
        (name = AUTHZ_TAG, description = "Authorization endpoints")
    ),
    info(
        title = "Permit.io PDP API",
        description = "Authorization microservice",
        version = "2.0.0"
    )
)]
pub(crate) struct ApiDoc;
