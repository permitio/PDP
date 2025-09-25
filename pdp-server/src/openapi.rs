use utoipa::OpenApi;

pub(crate) const HEALTH_TAG: &str = "Health API";
pub(crate) const AUTHZ_TAG: &str = "Authorization API";
pub(crate) const AUTHZEN_TAG: &str = "AuthZen API";
pub(crate) const OAUTH_TAG: &str = "OAuth 2.0";

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::api::oauth::handlers::authorize,
        crate::api::oauth::handlers::token,
        crate::api::oauth::handlers::introspect
    ),
    components(
        schemas(
            crate::api::oauth::models::AuthorizationRequest,
            crate::api::oauth::models::AuthorizationResponse,
            crate::api::oauth::models::AuthorizationError,
            crate::api::oauth::models::TokenRequest,
            crate::api::oauth::models::TokenResponse,
            crate::api::oauth::models::IntrospectionRequest,
            crate::api::oauth::models::IntrospectionResponse,
            crate::api::oauth::models::OAuthError,
            crate::api::oauth::models::UserAuthenticationRequest,
            crate::api::oauth::models::UserAuthenticationResponse,
            crate::api::oauth::models::PermitCheckWithContextRequest
        )
    ),
    tags(
        (name = HEALTH_TAG, description = "Health check endpoints"),
        (name = AUTHZ_TAG, description = "Authorization endpoints"),
        (name = OAUTH_TAG, description = "OAuth 2.0 Authorization Server endpoints integrated with Permit.io")
    ),
    info(
        title = "Permit.io PDP API",
        description = "Authorization microservice with OAuth 2.0 Authorization Server",
        version = "2.0.0"
    )
)]
pub(crate) struct ApiDoc;
