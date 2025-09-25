//! OAuth 2.0 endpoint handlers

use crate::api::oauth::{
    models::{
        AuthorizationError, AuthorizationRequest, AuthorizationResponse,
        IntrospectionRequest, IntrospectionResponse, OAuthError, TokenRequest, TokenResponse,
        UserAuthenticationRequest,
    },
    permit_client::{PermitClient, PermitError},
    token_manager::{TokenError, TokenManager},
};
use crate::state::AppState;
use axum::{
    async_trait,
    extract::{Form, FromRequest, Query, Request, State},
    http::{header::CONTENT_TYPE, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use log::{debug, error, info, warn};
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;
use utoipa::ToSchema;

/// OAuth 2.0 Authorization endpoint (RFC 6749 Section 4.1.1)
/// Implements user authorization for Authorization Code flow
#[utoipa::path(
    get,
    path = "/authorize",
    params(
        ("response_type" = String, Query, description = "Must be 'code'"),
        ("client_id" = String, Query, description = "Client identifier"),
        ("redirect_uri" = String, Query, description = "Redirect URI"),
        ("scope" = Option<String>, Query, description = "Requested scopes"),
        ("state" = Option<String>, Query, description = "State parameter for CSRF protection"),
        ("code_challenge" = Option<String>, Query, description = "PKCE code challenge"),
        ("code_challenge_method" = Option<String>, Query, description = "PKCE code challenge method")
    ),
    responses(
        (status = 302, description = "Redirect to authorization page or redirect_uri with code"),
        (status = 400, description = "Invalid request", body = AuthorizationError),
        (status = 500, description = "Internal server error", body = AuthorizationError)
    ),
    tag = "OAuth 2.0"
)]
pub async fn authorize(
    State(state): State<AppState>,
    Query(request): Query<AuthorizationRequest>,
) -> Response {
    info!(
        "OAuth authorization request from client_id: {}",
        request.client_id
    );

    // Check if OAuth is enabled
    if !state.config.oauth.enabled {
        return redirect_with_error(
            &request.redirect_uri,
            AuthorizationError::server_error("OAuth 2.0 service is disabled", request.state),
        );
    }

    // Validate response_type
    if request.response_type != "code" {
        return redirect_with_error(
            &request.redirect_uri,
            AuthorizationError::unsupported_response_type(request.state),
        );
    }

    // Validate required parameters
    if request.client_id.is_empty() || request.redirect_uri.is_empty() {
        return redirect_with_error(
            &request.redirect_uri,
            AuthorizationError::invalid_request("client_id and redirect_uri are required", request.state),
        );
    }

    // Validate redirect_uri format
    if Url::parse(&request.redirect_uri).is_err() {
        return error_response(
            StatusCode::BAD_REQUEST,
            Json(AuthorizationError::invalid_request(
                "Invalid redirect_uri format",
                request.state,
            )),
        );
    }

    // Validate client exists
    let permit_client = PermitClient::new(
        state.horizon_client.clone(),
        Some(state.config.oauth.permit_api_url.clone()),
    );

    let client_valid = match permit_client.validate_client(&request.client_id).await {
        Ok(valid) => valid,
        Err(e) => {
            error!("Error validating client: {}", e);
            return redirect_with_error(
                &request.redirect_uri,
                AuthorizationError::server_error("Failed to validate client", request.state),
            );
        }
    };

    if !client_valid {
        return redirect_with_error(
            &request.redirect_uri,
            AuthorizationError::invalid_request("Invalid client_id", request.state),
        );
    }

    // For this simplified implementation, we'll return a simple HTML login form
    // In a real implementation, you'd have a proper UI with session management
    let login_form = format!(
        r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>OAuth 2.0 Authorization</title>
            <style>
                body {{ font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }}
                .form-group {{ margin-bottom: 15px; }}
                label {{ display: block; margin-bottom: 5px; }}
                input {{ width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }}
                button {{ background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }}
                button:hover {{ background: #0056b3; }}
                .scope-list {{ background: #f8f9fa; padding: 10px; border-radius: 4px; margin: 10px 0; }}
            </style>
        </head>
        <body>
            <h2>Authorization Required</h2>
            <p>Application <strong>{}</strong> is requesting access to your account.</p>
            
            <div class="scope-list">
                <strong>Requested permissions:</strong><br>
                {}
            </div>

            <form method="post" action="/oauth/authenticate">
                <input type="hidden" name="client_id" value="{}">
                <input type="hidden" name="redirect_uri" value="{}">
                <input type="hidden" name="scope" value="{}">
                <input type="hidden" name="state" value="{}">
                <input type="hidden" name="code_challenge" value="{}">
                <input type="hidden" name="code_challenge_method" value="{}">
                
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                
                <button type="submit" name="action" value="authorize">Authorize</button>
                <button type="submit" name="action" value="deny">Deny</button>
            </form>
        </body>
        </html>
        "#,
        request.client_id,
        request.scope.as_deref().unwrap_or("No specific scopes requested"),
        request.client_id,
        request.redirect_uri,
        request.scope.as_deref().unwrap_or(""),
        request.state.as_deref().unwrap_or(""),
        request.code_challenge.as_deref().unwrap_or(""),
        request.code_challenge_method.as_deref().unwrap_or("")
    );

    (StatusCode::OK, [("content-type", "text/html")], login_form).into_response()
}

/// OAuth 2.0 Authentication handler (processes login form)
pub async fn authenticate(
    State(state): State<AppState>,
    Form(mut params): Form<std::collections::HashMap<String, String>>,
) -> Response {
    let action = params.get("action").cloned().unwrap_or_default();
    let client_id = params.get("client_id").cloned().unwrap_or_default();
    let redirect_uri = params.get("redirect_uri").cloned().unwrap_or_default();
    let scope = params.get("scope").cloned();
    let state_param = params.get("state").cloned();
    let code_challenge = params.get("code_challenge").cloned();
    let code_challenge_method = params.get("code_challenge_method").cloned();

    // Check if user denied authorization
    if action == "deny" {
        return redirect_with_error(
            &redirect_uri,
            AuthorizationError::access_denied("User denied authorization", state_param),
        );
    }

    let username = params.get("username").cloned().unwrap_or_default();
    let password = params.get("password").cloned().unwrap_or_default();

    if username.is_empty() || password.is_empty() {
        return redirect_with_error(
            &redirect_uri,
            AuthorizationError::invalid_request("Username and password are required", state_param),
        );
    }

    // Authenticate user
    let permit_client = PermitClient::new(
        state.horizon_client.clone(),
        Some(state.config.oauth.permit_api_url.clone()),
    );

    let user = match permit_client.authenticate_user(&username, &password).await {
        Ok(user) => user,
        Err(PermitError::InvalidCredentials) | Err(PermitError::UserNotFound(_)) => {
            return redirect_with_error(
                &redirect_uri,
                AuthorizationError::access_denied("Invalid username or password", state_param),
            );
        }
        Err(e) => {
            error!("Error authenticating user: {}", e);
            return redirect_with_error(
                &redirect_uri,
                AuthorizationError::server_error("Authentication failed", state_param),
            );
        }
    };

    // Generate authorization code
    let token_manager = TokenManager::new(
        state.cache.as_ref().clone(),
        state.config.oauth.token_ttl,
    );

    let requested_scopes = if let Some(scope_str) = &scope {
        scope_str.split_whitespace().map(|s| s.to_string()).collect()
    } else {
        Vec::new()
    };

    let (auth_code, _) = match token_manager
        .generate_authorization_code(
            &user.id,
            &client_id,
            &redirect_uri,
            requested_scopes,
            code_challenge,
            code_challenge_method,
        )
        .await
    {
        Ok(code_data) => code_data,
        Err(e) => {
            error!("Error generating authorization code: {}", e);
            return redirect_with_error(
                &redirect_uri,
                AuthorizationError::server_error("Failed to generate authorization code", state_param),
            );
        }
    };

    info!(
        "Generated authorization code for user '{}' via client '{}'",
        user.id, client_id
    );

    // Redirect back to client with authorization code
    let mut redirect_url = Url::parse(&redirect_uri).unwrap();
    redirect_url.query_pairs_mut()
        .append_pair("code", &auth_code);
    
    if let Some(state_val) = &state_param {
        redirect_url.query_pairs_mut()
            .append_pair("state", state_val);
    }

    Redirect::to(redirect_url.as_str()).into_response()
}

/// OAuth 2.0 Token endpoint (RFC 6749)
/// Supports both Authorization Code and Client Credentials flows
#[utoipa::path(
    post,
    path = "/token",
    request_body = TokenRequest,
    responses(
        (status = 200, description = "Access token issued successfully", body = TokenResponse),
        (status = 400, description = "Invalid request", body = OAuthError),
        (status = 401, description = "Invalid client credentials", body = OAuthError),
        (status = 500, description = "Internal server error", body = OAuthError)
    ),
    tag = "OAuth 2.0"
)]
pub async fn token(
    State(state): State<AppState>,
    Form(request): Form<TokenRequest>,
) -> Response {
    info!(
        "OAuth token request from client_id: {} with grant_type: {}",
        request.client_id, request.grant_type
    );

    // Check if OAuth is enabled
    if !state.config.oauth.enabled {
        warn!("OAuth 2.0 endpoints are disabled");
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            OAuthError::server_error("OAuth 2.0 service is disabled"),
        );
    }

    // Validate request parameters
    if request.client_id.is_empty() || request.client_secret.is_empty() {
        warn!("Missing client credentials in token request");
        return error_response(
            StatusCode::BAD_REQUEST,
            OAuthError::invalid_request("client_id and client_secret are required"),
        );
    }

    // Route to appropriate flow based on grant_type
    match request.grant_type.as_str() {
        "authorization_code" => handle_authorization_code_flow(state, request).await,
        "client_credentials" => handle_client_credentials_flow(state, request).await,
        _ => {
            warn!(
                "Unsupported grant type '{}' from client '{}'", 
                request.grant_type, request.client_id
            );
            error_response(
                StatusCode::BAD_REQUEST,
                OAuthError::unsupported_grant_type(),
            )
        }
    }
}

/// Handle Authorization Code flow token exchange
async fn handle_authorization_code_flow(
    state: AppState,
    request: TokenRequest,
) -> Response {
    // Validate authorization code flow parameters
    let code = match &request.code {
        Some(code) => code,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                OAuthError::invalid_request("code parameter is required for authorization_code grant"),
            );
        }
    };

    let redirect_uri = match &request.redirect_uri {
        Some(uri) => uri,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                OAuthError::invalid_request("redirect_uri parameter is required for authorization_code grant"),
            );
        }
    };

    // Create token manager
    let token_manager = TokenManager::new(
        state.cache.as_ref().clone(),
        state.config.oauth.token_ttl,
    );

    // Validate and consume authorization code
    let stored_code = match token_manager
        .validate_authorization_code(
            code,
            &request.client_id,
            redirect_uri,
            request.code_verifier.as_deref(),
        )
        .await
    {
        Ok(code) => code,
        Err(TokenError::CodeNotFound) => {
            warn!("Invalid or expired authorization code");
            return error_response(
                StatusCode::BAD_REQUEST,
                OAuthError::invalid_grant("Invalid or expired authorization code"),
            );
        }
        Err(TokenError::RedirectUriMismatch) => {
            warn!("Redirect URI mismatch in token request");
            return error_response(
                StatusCode::BAD_REQUEST,
                OAuthError::invalid_grant("redirect_uri does not match authorization request"),
            );
        }
        Err(TokenError::PkceValidation(msg)) => {
            warn!("PKCE validation failed: {}", msg);
            return error_response(
                StatusCode::BAD_REQUEST,
                OAuthError::invalid_grant(&format!("PKCE validation failed: {}", msg)),
            );
        }
        Err(e) => {
            error!("Error validating authorization code: {}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                OAuthError::server_error("Failed to validate authorization code"),
            );
        }
    };

    // Generate access token for the user
    let (access_token, _) = match token_manager
        .generate_token(
            &stored_code.user_id,
            &request.client_id,
            stored_code.requested_scopes.clone(),
        )
        .await
    {
        Ok(token_data) => token_data,
        Err(e) => {
            error!("Error generating access token: {}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                OAuthError::server_error("Failed to generate access token"),
            );
        }
    };

    info!(
        "Successfully issued access token for user '{}' via client '{}' with {} scopes",
        stored_code.user_id,
        request.client_id,
        stored_code.requested_scopes.len()
    );

    let response = TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: state.config.oauth.token_ttl,
        scope: stored_code.requested_scopes.join(" "),
    };

    Json(response).into_response()
}

/// Handle Client Credentials flow (for service accounts)
async fn handle_client_credentials_flow(
    state: AppState,
    request: TokenRequest,
) -> Response {
    // Create Permit client
    let permit_client = PermitClient::new(
        state.horizon_client.clone(), 
        Some(state.config.oauth.permit_api_url.clone())
    );

    // Validate client credentials with Permit
    let user = match permit_client
        .validate_client_credentials(&request.client_id, &request.client_secret)
        .await
    {
        Ok(user) => user,
        Err(PermitError::InvalidCredentials) | Err(PermitError::UserNotFound(_)) => {
            warn!(
                "Invalid client credentials for client_id: {}",
                request.client_id
            );
            return error_response(
                StatusCode::UNAUTHORIZED,
                OAuthError::invalid_client("Invalid client credentials"),
            );
        }
        Err(e) => {
            error!("Error validating client credentials: {}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                OAuthError::server_error("Failed to validate client credentials"),
            );
        }
    };

    // Get user permissions from Permit and convert to scopes
    let resource_types = state.config.oauth.get_resource_types();
    
    let permissions = match permit_client
        .get_user_permissions(&user.id, &resource_types)
        .await
    {
        Ok(permissions) => permissions,
        Err(e) => {
            error!("Error fetching user permissions: {}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                OAuthError::server_error("Failed to fetch user permissions"),
            );
        }
    };

    let granted_scopes = permit_client.permissions_to_scopes(&permissions);

    // Filter requested scopes if provided
    let final_scopes = if let Some(requested_scopes) = &request.scope {
        let requested: Vec<&str> = requested_scopes.split_whitespace().collect();
        granted_scopes
            .into_iter()
            .filter(|scope| requested.contains(&scope.as_str()))
            .collect()
    } else {
        granted_scopes
    };

    debug!(
        "Granting {} scopes to service account '{}': {:?}",
        final_scopes.len(),
        request.client_id,
        final_scopes
    );

    // Generate access token (for client credentials, user_id and client_id are the same)
    let token_manager = TokenManager::new(
        state.cache.as_ref().clone(),
        state.config.oauth.token_ttl,
    );

    let (access_token, _) = match token_manager
        .generate_token(&user.id, &request.client_id, final_scopes.clone())
        .await
    {
        Ok(token_data) => token_data,
        Err(e) => {
            error!("Error generating access token: {}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                OAuthError::server_error("Failed to generate access token"),
            );
        }
    };

    info!(
        "Successfully issued access token to service account '{}' with {} scopes",
        request.client_id,
        final_scopes.len()
    );

    let response = TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: state.config.oauth.token_ttl,
        scope: final_scopes.join(" "),
    };

    Json(response).into_response()
}

/// OAuth 2.0 Token Introspection endpoint (RFC 7662)
/// Validates tokens and optionally performs real-time authorization checks
/// Supports both form-encoded and JSON request bodies
#[utoipa::path(
    post,
    path = "/introspect",
    request_body = IntrospectionRequest,
    responses(
        (status = 200, description = "Token introspection result", body = IntrospectionResponse),
        (status = 400, description = "Invalid request", body = OAuthError),
        (status = 500, description = "Internal server error", body = OAuthError)
    ),
    tag = "OAuth 2.0"
)]
pub async fn introspect(
    State(state): State<AppState>,
    request: IntrospectionRequestExtractor,
) -> Response {
    debug!("OAuth introspection request for token");

    // Validate request
    if request.token.is_empty() {
        warn!("Empty token in introspection request");
        return error_response(
            StatusCode::BAD_REQUEST,
            OAuthError::invalid_request("token parameter is required"),
        );
    }

    // Check if OAuth is enabled
    if !state.config.oauth.enabled {
        return Json(IntrospectionResponse {
            active: false,
            client_id: None,
            scope: None,
            exp: None,
            iat: None,
            iss: None,
            allowed: None,
        })
        .into_response();
    }

    let token_manager = TokenManager::new(
        state.cache.as_ref().clone(),
        state.config.oauth.token_ttl,
    );

    // Validate token
    let stored_token = match token_manager.validate_token(&request.token).await {
        Ok(token) => token,
        Err(TokenError::NotFound) => {
            debug!("Token not found or expired during introspection");
            return Json(IntrospectionResponse {
                active: false,
                client_id: None,
                scope: None,
                exp: None,
                iat: None,
                iss: None,
                allowed: None,
            })
            .into_response();
        }
        Err(e) => {
            error!("Error validating token during introspection: {}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                OAuthError::server_error("Failed to validate token"),
            );
        }
    };

    debug!(
        "Token introspection: user_id={}, client_id={}, scopes={:?}",
        stored_token.user_id, stored_token.client_id, stored_token.requested_scopes
    );

    // Perform real-time authorization check if resource and action provided
    let allowed = if let (Some(resource), Some(action)) = (&request.resource, &request.action) {
        let permit_client = PermitClient::new(
            state.horizon_client.clone(), 
            Some(state.config.oauth.permit_api_url.clone())
        );
        
        // Check if the token has the required scope
        let required_scope = format!("{}:{}", resource, action);
        let has_scope = permit_client.has_scope(&stored_token.requested_scopes, &required_scope);
        
        if !has_scope {
            debug!(
                "Token missing required scope '{}' for real-time authorization check",
                required_scope
            );
            Some(false)
        } else {
            // Perform real-time check with Permit using the user_id from the token
            match permit_client
                .check_permission_with_context(&stored_token.user_id, action, resource, request.context.clone())
                .await
            {
                Ok(result) => {
                    debug!(
                        "Real-time authorization check: user={}, resource={}, action={}, allowed={}",
                        stored_token.user_id, resource, action, result
                    );
                    Some(result)
                }
                Err(e) => {
                    warn!("Error performing real-time authorization check: {}", e);
                    // Don't fail the introspection, just omit the allowed field
                    None
                }
            }
        }
    } else {
        None
    };

    info!(
        "Token introspection successful: user_id={}, client_id={}, active=true{}",
        stored_token.user_id,
        stored_token.client_id,
        if allowed.is_some() {
            format!(", real-time_check={:?}", allowed)
        } else {
            String::new()
        }
    );

    let response = IntrospectionResponse {
        active: true,
        client_id: Some(stored_token.client_id),
        scope: Some(stored_token.requested_scopes.join(" ")),
        exp: Some(stored_token.expires_at),
        iat: Some(stored_token.issued_at),
        iss: Some(state.config.oauth.issuer.clone()),
        allowed,
    };

    Json(response).into_response()
}

/// Custom extractor that handles both form-encoded and JSON introspection requests
pub struct IntrospectionRequestExtractor {
    pub token: String,
    pub resource: Option<String>,
    pub action: Option<String>,
    pub context: Option<serde_json::Value>,
}

#[async_trait]
impl<S> FromRequest<S> for IntrospectionRequestExtractor
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let content_type = req
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|ct| ct.to_str().ok())
            .unwrap_or("");

        if content_type.starts_with("application/json") {
            // Handle JSON request
            match Json::<IntrospectionRequest>::from_request(req, state).await {
                Ok(Json(request)) => Ok(IntrospectionRequestExtractor {
                    token: request.token,
                    resource: request.resource,
                    action: request.action,
                    context: request.context,
                }),
                Err(_) => Err(error_response(
                    StatusCode::BAD_REQUEST,
                    OAuthError::invalid_request("Invalid JSON in request body"),
                )),
            }
        } else {
            // Handle form-encoded request (default)
            match Form::<IntrospectionRequest>::from_request(req, state).await {
                Ok(Form(request)) => Ok(IntrospectionRequestExtractor {
                    token: request.token,
                    resource: request.resource,
                    action: request.action,
                    context: request.context,
                }),
                Err(_) => Err(error_response(
                    StatusCode::BAD_REQUEST,
                    OAuthError::invalid_request("Invalid form data in request body"),
                )),
            }
        }
    }
}

/// Helper function to create error responses
fn error_response(status: StatusCode, error: OAuthError) -> Response {
    (status, Json(error)).into_response()
}

/// Helper function to redirect with authorization error
fn redirect_with_error(redirect_uri: &str, error: AuthorizationError) -> Response {
    match Url::parse(redirect_uri) {
        Ok(mut url) => {
            url.query_pairs_mut()
                .append_pair("error", &error.error)
                .append_pair("error_description", error.error_description.as_deref().unwrap_or(""));
            
            if let Some(state) = &error.state {
                url.query_pairs_mut()
                    .append_pair("state", state);
            }
            
            Redirect::to(url.as_str()).into_response()
        }
        Err(_) => {
            // If redirect_uri is invalid, return error as JSON
            error_response(
                StatusCode::BAD_REQUEST,
                OAuthError::invalid_request("Invalid redirect_uri"),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{memory::InMemoryCache, Cache};
    use crate::config::PDPConfig;
    use crate::state::AppState;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use serde_json::json;
    use tower::ServiceExt;

    async fn create_test_app_state() -> AppState {
        let config = PDPConfig {
            api_key: "test-api-key".to_string(),
            debug: Some(true),
            port: 3000,
            use_new_authorized_users: false,
            healthcheck_timeout: 1.0,
            horizon: crate::config::horizon::HorizonConfig {
                host: "localhost".to_string(),
                port: 3001,
                python_path: "python3".to_string(),
                client_timeout: 60,
                health_check_timeout: 1,
                health_check_interval: 5,
                health_check_failure_threshold: 12,
                startup_delay: 5,
                restart_interval: 1,
                termination_timeout: 30,
            },
            opa: crate::config::opa::OpaConfig {
                url: "http://localhost:8181".to_string(),
                client_query_timeout: 5,
            },
            cache: crate::config::cache::CacheConfig {
                ttl: 60,
                store: crate::config::cache::CacheStore::InMemory,
                memory: crate::config::cache::InMemoryConfig { capacity: 128 },
                redis: crate::config::cache::RedisConfig::default(),
            },
            oauth: crate::config::oauth::OAuthConfig::default(),
        };
        
        AppState::for_testing(&config)
    }

    #[tokio::test]
    async fn test_token_endpoint_invalid_grant_type() {
        let state = create_test_app_state().await;
        
        let request = Request::builder()
            .method("POST")
            .uri("/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(
                "grant_type=authorization_code&client_id=test&client_secret=secret",
            ))
            .unwrap();

        let response = crate::create_app(state)
            .await
            .oneshot(request)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_token_endpoint_missing_credentials() {
        let state = create_test_app_state().await;
        
        let request = Request::builder()
            .method("POST")
            .uri("/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from("grant_type=client_credentials&client_id="))
            .unwrap();

        let response = crate::create_app(state)
            .await
            .oneshot(request)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_introspect_endpoint_missing_token() {
        let state = create_test_app_state().await;
        
        let request = Request::builder()
            .method("POST")
            .uri("/introspect")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from("token="))
            .unwrap();

        let response = crate::create_app(state)
            .await
            .oneshot(request)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_introspect_endpoint_invalid_token() {
        let state = create_test_app_state().await;
        
        let request = Request::builder()
            .method("POST")
            .uri("/introspect")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from("token=invalid_token"))
            .unwrap();

        let response = crate::create_app(state)
            .await
            .oneshot(request)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        
        // Should return active: false for invalid token
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let introspection_response: IntrospectionResponse = 
            serde_json::from_slice(&body).unwrap();
        assert!(!introspection_response.active);
    }
}