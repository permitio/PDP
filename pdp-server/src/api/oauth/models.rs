//! OAuth 2.0 data models and request/response structures

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;
use url::Url;

/// OAuth 2.0 Authorization Request (Authorization Code Flow)
#[derive(Debug, Deserialize, ToSchema)]
pub struct AuthorizationRequest {
    /// Response type - must be "code"
    pub response_type: String,
    /// Client identifier
    pub client_id: String,
    /// Redirect URI where authorization code will be sent
    pub redirect_uri: String,
    /// Requested scopes (space-separated)
    pub scope: Option<String>,
    /// State parameter for CSRF protection
    pub state: Option<String>,
    /// PKCE code challenge
    pub code_challenge: Option<String>,
    /// PKCE code challenge method (S256 or plain)
    pub code_challenge_method: Option<String>,
}

/// OAuth 2.0 Authorization Response
#[derive(Debug, Serialize, ToSchema)]
pub struct AuthorizationResponse {
    /// Authorization code
    pub code: String,
    /// State parameter (if provided in request)
    pub state: Option<String>,
}

/// OAuth 2.0 Authorization Error Response
#[derive(Debug, Serialize, ToSchema)]
pub struct AuthorizationError {
    /// Error code
    pub error: String,
    /// Human-readable error description
    pub error_description: Option<String>,
    /// State parameter (if provided in request)
    pub state: Option<String>,
}

/// OAuth 2.0 Token Request (supports both Authorization Code and Client Credentials)
#[derive(Debug, Deserialize, ToSchema)]
pub struct TokenRequest {
    /// OAuth 2.0 grant type - "authorization_code" or "client_credentials"
    pub grant_type: String,
    /// Client identifier
    pub client_id: String,
    /// Client secret
    pub client_secret: String,
    /// Authorization code (for authorization_code grant)
    pub code: Option<String>,
    /// Redirect URI (for authorization_code grant, must match authorization request)
    pub redirect_uri: Option<String>,
    /// PKCE code verifier (for authorization_code grant with PKCE)
    pub code_verifier: Option<String>,
    /// Optional requested scopes (space-separated, for client_credentials grant)
    pub scope: Option<String>,
}

/// OAuth 2.0 Token Response
#[derive(Debug, Serialize, ToSchema)]
pub struct TokenResponse {
    /// The access token string
    pub access_token: String,
    /// Token type - always "Bearer"
    pub token_type: String,
    /// Token expiration in seconds
    pub expires_in: u64,
    /// Granted scopes (space-separated)
    pub scope: String,
}

/// OAuth 2.0 Token Introspection Request
#[derive(Debug, Deserialize, ToSchema)]
pub struct IntrospectionRequest {
    /// The token to introspect
    pub token: String,
    /// Optional resource for real-time authorization check
    pub resource: Option<String>,
    /// Optional action for real-time authorization check
    pub action: Option<String>,
    /// Optional context for more complex authorization checks
    pub context: Option<serde_json::Value>,
}

/// Enhanced Permit.io permission check request with context
#[derive(Debug, Serialize)]
pub struct PermitCheckWithContextRequest {
    /// User performing the action
    pub user: String,
    /// Action being performed
    pub action: String,
    /// Resource being accessed
    pub resource: String,
    /// Additional context for the authorization check
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
}

/// OAuth 2.0 Token Introspection Response
#[derive(Debug, Serialize, ToSchema)]
pub struct IntrospectionResponse {
    /// Whether the token is active
    pub active: bool,
    /// Client identifier that was issued the token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Token scopes (space-separated)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Token expiration timestamp (Unix time)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    /// Token issued at timestamp (Unix time)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,
    /// Token issuer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Real-time authorization result (if resource/action provided)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed: Option<bool>,
}

/// OAuth 2.0 Error Response
#[derive(Debug, Serialize, ToSchema)]
pub struct OAuthError {
    /// Error code
    pub error: String,
    /// Human-readable error description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

/// Token storage model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredToken {
    /// User ID (subject) that owns this token
    pub user_id: String,
    /// Client ID that requested this token
    pub client_id: String,
    /// Requested scopes (what user requested access to)
    pub requested_scopes: Vec<String>,
    /// Token expiration timestamp
    pub expires_at: u64,
    /// Token issued at timestamp
    pub issued_at: u64,
}

/// Authorization code storage model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAuthorizationCode {
    /// User ID that authorized this code
    pub user_id: String,
    /// Client ID that requested authorization
    pub client_id: String,
    /// Redirect URI (must match token request)
    pub redirect_uri: String,
    /// Requested scopes
    pub requested_scopes: Vec<String>,
    /// PKCE code challenge (if used)
    pub code_challenge: Option<String>,
    /// PKCE code challenge method (if used)
    pub code_challenge_method: Option<String>,
    /// Code expiration timestamp (short-lived, ~10 minutes)
    pub expires_at: u64,
    /// Code issued at timestamp
    pub issued_at: u64,
}

/// User authentication request
#[derive(Debug, Deserialize, ToSchema)]
pub struct UserAuthenticationRequest {
    /// Username or email
    pub username: String,
    /// Password
    pub password: String,
}

/// User authentication response
#[derive(Debug, Serialize, ToSchema)]
pub struct UserAuthenticationResponse {
    /// Whether authentication was successful
    pub authenticated: bool,
    /// User ID if authenticated
    pub user_id: Option<String>,
    /// Error message if authentication failed
    pub error: Option<String>,
}

/// Permit.io user/client representation
#[derive(Debug, Deserialize)]
pub struct PermitUser {
    pub id: String,
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub attributes: Option<HashMap<String, serde_json::Value>>,
}

/// Permit.io permission check request
#[derive(Debug, Serialize)]
pub struct PermitCheckRequest {
    pub user: String,
    pub action: String,
    pub resource: String,
}

/// Permit.io permission check response
#[derive(Debug, Deserialize)]
pub struct PermitCheckResponse {
    pub allow: bool,
}

/// Permit.io bulk permission check request
#[derive(Debug, Serialize)]
pub struct PermitBulkCheckRequest {
    pub user: String,
    pub resource_types: Vec<String>,
}

/// Permit.io bulk permission check response
#[derive(Debug, Deserialize)]
pub struct PermitBulkCheckResponse {
    pub checks: HashMap<String, HashMap<String, bool>>,
}

impl OAuthError {
    /// Create an invalid_request error
    pub fn invalid_request(description: &str) -> Self {
        Self {
            error: "invalid_request".to_string(),
            error_description: Some(description.to_string()),
        }
    }

    /// Create an invalid_client error
    pub fn invalid_client(description: &str) -> Self {
        Self {
            error: "invalid_client".to_string(),
            error_description: Some(description.to_string()),
        }
    }

    /// Create an invalid_grant error
    pub fn invalid_grant(description: &str) -> Self {
        Self {
            error: "invalid_grant".to_string(),
            error_description: Some(description.to_string()),
        }
    }

    /// Create an unsupported_grant_type error
    pub fn unsupported_grant_type() -> Self {
        Self {
            error: "unsupported_grant_type".to_string(),
            error_description: Some("Supported grant types: authorization_code, client_credentials".to_string()),
        }
    }

    /// Create an unsupported_response_type error
    pub fn unsupported_response_type() -> Self {
        Self {
            error: "unsupported_response_type".to_string(),
            error_description: Some("Only 'code' response type is supported".to_string()),
        }
    }

    /// Create an access_denied error
    pub fn access_denied(description: &str) -> Self {
        Self {
            error: "access_denied".to_string(),
            error_description: Some(description.to_string()),
        }
    }

    /// Create a server_error
    pub fn server_error(description: &str) -> Self {
        Self {
            error: "server_error".to_string(),
            error_description: Some(description.to_string()),
        }
    }
}

impl AuthorizationError {
    /// Create an invalid_request error for authorization
    pub fn invalid_request(description: &str, state: Option<String>) -> Self {
        Self {
            error: "invalid_request".to_string(),
            error_description: Some(description.to_string()),
            state,
        }
    }

    /// Create an unsupported_response_type error for authorization
    pub fn unsupported_response_type(state: Option<String>) -> Self {
        Self {
            error: "unsupported_response_type".to_string(),
            error_description: Some("Only 'code' response type is supported".to_string()),
            state,
        }
    }

    /// Create an access_denied error for authorization
    pub fn access_denied(description: &str, state: Option<String>) -> Self {
        Self {
            error: "access_denied".to_string(),
            error_description: Some(description.to_string()),
            state,
        }
    }

    /// Create a server_error for authorization
    pub fn server_error(description: &str, state: Option<String>) -> Self {
        Self {
            error: "server_error".to_string(),
            error_description: Some(description.to_string()),
            state,
        }
    }
}