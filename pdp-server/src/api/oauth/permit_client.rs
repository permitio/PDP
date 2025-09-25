//! Permit.io API client for OAuth integration

use crate::api::oauth::models::{
    PermitBulkCheckRequest, PermitBulkCheckResponse, PermitCheckRequest, PermitCheckResponse,
    PermitCheckWithContextRequest, PermitUser,
};
use log::{debug, error, warn};
use reqwest::Client;
use std::collections::HashMap;
use thiserror::Error;

/// Errors that can occur during Permit API operations
#[derive(Debug, Error)]
pub enum PermitError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Authentication failed: invalid client credentials")]
    InvalidCredentials,
    #[error("User not found: {0}")]
    UserNotFound(String),
    #[error("Permission denied")]
    PermissionDenied,
    #[error("API response error: {0}")]
    ApiError(String),
    #[error("Configuration error: {0}")]
    Config(String),
}

/// Permit.io API client
#[derive(Clone)]
pub struct PermitClient {
    client: Client,
    base_url: String,
}

impl PermitClient {
    /// Create a new Permit client
    pub fn new(client: Client, base_url: Option<String>) -> Self {
        let base_url = base_url.unwrap_or_else(|| "https://api.permit.io".to_string());
        Self { client, base_url }
    }

    /// Authenticate a user with username/password
    /// This is a simplified implementation - in production you'd want proper password hashing
    pub async fn authenticate_user(
        &self,
        username: &str,
        password: &str,
    ) -> Result<PermitUser, PermitError> {
        debug!("Authenticating user: {}", username);

        // Get user information from Permit
        let user = self.get_user(username).await?;

        // Check if user has authentication credentials
        // In a real implementation, you'd validate against stored password hash
        // For demo purposes, we'll check for a password attribute or use a simple check
        let stored_password = user
            .attributes
            .as_ref()
            .and_then(|attrs| attrs.get("password"))
            .and_then(|v| v.as_str())
            .unwrap_or("password123"); // Default demo password

        if password != stored_password {
            warn!("Invalid password for user: {}", username);
            return Err(PermitError::InvalidCredentials);
        }

        debug!("Successfully authenticated user: {}", username);
        Ok(user)
    }

    /// Validate OAuth client credentials by checking if the user exists in Permit
    /// and has the service_account client_type attribute
    pub async fn validate_client_credentials(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Result<PermitUser, PermitError> {
        debug!("Validating client credentials for client_id: {}", client_id);

        // Get user information from Permit
        let user = self.get_user(client_id).await?;

        // Check if the user has client_type: service_account
        let is_service_account = user
            .attributes
            .as_ref()
            .and_then(|attrs| attrs.get("client_type"))
            .and_then(|v| v.as_str())
            .map(|s| s == "service_account")
            .unwrap_or(false);

        if !is_service_account {
            warn!(
                "Client '{}' does not have client_type: service_account",
                client_id
            );
            return Err(PermitError::InvalidCredentials);
        }

        // In a real implementation, you would validate the client_secret
        // For now, we'll assume it's handled by the API key authentication
        // or stored in Permit user attributes

        debug!("Successfully validated client credentials for: {}", client_id);
        Ok(user)
    }

    /// Validate OAuth client (without credentials, just check if client exists)
    pub async fn validate_client(&self, client_id: &str) -> Result<bool, PermitError> {
        debug!("Validating client existence for client_id: {}", client_id);
        
        match self.get_user(client_id).await {
            Ok(_) => Ok(true),
            Err(PermitError::UserNotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Get user information from Permit
    pub async fn get_user(&self, user_id: &str) -> Result<PermitUser, PermitError> {
        let url = format!("{}/v2/facts/users/{}", self.base_url, user_id);

        debug!("Fetching user from Permit: {}", url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(PermitError::Http)?;

        if response.status() == 404 {
            return Err(PermitError::UserNotFound(user_id.to_string()));
        }

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            error!("Permit API error {}: {}", status, error_text);
            return Err(PermitError::ApiError(format!(
                "HTTP {}: {}",
                status, error_text
            )));
        }

        let user: PermitUser = response
            .json()
            .await
            .map_err(|e| PermitError::ApiError(format!("JSON parse error: {e}")))?;

        debug!("Successfully fetched user: {}", user.id);
        Ok(user)
    }

    /// Check a specific permission
    pub async fn check_permission(
        &self,
        user_id: &str,
        action: &str,
        resource: &str,
    ) -> Result<bool, PermitError> {
        self.check_permission_with_context(user_id, action, resource, None).await
    }

    /// Check a specific permission with additional context
    pub async fn check_permission_with_context(
        &self,
        user_id: &str,
        action: &str,
        resource: &str,
        context: Option<serde_json::Value>,
    ) -> Result<bool, PermitError> {
        let url = format!("{}/v2/allowed", self.base_url);

        let request = if context.is_some() {
            // Use the context-aware request format
            serde_json::to_value(PermitCheckWithContextRequest {
                user: user_id.to_string(),
                action: action.to_string(),
                resource: resource.to_string(),
                context,
            }).map_err(|e| PermitError::ApiError(format!("JSON serialization error: {e}")))?
        } else {
            // Use the simple request format
            serde_json::to_value(PermitCheckRequest {
                user: user_id.to_string(),
                action: action.to_string(),
                resource: resource.to_string(),
            }).map_err(|e| PermitError::ApiError(format!("JSON serialization error: {e}")))?
        };

        debug!(
            "Checking permission: user={}, action={}, resource={}, context={:?}",
            user_id, action, resource, context
        );

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(PermitError::Http)?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            error!("Permit permission check error {}: {}", status, error_text);
            return Err(PermitError::ApiError(format!(
                "HTTP {}: {}",
                status, error_text
            )));
        }

        let check_response: PermitCheckResponse = response
            .json()
            .await
            .map_err(|e| PermitError::ApiError(format!("JSON parse error: {e}")))?;

        debug!(
            "Permission check result: user={}, action={}, resource={}, allowed={}",
            user_id, action, resource, check_response.allow
        );

        Ok(check_response.allow)
    }

    /// Get all permissions for a user (bulk check)
    /// Returns a map of resource_type -> action -> allowed
    pub async fn get_user_permissions(
        &self,
        user_id: &str,
        resource_types: &[String],
    ) -> Result<HashMap<String, HashMap<String, bool>>, PermitError> {
        let url = format!("{}/v2/allowed/bulk", self.base_url);

        let request = PermitBulkCheckRequest {
            user: user_id.to_string(),
            resource_types: resource_types.to_vec(),
        };

        debug!(
            "Getting bulk permissions for user '{}' on resource types: {:?}",
            user_id, resource_types
        );

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(PermitError::Http)?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            error!("Permit bulk check error {}: {}", status, error_text);
            return Err(PermitError::ApiError(format!(
                "HTTP {}: {}",
                status, error_text
            )));
        }

        let bulk_response: PermitBulkCheckResponse = response
            .json()
            .await
            .map_err(|e| PermitError::ApiError(format!("JSON parse error: {e}")))?;

        debug!(
            "Retrieved {} resource types with permissions for user '{}'",
            bulk_response.checks.len(),
            user_id
        );

        Ok(bulk_response.checks)
    }

    /// Convert Permit permissions to OAuth scopes
    /// Scopes follow the format: resource_type:action
    pub fn permissions_to_scopes(
        &self,
        permissions: &HashMap<String, HashMap<String, bool>>,
    ) -> Vec<String> {
        let mut scopes = Vec::new();

        for (resource_type, actions) in permissions {
            for (action, allowed) in actions {
                if *allowed {
                    scopes.push(format!("{}:{}", resource_type, action));
                }
            }
        }

        scopes.sort();
        debug!("Converted permissions to {} OAuth scopes", scopes.len());
        scopes
    }

    /// Parse OAuth scope back to resource and action
    pub fn parse_scope(&self, scope: &str) -> Option<(String, String)> {
        if let Some((resource, action)) = scope.split_once(':') {
            Some((resource.to_string(), action.to_string()))
        } else {
            None
        }
    }

    /// Check if a token has a specific scope
    pub fn has_scope(&self, token_scopes: &[String], required_scope: &str) -> bool {
        token_scopes.iter().any(|scope| scope == required_scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_client() -> PermitClient {
        let client = Client::new();
        PermitClient::new(client, Some("https://api.test.permit.io".to_string()))
    }

    #[test]
    fn test_permissions_to_scopes() {
        let client = create_test_client();
        
        let mut permissions = HashMap::new();
        let mut documents_actions = HashMap::new();
        documents_actions.insert("read".to_string(), true);
        documents_actions.insert("write".to_string(), true);
        documents_actions.insert("delete".to_string(), false);
        permissions.insert("documents".to_string(), documents_actions);

        let mut cars_actions = HashMap::new();
        cars_actions.insert("read".to_string(), true);
        cars_actions.insert("update".to_string(), false);
        permissions.insert("cars".to_string(), cars_actions);

        let scopes = client.permissions_to_scopes(&permissions);
        
        assert_eq!(scopes.len(), 3);
        assert!(scopes.contains(&"documents:read".to_string()));
        assert!(scopes.contains(&"documents:write".to_string()));
        assert!(scopes.contains(&"cars:read".to_string()));
        assert!(!scopes.contains(&"documents:delete".to_string()));
        assert!(!scopes.contains(&"cars:update".to_string()));
    }

    #[test]
    fn test_parse_scope() {
        let client = create_test_client();
        
        let (resource, action) = client
            .parse_scope("documents:read")
            .expect("Should parse valid scope");
        assert_eq!(resource, "documents");
        assert_eq!(action, "read");

        assert!(client.parse_scope("invalid_scope").is_none());
        assert!(client.parse_scope("").is_none());
    }

    #[test]
    fn test_has_scope() {
        let client = create_test_client();
        let scopes = vec![
            "documents:read".to_string(),
            "documents:write".to_string(),
            "cars:read".to_string(),
        ];

        assert!(client.has_scope(&scopes, "documents:read"));
        assert!(client.has_scope(&scopes, "cars:read"));
        assert!(!client.has_scope(&scopes, "documents:delete"));
        assert!(!client.has_scope(&scopes, "cars:write"));
    }
}