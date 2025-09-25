//! Token and authorization code management functionality for OAuth 2.0

use crate::cache::{Cache, CacheBackend, CacheError};
use crate::api::oauth::models::{StoredToken, StoredAuthorizationCode};
use log::{debug, error, warn};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Errors that can occur during token and authorization code operations
#[derive(Debug, Error)]
pub enum TokenError {
    #[error("Cache error: {0}")]
    Cache(#[from] CacheError),
    #[error("Token not found or expired")]
    TokenNotFound,
    #[error("Authorization code not found or expired")]
    CodeNotFound,
    #[error("Invalid token format")]
    InvalidTokenFormat,
    #[error("Invalid authorization code format")]
    InvalidCodeFormat,
    #[error("Token generation failed: {0}")]
    TokenGeneration(String),
    #[error("Authorization code generation failed: {0}")]
    CodeGeneration(String),
    #[error("PKCE validation failed: {0}")]
    PkceValidation(String),
    #[error("Redirect URI mismatch")]
    RedirectUriMismatch,
}

/// Token and authorization code manager
#[derive(Clone)]
pub struct TokenManager {
    cache: Cache,
    token_ttl: u64,
    code_ttl: u64, // Authorization codes are short-lived (10 minutes)
}

impl TokenManager {
    /// Create a new token manager
    pub fn new(cache: Cache, token_ttl: u64) -> Self {
        Self { 
            cache, 
            token_ttl,
            code_ttl: 600, // 10 minutes for authorization codes
        }
    }

    /// Generate a new access token
    pub async fn generate_token(
        &self,
        user_id: &str,
        client_id: &str,
        requested_scopes: Vec<String>,
    ) -> Result<(String, StoredToken), TokenError> {
        // Generate a cryptographically secure random token
        let token = self.generate_secure_token()?;
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| TokenError::TokenGeneration(format!("System time error: {e}")))?
            .as_secs();

        let stored_token = StoredToken {
            user_id: user_id.to_string(),
            client_id: client_id.to_string(),
            requested_scopes,
            expires_at: now + self.token_ttl,
            issued_at: now,
        };

        // Store token in cache
        let cache_key = format!("oauth_token:{}", token);
        self.cache
            .set(&cache_key, &stored_token)
            .await
            .map_err(TokenError::Cache)?;

        debug!(
            "Generated token for user '{}' via client '{}' with {} scopes, expires in {}s",
            user_id,
            client_id,
            stored_token.requested_scopes.len(),
            self.token_ttl
        );

        Ok((token, stored_token))
    }

    /// Validate and retrieve token information
    pub async fn validate_token(&self, token: &str) -> Result<StoredToken, TokenError> {
        let cache_key = format!("oauth_token:{}", token);
        
        let stored_token: StoredToken = self
            .cache
            .get(&cache_key)
            .await
            .map_err(TokenError::Cache)?
            .ok_or(TokenError::TokenNotFound)?;

        // Check if token is expired
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| TokenError::TokenGeneration(format!("System time error: {e}")))?
            .as_secs();

        if now >= stored_token.expires_at {
            // Token is expired, remove it from cache
            if let Err(e) = self.cache.delete(&cache_key).await {
                warn!("Failed to delete expired token from cache: {}", e);
            }
            return Err(TokenError::TokenNotFound);
        }

        debug!(
            "Validated token for user '{}' via client '{}' with {} scopes",
            stored_token.user_id,
            stored_token.client_id,
            stored_token.requested_scopes.len()
        );

        Ok(stored_token)
    }

    /// Revoke a token by removing it from cache
    pub async fn revoke_token(&self, token: &str) -> Result<(), TokenError> {
        let cache_key = format!("oauth_token:{}", token);
        self.cache
            .delete(&cache_key)
            .await
            .map_err(TokenError::Cache)?;

        debug!("Revoked token: {}", token);
        Ok(())
    }

    /// Generate a new authorization code
    pub async fn generate_authorization_code(
        &self,
        user_id: &str,
        client_id: &str,
        redirect_uri: &str,
        requested_scopes: Vec<String>,
        code_challenge: Option<String>,
        code_challenge_method: Option<String>,
    ) -> Result<(String, StoredAuthorizationCode), TokenError> {
        // Generate a cryptographically secure random authorization code
        let code = self.generate_secure_code()?;
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| TokenError::CodeGeneration(format!("System time error: {e}")))?
            .as_secs();

        let stored_code = StoredAuthorizationCode {
            user_id: user_id.to_string(),
            client_id: client_id.to_string(),
            redirect_uri: redirect_uri.to_string(),
            requested_scopes,
            code_challenge,
            code_challenge_method,
            expires_at: now + self.code_ttl,
            issued_at: now,
        };

        // Store authorization code in cache
        let cache_key = format!("oauth_code:{}", code);
        self.cache
            .set(&cache_key, &stored_code)
            .await
            .map_err(TokenError::Cache)?;

        debug!(
            "Generated authorization code for user '{}' via client '{}' with {} scopes, expires in {}s",
            user_id,
            client_id,
            stored_code.requested_scopes.len(),
            self.code_ttl
        );

        Ok((code, stored_code))
    }

    /// Validate and consume an authorization code (codes are single-use)
    pub async fn validate_authorization_code(
        &self,
        code: &str,
        client_id: &str,
        redirect_uri: &str,
        code_verifier: Option<&str>,
    ) -> Result<StoredAuthorizationCode, TokenError> {
        let cache_key = format!("oauth_code:{}", code);
        
        let stored_code: StoredAuthorizationCode = self
            .cache
            .get(&cache_key)
            .await
            .map_err(TokenError::Cache)?
            .ok_or(TokenError::CodeNotFound)?;

        // Check if code is expired
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| TokenError::CodeGeneration(format!("System time error: {e}")))?
            .as_secs();

        if now >= stored_code.expires_at {
            // Code is expired, remove it from cache
            if let Err(e) = self.cache.delete(&cache_key).await {
                warn!("Failed to delete expired authorization code from cache: {}", e);
            }
            return Err(TokenError::CodeNotFound);
        }

        // Validate client_id
        if stored_code.client_id != client_id {
            // Remove the code immediately for security
            if let Err(e) = self.cache.delete(&cache_key).await {
                warn!("Failed to delete authorization code after client_id mismatch: {}", e);
            }
            return Err(TokenError::InvalidCodeFormat);
        }

        // Validate redirect_uri
        if stored_code.redirect_uri != redirect_uri {
            // Remove the code immediately for security
            if let Err(e) = self.cache.delete(&cache_key).await {
                warn!("Failed to delete authorization code after redirect_uri mismatch: {}", e);
            }
            return Err(TokenError::RedirectUriMismatch);
        }

        // Validate PKCE if used
        if let Some(challenge) = &stored_code.code_challenge {
            let verifier = code_verifier.ok_or_else(|| {
                TokenError::PkceValidation("code_verifier required for PKCE".to_string())
            })?;
            
            self.validate_pkce(challenge, &stored_code.code_challenge_method, verifier)?;
        }

        // Authorization code is valid - consume it (remove from cache)
        if let Err(e) = self.cache.delete(&cache_key).await {
            warn!("Failed to delete consumed authorization code from cache: {}", e);
        }

        debug!(
            "Validated and consumed authorization code for user '{}' via client '{}'",
            stored_code.user_id,
            stored_code.client_id
        );

        Ok(stored_code)
    }

    /// Validate PKCE code challenge
    fn validate_pkce(
        &self,
        code_challenge: &str,
        code_challenge_method: &Option<String>,
        code_verifier: &str,
    ) -> Result<(), TokenError> {
        let method = code_challenge_method.as_deref().unwrap_or("S256");
        
        let expected_challenge = match method {
            "S256" => {
                // SHA256 hash of code_verifier, then base64url encode
                let mut hasher = Sha256::new();
                hasher.update(code_verifier.as_bytes());
                let digest = hasher.finalize();
                base64_url::encode(&digest)
            }
            "plain" => {
                // code_verifier is used directly as challenge
                code_verifier.to_string()
            }
            _ => {
                return Err(TokenError::PkceValidation(format!(
                    "Unsupported code_challenge_method: {}",
                    method
                )));
            }
        };

        if expected_challenge != code_challenge {
            return Err(TokenError::PkceValidation(
                "code_verifier does not match code_challenge".to_string(),
            ));
        }

        debug!("PKCE validation successful using method: {}", method);
        Ok(())
    }

    /// Generate a cryptographically secure random token
    fn generate_secure_token(&self) -> Result<String, TokenError> {
        // Generate 32 random bytes (256 bits) and encode as base64url
        let mut rng = rand::thread_rng();
        let token_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        
        // Use base64url encoding (URL-safe, no padding)
        let token = base64_url::encode(&token_bytes);
        
        if token.is_empty() {
            return Err(TokenError::TokenGeneration("Generated empty token".to_string()));
        }

        Ok(token)
    }

    /// Generate a cryptographically secure random authorization code
    fn generate_secure_code(&self) -> Result<String, TokenError> {
        // Generate 32 random bytes (256 bits) and encode as base64url
        let mut rng = rand::thread_rng();
        let code_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        
        // Use base64url encoding (URL-safe, no padding)
        let code = base64_url::encode(&code_bytes);
        
        if code.is_empty() {
            return Err(TokenError::CodeGeneration("Generated empty code".to_string()));
        }

        Ok(code)
    }

    /// Clean up expired tokens (maintenance operation)
    pub async fn cleanup_expired_tokens(&self) -> Result<usize, TokenError> {
        // Note: This is a simplified implementation
        // In a real-world scenario, you might want to scan for expired tokens
        // and remove them. For now, we rely on TTL-based expiration in the cache backend.
        debug!("Token cleanup completed (relying on cache TTL)");
        Ok(0)
    }
}

// Add base64url encoding support
mod base64_url {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    
    pub fn encode(input: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{memory::InMemoryCache, Cache};
    use tokio::time::{sleep, Duration};

    async fn create_test_token_manager() -> TokenManager {
        let memory_cache = InMemoryCache::new(60, 128).expect("Failed to create test cache");
        let cache = Cache::InMemory(memory_cache);
        TokenManager::new(cache, 3600) // 1 hour TTL
    }

    #[tokio::test]
    async fn test_generate_and_validate_token() {
        let manager = create_test_token_manager().await;
        let user_id = "test_user";
        let client_id = "test_client";
        let scopes = vec!["read".to_string(), "write".to_string()];

        // Generate token
        let (token, stored_token) = manager
            .generate_token(user_id, client_id, scopes.clone())
            .await
            .expect("Failed to generate token");

        assert!(!token.is_empty());
        assert_eq!(stored_token.user_id, user_id);
        assert_eq!(stored_token.client_id, client_id);
        assert_eq!(stored_token.requested_scopes, scopes);

        // Validate token
        let validated_token = manager
            .validate_token(&token)
            .await
            .expect("Failed to validate token");

        assert_eq!(validated_token.user_id, stored_token.user_id);
        assert_eq!(validated_token.client_id, stored_token.client_id);
        assert_eq!(validated_token.requested_scopes, stored_token.requested_scopes);
        assert_eq!(validated_token.expires_at, stored_token.expires_at);
    }

    #[tokio::test]
    async fn test_token_expiration() {
        let memory_cache = InMemoryCache::new(1, 128).expect("Failed to create test cache"); // 1 second TTL
        let cache = Cache::InMemory(memory_cache);
        let manager = TokenManager::new(cache, 1); // 1 second token TTL

        let user_id = "test_user";
        let client_id = "test_client";
        let scopes = vec!["read".to_string()];

        // Generate token
        let (token, _) = manager
            .generate_token(user_id, client_id, scopes)
            .await
            .expect("Failed to generate token");

        // Token should be valid immediately
        assert!(manager.validate_token(&token).await.is_ok());

        // Wait for expiration
        sleep(Duration::from_secs(2)).await;

        // Token should be expired
        assert!(matches!(
            manager.validate_token(&token).await,
            Err(TokenError::TokenNotFound)
        ));
    }

    #[tokio::test]
    async fn test_revoke_token() {
        let manager = create_test_token_manager().await;
        let user_id = "test_user";
        let client_id = "test_client";
        let scopes = vec!["read".to_string()];

        // Generate token
        let (token, _) = manager
            .generate_token(user_id, client_id, scopes)
            .await
            .expect("Failed to generate token");

        // Token should be valid
        assert!(manager.validate_token(&token).await.is_ok());

        // Revoke token
        manager
            .revoke_token(&token)
            .await
            .expect("Failed to revoke token");

        // Token should no longer be valid
        assert!(matches!(
            manager.validate_token(&token).await,
            Err(TokenError::TokenNotFound)
        ));
    }

    #[tokio::test]
    async fn test_invalid_token() {
        let manager = create_test_token_manager().await;

        // Try to validate non-existent token
        assert!(matches!(
            manager.validate_token("invalid_token").await,
            Err(TokenError::TokenNotFound)
        ));
    }

    #[tokio::test]
    async fn test_token_uniqueness() {
        let manager = create_test_token_manager().await;
        let user_id = "test_user";
        let client_id = "test_client";
        let scopes = vec!["read".to_string()];

        // Generate multiple tokens
        let (token1, _) = manager
            .generate_token(user_id, client_id, scopes.clone())
            .await
            .expect("Failed to generate token 1");
        let (token2, _) = manager
            .generate_token(user_id, client_id, scopes)
            .await
            .expect("Failed to generate token 2");

        // Tokens should be different
        assert_ne!(token1, token2);

        // Both tokens should be valid
        assert!(manager.validate_token(&token1).await.is_ok());
        assert!(manager.validate_token(&token2).await.is_ok());
    }

    #[tokio::test]
    async fn test_generate_and_validate_authorization_code() {
        let manager = create_test_token_manager().await;
        let user_id = "test_user";
        let client_id = "test_client";
        let redirect_uri = "https://example.com/callback";
        let scopes = vec!["read".to_string(), "write".to_string()];

        // Generate authorization code
        let (code, stored_code) = manager
            .generate_authorization_code(user_id, client_id, redirect_uri, scopes.clone(), None, None)
            .await
            .expect("Failed to generate authorization code");

        assert!(!code.is_empty());
        assert_eq!(stored_code.user_id, user_id);
        assert_eq!(stored_code.client_id, client_id);
        assert_eq!(stored_code.redirect_uri, redirect_uri);
        assert_eq!(stored_code.requested_scopes, scopes);

        // Validate and consume authorization code
        let validated_code = manager
            .validate_authorization_code(&code, client_id, redirect_uri, None)
            .await
            .expect("Failed to validate authorization code");

        assert_eq!(validated_code.user_id, stored_code.user_id);
        assert_eq!(validated_code.client_id, stored_code.client_id);
        assert_eq!(validated_code.redirect_uri, stored_code.redirect_uri);
        assert_eq!(validated_code.requested_scopes, stored_code.requested_scopes);

        // Authorization code should be consumed (single-use)
        assert!(matches!(
            manager.validate_authorization_code(&code, client_id, redirect_uri, None).await,
            Err(TokenError::CodeNotFound)
        ));
    }

    #[tokio::test]
    async fn test_authorization_code_redirect_uri_mismatch() {
        let manager = create_test_token_manager().await;
        let user_id = "test_user";
        let client_id = "test_client";
        let redirect_uri = "https://example.com/callback";
        let wrong_redirect_uri = "https://evil.com/callback";
        let scopes = vec!["read".to_string()];

        // Generate authorization code
        let (code, _) = manager
            .generate_authorization_code(user_id, client_id, redirect_uri, scopes, None, None)
            .await
            .expect("Failed to generate authorization code");

        // Try to validate with wrong redirect_uri
        assert!(matches!(
            manager.validate_authorization_code(&code, client_id, wrong_redirect_uri, None).await,
            Err(TokenError::RedirectUriMismatch)
        ));
    }

    #[tokio::test]
    async fn test_pkce_validation() {
        let manager = create_test_token_manager().await;
        let user_id = "test_user";
        let client_id = "test_client";
        let redirect_uri = "https://example.com/callback";
        let scopes = vec!["read".to_string()];
        
        // Test S256 PKCE
        let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"; // SHA256 of verifier
        
        // Generate authorization code with PKCE
        let (code, _) = manager
            .generate_authorization_code(
                user_id, 
                client_id, 
                redirect_uri, 
                scopes, 
                Some(code_challenge.to_string()),
                Some("S256".to_string())
            )
            .await
            .expect("Failed to generate authorization code");

        // Validate with correct code_verifier
        assert!(manager
            .validate_authorization_code(&code, client_id, redirect_uri, Some(code_verifier))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_pkce_validation_failure() {
        let manager = create_test_token_manager().await;
        let user_id = "test_user";
        let client_id = "test_client";
        let redirect_uri = "https://example.com/callback";
        let scopes = vec!["read".to_string()];
        
        let code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        let wrong_verifier = "wrong_verifier";
        
        // Generate authorization code with PKCE
        let (code, _) = manager
            .generate_authorization_code(
                user_id, 
                client_id, 
                redirect_uri, 
                scopes, 
                Some(code_challenge.to_string()),
                Some("S256".to_string())
            )
            .await
            .expect("Failed to generate authorization code");

        // Validate with wrong code_verifier
        assert!(matches!(
            manager.validate_authorization_code(&code, client_id, redirect_uri, Some(wrong_verifier)).await,
            Err(TokenError::PkceValidation(_))
        ));
    }
}