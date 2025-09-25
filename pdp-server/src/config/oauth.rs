//! OAuth 2.0 configuration

use confique::Config;

/// OAuth 2.0 configuration
#[derive(Debug, Config, Clone, Default)]
pub struct OAuthConfig {
    /// Enable OAuth 2.0 endpoints (default: true)
    #[config(env = "PDP_OAUTH_ENABLED", default = true)]
    pub enabled: bool,

    /// OAuth token TTL in seconds (default: 3600 = 1 hour)
    #[config(env = "PDP_OAUTH_TOKEN_TTL", default = 3600)]
    pub token_ttl: u64,

    /// Permit.io API base URL for OAuth client validation
    /// (default: https://api.permit.io)
    #[config(env = "PDP_OAUTH_PERMIT_API_URL", default = "https://api.permit.io")]
    pub permit_api_url: String,

    /// Resource types to check for OAuth scope generation
    /// Comma-separated list (default: "documents,cars")
    #[config(env = "PDP_OAUTH_RESOURCE_TYPES", default = "documents,cars")]
    pub resource_types: String,

    /// OAuth issuer identifier (default: "permit-pdp")
    #[config(env = "PDP_OAUTH_ISSUER", default = "permit-pdp")]
    pub issuer: String,
}

impl OAuthConfig {
    /// Get resource types as a vector
    pub fn get_resource_types(&self) -> Vec<String> {
        self.resource_types
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_oauth_config() {
        let config = OAuthConfig::default();
        assert!(config.enabled);
        assert_eq!(config.token_ttl, 3600);
        assert_eq!(config.permit_api_url, "https://api.permit.io");
        assert_eq!(config.resource_types, "documents,cars");
        assert_eq!(config.issuer, "permit-pdp");
    }

    #[test]
    fn test_get_resource_types() {
        let config = OAuthConfig {
            resource_types: "documents,cars,files".to_string(),
            ..Default::default()
        };
        let types = config.get_resource_types();
        assert_eq!(types, vec!["documents", "cars", "files"]);
    }

    #[test]
    fn test_get_resource_types_with_spaces() {
        let config = OAuthConfig {
            resource_types: " documents , cars , files ".to_string(),
            ..Default::default()
        };
        let types = config.get_resource_types();
        assert_eq!(types, vec!["documents", "cars", "files"]);
    }

    #[test]
    fn test_get_resource_types_empty() {
        let config = OAuthConfig {
            resource_types: "".to_string(),
            ..Default::default()
        };
        let types = config.get_resource_types();
        assert!(types.is_empty());
    }
}