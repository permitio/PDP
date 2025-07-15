use axum::http::HeaderValue;
use chrono::{DateTime, Utc};
use http::header::{CACHE_CONTROL, EXPIRES, PRAGMA};
use log::warn;

/// Cache-Control directives
#[derive(Debug, Clone, Default)]
pub struct CacheControl {
    pub no_cache: bool,
    pub no_store: bool,
    pub must_revalidate: bool,
    pub public: bool,
    pub private: bool,
    pub max_age: Option<u32>,
    pub s_maxage: Option<u32>,
}

impl CacheControl {
    /// Create a new CacheControl instance
    pub fn new() -> Self {
        Self::default()
    }

    /// Set no-cache directive
    #[allow(dead_code)]
    pub fn no_cache(mut self) -> Self {
        self.no_cache = true;
        self
    }

    /// Set no-store directive
    #[allow(dead_code)]
    pub fn no_store(mut self) -> Self {
        self.no_store = true;
        self
    }

    /// Set must-revalidate directive
    #[allow(dead_code)]
    pub fn must_revalidate(mut self) -> Self {
        self.must_revalidate = true;
        self
    }

    /// Set public directive
    #[allow(dead_code)]
    pub fn public(mut self) -> Self {
        self.public = true;
        self.private = false;
        self
    }

    /// Set private directive
    pub fn private(mut self) -> Self {
        self.private = true;
        self.public = false;
        self
    }

    /// Set max-age directive
    pub fn max_age(mut self, seconds: u32) -> Self {
        self.max_age = Some(seconds);
        self
    }

    /// Set s-maxage directive
    #[allow(dead_code)]
    pub fn s_maxage(mut self, seconds: u32) -> Self {
        self.s_maxage = Some(seconds);
        self
    }

    /// Convert to HeaderValue
    pub fn to_header_value(&self) -> HeaderValue {
        let mut parts = Vec::new();

        if self.no_cache {
            parts.push("no-cache".to_string());
        }
        if self.no_store {
            parts.push("no-store".to_string());
        }
        if self.must_revalidate {
            parts.push("must-revalidate".to_string());
        }
        if self.public {
            parts.push("public".to_string());
        }
        if self.private {
            parts.push("private".to_string());
        }
        if let Some(max_age) = self.max_age {
            parts.push(format!("max-age={max_age}"));
        }
        if let Some(s_maxage) = self.s_maxage {
            parts.push(format!("s-maxage={s_maxage}"));
        }

        HeaderValue::from_str(&parts.join(", ")).unwrap_or(HeaderValue::from_static(""))
    }
}

/// Helper struct for setting cache-related headers
#[derive(Debug, Clone, Default)]
pub struct CacheHeaders {
    cache_control: CacheControl,
    expires: Option<DateTime<Utc>>,
}

impl CacheHeaders {
    /// Create a new CacheHeaders instance
    pub fn new() -> Self {
        Self::default()
    }

    /// Set cache control directives
    pub fn cache_control(mut self, cache_control: CacheControl) -> Self {
        self.cache_control = cache_control;
        self
    }

    /// Set expires header
    pub fn expires(mut self, expires: DateTime<Utc>) -> Self {
        self.expires = Some(expires);
        self
    }

    /// Apply headers to a response
    pub fn apply<B>(&self, response: &mut axum::response::Response<B>) {
        let headers = response.headers_mut();

        // Set Cache-Control header
        headers.insert(CACHE_CONTROL, self.cache_control.to_header_value());

        // Set Pragma header if no-cache is set
        if self.cache_control.no_cache {
            headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
        }

        // Set Expires header
        if let Some(expires) = self.expires {
            match HeaderValue::from_str(&expires.to_rfc2822()) {
                Ok(expires_value) => {
                    headers.insert(EXPIRES, expires_value);
                }
                Err(e) => warn!("failed to set expires header: {e}"),
            }
        } else if self.cache_control.no_store || self.cache_control.no_cache {
            // Set Expires to 0 for no-store/no-cache
            headers.insert(EXPIRES, HeaderValue::from_static("0"));
        }
    }
}

/// Common cache control presets
pub mod presets {
    use super::*;
    use chrono::Duration;

    /// No caching allowed
    #[allow(dead_code)]
    pub fn no_cache() -> CacheHeaders {
        CacheHeaders::new()
            .cache_control(CacheControl::new().no_cache().no_store().must_revalidate())
            .expires(Utc::now() - Duration::hours(1)) // Set to past date
    }

    /// Public caching with max age
    #[allow(dead_code)]
    pub fn public_cache(max_age_seconds: u32) -> CacheHeaders {
        CacheHeaders::new()
            .cache_control(CacheControl::new().public().max_age(max_age_seconds))
            .expires(Utc::now() + Duration::seconds(max_age_seconds as i64))
    }

    /// Private caching with max age
    pub fn private_cache(max_age_seconds: u32) -> CacheHeaders {
        CacheHeaders::new()
            .cache_control(CacheControl::new().private().max_age(max_age_seconds))
            .expires(Utc::now() + Duration::seconds(max_age_seconds as i64))
    }
}

/// Client cache control directives
#[derive(Debug, Clone, Default)]
pub struct ClientCacheControl {
    pub no_cache: bool,
    pub no_store: bool,
    pub max_age: Option<u32>,
}

impl ClientCacheControl {
    /// Parse cache control header from request
    pub fn from_header_value(value: Option<&HeaderValue>) -> Self {
        let mut control = Self::default();

        if let Some(value) = value.and_then(|v| v.to_str().ok()) {
            for directive in value.split(',').map(str::trim) {
                match directive {
                    "no-cache" => control.no_cache = true,
                    "no-store" => control.no_store = true,
                    d if d.starts_with("max-age=") => {
                        if let Ok(age) = d[8..].parse::<u32>() {
                            warn!("setting max-age is currently not supported and ignored");
                            control.max_age = Some(age);
                        }
                    }
                    _ => {} // Ignore unknown directives
                }
            }
        }

        control
    }

    /// Check if caching is allowed based on the directives
    pub fn should_use_cache(&self) -> bool {
        !self.no_cache && !self.no_store && self.max_age.unwrap_or(1) > 0
    }
}
