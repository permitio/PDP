use http::HeaderValue;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer};
use std::fmt;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::watch;

pub mod handoff;

/// What the image sets `PDP_API_KEY` to when a deployment leaves it out (horizon's
/// `MOCK_API_KEY`). It is never a key.
pub const PLACEHOLDER: &str = "MUST BE DEFINED";

/// The body of the 503 the PDP answers with while it has no key to check or send.
pub const NO_KEY_YET: &str = "The PDP has no API key yet; it is still starting.";

/// A key the PDP accepts from callers and presents to OPA and horizon.
///
/// It is never empty and never the image's placeholder. `Debug` leaves the value out.
#[derive(Clone, PartialEq, Eq)]
pub struct ApiKey {
    value: Arc<str>,
    bearer: HeaderValue,
}

/// Why a value is not an [`ApiKey`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum InvalidApiKey {
    #[error("the value is empty")]
    Empty,
    #[error("the value is the image's placeholder")]
    Placeholder,
    #[error("the value cannot be sent in an HTTP header")]
    NotHeaderSafe,
}

impl ApiKey {
    pub fn new(value: &str) -> Result<Self, InvalidApiKey> {
        if value.is_empty() {
            return Err(InvalidApiKey::Empty);
        }
        if value == PLACEHOLDER {
            return Err(InvalidApiKey::Placeholder);
        }
        let Ok(mut bearer) = HeaderValue::from_str(&format!("Bearer {value}")) else {
            return Err(InvalidApiKey::NotHeaderSafe);
        };
        bearer.set_sensitive(true);
        Ok(Self {
            value: value.into(),
            bearer,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// The `Authorization` header value that presents this key.
    pub fn bearer(&self) -> HeaderValue {
        self.bearer.clone()
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApiKey(..)")
    }
}

/// Where the PDP's API key comes from, as `PDP_API_KEY` decides.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ApiKeySource {
    /// `PDP_API_KEY` holds a key.
    Env(ApiKey),
    /// `PDP_API_KEY` is unset, empty or the image's placeholder. In project and org key modes
    /// horizon derives the environment's key from the control plane and hands it over.
    #[default]
    Horizon,
}

impl ApiKeySource {
    /// Reads a value of `PDP_API_KEY`.
    pub fn from_env_value(value: &str) -> Result<Self, InvalidApiKey> {
        match ApiKey::new(value) {
            Ok(key) => Ok(Self::Env(key)),
            Err(InvalidApiKey::Empty | InvalidApiKey::Placeholder) => Ok(Self::Horizon),
            Err(err @ InvalidApiKey::NotHeaderSafe) => Err(err),
        }
    }

    /// The key `PDP_API_KEY` holds, if it holds one.
    pub fn env_key(&self) -> Option<ApiKey> {
        match self {
            Self::Env(key) => Some(key.clone()),
            Self::Horizon => None,
        }
    }
}

impl<'de> Deserialize<'de> for ApiKeySource {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::from_env_value(&value).map_err(D::Error::custom)
    }
}

/// The key in force: the one `PDP_API_KEY` holds, or the latest one horizon handed over.
///
/// Clones share the key, so a key horizon hands over reaches every holder at once. Once there is
/// a key there is always one; a new key replaces the old.
#[derive(Clone)]
pub struct CurrentApiKey(watch::Sender<Option<ApiKey>>);

impl CurrentApiKey {
    pub fn new(initial: Option<ApiKey>) -> Self {
        Self(watch::Sender::new(initial))
    }

    pub fn get(&self) -> Option<ApiKey> {
        self.0.borrow().clone()
    }

    /// The `Authorization` header value that presents the current key, if there is one.
    pub fn bearer(&self) -> Option<HeaderValue> {
        self.0.borrow().as_ref().map(ApiKey::bearer)
    }

    /// Makes `key` the current key. Returns whether it differs from the key it replaces.
    pub fn replace(&self, key: ApiKey) -> bool {
        self.0.send_if_modified(|current| {
            if current.as_ref() == Some(&key) {
                return false;
            }
            *current = Some(key);
            true
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_or_placeholder_is_not_a_key() {
        assert_eq!(ApiKey::new("").unwrap_err(), InvalidApiKey::Empty);
        assert_eq!(
            ApiKey::new(PLACEHOLDER).unwrap_err(),
            InvalidApiKey::Placeholder
        );
        assert_eq!(
            ApiKey::new("key\nwith a newline").unwrap_err(),
            InvalidApiKey::NotHeaderSafe
        );
    }

    #[test]
    fn test_key_presents_itself_as_a_bearer_token() {
        let key = ApiKey::new("permit_key_abc").unwrap();

        assert_eq!(key.as_str(), "permit_key_abc");
        assert_eq!(key.bearer(), "Bearer permit_key_abc");
        assert!(key.bearer().is_sensitive());
    }

    #[test]
    fn test_debug_leaves_the_key_out() {
        let key = ApiKey::new("permit_key_abc").unwrap();
        let source = ApiKeySource::Env(key.clone());
        let current = CurrentApiKey::new(Some(key.clone()));

        for printed in [
            format!("{key:?}"),
            format!("{source:?}"),
            format!("{:?}", current.get()),
        ] {
            assert!(!printed.contains("permit_key_abc"), "{printed}");
        }
    }

    #[test]
    fn test_env_value_without_a_key_means_horizon_hands_it_over() {
        assert_eq!(ApiKeySource::from_env_value(""), Ok(ApiKeySource::Horizon));
        assert_eq!(
            ApiKeySource::from_env_value(PLACEHOLDER),
            Ok(ApiKeySource::Horizon)
        );
        assert_eq!(
            ApiKeySource::from_env_value("permit_key_abc"),
            Ok(ApiKeySource::Env(ApiKey::new("permit_key_abc").unwrap()))
        );
        assert_eq!(
            ApiKeySource::from_env_value("permit_key\r\n"),
            Err(InvalidApiKey::NotHeaderSafe)
        );
    }

    #[test]
    fn test_replacing_the_current_key() {
        let current = CurrentApiKey::new(None);
        let first = ApiKey::new("first").unwrap();
        let second = ApiKey::new("second").unwrap();

        assert!(current.get().is_none());
        assert!(current.bearer().is_none());

        assert!(current.replace(first.clone()));
        assert_eq!(current.get(), Some(first.clone()));
        assert!(!current.replace(first));

        let clone = current.clone();
        assert!(current.replace(second.clone()));
        assert_eq!(clone.get(), Some(second));
        assert_eq!(clone.bearer().unwrap(), "Bearer second");
    }
}
