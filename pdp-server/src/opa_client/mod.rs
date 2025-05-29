use crate::errors::ApiError;
use crate::state::AppState;
use axum::http::StatusCode;
use http::header::InvalidHeaderValue;
use log::debug;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value::{Bool, Object};
use thiserror::Error;

// Reexport modules
pub mod allowed;
pub mod allowed_bulk;
pub mod authorized_users;
pub mod user_permissions;

/// Generic function to send a request to OPA and return a specific response type
async fn send_request_to_opa<R: DeserializeOwned, B: Serialize>(
    state: &AppState,
    endpoint: &str,
    body: &B,
) -> Result<R, ForwardingError> {
    // Create a new OPA request
    let request = create_opa_request(body, state.config.debug)?;

    // Send the request to OPA
    let response: OpaResponse<R> = send_raw_request_to_opa(state, endpoint, &request).await?;
    Ok(response.result)
}

/// Generic function to forward requests to OPA
async fn send_raw_request_to_opa<B: Serialize, R: DeserializeOwned>(
    state: &AppState,
    endpoint: &str,
    body: &OpaRequest<B>,
) -> Result<OpaResponse<R>, ForwardingError> {
    // Build the OPA URL from the settings
    let endpoint = endpoint.strip_prefix("/").unwrap_or(endpoint);
    let opa_url = format!("{}/{}", state.config.opa.url, endpoint);
    debug!("Forwarding request to OPA at: {}", opa_url);

    // Send request to OPA using the specialized OPA client
    let response = state.opa_client.post(&opa_url).json(body).send().await?;

    // Check if the request was successful
    if !response.status().is_success() {
        let status = response.status();
        return Err(ForwardingError::InvalidStatus(status));
    }

    // Parse the response body
    let body = response.bytes().await?;
    Ok(serde_json::from_slice(&body)?)
}

/// Helper function to create an OPA request from any serializable type
///
/// It serializes the value inside the 'input' field of the OPA request.
/// If the value is an object, it injects a `use_debugger` field if the debug flag is set.
fn create_opa_request<T: Serialize>(
    value: T,
    debug: Option<bool>,
) -> Result<OpaRequest<serde_json::Value>, ForwardingError> {
    let mut value = serde_json::to_value(&value)?;
    if let Some(debug) = debug {
        // Inject `use_debugger` if the value is an object
        if let Object(ref mut obj) = value {
            if !obj.contains_key("use_debugger") {
                obj.insert("use_debugger".to_string(), Bool(debug));
            }
        }
    }
    Ok(OpaRequest { input: value })
}

/// A generic wrapper for OPA requests, wrapping the input data.
/// https://www.openpolicyagent.org/docs/latest/integration/#named-policy-decisions
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct OpaRequest<T> {
    pub input: T,
}

/// A generic wrapper for OPA responses, wrapping the result data.
/// https://www.openpolicyagent.org/docs/latest/integration/#named-policy-decisions
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct OpaResponse<T> {
    pub result: T,
}

/// Errors that can occur when forwarding requests to OPA
#[derive(Debug, Error)]
pub enum ForwardingError {
    #[error("Failed to build request to OPA: {0}")]
    BuildError(#[from] InvalidHeaderValue),
    #[error("Failed to send request to OPA: {0}")]
    RequestError(#[from] reqwest::Error),
    #[error("OPA request failed with status: {0}")]
    InvalidStatus(StatusCode),
    #[error("Failed to parse OPA response: {0}")]
    ParseError(#[from] serde_json::Error),
}

impl From<ForwardingError> for ApiError {
    fn from(err: ForwardingError) -> Self {
        match err {
            ForwardingError::BuildError(_) => ApiError::internal("Failed to build request to OPA"),
            ForwardingError::RequestError(_) => {
                ApiError::bad_gateway("Failed to send request to OPA")
            }
            ForwardingError::InvalidStatus(status) => {
                ApiError::bad_gateway(format!("OPA request failed with status: {}", status))
            }
            ForwardingError::ParseError(e) => {
                ApiError::internal(format!("Failed to parse OPA response: {}", e))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::create_opa_request;
    use serde_json::json;

    #[test]
    fn test_opa_request() {
        let request = create_opa_request(
            json!({
                "user": "test_user",
                "action": "read",
                "resource": {
                    "type": "document",
                    "key": "doc1"
                },
            }),
            None,
        )
        .expect("Failed to create OPA request");
        let json = serde_json::to_value(request).expect("Failed to serialize OPA request");
        assert_eq!(
            json,
            json!({
                "input": {
                    "user": "test_user",
                    "action": "read",
                    "resource": {
                        "type": "document",
                        "key": "doc1"
                    },
                }
            })
        )
    }

    #[test]
    fn test_opa_request_with_debug() {
        let request = create_opa_request(
            json!({
                "user": "test_user",
                "action": "read",
                "resource": {
                    "type": "document",
                    "key": "doc1"
                },
            }),
            Some(true),
        )
        .expect("Failed to create OPA request");
        let json = serde_json::to_value(request).expect("Failed to serialize OPA request");
        assert_eq!(
            json,
            json!({
                "input": {
                    "user": "test_user",
                    "action": "read",
                    "resource": {
                        "type": "document",
                        "key": "doc1"
                    },
                    "use_debugger": true
                }
            })
        )
    }
}
