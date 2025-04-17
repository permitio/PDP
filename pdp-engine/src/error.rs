use thiserror::Error;

#[derive(Error, Debug)]
pub enum PDPError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Process not running")]
    ProcessNotRunning,

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("Python binary not found: {0}")]
    PythonBinaryNotFound(String),

    #[error("PDP directory not found or invalid: {0}")]
    PDPDirNotFound(String),

    #[error("Operation cancelled due to shutdown")]
    ShutdownTriggered,

    #[error("Health check timed out: {0}")]
    HealthCheckTimeout(String),

    #[error("Process management error: {0}")]
    ProcessManagement(String),

    #[error("Failed to send request: {0}")]
    RequestFailed(String),

    #[error("Response error (status {0}): {1}")]
    ResponseError(u16, String),

    #[error("Failed to deserialize response: {0}")]
    DeserializationError(String),

    #[error("Other error: {0}")]
    Other(String),

    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
}
