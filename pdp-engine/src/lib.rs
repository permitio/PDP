//! # pdp-engine
//!
//! A crate for interacting with a Python-based Policy Decision Point (PDP) server.
//!
//! ## Components
//!
//! - **Runner:** Runs PDP as a subprocess with a typed CLI arguments API.
//! - **Client:** HTTP client for interacting with the PDP API.
//! - **Engine:** High-level API for configuring and querying the PDP.

pub mod args;
pub mod builder;
pub mod error;
pub mod health;
pub mod runner;

use crate::builder::{PDPEngineBuilder, Present};
use crate::error::PDPError;
use crate::runner::PDPRunner;
use async_trait::async_trait;
use log::error;
use reqwest::header::{self, HeaderMap, HeaderValue};
use reqwest::{Client, RequestBuilder, Response};
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use url::Url;

/// Trait defining the core functionality for interacting with a PDP server
#[async_trait]
pub trait PDPEngine {
    /// Checks PDP health
    async fn health(&self) -> bool;

    /// Waits until PDP becomes healthy or the timeout is reached
    async fn wait_until_healthy(&self, timeout: Duration) -> Result<(), PDPError>;

    /// Stops the PDP server
    async fn stop(self) -> Result<(), PDPError>
    where
        Self: Sized;

    /// Create a request builder for custom requests to the PDP
    fn request(&self, method: reqwest::Method, endpoint: &str) -> Result<RequestBuilder, PDPError>;

    /// Sends a GET request to the specified endpoint
    async fn get<R>(
        &self,
        endpoint: &str,
        headers: Option<reqwest::header::HeaderMap>,
    ) -> Result<R, PDPError>
    where
        R: DeserializeOwned + Send + 'static;

    /// Sends a POST request with a JSON payload to the specified endpoint
    async fn post<T, R>(
        &self,
        endpoint: &str,
        payload: &T,
        headers: Option<reqwest::header::HeaderMap>,
    ) -> Result<R, PDPError>
    where
        T: Serialize + Send + Sync + 'static,
        R: DeserializeOwned + Send + 'static;

    /// Sends a PUT request with a JSON payload to the specified endpoint
    async fn put<T, R>(
        &self,
        endpoint: &str,
        payload: &T,
        headers: Option<reqwest::header::HeaderMap>,
    ) -> Result<R, PDPError>
    where
        T: Serialize + Send + Sync + 'static,
        R: DeserializeOwned + Send + 'static;

    /// Sends a PATCH request with a JSON payload to the specified endpoint
    async fn patch<T, R>(
        &self,
        endpoint: &str,
        payload: &T,
        headers: Option<reqwest::header::HeaderMap>,
    ) -> Result<R, PDPError>
    where
        T: Serialize + Send + Sync + 'static,
        R: DeserializeOwned + Send + 'static;

    /// Sends a DELETE request to the specified endpoint
    async fn delete<R>(
        &self,
        endpoint: &str,
        headers: Option<reqwest::header::HeaderMap>,
    ) -> Result<R, PDPError>
    where
        R: DeserializeOwned + Send + 'static;

    /// Send a custom request and parse the response
    async fn send<R>(&self, request: RequestBuilder) -> Result<R, PDPError>
    where
        R: DeserializeOwned + Send + 'static;

    /// Send a custom request and return the raw response
    async fn send_raw(&self, request: RequestBuilder) -> Result<Response, PDPError>;
}

/// `PDPPythonEngine` provides a high-level API for interacting with a PDP server.
/// It contains both a running runner and a connected HTTP client.
#[derive(Clone)]
pub struct PDPPythonEngine {
    pub runner: PDPRunner,
    pub base_url: Url,
    pub client: Client,
    health_monitor_token: CancellationToken,
}

impl std::fmt::Debug for PDPPythonEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PDPPythonEngine")
            .field("runner", &self.runner)
            .field("base_url", &self.base_url)
            // Skip client and health_monitor_token as they don't implement Debug
            .finish_non_exhaustive()
    }
}

impl PDPPythonEngine {
    pub(crate) async fn new(
        builder: PDPEngineBuilder<Present>,
    ) -> Result<PDPPythonEngine, PDPError> {
        // Unwrap is safe because type is Present.
        let python_path = builder.python_path.unwrap();
        let pdp_dir = builder.pdp_dir.unwrap();

        // Start the PDP runner.
        let runner = PDPRunner::start(python_path, pdp_dir, builder.args, builder.env_vars).await?;

        // Connect to the PDP server.
        let base_url = Url::parse(&builder.base_url)?;
        let client = Client::builder().build()?;

        // Create a cancellation token for the health monitor
        // This token will be cancelled when the runner is stopped or killed because
        // it is a child of the runner's shutdown token.
        let health_monitor_token = runner.get_shutdown_token().child_token();

        // Create the engine.
        let mut engine = Self {
            runner,
            base_url,
            client,
            health_monitor_token,
        };

        // Wait until PDP is healthy.
        engine.wait_until_healthy(builder.health_timeout).await?;

        // Start health monitor if interval > 0
        if !builder.health_check_interval.is_zero() {
            engine
                .start_health_monitor(builder.health_check_interval, builder.health_timeout)
                .await;
        }

        Ok(engine)
    }

    /// Starts a background task that periodically monitors PDP's health status.
    /// If the health check fails, it will attempt recovery or restart PDP.
    async fn start_health_monitor(
        &mut self,
        health_check_interval: Duration,
        health_timeout: Duration,
    ) {
        // Clone what we need for the task
        let base_url = self.base_url.clone();
        let client = self.client.clone();
        let runner = Arc::new(self.runner.clone());
        let token = self.health_monitor_token.clone();

        tokio::spawn(async move {
            health::run_health_monitor(
                base_url,
                client,
                runner,
                token,
                health_check_interval,
                health_timeout,
            )
            .await;
        });
    }
}

#[async_trait]
impl PDPEngine for PDPPythonEngine {
    //// Stops the PDP server and returns an engine with a stopped runner.
    async fn stop(self) -> Result<(), PDPError> {
        // Cancel health monitoring
        self.health_monitor_token.cancel();
        self.runner.stop().await
    }

    /// Checks PDP health by sending a GET request to `/healthy`.
    async fn health(&self) -> bool {
        health::is_healthy(&self.base_url, &self.client).await
    }

    /// Waits until PDP becomes healthy or the timeout is reached.
    /// Also returns early if the health_monitor_token is cancelled.
    async fn wait_until_healthy(&self, timeout: Duration) -> Result<(), PDPError> {
        health::wait_for_healthy(
            &self.base_url,
            &self.client,
            timeout,
            &self.health_monitor_token,
        )
        .await
    }

    /// Create a request builder for custom requests to the PDP
    fn request(&self, method: reqwest::Method, endpoint: &str) -> Result<RequestBuilder, PDPError> {
        let url = self.base_url.join(endpoint)?;
        Ok(self.client.request(method, url))
    }

    /// Sends a GET request to the specified endpoint
    async fn get<R>(
        &self,
        endpoint: &str,
        headers: Option<reqwest::header::HeaderMap>,
    ) -> Result<R, PDPError>
    where
        R: DeserializeOwned + Send + 'static,
    {
        let url = self.base_url.join(endpoint)?;
        let mut request_builder = self.client.get(url);

        if let Some(headers) = headers {
            request_builder = request_builder.headers(headers);
        }

        self.send(request_builder).await
    }

    /// Sends a POST request with a JSON payload to the specified endpoint
    async fn post<T, R>(
        &self,
        endpoint: &str,
        payload: &T,
        headers: Option<reqwest::header::HeaderMap>,
    ) -> Result<R, PDPError>
    where
        T: Serialize + Send + Sync + 'static,
        R: DeserializeOwned + Send + 'static,
    {
        let url = self.base_url.join(endpoint)?;
        let mut request_builder = self.client.post(url).json(payload);

        if let Some(headers) = headers {
            request_builder = request_builder.headers(headers);
        }

        self.send(request_builder).await
    }

    /// Sends a PUT request with a JSON payload to the specified endpoint
    async fn put<T, R>(
        &self,
        endpoint: &str,
        payload: &T,
        headers: Option<reqwest::header::HeaderMap>,
    ) -> Result<R, PDPError>
    where
        T: Serialize + Send + Sync + 'static,
        R: DeserializeOwned + Send + 'static,
    {
        let url = self.base_url.join(endpoint)?;
        let mut request_builder = self.client.put(url).json(payload);

        if let Some(headers) = headers {
            request_builder = request_builder.headers(headers);
        }

        self.send(request_builder).await
    }

    /// Sends a PATCH request with a JSON payload to the specified endpoint
    async fn patch<T, R>(
        &self,
        endpoint: &str,
        payload: &T,
        headers: Option<reqwest::header::HeaderMap>,
    ) -> Result<R, PDPError>
    where
        T: Serialize + Send + Sync + 'static,
        R: DeserializeOwned + Send + 'static,
    {
        let url = self.base_url.join(endpoint)?;
        let mut request_builder = self.client.patch(url).json(payload);

        if let Some(headers) = headers {
            request_builder = request_builder.headers(headers);
        }

        self.send(request_builder).await
    }

    /// Sends a DELETE request to the specified endpoint
    async fn delete<R>(
        &self,
        endpoint: &str,
        headers: Option<reqwest::header::HeaderMap>,
    ) -> Result<R, PDPError>
    where
        R: DeserializeOwned + Send + 'static,
    {
        let url = self.base_url.join(endpoint)?;
        let mut request_builder = self.client.delete(url);

        if let Some(headers) = headers {
            request_builder = request_builder.headers(headers);
        }

        self.send(request_builder).await
    }

    /// Send a custom request and parse the response
    async fn send<R>(&self, request: RequestBuilder) -> Result<R, PDPError>
    where
        R: DeserializeOwned + Send + 'static,
    {
        let response = request
            .send()
            .await
            .map_err(|e| PDPError::RequestFailed(format!("Failed to send request: {}", e)))?;

        if !response.status().is_success() {
            return Err(PDPError::ResponseError(
                response.status().as_u16(),
                format!("Request failed with status: {}", response.status()),
            ));
        }

        response.json::<R>().await.map_err(|e| {
            PDPError::DeserializationError(format!("Failed to deserialize response: {}", e))
        })
    }

    /// Send a custom request and return the raw response
    async fn send_raw(&self, request: RequestBuilder) -> Result<Response, PDPError> {
        request
            .send()
            .await
            .map_err(|e| PDPError::RequestFailed(format!("Failed to send request: {}", e)))
    }
}

/// A no-op implementation of PDPEngine that always returns errors
#[derive(Clone, Debug)]
pub struct MockEngine {
    client: Client,
    base_url: Url,
}

impl MockEngine {
    pub fn new(base_url: Url, api_key: String) -> Self {
        let bearer_header_value = HeaderValue::from_str(&format!("Bearer {}", api_key));
        let headers = match bearer_header_value {
            Ok(bearer_header_value) => {
                HeaderMap::from_iter(vec![(header::AUTHORIZATION, bearer_header_value)])
            }
            Err(_) => {
                error!("Failed to create bearer header value from given token, please check your configuration");
                HeaderMap::new()
            }
        };
        Self {
            client: Client::builder()
                .default_headers(headers)
                .build()
                .unwrap_or_default(),
            base_url,
        }
    }
}

#[async_trait]
impl PDPEngine for MockEngine {
    async fn health(&self) -> bool {
        true
    }
    async fn wait_until_healthy(&self, _: Duration) -> Result<(), PDPError> {
        Ok(())
    }
    async fn stop(self) -> Result<(), PDPError> {
        Ok(())
    }
    fn request(
        &self,
        method: reqwest::Method,
        endpoint: &str,
    ) -> Result<reqwest::RequestBuilder, PDPError> {
        let url = self.base_url.join(endpoint)?;
        Ok(self.client.request(method, url))
    }
    /// Sends a GET request to the specified endpoint
    async fn get<R>(
        &self,
        endpoint: &str,
        headers: Option<reqwest::header::HeaderMap>,
    ) -> Result<R, PDPError>
    where
        R: DeserializeOwned + Send + 'static,
    {
        let url = self.base_url.join(endpoint)?;
        let mut request_builder = self.client.get(url);

        if let Some(headers) = headers {
            request_builder = request_builder.headers(headers);
        }

        self.send(request_builder).await
    }

    /// Sends a POST request with a JSON payload to the specified endpoint
    async fn post<T, R>(
        &self,
        endpoint: &str,
        payload: &T,
        headers: Option<reqwest::header::HeaderMap>,
    ) -> Result<R, PDPError>
    where
        T: Serialize + Send + Sync + 'static,
        R: DeserializeOwned + Send + 'static,
    {
        let url = self.base_url.join(endpoint)?;
        let mut request_builder = self.client.post(url).json(payload);

        if let Some(headers) = headers {
            request_builder = request_builder.headers(headers);
        }

        self.send(request_builder).await
    }

    /// Sends a PUT request with a JSON payload to the specified endpoint
    async fn put<T, R>(
        &self,
        endpoint: &str,
        payload: &T,
        headers: Option<reqwest::header::HeaderMap>,
    ) -> Result<R, PDPError>
    where
        T: Serialize + Send + Sync + 'static,
        R: DeserializeOwned + Send + 'static,
    {
        let url = self.base_url.join(endpoint)?;
        let mut request_builder = self.client.put(url).json(payload);

        if let Some(headers) = headers {
            request_builder = request_builder.headers(headers);
        }

        self.send(request_builder).await
    }

    /// Sends a PATCH request with a JSON payload to the specified endpoint
    async fn patch<T, R>(
        &self,
        endpoint: &str,
        payload: &T,
        headers: Option<reqwest::header::HeaderMap>,
    ) -> Result<R, PDPError>
    where
        T: Serialize + Send + Sync + 'static,
        R: DeserializeOwned + Send + 'static,
    {
        let url = self.base_url.join(endpoint)?;
        let mut request_builder = self.client.patch(url).json(payload);

        if let Some(headers) = headers {
            request_builder = request_builder.headers(headers);
        }

        self.send(request_builder).await
    }

    /// Sends a DELETE request to the specified endpoint
    async fn delete<R>(
        &self,
        endpoint: &str,
        headers: Option<reqwest::header::HeaderMap>,
    ) -> Result<R, PDPError>
    where
        R: DeserializeOwned + Send + 'static,
    {
        let url = self.base_url.join(endpoint)?;
        let mut request_builder = self.client.delete(url);

        if let Some(headers) = headers {
            request_builder = request_builder.headers(headers);
        }

        self.send(request_builder).await
    }

    /// Send a custom request and parse the response
    async fn send<R>(&self, request: RequestBuilder) -> Result<R, PDPError>
    where
        R: DeserializeOwned + Send + 'static,
    {
        let response = request
            .send()
            .await
            .map_err(|e| PDPError::RequestFailed(format!("Failed to send request: {}", e)))?;

        if !response.status().is_success() {
            return Err(PDPError::ResponseError(
                response.status().as_u16(),
                format!("Request failed with status: {}", response.status()),
            ));
        }

        response.json::<R>().await.map_err(|e| {
            PDPError::DeserializationError(format!("Failed to deserialize response: {}", e))
        })
    }

    /// Send a custom request and return the raw response
    async fn send_raw(&self, request: RequestBuilder) -> Result<Response, PDPError> {
        request
            .send()
            .await
            .map_err(|e| PDPError::RequestFailed(format!("Failed to send request: {}", e)))
    }
}

/// An enum that can hold different types of PDPEngine implementations
#[derive(Clone, Debug)]
pub enum EngineType {
    /// A no-op engine that always returns errors
    Mock(MockEngine),
    /// A Python-based PDP engine
    Python(PDPPythonEngine),
}

#[async_trait]
impl PDPEngine for EngineType {
    async fn health(&self) -> bool {
        match self {
            EngineType::Mock(e) => e.health().await,
            EngineType::Python(e) => e.health().await,
        }
    }
    async fn wait_until_healthy(&self, timeout: Duration) -> Result<(), PDPError> {
        match self {
            EngineType::Mock(e) => e.wait_until_healthy(timeout).await,
            EngineType::Python(e) => e.wait_until_healthy(timeout).await,
        }
    }
    async fn stop(self) -> Result<(), PDPError> {
        match self {
            EngineType::Mock(e) => e.stop().await,
            EngineType::Python(e) => e.stop().await,
        }
    }
    fn request(
        &self,
        method: reqwest::Method,
        endpoint: &str,
    ) -> Result<reqwest::RequestBuilder, PDPError> {
        match self {
            EngineType::Mock(e) => e.request(method, endpoint),
            EngineType::Python(e) => e.request(method, endpoint),
        }
    }
    async fn get<R>(
        &self,
        endpoint: &str,
        headers: Option<reqwest::header::HeaderMap>,
    ) -> Result<R, PDPError>
    where
        R: DeserializeOwned + Send + 'static,
    {
        match self {
            EngineType::Mock(e) => e.get(endpoint, headers).await,
            EngineType::Python(e) => e.get(endpoint, headers).await,
        }
    }
    async fn post<T, R>(
        &self,
        endpoint: &str,
        payload: &T,
        headers: Option<reqwest::header::HeaderMap>,
    ) -> Result<R, PDPError>
    where
        T: Serialize + Send + Sync + 'static,
        R: DeserializeOwned + Send + 'static,
    {
        match self {
            EngineType::Mock(e) => e.post(endpoint, payload, headers).await,
            EngineType::Python(e) => e.post(endpoint, payload, headers).await,
        }
    }
    async fn put<T, R>(
        &self,
        endpoint: &str,
        payload: &T,
        headers: Option<reqwest::header::HeaderMap>,
    ) -> Result<R, PDPError>
    where
        T: Serialize + Send + Sync + 'static,
        R: DeserializeOwned + Send + 'static,
    {
        match self {
            EngineType::Mock(e) => e.put(endpoint, payload, headers).await,
            EngineType::Python(e) => e.put(endpoint, payload, headers).await,
        }
    }
    async fn patch<T, R>(
        &self,
        endpoint: &str,
        payload: &T,
        headers: Option<reqwest::header::HeaderMap>,
    ) -> Result<R, PDPError>
    where
        T: Serialize + Send + Sync + 'static,
        R: DeserializeOwned + Send + 'static,
    {
        match self {
            EngineType::Mock(e) => e.patch(endpoint, payload, headers).await,
            EngineType::Python(e) => e.patch(endpoint, payload, headers).await,
        }
    }
    async fn delete<R>(
        &self,
        endpoint: &str,
        headers: Option<reqwest::header::HeaderMap>,
    ) -> Result<R, PDPError>
    where
        R: DeserializeOwned + Send + 'static,
    {
        match self {
            EngineType::Mock(e) => e.delete(endpoint, headers).await,
            EngineType::Python(e) => e.delete(endpoint, headers).await,
        }
    }
    async fn send<R>(&self, request: reqwest::RequestBuilder) -> Result<R, PDPError>
    where
        R: DeserializeOwned + Send + 'static,
    {
        match self {
            EngineType::Mock(e) => e.send(request).await,
            EngineType::Python(e) => e.send(request).await,
        }
    }
    async fn send_raw(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, PDPError> {
        match self {
            EngineType::Mock(e) => e.send_raw(request).await,
            EngineType::Python(e) => e.send_raw(request).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::Arg;
    use crate::builder::PDPEngineBuilder;
    use log::LevelFilter;
    use std::time::Duration;

    #[tokio::test]
    #[ignore = "This test requires a real configuration to run the PDP server"]
    async fn test_builder_success() -> Result<(), PDPError> {
        let _ = env_logger::builder()
            .filter_level(LevelFilter::Debug)
            .is_test(true)
            .try_init();

        let builder = PDPEngineBuilder::new()
            .with_python_path("/Users/omerzuarets/.pyenv/versions/pdp-25/bin/python")?
            .with_pdp_dir("/Users/omerzuarets/IdeaProjects/Git/permit/sidecar")?
            .with_base_url("http://localhost:9876/")
            .with_args(vec![
                Arg::Module("uvicorn".to_string()),
                Arg::App("horizon.main:app".to_string()),
                Arg::Port(9876),
                Arg::Reload,
            ])
            .with_health_timeout(Duration::from_secs(5));

        let engine = builder.start().await?;
        engine.stop().await?;
        Ok(())
    }
}

// Uncomment when we figure out the correct path
// #[cfg(test)]
// pub use self::mock_pdp_engine::MockPDPEngine;
