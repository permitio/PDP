//! # pdp-engine
//!
//! A crate for interacting with a Python-based Policy Decision Point (PDP) server.
//!
//! ## Components
//!
//! - **Runner:** Runs PDP as a subprocess with a typed CLI arguments API.
//! - **Client:** HTTP client for interacting with the PDP API.
//! - **Engine:** High-level API for configuring and querying the PDP.

mod args;
mod builder;
mod error;
mod health;
mod mock_engine;
mod python_engine;
mod runner;

// Flattening public API for easier access
pub use crate::args::*;
pub use crate::builder::*;
pub use crate::error::PDPError;
pub use crate::mock_engine::MockEngine;
pub use crate::python_engine::PDPPythonEngine;

use async_trait::async_trait;
use reqwest::{RequestBuilder, Response};
use serde::{Serialize, de::DeserializeOwned};
use std::time::Duration;

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
