use crate::PDPEngine;
use crate::error::PDPError;

use async_trait::async_trait;
use log::error;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Client, RequestBuilder, Response, header};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::time::Duration;
use url::Url;

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
                error!(
                    "Failed to create bearer header value from given token, please check your configuration"
                );
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
