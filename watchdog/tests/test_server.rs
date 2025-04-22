use reqwest::Client;
use serde::Deserialize;
use std::net::{SocketAddr, TcpListener};
use std::time::Duration;
use tokio::process::Command;

#[derive(Debug, Clone)]
pub struct TestServer {
    port: u16,
    pub base_url: String,
    pub client: Client,
}

impl TestServer {
    pub fn new() -> Self {
        let port = Self::find_available_port();
        let base_url = format!("http://localhost:{}", port);
        let client = Client::new();
        TestServer {
            port,
            base_url,
            client,
        }
    }

    /// Find an available port for testing
    pub fn find_available_port() -> u16 {
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let listener = TcpListener::bind(addr).unwrap();
        listener.local_addr().unwrap().port()
    }

    pub fn get_command(&self) -> Command {
        let mut command = Command::new("python3");
        command.arg("tests/test_server.py");
        command.arg("--port");
        command.arg(self.port.to_string());
        command
    }

    /// Send a ping request to the server
    pub async fn ping(&self) -> reqwest::Result<String> {
        let resp = self
            .client
            .get(format!("{}/ping", self.base_url))
            .send()
            .await?
            .error_for_status()?;
        resp.text().await
    }

    /// Send a ping request to the server
    pub async fn health(&self) -> reqwest::Result<String> {
        let resp = self
            .client
            .get(format!("{}/health", self.base_url))
            .send()
            .await?
            .error_for_status()?;
        resp.text().await
    }

    /// Retrieve the server status
    pub async fn status(&self) -> reqwest::Result<StatusResult> {
        let resp = self
            .client
            .get(format!("{}/status", self.base_url))
            .send()
            .await?
            .error_for_status()?;
        resp.json().await
    }

    /// Crash the server
    pub async fn crash(&self) -> reqwest::Result<String> {
        let resp = self
            .client
            .post(format!("{}/crash", self.base_url))
            .send()
            .await?
            .error_for_status()?;
        resp.text().await
    }

    /// Make the server unhealthy
    pub async fn make_unhealthy(&self) -> reqwest::Result<String> {
        let resp = self
            .client
            .post(format!("{}/unhealthy", self.base_url))
            .send()
            .await?
            .error_for_status()?;
        resp.text().await
    }

    /// Make the server health checks unresponsive
    pub async fn make_unresponsive(&self) -> reqwest::Result<String> {
        let resp = self
            .client
            .post(format!("{}/unresponsive", self.base_url))
            .send()
            .await?
            .error_for_status()?;
        resp.text().await
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct StatusResult {
    pub pid: u32,
    pub uptime: f32,
    pub request_count: u32,
}
