use crate::config::PDPConfig;
use crate::create_app;
use crate::state::AppState;
use axum::body::Body;
use axum::Router;
use http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use log::LevelFilter;
use serde::{de::DeserializeOwned, Serialize};
use tower::ServiceExt;
use wiremock::matchers;
use wiremock::Mock;
use wiremock::MockServer;
use wiremock::ResponseTemplate;

/// Test fixture for setting up a complete test environment with mocked services.
///
/// The TestFixture provides a convenient way to test API endpoints with mock backends for
/// external services like OPA and Horizon. It automatically sets up mock servers, configures
/// the application, and provides helper methods for making requests.
///
/// # Examples
///
/// ```rust
/// #[tokio::test]
/// async fn test_endpoint() {
///     // Create a new test fixture with mock servers
///     let fixture = TestFixture::new().await;
///
///     // Set up a mock OPA response
///     Mock::given(matchers::method("POST"))
///         .and(matchers::path("/v1/data/permit/root"))
///         .respond_with(ResponseTemplate::new(200)
///             .set_body_json(json!({
///                 "result": { "allow": true }
///             })))
///         .mount(&fixture.opa_mock)
///         .await;
///
///     // Create test query data
///     let test_query = create_test_data();
///
///     // Send a request to the API
///     let response = fixture.post("/endpoint", &test_query).await;
///
///     // Verify the response
///     response.assert_ok();
///     let result = response.json_as::<YourResponseType>();
///     assert!(result.some_field);
/// }
/// ```
pub struct TestFixture {
    /// The application router
    pub app: Router,
    /// The application state
    pub state: AppState,
    /// Configuration settings
    pub config: PDPConfig,
    /// Mock server for OPA
    pub opa_mock: MockServer,
    /// Mock server for Horizon
    pub horizon_mock: MockServer,
}

impl TestFixture {
    /// Creates a new test fixture with mock servers for OPA and Horizon.
    ///
    /// This method sets up:
    /// - Mock servers for OPA and Horizon
    /// - Application settings configured to use the mock servers
    /// - The application router with test state
    ///
    /// # Examples
    ///
    /// ```rust
    /// #[tokio::test]
    /// async fn test_example() {
    ///     let fixture = TestFixture::new().await;
    ///
    ///     // The fixture is ready to use for testing
    ///     // You can now set up mock responses and make requests
    /// }
    /// ```
    pub async fn new() -> Self {
        // Initialize test logger
        let _ = env_logger::builder()
            .filter_level(LevelFilter::Debug)
            .is_test(true)
            .try_init();

        // Create mock servers
        let opa_mock = MockServer::start().await;
        let horizon_mock = MockServer::start().await;

        // Create settings configured with mocks
        let config = PDPConfig::for_test_with_mocks(&horizon_mock, &opa_mock);

        // Create app state
        let state = AppState::for_testing(&config);
        let app = create_app(state.clone()).await;

        Self {
            app,
            state,
            config,
            opa_mock,
            horizon_mock,
        }
    }

    /// Creates a new test fixture with custom configuration.
    ///
    /// This method creates a fixture and then allows modifying its config
    /// before it's returned, making it easy to create tests with custom settings.
    ///
    /// # Parameters
    ///
    /// - `config_modifier`: A function that modifies the config
    ///
    /// # Returns
    ///
    /// A TestFixture with the modified configuration
    ///
    /// # Examples
    ///
    /// ```rust
    /// #[tokio::test]
    /// async fn test_with_custom_config() {
    ///     let fixture = TestFixture::with_config_modifier(|config| {
    ///         config.use_new_authorized_users = true;
    ///         config.custom_option = "test value".to_string();
    ///     }).await;
    ///
    ///     // The fixture now has custom configuration
    /// }
    /// ```
    pub async fn with_config_modifier(mut config_modifier: impl FnMut(&mut PDPConfig)) -> Self {
        // Create mock servers
        let opa_mock = MockServer::start().await;
        let horizon_mock = MockServer::start().await;

        // Create settings configured with mocks
        let mut config = PDPConfig::for_test_with_mocks(&horizon_mock, &opa_mock);

        // Apply the config modifications
        config_modifier(&mut config);

        Self::with_config(config, opa_mock, horizon_mock).await
    }

    /// Creates a new test fixture with a provided configuration.
    ///
    /// This method allows providing a fully configured PDPConfig object directly.
    ///
    /// # Parameters
    ///
    /// - `config`: The configuration to use
    ///
    /// # Returns
    ///
    /// A TestFixture with the provided configuration
    ///
    /// # Examples
    ///
    /// ```rust
    /// #[tokio::test]
    /// async fn test_with_specific_config() {
    ///     // Create mock servers
    ///     let opa_mock = MockServer::start().await;
    ///     let horizon_mock = MockServer::start().await;
    ///
    ///     // Create and customize a config
    ///     let mut config = PDPConfig::for_test_with_mocks(&horizon_mock, &opa_mock);
    ///     config.use_new_authorized_users = true;
    ///
    ///     // Create fixture with the config
    ///     let fixture = TestFixture::with_config(config, opa_mock, horizon_mock).await;
    ///
    ///     // The fixture now has the specific configuration
    /// }
    /// ```
    pub async fn with_config(
        config: PDPConfig,
        opa_mock: MockServer,
        horizon_mock: MockServer,
    ) -> Self {
        // Create app state with the config
        let state = AppState::for_testing(&config);
        let app = create_app(state.clone()).await;

        Self {
            app,
            state,
            config,
            opa_mock,
            horizon_mock,
        }
    }

    /// Initializes the test logger with customized settings.
    ///
    /// This method can be called to configure custom log levels for tests.
    /// Note that this is automatically called by TestFixture::new() with default settings.
    /// Only use this method if you need specific logger configuration.
    ///
    /// # Parameters
    ///
    /// - `level`: The log level filter to apply
    ///
    /// # Examples
    ///
    /// ```rust
    /// #[tokio::test]
    /// async fn test_with_custom_logger() {
    ///     // Set up trace-level logging for this test
    ///     TestFixture::setup_logger(log::LevelFilter::Trace);
    ///
    ///     // Create the fixture and run tests
    ///     let fixture = TestFixture::new().await;
    ///     // ...
    /// }
    /// ```
    pub fn setup_logger(level: LevelFilter) {
        let _ = env_logger::builder()
            .filter_level(level)
            .is_test(true)
            .try_init();
    }

    /// Creates a request builder with pre-configured headers.
    ///
    /// The request builder includes standard headers:
    /// - Authorization: Bearer token using the test API key
    /// - Content-Type: application/json
    ///
    /// # Parameters
    ///
    /// - `method`: The HTTP method for the request
    /// - `uri`: The URI path for the request (e.g., "/allowed")
    ///
    /// # Returns
    ///
    /// A request builder that can be further customized before sending.
    ///
    /// # Examples
    ///
    /// ```rust
    /// // Create a custom request with additional headers
    /// let request = fixture.request_builder(Method::POST, "/some/endpoint")
    ///     .header("X-Custom-Header", "value")
    ///     .body(Body::from(json_body))
    ///     .expect("Failed to build request");
    ///
    /// let response = fixture.send(request).await;
    /// ```
    pub fn request_builder(&self, method: Method, uri: impl AsRef<str>) -> http::request::Builder {
        let mut builder = Request::builder().method(method).uri(uri.as_ref());

        // Add default headers
        builder = builder.header("Authorization", format!("Bearer {}", self.config.api_key));
        builder = builder.header("Content-Type", "application/json");

        builder
    }

    /// Sends a GET request to the specified URI.
    ///
    /// # Parameters
    ///
    /// - `uri`: The URI path for the request (e.g., "/allowed")
    ///
    /// # Returns
    ///
    /// A `TestResponse` containing the status code and response body.
    ///
    /// # Examples
    ///
    /// ```rust
    /// // Send a GET request to fetch a resource
    /// let response = fixture.get("/resources/123").await;
    ///
    /// // Assert the response is successful and contains expected data
    /// response.assert_ok();
    /// let resource = response.json_as::<Resource>();
    /// assert_eq!(resource.id, "123");
    /// ```
    pub async fn get(&self, uri: impl AsRef<str>) -> TestResponse {
        let request = self
            .request_builder(Method::GET, uri)
            .body(Body::empty())
            .expect("Failed to build request");

        self.send(request).await
    }

    /// Sends a POST request with a JSON body to the specified URI.
    ///
    /// # Parameters
    ///
    /// - `uri`: The URI path for the request (e.g., "/allowed")
    /// - `body`: The request body to serialize as JSON
    ///
    /// # Returns
    ///
    /// A `TestResponse` containing the status code and response body.
    ///
    /// # Examples
    ///
    /// ```rust
    /// // Create test data for the request
    /// let query = AllowedQuery {
    ///     user: User { key: "test-user".to_string(), ... },
    ///     action: "read".to_string(),
    ///     resource: Resource { ... },
    ///     context: HashMap::new(),
    ///     sdk: None,
    /// };
    ///
    /// // Send the POST request
    /// let response = fixture.post("/allowed", &query).await;
    ///
    /// // Verify the response
    /// response.assert_ok();
    /// let result = response.json_as::<AllowedResult>();
    /// assert!(result.allow);
    /// ```
    pub async fn post<T: Serialize>(&self, uri: impl AsRef<str>, body: &T) -> TestResponse {
        let json_body = serde_json::to_vec(body).expect("Failed to serialize body to JSON");
        let request = self
            .request_builder(Method::POST, uri)
            .body(Body::from(json_body))
            .expect("Failed to build request");

        self.send(request).await
    }

    /// Sends a POST request with a JSON body and custom headers.
    ///
    /// # Parameters
    ///
    /// - `uri`: The URI path for the request (e.g., "/allowed")
    /// - `body`: The request body to serialize as JSON
    /// - `headers`: Array of header name-value pairs to add to the request
    ///
    /// # Returns
    ///
    /// A `TestResponse` containing the status code and response body.
    ///
    /// # Examples
    ///
    /// ```rust
    /// // Create test data for the request
    /// let query = create_test_query();
    ///
    /// // Define custom headers
    /// let custom_headers = &[
    ///     ("X-Trace-ID", "test-trace-123"),
    ///     ("X-Custom-Header", "test-value"),
    /// ];
    ///
    /// // Send the POST request with custom headers
    /// let response = fixture.post_with_headers("/allowed", &query, custom_headers).await;
    ///
    /// // Verify the response
    /// response.assert_ok();
    /// let result = response.json_as::<AllowedResult>();
    /// assert!(result.allow);
    /// ```
    pub async fn post_with_headers<T: Serialize>(
        &self,
        uri: impl AsRef<str>,
        body: &T,
        headers: &[(&str, &str)],
    ) -> TestResponse {
        let json_body = serde_json::to_vec(body).expect("Failed to serialize body to JSON");
        let mut builder = self.request_builder(Method::POST, uri);

        // Add custom headers
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }

        let request = builder
            .body(Body::from(json_body))
            .expect("Failed to build request");

        self.send(request).await
    }

    /// Sends a request and returns a TestResponse.
    ///
    /// This is a lower-level method that is used by the convenience methods
    /// like `get()` and `post()`. Use this method when you need more control
    /// over the request details.
    ///
    /// # Parameters
    ///
    /// - `request`: The HTTP request to send
    ///
    /// # Returns
    ///
    /// A `TestResponse` containing the status code and response body.
    ///
    /// # Examples
    ///
    /// ```rust
    /// // Create an invalid query (missing required fields)
    /// let invalid_query = json!({
    ///     "action": "read",
    ///     // Missing user and resource
    /// });
    ///
    /// // Build a custom request
    /// let request = fixture.request_builder(Method::POST, "/allowed")
    ///     .body(Body::from(serde_json::to_vec(&invalid_query).unwrap()))
    ///     .expect("Failed to build request");
    ///
    /// // Send the request
    /// let response = fixture.send(request).await;
    ///
    /// // Should get a 422 Unprocessable Entity for invalid request
    /// response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
    /// ```
    pub async fn send(&self, request: Request<Body>) -> TestResponse {
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("Failed to send request");

        let status = response.status();
        let headers = response.headers().clone();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("Failed to read response body")
            .to_bytes()
            .to_vec();

        TestResponse {
            status,
            headers,
            body,
        }
    }

    /// Adds a mock OPA route with the given method, path, and response.
    ///
    /// This is a convenience method for setting up OPA mock responses in tests.
    ///
    /// # Parameters
    ///
    /// - `method`: The HTTP method (e.g., Method::POST)
    /// - `path`: The API path to mock (e.g., "/v1/data/permit/root")
    /// - `response_body`: The JSON response body to return
    /// - `status_code`: HTTP status code for the response
    /// - `expected_calls`: Number of expected calls to this mock
    ///
    /// # Examples
    ///
    /// ```rust
    /// // Setup a mock for the /v1/data/permit/root OPA route
    /// let mock = fixture.add_opa_mock(
    ///     Method::POST,
    ///     "/v1/data/permit/root",
    ///     json!({ "result": { "allow": true } }),
    ///     StatusCode::OK,
    ///     1
    /// ).await;
    ///
    /// // Send a request that should use this mock
    /// let response = fixture.post("/allowed", &query).await;
    /// ```
    pub async fn add_opa_mock(
        &self,
        method: Method,
        path: impl Into<String>,
        response_body: impl Serialize,
        status_code: StatusCode,
        expected_calls: u64,
    ) {
        let path_string = path.into();

        Mock::given(matchers::method(method.as_str()))
            .and(matchers::path(path_string))
            .respond_with(ResponseTemplate::new(status_code.as_u16()).set_body_json(response_body))
            .expect(expected_calls)
            .mount(&self.opa_mock)
            .await;
    }
}

/// Response from a test request that provides convenient access to status and JSON body.
///
/// TestResponse simplifies assertions on responses and accessing their content.
pub struct TestResponse {
    /// HTTP status code
    pub status: StatusCode,
    /// Response headers
    pub headers: http::HeaderMap,
    /// Raw response body
    pub body: Vec<u8>,
}

impl TestResponse {
    /// Asserts that the response has the expected status code.
    ///
    /// # Parameters
    ///
    /// - `expected`: The expected HTTP status code
    ///
    /// # Returns
    ///
    /// A reference to self for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust
    /// // Expect a not found status
    /// response.assert_status(StatusCode::NOT_FOUND);
    ///
    /// // Chain assertions
    /// response
    ///     .assert_status(StatusCode::OK)
    ///     .json_as::<MyResponseType>();
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if the status code doesn't match the expected value.
    pub fn assert_status(&self, expected: StatusCode) -> &Self {
        assert_eq!(
            self.status,
            expected,
            "Expected status {} but got {} with body: {}",
            expected,
            self.status,
            String::from_utf8_lossy(&self.body)
        );
        self
    }

    /// Asserts that the response status is OK (200).
    ///
    /// A shorthand for `assert_status(StatusCode::OK)`.
    ///
    /// # Returns
    ///
    /// A reference to self for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust
    /// // Assert response is OK and then extract the result
    /// let result = response
    ///     .assert_ok()
    ///     .json_as::<AllowedResult>();
    /// assert!(result.allow);
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if the status code is not 200 OK.
    pub fn assert_ok(&self) -> &Self {
        self.assert_status(StatusCode::OK)
    }

    /// Get the response body as a JSON value.
    ///
    /// # Returns
    ///
    /// The response body parsed as JSON. If the body is not valid JSON and not empty,
    /// it will be returned as a JSON string. If empty, returns an empty JSON object.
    ///
    /// # Panics
    ///
    /// This function does not panic, but returns a default value if parsing fails.
    pub fn json(&self) -> serde_json::Value {
        if self.body.is_empty() {
            return serde_json::json!({});
        }

        serde_json::from_slice(&self.body).unwrap_or_else(|_| {
            // Try to convert to UTF-8 string and use as a JSON string value
            match std::str::from_utf8(&self.body) {
                Ok(s) => serde_json::Value::String(s.to_string()),
                Err(_) => serde_json::json!({}), // If not valid UTF-8, default to empty object
            }
        })
    }

    /// Converts the response body to the specified type.
    ///
    /// # Type Parameters
    ///
    /// - `T`: The type to deserialize the response into
    ///
    /// # Returns
    ///
    /// The deserialized value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// // Get the response and deserialize it
    /// let response = fixture.post("/allowed", &query).await;
    /// response.assert_ok();
    ///
    /// // Convert to a specific type
    /// let result = response.json_as::<AllowedResult>();
    /// assert!(result.allow);
    /// assert_eq!(result.debug.as_ref().unwrap().get("policy").unwrap(), "test-policy");
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if deserialization fails.
    pub fn json_as<T: DeserializeOwned>(&self) -> T {
        serde_json::from_slice(&self.body).expect("Failed to deserialize response JSON")
    }

    /// Asserts that the response has a header with the expected value.
    ///
    /// # Parameters
    ///
    /// - `name`: The header name
    /// - `expected_value`: The expected header value
    ///
    /// # Returns
    ///
    /// A reference to self for method chaining.
    ///
    /// # Panics
    ///
    /// Panics if the header is missing or doesn't match the expected value.
    pub fn assert_header(&self, name: &str, expected_value: &str) -> &Self {
        let header = self
            .headers
            .get(name)
            .unwrap_or_else(|| panic!("Header '{name}' not found"));
        assert_eq!(
            header.to_str().unwrap(),
            expected_value,
            "Expected header '{}' to have value '{}' but got '{}'",
            name,
            expected_value,
            header.to_str().unwrap_or_default()
        );
        self
    }

    /// Gets the response headers.
    ///
    /// # Returns
    ///
    /// A reference to the response headers.
    #[allow(dead_code)]
    pub fn headers(&self) -> &http::HeaderMap {
        &self.headers
    }

    /// Converts the response into its body.
    ///
    /// # Returns
    ///
    /// The response body.
    pub fn into_body(self) -> Body {
        Body::from(self.body)
    }

    /// Get the response body as a UTF-8 string.
    ///
    /// # Returns
    ///
    /// The response body converted to a string. If the body is not valid UTF-8,
    /// returns an empty string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let response = fixture.get("/some-text-endpoint").await;
    /// let text = response.text();
    /// assert!(text.contains("Expected message"));
    /// ```
    #[allow(dead_code)]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }
}
