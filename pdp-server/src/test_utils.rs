use crate::config::Settings;
use crate::create_app;
use crate::state::AppState;
use axum::body::Body;
use axum::Router;
use env_logger;
use http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use log::LevelFilter;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
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
    /// Configuration settings
    pub settings: Settings,
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
        let settings = Settings::for_test_with_mocks(&horizon_mock, &opa_mock);

        // Create app state
        let state = AppState::for_testing(&settings);
        let app = create_app(state).await;

        Self {
            app,
            settings,
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
        builder = builder.header("Authorization", format!("Bearer {}", self.settings.api_key));
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
        let body = response
            .into_body()
            .collect()
            .await
            .expect("Failed to read response body")
            .to_bytes();

        // Try to parse as JSON, defaulting to empty object if parsing fails or empty body
        let json = if !body.is_empty() {
            serde_json::from_slice(&body).unwrap_or_else(|_| serde_json::json!({}))
        } else {
            serde_json::json!({})
        };

        TestResponse { status, json }
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
    ) -> () {
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
    /// Response body as JSON (if present and valid JSON)
    pub json: Value,
}

impl TestResponse {
    /// Checks if the response status is successful (2xx).
    ///
    /// # Returns
    ///
    /// `true` if the status code is in the 200-299 range, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let response = fixture.get("/resource").await;
    /// if response.is_success() {
    ///     // Process successful response
    /// } else {
    ///     // Handle error
    /// }
    /// ```
    pub fn is_success(&self) -> bool {
        self.status.is_success()
    }

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
            serde_json::to_string_pretty(&self.json).unwrap_or_default()
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
        serde_json::from_value(self.json.clone()).expect("Failed to deserialize response JSON")
    }
}
