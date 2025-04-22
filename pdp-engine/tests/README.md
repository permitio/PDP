# Integration Tests for Horizon Runner

This directory contains integration tests for the Horizon Runner crate. These tests interact with the actual Horizon PDP service.

## Requirements

- Python environment with Horizon dependencies installed
- Rust development environment
- Environment variables properly configured

## Running the tests

1. Copy the `.env.example` file to `.env` in the root of the `horizon-runner` directory:
   ```
   cp .env.example .env
   ```

2. Edit the `.env` file to uncomment and set the `PDP_API_KEY` value:
   ```
   PDP_API_KEY=your_test_api_key_here
   ```

3. Run the integration tests:
   ```
   cargo test --test integration_tests
   ```

## Notes

- The integration tests will start a real Python PDP process, so ensure you have the necessary Python environment set up
- If `PDP_API_KEY` is not set in the environment or `.env` file, the tests will use a fallback value of "test_key" (which may not work depending on your PDP configuration)
- The tests use a port (9876 by default) that should be available on your machine
