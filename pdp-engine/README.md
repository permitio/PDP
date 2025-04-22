# PDP Engine

A Rust crate for managing a Python-based Policy Decision Point (PDP) server as a subprocess. This crate is designed to run and monitor a PDP server, automatically restarting it if it crashes, and providing a convenient interface to interact with it.

## Features

- Run a Python PDP server as a subprocess
- Monitor the subprocess health and automatically restart it if it crashes
- Configure the PDP via CLI arguments and environment variables
- Health checking and automatic recovery
- Clean shutdown and process management

## Usage

```rust
use pdp_engine::args::Arg;
use pdp_engine::builder::PDPEngineBuilder;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the logger
    env_logger::init();

    // Create a builder for the PDP engine
    let builder = PDPEngineBuilder::new()
        .with_python_path("/path/to/python")?
        .with_pdp_dir("/path/to/pdp")?
        .with_base_url("http://localhost:7001/")
        .with_args(vec![
            Arg::Module("uvicorn".to_string()),
            Arg::App("horizon.main:app".to_string()),
            Arg::Port(7001),
            Arg::Reload,
        ])
        .add_env("PDP_API_KEY".to_string(), "<your-permit-token>".to_string())
        .add_env("PDP_DEBUG".to_string(), "true".to_string())
        .with_health_timeout(Duration::from_secs(10));

    // Start the PDP engine
    let engine = builder.start().await?;

    // Do some work with the PDP engine

    // When done, stop the PDP engine
    engine.stop().await?;

    Ok(())
}
```

## Running the Example

To run the example provided with the crate:

```bash
PDP_API_KEY=<your-token> cargo run --example run_pdp
```

The example demonstrates starting a PDP server, keeping it running until interrupted (Ctrl+C), and then shutting it down gracefully.

## Configuration

The builder pattern allows you to configure:

- The Python binary path (`with_python_path`)
- The PDP directory where the application code resides (`with_pdp_dir`)
- CLI arguments for the PDP server (`with_args` or `add_arg`)
- Environment variables (`with_env_vars` to set all variables or `add_env` to add individual variables)
- Base URL for the PDP server (`with_base_url`)
- Health check timeout (`with_health_timeout`)
- Health check interval (`with_health_check_interval`)

### Environment Variables

By default, the PDP subprocess inherits all environment variables from the parent process. You can also:

- Add or override specific environment variables using `add_env`
- Replace all environment variables with your own set using `with_env_vars`

This makes it easy to pass configuration from your application to the PDP server without having to enumerate all variables.

## Health Checking

The PDP engine automatically monitors the health of the PDP server. By default, it:

1. Waits for the server to become healthy on startup
2. Checks the `/healthy` endpoint periodically
3. Attempts to restart the server if it becomes unhealthy

You can disable health monitoring by setting the health check interval to zero:

```rust
builder.with_health_check_interval(Duration::from_secs(0))
```
