use dotenv::dotenv;
use log::LevelFilter;
use pdp_engine::Arg;
use pdp_engine::PDPEngine;
use pdp_engine::PDPEngineBuilder;
use pdp_engine::PDPError;
use std::env;
use std::str::FromStr;
use std::time::Duration;

/// Integration test for the HorizonEngine builder.
/// This test requires a Python environment with Horizon installed.
///
/// Set environment variables in .env file:
/// - PDP_API_KEY: API key for the PDP service
/// - PDP_PORT: Port to run the test PDP service on (default: 9876)
/// - PDP_HEALTH_TIMEOUT: Timeout for health checks in seconds (default: 5)
#[tokio::test]
async fn test_builder_success() -> Result<(), PDPError> {
    // Load environment variables from .env file
    dotenv().ok();

    // Ensure PDP_API_KEY is set
    let api_key = env::var("PDP_API_KEY").expect("PDP_API_KEY must be set");

    // Get port from environment or use default
    let port = env::var("PDP_PORT")
        .ok()
        .and_then(|p| u16::from_str(&p).ok())
        .unwrap_or(7001);

    // Get health timeout from environment or use default
    let health_timeout = env::var("PDP_HEALTH_TIMEOUT")
        .map(|t| u64::from_str(&t).unwrap_or(5))
        .unwrap_or(5);

    let _ = env_logger::builder()
        .filter_level(LevelFilter::Debug)
        .is_test(true)
        .try_init();

    println!("Starting PDP on port {port} with health timeout of {health_timeout}s");

    let builder = PDPEngineBuilder::new()
        .with_located_python()
        .unwrap()
        .with_pdp_dir("../horizon")?
        .with_base_url(&format!("http://localhost:{}/", port))
        .with_args(vec![
            Arg::Module("uvicorn".to_string()),
            Arg::App("horizon.main:app".to_string()),
            Arg::Port(port),
            Arg::Reload,
        ])
        .add_env("PDP_API_KEY".to_string(), api_key)
        .with_health_timeout(Duration::from_secs(health_timeout));

    let engine = builder.start().await?;
    println!("PDP started successfully, checking health...");
    assert!(
        engine.health().await,
        "PDP not healthy after runner has started"
    );
    println!("PDP is healthy, stopping...");
    engine.stop().await?;
    println!("PDP stopped successfully");
    Ok(())
}
