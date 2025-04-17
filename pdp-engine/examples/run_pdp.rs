use pdp_engine::args::Arg;
use pdp_engine::builder::PDPEngineBuilder;
use pdp_engine::PDPEngine;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the logger
    env_logger::init();

    // Create a builder for the PDP engine
    let builder = PDPEngineBuilder::new()
        .with_located_python()?
        .with_pdp_dir("./PDP")?
        .with_base_url("http://localhost:7001/")
        .with_args(vec![
            Arg::Module("uvicorn".to_string()),
            Arg::App("horizon.main:app".to_string()),
            Arg::Port(7001),
            Arg::Reload,
        ])
        .add_env("PDP_DEBUG".to_string(), "true".to_string())
        .with_health_timeout(Duration::from_secs(360));

    // Start the PDP engine
    println!("Starting PDP engine...");
    let engine = builder.start().await?;

    // Wait a moment to let it run
    println!("PDP is running, press Ctrl+C to exit...");
    tokio::signal::ctrl_c().await?;

    // Stop the PDP engine
    println!("Stopping PDP engine...");
    engine.stop().await?;

    println!("PDP engine stopped.");
    Ok(())
}
