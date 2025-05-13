# Watchdog

A Rust library for monitoring and automatically restarting services and processes.

## Features

- **CommandWatchdog**: Automatically restarts a process when it terminates
- **ServiceWatchdog**: Monitors service health and restarts services that are unhealthy
- **Health Checkers**: HTTP, TCP, and composite health checks to monitor service health
- **Configurable**: Customizable retry intervals, health check thresholds, and startup delays
- **Statistics**: Track health checks, failures, and restarts
- **Graceful Termination**: Uses SIGTERM with a configurable timeout before SIGKILL

## Usage

### CommandWatchdog

```rust
use tokio::process::Command;
use watchdog::CommandWatchdog;

// Create a command to run your process
let mut cmd = Command::new("my-service");
cmd.args(["--port", "8080"]);

// Start the watchdog to monitor the process
let watchdog = CommandWatchdog::start(cmd);

// The process will be automatically restarted if it terminates
// When the watchdog is dropped, the process will be terminated gracefully

// You can also manually restart the process
watchdog.restart().await.expect("Failed to restart process");
```

### ServiceWatchdog

The `ServiceWatchdog` adds health checking capabilities to restart unresponsive services:

```rust
use tokio::process::Command;
use watchdog::{
    HttpHealthChecker, ServiceWatchdog, ServiceWatchdogOptions,
};
use std::time::Duration;

// Create a command to run your service
let mut cmd = Command::new("my-service");
cmd.args(["--port", "8080"]);

// Create a health checker to monitor the service
let health_checker = HttpHealthChecker::new("http://localhost:8080/health".to_string());

// Configure the service watchdog
let config = ServiceWatchdogOptions {
    health_check_interval: Duration::from_secs(10),
    health_check_failure_threshold: 3,
    initial_startup_delay: Duration::from_secs(5),
};

// Create and start the service watchdog
let watchdog = ServiceWatchdog::start_with_options(
    cmd,
    health_checker,
    config,
);

// Wait for the service to become healthy before proceeding
watchdog.wait_for_healthy(Duration::from_secs(30)).await
    .expect("Service failed to become healthy within timeout");

// Get statistics about the service watchdog
println!("Health checks: {}", watchdog.stats().health_checks());
println!("Failed health checks: {}", watchdog.stats().failed_health_checks());
println!("Health-triggered restarts: {}", watchdog.stats().health_restart_count());

// Manually restart the service if needed
watchdog.restart().await.expect("Failed to restart service");
```

### Waiting for Service Health

It's common to need to wait for a service to become healthy after starting it:

```rust
// Start the service watchdog
let watchdog = ServiceWatchdog::start(cmd, health_checker);

// Wait for the service to become healthy with a timeout
match watchdog.wait_for_healthy(Duration::from_secs(60)).await {
    Ok(_) => println!("Service is healthy and ready to use"),
    Err(e) => println!("Service failed to become healthy: {}", e),
}

// Alternatively, wait indefinitely for the service to become healthy
watchdog.wait_for_healthy(None).await
    .expect("Service failed to become healthy");
```

### Using Multiple Health Checks

```rust
use watchdog::{CompositeHealthChecker, HttpHealthChecker, TcpHealthChecker};

// Create multiple health checkers
let http_checker = HttpHealthChecker::new("http://localhost:8080/health".to_string());
let tcp_checker = TcpHealthChecker::new("localhost:8080".to_string());

// Combine them into a composite health checker
let mut composite_checker = CompositeHealthChecker::new();
composite_checker.add(Box::new(http_checker));
composite_checker.add(Box::new(tcp_checker));

// Use the composite checker with the service watchdog
let watchdog = ServiceWatchdog::start(cmd, composite_checker);
```

### Customizing Health Checks

Health checks handle their own timeouts:

```rust
use std::time::Duration;
use watchdog::HttpHealthChecker;

// HTTP health checker with custom timeout and expected status code
let health_checker = HttpHealthChecker::with_options(
    "http://localhost:8080/health".to_string(),
    200,  // Expected status code
    Duration::from_secs(3)  // Timeout
);

// TCP health checker with custom timeout
let tcp_checker = TcpHealthChecker::with_timeout(
    "localhost:8080".to_string(),
    Duration::from_secs(2)
);
```

## Configuration Options

### CommandWatchdogOptions

- `restart_interval`: Maximum duration between restarts (default: 1s)
- `termination_timeout`: Maximum time to wait for a process to terminate after SIGTERM (default: 60s)

### ServiceWatchdogOptions

- `health_check_interval`: How often to check service health (default: 10s)
- `health_check_failure_threshold`: How many consecutive health check failures before restarting (default: 3)
- `initial_startup_delay`: How long to wait before starting health checks after a restart (default: 5s)

## Implementation Details

The `ServiceWatchdog` builds upon `CommandWatchdog` by adding:
1. Health checking with configurable checks and intervals
2. Automatic restart when health checks fail consecutively
3. Statistics tracking for health checks and restarts

Each health checker implementation handles its own timeout configuration, so health checks can have different timeouts based on their specific needs.
