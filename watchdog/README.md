# Watchdog

A Rust library for monitoring and automatically restarting services and processes.

## Features

- **CommandWatchdog**: Restarts a process when it exits, backing off while it keeps failing
- **ServiceWatchdog**: Checks a service's health and restarts it when the checks keep failing
- **Health checks**: `HttpHealthChecker` for HTTP endpoints; implement `HealthCheck` for any other check
- **Configurable**: Restart intervals and backoff cap, health check interval and threshold, startup delay and termination timeout
- **Statistics**: Starts, last exit code, failures in a row, health checks and failed health checks
- **Graceful Termination**: Uses SIGTERM with a configurable timeout before SIGKILL
- **Child Output Capture**: Optionally capture a child's stdout/stderr and receive it line by line, so its output can be attributed to the process that produced it

The examples below are compiled as doctests of this crate, so they stay in step with its API.
The ones that start a process are compiled but not run.

## Usage

### CommandWatchdog

```rust no_run
use tokio::process::Command;
use watchdog::CommandWatchdog;

#[tokio::main]
async fn main() {
    // Create a command to run your process
    let mut cmd = Command::new("my-service");
    cmd.args(["--port", "8080"]);

    // Start the process; whenever it exits, the watchdog starts it again
    let watchdog = CommandWatchdog::start(cmd);

    // You can also restart the process yourself
    watchdog.restart().await.expect("the watchdog has shut down");

    println!("Started {} times", watchdog.start_counter());

    // Dropping the watchdog terminates the process gracefully
    drop(watchdog);
}
```

### Capturing child output

By default a watched child inherits the parent's stdout and stderr, so its
output is indistinguishable from the parent's. Supply a `ChildOutputHandler` to
receive it line by line instead:

```rust no_run
use std::sync::Arc;
use tokio::process::Command;
use watchdog::{ChildOutputHandler, ChildStream, CommandWatchdog, CommandWatchdogOptions};

struct LogLines;

impl ChildOutputHandler for LogLines {
    fn on_line(&self, stream: ChildStream, line: &str) {
        log::info!("[my-service {stream}] {line}");
    }
}

#[tokio::main]
async fn main() {
    let opt = CommandWatchdogOptions {
        output_handler: Some(Arc::new(LogLines)),
        ..Default::default()
    };
    let _watchdog = CommandWatchdog::start_with_opt(Command::new("my-service"), opt);
}
```

The handler runs on the task that keeps the child's pipes drained. Bounded,
synchronous work — a line-buffered write through a logger, as above — is fine.
What must not happen is `await`ing, an unbounded blocking call, or taking a lock
some other task may hold for a long time: for as long as `on_line` has not
returned, that task is not reading, and a pipe that stops being read fills its
kernel buffer and the child then blocks in `write`. Panicking is worse than
stalling — it drops the pipe handle, closing the read end, so a child that goes
on writing takes `SIGPIPE` and dies.

Lines longer than `MAX_LINE_BYTES` (16 KiB read from the child) are delivered
truncated with `TRUNCATION_MARKER` appended.

### ServiceWatchdog

The `ServiceWatchdog` adds health checks, and restarts a service that keeps failing them:

```rust no_run
use std::time::Duration;
use tokio::process::Command;
use watchdog::{
    CommandWatchdogOptions, HttpHealthChecker, ServiceWatchdog, ServiceWatchdogOptions,
};

#[tokio::main]
async fn main() {
    // Create a command to run your service
    let mut cmd = Command::new("my-service");
    cmd.args(["--port", "8080"]);

    // Create a health checker to monitor the service
    let health_checker = HttpHealthChecker::new("http://localhost:8080/health".to_string());

    // Configure the service watchdog
    let opt = ServiceWatchdogOptions {
        health_check_interval: Duration::from_secs(10),
        health_check_failure_threshold: 3,
        health_check_unhealthy_threshold: 2,
        initial_startup_delay: Duration::from_secs(5),
        command_options: CommandWatchdogOptions {
            restart_interval: Duration::from_secs(1),
            max_restart_interval: Duration::from_secs(60),
            ..Default::default()
        },
    };

    // Create and start the service watchdog
    let watchdog = ServiceWatchdog::start_with_opt(cmd, health_checker, opt);

    // Wait until a health check passes, for at most 30 seconds
    match watchdog.wait_for_healthy(Duration::from_secs(30)).await {
        Ok(()) => println!("Service is healthy"),
        Err(elapsed) => println!("Service is not healthy yet: {elapsed}"),
    }

    // Get statistics about the service watchdog
    println!("Healthy now: {}", watchdog.is_healthy());
    println!("Health checks: {}", watchdog.health_checks());
    println!("Failed health checks: {}", watchdog.failed_health_checks());
    println!("Failures in a row: {}", watchdog.consecutive_failures());

    // Manually restart the service if needed
    watchdog.restart().await.expect("the watchdog has shut down");
}
```

`ServiceWatchdog::start(cmd, health_checker)` does the same with the default options.
`wait_for_healthy` waits for the next passing health check, even when the service is already
healthy, and fails once the timeout elapses.

### HTTP health checks

Health checks handle their own timeouts:

```rust
use std::time::Duration;
use watchdog::HttpHealthChecker;

let url = "http://localhost:8080/health".to_string();

// Healthy on status 200, with a 5 second timeout
let default = HttpHealthChecker::new(url.clone());

// Healthy on another status code, with a 5 second timeout
let no_content = HttpHealthChecker::with_status(url.clone(), 204);

// Healthy on a given status code, with a custom timeout
let quick = HttpHealthChecker::with_options(url, 200, Duration::from_secs(3));
```

### Custom health checks

Any type that implements `HealthCheck` can be the service watchdog's health checker. To check
more than one thing, call each check in turn from one implementation:

```rust
use async_trait::async_trait;
use std::error::Error;
use std::time::Duration;
use watchdog::HealthCheck;

/// Healthy when the service accepts a TCP connection within 2 seconds
#[derive(Debug)]
struct AcceptsConnections(String);

#[async_trait]
impl HealthCheck for AcceptsConnections {
    async fn check_health(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let connect = tokio::net::TcpStream::connect(&self.0);
        tokio::time::timeout(Duration::from_secs(2), connect).await??;
        Ok(())
    }
}

let health_checker = AcceptsConnections("localhost:8080".to_string());
```

## Configuration Options

### CommandWatchdogOptions

- `restart_interval`: Shortest time from one start to the next once the process has failed (default: 1s)
- `max_restart_interval`: The most that time between starts grows to (default: 60s)
- `termination_timeout`: Maximum time to wait for a process to terminate after SIGTERM before SIGKILL (default: 60s)
- `output_handler`: Receives the child's stdout and stderr line by line (default: `None`, the child inherits the parent's)

### Restart backoff

A failure is the process exiting, failing to start, or, under a `ServiceWatchdog`, being
restarted for failing its health checks. After the first failure in a row the next start comes
no sooner than `restart_interval` after the previous one; each further failure doubles that, up
to `max_restart_interval`. With the defaults, starts are at least 1, 2, 4, 8, 16, 32 and then 60
seconds apart. A process that ran longer than that is restarted at once.

The failures stop counting once the process stays up for `max_restart_interval`, or under a
`ServiceWatchdog` passes its health checks for that long: a process that stays up but fails its
health checks keeps counting. `consecutive_failures()` returns the current count. While no
process runs, a `ServiceWatchdog` reports it unhealthy and skips its health checks, so it does
not ask to restart a process the backoff is already restarting.

### ServiceWatchdogOptions

- `health_check_interval`: How often to check service health (default: 10s)
- `health_check_failure_threshold`: How many consecutive health check failures before restarting (default: 3)
- `health_check_unhealthy_threshold`: How many consecutive health check failures before `is_healthy()` reports the service unhealthy; one passing check reports it healthy again (default: 1). A service that is not running, or a new run that has not passed a check yet, is reported unhealthy at once
- `initial_startup_delay`: How long to wait before the first health check, and again after a restart for failed health checks (default: 5s)
- `command_options`: The `CommandWatchdogOptions` for the service's process (default: their defaults)

## Statistics

Both watchdogs report:

- `start_counter()`: How many times the process has been started, counting attempts that failed to start
- `last_exit_code()`: The process's last exit code: 0 until it first exits, -1 when a signal ended it
- `consecutive_failures()`: How many times in a row the process has failed (see Restart backoff)

The `ServiceWatchdog` also reports:

- `is_healthy()`: Whether the service is reported healthy (see `health_check_unhealthy_threshold`); false while the process is not running
- `health_checks()` and `failed_health_checks()`: How many health checks it has run, and how many of them failed
- `command_watchdog()`: The `CommandWatchdog` that runs the service's process

## Implementation Details

The `ServiceWatchdog` builds upon `CommandWatchdog` by adding:
1. Health checking with configurable checks and intervals
2. Automatic restart when health checks fail consecutively
3. Counts of health checks and failed health checks

Each health checker implementation handles its own timeout configuration, so health checks can have different timeouts based on their specific needs.
