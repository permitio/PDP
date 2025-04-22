use log::LevelFilter;
use std::time::Duration;
use test_server::TestServer;
use tokio::process::Command;
use watchdog::{CommandWatchdog, CommandWatchdogOptions, ServiceWatchdog, ServiceWatchdogOptions};

mod test_server;

fn setup_logger() {
    let _ = env_logger::builder()
        .is_test(true)
        .filter_level(LevelFilter::Debug)
        .try_init();
}

#[tokio::test]
async fn test_watchdog_spawn() {
    setup_logger();

    let test_server = TestServer::new();

    // Start the test server
    let watchdog = CommandWatchdog::start(test_server.get_command());
    tokio::time::sleep(Duration::from_millis(100)).await;

    let ping_response = test_server.ping().await.unwrap();
    assert_eq!(ping_response, "pong");
    drop(watchdog);

    let ping_response = test_server.ping().await;
    assert!(ping_response.is_err(), "Server should be stopped");
}

#[tokio::test]
async fn test_watchdog_restart_after_crash() {
    setup_logger();

    let test_server = TestServer::new();

    // Start the test server
    let opt = CommandWatchdogOptions {
        restart_interval: Duration::from_millis(10),
        ..Default::default()
    };
    let watchdog = CommandWatchdog::start_with_opt(test_server.get_command(), opt);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Check if the server is running
    let ping_response = test_server.ping().await.unwrap();
    assert_eq!(ping_response, "pong");

    // Simulate a crash
    let crash_response = test_server.crash().await;
    assert!(crash_response.is_ok(), "Failed to crash the server");

    // Wait for the server to restart
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Check if the server is running again
    let ping_response = test_server.ping().await.unwrap();
    assert_eq!(ping_response, "pong");

    assert_eq!(
        watchdog.start_counter(),
        2,
        "Service should have started twice"
    );
    // exit code from the test server POST /crash
    assert_eq!(
        watchdog.last_exit_code(),
        12,
        "Service should have exit code 12"
    );
}

#[tokio::test]
async fn test_watchdog_fail_to_start() {
    setup_logger();

    let opt = CommandWatchdogOptions {
        restart_interval: Duration::from_millis(10),
        ..Default::default()
    };
    let command = Command::new("doesnotexist");
    let watchdog = CommandWatchdog::start_with_opt(command, opt);
    tokio::time::sleep(Duration::from_millis(55)).await;

    assert!(
        watchdog.start_counter() > 1,
        "Should have started more than once"
    );
    assert_eq!(watchdog.last_exit_code(), 0);
}

#[tokio::test]
async fn test_watchdog_crash_immediately() {
    setup_logger();

    let opt = CommandWatchdogOptions {
        restart_interval: Duration::from_millis(10),
        ..Default::default()
    };
    let mut command = Command::new("sh");
    command.arg("-c");
    command.arg("exit 12");

    let watchdog = CommandWatchdog::start_with_opt(command, opt);
    tokio::time::sleep(Duration::from_millis(55)).await;

    assert!(
        watchdog.start_counter() > 1,
        "Should have started more than once"
    );
    assert_eq!(watchdog.last_exit_code(), 12, "Should have exit code 12");
}

#[tokio::test]
async fn test_watchdog_explicit_restart() {
    setup_logger();

    let test_server = TestServer::new();

    // Start the test server
    let opt = CommandWatchdogOptions {
        restart_interval: Duration::from_millis(100),
        ..Default::default()
    };
    let watchdog = CommandWatchdog::start_with_opt(test_server.get_command(), opt);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Check if the server is running
    let ping_response = test_server.ping().await.unwrap();
    assert_eq!(ping_response, "pong");

    // Get server status to capture the PID
    let initial_status = test_server.status().await.unwrap();
    let initial_pid = initial_status.pid;

    // Request restart
    watchdog.restart().await.unwrap();

    // Wait for the server to restart
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Check if the server is running again with a different PID
    let ping_response = test_server.ping().await.unwrap();
    assert_eq!(ping_response, "pong");

    let new_status = test_server.status().await.unwrap();
    assert_ne!(
        initial_pid, new_status.pid,
        "Server PID should be different after restart"
    );

    assert_eq!(
        watchdog.start_counter(),
        2,
        "Service should have started twice"
    );
    assert_eq!(
        watchdog.last_exit_code(),
        0,
        "Service should still be running"
    );
}

#[tokio::test]
async fn test_watchdog_termination_timeout() {
    setup_logger();

    // Start a test server that ignores SIGTERM signals
    let test_server = TestServer::new_with_options(true);

    // Configure the watchdog with a short termination timeout
    let opt = CommandWatchdogOptions {
        restart_interval: Duration::from_millis(100),
        termination_timeout: Duration::from_millis(500),
        ..Default::default()
    };
    let watchdog = CommandWatchdog::start_with_opt(test_server.get_command(), opt);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Get initial status
    let status = test_server.status().await.unwrap();
    let initial_pid = status.pid;

    // Request a restart - this should force termination after timeout
    watchdog.restart().await.unwrap();

    // Verify the server is still running, ignoring the SIGKILL
    let ping_response = test_server.ping().await.unwrap();
    assert_eq!(ping_response, "pong");

    // Wait for the termination timeout and eventual restart
    tokio::time::sleep(Duration::from_millis(600)).await;

    // Verify the server is running again with a different PID
    let ping_response = test_server.ping().await.unwrap();
    assert_eq!(ping_response, "pong");

    let new_status = test_server.status().await.unwrap();
    assert_ne!(
        initial_pid, new_status.pid,
        "Server PID should be different after forced termination and restart"
    );

    assert_eq!(
        watchdog.start_counter(),
        2,
        "Service should have started twice"
    );
}

#[tokio::test]
async fn test_service_watchdog_http() {
    setup_logger();

    let test_server = TestServer::new();
    let opt = ServiceWatchdogOptions {
        health_check_interval: Duration::from_millis(50),
        health_check_failure_threshold: 5,
        initial_startup_delay: Duration::from_millis(50),
    };
    let watchdog = ServiceWatchdog::start_with_opt(
        test_server.get_command(),
        test_server.get_health_checker(),
        opt,
    );
    assert!(!watchdog.is_healthy());
    watchdog
        .wait_for_healthy(Duration::from_millis(1000))
        .await
        .expect("Service should be healthy");

    // Verify the server is healthy
    let health_response = test_server.health().await.unwrap();
    assert_eq!(health_response, "healthy");

    assert_eq!(
        watchdog.start_counter(),
        1,
        "Service should have started once"
    );
    assert_eq!(
        watchdog.last_exit_code(),
        0,
        "Service should still be running"
    );
    assert!(
        watchdog.health_checks() > 0,
        "Service should have performed health checks"
    );
    assert!(
        watchdog.failed_health_checks() < watchdog.health_checks(),
        "Service should have less failed health checks than total health checks"
    );
}

#[tokio::test]
async fn test_service_watchdog_recover() {
    setup_logger();

    let test_server = TestServer::new();
    let opt = ServiceWatchdogOptions {
        health_check_interval: Duration::from_millis(50),
        health_check_failure_threshold: 2,
        initial_startup_delay: Duration::from_millis(50),
    };
    let watchdog = ServiceWatchdog::start_with_opt(
        test_server.get_command(),
        test_server.get_health_checker(),
        opt,
    );
    watchdog
        .wait_for_healthy(Duration::from_millis(1000))
        .await
        .expect("Service should be healthy");

    test_server
        .make_unhealthy()
        .await
        .expect("Failed to make server unhealthy");
    watchdog
        .wait_for_healthy(Duration::from_millis(1000))
        .await
        .expect("Service should recover from unhealthy state");

    assert_eq!(
        watchdog.start_counter(),
        2,
        "Service should have started twice"
    );
    assert_eq!(
        watchdog.last_exit_code(),
        0,
        "Service should still be running"
    );
    assert!(
        watchdog.health_checks() > 0,
        "Service should have performed health checks"
    );
    assert!(
        watchdog.failed_health_checks() < watchdog.health_checks(),
        "Service should have less failed health checks than total health checks"
    );
}

#[tokio::test]
async fn test_service_watchdog_recover_unresponsive() {
    setup_logger();

    let test_server = TestServer::new();
    let opt = ServiceWatchdogOptions {
        health_check_interval: Duration::from_millis(50),
        health_check_failure_threshold: 2,
        initial_startup_delay: Duration::from_millis(50),
    };
    let watchdog = ServiceWatchdog::start_with_opt(
        test_server.get_command(),
        test_server.get_health_checker(),
        opt,
    );
    watchdog
        .wait_for_healthy(Duration::from_millis(1000))
        .await
        .expect("Service should be healthy");

    // Simulate unresponsive health check
    test_server
        .make_unresponsive()
        .await
        .expect("Failed to make server unhealthy");
    watchdog
        .wait_for_healthy(Duration::from_millis(1000))
        .await
        .expect("Service should recover from unhealthy state");

    // Verify the server is healthy
    let health_response = test_server.health().await.unwrap();
    assert_eq!(health_response, "healthy");

    assert!(
        watchdog.start_counter() > 1,
        "Service should have started twice"
    );
    assert_eq!(
        watchdog.last_exit_code(),
        0,
        "Service should still be running"
    );
    assert!(
        watchdog.health_checks() > 0,
        "Service should have performed health checks"
    );
    assert!(
        watchdog.failed_health_checks() < watchdog.health_checks(),
        "Service should have less failed health checks than total health checks"
    );
}
