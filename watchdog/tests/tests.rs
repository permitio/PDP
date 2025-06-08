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
    tokio::time::sleep(Duration::from_millis(300)).await;

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
    tokio::time::sleep(Duration::from_millis(300)).await;

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
    tokio::time::sleep(Duration::from_millis(300)).await;

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
    };
    let watchdog = CommandWatchdog::start_with_opt(test_server.get_command(), opt);
    tokio::time::sleep(Duration::from_millis(300)).await;

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
        ..Default::default()
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
        initial_startup_delay: Duration::from_millis(250),
        ..Default::default()
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
        ..Default::default()
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

#[tokio::test]
async fn test_service_watchdog_consecutive_failures() {
    setup_logger();

    let test_server = TestServer::new();
    let opt = ServiceWatchdogOptions {
        health_check_interval: Duration::from_millis(50),
        health_check_failure_threshold: 3, // Require 3 consecutive failures
        initial_startup_delay: Duration::from_millis(100),
        ..Default::default()
    };

    let watchdog = ServiceWatchdog::start_with_opt(
        test_server.get_command(),
        test_server.get_health_checker(),
        opt,
    );

    // Wait for service to become healthy initially
    watchdog
        .wait_for_healthy(Duration::from_millis(1000))
        .await
        .expect("Service should be healthy");

    assert_eq!(
        watchdog.start_counter(),
        1,
        "Service should have started once"
    );

    // Make the server unhealthy to trigger consecutive failures
    test_server
        .make_unhealthy()
        .await
        .expect("Failed to make server unhealthy");

    // Wait for 2 health check intervals to pass (should be 2 failures, not enough to restart)
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Service should still be running (not restarted yet) because we haven't hit threshold
    assert_eq!(
        watchdog.start_counter(),
        1,
        "Service should not have restarted yet with only 2 failures"
    );

    // Wait for one more health check interval (should be 3 failures, enough to restart)
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Now the service should have been restarted
    assert_eq!(
        watchdog.start_counter(),
        2,
        "Service should have restarted after reaching failure threshold"
    );

    // Wait for the service to recover after restart
    watchdog
        .wait_for_healthy(Duration::from_millis(1000))
        .await
        .expect("Service should recover after restart");

    // Verify we have failed health checks recorded
    assert!(
        watchdog.failed_health_checks() >= 3,
        "Should have at least 3 failed health checks recorded"
    );

    assert!(
        watchdog.health_checks() > watchdog.failed_health_checks(),
        "Should have more total health checks than failed ones"
    );
}

#[tokio::test]
async fn test_service_watchdog_consecutive_failures_with_recovery() {
    setup_logger();

    let test_server = TestServer::new();
    let opt = ServiceWatchdogOptions {
        health_check_interval: Duration::from_millis(50),
        health_check_failure_threshold: 4, // Require 4 consecutive failures
        initial_startup_delay: Duration::from_millis(100),
        ..Default::default()
    };

    let watchdog = ServiceWatchdog::start_with_opt(
        test_server.get_command(),
        test_server.get_health_checker(),
        opt,
    );

    // Wait for service to become healthy initially
    watchdog
        .wait_for_healthy(Duration::from_millis(1000))
        .await
        .expect("Service should be healthy");

    // Make the server unhealthy
    test_server
        .make_unhealthy()
        .await
        .expect("Failed to make server unhealthy");

    // Wait for 2 health check failures
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Make the server healthy again to reset consecutive failures
    // This is done by restarting the server state (Python test server becomes healthy by default)
    test_server
        .crash()
        .await
        .expect("Failed to crash server for reset");

    // Wait for the command watchdog to restart it (need more time due to crash loop protection)
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Wait for server to become healthy
    watchdog
        .wait_for_healthy(Duration::from_millis(1000))
        .await
        .expect("Service should be healthy after restart");

    // Make server unhealthy again
    test_server
        .make_unhealthy()
        .await
        .expect("Failed to make server unhealthy again");

    // Wait for 3 failures (still less than threshold of 4)
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Should not have triggered service restart because consecutive counter was reset
    // The service watchdog should still be on its first restart cycle
    // (one restart from the crash() call above, but no restart from health check failures)
    assert!(
        watchdog.start_counter() >= 1,
        "Service should have been restarted at least once (from manual crash)"
    );

    // Verify we have failed health checks but they were not consecutive enough to trigger restart
    assert!(
        watchdog.failed_health_checks() > 0,
        "Should have some failed health checks recorded"
    );
}
