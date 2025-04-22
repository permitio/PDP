use log::LevelFilter;
use std::time::Duration;
use test_server::TestServer;
use tokio::process::Command;
use watchdog::{CommandWatchdog, CommandWatchdogOptions};

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

    assert_eq!(watchdog.start_counter(), 2);
    assert_eq!(watchdog.last_exit_code(), 12); // exit code from the test server POST /crash
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

    assert_eq!(watchdog.start_counter(), 5);
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

    assert_eq!(watchdog.start_counter(), 5);
    assert_eq!(watchdog.last_exit_code(), 12);
}
