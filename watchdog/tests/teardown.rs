//! Dropping a `CommandWatchdog` stops its child for good, and its supervising
//! loop ends.
//!
//! The drop cancels the shutdown token and drops the restart sender in the same
//! moment, so the loop wakes with both its shutdown branch and a closed restart
//! channel ready. These tests count the loop's own "Starting process" and
//! "received restart signal" log lines, so they hold no handle that would keep
//! the restart channel open and hide the race. Whether the loop has ended is
//! read from an output handler it owns: its `Arc` goes back to one owner when
//! the loop's task drops its options.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::process::Command;
use watchdog::{ChildOutputHandler, ChildStream, CommandWatchdog, CommandWatchdogOptions};

/// Every "Starting process" and "received restart signal" line the watchdog
/// logs, across the whole binary.
struct StartLines(Mutex<Vec<String>>);

impl log::Log for StartLines {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let line = record.args().to_string();
        if line.starts_with("Starting process ")
            || line.starts_with("Watchdog received restart signal")
        {
            self.0.lock().unwrap().push(line);
        }
    }

    fn flush(&self) {}
}

/// Installs the logger on first use. Each test calls it before it starts a
/// watchdog, so no line is logged before the logger is there.
fn start_lines() -> &'static StartLines {
    static LINES: OnceLock<&'static StartLines> = OnceLock::new();
    LINES.get_or_init(|| {
        let lines: &'static StartLines = Box::leak(Box::new(StartLines(Mutex::new(Vec::new()))));
        log::set_logger(lines).expect("this binary's only logger");
        log::set_max_level(log::LevelFilter::Info);
        lines
    })
}

fn lines_of(prefix: &str, marker: &str) -> usize {
    start_lines()
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|line| line.starts_with(prefix) && line.contains(marker))
        .count()
}

/// How many times the watchdog started the command whose line contains `marker`.
fn starts_of(marker: &str) -> usize {
    lines_of("Starting process ", marker)
}

/// How many times the loop took its restart branch for that command. At a drop
/// it must take the shutdown branch instead.
fn restarts_of(marker: &str) -> usize {
    lines_of("Watchdog received restart signal", marker)
}

/// A marker no other test's command line contains.
fn marker(name: &str, round: usize) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{name}-{round}-{nanos}")
}

/// `sh -c <script> <marker>`: the marker rides as `$0`, so it shows in the
/// logged command line and nowhere else.
fn sh(script: &str, marker: &str) -> Command {
    let mut command = Command::new("sh");
    command.arg("-c").arg(script).arg(marker);
    command
}

async fn wait_for_starts(marker: &str, n: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while starts_of(marker) < n {
        assert!(
            Instant::now() < deadline,
            "{marker}: never started {n} time(s)"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// An output handler that does nothing: the loop owns a clone of it in its
/// options, so its strong count says whether the loop has ended.
struct Ignore;

impl ChildOutputHandler for Ignore {
    fn on_line(&self, _: ChildStream, _: &str) {}
}

async fn wait_for_loop_end(handler: &Arc<Ignore>, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while Arc::strong_count(handler) > 1 {
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    true
}

/// The child runs when the watchdog is dropped. Before the fix, the loop picked
/// the closed restart channel about one time in three (the unbiased select
/// starts at one of its three branches at random) and started the child again.
/// Thirty rounds: the old code passes them all with odds of about one in
/// 200,000.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_watchdog_does_not_start_a_running_child_again() {
    start_lines();
    for round in 0..30 {
        let marker = marker("running", round);
        let watchdog = CommandWatchdog::start_with_opt(
            sh("exec sleep 30", &marker),
            CommandWatchdogOptions {
                restart_interval: Duration::from_millis(50),
                termination_timeout: Duration::from_secs(5),
                ..Default::default()
            },
        );
        wait_for_starts(&marker, 1).await;

        drop(watchdog);
        tokio::time::sleep(Duration::from_millis(300)).await;

        assert_eq!(
            starts_of(&marker),
            1,
            "round {round}: started again after the drop"
        );
        assert_eq!(
            restarts_of(&marker),
            0,
            "round {round}: read the closed channel as a restart"
        );
    }
}

/// A restart was asked for and is still buffered when the watchdog is dropped.
/// The shutdown must win: before the fix, an unbiased select chose the buffered
/// request about one time in three and started the child again during teardown.
/// On one thread, nothing runs the loop between the request and the drop.
#[tokio::test(flavor = "current_thread")]
async fn a_restart_buffered_at_the_drop_does_not_start_the_child_again() {
    start_lines();
    for round in 0..30 {
        let marker = marker("buffered", round);
        let watchdog = CommandWatchdog::start_with_opt(
            sh("exec sleep 30", &marker),
            CommandWatchdogOptions {
                restart_interval: Duration::from_millis(50),
                termination_timeout: Duration::from_secs(5),
                ..Default::default()
            },
        );
        wait_for_starts(&marker, 1).await;
        // Let the loop reach its select before asking.
        tokio::time::sleep(Duration::from_millis(50)).await;

        watchdog
            .restart()
            .await
            .expect("the loop holds the receiver");
        drop(watchdog);
        tokio::time::sleep(Duration::from_millis(300)).await;

        assert_eq!(
            starts_of(&marker),
            1,
            "round {round}: started again after the drop"
        );
        assert_eq!(
            restarts_of(&marker),
            0,
            "round {round}: the buffered restart won over the shutdown"
        );
    }
}

/// The watchdog is dropped while a restart is under way: the child ignores
/// SIGTERM, so the loop is waiting out its termination timeout. Before the fix,
/// the loop then started the child again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restart_under_way_at_the_drop_does_not_start_the_child_again() {
    start_lines();
    let marker = marker("restarting", 0);
    let watchdog = CommandWatchdog::start_with_opt(
        // An ignored SIGTERM stays ignored across `exec`, so `sleep` ignores it
        // too, and the SIGKILL at the timeout leaves no orphan.
        sh("trap '' TERM; exec sleep 30", &marker),
        CommandWatchdogOptions {
            restart_interval: Duration::from_millis(50),
            termination_timeout: Duration::from_millis(700),
            ..Default::default()
        },
    );
    wait_for_starts(&marker, 1).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    watchdog
        .restart()
        .await
        .expect("the loop holds the receiver");
    // The loop has sent SIGTERM and is waiting for the child to exit.
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(watchdog);
    // Past the termination timeout, after which the loop would have looped.
    tokio::time::sleep(Duration::from_millis(1200)).await;

    assert_eq!(starts_of(&marker), 1, "started again after the drop");
}

/// The watchdog is dropped while it waits out a crash loop's delay. Before the
/// fix, the loop slept the whole delay out before it saw the shutdown, and then
/// started the child again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_watchdog_ends_a_crash_loops_delay_at_once() {
    start_lines();
    let marker = marker("crashing", 0);
    let handler = Arc::new(Ignore);
    let watchdog = CommandWatchdog::start_with_opt(
        sh("exit 3", &marker),
        CommandWatchdogOptions {
            restart_interval: Duration::from_secs(5),
            termination_timeout: Duration::from_secs(5),
            output_handler: Some(handler.clone()),
        },
    );
    wait_for_starts(&marker, 1).await;
    // The child exits at once, and the loop is now in its crash-loop delay.
    tokio::time::sleep(Duration::from_millis(300)).await;

    drop(watchdog);

    assert!(
        wait_for_loop_end(&handler, Duration::from_secs(1)).await,
        "the loop sat out its delay after the drop"
    );
    assert_eq!(starts_of(&marker), 1, "started again after the drop");
}

/// The command cannot be spawned, and the watchdog is dropped while it waits to
/// retry. Before the fix, nothing between two failed spawns looked at the
/// shutdown token, so the loop kept retrying for good.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_watchdog_stops_retrying_a_command_that_cannot_spawn() {
    start_lines();
    let marker = marker("missing", 0);
    let handler = Arc::new(Ignore);
    let mut command = Command::new(format!("/nonexistent/{marker}"));
    command.arg(&marker);
    let watchdog = CommandWatchdog::start_with_opt(
        command,
        CommandWatchdogOptions {
            restart_interval: Duration::from_secs(5),
            termination_timeout: Duration::from_secs(5),
            output_handler: Some(handler.clone()),
        },
    );
    wait_for_starts(&marker, 1).await;
    // The spawn failed, and the loop is now waiting to retry.
    tokio::time::sleep(Duration::from_millis(100)).await;

    drop(watchdog);

    assert!(
        wait_for_loop_end(&handler, Duration::from_secs(1)).await,
        "the loop sat out its retry delay after the drop"
    );
    assert_eq!(starts_of(&marker), 1, "retried after the drop");
}
