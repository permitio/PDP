//! The restart backoff, driven through real child processes.
//!
//! The `CommandWatchdog` tests run on tokio's paused clock. Nothing waits on a timer while a child
//! runs, so the clock stands still until the watchdog sleeps out a backoff and then jumps to the
//! end of it: the times between starts are exact. The `ServiceWatchdog` tests use the real clock
//! instead, because their health checks wait on timers while a child runs, and a paused clock
//! would race through them.
//!
//! Unix-only: every child runs through a POSIX shell.
#![cfg(unix)]

use async_trait::async_trait;
use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tempfile::TempDir;
use tokio::process::Command;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::time::Instant;
use watchdog::{
    ChildOutputHandler, ChildStream, CommandWatchdog, CommandWatchdogOptions, HealthCheck,
    ServiceWatchdog, ServiceWatchdogOptions,
};

const SECOND: Duration = Duration::from_secs(1);
const MILLISECOND: Duration = Duration::from_millis(1);

/// Run N prints `started` and lingers `$LINGER` seconds. If the test made a file `up-N`, the
/// run stays up until the test makes `stop-N`. Then it exits with 3.
const SCRIPT: &str = r#"
n=$(( $(cat count 2>/dev/null || echo 0) + 1 ))
echo "$n" > count
echo started
sleep "${LINGER:-0}"
if [ -e "up-$n" ]; then
    while [ ! -e "stop-$n" ]; do sleep 0.01; done
fi
exit 3
"#;

/// The directory the child runs in. The test steers each run through files in it.
struct Runs {
    dir: TempDir,
}

impl Runs {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("create a directory for the child to run in");
        Self { dir }
    }

    fn touch(&self, name: &str) {
        let path = self.dir.path().join(name);
        std::fs::write(&path, "").unwrap_or_else(|e| panic!("create {}: {e}", path.display()));
    }

    /// Run `run` stays up until [`Runs::stop`].
    fn keep_up(&self, run: usize) {
        self.touch(&format!("up-{run}"));
    }

    fn stop(&self, run: usize) {
        self.touch(&format!("stop-{run}"));
    }

    /// The command for the runs. `linger` keeps each run up after it prints, so its line is
    /// read while the paused clock still stands at its start.
    fn command(&self, linger: &str) -> Command {
        let mut command = Command::new("sh");
        command
            .current_dir(self.dir.path())
            .env("LINGER", linger)
            .arg("-c")
            .arg(SCRIPT);
        command
    }
}

/// Reports the clock's time each time a run prints `started`.
struct Starts(UnboundedSender<Instant>);

impl Starts {
    fn new() -> (Arc<Self>, UnboundedReceiver<Instant>) {
        let (sender, receiver) = unbounded_channel();
        (Arc::new(Self(sender)), receiver)
    }
}

impl ChildOutputHandler for Starts {
    fn on_line(&self, _stream: ChildStream, line: &str) {
        // Sending fails only once the test has finished and dropped the receiver
        if line == "started" && self.0.send(Instant::now()).is_err() {
            log::debug!("A run started after the test finished");
        }
    }
}

async fn next_start(starts: &mut UnboundedReceiver<Instant>) -> Instant {
    starts
        .recv()
        .await
        .expect("the watchdog stopped starting the process")
}

/// Asserts the time between consecutive starts, in seconds.
fn assert_gaps(starts: &[Instant], expected_secs: &[u64]) {
    let gaps: Vec<Duration> = starts.windows(2).map(|pair| pair[1] - pair[0]).collect();
    assert_eq!(
        gaps.len(),
        expected_secs.len(),
        "gaps between starts: {gaps:?}"
    );
    for (gap, expected) in gaps.iter().zip(expected_secs) {
        let expected = Duration::from_secs(*expected);
        // The timer wheel rounds a deadline up to the next millisecond
        assert!(
            *gap >= expected && *gap <= expected + MILLISECOND,
            "expected gaps of {expected_secs:?} s between starts, got {gaps:?}"
        );
    }
}

fn backoff_options(base: Duration, max: Duration) -> CommandWatchdogOptions {
    CommandWatchdogOptions {
        restart_interval: base,
        max_restart_interval: max,
        ..Default::default()
    }
}

#[tokio::test(start_paused = true)]
async fn a_crash_loop_backs_off_doubling_up_to_the_cap() {
    let runs = Runs::new();
    let (handler, mut starts) = Starts::new();
    let opt = CommandWatchdogOptions {
        output_handler: Some(handler),
        ..backoff_options(SECOND, 8 * SECOND)
    };
    let watchdog = CommandWatchdog::start_with_opt(runs.command("0.1"), opt);

    let mut times = Vec::new();
    for _ in 0..7 {
        times.push(next_start(&mut starts).await);
    }

    assert_gaps(&times, &[1, 2, 4, 8, 8, 8]);
    assert!(
        watchdog.consecutive_failures() >= 6,
        "{} failures in a row",
        watchdog.consecutive_failures()
    );
}

#[tokio::test(start_paused = true)]
async fn after_a_long_run_a_crash_restarts_at_once_and_the_backoff_starts_over() {
    let runs = Runs::new();
    runs.keep_up(4);
    let (handler, mut starts) = Starts::new();
    let opt = CommandWatchdogOptions {
        output_handler: Some(handler),
        ..backoff_options(SECOND, 8 * SECOND)
    };
    let watchdog = CommandWatchdog::start_with_opt(runs.command("0.1"), opt);
    let mut times = Vec::new();
    for _ in 0..4 {
        times.push(next_start(&mut starts).await);
    }
    assert_gaps(&times, &[1, 2, 4]);
    assert_eq!(watchdog.consecutive_failures(), 3);

    // Run 4 stays up for longer than the longest wait, then crashes
    tokio::time::advance(20 * SECOND).await;
    let crashed_at = Instant::now();
    runs.stop(4);
    let fifth = next_start(&mut starts).await;

    assert!(
        fifth - crashed_at <= MILLISECOND,
        "a crash after a long run waited {:?} to restart",
        fifth - crashed_at
    );
    assert_eq!(watchdog.consecutive_failures(), 1);
    // Run 5 crashes at once: the second failure in a row, not the fifth
    let sixth = next_start(&mut starts).await;
    assert_gaps(&[fifth, sixth], &[2]);
}

#[tokio::test(start_paused = true)]
async fn a_process_that_fails_to_start_backs_off_too() {
    let opt = backoff_options(SECOND, 8 * SECOND);
    let watchdog = CommandWatchdog::start_with_opt(Command::new("doesnotexist"), opt);

    // Attempts at 0, 1, 3 and 7 s
    tokio::time::sleep(7500 * MILLISECOND).await;

    assert_eq!(watchdog.start_counter(), 4);
    assert_eq!(watchdog.consecutive_failures(), 4);
}

#[tokio::test]
async fn a_restart_asked_for_between_runs_does_not_stop_the_next_run() {
    let runs = Runs::new();
    runs.keep_up(2);
    let base = 300 * MILLISECOND;
    let watchdog =
        CommandWatchdog::start_with_opt(runs.command("0"), backoff_options(base, 2 * base));
    wait_until("run 1 crashes", || watchdog.consecutive_failures() == 1).await;

    watchdog.restart().await.expect("ask for a restart");
    wait_until("run 2 starts", || watchdog.start_counter() == 2).await;
    tokio::time::sleep(2 * base).await;

    assert_eq!(
        watchdog.start_counter(),
        2,
        "run 2 was stopped and replaced"
    );
}

#[tokio::test]
async fn dropping_the_watchdog_while_it_waits_starts_nothing_more() {
    let runs = Runs::new();
    let base = 300 * MILLISECOND;
    let watchdog =
        CommandWatchdog::start_with_opt(runs.command("0"), backoff_options(base, 2 * base));
    wait_until("run 1 crashes", || watchdog.consecutive_failures() == 1).await;

    // Dropping any handle shuts the watchdog down; the clone only reads the count afterwards
    let observer = watchdog.clone();
    drop(watchdog);
    tokio::time::sleep(2 * base).await;

    assert_eq!(observer.start_counter(), 1);
}

/// Health checks the test turns on and off.
#[derive(Debug, Clone, Default)]
struct HealthSwitch(Arc<AtomicBool>);

impl HealthSwitch {
    fn set(&self, healthy: bool) {
        self.0.store(healthy, Ordering::SeqCst);
    }
}

#[async_trait]
impl HealthCheck for HealthSwitch {
    async fn check_health(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        if self.0.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err("the test switched the health checks off".into())
        }
    }
}

/// Health checks that pass and fail by turns.
#[derive(Debug, Default)]
struct Flapping(AtomicUsize);

#[async_trait]
impl HealthCheck for Flapping {
    async fn check_health(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        if self.0.fetch_add(1, Ordering::SeqCst).is_multiple_of(2) {
            Ok(())
        } else {
            Err("every other check fails".into())
        }
    }
}

fn service_options(base: Duration, max: Duration, threshold: u32) -> ServiceWatchdogOptions {
    ServiceWatchdogOptions {
        health_check_interval: 10 * MILLISECOND,
        health_check_failure_threshold: threshold,
        initial_startup_delay: Duration::ZERO,
        command_options: backoff_options(base, max),
    }
}

/// Waits on the real clock until `condition` holds.
async fn wait_until(what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + 5 * SECOND;
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting until {what}");
        tokio::time::sleep(5 * MILLISECOND).await;
    }
}

#[tokio::test]
async fn passing_health_checks_reset_the_backoff_and_failing_ones_do_not() {
    let runs = Runs::new();
    runs.keep_up(3);
    let health = HealthSwitch::default();
    let max = 300 * MILLISECOND;
    let watchdog = ServiceWatchdog::start_with_opt(
        runs.command("0"),
        health.clone(),
        service_options(50 * MILLISECOND, max, u32::MAX),
    );
    wait_until("run 3 starts", || watchdog.start_counter() == 3).await;
    assert_eq!(watchdog.consecutive_failures(), 2);

    // Up, but failing its health checks for twice the longest wait
    tokio::time::sleep(2 * max).await;
    assert_eq!(watchdog.consecutive_failures(), 2);

    health.set(true);
    let healthy_from = Instant::now();
    wait_until("the failures stop counting", || {
        watchdog.consecutive_failures() == 0
    })
    .await;

    assert!(
        healthy_from.elapsed() >= max,
        "the failures stopped counting {:?} after the service turned healthy",
        healthy_from.elapsed()
    );
    assert!(watchdog.is_healthy());
    assert_eq!(watchdog.start_counter(), 3);
}

#[tokio::test]
async fn a_run_that_stays_up_but_fails_its_health_checks_keeps_the_failures_counting() {
    let runs = Runs::new();
    runs.keep_up(3);
    runs.keep_up(4);
    let max = 300 * MILLISECOND;
    let watchdog = ServiceWatchdog::start_with_opt(
        runs.command("0"),
        HealthSwitch::default(),
        service_options(50 * MILLISECOND, max, u32::MAX),
    );
    wait_until("run 3 starts", || watchdog.start_counter() == 3).await;

    // Up for twice the longest wait, never healthy, then it crashes
    tokio::time::sleep(2 * max).await;
    runs.stop(3);
    wait_until("run 4 starts", || watchdog.start_counter() == 4).await;

    assert_eq!(watchdog.consecutive_failures(), 3);
}

#[tokio::test]
async fn health_checks_that_pass_only_by_turns_do_not_reset_the_backoff() {
    let runs = Runs::new();
    runs.keep_up(3);
    let max = 300 * MILLISECOND;
    let watchdog = ServiceWatchdog::start_with_opt(
        runs.command("0"),
        Flapping::default(),
        service_options(50 * MILLISECOND, max, u32::MAX),
    );
    wait_until("run 3 starts", || watchdog.start_counter() == 3).await;

    tokio::time::sleep(2 * max).await;

    assert_eq!(watchdog.consecutive_failures(), 2);
}

#[tokio::test]
async fn restarts_for_failed_health_checks_count_and_back_off() {
    let runs = Runs::new();
    runs.keep_up(1);
    runs.keep_up(2);
    let base = 300 * MILLISECOND;
    let started = Instant::now();
    let watchdog = ServiceWatchdog::start_with_opt(
        runs.command("0"),
        HealthSwitch::default(),
        service_options(base, 2 * base, 10),
    );
    wait_until("run 2 starts", || watchdog.start_counter() == 2).await;

    // Ten failed checks take 100 ms; the restart still waits out the base from run 1's start
    assert!(
        started.elapsed() >= base,
        "run 2 started {:?} after run 1",
        started.elapsed()
    );
    assert_eq!(watchdog.consecutive_failures(), 1);
}

#[tokio::test]
async fn a_crash_after_a_healthy_run_restarts_at_once() {
    let runs = Runs::new();
    runs.keep_up(3);
    runs.keep_up(4);
    let health = HealthSwitch::default();
    health.set(true);
    let base = 300 * MILLISECOND;
    let watchdog = ServiceWatchdog::start_with_opt(
        runs.command("0"),
        health,
        service_options(base, 2 * base, u32::MAX),
    );
    wait_until("run 3 has been healthy for the longest wait", || {
        watchdog.start_counter() == 3 && watchdog.consecutive_failures() == 0
    })
    .await;

    runs.stop(3);
    let crashed_at = Instant::now();
    wait_until("run 4 starts", || watchdog.start_counter() == 4).await;
    let restarted_after = crashed_at.elapsed();
    // Run 4 passes several checks, for less than the longest wait. Run 3's healthy time does not
    // carry over to it, so the crash still counts.
    tokio::time::sleep(100 * MILLISECOND).await;

    assert!(
        restarted_after < base,
        "a crash after a healthy run waited {restarted_after:?} to restart"
    );
    assert_eq!(watchdog.consecutive_failures(), 1);
}

#[tokio::test]
async fn while_it_waits_to_restart_the_service_reports_unhealthy() {
    let runs = Runs::new();
    runs.keep_up(1);
    // Checks that would pass whether or not anything runs: only the watchdog knows nothing does
    let health = HealthSwitch::default();
    health.set(true);
    let watchdog = ServiceWatchdog::start_with_opt(
        runs.command("0"),
        health,
        service_options(200 * MILLISECOND, 400 * MILLISECOND, u32::MAX),
    );
    watchdog
        .wait_for_healthy(5 * SECOND)
        .await
        .expect("run 1 turns healthy");

    runs.stop(1);
    // Runs 2 and 3 crash at once; run 4 is 400 ms after run 3
    wait_until("run 3 has crashed", || watchdog.consecutive_failures() == 3).await;
    tokio::time::sleep(50 * MILLISECOND).await;

    assert!(!watchdog.is_healthy());
    assert_eq!(watchdog.start_counter(), 3);
}

#[tokio::test]
async fn failed_health_checks_do_not_restart_a_service_that_is_not_running() {
    let runs = Runs::new();
    runs.keep_up(1);
    let health = HealthSwitch::default();
    health.set(true);
    let threshold = 10;
    let watchdog = ServiceWatchdog::start_with_opt(
        runs.command("0"),
        health.clone(),
        service_options(200 * MILLISECOND, 400 * MILLISECOND, threshold),
    );
    watchdog
        .wait_for_healthy(5 * SECOND)
        .await
        .expect("run 1 turns healthy");

    // Run 1 crashes and takes its health with it; runs 2 and 3 crash at once
    runs.stop(1);
    health.set(false);
    wait_until("run 4 starts", || watchdog.start_counter() == 4).await;

    // Each 400 ms wait spans 40 failing checks, enough for four restarts if they counted
    let failures = watchdog.consecutive_failures();
    assert!(
        (3..=4).contains(&failures),
        "{failures} failures in a row for 3 crashes"
    );
}
