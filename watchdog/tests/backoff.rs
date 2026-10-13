//! The restart backoff, and how the service watchdog reports health, driven through real child
//! processes.
//!
//! The `CommandWatchdog` tests run on tokio's paused clock. Nothing waits on a timer while a child
//! runs, so the clock stands still until the watchdog sleeps out a backoff and then jumps to the
//! end of it: the times between starts are exact. The `ServiceWatchdog` backoff tests use the
//! real clock instead, because their health checks wait on timers while a child starts or exits,
//! and a paused clock would race through them. The health reporting tests keep their child up, so
//! they too run on the paused clock, one health check per interval.
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

/// Run N prints `started`. With `$GATED` set, it then waits for the test to make `ack-N`. If
/// the test made a file `up-N`, the run stays up until the test makes `stop-N`. Then it exits
/// with 3.
const SCRIPT: &str = r#"
n=$(( $(cat count 2>/dev/null || echo 0) + 1 ))
echo "$n" > count
echo started
if [ -n "$GATED" ]; then
    while [ ! -e "ack-$n" ]; do sleep 0.01; done
fi
if [ -e "up-$n" ]; then
    while [ ! -e "stop-$n" ]; do sleep 0.01; done
fi
exit 3
"#;

/// The directory the child runs in. The test steers each run through files in it.
#[derive(Debug)]
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

    /// The command for runs that go on as soon as they print.
    fn command(&self) -> Command {
        let mut command = Command::new("sh");
        command.current_dir(self.dir.path()).arg("-c").arg(SCRIPT);
        command
    }

    /// The command for runs that wait after printing until [`next_start`] acknowledges them.
    /// The paused clock stands still while a run waits, as no timer is pending, so the time
    /// reported for its start is the time it started.
    fn gated_command(&self) -> Command {
        let mut command = self.command();
        command.env("GATED", "1");
        command
    }

    /// The number of the latest run, 0 before the first.
    fn latest(&self) -> usize {
        let path = self.dir.path().join("count");
        match std::fs::read_to_string(&path) {
            // Empty while a run rewrites it
            Ok(count) => count.trim().parse().unwrap_or(0),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
            Err(e) => panic!("read {}: {e}", path.display()),
        }
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

/// Waits for gated run `run` to start, lets it go on, and returns when it started.
async fn next_start(starts: &mut UnboundedReceiver<Instant>, runs: &Runs, run: usize) -> Instant {
    let started = starts
        .recv()
        .await
        .expect("the watchdog stopped starting the process");
    runs.touch(&format!("ack-{run}"));
    started
}

/// Waits, without letting the paused clock move, until `condition` holds. `yield_now` lets the
/// runtime take in a child's exit but never advances a paused clock, so no backoff can elapse
/// meanwhile.
async fn spin_until(condition: impl Fn() -> bool) {
    while !condition() {
        tokio::task::yield_now().await;
    }
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
    let watchdog = CommandWatchdog::start_with_opt(runs.gated_command(), opt);

    let mut times = Vec::new();
    for run in 1..=7 {
        times.push(next_start(&mut starts, &runs, run).await);
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
    let watchdog = CommandWatchdog::start_with_opt(runs.gated_command(), opt);
    let mut times = Vec::new();
    for run in 1..=4 {
        times.push(next_start(&mut starts, &runs, run).await);
    }
    assert_gaps(&times, &[1, 2, 4]);
    assert_eq!(watchdog.consecutive_failures(), 3);

    // Run 4 stays up for longer than the longest wait, then crashes
    tokio::time::advance(20 * SECOND).await;
    let crashed_at = Instant::now();
    runs.stop(4);
    let fifth = next_start(&mut starts, &runs, 5).await;

    assert!(
        fifth - crashed_at <= MILLISECOND,
        "a crash after a long run waited {:?} to restart",
        fifth - crashed_at
    );
    assert_eq!(watchdog.consecutive_failures(), 1);
    // Run 5 crashes at once: the second failure in a row, not the fifth
    let sixth = next_start(&mut starts, &runs, 6).await;
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

#[tokio::test(start_paused = true)]
async fn a_restart_asked_for_between_runs_does_not_stop_the_next_run() {
    let runs = Runs::new();
    runs.keep_up(2);
    let (handler, mut starts) = Starts::new();
    let opt = CommandWatchdogOptions {
        output_handler: Some(handler),
        ..backoff_options(SECOND, 8 * SECOND)
    };
    let watchdog = CommandWatchdog::start_with_opt(runs.gated_command(), opt);
    let first = next_start(&mut starts, &runs, 1).await;
    spin_until(|| watchdog.consecutive_failures() == 1).await;

    // Run 1 has crashed and the watchdog waits 1 s to start run 2
    watchdog.restart().await.expect("ask for a restart");
    let second = next_start(&mut starts, &runs, 2).await;
    // Run 2 exits by itself: had the restart stopped it, it would not count as a failure
    runs.stop(2);
    let third = next_start(&mut starts, &runs, 3).await;

    assert_gaps(&[first, second, third], &[1, 2]);
    assert_eq!(watchdog.consecutive_failures(), 2);
}

#[tokio::test(start_paused = true)]
async fn dropping_the_watchdog_while_it_waits_starts_nothing_more() {
    let runs = Runs::new();
    let (handler, mut starts) = Starts::new();
    let opt = CommandWatchdogOptions {
        output_handler: Some(handler),
        ..backoff_options(SECOND, 8 * SECOND)
    };
    let watchdog = CommandWatchdog::start_with_opt(runs.gated_command(), opt);
    next_start(&mut starts, &runs, 1).await;
    spin_until(|| watchdog.consecutive_failures() == 1).await;

    // Dropping any handle shuts the watchdog down; the clone only reads the count afterwards
    let observer = watchdog.clone();
    drop(watchdog);
    tokio::time::sleep(10 * SECOND).await;

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

/// Health checks that fail until run `from` starts, and pass from then on.
#[derive(Debug)]
struct HealthyFromRun {
    runs: Arc<Runs>,
    from: usize,
}

#[async_trait]
impl HealthCheck for HealthyFromRun {
    async fn check_health(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        if self.runs.latest() >= self.from {
            Ok(())
        } else {
            Err(format!("run {} has not started yet", self.from).into())
        }
    }
}

fn service_options(base: Duration, max: Duration, threshold: u32) -> ServiceWatchdogOptions {
    ServiceWatchdogOptions {
        health_check_interval: 10 * MILLISECOND,
        health_check_failure_threshold: threshold,
        health_check_unhealthy_threshold: 1,
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
        runs.command(),
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
        runs.command(),
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
        runs.command(),
        Flapping::default(),
        service_options(50 * MILLISECOND, max, u32::MAX),
    );
    wait_until("run 3 starts", || watchdog.start_counter() == 3).await;

    tokio::time::sleep(2 * max).await;

    assert_eq!(watchdog.consecutive_failures(), 2);
}

#[tokio::test]
async fn restarts_for_failed_health_checks_count_and_back_off() {
    let runs = Arc::new(Runs::new());
    runs.keep_up(1);
    runs.keep_up(2);
    let health = HealthyFromRun {
        runs: Arc::clone(&runs),
        from: 2,
    };
    let base = 300 * MILLISECOND;
    let started = Instant::now();
    // The count would reset only after run 2 is healthy for 10 s
    let watchdog = ServiceWatchdog::start_with_opt(
        runs.command(),
        health,
        service_options(base, 10 * SECOND, 10),
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
async fn a_crash_after_a_healthy_run_counts_as_the_first_failure() {
    let runs = Runs::new();
    runs.keep_up(3);
    runs.keep_up(4);
    let health = HealthSwitch::default();
    health.set(true);
    let max = SECOND;
    let watchdog = ServiceWatchdog::start_with_opt(
        runs.command(),
        health,
        service_options(300 * MILLISECOND, max, u32::MAX),
    );
    wait_until("run 3 has been healthy for the longest wait", || {
        watchdog.start_counter() == 3 && watchdog.consecutive_failures() == 0
    })
    .await;

    runs.stop(3);
    wait_until("run 4 starts", || watchdog.start_counter() == 4).await;
    // Run 4 passes a few checks, which take far less than the longest wait. Run 3's healthy time
    // does not carry over to it, so the crash still counts.
    let checks = watchdog.health_checks();
    wait_until("run 4 passes three checks", || {
        watchdog.health_checks() >= checks + 3
    })
    .await;

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
        runs.command(),
        health,
        service_options(200 * MILLISECOND, 400 * MILLISECOND, u32::MAX),
    );
    watchdog
        .wait_for_healthy(5 * SECOND)
        .await
        .expect("run 1 turns healthy");

    // Every later run crashes at once, so the watchdog spends nearly all its time waiting
    runs.stop(1);
    wait_until("the service reports unhealthy between runs", || {
        watchdog.consecutive_failures() >= 2 && !watchdog.is_healthy()
    })
    .await;
}

#[tokio::test]
async fn failed_health_checks_do_not_restart_a_service_that_is_not_running() {
    let runs = Runs::new();
    runs.keep_up(1);
    let health = HealthSwitch::default();
    health.set(true);
    // A crashing run is up for milliseconds, far short of 25 checks 10 ms apart
    let threshold = 25;
    let watchdog = ServiceWatchdog::start_with_opt(
        runs.command(),
        health.clone(),
        service_options(300 * MILLISECOND, 600 * MILLISECOND, threshold),
    );
    watchdog
        .wait_for_healthy(5 * SECOND)
        .await
        .expect("run 1 turns healthy");

    // Run 1 crashes and takes its health with it; every later run crashes at once
    runs.stop(1);
    health.set(false);
    wait_until("run 4 starts", || watchdog.start_counter() >= 4).await;

    // Each run so far ended in one failure, or is still up. The 600 ms waits span 60 failing
    // checks each, enough for two more restarts apiece if checks counted while nothing runs.
    let starts = watchdog.start_counter();
    let failures = watchdog.consecutive_failures() as usize;
    assert!(
        failures == starts || failures + 1 == starts,
        "{failures} failures in a row after {starts} starts"
    );
}

/// What one scripted health check does.
#[derive(Debug, Clone, Copy)]
enum Check {
    Pass,
    Fail,
    /// Answers too late: times out after a second, as an HTTP check does under load
    Slow,
}

/// Health checks that follow a script, one step per check; the last step repeats.
#[derive(Debug)]
struct Scripted {
    steps: Vec<Check>,
    calls: AtomicUsize,
}

impl Scripted {
    fn new(steps: &[Check]) -> Self {
        Self {
            steps: steps.to_vec(),
            calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl HealthCheck for Scripted {
    async fn check_health(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        match self.steps[call.min(self.steps.len() - 1)] {
            Check::Pass => Ok(()),
            Check::Fail => Err("the script fails this check".into()),
            Check::Slow => {
                tokio::time::timeout(SECOND, tokio::time::sleep(10 * SECOND)).await?;
                Ok(())
            }
        }
    }
}

/// Health checks that pass for run `run` alone.
#[derive(Debug)]
struct PassesOnlyRun {
    runs: Arc<Runs>,
    run: usize,
}

#[async_trait]
impl HealthCheck for PassesOnlyRun {
    async fn check_health(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let latest = self.runs.latest();
        if latest == self.run {
            Ok(())
        } else {
            Err(format!("run {latest} is still starting").into())
        }
    }
}

const INTERVAL: Duration = Duration::from_secs(10);

/// A health check every 10 s. Three failures in a row report the service unhealthy; five restart
/// it.
fn hysteresis_options() -> ServiceWatchdogOptions {
    ServiceWatchdogOptions {
        health_check_interval: INTERVAL,
        health_check_failure_threshold: 5,
        health_check_unhealthy_threshold: 3,
        initial_startup_delay: Duration::ZERO,
        command_options: backoff_options(SECOND, 8 * SECOND),
    }
}

/// Waits on the paused clock until health check `check`, counted from `start`, has run.
async fn after_check(start: Instant, check: u32) {
    tokio::time::sleep_until(start + INTERVAL * check + INTERVAL / 2).await;
}

#[tokio::test(start_paused = true)]
async fn one_slow_health_check_does_not_report_the_service_unhealthy() {
    let runs = Runs::new();
    runs.keep_up(1);
    let start = Instant::now();
    let watchdog = ServiceWatchdog::start_with_opt(
        runs.command(),
        Scripted::new(&[Check::Pass, Check::Slow, Check::Pass]),
        hysteresis_options(),
    );

    after_check(start, 1).await;
    assert!(watchdog.is_healthy());
    after_check(start, 2).await;
    assert_eq!(watchdog.failed_health_checks(), 1);
    assert!(
        watchdog.is_healthy(),
        "one slow check reported the service unhealthy"
    );
    after_check(start, 3).await;
    assert!(watchdog.is_healthy());
}

#[tokio::test(start_paused = true)]
async fn three_failed_checks_in_a_row_report_it_unhealthy_and_one_pass_healthy_again() {
    let runs = Runs::new();
    runs.keep_up(1);
    let start = Instant::now();
    let watchdog = ServiceWatchdog::start_with_opt(
        runs.command(),
        Scripted::new(&[
            Check::Pass,
            Check::Fail,
            Check::Fail,
            Check::Fail,
            Check::Pass,
        ]),
        hysteresis_options(),
    );

    after_check(start, 3).await;
    assert!(watchdog.is_healthy(), "two failures in a row");
    after_check(start, 4).await;
    assert!(!watchdog.is_healthy(), "three failures in a row");
    // Reported unhealthy, but short of the five failures that restart it
    assert_eq!(watchdog.consecutive_failures(), 0);
    assert_eq!(watchdog.start_counter(), 1);
    after_check(start, 5).await;
    assert!(watchdog.is_healthy(), "one passing check");
}

#[tokio::test(start_paused = true)]
async fn failed_checks_that_are_not_in_a_row_do_not_add_up() {
    let runs = Runs::new();
    runs.keep_up(1);
    let start = Instant::now();
    let watchdog = ServiceWatchdog::start_with_opt(
        runs.command(),
        Scripted::new(&[
            Check::Pass,
            Check::Fail,
            Check::Fail,
            Check::Pass,
            Check::Fail,
            Check::Fail,
            Check::Pass,
        ]),
        hysteresis_options(),
    );

    for check in 1..=7 {
        after_check(start, check).await;
        assert!(watchdog.is_healthy(), "after check {check}");
    }
    assert_eq!(watchdog.failed_health_checks(), 4);
}

#[tokio::test(start_paused = true)]
async fn a_service_that_stops_running_is_unhealthy_at_once() {
    let runs = Runs::new();
    runs.keep_up(1);
    let mut opt = hysteresis_options();
    // Run 2 would start an hour after run 1
    opt.command_options = backoff_options(3600 * SECOND, 3600 * SECOND);
    let start = Instant::now();
    let watchdog =
        ServiceWatchdog::start_with_opt(runs.command(), Scripted::new(&[Check::Pass]), opt);
    after_check(start, 1).await;
    assert!(watchdog.is_healthy());

    runs.stop(1);
    // Takes in the exit without letting the clock reach another check
    spin_until(|| watchdog.consecutive_failures() == 1).await;
    tokio::time::sleep(INTERVAL).await;

    assert!(
        !watchdog.is_healthy(),
        "one check after the service stopped, it still passed for healthy"
    );
    assert_eq!(watchdog.start_counter(), 1);
}

#[tokio::test(start_paused = true)]
async fn a_new_run_is_unhealthy_until_it_passes_a_check() {
    let runs = Arc::new(Runs::new());
    runs.keep_up(1);
    runs.keep_up(2);
    let health = PassesOnlyRun {
        runs: Arc::clone(&runs),
        run: 1,
    };
    let start = Instant::now();
    let watchdog = ServiceWatchdog::start_with_opt(runs.command(), health, hysteresis_options());
    // The first check must not come before run 1 has started
    spin_until(|| runs.latest() == 1).await;
    after_check(start, 1).await;
    assert!(watchdog.is_healthy());

    // Run 1 has run longer than its 1 s restart interval, so run 2 starts as soon as it exits
    runs.stop(1);
    spin_until(|| runs.latest() == 2).await;
    tokio::time::sleep(INTERVAL).await;

    // Run 2 failed one check: short of three, but it never passed one
    assert_eq!(watchdog.failed_health_checks(), 1);
    assert!(
        !watchdog.is_healthy(),
        "run 2 took over run 1's healthy state"
    );
}
