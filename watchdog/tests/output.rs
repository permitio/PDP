//! Child output capture, driven through real child processes.
//!
//! Unix-only: every test here drives a child through a POSIX shell, and the
//! crate itself already forks its termination path on `cfg(unix)`.
#![cfg(unix)]

use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::process::Command;
use watchdog::{ChildOutputHandler, ChildStream, CommandWatchdog, CommandWatchdogOptions};

#[derive(Default)]
struct Collector(Mutex<Vec<(ChildStream, String)>>);

impl ChildOutputHandler for Collector {
    fn on_line(&self, stream: ChildStream, line: &str) {
        self.0
            .lock()
            .expect("lock")
            .push((stream, line.to_string()));
    }
}

impl Collector {
    fn lines(&self) -> Vec<(ChildStream, String)> {
        self.0.lock().expect("lock").clone()
    }
    fn texts(&self) -> Vec<String> {
        self.lines().into_iter().map(|(_, line)| line).collect()
    }
}

/// A shell command is used rather than a fixture binary so the test depends on
/// nothing but a POSIX shell — no fixture to build, and no `awk` or other
/// external the script would otherwise reach for.
///
/// `sh` is resolved through `PATH` rather than hard-coded to `/bin/sh`, which
/// is not where every Unix keeps it (some Nix setups among them).
fn sh(script: &str) -> Command {
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(script);
    cmd
}

/// Poll rather than sleep a fixed amount: the child is a process, so how long
/// it takes to produce output is not something a test can assume.
async fn wait_for(collector: &Collector, want: usize, label: &str) {
    for _ in 0..200 {
        if collector.lines().len() >= want {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!(
        "{label}: expected at least {want} lines, got {:?}",
        collector.lines()
    );
}

#[tokio::test]
async fn both_streams_are_captured_and_attributed() {
    let collector = Arc::new(Collector::default());
    let opt = CommandWatchdogOptions {
        // The child exits immediately, so keep the restart interval long
        // enough that a second generation cannot muddy the assertion.
        restart_interval: Duration::from_secs(30),
        output_handler: Some(collector.clone()),
        ..Default::default()
    };
    let _watchdog = CommandWatchdog::start_with_opt(sh("echo to-stdout; echo to-stderr >&2"), opt);

    wait_for(&collector, 2, "both streams").await;

    let lines = collector.lines();
    assert!(
        lines.contains(&(ChildStream::Stdout, "to-stdout".to_string())),
        "stdout line missing or misattributed: {lines:?}"
    );
    assert!(
        lines.contains(&(ChildStream::Stderr, "to-stderr".to_string())),
        "stderr line missing or misattributed: {lines:?}"
    );
}

/// The watchdog respawns the child, and each spawn creates fresh pipes. If the
/// readers were attached once rather than per spawn, the second generation's
/// output would vanish.
#[tokio::test]
async fn output_is_captured_across_a_restart() {
    let collector = Arc::new(Collector::default());
    let opt = CommandWatchdogOptions {
        restart_interval: Duration::from_millis(50),
        output_handler: Some(collector.clone()),
        ..Default::default()
    };
    let _watchdog = CommandWatchdog::start_with_opt(sh("echo generation"), opt);

    wait_for(&collector, 3, "restart generations").await;

    let texts = collector.texts();
    assert!(
        texts.iter().filter(|line| *line == "generation").count() >= 3,
        "each respawned generation must have its output captured, got {texts:?}"
    );
}

/// A child that writes a very long line must not be able to grow the
/// supervisor without bound, and must not take the rest of the stream with it.
#[tokio::test]
async fn an_over_long_child_line_is_truncated_and_the_stream_survives() {
    let collector = Arc::new(Collector::default());
    let opt = CommandWatchdogOptions {
        restart_interval: Duration::from_secs(30),
        output_handler: Some(collector.clone()),
        ..Default::default()
    };
    // 2^18 = 262_144 `x`, well past MAX_LINE_BYTES, then a normal line.
    // Built by doubling rather than with `awk`: it keeps this file's only
    // dependency a POSIX shell, and 18 doublings beat a 262k-iteration loop.
    let _watchdog = CommandWatchdog::start_with_opt(
        sh(
            "s=x; i=0; while [ $i -lt 18 ]; do s=$s$s; i=$((i+1)); done; \
            printf '%s\\n' \"$s\"; echo after",
        ),
        opt,
    );

    wait_for(&collector, 2, "truncation").await;

    let texts = collector.texts();
    assert!(
        texts[0].len() <= watchdog::MAX_LINE_BYTES + watchdog::TRUNCATION_MARKER.len(),
        "the long line must be bounded, got {} bytes",
        texts[0].len()
    );
    assert!(
        texts[0].ends_with(watchdog::TRUNCATION_MARKER),
        "a truncated line must say so"
    );
    assert!(
        texts.contains(&"after".to_string()),
        "the stream must survive a truncated line, got {texts:?}"
    );
}

/// The default must stay behaviour-preserving: no handler means the child
/// keeps inheriting the parent's file descriptors, exactly as before.
#[test]
fn the_default_supplies_no_handler() {
    assert!(CommandWatchdogOptions::default().output_handler.is_none());
}
