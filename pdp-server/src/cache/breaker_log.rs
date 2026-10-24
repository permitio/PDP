//! The circuit breaker's log, rate limited.
//!
//! A Redis that answers `PING` but rejects every write (out of memory, or a read-only replica)
//! makes the breaker cycle open, half-open and closed about once a second. Logging each of
//! those changes would add three lines a second for as long as it lasts. So a change is logged
//! at once only when no line went out in the last [`LOG_INTERVAL`]. Changes inside the
//! interval are counted instead, and one summary line reports them when it has passed: with
//! the next change, or with the next cache operation if the breaker has stopped changing.
//!
//! Errors are named by kind only, such as `OOM` or `timeout`. A Redis error message can quote
//! the command's arguments, and those include cache keys.

use super::circuit_breaker::BreakerState;
use log::Level;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;
use tokio::time::Instant;

/// The breaker logs at most one line per interval.
pub(crate) const LOG_INTERVAL: Duration = Duration::from_secs(60);

/// A change of breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Transition<'a> {
    /// An operation failed with an error of kind `error`, and the breaker opened.
    Opened {
        error: &'a str,
        cooldown: Duration,
    },
    /// The probe failed with an error of kind `error`, and the breaker opened again.
    Reopened {
        error: &'a str,
        cooldown: Duration,
    },
    HalfOpen,
    Closed,
}

impl Transition<'_> {
    fn line(self) -> (Level, String) {
        match self {
            Self::Opened { error, cooldown } => (
                Level::Warn,
                format!(
                    "Redis cache unavailable ({error}). Circuit breaker open: checks skip the \
                     cache for {cooldown:?}, then a probe retries Redis"
                ),
            ),
            Self::Reopened { error, cooldown } => (
                Level::Warn,
                format!(
                    "Redis cache probe failed ({error}). Circuit breaker open for {cooldown:?}"
                ),
            ),
            Self::HalfOpen => (
                Level::Info,
                "Redis cache circuit breaker half-open: probing Redis".to_string(),
            ),
            Self::Closed => (
                Level::Info,
                "Redis cache reachable again. Circuit breaker closed".to_string(),
            ),
        }
    }
}

/// The changes held back since the last line.
#[derive(Debug, Default)]
struct Window {
    /// When the last line went out.
    last_line: Option<Instant>,
    /// Changes since then.
    changes: u32,
    /// How many of those opened the breaker.
    openings: u32,
    /// The kind of error behind the last opening.
    last_error: Option<String>,
}

impl Window {
    fn hold(&mut self, transition: Transition<'_>) {
        self.changes = self.changes.saturating_add(1);
        match transition {
            Transition::Opened { error, cooldown: _ }
            | Transition::Reopened { error, cooldown: _ } => {
                self.openings = self.openings.saturating_add(1);
                self.last_error = Some(error.to_string());
            }
            Transition::HalfOpen | Transition::Closed => {}
        }
    }

    fn summary(&self, now: Instant, state: BreakerState) -> (Level, String) {
        let seconds = match self.last_line {
            Some(last_line) => now.saturating_duration_since(last_line).as_secs(),
            None => 0,
        };
        let state = state.name();
        if self.openings == 0 {
            let changes = self.changes;
            return (
                Level::Info,
                format!(
                    "Redis circuit breaker changed state {changes} times in the last {seconds} s; \
                     now {state}"
                ),
            );
        }
        let openings = self.openings;
        let error = self.last_error.as_deref().unwrap_or("unknown");
        (
            Level::Warn,
            format!(
                "Redis circuit breaker opened {openings} times in the last {seconds} s; last \
                 error: {error}; now {state}"
            ),
        )
    }
}

pub(crate) struct BreakerLog {
    epoch: Instant,
    /// When the summary of held-back changes is due, in nanoseconds after `epoch`, or zero
    /// when nothing is held back. Every cache operation reads it, without taking the lock.
    summary_due: AtomicU64,
    window: Mutex<Window>,
}

impl BreakerLog {
    pub(crate) fn new() -> Self {
        Self {
            epoch: Instant::now(),
            summary_due: AtomicU64::new(0),
            window: Mutex::new(Window::default()),
        }
    }

    /// Logs `transition`, which left the breaker in `state`, or holds it for the summary.
    pub(crate) fn record(&self, now: Instant, transition: Transition<'_>, state: BreakerState) {
        let mut window = self.window.lock().unwrap_or_else(PoisonError::into_inner);
        let line = match window.last_line {
            Some(last_line) if now < last_line + LOG_INTERVAL => {
                window.hold(transition);
                let due = self.offset(last_line + LOG_INTERVAL);
                self.summary_due.store(due, Ordering::Relaxed);
                None
            }
            Some(_) | None => {
                let line = if window.changes == 0 {
                    transition.line()
                } else {
                    window.hold(transition);
                    window.summary(now, state)
                };
                self.start_window(&mut window, now);
                Some(line)
            }
        };
        drop(window);
        if let Some((level, line)) = line {
            log::log!(level, "{line}");
        }
    }

    /// Logs the summary of held-back changes if it is due. `state` is the breaker's state now.
    pub(crate) fn flush(&self, now: Instant, state: BreakerState) {
        let due = self.summary_due.load(Ordering::Relaxed);
        if due == 0 || self.offset(now) < due {
            return;
        }
        let mut window = self.window.lock().unwrap_or_else(PoisonError::into_inner);
        // Checked again under the lock: a line may have gone out since `due` was read.
        let Some(last_line) = window.last_line else {
            return;
        };
        if window.changes == 0 || now < last_line + LOG_INTERVAL {
            return;
        }
        let (level, line) = window.summary(now, state);
        self.start_window(&mut window, now);
        drop(window);
        log::log!(level, "{line}");
    }

    fn start_window(&self, window: &mut Window, now: Instant) {
        *window = Window {
            last_line: Some(now),
            ..Window::default()
        };
        self.summary_due.store(0, Ordering::Relaxed);
    }

    /// `at` as nanoseconds after `epoch`, and at least 1, since zero means nothing is due.
    fn offset(&self, at: Instant) -> u64 {
        let nanos = at.saturating_duration_since(self.epoch).as_nanos();
        u64::try_from(nanos).unwrap_or(u64::MAX).max(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::LogCapture;

    const COOLDOWN: Duration = Duration::from_secs(1);
    const HALF_OPEN: BreakerState = BreakerState::HalfOpen { cooldown: COOLDOWN };

    fn opened(error: &str) -> Transition<'_> {
        Transition::Opened {
            error,
            cooldown: COOLDOWN,
        }
    }

    fn open(now: Instant) -> BreakerState {
        BreakerState::Open {
            retry_at: now + COOLDOWN,
            cooldown: COOLDOWN,
        }
    }

    #[test]
    fn test_the_first_change_is_logged_at_once() {
        let logs = LogCapture::start();
        let log = BreakerLog::new();
        let t0 = Instant::now();

        log.record(t0, opened("OOM"), open(t0));

        assert_eq!(
            logs.lines(),
            [
                "WARN Redis cache unavailable (OOM). Circuit breaker open: checks skip the cache \
              for 1s, then a probe retries Redis"
            ]
        );
    }

    #[test]
    fn test_changes_within_the_interval_go_into_one_summary() {
        let logs = LogCapture::start();
        let log = BreakerLog::new();
        let t0 = Instant::now();
        log.record(t0, opened("OOM"), open(t0));
        let mut now = t0;
        for _ in 0..10 {
            now += COOLDOWN;
            log.record(now, Transition::HalfOpen, HALF_OPEN);
            log.record(now, Transition::Closed, BreakerState::Closed);
            log.record(now, opened("READONLY"), open(now));
        }
        assert_eq!(logs.lines().len(), 1, "{:?}", logs.lines());

        // The first change once the interval has passed brings the summary, itself included.
        let t1 = t0 + LOG_INTERVAL;
        log.record(t1, Transition::HalfOpen, HALF_OPEN);
        assert_eq!(
            logs.lines()[1..],
            [
                "WARN Redis circuit breaker opened 10 times in the last 60 s; last error: \
              READONLY; now half_open"
            ]
        );

        // And it starts the next interval.
        log.record(t1 + COOLDOWN, Transition::Closed, BreakerState::Closed);
        assert_eq!(logs.lines().len(), 2, "{:?}", logs.lines());
    }

    #[test]
    fn test_a_change_one_interval_after_the_last_line_is_logged() {
        let logs = LogCapture::start();
        let t0 = Instant::now();

        let held = BreakerLog::new();
        held.record(t0, opened("OOM"), open(t0));
        let just_inside = t0 + LOG_INTERVAL - Duration::from_millis(1);
        held.record(just_inside, Transition::HalfOpen, HALF_OPEN);
        assert_eq!(logs.lines().len(), 1, "{:?}", logs.lines());

        let logged = BreakerLog::new();
        logged.record(t0, opened("OOM"), open(t0));
        logged.record(t0 + LOG_INTERVAL, Transition::HalfOpen, HALF_OPEN);
        assert_eq!(
            logs.lines()[2..],
            ["INFO Redis cache circuit breaker half-open: probing Redis"]
        );
    }

    #[test]
    fn test_flush_reports_held_changes_once_due() {
        let logs = LogCapture::start();
        let log = BreakerLog::new();
        let t0 = Instant::now();
        log.record(t0, opened("OOM"), open(t0));
        log.record(t0 + COOLDOWN, Transition::HalfOpen, HALF_OPEN);
        log.record(t0 + COOLDOWN, Transition::Closed, BreakerState::Closed);

        log.flush(
            t0 + LOG_INTERVAL - Duration::from_millis(1),
            BreakerState::Closed,
        );
        assert_eq!(logs.lines().len(), 1, "{:?}", logs.lines());

        log.flush(t0 + LOG_INTERVAL, BreakerState::Closed);
        assert_eq!(
            logs.lines()[1..],
            ["INFO Redis circuit breaker changed state 2 times in the last 60 s; now closed"]
        );

        // Nothing is held any more.
        log.flush(t0 + LOG_INTERVAL * 3, BreakerState::Closed);
        assert_eq!(logs.lines().len(), 2, "{:?}", logs.lines());
    }

    /// A line can go out between `flush` reading the due time and taking the lock, leaving it
    /// holding an old due time while a new interval has begun. The interval decides.
    #[test]
    fn test_flush_goes_by_the_interval_not_a_stale_due_time() {
        let logs = LogCapture::start();
        let log = BreakerLog::new();
        let t0 = Instant::now();
        log.record(t0, opened("OOM"), open(t0));
        log.record(t0 + COOLDOWN, Transition::HalfOpen, HALF_OPEN);
        let t1 = t0 + LOG_INTERVAL;
        log.record(t1, Transition::Closed, BreakerState::Closed);
        log.record(t1 + COOLDOWN, opened("OOM"), open(t1 + COOLDOWN));
        assert_eq!(logs.lines().len(), 2, "{:?}", logs.lines());

        log.summary_due.store(log.offset(t1), Ordering::Relaxed);
        log.flush(t1 + LOG_INTERVAL / 2, BreakerState::Closed);

        assert_eq!(logs.lines().len(), 2, "{:?}", logs.lines());
    }

    #[test]
    fn test_flush_with_nothing_held_logs_nothing() {
        let logs = LogCapture::start();
        let log = BreakerLog::new();
        let t0 = Instant::now();
        log.flush(t0 + LOG_INTERVAL, BreakerState::Closed);
        log.record(t0, opened("OOM"), open(t0));
        log.flush(t0 + LOG_INTERVAL * 2, BreakerState::Closed);
        assert_eq!(logs.lines().len(), 1, "{:?}", logs.lines());
    }

    #[test]
    fn test_failed_probes_count_as_openings() {
        let logs = LogCapture::start();
        let log = BreakerLog::new();
        let t0 = Instant::now();
        log.record(t0, opened("timeout"), open(t0));
        let mut now = t0;
        for error in ["timeout", "I/O error", "connection refused"] {
            now += COOLDOWN;
            log.record(now, Transition::HalfOpen, HALF_OPEN);
            let reopened = Transition::Reopened {
                error,
                cooldown: COOLDOWN,
            };
            log.record(now, reopened, open(now));
        }

        log.flush(t0 + LOG_INTERVAL, open(now));

        assert_eq!(
            logs.lines()[1..],
            [
                "WARN Redis circuit breaker opened 3 times in the last 60 s; last error: \
              connection refused; now open"
            ]
        );
    }
}
