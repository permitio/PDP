//! A circuit breaker that keeps a Redis outage from stalling authorization checks.
//!
//! While Redis answers, every cache operation reaches it: the breaker is closed. The first
//! error or timeout opens it, and from then on operations skip Redis, so decisions come
//! straight from OPA. Once the cooldown has passed, the next operation starts one background
//! probe and the breaker is half-open until the probe finishes. A successful probe closes the
//! breaker; a failed one opens it again with double the cooldown, up to a cap. The cooldown
//! starts over from the initial value after the breaker closes.
//!
//! State changes are logged through [`BreakerLog`], at most one line a minute. Nothing is
//! logged per operation.

use super::breaker_log::{BreakerLog, Transition};
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::Instant;

/// How long the breaker stays open before the next probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cooldowns {
    /// The cooldown after the breaker first opens.
    pub(crate) initial: Duration,
    /// The longest cooldown that failed probes can double it to.
    pub(crate) max: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BreakerState {
    /// Operations use Redis.
    Closed,
    /// Operations skip Redis until `retry_at`.
    Open {
        retry_at: Instant,
        cooldown: Duration,
    },
    /// Operations skip Redis while a probe runs. `cooldown` is the one that just elapsed.
    HalfOpen { cooldown: Duration },
}

impl BreakerState {
    /// The state's name, as the cache health check reports it.
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Open {
                retry_at: _,
                cooldown: _,
            } => "open",
            Self::HalfOpen { cooldown: _ } => "half_open",
        }
    }
}

/// Whether an operation may use Redis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Admission {
    Allow,
    Skip,
    /// Skip Redis, and start the probe that decides whether the breaker closes.
    SkipAndProbe,
}

pub(crate) struct CircuitBreaker {
    cooldowns: Cooldowns,
    state: watch::Sender<BreakerState>,
    log: BreakerLog,
}

impl CircuitBreaker {
    pub(crate) fn new(cooldowns: Cooldowns) -> Self {
        Self {
            cooldowns,
            state: watch::Sender::new(BreakerState::Closed),
            log: BreakerLog::new(),
        }
    }

    pub(crate) fn state(&self) -> BreakerState {
        *self.state.borrow()
    }

    /// Decides whether an operation starting at `now` may use Redis. When an open breaker's
    /// cooldown has passed, exactly one caller gets [`Admission::SkipAndProbe`].
    pub(crate) fn admit(&self, now: Instant) -> Admission {
        if *self.state.borrow() == BreakerState::Closed {
            // A breaker that stopped changing state still owes the summary of its last changes.
            self.log.flush(now, BreakerState::Closed);
            return Admission::Allow;
        }
        let mut admission = Admission::Skip;
        let mut half_open = None;
        self.state.send_if_modified(|state| match *state {
            BreakerState::Closed => {
                admission = Admission::Allow;
                false
            }
            BreakerState::Open { retry_at, cooldown } if now >= retry_at => {
                *state = BreakerState::HalfOpen { cooldown };
                half_open = Some(*state);
                admission = Admission::SkipAndProbe;
                true
            }
            BreakerState::Open {
                retry_at: _,
                cooldown: _,
            }
            | BreakerState::HalfOpen { cooldown: _ } => false,
        });
        if let Some(state) = half_open {
            self.log.record(now, Transition::HalfOpen, state);
        }
        admission
    }

    /// Records that an operation failed with an error of kind `error`. This opens a closed
    /// breaker. An open or half-open breaker is left alone: the failure belongs to an operation
    /// that started before it opened, and only the probe decides what happens next.
    pub(crate) fn record_failure(&self, now: Instant, error: &str) {
        let cooldown = self.cooldowns.initial;
        let mut opened = None;
        self.state.send_if_modified(|state| {
            if *state != BreakerState::Closed {
                return false;
            }
            *state = BreakerState::Open {
                retry_at: now + cooldown,
                cooldown,
            };
            opened = Some(*state);
            true
        });
        if let Some(state) = opened {
            self.log
                .record(now, Transition::Opened { error, cooldown }, state);
        }
    }

    /// Records that the probe reached Redis, closing the breaker.
    pub(crate) fn record_probe_success(&self, now: Instant) {
        let closed = self.state.send_if_modified(|state| {
            let BreakerState::HalfOpen { cooldown: _ } = *state else {
                return false;
            };
            *state = BreakerState::Closed;
            true
        });
        if closed {
            self.log
                .record(now, Transition::Closed, BreakerState::Closed);
        }
    }

    /// Records that the probe failed with an error of kind `error`, opening the breaker for
    /// double the last cooldown.
    pub(crate) fn record_probe_failure(&self, now: Instant, error: &str) {
        let max = self.cooldowns.max;
        let mut reopened = None;
        self.state.send_if_modified(|state| {
            let BreakerState::HalfOpen { cooldown } = *state else {
                return false;
            };
            let next = cooldown.saturating_mul(2).min(max);
            *state = BreakerState::Open {
                retry_at: now + next,
                cooldown: next,
            };
            reopened = Some((next, *state));
            true
        });
        if let Some((cooldown, state)) = reopened {
            self.log
                .record(now, Transition::Reopened { error, cooldown }, state);
        }
    }

    #[cfg(test)]
    pub(crate) fn subscribe(&self) -> watch::Receiver<BreakerState> {
        self.state.subscribe()
    }

    /// Ends the current cooldown now, so a test need not wait it out.
    #[cfg(test)]
    pub(crate) fn expire_cooldown(&self) {
        self.state.send_if_modified(|state| {
            let BreakerState::Open { retry_at, cooldown } = *state else {
                return false;
            };
            *state = BreakerState::Open {
                retry_at: retry_at - cooldown,
                cooldown,
            };
            true
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::breaker_log::LOG_INTERVAL;
    use crate::test_utils::LogCapture;

    const COOLDOWNS: Cooldowns = Cooldowns {
        initial: Duration::from_secs(1),
        max: Duration::from_secs(5),
    };

    fn open_at(now: Instant, cooldown: Duration) -> BreakerState {
        BreakerState::Open {
            retry_at: now + cooldown,
            cooldown,
        }
    }

    #[test]
    fn test_closed_breaker_allows_operations() {
        let breaker = CircuitBreaker::new(COOLDOWNS);
        assert_eq!(breaker.admit(Instant::now()), Admission::Allow);
        assert_eq!(breaker.state(), BreakerState::Closed);
    }

    #[test]
    fn test_failure_opens_the_breaker_for_the_initial_cooldown() {
        let breaker = CircuitBreaker::new(COOLDOWNS);
        let t0 = Instant::now();
        breaker.record_failure(t0, "timeout");
        assert_eq!(breaker.state(), open_at(t0, COOLDOWNS.initial));
        assert_eq!(breaker.admit(t0), Admission::Skip);
        assert_eq!(
            breaker.admit(t0 + COOLDOWNS.initial - Duration::from_millis(1)),
            Admission::Skip
        );
    }

    #[test]
    fn test_failures_while_open_change_nothing() {
        let breaker = CircuitBreaker::new(COOLDOWNS);
        let t0 = Instant::now();
        breaker.record_failure(t0, "timeout");
        // The breaker logs exactly when its state changes, so no change means no log line.
        let states = breaker.subscribe();
        for offset_ms in [1, 10, 500] {
            breaker.record_failure(t0 + Duration::from_millis(offset_ms), "timeout");
            assert_eq!(breaker.admit(t0), Admission::Skip);
        }
        assert!(!states.has_changed().unwrap());
        assert_eq!(breaker.state(), open_at(t0, COOLDOWNS.initial));
    }

    #[test]
    fn test_one_probe_after_the_cooldown() {
        let breaker = CircuitBreaker::new(COOLDOWNS);
        let t0 = Instant::now();
        breaker.record_failure(t0, "timeout");
        let t1 = t0 + COOLDOWNS.initial;
        assert_eq!(breaker.admit(t1), Admission::SkipAndProbe);
        assert_eq!(
            breaker.state(),
            BreakerState::HalfOpen {
                cooldown: COOLDOWNS.initial
            }
        );
        // While the probe runs, everything else still skips Redis.
        assert_eq!(breaker.admit(t1), Admission::Skip);
        assert_eq!(breaker.admit(t1 + COOLDOWNS.max), Admission::Skip);
    }

    #[test]
    fn test_failed_probes_double_the_cooldown_up_to_the_cap() {
        let breaker = CircuitBreaker::new(COOLDOWNS);
        let mut now = Instant::now();
        breaker.record_failure(now, "timeout");
        let mut cooldowns = Vec::new();
        for _ in 0..5 {
            let BreakerState::Open { retry_at, cooldown } = breaker.state() else {
                panic!("expected an open breaker, got {:?}", breaker.state());
            };
            cooldowns.push(cooldown.as_secs());
            now = retry_at;
            assert_eq!(breaker.admit(now), Admission::SkipAndProbe);
            breaker.record_probe_failure(now, "timeout");
        }
        assert_eq!(cooldowns, [1, 2, 4, 5, 5]);
        assert_eq!(breaker.state(), open_at(now, COOLDOWNS.max));
    }

    #[test]
    fn test_successful_probe_closes_and_resets_the_cooldown() {
        let breaker = CircuitBreaker::new(COOLDOWNS);
        let t0 = Instant::now();
        breaker.record_failure(t0, "timeout");
        let t1 = t0 + COOLDOWNS.initial;
        assert_eq!(breaker.admit(t1), Admission::SkipAndProbe);
        breaker.record_probe_failure(t1, "timeout");
        let t2 = t1 + COOLDOWNS.initial * 2;
        assert_eq!(breaker.admit(t2), Admission::SkipAndProbe);

        breaker.record_probe_success(t2);
        assert_eq!(breaker.state(), BreakerState::Closed);
        assert_eq!(breaker.admit(t2), Admission::Allow);

        // The next outage starts from the initial cooldown again.
        breaker.record_failure(t2, "timeout");
        assert_eq!(breaker.state(), open_at(t2, COOLDOWNS.initial));
    }

    #[test]
    fn test_probe_results_only_count_while_half_open() {
        let breaker = CircuitBreaker::new(COOLDOWNS);
        let t0 = Instant::now();
        breaker.record_probe_failure(t0, "timeout");
        assert_eq!(breaker.state(), BreakerState::Closed);

        breaker.record_failure(t0, "timeout");
        breaker.record_probe_success(t0);
        breaker.record_probe_failure(t0, "timeout");
        assert_eq!(breaker.state(), open_at(t0, COOLDOWNS.initial));
    }

    fn breaker_lines(logs: &LogCapture) -> Vec<String> {
        let mut lines = Vec::new();
        for line in logs.lines() {
            if line.to_lowercase().contains("circuit breaker") {
                lines.push(line);
            }
        }
        lines
    }

    /// Redis answers PING but rejects every write, as one that is out of memory does: each
    /// write opens the breaker and each probe closes it again. Over five simulated minutes the
    /// breaker logs one line at once, then at most one a minute, and those lines account for
    /// every opening.
    #[tokio::test(start_paused = true)]
    async fn test_cycling_logs_at_most_one_line_a_minute() {
        let logs = LogCapture::start();
        let breaker = CircuitBreaker::new(COOLDOWNS);
        let started = Instant::now();
        let minutes = 5;
        let mut openings = 0;
        while started.elapsed() < LOG_INTERVAL * minutes {
            // A write is rejected.
            breaker.record_failure(Instant::now(), "OOM");
            openings += 1;
            // The cooldown passes, the next operation starts the probe, and PING answers.
            tokio::time::advance(COOLDOWNS.initial).await;
            assert_eq!(breaker.admit(Instant::now()), Admission::SkipAndProbe);
            breaker.record_probe_success(Instant::now());
            // Reads go to Redis again until the next write.
            tokio::time::advance(Duration::from_millis(100)).await;
            assert_eq!(breaker.admit(Instant::now()), Admission::Allow);
        }
        // Once the breaker settles, the first operation after the interval logs the last
        // summary, and /health shows the state throughout.
        tokio::time::advance(LOG_INTERVAL).await;
        assert_eq!(breaker.admit(Instant::now()), Admission::Allow);
        assert_eq!(breaker.state().name(), "closed");

        let lines = breaker_lines(&logs);
        let most = 1 + usize::try_from(minutes).unwrap() + 1;
        assert!(lines.len() <= most, "{} lines: {lines:?}", lines.len());
        assert!(
            lines[0].starts_with("WARN Redis cache unavailable (OOM)."),
            "{lines:?}"
        );
        let mut reported = 1;
        for line in &lines[1..] {
            let summary = line.strip_prefix("WARN Redis circuit breaker opened ");
            let Some((count, rest)) =
                summary.and_then(|rest| rest.split_once(" times in the last "))
            else {
                panic!("not a summary: {line}");
            };
            let Some((seconds, rest)) = rest.split_once(" s; ") else {
                panic!("not a summary: {line}");
            };
            assert!(
                seconds.parse::<u64>().unwrap() >= LOG_INTERVAL.as_secs(),
                "{line}"
            );
            assert!(rest.starts_with("last error: OOM; now "), "{line}");
            reported += count.parse::<u32>().unwrap();
        }
        assert_eq!(reported, openings, "{lines:?}");
        assert!(openings > 200, "only {openings} cycles");
    }

    #[test]
    fn test_state_names() {
        let now = Instant::now();
        assert_eq!(BreakerState::Closed.name(), "closed");
        assert_eq!(open_at(now, COOLDOWNS.initial).name(), "open");
        let half_open = BreakerState::HalfOpen {
            cooldown: COOLDOWNS.initial,
        };
        assert_eq!(half_open.name(), "half_open");
    }
}
