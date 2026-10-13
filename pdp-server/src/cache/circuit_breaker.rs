//! A circuit breaker that keeps a Redis outage from stalling authorization checks.
//!
//! While Redis answers, every cache operation reaches it: the breaker is closed. The first
//! error or timeout opens it, and from then on operations skip Redis, so decisions come
//! straight from OPA. Once the cooldown has passed, the next operation starts one background
//! probe and the breaker is half-open until the probe finishes. A successful probe closes the
//! breaker; a failed one opens it again with double the cooldown, up to a cap. The cooldown
//! starts over from the initial value after the breaker closes.
//!
//! Each state change is logged once. Nothing is logged per operation.

use log::{info, warn};
use std::fmt::Display;
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
}

impl CircuitBreaker {
    pub(crate) fn new(cooldowns: Cooldowns) -> Self {
        Self {
            cooldowns,
            state: watch::Sender::new(BreakerState::Closed),
        }
    }

    pub(crate) fn state(&self) -> BreakerState {
        *self.state.borrow()
    }

    /// Decides whether an operation starting at `now` may use Redis. When an open breaker's
    /// cooldown has passed, exactly one caller gets [`Admission::SkipAndProbe`].
    pub(crate) fn admit(&self, now: Instant) -> Admission {
        if *self.state.borrow() == BreakerState::Closed {
            return Admission::Allow;
        }
        let mut admission = Admission::Skip;
        self.state.send_if_modified(|state| match *state {
            BreakerState::Closed => {
                admission = Admission::Allow;
                false
            }
            BreakerState::Open { retry_at, cooldown } if now >= retry_at => {
                *state = BreakerState::HalfOpen { cooldown };
                admission = Admission::SkipAndProbe;
                true
            }
            BreakerState::Open {
                retry_at: _,
                cooldown: _,
            }
            | BreakerState::HalfOpen { cooldown: _ } => false,
        });
        if admission == Admission::SkipAndProbe {
            info!("Redis cache circuit breaker half-open: probing Redis");
        }
        admission
    }

    /// Records that an operation failed. This opens a closed breaker. An open or half-open
    /// breaker is left alone: the failure belongs to an operation that started before it
    /// opened, and only the probe decides what happens next.
    pub(crate) fn record_failure(&self, now: Instant, error: &dyn Display) {
        let cooldown = self.cooldowns.initial;
        let opened = self.state.send_if_modified(|state| {
            if *state != BreakerState::Closed {
                return false;
            }
            *state = BreakerState::Open {
                retry_at: now + cooldown,
                cooldown,
            };
            true
        });
        if opened {
            warn!(
                "Redis cache unavailable ({error}). Circuit breaker open: checks skip the cache \
                 for {cooldown:?}, then a probe retries Redis"
            );
        }
    }

    /// Records that the probe reached Redis, closing the breaker.
    pub(crate) fn record_probe_success(&self) {
        let closed = self.state.send_if_modified(|state| {
            let BreakerState::HalfOpen { cooldown: _ } = *state else {
                return false;
            };
            *state = BreakerState::Closed;
            true
        });
        if closed {
            info!("Redis cache reachable again. Circuit breaker closed");
        }
    }

    /// Records that the probe failed, opening the breaker for double the last cooldown.
    pub(crate) fn record_probe_failure(&self, now: Instant, error: &dyn Display) {
        let max = self.cooldowns.max;
        let mut next = max;
        let reopened = self.state.send_if_modified(|state| {
            let BreakerState::HalfOpen { cooldown } = *state else {
                return false;
            };
            next = cooldown.saturating_mul(2).min(max);
            *state = BreakerState::Open {
                retry_at: now + next,
                cooldown: next,
            };
            true
        });
        if reopened {
            warn!("Redis cache probe failed ({error}). Circuit breaker open for {next:?}");
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
        breaker.record_failure(t0, &"timed out");
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
        breaker.record_failure(t0, &"timed out");
        // The breaker logs exactly when its state changes, so no change means no log line.
        let states = breaker.subscribe();
        for offset_ms in [1, 10, 500] {
            breaker.record_failure(t0 + Duration::from_millis(offset_ms), &"timed out");
            assert_eq!(breaker.admit(t0), Admission::Skip);
        }
        assert!(!states.has_changed().unwrap());
        assert_eq!(breaker.state(), open_at(t0, COOLDOWNS.initial));
    }

    #[test]
    fn test_one_probe_after_the_cooldown() {
        let breaker = CircuitBreaker::new(COOLDOWNS);
        let t0 = Instant::now();
        breaker.record_failure(t0, &"timed out");
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
        breaker.record_failure(now, &"timed out");
        let mut cooldowns = Vec::new();
        for _ in 0..5 {
            let BreakerState::Open { retry_at, cooldown } = breaker.state() else {
                panic!("expected an open breaker, got {:?}", breaker.state());
            };
            cooldowns.push(cooldown.as_secs());
            now = retry_at;
            assert_eq!(breaker.admit(now), Admission::SkipAndProbe);
            breaker.record_probe_failure(now, &"timed out");
        }
        assert_eq!(cooldowns, [1, 2, 4, 5, 5]);
        assert_eq!(breaker.state(), open_at(now, COOLDOWNS.max));
    }

    #[test]
    fn test_successful_probe_closes_and_resets_the_cooldown() {
        let breaker = CircuitBreaker::new(COOLDOWNS);
        let t0 = Instant::now();
        breaker.record_failure(t0, &"timed out");
        let t1 = t0 + COOLDOWNS.initial;
        assert_eq!(breaker.admit(t1), Admission::SkipAndProbe);
        breaker.record_probe_failure(t1, &"timed out");
        let t2 = t1 + COOLDOWNS.initial * 2;
        assert_eq!(breaker.admit(t2), Admission::SkipAndProbe);

        breaker.record_probe_success();
        assert_eq!(breaker.state(), BreakerState::Closed);
        assert_eq!(breaker.admit(t2), Admission::Allow);

        // The next outage starts from the initial cooldown again.
        breaker.record_failure(t2, &"timed out");
        assert_eq!(breaker.state(), open_at(t2, COOLDOWNS.initial));
    }

    #[test]
    fn test_probe_results_only_count_while_half_open() {
        let breaker = CircuitBreaker::new(COOLDOWNS);
        let t0 = Instant::now();
        breaker.record_probe_failure(t0, &"timed out");
        assert_eq!(breaker.state(), BreakerState::Closed);

        breaker.record_failure(t0, &"timed out");
        breaker.record_probe_success();
        breaker.record_probe_failure(t0, &"timed out");
        assert_eq!(breaker.state(), open_at(t0, COOLDOWNS.initial));
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
