//! How long the watchdog waits between starts of a process that keeps failing.

use std::time::Duration;

/// Doubles the shortest time between starts with each failure in a row, from `base` up to `max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RestartBackoff {
    base: Duration,
    max: Duration,
}

impl RestartBackoff {
    /// A `max` below `base` acts as `base`: the process then restarts at a fixed interval.
    pub(crate) fn new(base: Duration, max: Duration) -> Self {
        Self {
            base,
            max: max.max(base),
        }
    }

    /// The shortest time from a start to the next one after `failures` failures in a row: none
    /// before the first failure, `base` after it, then twice the previous one, at most `max`.
    pub(crate) fn delay(&self, failures: u32) -> Duration {
        let Some(doublings) = failures.checked_sub(1) else {
            return Duration::ZERO;
        };
        let mut delay = self.base;
        for _ in 0..doublings {
            // Past the cap, or from zero, further doublings change nothing
            if delay.is_zero() || delay >= self.max {
                break;
            }
            delay = delay.saturating_mul(2);
        }
        delay.min(self.max)
    }

    /// How long the process has to stay up, or pass its health checks, before its earlier
    /// failures stop counting: as long as the longest wait.
    pub(crate) fn reset_after(&self) -> Duration {
        self.max
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECOND: Duration = Duration::from_secs(1);

    #[test]
    fn delays_double_from_the_base_and_stop_at_the_cap() {
        let backoff = RestartBackoff::new(SECOND, 60 * SECOND);

        let delays: Vec<u64> = (0..=9)
            .map(|failures| backoff.delay(failures).as_secs())
            .collect();

        assert_eq!(delays, [0, 1, 2, 4, 8, 16, 32, 60, 60, 60]);
    }

    #[test]
    fn delays_stay_at_the_cap_however_many_failures() {
        let backoff = RestartBackoff::new(SECOND, 60 * SECOND);

        for failures in [32, 33, 64, 1_000, u32::MAX] {
            assert_eq!(backoff.delay(failures), 60 * SECOND, "{failures} failures");
        }
    }

    #[test]
    fn a_cap_below_the_base_restarts_at_the_base() {
        let backoff = RestartBackoff::new(5 * SECOND, SECOND);

        for failures in [1, 2, 10] {
            assert_eq!(backoff.delay(failures), 5 * SECOND, "{failures} failures");
        }
        assert_eq!(backoff.reset_after(), 5 * SECOND);
    }

    #[test]
    fn a_zero_base_never_waits() {
        let backoff = RestartBackoff::new(Duration::ZERO, 60 * SECOND);

        for failures in [0, 1, 2, 40] {
            assert_eq!(
                backoff.delay(failures),
                Duration::ZERO,
                "{failures} failures"
            );
        }
    }

    #[test]
    fn failures_stop_counting_after_the_longest_wait() {
        let backoff = RestartBackoff::new(SECOND, 60 * SECOND);

        assert_eq!(backoff.reset_after(), 60 * SECOND);
    }
}
