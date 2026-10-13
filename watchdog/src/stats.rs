use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicUsize, Ordering};

/// Statistics for the subprocess managed by CommandWatchdog
#[derive(Debug, Default)]
pub(crate) struct CommandWatchdogStats {
    /// Counter for how many times the process has been started
    start_counter: AtomicUsize,
    /// The last exit code of the subprocess (0 if not yet exited)
    last_exit_code: AtomicI32,
    /// How many times in a row the process has failed since it last stayed up or healthy
    consecutive_failures: AtomicU32,
    /// Whether a started process is running
    running: AtomicBool,
}

impl CommandWatchdogStats {
    /// Gets the number of times the process has been started
    pub(crate) fn start_counter(&self) -> usize {
        self.start_counter.load(Ordering::Relaxed)
    }

    /// Gets the last exit code of the subprocess
    pub(crate) fn last_exit_code(&self) -> i32 {
        self.last_exit_code.load(Ordering::Relaxed)
    }

    /// Increments the start counter and returns the previous value
    pub(crate) fn increment_start_counter(&self) -> usize {
        self.start_counter.fetch_add(1, Ordering::SeqCst)
    }

    /// Sets the last exit code
    pub(crate) fn set_last_exit_code(&self, code: i32) {
        self.last_exit_code.store(code, Ordering::SeqCst);
    }

    /// Gets how many times in a row the process has failed
    pub(crate) fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures.load(Ordering::SeqCst)
    }

    /// Counts one more failure in a row
    pub(crate) fn record_failure(&self) {
        // At u32::MAX the count stays put rather than wrapping to 0: the backoff is long past its
        // cap by then, so the `Err` that leaves it unchanged is not a failure to report
        self.consecutive_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |failures| {
                failures.checked_add(1)
            })
            .ok();
    }

    /// Forgets the failures in a row and returns how many there were
    pub(crate) fn reset_failures(&self) -> u32 {
        self.consecutive_failures.swap(0, Ordering::SeqCst)
    }

    /// Whether a started process is running
    pub(crate) fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Records whether a started process is running
    pub(crate) fn set_running(&self, running: bool) {
        self.running.store(running, Ordering::SeqCst);
    }
}

/// Statistics for the ServiceWatchdog
#[derive(Debug, Default)]
pub(crate) struct ServiceWatchdogStats {
    /// Total number of health checks performed
    health_checks: AtomicUsize,
    /// Total number of failed health checks
    failed_health_checks: AtomicUsize,
}

impl ServiceWatchdogStats {
    /// Get the total number of health checks performed
    pub(crate) fn health_checks(&self) -> usize {
        self.health_checks.load(Ordering::Relaxed)
    }

    /// Increment the total number of health checks performed
    pub(crate) fn increment_health_checks(&self) {
        self.health_checks.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the total number of failed health checks
    pub(crate) fn failed_health_checks(&self) -> usize {
        self.failed_health_checks.load(Ordering::Relaxed)
    }

    /// Increment the total number of failed health checks
    pub(crate) fn increment_failed_health_checks(&self) {
        self.failed_health_checks.fetch_add(1, Ordering::Relaxed);
    }
}
