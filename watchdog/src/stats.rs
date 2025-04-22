use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

/// Statistics for the subprocess managed by CommandWatchdog
#[derive(Debug, Default)]
pub(crate) struct CommandWatchdogStats {
    /// Counter for how many times the process has been started
    start_counter: AtomicUsize,
    /// The last exit code of the subprocess (0 if not yet exited)
    last_exit_code: AtomicI32,
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
