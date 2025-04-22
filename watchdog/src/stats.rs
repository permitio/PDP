use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

/// Statistics for the subprocess managed by CommandWatchdog
#[derive(Debug)]
pub(crate) struct WatchdogStats {
    /// Counter for how many times the process has been started
    start_counter: AtomicUsize,
    /// The last exit code of the subprocess (0 if not yet exited)
    last_exit_code: AtomicI32,
}

impl WatchdogStats {
    /// Creates a new WatchdogStats instance with default values
    pub(crate) fn new() -> Self {
        Self {
            start_counter: AtomicUsize::new(0),
            last_exit_code: AtomicI32::new(0),
        }
    }

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
