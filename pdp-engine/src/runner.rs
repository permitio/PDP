use crate::PDPError;
use crate::args::Arg;
use log::{debug, error, info, warn};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use once_cell::sync::Lazy;
use signal_hook::{consts::signal::*, iterator::Signals};
use std::collections::{HashMap, HashSet};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

// Global state for signal handling to avoid registering duplicate handlers
// and to track child processes that need to receive forwarded signals
static SIGNAL_HANDLER_INITIALIZED: AtomicBool = AtomicBool::new(false);
// Using an RwLock instead of a regular Mutex for better concurrency - read locks for iteration,
// write locks for modifications
static CHILD_PROCESSES: Lazy<RwLock<HashSet<u32>>> = Lazy::new(|| RwLock::new(HashSet::new()));
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

/// `PDPRunner` is a process runner for the Python PDP server.
/// It stores the Python binary path, PDP directory, CLI arguments, environment variables,
/// and a shared always‐running child process.
/// A background task continuously monitors the process and, if it terminates,
/// restarts it automatically while logging the events.
/// Shutdown is controlled by a CancellationToken.
#[derive(Clone, Debug)]
pub struct PDPRunner {
    pub python_path: PathBuf,
    pub pdp_dir: PathBuf,
    pub args: Vec<Arg>,
    pub env_vars: HashMap<String, String>,
    /// The currently running child, wrapped in an `Arc<Mutex<Child>>` for safe concurrent updates.
    child: Arc<Mutex<Child>>, // Note: the monitoring task is holding a write lock on this.
    current_pid: Arc<AtomicU32>,
    shutdown_token: CancellationToken,
}

impl PDPRunner {
    pub fn get_shutdown_token(&self) -> CancellationToken {
        self.shutdown_token.clone()
    }

    /// Starts the PDP server as a subprocess.
    ///
    /// This method spawns the process with the provided binary, directory, CLI arguments, and environment variables,
    /// wraps the child in an `Arc<Mutex<_>>`, creates a CancellationToken,
    /// and spawns a background monitor task that watches the process and restarts it if it exits.
    pub(crate) async fn start<P: AsRef<Path>, D: AsRef<Path>>(
        python_path: P,
        pdp_dir: D,
        args: Vec<Arg>,
        env_vars: HashMap<String, String>,
    ) -> Result<PDPRunner, PDPError> {
        let python_path_buf = python_path.as_ref().to_path_buf();
        let pdp_dir_buf = pdp_dir.as_ref().to_path_buf();

        let shutdown_token = CancellationToken::new();
        // Set up the global signal handler if it hasn't been set up yet
        if let Err(e) = Self::setup_global_signal_handler(shutdown_token.clone()) {
            error!("Failed to set up signal handler: {}", e);
            // Continue execution even if signal handler setup fails
        }

        // Check if shutdown was already requested before we even started
        if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
            shutdown_token.cancel();
            return Err(PDPError::ShutdownTriggered);
        }

        let child = Self::spawn_child(&python_path_buf, &pdp_dir_buf, &args, &env_vars).await?;
        let pid = child.id().unwrap_or(0);
        if pid > 0 {
            // Register this child process for signal forwarding
            if let Err(e) = Self::register_child_process(pid) {
                warn!(
                    "Failed to register PID {} for signal forwarding: {}",
                    pid, e
                );
                // Continue execution even if registration fails
            }
        } else {
            warn!("Unable to register PID 0 for signal forwarding");
        }

        let current_pid = Arc::new(AtomicU32::new(pid));
        let child = Arc::new(Mutex::new(child));

        Self::spawn_monitor_task(
            python_path_buf.clone(),
            pdp_dir_buf.clone(),
            args.clone(),
            env_vars.clone(),
            Arc::clone(&child),
            Arc::clone(&current_pid),
            shutdown_token.clone(),
        );

        Ok(Self {
            python_path: python_path_buf,
            pdp_dir: pdp_dir_buf,
            args,
            env_vars,
            child,
            current_pid,
            shutdown_token,
        })
    }

    /// Register a child process PID for signal forwarding
    fn register_child_process(pid: u32) -> Result<(), PDPError> {
        match CHILD_PROCESSES.write() {
            Ok(mut guard) => {
                guard.insert(pid);
                info!("Registered PID {} for signal forwarding", pid);
                Ok(())
            }
            Err(e) => {
                error!("Failed to acquire write lock for CHILD_PROCESSES: {:?}", e);
                Err(PDPError::ProcessManagement(format!(
                    "Failed to register child process: {:?}",
                    e
                )))
            }
        }
    }

    /// Unregister a child process PID from signal forwarding
    fn unregister_child_process(pid: u32) -> Result<(), PDPError> {
        match CHILD_PROCESSES.write() {
            Ok(mut guard) => {
                if guard.remove(&pid) {
                    info!("Unregistered PID {} from signal forwarding", pid);
                }
                Ok(())
            }
            Err(e) => {
                error!("Failed to acquire write lock for CHILD_PROCESSES: {:?}", e);
                Err(PDPError::ProcessManagement(format!(
                    "Failed to unregister child process: {:?}",
                    e
                )))
            }
        }
    }

    /// Sets up a global signal handler that forwards signals to all running child processes
    fn setup_global_signal_handler(shutdown_token: CancellationToken) -> Result<(), PDPError> {
        // Only initialize once
        if SIGNAL_HANDLER_INITIALIZED
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            info!("Setting up global signal handler for PDP processes");

            // Which signals we want to handle
            let signals = vec![
                // Standard termination signals
                SIGTERM, SIGINT, SIGHUP, // Other signals to forward
                SIGUSR1, SIGUSR2,
            ];

            // Create the signals iterator
            let mut signals = match Signals::new(signals) {
                Ok(signals) => signals,
                Err(err) => {
                    let msg = format!("Failed to register signal handler: {}", err);
                    error!("{}", msg);
                    return Err(PDPError::ProcessManagement(msg));
                }
            };

            // Spawn a dedicated thread for handling signals
            thread::spawn(move || {
                // This thread will receive signals when they arrive
                info!("Signal handling thread started");

                // Iterate through signals as they arrive
                for signal in signals.forever() {
                    info!("Received signal: {}", signal);

                    // For termination signals, notify shutdown
                    let is_termination = match signal {
                        SIGTERM | SIGINT | SIGHUP => {
                            info!(
                                "Received termination signal {}, initiating shutdown",
                                signal
                            );
                            SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
                            true
                        }
                        _ => false,
                    };

                    if let Err(e) = Self::forward_signal_to_children(signal, shutdown_token.clone())
                    {
                        error!("Error forwarding signal {} to children: {}", signal, e);
                    }

                    // If this is a termination signal, break the loop to stop the signal handling thread
                    if is_termination {
                        info!("Termination signal processed, signal handler thread will exit");
                        break;
                    }
                }
            });

            Ok(())
        } else {
            // Handler already initialized
            debug!("Signal handler already initialized");
            Ok(())
        }
    }

    /// Forward a signal to all registered child processes
    fn forward_signal_to_children(
        signal: i32,
        shutdown_token: CancellationToken,
    ) -> Result<(), PDPError> {
        // Try to acquire a read lock - better concurrency than a write lock
        match CHILD_PROCESSES.read() {
            Ok(guard) => {
                // Create a copy of PIDs to avoid holding the lock while sending signals
                let pids: Vec<u32> = guard.iter().copied().collect();
                drop(guard); // Release the lock as soon as possible

                // Now forward the signal to each child process
                for pid in pids {
                    let pid_i32: i32 = match pid.try_into() {
                        Ok(i32_pid) => i32_pid,
                        Err(e) => {
                            error!("Failed to convert PID {} to i32: {}", pid, e);
                            continue;
                        }
                    };
                    if let Ok(sig) = Signal::try_from(signal) {
                        // For termination signals, we want to wait for the process to finish
                        let is_termination =
                            matches!(sig, Signal::SIGTERM | Signal::SIGINT | Signal::SIGHUP);

                        if let Err(e) = kill(Pid::from_raw(pid_i32), sig) {
                            // Only log as error if not ESRCH (No such process) which is common
                            // when a child has already terminated
                            match e {
                                nix::Error::ESRCH => {
                                    debug!(
                                        "Process {} no longer exists when forwarding signal {}",
                                        pid, signal
                                    );
                                    // Clean up the stale PID from our tracking set
                                    if let Err(e) = Self::unregister_child_process(pid) {
                                        debug!("Failed to unregister stale PID {}: {}", pid, e);
                                    }
                                }
                                _ => {
                                    error!(
                                        "Failed to forward signal {} to child process {}: {}",
                                        signal, pid, e
                                    );
                                }
                            }
                        } else {
                            info!("Forwarded signal {} to child process {}", signal, pid);
                            // If this is a termination signal, wait for the process to exit with timeout
                            if is_termination {
                                shutdown_token.cancel();
                                let start = std::time::Instant::now();
                                let timeout = std::time::Duration::from_secs(5); // 5 second timeout

                                while start.elapsed() < timeout {
                                    match nix::sys::wait::waitpid(
                                        Pid::from_raw(pid_i32),
                                        Some(nix::sys::wait::WaitPidFlag::WNOHANG),
                                    ) {
                                        Ok(nix::sys::wait::WaitStatus::StillAlive) => {
                                            // Process still running, wait a bit before checking again
                                            info!(
                                                "Process {} still running after signal {}, waiting a bit before checking again to allow graceful shutdown",
                                                pid, signal
                                            );
                                            std::thread::sleep(std::time::Duration::from_millis(
                                                100,
                                            ));
                                            continue;
                                        }
                                        Ok(_) => {
                                            // Process has exited
                                            debug!(
                                                "Process {} exited gracefully after signal {}",
                                                pid, signal
                                            );
                                            break;
                                        }
                                        Err(nix::Error::ECHILD) => {
                                            // No child process found - it has already been reaped
                                            debug!(
                                                "Process {} already reaped after signal {}",
                                                pid, signal
                                            );
                                            break;
                                        }
                                        Err(e) => {
                                            error!("Error waiting for process {}: {}", pid, e);
                                            break;
                                        }
                                    }
                                }

                                if start.elapsed() >= timeout {
                                    warn!(
                                        "Timeout waiting for process {} to exit after signal {}, force killing it",
                                        pid, signal
                                    );
                                    // force kill the process
                                    if let Err(e) = kill(Pid::from_raw(pid_i32), Signal::SIGKILL) {
                                        error!("Failed to force kill process {}: {}", pid, e);
                                    }
                                }
                            }
                        }
                    }
                }

                Ok(())
            }
            Err(e) => {
                error!("Failed to acquire read lock for CHILD_PROCESSES: {:?}", e);
                Err(PDPError::ProcessManagement(format!(
                    "Failed to forward signals: {:?}",
                    e
                )))
            }
        }
    }

    /// Helper method that spawns a new child process using the provided binary, directory, CLI arguments, and environment variables.
    async fn spawn_child(
        python_path: &PathBuf,
        pdp_dir: &PathBuf,
        args: &Vec<Arg>,
        env_vars: &HashMap<String, String>,
    ) -> Result<Child, PDPError> {
        // Check if shutdown is requested and abort if it is
        if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
            return Err(PDPError::ShutdownTriggered);
        }

        let mut cmd = Command::new(python_path);
        cmd.kill_on_drop(true);

        // Set working directory to the PDP directory
        cmd.current_dir(pdp_dir);

        // Inherit all environment variables from the parent process
        // and then add/override with the specifically provided ones
        cmd.envs(env_vars);

        // Inherit STDOUT and STDERR so all the output will be forwarded to the parent process.
        cmd.stdout(std::process::Stdio::inherit());
        cmd.stderr(std::process::Stdio::inherit());

        // Add the arguments.
        let mut cmd_str = python_path.to_string_lossy().to_string();
        for arg in args {
            for s in arg.to_args() {
                cmd.arg(&s);
                cmd_str.push(' ');
                cmd_str.push_str(&s);
            }
        }

        // Spawn the child process.
        let child = cmd.spawn()?;
        let pid = child.id().unwrap_or(0);
        info!(
            "PDP process started with PID {} using command: {}",
            pid, cmd_str
        );

        Ok(child)
    }

    /// Spawns a background task that continuously monitors the child process.
    /// If the child terminates, it logs the exit status and spawns a new process,
    /// updating the shared `child` handle.
    /// The task exits when the shutdown token is cancelled.
    fn spawn_monitor_task(
        python_path: PathBuf,
        pdp_dir: PathBuf,
        args: Vec<Arg>,
        env_vars: HashMap<String, String>,
        child: Arc<Mutex<Child>>,
        current_pid: Arc<AtomicU32>,
        shutdown_token: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_token.cancelled() => {
                        info!("Stopping PDP runner due to cancellation token.");

                        // When shutting down, remove our process from the global tracking set
                        let pid = current_pid.load(Ordering::SeqCst);
                        if pid > 0 {
                            if let Err(e) = Self::unregister_child_process(pid) {
                                error!("Failed to unregister PID {}: {}", pid, e);
                            }
                        }

                        break;
                    },
                    wait_res = async {
                        // Acquire a write lock only for taking the child out.
                        let mut child_lock = child.lock().await;
                        // Get the PID of the child process before it exits.
                        let pid = child_lock.id();
                        match child_lock.wait().await {
                            Ok(status) => Ok((pid, status)),
                            Err(e) => Err(e),
                        }
                    } => {
                        match wait_res {
                            Ok((pid, status)) => {
                                info!("PDP process {} exited with code {:?} from signal {}.",
                                      pid.unwrap_or(0),
                                      status.code().unwrap_or(-1),
                                      status.signal().unwrap_or(-1));

                                // Remove exited process from the global tracking set
                                if let Some(p) = pid {
                                    if let Err(e) = Self::unregister_child_process(p) {
                                        error!("Failed to unregister PID {}: {}", p, e);
                                    }
                                }

                                // Check if this was due to a shutdown signal
                                if status.signal() == Some(SIGINT) ||
                                   status.signal() == Some(SIGTERM) ||
                                   SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
                                    info!("Detected termination signal, will not restart process.");
                                    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
                                    shutdown_token.cancel();
                                    break;
                                }

                                info!("Will attempt to restart PDP process...");
                            },
                            Err(e) => {
                                error!("Error waiting on PDP process: {}. Retrying...", e);
                                sleep(Duration::from_secs(1)).await;
                                continue;
                            }
                        }
                    }
                }

                // Before restarting, check if shutdown has been signalled.
                if shutdown_token.is_cancelled() || SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
                    info!("Shutdown requested, will not restart process.");
                    if !shutdown_token.is_cancelled() {
                        // Cancel our token if the global shutdown flag is set
                        shutdown_token.cancel();
                    }
                    break;
                }

                // Attempt to spawn a new child process.
                match Self::spawn_child(&python_path, &pdp_dir, &args, &env_vars).await {
                    Ok(new_child) => {
                        let new_pid = new_child.id().unwrap_or(0);

                        // Register the new child for signal forwarding
                        if new_pid > 0 {
                            if let Err(e) = Self::register_child_process(new_pid) {
                                error!("Failed to register new PID {}: {}", new_pid, e);
                            }
                        }

                        {
                            let mut child_lock = child.lock().await;
                            current_pid.store(new_pid, Ordering::SeqCst);
                            *child_lock = new_child;
                        }
                        sleep(Duration::from_secs(1)).await; // Wait a bit before checking again.
                    }
                    Err(e) => {
                        error!(
                            "Failed to restart PDP process: {}. Retrying in 1 second...",
                            e
                        );
                        sleep(Duration::from_secs(1)).await;
                    }
                }
            }
            debug!("PDP monitor task exiting.");
        })
    }

    /// Returns the current PID of the PDP process
    pub async fn get_pid(&self) -> u32 {
        self.current_pid.load(Ordering::SeqCst)
    }

    /// Stops the PDP runner by cancelling the monitor task and then killing the current process.
    /// This ensures that the monitor task does not restart the process.
    pub async fn stop(self) -> Result<(), PDPError> {
        // Signal shutdown.
        self.shutdown_token.cancel();

        // Remove from global tracking before killing
        let pid = self.current_pid.load(Ordering::SeqCst);
        if pid > 0 {
            if let Err(e) = Self::unregister_child_process(pid) {
                error!("Failed to unregister PID {} during stop: {}", pid, e);
            }
        }

        // Kill the current process.
        let mut child_lock = self.child.lock().await;
        if let Err(e) = child_lock.kill().await {
            error!("Failed to kill process {}: {}", pid, e);
            // Continue anyway to attempt to wait for it
        }

        match child_lock.wait().await {
            Ok(status) => {
                info!(
                    "PDP process {} exited with code {:?}, stopping runner.",
                    child_lock.id().unwrap_or(0),
                    status.code()
                );
            }
            Err(e) => {
                error!("Error waiting for process to exit: {}", e);
                // We continue anyway since we're shutting down
            }
        }

        Ok(())
    }

    /// Forcefully kills the current PDP process.
    async fn kill_current_process(&self) -> Result<(), PDPError> {
        let pid = self.current_pid.load(Ordering::SeqCst);

        // Remove from global tracking before killing
        if pid > 0 {
            if let Err(e) = Self::unregister_child_process(pid) {
                error!("Failed to unregister PID {} during kill: {}", pid, e);
            }
        }

        let mut child_lock = self.child.lock().await;
        if let Err(e) = child_lock.kill().await {
            error!("Failed to kill process {}: {}", pid, e);
            return Err(PDPError::ProcessManagement(e.to_string()));
        }

        match child_lock.wait().await {
            Ok(status) => {
                info!(
                    "PDP process {} exited with code {:?}.",
                    child_lock.id().unwrap_or(0),
                    status.code()
                );
                Ok(())
            }
            Err(e) => {
                error!("Error killing PDP process: {}", e);
                Err(PDPError::ProcessManagement(e.to_string()))
            }
        }
    }

    /// Restarts the PDP process by killing the current process and letting the monitor task restart it.
    pub async fn restart(&self) -> Result<(), PDPError> {
        // Check if shutdown is requested and abort if it is
        if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
            return Err(PDPError::ShutdownTriggered);
        }

        info!("Restarting PDP process...");

        // Kill the current process
        self.kill_current_process().await?;

        // Wait a moment for the monitor to restart the process
        sleep(Duration::from_millis(500)).await;

        // Check if a new process was started
        let pid = self.current_pid.load(Ordering::SeqCst);
        if pid == 0 {
            return Err(PDPError::ProcessManagement(
                "PDP process failed to restart after kill".to_string(),
            ));
        }

        info!("PDP process restarted with PID {}", pid);
        Ok(())
    }

    /// Sends a specific signal to the child process.
    pub async fn send_signal(&self, signal: Signal) -> Result<(), PDPError> {
        let pid = self.current_pid.load(Ordering::SeqCst);
        if pid == 0 {
            return Err(PDPError::ProcessNotRunning);
        }

        match kill(Pid::from_raw(pid as i32), signal) {
            Ok(_) => {
                info!("Sent signal {:?} to PDP process {}", signal, pid);
                Ok(())
            }
            Err(e) => {
                error!(
                    "Failed to send signal {:?} to PDP process {}: {}",
                    signal, pid, e
                );
                Err(PDPError::ProcessManagement(format!(
                    "Failed to send signal: {}",
                    e
                )))
            }
        }
    }
}

// Ensure clean shutdown
impl Drop for PDPRunner {
    fn drop(&mut self) {
        // Cancel our token
        self.shutdown_token.cancel();

        // Remove our process from the global tracking set
        let pid = self.current_pid.load(Ordering::SeqCst);
        if pid > 0 {
            // We can't use async function in Drop, so we have to use a direct lock approach
            if let Ok(mut guard) = CHILD_PROCESSES.write() {
                guard.remove(&pid);
                info!(
                    "Unregistered PID {} from signal forwarding during drop",
                    pid
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use log::LevelFilter;
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;
    use std::collections::HashMap;
    use std::time::Duration;

    // Helper function to get a sleep command for testing the process monitor
    fn get_test_python_command() -> (String, PathBuf, Vec<Arg>, HashMap<String, String>) {
        let python_path = "/usr/bin/python3".to_string();
        let pdp_dir = PathBuf::from("/tmp");

        let args = vec![
            Arg::Custom("-c".to_string()),
            Arg::Custom(
                "import time; print('Starting'); time.sleep(30); print('Done')".to_string(),
            ),
        ];

        let env_vars = HashMap::new();

        (python_path, pdp_dir, args, env_vars)
    }

    // Helper function to get a signal handling test script
    fn get_signal_test_python_command() -> (String, PathBuf, Vec<Arg>, HashMap<String, String>) {
        let python_path = "/usr/bin/python3".to_string();
        let pdp_dir = PathBuf::from("/tmp");

        // Python script that sets up signal handlers and prints when signals are received
        let args = vec![
            Arg::Custom("-c".to_string()),
            Arg::Custom(
                r#"
import signal
import time
import os
import sys

def signal_handler(signum, frame):
    print(f'Received signal {signum}')
    sys.stdout.flush()
    if signum == signal.SIGTERM:
        sys.exit(0)

# Register signal handlers
signal.signal(signal.SIGUSR1, signal_handler)
signal.signal(signal.SIGUSR2, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

print(f'Process started with PID {os.getpid()}')
sys.stdout.flush()

# Keep running until terminated
while True:
    time.sleep(1)
"#
                .to_string(),
            ),
        ];

        let env_vars = HashMap::new();

        (python_path, pdp_dir, args, env_vars)
    }

    #[tokio::test]
    async fn test_monitor_restarts_process_when_killed() -> Result<(), PDPError> {
        let _ = env_logger::builder()
            .filter_level(LevelFilter::Debug)
            .is_test(true)
            .try_init();

        let (python_path, pdp_dir, args, env_vars) = get_test_python_command();

        let runner = PDPRunner::start(python_path, pdp_dir, args, env_vars).await?;

        // Get the PID of the original process
        let original_pid = runner.get_pid().await;

        // Kill the process using an external signal
        if let Err(e) = kill(Pid::from_raw(original_pid as i32), Signal::SIGTERM) {
            error!("Failed to kill process: {}", e);
            // Continue with the test even if we couldn't kill the process
        }

        // Wait for the monitor to restart the process
        sleep(Duration::from_secs(2)).await;

        // Get the PID of the new process
        let new_pid = runner.get_pid().await;

        // Verify that a new process has been started with a different PID
        assert_ne!(original_pid, new_pid);
        assert_ne!(new_pid, 0);

        runner.stop().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_signal_forwarding() -> Result<(), PDPError> {
        let _ = env_logger::builder()
            .filter_level(LevelFilter::Debug)
            .is_test(true)
            .try_init();

        let (python_path, pdp_dir, args, env_vars) = get_signal_test_python_command();

        let runner = PDPRunner::start(python_path, pdp_dir, args, env_vars).await?;

        // Give the Python process time to start up
        sleep(Duration::from_secs(1)).await;

        // Send a signal to the process using the runner
        runner.send_signal(Signal::SIGUSR1).await?;

        // Wait a moment for the signal to be processed
        sleep(Duration::from_secs(1)).await;

        // Send another signal
        runner.send_signal(Signal::SIGUSR2).await?;

        // Wait a moment for the signal to be processed
        sleep(Duration::from_secs(1)).await;

        // Stop the process
        runner.stop().await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_stop() -> Result<(), PDPError> {
        let _ = env_logger::builder()
            .filter_level(LevelFilter::Debug)
            .is_test(true)
            .try_init();

        let (python_path, pdp_dir, args, env_vars) = get_test_python_command();

        let runner = PDPRunner::start(python_path, pdp_dir, args, env_vars).await?;

        // Get the PID of the process
        let pid = runner.get_pid().await;
        assert_ne!(pid, 0);

        // Stop the runner
        runner.stop().await?;

        // Try to send a signal to the process, which should fail because the process is gone
        let result = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
        assert!(result.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_restart() -> Result<(), PDPError> {
        let _ = env_logger::builder()
            .filter_level(LevelFilter::Debug)
            .is_test(true)
            .try_init();

        let (python_path, pdp_dir, args, env_vars) = get_test_python_command();

        let runner = PDPRunner::start(python_path, pdp_dir, args, env_vars).await?;

        // Get the PID of the original process
        let original_pid = runner.get_pid().await;
        assert_ne!(original_pid, 0);

        // Restart the process
        runner.restart().await?;

        // Wait a moment
        sleep(Duration::from_millis(500)).await;

        // Get the PID of the restarted process
        let new_pid = runner.get_pid().await;
        assert_ne!(new_pid, 0);
        assert_ne!(original_pid, new_pid);

        runner.stop().await?;
        Ok(())
    }
}
