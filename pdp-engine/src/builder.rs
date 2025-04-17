use std::collections::HashMap;
use std::marker::PhantomData;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

use crate::args::Arg;
use crate::error::PDPError;

/// Marker types to track whether the required paths have been provided.
pub struct Missing;
pub struct Present;

/// A builder for configuring and starting a PDP engine.
/// The builder is generic over one type parameter:
/// - PathsSet: whether the required paths have been supplied.
pub struct PDPEngineBuilder<PathsSet> {
    pub(crate) python_path: Option<PathBuf>,
    pub(crate) pdp_dir: Option<PathBuf>,
    pub(crate) args: Vec<Arg>,
    pub(crate) env_vars: HashMap<String, String>,
    pub(crate) base_url: String,
    pub(crate) health_timeout: Duration,
    pub(crate) health_check_interval: Duration,
    _paths: PhantomData<PathsSet>,
}

impl PDPEngineBuilder<Missing> {
    /// Creates a new builder with no paths set and a default base URL.
    pub fn new() -> Self {
        Self {
            python_path: None,
            pdp_dir: None,
            args: Vec::new(),
            env_vars: HashMap::new(),
            base_url: "http://localhost:7001/".to_string(),
            health_timeout: Duration::from_secs(10),
            health_check_interval: Duration::from_secs(10),
            _paths: PhantomData,
        }
    }
}

impl Default for PDPEngineBuilder<Missing> {
    fn default() -> Self {
        Self::new()
    }
}

impl<PathsSet> PDPEngineBuilder<PathsSet> {
    /// Adds a CLI argument (typed via `Arg`).
    pub fn add_arg(mut self, arg: Arg) -> Self {
        self.args.push(arg);
        self
    }

    /// Adds a custom CLI argument.
    pub fn add_arg_custom(mut self, arg: String) -> Self {
        self.args.push(Arg::Custom(arg));
        self
    }

    /// Overrides CLI arguments (typed via `Arg`).
    pub fn with_args(mut self, args: Vec<Arg>) -> Self {
        self.args = args;
        self
    }

    /// Sets or overwrites environment variables for the PDP process.
    pub fn with_env_vars(mut self, env_vars: HashMap<String, String>) -> Self {
        self.env_vars = env_vars;
        self
    }

    /// Adds a single environment variable to the PDP process.
    pub fn add_env(mut self, name: String, value: String) -> Self {
        self.env_vars.insert(name, value);
        self
    }

    /// Overrides the default base URL for the PDP server.
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Sets the maximum time to wait for PDP to become healthy.
    /// This timeout is used in two scenarios:
    /// 1. When initially starting PDP, waiting for it to become healthy
    /// 2. When PDP becomes unhealthy during operation, waiting for it to recover before attempting a restart
    pub fn with_health_timeout(mut self, timeout: Duration) -> Self {
        self.health_timeout = timeout;
        self
    }

    /// Sets the interval for health checks when PDP is healthy.
    /// If set to zero, health monitoring will be disabled.
    pub fn with_health_check_interval(mut self, interval: Duration) -> Self {
        self.health_check_interval = interval;
        self
    }
}

// Methods for setting required paths:
impl PDPEngineBuilder<Missing> {
    pub fn with_located_python(self) -> Result<PDPEngineBuilder<Missing>, PDPError> {
        let path =
            which::which("python3").map_err(|e| PDPError::PythonBinaryNotFound(e.to_string()))?;
        self.with_python_path(path)
    }

    /// Sets the Python binary path.
    pub fn with_python_path(
        self,
        path: impl Into<PathBuf>,
    ) -> Result<PDPEngineBuilder<Missing>, PDPError> {
        let path = path.into();
        if !path.is_file()
            || !path
                .metadata()
                .map(|m| m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        {
            return Err(PDPError::PythonBinaryNotFound(
                "Provided Python path is not an executable file".to_string(),
            ));
        }

        Ok(PDPEngineBuilder {
            python_path: Some(path),
            pdp_dir: self.pdp_dir,
            args: self.args,
            env_vars: self.env_vars,
            base_url: self.base_url,
            health_timeout: self.health_timeout,
            health_check_interval: self.health_check_interval,
            _paths: PhantomData,
        })
    }

    pub fn with_cwd_as_pdp_dir(self) -> Result<PDPEngineBuilder<Missing>, PDPError> {
        let cwd = std::env::current_dir().map_err(|e| PDPError::PDPDirNotFound(e.to_string()))?;
        self.with_pdp_dir(cwd)
    }

    /// Sets the PDP directory path.
    pub fn with_pdp_dir(
        self,
        dir: impl Into<PathBuf>,
    ) -> Result<PDPEngineBuilder<Missing>, PDPError> {
        let dir = dir.into();
        if !dir.is_dir() {
            return Err(PDPError::PDPDirNotFound(
                "Provided PDP directory path does not exist".to_string(),
            ));
        }

        Ok(PDPEngineBuilder {
            python_path: self.python_path,
            pdp_dir: Some(dir),
            args: self.args,
            env_vars: self.env_vars,
            base_url: self.base_url,
            health_timeout: self.health_timeout,
            health_check_interval: self.health_check_interval,
            _paths: PhantomData,
        })
    }
}

// Only when both paths are set can we convert to Present
impl PDPEngineBuilder<Missing> {
    /// Checks if both required paths are set and converts to Present if they are
    fn into_present(self) -> Result<PDPEngineBuilder<Present>, PDPError> {
        if self.python_path.is_none() {
            return Err(PDPError::PythonBinaryNotFound(
                "Python binary path not provided".to_string(),
            ));
        }

        if self.pdp_dir.is_none() {
            return Err(PDPError::PDPDirNotFound(
                "PDP directory path not provided".to_string(),
            ));
        }

        Ok(PDPEngineBuilder {
            python_path: self.python_path,
            pdp_dir: self.pdp_dir,
            args: self.args,
            env_vars: self.env_vars,
            base_url: self.base_url,
            health_timeout: self.health_timeout,
            health_check_interval: self.health_check_interval,
            _paths: PhantomData,
        })
    }
}

// Only when both required paths are Present can we start.
impl PDPEngineBuilder<Missing> {
    /// Starts the PDP engine:
    /// 1. Checks that both required paths are set
    /// 2. Spawns the PDP process
    /// 3. Creates the HTTP client
    /// 4. Waits until PDP is healthy
    /// 5. Returns a PDPPythonEngine
    pub async fn start(self) -> Result<crate::PDPPythonEngine, PDPError> {
        let builder = self.into_present()?;
        crate::PDPPythonEngine::new(builder).await
    }
}

impl PDPEngineBuilder<Present> {
    /// Starts the PDP engine:
    /// 1. Spawns the PDP process
    /// 2. Creates the HTTP client
    /// 3. Waits until PDP is healthy
    /// 4. Returns a PDPPythonEngine
    pub async fn start(self) -> Result<crate::PDPPythonEngine, PDPError> {
        crate::PDPPythonEngine::new(self).await
    }
}
