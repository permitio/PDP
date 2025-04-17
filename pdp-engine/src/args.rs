use std::fmt::Display;

/// `Arg` represents a typed CLI argument for the Python PDP process.
/// This enum ensures that valid CLI options are used.
#[derive(Debug, Clone)]
pub enum Arg {
    /// Specifies the Python module to run (e.g., `uvicorn`).
    Module(String),
    /// Specifies the application to run (e.g., `horizon.main:app`).
    App(String),
    /// Enables reload mode (`--reload`).
    Reload,
    /// Sets the network port for the PDP server.
    Port(u16),
    /// Sets the network host for the PDP server.
    Host(String),
    /// Sets the logging level for the server.
    LogLevel(LogLevel),
    /// A custom argument for cases not covered by the other variants.
    Custom(String),
}

/// Represents valid log levels.
#[derive(Debug, Clone)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

impl Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Debug => write!(f, "debug"),
            LogLevel::Info => write!(f, "info"),
            LogLevel::Warning => write!(f, "warning"),
            LogLevel::Error => write!(f, "error"),
            LogLevel::Critical => write!(f, "critical"),
        }
    }
}

impl Arg {
    /// Converts a typed argument into one or more command-line arguments.
    pub fn to_args(&self) -> Vec<String> {
        match self {
            Arg::Module(module) => vec!["-m".into(), module.clone()],
            Arg::App(app) => vec![app.clone()],
            Arg::Reload => vec!["--reload".into()],
            Arg::Port(port) => vec!["--port".into(), port.to_string()],
            Arg::Host(host) => vec!["--host".into(), host.clone()],
            Arg::LogLevel(level) => vec!["--log-level".into(), level.to_string()],
            Arg::Custom(arg) => vec![arg.clone()],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arg_module() {
        let arg = Arg::Module("uvicorn".to_string());
        assert_eq!(arg.to_args(), vec!["-m".to_string(), "uvicorn".to_string()]);
    }

    #[test]
    fn test_arg_app() {
        let app = "horizon.main:app".to_string();
        let arg = Arg::App(app.clone());
        assert_eq!(arg.to_args(), vec![app]);
    }

    #[test]
    fn test_arg_reload() {
        let arg = Arg::Reload;
        assert_eq!(arg.to_args(), vec!["--reload".to_string()]);
    }

    #[test]
    fn test_arg_port() {
        let port = 7001;
        let arg = Arg::Port(port);
        assert_eq!(arg.to_args(), vec!["--port".to_string(), port.to_string()]);
    }

    #[test]
    fn test_arg_host() {
        let host = "0.0.0.0".to_string();
        let arg = Arg::Host(host.clone());
        assert_eq!(arg.to_args(), vec!["--host".to_string(), host]);
    }

    #[test]
    fn test_arg_log_level() {
        let arg = Arg::LogLevel(LogLevel::Info);
        assert_eq!(
            arg.to_args(),
            vec!["--log-level".to_string(), "info".to_string()]
        );
    }

    #[test]
    fn test_arg_custom() {
        let custom = "--workers=4".to_string();
        let arg = Arg::Custom(custom.clone());
        assert_eq!(arg.to_args(), vec![custom]);
    }
}
