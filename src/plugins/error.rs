use extism::Error as ExtismError;
use std::fmt;

/// Plugin operation result type
pub type PluginResult<T> = Result<T, PluginError>;

/// Error types for plugin operations
#[derive(Debug)]
pub enum PluginError {
    /// Initialization error
    Init(String),
    /// Error during plugin execution
    Execution(String),
    /// Plugin not found
    NotFound(String),
    /// Configuration error
    Config(String),
    /// Serialization/deserialization error
    Serialization(String),
    /// Timeout during plugin execution
    Timeout(String),
    /// Exceeded memory limit
    MemoryLimit,
    /// Plugin returned invalid data
    InvalidData(String),
}

impl fmt::Display for PluginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PluginError::Init(msg) => write!(f, "Plugin initialization error: {}", msg),
            PluginError::Execution(msg) => write!(f, "Plugin execution error: {}", msg),
            PluginError::NotFound(name) => write!(f, "Plugin not found: {}", name),
            PluginError::Config(msg) => write!(f, "Plugin configuration error: {}", msg),
            PluginError::Serialization(msg) => write!(f, "Plugin serialization error: {}", msg),
            PluginError::Timeout(name) => write!(f, "Plugin timeout: {}", name),
            PluginError::MemoryLimit => write!(f, "Plugin exceeded memory limit"),
            PluginError::InvalidData(msg) => write!(f, "Plugin returned invalid data: {}", msg),
        }
    }
}

impl std::error::Error for PluginError {}

impl From<ExtismError> for PluginError {
    fn from(err: ExtismError) -> Self {
        // In newer Extism versions, the error structure is simpler
        // so we map all errors to their appropriate categories based on error message
        let err_str = err.to_string();

        if err_str.contains("manifest") || err_str.contains("config") {
            PluginError::Config(err_str)
        } else if err_str.contains("timeout") {
            PluginError::Timeout(err_str)
        } else if err_str.contains("memory") || err_str.contains("allocation") {
            PluginError::MemoryLimit
        } else if err_str.contains("path") || err_str.contains("file") {
            PluginError::Init(err_str)
        // } else if err_str.contains("function") || err_str.contains("call") {
        //     PluginError::Execution(err_str)
        } else {
            PluginError::Execution(err_str)
        }
    }
}

impl From<serde_json::Error> for PluginError {
    fn from(err: serde_json::Error) -> Self {
        PluginError::Serialization(err.to_string())
    }
}
