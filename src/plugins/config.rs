use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Execution points in the request/response lifecycle where plugins can run
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginExecutionPoint {
    /// Execute before processing request headers
    RequestHeaders,
    /// Execute before processing request body
    RequestBody,
    /// Execute before processing response headers
    ResponseHeaders,
    /// Execute before processing response body
    ResponseBody,
    /// Execute to potentially generate a response without forwarding to upstream
    GenerateResponse,
}

impl PluginExecutionPoint {
    /// Convert the execution point to a function name that will be called in the plugin
    pub fn function_name(&self) -> &'static str {
        match self {
            PluginExecutionPoint::RequestHeaders => "process_request_headers",
            PluginExecutionPoint::RequestBody => "process_request_body",
            PluginExecutionPoint::ResponseHeaders => "process_response_headers",
            PluginExecutionPoint::ResponseBody => "process_response_body",
            PluginExecutionPoint::GenerateResponse => "generate_response",
        }
    }
}

/// Configuration for a single plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    /// Name of the plugin
    pub name: String,
    /// Path to the WASM module
    pub path: PathBuf,
    /// Whether the plugin is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Execution points where this plugin should run
    pub execution_points: Vec<PluginExecutionPoint>,
    /// Timeout in milliseconds
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    /// Memory limit in megabytes
    #[serde(default = "default_memory_limit")]
    pub memory_limit_mb: u64,
    /// Plugin-specific configuration
    #[serde(default)]
    pub config: HashMap<String, serde_json::Value>,
}

/// Plugin configuration list for the entire application
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PluginsConfig {
    /// List of configured plugins
    #[serde(default)]
    pub plugins: Vec<PluginConfig>,
}

fn default_enabled() -> bool {
    true
}

fn default_timeout() -> u64 {
    1000 // 1 second default timeout
}

fn default_memory_limit() -> u64 {
    10 // 10 MB default memory limit
}
