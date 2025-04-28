mod config;
mod error;
mod interface;
mod manager;
mod registry;
mod types;

pub use config::{PluginConfig, PluginExecutionPoint};
pub use error::{PluginError, PluginResult};
pub use interface::PluginInterface;
pub use manager::PluginManager;
pub use registry::PluginRegistry;
pub use types::{PluginRequest, PluginResponse};

/// Represents an individual plugin instance
#[derive(Debug)]
pub struct Plugin {
    /// Name of the plugin
    pub name: String,
    /// Path to the WASM module
    pub path: String,
    /// Extism plugin instance
    pub instance: extism::Plugin,
    /// Plugin configuration
    pub config: PluginConfig,
}
