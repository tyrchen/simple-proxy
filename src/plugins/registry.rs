use crate::plugins::{Plugin, PluginConfig, PluginError, PluginResult};
use dashmap::DashMap;
use std::{ops::Deref, sync::Arc};

/// Registry that stores and provides access to loaded plugins
#[derive(Debug, Clone, Default)]
pub struct PluginRegistry {
    /// Thread-safe storage of plugins by name
    plugins: Arc<DashMap<String, Plugin>>,
}

impl Deref for PluginRegistry {
    type Target = DashMap<String, Plugin>;

    fn deref(&self) -> &Self::Target {
        &self.plugins
    }
}

impl PluginRegistry {
    /// Create a new empty plugin registry
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a plugin to the registry
    pub fn add(&self, plugin: Plugin) {
        let name = plugin.name.clone();

        self.plugins.insert(name, plugin);
    }

    /// Remove a plugin from the registry
    pub fn remove(&self, name: &str) -> bool {
        self.plugins.remove(name).is_some()
    }

    /// Update a plugin configuration
    pub fn update_config(&self, name: &str, config: PluginConfig) -> PluginResult<()> {
        if let Some(mut p) = self.plugins.get_mut(name) {
            // If path changed, we need to reinitialize the plugin
            if p.path != config.path.to_string_lossy() {
                return Err(PluginError::Config(
                    "Cannot change plugin path after initialization".to_string(),
                ));
            }
            p.config = config;

            Ok(())
        } else {
            Err(PluginError::NotFound(name.to_string()))
        }
    }
}
