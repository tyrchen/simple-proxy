use crate::plugins::{
    Plugin,
    config::PluginConfig,
    error::{PluginError, PluginResult},
    interface::*,
    registry::PluginRegistry,
};
use extism::{Manifest, Plugin as ExtismPlugin, Wasm};
use pingora::http::{RequestHeader, ResponseHeader};
use tracing::{debug, error, info, warn};

/// Manager for plugin operations
#[derive(Debug, Clone, Default)]
pub struct PluginManager {
    /// Plugin registry
    registry: PluginRegistry,
}

impl PluginManager {
    /// Create a new plugin manager
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the plugin registry
    pub fn registry(&self) -> &PluginRegistry {
        &self.registry
    }

    /// Load a plugin from configuration
    pub fn load_plugin(&self, config: PluginConfig) -> PluginResult<()> {
        let path = config.path.clone();
        let name = config.name.clone();

        info!("Loading plugin: {} from {}", name, path.display());

        // Ensure the plugin file exists
        if !path.exists() {
            return Err(PluginError::Init(format!(
                "Plugin file not found: {}",
                path.display()
            )));
        }

        // Initialize plugin configuration
        let wasm_file = path.to_string_lossy().to_string();

        // Configure plugin options using Manifest
        let wasm = Wasm::file(&wasm_file);
        let mut manifest = Manifest::new([wasm]);

        // Configure plugin with memory limits and timeout
        // These are now handled by the Extism runtime internally

        // Add plugin configuration
        if !config.config.is_empty() {
            // Create configuration map outside the loop
            let mut config_map = std::collections::HashMap::new();
            for (key, value) in config.config.iter() {
                config_map.insert(key.clone(), value.to_string());
            }
            // Apply all configurations at once
            for (key, value) in config_map {
                manifest = manifest.with_config_key(&key, value);
            }
        }

        // Initialize plugin
        let instance =
            ExtismPlugin::new(&manifest, [], true).map_err(|e| PluginError::Init(e.to_string()))?;

        // Create our Plugin wrapper
        let plugin = Plugin {
            name: name.clone(),
            path: path.to_string_lossy().to_string(),
            instance,
            config: config.clone(),
        };

        // Add to registry
        self.registry.add(plugin);
        info!("Plugin loaded successfully: {}", name);
        Ok(())
    }

    /// Execute relevant plugins for the request phase.
    pub async fn execute_request_plugins(
        &self,
        request_header: &mut RequestHeader,
    ) -> PluginResult<()> {
        // TODO: Get configured plugins for the request phase from config
        let relevant_plugin_names: Vec<String> = vec![]; // Placeholder

        for plugin_name in relevant_plugin_names {
            if let Some(mut plugin_instance) = self.registry.get_mut(&plugin_name) {
                if plugin_instance
                    .instance
                    .function_exists(REQUEST_FUNCTION_NAME)
                {
                    debug!("Executing request plugin: {}", plugin_name);

                    // 1. Prepare input data
                    let input_data = PluginRequestData {
                        method: request_header.method.to_string(),
                        uri: request_header.uri.to_string(),
                        version: format!("{:?}", request_header.version),
                        headers: JsonHeaderMap::from(&request_header.headers),
                        body: None, // TODO: Handle request body
                    };
                    let input_json = match serde_json::to_string(&input_data) {
                        Ok(json) => json,
                        Err(e) => {
                            warn!(
                                "Failed to serialize request data for plugin {}: {}",
                                plugin_name, e
                            );
                            continue; // Skip this plugin
                        }
                    };

                    // 2. Call plugin (synchronous)
                    match plugin_instance
                        .instance
                        .call::<&str, String>(REQUEST_FUNCTION_NAME, &input_json)
                    {
                        Ok(output_json) => {
                            if output_json.is_empty() || output_json == "{}" {
                                debug!(
                                    "Plugin {} returned empty response, no changes.",
                                    plugin_name
                                );
                                continue;
                            }
                            // 3. Deserialize response
                            match serde_json::from_str::<PluginModifiedRequest>(&output_json) {
                                Ok(mods) => {
                                    // 4. Apply modifications
                                    if let Err(e) = self.apply_request_mods(request_header, mods) {
                                        warn!(
                                            "Failed to apply mods from plugin {}: {}",
                                            plugin_name, e
                                        );
                                    }
                                }
                                Err(e) => {
                                    warn!(
                                        "Failed to deserialize response from plugin {}: {}\nResponse: {}",
                                        plugin_name, e, output_json
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            error!("Error executing plugin {}: {}", plugin_name, e);
                            // Decide whether to continue or halt processing
                        }
                    }
                }
            }
        }
        Ok(())
    }

    // Helper to apply request modifications
    fn apply_request_mods(
        &self,
        req: &mut RequestHeader,
        mods: PluginModifiedRequest,
    ) -> Result<(), anyhow::Error> {
        if mods.method.is_some() {
            warn!(
                "Plugin requested method modification, but it's not supported directly on RequestHeader."
            );
        }
        if mods.uri.is_some() {
            warn!(
                "Plugin requested URI modification, but it's not supported directly on RequestHeader."
            );
        }
        if let Some(headers_to_remove) = mods.headers_to_remove {
            for name in headers_to_remove {
                let _ = req.remove_header(&name);
            }
        }
        if let Some(headers_to_add) = mods.headers_to_add {
            let new_headers: http::HeaderMap = headers_to_add.try_into()?;
            for (name, value) in new_headers.iter() {
                req.insert_header(name.clone(), value.clone())?;
            }
        }
        if mods.body.is_some() {
            warn!("Plugin requested body modification, but it's not implemented yet.");
        }
        Ok(())
    }

    /// Execute relevant plugins for the response phase.
    pub fn execute_response_plugins(
        &self,
        response_header: &mut ResponseHeader,
    ) -> PluginResult<()> {
        // TODO: Get configured plugins for the response phase from config
        let relevant_plugin_names: Vec<String> = vec![]; // Placeholder

        for plugin_name in relevant_plugin_names {
            if let Some(mut plugin_instance) = self.registry.get_mut(&plugin_name) {
                if plugin_instance
                    .instance
                    .function_exists(RESPONSE_FUNCTION_NAME)
                {
                    debug!("Executing response plugin: {}", plugin_name);

                    // 1. Prepare input data
                    let input_data = PluginResponseData {
                        status: response_header.status.as_u16(),
                        version: format!("{:?}", response_header.version),
                        headers: JsonHeaderMap::from(&response_header.headers),
                        body: None, // TODO: Handle response body
                    };
                    let input_json = match serde_json::to_string(&input_data) {
                        Ok(json) => json,
                        Err(e) => {
                            warn!(
                                "Failed to serialize response data for plugin {}: {}",
                                plugin_name, e
                            );
                            continue;
                        }
                    };

                    // 2. Call plugin (synchronous)
                    match plugin_instance
                        .instance
                        .call::<&str, String>(RESPONSE_FUNCTION_NAME, &input_json)
                    {
                        Ok(output_json) => {
                            if output_json.is_empty() || output_json == "{}" {
                                debug!(
                                    "Plugin {} returned empty response, no changes.",
                                    plugin_name
                                );
                                continue;
                            }
                            // 3. Deserialize response
                            match serde_json::from_str::<PluginModifiedResponse>(&output_json) {
                                Ok(mods) => {
                                    // 4. Apply modifications
                                    if let Err(e) = self.apply_response_mods(response_header, mods)
                                    {
                                        warn!(
                                            "Failed to apply mods from plugin {}: {}",
                                            plugin_name, e
                                        );
                                    }
                                }
                                Err(e) => {
                                    warn!(
                                        "Failed to deserialize response from plugin {}: {}\nResponse: {}",
                                        plugin_name, e, output_json
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            error!("Error executing plugin {}: {}", plugin_name, e);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    // Helper to apply response modifications
    fn apply_response_mods(
        &self,
        resp: &mut ResponseHeader,
        mods: PluginModifiedResponse,
    ) -> Result<(), anyhow::Error> {
        if let Some(new_status_code) = mods.status {
            let new_status =
                pingora::http::StatusCode::from_u16(new_status_code).map_err(|_| {
                    anyhow::anyhow!("Invalid status code {} from plugin", new_status_code)
                })?;
            resp.set_status(new_status)?;
        }
        if let Some(headers_to_remove) = mods.headers_to_remove {
            for name in headers_to_remove {
                let _ = resp.remove_header(&name);
            }
        }
        if let Some(headers_to_add) = mods.headers_to_add {
            let new_headers: http::HeaderMap = headers_to_add.try_into()?;
            for (name, value) in new_headers.iter() {
                resp.insert_header(name.clone(), value.clone())?;
            }
        }
        if mods.body.is_some() {
            warn!("Plugin requested body modification, but it's not implemented yet.");
        }
        Ok(())
    }

    /// Remove a plugin by name
    pub fn remove_plugin(&self, name: &str) -> bool {
        let result = self.registry.remove(name);
        if result {
            info!("Plugin removed: {}", name);
        }
        result
    }

    /// Check if a plugin exists
    pub fn has_plugin(&self, name: &str) -> bool {
        self.registry.get(name).is_some()
    }
}
