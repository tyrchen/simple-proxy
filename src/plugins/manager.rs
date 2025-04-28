use crate::plugins::{
    Plugin, PluginConfig, PluginError, PluginExecutionPoint, PluginInterface, PluginRegistry,
    PluginRequest, PluginResponse, PluginResult,
};
use extism::{Manifest, Plugin as ExtismPlugin, Wasm};
use serde_json::json;
use tracing::{debug, info};

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

    /// Execute a plugin at a specific execution point
    pub async fn execute_plugin(
        &self,
        plugin_name: &str,
        execution_point: PluginExecutionPoint,
        request: &PluginRequest,
        response: Option<&PluginResponse>,
    ) -> PluginResult<PluginResponse> {
        // Get the plugin from the registry
        let mut plugin = self
            .registry
            .get_mut(plugin_name)
            .ok_or_else(|| PluginError::NotFound(plugin_name.to_string()))?;

        // Check if the plugin should execute at this point
        if !plugin.config.execution_points.contains(&execution_point) {
            return Err(PluginError::Execution(format!(
                "Plugin {} does not execute at point {:?}",
                plugin_name, execution_point
            )));
        }

        // Execute the appropriate function based on the execution point
        match execution_point {
            PluginExecutionPoint::RequestHeaders => plugin.process_request_headers(request),
            PluginExecutionPoint::RequestBody => plugin.process_request_body(request),
            PluginExecutionPoint::ResponseHeaders => {
                let response = response.ok_or_else(|| {
                    PluginError::Execution("Response required for ResponseHeaders".to_string())
                })?;
                plugin.process_response_headers(request, response)
            }
            PluginExecutionPoint::ResponseBody => {
                let response = response.ok_or_else(|| {
                    PluginError::Execution("Response required for ResponseBody".to_string())
                })?;
                plugin.process_response_body(request, response)
            }
            PluginExecutionPoint::GenerateResponse => match plugin.generate_response(request)? {
                Some(resp) => Ok(resp),
                None => {
                    // Return empty response if plugin doesn't want to generate one
                    Ok(PluginResponse::new())
                }
            },
        }
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

// Implement PluginInterface for Plugin
impl PluginInterface for Plugin {
    fn process_request_headers(&mut self, request: &PluginRequest) -> PluginResult<PluginResponse> {
        let function_name = PluginExecutionPoint::RequestHeaders.function_name();

        // Skip if function doesn't exist in plugin
        let instance = &mut self.instance;
        if !instance.function_exists(function_name) {
            debug!("Plugin {} does not implement {}", self.name, function_name);
            return Ok(PluginResponse::new());
        }

        // Create a serialized input
        let input_json = serde_json::to_string(request)?;

        // Get bytes from the JSON string
        let input_bytes = input_json.as_bytes();

        // Call the plugin function with explicit type
        let result = instance.call::<&[u8], Vec<u8>>(function_name, input_bytes)?;

        // Parse the response
        let response: PluginResponse = if !result.is_empty() {
            serde_json::from_slice(&result)?
        } else {
            PluginResponse::new()
        };

        Ok(response)
    }

    fn process_request_body(&mut self, request: &PluginRequest) -> PluginResult<PluginResponse> {
        let function_name = PluginExecutionPoint::RequestBody.function_name();

        // Skip if function doesn't exist in plugin
        let instance = &mut self.instance;
        if !instance.function_exists(function_name) {
            debug!("Plugin {} does not implement {}", self.name, function_name);
            return Ok(PluginResponse::new());
        }

        // Create a serialized input
        let input_json = serde_json::to_string(request)?;

        // Get bytes from the JSON string
        let input_bytes = input_json.as_bytes();

        // Call the plugin function with explicit type
        let result = instance.call::<&[u8], Vec<u8>>(function_name, input_bytes)?;

        // Parse the response
        let response: PluginResponse = if !result.is_empty() {
            serde_json::from_slice(&result)?
        } else {
            PluginResponse::new()
        };

        Ok(response)
    }

    fn process_response_headers(
        &mut self,
        request: &PluginRequest,
        response: &PluginResponse,
    ) -> PluginResult<PluginResponse> {
        let function_name = PluginExecutionPoint::ResponseHeaders.function_name();

        // Skip if function doesn't exist in plugin
        let instance = &mut self.instance;
        if !instance.function_exists(function_name) {
            debug!("Plugin {} does not implement {}", self.name, function_name);
            return Ok(response.clone());
        }

        // Create a combined input with request and response
        let input = json!({
            "request": request,
            "response": response
        });

        // Serialize input
        let input_json = serde_json::to_string(&input)?;

        // Get bytes from the JSON string
        let input_bytes = input_json.as_bytes();

        // Call the plugin function with explicit type
        let result = instance.call::<&[u8], Vec<u8>>(function_name, input_bytes)?;

        // Parse the response
        let result_response: PluginResponse = if !result.is_empty() {
            serde_json::from_slice(&result)?
        } else {
            response.clone()
        };

        Ok(result_response)
    }

    fn process_response_body(
        &mut self,
        request: &PluginRequest,
        response: &PluginResponse,
    ) -> PluginResult<PluginResponse> {
        let function_name = PluginExecutionPoint::ResponseBody.function_name();

        // Skip if function doesn't exist in plugin
        let instance = &mut self.instance;
        if !instance.function_exists(function_name) {
            debug!("Plugin {} does not implement {}", self.name, function_name);
            return Ok(response.clone());
        }

        // Create a combined input with request and response
        let input = json!({
            "request": request,
            "response": response
        });

        // Serialize input
        let input_json = serde_json::to_string(&input)?;

        // Get bytes from the JSON string
        let input_bytes = input_json.as_bytes();

        // Call the plugin function with explicit type
        let result = instance.call::<&[u8], Vec<u8>>(function_name, input_bytes)?;

        // Parse the response
        let result_response: PluginResponse = if !result.is_empty() {
            serde_json::from_slice(&result)?
        } else {
            response.clone()
        };

        Ok(result_response)
    }

    fn generate_response(
        &mut self,
        request: &PluginRequest,
    ) -> PluginResult<Option<PluginResponse>> {
        let function_name = PluginExecutionPoint::GenerateResponse.function_name();

        // Skip if function doesn't exist in plugin
        let instance = &mut self.instance;
        if !instance.function_exists(function_name) {
            debug!("Plugin {} does not implement {}", self.name, function_name);
            return Ok(None);
        }

        // Serialize the request
        let input_json = serde_json::to_string(request)?;

        // Get bytes from the JSON string
        let input_bytes = input_json.as_bytes();

        // Call the plugin function with explicit type
        let result = instance.call::<&[u8], Vec<u8>>(function_name, input_bytes)?;

        // Empty response means no response generated
        if result.is_empty() {
            return Ok(None);
        }

        // Parse the response
        let response: PluginResponse = serde_json::from_slice(&result)?;
        Ok(Some(response))
    }
}
