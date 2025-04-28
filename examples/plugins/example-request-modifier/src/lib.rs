use extism_pdk::*; // Import PDK macros and functions
use serde::{Deserialize, Serialize};
use std::collections::HashMap; // Using std HashMap now

// --- Interface Structs (Duplicated from host for decoupling) ---

/// Represents HTTP headers, easily serializable to/from JSON.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct JsonHeaderMap {
    headers: HashMap<String, Vec<String>>,
}

/// Data passed to the plugin when processing a request.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PluginRequestData {
    pub method: String,
    pub uri: String,
    pub version: String,
    pub headers: JsonHeaderMap,
    #[serde(with = "serde_bytes")]
    pub body: Option<Vec<u8>>,
}

/// Data returned by the plugin after processing a request.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct PluginModifiedRequest {
    // Option fields mean "no change" if None
    pub method: Option<String>,
    pub uri: Option<String>,
    pub headers_to_add: Option<JsonHeaderMap>,
    pub headers_to_remove: Option<Vec<String>>, // List of header names to remove
    #[serde(with = "serde_bytes")]
    pub body: Option<Vec<u8>>, // None = no change, Some(vec) = set body
}

// --- Plugin Implementation ---

#[plugin_fn]
pub fn on_request(input: String) -> FnResult<String> {
    // 1. Deserialize input from host
    let request_data: PluginRequestData = match serde_json::from_str(&input) {
        Ok(data) => data,
        Err(e) => {
            // Log error (goes to host stderr)
            error!("Failed to deserialize input: {}. Input: {}", e, input);
            // Return empty JSON object indicating no changes/error during deserialization
            return Ok("{}".to_string());
        }
    };

    // 2. Log received data (optional)
    info!(
        "Plugin received request: Method={}, URI={}",
        request_data.method, request_data.uri
    );

    // 3. Define modifications
    let mut headers_to_add = HashMap::new();
    headers_to_add.insert(
        "x-plugin-request-processed".to_string(),
        vec!["true".to_string()],
    );

    let mods = PluginModifiedRequest {
        headers_to_add: Some(JsonHeaderMap {
            headers: headers_to_add,
        }),
        ..Default::default() // No other changes
    };

    // 4. Serialize modifications and return
    let output_json = serde_json::to_string(&mods)?;
    Ok(output_json)
}

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
