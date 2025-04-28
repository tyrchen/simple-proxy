use crate::plugins::{PluginRequest, PluginResponse, PluginResult};
use http::HeaderMap as HttpHeaderMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Interface for plugins with different execution points
#[allow(unused)]
pub trait PluginInterface {
    /// Process request headers
    ///
    /// This function allows plugins to modify request headers before they are sent to the upstream.
    ///
    /// # Arguments
    /// * `request` - The plugin request containing headers and context
    ///
    /// # Returns
    /// * `PluginResult<PluginResponse>` - The response with modified headers
    fn process_request_headers(&mut self, request: &PluginRequest) -> PluginResult<PluginResponse>;

    /// Process request body
    ///
    /// This function allows plugins to modify the request body before it is sent to the upstream.
    ///
    /// # Arguments
    /// * `request` - The plugin request containing headers, body, and context
    ///
    /// # Returns
    /// * `PluginResult<PluginResponse>` - The response with modified body
    fn process_request_body(&mut self, request: &PluginRequest) -> PluginResult<PluginResponse>;

    /// Process response headers
    ///
    /// This function allows plugins to modify response headers before they are sent to the client.
    ///
    /// # Arguments
    /// * `request` - The original plugin request
    /// * `response` - The response from the upstream with headers
    ///
    /// # Returns
    /// * `PluginResult<PluginResponse>` - The response with modified headers
    fn process_response_headers(
        &mut self,
        request: &PluginRequest,
        response: &PluginResponse,
    ) -> PluginResult<PluginResponse>;

    /// Process response body
    ///
    /// This function allows plugins to modify the response body before it is sent to the client.
    ///
    /// # Arguments
    /// * `request` - The original plugin request
    /// * `response` - The response from the upstream with body
    ///
    /// # Returns
    /// * `PluginResult<PluginResponse>` - The response with modified body
    fn process_response_body(
        &mut self,
        request: &PluginRequest,
        response: &PluginResponse,
    ) -> PluginResult<PluginResponse>;

    /// Generate response
    ///
    /// This function allows plugins to generate a complete response without forwarding to upstream.
    /// If None is returned, the request continues normally to the upstream.
    ///
    /// # Arguments
    /// * `request` - The plugin request containing headers, body, and context
    ///
    /// # Returns
    /// * `PluginResult<Option<PluginResponse>>` - Optionally, a complete response to return to the client
    fn generate_response(
        &mut self,
        request: &PluginRequest,
    ) -> PluginResult<Option<PluginResponse>>;
}

/// Represents HTTP headers, easily serializable to/from JSON.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct JsonHeaderMap {
    headers: HashMap<String, Vec<String>>,
}

impl From<&HttpHeaderMap> for JsonHeaderMap {
    fn from(header_map: &HttpHeaderMap) -> Self {
        let mut headers = HashMap::new();
        for (name, value) in header_map.iter() {
            let name_str = name.as_str().to_string();
            let value_str = String::from_utf8_lossy(value.as_bytes()).to_string();
            headers
                .entry(name_str)
                .or_insert_with(Vec::new)
                .push(value_str);
        }
        JsonHeaderMap { headers }
    }
}

impl TryInto<HttpHeaderMap> for JsonHeaderMap {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<HttpHeaderMap, Self::Error> {
        let mut header_map = HttpHeaderMap::new();
        for (name, values) in self.headers {
            let header_name = http::HeaderName::from_bytes(name.as_bytes())?;
            for value in values {
                let header_value = http::HeaderValue::from_str(&value)?;
                header_map.append(header_name.clone(), header_value);
            }
        }
        Ok(header_map)
    }
}

/// Data passed to the plugin when processing a request.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PluginRequestData {
    pub method: String,
    pub uri: String,
    pub version: String, // e.g., "HTTP/1.1"
    pub headers: JsonHeaderMap,
    #[serde(with = "serde_bytes")]
    pub body: Option<Vec<u8>>,
}

/// Data returned by the plugin after processing a request.
/// Allows modification of the request before it's sent upstream.
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

/// Data passed to the plugin when processing a response.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PluginResponseData {
    pub status: u16,
    pub version: String,
    pub headers: JsonHeaderMap,
    #[serde(with = "serde_bytes")]
    pub body: Option<Vec<u8>>,
}

/// Data returned by the plugin after processing a response.
/// Allows modification of the response before it's sent to the client.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct PluginModifiedResponse {
    // Option fields mean "no change" if None
    pub status: Option<u16>,
    pub headers_to_add: Option<JsonHeaderMap>,
    pub headers_to_remove: Option<Vec<String>>,
    #[serde(with = "serde_bytes")]
    pub body: Option<Vec<u8>>, // None = no change, Some(vec) = set body
}

// Define the expected function names within the Wasm plugin
pub const REQUEST_FUNCTION_NAME: &str = "on_request";
pub const RESPONSE_FUNCTION_NAME: &str = "on_response";
