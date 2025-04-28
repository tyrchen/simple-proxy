use crate::plugins::{PluginRequest, PluginResponse, PluginResult};

/// Interface for plugins with different execution points
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
