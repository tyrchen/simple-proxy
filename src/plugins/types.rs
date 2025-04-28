use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Context information passed to plugins
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginContext {
    /// Original host requested
    pub host: String,
    /// Original path requested
    pub path: String,
    /// HTTP method used
    pub method: String,
    /// Client IP address
    pub client_ip: String,
    /// Request scheme (http/https)
    pub scheme: String,
    /// Plugin-specific configuration passed from the main config
    pub config: HashMap<String, serde_json::Value>,
}

/// Representation of a request to be processed by a plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginRequest {
    /// HTTP headers as a map
    pub headers: HashMap<String, String>,
    /// Request body (may be empty)
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    /// Additional context information
    pub context: PluginContext,
}

impl PluginRequest {
    /// Create a new PluginRequest from HTTP headers and body
    pub fn new(headers: &HeaderMap, body: Option<&Bytes>, context: PluginContext) -> Self {
        let headers_map = headers
            .iter()
            .filter_map(|(k, v)| {
                let key = k.as_str().to_string();
                let value = v.to_str().ok()?.to_string();
                Some((key, value))
            })
            .collect();

        let body_vec = match body {
            Some(b) => b.to_vec(),
            None => Vec::new(),
        };

        Self {
            headers: headers_map,
            body: body_vec,
            context,
        }
    }
}

/// Response from a plugin
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginResponse {
    /// HTTP headers as a map
    pub headers: HashMap<String, String>,
    /// Response body
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    /// HTTP status code (only used for direct responses)
    pub status: Option<u16>,
}

impl PluginResponse {
    /// Create a new empty response
    pub fn new() -> Self {
        Self::default()
    }

    /// Convert the response to HTTP HeaderMap
    pub fn to_header_map(&self) -> HeaderMap {
        let mut header_map = HeaderMap::new();
        for (key, value) in &self.headers {
            if let Ok(header_name) = key.parse::<HeaderName>() {
                if let Ok(header_value) = value.parse::<HeaderValue>() {
                    header_map.insert(header_name, header_value);
                }
            }
        }
        header_map
    }

    /// Convert the response to HTTP status code
    pub fn to_status_code(&self) -> StatusCode {
        match self.status {
            Some(code) => StatusCode::from_u16(code).unwrap_or(StatusCode::OK),
            None => StatusCode::OK,
        }
    }

    /// Convert response body to Bytes
    pub fn to_bytes(&self) -> Bytes {
        Bytes::from(self.body.clone())
    }
}
