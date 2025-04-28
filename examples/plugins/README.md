# Simple Proxy Plugin System (Extism)

This directory contains examples of how to create plugins for the Simple Proxy using the Extism SDK.

## Overview

Plugins are WebAssembly (Wasm) modules compiled to the `wasm32-wasip1` target. They allow you to hook into the proxy's request/response lifecycle to inspect or modify traffic.

## Plugin Interface

Plugins communicate with the proxy host using JSON-serialized data structures passed as strings.

### Host -> Plugin Data Structures

*   **`PluginRequestData`**: Sent to the `on_request` function.
    ```json
    {
      "method": "GET",
      "uri": "/path?query=value",
      "version": "HTTP/1.1",
      "headers": {
        "host": ["example.com"],
        "user-agent": ["curl/7.88.1"],
        ...
      },
      "body": <Optional<Base64-encoded bytes>> // Currently None
    }
    ```
*   **`PluginResponseData`**: Sent to the `on_response` function.
    ```json
    {
      "status": 200,
      "version": "HTTP/1.1",
      "headers": {
        "content-type": ["application/json"],
        "content-length": ["123"],
        ...
      },
      "body": <Optional<Base64-encoded bytes>> // Currently None
    }
    ```

### Plugin -> Host Data Structures (for modifications)

*   **`PluginModifiedRequest`**: Returned (as JSON string) from `on_request`.
    *   Fields are `Option`al. `None` means no change.
    *   `method`: `Option<String>`
    *   `uri`: `Option<String>` (Currently ignored by host)
    *   `headers_to_add`: `Option<JsonHeaderMap>`
    *   `headers_to_remove`: `Option<Vec<String>>` (List of header names)
    *   `body`: `Option<Vec<u8>>` (Currently ignored by host)
*   **`PluginModifiedResponse`**: Returned (as JSON string) from `on_response`.
    *   Fields are `Option`al. `None` means no change.
    *   `status`: `Option<u16>`
    *   `headers_to_add`: `Option<JsonHeaderMap>`
    *   `headers_to_remove`: `Option<Vec<String>>`
    *   `body`: `Option<Vec<u8>>` (Currently ignored by host)

### Plugin Exported Functions

Plugins *must* export functions matching the names defined in the host (`src/plugins/interface.rs`):

*   `on_request(input: String) -> String`: Receives JSON `PluginRequestData`, returns JSON `PluginModifiedRequest`.
*   `on_response(input: String) -> String`: Receives JSON `PluginResponseData`, returns JSON `PluginModifiedResponse`.

Use the `extism_pdk::plugin_fn` macro for exporting.

## Creating a Plugin

1.  **Create a new Rust library project:**
    ```sh
    # In examples/plugins/
    mkdir my-plugin
    cd my-plugin
    cargo init --lib
    ```
2.  **Update `Cargo.toml`:**
    *   Add `[lib]` section with `crate-type = ["cdylib"]`.
    *   Add dependencies: `extism-pdk`, `serde`, `serde_json`, `serde_bytes`, `http` (optional, for types).
    *   Add release profile optimizations (see `example-request-modifier/Cargo.toml`).
3.  **Install Wasm target:**
    ```sh
    rustup target add wasm32-wasip1
    ```
4.  **Write plugin code (`src/lib.rs`):**
    *   Define (or duplicate) the interface structs.
    *   Implement `#[plugin_fn]` functions (`on_request`, `on_response`).
    *   Use `extism_pdk::{info, error, ...}` for logging (output goes to host stderr).
    *   Deserialize input JSON, perform logic, serialize output modification JSON.
5.  **Build the plugin:**
    ```sh
    cargo build --target wasm32-wasip1 --release
    ```
    The output will be in `target/wasm32-wasip1/release/your_plugin_name.wasm`.

## Configuring Plugins

Add a `plugins` section to your main proxy configuration YAML file (`sample.yml`):

```yaml
plugins:
  - name: "My Plugin Name"
    path: "path/to/your_plugin_name.wasm" # Relative to proxy execution dir or absolute
    enabled: true # Optional, defaults to true
    execution_points: ["request_headers", "response_headers"] # List of points to run
    # timeout_ms: 1000 # Optional, Extism default
    # memory_limit_mb: 10 # Optional, Extism default
    config: # Optional, plugin-specific config passed via Extism manifest
      api_key: "your-secret-key"
      threshold: 50
```

See `example-request-modifier/` for a concrete example.
