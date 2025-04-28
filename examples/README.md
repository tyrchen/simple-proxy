# Simple Proxy Examples

This directory contains examples for using and extending the simple-proxy.

## Example Proxy Server

Run the example server with:

```bash
cargo run --example server
```

## Example Plugins

### Header Addition Plugin

This plugin demonstrates how to create a simple Extism plugin that adds a custom header to HTTP responses.

To build the plugin:

```bash
cargo build --example add_header_plugin --release
```

The compiled WebAssembly module will be in `target/wasm32-wasi/release/examples/add_header_plugin.wasm`.

To use the plugin with simple-proxy, add this to your configuration:

```yaml
plugins:
  - name: header_adder
    path: ./target/wasm32-wasi/release/examples/add_header_plugin.wasm
    execution_points:
      - response_headers
    config:
      plugin_config: '{"header_name": "X-Custom-Header", "header_value": "Plugin is working!"}'
```

## Testing the API

The `test.rest` file contains example HTTP requests for testing the proxy server. Use a REST client like VS Code's REST Client extension to execute these requests.
