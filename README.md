# Simple Proxy

A lightweight, configurable HTTP reverse proxy built with [Pingora](https://github.com/cloudflare/pingora), designed to proxy requests to upstream services with support for load balancing, health checks, and WASM plugins.

## Features

- Configurable HTTP reverse proxying
- Load balancing across multiple upstream servers (Round Robin)
- Health checks for upstream servers
- TLS termination support (via configuration)
- Extensible via WebAssembly (WASM) plugins using [Extism](https://extism.org/)
- Customizable request/response header modifications (via proxy logic and plugins)
- Caching support (configurable via Pingora features)
- Dynamic configuration updates (planned, infrastructure in place with `ArcSwap`)

## Architecture

The project consists of several key components:

1.  **Reverse Proxy Engine (Pingora)**
    - Handles incoming HTTP/HTTPS requests based on configuration.
    - Manages TLS termination if configured.
    - Implements load balancing and health checks for upstream targets.
    - Provides hooks for request/response filtering and modification.
    - Includes caching capabilities.

2.  **Simple Proxy Logic (`src/proxy`)**
    - Implements the `ProxyHttp` trait from Pingora.
    - Parses configuration (`src/conf`).
    - Selects upstream peers based on hostname and routing table (`RouteTable`).
    - Integrates with the Plugin Manager to execute WASM plugins at various stages.
    - Performs basic header modifications (e.g., `user-agent`, `x-simple-proxy`).

3.  **Plugin System (`src/plugins`)**
    - Manages the lifecycle of WASM plugins (loading, execution, removal).
    - Uses `PluginManager` and `PluginRegistry`.
    - Defines interfaces (`PluginRequestData`, `PluginModifiedRequest`, etc.) for plugins to interact with request/response data.
    - Allows plugins to run at defined `PluginExecutionPoint`s (request headers/body, response headers/body, generate response).

4.  **Configuration (`src/conf`)**
    - Defines configuration structure using YAML (`raw.rs`) and a resolved, validated version (`resolved.rs`).
    - Supports global settings, TLS certificates, server definitions (listeners), and upstream backends.
    - Manages configuration updates using `ProxyConfig` wrapper around `ArcSwap`.

5.  **Example Backend Service (`examples/server.rs`)**
    - A simple Axum-based REST API for testing the proxy.
    - Supports basic user CRUD operations.
    - Can be run on multiple ports to test load balancing.

## Getting Started

### Prerequisites

- Rust toolchain (latest stable version)
- Cargo package manager
- `wasm32-unknown-unknown` target for building plugins (`rustup target add wasm32-unknown-unknown`)

### Running the Demo (Proxy + 2 Backend Servers)

The easiest way to see the proxy in action is to run the demo setup which includes two backend instances and the proxy configured via `fixtures/app.yml`.

1.  **Start the first backend server:**

    ```bash
    RUST_LOG=info cargo run --example server -- -p 3001
    ```

2.  **Start the second backend server (in a separate terminal):**

    ```bash
    RUST_LOG=info cargo run --example server -- -p 3002
    ```

3.  **Start the proxy (in a separate terminal):**
    This command uses the configuration file `fixtures/app.yml`, which is set up to listen on port 8080 and load balance between `localhost:3001` and `localhost:3002`.

    ```bash
    RUST_LOG=info cargo run -- -c fixtures/app.yml
    ```

Now, requests to `http://localhost:8080` will be proxied to either backend server instance on port 3001 or 3002.

### Running Only the Proxy with Custom Configuration

To run the proxy with your own configuration:

```bash
RUST_LOG=info cargo run -- -c /path/to/your/config.yml
```

## Configuration

Simple Proxy is configured using a YAML file. The main components are:

-   **`global`**: Global settings like worker threads.
-   **`tls`**: Optional TLS certificate and key paths for HTTPS listeners.
-   **`servers`**: A list of proxy server definitions. Each server includes:
    -   `name`: A unique name for the server.
    -   `addr`: The address and port to listen on (e.g., `0.0.0.0:8080`).
    -   `tls`: Optional boolean to enable TLS for this server (requires global TLS config).
    -   `upstreams`: Configuration for backend servers.
        -   `backends`: A list of upstream addresses (e.g., `127.0.0.1:3001`).
        -   `health_check`: Optional TCP health check interval (e.g., `"5s"`).
    -   `plugins`: An optional list of WASM plugins to load for this server (see Plugin Development section).

Refer to `src/conf/raw.rs` for the exact structure (`SimpleProxyConfig`) and `fixtures/app.yml` for an example.

## API Examples (Using Demo Setup)

### Create a User

```bash
curl -X POST http://localhost:8080/users \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "secret",
    "name": "John Doe"
  }'
```

### List Users

```bash
curl http://localhost:8080/users
```

### Get a Specific User

```bash
curl http://localhost:8080/users/1
```

### Update a User

```bash
curl -X PUT http://localhost:8080/users/1 \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Jane Doe"
  }'
```

### Delete a User

```bash
curl -X DELETE http://localhost:8080/users/1
```

## Plugin Development

Simple Proxy supports extending its functionality through WebAssembly (WASM) plugins, leveraging the [Extism](https://extism.org/) runtime.

### Creating a Plugin

1.  **Create a new Rust library project**: This will contain your plugin logic.
2.  **Add dependencies**: Include `extism-pdk` and `serde` in your `Cargo.toml`.
3.  **Implement plugin functions**: Use the `#[plugin_fn]` macro to define functions that hook into specific execution points (e.g., `on_request_headers`, `on_response_body`). These functions receive serialized data (like `PluginRequestData`) as input and return serialized data (like `PluginModifiedRequest`) to modify the request/response flow. Refer to `src/plugins/interface.rs` for available data structures and `examples/plugins/example-request-modifier/src/lib.rs` for a concrete example.
4.  **Define Execution Points**: The functions you implement must correspond to names defined in `PluginExecutionPoint::function_name()`. Current points include:
    *   `request_headers`
    *   `request_body`
    *   `response_headers`
    *   `response_body`
    *   `generate_response`

### Building the Plugin

Compile your Rust library into a WASM module (under examples/plugins/example-request-modifier directory):

```bash
# Inside your plugin's directory
cargo build --target wasm32-unknown-unknown --release
```

This will produce a `.wasm` file in the `target/wasm32-unknown-unknown/release/` directory. Copy it to the directory that is easier to use in config (e.g. `fixtures/example_request_modifier.wasm`).

### Configuring the Plugin

To use your plugin, you need to configure it in the main proxy configuration file (e.g., `fixtures/app.yml`). Add a `plugins` section under the relevant server configuration:

```yaml
servers:
  - name: my_server
    # ... other server config ...
    plugins:
      - name: my_request_modifier # Unique name for this plugin instance
        path: /path/to/your/plugin.wasm # Path to the compiled WASM file
        # Optional: Configuration specific to your plugin, passed as JSON string
        config: '{"allowed_headers": ["x-custom-id"]}'
        # Optional: Specify execution points if not all are implemented or needed
        # execution_points:
        #  - request_headers
        #  - response_headers
```

Refer to `src/plugins/config.rs` for the `PluginConfig` structure details. The proxy will load the WASM file, instantiate the plugin, and call its exported functions at the appropriate execution points.

## Demo: Running with Multiple Upstreams

This demo shows how to run the proxy with two backend server instances load-balanced.

1.  **Start the first backend server:**

    ```bash
    RUST_LOG=info cargo run --example server -- -p 3001
    ```

2.  **Start the second backend server:**

    ```bash
    RUST_LOG=info cargo run --example server -- -p 3002
    ```

3.  **Start the proxy:**
    The `fixtures/app.yml` configuration file is set up to load balance between `localhost:3001` and `localhost:3002`.

    ```bash
    RUST_LOG=info cargo run -- -c fixtures/app.yml
    ```

Now, requests to `http://localhost:8080` will be proxied to either backend server instance 3001 or 3002.

## Headers Modified by Proxy

By default, the proxy modifies the following headers:

- Adds `user-agent: SimpleProxy/0.1` (or similar, based on version) to requests sent to the upstream.
- Adds `x-simple-proxy: v0.1` (or similar) to responses sent back to the client.
- Manages the `server` header in responses (can be influenced by Pingora settings).

Additional header modifications can be implemented via WASM plugins.

## License

MIT License. See [LICENSE](./LICENSE.md) for details.
