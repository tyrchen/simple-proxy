# Technical Context

## Programming Language
- **Rust 2024 Edition**: The project uses the 2024 edition of Rust.

## Core Libraries
- **Pingora**: The underlying proxy server library from Cloudflare that provides the core functionality.
- **Tokio**: Async runtime used for handling concurrent operations.
- **Arc-Swap**: Used for thread-safe atomic reference counting and swapping for configuration updates.
- **Serde/Serde_yaml**: Used for serializing and deserializing configuration data from YAML.
- **Clap**: Command-line argument parsing with derive features.
- **Tracing**: Logging infrastructure.

## Architecture
- **Proxy Pattern**: The application implements a reverse proxy pattern.
- **Load Balancing**: Uses round-robin load balancing algorithm.
- **Health Checking**: Periodic TCP health checks for upstream servers.

## Configuration
- **YAML-based**: Configuration is loaded from YAML files.
- **Two-stage Configuration**: Raw configuration is loaded and then resolved into a runtime configuration.
- **Dynamic Updates**: Configuration can be updated at runtime via `ArcSwap`.

## Transport
- **HTTP/1.1 and HTTP/2**: Supports both HTTP protocols.
- **TLS**: Optional TLS termination with certificate and key configuration.

## Testing
- **Unit Tests**: Comprehensive unit tests for configuration parsing and utilities.
- **Integration Tests**: Example server implementation for testing proxy functionality.

## Development Tools
- **Cargo**: Rust's package manager and build tool.
- **Makefile**: Additional build automation.
- **Fixtures**: Sample configuration and certificates for testing.
