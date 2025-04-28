# Simple Proxy Project Brief

## Project Overview
Simple Proxy is a Rust-based proxy server built on top of the Pingora library. It provides HTTP/HTTPS proxying capabilities with features like TLS termination, load balancing, and health checking.

## Key Components
- **Configuration Management**: YAML-based configuration for proxy settings
- **Route Table**: Maps host names to upstream server configurations
- **Load Balancing**: Round-robin load balancing of upstream servers
- **Health Checking**: Regular health checks of upstream servers
- **TLS Support**: Support for TLS termination and HTTP/2

## Project Structure
- `src/conf/`: Configuration handling (raw and resolved configs)
- `src/proxy/`: Core proxy implementation
- `src/utils/`: Utility functions

## Dependencies
- **pingora**: Core proxy functionality
- **clap**: Command-line argument parsing
- **serde/serde_yaml**: Configuration parsing
- **tokio**: Async runtime
- **arc-swap**: Thread-safe configuration updates

## Project Goals
Provide a simple, efficient, and configurable HTTP proxy server with production-ready features like health checking and load balancing.
