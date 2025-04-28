# Product Context

## Product Purpose
Simple Proxy is designed to serve as a flexible, high-performance HTTP/HTTPS proxy for service routing, load balancing, and TLS termination. It's built on the Pingora library, which is also used by Cloudflare for their edge services.

## Target Use Cases
- **API Gateway**: Routing requests to different backend services based on hostname
- **Load Balancer**: Distributing traffic across multiple backend instances
- **TLS Termination**: Handling HTTPS connections and forwarding as HTTP to backends
- **Health Monitoring**: Continuously checking backend health and routing only to healthy instances

## Configuration Model
The proxy uses a YAML-based configuration model with three main sections:
1. **Global Settings**: Port and TLS configuration
2. **Server Definitions**: Hostname mappings to upstream groups
3. **Upstream Definitions**: Groups of backend servers

Example configuration:
```yaml
global:
  port: 8080
  tls:  # Optional
    cert: /path/to/cert.pem
    key: /path/to/key.pem
    ca: /path/to/ca.pem  # Optional

servers:
  - server_name: ["acme.com", "www.acme.com"]
    upstream: web_servers
    tls: false  # Optional, defaults to false

  - server_name: ["api.acme.com"]
    upstream: api_servers
    tls: true

upstreams:
  - name: web_servers
    servers: ["127.0.0.1:3001", "127.0.0.1:3002"]

  - name: api_servers
    servers: ["127.0.0.1:9090", "127.0.0.1:9091"]
```

## User Interface
- **Command Line**: The proxy is launched from the command line with a path to the configuration file
- **Health API**: A health check endpoint is provided for monitoring

## Operational Characteristics
- **High Performance**: Built on Rust and Pingora for efficient proxy operations
- **Dynamic Backend Selection**: Automatically routes around failed backends
- **HTTP/2 Support**: Modern protocol support with multiplexing
- **Logging**: Comprehensive logging for debugging and monitoring

## Ecosystem Integration
- **Containerization**: Can be deployed in containers
- **Load Balancers**: Can be placed behind infrastructure load balancers
- **Monitoring Systems**: Integrates with monitoring via health endpoint
