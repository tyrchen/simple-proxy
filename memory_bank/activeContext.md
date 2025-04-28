# Active Context

## Project Status
Simple Proxy is a functional HTTP/HTTPS proxy server with core features implemented:
- Configuration loading and validation
- Route table management
- Load balancing between upstream servers
- Health checking
- TLS termination
- HTTP/2 support

## Current Focus
The project is now focusing on implementing an Extism-based plugin system to make the proxy extensible. The plugin system will allow:

1. **Request Modification**:
   - Modify request headers
   - Modify request body

2. **Response Modification**:
   - Modify response headers
   - Modify response body

3. **Custom Response Generation**:
   - Generate responses directly without forwarding to upstream
   - Implement custom handlers for specific requests

4. **Plugin Management**:
   - Configure plugins via YAML
   - Load WebAssembly modules
   - Set execution points in the request/response lifecycle

## Components Overview
- **SimpleProxy**: Main proxy implementation that implements the `ProxyHttp` trait
- **ProxyContext**: Context object passed through the proxy pipeline
- **RouteTable**: Maps hostnames to upstream configurations
- **HealthService**: Service for health checking upstream servers
- **Configuration**: Two-stage configuration parsing and resolution
- **Plugin System** (Planned): Extism-based plugin infrastructure

## Immediate Implementation Plan
1. **Extism Integration**: Add Extism SDK and create plugin management subsystem
2. **Plugin Interface Design**: Define standardized data structures and function signatures
3. **Proxy Pipeline Integration**: Add plugin execution points in request/response flow
4. **Configuration System**: Extend configuration to support plugin loading and settings
5. **Example Plugins**: Create reference implementations and documentation

## Known Challenges
- Balancing flexibility with performance in plugin execution
- Ensuring memory safety and stability with third-party plugins
- Designing an intuitive and consistent plugin API
- Managing plugin lifecycle and error handling
- Supporting different languages for plugin development

## Immediate Potential Improvements
1. **Configuration Hot Reloading**: Ability to reload configuration without restarting
2. **Metrics Collection**: More detailed metrics on proxy performance
3. **Advanced Load Balancing**: Additional load balancing algorithms
4. **Cache Implementation**: Content caching support
5. **Request Rate Limiting**: Protection against overloading
6. **Authentication Support**: Adding authentication mechanisms
7. **Request/Response Transformation**: More advanced content modification

## Known Limitations
- Basic round-robin load balancing only
- Limited header manipulation
- No built-in authentication
- No response caching capabilities
- Limited metrics and monitoring
- No dynamic configuration updating
