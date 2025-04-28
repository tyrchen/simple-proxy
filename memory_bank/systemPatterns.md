# System Patterns

## Configuration Management
- **Two-Phase Configuration**: Raw configuration is loaded from YAML and then resolved into a runtime configuration.
- **Immutable Configuration**: Configuration is treated as immutable after loading, with changes only through controlled mechanisms.
- **ArcSwap Pattern**: Thread-safe configuration updates using `ArcSwap`.

## Module Organization
- **Hierarchical Module Structure**: Clear separation of concerns with nested modules.
- **Public API Exports**: Selective exports to create a clean public interface.

## Error Handling
- **Result Types**: Extensive use of `Result<T, E>` for proper error propagation.
- **Anyhow Library**: Flexible error handling with context.
- **Error Type Taxonomy**: Categorized error types by source and type.

## Proxy Implementation Patterns
- **Trait-Based Design**: Implementation of the `ProxyHttp` trait for behavior definition.
- **Context Object**: `ProxyContext` for passing state through the proxy pipeline.
- **Pipeline Pattern**: Request and response filtering through sequential stages.
- **Service Pattern**: Implementation of Pingora's `Service` trait for service lifecycle management.

## Concurrency Patterns
- **Async/Await**: Modern asynchronous programming using Tokio.
- **Pin & Arc**: Thread-safe reference counting for shared data structures.
- **Atomic Operations**: For thread-safe counter increments.

## Testing Patterns
- **Modular Tests**: Small, focused unit tests.
- **Test-Specific Data Structures**: Creating test environments with controlled inputs.
- **Temporary Files**: Use of `tempfile` crate for test file creation.
- **Mock Objects**: Creating test instances with controlled behavior.

## Load Balancing
- **Round-Robin Algorithm**: Simple load distribution across backends.
- **Health Checking**: Regular health checks to detect and exclude unhealthy backends.

## Route Management
- **Hash Map-Based Routing**: Efficient host-to-backend mapping.
- **Lazy Initialization**: Components are initialized on demand.
