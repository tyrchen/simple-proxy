VAN: please initialize memory bank based on the @_code.md


Enter PLAN mode: the next biggest thing for this project is to use extism to support a plugin based system to make it pretty flexible to extend the tool. The core system should allow plugin to do the following things:
- modify request header
- modify request header and body
- modify response header
- modify response header and body
- based on the request info, directly generated response header and body for the core to response

plugin flow:

```mermaid
graph TD
    A[Client Request] --> B[Request Headers]
    B --> C{Plugin: Modify Headers?}
    C -->|Yes| D[Apply Header Modifications]
    C -->|No| E[Original Headers]
    D --> F[Request Body]
    E --> F
    F --> G{Plugin: Modify Body?}
    G -->|Yes| H[Apply Body Modifications]
    G -->|No| I[Original Body]
    H --> J[Forward to Upstream]
    I --> J
    J --> K[Upstream Response]
    K --> L[Response Headers]
    L --> M{Plugin: Modify Response Headers?}
    M -->|Yes| N[Apply Header Modifications]
    M -->|No| O[Original Headers]
    N --> P[Response Body]
    O --> P
    P --> Q{Plugin: Modify Response Body?}
    Q -->|Yes| R[Apply Body Modifications]
    Q -->|No| S[Original Body]
    R --> T[Return to Client]
    S --> T

    B -.-> U{Plugin: Generate Response?}
    U -->|Yes| V[Custom Response]
    V --> T
```

plugin architecture:

```mermaid
graph TD
    A[Simple Proxy] --> B[Plugin Manager]
    B --> C[Plugin Registry]
    B --> D[Plugin Loader]
    D --> E[Extism Runtime]

    C --> F[Plugin Configuration]
    F --> G[Execution Points]
    F --> H[Resource Limits]
    F --> I[Timeout Settings]

    J[Plugin WASM Module] --> D

    K[Hook Points] --> L[Request Headers]
    K --> M[Request Body]
    K --> N[Response Headers]
    K --> O[Response Body]
    K --> P[Response Generation]
```


Enter IMPLEMENT mode, please first define proper data structure to integrate extism sdk


Based on @_code.md please help me update README.md. Make sure you have a section on how to develop / build / config a plugin. Then have a demo section to tell user how to run the whole setup by:

```
RUST_LOG=info cargo run --example server -- -p 3001 # run first  server
RUST_LOG=info cargo run --example server -- -p 3002 # run second server
RUST_LOG=info cargo run -- -c fixtures/app.yml # run proxy
```
