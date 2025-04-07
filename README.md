# Simple Proxy

A lightweight HTTP reverse proxy built with [Pingora](https://github.com/cloudflare/pingora), designed to proxy requests to an upstream service.

## Features

- HTTP reverse proxy running on port 8080
- Forwards requests to an upstream service
- Custom request/response header modifications

## Architecture

The project consists of two main components:

1. **Reverse Proxy** (port 8080)
   - Handles incoming HTTP requests
   - Modifies request/response headers
   - Forwards traffic to backend service
   - Adds custom headers:
     - `user-agent: SimpleProxy/0.1`
     - `x-simple-proxy: v0.1`
     - Custom `server` header management

2. **Backend Service** (port 3000)
   - User management REST API
   - Supports CRUD operations for users
   - Uses Argon2 for password hashing
   - In-memory storage using DashMap
   - Health check endpoint

## Getting Started

### Prerequisites

- Rust toolchain (latest stable version)
- Cargo package manager

### Running the Backend Service

```bash
RUST_LOG=info cargo run --example server
```

The backend service will start on `http://127.0.0.1:3000` with the following endpoints:

- `GET /users` - List all users
- `POST /users` - Create a new user
- `GET /users/{id}` - Get a specific user
- `PUT /users/{id}` - Update a user
- `DELETE /users/{id}` - Delete a user
- `GET /health` - Health check endpoint

### Running the Proxy

```bash
RUST_LOG=info cargo run
```

The proxy will start on `http://0.0.0.0:8080` and forward all requests to the backend service.

## API Examples

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

## Development

The project includes a comprehensive test suite for the backend service. Run the tests with:

```bash
make test
```

## Headers Modified by Proxy

The proxy modifies the following headers:

- Adds `user-agent: SimpleProxy/0.1` to all upstream requests
- Adds `x-simple-proxy: v0.1` to all responses
- Manages the `server` header in responses

## License

MIT License. See [LICENSE](./LICENSE.md) for details.
