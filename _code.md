# Code Bank
## Package File
```toml
[package]
name = "simple-proxy"
version = "0.1.0"
authors = ["Tyr Chen <tyr.chen@gmail.com>"]
edition = "2024"
license = "MIT"
documentation = "https://docs.rs/"
repository = "https://github.com/tyrchen/simple-proxy"
homepage = "https://github.com/tyrchen/simple-proxy"
description = """
A simple proxy server in Rust.
"""
readme = "README.md"
categories = ["development-tools"]
keywords = []
[dependencies]
anyhow = "1.0.97"
arc-swap = "1.7.1"
async-trait = "0.1.88"
bytes = "1.10.1"
clap = { version = "4.5.36", features = ["derive"] }
http = "1.3.1"
papaya = { version = "0.2.1", features = ["serde"] }
pingora = { version = "0.4.0", features = ["lb", "rustls", "cache"] }
rand = "0.8"
serde = { version = "1.0", features = ["derive"] }
serde_yaml = "0.9.34"
tokio = { version = "1.44", features = ["macros", "rt-multi-thread"] }
tracing = "0.1.41"
tracing-subscriber = "0.3.19"
[dev-dependencies]
argon2 = "0.5.3"
axum = { version = "0.8", features = ["http2"] }
axum-server = { version = "0.7.2", features = ["tls-rustls"] }
chrono = { version = "0.4", features = ["serde"] }
dashmap = "6.1"
serde_json = "1.0"
tempfile = "3"
tower-http = { version = "0.6.2", features = ["trace"] }
[patch.crates-io]
sfv = { git = "https://github.com/undef1nd/sfv.git", tag = "v0.9.4" }
```
## examples/server.rs
```rust
use anyhow::Result;
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use axum::{
    Json, Router,
    extract::{Path, Request, State},
    http::StatusCode,
    middleware::{Next, from_fn_with_state},
    response::Response,
    routing::{delete, get, post, put},
};
use axum_server::tls_rustls::RustlsConfig;
use chrono::{DateTime, Utc};
use clap::Parser;
use dashmap::DashMap;
use http::HeaderValue;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tower_http::trace::TraceLayer;
use tracing::{Span, info};
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Port to run the server on
    #[arg(short, long, default_value_t = 3001)]
    port: u16,
}
// User model
#[derive(Debug, Clone, Serialize, Deserialize)]
struct User {
    id: u64,
    email: String,
    #[serde(skip_serializing)]
    password: String,
    name: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}
// Request models
#[derive(Debug, Deserialize)]
struct CreateUser {
    email: String,
    password: String,
    name: String,
}
#[derive(Debug, Deserialize)]
struct UpdateUser {
    email: Option<String>,
    password: Option<String>,
    name: Option<String>,
}
// App state
#[derive(Clone)]
struct AppState {
    inner: Arc<AppStateInner>,
}
struct AppStateInner {
    next_id: AtomicU64,
    users: DashMap<u64, User>,
    argon2: Argon2<'static>,
    addr: SocketAddr,
}
impl AppState {
    fn new(addr: impl Into<SocketAddr>) -> Self {
        Self {
            inner: Arc::new(AppStateInner {
                next_id: AtomicU64::new(1),
                users: DashMap::new(),
                argon2: Argon2::default(),
                addr: addr.into(),
            }),
        }
    }
    fn get_user(&self, id: u64) -> Option<User> {
        self.inner.users.get(&id).map(|user| user.clone())
    }
    fn create_user(&self, create_user: CreateUser) -> Result<User, anyhow::Error> {
        let password_hash = hash_password(&self.inner.argon2, &create_user.password)?;
        let id = self.inner.next_id.fetch_add(1, Ordering::SeqCst);
        let now = Utc::now();
        let user = User {
            id,
            email: create_user.email,
            password: password_hash,
            name: create_user.name,
            created_at: now,
            updated_at: now,
        };
        self.inner.users.insert(id, user.clone());
        Ok(user)
    }
    fn update_user(&self, id: u64, update: UpdateUser) -> Option<User> {
        let mut user = self.get_user(id)?;
        if let Some(email) = update.email {
            user.email = email;
        }
        if let Some(password) = update.password {
            let password_hash = hash_password(&self.inner.argon2, &password).ok()?;
            user.password = password_hash;
        }
        if let Some(name) = update.name {
            user.name = name;
        }
        user.updated_at = Utc::now();
        self.inner.users.insert(id, user.clone());
        Some(user)
    }
    fn delete_user(&self, id: u64) -> Option<User> {
        self.inner.users.remove(&id).map(|(_, user)| user)
    }
    fn list_users(&self) -> Vec<User> {
        self.inner
            .users
            .iter()
            .map(|ref_multi| ref_multi.value().clone())
            .collect()
    }
    fn health(&self) -> bool {
        true
    }
}
fn hash_password(argon2: &Argon2<'static>, password: &str) -> Result<String, anyhow::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| anyhow::anyhow!("Failed to hash password"))?
        .to_string();
    Ok(password_hash)
}
// Route handlers
async fn get_user(
    Path(id): Path<u64>,
    State(state): State<AppState>,
) -> Result<Json<User>, StatusCode> {
    state.get_user(id).map(Json).ok_or(StatusCode::NOT_FOUND)
}
async fn list_users(State(state): State<AppState>) -> Json<Vec<User>> {
    Json(state.list_users())
}
async fn create_user(
    State(state): State<AppState>,
    Json(create_user): Json<CreateUser>,
) -> Result<(StatusCode, Json<User>), (StatusCode, String)> {
    state
        .create_user(create_user)
        .map(|user| (StatusCode::CREATED, Json(user)))
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
}
async fn update_user(
    Path(id): Path<u64>,
    State(state): State<AppState>,
    Json(update_user): Json<UpdateUser>,
) -> Result<Json<User>, StatusCode> {
    state
        .update_user(id, update_user)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}
async fn delete_user(
    Path(id): Path<u64>,
    State(state): State<AppState>,
) -> Result<Json<User>, StatusCode> {
    state.delete_user(id).map(Json).ok_or(StatusCode::NOT_FOUND)
}
#[derive(Serialize)]
struct Health {
    status: &'static str,
}
async fn health_check(State(state): State<AppState>) -> Json<Health> {
    Json(Health {
        status: if state.health() {
            "healthy"
        } else {
            "unhealthy"
        },
    })
}
async fn server_info(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        "X-Server-Info",
        HeaderValue::from_str(&format!("{}", state.inner.addr)).unwrap(),
    );
    response
}
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let addr = SocketAddr::from(([127, 0, 0, 1], args.port));
    let app_state = AppState::new(addr);
    let app = Router::new()
        .route("/users/{id}", get(get_user))
        .route("/users", get(list_users))
        .route("/users", post(create_user))
        .route("/users/{id}", put(update_user))
        .route("/users/{id}", delete(delete_user))
        .route("/health", get(health_check))
        .route_layer(from_fn_with_state(app_state.clone(), server_info))
        .with_state(app_state)
        .layer(
            TraceLayer::new_for_http()
                .on_request(|request: &Request<_>, _span: &Span| {
                    info!("request: {:?}", request.headers());
                })
                .on_response(
                    |_response: &Response<_>, _latency: Duration, _span: &Span| {
                        info!("response: {:?}", _response.headers());
                    },
                ),
        );
    let cert = include_bytes!("../fixtures/certs/api.acme.com.crt");
    let key = include_bytes!("../fixtures/certs/api.acme.com.key");
    let config = RustlsConfig::from_pem(cert.to_vec(), key.to_vec()).await?;
    info!("Server running on https://{}", addr);
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn create_test_user(state: &AppState, email: &str) -> User {
        let create_user = CreateUser {
            email: email.to_string(),
            password: "test_password".to_string(),
            name: "Test User".to_string(),
        };
        state.create_user(create_user).unwrap()
    }
    #[test]
    fn test_create_user() {
        let state = AppState::new("127.0.0.1:3001");
        let user = create_test_user(&state, "test@example.com");
        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.name, "Test User");
        assert_eq!(user.id, 1);
        assert!(user.password.starts_with("$argon2"));
    }
    #[test]
    fn test_get_user() {
        let state = AppState::new("127.0.0.1:3001");
        let created_user = create_test_user(&state, "test@example.com");
        let retrieved_user = state.get_user(created_user.id).unwrap();
        assert_eq!(retrieved_user.email, created_user.email);
        assert_eq!(retrieved_user.name, created_user.name);
        assert_eq!(retrieved_user.id, created_user.id);
        assert!(state.get_user(999).is_none());
    }
    #[test]
    fn test_update_user() {
        let state = AppState::new("127.0.0.1:3001");
        let user = create_test_user(&state, "test@example.com");
        let update = UpdateUser {
            email: Some("updated@example.com".to_string()),
            password: Some("new_password".to_string()),
            name: Some("Updated Name".to_string()),
        };
        let updated_user = state.update_user(user.id, update).unwrap();
        assert_eq!(updated_user.email, "updated@example.com");
        assert_eq!(updated_user.name, "Updated Name");
        assert_ne!(updated_user.password, user.password);
        assert!(updated_user.updated_at > user.updated_at);
        // Test partial update
        let partial_update = UpdateUser {
            email: None,
            password: None,
            name: Some("Just Name Update".to_string()),
        };
        let partially_updated_user = state.update_user(user.id, partial_update).unwrap();
        assert_eq!(partially_updated_user.email, "updated@example.com"); // unchanged
        assert_eq!(partially_updated_user.name, "Just Name Update");
    }
    #[test]
    fn test_delete_user() {
        let state = AppState::new("127.0.0.1:3001");
        let user = create_test_user(&state, "test@example.com");
        let deleted_user = state.delete_user(user.id).unwrap();
        assert_eq!(deleted_user.id, user.id);
        assert!(state.get_user(user.id).is_none());
        assert!(state.delete_user(user.id).is_none());
    }
    #[test]
    fn test_list_users() {
        let state = AppState::new("127.0.0.1:3001");
        let user1 = create_test_user(&state, "test1@example.com");
        let user2 = create_test_user(&state, "test2@example.com");
        let users = state.list_users();
        assert_eq!(users.len(), 2);
        let emails: Vec<_> = users.iter().map(|u| &u.email).collect();
        assert!(emails.contains(&&user1.email));
        assert!(emails.contains(&&user2.email));
    }
    #[test]
    fn test_health() {
        let state = AppState::new("127.0.0.1:3001");
        assert!(state.health());
    }
    #[test]
    fn test_password_hashing() {
        let state = AppState::new("127.0.0.1:3001");
        let user1 = create_test_user(&state, "test1@example.com");
        let user2 = create_test_user(&state, "test2@example.com");
        // Even with same password, hashes should be different due to salt
        assert_ne!(user1.password, user2.password);
        assert!(user1.password.starts_with("$argon2"));
        assert!(user2.password.starts_with("$argon2"));
    }
}
```
## src/conf/mod.rs
```rust
mod raw;
mod resolved;
pub use resolved::*;
use arc_swap::ArcSwap;
use std::sync::Arc;
#[derive(Debug, Clone)]
pub struct ProxyConfig(Arc<ArcSwap<ProxyConfigResolved>>);
impl ProxyConfig {
    pub fn new(config: ProxyConfigResolved) -> Self {
        let config = Arc::new(ArcSwap::new(Arc::new(config)));
        Self(config)
    }
    pub fn update(&self, config: ProxyConfigResolved) {
        self.0.store(Arc::new(config));
    }
    pub fn get_full(&self) -> Arc<ProxyConfigResolved> {
        self.0.load_full()
    }
}
impl std::ops::Deref for ProxyConfig {
    type Target = ArcSwap<ProxyConfigResolved>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
```
## src/conf/raw.rs
```rust
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
/// The main configuration struct for Simple Proxy
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SimpleProxyConfig {
    /// Global configuration settings
    pub global: GlobalConfig,
    /// Server configurations
    pub servers: Vec<ServerConfig>,
    /// Upstream server configurations
    pub upstreams: Vec<UpstreamConfig>,
}
/// Global configuration settings
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GlobalConfig {
    /// Port on which the proxy listens
    pub port: u16,
    /// TLS configuration (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,
}
/// TLS configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsConfig {
    /// Path to CA certificate file (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca: Option<PathBuf>,
    /// Path to certificate file
    pub cert: PathBuf,
    /// Path to key file
    pub key: PathBuf,
}
/// Server configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    /// List of server names (domains) this server handles
    pub server_name: Vec<String>,
    /// Name of the upstream server group to forward requests to
    pub upstream: String,
    /// Whether TLS is enabled for this server
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<bool>,
}
/// Upstream server configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpstreamConfig {
    /// Name of the upstream server group
    pub name: String,
    /// List of server addresses in this group
    pub servers: Vec<String>,
}
impl SimpleProxyConfig {
    /// Load configuration from a YAML file
    pub fn from_yaml_file(path: impl AsRef<Path>) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        let config = serde_yaml::from_reader(file)?;
        Ok(config)
    }
    /// Load configuration from YAML string
    pub fn from_yaml_str(yaml: &str) -> Result<Self> {
        let config = serde_yaml::from_str(yaml)?;
        Ok(config)
    }
    /// Save configuration to a YAML file
    pub fn to_yaml_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let file = std::fs::File::create(path)?;
        serde_yaml::to_writer(file, self)?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_load_sample_config() {
        let yaml = include_str!("../../fixtures/sample.yml");
        let config = SimpleProxyConfig::from_yaml_str(yaml).unwrap();
        assert_eq!(config.global.port, 8080);
        assert!(config.global.tls.is_none());
        assert_eq!(config.servers.len(), 2);
        assert_eq!(
            config.servers[0].server_name,
            vec!["acme.com", "www.acme.com"]
        );
        assert_eq!(config.servers[0].upstream, "web_servers");
        assert_eq!(config.servers[0].tls, Some(false));
        assert_eq!(config.upstreams.len(), 2);
        assert_eq!(config.upstreams[0].name, "web_servers");
        assert_eq!(
            config.upstreams[0].servers,
            vec!["127.0.0.1:3001", "127.0.0.1:3002"]
        );
    }
}
```
## src/conf/resolved.rs
```rust
use crate::conf::raw::{GlobalConfig, ServerConfig, SimpleProxyConfig, TlsConfig, UpstreamConfig};
use anyhow::{Result, anyhow};
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::path::Path;
#[derive(Debug, Clone)]
pub struct ProxyConfigResolved {
    pub global: GlobalConfigResolved,
    pub servers: HashMap<String, ServerConfigResolved>,
}
#[derive(Debug, Clone)]
pub struct GlobalConfigResolved {
    pub port: u16,
    pub tls: Option<TlsConfigResolved>,
}
#[derive(Debug, Clone)]
pub struct TlsConfigResolved {
    pub cert: String,
    pub key: String,
    pub ca: Option<String>,
}
#[derive(Debug, Clone)]
pub struct ServerConfigResolved {
    pub tls: bool,
    pub upstream: UpstreamConfigResolved,
}
#[derive(Debug, Clone)]
pub struct UpstreamConfigResolved {
    pub servers: Vec<String>,
}
impl ProxyConfigResolved {
    pub fn load(file: impl AsRef<Path>) -> Result<Self> {
        let config = SimpleProxyConfig::from_yaml_file(file)?;
        Self::try_from(config)
    }
}
impl TryFrom<&TlsConfig> for TlsConfigResolved {
    type Error = anyhow::Error;
    fn try_from(tls: &TlsConfig) -> Result<Self, Self::Error> {
        let cert_path = tls.cert.as_path();
        let key_path = tls.key.as_path();
        // Check if files exist
        if !cert_path.exists() {
            return Err(anyhow!("Certificate file does not exist: {:?}", cert_path));
        }
        if !key_path.exists() {
            return Err(anyhow!("Key file does not exist: {:?}", key_path));
        }
        // Check if CA file exists if present
        let ca = if let Some(ca_path) = &tls.ca {
            if !ca_path.exists() {
                return Err(anyhow!("CA file does not exist: {:?}", ca_path));
            }
            Some(ca_path.to_string_lossy().to_string())
        } else {
            None
        };
        Ok(TlsConfigResolved {
            cert: cert_path.to_string_lossy().to_string(),
            key: key_path.to_string_lossy().to_string(),
            ca,
        })
    }
}
impl From<&UpstreamConfig> for UpstreamConfigResolved {
    fn from(upstream: &UpstreamConfig) -> Self {
        UpstreamConfigResolved {
            servers: upstream.servers.clone(),
        }
    }
}
impl TryFrom<SimpleProxyConfig> for ProxyConfigResolved {
    type Error = anyhow::Error;
    fn try_from(raw: SimpleProxyConfig) -> Result<Self, Self::Error> {
        // Build upstream map for lookups
        let mut upstream_map = HashMap::new();
        for upstream in &raw.upstreams {
            let resolved_upstream = UpstreamConfigResolved::from(upstream);
            upstream_map.insert(upstream.name.clone(), resolved_upstream);
        }
        // Resolve global config
        let global = GlobalConfigResolved::try_from(&raw.global)?;
        // Resolve server configs
        let mut servers = HashMap::new();
        for server in raw.servers {
            let resolved_server = ServerConfigResolved::try_from_with_maps(&server, &upstream_map)?;
            // Add server for each domain name
            for server_name in server.server_name {
                if servers.contains_key(&server_name) {
                    return Err(anyhow!("Duplicate server name: {}", server_name));
                }
                servers.insert(server_name, resolved_server.clone());
            }
        }
        Ok(ProxyConfigResolved { global, servers })
    }
}
impl TryFrom<&GlobalConfig> for GlobalConfigResolved {
    type Error = anyhow::Error;
    fn try_from(global: &GlobalConfig) -> Result<Self, Self::Error> {
        let tls = match &global.tls {
            Some(tls_config) => {
                let resolved_tls = TlsConfigResolved::try_from(tls_config)?;
                Some(resolved_tls)
            }
            None => None,
        };
        Ok(GlobalConfigResolved {
            port: global.port,
            tls,
        })
    }
}
// Helper for ServerConfigResolved that requires upstream maps for lookups
impl ServerConfigResolved {
    fn try_from_with_maps(
        server: &ServerConfig,
        upstream_map: &HashMap<String, UpstreamConfigResolved>,
    ) -> Result<Self> {
        // Get the tls setting, default to false if not specified
        let tls = server.tls.unwrap_or(false);
        // Get the upstream configuration
        let upstream_name = &server.upstream;
        let upstream = upstream_map
            .get(upstream_name)
            .ok_or_else(|| anyhow!("Upstream '{}' not found", upstream_name))?
            .clone();
        Ok(ServerConfigResolved { tls, upstream })
    }
    pub fn choose(&self) -> Option<&str> {
        let upstream = self.upstream.servers.choose(&mut OsRng);
        upstream.map(|s| s.as_str())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};
    use tempfile::TempDir;
    // Helper to create a temporary file with content
    fn create_temp_file(dir: &TempDir, filename: &str, content: &str) -> PathBuf {
        let file_path = dir.path().join(filename);
        fs::write(&file_path, content).expect("Failed to write temp file");
        file_path
    }
    #[test]
    fn test_tls_config_resolved_try_from() {
        let temp_dir = TempDir::new().unwrap();
        // Create temporary cert and key files
        let cert_content = "-----BEGIN CERTIFICATE-----\nMIICert\n-----END CERTIFICATE-----";
        let key_content = "-----BEGIN PRIVATE KEY-----\nMIIKey\n-----END PRIVATE KEY-----";
        let ca_content = "-----BEGIN CERTIFICATE-----\nMIICA\n-----END CERTIFICATE-----";
        let cert_path = create_temp_file(&temp_dir, "cert.pem", cert_content);
        let key_path = create_temp_file(&temp_dir, "key.pem", key_content);
        let ca_path = create_temp_file(&temp_dir, "ca.pem", ca_content);
        // Create raw TlsConfig with CA
        let raw_tls_with_ca = TlsConfig {
            cert: cert_path.clone(),
            key: key_path.clone(),
            ca: Some(ca_path.clone()),
        };
        // Create raw TlsConfig without CA
        let raw_tls_without_ca = TlsConfig {
            cert: cert_path.clone(),
            key: key_path.clone(),
            ca: None,
        };
        // Convert to resolved
        let resolved_tls_with_ca = TlsConfigResolved::try_from(&raw_tls_with_ca).unwrap();
        let resolved_tls_without_ca = TlsConfigResolved::try_from(&raw_tls_without_ca).unwrap();
        // Verify contents - we now store paths as strings
        assert_eq!(resolved_tls_with_ca.cert, cert_path.to_string_lossy());
        assert_eq!(resolved_tls_with_ca.key, key_path.to_string_lossy());
        assert_eq!(
            resolved_tls_with_ca.ca,
            Some(ca_path.to_string_lossy().to_string())
        );
        assert_eq!(resolved_tls_without_ca.cert, cert_path.to_string_lossy());
        assert_eq!(resolved_tls_without_ca.key, key_path.to_string_lossy());
        assert_eq!(resolved_tls_without_ca.ca, None);
    }
    #[test]
    fn test_upstream_config_resolved_from() {
        let raw_upstream = UpstreamConfig {
            name: "test_upstream".to_string(),
            servers: vec!["127.0.0.1:8080".to_string(), "127.0.0.1:8081".to_string()],
        };
        let resolved_upstream = UpstreamConfigResolved::from(&raw_upstream);
        assert_eq!(
            resolved_upstream.servers,
            vec!["127.0.0.1:8080".to_string(), "127.0.0.1:8081".to_string()]
        );
    }
    #[test]
    fn test_global_config_resolved_without_tls() {
        let raw_global = GlobalConfig {
            port: 8080,
            tls: None,
        };
        let resolved_global = GlobalConfigResolved::try_from(&raw_global).unwrap();
        assert_eq!(resolved_global.port, 8080);
        assert!(resolved_global.tls.is_none());
    }
    #[test]
    fn test_global_config_resolved_with_tls() {
        let temp_dir = TempDir::new().unwrap();
        // Create temporary cert and key files
        let cert_content = "-----BEGIN CERTIFICATE-----\nMIICert\n-----END CERTIFICATE-----";
        let key_content = "-----BEGIN PRIVATE KEY-----\nMIIKey\n-----END PRIVATE KEY-----";
        let cert_path = create_temp_file(&temp_dir, "cert.pem", cert_content);
        let key_path = create_temp_file(&temp_dir, "key.pem", key_content);
        let tls_config = TlsConfig {
            cert: cert_path.clone(),
            key: key_path.clone(),
            ca: None,
        };
        let raw_global = GlobalConfig {
            port: 8080,
            tls: Some(tls_config),
        };
        let resolved_global = GlobalConfigResolved::try_from(&raw_global).unwrap();
        assert_eq!(resolved_global.port, 8080);
        assert!(resolved_global.tls.is_some());
        let tls = resolved_global.tls.unwrap();
        assert_eq!(tls.cert, cert_path.to_string_lossy());
        assert_eq!(tls.key, key_path.to_string_lossy());
        assert!(tls.ca.is_none());
    }
    #[test]
    fn test_server_config_resolved() {
        let upstream = UpstreamConfigResolved {
            servers: vec!["127.0.0.1:8080".to_string(), "127.0.0.1:8081".to_string()],
        };
        let mut upstream_map = HashMap::new();
        upstream_map.insert("test_upstream".to_string(), upstream);
        let raw_server = ServerConfig {
            server_name: vec!["test.com".to_string(), "www.test.com".to_string()],
            upstream: "test_upstream".to_string(),
            tls: Some(true),
        };
        let resolved_server =
            ServerConfigResolved::try_from_with_maps(&raw_server, &upstream_map).unwrap();
        assert!(resolved_server.tls);
        assert_eq!(
            resolved_server.upstream.servers,
            vec!["127.0.0.1:8080".to_string(), "127.0.0.1:8081".to_string()]
        );
        // Test with tls=false
        let raw_server_no_tls = ServerConfig {
            server_name: vec!["test2.com".to_string()],
            upstream: "test_upstream".to_string(),
            tls: Some(false),
        };
        let resolved_server_no_tls =
            ServerConfigResolved::try_from_with_maps(&raw_server_no_tls, &upstream_map).unwrap();
        assert!(!resolved_server_no_tls.tls);
        // Test with tls=None (should default to false)
        let raw_server_default_tls = ServerConfig {
            server_name: vec!["test3.com".to_string()],
            upstream: "test_upstream".to_string(),
            tls: None,
        };
        let resolved_server_default_tls =
            ServerConfigResolved::try_from_with_maps(&raw_server_default_tls, &upstream_map)
                .unwrap();
        assert!(!resolved_server_default_tls.tls);
    }
    #[test]
    fn test_proxy_config_resolved_try_from() {
        let temp_dir = TempDir::new().unwrap();
        // Create temporary cert and key files
        let cert_content = "-----BEGIN CERTIFICATE-----\nMIICert\n-----END CERTIFICATE-----";
        let key_content = "-----BEGIN PRIVATE KEY-----\nMIIKey\n-----END PRIVATE KEY-----";
        let cert_path = create_temp_file(&temp_dir, "cert.pem", cert_content);
        let key_path = create_temp_file(&temp_dir, "key.pem", key_content);
        // Create raw configuration
        let tls_config = TlsConfig {
            cert: cert_path.clone(),
            key: key_path.clone(),
            ca: None,
        };
        let global_config = GlobalConfig {
            port: 8080,
            tls: Some(tls_config),
        };
        let server_configs = vec![
            ServerConfig {
                server_name: vec!["test.com".to_string(), "www.test.com".to_string()],
                upstream: "web_servers".to_string(),
                tls: Some(true),
            },
            ServerConfig {
                server_name: vec!["api.test.com".to_string()],
                upstream: "api_servers".to_string(),
                tls: Some(false),
            },
        ];
        let upstream_configs = vec![
            UpstreamConfig {
                name: "web_servers".to_string(),
                servers: vec!["127.0.0.1:8080".to_string(), "127.0.0.1:8081".to_string()],
            },
            UpstreamConfig {
                name: "api_servers".to_string(),
                servers: vec!["127.0.0.1:9090".to_string(), "127.0.0.1:9091".to_string()],
            },
        ];
        let raw_config = SimpleProxyConfig {
            global: global_config,
            servers: server_configs,
            upstreams: upstream_configs,
        };
        // Convert to resolved
        let resolved_config = ProxyConfigResolved::try_from(raw_config).unwrap();
        // Verify global config
        assert_eq!(resolved_config.global.port, 8080);
        assert!(resolved_config.global.tls.is_some());
        let tls = &resolved_config.global.tls.as_ref().unwrap();
        assert_eq!(tls.cert, cert_path.to_string_lossy());
        assert_eq!(tls.key, key_path.to_string_lossy());
        // Verify server configs
        assert_eq!(resolved_config.servers.len(), 3);
        let test_com_server = resolved_config.servers.get("test.com").unwrap();
        assert!(test_com_server.tls);
        assert_eq!(
            test_com_server.upstream.servers,
            vec!["127.0.0.1:8080".to_string(), "127.0.0.1:8081".to_string()]
        );
        let www_test_com_server = resolved_config.servers.get("www.test.com").unwrap();
        assert!(www_test_com_server.tls);
        assert_eq!(
            www_test_com_server.upstream.servers,
            vec!["127.0.0.1:8080".to_string(), "127.0.0.1:8081".to_string()]
        );
        let api_test_com_server = resolved_config.servers.get("api.test.com").unwrap();
        assert!(!api_test_com_server.tls);
        assert_eq!(
            api_test_com_server.upstream.servers,
            vec!["127.0.0.1:9090".to_string(), "127.0.0.1:9091".to_string()]
        );
    }
    #[test]
    fn test_error_handling_unknown_upstream() {
        let server_config = ServerConfig {
            server_name: vec!["test.com".to_string()],
            upstream: "unknown_upstream".to_string(),
            tls: Some(false),
        };
        let upstream_map = HashMap::new();
        let result = ServerConfigResolved::try_from_with_maps(&server_config, &upstream_map);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Upstream 'unknown_upstream' not found"
        );
    }
    #[test]
    fn test_error_handling_duplicate_server_name() {
        let temp_dir = TempDir::new().unwrap();
        // Create temporary cert and key files
        let cert_content = "-----BEGIN CERTIFICATE-----\nMIICert\n-----END CERTIFICATE-----";
        let key_content = "-----BEGIN PRIVATE KEY-----\nMIIKey\n-----END PRIVATE KEY-----";
        let cert_path = create_temp_file(&temp_dir, "cert.pem", cert_content);
        let key_path = create_temp_file(&temp_dir, "key.pem", key_content);
        // Create raw configuration with duplicate server names
        let tls_config = TlsConfig {
            cert: cert_path,
            key: key_path,
            ca: None,
        };
        let global_config = GlobalConfig {
            port: 8080,
            tls: Some(tls_config),
        };
        let server_configs = vec![
            ServerConfig {
                server_name: vec!["test.com".to_string()],
                upstream: "web_servers".to_string(),
                tls: Some(true),
            },
            ServerConfig {
                server_name: vec!["test.com".to_string()], // Duplicate server name
                upstream: "api_servers".to_string(),
                tls: Some(false),
            },
        ];
        let upstream_configs = vec![
            UpstreamConfig {
                name: "web_servers".to_string(),
                servers: vec!["127.0.0.1:8080".to_string()],
            },
            UpstreamConfig {
                name: "api_servers".to_string(),
                servers: vec!["127.0.0.1:9090".to_string()],
            },
        ];
        let raw_config = SimpleProxyConfig {
            global: global_config,
            servers: server_configs,
            upstreams: upstream_configs,
        };
        // Try to convert to resolved
        let result = ProxyConfigResolved::try_from(raw_config);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Duplicate server name: test.com"
        );
    }
}
```
## src/lib.rs
```rust
mod proxy;
mod utils;
pub mod conf;
pub use proxy::*;
pub(crate) use utils::*;
```
## src/main.rs
```rust
use clap::Parser;
use pingora::{listeners::tls::TlsSettings, prelude::*, server::configuration::ServerConf};
use simple_proxy::{HealthService, SimpleProxy, conf::ProxyConfigResolved};
use std::path::PathBuf;
use tracing::info;
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the configuration file
    #[arg(short, long)]
    config: PathBuf,
}
fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let config = ProxyConfigResolved::load(args.config)?;
    let tls_settings = {
        match config.global.tls.as_ref() {
            None => None,
            Some(tls) => {
                let mut tls_settings = TlsSettings::intermediate(&tls.cert, &tls.key)?;
                tls_settings.enable_h2();
                Some(tls_settings)
            }
        }
    };
    let proxy_addr = format!("0.0.0.0:{}", config.global.port);
    let conf = {
        let ca_file = config.global.tls.as_ref().and_then(|tls| tls.ca.clone());
        ServerConf {
            ca_file,
            ..Default::default()
        }
    };
    let mut server = Server::new_with_opt_and_conf(None, conf);
    server.bootstrap();
    let rp = SimpleProxy::try_new(config)?;
    let health_service = HealthService::new(rp.route_table().clone());
    let mut proxy = http_proxy_service(&server.configuration, rp);
    match tls_settings {
        Some(tls_settings) => {
            proxy.add_tls_with_settings(&proxy_addr, None, tls_settings);
        }
        None => {
            proxy.add_tcp(&proxy_addr);
        }
    }
    info!("proxy server is running on {}", proxy_addr);
    server.add_service(proxy);
    server.add_service(health_service);
    server.run_forever();
}
```
## src/proxy/health.rs
```rust
use super::{HealthService, RouteTable};
use async_trait::async_trait;
use pingora::{
    server::{ListenFds, ShutdownWatch},
    services::Service,
};
use std::time::Duration;
use tokio::time::interval;
use tracing::info;
const HEALTH_SERVICE_INTERVAL: Duration = Duration::from_secs(5);
impl HealthService {
    pub fn new(route_table: RouteTable) -> Self {
        Self { route_table }
    }
}
#[async_trait]
impl Service for HealthService {
    async fn start_service(
        &mut self,
        #[cfg(unix)] _fds: Option<ListenFds>,
        mut _shutdown: ShutdownWatch,
    ) {
        info!("Starting health check service");
        let mut interval = interval(HEALTH_SERVICE_INTERVAL);
        let route_table = self.route_table.pin_owned();
        loop {
            interval.tick().await;
            for (host, entry) in route_table.iter() {
                info!("Checking health of {}", host);
                entry.upstream.update().await.ok();
                entry.upstream.backends().run_health_check(true).await;
            }
        }
    }
    fn name(&self) -> &str {
        "health_check"
    }
    fn threads(&self) -> Option<usize> {
        Some(1)
    }
}
```
## src/proxy/mod.rs
```rust
mod health;
mod route;
mod simple_proxy;
use std::sync::Arc;
use crate::conf::ProxyConfig;
use papaya::HashMap;
use pingora::{lb::LoadBalancer, prelude::RoundRobin};
pub struct SimpleProxy {
    pub(crate) config: ProxyConfig,
    pub(crate) route_table: RouteTable,
}
#[allow(dead_code)]
pub struct ProxyContext {
    pub(crate) config: ProxyConfig,
    pub(crate) route_entry: Option<RouteEntry>,
    pub(crate) host: String,
    pub(crate) port: u16,
}
#[derive(Clone)]
pub struct RouteTable(pub(crate) Arc<HashMap<String, RouteEntry>>);
#[derive(Clone)]
pub struct RouteEntry {
    pub(crate) upstream: Arc<LoadBalancer<RoundRobin>>,
    pub(crate) tls: bool,
}
pub struct HealthService {
    pub(crate) route_table: RouteTable,
}
```
## src/proxy/route.rs
```rust
use super::{RouteEntry, RouteTable};
use crate::conf::{ProxyConfigResolved, ServerConfigResolved};
use anyhow::Result;
use papaya::HashMap;
use pingora::{
    lb::{Backend, LoadBalancer},
    prelude::TcpHealthCheck,
};
use std::{ops::Deref, sync::Arc, time::Duration};
use tracing::info;
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(1);
impl RouteTable {
    pub fn try_new(config: &ProxyConfigResolved) -> Result<Self> {
        let route_table = HashMap::new();
        {
            let pinned = route_table.pin();
            for (name, server) in config.servers.iter() {
                pinned.insert(name.clone(), RouteEntry::try_new(server)?);
            }
        }
        Ok(Self(Arc::new(route_table)))
    }
}
impl RouteEntry {
    pub fn try_new(config: &ServerConfigResolved) -> Result<Self> {
        let mut lb = LoadBalancer::try_from_iter(&config.upstream.servers)?;
        let hc = TcpHealthCheck::new();
        lb.set_health_check(hc);
        lb.health_check_frequency = Some(HEALTH_CHECK_INTERVAL);
        Ok(Self {
            upstream: Arc::new(lb),
            tls: config.tls,
        })
    }
    pub fn select(&self) -> Option<Backend> {
        let accept = |b: &Backend, healthy: bool| {
            info!("select: {:?}, healthy: {}", b, healthy);
            healthy
        };
        self.upstream.select_with(b"", 32, accept)
    }
}
impl Deref for RouteTable {
    type Target = HashMap<String, RouteEntry>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
```
## src/proxy/simple_proxy.rs
```rust
use super::{ProxyContext, RouteTable, SimpleProxy};
use crate::{
    conf::{ProxyConfig, ProxyConfigResolved},
    get_host_port,
};
use async_trait::async_trait;
use http::{StatusCode, header};
use pingora::{
    cache::{CacheKey, CacheMeta, NoCacheReason, RespCacheable, key::HashBinary},
    http::{RequestHeader, ResponseHeader},
    modules::http::{HttpModules, compression::ResponseCompressionBuilder},
    prelude::*,
    protocols::{Digest, http::conditional_filter},
    proxy::PurgeStatus,
    upstreams::peer::Peer,
};
use std::time::Duration;
use tracing::{info, warn};
impl SimpleProxy {
    pub fn try_new(config: ProxyConfigResolved) -> anyhow::Result<Self> {
        let route_table = RouteTable::try_new(&config)?;
        Ok(Self {
            config: ProxyConfig::new(config),
            route_table,
        })
    }
    pub fn config(&self) -> &ProxyConfig {
        &self.config
    }
    pub fn route_table(&self) -> &RouteTable {
        &self.route_table
    }
}
#[async_trait]
impl ProxyHttp for SimpleProxy {
    type CTX = ProxyContext;
    fn new_ctx(&self) -> Self::CTX {
        info!("new_ctx");
        ProxyContext {
            config: self.config.clone(),
            route_entry: None,
            host: "".to_string(),
            port: 80,
        }
    }
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        info!("request_filter");
        let (host, port) = get_host_port(
            session.get_header(http::header::HOST),
            &session.req_header().uri,
        );
        let route_table = self.route_table.pin();
        let route_entry = route_table.get(host);
        ctx.route_entry = route_entry.cloned();
        ctx.host = host.to_string();
        ctx.port = port;
        Ok(false)
    }
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let Some(route_entry) = ctx.route_entry.as_ref() else {
            return Err(Error::create(
                ErrorType::HTTPStatus(StatusCode::NOT_FOUND.into()),
                ErrorSource::Upstream,
                None,
                None,
            ));
        };
        let Some(upstream) = route_entry.select() else {
            return Err(Error::create(
                ErrorType::HTTPStatus(StatusCode::BAD_GATEWAY.into()),
                ErrorSource::Upstream,
                None,
                None,
            ));
        };
        let mut peer = HttpPeer::new(upstream, route_entry.tls, ctx.host.clone());
        if let Some(options) = peer.get_mut_peer_options() {
            options.set_http_version(2, 2);
        }
        info!("upstream_peer: {}", peer.to_string());
        Ok(Box::new(peer))
    }
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        info!("upstream_request_filter: {:?}", upstream_request);
        upstream_request.insert_header("user-agent", "SimpleProxy/0.1")?;
        Ok(())
    }
    fn upstream_response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        _ctx: &mut Self::CTX,
    ) {
        info!("upstream_response_filter: {:?}", upstream_response);
        if let Err(e) = upstream_response.insert_header("x-simple-proxy", "v0.1") {
            warn!("failed to insert header: {}", e);
        }
        match upstream_response.remove_header("server") {
            Some(server) => {
                if let Err(e) = upstream_response.insert_header("server", server) {
                    warn!("failed to insert header: {}", e);
                }
            }
            None => {
                if let Err(e) = upstream_response.insert_header("server", "SimpleProxy/0.1") {
                    warn!("failed to insert header: {}", e);
                }
            }
        }
    }
    fn init_downstream_modules(&self, modules: &mut HttpModules) {
        info!("init_downstream_modules");
        // Add disabled downstream compression module by default
        modules.add_module(ResponseCompressionBuilder::enable(0));
    }
    async fn early_request_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        info!("early_request_filter");
        Ok(())
    }
    async fn request_body_filter(
        &self,
        _session: &mut Session,
        _body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        info!("request_body_filter: end_of_stream={}", end_of_stream);
        Ok(())
    }
    fn request_cache_filter(&self, _session: &mut Session, _ctx: &mut Self::CTX) -> Result<()> {
        info!("request_cache_filter");
        Ok(())
    }
    fn cache_key_callback(&self, session: &Session, _ctx: &mut Self::CTX) -> Result<CacheKey> {
        info!("cache_key_callback");
        let req_header = session.req_header();
        Ok(CacheKey::default(req_header))
    }
    fn cache_miss(&self, session: &mut Session, _ctx: &mut Self::CTX) {
        info!("cache_miss");
        session.cache.cache_miss();
    }
    async fn cache_hit_filter(
        &self,
        _session: &Session,
        meta: &CacheMeta,
        _ctx: &mut Self::CTX,
    ) -> Result<bool> {
        info!("cache_hit_filter: meta={:?}", meta);
        Ok(false)
    }
    async fn proxy_upstream_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<bool> {
        info!("proxy_upstream_filter");
        Ok(true)
    }
    fn response_cache_filter(
        &self,
        _session: &Session,
        resp: &ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<RespCacheable> {
        info!("response_cache_filter: headers={:?}", resp);
        Ok(RespCacheable::Uncacheable(NoCacheReason::Custom("default")))
    }
    fn cache_vary_filter(
        &self,
        _meta: &CacheMeta,
        _ctx: &mut Self::CTX,
        _req: &RequestHeader,
    ) -> Option<HashBinary> {
        info!("cache_vary_filter");
        None
    }
    fn cache_not_modified_filter(
        &self,
        session: &Session,
        resp: &ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<bool> {
        info!("cache_not_modified_filter");
        // Using Pingora's standard implementation
        Ok(conditional_filter::not_modified_filter(
            session.req_header(),
            resp,
        ))
    }
    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        info!("response_filter: headers={:?}", upstream_response);
        Ok(())
    }
    fn upstream_response_body_filter(
        &self,
        _session: &mut Session,
        _body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
        _ctx: &mut Self::CTX,
    ) {
        info!(
            "upstream_response_body_filter: end_of_stream={}",
            end_of_stream
        );
    }
    fn upstream_response_trailer_filter(
        &self,
        _session: &mut Session,
        upstream_trailers: &mut header::HeaderMap,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        info!(
            "upstream_response_trailer_filter: trailer_count={}",
            upstream_trailers.len()
        );
        Ok(())
    }
    fn response_body_filter(
        &self,
        _session: &mut Session,
        _body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
        _ctx: &mut Self::CTX,
    ) -> Result<Option<Duration>> {
        info!("response_body_filter: end_of_stream={}", end_of_stream);
        Ok(None)
    }
    async fn response_trailer_filter(
        &self,
        _session: &mut Session,
        upstream_trailers: &mut header::HeaderMap,
        _ctx: &mut Self::CTX,
    ) -> Result<Option<bytes::Bytes>> {
        info!(
            "response_trailer_filter: trailer_count={}",
            upstream_trailers.len()
        );
        Ok(None)
    }
    async fn logging(&self, _session: &mut Session, e: Option<&Error>, _ctx: &mut Self::CTX) {
        info!("logging: {:?}", e);
    }
    fn suppress_error_log(&self, _session: &Session, _ctx: &Self::CTX, error: &Error) -> bool {
        info!("suppress_error_log: error={}", error);
        false
    }
    fn error_while_proxy(
        &self,
        peer: &HttpPeer,
        session: &mut Session,
        e: Box<Error>,
        _ctx: &mut Self::CTX,
        client_reused: bool,
    ) -> Box<Error> {
        info!(
            "error_while_proxy: peer={}, reused={}, error={}",
            peer, client_reused, e
        );
        let mut e = e.more_context(format!("Peer: {}", peer));
        e.retry
            .decide_reuse(client_reused && !session.as_ref().retry_buffer_truncated());
        e
    }
    fn fail_to_connect(
        &self,
        _session: &mut Session,
        peer: &HttpPeer,
        _ctx: &mut Self::CTX,
        e: Box<Error>,
    ) -> Box<Error> {
        info!("fail_to_connect: peer={}, error={}", peer, e);
        e
    }
    async fn fail_to_proxy(&self, session: &mut Session, e: &Error, _ctx: &mut Self::CTX) -> u16 {
        info!("fail_to_proxy: error={}", e);
        let server_session = session.as_mut();
        let code = match e.etype() {
            HTTPStatus(code) => *code,
            _ => {
                match e.esource() {
                    ErrorSource::Upstream => 502,
                    ErrorSource::Downstream => {
                        match e.etype() {
                            WriteError | ReadError | ConnectionClosed => {
                                /* conn already dead */
                                0
                            }
                            _ => 400,
                        }
                    }
                    ErrorSource::Internal | ErrorSource::Unset => 500,
                }
            }
        };
        if code > 0 {
            server_session.respond_error(code).await
        }
        code
    }
    fn should_serve_stale(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
        error: Option<&Error>,
    ) -> bool {
        match error {
            Some(e) => {
                info!("should_serve_stale: error={}", e);
                e.esource() == &ErrorSource::Upstream
            }
            None => {
                info!("should_serve_stale: during revalidation");
                false
            }
        }
    }
    async fn connected_to_upstream(
        &self,
        _session: &mut Session,
        reused: bool,
        peer: &HttpPeer,
        #[cfg(unix)] fd: std::os::unix::io::RawFd,
        #[cfg(windows)] _sock: std::os::windows::io::RawSocket,
        digest: Option<&Digest>,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        #[cfg(unix)]
        info!(
            "connected_to_upstream: peer={}, reused={}, fd={}, digest={:?}",
            peer, reused, fd, digest
        );
        #[cfg(windows)]
        info!(
            "connected_to_upstream: peer={}, reused={}, digest={:?}",
            peer, reused, digest
        );
        Ok(())
    }
    fn request_summary(&self, session: &Session, _ctx: &Self::CTX) -> String {
        let summary = session.as_ref().request_summary();
        info!("request_summary: {}", summary);
        summary
    }
    fn is_purge(&self, _session: &Session, _ctx: &Self::CTX) -> bool {
        info!("is_purge");
        false
    }
    fn purge_response_filter(
        &self,
        _session: &Session,
        _ctx: &mut Self::CTX,
        _purge_status: PurgeStatus,
        _purge_response: &mut std::borrow::Cow<'static, ResponseHeader>,
    ) -> Result<()> {
        info!("purge_response_filter");
        Ok(())
    }
}
```
## src/utils.rs
```rust
use http::{HeaderValue, Uri};
pub(crate) fn get_host_port<'a>(host: Option<&'a HeaderValue>, uri: &'a Uri) -> (&'a str, u16) {
    let default_port = match uri.scheme() {
        Some(scheme) if scheme.as_str() == "https" => 443,
        _ => 80,
    };
    match host {
        Some(h) => split_host_port(h.to_str().unwrap_or_default(), default_port),
        None => (
            uri.host().unwrap_or_default(),
            uri.port_u16().unwrap_or(default_port),
        ),
    }
}
fn split_host_port(host: &str, default_port: u16) -> (&str, u16) {
    let mut parts = host.split(':');
    let host = parts.next().unwrap_or("");
    let port = parts.next();
    match port {
        Some(port) => (host, port.parse().unwrap_or(default_port)),
        None => (host, default_port),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, HeaderValue, Uri};
    #[test]
    fn test_get_host_port_with_host_header() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("example.com"));
        let uri = "http://example.org/path".parse::<Uri>().unwrap();
        let (host, port) = get_host_port(headers.get("host"), &uri);
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
    }
    #[test]
    fn test_get_host_port_with_host_header_and_port() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("example.com:8080"));
        let uri = "http://example.org/path".parse::<Uri>().unwrap();
        let (host, port) = get_host_port(headers.get("host"), &uri);
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
    }
    #[test]
    fn test_get_host_port_with_https_scheme() {
        let headers = HeaderMap::new();
        let uri = "https://example.org/path".parse::<Uri>().unwrap();
        let (host, port) = get_host_port(headers.get("host"), &uri);
        assert_eq!(host, "example.org");
        assert_eq!(port, 443);
    }
    #[test]
    fn test_get_host_port_with_uri_port() {
        let headers = HeaderMap::new();
        let uri = "http://example.org:8443/path".parse::<Uri>().unwrap();
        let (host, port) = get_host_port(headers.get("host"), &uri);
        assert_eq!(host, "example.org");
        assert_eq!(port, 8443);
    }
    #[test]
    fn test_get_host_port_with_invalid_host_header() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_bytes(b"\xFF\xFF").unwrap());
        let uri = "http://example.org/path".parse::<Uri>().unwrap();
        let (host, port) = get_host_port(headers.get("host"), &uri);
        assert_eq!(host, "");
        assert_eq!(port, 80);
    }
    #[test]
    fn test_split_host_port_with_port() {
        let (host, port) = split_host_port("example.com:8080", 80);
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
    }
    #[test]
    fn test_split_host_port_without_port() {
        let (host, port) = split_host_port("example.com", 80);
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
    }
    #[test]
    fn test_split_host_port_with_invalid_port() {
        let (host, port) = split_host_port("example.com:invalid", 80);
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
    }
    #[test]
    fn test_split_host_port_empty_host() {
        let (host, port) = split_host_port("", 80);
        assert_eq!(host, "");
        assert_eq!(port, 80);
    }
}
```
