# Code Bank
## Package File
```toml
[workspace]
resolver = "2"
members = [
    "pingora",
    "pingora-core",
    "pingora-pool",
    "pingora-error",
    "pingora-limits",
    "pingora-timeout",
    "pingora-header-serde",
    "pingora-proxy",
    "pingora-cache",
    "pingora-http",
    "pingora-lru",
    "pingora-openssl",
    "pingora-boringssl",
    "pingora-runtime",
    "pingora-rustls",
    "pingora-ketama",
    "pingora-load-balancing",
    "pingora-memory-cache",
    "tinyufo",
]
[workspace.dependencies]
tokio = "1"
async-trait = "0.1.42"
httparse = "1"
bytes = "1.0"
derivative = "2.2.0"
http = "1.0.0"
log = "0.4"
h2 = ">=0.4.6"
once_cell = "1"
lru = "0"
ahash = ">=0.8.9"
[profile.bench]
debug = true
```
## pingora/examples/app/echo.rs
```rust
use async_trait::async_trait;
use bytes::Bytes;
use http::{Response, StatusCode};
use log::debug;
use once_cell::sync::Lazy;
use pingora_timeout::timeout;
use prometheus::{register_int_counter, IntCounter};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use pingora::apps::http_app::ServeHttp;
use pingora::apps::ServerApp;
use pingora::protocols::http::ServerSession;
use pingora::protocols::Stream;
use pingora::server::ShutdownWatch;
#[derive(Clone)]
pub struct EchoApp; { ... }
pub struct HttpEchoApp; { ... }
#[async_trait]
impl ServerApp for EchoApp {
    async fn process_new(
            self: &Arc<Self>,
            mut io: Stream,
            _shutdown: &ShutdownWatch,
        ) -> Option<Stream> { ... }
}
#[async_trait]
impl ServeHttp for HttpEchoApp {
    async fn response(&self, http_stream: &mut ServerSession) -> Response<Vec<u8>> { ... }
}
```
## pingora/examples/app/mod.rs
```rust
pub mod echo {
}
pub mod proxy {
}
```
## pingora/examples/app/proxy.rs
```rust
use async_trait::async_trait;
use log::debug;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::select;
use pingora::apps::ServerApp;
use pingora::connectors::TransportConnector;
use pingora::protocols::Stream;
use pingora::server::ShutdownWatch;
use pingora::upstreams::peer::BasicPeer;
pub struct ProxyApp { ... }
impl ProxyApp {
    pub fn new(proxy_to: BasicPeer) -> Self { ... }
}
#[async_trait]
impl ServerApp for ProxyApp {
    async fn process_new(
            self: &Arc<Self>,
            io: Stream,
            _shutdown: &ShutdownWatch,
        ) -> Option<Stream> { ... }
}
```
## pingora/examples/client.rs
```rust
use pingora::{connectors::http::Connector, prelude::*};
use pingora_http::RequestHeader;
use regex::Regex;
```
## pingora/examples/server.rs
```rust
use pingora::listeners::tls::TlsSettings;
use pingora::protocols::TcpKeepalive;
use pingora::server::configuration::Opt;
use pingora::server::{Server, ShutdownWatch};
use pingora::services::background::{background_service, BackgroundService};
use pingora::services::{listening::Service as ListeningService, Service};
use async_trait::async_trait;
use clap::Parser;
use tokio::time::interval;
use std::time::Duration;
pub fn main() { ... }
pub struct ExampleBackgroundService; { ... }
#[async_trait]
impl BackgroundService for ExampleBackgroundService {
    async fn start(&self, mut shutdown: ShutdownWatch) { ... }
}
```
## pingora/examples/service/echo.rs
```rust
use crate::app::echo::{EchoApp, HttpEchoApp};
use pingora::services::listening::Service;
pub fn echo_service() -> Service<EchoApp> { ... }
pub fn echo_service_http() -> Service<HttpEchoApp> { ... }
```
## pingora/examples/service/mod.rs
```rust
pub mod echo {
}
pub mod proxy {
}
```
## pingora/examples/service/proxy.rs
```rust
use crate::app::proxy::ProxyApp;
use pingora_core::listeners::Listeners;
use pingora_core::services::listening::Service;
use pingora_core::upstreams::peer::BasicPeer;
pub fn proxy_service(addr: &str, proxy_addr: &str) -> Service<ProxyApp> { ... }
pub fn proxy_service_tls(
    addr: &str,
    proxy_addr: &str,
    proxy_sni: &str,
    cert_path: &str,
    key_path: &str,
) -> Service<ProxyApp> { ... }
```
## pingora/src/lib.rs
```rust
pub use pingora_core::*;
/// HTTP header objects that preserve http header cases
pub mod http {
    pub use pingora_http::*;
}
/// Caching services and tooling
pub mod cache {
    pub use pingora_cache::*;
}
/// Load balancing recipes
pub mod lb {
    pub use pingora_load_balancing::*;
}
/// Proxying recipes
pub mod proxy {
    pub use pingora_proxy::*;
}
/// Timeouts and other useful time utilities
pub mod time {
    pub use pingora_timeout::*;
}
/// A useful set of types for getting started
pub mod prelude {
    pub use pingora_core::prelude::*;
    pub use pingora_http::prelude::*;
    pub use pingora_timeout::*;
    pub use pingora_cache::prelude::*;
    pub use pingora_load_balancing::prelude::*;
    pub use pingora_proxy::prelude::*;
    pub use pingora_timeout::*;
}
```
## pingora-boringssl/src/boring_tokio.rs
```rust
use boring::error::ErrorStack;
use boring::ssl::{self, ErrorCode, ShutdownResult, Ssl, SslRef, SslStream as SslStreamCore};
use futures_util::future;
use std::fmt;
use std::io::{self, Read, Write};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
/// An asynchronous version of [`boring::ssl::SslStream`].
#[derive(Debug)]
pub struct SslStream<S>(SslStreamCore<StreamWrapper<S>>); { ... }
impl<S> fmt::Debug for StreamWrapper<S>
where
    S: fmt::Debug, {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result { ... }
}
impl<S> Read for StreamWrapper<S>
where
    S: AsyncRead, {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> { ... }
}
impl<S> Write for StreamWrapper<S>
where
    S: AsyncWrite, {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> { ... }
    fn flush(&mut self) -> io::Result<()> { ... }
}
impl<S: AsyncRead + AsyncWrite> SslStream<S> {
    /// Like [`SslStream::new`](ssl::SslStream::new).
    pub fn new(ssl: Ssl, stream: S) -> Result<Self, ErrorStack> { ... }
    /// Like [`SslStream::connect`](ssl::SslStream::connect).
    pub fn poll_connect(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), ssl::Error>> { ... }
    /// A convenience method wrapping [`poll_connect`](Self::poll_connect).
    pub async fn connect(mut self: Pin<&mut Self>) -> Result<(), ssl::Error> { ... }
    /// Like [`SslStream::accept`](ssl::SslStream::accept).
    pub fn poll_accept(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), ssl::Error>> { ... }
    /// A convenience method wrapping [`poll_accept`](Self::poll_accept).
    pub async fn accept(mut self: Pin<&mut Self>) -> Result<(), ssl::Error> { ... }
    /// Like [`SslStream::do_handshake`](ssl::SslStream::do_handshake).
    pub fn poll_do_handshake(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), ssl::Error>> { ... }
    /// A convenience method wrapping [`poll_do_handshake`](Self::poll_do_handshake).
    pub async fn do_handshake(mut self: Pin<&mut Self>) -> Result<(), ssl::Error> { ... }
}
impl<S> SslStream<S> {
    /// Returns a shared reference to the `Ssl` object associated with this stream.
    pub fn ssl(&self) -> &SslRef { ... }
    /// Returns a shared reference to the underlying stream.
    pub fn get_ref(&self) -> &S { ... }
    /// Returns a mutable reference to the underlying stream.
    pub fn get_mut(&mut self) -> &mut S { ... }
    /// Returns a pinned mutable reference to the underlying stream.
    pub fn get_pin_mut(self: Pin<&mut Self>) -> Pin<&mut S> { ... }
}
#[cfg(feature = "read_uninit")]
impl<S> AsyncRead for SslStream<S>
where
    S: AsyncRead + AsyncWrite, {
    fn poll_read(
            self: Pin<&mut Self>,
            ctx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> { ... }
}
#[cfg(not(feature = "read_uninit"))]
impl<S> AsyncRead for SslStream<S>
where
    S: AsyncRead + AsyncWrite, {
    fn poll_read(
            self: Pin<&mut Self>,
            ctx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> { ... }
}
impl<S> AsyncWrite for SslStream<S>
where
    S: AsyncRead + AsyncWrite, {
    fn poll_write(self: Pin<&mut Self>, ctx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> { ... }
    fn poll_flush(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<io::Result<()>> { ... }
    fn poll_shutdown(mut self: Pin<&mut Self>, ctx: &mut Context) -> Poll<io::Result<()>> { ... }
}
```
## pingora-boringssl/src/ext.rs
```rust
use boring::error::ErrorStack;
use boring::pkey::{HasPrivate, PKeyRef};
use boring::ssl::{Ssl, SslAcceptor, SslRef};
use boring::x509::store::X509StoreRef;
use boring::x509::verify::X509VerifyParamRef;
use boring::x509::X509Ref;
use foreign_types_shared::ForeignTypeRef;
use libc::*;
use std::ffi::CString;
/// Add name as an additional reference identifier that can match the peer's certificate
///
/// See [X509_VERIFY_PARAM_set1_host](https://www.openssl.org/docs/man3.1/man3/X509_VERIFY_PARAM_set1_host.html).
pub fn add_host(verify_param: &mut X509VerifyParamRef, host: &str) -> Result<(), ErrorStack> { ... }
/// Set the verify cert store of `ssl`
///
/// See [SSL_set1_verify_cert_store](https://www.openssl.org/docs/man1.1.1/man3/SSL_set1_verify_cert_store.html).
pub fn ssl_set_verify_cert_store(
    ssl: &mut SslRef,
    cert_store: &X509StoreRef,
) -> Result<(), ErrorStack> { ... }
/// Load the certificate into `ssl`
///
/// See [SSL_use_certificate](https://www.openssl.org/docs/man1.1.1/man3/SSL_use_certificate.html).
pub fn ssl_use_certificate(ssl: &mut SslRef, cert: &X509Ref) -> Result<(), ErrorStack> { ... }
/// Load the private key into `ssl`
///
/// See [SSL_use_certificate](https://www.openssl.org/docs/man1.1.1/man3/SSL_use_PrivateKey.html).
pub fn ssl_use_private_key<T>(ssl: &mut SslRef, key: &PKeyRef<T>) -> Result<(), ErrorStack>
where
    T: HasPrivate, { ... }
/// Add the certificate into the cert chain of `ssl`
///
/// See [SSL_add1_chain_cert](https://www.openssl.org/docs/man1.1.1/man3/SSL_add1_chain_cert.html)
pub fn ssl_add_chain_cert(ssl: &mut SslRef, cert: &X509Ref) -> Result<(), ErrorStack> { ... }
/// Set renegotiation
///
/// This function is specific to BoringSSL
/// See <https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_set_renegotiate_mode>
pub fn ssl_set_renegotiate_mode_freely(ssl: &mut SslRef) { ... }
/// Set the curves/groups of `ssl`
///
/// See [set_groups_list](https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set1_curves.html).
pub fn ssl_set_groups_list(ssl: &mut SslRef, groups: &str) -> Result<(), ErrorStack> { ... }
/// Set's whether a second keyshare to be sent in client hello when PQ is used.
///
/// Default is true. When `true`, the first PQ (if any) and none-PQ keyshares are sent.
/// When `false`, only the first configured keyshares are sent.
#[cfg(feature = "pq_use_second_keyshare")]
pub fn ssl_use_second_key_share(ssl: &mut SslRef, enabled: bool) { ... }
#[cfg(not(feature = "pq_use_second_keyshare"))]
pub fn ssl_use_second_key_share(_ssl: &mut SslRef, _enabled: bool) { ... }
/// Clear the error stack
///
/// SSL calls should check and clear the BoringSSL error stack. But some calls fail to do so.
/// This causes the next unrelated SSL call to fail due to the leftover errors. This function allows
/// the caller to clear the error stack before performing SSL calls to avoid this issue.
pub fn clear_error_stack() { ... }
/// Create a new [Ssl] from &[SslAcceptor]
///
/// This function is needed because [Ssl::new()] doesn't take `&SslContextRef` like openssl-rs
pub fn ssl_from_acceptor(acceptor: &SslAcceptor) -> Result<Ssl, ErrorStack> { ... }
/// Suspend the TLS handshake when a certificate is needed.
///
/// This function will cause tls handshake to pause and return the error: SSL_ERROR_WANT_X509_LOOKUP.
/// The caller should set the certificate and then call [unblock_ssl_cert()] before continue the
/// handshake on the tls connection.
pub fn suspend_when_need_ssl_cert(ssl: &mut SslRef) { ... }
/// Unblock a TLS handshake after the certificate is set.
///
/// The user should continue to call tls handshake after this function is called.
pub fn unblock_ssl_cert(ssl: &mut SslRef) { ... }
/// Whether the TLS error is SSL_ERROR_WANT_X509_LOOKUP
pub fn is_suspended_for_cert(error: &boring::ssl::Error) -> bool { ... }
/// Get a mutable SslRef ouf of SslRef. which is a missing functionality for certain SslStream
/// # Safety
/// the caller needs to make sure that they hold a &mut SslRef
pub unsafe fn ssl_mut(ssl: &SslRef) -> &mut SslRef { ... }
```
## pingora-boringssl/src/lib.rs
```rust
use boring as ssl_lib;
pub use boring_sys as ssl_sys;
pub use boring_tokio as tokio_ssl;
pub use ssl_lib::error;
pub use ssl_lib::hash;
pub use ssl_lib::nid;
pub use ssl_lib::pkey;
pub use ssl_lib::ssl;
pub use ssl_lib::x509;
pub mod boring_tokio {
}
pub mod ext {
}
```
## pingora-cache/benches/lru_memory.rs
```rust
use pingora_cache::{
    eviction::{lru::Manager, EvictionManager},
    CacheKey,
};
```
## pingora-cache/benches/lru_serde.rs
```rust
use std::time::Instant;
use pingora_cache::{
    eviction::{lru::Manager, EvictionManager},
    CacheKey,
};
```
## pingora-cache/benches/simple_lru_memory.rs
```rust
use pingora_cache::{
    eviction::{simple_lru::Manager, EvictionManager},
    CacheKey,
};
```
## pingora-cache/src/cache_control.rs
```rust
use super::*;
use http::header::HeaderName;
use http::HeaderValue;
use indexmap::IndexMap;
use once_cell::sync::Lazy;
use pingora_error::{Error, ErrorType};
use regex::bytes::Regex;
use std::num::IntErrorKind;
use std::slice;
use std::str;
/// Cache control directive value type
#[derive(Debug)]
pub struct DirectiveValue(pub Vec<u8>); { ... }
/// Parsed Cache-Control directives
#[derive(Debug)]
pub struct CacheControl { ... }
/// Cacheability calculated from cache control.
#[derive(Debug, PartialEq, Eq)]
pub enum Cacheable {
    /// Cacheable
    Yes,
    /// Not cacheable
    No,
    /// No directive found for explicit cacheability
    Default,
}
/// An iter over all the cache control directives
pub struct ListValueIter<'a>(slice::Split<'a, u8, fn(&u8) -> bool>); { ... }
/// `InterpretCacheControl` provides a meaningful interface to the parsed `CacheControl`.
/// These functions actually interpret the parsed cache-control directives to return
/// the freshness or other cache meta values that cache-control is signaling.
///
/// By default `CacheControl` implements an RFC-7234 compliant reading that assumes it is being
/// used with a shared (proxy) cache.
pub trait InterpretCacheControl { ... }
impl AsRef<[u8]> for DirectiveValue {
    fn as_ref(&self) -> &[u8] { ... }
}
impl DirectiveValue {
    /// A [DirectiveValue] without quotes (`"`).
    pub fn parse_as_bytes(&self) -> &[u8] { ... }
    /// A [DirectiveValue] without quotes (`"`) as `str`.
    pub fn parse_as_str(&self) -> Result<&str> { ... }
    /// Parse the [DirectiveValue] as delta seconds
    ///
    /// `"`s are ignored. The value is capped to [DELTA_SECONDS_OVERFLOW_VALUE].
    pub fn parse_as_delta_seconds(&self) -> Result<u32> { ... }
}
impl<'a> ListValueIter<'a> {
    pub fn from(value: &'a DirectiveValue) -> Self { ... }
}
impl<'a> Iterator for ListValueIter<'a> {
    fn next(&mut self) -> Option<Self::Item> { ... }
}
impl CacheControl {
    /// Parse from the given header name in `headers`
    pub fn from_headers_named(header_name: &str, headers: &http::HeaderMap) -> Option<Self> { ... }
    /// Parse from the given header name in the [ReqHeader]
    pub fn from_req_headers_named(header_name: &str, req_header: &ReqHeader) -> Option<Self> { ... }
    /// Parse `Cache-Control` header name from the [ReqHeader]
    pub fn from_req_headers(req_header: &ReqHeader) -> Option<Self> { ... }
    /// Parse from the given header name in the [RespHeader]
    pub fn from_resp_headers_named(header_name: &str, resp_header: &RespHeader) -> Option<Self> { ... }
    /// Parse `Cache-Control` header name from the [RespHeader]
    pub fn from_resp_headers(resp_header: &RespHeader) -> Option<Self> { ... }
    /// Whether the given directive is in the cache control.
    pub fn has_key(&self, key: &str) -> bool { ... }
    /// Whether the `public` directive is in the cache control.
    pub fn public(&self) -> bool { ... }
    pub fn private(&self) -> bool { ... }
    /// Get the values of `private=`
    pub fn private_field_names(&self) -> Option<ListValueIter> { ... }
    /// Whether the standalone `no-cache` exists in the cache control
    pub fn no_cache(&self) -> bool { ... }
    /// Get the values of `no-cache=`
    pub fn no_cache_field_names(&self) -> Option<ListValueIter> { ... }
    /// Whether `no-store` exists.
    pub fn no_store(&self) -> bool { ... }
    /// Return the `max-age` seconds
    pub fn max_age(&self) -> Result<Option<u32>> { ... }
    /// Return the `s-maxage` seconds
    pub fn s_maxage(&self) -> Result<Option<u32>> { ... }
    /// Return the `stale-while-revalidate` seconds
    pub fn stale_while_revalidate(&self) -> Result<Option<u32>> { ... }
    /// Return the `stale-if-error` seconds
    pub fn stale_if_error(&self) -> Result<Option<u32>> { ... }
    /// Whether `must-revalidate` exists.
    pub fn must_revalidate(&self) -> bool { ... }
    /// Whether `proxy-revalidate` exists.
    pub fn proxy_revalidate(&self) -> bool { ... }
    /// Whether `only-if-cached` exists.
    pub fn only_if_cached(&self) -> bool { ... }
}
impl InterpretCacheControl for CacheControl {
    fn is_cacheable(&self) -> Cacheable { ... }
    fn allow_caching_authorized_req(&self) -> bool { ... }
    fn fresh_sec(&self) -> Option<u32> { ... }
    fn serve_stale_while_revalidate_sec(&self) -> Option<u32> { ... }
    fn serve_stale_if_error_sec(&self) -> Option<u32> { ... }
    fn strip_private_headers(&self, resp_header: &mut ResponseHeader) { ... }
}
```
## pingora-cache/src/eviction/lru.rs
```rust
use super::EvictionManager;
use crate::key::CompactCacheKey;
use async_trait::async_trait;
use pingora_error::{BError, ErrorType::*, OrErr, Result};
use pingora_lru::Lru;
use serde::de::SeqAccess;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::prelude::*;
use std::path::Path;
use std::time::SystemTime;
/// A shared LRU cache manager designed to manage a large volume of assets.
///
/// - Space optimized in-memory LRU (see [pingora_lru]).
/// - Instead of a single giant LRU, this struct shards the assets into `N` independent LRUs.
///
/// This allows [EvictionManager::save()] not to lock the entire cache manager while performing
/// serialization.
pub struct Manager<const N: usize>(Lru<CompactCacheKey, N>); { ... }
impl<const N: usize> Manager<N> {
    /// Create a [Manager] with the given size limit and estimated per shard capacity.
    ///
    /// The `capacity` is for preallocating to avoid reallocation cost when the LRU grows.
    pub fn with_capacity(limit: usize, capacity: usize) -> Self { ... }
    /// Serialize the given shard
    pub fn serialize_shard(&self, shard: usize) -> Result<Vec<u8>> { ... }
    /// Deserialize a shard
    ///
    /// Shard number is not needed because the key itself will hash to the correct shard.
    pub fn deserialize_shard(&self, buf: &[u8]) -> Result<()> { ... }
}
impl<'de, const N: usize> serde::de::Visitor<'de> for InsertToManager<'_, N> {
    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result { ... }
    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>, { ... }
}
#[async_trait]
impl<const N: usize> EvictionManager for Manager<N> {
    fn total_size(&self) -> usize { ... }
    fn total_items(&self) -> usize { ... }
    fn evicted_size(&self) -> usize { ... }
    fn evicted_items(&self) -> usize { ... }
    fn admit(
            &self,
            item: CompactCacheKey,
            size: usize,
            _fresh_until: SystemTime,
        ) -> Vec<CompactCacheKey> { ... }
    fn remove(&self, item: &CompactCacheKey) { ... }
    fn access(&self, item: &CompactCacheKey, size: usize, _fresh_until: SystemTime) -> bool { ... }
    fn peek(&self, item: &CompactCacheKey) -> bool { ... }
    async fn save(&self, dir_path: &str) -> Result<()> { ... }
    async fn load(&self, dir_path: &str) -> Result<()> { ... }
}
```
## pingora-cache/src/eviction/mod.rs
```rust
use crate::key::CompactCacheKey;
use async_trait::async_trait;
use pingora_error::Result;
use std::time::SystemTime;
pub mod lru {
}
pub mod simple_lru {
}
/// The trait that a cache eviction algorithm needs to implement
///
/// NOTE: these trait methods require &self not &mut self, which means concurrency should
/// be handled the implementations internally.
#[async_trait]
pub trait EvictionManager { ... }
```
## pingora-cache/src/eviction/simple_lru.rs
```rust
use super::EvictionManager;
use crate::key::CompactCacheKey;
use async_trait::async_trait;
use lru::LruCache;
use parking_lot::RwLock;
use pingora_error::{BError, ErrorType::*, OrErr, Result};
use serde::de::SeqAccess;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::prelude::*;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::SystemTime;
/// A simple LRU eviction manager
///
/// The implementation is not optimized. All operations require global locks.
pub struct Manager { ... }
impl Manager {
    /// Create a new [Manager] with the given total size limit `limit`.
    pub fn new(limit: usize) -> Self { ... }
}
impl<'de> serde::de::Visitor<'de> for InsertToManager<'_> {
    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result { ... }
    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>, { ... }
}
#[async_trait]
impl EvictionManager for Manager {
    fn total_size(&self) -> usize { ... }
    fn total_items(&self) -> usize { ... }
    fn evicted_size(&self) -> usize { ... }
    fn evicted_items(&self) -> usize { ... }
    fn admit(
            &self,
            item: CompactCacheKey,
            size: usize,
            _fresh_until: SystemTime,
        ) -> Vec<CompactCacheKey> { ... }
    fn remove(&self, item: &CompactCacheKey) { ... }
    fn access(&self, item: &CompactCacheKey, size: usize, _fresh_until: SystemTime) -> bool { ... }
    fn peek(&self, item: &CompactCacheKey) -> bool { ... }
    async fn save(&self, dir_path: &str) -> Result<()> { ... }
    async fn load(&self, dir_path: &str) -> Result<()> { ... }
}
```
## pingora-cache/src/filters.rs
```rust
use super::*;
use crate::cache_control::{CacheControl, Cacheable, InterpretCacheControl};
use crate::RespCacheable::*;
use http::{header, HeaderValue};
use httpdate::HttpDate;
use log::warn;
use pingora_http::RequestHeader;
/// Filters to run when sending requests to upstream
pub mod upstream {
    use super::*;
    /// Adjust the request header for cacheable requests
    ///
    /// This filter does the following in order to fetch the entire response to cache
    /// - Convert HEAD to GET
    /// - `If-*` headers are removed
    /// - `Range` header is removed
    ///
    /// When `meta` is set, this function will inject `If-modified-since` according to the `Last-Modified` header
    /// and inject `If-none-match` according to `Etag` header
    pub fn request_filter(req: &mut RequestHeader, meta: Option<&CacheMeta>) -> Result<()> { ... }
}
/// Decide if the request can be cacheable
pub fn request_cacheable(req_header: &ReqHeader) -> bool { ... }
/// Decide if the response is cacheable.
///
/// `cache_control` is the parsed [CacheControl] from the response header. It is a standalone
/// argument so that caller has the flexibility to choose to use, change or ignore it.
pub fn resp_cacheable(
    cache_control: Option<&CacheControl>,
    mut resp_header: ResponseHeader,
    authorization_present: bool,
    defaults: &CacheMetaDefaults,
) -> RespCacheable { ... }
/// Calculate the [SystemTime] at which the asset expires
///
/// Return None when not cacheable.
pub fn calculate_fresh_until(
    now: SystemTime,
    cache_control: Option<&CacheControl>,
    resp_header: &RespHeader,
    authorization_present: bool,
    defaults: &CacheMetaDefaults,
) -> Option<SystemTime> { ... }
/// Calculate the expire time from the `Expires` header only
pub fn calculate_expires_header_time(resp_header: &RespHeader) -> Option<SystemTime> { ... }
/// Calculates stale-while-revalidate and stale-if-error seconds from Cache-Control or the [CacheMetaDefaults].
pub fn calculate_serve_stale_sec(
    cache_control: Option<&impl InterpretCacheControl>,
    defaults: &CacheMetaDefaults,
) -> (u32, u32) { ... }
```
## pingora-cache/src/hashtable.rs
```rust
use lru::LruCache;
use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::collections::HashMap;
/// A hash table that shards to a constant number of tables to reduce lock contention
pub struct ConcurrentHashTable<V, const N: usize> { ... }
pub struct LruShard<V>(RwLock<LruCache<u128, V>>); { ... }
/// Sharded concurrent data structure for LruCache
pub struct ConcurrentLruCache<V, const N: usize> { ... }
impl<V, const N: usize> ConcurrentHashTable<V, N>
where
    [RwLock<HashMap<u128, V>>; N]: Default, {
    pub fn new() -> Self { ... }
    pub fn get(&self, key: u128) -> &RwLock<HashMap<u128, V>> { ... }
    #[allow(dead_code)]
    pub fn read(&self, key: u128) -> RwLockReadGuard<HashMap<u128, V>> { ... }
    pub fn write(&self, key: u128) -> RwLockWriteGuard<HashMap<u128, V>> { ... }
}
impl<V, const N: usize> Default for ConcurrentHashTable<V, N>
where
    [RwLock<HashMap<u128, V>>; N]: Default, {
    fn default() -> Self { ... }
}
impl<V> Default for LruShard<V> {
    fn default() -> Self { ... }
}
impl<V, const N: usize> ConcurrentLruCache<V, N>
where
    [LruShard<V>; N]: Default, {
    pub fn new(shard_capacity: usize) -> Self { ... }
    pub fn get(&self, key: u128) -> &RwLock<LruCache<u128, V>> { ... }
    #[allow(dead_code)]
    pub fn read(&self, key: u128) -> RwLockReadGuard<LruCache<u128, V>> { ... }
    pub fn write(&self, key: u128) -> RwLockWriteGuard<LruCache<u128, V>> { ... }
}
```
## pingora-cache/src/key.rs
```rust
use super::*;
use blake2::{Blake2b, Digest};
use http::Extensions;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter, Result as FmtResult};
/// Decode the hex str into [HashBinary].
///
/// Return `None` when the decode fails or the input is not exact 32 (to decode to 16 bytes).
pub fn str2hex(s: &str) -> Option<HashBinary> { ... }
/// helper function: hash str to u8
pub fn hash_u8(key: &str) -> u8 { ... }
/// helper function: hash str to [HashBinary]
pub fn hash_key(key: &str) -> HashBinary { ... }
/// General purpose cache key
#[derive(Debug, Clone)]
pub struct CacheKey { ... }
#[derive(Debug, Deserialize, Serialize, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct CompactCacheKey { ... }
/// The trait for cache key
pub trait CacheHashKey { ... }
impl CacheKey {
    /// Set the value of the variance hash
    pub fn set_variance_key(&mut self, key: HashBinary) { ... }
    /// Get the value of the variance hash
    pub fn get_variance_key(&self) -> Option<&HashBinary> { ... }
    /// Removes the variance from this cache key
    pub fn remove_variance_key(&mut self) { ... }
    /// Override the primary key hash
    pub fn set_primary_bin_override(&mut self, key: HashBinary) { ... }
}
impl Display for CompactCacheKey {
    fn fmt(&self, f: &mut Formatter) -> FmtResult { ... }
}
impl CacheHashKey for CompactCacheKey {
    fn primary_bin(&self) -> HashBinary { ... }
    fn variance_bin(&self) -> Option<HashBinary> { ... }
    fn user_tag(&self) -> &str { ... }
}
impl CacheKey {
    /// Create a default [CacheKey] from a request, which just takes it URI as the primary key.
    pub fn default(req_header: &ReqHeader) -> Self { ... }
    /// Create a new [CacheKey] from the given namespace, primary, and user_tag string.
    ///
    /// Both `namespace` and `primary` will be used for the primary hash
    pub fn new<S1, S2, S3>(namespace: S1, primary: S2, user_tag: S3) -> Self
        where
            S1: Into<String>,
            S2: Into<String>,
            S3: Into<String>, { ... }
    /// Return the namespace of this key
    pub fn namespace(&self) -> &str { ... }
    /// Return the primary key of this key
    pub fn primary_key(&self) -> &str { ... }
    /// Convert this key to [CompactCacheKey].
    pub fn to_compact(&self) -> CompactCacheKey { ... }
}
impl CacheHashKey for CacheKey {
    fn primary_bin(&self) -> HashBinary { ... }
    fn variance_bin(&self) -> Option<HashBinary> { ... }
    fn user_tag(&self) -> &str { ... }
}
```
## pingora-cache/src/lib.rs
```rust
use cf_rustracing::tag::Tag;
use http::{method::Method, request::Parts as ReqHeader, response::Parts as RespHeader};
use key::{CacheHashKey, HashBinary};
use lock::WritePermit;
use log::warn;
use pingora_error::Result;
use pingora_http::ResponseHeader;
use std::time::{Duration, Instant, SystemTime};
use strum::IntoStaticStr;
use trace::CacheTraceCTX;
use crate::max_file_size::MaxFileSizeMissHandler;
pub use key::CacheKey;
use lock::{CacheKeyLockImpl, LockStatus, Locked};
pub use memory::MemCache;
pub use meta::{CacheMeta, CacheMetaDefaults};
pub use storage::{HitHandler, MissHandler, PurgeType, Storage};
pub use variance::VarianceBuilder;
pub mod cache_control {
}
pub mod eviction {
}
pub mod filters {
}
pub mod hashtable {
}
pub mod key {
}
pub mod lock {
}
pub mod max_file_size {
}
pub mod meta {
}
pub mod predictor {
}
pub mod put {
}
pub mod storage {
}
pub mod trace {
}
pub mod prelude {
}
/// Set the header compression dictionary, which helps serialize http header.
///
/// Return false if it is already set.
pub fn set_compression_dict_path(path: &str) -> bool { ... }
/// The state machine for http caching
///
/// This object is used to handle the state and transitions for HTTP caching through the life of a
/// request.
pub struct HttpCache { ... }
/// This reflects the phase of HttpCache during the lifetime of a request
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CachePhase {
    /// Cache disabled, with reason (NeverEnabled if never explicitly used)
    Disabled(NoCacheReason),
    /// Cache enabled but nothing is set yet
    Uninit,
    /// Cache was enabled, the request decided not to use it
    // HttpCache.inner is kept
    Bypass,
    /// Awaiting the cache key to be generated
    CacheKey,
    /// Cache hit
    Hit,
    /// No cached asset is found
    Miss,
    /// A staled (expired) asset is found
    Stale,
    /// A staled (expired) asset was found, but another request is revalidating it
    StaleUpdating,
    /// A staled (expired) asset was found, so a fresh one was fetched
    Expired,
    /// A staled (expired) asset was found, and it was revalidated to be fresh
    Revalidated,
    /// Revalidated, but deemed uncacheable, so we do not freshen it
    RevalidatedNoCache(NoCacheReason),
}
/// The possible reasons for not caching
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NoCacheReason {
    /// Caching is not enabled to begin with
    NeverEnabled,
    /// Origin directives indicated this was not cacheable
    OriginNotCache,
    /// Response size was larger than the cache's configured maximum asset size
    ResponseTooLarge,
    /// Due to internal caching storage error
    StorageError,
    /// Due to other types of internal issues
    InternalError,
    /// will be cacheable but skip cache admission now
    ///
    /// This happens when the cache predictor predicted that this request is not cacheable, but
    /// the response turns out to be OK to cache. However, it might be too large to re-enable caching
    /// for this request
    Deferred,
    /// Due to the proxy upstream filter declining the current request from going upstream
    DeclinedToUpstream,
    /// Due to the upstream being unreachable or otherwise erroring during proxying
    UpstreamError,
    /// The writer of the cache lock sees that the request is not cacheable (Could be OriginNotCache)
    CacheLockGiveUp,
    /// This request waited too long for the writer of the cache lock to finish, so this request will
    /// fetch from the origin without caching
    CacheLockTimeout,
    /// Other custom defined reasons
    Custom(&'static str),
}
/// Information collected about the caching operation that will not be cleared
#[derive(Debug, Default)]
pub struct HttpCacheDigest { ... }
/// Response cacheable decision
///
#[derive(Debug)]
pub enum RespCacheable {
    Cacheable(CacheMeta),
    Uncacheable(NoCacheReason),
}
/// Indicators of which level of purge logic to apply to an asset. As in should
/// the purged file be revalidated or re-retrieved altogether
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForcedInvalidationKind {
    /// Indicates the asset should be considered stale and revalidated
    ForceExpired,
    /// Indicates the asset should be considered absent and treated like a miss
    /// instead of a hit
    ForceMiss,
}
/// Freshness state of cache hit asset
///
#[derive(Debug, Copy, Clone, IntoStaticStr, PartialEq, Eq)]
#[strum(serialize_all = "snake_case")]
pub enum HitStatus {
    /// The asset's freshness directives indicate it has expired
    Expired,
    /// The asset was marked as expired, and should be treated as stale
    ForceExpired,
    /// The asset was marked as absent, and should be treated as a miss
    ForceMiss,
    /// An error occurred while processing the asset, so it should be treated as
    /// a miss
    FailedHitFilter,
    /// The asset is not expired
    Fresh,
}
impl CachePhase {
    /// Convert [CachePhase] as `str`, for logging and debugging.
    pub fn as_str(&self) -> &'static str { ... }
}
impl NoCacheReason {
    /// Convert [NoCacheReason] as `str`, for logging and debugging.
    pub fn as_str(&self) -> &'static str { ... }
}
impl RespCacheable {
    /// Whether it is cacheable
    #[inline]
    pub fn is_cacheable(&self) -> bool { ... }
    /// Unwrap [RespCacheable] to get the [CacheMeta] stored
    /// # Panic
    /// Panic when this object is not cacheable. Check [Self::is_cacheable()] first.
    pub fn unwrap_meta(self) -> CacheMeta { ... }
}
impl HitStatus {
    /// For displaying cache hit status
    pub fn as_str(&self) -> &'static str { ... }
    /// Whether cached asset can be served as fresh
    pub fn is_fresh(&self) -> bool { ... }
    /// Check whether the hit status should be treated as a miss. A forced miss
    /// is obviously treated as a miss. A hit-filter failure is treated as a
    /// miss because we can't use the asset as an actual hit. If we treat it as
    /// expired, we still might not be able to use it even if revalidation
    /// succeeds.
    pub fn is_treated_as_miss(self) -> bool { ... }
}
impl HttpCache {
    /// Create a new [HttpCache].
    ///
    /// Caching is not enabled by default.
    pub fn new() -> Self { ... }
    /// Whether the cache is enabled
    pub fn enabled(&self) -> bool { ... }
    /// Whether the cache is being bypassed
    pub fn bypassing(&self) -> bool { ... }
    /// Return the [CachePhase]
    pub fn phase(&self) -> CachePhase { ... }
    /// Whether anything was fetched from the upstream
    ///
    /// This essentially checks all possible [CachePhase] who need to contact the upstream server
    pub fn upstream_used(&self) -> bool { ... }
    /// Check whether the backend storage is the type `T`.
    pub fn storage_type_is<T: 'static>(&self) -> bool { ... }
    /// Release the cache lock if the current request is a cache writer.
    ///
    /// Generally callers should prefer using `disable` when a cache lock should be released
    /// due to an error to clear all cache context. This function is for releasing the cache lock
    /// while still keeping the cache around for reading, e.g. when serving stale.
    pub fn release_write_lock(&mut self, reason: NoCacheReason) { ... }
    /// Disable caching
    pub fn disable(&mut self, reason: NoCacheReason) { ... }
    /// Set the cache to bypass
    ///
    /// # Panic
    /// This call is only allowed in [CachePhase::CacheKey] phase (before any cache lookup is performed).
    /// Use it in any other phase will lead to panic.
    pub fn bypass(&mut self) { ... }
    /// Enable the cache
    ///
    /// - `storage`: the cache storage backend that implements [storage::Storage]
    /// - `eviction`: optionally the eviction manager, without it, nothing will be evicted from the storage
    /// - `predictor`: optionally a cache predictor. The cache predictor predicts whether something is likely
    /// to be cacheable or not. This is useful because the proxy can apply different types of optimization to
    /// cacheable and uncacheable requests.
    /// - `cache_lock`: optionally a cache lock which handles concurrent lookups to the same asset. Without it
    /// such lookups will all be allowed to fetch the asset independently.
    pub fn enable(
            &mut self,
            storage: &'static (dyn storage::Storage + Sync),
            eviction: Option<&'static (dyn eviction::EvictionManager + Sync)>,
            predictor: Option<&'static (dyn predictor::CacheablePredictor + Sync)>,
            cache_lock: Option<&'static CacheKeyLockImpl>,
        ) { ... }
    pub fn enable_tracing(&mut self, parent_span: trace::Span) { ... }
    pub fn get_cache_span(&self) -> Option<trace::SpanHandle> { ... }
    pub fn get_miss_span(&self) -> Option<trace::SpanHandle> { ... }
    pub fn get_hit_span(&self) -> Option<trace::SpanHandle> { ... }
    /// Set the cache key
    /// # Panic
    /// Cache key is only allowed to be set in its own phase. Set it in other phases will cause panic.
    pub fn set_cache_key(&mut self, key: CacheKey) { ... }
    /// Return the cache key used for asset lookup
    /// # Panic
    /// Can only be called after the cache key is set and the cache is not disabled. Panic otherwise.
    pub fn cache_key(&self) -> &CacheKey { ... }
    /// Return the max size allowed to be cached.
    pub fn max_file_size_bytes(&self) -> Option<usize> { ... }
    /// Set the maximum response _body_ size in bytes that will be admitted to the cache.
    ///
    /// Response header size does not contribute to the max file size.
    pub fn set_max_file_size_bytes(&mut self, max_file_size_bytes: usize) { ... }
    /// Set that cache is found in cache storage.
    ///
    /// This function is called after [Self::cache_lookup()] which returns the [CacheMeta] and
    /// [HitHandler].
    ///
    /// The `hit_status` enum allows the caller to force expire assets.
    pub fn cache_found(&mut self, meta: CacheMeta, hit_handler: HitHandler, hit_status: HitStatus) { ... }
    /// Mark `self` to be cache miss.
    ///
    /// This function is called after [Self::cache_lookup()] finds nothing or the caller decides
    /// not to use the assets found.
    /// # Panic
    /// Panic in other phases.
    pub fn cache_miss(&mut self) { ... }
    /// Return the [HitHandler]
    /// # Panic
    /// Call this after [Self::cache_found()], panic in other phases.
    pub fn hit_handler(&mut self) -> &mut HitHandler { ... }
    /// Return the body reader during a cache admission (miss/expired) which decouples the downstream
    /// read and upstream cache write
    pub fn miss_body_reader(&mut self) -> Option<&mut HitHandler> { ... }
    /// Call this when cache hit is fully read.
    ///
    /// This call will release resource if any and log the timing in tracing if set.
    /// # Panic
    /// Panic in phases where there is no cache hit.
    pub async fn finish_hit_handler(&mut self) -> Result<()> { ... }
    /// Set the [MissHandler] according to cache_key and meta, can only call once
    pub async fn set_miss_handler(&mut self) -> Result<()> { ... }
    /// Return the [MissHandler] to write the response body to cache.
    ///
    /// `None`: the handler has not been set or already finished
    pub fn miss_handler(&mut self) -> Option<&mut MissHandler> { ... }
    /// Finish cache admission
    ///
    /// If [self] is dropped without calling this, the cache admission is considered incomplete and
    /// should be cleaned up.
    ///
    /// This call will also trigger eviction if set.
    pub async fn finish_miss_handler(&mut self) -> Result<()> { ... }
    /// Set the [CacheMeta] of the cache
    pub fn set_cache_meta(&mut self, meta: CacheMeta) { ... }
    /// Set the [CacheMeta] of the cache after revalidation.
    ///
    /// Certain info such as the original cache admission time will be preserved. Others will
    /// be replaced by the input `meta`.
    pub async fn revalidate_cache_meta(&mut self, mut meta: CacheMeta) -> Result<bool> { ... }
    /// After a successful revalidation, update certain headers for the cached asset
    /// such as `Etag` with the fresh response header `resp`.
    pub fn revalidate_merge_header(&mut self, resp: &RespHeader) -> ResponseHeader { ... }
    /// Mark this asset uncacheable after revalidation
    pub fn revalidate_uncacheable(&mut self, header: ResponseHeader, reason: NoCacheReason) { ... }
    /// Mark this asset as stale, but being updated separately from this request.
    pub fn set_stale_updating(&mut self) { ... }
    /// Update the variance of the [CacheMeta].
    ///
    /// Note that this process may change the lookup `key`, and eventually (when the asset is
    /// written to storage) invalidate other cached variants under the same primary key as the
    /// current asset.
    pub fn update_variance(&mut self, variance: Option<HashBinary>) { ... }
    /// Return the [CacheMeta] of this asset
    ///
    /// # Panic
    /// Panic in phases which has no cache meta.
    pub fn cache_meta(&self) -> &CacheMeta { ... }
    /// Return the [CacheMeta] of this asset if any
    ///
    /// Different from [Self::cache_meta()], this function is allowed to be called in
    /// [CachePhase::Miss] phase where the cache meta maybe set.
    /// # Panic
    /// Panic in phases that shouldn't have cache meta.
    pub fn maybe_cache_meta(&self) -> Option<&CacheMeta> { ... }
    /// Perform the cache lookup from the given cache storage with the given cache key
    ///
    /// A cache hit will return [CacheMeta] which contains the header and meta info about
    /// the cache as well as a [HitHandler] to read the cache hit body.
    /// # Panic
    /// Panic in other phases.
    pub async fn cache_lookup(&mut self) -> Result<Option<(CacheMeta, HitHandler)>> { ... }
    /// Update variance and see if the meta matches the current variance
    ///
    /// `cache_lookup() -> compute vary hash -> cache_vary_lookup()`
    /// This function allows callers to compute vary based on the initial cache hit.
    /// `meta` should be the ones returned from the initial cache_lookup()
    /// - return true if the meta is the variance.
    /// - return false if the current meta doesn't match the variance, need to cache_lookup() again
    pub fn cache_vary_lookup(&mut self, variance: HashBinary, meta: &CacheMeta) -> bool { ... }
    /// Whether this request is behind a cache lock in order to wait for another request to read the
    /// asset.
    pub fn is_cache_locked(&self) -> bool { ... }
    /// Whether this request is the leader request to fetch the assets for itself and other requests
    /// behind the cache lock.
    pub fn is_cache_lock_writer(&self) -> bool { ... }
    /// Take the write lock from this request to transfer it to another one.
    /// # Panic
    /// Call is_cache_lock_writer() to check first, will panic otherwise.
    pub fn take_write_lock(&mut self) -> (WritePermit, &'static CacheKeyLockImpl) { ... }
    /// Set the write lock, which is usually transferred from [Self::take_write_lock()]
    pub fn set_write_lock(&mut self, write_lock: WritePermit) { ... }
    /// Whether this asset is staled and stale if error is allowed
    pub fn can_serve_stale_error(&self) -> bool { ... }
    /// Whether this asset is staled and stale while revalidate is allowed.
    pub fn can_serve_stale_updating(&self) -> bool { ... }
    /// Wait for the cache read lock to be unlocked
    /// # Panic
    /// Check [Self::is_cache_locked()], panic if this request doesn't have a read lock.
    pub async fn cache_lock_wait(&mut self) -> LockStatus { ... }
    /// How long did this request wait behind the read lock
    pub fn lock_duration(&self) -> Option<Duration> { ... }
    /// How long did this request spent on cache lookup and reading the header
    pub fn lookup_duration(&self) -> Option<Duration> { ... }
    /// Delete the asset from the cache storage
    /// # Panic
    /// Need to be called after the cache key is set. Panic otherwise.
    pub async fn purge(&mut self) -> Result<bool> { ... }
    /// Check the cacheable prediction
    ///
    /// Return true if the predictor is not set
    pub fn cacheable_prediction(&self) -> bool { ... }
    /// Tell the predictor that this response, which is previously predicted to be uncacheable,
    /// is cacheable now.
    pub fn response_became_cacheable(&self) { ... }
    /// Tell the predictor that this response is uncacheable so that it will know next time
    /// this request arrives.
    pub fn response_became_uncacheable(&self, reason: NoCacheReason) { ... }
    /// Tag all spans as being part of a subrequest.
    pub fn tag_as_subrequest(&mut self) { ... }
}
```
## pingora-cache/src/lock.rs
```rust
use crate::{hashtable::ConcurrentHashTable, key::CacheHashKey, CacheKey};
use pingora_timeout::timeout;
use std::sync::Arc;
use log::warn;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};
use strum::IntoStaticStr;
use tokio::sync::Semaphore;
/// The global cache locking manager
pub struct CacheLock { ... }
/// A struct representing locked cache access
#[derive(Debug)]
pub enum Locked {
    /// The writer is allowed to fetch the asset
    Write(WritePermit),
    /// The reader waits for the writer to fetch the asset
    Read(ReadLock),
}
/// Status which the read locks could possibly see.
#[derive(Debug, Copy, Clone, PartialEq, Eq, IntoStaticStr)]
pub enum LockStatus {
    /// Waiting for the writer to populate the asset
    Waiting,
    /// The writer finishes, readers can start
    Done,
    /// The writer encountered error, such as network issue. A new writer will be elected.
    TransientError,
    /// The writer observed that no cache lock is needed (e.g., uncacheable), readers should start
    /// to fetch independently without a new writer
    GiveUp,
    /// The write lock is dropped without being unlocked
    Dangling,
    /// The lock is held for too long
    Timeout,
}
#[derive(Debug)]
pub struct LockCore { ... }
/// ReadLock: the requests who get it need to wait until it is released
#[derive(Debug)]
pub struct ReadLock(Arc<LockCore>); { ... }
/// WritePermit: requires who get it need to populate the cache and then release it
#[derive(Debug)]
pub struct WritePermit { ... }
pub struct LockStub(pub Arc<LockCore>); { ... }
pub trait CacheKeyLock { ... }
impl Locked {
    /// Is this a write lock
    pub fn is_write(&self) -> bool { ... }
}
impl CacheLock {
    /// Create a new [CacheLock] with the given lock timeout
    ///
    /// When the timeout is reached, the read locks are automatically unlocked
    pub fn new_boxed(timeout: Duration) -> Box<Self> { ... }
    /// Create a new [CacheLock] with the given lock timeout
    ///
    /// When the timeout is reached, the read locks are automatically unlocked
    pub fn new(timeout: Duration) -> Self { ... }
}
impl CacheKeyLock for CacheLock {
    fn lock(&self, key: &CacheKey) -> Locked { ... }
    fn release(&self, key: &CacheKey, mut permit: WritePermit, reason: LockStatus) { ... }
}
impl From<LockStatus> for u8 {
    fn from(l: LockStatus) -> u8 { ... }
}
impl From<u8> for LockStatus {
    fn from(v: u8) -> Self { ... }
}
impl LockCore {
    pub fn new_arc(timeout: Duration) -> Arc<Self> { ... }
    pub fn locked(&self) -> bool { ... }
    pub fn unlock(&self, reason: LockStatus) { ... }
    pub fn lock_status(&self) -> LockStatus { ... }
}
impl ReadLock {
    /// Wait for the writer to release the lock
    pub async fn wait(&self) { ... }
    /// Test if it is still locked
    pub fn locked(&self) -> bool { ... }
    /// Whether the lock is expired, e.g., the writer has been holding the lock for too long
    pub fn expired(&self) -> bool { ... }
    /// The current status of the lock
    pub fn lock_status(&self) -> LockStatus { ... }
}
impl WritePermit {
    pub fn new(timeout: Duration) -> (WritePermit, LockStub) { ... }
    pub fn unlock(&mut self, reason: LockStatus) { ... }
}
impl Drop for WritePermit {
    fn drop(&mut self) { ... }
}
impl LockStub {
    pub fn read_lock(&self) -> ReadLock { ... }
}
```
## pingora-cache/src/max_file_size.rs
```rust
use crate::storage::HandleMiss;
use crate::MissHandler;
use async_trait::async_trait;
use bytes::Bytes;
use pingora_error::{Error, ErrorType};
/// [MaxFileSizeMissHandler] wraps a MissHandler to enforce a maximum asset size that should be
/// written to the MissHandler.
///
/// This is used to enforce a maximum cache size for a request when the
/// response size is not known ahead of time (no Content-Length header). When the response size _is_
/// known ahead of time, it should be checked up front (when calculating cacheability) for efficiency.
/// Note: for requests with partial read support (where downstream reads the response from cache as
/// it is filled), this will cause the request as a whole to fail. The response will be remembered
/// as uncacheable, though, so downstream will be able to retry the request, since the cache will be
/// disabled for the retried request.
pub struct MaxFileSizeMissHandler { ... }
impl MaxFileSizeMissHandler {
    /// Create a new [MaxFileSizeMissHandler] wrapping the given [MissHandler]
    pub fn new(inner: MissHandler, max_file_size_bytes: usize) -> MaxFileSizeMissHandler { ... }
}
#[async_trait]
impl HandleMiss for MaxFileSizeMissHandler {
    async fn write_body(&mut self, data: Bytes, eof: bool) -> pingora_error::Result<()> { ... }
    async fn finish(self: Box<Self>) -> pingora_error::Result<usize> { ... }
    fn streaming_write_tag(&self) -> Option<&[u8]> { ... }
}
```
## pingora-cache/src/memory.rs
```rust
use super::*;
use crate::key::CompactCacheKey;
use crate::storage::{streaming_write::U64WriteId, HandleHit, HandleMiss};
use crate::trace::SpanHandle;
use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::RwLock;
use pingora_error::*;
use std::any::Any;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::watch;
/// Hash map based in memory cache
///
/// For testing only, not for production use.
pub struct MemCache { ... }
pub enum MemHitHandler {
    Complete(CompleteHit),
    Partial(PartialHit),
}
pub struct CompleteHit { ... }
pub struct PartialHit { ... }
pub struct MemMissHandler { ... }
impl MemCache {
    /// Create a new [MemCache]
    pub fn new() -> Self { ... }
}
#[async_trait]
impl HandleHit for MemHitHandler {
    async fn read_body(&mut self) -> Result<Option<Bytes>> { ... }
    async fn finish(
            self: Box<Self>, // because self is always used as a trait object
            _storage: &'static (dyn storage::Storage + Sync),
            _key: &CacheKey,
            _trace: &SpanHandle,
        ) -> Result<()> { ... }
    fn can_seek(&self) -> bool { ... }
    fn seek(&mut self, start: usize, end: Option<usize>) -> Result<()> { ... }
    fn should_count_access(&self) -> bool { ... }
    fn get_eviction_weight(&self) -> usize { ... }
    fn as_any(&self) -> &(dyn Any + Send + Sync) { ... }
}
#[async_trait]
impl HandleMiss for MemMissHandler {
    async fn write_body(&mut self, data: bytes::Bytes, eof: bool) -> Result<()> { ... }
    async fn finish(self: Box<Self>) -> Result<usize> { ... }
    fn streaming_write_tag(&self) -> Option<&[u8]> { ... }
}
impl Drop for MemMissHandler {
    fn drop(&mut self) { ... }
}
#[async_trait]
impl Storage for MemCache {
    async fn lookup(
            &'static self,
            key: &CacheKey,
            _trace: &SpanHandle,
        ) -> Result<Option<(CacheMeta, HitHandler)>> { ... }
    async fn lookup_streaming_write(
            &'static self,
            key: &CacheKey,
            streaming_write_tag: Option<&[u8]>,
            _trace: &SpanHandle,
        ) -> Result<Option<(CacheMeta, HitHandler)>> { ... }
    async fn get_miss_handler(
            &'static self,
            key: &CacheKey,
            meta: &CacheMeta,
            _trace: &SpanHandle,
        ) -> Result<MissHandler> { ... }
    async fn purge(
            &'static self,
            key: &CompactCacheKey,
            _type: PurgeType,
            _trace: &SpanHandle,
        ) -> Result<bool> { ... }
    async fn update_meta(
            &'static self,
            key: &CacheKey,
            meta: &CacheMeta,
            _trace: &SpanHandle,
        ) -> Result<bool> { ... }
    fn support_streaming_partial_write(&self) -> bool { ... }
    fn as_any(&self) -> &(dyn Any + Send + Sync) { ... }
}
```
## pingora-cache/src/meta.rs
```rust
pub use http::Extensions;
use pingora_error::{Error, ErrorType::*, OrErr, Result};
use pingora_http::{HMap, ResponseHeader};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};
use crate::key::HashBinary;
use http::StatusCode;
use log::warn;
use once_cell::sync::{Lazy, OnceCell};
use pingora_header_serde::HeaderSerde;
use std::fs::File;
use std::io::Read;
/// The cacheable response header and cache metadata
#[derive(Debug)]
pub struct CacheMeta(pub(crate) Box<CacheMetaInner>); { ... }
/// The default settings to generate [CacheMeta]
pub struct CacheMetaDefaults { ... }
impl CacheMeta {
    /// Create a [CacheMeta] from the given metadata and the response header
    pub fn new(
            fresh_until: SystemTime,
            created: SystemTime,
            stale_while_revalidate_sec: u32,
            stale_if_error_sec: u32,
            header: ResponseHeader,
        ) -> CacheMeta { ... }
    /// When the asset was created/admitted to cache
    pub fn created(&self) -> SystemTime { ... }
    /// The last time the asset was revalidated
    ///
    /// This value will be the same as [Self::created()] if no revalidation ever happens
    pub fn updated(&self) -> SystemTime { ... }
    /// Is the asset still valid
    pub fn is_fresh(&self, time: SystemTime) -> bool { ... }
    /// How long (in seconds) the asset should be fresh since its admission/revalidation
    ///
    /// This is essentially the max-age value (or its equivalence)
    pub fn fresh_sec(&self) -> u64 { ... }
    /// Until when the asset is considered fresh
    pub fn fresh_until(&self) -> SystemTime { ... }
    /// How old the asset is since its admission/revalidation
    pub fn age(&self) -> Duration { ... }
    /// The stale-while-revalidate limit in seconds
    pub fn stale_while_revalidate_sec(&self) -> u32 { ... }
    /// The stale-if-error limit in seconds
    pub fn stale_if_error_sec(&self) -> u32 { ... }
    /// Can the asset be used to serve stale during revalidation at the given time.
    ///
    /// NOTE: the serve stale functions do not check !is_fresh(time),
    /// i.e. the object is already assumed to be stale.
    pub fn serve_stale_while_revalidate(&self, time: SystemTime) -> bool { ... }
    /// Can the asset be used to serve stale after error at the given time.
    ///
    /// NOTE: the serve stale functions do not check !is_fresh(time),
    /// i.e. the object is already assumed to be stale.
    pub fn serve_stale_if_error(&self, time: SystemTime) -> bool { ... }
    /// Disable serve stale for this asset
    pub fn disable_serve_stale(&mut self) { ... }
    /// Get the variance hash of this asset
    pub fn variance(&self) -> Option<HashBinary> { ... }
    /// Set the variance key of this asset
    pub fn set_variance_key(&mut self, variance_key: HashBinary) { ... }
    /// Set the variance (hash) of this asset
    pub fn set_variance(&mut self, variance: HashBinary) { ... }
    /// Removes the variance (hash) of this asset
    pub fn remove_variance(&mut self) { ... }
    /// Get the response header in this asset
    pub fn response_header(&self) -> &ResponseHeader { ... }
    /// Modify the header in this asset
    pub fn response_header_mut(&mut self) -> &mut ResponseHeader { ... }
    /// Expose the extensions to read
    pub fn extensions(&self) -> &Extensions { ... }
    /// Expose the extensions to modify
    pub fn extensions_mut(&mut self) -> &mut Extensions { ... }
    /// Get a copy of the response header
    pub fn response_header_copy(&self) -> ResponseHeader { ... }
    /// get all the headers of this asset
    pub fn headers(&self) -> &HMap { ... }
    /// Serialize this object
    pub fn serialize(&self) -> Result<(Vec<u8>, Vec<u8>)> { ... }
    /// Deserialize from the binary format
    pub fn deserialize(internal: &[u8], header: &[u8]) -> Result<Self> { ... }
}
impl CacheMetaDefaults {
    /// Create a new [CacheMetaDefaults]
    pub const fn new(
            fresh_sec_fn: FreshSecByStatusFn,
            stale_while_revalidate_sec: u32,
            stale_if_error_sec: u32,
        ) -> Self { ... }
    /// Return the default TTL for the given [StatusCode]
    ///
    /// `None`: do no cache this code.
    pub fn fresh_sec(&self, resp_status: StatusCode) -> Option<u32> { ... }
    /// The default SWR seconds
    pub fn serve_stale_while_revalidate_sec(&self) -> u32 { ... }
    /// The default SIE seconds
    pub fn serve_stale_if_error_sec(&self) -> u32 { ... }
}
```
## pingora-cache/src/predictor.rs
```rust
use crate::hashtable::{ConcurrentLruCache, LruShard};
use crate::{key::CacheHashKey, CacheKey, NoCacheReason};
use log::debug;
/// Cacheability Predictor
///
/// Remembers previously uncacheable assets.
/// Allows bypassing cache / cache lock early based on historical precedent.
///
/// NOTE: to simply avoid caching requests with certain characteristics,
/// add checks in request_cache_filter to avoid enabling cache in the first place.
/// The predictor's bypass mechanism handles cases where the request _looks_ cacheable
/// but its previous responses suggest otherwise. The request _could_ be cacheable in the future.
pub struct Predictor<const N_SHARDS: usize> { ... }
/// The cache predictor trait.
///
/// This trait allows user defined predictor to replace [Predictor].
pub trait CacheablePredictor { ... }
impl<const N_SHARDS: usize> Predictor<N_SHARDS>
where
    [LruShard<()>; N_SHARDS]: Default, {
    /// Create a new Predictor with `N_SHARDS * shard_capacity` total capacity for
    /// uncacheable cache keys.
    ///
    /// - `shard_capacity`: defines number of keys remembered as uncacheable per LRU shard.
    /// - `skip_custom_reasons_fn`: an optional predicate used in `mark_uncacheable`
    /// that can customize which `Custom` `NoCacheReason`s ought to be remembered as uncacheable.
    /// If the predicate returns true, then the predictor will skip remembering the current
    /// cache key as uncacheable (and avoid bypassing cache on the next request).
    pub fn new(
            shard_capacity: usize,
            skip_custom_reasons_fn: Option<CustomReasonPredicate>,
        ) -> Predictor<N_SHARDS> { ... }
}
impl<const N_SHARDS: usize> CacheablePredictor for Predictor<N_SHARDS>
where
    [LruShard<()>; N_SHARDS]: Default, {
    fn cacheable_prediction(&self, key: &CacheKey) -> bool { ... }
    fn mark_cacheable(&self, key: &CacheKey) -> bool { ... }
    fn mark_uncacheable(&self, key: &CacheKey, reason: NoCacheReason) -> Option<bool> { ... }
}
```
## pingora-cache/src/put.rs
```rust
use crate::*;
use bytes::Bytes;
use http::header;
use log::warn;
use pingora_core::protocols::http::{
    v1::common::header_value_content_length, HttpTask, ServerSession,
};
use parse_response::ResponseParse;
/// The cache put context
pub struct CachePutCtx<C: CachePut> { ... }
/// The interface to define cache put behavior
pub trait CachePut { ... }
impl<C: CachePut> CachePutCtx<C> {
    /// Create a new [CachePutCtx]
    pub fn new(
            cache_put: C,
            key: CacheKey,
            storage: &'static (dyn storage::Storage + Sync),
            eviction: Option<&'static (dyn eviction::EvictionManager + Sync)>,
            trace: trace::Span,
        ) -> Self { ... }
    /// Set the max cacheable size limit
    pub fn set_max_file_size_bytes(&mut self, max_file_size_bytes: usize) { ... }
    /// Start the cache put logic for the given request
    ///
    /// This function will start to read the request body to put into cache.
    /// Return:
    /// - `Ok(None)` when the payload will be cache.
    /// - `Ok(Some(reason))` when the payload is not cacheable
    pub async fn cache_put(
            &mut self,
            session: &mut ServerSession,
        ) -> Result<Option<NoCacheReason>> { ... }
}
```
## pingora-cache/src/storage.rs
```rust
use super::{CacheKey, CacheMeta};
use crate::key::CompactCacheKey;
use crate::trace::SpanHandle;
use async_trait::async_trait;
use pingora_error::Result;
use std::any::Any;
pub mod streaming_write {
    /// Portable u64 (sized) write id convenience type for use with streaming writes.
    ///
    /// Often an integer value is sufficient for a streaming write tag. This convenience type enables
    /// storing such a value and functions for consistent conversion between byte sequence data types.
    #[derive(Debug, Clone, Copy)]
    pub struct U64WriteId([u8; { ... }
    /// Portable u32 (sized) write id convenience type for use with streaming writes.
    ///
    /// Often an integer value is sufficient for a streaming write tag. This convenience type enables
    /// storing such a value and functions for consistent conversion between byte sequence data types.
    #[derive(Debug, Clone, Copy)]
    pub struct U32WriteId([u8; { ... }
    impl U64WriteId {
        pub fn as_bytes(&self) -> &[u8] { ... }
    }
    impl From<u64> for U64WriteId {
        fn from(value: u64) -> U64WriteId { ... }
    }
    impl From<U64WriteId> for u64 {
        fn from(value: U64WriteId) -> u64 { ... }
    }
    impl TryFrom<&[u8]> for U64WriteId {
        fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> { ... }
    }
    impl U32WriteId {
        pub fn as_bytes(&self) -> &[u8] { ... }
    }
    impl From<u32> for U32WriteId {
        fn from(value: u32) -> U32WriteId { ... }
    }
    impl From<U32WriteId> for u32 {
        fn from(value: U32WriteId) -> u32 { ... }
    }
    impl TryFrom<&[u8]> for U32WriteId {
        fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> { ... }
    }
}
/// The reason a purge() is called
#[derive(Debug, Clone, Copy)]
pub enum PurgeType {
    // For eviction because the cache storage is full
    Eviction,
    // For cache invalidation
    Invalidation,
}
/// Cache storage interface
#[async_trait]
pub trait Storage { ... }
/// Cache hit handling trait
#[async_trait]
pub trait HandleHit { ... }
/// Cache miss handling trait
#[async_trait]
pub trait HandleMiss { ... }
```
## pingora-cache/src/trace.rs
```rust
use cf_rustracing_jaeger::span::SpanContextState;
use std::time::SystemTime;
use crate::{CacheMeta, CachePhase, HitStatus};
pub use cf_rustracing::tag::Tag;
impl CacheTraceCTX {
    pub fn new() -> Self { ... }
    pub fn enable(&mut self, cache_span: Span) { ... }
    pub fn get_cache_span(&self) -> SpanHandle { ... }
    #[inline]
    pub fn child(&self, name: &'static str) -> Span { ... }
    pub fn start_miss_span(&mut self) { ... }
    pub fn get_miss_span(&self) -> SpanHandle { ... }
    pub fn finish_miss_span(&mut self) { ... }
    pub fn start_hit_span(&mut self, phase: CachePhase, hit_status: HitStatus) { ... }
    pub fn get_hit_span(&self) -> SpanHandle { ... }
    pub fn finish_hit_span(&mut self) { ... }
    pub fn log_meta_in_hit_span(&mut self, meta: &CacheMeta) { ... }
    pub fn log_meta_in_miss_span(&mut self, meta: &CacheMeta) { ... }
}
```
## pingora-cache/src/variance.rs
```rust
use std::{borrow::Cow, collections::BTreeMap};
use blake2::Digest;
use crate::key::{Blake2b128, HashBinary};
/// A builder for variance keys, used for distinguishing multiple cached assets
/// at the same URL. This is intended to be easily passed to helper functions,
/// which can each populate a portion of the variance.
pub struct VarianceBuilder<'a> { ... }
impl<'a> VarianceBuilder<'a> {
    /// Create an empty variance key. Has no variance by default - add some variance using
    /// [`Self::add_value`].
    pub fn new() -> Self { ... }
    /// Add a byte string to the variance key. Not sensitive to insertion order.
    /// `value` is intended to take either `&str` or `&[u8]`.
    pub fn add_value(&mut self, name: &'a str, value: &'a (impl AsRef<[u8]> + ?Sized)) { ... }
    /// Move a byte string to the variance key. Not sensitive to insertion order. Useful when
    /// writing helper functions which generate a value then add said value to the VarianceBuilder.
    /// Without this, the helper function would have to move the value to the calling function
    /// to extend its lifetime to at least match the VarianceBuilder.
    pub fn add_owned_value(&mut self, name: &'a str, value: Vec<u8>) { ... }
    /// Check whether this variance key actually has variance, or just refers to the root asset
    pub fn has_variance(&self) -> bool { ... }
    /// Hash this variance key. Returns [`None`] if [`Self::has_variance`] is false.
    pub fn finalize(self) -> Option<HashBinary> { ... }
}
```
## pingora-core/src/apps/http_app.rs
```rust
use async_trait::async_trait;
use http::Response;
use log::{debug, error, trace};
use pingora_http::ResponseHeader;
use std::sync::Arc;
use crate::apps::HttpServerApp;
use crate::modules::http::{HttpModules, ModuleBuilder};
use crate::protocols::http::HttpTask;
use crate::protocols::http::ServerSession;
use crate::protocols::Stream;
use crate::server::ShutdownWatch;
/// A helper struct for HTTP server with http modules embedded
pub struct HttpServer<SV> { ... }
/// This trait defines how to map a request to a response
#[async_trait]
pub trait ServeHttp { ... }
#[async_trait]
impl<SV> HttpServerApp for SV
where
    SV: ServeHttp + Send + Sync, {
    async fn process_new_http(
            self: &Arc<Self>,
            mut http: ServerSession,
            shutdown: &ShutdownWatch,
        ) -> Option<Stream> { ... }
}
impl<SV> HttpServer<SV> {
    /// Create a new [HttpServer] with the given app which implements [ServeHttp]
    pub fn new_app(app: SV) -> Self { ... }
    /// Add [ModuleBuilder] to this [HttpServer]
    pub fn add_module(&mut self, module: ModuleBuilder) { ... }
}
#[async_trait]
impl<SV> HttpServerApp for HttpServer<SV>
where
    SV: ServeHttp + Send + Sync, {
    async fn process_new_http(
            self: &Arc<Self>,
            mut http: ServerSession,
            shutdown: &ShutdownWatch,
        ) -> Option<Stream> { ... }
}
```
## pingora-core/src/apps/mod.rs
```rust
use crate::server::ShutdownWatch;
use async_trait::async_trait;
use log::{debug, error};
use std::future::poll_fn;
use std::sync::Arc;
use crate::protocols::http::v2::server;
use crate::protocols::http::ServerSession;
use crate::protocols::Digest;
use crate::protocols::Stream;
use crate::protocols::ALPN;
pub mod http_app {
}
pub mod prometheus_http_app {
}
/// HTTP Server options that control how the server handles some transport types.
pub struct HttpServerOptions { ... }
/// This trait defines the interface of a transport layer (TCP or TLS) application.
pub trait ServerApp { ... }
/// This trait defines the interface of an HTTP application.
#[async_trait]
pub trait HttpServerApp { ... }
#[async_trait]
impl<T> ServerApp for T
where
    T: HttpServerApp + Send + Sync + 'static, {
    async fn process_new(
            self: &Arc<Self>,
            mut stream: Stream,
            shutdown: &ShutdownWatch,
        ) -> Option<Stream> { ... }
    async fn cleanup(&self) { ... }
}
```
## pingora-core/src/apps/prometheus_http_app.rs
```rust
use async_trait::async_trait;
use http::Response;
use prometheus::{Encoder, TextEncoder};
use super::http_app::HttpServer;
use crate::apps::http_app::ServeHttp;
use crate::modules::http::compression::ResponseCompressionBuilder;
use crate::protocols::http::ServerSession;
/// An HTTP application that reports Prometheus metrics.
///
/// This application will report all the [static metrics](https://docs.rs/prometheus/latest/prometheus/index.html#static-metrics)
/// collected via the [Prometheus](https://docs.rs/prometheus/) crate;
pub struct PrometheusHttpApp; { ... }
#[async_trait]
impl ServeHttp for PrometheusHttpApp {
    async fn response(&self, _http_session: &mut ServerSession) -> Response<Vec<u8>> { ... }
}
impl PrometheusServer {
    pub fn new() -> Self { ... }
}
```
## pingora-core/src/connectors/http/mod.rs
```rust
use crate::connectors::ConnectorOptions;
use crate::protocols::http::client::HttpSession;
use crate::upstreams::peer::Peer;
use pingora_error::Result;
use std::time::Duration;
pub mod v1 {
}
pub mod v2 {
}
pub struct Connector { ... }
impl Connector {
    pub fn new(options: Option<ConnectorOptions>) -> Self { ... }
    /// Get an [HttpSession] to the given server.
    ///
    /// The second return value indicates whether the session is connected via a reused stream.
    pub async fn get_http_session<P: Peer + Send + Sync + 'static>(
            &self,
            peer: &P,
        ) -> Result<(HttpSession, bool)> { ... }
    pub async fn release_http_session<P: Peer + Send + Sync + 'static>(
            &self,
            session: HttpSession,
            peer: &P,
            idle_timeout: Option<Duration>,
        ) { ... }
    /// Tell the connector to always send h1 for ALPN for the given peer in the future.
    pub fn prefer_h1(&self, peer: &impl Peer) { ... }
}
```
## pingora-core/src/connectors/http/v1.rs
```rust
use crate::connectors::{ConnectorOptions, TransportConnector};
use crate::protocols::http::v1::client::HttpSession;
use crate::upstreams::peer::Peer;
use pingora_error::Result;
use std::time::Duration;
pub struct Connector { ... }
impl Connector {
    pub fn new(options: Option<ConnectorOptions>) -> Self { ... }
    pub async fn get_http_session<P: Peer + Send + Sync + 'static>(
            &self,
            peer: &P,
        ) -> Result<(HttpSession, bool)> { ... }
    pub async fn reused_http_session<P: Peer + Send + Sync + 'static>(
            &self,
            peer: &P,
        ) -> Option<HttpSession> { ... }
    pub async fn release_http_session<P: Peer + Send + Sync + 'static>(
            &self,
            mut session: HttpSession,
            peer: &P,
            idle_timeout: Option<Duration>,
        ) { ... }
}
```
## pingora-core/src/connectors/http/v2.rs
```rust
use super::HttpSession;
use crate::connectors::{ConnectorOptions, TransportConnector};
use crate::protocols::http::v1::client::HttpSession as Http1Session;
use crate::protocols::http::v2::client::{drive_connection, Http2Session};
use crate::protocols::{Digest, Stream, UniqueIDType};
use crate::upstreams::peer::{Peer, ALPN};
use bytes::Bytes;
use h2::client::SendRequest;
use log::debug;
use parking_lot::{Mutex, RwLock};
use pingora_error::{Error, ErrorType::*, OrErr, Result};
use pingora_pool::{ConnectionMeta, ConnectionPool, PoolNode};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
/// Http2 connector
pub struct Connector { ... }
impl ConnectionRef {
    pub fn new(
            send_req: SendRequest<Bytes>,
            closed: watch::Receiver<bool>,
            ping_timeout_occurred: Arc<AtomicBool>,
            id: UniqueIDType,
            max_streams: usize,
            digest: Digest,
        ) -> Self { ... }
    pub fn more_streams_allowed(&self) -> bool { ... }
    pub fn is_idle(&self) -> bool { ... }
    pub fn release_stream(&self) { ... }
    pub fn id(&self) -> UniqueIDType { ... }
    pub fn digest(&self) -> &Digest { ... }
    pub fn digest_mut(&mut self) -> Option<&mut Digest> { ... }
    pub fn ping_timedout(&self) -> bool { ... }
    pub fn is_closed(&self) -> bool { ... }
    pub fn is_shutting_down(&self) -> bool { ... }
    pub async fn spawn_stream(&self) -> Result<Option<Http2Session>> { ... }
}
impl Connector {
    /// Create a new [Connector] from the given [ConnectorOptions]
    pub fn new(options: Option<ConnectorOptions>) -> Self { ... }
    /// Create a new Http2 connection to the given server
    ///
    /// Either an Http2 or Http1 session can be returned depending on the server's preference.
    pub async fn new_http_session<P: Peer + Send + Sync + 'static>(
            &self,
            peer: &P,
        ) -> Result<HttpSession> { ... }
    /// Try to create a new http2 stream from any existing H2 connection.
    ///
    /// None means there is no "free" connection left.
    pub async fn reused_http_session<P: Peer + Send + Sync + 'static>(
            &self,
            peer: &P,
        ) -> Result<Option<Http2Session>> { ... }
    /// Release a finished h2 stream.
    ///
    /// This function will terminate the [Http2Session]. The corresponding h2 connection will now
    /// have one more free stream to use.
    ///
    /// The h2 connection will be closed after `idle_timeout` if it has no active streams.
    pub fn release_http_session<P: Peer + Send + Sync + 'static>(
            &self,
            session: Http2Session,
            peer: &P,
            idle_timeout: Option<Duration>,
        ) { ... }
    /// Tell the connector to always send h1 for ALPN for the given peer in the future.
    pub fn prefer_h1(&self, peer: &impl Peer) { ... }
}
```
## pingora-core/src/connectors/l4.rs
```rust
use crate::protocols::l4::ext::connect_uds;
use crate::protocols::l4::ext::{
    connect_with as tcp_connect, set_dscp, set_recv_buf, set_tcp_fastopen_connect,
};
use crate::protocols::l4::socket::SocketAddr;
use crate::protocols::l4::stream::Stream;
use crate::protocols::{GetSocketDigest, SocketDigest};
use crate::upstreams::peer::Peer;
use async_trait::async_trait;
use log::debug;
use pingora_error::{Context, Error, ErrorType::*, OrErr, Result};
use rand::seq::SliceRandom;
use std::net::SocketAddr as InetSocketAddr;
use std::os::unix::io::AsRawFd;
use std::os::windows::io::AsRawSocket;
use crate::protocols::raw_connect;
/// Settings for binding on connect
#[derive(Clone, Debug, Default)]
pub struct BindTo { ... }
/// The interface to establish a L4 connection
#[async_trait]
pub trait Connect { ... }
impl BindTo {
    /// Sets the port range we will bind to where the first item in the tuple is the lower bound
    /// and the second item is the upper bound.
    ///
    /// Note this bind option is only supported on Linux since 6.3, this is a no-op on other systems.
    /// To reset the range, pass a `None` or `Some((0,0))`, more information can be found [here](https://man7.org/linux/man-pages/man7/ip.7.html)
    pub fn set_port_range(&mut self, range: Option<(u16, u16)>) -> Result<()> { ... }
    /// Set whether we fallback on no address available if a port range is set
    pub fn set_fallback(&mut self, fallback: bool) { ... }
    /// Configured bind port range
    pub fn port_range(&self) -> Option<(u16, u16)> { ... }
    /// Whether we attempt to fallback on no address available
    pub fn will_fallback(&self) -> bool { ... }
}
```
## pingora-core/src/connectors/mod.rs
```rust
use crate::tls::connectors as tls;
use crate::protocols::Stream;
use crate::server::configuration::ServerConf;
use crate::upstreams::peer::{Peer, ALPN};
pub use l4::Connect as L4Connect;
use l4::{connect as l4_connect, BindTo};
use log::{debug, error, warn};
use offload::OffloadRuntime;
use parking_lot::RwLock;
use pingora_error::{Error, ErrorType::*, OrErr, Result};
use pingora_pool::{ConnectionMeta, ConnectionPool};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tls::TlsConnector;
use tokio::sync::Mutex;
use futures::future::FutureExt;
use tokio::io::AsyncReadExt;
pub mod http {
}
pub mod l4 {
}
/// The options to configure a [TransportConnector]
#[derive(Clone)]
pub struct ConnectorOptions { ... }
/// [TransportConnector] provides APIs to connect to servers via TCP or TLS with connection reuse
pub struct TransportConnector { ... }
impl ConnectorOptions {
    /// Derive the [ConnectorOptions] from a [ServerConf]
    pub fn from_server_conf(server_conf: &ServerConf) -> Self { ... }
    /// Create a new [ConnectorOptions] with the given keepalive pool size
    pub fn new(keepalive_pool_size: usize) -> Self { ... }
}
impl TransportConnector {
    /// Create a new [TransportConnector] with the given [ConnectorOptions]
    pub fn new(mut options: Option<ConnectorOptions>) -> Self { ... }
    /// Connect to the given server [Peer]
    ///
    /// No connection is reused.
    pub async fn new_stream<P: Peer + Send + Sync + 'static>(&self, peer: &P) -> Result<Stream> { ... }
    /// Try to find a reusable connection to the given server [Peer]
    pub async fn reused_stream<P: Peer + Send + Sync>(&self, peer: &P) -> Option<Stream> { ... }
    /// Return the [Stream] to the [TransportConnector] for connection reuse.
    ///
    /// Not all TCP/TLS connections can be reused. It is the caller's responsibility to make sure
    /// that protocol over the [Stream] supports connection reuse and the [Stream] itself is ready
    /// to be reused.
    ///
    /// If a [Stream] is dropped instead of being returned via this function. it will be closed.
    pub fn release_stream(
            &self,
            mut stream: Stream,
            key: u64, // usually peer.reuse_hash()
            idle_timeout: Option<std::time::Duration>,
        ) { ... }
    /// Get a stream to the given server [Peer]
    ///
    /// This function will try to find a reusable [Stream] first. If there is none, a new connection
    /// will be made to the server.
    ///
    /// The returned boolean will indicate whether the stream is reused.
    pub async fn get_stream<P: Peer + Send + Sync + 'static>(
            &self,
            peer: &P,
        ) -> Result<(Stream, bool)> { ... }
    /// Tell the connector to always send h1 for ALPN for the given peer in the future.
    pub fn prefer_h1(&self, peer: &impl Peer) { ... }
}
impl PreferredHttpVersion {
    pub fn new() -> Self { ... }
    pub fn add(&self, peer: &impl Peer, version: u8) { ... }
    pub fn get(&self, peer: &impl Peer) -> Option<ALPN> { ... }
}
```
## pingora-core/src/connectors/offload.rs
```rust
use log::debug;
use once_cell::sync::OnceCell;
use rand::Rng;
use tokio::runtime::{Builder, Handle};
use tokio::sync::oneshot::{channel, Sender};
impl OffloadRuntime {
    pub fn new(shards: usize, thread_per_shard: usize) -> Self { ... }
    pub fn get_runtime(&self, hash: u64) -> &Handle { ... }
}
```
## pingora-core/src/connectors/tls/boringssl_openssl/mod.rs
```rust
use log::debug;
use pingora_error::{Error, ErrorType::*, OrErr, Result};
use std::sync::{Arc, Once};
use crate::connectors::tls::replace_leftmost_underscore;
use crate::connectors::ConnectorOptions;
use crate::protocols::tls::client::handshake;
use crate::protocols::tls::SslStream;
use crate::protocols::IO;
use crate::tls::ext::{
    add_host, clear_error_stack, ssl_add_chain_cert, ssl_set_groups_list,
    ssl_set_renegotiate_mode_freely, ssl_set_verify_cert_store, ssl_use_certificate,
    ssl_use_private_key, ssl_use_second_key_share,
};
use crate::tls::ssl::SslCurve;
use crate::tls::ssl::{SslConnector, SslFiletype, SslMethod, SslVerifyMode, SslVersion};
use crate::tls::x509::store::X509StoreBuilder;
use crate::upstreams::peer::{Peer, ALPN};
#[derive(Clone)]
pub struct Connector { ... }
impl Connector {
    pub fn new(options: Option<ConnectorOptions>) -> Self { ... }
}
```
## pingora-core/src/connectors/tls/mod.rs
```rust
pub use boringssl_openssl::*;
pub use rustls::*;
/// OpenSSL considers underscores in hostnames non-compliant.
/// We replace the underscore in the leftmost label as we must support these
/// hostnames for wildcard matches and we have not patched OpenSSL.
///
/// https://github.com/openssl/openssl/issues/12566
///
/// > The labels must follow the rules for ARPANET host names. They must
/// > start with a letter, end with a letter or digit, and have as interior
/// > characters only letters, digits, and hyphen.  There are also some
/// > restrictions on the length.  Labels must be 63 characters or less.
/// - https://datatracker.ietf.org/doc/html/rfc1034#section-3.5
#[cfg(feature = "any_tls")]
pub fn replace_leftmost_underscore(sni: &str) -> Option<String> { ... }
```
## pingora-core/src/connectors/tls/rustls/mod.rs
```rust
use std::sync::Arc;
use log::debug;
use pingora_error::{
    Error,
    ErrorType::{ConnectTimedout, InvalidCert},
    OrErr, Result,
};
use pingora_rustls::{
    load_ca_file_into_store, load_certs_and_key_files, load_platform_certs_incl_env_into_store,
    version, CertificateDer, ClientConfig as RusTlsClientConfig, PrivateKeyDer, RootCertStore,
    TlsConnector as RusTlsConnector,
};
use crate::protocols::tls::{client::handshake, TlsStream};
use crate::{connectors::ConnectorOptions, listeners::ALPN, protocols::IO, upstreams::peer::Peer};
use super::replace_leftmost_underscore;
pub async fn connect<T, P>(
    stream: T,
    peer: &P,
    alpn_override: Option<ALPN>,
    tls_ctx: &TlsConnector,
) -> Result<TlsStream<T>>
where
    T: IO,
    P: Peer + Send + Sync, { ... }
#[derive(Clone)]
pub struct Connector { ... }
pub struct TlsConnector { ... }
impl Connector {
    /// Create a new connector based on the optional configurations. If no
    /// configurations are provided, no customized certificates or keys will be
    /// used
    pub fn new(config_opt: Option<ConnectorOptions>) -> Self { ... }
}
```
## pingora-core/src/lib.rs
```rust
pub use pingora_error::{ErrorType::*, *};
pub use pingora_boringssl as tls;
pub use pingora_openssl as tls;
pub use pingora_rustls as tls;
pub use protocols::tls::noop_tls as tls;
pub mod apps {
}
pub mod connectors {
}
pub mod listeners {
}
pub mod modules {
}
pub mod protocols {
}
pub mod server {
}
pub mod services {
}
pub mod upstreams {
}
pub mod utils {
}
pub mod prelude {
    pub use crate::server::configuration::Opt;
    pub use crate::server::Server;
    pub use crate::services::background::background_service;
    pub use crate::upstreams::peer::HttpPeer;
    pub use pingora_error::{ErrorType::*, *};
}
```
## pingora-core/src/listeners/l4.rs
```rust
use log::warn;
use pingora_error::{
    ErrorType::{AcceptError, BindError},
    OrErr, Result,
};
use std::io::ErrorKind;
use std::net::{SocketAddr, ToSocketAddrs};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixListener as StdUnixListener;
use std::os::windows::io::{AsRawSocket, FromRawSocket};
use std::time::Duration;
use std::{fs::Permissions, sync::Arc};
use tokio::net::TcpSocket;
use crate::protocols::l4::ext::{set_dscp, set_tcp_fastopen_backlog};
use crate::protocols::l4::listener::Listener;
pub use crate::protocols::l4::stream::Stream;
use crate::protocols::TcpKeepalive;
use crate::server::ListenFds;
/// Address for listening server, either TCP/UDS socket.
#[derive(Clone, Debug)]
pub enum ServerAddress {
    Tcp(String, Option<TcpSocketOptions>),
    #[cfg(unix)]
    Uds(String, Option<Permissions>),
}
/// TCP socket configuration options, this is used for setting options on
/// listening sockets and accepted connections.
#[non_exhaustive]
#[derive(Clone, Debug, Default)]
pub struct TcpSocketOptions { ... }
#[derive(Clone)]
pub struct ListenerEndpoint { ... }
#[derive(Default)]
pub struct ListenerEndpointBuilder { ... }
impl AsRef<str> for ServerAddress {
    fn as_ref(&self) -> &str { ... }
}
impl ListenerEndpointBuilder {
    pub fn new() -> ListenerEndpointBuilder { ... }
    pub fn listen_addr(&mut self, addr: ServerAddress) -> &mut Self { ... }
    #[cfg(unix)]
    pub async fn listen(self, fds: Option<ListenFds>) -> Result<ListenerEndpoint> { ... }
    #[cfg(windows)]
    pub async fn listen(self) -> Result<ListenerEndpoint> { ... }
}
impl ListenerEndpoint {
    pub fn builder() -> ListenerEndpointBuilder { ... }
    pub fn as_str(&self) -> &str { ... }
    pub async fn accept(&self) -> Result<Stream> { ... }
}
```
## pingora-core/src/listeners/mod.rs
```rust
pub use crate::tls::listeners as tls;
use crate::protocols::{l4::socket::SocketAddr, tls::TlsRef, Stream};
use crate::server::ListenFds;
use async_trait::async_trait;
use pingora_error::Result;
use std::{fs::Permissions, sync::Arc};
use l4::{ListenerEndpoint, Stream as L4Stream};
use tls::{Acceptor, TlsSettings};
pub use crate::protocols::tls::ALPN;
use crate::protocols::GetSocketDigest;
pub use l4::{ServerAddress, TcpSocketOptions};
#[cfg(feature = "any_tls")]
pub mod tls {
}
/// The struct to hold one more multiple listening endpoints
pub struct Listeners { ... }
/// The APIs to customize things like certificate during TLS server side handshake
#[async_trait]
pub trait TlsAccept { ... }
impl TransportStackBuilder {
    pub async fn build(
            &mut self,
            #[cfg(unix)] upgrade_listeners: Option<ListenFds>,
        ) -> Result<TransportStack> { ... }
}
impl TransportStack {
    pub fn as_str(&self) -> &str { ... }
    pub async fn accept(&self) -> Result<UninitializedStream> { ... }
    pub fn cleanup(&mut self) { ... }
}
impl UninitializedStream {
    pub async fn handshake(mut self) -> Result<Stream> { ... }
    /// Get the peer address of the connection if available
    pub fn peer_addr(&self) -> Option<SocketAddr> { ... }
}
impl Listeners {
    /// Create a new [`Listeners`] with no listening endpoints.
    pub fn new() -> Self { ... }
    /// Create a new [`Listeners`] with a TCP server endpoint from the given string.
    pub fn tcp(addr: &str) -> Self { ... }
    /// Create a new [`Listeners`] with a Unix domain socket endpoint from the given string.
    #[cfg(unix)]
    pub fn uds(addr: &str, perm: Option<Permissions>) -> Self { ... }
    /// Create a new [`Listeners`] with a TLS (TCP) endpoint with the given address string,
    /// and path to the certificate/private key pairs.
    /// This endpoint will adopt the [Mozilla Intermediate](https://wiki.mozilla.org/Security/Server_Side_TLS#Intermediate_compatibility_.28recommended.29)
    /// server side TLS settings.
    pub fn tls(addr: &str, cert_path: &str, key_path: &str) -> Result<Self> { ... }
    /// Add a TCP endpoint to `self`.
    pub fn add_tcp(&mut self, addr: &str) { ... }
    /// Add a TCP endpoint to `self`, with the given [`TcpSocketOptions`].
    pub fn add_tcp_with_settings(&mut self, addr: &str, sock_opt: TcpSocketOptions) { ... }
    /// Add a Unix domain socket endpoint to `self`.
    #[cfg(unix)]
    pub fn add_uds(&mut self, addr: &str, perm: Option<Permissions>) { ... }
    /// Add a TLS endpoint to `self` with the [Mozilla Intermediate](https://wiki.mozilla.org/Security/Server_Side_TLS#Intermediate_compatibility_.28recommended.29)
    /// server side TLS settings.
    pub fn add_tls(&mut self, addr: &str, cert_path: &str, key_path: &str) -> Result<()> { ... }
    /// Add a TLS endpoint to `self` with the given socket and server side TLS settings.
    /// See [`TlsSettings`] and [`TcpSocketOptions`] for more details.
    pub fn add_tls_with_settings(
            &mut self,
            addr: &str,
            sock_opt: Option<TcpSocketOptions>,
            settings: TlsSettings,
        ) { ... }
    /// Add the given [`ServerAddress`] to `self`.
    pub fn add_address(&mut self, addr: ServerAddress) { ... }
    /// Add the given [`ServerAddress`] to `self` with the given [`TlsSettings`] if provided
    pub fn add_endpoint(&mut self, l4: ServerAddress, tls: Option<TlsSettings>) { ... }
}
```
## pingora-core/src/listeners/tls/boringssl_openssl/mod.rs
```rust
use log::debug;
use pingora_error::{ErrorType, OrErr, Result};
use std::ops::{Deref, DerefMut};
pub use crate::protocols::tls::ALPN;
use crate::protocols::IO;
use crate::tls::ssl::{SslAcceptor, SslAcceptorBuilder, SslFiletype, SslMethod};
use crate::{
    listeners::TlsAcceptCallbacks,
    protocols::tls::{
        server::{handshake, handshake_with_callback},
        SslStream,
    },
};
/// The TLS settings of a listening endpoint
pub struct TlsSettings { ... }
impl From<SslAcceptorBuilder> for TlsSettings {
    fn from(settings: SslAcceptorBuilder) -> Self { ... }
}
impl Deref for TlsSettings {
    fn deref(&self) -> &Self::Target { ... }
}
impl DerefMut for TlsSettings {
    fn deref_mut(&mut self) -> &mut Self::Target { ... }
}
impl TlsSettings {
    /// Create a new [`TlsSettings`] with the [Mozilla Intermediate](https://wiki.mozilla.org/Security/Server_Side_TLS#Intermediate_compatibility_.28recommended.29)
    /// server side TLS settings. Users can adjust the TLS settings after this object is created.
    /// Return error if the provided certificate and private key are invalid or not found.
    pub fn intermediate(cert_path: &str, key_path: &str) -> Result<Self> { ... }
    /// Create a new [`TlsSettings`] similar to [TlsSettings::intermediate()]. A struct that implements [TlsAcceptCallbacks]
    /// is needed to provide the certificate during the TLS handshake.
    pub fn with_callbacks(callbacks: TlsAcceptCallbacks) -> Result<Self> { ... }
    /// Enable HTTP/2 support for this endpoint, which is default off.
    /// This effectively sets the ALPN to prefer HTTP/2 with HTTP/1.1 allowed
    pub fn enable_h2(&mut self) { ... }
    /// Set the ALPN preference of this endpoint. See [`ALPN`] for more details
    pub fn set_alpn(&mut self, alpn: ALPN) { ... }
}
impl Acceptor {
    pub async fn tls_handshake<S: IO>(&self, stream: S) -> Result<SslStream<S>> { ... }
}
```
## pingora-core/src/listeners/tls/mod.rs
```rust
pub use boringssl_openssl::*;
pub use rustls::*;
```
## pingora-core/src/listeners/tls/rustls/mod.rs
```rust
use std::sync::Arc;
use crate::listeners::TlsAcceptCallbacks;
use crate::protocols::tls::{server::handshake, server::handshake_with_callback, TlsStream};
use log::debug;
use pingora_error::ErrorType::InternalError;
use pingora_error::{Error, OrErr, Result};
use pingora_rustls::load_certs_and_key_files;
use pingora_rustls::ServerConfig;
use pingora_rustls::{version, TlsAcceptor as RusTlsAcceptor};
use crate::protocols::{ALPN, IO};
/// The TLS settings of a listening endpoint
pub struct TlsSettings { ... }
pub struct Acceptor { ... }
impl TlsSettings {
    /// Create a Rustls acceptor based on the current setting for certificates,
    /// keys, and protocols.
    ///
    /// _NOTE_ This function will panic if there is an error in loading
    /// certificate files or constructing the builder
    ///
    /// Todo: Return a result instead of panicking XD
    pub fn build(self) -> Acceptor { ... }
    /// Enable HTTP/2 support for this endpoint, which is default off.
    /// This effectively sets the ALPN to prefer HTTP/2 with HTTP/1.1 allowed
    pub fn enable_h2(&mut self) { ... }
    pub fn intermediate(cert_path: &str, key_path: &str) -> Result<Self>
        where
            Self: Sized, { ... }
    pub fn with_callbacks() -> Result<Self>
        where
            Self: Sized, { ... }
}
impl Acceptor {
    pub async fn tls_handshake<S: IO>(&self, stream: S) -> Result<TlsStream<S>> { ... }
}
```
## pingora-core/src/modules/http/compression.rs
```rust
use super::*;
use crate::protocols::http::compression::ResponseCompressionCtx;
use std::ops::{Deref, DerefMut};
/// HTTP response compression module
pub struct ResponseCompression(ResponseCompressionCtx); { ... }
/// The builder for HTTP response compression module
pub struct ResponseCompressionBuilder { ... }
impl Deref for ResponseCompression {
    fn deref(&self) -> &Self::Target { ... }
}
impl DerefMut for ResponseCompression {
    fn deref_mut(&mut self) -> &mut Self::Target { ... }
}
#[async_trait]
impl HttpModule for ResponseCompression {
    fn as_any(&self) -> &dyn std::any::Any { ... }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { ... }
    async fn request_header_filter(&mut self, req: &mut RequestHeader) -> Result<()> { ... }
    async fn response_header_filter(
            &mut self,
            resp: &mut ResponseHeader,
            end_of_stream: bool,
        ) -> Result<()> { ... }
    fn response_body_filter(
            &mut self,
            body: &mut Option<Bytes>,
            end_of_stream: bool,
        ) -> Result<()> { ... }
}
impl ResponseCompressionBuilder {
    /// Return a [ModuleBuilder] for [ResponseCompression] with the given compression level
    pub fn enable(level: u32) -> ModuleBuilder { ... }
}
impl HttpModuleBuilder for ResponseCompressionBuilder {
    fn init(&self) -> Module { ... }
    fn order(&self) -> i16 { ... }
}
```
## pingora-core/src/modules/http/grpc_web.rs
```rust
use super::*;
use crate::protocols::http::bridge::grpc_web::GrpcWebCtx;
use std::ops::{Deref, DerefMut};
/// gRPC-web bridge module, this will convert
/// HTTP/1.1 gRPC-web requests to H2 gRPC requests
#[derive(Default)]
pub struct GrpcWebBridge(GrpcWebCtx); { ... }
/// The builder for gRPC-web bridge module
pub struct GrpcWeb; { ... }
impl Deref for GrpcWebBridge {
    fn deref(&self) -> &Self::Target { ... }
}
impl DerefMut for GrpcWebBridge {
    fn deref_mut(&mut self) -> &mut Self::Target { ... }
}
#[async_trait]
impl HttpModule for GrpcWebBridge {
    fn as_any(&self) -> &dyn std::any::Any { ... }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { ... }
    async fn request_header_filter(&mut self, req: &mut RequestHeader) -> Result<()> { ... }
    async fn response_header_filter(
            &mut self,
            resp: &mut ResponseHeader,
            _end_of_stream: bool,
        ) -> Result<()> { ... }
    fn response_trailer_filter(
            &mut self,
            trailers: &mut Option<Box<HeaderMap>>,
        ) -> Result<Option<Bytes>> { ... }
}
impl HttpModuleBuilder for GrpcWeb {
    fn init(&self) -> Module { ... }
}
```
## pingora-core/src/modules/http/mod.rs
```rust
use async_trait::async_trait;
use bytes::Bytes;
use http::HeaderMap;
use once_cell::sync::OnceCell;
use pingora_error::Result;
use pingora_http::{RequestHeader, ResponseHeader};
use std::any::Any;
use std::any::TypeId;
use std::collections::HashMap;
use std::sync::Arc;
pub mod compression {
}
pub mod grpc_web {
}
/// The object to hold multiple http modules
pub struct HttpModules { ... }
/// The Contexts of multiple modules
///
/// This is the object that will apply all the included modules to a certain HTTP request.
/// The modules are ordered according to their `order()`.
pub struct HttpModuleCtx { ... }
/// The trait an HTTP traffic module needs to implement
#[async_trait]
pub trait HttpModule { ... }
/// Trait to init the http module ctx for each request
pub trait HttpModuleBuilder { ... }
impl HttpModules {
    /// Create a new [HttpModules]
    pub fn new() -> Self { ... }
    /// Add a new [ModuleBuilder] to [HttpModules]
    ///
    /// Each type of [HttpModule] can be only added once.
    /// # Panic
    /// Panic if any [HttpModule] is added more than once.
    pub fn add_module(&mut self, builder: ModuleBuilder) { ... }
    /// Build the contexts of all the modules added to this [HttpModules]
    pub fn build_ctx(&self) -> HttpModuleCtx { ... }
}
impl HttpModuleCtx {
    /// Create a placeholder empty [HttpModuleCtx].
    ///
    /// [HttpModules] should be used to create nonempty [HttpModuleCtx].
    pub fn empty() -> Self { ... }
    /// Get a ref to [HttpModule] if any.
    pub fn get<T: 'static>(&self) -> Option<&T> { ... }
    /// Get a mut ref to [HttpModule] if any.
    pub fn get_mut<T: 'static>(&mut self) -> Option<&mut T> { ... }
    /// Run the `request_header_filter` for all the modules according to their orders.
    pub async fn request_header_filter(&mut self, req: &mut RequestHeader) -> Result<()> { ... }
    /// Run the `request_body_filter` for all the modules according to their orders.
    pub async fn request_body_filter(
            &mut self,
            body: &mut Option<Bytes>,
            end_of_stream: bool,
        ) -> Result<()> { ... }
    /// Run the `response_header_filter` for all the modules according to their orders.
    pub async fn response_header_filter(
            &mut self,
            req: &mut ResponseHeader,
            end_of_stream: bool,
        ) -> Result<()> { ... }
    /// Run the `response_body_filter` for all the modules according to their orders.
    pub fn response_body_filter(
            &mut self,
            body: &mut Option<Bytes>,
            end_of_stream: bool,
        ) -> Result<()> { ... }
    /// Run the `response_trailer_filter` for all the modules according to their orders.
    ///
    /// Returns an `Option<Bytes>` which can be used to write response trailers into
    /// the response body. Note, if multiple modules attempt to write trailers into
    /// the body the last one will be used.
    ///
    /// Implementors that intend to write trailers into the body need to ensure their filter
    /// is using an encoding that supports this.
    pub fn response_trailer_filter(
            &mut self,
            trailers: &mut Option<Box<HeaderMap>>,
        ) -> Result<Option<Bytes>> { ... }
}
```
## pingora-core/src/modules/mod.rs
```rust
pub mod http {
}
```
## pingora-core/src/protocols/digest.rs
```rust
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use once_cell::sync::OnceCell;
use super::l4::ext::{get_original_dest, get_recv_buf, get_tcp_info, TCP_INFO};
use super::l4::socket::SocketAddr;
use super::raw_connect::ProxyDigest;
use super::tls::digest::SslDigest;
/// The information can be extracted from a connection
#[derive(Clone, Debug, Default)]
pub struct Digest { ... }
/// The timing information of the connection
#[derive(Clone, Debug)]
pub struct TimingDigest { ... }
/// The interface to return socket-related information
pub struct SocketDigest { ... }
/// The interface to return protocol related information
pub trait ProtoDigest { ... }
/// The interface to return timing information
pub trait GetTimingDigest { ... }
/// The interface to set or return proxy information
pub trait GetProxyDigest { ... }
/// The interface to set or return socket information
pub trait GetSocketDigest { ... }
impl Default for TimingDigest {
    fn default() -> Self { ... }
}
impl SocketDigest {
    #[cfg(unix)]
    pub fn from_raw_fd(raw_fd: std::os::unix::io::RawFd) -> SocketDigest { ... }
    #[cfg(windows)]
    pub fn from_raw_socket(raw_sock: std::os::windows::io::RawSocket) -> SocketDigest { ... }
    #[cfg(unix)]
    pub fn peer_addr(&self) -> Option<&SocketAddr> { ... }
    #[cfg(windows)]
    pub fn peer_addr(&self) -> Option<&SocketAddr> { ... }
    #[cfg(unix)]
    pub fn local_addr(&self) -> Option<&SocketAddr> { ... }
    #[cfg(windows)]
    pub fn local_addr(&self) -> Option<&SocketAddr> { ... }
    #[cfg(unix)]
    pub fn tcp_info(&self) -> Option<TCP_INFO> { ... }
    #[cfg(windows)]
    pub fn tcp_info(&self) -> Option<TCP_INFO> { ... }
    #[cfg(unix)]
    pub fn get_recv_buf(&self) -> Option<usize> { ... }
    #[cfg(windows)]
    pub fn get_recv_buf(&self) -> Option<usize> { ... }
    #[cfg(unix)]
    pub fn original_dst(&self) -> Option<&SocketAddr> { ... }
    #[cfg(windows)]
    pub fn original_dst(&self) -> Option<&SocketAddr> { ... }
}
```
## pingora-core/src/protocols/http/body_buffer.rs
```rust
use bytes::{Bytes, BytesMut};
impl FixedBuffer {
    pub fn new(capacity: usize) -> Self { ... }
    pub fn write_to_buffer(&mut self, data: &Bytes) { ... }
    pub fn clear(&mut self) { ... }
    pub fn is_empty(&self) -> bool { ... }
    pub fn is_truncated(&self) -> bool { ... }
    pub fn get_buffer(&self) -> Option<Bytes> { ... }
}
```
## pingora-core/src/protocols/http/bridge/grpc_web.rs
```rust
use bytes::{BufMut, Bytes, BytesMut};
use http::{
    header::{CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING},
    HeaderMap,
};
use pingora_error::{ErrorType::ReadError, OrErr, Result};
use pingora_http::{RequestHeader, ResponseHeader};
/// Used for bridging gRPC to gRPC-web and vice-versa.
/// See gRPC-web [spec](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-WEB.md) and
/// gRPC h2 [spec](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md) for more details.
#[derive(Default, PartialEq, Debug)]
pub enum GrpcWebCtx {
    #[default]
    Disabled,
    Init,
    Upgrade,
    Trailers,
    Done,
}
impl GrpcWebCtx {
    pub fn init(&mut self) { ... }
    /// gRPC-web request is fed into this filter, if the module is initialized
    /// we attempt to convert it to a gRPC request
    pub fn request_header_filter(&mut self, req: &mut RequestHeader) { ... }
    /// gRPC response is fed into this filter, if the module is in the bridge state
    /// attempt to convert the response it to a gRPC-web response
    pub fn response_header_filter(&mut self, resp: &mut ResponseHeader) { ... }
    /// Used to convert gRPC trailers into gRPC-web trailers, note
    /// gRPC-web trailers are encoded into the response body so we return
    /// the encoded bytes here.
    pub fn response_trailer_filter(
            &mut self,
            resp_trailers: &mut HeaderMap,
        ) -> Result<Option<Bytes>> { ... }
}
```
## pingora-core/src/protocols/http/bridge/mod.rs
```rust
pub mod grpc_web {
}
```
## pingora-core/src/protocols/http/client.rs
```rust
use bytes::Bytes;
use pingora_error::Result;
use pingora_http::{RequestHeader, ResponseHeader};
use std::time::Duration;
use super::v1::client::HttpSession as Http1Session;
use super::v2::client::Http2Session;
use crate::protocols::{Digest, SocketAddr, Stream};
/// A type for Http client session. It can be either an Http1 connection or an Http2 stream.
pub enum HttpSession {
    H1(Http1Session),
    H2(Http2Session),
}
impl HttpSession {
    pub fn as_http1(&self) -> Option<&Http1Session> { ... }
    pub fn as_http2(&self) -> Option<&Http2Session> { ... }
    /// Write the request header to the server
    /// After the request header is sent. The caller can either start reading the response or
    /// sending request body if any.
    pub async fn write_request_header(&mut self, req: Box<RequestHeader>) -> Result<()> { ... }
    /// Write a chunk of the request body.
    pub async fn write_request_body(&mut self, data: Bytes, end: bool) -> Result<()> { ... }
    /// Signal that the request body has ended
    pub async fn finish_request_body(&mut self) -> Result<()> { ... }
    /// Set the read timeout for reading header and body.
    ///
    /// The timeout is per read operation, not on the overall time reading the entire response
    pub fn set_read_timeout(&mut self, timeout: Duration) { ... }
    /// Set the write timeout for writing header and body.
    ///
    /// The timeout is per write operation, not on the overall time writing the entire request.
    ///
    /// This is a noop for h2.
    pub fn set_write_timeout(&mut self, timeout: Duration) { ... }
    /// Read the response header from the server
    /// For http1, this function can be called multiple times, if the headers received are just
    /// informational headers.
    pub async fn read_response_header(&mut self) -> Result<()> { ... }
    /// Read response body
    ///
    /// `None` when no more body to read.
    pub async fn read_response_body(&mut self) -> Result<Option<Bytes>> { ... }
    /// No (more) body to read
    pub fn response_done(&mut self) -> bool { ... }
    /// Give up the http session abruptly.
    /// For H1 this will close the underlying connection
    /// For H2 this will send RST_STREAM frame to end this stream if the stream has not ended at all
    pub async fn shutdown(&mut self) { ... }
    /// Get the response header of the server
    ///
    /// `None` if the response header is not read yet.
    pub fn response_header(&self) -> Option<&ResponseHeader> { ... }
    /// Return the [Digest] of the connection
    ///
    /// For reused connection, the timing in the digest will reflect its initial handshakes
    /// The caller should check if the connection is reused to avoid misuse of the timing field.
    pub fn digest(&self) -> Option<&Digest> { ... }
    /// Return a mutable [Digest] reference for the connection.
    ///
    /// Will return `None` if this is an H2 session and multiple streams are open.
    pub fn digest_mut(&mut self) -> Option<&mut Digest> { ... }
    /// Return the server (peer) address of the connection.
    pub fn server_addr(&self) -> Option<&SocketAddr> { ... }
    /// Return the client (local) address of the connection.
    pub fn client_addr(&self) -> Option<&SocketAddr> { ... }
    /// Get the reference of the [Stream] that this HTTP/1 session is operating upon.
    /// None if the HTTP session is over H2
    pub fn stream(&self) -> Option<&Stream> { ... }
}
```
## pingora-core/src/protocols/http/compression/brotli.rs
```rust
use super::Encode;
use super::COMPRESSION_ERROR;
use brotli::{CompressorWriter, DecompressorWriter};
use bytes::Bytes;
use pingora_error::{OrErr, Result};
use std::io::Write;
use std::time::{Duration, Instant};
pub struct Decompressor { ... }
pub struct Compressor { ... }
impl Decompressor {
    pub fn new() -> Self { ... }
}
impl Encode for Decompressor {
    fn encode(&mut self, input: &[u8], end: bool) -> Result<Bytes> { ... }
    fn stat(&self) -> (&'static str, usize, usize, Duration) { ... }
}
impl Compressor {
    pub fn new(level: u32) -> Self { ... }
}
impl Encode for Compressor {
    fn encode(&mut self, input: &[u8], end: bool) -> Result<Bytes> { ... }
    fn stat(&self) -> (&'static str, usize, usize, Duration) { ... }
}
```
## pingora-core/src/protocols/http/compression/gzip.rs
```rust
use super::{Encode, COMPRESSION_ERROR};
use bytes::Bytes;
use flate2::write::{GzDecoder, GzEncoder};
use pingora_error::{OrErr, Result};
use std::io::Write;
use std::time::{Duration, Instant};
use std::ops::{Deref, DerefMut};
pub struct Decompressor { ... }
pub struct Compressor {
    // TODO: enum for other compression algorithms
    compress: GzEncoder<Vec<u8>>,
    total_in: usize,
    total_out: usize,
    duration: Duration,
}
impl Decompressor {
    pub fn new() -> Self { ... }
}
impl Encode for Decompressor {
    fn encode(&mut self, input: &[u8], end: bool) -> Result<Bytes> { ... }
    fn stat(&self) -> (&'static str, usize, usize, Duration) { ... }
}
impl Compressor {
    pub fn new(level: u32) -> Compressor { ... }
}
impl Encode for Compressor {
    fn encode(&mut self, input: &[u8], end: bool) -> Result<Bytes> { ... }
    fn stat(&self) -> (&'static str, usize, usize, Duration) { ... }
}
impl Deref for Decompressor {
    fn deref(&self) -> &Self::Target { ... }
}
impl DerefMut for Decompressor {
    fn deref_mut(&mut self) -> &mut Self::Target { ... }
}
impl Deref for Compressor {
    fn deref(&self) -> &Self::Target { ... }
}
impl DerefMut for Compressor {
    fn deref_mut(&mut self) -> &mut Self::Target { ... }
}
```
## pingora-core/src/protocols/http/compression/mod.rs
```rust
use super::HttpTask;
use bytes::Bytes;
use log::warn;
use pingora_error::{ErrorType, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use std::time::Duration;
use strum::EnumCount;
use strum_macros::EnumCount as EnumCountMacro;
use once_cell::sync::Lazy;
use regex::Regex;
/// The response compression object. Currently support gzip compression and brotli decompression.
///
/// To use it, the caller should create a [`ResponseCompressionCtx`] per HTTP session.
/// The caller should call the corresponding filters for the request header, response header and
/// response body. If the algorithms are supported, the output response body will be encoded.
/// The response header will be adjusted accordingly as well. If the algorithm is not supported
/// or no encoding is needed, the response is untouched.
///
/// If configured and if the request's `accept-encoding` header contains the algorithm supported and the
/// incoming response doesn't have that encoding, the filter will compress the response.
/// If configured and supported, and if the incoming response's `content-encoding` isn't one of the
/// request's `accept-encoding` supported algorithm, the ctx will decompress the response.
///
/// # Currently supported algorithms and actions
/// - Brotli decompression: if the response is br compressed, this ctx can decompress it
/// - Gzip compression: if the response is uncompressed, this ctx can compress it with gzip
pub struct ResponseCompressionCtx(CtxInner); { ... }
#[derive(Debug, PartialEq, Eq, Clone, Copy, EnumCountMacro)]
pub enum Algorithm {
    Any, // the "*"
    Gzip,
    Brotli,
    Zstd,
    // TODO: Identity,
    // TODO: Deflate
    Other, // anything unknown
}
/// The trait for both compress and decompress because the interface and syntax are the same:
/// encode some bytes to other bytes
pub trait Encode { ... }
impl ResponseCompressionCtx {
    /// Create a new [`ResponseCompressionCtx`] with the expected compression level. `0` will disable
    /// the compression. The compression level is applied across all algorithms.
    /// The `decompress_enable` flag will tell the ctx to decompress if needed.
    /// The `preserve_etag` flag indicates whether the ctx should avoid modifying the etag,
    /// which will otherwise be weakened if the flag is false and (de)compression is applied.
    pub fn new(compression_level: u32, decompress_enable: bool, preserve_etag: bool) -> Self { ... }
    /// Whether the encoder is enabled.
    /// The enablement will change according to the request and response filter by this ctx.
    pub fn is_enabled(&self) -> bool { ... }
    /// Return the stat of this ctx:
    /// algorithm name, in bytes, out bytes, time took for the compression
    pub fn get_info(&self) -> Option<(&'static str, usize, usize, Duration)> { ... }
    /// Adjust the compression level for all compression algorithms.
    /// # Panic
    /// This function will panic if it has already started encoding the response body.
    pub fn adjust_level(&mut self, new_level: u32) { ... }
    /// Adjust the compression level for a specific algorithm.
    /// # Panic
    /// This function will panic if it has already started encoding the response body.
    pub fn adjust_algorithm_level(&mut self, algorithm: Algorithm, new_level: u32) { ... }
    /// Adjust the decompression flag for all compression algorithms.
    /// # Panic
    /// This function will panic if it has already started encoding the response body.
    pub fn adjust_decompression(&mut self, enabled: bool) { ... }
    /// Adjust the decompression flag for a specific algorithm.
    /// # Panic
    /// This function will panic if it has already started encoding the response body.
    pub fn adjust_algorithm_decompression(&mut self, algorithm: Algorithm, enabled: bool) { ... }
    /// Adjust preserve etag setting.
    /// # Panic
    /// This function will panic if it has already started encoding the response body.
    pub fn adjust_preserve_etag(&mut self, enabled: bool) { ... }
    /// Adjust preserve etag setting for a specific algorithm.
    /// # Panic
    /// This function will panic if it has already started encoding the response body.
    pub fn adjust_algorithm_preserve_etag(&mut self, algorithm: Algorithm, enabled: bool) { ... }
    /// Feed the request header into this ctx.
    pub fn request_filter(&mut self, req: &RequestHeader) { ... }
    /// Feed the response header into this ctx
    pub fn response_header_filter(&mut self, resp: &mut ResponseHeader, end: bool) { ... }
    /// Stream the response body chunks into this ctx. The return value will be the compressed data
    ///
    /// Return None if the compressed is not enabled
    pub fn response_body_filter(&mut self, data: Option<&Bytes>, end: bool) -> Option<Bytes> { ... }
    /// Feed the response into this ctx.
    /// This filter will mutate the response accordingly if encoding is needed.
    pub fn response_filter(&mut self, t: &mut HttpTask) { ... }
}
impl Algorithm {
    pub fn as_str(&self) -> &'static str { ... }
    pub fn compressor(&self, level: u32) -> Option<Box<dyn Encode + Send + Sync>> { ... }
    pub fn decompressor(&self, enabled: bool) -> Option<Box<dyn Encode + Send + Sync>> { ... }
    pub fn index(&self) -> usize { ... }
}
impl From<&str> for Algorithm {
    fn from(s: &str) -> Self { ... }
}
```
## pingora-core/src/protocols/http/compression/zstd.rs
```rust
use super::{Encode, COMPRESSION_ERROR};
use bytes::Bytes;
use parking_lot::Mutex;
use pingora_error::{OrErr, Result};
use std::io::Write;
use std::time::{Duration, Instant};
use zstd::stream::write::Encoder;
pub struct Compressor { ... }
impl Compressor {
    pub fn new(level: u32) -> Self { ... }
}
impl Encode for Compressor {
    fn encode(&mut self, input: &[u8], end: bool) -> Result<Bytes> { ... }
    fn stat(&self) -> (&'static str, usize, usize, Duration) { ... }
}
```
## pingora-core/src/protocols/http/conditional_filter.rs
```rust
use http::{header::*, StatusCode};
use httpdate::{parse_http_date, HttpDate};
use pingora_error::{ErrorType::InvalidHTTPHeader, OrErr, Result};
use pingora_http::{RequestHeader, ResponseHeader};
/// Evaluates conditional headers according to the [RFC](https://datatracker.ietf.org/doc/html/rfc9111#name-handling-a-received-validat).
///
/// Returns true if the request should receive 304 Not Modified.
pub fn not_modified_filter(req: &RequestHeader, resp: &ResponseHeader) -> bool { ... }
/// Search for an ETag matching `target_etag` from the input header, using
/// [weak comparison](https://datatracker.ietf.org/doc/html/rfc9110#section-8.8.3.2).
/// Multiple ETags can exist in the header as a comma-separated list.
///
/// Returns true if a matching ETag exists.
pub fn weak_validate_etag(input_etag_header: &[u8], target_etag: &[u8]) -> bool { ... }
/// Utility function to parse an HTTP request header as an [HTTP-date](https://datatracker.ietf.org/doc/html/rfc9110#name-date-time-formats).
pub fn req_header_as_http_date<H>(req: &RequestHeader, header_name: H) -> Result<Option<HttpDate>>
where
    H: AsHeaderName, { ... }
/// Utility function to parse an HTTP response header as an [HTTP-date](https://datatracker.ietf.org/doc/html/rfc9110#name-date-time-formats).
pub fn resp_header_as_http_date<H>(
    resp: &ResponseHeader,
    header_name: H,
) -> Result<Option<HttpDate>>
where
    H: AsHeaderName, { ... }
/// Utility function to convert the input response header to a 304 Not Modified response.
pub fn to_304(resp: &mut ResponseHeader) { ... }
```
## pingora-core/src/protocols/http/date.rs
```rust
use chrono::DateTime;
use http::header::HeaderValue;
use std::cell::RefCell;
use std::time::{Duration, SystemTime};
pub fn get_cached_date() -> HeaderValue { ... }
impl CacheableDate {
    pub fn new() -> Self { ... }
    pub fn update(&mut self, d_now: Duration) { ... }
    pub fn get_date(&mut self) -> HeaderValue { ... }
}
```
## pingora-core/src/protocols/http/error_resp.rs
```rust
use http::header;
use once_cell::sync::Lazy;
use pingora_http::ResponseHeader;
use super::SERVER_NAME;
/// Generate an error response with the given status code.
///
/// This error response has a zero `Content-Length` and `Cache-Control: private, no-store`.
pub fn gen_error_response(code: u16) -> ResponseHeader { ... }
```
## pingora-core/src/protocols/http/mod.rs
```rust
pub use server::Session as ServerSession;
pub mod bridge {
}
pub mod client {
}
pub mod compression {
}
pub mod conditional_filter {
}
pub mod error_resp {
}
pub mod server {
}
pub mod v1 {
}
pub mod v2 {
}
/// An enum to hold all possible HTTP response events.
#[derive(Debug)]
pub enum HttpTask {
    /// the response header and the boolean end of response flag
    Header(Box<pingora_http::ResponseHeader>, bool),
    /// A piece of response body and the end of response boolean flag
    Body(Option<bytes::Bytes>, bool),
    /// HTTP response trailer
    Trailer(Option<Box<http::HeaderMap>>),
    /// Signal that the response is already finished
    Done,
    /// Signal that the reading of the response encountered errors.
    Failed(pingora_error::BError),
}
impl HttpTask {
    /// Whether this [`HttpTask`] means the end of the response
    pub fn is_end(&self) -> bool { ... }
}
```
## pingora-core/src/protocols/http/server.rs
```rust
use super::error_resp;
use super::v1::server::HttpSession as SessionV1;
use super::v2::server::HttpSession as SessionV2;
use super::HttpTask;
use crate::protocols::{Digest, SocketAddr, Stream};
use bytes::Bytes;
use http::HeaderValue;
use http::{header::AsHeaderName, HeaderMap};
use pingora_error::Result;
use pingora_http::{RequestHeader, ResponseHeader};
use std::time::Duration;
/// HTTP server session object for both HTTP/1.x and HTTP/2
pub enum Session {
    H1(SessionV1),
    H2(SessionV2),
}
impl Session {
    /// Create a new [`Session`] from an established connection for HTTP/1.x
    pub fn new_http1(stream: Stream) -> Self { ... }
    /// Create a new [`Session`] from an established HTTP/2 stream
    pub fn new_http2(session: SessionV2) -> Self { ... }
    /// Whether the session is HTTP/2. If not it is HTTP/1.x
    pub fn is_http2(&self) -> bool { ... }
    /// Read the request header. This method is required to be called first before doing anything
    /// else with the session.
    /// - `Ok(true)`: successful
    /// - `Ok(false)`: client exit without sending any bytes. This is normal on reused connection.
    /// In this case the user should give up this session.
    pub async fn read_request(&mut self) -> Result<bool> { ... }
    /// Return the request header it just read.
    /// # Panic
    /// This function will panic if [`Self::read_request()`] is not called.
    pub fn req_header(&self) -> &RequestHeader { ... }
    /// Return a mutable reference to request header it just read.
    /// # Panic
    /// This function will panic if [`Self::read_request()`] is not called.
    pub fn req_header_mut(&mut self) -> &mut RequestHeader { ... }
    /// Return the header by name. None if the header doesn't exist.
    ///
    /// In case there are multiple headers under the same name, the first one will be returned. To
    /// get all the headers: use `self.req_header().headers.get_all()`.
    pub fn get_header<K: AsHeaderName>(&self, key: K) -> Option<&HeaderValue> { ... }
    /// Get the header value in its raw format.
    /// If the header doesn't exist, return an empty slice.
    pub fn get_header_bytes<K: AsHeaderName>(&self, key: K) -> &[u8] { ... }
    /// Read the request body. Ok(None) if no (more) body to read
    pub async fn read_request_body(&mut self) -> Result<Option<Bytes>> { ... }
    /// Discard the request body by reading it until completion.
    ///
    /// This is useful for making streams reusable (in particular for HTTP/1.1) after returning an
    /// error before the whole body has been read.
    pub async fn drain_request_body(&mut self) -> Result<()> { ... }
    /// Write the response header to client
    /// Informational headers (status code 100-199, excluding 101) can be written multiple times the final
    /// response header (status code 200+ or 101) is written.
    pub async fn write_response_header(&mut self, resp: Box<ResponseHeader>) -> Result<()> { ... }
    /// Similar to `write_response_header()`, this fn will clone the `resp` internally
    pub async fn write_response_header_ref(&mut self, resp: &ResponseHeader) -> Result<()> { ... }
    /// Write the response body to client
    pub async fn write_response_body(&mut self, data: Bytes, end: bool) -> Result<()> { ... }
    /// Write the response trailers to client
    pub async fn write_response_trailers(&mut self, trailers: HeaderMap) -> Result<()> { ... }
    /// Finish the life of this request.
    /// For H1, if connection reuse is supported, a Some(Stream) will be returned, otherwise None.
    /// For H2, always return None because H2 stream is not reusable.
    pub async fn finish(self) -> Result<Option<Stream>> { ... }
    pub async fn response_duplex_vec(&mut self, tasks: Vec<HttpTask>) -> Result<bool> { ... }
    /// Set connection reuse. `duration` defines how long the connection is kept open for the next
    /// request to reuse. Noop for h2
    pub fn set_keepalive(&mut self, duration: Option<u64>) { ... }
    /// Sets the downstream read timeout. This will trigger if we're unable
    /// to read from the stream after `timeout`.
    ///
    /// This is a noop for h2.
    pub fn set_read_timeout(&mut self, timeout: Duration) { ... }
    /// Sets the downstream write timeout. This will trigger if we're unable
    /// to write to the stream after `timeout`. If a `min_send_rate` is
    /// configured then the `min_send_rate` calculated timeout has higher priority.
    ///
    /// This is a noop for h2.
    pub fn set_write_timeout(&mut self, timeout: Duration) { ... }
    /// Sets the total drain timeout, which will be applied while discarding the
    /// request body using `drain_request_body`.
    ///
    /// For HTTP/1.1, reusing a session requires ensuring that the request body
    /// is consumed. If the timeout is exceeded, the caller should give up on
    /// trying to reuse the session.
    pub fn set_total_drain_timeout(&mut self, timeout: Duration) { ... }
    /// Sets the minimum downstream send rate in bytes per second. This
    /// is used to calculate a write timeout in seconds based on the size
    /// of the buffer being written. If a `min_send_rate` is configured it
    /// has higher priority over a set `write_timeout`. The minimum send
    /// rate must be greater than zero.
    ///
    /// Calculated write timeout is guaranteed to be at least 1s if `min_send_rate`
    /// is greater than zero, a send rate of zero is a noop.
    ///
    /// This is a noop for h2.
    pub fn set_min_send_rate(&mut self, rate: usize) { ... }
    /// Sets whether we ignore writing informational responses downstream.
    ///
    /// For HTTP/1.1 this is a noop if the response is Upgrade or Continue and
    /// Expect: 100-continue was set on the request.
    ///
    /// This is a noop for h2 because informational responses are always ignored.
    pub fn set_ignore_info_resp(&mut self, ignore: bool) { ... }
    pub fn request_summary(&self) -> String { ... }
    /// Return the written response header. `None` if it is not written yet.
    /// Only the final (status code >= 200 or 101) response header will be returned
    pub fn response_written(&self) -> Option<&ResponseHeader> { ... }
    /// Give up the http session abruptly.
    /// For H1 this will close the underlying connection
    /// For H2 this will send RESET frame to end this stream without impacting the connection
    pub async fn shutdown(&mut self) { ... }
    pub fn to_h1_raw(&self) -> Bytes { ... }
    /// Whether the whole request body is sent
    pub fn is_body_done(&mut self) -> bool { ... }
    /// Notify the client that the entire body is sent
    /// for H1 chunked encoding, this will end the last empty chunk
    /// for H1 content-length, this has no effect.
    /// for H2, this will send an empty DATA frame with END_STREAM flag
    pub async fn finish_body(&mut self) -> Result<()> { ... }
    pub fn generate_error(error: u16) -> ResponseHeader { ... }
    /// Send error response to client using a pre-generated error message.
    pub async fn respond_error(&mut self, error: u16) -> Result<()> { ... }
    /// Send error response to client using a pre-generated error message and custom body.
    pub async fn respond_error_with_body(&mut self, error: u16, body: Bytes) -> Result<()> { ... }
    /// Send an error response to a client with a response header and body.
    pub async fn write_error_response(&mut self, resp: ResponseHeader, body: Bytes) -> Result<()> { ... }
    /// Whether there is no request body
    pub fn is_body_empty(&mut self) -> bool { ... }
    pub fn retry_buffer_truncated(&self) -> bool { ... }
    pub fn enable_retry_buffering(&mut self) { ... }
    pub fn get_retry_buffer(&self) -> Option<Bytes> { ... }
    /// Read body (same as `read_request_body()`) or pending forever until downstream
    /// terminates the session.
    pub async fn read_body_or_idle(&mut self, no_body_expected: bool) -> Result<Option<Bytes>> { ... }
    pub fn as_http1(&self) -> Option<&SessionV1> { ... }
    pub fn as_http2(&self) -> Option<&SessionV2> { ... }
    /// Write a 100 Continue response to the client.
    pub async fn write_continue_response(&mut self) -> Result<()> { ... }
    /// Whether this request is for upgrade (e.g., websocket)
    pub fn is_upgrade_req(&self) -> bool { ... }
    /// Return how many response body bytes (application, not wire) already sent downstream
    pub fn body_bytes_sent(&self) -> usize { ... }
    /// Return how many request body bytes (application, not wire) already read from downstream
    pub fn body_bytes_read(&self) -> usize { ... }
    /// Return the [Digest] for the connection.
    pub fn digest(&self) -> Option<&Digest> { ... }
    /// Return a mutable [Digest] reference for the connection.
    ///
    /// Will return `None` if multiple H2 streams are open.
    pub fn digest_mut(&mut self) -> Option<&mut Digest> { ... }
    /// Return the client (peer) address of the connection.
    pub fn client_addr(&self) -> Option<&SocketAddr> { ... }
    /// Return the server (local) address of the connection.
    pub fn server_addr(&self) -> Option<&SocketAddr> { ... }
    /// Get the reference of the [Stream] that this HTTP/1 session is operating upon.
    /// None if the HTTP session is over H2
    pub fn stream(&self) -> Option<&Stream> { ... }
}
```
## pingora-core/src/protocols/http/v1/body.rs
```rust
use bytes::{Buf, BufMut, Bytes, BytesMut};
use log::{debug, trace, warn};
use pingora_error::{
    Error,
    ErrorType::{self, *},
    OrErr, Result,
};
use std::fmt::Debug;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use crate::protocols::l4::stream::AsyncWriteVec;
use crate::utils::BufRef;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseState {
    ToStart,
    Complete(usize),                     // total size
    Partial(usize, usize),               // size read, remaining size
    Chunked(usize, usize, usize, usize), // size read, next to read in current buf start, read in current buf start, remaining chucked size to read from IO
    Done(usize),                         // done but there is error, size read
    HTTP1_0(usize),                      // read until connection closed, size read
}
pub struct BodyReader { ... }
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BodyMode {
    ToSelect,
    ContentLength(usize, usize), // total length to write, bytes already written
    ChunkedEncoding(usize),      //bytes written
    HTTP1_0(usize),              //bytes written
    Complete(usize),             //bytes written
}
pub struct BodyWriter { ... }
impl ParseState {
    pub fn finish(&self, additional_bytes: usize) -> Self { ... }
    pub fn done(&self, additional_bytes: usize) -> Self { ... }
    pub fn partial_chunk(&self, bytes_read: usize, bytes_to_read: usize) -> Self { ... }
    pub fn multi_chunk(&self, bytes_read: usize, buf_start_index: usize) -> Self { ... }
    pub fn partial_chunk_head(&self, head_end: usize, head_size: usize) -> Self { ... }
    pub fn new_buf(&self, buf_end: usize) -> Self { ... }
}
impl BodyReader {
    pub fn new() -> Self { ... }
    pub fn need_init(&self) -> bool { ... }
    pub fn reinit(&mut self) { ... }
    pub fn init_chunked(&mut self, buf_to_rewind: &[u8]) { ... }
    pub fn init_content_length(&mut self, cl: usize, buf_to_rewind: &[u8]) { ... }
    pub fn init_http10(&mut self, buf_to_rewind: &[u8]) { ... }
    pub fn get_body(&self, buf_ref: &BufRef) -> &[u8] { ... }
    pub fn body_done(&self) -> bool { ... }
    pub fn body_empty(&self) -> bool { ... }
    pub async fn read_body<S>(&mut self, stream: &mut S) -> Result<Option<BufRef>>
        where
            S: AsyncRead + Unpin + Send, { ... }
    pub async fn do_read_body<S>(&mut self, stream: &mut S) -> Result<Option<BufRef>>
        where
            S: AsyncRead + Unpin + Send, { ... }
    pub async fn do_read_body_until_closed<S>(&mut self, stream: &mut S) -> Result<Option<BufRef>>
        where
            S: AsyncRead + Unpin + Send, { ... }
    pub async fn do_read_chunked_body<S>(&mut self, stream: &mut S) -> Result<Option<BufRef>>
        where
            S: AsyncRead + Unpin + Send, { ... }
}
impl BodyWriter {
    pub fn new() -> Self { ... }
    pub fn init_chunked(&mut self) { ... }
    pub fn init_http10(&mut self) { ... }
    pub fn init_content_length(&mut self, cl: usize) { ... }
    pub async fn write_body<S>(&mut self, stream: &mut S, buf: &[u8]) -> Result<Option<usize>>
        where
            S: AsyncWrite + Unpin + Send, { ... }
    pub fn finished(&self) -> bool { ... }
    pub async fn finish<S>(&mut self, stream: &mut S) -> Result<Option<usize>>
        where
            S: AsyncWrite + Unpin + Send, { ... }
}
```
## pingora-core/src/protocols/http/v1/client.rs
```rust
use bytes::{BufMut, Bytes, BytesMut};
use http::{header, header::AsHeaderName, HeaderValue, StatusCode, Version};
use log::{debug, trace};
use pingora_error::{Error, ErrorType::*, OrErr, Result, RetryType};
use pingora_http::{HMap, IntoCaseHeaderName, RequestHeader, ResponseHeader};
use pingora_timeout::timeout;
use std::io::ErrorKind;
use std::str;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use super::body::{BodyReader, BodyWriter};
use super::common::*;
use crate::protocols::http::HttpTask;
use crate::protocols::{Digest, SocketAddr, Stream, UniqueID, UniqueIDType};
use crate::utils::{BufRef, KVRef};
/// The HTTP 1.x client session
pub struct HttpSession { ... }
/// HTTP 1.x client session
impl HttpSession {
    /// Create a new http client session from an established (TCP or TLS) [`Stream`].
    pub fn new(stream: Stream) -> Self { ... }
    /// Write the request header to the server
    /// After the request header is sent. The caller can either start reading the response or
    /// sending request body if any.
    pub async fn write_request_header(&mut self, req: Box<RequestHeader>) -> Result<usize> { ... }
    /// Write request body. Return Ok(None) if no more body should be written, either due to
    /// Content-Length or the last chunk is already sent
    pub async fn write_body(&mut self, buf: &[u8]) -> Result<Option<usize>> { ... }
    /// Flush local buffer and notify the server by sending the last chunk if chunked encoding is
    /// used.
    pub async fn finish_body(&mut self) -> Result<Option<usize>> { ... }
    /// Read the response header from the server
    /// This function can be called multiple times, if the headers received are just informational
    /// headers.
    pub async fn read_response(&mut self) -> Result<usize> { ... }
    /// Similar to [`Self::read_response()`], read the response header and then return a copy of it.
    pub async fn read_resp_header_parts(&mut self) -> Result<Box<ResponseHeader>> { ... }
    /// Return a reference of the [`ResponseHeader`] if the response is read
    pub fn resp_header(&self) -> Option<&ResponseHeader> { ... }
    /// Get the header value for the given header name from the response header
    /// If there are multiple headers under the same name, the first one will be returned
    /// Use `self.resp_header().header.get_all(name)` to get all the headers under the same name
    /// Always return `None` if the response is not read yet.
    pub fn get_header(&self, name: impl AsHeaderName) -> Option<&HeaderValue> { ... }
    /// Get the request header as raw bytes, `b""` when the header doesn't exist or response not read
    pub fn get_header_bytes(&self, name: impl AsHeaderName) -> &[u8] { ... }
    /// Return the status code of the response if read
    pub fn get_status(&self) -> Option<StatusCode> { ... }
    /// Read the response body into the internal buffer.
    /// Return `Ok(Some(ref)) after a successful read.
    /// Return `Ok(None)` if there is no more body to read.
    pub async fn read_body_ref(&mut self) -> Result<Option<&[u8]>> { ... }
    /// Similar to [`Self::read_body_ref`] but return `Bytes` instead of a slice reference.
    pub async fn read_body_bytes(&mut self) -> Result<Option<Bytes>> { ... }
    /// Whether there is no more body to read.
    pub fn is_body_done(&mut self) -> bool { ... }
    /// Get the raw response header bytes
    pub fn get_headers_raw_bytes(&self) -> Bytes { ... }
    /// Apply keepalive settings according to the server's response
    /// For HTTP 1.1, assume keepalive as long as there is no `Connection: Close` request header.
    /// For HTTP 1.0, only keepalive if there is an explicit header `Connection: keep-alive`.
    pub fn respect_keepalive(&mut self) { ... }
    pub fn will_keepalive(&self) -> bool { ... }
    /// Close the connection abruptly. This allows to signal the server that the connection is closed
    /// before dropping [`HttpSession`]
    pub async fn shutdown(&mut self) { ... }
    /// Consume `self`, if the connection can be reused, the underlying stream will be returned.
    /// The returned connection can be kept in a connection pool so that next time the same
    /// server is being contacted. A new client session can be created via [`Self::new()`].
    /// If the connection cannot be reused, the underlying stream will be closed and `None` will be
    /// returned.
    pub async fn reuse(mut self) -> Option<Stream> { ... }
    /// Whether this request is for upgrade
    pub fn is_upgrade_req(&self) -> bool { ... }
    pub async fn read_response_task(&mut self) -> Result<HttpTask> { ... }
    /// Return the [Digest] of the connection
    ///
    /// For reused connection, the timing in the digest will reflect its initial handshakes
    /// The caller should check if the connection is reused to avoid misuse the timing field.
    pub fn digest(&self) -> &Digest { ... }
    /// Return a mutable [Digest] reference for the connection.
    pub fn digest_mut(&mut self) -> &mut Digest { ... }
    /// Return the server (peer) address recorded in the connection digest.
    pub fn server_addr(&self) -> Option<&SocketAddr> { ... }
    /// Return the client (local) address recorded in the connection digest.
    pub fn client_addr(&self) -> Option<&SocketAddr> { ... }
    /// Get the reference of the [Stream] that this HTTP session is operating upon.
    pub fn stream(&self) -> &Stream { ... }
    /// Consume `self`, the underlying [Stream] will be returned and can be used
    /// directly, for example, in the case of HTTP upgrade. It is not flushed
    /// prior to being returned.
    pub fn into_inner(self) -> Stream { ... }
}
impl UniqueID for HttpSession {
    fn id(&self) -> UniqueIDType { ... }
}
```
## pingora-core/src/protocols/http/v1/common.rs
```rust
use http::{header, HeaderValue};
use log::warn;
use pingora_error::Result;
use pingora_http::{HMap, RequestHeader, ResponseHeader};
use std::str;
use std::time::Duration;
use super::body::BodyWriter;
use crate::utils::KVRef;
#[inline]
pub fn header_value_content_length(
    header_value: Option<&http::header::HeaderValue>,
) -> Option<usize> { ... }
```
## pingora-core/src/protocols/http/v1/mod.rs
```rust
pub mod client {
}
pub mod common {
}
pub mod server {
}
```
## pingora-core/src/protocols/http/v1/server.rs
```rust
use bytes::Bytes;
use bytes::{BufMut, BytesMut};
use http::header::{CONTENT_LENGTH, TRANSFER_ENCODING};
use http::HeaderValue;
use http::{header, header::AsHeaderName, Method, Version};
use log::{debug, warn};
use once_cell::sync::Lazy;
use percent_encoding::{percent_encode, AsciiSet, CONTROLS};
use pingora_error::{Error, ErrorType::*, OrErr, Result};
use pingora_http::{IntoCaseHeaderName, RequestHeader, ResponseHeader};
use pingora_timeout::timeout;
use regex::bytes::Regex;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use super::body::{BodyReader, BodyWriter};
use super::common::*;
use crate::protocols::http::{body_buffer::FixedBuffer, date, HttpTask};
use crate::protocols::{Digest, SocketAddr, Stream};
use crate::utils::{BufRef, KVRef};
/// The HTTP 1.x server session
pub struct HttpSession { ... }
impl HttpSession {
    /// Create a new http server session from an established (TCP or TLS) [`Stream`].
    /// The created session needs to call [`Self::read_request()`] first before performing
    /// any other operations.
    pub fn new(underlying_stream: Stream) -> Self { ... }
    /// Read the request header. Return `Ok(Some(n))` where the read and parsing are successful.
    /// Return `Ok(None)` when the client closed the connection without sending any data, which
    /// is common on a reused connection.
    pub async fn read_request(&mut self) -> Result<Option<usize>> { ... }
    /// Return a reference of the `RequestHeader` this session read
    /// # Panics
    /// this function and most other functions will panic if called before [`Self::read_request()`]
    pub fn req_header(&self) -> &RequestHeader { ... }
    /// Return a mutable reference of the `RequestHeader` this session read
    /// # Panics
    /// this function and most other functions will panic if called before [`Self::read_request()`]
    pub fn req_header_mut(&mut self) -> &mut RequestHeader { ... }
    /// Get the header value for the given header name
    /// If there are multiple headers under the same name, the first one will be returned
    /// Use `self.req_header().header.get_all(name)` to get all the headers under the same name
    pub fn get_header(&self, name: impl AsHeaderName) -> Option<&HeaderValue> { ... }
    /// Return a string `$METHOD $PATH, Host: $HOST`. Mostly for logging and debug purpose
    pub fn request_summary(&self) -> String { ... }
    /// Is the request a upgrade request
    pub fn is_upgrade_req(&self) -> bool { ... }
    /// Get the request header as raw bytes, `b""` when the header doesn't exist
    pub fn get_header_bytes(&self, name: impl AsHeaderName) -> &[u8] { ... }
    /// Read the request body. `Ok(None)` when there is no (more) body to read.
    pub async fn read_body_bytes(&mut self) -> Result<Option<Bytes>> { ... }
    /// Drain the request body. `Ok(())` when there is no (more) body to read.
    pub async fn drain_request_body(&mut self) -> Result<()> { ... }
    /// Whether there is no (more) body need to be read.
    pub fn is_body_done(&mut self) -> bool { ... }
    /// Whether the request has an empty body
    /// Because HTTP 1.1 clients have to send either `Content-Length` or `Transfer-Encoding` in order
    /// to signal the server that it will send the body, this function returns accurate results even
    /// only when the request header is just read.
    pub fn is_body_empty(&mut self) -> bool { ... }
    /// Write the response header to the client.
    /// This function can be called more than once to send 1xx informational headers excluding 101.
    pub async fn write_response_header(&mut self, mut header: Box<ResponseHeader>) -> Result<()> { ... }
    /// Return the response header if it is already sent.
    pub fn response_written(&self) -> Option<&ResponseHeader> { ... }
    /// `Some(true)` if the this is a successful upgrade
    /// `Some(false)` if the request is an upgrade but the response refuses it
    /// `None` if the request is not an upgrade.
    pub fn is_upgrade(&self, header: &ResponseHeader) -> Option<bool> { ... }
    /// Return whether the session will be keepalived for connection reuse.
    pub fn will_keepalive(&self) -> bool { ... }
    /// Apply keepalive settings according to the client
    /// For HTTP 1.1, assume keepalive as long as there is no `Connection: Close` request header.
    /// For HTTP 1.0, only keepalive if there is an explicit header `Connection: keep-alive`.
    pub fn respect_keepalive(&mut self) { ... }
    /// Same as [`Self::write_response_header()`] but takes a reference.
    pub async fn write_response_header_ref(&mut self, resp: &ResponseHeader) -> Result<()> { ... }
    /// Write response body to the client. Return `Ok(None)` when there shouldn't be more body
    /// to be written, e.g., writing more bytes than what the `Content-Length` header suggests
    pub async fn write_body(&mut self, buf: &[u8]) -> Result<Option<usize>> { ... }
    /// Signal that there is no more body to write.
    /// This call will try to flush the buffer if there is any un-flushed data.
    /// For chunked encoding response, this call will also send the last chunk.
    /// For upgraded sessions, this call will also close the reading of the client body.
    pub async fn finish_body(&mut self) -> Result<Option<usize>> { ... }
    /// Return how many response body bytes (application, not wire) already sent downstream
    pub fn body_bytes_sent(&self) -> usize { ... }
    /// Return how many request body bytes (application, not wire) already read from downstream
    pub fn body_bytes_read(&self) -> usize { ... }
    pub fn retry_buffer_truncated(&self) -> bool { ... }
    pub fn enable_retry_buffering(&mut self) { ... }
    pub fn get_retry_buffer(&self) -> Option<Bytes> { ... }
    /// This function will (async) block forever until the client closes the connection.
    pub async fn idle(&mut self) -> Result<usize> { ... }
    /// This function will return body bytes (same as [`Self::read_body_bytes()`]), but after
    /// the client body finishes (`Ok(None)` is returned), calling this function again will block
    /// forever, same as [`Self::idle()`].
    pub async fn read_body_or_idle(&mut self, no_body_expected: bool) -> Result<Option<Bytes>> { ... }
    /// Return the raw bytes of the request header.
    pub fn get_headers_raw_bytes(&self) -> Bytes { ... }
    /// Close the connection abruptly. This allows to signal the client that the connection is closed
    /// before dropping [`HttpSession`]
    pub async fn shutdown(&mut self) { ... }
    /// Set the server keepalive timeout.
    /// `None`: disable keepalive, this session cannot be reused.
    /// `Some(0)`: reusing this session is allowed and there is no timeout.
    /// `Some(>0)`: reusing this session is allowed within the given timeout in seconds.
    /// If the client disallows connection reuse, then `keepalive` will be ignored.
    pub fn set_server_keepalive(&mut self, keepalive: Option<u64>) { ... }
    /// Sets the downstream read timeout. This will trigger if we're unable
    /// to read from the stream after `timeout`.
    pub fn set_read_timeout(&mut self, timeout: Duration) { ... }
    /// Sets the downstream write timeout. This will trigger if we're unable
    /// to write to the stream after `timeout`. If a `min_send_rate` is
    /// configured then the `min_send_rate` calculated timeout has higher priority.
    pub fn set_write_timeout(&mut self, timeout: Duration) { ... }
    /// Sets the total drain timeout. For HTTP/1.1, reusing a session requires
    /// ensuring that the request body is consumed. This `timeout` will be used
    /// to determine how long to wait for the entirety of the downstream request
    /// body to finish after the upstream response is completed to return the
    /// session to the reuse pool. If the timeout is exceeded, we will give up
    /// on trying to reuse the session.
    ///
    /// Note that the downstream read timeout still applies between body byte reads.
    pub fn set_total_drain_timeout(&mut self, timeout: Duration) { ... }
    /// Sets the minimum downstream send rate in bytes per second. This
    /// is used to calculate a write timeout in seconds based on the size
    /// of the buffer being written. If a `min_send_rate` is configured it
    /// has higher priority over a set `write_timeout`. The minimum send
    /// rate must be greater than zero.
    ///
    /// Calculated write timeout is guaranteed to be at least 1s if `min_send_rate`
    /// is greater than zero, a send rate of zero is a noop.
    pub fn set_min_send_rate(&mut self, min_send_rate: usize) { ... }
    /// Sets whether we ignore writing informational responses downstream.
    ///
    /// This is a noop if the response is Upgrade or Continue and
    /// Expect: 100-continue was set on the request.
    pub fn set_ignore_info_resp(&mut self, ignore: bool) { ... }
    /// Return the [Digest] of the connection.
    pub fn digest(&self) -> &Digest { ... }
    /// Return a mutable [Digest] reference for the connection.
    pub fn digest_mut(&mut self) -> &mut Digest { ... }
    /// Return the client (peer) address of the underlying connection.
    pub fn client_addr(&self) -> Option<&SocketAddr> { ... }
    /// Return the server (local) address of the underlying connection.
    pub fn server_addr(&self) -> Option<&SocketAddr> { ... }
    /// Consume `self`, if the connection can be reused, the underlying stream will be returned
    /// to be fed to the next [`Self::new()`]. This drains any remaining request body if it hasn't
    /// yet been read and the stream is reusable.
    ///
    /// The next session can just call [`Self::read_request()`].
    ///
    /// If the connection cannot be reused, the underlying stream will be closed and `None` will be
    /// returned. If there was an error while draining any remaining request body that error will
    /// be returned.
    pub async fn reuse(mut self) -> Result<Option<Stream>> { ... }
    /// Write a `100 Continue` response to the client.
    pub async fn write_continue_response(&mut self) -> Result<()> { ... }
    pub async fn response_duplex_vec(&mut self, mut tasks: Vec<HttpTask>) -> Result<bool> { ... }
    /// Get the reference of the [Stream] that this HTTP session is operating upon.
    pub fn stream(&self) -> &Stream { ... }
    /// Consume `self`, the underlying stream will be returned and can be used
    /// directly, for example, in the case of HTTP upgrade. The stream is not
    /// flushed prior to being returned.
    pub fn into_inner(self) -> Stream { ... }
}
```
## pingora-core/src/protocols/http/v2/client.rs
```rust
use bytes::Bytes;
use futures::FutureExt;
use h2::client::{self, ResponseFuture, SendRequest};
use h2::{Reason, RecvStream, SendStream};
use http::HeaderMap;
use log::{debug, error, warn};
use pingora_error::{Error, ErrorType, ErrorType::*, OrErr, Result, RetryType};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_timeout::timeout;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;
use crate::connectors::http::v2::ConnectionRef;
use crate::protocols::{Digest, SocketAddr, UniqueIDType};
use tokio::sync::oneshot;
pub async fn drive_connection<S>(
    mut c: client::Connection<S>,
    id: UniqueIDType,
    closed: watch::Sender<bool>,
    ping_interval: Option<Duration>,
    ping_timeout_occurred: Arc<AtomicBool>,
) where
    S: AsyncRead + AsyncWrite + Send + Unpin, { ... }
pub struct Http2Session { ... }
impl Drop for Http2Session {
    fn drop(&mut self) { ... }
}
impl Http2Session {
    /// Write the request header to the server
    pub fn write_request_header(&mut self, mut req: Box<RequestHeader>, end: bool) -> Result<()> { ... }
    /// Write a request body chunk
    pub async fn write_request_body(&mut self, data: Bytes, end: bool) -> Result<()> { ... }
    /// Signal that the request body has ended
    pub fn finish_request_body(&mut self) -> Result<()> { ... }
    /// Read the response header
    pub async fn read_response_header(&mut self) -> Result<()> { ... }
    /// Read the response body
    ///
    /// `None` means, no more body to read
    pub async fn read_response_body(&mut self) -> Result<Option<Bytes>> { ... }
    /// Whether the response has ended
    pub fn response_finished(&self) -> bool { ... }
    /// Check whether stream finished with error.
    /// Like `response_finished`, but also attempts to poll the h2 stream for errors that may have
    /// caused the stream to terminate, and returns them as `H2Error`s.
    pub fn check_response_end_or_error(&mut self) -> Result<bool> { ... }
    /// Read the optional trailer headers
    pub async fn read_trailers(&mut self) -> Result<Option<HeaderMap>> { ... }
    /// The request header if it is already sent
    pub fn request_header(&self) -> Option<&RequestHeader> { ... }
    /// The response header if it is already read
    pub fn response_header(&self) -> Option<&ResponseHeader> { ... }
    /// Give up the http session abruptly.
    pub fn shutdown(&mut self) { ... }
    /// Return the [Digest] of the connection
    ///
    /// For reused connection, the timing in the digest will reflect its initial handshakes
    /// The caller should check if the connection is reused to avoid misuse the timing field.
    pub fn digest(&self) -> Option<&Digest> { ... }
    /// Return a mutable [Digest] reference for the connection
    ///
    /// Will return `None` if multiple H2 streams are open.
    pub fn digest_mut(&mut self) -> Option<&mut Digest> { ... }
    /// Return the server (peer) address recorded in the connection digest.
    pub fn server_addr(&self) -> Option<&SocketAddr> { ... }
    /// Return the client (local) address recorded in the connection digest.
    pub fn client_addr(&self) -> Option<&SocketAddr> { ... }
    /// the FD of the underlying connection
    pub fn fd(&self) -> UniqueIDType { ... }
    /// take the body sender to another task to perform duplex read and write
    pub fn take_request_body_writer(&mut self) -> Option<SendStream<Bytes>> { ... }
}
```
## pingora-core/src/protocols/http/v2/mod.rs
```rust
use crate::{Error, ErrorType::*, OrErr, Result};
use bytes::Bytes;
use h2::SendStream;
pub mod client {
}
pub mod server {
}
/// A helper function to write the body of h2 streams.
pub async fn write_body(writer: &mut SendStream<Bytes>, data: Bytes, end: bool) -> Result<()> { ... }
```
## pingora-core/src/protocols/http/v2/server.rs
```rust
use bytes::Bytes;
use futures::Future;
use h2::server;
use h2::server::SendResponse;
use h2::{RecvStream, SendStream};
use http::header::HeaderName;
use http::uri::PathAndQuery;
use http::{header, HeaderMap, Response};
use log::{debug, warn};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_timeout::timeout;
use std::sync::Arc;
use std::time::Duration;
use crate::protocols::http::body_buffer::FixedBuffer;
use crate::protocols::http::date::get_cached_date;
use crate::protocols::http::v1::client::http_req_header_to_wire;
use crate::protocols::http::HttpTask;
use crate::protocols::{Digest, SocketAddr, Stream};
use crate::{Error, ErrorType, OrErr, Result};
pub use h2::server::Builder as H2Options;
use futures::task::Context;
use futures::task::Poll;
use std::pin::Pin;
/// Perform HTTP/2 connection handshake with an established (TLS) connection.
///
/// The optional `options` allow to adjust certain HTTP/2 parameters and settings.
/// See [`H2Options`] for more details.
pub async fn handshake(io: Stream, options: Option<H2Options>) -> Result<H2Connection<Stream>> { ... }
/// The future to poll for an idle session.
///
/// Calling `.await` in this object will not return until the client decides to close this stream.
pub struct Idle<'a>(&'a mut HttpSession); { ... }
/// HTTP/2 server session
pub struct HttpSession { ... }
impl Future for Idle<'_> {
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> { ... }
}
impl HttpSession {
    /// Create a new [`HttpSession`] from the HTTP/2 connection.
    /// This function returns a new HTTP/2 session when the provided HTTP/2 connection, `conn`,
    /// establishes a new HTTP/2 stream to this server.
    ///
    /// A [`Digest`] from the IO stream is also stored in the resulting session, since the
    /// session doesn't have access to the underlying stream (and the stream itself isn't
    /// accessible from the `h2::server::Connection`).
    ///
    /// Note: in order to handle all **existing** and new HTTP/2 sessions, the server must call
    /// this function in a loop until the client decides to close the connection.
    ///
    /// `None` will be returned when the connection is closing so that the loop can exit.
    pub async fn from_h2_conn(
            conn: &mut H2Connection<Stream>,
            digest: Arc<Digest>,
        ) -> Result<Option<Self>> { ... }
    /// The request sent from the client
    ///
    /// Different from its HTTP/1.X counterpart, this function never panics as the request is already
    /// read when established a new HTTP/2 stream.
    pub fn req_header(&self) -> &RequestHeader { ... }
    /// A mutable reference to request sent from the client
    ///
    /// Different from its HTTP/1.X counterpart, this function never panics as the request is already
    /// read when established a new HTTP/2 stream.
    pub fn req_header_mut(&mut self) -> &mut RequestHeader { ... }
    /// Read request body bytes. `None` when there is no more body to read.
    pub async fn read_body_bytes(&mut self) -> Result<Option<Bytes>> { ... }
    pub async fn drain_request_body(&mut self) -> Result<()> { ... }
    /// Sets the total drain timeout. This `timeout` will be used while draining
    /// the request body.
    pub fn set_total_drain_timeout(&mut self, timeout: Duration) { ... }
    /// Write the response header to the client.
    /// # the `end` flag
    /// `end` marks the end of this session.
    /// If the `end` flag is set, no more header or body can be sent to the client.
    pub fn write_response_header(
            &mut self,
            mut header: Box<ResponseHeader>,
            end: bool,
        ) -> Result<()> { ... }
    /// Write response body to the client. See [Self::write_response_header] for how to use `end`.
    pub async fn write_body(&mut self, data: Bytes, end: bool) -> Result<()> { ... }
    /// Write response trailers to the client, this also closes the stream.
    pub fn write_trailers(&mut self, trailers: HeaderMap) -> Result<()> { ... }
    /// Similar to [Self::write_response_header], this function takes a reference instead
    pub fn write_response_header_ref(&mut self, header: &ResponseHeader, end: bool) -> Result<()> { ... }
    /// Mark the session end. If no `end` flag is already set before this call, this call will
    /// signal the client. Otherwise this call does nothing.
    ///
    /// Dropping this object without sending `end` will cause an error to the client, which will cause
    /// the client to treat this session as bad or incomplete.
    pub fn finish(&mut self) -> Result<()> { ... }
    pub async fn response_duplex_vec(&mut self, tasks: Vec<HttpTask>) -> Result<bool> { ... }
    /// Return a string `$METHOD $PATH, Host: $HOST`. Mostly for logging and debug purpose
    pub fn request_summary(&self) -> String { ... }
    /// Return the written response header. `None` if it is not written yet.
    pub fn response_written(&self) -> Option<&ResponseHeader> { ... }
    /// Give up the stream abruptly.
    ///
    /// This will send a `INTERNAL_ERROR` stream error to the client
    pub fn shutdown(&mut self) { ... }
    pub fn pseudo_raw_h1_request_header(&self) -> Bytes { ... }
    /// Whether there is no more body to read
    pub fn is_body_done(&self) -> bool { ... }
    /// Whether there is any body to read. true means there no body in request.
    pub fn is_body_empty(&self) -> bool { ... }
    pub fn retry_buffer_truncated(&self) -> bool { ... }
    pub fn enable_retry_buffering(&mut self) { ... }
    pub fn get_retry_buffer(&self) -> Option<Bytes> { ... }
    /// `async fn idle() -> Result<Reason, Error>;`
    /// This async fn will be pending forever until the client closes the stream/connection
    /// This function is used for watching client status so that the server is able to cancel
    /// its internal tasks as the client waiting for the tasks goes away
    pub fn idle(&mut self) -> Idle { ... }
    /// Similar to `read_body_bytes()` but will be pending after Ok(None) is returned,
    /// until the client closes the connection
    pub async fn read_body_or_idle(&mut self, no_body_expected: bool) -> Result<Option<Bytes>> { ... }
    /// Return how many response body bytes (application, not wire) already sent downstream
    pub fn body_bytes_sent(&self) -> usize { ... }
    /// Return how many request body bytes (application, not wire) already read from downstream
    pub fn body_bytes_read(&self) -> usize { ... }
    /// Return the [Digest] of the connection.
    pub fn digest(&self) -> Option<&Digest> { ... }
    /// Return a mutable [Digest] reference for the connection.
    pub fn digest_mut(&mut self) -> Option<&mut Digest> { ... }
    /// Return the server (local) address recorded in the connection digest.
    pub fn server_addr(&self) -> Option<&SocketAddr> { ... }
    /// Return the client (peer) address recorded in the connection digest.
    pub fn client_addr(&self) -> Option<&SocketAddr> { ... }
}
```
## pingora-core/src/protocols/l4/ext.rs
```rust
use libc::socklen_t;
use libc::{c_int, c_ulonglong, c_void};
use pingora_error::{Error, ErrorType::*, OrErr, Result};
use std::io::{self, ErrorKind};
use std::mem;
use std::net::SocketAddr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::windows::io::{AsRawSocket, RawSocket};
use std::time::Duration;
use tokio::net::UnixStream;
use tokio::net::{TcpSocket, TcpStream};
use crate::connectors::l4::BindTo;
/// Get the kernel TCP_INFO for the given FD.
#[cfg(target_os = "linux")]
pub fn get_tcp_info(fd: RawFd) -> io::Result<TCP_INFO> { ... }
#[cfg(all(unix, not(target_os = "linux")))]
pub fn get_tcp_info(_fd: RawFd) -> io::Result<TCP_INFO> { ... }
#[cfg(windows)]
pub fn get_tcp_info(_fd: RawSocket) -> io::Result<TCP_INFO> { ... }
/// Set the TCP receive buffer size. See SO_RCVBUF.
#[cfg(target_os = "linux")]
pub fn set_recv_buf(fd: RawFd, val: usize) -> Result<()> { ... }
#[cfg(all(unix, not(target_os = "linux")))]
pub fn set_recv_buf(_fd: RawFd, _: usize) -> Result<()> { ... }
#[cfg(windows)]
pub fn set_recv_buf(_sock: RawSocket, _: usize) -> Result<()> { ... }
#[cfg(target_os = "linux")]
pub fn get_recv_buf(fd: RawFd) -> io::Result<usize> { ... }
#[cfg(all(unix, not(target_os = "linux")))]
pub fn get_recv_buf(_fd: RawFd) -> io::Result<usize> { ... }
#[cfg(windows)]
pub fn get_recv_buf(_sock: RawSocket) -> io::Result<usize> { ... }
/// Enable client side TCP fast open.
#[cfg(target_os = "linux")]
pub fn set_tcp_fastopen_connect(fd: RawFd) -> Result<()> { ... }
#[cfg(all(unix, not(target_os = "linux")))]
pub fn set_tcp_fastopen_connect(_fd: RawFd) -> Result<()> { ... }
#[cfg(windows)]
pub fn set_tcp_fastopen_connect(_sock: RawSocket) -> Result<()> { ... }
/// Enable server side TCP fast open.
#[cfg(target_os = "linux")]
pub fn set_tcp_fastopen_backlog(fd: RawFd, backlog: usize) -> Result<()> { ... }
#[cfg(all(unix, not(target_os = "linux")))]
pub fn set_tcp_fastopen_backlog(_fd: RawFd, _backlog: usize) -> Result<()> { ... }
#[cfg(windows)]
pub fn set_tcp_fastopen_backlog(_sock: RawSocket, _backlog: usize) -> Result<()> { ... }
#[cfg(target_os = "linux")]
pub fn set_dscp(fd: RawFd, value: u8) -> Result<()> { ... }
#[cfg(all(unix, not(target_os = "linux")))]
pub fn set_dscp(_fd: RawFd, _value: u8) -> Result<()> { ... }
#[cfg(windows)]
pub fn set_dscp(_sock: RawSocket, _value: u8) -> Result<()> { ... }
#[cfg(target_os = "linux")]
pub fn get_socket_cookie(fd: RawFd) -> io::Result<u64> { ... }
#[cfg(all(unix, not(target_os = "linux")))]
pub fn get_socket_cookie(_fd: RawFd) -> io::Result<u64> { ... }
#[cfg(target_os = "linux")]
pub fn get_original_dest(fd: RawFd) -> Result<Option<SocketAddr>> { ... }
#[cfg(all(unix, not(target_os = "linux")))]
pub fn get_original_dest(_fd: RawFd) -> Result<Option<SocketAddr>> { ... }
#[cfg(windows)]
pub fn get_original_dest(_sock: RawSocket) -> Result<Option<SocketAddr>> { ... }
/// connect() to the given address while optionally binding to the specific source address.
///
/// `IP_BIND_ADDRESS_NO_PORT` is used
/// `IP_LOCAL_PORT_RANGE` is used if a port range is set on [`BindTo`].
pub async fn connect(addr: &SocketAddr, bind_to: Option<&BindTo>) -> Result<TcpStream> { ... }
/// connect() to the given Unix domain socket
#[cfg(unix)]
pub async fn connect_uds(path: &std::path::Path) -> Result<UnixStream> { ... }
/// Apply the given TCP keepalive settings to the given connection
pub fn set_tcp_keepalive(stream: &TcpStream, ka: &TcpKeepalive) -> Result<()> { ... }
/// The (copy of) the kernel struct tcp_info returns
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct TCP_INFO { ... }
/// The configuration for TCP keepalive
#[derive(Clone, Debug)]
pub struct TcpKeepalive { ... }
impl TCP_INFO {
    /// Create a new zeroed out [`TCP_INFO`]
    pub unsafe fn new() -> Self { ... }
    /// Return the size of [`TCP_INFO`]
    #[cfg(unix)]
    pub fn len() -> socklen_t { ... }
    /// Return the size of [`TCP_INFO`]
    #[cfg(windows)]
    pub fn len() -> usize { ... }
}
impl std::fmt::Display for TcpKeepalive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { ... }
}
```
## pingora-core/src/protocols/l4/listener.rs
```rust
use std::io;
use std::os::unix::io::AsRawFd;
use std::os::windows::io::AsRawSocket;
use tokio::net::TcpListener;
use tokio::net::UnixListener;
use crate::protocols::digest::{GetSocketDigest, SocketDigest};
use crate::protocols::l4::stream::Stream;
/// The type for generic listener for both TCP and Unix domain socket
#[derive(Debug)]
pub enum Listener {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(UnixListener),
}
impl From<TcpListener> for Listener {
    fn from(s: TcpListener) -> Self { ... }
}
#[cfg(unix)]
impl From<UnixListener> for Listener {
    fn from(s: UnixListener) -> Self { ... }
}
#[cfg(unix)]
impl AsRawFd for Listener {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd { ... }
}
#[cfg(windows)]
impl AsRawSocket for Listener {
    fn as_raw_socket(&self) -> std::os::windows::io::RawSocket { ... }
}
impl Listener {
    /// Accept a connection from the listening endpoint
    pub async fn accept(&self) -> io::Result<Stream> { ... }
}
```
## pingora-core/src/protocols/l4/mod.rs
```rust
pub mod ext {
}
pub mod listener {
}
pub mod socket {
}
pub mod stream {
}
```
## pingora-core/src/protocols/l4/socket.rs
```rust
use crate::{Error, OrErr};
use log::warn;
use nix::sys::socket::{getpeername, getsockname, SockaddrStorage};
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr as StdSockAddr;
use std::os::unix::net::SocketAddr as StdUnixSockAddr;
use tokio::net::unix::SocketAddr as TokioUnixSockAddr;
/// [`SocketAddr`] is a storage type that contains either a Internet (IP address)
/// socket address or a Unix domain socket address.
#[derive(Debug, Clone)]
pub enum SocketAddr {
    Inet(StdSockAddr),
    #[cfg(unix)]
    Unix(StdUnixSockAddr),
}
impl SocketAddr {
    /// Get a reference to the IP socket if it is one
    pub fn as_inet(&self) -> Option<&StdSockAddr> { ... }
    /// Get a reference to the Unix domain socket if it is one
    #[cfg(unix)]
    pub fn as_unix(&self) -> Option<&StdUnixSockAddr> { ... }
    /// Set the port if the address is an IP socket.
    pub fn set_port(&mut self, port: u16) { ... }
    #[cfg(unix)]
    pub fn from_raw_fd(fd: std::os::unix::io::RawFd, peer_addr: bool) -> Option<SocketAddr> { ... }
    #[cfg(windows)]
    pub fn from_raw_socket(
            sock: std::os::windows::io::RawSocket,
            is_peer_addr: bool,
        ) -> Option<SocketAddr> { ... }
}
impl std::fmt::Display for SocketAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { ... }
}
impl Hash for SocketAddr {
    fn hash<H: Hasher>(&self, state: &mut H) { ... }
}
impl PartialEq for SocketAddr {
    fn eq(&self, other: &Self) -> bool { ... }
}
impl PartialOrd for SocketAddr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { ... }
}
impl Ord for SocketAddr {
    fn cmp(&self, other: &Self) -> Ordering { ... }
}
impl Eq for SocketAddr {
}
impl std::str::FromStr for SocketAddr {
    #[cfg(unix)]
    fn from_str(s: &str) -> Result<Self, Self::Err> { ... }
    #[cfg(windows)]
    fn from_str(s: &str) -> Result<Self, Self::Err> { ... }
}
impl std::net::ToSocketAddrs for SocketAddr {
    fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> { ... }
}
impl From<StdSockAddr> for SocketAddr {
    fn from(sockaddr: StdSockAddr) -> Self { ... }
}
#[cfg(unix)]
impl From<StdUnixSockAddr> for SocketAddr {
    fn from(sockaddr: StdUnixSockAddr) -> Self { ... }
}
#[cfg(unix)]
impl TryFrom<TokioUnixSockAddr> for SocketAddr {
    fn try_from(value: TokioUnixSockAddr) -> Result<Self, Self::Error> { ... }
}
```
## pingora-core/src/protocols/l4/stream.rs
```rust
use async_trait::async_trait;
use futures::FutureExt;
use log::{debug, error};
use pingora_error::{ErrorType::*, OrErr, Result};
use std::io::IoSliceMut;
use std::os::unix::io::AsRawFd;
use std::os::windows::io::AsRawSocket;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime};
use tokio::io::Interest;
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt, BufStream, ReadBuf};
use tokio::net::TcpStream;
use tokio::net::UnixStream;
use crate::protocols::l4::ext::{set_tcp_keepalive, TcpKeepalive};
use crate::protocols::raw_connect::ProxyDigest;
use crate::protocols::{
    GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Shutdown, SocketDigest, Ssl,
    TimingDigest, UniqueID, UniqueIDType,
};
use crate::upstreams::peer::Tracer;
pub use async_write_vec::AsyncWriteVec;
pub mod async_write_vec {
    use bytes::Buf;
    use futures::ready;
    use std::future::Future;
    use std::io::IoSlice;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io;
    use tokio::io::AsyncWrite;
    #[must_use = "futures do nothing unless you `.await` or poll them"]
    pub struct WriteVec<'a, W, B> { ... }
    #[must_use = "futures do nothing unless you `.await` or poll them"]
    pub struct WriteVecAll<'a, W, B> { ... }
    pub trait AsyncWriteVec { ... }
    impl<W, B> Future for WriteVec<'_, W, B>
        where
            W: AsyncWriteVec + Unpin,
            B: Buf, {
        fn poll(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<usize>> { ... }
    }
    impl<W, B> Future for WriteVecAll<'_, W, B>
        where
            W: AsyncWriteVec + Unpin,
            B: Buf, {
        fn poll(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> { ... }
    }
    impl<T> AsyncWriteVec for T
        where
            T: AsyncWrite, {
        fn poll_write_vec<B: Buf>(
                    self: Pin<&mut Self>,
                    ctx: &mut Context,
                    buf: &mut B,
                ) -> Poll<io::Result<usize>> { ... }
    }
}
/// A concrete type for transport layer connection + extra fields for logging
#[derive(Debug)]
pub struct Stream { ... }
impl AsyncRead for RawStream {
    fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> { ... }
}
impl AsyncWrite for RawStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> { ... }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> { ... }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> { ... }
    fn poll_write_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[std::io::IoSlice<'_>],
        ) -> Poll<io::Result<usize>> { ... }
    fn is_write_vectored(&self) -> bool { ... }
}
#[cfg(unix)]
impl AsRawFd for RawStream {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd { ... }
}
#[cfg(windows)]
impl AsRawSocket for RawStream {
    fn as_raw_socket(&self) -> std::os::windows::io::RawSocket { ... }
}
impl RawStreamWrapper {
    pub fn new(stream: RawStream) -> Self { ... }
    #[cfg(target_os = "linux")]
    pub fn enable_rx_ts(&mut self, enable_rx_ts: bool) { ... }
}
impl AsyncRead for RawStreamWrapper {
    #[cfg(not(target_os = "linux"))]
    fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> { ... }
    #[cfg(target_os = "linux")]
    fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> { ... }
}
impl AsyncWrite for RawStreamWrapper {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> { ... }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> { ... }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> { ... }
    fn poll_write_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[std::io::IoSlice<'_>],
        ) -> Poll<io::Result<usize>> { ... }
    fn is_write_vectored(&self) -> bool { ... }
}
#[cfg(unix)]
impl AsRawFd for RawStreamWrapper {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd { ... }
}
#[cfg(windows)]
impl AsRawSocket for RawStreamWrapper {
    fn as_raw_socket(&self) -> std::os::windows::io::RawSocket { ... }
}
impl Stream {
    /// set TCP nodelay for this connection if `self` is TCP
    pub fn set_nodelay(&mut self) -> Result<()> { ... }
    /// set TCP keepalive settings for this connection if `self` is TCP
    pub fn set_keepalive(&mut self, ka: &TcpKeepalive) -> Result<()> { ... }
    #[cfg(target_os = "linux")]
    pub fn set_rx_timestamp(&mut self) -> Result<()> { ... }
    #[cfg(not(target_os = "linux"))]
    pub fn set_rx_timestamp(&mut self) -> io::Result<()> { ... }
}
impl From<TcpStream> for Stream {
    fn from(s: TcpStream) -> Self { ... }
}
#[cfg(unix)]
impl From<UnixStream> for Stream {
    fn from(s: UnixStream) -> Self { ... }
}
#[cfg(unix)]
impl AsRawFd for Stream {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd { ... }
}
#[cfg(windows)]
impl AsRawSocket for Stream {
    fn as_raw_socket(&self) -> std::os::windows::io::RawSocket { ... }
}
#[cfg(unix)]
impl UniqueID for Stream {
    fn id(&self) -> UniqueIDType { ... }
}
#[cfg(windows)]
impl UniqueID for Stream {
    fn id(&self) -> usize { ... }
}
impl Ssl for Stream {
}
#[async_trait]
impl Peek for Stream {
    async fn try_peek(&mut self, buf: &mut [u8]) -> std::io::Result<bool> { ... }
}
#[async_trait]
impl Shutdown for Stream {
    async fn shutdown(&mut self) { ... }
}
impl GetTimingDigest for Stream {
    fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> { ... }
    fn get_read_pending_time(&self) -> Duration { ... }
    fn get_write_pending_time(&self) -> Duration { ... }
}
impl GetProxyDigest for Stream {
    fn get_proxy_digest(&self) -> Option<Arc<ProxyDigest>> { ... }
    fn set_proxy_digest(&mut self, digest: ProxyDigest) { ... }
}
impl GetSocketDigest for Stream {
    fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> { ... }
    fn set_socket_digest(&mut self, socket_digest: SocketDigest) { ... }
}
impl Drop for Stream {
    fn drop(&mut self) { ... }
}
impl AsyncRead for Stream {
    fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> { ... }
}
impl AsyncWrite for Stream {
    fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> { ... }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> { ... }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> { ... }
    fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[std::io::IoSlice<'_>],
        ) -> Poll<io::Result<usize>> { ... }
    fn is_write_vectored(&self) -> bool { ... }
}
```
## pingora-core/src/protocols/mod.rs
```rust
pub use digest::{
    Digest, GetProxyDigest, GetSocketDigest, GetTimingDigest, ProtoDigest, SocketDigest,
    TimingDigest,
};
pub use l4::ext::TcpKeepalive;
pub use tls::ALPN;
use async_trait::async_trait;
use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::any::Any;
use tokio::io::{AsyncRead, AsyncWrite};
use l4::socket::SocketAddr;
use log::{debug, error};
use nix::sys::socket::{getpeername, SockaddrStorage, UnixAddr};
use std::os::unix::prelude::AsRawFd;
use std::os::windows::io::AsRawSocket;
use std::{net::SocketAddr as InetSocketAddr, path::Path};
use crate::protocols::tls::TlsRef;
pub mod http {
}
pub mod l4 {
}
pub mod raw_connect {
}
pub mod tls {
}
/// Define how a protocol should shutdown its connection.
#[async_trait]
pub trait Shutdown { ... }
/// Define how a given session/connection identifies itself.
pub trait UniqueID { ... }
/// Interface to get TLS info
pub trait Ssl { ... }
/// The ability peek data before consuming it
#[async_trait]
pub trait Peek { ... }
/// The abstraction of transport layer IO
pub trait IO { ... }
impl<
        T: AsyncRead
            + AsyncWrite
            + Shutdown
            + UniqueID
            + Ssl
            + GetTimingDigest
            + GetProxyDigest
            + GetSocketDigest
            + Peek
            + Unpin
            + Debug
            + Send
            + Sync,
    > IO for T
where
    T: 'static, {
    fn as_any(&self) -> &dyn Any { ... }
    fn into_any(self: Box<Self>) -> Box<dyn Any> { ... }
}
#[cfg(unix)]
impl ConnFdReusable for SocketAddr {
    fn check_fd_match<V: AsRawFd>(&self, fd: V) -> bool { ... }
}
#[cfg(windows)]
impl ConnSockReusable for SocketAddr {
    fn check_sock_match<V: AsRawSocket>(&self, sock: V) -> bool { ... }
}
#[cfg(unix)]
impl ConnFdReusable for Path {
    fn check_fd_match<V: AsRawFd>(&self, fd: V) -> bool { ... }
}
#[cfg(unix)]
impl ConnFdReusable for InetSocketAddr {
    fn check_fd_match<V: AsRawFd>(&self, fd: V) -> bool { ... }
}
#[cfg(windows)]
impl ConnSockReusable for InetSocketAddr {
    fn check_sock_match<V: AsRawSocket>(&self, sock: V) -> bool { ... }
}
```
## pingora-core/src/protocols/raw_connect.rs
```rust
use super::http::v1::client::HttpSession;
use super::http::v1::common::*;
use super::Stream;
use bytes::{BufMut, BytesMut};
use http::request::Parts as ReqHeader;
use http::Version;
use pingora_error::{Error, ErrorType::*, OrErr, Result};
use pingora_http::ResponseHeader;
use tokio::io::AsyncWriteExt;
/// Try to establish a CONNECT proxy via the given `stream`.
///
/// `request_header` should include the necessary request headers for the CONNECT protocol.
///
/// When successful, a [`Stream`] will be returned which is the established CONNECT proxy connection.
pub async fn connect(stream: Stream, request_header: &ReqHeader) -> Result<(Stream, ProxyDigest)> { ... }
/// Generate the CONNECT header for the given destination
pub fn generate_connect_header<'a, H, S>(
    host: &str,
    port: u16,
    headers: H,
) -> Result<Box<ReqHeader>>
where
    S: AsRef<[u8]>,
    H: Iterator<Item = (S, &'a Vec<u8>)>, { ... }
/// The information about the CONNECT proxy.
#[derive(Debug)]
pub struct ProxyDigest { ... }
/// The error returned when the CONNECT proxy fails to establish.
#[derive(Debug)]
pub struct ConnectProxyError { ... }
impl ProxyDigest {
    pub fn new(response: Box<ResponseHeader>) -> Self { ... }
}
impl ConnectProxyError {
    pub fn boxed_new(response: Box<ResponseHeader>) -> Box<Self> { ... }
}
impl std::fmt::Display for ConnectProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { ... }
}
impl std::error::Error for ConnectProxyError {
}
```
## pingora-core/src/protocols/tls/boringssl_openssl/client.rs
```rust
use crate::protocols::raw_connect::ProxyDigest;
use crate::protocols::tls::SslStream;
use crate::protocols::{
    GetProxyDigest, GetSocketDigest, GetTimingDigest, SocketDigest, TimingDigest, IO,
};
use crate::tls::{ssl, ssl::ConnectConfiguration, ssl_sys::X509_V_ERR_INVALID_CALL};
use pingora_error::{Error, ErrorType::*, OrErr, Result};
use std::sync::Arc;
use std::time::Duration;
/// Perform the TLS handshake for the given connection with the given configuration
pub async fn handshake<S: IO>(
    conn_config: ConnectConfiguration,
    domain: &str,
    io: S,
) -> Result<SslStream<S>> { ... }
impl<S> GetTimingDigest for SslStream<S>
where
    S: GetTimingDigest, {
    fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> { ... }
    fn get_read_pending_time(&self) -> Duration { ... }
    fn get_write_pending_time(&self) -> Duration { ... }
}
impl<S> GetProxyDigest for SslStream<S>
where
    S: GetProxyDigest, {
    fn get_proxy_digest(&self) -> Option<Arc<ProxyDigest>> { ... }
}
impl<S> GetSocketDigest for SslStream<S>
where
    S: GetSocketDigest, {
    fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> { ... }
    fn set_socket_digest(&mut self, socket_digest: SocketDigest) { ... }
}
```
## pingora-core/src/protocols/tls/boringssl_openssl/mod.rs
```rust
use pingora_boringssl as ssl_lib;
use pingora_openssl as ssl_lib;
use ssl_lib::{ssl::SslRef, x509::X509};
pub use stream::*;
pub mod client {
}
pub mod server {
}
```
## pingora-core/src/protocols/tls/boringssl_openssl/server.rs
```rust
use crate::listeners::TlsAcceptCallbacks;
use crate::protocols::tls::SslStream;
use crate::protocols::{Shutdown, IO};
use crate::tls::ext;
use crate::tls::ext::ssl_from_acceptor;
use crate::tls::ssl;
use crate::tls::ssl::SslAcceptor;
use async_trait::async_trait;
use log::warn;
use pingora_error::{ErrorType::*, OrErr, Result};
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
/// Prepare a TLS stream for handshake
pub fn prepare_tls_stream<S: IO>(ssl_acceptor: &SslAcceptor, io: S) -> Result<SslStream<S>> { ... }
/// Perform TLS handshake for the given connection with the given configuration
pub async fn handshake<S: IO>(ssl_acceptor: &SslAcceptor, io: S) -> Result<SslStream<S>> { ... }
/// Perform TLS handshake for the given connection with the given configuration and callbacks
pub async fn handshake_with_callback<S: IO>(
    ssl_acceptor: &SslAcceptor,
    io: S,
    callbacks: &TlsAcceptCallbacks,
) -> Result<SslStream<S>> { ... }
/// Resumable TLS server side handshake.
#[async_trait]
pub trait ResumableAccept { ... }
#[async_trait]
impl<S> Shutdown for SslStream<S>
where
    S: AsyncRead + AsyncWrite + Sync + Unpin + Send, {
    async fn shutdown(&mut self) { ... }
}
#[async_trait]
impl<S: AsyncRead + AsyncWrite + Send + Unpin> ResumableAccept for SslStream<S> {
    async fn start_accept(mut self: Pin<&mut Self>) -> Result<bool, ssl::Error> { ... }
    async fn resume_accept(mut self: Pin<&mut Self>) -> Result<(), ssl::Error> { ... }
}
```
## pingora-core/src/protocols/tls/boringssl_openssl/stream.rs
```rust
use crate::protocols::digest::TimingDigest;
use crate::protocols::tls::{SslDigest, ALPN};
use crate::protocols::{Peek, Ssl, UniqueID, UniqueIDType};
use crate::tls::{self, ssl, tokio_ssl::SslStream as InnerSsl};
use crate::utils::tls::{get_organization, get_serial};
use log::warn;
use pingora_error::{ErrorType::*, OrErr, Result};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::SystemTime;
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};
use pingora_boringssl as ssl_lib;
use pingora_openssl as ssl_lib;
use ssl_lib::{hash::MessageDigest, ssl::SslRef};
use std::ops::{Deref, DerefMut};
/// The TLS connection
#[derive(Debug)]
pub struct SslStream<T> { ... }
impl<T> SslStream<T>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin, {
    /// Create a new TLS connection from the given `stream`
    ///
    /// The caller needs to perform [`Self::connect()`] or [`Self::accept()`] to perform TLS
    /// handshake after.
    pub fn new(ssl: ssl::Ssl, stream: T) -> Result<Self> { ... }
    /// Connect to the remote TLS server as a client
    pub async fn connect(&mut self) -> Result<(), ssl::Error> { ... }
    /// Finish the TLS handshake from client as a server
    pub async fn accept(&mut self) -> Result<(), ssl::Error> { ... }
}
impl<T> SslStream<T> {
    pub fn ssl_digest(&self) -> Option<Arc<SslDigest>> { ... }
}
impl<T> Deref for SslStream<T> {
    fn deref(&self) -> &Self::Target { ... }
}
impl<T> DerefMut for SslStream<T> {
    fn deref_mut(&mut self) -> &mut Self::Target { ... }
}
impl<T> AsyncRead for SslStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin, {
    fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> { ... }
}
impl<T> AsyncWrite for SslStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin, {
    fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> { ... }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> { ... }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> { ... }
    fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[std::io::IoSlice<'_>],
        ) -> Poll<io::Result<usize>> { ... }
    fn is_write_vectored(&self) -> bool { ... }
}
impl<T> UniqueID for SslStream<T>
where
    T: UniqueID, {
    fn id(&self) -> UniqueIDType { ... }
}
impl<T> Ssl for SslStream<T> {
    fn get_ssl(&self) -> Option<&ssl::SslRef> { ... }
    fn get_ssl_digest(&self) -> Option<Arc<SslDigest>> { ... }
    /// Return selected ALPN if any
    fn selected_alpn_proto(&self) -> Option<ALPN> { ... }
}
impl SslDigest {
    pub fn from_ssl(ssl: &SslRef) -> Self { ... }
}
impl<T> Peek for SslStream<T> {
}
```
## pingora-core/src/protocols/tls/digest.rs
```rust
/// The TLS connection information
/// The TLS connection information
#[derive(Clone, Debug)]
pub struct SslDigest { ... }
```
## pingora-core/src/protocols/tls/mod.rs
```rust
pub use digest::*;
pub use boringssl_openssl::*;
pub use rustls::*;
pub use noop_tls::*;
pub mod digest {
}
#[cfg(not(feature = "any_tls"))]
pub mod noop_tls {
}
/// The protocol for Application-Layer Protocol Negotiation
#[derive(Hash, Clone, Debug)]
pub enum ALPN {
    /// Prefer HTTP/1.1 only
    H1,
    /// Prefer HTTP/2 only
    H2,
    /// Prefer HTTP/2 over HTTP/1.1
    H2H1,
}
impl std::fmt::Display for ALPN {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { ... }
}
impl ALPN {
    /// Create a new ALPN according to the `max` and `min` version constraints
    pub fn new(max: u8, min: u8) -> Self { ... }
    /// Return the max http version this [`ALPN`] allows
    pub fn get_max_http_version(&self) -> u8 { ... }
    /// Return the min http version this [`ALPN`] allows
    pub fn get_min_http_version(&self) -> u8 { ... }
}
```
## pingora-core/src/protocols/tls/noop_tls/mod.rs
```rust
pub mod connectors {
    use pingora_error::Result;
    use crate::{
        connectors::ConnectorOptions,
        protocols::{ALPN, IO},
        upstreams::peer::Peer,
    };
    use super::stream::SslStream;
    pub async fn connect<T, P>(
            _: T,
            _: &P,
            _: Option<ALPN>,
            _: &TlsConnector,
        ) -> Result<SslStream<T>>
        where
            T: IO,
            P: Peer + Send + Sync, { ... }
    #[derive(Clone)]
    pub struct Connector { ... }
    #[derive(Clone)]
    pub struct TlsConnector; { ... }
    pub struct TlsSettings; { ... }
    impl Connector {
        pub fn new(_: Option<ConnectorOptions>) -> Self { ... }
    }
}
pub mod listeners {
    use pingora_error::Result;
    use tokio::io::{AsyncRead, AsyncWrite};
    use super::stream::SslStream;
    pub struct Acceptor; { ... }
    pub struct TlsSettings; { ... }
    impl TlsSettings {
        pub fn build(&self) -> Acceptor { ... }
        pub fn intermediate(_: &str, _: &str) -> Result<Self> { ... }
        pub fn enable_h2(&mut self) { ... }
    }
    impl Acceptor {
        pub async fn tls_handshake<S: AsyncRead + AsyncWrite>(&self, _: S) -> Result<SslStream<S>> { ... }
    }
}
pub mod stream {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };
    use async_trait::async_trait;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use crate::protocols::{
        GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Shutdown, Ssl, UniqueID,
    };
    /// A TLS session over a stream.
    #[derive(Debug)]
    pub struct SslStream<S> { ... }
    impl<S> Default for SslStream<S> {
        fn default() -> Self { ... }
    }
    impl<S> AsyncRead for SslStream<S>
        where
            S: AsyncRead + AsyncWrite, {
        fn poll_read(
                    self: Pin<&mut Self>,
                    _ctx: &mut Context<'_>,
                    _buf: &mut ReadBuf<'_>,
                ) -> Poll<std::io::Result<()>> { ... }
    }
    impl<S> AsyncWrite for SslStream<S>
        where
            S: AsyncRead + AsyncWrite, {
        fn poll_write(
                    self: Pin<&mut Self>,
                    _ctx: &mut Context<'_>,
                    buf: &[u8],
                ) -> Poll<std::io::Result<usize>> { ... }
        fn poll_flush(self: Pin<&mut Self>, _ctx: &mut Context<'_>) -> Poll<std::io::Result<()>> { ... }
        fn poll_shutdown(
                    self: Pin<&mut Self>,
                    _ctx: &mut Context<'_>,
                ) -> Poll<std::io::Result<()>> { ... }
    }
    #[async_trait]
    impl<S: Send> Shutdown for SslStream<S> {
        async fn shutdown(&mut self) { ... }
    }
    impl<S> UniqueID for SslStream<S> {
        fn id(&self) -> crate::protocols::UniqueIDType { ... }
    }
    impl<S> Ssl for SslStream<S> {
    }
    impl<S> GetTimingDigest for SslStream<S> {
        fn get_timing_digest(&self) -> Vec<Option<crate::protocols::TimingDigest>> { ... }
    }
    impl<S> GetProxyDigest for SslStream<S> {
        fn get_proxy_digest(
                    &self,
                ) -> Option<std::sync::Arc<crate::protocols::raw_connect::ProxyDigest>> { ... }
    }
    impl<S> GetSocketDigest for SslStream<S> {
        fn get_socket_digest(&self) -> Option<std::sync::Arc<crate::protocols::SocketDigest>> { ... }
    }
    impl<S> Peek for SslStream<S> {
    }
}
pub mod utils {
    use std::fmt::Display;
    use super::CertWrapper;
    pub fn get_organization_unit(_: &CertWrapper) -> Option<String> { ... }
    #[derive(Debug, Clone, Hash)]
    pub struct CertKey; { ... }
    impl Display for CertKey {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { ... }
    }
}
pub struct TlsRef; { ... }
#[derive(Debug)]
pub struct CertWrapper; { ... }
impl CertWrapper {
    pub fn not_after(&self) -> &str { ... }
}
```
## pingora-core/src/protocols/tls/rustls/client.rs
```rust
use crate::protocols::tls::rustls::TlsStream;
use crate::protocols::IO;
use pingora_error::ErrorType::TLSHandshakeFailure;
use pingora_error::{Error, OrErr, Result};
use pingora_rustls::TlsConnector;
pub async fn handshake<S: IO>(
    connector: &TlsConnector,
    domain: &str,
    io: S,
) -> Result<TlsStream<S>> { ... }
```
## pingora-core/src/protocols/tls/rustls/mod.rs
```rust
pub use stream::*;
use crate::utils::tls::WrappedX509;
pub mod client {
}
pub mod server {
}
pub struct TlsRef; { ... }
```
## pingora-core/src/protocols/tls/rustls/server.rs
```rust
use crate::listeners::TlsAcceptCallbacks;
use crate::protocols::tls::rustls::TlsStream;
use crate::protocols::IO;
use crate::{listeners::tls::Acceptor, protocols::Shutdown};
use async_trait::async_trait;
use log::warn;
use pingora_error::{ErrorType::*, OrErr, Result};
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
/// Perform TLS handshake for the given connection with the given configuration
pub async fn handshake<S: IO>(acceptor: &Acceptor, io: S) -> Result<TlsStream<S>> { ... }
/// Perform TLS handshake for the given connection with the given configuration and callbacks
/// callbacks are currently not supported within pingora Rustls and are ignored
pub async fn handshake_with_callback<S: IO>(
    acceptor: &Acceptor,
    io: S,
    _callbacks: &TlsAcceptCallbacks,
) -> Result<TlsStream<S>> { ... }
#[async_trait]
impl<S> Shutdown for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Sync + Unpin + Send, {
    async fn shutdown(&mut self) { ... }
}
```
## pingora-core/src/protocols/tls/rustls/stream.rs
```rust
use std::io::Result as IoResult;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};
use crate::listeners::tls::Acceptor;
use crate::protocols::raw_connect::ProxyDigest;
use crate::protocols::{tls::SslDigest, Peek, TimingDigest, UniqueIDType};
use crate::protocols::{
    GetProxyDigest, GetSocketDigest, GetTimingDigest, SocketDigest, Ssl, UniqueID, ALPN,
};
use crate::utils::tls::get_organization_serial_bytes;
use pingora_error::ErrorType::{AcceptError, ConnectError, InternalError, TLSHandshakeFailure};
use pingora_error::{OkOrErr, OrErr, Result};
use pingora_rustls::TlsStream as RusTlsStream;
use pingora_rustls::{hash_certificate, NoDebug};
use pingora_rustls::{Accept, Connect, ServerName, TlsConnector};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use x509_parser::nom::AsBytes;
#[derive(Debug)]
pub struct InnerStream<T> { ... }
/// The TLS connection
#[derive(Debug)]
pub struct TlsStream<T> { ... }
impl<T> TlsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send, {
    /// Create a new TLS connection from the given `stream`
    ///
    /// Using RustTLS the stream is only returned after the handshake.
    /// The caller does therefor not need to perform [`Self::connect()`].
    pub async fn from_connector(connector: &TlsConnector, domain: &str, stream: T) -> Result<Self> { ... }
}
impl<S> GetSocketDigest for TlsStream<S>
where
    S: GetSocketDigest, {
    fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> { ... }
    fn set_socket_digest(&mut self, socket_digest: SocketDigest) { ... }
}
impl<S> GetTimingDigest for TlsStream<S>
where
    S: GetTimingDigest, {
    fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> { ... }
    fn get_read_pending_time(&self) -> Duration { ... }
    fn get_write_pending_time(&self) -> Duration { ... }
}
impl<S> GetProxyDigest for TlsStream<S>
where
    S: GetProxyDigest, {
    fn get_proxy_digest(&self) -> Option<Arc<ProxyDigest>> { ... }
}
impl<T> TlsStream<T> {
    pub fn ssl_digest(&self) -> Option<Arc<SslDigest>> { ... }
}
impl<T> Deref for TlsStream<T> {
    fn deref(&self) -> &Self::Target { ... }
}
impl<T> DerefMut for TlsStream<T> {
    fn deref_mut(&mut self) -> &mut Self::Target { ... }
}
impl<T> AsyncRead for TlsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin, {
    fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<IoResult<()>> { ... }
}
impl<T> AsyncWrite for TlsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin, {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<IoResult<usize>> { ... }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<IoResult<()>> { ... }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<IoResult<()>> { ... }
    fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[std::io::IoSlice<'_>],
        ) -> Poll<IoResult<usize>> { ... }
    fn is_write_vectored(&self) -> bool { ... }
}
impl<T> UniqueID for TlsStream<T>
where
    T: UniqueID, {
    fn id(&self) -> UniqueIDType { ... }
}
impl<T> Ssl for TlsStream<T> {
    fn get_ssl_digest(&self) -> Option<Arc<SslDigest>> { ... }
    fn selected_alpn_proto(&self) -> Option<ALPN> { ... }
}
impl<S> GetSocketDigest for InnerStream<S>
where
    S: GetSocketDigest, {
    fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> { ... }
    fn set_socket_digest(&mut self, socket_digest: SocketDigest) { ... }
}
impl<S> GetTimingDigest for InnerStream<S>
where
    S: GetTimingDigest, {
    fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> { ... }
}
impl<S> GetProxyDigest for InnerStream<S>
where
    S: GetProxyDigest, {
    fn get_proxy_digest(&self) -> Option<Arc<ProxyDigest>> { ... }
}
impl<S> Peek for TlsStream<S> {
}
```
## pingora-core/src/protocols/windows.rs
```rust
use std::os::windows::io::RawSocket;
use std::{io, mem, net::SocketAddr};
use windows_sys::Win32::Networking::WinSock::{
    getpeername, getsockname, AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_STORAGE,
    SOCKET,
};
```
## pingora-core/src/server/configuration/mod.rs
```rust
use clap::Parser;
use log::{debug, trace};
use pingora_error::{Error, ErrorType::*, OrErr, Result};
use serde::{Deserialize, Serialize};
use std::fs;
/// The configuration file
///
/// Pingora configuration files are by default YAML files, but any key value format can potentially
/// be used.
///
/// # Extension
/// New keys can be added to the configuration files which this configuration object will ignore.
/// Then, users can parse these key-values to pass to their code to use.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConf { ... }
/// Command-line options
///
/// Call `Opt::parse_args()` to build this object from the process's command line arguments.
#[derive(Parser, Debug, Default)]
#[clap(name = "basic", long_about = None)]
pub struct Opt { ... }
impl Default for ServerConf {
    fn default() -> Self { ... }
}
impl ServerConf {
    pub fn load_from_yaml<P>(path: P) -> Result<Self>
        where
            P: AsRef<std::path::Path> + std::fmt::Display, { ... }
    pub fn load_yaml_with_opt_override(opt: &Opt) -> Result<Self> { ... }
    pub fn new() -> Option<Self> { ... }
    pub fn new_with_opt_override(opt: &Opt) -> Option<Self> { ... }
    pub fn from_yaml(conf_str: &str) -> Result<Self> { ... }
    pub fn to_yaml(&self) -> String { ... }
    pub fn validate(self) -> Result<Self> { ... }
    pub fn merge_with_opt(&mut self, opt: &Opt) { ... }
}
/// Create an instance of Opt by parsing the current command-line args.
/// This is equivalent to running `Opt::parse` but does not require the
/// caller to have included the `clap::Parser`
impl Opt {
    pub fn parse_args() -> Self { ... }
}
```
## pingora-core/src/server/daemon.rs
```rust
use daemonize::Daemonize;
use log::{debug, error};
use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::os::unix::prelude::OpenOptionsExt;
use std::path::Path;
use crate::server::configuration::ServerConf;
/// Start a server instance as a daemon.
#[cfg(unix)]
pub fn daemonize(conf: &ServerConf) { ... }
```
## pingora-core/src/server/mod.rs
```rust
use async_trait::async_trait;
use daemon::daemonize;
use log::{debug, error, info, warn};
use pingora_runtime::Runtime;
use pingora_timeout::fast_timeout;
use sentry::ClientOptions;
use std::sync::Arc;
use std::thread;
use tokio::signal::unix;
use tokio::sync::{watch, Mutex};
use tokio::time::{sleep, Duration};
use crate::services::Service;
use configuration::{Opt, ServerConf};
pub use transfer_fd::Fds;
use pingora_error::{Error, ErrorType, Result};
pub mod configuration {
}
/// The type of shutdown process that has been requested.
#[derive(Debug)]
pub enum ShutdownSignal {
    /// Send file descriptors to the new process before starting runtime shutdown with
    /// [ServerConf::graceful_shutdown_timeout_seconds] timeout.
    GracefulUpgrade,
    /// Wait for [ServerConf::grace_period_seconds] before starting runtime shutdown with
    /// [ServerConf::graceful_shutdown_timeout_seconds] timeout.
    GracefulTerminate,
    /// Shutdown with no timeout for runtime shutdown.
    FastShutdown,
}
/// A Unix shutdown watcher that awaits for Unix signals.
///
/// - `SIGQUIT`: graceful upgrade
/// - `SIGTERM`: graceful terminate
/// - `SIGINT`: fast shutdown
#[cfg(unix)]
pub struct UnixShutdownSignalWatch; { ... }
/// Arguments to configure running of the pingora server.
pub struct RunArgs { ... }
/// The server object
///
/// This object represents an entire pingora server process which may have multiple independent
/// services (see [crate::services]). The server object handles signals, reading configuration,
/// zero downtime upgrade and error reporting.
pub struct Server { ... }
/// Watcher of a shutdown signal, e.g., [UnixShutdownSignalWatch] for Unix-like
/// platforms.
#[async_trait]
pub trait ShutdownSignalWatch { ... }
#[cfg(unix)]
#[async_trait]
impl ShutdownSignalWatch for UnixShutdownSignalWatch {
    async fn recv(&self) -> ShutdownSignal { ... }
}
impl Default for RunArgs {
    #[cfg(unix)]
    fn default() -> Self { ... }
    #[cfg(windows)]
    fn default() -> Self { ... }
}
impl Server {
    /// Create a new [`Server`], using the [`Opt`] and [`ServerConf`] values provided
    ///
    /// This method is intended for pingora frontends that are NOT using the built-in
    /// command line and configuration file parsing, and are instead using their own.
    ///
    /// If a configuration file path is provided as part of `opt`, it will be ignored
    /// and a warning will be logged.
    pub fn new_with_opt_and_conf(raw_opt: impl Into<Option<Opt>>, mut conf: ServerConf) -> Server { ... }
    /// Create a new [`Server`].
    ///
    /// Only one [`Server`] needs to be created for a process. A [`Server`] can hold multiple
    /// independent services.
    ///
    /// Command line options can either be passed by parsing the command line arguments via
    /// `Opt::parse_args()`, or be generated by other means.
    pub fn new(opt: impl Into<Option<Opt>>) -> Result<Server> { ... }
    /// Add a service to this server.
    ///
    /// A service is anything that implements [`Service`].
    pub fn add_service(&mut self, service: impl Service + 'static) { ... }
    /// Similar to [`Self::add_service()`], but take a list of services
    pub fn add_services(&mut self, services: Vec<Box<dyn Service>>) { ... }
    /// Prepare the server to start
    ///
    /// When trying to zero downtime upgrade from an older version of the server which is already
    /// running, this function will try to get all its listening sockets in order to take them over.
    pub fn bootstrap(&mut self) { ... }
    /// Start the server using [Self::run] and default [RunArgs].
    pub fn run_forever(self) -> ! { ... }
    /// Start the server
    ///
    /// This function will block forever until the server needs to quit. So this would be the last
    /// function to call for this object.
    ///
    /// Note: this function may fork the process for daemonization, so any additional threads created
    /// before this function will be lost to any service logic once this function is called.
    pub fn run(mut self, run_args: RunArgs) { ... }
}
```
## pingora-core/src/server/transfer_fd/mod.rs
```rust
use log::{debug, error, warn};
use nix::errno::Errno;
use nix::sys::socket::{self, AddressFamily, RecvMsg, SockFlag, SockType, UnixAddr};
use nix::sys::stat;
use nix::{Error, NixPath};
use std::collections::HashMap;
use std::io::Write;
use std::io::{IoSlice, IoSliceMut};
use std::os::unix::io::RawFd;
use std::{thread, time};
#[cfg(target_os = "linux")]
pub fn get_fds_from<P>(path: &P, payload: &mut [u8]) -> Result<(Vec<RawFd>, usize), Error>
where
    P: ?Sized + NixPath + std::fmt::Display, { ... }
#[cfg(not(target_os = "linux"))]
pub fn get_fds_from<P>(_path: &P, _payload: &mut [u8]) -> Result<(Vec<RawFd>, usize), Error>
where
    P: ?Sized + NixPath + std::fmt::Display, { ... }
#[cfg(target_os = "linux")]
pub fn send_fds_to<P>(fds: Vec<RawFd>, payload: &[u8], path: &P) -> Result<usize, Error>
where
    P: ?Sized + NixPath + std::fmt::Display, { ... }
#[cfg(not(target_os = "linux"))]
pub fn send_fds_to<P>(_fds: Vec<RawFd>, _payload: &[u8], _path: &P) -> Result<usize, Error>
where
    P: ?Sized + NixPath + std::fmt::Display, { ... }
/// Container for open file descriptors and their associated bind addresses.
pub struct Fds { ... }
impl Fds {
    pub fn new() -> Self { ... }
    pub fn add(&mut self, bind: String, fd: RawFd) { ... }
    pub fn get(&self, bind: &str) -> Option<&RawFd> { ... }
    pub fn serialize(&self) -> (Vec<String>, Vec<RawFd>) { ... }
    pub fn deserialize(&mut self, binds: Vec<String>, fds: Vec<RawFd>) { ... }
    pub fn send_to_sock<P>(&self, path: &P) -> Result<usize, Error>
        where
            P: ?Sized + NixPath + std::fmt::Display, { ... }
    pub fn get_from_sock<P>(&mut self, path: &P) -> Result<(), Error>
        where
            P: ?Sized + NixPath + std::fmt::Display, { ... }
}
```
## pingora-core/src/services/background.rs
```rust
use async_trait::async_trait;
use std::sync::Arc;
use super::Service;
use crate::server::ListenFds;
use crate::server::ShutdownWatch;
pub fn background_service<SV>(name: &str, task: SV) -> GenBackgroundService<SV> { ... }
/// A generic type of background service
pub struct GenBackgroundService<A> { ... }
/// The background service interface
#[async_trait]
pub trait BackgroundService { ... }
impl<A> GenBackgroundService<A> {
    /// Generates a background service that can run in the pingora runtime
    pub fn new(name: String, task: Arc<A>) -> Self { ... }
    /// Return the task behind [Arc] to be shared other logic.
    pub fn task(&self) -> Arc<A> { ... }
}
#[async_trait]
impl<A> Service for GenBackgroundService<A>
where
    A: BackgroundService + Send + Sync + 'static, {
    async fn start_service(
            &mut self,
            #[cfg(unix)] _fds: Option<ListenFds>,
            shutdown: ShutdownWatch,
            _listeners_per_fd: usize,
        ) { ... }
    fn name(&self) -> &str { ... }
    fn threads(&self) -> Option<usize> { ... }
}
```
## pingora-core/src/services/listening.rs
```rust
use crate::apps::ServerApp;
use crate::listeners::tls::TlsSettings;
use crate::listeners::{Listeners, ServerAddress, TcpSocketOptions, TransportStack};
use crate::protocols::Stream;
use crate::server::ListenFds;
use crate::server::ShutdownWatch;
use crate::services::Service as ServiceTrait;
use async_trait::async_trait;
use log::{debug, error, info};
use pingora_error::Result;
use pingora_runtime::current_handle;
use std::fs::Permissions;
use std::sync::Arc;
use crate::apps::prometheus_http_app::PrometheusServer;
/// The type of service that is associated with a list of listening endpoints and a particular application
pub struct Service<A> { ... }
impl<A> Service<A> {
    /// Create a new [`Service`] with the given application (see [`crate::apps`]).
    pub fn new(name: String, app_logic: A) -> Self { ... }
    /// Create a new [`Service`] with the given application (see [`crate::apps`]) and the given
    /// [`Listeners`].
    pub fn with_listeners(name: String, listeners: Listeners, app_logic: A) -> Self { ... }
    /// Get the [`Listeners`], mostly to add more endpoints.
    pub fn endpoints(&mut self) -> &mut Listeners { ... }
    /// Add a TCP listening endpoint with the given address (e.g., `127.0.0.1:8000`).
    pub fn add_tcp(&mut self, addr: &str) { ... }
    /// Add a TCP listening endpoint with the given [`TcpSocketOptions`].
    pub fn add_tcp_with_settings(&mut self, addr: &str, sock_opt: TcpSocketOptions) { ... }
    /// Add a Unix domain socket listening endpoint with the given path.
    ///
    /// Optionally take a permission of the socket file. The default is read and write access for
    /// everyone (0o666).
    #[cfg(unix)]
    pub fn add_uds(&mut self, addr: &str, perm: Option<Permissions>) { ... }
    /// Add a TLS listening endpoint with the given certificate and key paths.
    pub fn add_tls(&mut self, addr: &str, cert_path: &str, key_path: &str) -> Result<()> { ... }
    /// Add a TLS listening endpoint with the given [`TlsSettings`] and [`TcpSocketOptions`].
    pub fn add_tls_with_settings(
            &mut self,
            addr: &str,
            sock_opt: Option<TcpSocketOptions>,
            settings: TlsSettings,
        ) { ... }
    /// Add an endpoint according to the given [`ServerAddress`]
    pub fn add_address(&mut self, addr: ServerAddress) { ... }
    /// Get a reference to the application inside this service
    pub fn app_logic(&self) -> Option<&A> { ... }
    /// Get a mutable reference to the application inside this service
    pub fn app_logic_mut(&mut self) -> Option<&mut A> { ... }
}
impl<A: ServerApp + Send + Sync + 'static> Service<A> {
    pub async fn handle_event(event: Stream, app_logic: Arc<A>, shutdown: ShutdownWatch) { ... }
}
#[async_trait]
impl<A: ServerApp + Send + Sync + 'static> ServiceTrait for Service<A> {
    async fn start_service(
            &mut self,
            #[cfg(unix)] fds: Option<ListenFds>,
            shutdown: ShutdownWatch,
            listeners_per_fd: usize,
        ) { ... }
    fn name(&self) -> &str { ... }
    fn threads(&self) -> Option<usize> { ... }
}
impl Service<PrometheusServer> {
    /// The Prometheus HTTP server
    ///
    /// The HTTP server endpoint that reports Prometheus metrics collected in the entire service
    pub fn prometheus_http_service() -> Self { ... }
}
```
## pingora-core/src/services/mod.rs
```rust
use async_trait::async_trait;
use crate::server::ListenFds;
use crate::server::ShutdownWatch;
pub mod background {
}
pub mod listening {
}
/// The service interface
#[async_trait]
pub trait Service { ... }
```
## pingora-core/src/tls/mod.rs
```rust
pub mod ssl {
    use super::error::ErrorStack;
    use super::x509::verify::X509VerifyParamRef;
    use super::x509::{X509VerifyResult, X509};
    /// A standard implementation of protocol selection for Application Layer Protocol Negotiation
    /// (ALPN).
    pub fn select_next_proto<'a>(_server: &[u8], _client: &'a [u8]) -> Option<&'a [u8]> { ... }
    /// An error returned from an ALPN selection callback.
    pub struct AlpnError; { ... }
    /// A type which allows for configuration of a client-side TLS session before connection.
    pub struct ConnectConfiguration; { ... }
    /// An SSL error.
    #[derive(Debug)]
    pub struct Error; { ... }
    /// An error code returned from SSL functions.
    #[derive(PartialEq)]
    pub struct ErrorCode(i32); { ... }
    /// An identifier of a session name type.
    pub struct NameType; { ... }
    /// The state of an SSL/TLS session.
    pub struct Ssl; { ... }
    /// A type which wraps server-side streams in a TLS session.
    pub struct SslAcceptor; { ... }
    /// A builder for `SslAcceptor`s.
    pub struct SslAcceptorBuilder; { ... }
    /// Reference to an [`SslCipher`].
    pub struct SslCipherRef; { ... }
    /// A type which wraps client-side streams in a TLS session.
    pub struct SslConnector; { ... }
    /// A builder for `SslConnector`s.
    pub struct SslConnectorBuilder; { ... }
    /// A context object for TLS streams.
    pub struct SslContext; { ... }
    /// A builder for `SslContext`s.
    pub struct SslContextBuilder; { ... }
    /// Reference to [`SslContext`]
    pub struct SslContextRef; { ... }
    /// An identifier of the format of a certificate or key file.
    pub struct SslFiletype; { ... }
    /// A type specifying the kind of protocol an `SslContext`` will speak.
    pub struct SslMethod; { ... }
    /// Reference to an [`Ssl`].
    pub struct SslRef; { ... }
    /// Options controlling the behavior of certificate verification.
    pub struct SslVerifyMode; { ... }
    /// An SSL/TLS protocol version.
    pub struct SslVersion; { ... }
    impl ConnectConfiguration {
        /// Configures the use of Server Name Indication (SNI) when connecting.
        pub fn set_use_server_name_indication(&mut self, _use_sni: bool) { ... }
        /// Configures the use of hostname verification when connecting.
        pub fn set_verify_hostname(&mut self, _verify_hostname: bool) { ... }
        /// Returns an `Ssl` configured to connect to the provided domain.
        pub fn into_ssl(self, _domain: &str) -> Result<Ssl, ErrorStack> { ... }
        /// Like `SslContextBuilder::set_verify`.
        pub fn set_verify(&mut self, _mode: SslVerifyMode) { ... }
        /// Like `SslContextBuilder::set_alpn_protos`.
        pub fn set_alpn_protos(&mut self, _protocols: &[u8]) -> Result<(), ErrorStack> { ... }
        /// Returns a mutable reference to the X509 verification configuration.
        pub fn param_mut(&mut self) -> &mut X509VerifyParamRef { ... }
    }
    impl Error {
        pub fn code(&self) -> ErrorCode { ... }
    }
    impl Ssl {
        /// Creates a new `Ssl`.
        pub fn new(_ctx: &SslContextRef) -> Result<Ssl, ErrorStack> { ... }
    }
    impl SslAcceptor {
        /// Creates a new builder configured to connect to non-legacy clients. This should
        /// generally be considered a reasonable default choice.
        pub fn mozilla_intermediate_v5(
                    _method: SslMethod,
                ) -> Result<SslAcceptorBuilder, ErrorStack> { ... }
    }
    impl SslAcceptorBuilder {
        /// Consumes the builder, returning a `SslAcceptor`.
        pub fn build(self) -> SslAcceptor { ... }
        /// Sets the callback used by a server to select a protocol for Application Layer Protocol
        /// Negotiation (ALPN).
        pub fn set_alpn_select_callback<F>(&mut self, _callback: F)
                where
                    F: for<'a> Fn(&mut SslRef, &'a [u8]) -> Result<&'a [u8], AlpnError>
                        + 'static
                        + Sync
                        + Send, { ... }
        /// Loads a certificate chain from a file.
        pub fn set_certificate_chain_file<P: AsRef<std::path::Path>>(
                    &mut self,
                    _file: P,
                ) -> Result<(), ErrorStack> { ... }
        /// Loads the private key from a file.
        pub fn set_private_key_file<P: AsRef<std::path::Path>>(
                    &mut self,
                    _file: P,
                    _file_type: SslFiletype,
                ) -> Result<(), ErrorStack> { ... }
        /// Sets the maximum supported protocol version.
        pub fn set_max_proto_version(
                    &mut self,
                    _version: Option<SslVersion>,
                ) -> Result<(), ErrorStack> { ... }
    }
    impl SslCipherRef {
        /// Returns the name of the cipher.
        pub fn name(&self) -> &'static str { ... }
    }
    impl SslConnector {
        /// Creates a new builder for TLS connections.
        pub fn builder(_method: SslMethod) -> Result<SslConnectorBuilder, ErrorStack> { ... }
        /// Returns a structure allowing for configuration of a single TLS session before connection.
        pub fn configure(&self) -> Result<ConnectConfiguration, ErrorStack> { ... }
        /// Returns a shared reference to the inner raw `SslContext`.
        pub fn context(&self) -> &SslContextRef { ... }
    }
    impl SslConnectorBuilder {
        /// Consumes the builder, returning an `SslConnector`.
        pub fn build(self) -> SslConnector { ... }
        /// Sets the list of supported ciphers for protocols before TLSv1.3.
        pub fn set_cipher_list(&mut self, _cipher_list: &str) -> Result<(), ErrorStack> { ... }
        /// Sets the context’s supported signature algorithms.
        pub fn set_sigalgs_list(&mut self, _sigalgs: &str) -> Result<(), ErrorStack> { ... }
        /// Sets the minimum supported protocol version.
        pub fn set_min_proto_version(
                    &mut self,
                    _version: Option<SslVersion>,
                ) -> Result<(), ErrorStack> { ... }
        /// Sets the maximum supported protocol version.
        pub fn set_max_proto_version(
                    &mut self,
                    _version: Option<SslVersion>,
                ) -> Result<(), ErrorStack> { ... }
        /// Use the default locations of trusted certificates for verification.
        pub fn set_default_verify_paths(&mut self) -> Result<(), ErrorStack> { ... }
        /// Loads trusted root certificates from a file.
        pub fn set_ca_file<P: AsRef<std::path::Path>>(
                    &mut self,
                    _file: P,
                ) -> Result<(), ErrorStack> { ... }
        /// Loads a leaf certificate from a file.
        pub fn set_certificate_file<P: AsRef<std::path::Path>>(
                    &mut self,
                    _file: P,
                    _file_type: SslFiletype,
                ) -> Result<(), ErrorStack> { ... }
        /// Loads the private key from a file.
        pub fn set_private_key_file<P: AsRef<std::path::Path>>(
                    &mut self,
                    _file: P,
                    _file_type: SslFiletype,
                ) -> Result<(), ErrorStack> { ... }
        /// Sets the TLS key logging callback.
        pub fn set_keylog_callback<F>(&mut self, _callback: F)
                where
                    F: Fn(&SslRef, &str) + 'static + Sync + Send, { ... }
    }
    impl SslContext {
        /// Creates a new builder object for an `SslContext`.
        pub fn builder(_method: SslMethod) -> Result<SslContextBuilder, ErrorStack> { ... }
    }
    impl SslContextBuilder {
        /// Consumes the builder, returning a new `SslContext`.
        pub fn build(self) -> SslContext { ... }
    }
    impl SslMethod {
        /// Support all versions of the TLS protocol.
        pub fn tls() -> SslMethod { ... }
    }
    impl SslRef {
        /// Like [`SslContextBuilder::set_verify`].
        pub fn set_verify(&mut self, _mode: SslVerifyMode) { ... }
        /// Returns the current cipher if the session is active.
        pub fn current_cipher(&self) -> Option<&SslCipherRef> { ... }
        /// Sets the host name to be sent to the server for Server Name Indication (SNI).
        pub fn set_hostname(&mut self, _hostname: &str) -> Result<(), ErrorStack> { ... }
        /// Returns the peer’s certificate, if present.
        pub fn peer_certificate(&self) -> Option<X509> { ... }
        /// Returns the certificate verification result.
        pub fn verify_result(&self) -> X509VerifyResult { ... }
        /// Returns a string describing the protocol version of the session.
        pub fn version_str(&self) -> &'static str { ... }
        /// Returns the protocol selected via Application Layer Protocol Negotiation (ALPN).
        pub fn selected_alpn_protocol(&self) -> Option<&[u8]> { ... }
        /// Returns the servername sent by the client via Server Name Indication (SNI).
        pub fn servername(&self, _type_: NameType) -> Option<&str> { ... }
    }
}
pub mod ssl_sys {
}
pub mod error {
    use super::ssl::Error;
    /// Collection of [`Errors`] from OpenSSL.
    #[derive(Debug)]
    pub struct ErrorStack; { ... }
    impl std::error::Error for ErrorStack {
    }
    impl ErrorStack {
        /// Returns the contents of the OpenSSL error stack.
        pub fn get() -> ErrorStack { ... }
        /// Returns the errors in the stack.
        pub fn errors(&self) -> &[Error] { ... }
    }
}
pub mod x509 {
    use super::asn1::{Asn1IntegerRef, Asn1StringRef, Asn1TimeRef};
    use super::error::ErrorStack;
    use super::hash::{DigestBytes, MessageDigest};
    use super::nid::Nid;
    /// An `X509` public key certificate.
    #[derive(Debug, Clone)]
    pub struct X509; { ... }
    /// A type to destructure and examine an `X509Name`.
    pub struct X509NameEntries<'a> { ... }
    /// Reference to `X509NameEntry`.
    pub struct X509NameEntryRef; { ... }
    /// Reference to `X509Name`.
    pub struct X509NameRef; { ... }
    /// Reference to `X509`.
    pub struct X509Ref; { ... }
    /// The result of peer certificate verification.
    pub struct X509VerifyResult; { ... }
    impl X509 {
        /// Deserializes a PEM-encoded X509 structure.
        pub fn from_pem(_pem: &[u8]) -> Result<X509, ErrorStack> { ... }
    }
    impl<'a> Iterator for X509NameEntries<'a> {
        fn next(&mut self) -> Option<&'a X509NameEntryRef> { ... }
    }
    impl X509NameEntryRef {
        pub fn data(&self) -> &Asn1StringRef { ... }
    }
    impl X509NameRef {
        /// Returns the name entries by the nid.
        pub fn entries_by_nid(&self, _nid: Nid) -> X509NameEntries<'_> { ... }
    }
    impl X509Ref {
        /// Returns this certificate’s subject name.
        pub fn subject_name(&self) -> &X509NameRef { ... }
        /// Returns a digest of the DER representation of the certificate.
        pub fn digest(&self, _hash_type: MessageDigest) -> Result<DigestBytes, ErrorStack> { ... }
        /// Returns the certificate’s Not After validity period.
        pub fn not_after(&self) -> &Asn1TimeRef { ... }
        /// Returns this certificate’s serial number.
        pub fn serial_number(&self) -> &Asn1IntegerRef { ... }
    }
    impl X509VerifyResult {
        /// Return the integer representation of an `X509VerifyResult`.
        pub fn as_raw(&self) -> i32 { ... }
    }
    pub mod store {
        use super::super::error::ErrorStack;
        use super::X509;
        /// A builder type used to construct an `X509Store`.
        pub struct X509StoreBuilder; { ... }
        /// A certificate store to hold trusted X509 certificates.
        pub struct X509Store; { ... }
        /// Reference to an `X509Store`.
        pub struct X509StoreRef; { ... }
        impl X509StoreBuilder {
            /// Returns a builder for a certificate store..
            pub fn new() -> Result<X509StoreBuilder, ErrorStack> { ... }
            /// Constructs the `X509Store`.
            pub fn build(self) -> X509Store { ... }
            /// Adds a certificate to the certificate store.
            pub fn add_cert(&mut self, _cert: X509) -> Result<(), ErrorStack> { ... }
        }
    }
    pub mod verify {
        /// Reference to `X509VerifyParam`.
        pub struct X509VerifyParamRef; { ... }
    }
}
pub mod nid {
    /// A numerical identifier for an OpenSSL object.
    pub struct Nid; { ... }
}
pub mod pkey {
    use super::error::ErrorStack;
    /// A public or private key.
    #[derive(Clone)]
    pub struct PKey<T> { ... }
    /// Reference to `PKey`.
    pub struct PKeyRef<T> { ... }
    /// A tag type indicating that a key has private components.
    #[derive(Clone)]
    pub enum Private {}
    /// A trait indicating that a key has private components.
    pub trait HasPrivate { ... }
    impl<T> std::ops::Deref for PKey<T> {
        fn deref(&self) -> &PKeyRef<T> { ... }
    }
    impl<T> std::ops::DerefMut for PKey<T> {
        fn deref_mut(&mut self) -> &mut PKeyRef<T> { ... }
    }
    impl PKey<Private> {
        pub fn private_key_from_pem(_pem: &[u8]) -> Result<PKey<Private>, ErrorStack> { ... }
    }
    unsafe impl HasPrivate for Private {
    }
}
pub mod hash {
    /// A message digest algorithm.
    pub struct MessageDigest; { ... }
    /// The resulting bytes of a digest.
    pub struct DigestBytes; { ... }
    impl MessageDigest {
        pub fn sha256() -> MessageDigest { ... }
    }
    impl AsRef<[u8]> for DigestBytes {
        fn as_ref(&self) -> &[u8] { ... }
    }
}
pub mod asn1 {
    use super::bn::BigNum;
    use super::error::ErrorStack;
    /// A reference to an `Asn1Integer`.
    pub struct Asn1IntegerRef; { ... }
    /// A reference to an `Asn1String`.
    pub struct Asn1StringRef; { ... }
    /// Reference to an `Asn1Time`
    pub struct Asn1TimeRef; { ... }
    impl Asn1IntegerRef {
        /// Converts the integer to a `BigNum`.
        pub fn to_bn(&self) -> Result<BigNum, ErrorStack> { ... }
    }
    impl Asn1StringRef {
        pub fn as_utf8(&self) -> Result<&str, ErrorStack> { ... }
    }
}
pub mod bn {
    use super::error::ErrorStack;
    /// Dynamically sized large number implementation
    pub struct BigNum; { ... }
    impl BigNum {
        /// Returns a hexadecimal string representation of `self`.
        pub fn to_hex_str(&self) -> Result<&str, ErrorStack> { ... }
    }
}
pub mod ext {
    use super::error::ErrorStack;
    use super::pkey::{HasPrivate, PKeyRef};
    use super::ssl::{Ssl, SslAcceptor, SslRef};
    use super::x509::store::X509StoreRef;
    use super::x509::verify::X509VerifyParamRef;
    use super::x509::X509Ref;
    /// Add name as an additional reference identifier that can match the peer's certificate
    pub fn add_host(_verify_param: &mut X509VerifyParamRef, _host: &str) -> Result<(), ErrorStack> { ... }
    /// Set the verify cert store of `_ssl`
    pub fn ssl_set_verify_cert_store(
            _ssl: &mut SslRef,
            _cert_store: &X509StoreRef,
        ) -> Result<(), ErrorStack> { ... }
    /// Load the certificate into `_ssl`
    pub fn ssl_use_certificate(_ssl: &mut SslRef, _cert: &X509Ref) -> Result<(), ErrorStack> { ... }
    /// Load the private key into `_ssl`
    pub fn ssl_use_private_key<T>(_ssl: &mut SslRef, _key: &PKeyRef<T>) -> Result<(), ErrorStack>
        where
            T: HasPrivate, { ... }
    /// Clear the error stack
    pub fn clear_error_stack() { ... }
    /// Create a new [Ssl] from &[SslAcceptor]
    pub fn ssl_from_acceptor(_acceptor: &SslAcceptor) -> Result<Ssl, ErrorStack> { ... }
    /// Suspend the TLS handshake when a certificate is needed.
    pub fn suspend_when_need_ssl_cert(_ssl: &mut SslRef) { ... }
    /// Unblock a TLS handshake after the certificate is set.
    pub fn unblock_ssl_cert(_ssl: &mut SslRef) { ... }
    /// Whether the TLS error is SSL_ERROR_WANT_X509_LOOKUP
    pub fn is_suspended_for_cert(_error: &super::ssl::Error) -> bool { ... }
    /// Add the certificate into the cert chain of `_ssl`
    pub fn ssl_add_chain_cert(_ssl: &mut SslRef, _cert: &X509Ref) -> Result<(), ErrorStack> { ... }
    /// Set renegotiation
    pub fn ssl_set_renegotiate_mode_freely(_ssl: &mut SslRef) { ... }
    /// Set the curves/groups of `_ssl`
    pub fn ssl_set_groups_list(_ssl: &mut SslRef, _groups: &str) -> Result<(), ErrorStack> { ... }
    /// Sets whether a second keyshare to be sent in client hello when PQ is used.
    pub fn ssl_use_second_key_share(_ssl: &mut SslRef, _enabled: bool) { ... }
    /// Get a mutable SslRef ouf of SslRef, which is a missing functionality even when holding &mut SslStream
    /// # Safety
    pub unsafe fn ssl_mut(_ssl: &SslRef) -> &mut SslRef { ... }
}
pub mod tokio_ssl {
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use super::error::ErrorStack;
    use super::ssl::{Error, Ssl, SslRef};
    /// A TLS session over a stream.
    #[derive(Debug)]
    pub struct SslStream<S> { ... }
    impl<S> SslStream<S> {
        /// Creates a new `SslStream`.
        pub fn new(_ssl: Ssl, _stream: S) -> Result<Self, ErrorStack> { ... }
        /// Initiates a client-side TLS handshake.
        pub async fn connect(self: Pin<&mut Self>) -> Result<(), Error> { ... }
        /// Initiates a server-side TLS handshake.
        pub async fn accept(self: Pin<&mut Self>) -> Result<(), Error> { ... }
        /// Returns a shared reference to the `Ssl` object associated with this stream.
        pub fn ssl(&self) -> &SslRef { ... }
        /// Returns a shared reference to the underlying stream.
        pub fn get_ref(&self) -> &S { ... }
        /// Returns a mutable reference to the underlying stream.
        pub fn get_mut(&mut self) -> &mut S { ... }
    }
    impl<S> AsyncRead for SslStream<S>
        where
            S: AsyncRead + AsyncWrite, {
        fn poll_read(
                    self: Pin<&mut Self>,
                    _ctx: &mut Context<'_>,
                    _buf: &mut ReadBuf<'_>,
                ) -> Poll<std::io::Result<()>> { ... }
    }
    impl<S> AsyncWrite for SslStream<S>
        where
            S: AsyncRead + AsyncWrite, {
        fn poll_write(
                    self: Pin<&mut Self>,
                    _ctx: &mut Context<'_>,
                    _buf: &[u8],
                ) -> Poll<std::io::Result<usize>> { ... }
        fn poll_flush(self: Pin<&mut Self>, _ctx: &mut Context<'_>) -> Poll<std::io::Result<()>> { ... }
        fn poll_shutdown(
                    self: Pin<&mut Self>,
                    _ctx: &mut Context<'_>,
                ) -> Poll<std::io::Result<()>> { ... }
    }
}
```
## pingora-core/src/upstreams/mod.rs
```rust
pub mod peer {
}
```
## pingora-core/src/upstreams/peer.rs
```rust
use crate::connectors::{l4::BindTo, L4Connect};
use crate::protocols::l4::socket::SocketAddr;
use crate::protocols::tls::CaType;
use crate::protocols::ConnFdReusable;
use crate::protocols::TcpKeepalive;
use crate::utils::tls::{get_organization_unit, CertKey};
use ahash::AHasher;
use derivative::Derivative;
use pingora_error::{
    ErrorType::{InternalError, SocketError},
    OrErr, Result,
};
use std::collections::BTreeMap;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr as InetSocketAddr, ToSocketAddrs as ToInetSocketAddrs};
use std::os::unix::{net::SocketAddr as UnixSocketAddr, prelude::AsRawFd};
use std::os::windows::io::AsRawSocket;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpSocket;
pub use crate::protocols::tls::ALPN;
/// An object-safe version of Tracing object that can use Clone
#[derive(Debug)]
pub struct Tracer(pub Box<dyn Tracing>); { ... }
/// A simple TCP or TLS peer without many complicated settings.
#[derive(Debug, Clone)]
pub struct BasicPeer { ... }
/// Define whether to connect via http or https
#[derive(Hash, Clone, Debug, PartialEq)]
pub enum Scheme {
    HTTP,
    HTTPS,
}
/// The preferences to connect to a remote server
///
/// See [`Peer`] for the meaning of the fields
#[non_exhaustive]
#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct PeerOptions { ... }
/// A peer representing the remote HTTP server to connect to
#[derive(Debug, Clone)]
pub struct HttpPeer { ... }
/// The proxy settings to connect to the remote server, CONNECT only for now
#[derive(Debug, Hash, Clone)]
pub struct Proxy { ... }
/// The interface to trace the connection
pub trait Tracing { ... }
/// [`Peer`] defines the interface to communicate with the [`crate::connectors`] regarding where to
/// connect to and how to connect to it.
pub trait Peer { ... }
impl Clone for Tracer {
    fn clone(&self) -> Self { ... }
}
impl BasicPeer {
    /// Create a new [`BasicPeer`].
    pub fn new(address: &str) -> Self { ... }
    /// Create a new [`BasicPeer`] with the given path to a Unix domain socket.
    #[cfg(unix)]
    pub fn new_uds<P: AsRef<Path>>(path: P) -> Result<Self> { ... }
}
impl Display for BasicPeer {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult { ... }
}
impl Peer for BasicPeer {
    fn address(&self) -> &SocketAddr { ... }
    fn tls(&self) -> bool { ... }
    fn bind_to(&self) -> Option<&BindTo> { ... }
    fn sni(&self) -> &str { ... }
    fn reuse_hash(&self) -> u64 { ... }
    fn get_peer_options(&self) -> Option<&PeerOptions> { ... }
}
impl Display for Scheme {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult { ... }
}
impl Scheme {
    pub fn from_tls_bool(tls: bool) -> Self { ... }
}
impl PeerOptions {
    /// Create a new [`PeerOptions`]
    pub fn new() -> Self { ... }
    /// Set the ALPN according to the `max` and `min` constrains.
    pub fn set_http_version(&mut self, max: u8, min: u8) { ... }
}
impl Display for PeerOptions {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult { ... }
}
impl HttpPeer {
    pub fn is_tls(&self) -> bool { ... }
    /// Create a new [`HttpPeer`] with the given socket address and TLS settings.
    pub fn new<A: ToInetSocketAddrs>(address: A, tls: bool, sni: String) -> Self { ... }
    /// Create a new [`HttpPeer`] with the given path to Unix domain socket and TLS settings.
    #[cfg(unix)]
    pub fn new_uds(path: &str, tls: bool, sni: String) -> Result<Self> { ... }
    /// Create a new [`HttpPeer`] that uses a proxy to connect to the upstream IP and port
    /// combination.
    pub fn new_proxy(
            next_hop: &str,
            ip_addr: IpAddr,
            port: u16,
            tls: bool,
            sni: &str,
            headers: BTreeMap<String, Vec<u8>>,
        ) -> Self { ... }
}
impl Hash for HttpPeer {
    fn hash<H: Hasher>(&self, state: &mut H) { ... }
}
impl Display for HttpPeer {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult { ... }
}
impl Peer for HttpPeer {
    fn address(&self) -> &SocketAddr { ... }
    fn tls(&self) -> bool { ... }
    fn sni(&self) -> &str { ... }
    fn reuse_hash(&self) -> u64 { ... }
    fn get_peer_options(&self) -> Option<&PeerOptions> { ... }
    fn get_mut_peer_options(&mut self) -> Option<&mut PeerOptions> { ... }
    fn get_proxy(&self) -> Option<&Proxy> { ... }
    #[cfg(unix)]
    fn matches_fd<V: AsRawFd>(&self, fd: V) -> bool { ... }
    #[cfg(windows)]
    fn matches_sock<V: AsRawSocket>(&self, sock: V) -> bool { ... }
    fn get_client_cert_key(&self) -> Option<&Arc<CertKey>> { ... }
    fn get_tracer(&self) -> Option<Tracer> { ... }
}
impl Display for Proxy {
    fn fmt(&self, f: &mut Formatter) -> FmtResult { ... }
}
```
## pingora-core/src/utils/mod.rs
```rust
pub use crate::tls::utils as tls;
use bytes::Bytes;
#[cfg(feature = "any_tls")]
pub mod tls {
}
/// A `BufRef` is a reference to a buffer of bytes. It removes the need for self-referential data
/// structures. It is safe to use as long as the underlying buffer does not get mutated.
///
/// # Panics
///
/// This will panic if an index is out of bounds.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BufRef(pub usize, pub usize); { ... }
/// A `KVRef` contains a key name and value pair, stored as two [BufRef] types.
#[derive(Clone)]
pub struct KVRef { ... }
impl BufRef {
    /// Return a sub-slice of `buf`.
    pub fn get<'a>(&self, buf: &'a [u8]) -> &'a [u8] { ... }
    /// Return a slice of `buf`. This operation is O(1) and increases the reference count of `buf`.
    pub fn get_bytes(&self, buf: &Bytes) -> Bytes { ... }
    /// Return the size of the slice reference.
    pub fn len(&self) -> usize { ... }
    /// Return true if the length is zero.
    pub fn is_empty(&self) -> bool { ... }
}
impl BufRef {
    /// Initialize a `BufRef` that can reference a slice beginning at index `start` and has a
    /// length of `len`.
    pub fn new(start: usize, len: usize) -> Self { ... }
}
impl KVRef {
    /// Like [BufRef::get] for the name.
    pub fn get_name<'a>(&self, buf: &'a [u8]) -> &'a [u8] { ... }
    /// Like [BufRef::get] for the value.
    pub fn get_value<'a>(&self, buf: &'a [u8]) -> &'a [u8] { ... }
    /// Like [BufRef::get_bytes] for the name.
    pub fn get_name_bytes(&self, buf: &Bytes) -> Bytes { ... }
    /// Like [BufRef::get_bytes] for the value.
    pub fn get_value_bytes(&self, buf: &Bytes) -> Bytes { ... }
    /// Return a new `KVRef` with name and value start indices and lengths.
    pub fn new(name_s: usize, name_len: usize, value_s: usize, value_len: usize) -> Self { ... }
    /// Return a reference to the value.
    pub fn value(&self) -> &BufRef { ... }
}
```
## pingora-core/src/utils/tls/boringssl_openssl.rs
```rust
use crate::tls::{nid::Nid, pkey::PKey, pkey::Private, x509::X509};
use crate::Result;
use pingora_error::{ErrorType::*, OrErr};
use std::hash::{Hash, Hasher};
/// Return the organization associated with the X509 certificate.
pub fn get_organization(cert: &X509) -> Option<String> { ... }
/// Return the common name associated with the X509 certificate.
pub fn get_common_name(cert: &X509) -> Option<String> { ... }
/// Return the common name associated with the X509 certificate.
pub fn get_organization_unit(cert: &X509) -> Option<String> { ... }
/// Return the serial number associated with the X509 certificate as a hexadecimal value.
pub fn get_serial(cert: &X509) -> Result<String> { ... }
/// This type contains a list of one or more certificates and an associated private key. The leaf
/// certificate should always be first.
#[derive(Clone)]
pub struct CertKey { ... }
impl CertKey {
    /// Create a new `CertKey` given a list of certificates and a private key.
    pub fn new(certificates: Vec<X509>, key: PKey<Private>) -> CertKey { ... }
    /// Peek at the leaf certificate.
    pub fn leaf(&self) -> &X509 { ... }
    /// Return the key.
    pub fn key(&self) -> &PKey<Private> { ... }
    /// Return a slice of intermediate certificates. An empty slice means there are none.
    pub fn intermediates(&self) -> &[X509] { ... }
    /// Return the organization from the leaf certificate.
    pub fn organization(&self) -> Option<String> { ... }
    /// Return the serial from the leaf certificate.
    pub fn serial(&self) -> Result<String> { ... }
}
impl Hash for CertKey {
    fn hash<H: Hasher>(&self, state: &mut H) { ... }
}
impl std::fmt::Debug for CertKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { ... }
}
impl std::fmt::Display for CertKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { ... }
}
```
## pingora-core/src/utils/tls/mod.rs
```rust
pub use boringssl_openssl::*;
pub use rustls::*;
```
## pingora-core/src/utils/tls/rustls.rs
```rust
use ouroboros::self_referencing;
use pingora_error::Result;
use pingora_rustls::CertificateDer;
use std::hash::{Hash, Hasher};
use x509_parser::prelude::{FromDer, X509Certificate};
/// Get the organization and serial number associated with the given certificate
/// see https://en.wikipedia.org/wiki/X.509#Structure_of_a_certificate
pub fn get_organization_serial(x509cert: &WrappedX509) -> Result<(Option<String>, String)> { ... }
/// Get the serial number associated with the given certificate
/// see https://en.wikipedia.org/wiki/X.509#Structure_of_a_certificate
pub fn get_serial(x509cert: &WrappedX509) -> Result<String> { ... }
/// Return the organization associated with the X509 certificate.
/// see https://en.wikipedia.org/wiki/X.509#Structure_of_a_certificate
pub fn get_organization(x509cert: &WrappedX509) -> Option<String> { ... }
/// Return the organization associated with the X509 certificate.
/// see https://en.wikipedia.org/wiki/X.509#Structure_of_a_certificate
pub fn get_organization_x509(x509cert: &X509Certificate<'_>) -> Option<String> { ... }
/// Return the organization associated with the X509 certificate (as bytes).
/// see https://en.wikipedia.org/wiki/X.509#Structure_of_a_certificate
pub fn get_organization_serial_bytes(cert: &[u8]) -> Result<(Option<String>, String)> { ... }
/// Return the organization unit associated with the X509 certificate.
/// see https://en.wikipedia.org/wiki/X.509#Structure_of_a_certificate
pub fn get_organization_unit(x509cert: &WrappedX509) -> Option<String> { ... }
/// Get a combination of the common names for the given certificate
/// see https://en.wikipedia.org/wiki/X.509#Structure_of_a_certificate
pub fn get_common_name(x509cert: &WrappedX509) -> Option<String> { ... }
/// Get the `not_after` field for the valid time period for the given cert
/// see https://en.wikipedia.org/wiki/X.509#Structure_of_a_certificate
pub fn get_not_after(x509cert: &WrappedX509) -> String { ... }
/// This type contains a list of one or more certificates and an associated private key. The leaf
/// certificate should always be first.
pub struct CertKey { ... }
#[self_referencing]
#[derive(Debug)]
pub struct WrappedX509 { ... }
impl Clone for CertKey {
    fn clone(&self) -> Self { ... }
}
impl CertKey {
    /// Create a new `CertKey` given a list of certificates and a private key.
    pub fn new(certificates: Vec<Vec<u8>>, key: Vec<u8>) -> CertKey { ... }
    /// Peek at the leaf certificate.
    pub fn leaf(&self) -> &WrappedX509 { ... }
    /// Return the key.
    pub fn key(&self) -> &Vec<u8> { ... }
    /// Return a slice of intermediate certificates. An empty slice means there are none.
    pub fn intermediates(&self) -> Vec<&WrappedX509> { ... }
    /// Return the organization from the leaf certificate.
    pub fn organization(&self) -> Option<String> { ... }
    /// Return the serial from the leaf certificate.
    pub fn serial(&self) -> String { ... }
}
impl WrappedX509 {
    pub fn not_after(&self) -> String { ... }
}
impl std::fmt::Debug for CertKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { ... }
}
impl std::fmt::Display for CertKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { ... }
}
impl Hash for CertKey {
    fn hash<H: Hasher>(&self, state: &mut H) { ... }
}
impl<'a> From<&'a WrappedX509> for CertificateDer<'static> {
    fn from(value: &'a WrappedX509) -> Self { ... }
}
```
## pingora-core/tests/test_basic.rs
```rust
use hyperlocal::{UnixClientExt, Uri};
```
## pingora-core/tests/utils/mod.rs
```rust
use once_cell::sync::Lazy;
use std::{thread, time};
use clap::Parser;
use pingora_core::listeners::Listeners;
use pingora_core::server::configuration::Opt;
use pingora_core::server::Server;
use pingora_core::services::listening::Service;
use async_trait::async_trait;
use bytes::Bytes;
use http::{Response, StatusCode};
use pingora_timeout::timeout;
use std::time::Duration;
use pingora_core::apps::http_app::ServeHttp;
use pingora_core::protocols::http::ServerSession;
pub fn init() { ... }
#[derive(Clone)]
pub struct EchoApp; { ... }
pub struct MyServer { ... }
#[async_trait]
impl ServeHttp for EchoApp {
    async fn response(&self, http_stream: &mut ServerSession) -> Response<Vec<u8>> { ... }
}
impl MyServer {
    pub fn start() -> Self { ... }
}
```
## pingora-error/src/immut_str.rs
```rust
use std::fmt;
/// A data struct that holds either immutable string or reference to static str.
/// Compared to String or `Box<str>`, it avoids memory allocation on static str.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ImmutStr {
    Static(&'static str),
    Owned(Box<str>),
}
impl ImmutStr {
    #[inline]
    pub fn as_str(&self) -> &str { ... }
    pub fn is_owned(&self) -> bool { ... }
}
impl fmt::Display for ImmutStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { ... }
}
impl From<&'static str> for ImmutStr {
    fn from(s: &'static str) -> Self { ... }
}
impl From<String> for ImmutStr {
    fn from(s: String) -> Self { ... }
}
```
## pingora-error/src/lib.rs
```rust
pub use std::error::Error as ErrorTrait;
use std::fmt;
use std::fmt::Debug;
use std::result::Result as StdResult;
pub use immut_str::ImmutStr;
/// The struct that represents an error
#[derive(Debug)]
pub struct Error { ... }
/// The source of the error
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ErrorSource {
    /// The error is caused by the remote server
    Upstream,
    /// The error is caused by the remote client
    Downstream,
    /// The error is caused by the internal logic
    Internal,
    /// Error source unknown or to be set
    Unset,
}
/// Whether the request can be retried after encountering this error
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RetryType {
    Decided(bool),
    ReusedOnly, // only retry when the error is from a reused connection
}
/// Predefined type of errors
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ErrorType {
    // connect errors
    ConnectTimedout,
    ConnectRefused,
    ConnectNoRoute,
    TLSWantX509Lookup,
    TLSHandshakeFailure,
    TLSHandshakeTimedout,
    InvalidCert,
    HandshakeError, // other handshake
    ConnectError,   // catch all
    BindError,
    AcceptError,
    SocketError,
    ConnectProxyFailure,
    // protocol errors
    InvalidHTTPHeader,
    H1Error,     // catch all
    H2Error,     // catch all
    H2Downgrade, // Peer over h2 requests to downgrade to h1
    InvalidH2,   // Peer sends invalid h2 frames to us
    // IO error on established connections
    ReadError,
    WriteError,
    ReadTimedout,
    WriteTimedout,
    ConnectionClosed,
    // application error, will return HTTP status code
    HTTPStatus(u16),
    // file related
    FileOpenError,
    FileCreateError,
    FileReadError,
    FileWriteError,
    // other errors
    InternalError,
    // catch all
    UnknownError,
    /// Custom error with static string.
    /// this field is to allow users to extend the types of errors. If runtime generated string
    /// is needed, it is more likely to be treated as "context" rather than "type".
    Custom(&'static str),
    /// Custom error with static string and code.
    /// this field allows users to extend error further with error codes.
    CustomCode(&'static str, u16),
}
/// Helper trait to add more context to a given error
pub trait Context { ... }
/// Helper trait to chain errors with context
pub trait OrErr { ... }
/// Helper trait to convert an [Option] to an [Error] with context.
pub trait OkOrErr { ... }
impl RetryType {
    pub fn decide_reuse(&mut self, reused: bool) { ... }
    pub fn retry(&self) -> bool { ... }
}
impl From<bool> for RetryType {
    fn from(b: bool) -> Self { ... }
}
impl ErrorSource {
    /// for displaying the error source
    pub fn as_str(&self) -> &str { ... }
}
impl ErrorType {
    /// create a new type of error. Users should try to make `name` unique.
    pub const fn new(name: &'static str) -> Self { ... }
    /// create a new type of error. Users should try to make `name` unique.
    pub const fn new_code(name: &'static str, code: u16) -> Self { ... }
    /// for displaying the error type
    pub fn as_str(&self) -> &str { ... }
}
impl Error {
    /// Simply create the error. See other functions that provide less verbose interfaces.
    #[inline]
    pub fn create(
            etype: ErrorType,
            esource: ErrorSource,
            context: Option<ImmutStr>,
            cause: Option<Box<dyn ErrorTrait + Send + Sync>>,
        ) -> BError { ... }
    /// Create an error with the given type
    #[inline]
    pub fn new(e: ErrorType) -> BError { ... }
    /// Create an error with the given type, a context string and the causing error.
    /// This method is usually used when there the error is caused by another error.
    /// ```
    /// use pingora_error::{Error, ErrorType, Result};
    ///
    /// fn b() -> Result<()> {
    /// // ...
    /// Ok(())
    /// }
    /// fn do_something() -> Result<()> {
    /// // a()?;
    /// b().map_err(|e| Error::because(ErrorType::InternalError, "b failed after a", e))
    /// }
    /// ```
    /// Choose carefully between simply surfacing the causing error versus Because() here.
    /// Only use Because() when there is extra context that is not capture by
    /// the causing error itself.
    #[inline]
    pub fn because<S: Into<ImmutStr>, E: Into<Box<dyn ErrorTrait + Send + Sync>>>(
            e: ErrorType,
            context: S,
            cause: E,
        ) -> BError { ... }
    /// Short for Err(Self::because)
    #[inline]
    pub fn e_because<T, S: Into<ImmutStr>, E: Into<Box<dyn ErrorTrait + Send + Sync>>>(
            e: ErrorType,
            context: S,
            cause: E,
        ) -> Result<T> { ... }
    /// Create an error with context but no direct causing error
    #[inline]
    pub fn explain<S: Into<ImmutStr>>(e: ErrorType, context: S) -> BError { ... }
    /// Short for Err(Self::explain)
    #[inline]
    pub fn e_explain<T, S: Into<ImmutStr>>(e: ErrorType, context: S) -> Result<T> { ... }
    /// The new_{up, down, in} functions are to create new errors with source
    /// {upstream, downstream, internal}
    #[inline]
    pub fn new_up(e: ErrorType) -> BError { ... }
    #[inline]
    pub fn new_down(e: ErrorType) -> BError { ... }
    #[inline]
    pub fn new_in(e: ErrorType) -> BError { ... }
    /// Create a new custom error with the static string
    #[inline]
    pub fn new_str(s: &'static str) -> BError { ... }
    #[inline]
    pub fn err<T>(e: ErrorType) -> Result<T> { ... }
    #[inline]
    pub fn err_up<T>(e: ErrorType) -> Result<T> { ... }
    #[inline]
    pub fn err_down<T>(e: ErrorType) -> Result<T> { ... }
    #[inline]
    pub fn err_in<T>(e: ErrorType) -> Result<T> { ... }
    pub fn etype(&self) -> &ErrorType { ... }
    pub fn esource(&self) -> &ErrorSource { ... }
    pub fn retry(&self) -> bool { ... }
    pub fn set_retry(&mut self, retry: bool) { ... }
    pub fn reason_str(&self) -> &str { ... }
    pub fn source_str(&self) -> &str { ... }
    /// The as_{up, down, in} functions are to change the current errors with source
    /// {upstream, downstream, internal}
    pub fn as_up(&mut self) { ... }
    pub fn as_down(&mut self) { ... }
    pub fn as_in(&mut self) { ... }
    /// The into_{up, down, in} are the same as as_* but takes `self` and also return `self`
    pub fn into_up(mut self: BError) -> BError { ... }
    pub fn into_down(mut self: BError) -> BError { ... }
    pub fn into_in(mut self: BError) -> BError { ... }
    pub fn into_err<T>(self: BError) -> Result<T> { ... }
    pub fn set_cause<C: Into<Box<dyn ErrorTrait + Send + Sync>>>(&mut self, cause: C) { ... }
    pub fn set_context<T: Into<ImmutStr>>(&mut self, context: T) { ... }
    /// Create a new error from self, with the same type and source and put self as the cause
    /// ```
    /// use pingora_error::Result;
    ///
    /// fn b() -> Result<()> {
    /// // ...
    /// Ok(())
    /// }
    ///
    /// fn do_something() -> Result<()> {
    /// // a()?;
    /// b().map_err(|e| e.more_context("b failed after a"))
    /// }
    /// ```
    /// This function is less verbose than `Because`. But it only work for [Error] while
    /// `Because` works for all types of errors who implement [std::error::Error] trait.
    pub fn more_context<T: Into<ImmutStr>>(self: BError, context: T) -> BError { ... }
    /// Return the ErrorType of the root Error
    pub fn root_etype(&self) -> &ErrorType { ... }
    pub fn root_cause(&self) -> &(dyn ErrorTrait + Send + Sync + 'static) { ... }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { ... }
}
impl ErrorTrait for Error {
}
impl<T> Context<T> for Result<T, BError> {
    fn err_context<C: Into<ImmutStr>, F: FnOnce() -> C>(self, context: F) -> Result<T, BError> { ... }
}
impl<T, E> OrErr<T, E> for Result<T, E> {
    fn or_err(self, et: ErrorType, context: &'static str) -> Result<T, BError>
        where
            E: Into<Box<dyn ErrorTrait + Send + Sync>>, { ... }
    fn or_err_with<C: Into<ImmutStr>, F: FnOnce() -> C>(
            self,
            et: ErrorType,
            context: F,
        ) -> Result<T, BError>
        where
            E: Into<Box<dyn ErrorTrait + Send + Sync>>, { ... }
    fn explain_err<C: Into<ImmutStr>, F: FnOnce(E) -> C>(
            self,
            et: ErrorType,
            exp: F,
        ) -> Result<T, BError> { ... }
    fn or_fail(self) -> Result<T, BError>
        where
            E: Into<Box<dyn ErrorTrait + Send + Sync>>, { ... }
}
impl<T> OkOrErr<T> for Option<T> {
    /// Convert the [Option] to a new [Error] with [ErrorType] and context if None, Ok otherwise.
    ///
    /// This is a shortcut for .ok_or(Error::explain())
    fn or_err(self, et: ErrorType, context: &'static str) -> Result<T, BError> { ... }
    /// Similar to to_err(), but takes a closure, which is useful for constructing String.
    fn or_err_with<C: Into<ImmutStr>, F: FnOnce() -> C>(
            self,
            et: ErrorType,
            context: F,
        ) -> Result<T, BError> { ... }
}
```
## pingora-header-serde/src/dict.rs
```rust
use std::fs;
use zstd::dict;
/// Train the zstd dictionary from all the files under the given `dir_path`
///
/// The output will be the trained dictionary
pub fn train<P: AsRef<std::path::Path>>(dir_path: P) -> Vec<u8> { ... }
```
## pingora-header-serde/src/lib.rs
```rust
use bytes::BufMut;
use http::Version;
use pingora_error::{Error, ErrorType, Result};
use pingora_http::ResponseHeader;
use std::cell::RefCell;
use std::ops::DerefMut;
use thread_local::ThreadLocal;
pub mod dict {
}
/// HTTP Response header serialization
///
/// This struct provides the APIs to convert HTTP response header into compressed wired format for
/// storage.
pub struct HeaderSerde { ... }
impl HeaderSerde {
    /// Create a new [HeaderSerde]
    ///
    /// An optional zstd compression dictionary can be provided to improve the compression ratio
    /// and speed. See [dict] for more details.
    pub fn new(dict: Option<Vec<u8>>) -> Self { ... }
    /// Serialize the given response header
    pub fn serialize(&self, header: &ResponseHeader) -> Result<Vec<u8>> { ... }
    /// Deserialize the given response header
    pub fn deserialize(&self, data: &[u8]) -> Result<ResponseHeader> { ... }
}
```
## pingora-header-serde/src/thread_zstd.rs
```rust
use std::cell::{RefCell, RefMut};
use thread_local::ThreadLocal;
use zstd_safe::{CCtx, CDict, DCtx, DDict};
#[derive(Default)]
pub struct Compression(CompressionInner); { ... }
pub struct CompressionWithDict { ... }
impl Compression {
    pub fn new() -> Self { ... }
    pub fn compress_to_buffer<C: zstd_safe::WriteBuf + ?Sized>(
            &self,
            source: &[u8],
            destination: &mut C,
            level: i32,
        ) -> Result<usize, &'static str> { ... }
    pub fn compress(&self, data: &[u8], level: i32) -> Result<Vec<u8>, &'static str> { ... }
    pub fn decompress_to_buffer<C: zstd_safe::WriteBuf + ?Sized>(
            &self,
            source: &[u8],
            destination: &mut C,
        ) -> Result<usize, &'static str> { ... }
}
impl CompressionWithDict {
    pub fn new(dict: &[u8], compression_level: i32) -> Self { ... }
    pub fn compress_to_buffer<C: zstd_safe::WriteBuf + ?Sized>(
            &self,
            source: &[u8],
            destination: &mut C,
        ) -> Result<usize, &'static str> { ... }
    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> { ... }
    pub fn decompress_to_buffer<C: zstd_safe::WriteBuf + ?Sized>(
            &self,
            source: &[u8],
            destination: &mut C,
        ) -> Result<usize, &'static str> { ... }
}
impl CompressionInner {
    pub fn decompress_to_buffer_using_dict<C: zstd_safe::WriteBuf + ?Sized>(
            &self,
            source: &[u8],
            destination: &mut C,
            dict: &DDict,
        ) -> Result<usize, &'static str> { ... }
}
```
## pingora-header-serde/src/trainer.rs
```rust
use pingora_header_serde::dict::train;
use std::env;
use std::io::{self, Write};
pub fn main() { ... }
```
## pingora-http/src/case_header_name.rs
```rust
use crate::*;
use bytes::Bytes;
use http::header;
#[derive(Debug, Clone)]
pub struct CaseHeaderName(Bytes); { ... }
/// A trait that converts into case-sensitive header names.
pub trait IntoCaseHeaderName { ... }
impl CaseHeaderName {
    pub fn new(name: String) -> Self { ... }
}
impl CaseHeaderName {
    pub fn as_slice(&self) -> &[u8] { ... }
    pub fn from_slice(buf: &[u8]) -> Self { ... }
}
impl IntoCaseHeaderName for CaseHeaderName {
    fn into_case_header_name(self) -> CaseHeaderName { ... }
}
impl IntoCaseHeaderName for String {
    fn into_case_header_name(self) -> CaseHeaderName { ... }
}
impl IntoCaseHeaderName for &'static str {
    fn into_case_header_name(self) -> CaseHeaderName { ... }
}
impl IntoCaseHeaderName for HeaderName {
    fn into_case_header_name(self) -> CaseHeaderName { ... }
}
impl IntoCaseHeaderName for &HeaderName {
    fn into_case_header_name(self) -> CaseHeaderName { ... }
}
impl IntoCaseHeaderName for Bytes {
    fn into_case_header_name(self) -> CaseHeaderName { ... }
}
```
## pingora-http/src/lib.rs
```rust
use bytes::BufMut;
use http::header::{AsHeaderName, HeaderName, HeaderValue};
use http::request::Builder as ReqBuilder;
use http::request::Parts as ReqParts;
use http::response::Builder as RespBuilder;
use http::response::Parts as RespParts;
use http::uri::Uri;
use pingora_error::{ErrorType::*, OrErr, Result};
use std::ops::Deref;
pub use http::method::Method;
pub use http::status::StatusCode;
pub use http::version::Version;
pub use http::HeaderMap as HMap;
use case_header_name::CaseHeaderName;
pub use case_header_name::IntoCaseHeaderName;
pub mod prelude {
    pub use crate::RequestHeader;
}
/// The HTTP request header type.
///
/// This type is similar to [http::request::Parts] but preserves header name case.
/// It also preserves request path even if it is not UTF-8.
///
/// [RequestHeader] implements [Deref] for [http::request::Parts] so it can be used as it in most
/// places.
#[derive(Debug)]
pub struct RequestHeader { ... }
/// The HTTP response header type.
///
/// This type is similar to [http::response::Parts] but preserves header name case.
/// [ResponseHeader] implements [Deref] for [http::response::Parts] so it can be used as it in most
/// places.
#[derive(Debug)]
pub struct ResponseHeader { ... }
impl AsRef<ReqParts> for RequestHeader {
    fn as_ref(&self) -> &ReqParts { ... }
}
impl Deref for RequestHeader {
    fn deref(&self) -> &Self::Target { ... }
}
impl RequestHeader {
    /// Create a new [RequestHeader] with the given method and path.
    ///
    /// The `path` can be non UTF-8.
    pub fn build(
            method: impl TryInto<Method>,
            path: &[u8],
            size_hint: Option<usize>,
        ) -> Result<Self> { ... }
    /// Create a new [RequestHeader] with the given method and path without preserving header case.
    ///
    /// A [RequestHeader] created from this type is more space efficient than those from [Self::build()].
    ///
    /// Use this method if reading from or writing to HTTP/2 sessions where header case doesn't matter anyway.
    pub fn build_no_case(
            method: impl TryInto<Method>,
            path: &[u8],
            size_hint: Option<usize>,
        ) -> Result<Self> { ... }
    /// Append the header name and value to `self`.
    ///
    /// If there are already some headers under the same name, a new value will be added without
    /// any others being removed.
    pub fn append_header(
            &mut self,
            name: impl IntoCaseHeaderName,
            value: impl TryInto<HeaderValue>,
        ) -> Result<bool> { ... }
    /// Insert the header name and value to `self`.
    ///
    /// Different from [Self::append_header()], this method will replace all other existing headers
    /// under the same name (case-insensitive).
    pub fn insert_header(
            &mut self,
            name: impl IntoCaseHeaderName,
            value: impl TryInto<HeaderValue>,
        ) -> Result<()> { ... }
    /// Remove all headers under the name
    pub fn remove_header<'a, N: ?Sized>(&mut self, name: &'a N) -> Option<HeaderValue>
        where
            &'a N: 'a + AsHeaderName, { ... }
    /// Write the header to the `buf` in HTTP/1.1 wire format.
    ///
    /// The header case will be preserved.
    pub fn header_to_h1_wire(&self, buf: &mut impl BufMut) { ... }
    /// Set the request method
    pub fn set_method(&mut self, method: Method) { ... }
    /// Set the request URI
    pub fn set_uri(&mut self, uri: http::Uri) { ... }
    /// Set the request URI directly via raw bytes.
    ///
    /// Generally prefer [Self::set_uri()] to modify the header's URI if able.
    ///
    /// This API is to allow supporting non UTF-8 cases.
    pub fn set_raw_path(&mut self, path: &[u8]) -> Result<()> { ... }
    /// Set whether we send an END_STREAM on H2 request HEADERS if body is empty.
    pub fn set_send_end_stream(&mut self, send_end_stream: bool) { ... }
    /// Returns if we support sending an END_STREAM on H2 request HEADERS if body is empty,
    /// returns None if not H2.
    pub fn send_end_stream(&self) -> Option<bool> { ... }
    /// Return the request path in its raw format
    ///
    /// Non-UTF8 is supported.
    pub fn raw_path(&self) -> &[u8] { ... }
    /// Return the file extension of the path
    pub fn uri_file_extension(&self) -> Option<&str> { ... }
    /// Set http version
    pub fn set_version(&mut self, version: Version) { ... }
    /// Clone `self` into [http::request::Parts].
    pub fn as_owned_parts(&self) -> ReqParts { ... }
}
impl Clone for RequestHeader {
    fn clone(&self) -> Self { ... }
}
impl From<ReqParts> for RequestHeader {
    fn from(parts: ReqParts) -> RequestHeader { ... }
}
impl From<RequestHeader> for ReqParts {
    fn from(resp: RequestHeader) -> ReqParts { ... }
}
impl AsRef<RespParts> for ResponseHeader {
    fn as_ref(&self) -> &RespParts { ... }
}
impl Deref for ResponseHeader {
    fn deref(&self) -> &Self::Target { ... }
}
impl Clone for ResponseHeader {
    fn clone(&self) -> Self { ... }
}
impl From<RespParts> for ResponseHeader {
    fn from(parts: RespParts) -> ResponseHeader { ... }
}
impl From<ResponseHeader> for RespParts {
    fn from(resp: ResponseHeader) -> RespParts { ... }
}
impl From<Box<ResponseHeader>> for Box<RespParts> {
    fn from(resp: Box<ResponseHeader>) -> Box<RespParts> { ... }
}
impl ResponseHeader {
    /// Create a new [ResponseHeader] with the given status code.
    pub fn build(code: impl TryInto<StatusCode>, size_hint: Option<usize>) -> Result<Self> { ... }
    /// Create a new [ResponseHeader] with the given status code without preserving header case.
    ///
    /// A [ResponseHeader] created from this type is more space efficient than those from [Self::build()].
    ///
    /// Use this method if reading from or writing to HTTP/2 sessions where header case doesn't matter anyway.
    pub fn build_no_case(code: impl TryInto<StatusCode>, size_hint: Option<usize>) -> Result<Self> { ... }
    /// Append the header name and value to `self`.
    ///
    /// If there are already some headers under the same name, a new value will be added without
    /// any others being removed.
    pub fn append_header(
            &mut self,
            name: impl IntoCaseHeaderName,
            value: impl TryInto<HeaderValue>,
        ) -> Result<bool> { ... }
    /// Insert the header name and value to `self`.
    ///
    /// Different from [Self::append_header()], this method will replace all other existing headers
    /// under the same name (case insensitive).
    pub fn insert_header(
            &mut self,
            name: impl IntoCaseHeaderName,
            value: impl TryInto<HeaderValue>,
        ) -> Result<()> { ... }
    /// Remove all headers under the name
    pub fn remove_header<'a, N: ?Sized>(&mut self, name: &'a N) -> Option<HeaderValue>
        where
            &'a N: 'a + AsHeaderName, { ... }
    /// Write the header to the `buf` in HTTP/1.1 wire format.
    ///
    /// The header case will be preserved.
    pub fn header_to_h1_wire(&self, buf: &mut impl BufMut) { ... }
    /// Set the status code
    pub fn set_status(&mut self, status: impl TryInto<StatusCode>) -> Result<()> { ... }
    /// Set the HTTP version
    pub fn set_version(&mut self, version: Version) { ... }
    /// Set the HTTP reason phase. If `None`, a default reason phase will be used
    pub fn set_reason_phrase(&mut self, reason_phrase: Option<&str>) -> Result<()> { ... }
    /// Get the HTTP reason phase. If [Self::set_reason_phrase()] is never called
    /// or set to `None`, a default reason phase will be used
    pub fn get_reason_phrase(&self) -> Option<&str> { ... }
    /// Clone `self` into [http::response::Parts].
    pub fn as_owned_parts(&self) -> RespParts { ... }
    /// Helper function to set the HTTP content length on the response header.
    pub fn set_content_length(&mut self, len: usize) -> Result<()> { ... }
}
```
## pingora-ketama/benches/memory.rs
```rust
use pingora_ketama::{Bucket, Continuum};
pub fn main() { ... }
```
## pingora-ketama/benches/simple.rs
```rust
use pingora_ketama::{Bucket, Continuum};
use criterion::{criterion_group, criterion_main, Criterion};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
pub fn criterion_benchmark(c: &mut Criterion) { ... }
```
## pingora-ketama/examples/health_aware_selector.rs
```rust
use log::info;
use pingora_ketama::{Bucket, Continuum};
use std::collections::HashMap;
use std::net::SocketAddr;
```
## pingora-ketama/src/lib.rs
```rust
use std::cmp::Ordering;
use std::io::Write;
use std::net::SocketAddr;
use crc32fast::Hasher;
/// A [Bucket] represents a server for consistent hashing
///
/// A [Bucket] contains a [SocketAddr] to the server and a weight associated with it.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd)]
pub struct Bucket { ... }
/// The consistent hashing ring
///
/// A [Continuum] represents a ring of buckets where a node is associated with various points on
/// the ring.
pub struct Continuum { ... }
/// Iterator over a Continuum
pub struct NodeIterator<'a> { ... }
impl Bucket {
    /// Return a new bucket with the given node and weight.
    ///
    /// The chance that a [Bucket] is selected is proportional to the relative weight of all [Bucket]s.
    ///
    /// # Panics
    ///
    /// This will panic if the weight is zero.
    pub fn new(node: SocketAddr, weight: u32) -> Self { ... }
}
impl Ord for Point {
    fn cmp(&self, other: &Self) -> Ordering { ... }
}
impl PartialOrd for Point {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { ... }
}
impl Continuum {
    /// Create a new [Continuum] with the given list of buckets.
    pub fn new(buckets: &[Bucket]) -> Self { ... }
    /// Find the associated index for the given input.
    pub fn node_idx(&self, input: &[u8]) -> usize { ... }
    /// Hash the given `hash_key` to the server address.
    pub fn node(&self, hash_key: &[u8]) -> Option<SocketAddr> { ... }
    /// Get an iterator of nodes starting at the original hashed node of the `hash_key`.
    ///
    /// This function is useful to find failover servers if the original ones are offline, which is
    /// cheaper than rebuilding the entire hash ring.
    pub fn node_iter(&self, hash_key: &[u8]) -> NodeIterator { ... }
    pub fn get_addr(&self, idx: &mut usize) -> Option<&SocketAddr> { ... }
}
impl<'a> Iterator for NodeIterator<'a> {
    fn next(&mut self) -> Option<Self::Item> { ... }
}
```
## pingora-limits/benches/benchmark.rs
```rust
use ahash::RandomState;
use dashmap::DashMap;
use pingora_limits::estimator::Estimator;
use rand::distributions::Uniform;
use rand::{thread_rng, Rng};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Instant;
impl Counter for NaiveCounter {
    fn incr(&self, key: u32, value: usize) { ... }
    fn name() -> &'static str { ... }
}
impl Counter for OptimizedCounter {
    fn incr(&self, key: u32, value: usize) { ... }
    fn name() -> &'static str { ... }
}
impl Counter for Estimator {
    fn incr(&self, key: u32, value: usize) { ... }
    fn name() -> &'static str { ... }
}
```
## pingora-limits/src/estimator.rs
```rust
use crate::hash;
use crate::RandomState;
use std::hash::Hash;
use std::sync::atomic::{AtomicIsize, Ordering};
/// An implementation of a lock-free count–min sketch estimator. See the [wikipedia] page for more
/// information.
///
/// [wikipedia]: https://en.wikipedia.org/wiki/Count%E2%80%93min_sketch
pub struct Estimator { ... }
impl Estimator {
    /// Create a new `Estimator` with the given amount of hashes and columns (slots).
    pub fn new(hashes: usize, slots: usize) -> Self { ... }
    /// Increment `key` by the value given. Return the new estimated value as a result.
    /// Note: overflow can happen. When some of the internal counters overflow, a negative number
    /// will be returned. It is up to the caller to catch and handle this case.
    pub fn incr<T: Hash>(&self, key: T, value: isize) -> isize { ... }
    /// Decrement `key` by the value given.
    pub fn decr<T: Hash>(&self, key: T, value: isize) { ... }
    /// Get the estimated frequency of `key`.
    pub fn get<T: Hash>(&self, key: T) -> isize { ... }
    /// Reset all values inside this `Estimator`.
    pub fn reset(&self) { ... }
}
```
## pingora-limits/src/inflight.rs
```rust
use crate::estimator::Estimator;
use crate::{hash, RandomState};
use std::hash::Hash;
use std::sync::Arc;
/// An `Inflight` type tracks the frequency of actions that are actively occurring. When the value
/// is dropped from scope, the count will automatically decrease.
pub struct Inflight { ... }
/// A `Guard` is returned when an `Inflight` key is incremented via [Inflight::incr].
pub struct Guard { ... }
impl Inflight {
    /// Create a new `Inflight`.
    pub fn new() -> Self { ... }
    /// Increment `key` by the value given. The return value is a tuple of a [Guard] and the
    /// estimated count.
    pub fn incr<T: Hash>(&self, key: T, value: isize) -> (Guard, isize) { ... }
}
impl Guard {
    /// Increment the key's value that the `Guard` was created from.
    pub fn incr(&self) -> isize { ... }
    /// Get the estimated count of the key that the `Guard` was created from.
    pub fn get(&self) -> isize { ... }
}
impl Drop for Guard {
    fn drop(&mut self) { ... }
}
impl std::fmt::Debug for Guard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { ... }
}
```
## pingora-limits/src/lib.rs
```rust
use ahash::RandomState;
use std::hash::Hash;
pub mod estimator {
}
pub mod inflight {
}
pub mod rate {
}
```
## pingora-limits/src/rate.rs
```rust
use crate::estimator::Estimator;
use std::hash::Hash;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
/// Input struct to custom functions for calculating rate. Includes the counts
/// from the current interval, previous interval, the configured duration of an
/// interval, and the fraction into the current interval that the sample was
/// taken.
///
/// Ex. If the interval to the Rate instance is `10s`, and the rate calculation
/// is taken at 2 seconds after the start of the current interval, then the
/// fraction of the current interval returned in this struct will be `0.2`
/// meaning 20% of the current interval has elapsed
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct RateComponents { ... }
/// A stable rate estimator that reports the rate of events in the past `interval` time.
/// It returns the average rate between `interval` * 2 and `interval` while collecting the events
/// happening between `interval` and now.
///
/// This estimator ignores events that happen less than once per `interval` time.
pub struct Rate { ... }
impl Rate {
    /// Create a new `Rate` with the given interval.
    pub fn new(interval: std::time::Duration) -> Self { ... }
    /// Create a new `Rate` with the given interval and Estimator config with the given amount of hashes and columns (slots).
    #[inline]
    pub fn new_with_estimator_config(
            interval: std::time::Duration,
            hashes: usize,
            slots: usize,
        ) -> Self { ... }
    /// Return the per second rate estimation.
    pub fn rate<T: Hash>(&self, key: &T) -> f64 { ... }
    /// Report new events and return number of events seen so far in the current interval.
    pub fn observe<T: Hash>(&self, key: &T, events: isize) -> isize { ... }
    /// Get the current rate as calculated with the given closure. This closure
    /// will take an argument containing all the accessible information about
    /// the rate from this object and allow the caller to make their own
    /// estimation of rate based on:
    ///
    /// 1. The accumulated samples in the current interval (in progress)
    /// 2. The accumulated samples in the previous interval (completed)
    /// 3. The size of the interval
    /// 4. Elapsed fraction of current interval for this sample (0..1)
    pub fn rate_with<F, T, K>(&self, key: &K, mut rate_calc_fn: F) -> T
        where
            F: FnMut(RateComponents) -> T,
            K: Hash, { ... }
}
```
## pingora-load-balancing/src/background.rs
```rust
use std::time::{Duration, Instant};
use super::{BackendIter, BackendSelection, LoadBalancer};
use async_trait::async_trait;
use pingora_core::services::background::BackgroundService;
#[async_trait]
impl<S: Send + Sync + BackendSelection + 'static> BackgroundService for LoadBalancer<S>
where
    S::Iter: BackendIter, {
    async fn start(&self, shutdown: pingora_core::server::ShutdownWatch) -> () { ... }
}
```
## pingora-load-balancing/src/discovery.rs
```rust
use arc_swap::ArcSwap;
use async_trait::async_trait;
use http::Extensions;
use pingora_core::protocols::l4::socket::SocketAddr;
use pingora_error::Result;
use std::io::Result as IoResult;
use std::net::ToSocketAddrs;
use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
};
use crate::Backend;
/// A static collection of [Backend]s for service discovery.
#[derive(Default)]
pub struct Static { ... }
/// [ServiceDiscovery] is the interface to discover [Backend]s.
#[async_trait]
pub trait ServiceDiscovery { ... }
impl Static {
    /// Create a new boxed [Static] service discovery with the given backends.
    pub fn new(backends: BTreeSet<Backend>) -> Box<Self> { ... }
    /// Create a new boxed [Static] from a given iterator of items that implements [ToSocketAddrs].
    pub fn try_from_iter<A, T: IntoIterator<Item = A>>(iter: T) -> IoResult<Box<Self>>
        where
            A: ToSocketAddrs, { ... }
    /// return the collection to backends
    pub fn get(&self) -> BTreeSet<Backend> { ... }
}
#[async_trait]
impl ServiceDiscovery for Static {
    async fn discover(&self) -> Result<(BTreeSet<Backend>, HashMap<u64, bool>)> { ... }
}
```
## pingora-load-balancing/src/health_check.rs
```rust
use crate::Backend;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use pingora_core::connectors::{http::Connector as HttpConnector, TransportConnector};
use pingora_core::upstreams::peer::{BasicPeer, HttpPeer, Peer};
use pingora_error::{Error, ErrorType::CustomCode, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use std::sync::Arc;
use std::time::Duration;
/// TCP health check
///
/// This health check checks if a TCP (or TLS) connection can be established to a given backend.
pub struct TcpHealthCheck { ... }
/// HTTP health check
///
/// This health check checks if it can receive the expected HTTP(s) response from the given backend.
pub struct HttpHealthCheck { ... }
/// [HealthObserve] is an interface for observing health changes of backends,
/// this is what's used for our health observation callback.
#[async_trait]
pub trait HealthObserve { ... }
/// [HealthCheck] is the interface to implement health check for backends
#[async_trait]
pub trait HealthCheck { ... }
impl Default for TcpHealthCheck {
    fn default() -> Self { ... }
}
impl TcpHealthCheck {
    /// Create a new [TcpHealthCheck] with the following default values
    /// * connect timeout: 1 second
    /// * consecutive_success: 1
    /// * consecutive_failure: 1
    pub fn new() -> Box<Self> { ... }
    /// Create a new [TcpHealthCheck] that tries to establish a TLS connection.
    ///
    /// The default values are the same as [Self::new()].
    pub fn new_tls(sni: &str) -> Box<Self> { ... }
    /// Replace the internal tcp connector with the given [TransportConnector]
    pub fn set_connector(&mut self, connector: TransportConnector) { ... }
}
#[async_trait]
impl HealthCheck for TcpHealthCheck {
    fn health_threshold(&self, success: bool) -> usize { ... }
    async fn check(&self, target: &Backend) -> Result<()> { ... }
    async fn health_status_change(&self, target: &Backend, healthy: bool) { ... }
}
impl HttpHealthCheck {
    /// Create a new [HttpHealthCheck] with the following default settings
    /// * connect timeout: 1 second
    /// * read timeout: 1 second
    /// * req: a GET to the `/` of the given host name
    /// * consecutive_success: 1
    /// * consecutive_failure: 1
    /// * reuse_connection: false
    /// * validator: `None`, any 200 response is considered successful
    pub fn new(host: &str, tls: bool) -> Self { ... }
    /// Replace the internal http connector with the given [HttpConnector]
    pub fn set_connector(&mut self, connector: HttpConnector) { ... }
}
#[async_trait]
impl HealthCheck for HttpHealthCheck {
    fn health_threshold(&self, success: bool) -> usize { ... }
    async fn check(&self, target: &Backend) -> Result<()> { ... }
    async fn health_status_change(&self, target: &Backend, healthy: bool) { ... }
}
impl Default for Health {
    fn default() -> Self { ... }
}
impl Clone for Health {
    fn clone(&self) -> Self { ... }
}
impl Health {
    pub fn ready(&self) -> bool { ... }
    pub fn enable(&self, enabled: bool) { ... }
    pub fn observe_health(&self, health: bool, flip_threshold: usize) -> bool { ... }
}
```
## pingora-load-balancing/src/lib.rs
```rust
use arc_swap::ArcSwap;
use derivative::Derivative;
use futures::FutureExt;
pub use http::Extensions;
use pingora_core::protocols::l4::socket::SocketAddr;
use pingora_error::{ErrorType, OrErr, Result};
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeSet, HashMap};
use std::hash::{Hash, Hasher};
use std::io::Result as IoResult;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;
use discovery::ServiceDiscovery;
use health_check::Health;
use selection::UniqueIterator;
use selection::{BackendIter, BackendSelection};
pub mod discovery {
}
pub mod health_check {
}
pub mod selection {
}
pub mod prelude {
    pub use crate::health_check::TcpHealthCheck;
    pub use crate::selection::RoundRobin;
    pub use crate::LoadBalancer;
}
/// [Backend] represents a server to proxy or connect to.
#[derive(Derivative)]
#[derivative(Clone, Hash, PartialEq, PartialOrd, Eq, Ord, Debug)]
pub struct Backend { ... }
/// [Backends] is a collection of [Backend]s.
///
/// It includes a service discovery method (static or dynamic) to discover all
/// the available backends as well as an optional health check method to probe the liveness
/// of each backend.
pub struct Backends { ... }
/// A [LoadBalancer] instance contains the service discovery, health check and backend selection
/// all together.
///
/// In order to run service discovery and health check at the designated frequencies, the [LoadBalancer]
/// needs to be run as a [pingora_core::services::background::BackgroundService].
pub struct LoadBalancer<S> { ... }
impl Backend {
    /// Create a new [Backend] with `weight` 1. The function will try to parse
    /// `addr` into a [std::net::SocketAddr].
    pub fn new(addr: &str) -> Result<Self> { ... }
    /// Creates a new [Backend] with the specified `weight`. The function will try to parse
    /// `addr` into a [std::net::SocketAddr].
    pub fn new_with_weight(addr: &str, weight: usize) -> Result<Self> { ... }
}
impl std::ops::Deref for Backend {
    fn deref(&self) -> &Self::Target { ... }
}
impl std::ops::DerefMut for Backend {
    fn deref_mut(&mut self) -> &mut Self::Target { ... }
}
impl std::net::ToSocketAddrs for Backend {
    fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> { ... }
}
impl Backends {
    /// Create a new [Backends] with the given [ServiceDiscovery] implementation.
    ///
    /// The health check method is by default empty.
    pub fn new(discovery: Box<dyn ServiceDiscovery + Send + Sync + 'static>) -> Self { ... }
    /// Set the health check method. See [health_check] for the methods provided.
    pub fn set_health_check(
            &mut self,
            hc: Box<dyn health_check::HealthCheck + Send + Sync + 'static>,
        ) { ... }
    /// Whether a certain [Backend] is ready to serve traffic.
    ///
    /// This function returns true when the backend is both healthy and enabled.
    /// This function returns true when the health check is unset but the backend is enabled.
    /// When the health check is set, this function will return false for the `backend` it
    /// doesn't know.
    pub fn ready(&self, backend: &Backend) -> bool { ... }
    /// Manually set if a [Backend] is ready to serve traffic.
    ///
    /// This method does not override the health of the backend. It is meant to be used
    /// to stop a backend from accepting traffic when it is still healthy.
    ///
    /// This method is noop when the given backend doesn't exist in the service discovery.
    pub fn set_enable(&self, backend: &Backend, enabled: bool) { ... }
    /// Return the collection of the backends.
    pub fn get_backend(&self) -> Arc<BTreeSet<Backend>> { ... }
    /// Call the service discovery method to update the collection of backends.
    ///
    /// The callback will be invoked when the new set of backend is different
    /// from the current one so that the caller can update the selector accordingly.
    pub async fn update<F>(&self, callback: F) -> Result<()>
        where
            F: Fn(Arc<BTreeSet<Backend>>), { ... }
    /// Run health check on all backends if it is set.
    ///
    /// When `parallel: true`, all backends are checked in parallel instead of sequentially
    pub async fn run_health_check(&self, parallel: bool) { ... }
}
impl<S: BackendSelection> LoadBalancer<S>
where
    S: BackendSelection + 'static,
    S::Iter: BackendIter, {
    /// Build a [LoadBalancer] with static backends created from the iter.
    ///
    /// Note: [ToSocketAddrs] will invoke blocking network IO for DNS lookup if
    /// the input cannot be directly parsed as [SocketAddr].
    pub fn try_from_iter<A, T: IntoIterator<Item = A>>(iter: T) -> IoResult<Self>
        where
            A: ToSocketAddrs, { ... }
    /// Build a [LoadBalancer] with the given [Backends].
    pub fn from_backends(backends: Backends) -> Self { ... }
    /// Run the service discovery and update the selection algorithm.
    ///
    /// This function will be called every `update_frequency` if this [LoadBalancer] instance
    /// is running as a background service.
    pub async fn update(&self) -> Result<()> { ... }
    pub fn select(&self, key: &[u8], max_iterations: usize) -> Option<Backend> { ... }
    /// Similar to [Self::select], return the first healthy [Backend] according to the selection algorithm
    /// and the user defined `accept` function.
    ///
    /// The `accept` function takes two inputs, the backend being selected and the internal health of that
    /// backend. The function can do things like ignoring the internal health checks or skipping this backend
    /// because it failed before. The `accept` function is called multiple times iterating over backends
    /// until it returns `true`.
    pub fn select_with<F>(&self, key: &[u8], max_iterations: usize, accept: F) -> Option<Backend>
        where
            F: Fn(&Backend, bool) -> bool, { ... }
    /// Set the health check method. See [health_check].
    pub fn set_health_check(
            &mut self,
            hc: Box<dyn health_check::HealthCheck + Send + Sync + 'static>,
        ) { ... }
    /// Access the [Backends] of this [LoadBalancer]
    pub fn backends(&self) -> &Backends { ... }
}
```
## pingora-load-balancing/src/selection/algorithms.rs
```rust
use super::*;
use std::hash::Hasher;
use std::sync::atomic::{AtomicUsize, Ordering};
/// Round Robin selection
pub struct RoundRobin(AtomicUsize); { ... }
/// Random selection
pub struct Random; { ... }
impl<H> SelectionAlgorithm for H
where
    H: Default + Hasher, {
    fn new() -> Self { ... }
    fn next(&self, key: &[u8]) -> u64 { ... }
}
impl SelectionAlgorithm for RoundRobin {
    fn new() -> Self { ... }
    fn next(&self, _key: &[u8]) -> u64 { ... }
}
impl SelectionAlgorithm for Random {
    fn new() -> Self { ... }
    fn next(&self, _key: &[u8]) -> u64 { ... }
}
```
## pingora-load-balancing/src/selection/consistent.rs
```rust
use super::*;
use pingora_core::protocols::l4::socket::SocketAddr;
use pingora_ketama::{Bucket, Continuum};
use std::collections::HashMap;
/// Weighted Ketama consistent hashing
pub struct KetamaHashing { ... }
/// Iterator over a Continuum
pub struct OwnedNodeIterator { ... }
impl BackendSelection for KetamaHashing {
    fn build(backends: &BTreeSet<Backend>) -> Self { ... }
    fn iter(self: &Arc<Self>, key: &[u8]) -> Self::Iter { ... }
}
impl BackendIter for OwnedNodeIterator {
    fn next(&mut self) -> Option<&Backend> { ... }
}
```
## pingora-load-balancing/src/selection/mod.rs
```rust
use super::Backend;
use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;
use weighted::Weighted;
pub mod algorithms {
}
pub mod consistent {
}
pub mod weighted {
}
/// An iterator which wraps another iterator and yields unique items. It optionally takes a max
/// number of iterations if the wrapped iterator never returns.
pub struct UniqueIterator<I>
where
    I: BackendIter, { ... }
/// [BackendSelection] is the interface to implement backend selection mechanisms.
pub trait BackendSelection { ... }
/// An iterator to find the suitable backend
///
/// Similar to [Iterator] but allow self referencing.
pub trait BackendIter { ... }
/// [SelectionAlgorithm] is the interface to implement selection algorithms.
///
/// All [std::hash::Hasher] + [Default] can be used directly as a selection algorithm.
pub trait SelectionAlgorithm { ... }
impl<I> UniqueIterator<I>
where
    I: BackendIter, {
    /// Wrap a new iterator and specify the maximum number of times we want to iterate.
    pub fn new(iter: I, max_iterations: usize) -> Self { ... }
    pub fn get_next(&mut self) -> Option<Backend> { ... }
}
```
## pingora-load-balancing/src/selection/weighted.rs
```rust
use super::{Backend, BackendIter, BackendSelection, SelectionAlgorithm};
use fnv::FnvHasher;
use std::collections::BTreeSet;
use std::sync::Arc;
/// Weighted selection with a given selection algorithm
///
/// The default algorithm is [FnvHasher]. See [super::algorithms] for more choices.
pub struct Weighted<H = FnvHasher> { ... }
/// An iterator over the backends of a [Weighted] selection.
///
/// See [super::BackendSelection] for more information.
pub struct WeightedIterator<H> { ... }
impl<H: SelectionAlgorithm> BackendSelection for Weighted<H> {
    fn build(backends: &BTreeSet<Backend>) -> Self { ... }
    fn iter(self: &Arc<Self>, key: &[u8]) -> Self::Iter { ... }
}
impl<H: SelectionAlgorithm> BackendIter for WeightedIterator<H> {
    fn next(&mut self) -> Option<&Backend> { ... }
}
```
## pingora-lru/benches/bench_linked_list.rs
```rust
use std::time::Instant;
```
## pingora-lru/benches/bench_lru.rs
```rust
use rand::distributions::WeightedIndex;
use rand::prelude::*;
use std::sync::Arc;
use std::thread;
use std::time::Instant;
```
## pingora-lru/src/lib.rs
```rust
use linked_list::{LinkedList, LinkedListIter};
use hashbrown::HashMap;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicUsize, Ordering};
pub mod linked_list {
}
/// The LRU with `N` shards
pub struct Lru<T, const N: usize> { ... }
impl<T, const N: usize> Lru<T, N> {
    /// Create an [Lru] with the given weight limit and predicted capacity.
    ///
    /// The capacity is per shard (for simplicity). So the total capacity = capacity * N
    pub fn with_capacity(weight_limit: usize, capacity: usize) -> Self { ... }
    /// Admit the key value to the [Lru]
    ///
    /// Return the shard index which the asset is added to
    pub fn admit(&self, key: u64, data: T, weight: usize) -> usize { ... }
    /// Promote the key to the head of the LRU
    ///
    /// Return `true` if the key exists.
    pub fn promote(&self, key: u64) -> bool { ... }
    /// Promote to the top n of the LRU
    ///
    /// This function is a bit more efficient in terms of reducing lock contention because it
    /// will acquire a write lock only if the key is outside top n but only acquires a read lock
    /// when the key is already in the top n.
    ///
    /// Return false if the item doesn't exist
    pub fn promote_top_n(&self, key: u64, top: usize) -> bool { ... }
    /// Evict at most one item from the given shard
    ///
    /// Return the evicted asset and its size if there is anything to evict
    pub fn evict_shard(&self, shard: u64) -> Option<(T, usize)> { ... }
    /// Evict the [Lru] until the overall weight is below the limit.
    ///
    /// Return a list of evicted items.
    ///
    /// The evicted items are randomly selected from all the shards.
    pub fn evict_to_limit(&self) -> Vec<(T, usize)> { ... }
    /// Remove the given asset
    pub fn remove(&self, key: u64) -> Option<(T, usize)> { ... }
    /// Insert the item to the tail of this LRU
    ///
    /// Useful to recreate an LRU in most-to-least order
    pub fn insert_tail(&self, key: u64, data: T, weight: usize) -> bool { ... }
    /// Check existence of a key without changing the order in LRU
    pub fn peek(&self, key: u64) -> bool { ... }
    /// Return the current total weight
    pub fn weight(&self) -> usize { ... }
    /// Return the total weight of items evicted from this [Lru].
    pub fn evicted_weight(&self) -> usize { ... }
    /// Return the total count of items evicted from this [Lru].
    pub fn evicted_len(&self) -> usize { ... }
    /// The number of items inside this [Lru].
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize { ... }
    /// Scan a shard with the given function F
    pub fn iter_for_each<F>(&self, shard: usize, f: F)
        where
            F: FnMut((&T, usize)), { ... }
    /// Get the total number of shards
    pub const fn shards(&self) -> usize { ... }
    /// Get the number of items inside a shard
    pub fn shard_len(&self, shard: usize) -> usize { ... }
}
impl<T> LruUnit<T> {
    pub fn peek(&self, key: u64) -> Option<&T> { ... }
    pub fn admit(&mut self, key: u64, data: T, weight: usize) -> usize { ... }
    pub fn access(&mut self, key: u64) -> bool { ... }
    pub fn need_promote(&self, key: u64, limit: usize) -> bool { ... }
    pub fn evict(&mut self) -> Option<(T, usize)> { ... }
    pub fn remove(&mut self, key: u64) -> Option<(T, usize)> { ... }
    pub fn insert_tail(&mut self, key: u64, data: T, weight: usize) -> bool { ... }
    pub fn len(&self) -> usize { ... }
    pub fn iter(&self) -> LruUnitIter<'_, T> { ... }
}
impl<'a, T> Iterator for LruUnitIter<'a, T> {
    fn next(&mut self) -> Option<Self::Item> { ... }
    fn size_hint(&self) -> (usize, Option<usize>) { ... }
}
impl<T> DoubleEndedIterator for LruUnitIter<'_, T> {
    fn next_back(&mut self) -> Option<Self::Item> { ... }
}
```
## pingora-lru/src/linked_list.rs
```rust
use std::mem::replace;
/// Doubly linked list
pub struct LinkedList { ... }
/// The iter over the list
pub struct LinkedListIter<'a> { ... }
impl std::ops::Index<usize> for Nodes {
    fn index(&self, index: usize) -> &Self::Output { ... }
}
impl std::ops::IndexMut<usize> for Nodes {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output { ... }
}
impl LinkedList {
    /// Create a [LinkedList] with the given predicted capacity.
    pub fn with_capacity(capacity: usize) -> Self { ... }
    /// How many nodes in the list
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize { ... }
    /// Peek into the list
    pub fn peek(&self, index: Index) -> Option<u64> { ... }
    pub fn exist_near_head(&self, value: u64, search_limit: usize) -> bool { ... }
    /// Put the data at the head of the list.
    pub fn push_head(&mut self, data: u64) -> Index { ... }
    /// Put the data at the tail of the list.
    pub fn push_tail(&mut self, data: u64) -> Index { ... }
    /// Remove the node at the index, and return the value
    pub fn remove(&mut self, index: Index) -> u64 { ... }
    /// Remove the tail of the list
    pub fn pop_tail(&mut self) -> Option<u64> { ... }
    /// Put the node at the index to the head
    pub fn promote(&mut self, index: Index) { ... }
    /// Get the head of the list
    pub fn head(&self) -> Option<Index> { ... }
    /// Get the tail of the list
    pub fn tail(&self) -> Option<Index> { ... }
    /// Iterate over the list
    pub fn iter(&self) -> LinkedListIter<'_> { ... }
}
impl<'a> Iterator for LinkedListIter<'a> {
    fn next(&mut self) -> Option<Self::Item> { ... }
    fn size_hint(&self) -> (usize, Option<usize>) { ... }
}
impl DoubleEndedIterator for LinkedListIter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> { ... }
}
```
## pingora-memory-cache/src/lib.rs
```rust
use ahash::RandomState;
use std::borrow::Borrow;
use std::hash::Hash;
use std::marker::PhantomData;
use std::time::{Duration, Instant};
use tinyufo::TinyUfo;
pub use read_through::{Lookup, MultiLookup, RTCache};
/// [CacheStatus] indicates the response type for a query.
pub enum CacheStatus {
    /// The key was found in the cache
    Hit,
    /// The key was not found.
    Miss,
    /// The key was found but it was expired.
    Expired,
    /// The key was not initially found but was found after awaiting a lock.
    LockHit,
    /// The returned value was expired but still returned. The [Duration] is
    /// how long it has been since its expiration time.
    Stale(Duration),
}
/// A high performant in-memory cache with S3-FIFO + TinyLFU
pub struct MemoryCache<K: Hash, T: Clone> { ... }
impl CacheStatus {
    /// Return the string representation for [CacheStatus].
    pub fn as_str(&self) -> &str { ... }
    /// Returns whether this status represents a cache hit.
    pub fn is_hit(&self) -> bool { ... }
    /// Returns the stale duration if any
    pub fn stale(&self) -> Option<Duration> { ... }
}
impl<K: Hash, T: Clone + Send + Sync + 'static> MemoryCache<K, T> {
    /// Create a new [MemoryCache] with the given size.
    pub fn new(size: usize) -> Self { ... }
    /// Fetch the key and return its value in addition to a [CacheStatus].
    pub fn get<Q>(&self, key: &Q) -> (Option<T>, CacheStatus)
        where
            K: Borrow<Q>,
            Q: Hash + ?Sized, { ... }
    /// Similar to [Self::get], fetch the key and return its value in addition to a
    /// [CacheStatus] but also return the value even if it is expired. When the
    /// value is expired, the [Duration] of how long it has been stale will
    /// also be returned.
    pub fn get_stale<Q>(&self, key: &Q) -> (Option<T>, CacheStatus)
        where
            K: Borrow<Q>,
            Q: Hash + ?Sized, { ... }
    /// Insert a key and value pair with an optional TTL into the cache.
    ///
    /// An item with zero TTL of zero will not be inserted.
    pub fn put<Q>(&self, key: &Q, value: T, ttl: Option<Duration>)
        where
            K: Borrow<Q>,
            Q: Hash + ?Sized, { ... }
    /// Remove a key from the cache if it exists.
    pub fn remove<Q>(&self, key: &Q)
        where
            K: Borrow<Q>,
            Q: Hash + ?Sized, { ... }
    /// This is equivalent to [MemoryCache::get] but for an arbitrary amount of keys.
    pub fn multi_get<'a, I, Q>(&self, keys: I) -> Vec<(Option<T>, CacheStatus)>
        where
            I: Iterator<Item = &'a Q>,
            Q: Hash + ?Sized + 'a,
            K: Borrow<Q> + 'a, { ... }
    /// Same as [MemoryCache::multi_get] but returns the keys that are missing from the cache.
    pub fn multi_get_with_miss<'a, I, Q>(
            &self,
            keys: I,
        ) -> (Vec<(Option<T>, CacheStatus)>, Vec<&'a Q>)
        where
            I: Iterator<Item = &'a Q>,
            Q: Hash + ?Sized + 'a,
            K: Borrow<Q> + 'a, { ... }
}
```
## pingora-memory-cache/src/read_through.rs
```rust
use super::{CacheStatus, MemoryCache};
use async_trait::async_trait;
use log::warn;
use parking_lot::RwLock;
use pingora_error::{Error, ErrorTrait};
use std::collections::HashMap;
use std::hash::Hash;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
/// A read-through in-memory cache on top of [MemoryCache]
///
/// Instead of providing a `put` function, [RTCache] requires a type which implements [Lookup] to
/// be automatically called during cache miss to populate the cache. This is useful when trying to
/// cache queries to external system such as DNS or databases.
///
/// Lookup coalescing is provided so that multiple concurrent lookups for the same key results
/// only in one lookup callback.
pub struct RTCache<K, T, CB, S>
where
    K: Hash + Send,
    T: Clone + Send, { ... }
/// [Lookup] defines the caching behavior that the implementor needs. The `extra` field can be used
/// to define any additional metadata that the implementor uses to determine cache eligibility.
///
/// # Examples
///
/// ```ignore
/// use pingora_error::{ErrorTrait, Result};
/// use std::time::Duration;
///
/// struct MyLookup;
///
/// impl Lookup<usize, usize, ()> for MyLookup {
/// async fn lookup(
/// &self,
/// _key: &usize,
/// extra: Option<&()>,
/// ) -> Result<(usize, Option<Duration>), Box<dyn ErrorTrait + Send + Sync>> {
/// // Define your business logic here.
/// Ok(1, None)
/// }
/// }
/// ```
pub trait Lookup { ... }
/// [MultiLookup] is similar to [Lookup]. Implement this trait if the system being queried support
/// looking up multiple keys in a single API call.
pub trait MultiLookup { ... }
impl CacheLock {
    pub fn new_arc() -> Arc<Self> { ... }
    pub fn too_old(&self, age: Option<&Duration>) -> bool { ... }
}
impl<K, T, CB, S> RTCache<K, T, CB, S>
where
    K: Hash + Send,
    T: Clone + Send + Sync + 'static, {
    /// Create a new [RTCache] of given size. `lock_age` defines how long a lock is valid for.
    /// `lock_timeout` is used to stop a lookup from holding on to the key for too long.
    pub fn new(size: usize, lock_age: Option<Duration>, lock_timeout: Option<Duration>) -> Self { ... }
}
impl<K, T, CB, S> RTCache<K, T, CB, S>
where
    K: Hash + Send,
    T: Clone + Send + Sync + 'static,
    CB: Lookup<K, T, S>, {
    /// Query the cache for a given value. If it exists and no TTL is configured initially, it will
    /// use the `ttl` value given.
    pub async fn get(
            &self,
            key: &K,
            ttl: Option<Duration>,
            extra: Option<&S>,
        ) -> (Result<T, Box<Error>>, CacheStatus) { ... }
    /// Similar to [Self::get], query the cache for a given value, but also returns the value even if the
    /// value is expired up to `stale_ttl`. If it is a cache miss or the value is stale more than
    /// the `stale_ttl`, a lookup will be performed to populate the cache.
    pub async fn get_stale(
            &self,
            key: &K,
            ttl: Option<Duration>,
            extra: Option<&S>,
            stale_ttl: Duration,
        ) -> (Result<T, Box<Error>>, CacheStatus) { ... }
}
impl<K, T, CB, S> RTCache<K, T, CB, S>
where
    K: Hash + Clone + Send + Sync,
    T: Clone + Send + Sync + 'static,
    S: Clone + Send + Sync,
    CB: Lookup<K, T, S> + Sync + Send, {
    /// Similar to [Self::get_stale], but when it returns the stale value, it also initiates a lookup
    /// in the background in order to refresh the value.
    ///
    /// Note that this function requires the [RTCache] to be static, which can be done by wrapping
    /// it with something like [once_cell::sync::Lazy].
    ///
    /// [once_cell::sync::Lazy]: https://docs.rs/once_cell/latest/once_cell/sync/struct.Lazy.html
    pub async fn get_stale_while_update(
            &'static self,
            key: &K,
            ttl: Option<Duration>,
            extra: Option<&S>,
            stale_ttl: Duration,
        ) -> (Result<T, Box<Error>>, CacheStatus) { ... }
}
impl<K, T, CB, S> RTCache<K, T, CB, S>
where
    K: Hash + Send,
    T: Clone + Send + Sync + 'static,
    CB: MultiLookup<K, T, S>, {
    /// Same behavior as [RTCache::get] but for an arbitrary amount of keys.
    ///
    /// If there are keys that are missing from the cache, `multi_lookup` is invoked to populate the
    /// cache before returning the final results. This is useful if your type supports batch
    /// queries.
    ///
    /// To avoid dead lock for the same key across concurrent `multi_get` calls,
    /// this function does not provide lookup coalescing.
    pub async fn multi_get<'a, I>(
            &self,
            keys: I,
            ttl: Option<Duration>,
            extra: Option<&S>,
        ) -> Result<Vec<(T, CacheStatus)>, Box<Error>>
        where
            I: Iterator<Item = &'a K>,
            K: 'a, { ... }
}
```
## pingora-openssl/src/ext.rs
```rust
use foreign_types::ForeignTypeRef;
use libc::*;
use openssl::error::ErrorStack;
use openssl::pkey::{HasPrivate, PKeyRef};
use openssl::ssl::{Ssl, SslAcceptor, SslRef};
use openssl::x509::store::X509StoreRef;
use openssl::x509::verify::X509VerifyParamRef;
use openssl::x509::X509Ref;
use openssl_sys::{
    SSL_ctrl, EVP_PKEY, SSL, SSL_CTRL_SET_GROUPS_LIST, SSL_CTRL_SET_VERIFY_CERT_STORE, X509,
    X509_VERIFY_PARAM,
};
use std::ffi::CString;
use std::os::raw;
/// Add name as an additional reference identifier that can match the peer's certificate
///
/// See [X509_VERIFY_PARAM_set1_host](https://www.openssl.org/docs/man3.1/man3/X509_VERIFY_PARAM_set1_host.html).
pub fn add_host(verify_param: &mut X509VerifyParamRef, host: &str) -> Result<(), ErrorStack> { ... }
/// Set the verify cert store of `ssl`
///
/// See [SSL_set1_verify_cert_store](https://www.openssl.org/docs/man1.1.1/man3/SSL_set1_verify_cert_store.html).
pub fn ssl_set_verify_cert_store(
    ssl: &mut SslRef,
    cert_store: &X509StoreRef,
) -> Result<(), ErrorStack> { ... }
/// Load the certificate into `ssl`
///
/// See [SSL_use_certificate](https://www.openssl.org/docs/man1.1.1/man3/SSL_use_certificate.html).
pub fn ssl_use_certificate(ssl: &mut SslRef, cert: &X509Ref) -> Result<(), ErrorStack> { ... }
/// Load the private key into `ssl`
///
/// See [SSL_use_certificate](https://www.openssl.org/docs/man1.1.1/man3/SSL_use_PrivateKey.html).
pub fn ssl_use_private_key<T>(ssl: &mut SslRef, key: &PKeyRef<T>) -> Result<(), ErrorStack>
where
    T: HasPrivate, { ... }
/// Add the certificate into the cert chain of `ssl`
///
/// See [SSL_add1_chain_cert](https://www.openssl.org/docs/man1.1.1/man3/SSL_add1_chain_cert.html)
pub fn ssl_add_chain_cert(ssl: &mut SslRef, cert: &X509Ref) -> Result<(), ErrorStack> { ... }
/// Set renegotiation
///
/// This function is specific to BoringSSL. This function is noop for OpenSSL.
pub fn ssl_set_renegotiate_mode_freely(_ssl: &mut SslRef) { ... }
/// Set the curves/groups of `ssl`
///
/// See [set_groups_list](https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set1_curves.html).
pub fn ssl_set_groups_list(ssl: &mut SslRef, groups: &str) -> Result<(), ErrorStack> { ... }
/// Set's whether a second keyshare to be sent in client hello when PQ is used.
///
/// This function is specific to BoringSSL. This function is noop for OpenSSL.
pub fn ssl_use_second_key_share(_ssl: &mut SslRef, _enabled: bool) { ... }
/// Clear the error stack
///
/// SSL calls should check and clear the OpenSSL error stack. But some calls fail to do so.
/// This causes the next unrelated SSL call to fail due to the leftover errors. This function allows
/// caller to clear the error stack before performing SSL calls to avoid this issue.
pub fn clear_error_stack() { ... }
/// Create a new [Ssl] from &[SslAcceptor]
///
/// this function is to unify the interface between this crate and [`pingora-boringssl`](https://docs.rs/pingora-boringssl)
pub fn ssl_from_acceptor(acceptor: &SslAcceptor) -> Result<Ssl, ErrorStack> { ... }
/// Suspend the TLS handshake when a certificate is needed.
///
/// This function will cause tls handshake to pause and return the error: SSL_ERROR_WANT_X509_LOOKUP.
/// The caller should set the certificate and then call [unblock_ssl_cert()] before continue the
/// handshake on the tls connection.
pub fn suspend_when_need_ssl_cert(ssl: &mut SslRef) { ... }
/// Unblock a TLS handshake after the certificate is set.
///
/// The user should continue to call tls handshake after this function is called.
pub fn unblock_ssl_cert(ssl: &mut SslRef) { ... }
/// Whether the TLS error is SSL_ERROR_WANT_X509_LOOKUP
pub fn is_suspended_for_cert(error: &openssl::ssl::Error) -> bool { ... }
/// Get a mutable SslRef ouf of SslRef, which is a missing functionality even when holding &mut SslStream
/// # Safety
/// the caller needs to make sure that they hold a &mut SslStream (or other types of mutable ref to the Ssl)
pub unsafe fn ssl_mut(ssl: &SslRef) -> &mut SslRef { ... }
```
## pingora-openssl/src/lib.rs
```rust
use openssl as ssl_lib;
pub use openssl_sys as ssl_sys;
pub use tokio_openssl as tokio_ssl;
pub use ssl_lib::dh;
pub use ssl_lib::error;
pub use ssl_lib::hash;
pub use ssl_lib::nid;
pub use ssl_lib::pkey;
pub use ssl_lib::ssl;
pub use ssl_lib::x509;
pub mod ext {
}
```
## pingora-pool/src/connection.rs
```rust
use log::{debug, warn};
use parking_lot::{Mutex, RwLock};
use pingora_timeout::{sleep, timeout};
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::{oneshot, watch, Notify, OwnedMutexGuard};
use super::lru::Lru;
use crossbeam_queue::ArrayQueue;
/// the metadata of a connection
#[derive(Clone, Debug)]
pub struct ConnectionMeta { ... }
/// A pool of exchangeable items
pub struct PoolNode<T> { ... }
/// Connection pool
///
/// [ConnectionPool] holds reusable connections. A reusable connection is released to this pool to
/// be picked up by another user/request.
pub struct ConnectionPool<S> { ... }
impl ConnectionMeta {
    /// Create a new [ConnectionMeta]
    pub fn new(key: GroupKey, id: ID) -> Self { ... }
}
impl<S> PoolConnection<S> {
    pub fn new(notify_use: oneshot::Sender<bool>, connection: S) -> Self { ... }
    pub fn release(self) -> S { ... }
}
impl<T> PoolNode<T> {
    /// Create a new [PoolNode]
    pub fn new() -> Self { ... }
    /// Get any item from the pool
    pub fn get_any(&self) -> Option<(ID, T)> { ... }
    /// Insert an item with the given unique ID into the pool
    pub fn insert(&self, id: ID, conn: T) { ... }
    /// Remove the item associated with the id from the pool. The item is returned
    /// if it is found and removed.
    pub fn remove(&self, id: ID) -> Option<T> { ... }
}
impl<S> ConnectionPool<S> {
    /// Create a new [ConnectionPool] with a size limit.
    ///
    /// When a connection is released to this pool, the least recently used connection will be dropped.
    pub fn new(size: usize) -> Self { ... }
    pub fn pop_closed(&self, meta: &ConnectionMeta) { ... }
    /// Get a connection from this pool under the same group key
    pub fn get(&self, key: &GroupKey) -> Option<S> { ... }
    /// Release a connection to this pool for reuse
    ///
    /// - The returned [`Arc<Notify>`] will notify any listen when the connection is evicted from the pool.
    /// - The returned [`oneshot::Receiver<bool>`] will notify when the connection is being picked up by [Self::get()].
    pub fn put(
            &self,
            meta: &ConnectionMeta,
            connection: S,
        ) -> (Arc<Notify>, oneshot::Receiver<bool>) { ... }
    /// Actively monitor the health of a connection that is already released to this pool
    ///
    /// When the connection breaks, or the optional `timeout` is reached this function will
    /// remove it from the pool and drop the connection.
    ///
    /// If the connection is reused via [Self::get()] or being evicted, this function will just exit.
    pub async fn idle_poll<Stream>(
            &self,
            connection: OwnedMutexGuard<Stream>,
            meta: &ConnectionMeta,
            timeout: Option<Duration>,
            notify_evicted: Arc<Notify>,
            watch_use: oneshot::Receiver<bool>,
        ) where
            Stream: AsyncRead + Unpin + Send, { ... }
    /// Passively wait to close the connection after the timeout
    ///
    /// If this connection is not being picked up or evicted before the timeout is reach, this
    /// function will remove it from the pool and close the connection.
    pub async fn idle_timeout(
            &self,
            meta: &ConnectionMeta,
            timeout: Duration,
            notify_evicted: Arc<Notify>,
            mut notify_closed: watch::Receiver<bool>,
            watch_use: oneshot::Receiver<bool>,
        ) { ... }
}
```
## pingora-pool/src/lib.rs
```rust
pub use connection::{ConnectionMeta, ConnectionPool, PoolNode};
```
## pingora-pool/src/lru.rs
```rust
use core::hash::Hash;
use lru::LruCache;
use parking_lot::RwLock;
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::Arc;
use thread_local::ThreadLocal;
use tokio::sync::Notify;
pub struct Node<T> { ... }
pub struct Lru<K, T>
where
    K: Send,
    T: Send, { ... }
impl<T> Node<T> {
    pub fn new(meta: T) -> Self { ... }
    pub fn notify_close(&self) { ... }
}
impl<K, T> Lru<K, T>
where
    K: Hash + Eq + Send,
    T: Send, {
    pub fn new(size: usize) -> Self { ... }
    pub fn put(&self, key: K, value: Node<T>) -> Option<T> { ... }
    pub fn add(&self, key: K, meta: T) -> (Arc<Notify>, Option<T>) { ... }
    pub fn pop(&self, key: &K) -> Option<Node<T>> { ... }
    #[allow(dead_code)]
    pub fn drain(&self) { ... }
}
```
## pingora-proxy/examples/backoff_retry.rs
```rust
use std::time::Duration;
use async_trait::async_trait;
use clap::Parser;
use log::info;
use pingora_core::server::Server;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_core::{prelude::Opt, Error};
use pingora_proxy::{ProxyHttp, Session};
#[async_trait]
impl ProxyHttp for BackoffRetryProxy {
    fn new_ctx(&self) -> Self::CTX { ... }
    fn fail_to_connect(
            &self,
            _session: &mut Session,
            _peer: &HttpPeer,
            ctx: &mut Self::CTX,
            e: Box<Error>,
        ) -> Box<Error> { ... }
    async fn upstream_peer(
            &self,
            _session: &mut Session,
            ctx: &mut Self::CTX,
        ) -> Result<Box<HttpPeer>> { ... }
}
```
## pingora-proxy/examples/ctx.rs
```rust
use async_trait::async_trait;
use clap::Parser;
use log::info;
use std::sync::Mutex;
use pingora_core::server::configuration::Opt;
use pingora_core::server::Server;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_proxy::{ProxyHttp, Session};
pub struct MyProxy { ... }
pub struct MyCtx { ... }
#[async_trait]
impl ProxyHttp for MyProxy {
    fn new_ctx(&self) -> Self::CTX { ... }
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> { ... }
    async fn upstream_peer(
            &self,
            _session: &mut Session,
            ctx: &mut Self::CTX,
        ) -> Result<Box<HttpPeer>> { ... }
}
```
## pingora-proxy/examples/gateway.rs
```rust
use async_trait::async_trait;
use bytes::Bytes;
use clap::Parser;
use log::info;
use prometheus::register_int_counter;
use pingora_core::server::configuration::Opt;
use pingora_core::server::Server;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};
pub struct MyGateway { ... }
#[async_trait]
impl ProxyHttp for MyGateway {
    fn new_ctx(&self) -> Self::CTX { ... }
    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> { ... }
    async fn upstream_peer(
            &self,
            session: &mut Session,
            _ctx: &mut Self::CTX,
        ) -> Result<Box<HttpPeer>> { ... }
    async fn response_filter(
            &self,
            _session: &mut Session,
            upstream_response: &mut ResponseHeader,
            _ctx: &mut Self::CTX,
        ) -> Result<()>
        where
            Self::CTX: Send + Sync, { ... }
    async fn logging(
            &self,
            session: &mut Session,
            _e: Option<&pingora_core::Error>,
            ctx: &mut Self::CTX,
        ) { ... }
}
```
## pingora-proxy/examples/grpc_web_module.rs
```rust
use async_trait::async_trait;
use clap::Parser;
use pingora_core::server::Server;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_core::{
    modules::http::{
        grpc_web::{GrpcWeb, GrpcWebBridge},
        HttpModules,
    },
    prelude::Opt,
};
use pingora_proxy::{ProxyHttp, Session};
pub struct GrpcWebBridgeProxy; { ... }
#[async_trait]
impl ProxyHttp for GrpcWebBridgeProxy {
    fn new_ctx(&self) -> Self::CTX { ... }
    fn init_downstream_modules(&self, modules: &mut HttpModules) { ... }
    async fn early_request_filter(
            &self,
            session: &mut Session,
            _ctx: &mut Self::CTX,
        ) -> Result<()> { ... }
    async fn upstream_peer(
            &self,
            _session: &mut Session,
            _ctx: &mut Self::CTX,
        ) -> Result<Box<HttpPeer>> { ... }
}
```
## pingora-proxy/examples/load_balancer.rs
```rust
use async_trait::async_trait;
use clap::Parser;
use log::info;
use pingora_core::services::background::background_service;
use std::{sync::Arc, time::Duration};
use pingora_core::server::configuration::Opt;
use pingora_core::server::Server;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_load_balancing::{health_check, selection::RoundRobin, LoadBalancer};
use pingora_proxy::{ProxyHttp, Session};
pub struct LB(Arc<LoadBalancer<RoundRobin>>); { ... }
#[async_trait]
impl ProxyHttp for LB {
    fn new_ctx(&self) -> Self::CTX { ... }
    async fn upstream_peer(&self, _session: &mut Session, _ctx: &mut ()) -> Result<Box<HttpPeer>> { ... }
    async fn upstream_request_filter(
            &self,
            _session: &mut Session,
            upstream_request: &mut pingora_http::RequestHeader,
            _ctx: &mut Self::CTX,
        ) -> Result<()> { ... }
}
```
## pingora-proxy/examples/modify_response.rs
```rust
use async_trait::async_trait;
use bytes::Bytes;
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::net::ToSocketAddrs;
use pingora_core::server::configuration::Opt;
use pingora_core::server::Server;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};
#[derive(Serialize, Deserialize)]
pub struct Resp { ... }
pub struct Json2Yaml { ... }
pub struct MyCtx { ... }
#[async_trait]
impl ProxyHttp for Json2Yaml {
    fn new_ctx(&self) -> Self::CTX { ... }
    async fn upstream_peer(
            &self,
            _session: &mut Session,
            _ctx: &mut Self::CTX,
        ) -> Result<Box<HttpPeer>> { ... }
    async fn upstream_request_filter(
            &self,
            _session: &mut Session,
            upstream_request: &mut pingora_http::RequestHeader,
            _ctx: &mut Self::CTX,
        ) -> Result<()> { ... }
    async fn response_filter(
            &self,
            _session: &mut Session,
            upstream_response: &mut ResponseHeader,
            _ctx: &mut Self::CTX,
        ) -> Result<()>
        where
            Self::CTX: Send + Sync, { ... }
    fn response_body_filter(
            &self,
            _session: &mut Session,
            body: &mut Option<Bytes>,
            end_of_stream: bool,
            ctx: &mut Self::CTX,
        ) -> Result<Option<std::time::Duration>>
        where
            Self::CTX: Send + Sync, { ... }
}
```
## pingora-proxy/examples/multi_lb.rs
```rust
use async_trait::async_trait;
use std::sync::Arc;
use pingora_core::{prelude::*, services::background::GenBackgroundService};
use pingora_load_balancing::{
    health_check::TcpHealthCheck,
    selection::{BackendIter, BackendSelection, RoundRobin},
    LoadBalancer,
};
use pingora_proxy::{http_proxy_service, ProxyHttp, Session};
#[async_trait]
impl ProxyHttp for Router {
    fn new_ctx(&self) { ... }
    async fn upstream_peer(&self, session: &mut Session, _ctx: &mut ()) -> Result<Box<HttpPeer>> { ... }
}
```
## pingora-proxy/examples/rate_limiter.rs
```rust
use async_trait::async_trait;
use once_cell::sync::Lazy;
use pingora_core::prelude::*;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_limits::rate::Rate;
use pingora_load_balancing::prelude::{RoundRobin, TcpHealthCheck};
use pingora_load_balancing::LoadBalancer;
use pingora_proxy::{http_proxy_service, ProxyHttp, Session};
use std::sync::Arc;
use std::time::Duration;
pub struct LB(Arc<LoadBalancer<RoundRobin>>); { ... }
impl LB {
    pub fn get_request_appid(&self, session: &mut Session) -> Option<String> { ... }
}
#[async_trait]
impl ProxyHttp for LB {
    fn new_ctx(&self) { ... }
    async fn upstream_peer(
            &self,
            _session: &mut Session,
            _ctx: &mut Self::CTX,
        ) -> Result<Box<HttpPeer>> { ... }
    async fn upstream_request_filter(
            &self,
            _session: &mut Session,
            upstream_request: &mut RequestHeader,
            _ctx: &mut Self::CTX,
        ) -> Result<()>
        where
            Self::CTX: Send + Sync, { ... }
    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool>
        where
            Self::CTX: Send + Sync, { ... }
}
```
## pingora-proxy/examples/use_module.rs
```rust
use async_trait::async_trait;
use clap::Parser;
use pingora_core::modules::http::HttpModules;
use pingora_core::server::configuration::Opt;
use pingora_core::server::Server;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_http::RequestHeader;
use pingora_proxy::{ProxyHttp, Session};
pub struct MyProxy; { ... }
#[async_trait]
impl ProxyHttp for MyProxy {
    fn new_ctx(&self) -> Self::CTX { ... }
    fn init_downstream_modules(&self, modules: &mut HttpModules) { ... }
    async fn upstream_peer(
            &self,
            _session: &mut Session,
            _ctx: &mut Self::CTX,
        ) -> Result<Box<HttpPeer>> { ... }
}
```
## pingora-proxy/src/lib.rs
```rust
use async_trait::async_trait;
use bytes::Bytes;
use futures::future::FutureExt;
use http::{header, version::Version};
use log::{debug, error, trace, warn};
use once_cell::sync::Lazy;
use pingora_http::{RequestHeader, ResponseHeader};
use std::fmt::Debug;
use std::str;
use std::sync::Arc;
use tokio::sync::{mpsc, Notify};
use tokio::time;
use pingora_cache::NoCacheReason;
use pingora_core::apps::{HttpServerApp, HttpServerOptions};
use pingora_core::connectors::{http::Connector, ConnectorOptions};
use pingora_core::modules::http::compression::ResponseCompressionBuilder;
use pingora_core::modules::http::{HttpModuleCtx, HttpModules};
use pingora_core::protocols::http::client::HttpSession as ClientSession;
use pingora_core::protocols::http::v1::client::HttpSession as HttpSessionV1;
use pingora_core::protocols::http::HttpTask;
use pingora_core::protocols::http::ServerSession as HttpSession;
use pingora_core::protocols::http::SERVER_NAME;
use pingora_core::protocols::Stream;
use pingora_core::protocols::{Digest, UniqueID};
use pingora_core::server::configuration::ServerConf;
use pingora_core::server::ShutdownWatch;
use pingora_core::upstreams::peer::{HttpPeer, Peer};
use pingora_error::{Error, ErrorSource, ErrorType::*, OrErr, Result};
use subrequest::Ctx as SubReqCtx;
pub use proxy_cache::range_filter::{range_header_filter, RangeType};
pub use proxy_purge::PurgeStatus;
pub use proxy_trait::{FailToProxy, ProxyHttp};
use pingora_cache::HttpCache;
use pingora_core::protocols::http::compression::ResponseCompressionCtx;
use std::ops::{Deref, DerefMut};
use pingora_core::services::listening::Service;
pub mod prelude {
    pub use crate::{http_proxy_service, ProxyHttp, Session};
}
/// Create a [Service] from the user implemented [ProxyHttp].
///
/// The returned [Service] can be hosted by a [pingora_core::server::Server] directly.
pub fn http_proxy_service<SV>(conf: &Arc<ServerConf>, inner: SV) -> Service<HttpProxy<SV>>
where
    SV: ProxyHttp, { ... }
/// Create a [Service] from the user implemented [ProxyHttp].
///
/// The returned [Service] can be hosted by a [pingora_core::server::Server] directly.
pub fn http_proxy_service_with_name<SV>(
    conf: &Arc<ServerConf>,
    inner: SV,
    name: &str,
) -> Service<HttpProxy<SV>>
where
    SV: ProxyHttp, { ... }
/// The concrete type that holds the user defined HTTP proxy.
///
/// Users don't need to interact with this object directly.
pub struct HttpProxy<SV> { ... }
/// The established HTTP session
///
/// This object is what users interact with in order to access the request itself or change the proxy
/// behavior.
pub struct Session { ... }
impl Session {
    /// Create a new [Session] from the given [Stream]
    ///
    /// This function is mostly used for testing and mocking.
    pub fn new_h1(stream: Stream) -> Self { ... }
    /// Create a new [Session] from the given [Stream] with modules
    ///
    /// This function is mostly used for testing and mocking.
    pub fn new_h1_with_modules(stream: Stream, downstream_modules: &HttpModules) -> Self { ... }
    pub fn as_downstream_mut(&mut self) -> &mut HttpSession { ... }
    pub fn as_downstream(&self) -> &HttpSession { ... }
    /// Write HTTP response with the given error code to the downstream.
    pub async fn respond_error(&mut self, error: u16) -> Result<()> { ... }
    /// Write HTTP response with the given error code to the downstream with a body.
    pub async fn respond_error_with_body(&mut self, error: u16, body: Bytes) -> Result<()> { ... }
    /// Write the given HTTP response header to the downstream
    ///
    /// Different from directly calling [HttpSession::write_response_header], this function also
    /// invokes the filter modules.
    pub async fn write_response_header(
            &mut self,
            mut resp: Box<ResponseHeader>,
            end_of_stream: bool,
        ) -> Result<()> { ... }
    /// Write the given HTTP response body chunk to the downstream
    ///
    /// Different from directly calling [HttpSession::write_response_body], this function also
    /// invokes the filter modules.
    pub async fn write_response_body(
            &mut self,
            mut body: Option<Bytes>,
            end_of_stream: bool,
        ) -> Result<()> { ... }
    pub async fn write_response_tasks(&mut self, mut tasks: Vec<HttpTask>) -> Result<bool> { ... }
}
impl AsRef<HttpSession> for Session {
    fn as_ref(&self) -> &HttpSession { ... }
}
impl AsMut<HttpSession> for Session {
    fn as_mut(&mut self) -> &mut HttpSession { ... }
}
impl Deref for Session {
    fn deref(&self) -> &Self::Target { ... }
}
impl DerefMut for Session {
    fn deref_mut(&mut self) -> &mut Self::Target { ... }
}
#[async_trait]
impl<SV> Subrequest for HttpProxy<SV>
where
    SV: ProxyHttp + Send + Sync + 'static,
    <SV as ProxyHttp>::CTX: Send + Sync, {
    async fn process_subrequest(
            self: &Arc<Self>,
            session: Box<HttpSession>,
            sub_req_ctx: Box<SubReqCtx>,
        ) { ... }
}
#[async_trait]
impl<SV> HttpServerApp for HttpProxy<SV>
where
    SV: ProxyHttp + Send + Sync + 'static,
    <SV as ProxyHttp>::CTX: Send + Sync, {
    async fn process_new_http(
            self: &Arc<Self>,
            session: HttpSession,
            shutdown: &ShutdownWatch,
        ) -> Option<Stream> { ... }
    async fn http_cleanup(&self) { ... }
    fn server_options(&self) -> Option<&HttpServerOptions> { ... }
}
```
## pingora-proxy/src/proxy_cache.rs
```rust
use super::*;
use http::{Method, StatusCode};
use pingora_cache::key::CacheHashKey;
use pingora_cache::lock::LockStatus;
use pingora_cache::max_file_size::ERR_RESPONSE_TOO_LARGE;
use pingora_cache::{ForcedInvalidationKind, HitStatus, RespCacheable::*};
use pingora_core::protocols::http::conditional_filter::to_304;
use pingora_core::protocols::http::v1::common::header_value_content_length;
use pingora_core::ErrorType;
use range_filter::RangeBodyFilter;
use std::time::SystemTime;
pub mod range_filter {
    use super::*;
    use http::header::*;
    use std::ops::Range;
    pub fn range_header_filter(req: &RequestHeader, resp: &mut ResponseHeader) -> RangeType { ... }
    #[derive(Debug, Eq, PartialEq, Clone)]
    pub enum RangeType {
            None,
            Single(Range<usize>),
            // TODO: multi-range
            Invalid,
        }
    pub struct RangeBodyFilter { ... }
    impl RangeBodyFilter {
        pub fn new() -> Self { ... }
        pub fn set(&mut self, range: RangeType) { ... }
        pub fn filter_body(&mut self, data: Option<Bytes>) -> Option<Bytes> { ... }
    }
}
impl ServeFromCache {
    pub fn new() -> Self { ... }
    pub fn is_on(&self) -> bool { ... }
    pub fn is_miss(&self) -> bool { ... }
    pub fn is_miss_header(&self) -> bool { ... }
    pub fn is_miss_body(&self) -> bool { ... }
    pub fn should_discard_upstream(&self) -> bool { ... }
    pub fn should_send_to_downstream(&self) -> bool { ... }
    pub fn enable(&mut self) { ... }
    pub fn enable_miss(&mut self) { ... }
    pub fn enable_header_only(&mut self) { ... }
    pub async fn next_http_task(
            &mut self,
            cache: &mut HttpCache,
            range: &mut RangeBodyFilter,
        ) -> Result<HttpTask> { ... }
}
```
## pingora-proxy/src/proxy_common.rs
```rust
/// Possible downstream states during request multiplexing
#[allow(clippy::wrong_self_convention)]
impl DownstreamStateMachine {
    pub fn new(finished: bool) -> Self { ... }
    pub fn can_poll(&self) -> bool { ... }
    pub fn is_reading(&self) -> bool { ... }
    pub fn is_done(&self) -> bool { ... }
    pub fn is_errored(&self) -> bool { ... }
    /// Move the state machine to Finished state if `set` is true
    pub fn maybe_finished(&mut self, set: bool) { ... }
    pub fn to_errored(&mut self) { ... }
}
impl ResponseStateMachine {
    pub fn new() -> Self { ... }
    pub fn is_done(&self) -> bool { ... }
    pub fn upstream_done(&self) -> bool { ... }
    pub fn cached_done(&self) -> bool { ... }
    pub fn enable_cached_response(&mut self) { ... }
    pub fn maybe_set_upstream_done(&mut self, done: bool) { ... }
    pub fn maybe_set_cache_done(&mut self, done: bool) { ... }
}
```
## pingora-proxy/src/proxy_h1.rs
```rust
use super::*;
use crate::proxy_cache::{range_filter::RangeBodyFilter, ServeFromCache};
use crate::proxy_common::*;
```
## pingora-proxy/src/proxy_h2.rs
```rust
use super::*;
use crate::proxy_cache::{range_filter::RangeBodyFilter, ServeFromCache};
use crate::proxy_common::*;
use http::{header::CONTENT_LENGTH, Method, StatusCode};
use pingora_core::protocols::http::v2::{client::Http2Session, write_body};
```
## pingora-proxy/src/proxy_purge.rs
```rust
use super::*;
use pingora_core::protocols::http::error_resp;
use std::borrow::Cow;
#[derive(Debug)]
pub enum PurgeStatus {
    /// Cache was not enabled, purge ineffectual.
    NoCache,
    /// Asset was found in cache (and presumably purged or being purged).
    Found,
    /// Asset was not found in cache.
    NotFound,
    /// Cache returned a purge error.
    /// Contains causing error in case it should affect the downstream response.
    Error(Box<Error>),
}
```
## pingora-proxy/src/proxy_trait.rs
```rust
use super::*;
use pingora_cache::{
    key::HashBinary,
    CacheKey, CacheMeta, ForcedInvalidationKind,
    RespCacheable::{self, *},
};
use proxy_cache::range_filter::{self};
use std::time::Duration;
/// Context struct returned by `fail_to_proxy`.
pub struct FailToProxy { ... }
/// The interface to control the HTTP proxy
///
/// The methods in [ProxyHttp] are filters/callbacks which will be performed on all requests at their
/// particular stage (if applicable).
///
/// If any of the filters returns [Result::Err], the request will fail, and the error will be logged.
#[cfg_attr(not(doc_async_trait), async_trait)]
pub trait ProxyHttp { ... }
```
## pingora-proxy/src/subrequest.rs
```rust
use async_trait::async_trait;
use core::pin::Pin;
use core::task::{Context, Poll};
use pingora_cache::lock::{CacheKeyLockImpl, LockStatus, WritePermit};
use pingora_cache::CacheKey;
use pingora_core::protocols::raw_connect::ProxyDigest;
use pingora_core::protocols::{
    GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, SocketDigest, Ssl, TimingDigest,
    UniqueID, UniqueIDType,
};
use std::io::Cursor;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, Error, ReadBuf};
use crate::HttpSession;
/// Ctx to share state across the parent req and the sub req
pub struct Ctx { ... }
impl DummyIO {
    pub fn new(read_bytes: &[u8]) -> Self { ... }
}
impl AsyncRead for DummyIO {
    fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<Result<(), Error>> { ... }
}
impl AsyncWrite for DummyIO {
    fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, Error>> { ... }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> { ... }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> { ... }
}
impl UniqueID for DummyIO {
    fn id(&self) -> UniqueIDType { ... }
}
impl Ssl for DummyIO {
}
impl GetTimingDigest for DummyIO {
    fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> { ... }
}
impl GetProxyDigest for DummyIO {
    fn get_proxy_digest(&self) -> Option<Arc<ProxyDigest>> { ... }
}
impl GetSocketDigest for DummyIO {
    fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> { ... }
}
impl Peek for DummyIO {
}
#[async_trait]
impl pingora_core::protocols::Shutdown for DummyIO {
    async fn shutdown(&mut self) -> () { ... }
}
impl Ctx {
    pub fn with_write_lock(
            cache_lock: &'static CacheKeyLockImpl,
            key: CacheKey,
            write_permit: WritePermit,
        ) -> Ctx { ... }
    pub fn release_write_lock(&mut self) { ... }
    pub fn take_write_lock(&mut self) -> Option<WritePermit> { ... }
}
```
## pingora-proxy/tests/test_basic.rs
```rust
use bytes::Bytes;
use h2::client;
use http::Request;
use hyper::{body::HttpBody, header::HeaderValue, Body, Client};
use hyperlocal::{UnixClientExt, Uri};
use reqwest::{header, StatusCode};
use tokio::net::TcpStream;
use utils::server_utils::init;
```
## pingora-proxy/tests/test_upstream.rs
```rust
use utils::server_utils::init;
use utils::websocket::WS_ECHO;
use futures::{SinkExt, StreamExt};
use reqwest::header::{HeaderName, HeaderValue};
use reqwest::StatusCode;
use std::time::Duration;
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};
```
## pingora-proxy/tests/utils/cert.rs
```rust
use once_cell::sync::Lazy;
use pingora_core::tls::{load_pem_file_ca, load_pem_file_private_key};
use pingora_core::tls::{
    pkey::{PKey, Private},
    x509::X509,
};
use std::fs;
use key_types::*;
```
## pingora-proxy/tests/utils/mock_origin.rs
```rust
use once_cell::sync::Lazy;
use std::path::Path;
use std::process;
use std::{thread, time};
```
## pingora-proxy/tests/utils/mod.rs
```rust
use once_cell::sync::Lazy;
use tokio::runtime::{Builder, Runtime};
#[cfg(feature = "any_tls")]
pub mod cert {
}
pub mod mock_origin {
}
pub mod server_utils {
}
pub mod websocket {
}
pub fn conf_dir() -> String { ... }
```
## pingora-proxy/tests/utils/server_utils.rs
```rust
use super::cert;
use async_trait::async_trait;
use clap::Parser;
use http::header::VARY;
use http::HeaderValue;
use once_cell::sync::Lazy;
use pingora_cache::cache_control::CacheControl;
use pingora_cache::key::HashBinary;
use pingora_cache::lock::CacheKeyLockImpl;
use pingora_cache::{
    eviction::simple_lru::Manager, filters::resp_cacheable, lock::CacheLock, predictor::Predictor,
    set_compression_dict_path, CacheMeta, CacheMetaDefaults, CachePhase, MemCache, NoCacheReason,
    RespCacheable,
};
use pingora_cache::{ForcedInvalidationKind, PurgeType, VarianceBuilder};
use pingora_core::apps::{HttpServerApp, HttpServerOptions};
use pingora_core::modules::http::compression::ResponseCompression;
use pingora_core::protocols::{l4::socket::SocketAddr, Digest};
use pingora_core::server::configuration::Opt;
use pingora_core::services::Service;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::utils::tls::CertKey;
use pingora_error::{Error, ErrorSource, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use super::mock_origin::MOCK_ORIGIN;
pub fn init() { ... }
pub struct ExampleProxyHttps { ... }
#[allow(clippy::upper_case_acronyms)]
#[derive(Default)]
pub struct CTX { ... }
pub struct ExampleProxyHttp { ... }
pub struct CacheCTX { ... }
pub struct ExampleProxyCache { ... }
pub struct Server { ... }
#[async_trait]
#[cfg(feature = "any_tls")]
impl ProxyHttp for ExampleProxyHttps {
    fn new_ctx(&self) -> Self::CTX { ... }
    async fn upstream_peer(
            &self,
            session: &mut Session,
            _ctx: &mut Self::CTX,
        ) -> Result<Box<HttpPeer>> { ... }
    async fn response_filter(
            &self,
            session: &mut Session,
            upstream_response: &mut ResponseHeader,
            ctx: &mut Self::CTX,
        ) -> Result<()>
        where
            Self::CTX: Send + Sync, { ... }
    async fn upstream_request_filter(
            &self,
            session: &mut Session,
            req: &mut RequestHeader,
            _ctx: &mut Self::CTX,
        ) -> Result<()> { ... }
    async fn connected_to_upstream(
            &self,
            _http_session: &mut Session,
            reused: bool,
            _peer: &HttpPeer,
            #[cfg(unix)] _fd: std::os::unix::io::RawFd,
            #[cfg(windows)] _sock: std::os::windows::io::RawSocket,
            digest: Option<&Digest>,
            ctx: &mut CTX,
        ) -> Result<()> { ... }
}
#[async_trait]
impl ProxyHttp for ExampleProxyHttp {
    fn new_ctx(&self) -> Self::CTX { ... }
    async fn early_request_filter(
            &self,
            session: &mut Session,
            _ctx: &mut Self::CTX,
        ) -> Result<()> { ... }
    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> { ... }
    async fn response_filter(
            &self,
            session: &mut Session,
            upstream_response: &mut ResponseHeader,
            ctx: &mut Self::CTX,
        ) -> Result<()> { ... }
    async fn upstream_peer(
            &self,
            session: &mut Session,
            _ctx: &mut Self::CTX,
        ) -> Result<Box<HttpPeer>> { ... }
    async fn connected_to_upstream(
            &self,
            _http_session: &mut Session,
            reused: bool,
            _peer: &HttpPeer,
            #[cfg(unix)] _fd: std::os::unix::io::RawFd,
            #[cfg(windows)] _sock: std::os::windows::io::RawSocket,
            digest: Option<&Digest>,
            ctx: &mut CTX,
        ) -> Result<()> { ... }
}
#[async_trait]
impl ProxyHttp for ExampleProxyCache {
    fn new_ctx(&self) -> Self::CTX { ... }
    async fn upstream_peer(
            &self,
            session: &mut Session,
            _ctx: &mut Self::CTX,
        ) -> Result<Box<HttpPeer>> { ... }
    fn request_cache_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<()> { ... }
    async fn cache_hit_filter(
            &self,
            session: &Session,
            _meta: &CacheMeta,
            is_fresh: bool,
            _ctx: &mut Self::CTX,
        ) -> Result<Option<ForcedInvalidationKind>> { ... }
    fn cache_vary_filter(
            &self,
            meta: &CacheMeta,
            _ctx: &mut Self::CTX,
            req: &RequestHeader,
        ) -> Option<HashBinary> { ... }
    fn response_cache_filter(
            &self,
            _session: &Session,
            resp: &ResponseHeader,
            _ctx: &mut Self::CTX,
        ) -> Result<RespCacheable> { ... }
    fn upstream_response_filter(
            &self,
            _session: &mut Session,
            upstream_response: &mut ResponseHeader,
            ctx: &mut Self::CTX,
        ) where
            Self::CTX: Send + Sync, { ... }
    async fn response_filter(
            &self,
            session: &mut Session,
            upstream_response: &mut ResponseHeader,
            ctx: &mut Self::CTX,
        ) -> Result<()>
        where
            Self::CTX: Send + Sync, { ... }
    fn should_serve_stale(
            &self,
            _session: &mut Session,
            _ctx: &mut Self::CTX,
            error: Option<&Error>, // None when it is called during stale while revalidate
        ) -> bool { ... }
    fn is_purge(&self, session: &Session, _ctx: &Self::CTX) -> bool { ... }
}
impl Server {
    pub fn start() -> Self { ... }
}
```
## pingora-proxy/tests/utils/websocket.rs
```rust
use std::{io::Error, thread, time::Duration};
use futures_util::{SinkExt, StreamExt};
use log::debug;
use once_cell::sync::Lazy;
use tokio::{
    net::{TcpListener, TcpStream},
    runtime::Builder,
};
```
## pingora-runtime/benches/hello.rs
```rust
use pingora_runtime::{current_handle, Runtime};
use std::error::Error;
use std::{thread, time};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
```
## pingora-runtime/src/lib.rs
```rust
use once_cell::sync::{Lazy, OnceCell};
use rand::Rng;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;
use thread_local::ThreadLocal;
use tokio::runtime::{Builder, Handle};
use tokio::sync::oneshot::{channel, Sender};
/// Return the [Handle] of current runtime.
/// If the current thread is under a `Steal` runtime, the current [Handle] is returned.
/// If the current thread is under a `NoSteal` runtime, the [Handle] of a random thread
/// under this runtime is returned. This function will panic if called outside any runtime.
pub fn current_handle() -> Handle { ... }
/// Pingora async multi-threaded runtime
///
/// The `Steal` flavor is effectively tokio multi-threaded runtime.
///
/// The `NoSteal` flavor is backed by multiple tokio single-threaded runtime.
pub enum Runtime {
    Steal(tokio::runtime::Runtime),
    NoSteal(NoStealRuntime),
}
/// Multi-threaded runtime backed by a pool of single threaded tokio runtime
pub struct NoStealRuntime { ... }
impl Runtime {
    /// Create a `Steal` flavor runtime. This just a regular tokio runtime
    pub fn new_steal(threads: usize, name: &str) -> Self { ... }
    /// Create a `NoSteal` flavor runtime. This is backed by multiple tokio current-thread runtime
    pub fn new_no_steal(threads: usize, name: &str) -> Self { ... }
    /// Return the &[Handle] of the [Runtime].
    /// For `Steal` flavor, it will just return the &[Handle].
    /// For `NoSteal` flavor, it will return the &[Handle] of a random thread in its pool.
    /// So if we want tasks to spawn on all the threads, call this function to get a fresh [Handle]
    /// for each async task.
    pub fn get_handle(&self) -> &Handle { ... }
    /// Call tokio's `shutdown_timeout` of all the runtimes. This function is blocking until
    /// all runtimes exit.
    pub fn shutdown_timeout(self, timeout: Duration) { ... }
}
impl NoStealRuntime {
    /// Create a new [NoStealRuntime]. Panic if `threads` is 0
    pub fn new(threads: usize, name: &str) -> Self { ... }
    /// Return the &[Handle] of a random thread of this runtime
    pub fn get_runtime(&self) -> &Handle { ... }
    /// Return the number of threads of this runtime
    pub fn threads(&self) -> usize { ... }
    /// Return the &[Handle] of a given thread of this runtime
    pub fn get_runtime_at(&self, index: usize) -> &Handle { ... }
    /// Call tokio's `shutdown_timeout` of all the runtimes. This function is blocking until
    /// all runtimes exit.
    pub fn shutdown_timeout(mut self, timeout: Duration) { ... }
}
```
## pingora-rustls/src/lib.rs
```rust
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use log::warn;
pub use no_debug::{Ellipses, NoDebug, WithTypeInfo};
use pingora_error::{Error, ErrorType, OrErr, Result};
pub use rustls::{version, ClientConfig, RootCertStore, ServerConfig, Stream};
pub use rustls_native_certs::load_native_certs;
use rustls_pemfile::Item;
pub use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
pub use tokio_rustls::client::TlsStream as ClientTlsStream;
pub use tokio_rustls::server::TlsStream as ServerTlsStream;
pub use tokio_rustls::{Accept, Connect, TlsAcceptor, TlsConnector, TlsStream};
/// Load the certificates from the given pem file path into the given
/// certificate store
pub fn load_ca_file_into_store<P>(path: P, cert_store: &mut RootCertStore) -> Result<()>
where
    P: AsRef<Path>, { ... }
/// Attempt to load the native cas into the given root-certificate store
pub fn load_platform_certs_incl_env_into_store(ca_certs: &mut RootCertStore) -> Result<()> { ... }
/// Load the certificates and private key files
pub fn load_certs_and_key_files<'a>(
    cert: &str,
    key: &str,
) -> Result<Option<(Vec<CertificateDer<'a>>, PrivateKeyDer<'a>)>> { ... }
/// Load the certificate
pub fn load_pem_file_ca(path: &String) -> Result<Vec<u8>> { ... }
pub fn load_pem_file_private_key(path: &String) -> Result<Vec<u8>> { ... }
pub fn hash_certificate(cert: &CertificateDer) -> Vec<u8> { ... }
```
## pingora-timeout/benches/benchmark.rs
```rust
use pingora_timeout::*;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tokio::time::timeout as tokio_timeout;
use std::sync::Arc;
use pingora_timeout::timer::TimerManager;
```
## pingora-timeout/src/fast_timeout.rs
```rust
use super::timer::*;
use super::*;
use once_cell::sync::Lazy;
use std::sync::Arc;
/// Similar to [tokio::time::timeout] but more efficient.
pub fn fast_timeout<T>(duration: Duration, future: T) -> Timeout<T, FastTimeout>
where
    T: Future, { ... }
/// Similar to [tokio::time::sleep] but more efficient.
pub async fn fast_sleep(duration: Duration) { ... }
/// Pause the timer for fork()
///
/// Because RwLock across fork() is undefined behavior, this function makes sure that no one
/// holds any locks.
///
/// This function should be called right before fork().
pub fn pause_for_fork() { ... }
/// Unpause the timer after fork()
///
/// This function should be called right after fork().
pub fn unpause() { ... }
/// The timeout generated by [fast_timeout()].
///
/// Users don't need to interact with this object.
pub struct FastTimeout(Duration); { ... }
impl ToTimeout for FastTimeout {
    fn timeout(&self) -> Pin<Box<dyn Future<Output = ()> + Send + Sync>> { ... }
    fn create(d: Duration) -> Self { ... }
}
```
## pingora-timeout/src/lib.rs
```rust
pub use fast_timeout::fast_sleep as sleep;
pub use fast_timeout::fast_timeout as timeout;
use pin_project_lite::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::task::{self, Poll};
use tokio::time::{sleep as tokio_sleep, Duration};
pub mod fast_timeout {
}
pub mod timer {
}
/// The [tokio::time::timeout] with just lazy timer initialization.
///
/// The timer is created the first time the `future` is pending. This avoids unnecessary timer
/// creation and cancellation on busy IOs with a good chance to be already ready (e.g., reading
/// data from TCP where the recv buffer already has a lot of data to read right away).
pub fn tokio_timeout<T>(duration: Duration, future: T) -> Timeout<T, TokioTimeout>
where
    T: Future, { ... }
/// The timeout generated by [tokio_timeout()].
///
/// Users don't need to interact with this object.
pub struct TokioTimeout(Duration); { ... }
/// The error type returned when the timeout is reached.
#[derive(Debug)]
pub struct Elapsed; { ... }
/// The interface to start a timeout
///
/// Users don't need to interact with this trait
pub trait ToTimeout { ... }
impl ToTimeout for TokioTimeout {
    fn timeout(&self) -> Pin<Box<dyn Future<Output = ()> + Send + Sync>> { ... }
    fn create(d: Duration) -> Self { ... }
}
impl std::fmt::Display for Elapsed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { ... }
}
impl std::error::Error for Elapsed {
}
impl<T, F> Future for Timeout<T, F>
where
    T: Future,
    F: ToTimeout, {
    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> { ... }
}
```
## pingora-timeout/src/timer.rs
```rust
use parking_lot::RwLock;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thread_local::ThreadLocal;
use tokio::sync::Notify;
/// the stub for waiting for a timer to be expired.
pub struct TimerStub(Arc<Notify>, Arc<AtomicBool>); { ... }
/// The object that holds all the timers registered to it.
pub struct TimerManager { ... }
impl From<u128> for Time {
    fn from(raw_ms: u128) -> Self { ... }
}
impl From<Duration> for Time {
    fn from(d: Duration) -> Self { ... }
}
impl Time {
    pub fn not_after(&self, ts: u128) -> bool { ... }
}
impl TimerStub {
    /// Wait for the timer to expire.
    pub async fn poll(self) { ... }
}
impl Timer {
    pub fn new() -> Self { ... }
    pub fn fire(&self) { ... }
    pub fn subscribe(&self) -> TimerStub { ... }
}
impl Default for TimerManager {
    fn default() -> Self { ... }
}
impl TimerManager {
    /// Create a new [TimerManager]
    pub fn new() -> Self { ... }
    /// Register a timer.
    ///
    /// When the timer expires, the [TimerStub] will be notified.
    pub fn register_timer(&self, duration: Duration) -> TimerStub { ... }
    /// Pause the timer for fork()
    ///
    /// Because RwLock across fork() is undefined behavior, this function makes sure that no one
    /// holds any locks.
    ///
    /// This function should be called right before fork().
    pub fn pause_for_fork(&self) { ... }
    /// Unpause the timer after fork()
    ///
    /// This function should be called right after fork().
    pub fn unpause(&self) { ... }
}
```
## tinyufo/benches/bench_hit_ratio.rs
```rust
use rand::prelude::*;
use std::num::NonZeroUsize;
```
## tinyufo/benches/bench_memory.rs
```rust
use rand::prelude::*;
use std::num::NonZeroUsize;
```
## tinyufo/benches/bench_perf.rs
```rust
use rand::prelude::*;
use std::num::NonZeroUsize;
use std::sync::{Barrier, Mutex};
use std::thread;
use std::time::Instant;
```
## tinyufo/src/buckets.rs
```rust
use super::{Bucket, Key};
use ahash::RandomState;
use crossbeam_skiplist::{map::Entry, SkipMap};
use flurry::HashMap;
/// N-shard skip list. Memory efficient, constant time lookup on average, but a bit slower
/// than hash map
pub struct Compact<T>(Box<[SkipMap<Key, Bucket<T>>]>); { ... }
pub struct Fast<T>(HashMap<Key, Bucket<T>, RandomState>); { ... }
pub enum Buckets<T> {
    Fast(Box<Fast<T>>),
    Compact(Compact<T>),
}
impl<T: Send + 'static> Compact<T> {
    /// Create a new [Compact]
    pub fn new(total_items: usize, items_per_shard: usize) -> Self { ... }
    pub fn get(&self, key: &Key) -> Option<Entry<Key, Bucket<T>>> { ... }
    pub fn get_map<V, F: FnOnce(Entry<Key, Bucket<T>>) -> V>(&self, key: &Key, f: F) -> Option<V> { ... }
}
impl<T: Send + Sync> Fast<T> {
    pub fn new(total_items: usize) -> Self { ... }
    pub fn get_map<V, F: FnOnce(&Bucket<T>) -> V>(&self, key: &Key, f: F) -> Option<V> { ... }
}
impl<T: Send + Sync + 'static> Buckets<T> {
    pub fn new_fast(items: usize) -> Self { ... }
    pub fn new_compact(items: usize, items_per_shard: usize) -> Self { ... }
    pub fn insert(&self, key: Key, value: Bucket<T>) -> Option<()> { ... }
    pub fn remove(&self, key: &Key) { ... }
    pub fn get_map<V, F: FnOnce(&Bucket<T>) -> V>(&self, key: &Key, f: F) -> Option<V> { ... }
}
```
## tinyufo/src/estimation.rs
```rust
use ahash::RandomState;
use std::hash::Hash;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
impl Estimator {
    /// Create a new `Estimator` with the given amount of hashes and columns (slots) using
    /// the given random source.
    pub fn new(hashes: usize, slots: usize, random: impl Fn() -> RandomState) -> Self { ... }
    pub fn incr<T: Hash>(&self, key: T) -> u8 { ... }
    /// Get the estimated frequency of `key`.
    pub fn get<T: Hash>(&self, key: T) -> u8 { ... }
    /// right shift all values inside this `Estimator`.
    pub fn age(&self, shift: u8) { ... }
}
impl TinyLfu {
    pub fn get<T: Hash>(&self, key: T) -> u8 { ... }
    pub fn incr<T: Hash>(&self, key: T) -> u8 { ... }
    pub fn new(cache_size: usize) -> Self { ... }
    pub fn new_compact(cache_size: usize) -> Self { ... }
}
```
## tinyufo/src/lib.rs
```rust
use ahash::RandomState;
use crossbeam_queue::SegQueue;
use std::marker::PhantomData;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{
    AtomicBool, AtomicU8,
    Ordering::{Acquire, Relaxed, SeqCst},
};
use buckets::Buckets;
use estimation::TinyLfu;
use std::hash::Hash;
/// The key-value pair returned from cache eviction
#[derive(Clone)]
pub struct KV<T> { ... }
pub struct Bucket<T> { ... }
/// [TinyUfo] cache
pub struct TinyUfo<K, T> { ... }
impl Uses {
    pub fn inc_uses(&self) -> u8 { ... }
    pub fn decr_uses(&self) -> u8 { ... }
    pub fn uses(&self) -> u8 { ... }
}
impl<K: Hash, T: Clone + Send + Sync + 'static> TinyUfo<K, T> {
    /// Create a new TinyUfo cache with the given weight limit and the given
    /// size limit of the ghost queue.
    pub fn new(total_weight_limit: usize, estimated_size: usize) -> Self { ... }
    /// Create a new TinyUfo cache but with more memory efficient data structures.
    /// The trade-off is that the the get() is slower by a constant factor.
    /// The cache hit ratio could be higher as this type of TinyUFO allows to store
    /// more assets with the same memory.
    pub fn new_compact(total_weight_limit: usize, estimated_size: usize) -> Self { ... }
    /// Read the given key
    ///
    /// Return Some(T) if the key exists
    pub fn get(&self, key: &K) -> Option<T> { ... }
    /// Put the key value to the [TinyUfo]
    ///
    /// Return a list of [KV] of key and `T` that are evicted
    pub fn put(&self, key: K, data: T, weight: Weight) -> Vec<KV<T>> { ... }
    /// Remove the given key from the cache if it exists
    ///
    /// Returns Some(T) if the key was found and removed, None otherwise
    pub fn remove(&self, key: &K) -> Option<T> { ... }
    /// Always put the key value to the [TinyUfo]
    ///
    /// Return a list of [KV] of key and `T` that are evicted
    ///
    /// Similar to [Self::put] but guarantee the assertion of the asset.
    /// In [Self::put], the TinyLFU check may reject putting the current asset if it is less
    /// popular than the once being evicted.
    ///
    /// In some real world use cases, a few reads to the same asset may be pending for the put action
    /// to be finished so that they can read the asset from cache. Neither the above behaviors are ideal
    /// for this use case.
    ///
    /// Compared to [Self::put], the hit ratio when using this function is reduced by about 0.5pp or less in
    /// under zipf workloads.
    pub fn force_put(&self, key: K, data: T, weight: Weight) -> Vec<KV<T>> { ... }
}
```
