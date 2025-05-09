use super::{ProxyContext, RouteTable, SimpleProxy};
use crate::{
    PluginManager,
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
use tracing::{error, info, warn};

impl SimpleProxy {
    pub fn try_new(config: ProxyConfigResolved) -> anyhow::Result<Self> {
        let route_table = RouteTable::try_new(&config)?;
        let plugin_manager = PluginManager::new();

        // Load plugins from configuration
        if let Some(plugin_configs) = &config.plugins {
            for plugin_config in plugin_configs {
                if plugin_config.enabled {
                    // Clone the config for the manager
                    if let Err(e) = plugin_manager.load_plugin(plugin_config.clone()) {
                        // Log error but continue loading other plugins?
                        // Or fail hard?
                        // Let's log and continue for now.
                        warn!("Failed to load plugin '{}': {}", plugin_config.name, e);
                    } else {
                        info!("Successfully loaded plugin: {}", plugin_config.name);
                    }
                }
            }
        }

        Ok(Self {
            config: ProxyConfig::new(config),
            route_table,
            plugin_manager, // Use the manager with loaded plugins
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
            plugin_manager: self.plugin_manager.clone(),
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
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        info!(
            "upstream_request_filter: original headers = {:?}",
            upstream_request.headers
        );

        // >>> Execute Request Plugins <<<
        match ctx
            .plugin_manager
            .execute_request_plugins(upstream_request)
            .await
        {
            Ok(_) => {
                info!(
                    "Request plugins executed successfully. Modified headers: {:?}",
                    upstream_request.headers
                );
            }
            Err(e) => {
                error!("Error executing request plugins: {}", e);
            }
        }
        // >>> End Plugin Execution <<<

        // Original logic (can be modified/removed by plugins now)
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
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        info!(
            "response_filter: original headers = {:?}",
            upstream_response.headers
        );

        // >>> Execute Response Plugins <<<
        match ctx
            .plugin_manager
            .execute_response_plugins(upstream_response)
        {
            Ok(_) => {
                info!(
                    "Response plugins executed successfully. Modified headers: {:?}",
                    upstream_response.headers
                );
            }
            Err(e) => {
                error!("Error executing response plugins: {}", e);
            }
        }
        // >>> End Plugin Execution <<<

        // Original logic can be modified by plugins
        // Example: A plugin might have already set x-simple-proxy
        if !upstream_response.headers.contains_key("x-simple-proxy") {
            if let Err(e) = upstream_response.insert_header("x-simple-proxy", "v0.1") {
                warn!("failed to insert default x-simple-proxy header: {}", e);
            }
        }

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
