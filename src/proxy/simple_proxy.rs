use super::{ProxyContext, SimpleProxy};
use crate::conf::{ProxyConfig, ProxyConfigResolved};
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
    pub fn new(config: ProxyConfigResolved) -> Self {
        Self {
            config: ProxyConfig::new(config),
        }
    }

    pub fn config(&self) -> &ProxyConfig {
        &self.config
    }
}

#[async_trait]
impl ProxyHttp for SimpleProxy {
    type CTX = ProxyContext;

    fn new_ctx(&self) -> Self::CTX {
        info!("new_ctx");
        ProxyContext {
            config: self.config.clone(),
        }
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let config = ctx.config.load();
        let Some(host) = session
            .get_header(http::header::HOST)
            .and_then(|h| h.to_str().ok())
            .map(|h| h.split(':').next().unwrap_or(h))
        else {
            return Err(Error::create(
                ErrorType::CustomCode("No valid host found", StatusCode::BAD_REQUEST.into()),
                ErrorSource::Downstream,
                None,
                None,
            ));
        };

        let Some(server) = config.servers.get(host) else {
            return Err(Error::create(
                ErrorType::HTTPStatus(StatusCode::NOT_FOUND.into()),
                ErrorSource::Upstream,
                None,
                None,
            ));
        };

        let Some(upstream) = server.choose() else {
            return Err(Error::create(
                ErrorType::HTTPStatus(StatusCode::NOT_FOUND.into()),
                ErrorSource::Upstream,
                None,
                None,
            ));
        };

        let mut peer = HttpPeer::new(upstream.to_string(), server.tls, host.to_string());
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

    async fn request_filter(&self, _session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        info!("request_filter");
        Ok(false)
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
