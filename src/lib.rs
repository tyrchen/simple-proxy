pub mod conf;

use async_trait::async_trait;
use conf::{ProxyConfig, ProxyConfigResolved};
use http::StatusCode;
use pingora::{http::ResponseHeader, prelude::*};
use tracing::{info, warn};

pub struct SimpleProxy {
    pub(crate) config: ProxyConfig,
}

pub struct ProxyContext {
    pub(crate) config: ProxyConfig,
}

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

        let peer = HttpPeer::new(upstream.to_string(), false, host.to_string());
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
}
