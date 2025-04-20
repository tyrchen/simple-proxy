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
