mod health;
mod route;
mod simple_proxy;

use std::sync::Arc;

use crate::conf::ProxyConfig;
use crate::plugins::PluginManager;
use papaya::HashMap;
use pingora::{lb::LoadBalancer, prelude::RoundRobin};

pub struct SimpleProxy {
    pub(crate) config: ProxyConfig,
    pub(crate) route_table: RouteTable,
    pub(crate) plugin_manager: PluginManager,
}

#[allow(dead_code)]
pub struct ProxyContext {
    pub(crate) config: ProxyConfig,
    pub(crate) route_entry: Option<RouteEntry>,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) plugin_manager: PluginManager,
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
