mod health;
mod route;
mod simple_proxy;
mod waf;
mod rate_limiter;

use std::time::{Duration, Instant};
use std::sync::{Arc};

use crate::conf::ProxyConfig;
use crate::plugins::PluginManager;
use regex::Regex;
use papaya::HashMap;
use pingora::{lb::LoadBalancer, prelude::RoundRobin};

pub struct SimpleProxy {
    pub(crate) config: ProxyConfig,
    pub(crate) route_table: RouteTable,
    pub(crate) plugin_manager: PluginManager,
    pub(crate) waf_checker: WafChecker,
    pub(crate) rate_limiter: RateLimiter,
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

pub struct WafChecker {
    pub rules: Arc<HashMap<String, Vec<Regex>>>,
    pub param_types: Arc<Vec<String>>,
}

// waf 检测的数据项
#[derive(Default)]
pub struct WafMsg {
    pub user_agent: String,
    pub url: String,
    pub args: String,
    pub cookie: String,
    pub post: String,
}

// RateLimiter 限流器
pub struct RateLimiter {
    pub max_requests: usize,
    pub time_window: Duration,
    requests: Arc<HashMap<String, Vec<Instant>>>,
}
