mod health;
mod route;
mod simple_proxy;

use crate::conf::ProxyConfig;

pub struct SimpleProxy {
    pub(crate) config: ProxyConfig,
}

pub struct ProxyContext {
    pub(crate) config: ProxyConfig,
}
