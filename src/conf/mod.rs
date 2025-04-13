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
