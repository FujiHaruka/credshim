use std::sync::{Arc, RwLock};

use credshim_core::BaseUrls;

use crate::audit::Stats;
use crate::intercept::{Intercept, Services};

pub(crate) struct Routing {
    pub(crate) intercept: Option<Intercept>,
    pub(crate) services: Services,
    pub(crate) base_urls: BaseUrls,
}

#[derive(Clone)]
pub(crate) struct Live {
    routing: Arc<RwLock<Arc<Routing>>>,
    stats: Arc<Stats>,
}

impl Live {
    pub(crate) fn new(routing: Routing, stats: Arc<Stats>) -> Self {
        Self {
            routing: Arc::new(RwLock::new(Arc::new(routing))),
            stats,
        }
    }

    pub(crate) fn current(&self) -> Arc<Routing> {
        self.routing
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(crate) fn replace(&self, routing: Routing) {
        *self
            .routing
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Arc::new(routing);
    }

    pub(crate) fn stats(&self) -> &Arc<Stats> {
        &self.stats
    }
}
