use std::sync::{Arc, RwLock};

use crate::config::Config;

/// A thread-safe shared configuration that can be updated at runtime
#[derive(Clone)]
pub struct SharedConfig {
    inner: Arc<RwLock<Config>>,
}

impl SharedConfig {
    /// Create a new SharedConfig
    pub fn new(config: Config) -> Self {
        Self {
            inner: Arc::new(RwLock::new(config)),
        }
    }

    /// Get a read-only reference to the configuration
    pub fn read(&self) -> std::sync::RwLockReadGuard<'_, Config> {
        self.inner.read().unwrap()
    }

    /// Update the configuration
    pub fn update(&self, new_config: Config) {
        let mut config = self.inner.write().unwrap();
        *config = new_config;
    }
}