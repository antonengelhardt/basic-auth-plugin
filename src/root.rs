// proxy_wasm
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

// crate
use crate::auth::BasicAuthContext;
use crate::config::PluginConfiguration;

// std
use std::sync::Arc;

// log
use log::warn;

/// This is the root context
pub struct Root {
    pub config: Option<Arc<PluginConfiguration>>,
}

impl RootContext for Root {
    /// Configure the plugin
    ///
    /// # Arguments
    ///
    /// * `_` - The configuration size
    ///
    /// # Returns
    ///
    /// `true` if the configuration is valid, `false` otherwise
    fn on_configure(&mut self, _: usize) -> bool {
        match self.get_plugin_configuration() {
            None => warn!("No configuration found"),
            Some(config) => match serde_yaml::from_slice(&config) {
                Ok(config) => self.config = Some(Arc::new(config)),
                Err(e) => warn!("Error parsing configuration: {}", e),
            },
        }

        true
    }

    /// Create a new HTTP context
    ///
    /// # Arguments
    ///
    /// * `_` - The context ID
    ///
    /// # Returns
    ///
    /// A new `BasicAuthContext`
    fn create_http_context(&self, _: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(BasicAuthContext {
            config: self.config.clone().unwrap(),
        }))
    }

    /// Get the context type
    ///
    /// # Returns
    ///
    /// `HttpContext`
    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

impl Context for Root {}
