/// This module contains all functions related to cookie based sessions
mod auth;

/// This module contains all functions related to the configuration
mod config;

/// This module contains the root context
mod root;

// log
use log::info;

/// This is the root context
use crate::root::Root;

// proxy-wasm
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

// This is the initial entry point of the plugin.
proxy_wasm::main! {{

    proxy_wasm::set_log_level(LogLevel::Debug);

    info!("starting plugin");

    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(Root {
        config: None,
    }) });
}}
