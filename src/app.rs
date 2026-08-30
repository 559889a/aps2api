//! Shared application state: config + model list + outbound clients.

use std::sync::Arc;

use crate::channels::{cookie::CookieClient, express::ExpressClient, UpstreamClient};
use crate::config::{Config, ModelFile};
use crate::httpx;
use crate::pipeline::Ctx;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub models: Arc<ModelFile>,
    pub ctx: Arc<Ctx>,
}

impl AppState {
    /// Build the outbound clients and the pipeline context. Channel clients
    /// exist only when their credentials are configured (spec §2.2).
    pub fn build(config: Config, models: ModelFile) -> Result<Self, String> {
        let config = Arc::new(config);
        let models = Arc::new(models);

        let express = if config.express_enabled() {
            let http = httpx::build_express_client(&config)?;
            Some(UpstreamClient::Express(ExpressClient::new(
                http,
                &config.express,
                &config.express.api_key,
            )))
        } else {
            None
        };

        let cookie = if config.cookie_enabled() {
            // Startup validation (spec §7.1): SAPISID family mandatory.
            crate::sapisid::validate_cookie(&config.cookie.cookie)?;
            let client = httpx::build_cookie_client(&config)?;
            Some(UpstreamClient::Cookie(CookieClient::new(
                client,
                &config.cookie,
            )))
        } else {
            None
        };

        // Remote image fetcher: same proxy posture as the express client
        // (socks5 attached / direct), redirects disabled for per-hop SSRF
        // rechecks, see §9.3.
        let image_client = httpx::build_image_client(&config)?;

        let ctx = Arc::new(Ctx {
            config: config.clone(),
            express,
            cookie,
            image_client,
        });

        Ok(AppState {
            config,
            models,
            ctx,
        })
    }
}
