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
    ///
    /// With `socks5_transit` configured the clients point at the in-process
    /// loopback bridge instead of the remote exit directly (proxybridge.rs):
    /// the bridge chains transit → `socks5` exit per connection. Loopback
    /// never enters a TUN-mode VPN, so the chain works even while the
    /// device's VPN is on.
    pub fn build(config: Config, models: ModelFile) -> Result<Self, String> {
        let config = Arc::new(config);
        let models = Arc::new(models);

        // Egress wiring the clients actually dial: either the configured
        // socks5 as-is, or the loopback bridge when a transit is configured.
        // The bridge demands per-process credentials (it is a live proxy onto
        // the paid exit and loopback is shared with every other process on the
        // machine), so the clients dial the URL it hands back.
        let mut egress_cfg = (*config).clone();
        if config.socks5_transit.is_some() {
            let transit = config.socks5_transit.as_deref().unwrap();
            let exit = config.socks5.as_deref().unwrap();
            let bridge = crate::proxybridge::spawn_bridge(transit, exit)?;
            egress_cfg.socks5 = Some(bridge.proxy_url());
            egress_cfg.socks5_transit = None;
        }

        let express = if config.express_enabled() {
            let http = httpx::build_express_client(&egress_cfg)?;
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
            let client = httpx::build_cookie_client(&egress_cfg)?;
            // Cookie auto-refresh (spec §7.4): the jar persists rolled
            // credentials next to the binary and harvests Set-Cookie
            // rewrites on every response.
            let jar = if config.cookie.auto_refresh {
                let jar = crate::cookiejar::CookieJar::load(&config.cookie.cookie);
                tracing::info!(
                    auto_refresh = true,
                    "cookie auto-refresh enabled (jar persists to cookie.jar.yaml)"
                );
                Some(std::sync::Arc::new(jar))
            } else {
                tracing::info!("cookie auto-refresh disabled: startup string is frozen");
                None
            };
            Some(UpstreamClient::Cookie(CookieClient::new(
                client,
                &config.cookie,
                jar,
            )))
        } else {
            None
        };

        // Remote image fetcher: same proxy posture as the express client
        // (socks5 attached / direct), redirects disabled for per-hop SSRF
        // rechecks, see §9.3.
        let image_client = httpx::build_image_client(&egress_cfg)?;

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

    /// Best-effort SOCKS5 handshake probe of the configured egress chain
    /// (spec §2.2): a failure means EVERY upstream request will die as a
    /// transport error, so say so loudly at boot instead of leaving it to be
    /// inferred from per-request retry logs. With `socks5_transit` set the
    /// probe walks the whole chain (transit → exit) exactly as the bridge
    /// dials it. The probe's error text names the failing handshake stage
    /// (connect / not-a-SOCKS5-server / credentials rejected / dead exit);
    /// the checklist below maps onto those. Never blocks startup (the probe
    /// is advisory — entries may whitelist specific source IPs).
    pub async fn probe_outbound(&self) {
        if let Some(url) = &self.config.socks5 {
            if let Err(detail) =
                httpx::probe_socks5(self.config.socks5_transit.as_deref(), url).await
            {
                tracing::warn!(
                    proxy = %url,
                    transit = self.config.socks5_transit.as_deref().unwrap_or(""),
                    error = %detail,
                    "socks5 egress chain failed the handshake probe; every upstream request \
                     will fail until this is fixed. Checklist: 1) a TUN-mode proxy client \
                     (clash/mihomo) intercepts TCP to the entry — add a direct rule for the \
                     entry IP, point socks5 at a local chaining port (loopback is exempt from \
                     TUN), or set socks5_transit to the VPN client's local port; 2) the \
                     entry's firewall / IP whitelist does not allow this machine's egress IP; \
                     3) the node itself expired (rotating/residential entries do); 4) the \
                     credentials in the socks5 url were rejected"
                );
            }
        }
    }
}
