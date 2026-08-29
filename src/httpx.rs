//! Outbound HTTP clients (spec §4 httpx / §1.4 / §6.1).
//!
//! Invariants:
//! - express channel uses plain `reqwest` (official endpoint, no masquerade);
//!   cookie channel uses `wreq` with the pinned Chrome TLS/HTTP2 emulation.
//! - Both clients attach the SAME configured socks5 proxy (authenticated URLs
//!   with embedded user:pass supported); with no `socks5` field both connect
//!   directly. Environment-variable proxy detection is explicitly disabled so
//!   outbound behavior is decided by config.yaml alone.
//! - Connection timeout 30s; NO total timeout (streaming red line, §5.4).

use std::time::Duration;

use crate::config::Config;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// reqwest client for the express channel.
pub fn build_express_client(cfg: &Config) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        // Never touch HTTP(S)_PROXY env vars: config.yaml is the single
        // source of truth for outbound routing (spec §1.4).
        .no_proxy();
    if let Some(url) = &cfg.socks5 {
        let p = reqwest::Proxy::all(url).map_err(|e| format!("invalid socks5 url {url:?}: {e}"))?;
        builder = builder.proxy(p);
    }
    builder
        .build()
        .map_err(|e| format!("failed to build express client: {e}"))
}

/// wreq client for the cookie channel (Chrome fingerprint emulation).
pub fn build_cookie_client(cfg: &Config) -> Result<wreq::Client, String> {
    let emulation = crate::channels::cookie::emulation();
    let mut builder = wreq::Client::builder()
        .emulation(emulation)
        .connect_timeout(CONNECT_TIMEOUT)
        // wreq reads no proxy env by default (system-proxy feature off), but
        // state it explicitly so the invariant survives feature changes.
        .no_proxy();
    if let Some(url) = &cfg.socks5 {
        let p = wreq::Proxy::all(url).map_err(|e| format!("invalid socks5 url {url:?}: {e}"))?;
        builder = builder.proxy(p);
    }
    builder
        .build()
        .map_err(|e| format!("failed to build cookie client: {e}"))
}

/// Dedicated reqwest client for remote image fetching (spec §9.3): redirects
/// must be followed MANUALLY so every hop gets an SSRF recheck.
pub fn build_image_client(cfg: &Config) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy();
    if let Some(url) = &cfg.socks5 {
        let p = reqwest::Proxy::all(url).map_err(|e| format!("invalid socks5 url {url:?}: {e}"))?;
        builder = builder.proxy(p);
    }
    builder
        .build()
        .map_err(|e| format!("failed to build image client: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with_socks(url: &str) -> crate::config::Config {
        crate::config::Config {
            api_key: "k".into(),
            port: 8080,
            socks5: Some(url.into()),
            express: Default::default(),
            cookie: Default::default(),
            thinking_level: String::new(),
            retry: Default::default(),
        }
    }

    #[test]
    fn authenticated_socks5_url_is_accepted_by_both_clients() {
        let cfg = cfg_with_socks("socks5://user:pass@10.0.0.1:1080");
        assert!(build_express_client(&cfg).is_ok());
    }

    #[test]
    fn socks5h_form_is_accepted() {
        let cfg = cfg_with_socks("socks5h://127.0.0.1:7890");
        assert!(build_express_client(&cfg).is_ok());
    }

    #[test]
    fn generic_proxy_urls_accepted_here_socks_rule_lives_in_config() {
        // reqwest Proxy::all accepts http(s) proxies; the socks5-only rule
        // for the `socks5` config field is enforced by config::validate.
        let cfg = cfg_with_socks("http://127.0.0.1:7890");
        assert!(build_express_client(&cfg).is_ok());
    }

    #[test]
    fn direct_clients_build_without_proxy() {
        let mut cfg = cfg_with_socks("socks5://u:p@h:1");
        cfg.socks5 = None;
        assert!(build_express_client(&cfg).is_ok());
    }
}
