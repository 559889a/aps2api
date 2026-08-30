//! Outbound HTTP clients (spec §4 httpx / §1.4 / §6.1).
//!
//! Invariants:
//! - express channel uses plain `reqwest` (official endpoint, no masquerade)
//!   with an explicit preconfigured rustls TLS config (`express_tls`, bundled
//!   Mozilla roots): reqwest 0.13's default rustls-platform-verifier needs a
//!   JNI app context on Android and panics in a bare Termux process;
//!   cookie channel uses `wreq` with the pinned Chrome TLS/HTTP2 emulation.
//! - Both clients attach the SAME configured socks5 proxy (authenticated URLs
//!   with embedded user:pass supported); with no `socks5` field both connect
//!   directly. Environment-variable proxy detection is explicitly disabled so
//!   outbound behavior is decided by config.yaml alone.
//! - Connection timeout 30s; NO total timeout (streaming red line, §5.4).

use std::sync::Arc;
use std::time::Duration;

use crate::config::Config;

/// Force PROXY-SIDE DNS resolution for every configured proxy: `socks5://`
/// is normalized to `socks5h://` semantics (credentials and case preserved).
///
/// Verified on the dev machine (2026-08-30): with a local chaining entry,
/// local resolution fails the connect entirely (the device's own resolver
/// path is involved, which also means DNS queries leak to the local
/// network's resolver), while proxy-side resolution works. Proxy-side
/// resolution is also strictly better for the fixed-exit disguise: the
/// device's DNS never participates in upstream routing (spec §1.4).
pub fn proxied_url(url: &str) -> String {
    // "socks5://" is 9 chars; "socks5h://" is 10.
    if url.len() >= 9 {
        let (scheme, rest) = url.split_at(9);
        if scheme.eq_ignore_ascii_case("socks5://") {
            return format!("socks5h://{rest}");
        }
    }
    url.to_string()
}

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Explicit rustls TLS config for both reqwest clients (express + remote
/// image fetching, spec §6.1 note).
///
/// reqwest 0.13's `rustls` feature installs rustls-platform-verifier whenever
/// no root certificates are supplied; on Android that verifier requires a JNI
/// app context and PANICS in a bare Termux process ("Expect
/// rustls-platform-verifier to be initialized" — 2026-08-30 real-device
/// smoke, invisible to CI). Handing reqwest a preconfigured ClientConfig
/// switches every platform to rustls' own WebPkiServerVerifier over the
/// bundled Mozilla roots: no OS cert store, no JNI, identical verification
/// on Windows / Linux / Termux.
fn express_tls() -> Result<rustls::ClientConfig, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(rustls::ALL_VERSIONS)
        .map_err(|e| format!("rustls protocol versions: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    // Preconfigured configs bypass reqwest's ALPN wiring; mirror its default
    // (h2 + http/1.1) here.
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(tls)
}

/// reqwest client for the express channel.
pub fn build_express_client(cfg: &Config) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        // Never touch HTTP(S)_PROXY env vars: config.yaml is the single
        // source of truth for outbound routing (spec §1.4).
        .no_proxy()
        // Takes the bare ClientConfig: the builder wraps it in its own
        // Option before downcasting (passing Some() breaks the downcast and
        // the build fails with "Unknown TLS backend").
        .tls_backend_preconfigured(express_tls()?);
    if let Some(url) = &cfg.socks5 {
        let resolved = proxied_url(url);
        let p = reqwest::Proxy::all(&resolved)
            .map_err(|e| format!("invalid socks5 url {url:?}: {e}"))?;
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
        let resolved = proxied_url(url);
        let p =
            wreq::Proxy::all(&resolved).map_err(|e| format!("invalid socks5 url {url:?}: {e}"))?;
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
        .no_proxy()
        .tls_backend_preconfigured(express_tls()?);
    if let Some(url) = &cfg.socks5 {
        let resolved = proxied_url(url);
        let p = reqwest::Proxy::all(&resolved)
            .map_err(|e| format!("invalid socks5 url {url:?}: {e}"))?;
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
            bypass: false,
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
    fn socks5_urls_normalize_to_proxy_side_resolution() {
        assert_eq!(
            proxied_url("socks5://127.0.0.1:7890"),
            "socks5h://127.0.0.1:7890"
        );
        // Credentials and their case must survive untouched.
        assert_eq!(
            proxied_url("socks5://User:Pw@10.0.0.1:1080"),
            "socks5h://User:Pw@10.0.0.1:1080"
        );
        // Uppercase scheme accepted; socks5h stays as-is.
        assert_eq!(proxied_url("SOCKS5://h:1"), "socks5h://h:1");
        assert_eq!(proxied_url("socks5h://h:1"), "socks5h://h:1");
    }

    #[test]
    fn direct_clients_build_without_proxy() {
        let mut cfg = cfg_with_socks("socks5://u:p@h:1");
        cfg.socks5 = None;
        assert!(build_express_client(&cfg).is_ok());
    }
}
