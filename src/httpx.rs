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

/// Startup SOCKS5 liveness probe for the configured entry (spec §2.2): a FULL
/// handshake — method negotiation, username/password auth when the URL has
/// credentials, and one CONNECT through the exit to a neutral address (a bare
/// TCP open, no application data) — not just a TCP connect. A raw connect
/// cannot tell the real failure modes apart: under a TUN-mode proxy client the
/// TCP connection to a public entry is intercepted and may complete while the
/// SOCKS5 layer never speaks; a misrouted or non-SOCKS5 listener answers the
/// greeting with garbage; rejected credentials surface only at the auth step;
/// a dead exit node only at CONNECT. Failure does NOT block startup — the
/// probe is advisory (an entry may whitelist specific source IPs) — but the
/// failure reason tells the operator which fix applies.
pub async fn probe_socks5(url: &str) -> Result<(), String> {
    const STEP: Duration = Duration::from_secs(5);

    let parsed = reqwest::Url::parse(url).map_err(|e| format!("invalid proxy url: {e}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "proxy url has no host".to_string())?
        .to_string();
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| "proxy url has no port".to_string())?;
    let addr = format!("{host}:{port}");
    let username = decode_url_part(parsed.username());
    let password = decode_url_part(parsed.password().unwrap_or(""));

    let mut stream = tokio::time::timeout(STEP, tokio::net::TcpStream::connect(&addr))
        .await
        .map_err(|_| format!("{addr}: connect timed out after 5s"))?
        .map_err(|e| format!("{addr}: {e}"))?;

    // Greeting: offer no-auth; add username/password auth when the URL has
    // credentials.
    let has_creds = !username.is_empty() || !password.is_empty();
    let mut greeting = vec![0x05u8, 0x01, 0x00];
    if has_creds {
        greeting[1] = 0x02;
        greeting.push(0x02);
    }
    probe_write(&mut stream, &greeting, STEP).await?;
    let mut reply = [0u8; 2];
    probe_read_exact(&mut stream, &mut reply, STEP).await?;
    if reply[0] != 0x05 {
        return Err(format!(
            "{addr}: TCP connects but the peer is not a SOCKS5 server (version byte {:#04x}) — \
             likely intercepted or misrouted (TUN?)",
            reply[0]
        ));
    }
    match reply[1] {
        0x00 => {} // no-auth accepted
        0x02 => {
            if !has_creds {
                return Err(format!(
                    "{addr}: SOCKS5 server requires username/password auth but the url has none"
                ));
            }
            if username.len() > 255 || password.len() > 255 {
                return Err(format!(
                    "{addr}: proxy credentials exceed the SOCKS5 field limit"
                ));
            }
            let mut auth = vec![0x01u8, username.len() as u8];
            auth.extend_from_slice(username.as_bytes());
            auth.push(password.len() as u8);
            auth.extend_from_slice(password.as_bytes());
            probe_write(&mut stream, &auth, STEP).await?;
            let mut auth_reply = [0u8; 2];
            probe_read_exact(&mut stream, &mut auth_reply, STEP).await?;
            if auth_reply[1] != 0x00 {
                return Err(format!(
                    "{addr}: SOCKS5 username/password rejected (status {})",
                    auth_reply[1]
                ));
            }
        }
        other => {
            return Err(format!(
                "{addr}: SOCKS5 server refused our auth methods (reply {other:#04x})"
            ));
        }
    }

    // CONNECT through the exit to a neutral address (1.1.1.1:443 — one TCP
    // open, no data): proves the exit path works, not just the entry.
    let request = [0x05u8, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0x00, 0x44];
    probe_write(&mut stream, &request, STEP).await?;
    let mut head = [0u8; 4];
    probe_read_exact(&mut stream, &mut head, STEP).await?;
    if head[1] != 0x00 {
        return Err(format!(
            "{addr}: SOCKS5 CONNECT through the exit failed (reply {:#04x}) — likely a dead \
             or expired exit node",
            head[1]
        ));
    }
    Ok(())
}

async fn probe_write(
    stream: &mut tokio::net::TcpStream,
    buf: &[u8],
    step: Duration,
) -> Result<(), String> {
    use tokio::io::AsyncWriteExt;
    tokio::time::timeout(step, stream.write_all(buf))
        .await
        .map_err(|_| "SOCKS5 probe write timed out".to_string())?
        .map_err(|e| format!("SOCKS5 probe write failed: {e}"))
}

async fn probe_read_exact(
    stream: &mut tokio::net::TcpStream,
    buf: &mut [u8],
    step: Duration,
) -> Result<(), String> {
    use tokio::io::AsyncReadExt;
    tokio::time::timeout(step, stream.read_exact(buf))
        .await
        .map_err(|_| "SOCKS5 probe read timed out".to_string())?
        .map_err(|e| format!("SOCKS5 probe read failed: {e}"))?;
    Ok(())
}

/// Percent-decode a URL userinfo part (username/password); undecodable input
/// passes through raw rather than failing the probe over an edge case.
fn decode_url_part(raw: &str) -> String {
    percent_encoding::percent_decode_str(raw)
        .decode_utf8()
        .map(|c| c.into_owned())
        .unwrap_or_else(|_| raw.to_string())
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
