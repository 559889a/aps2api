//! Remote image fetching with SSRF protection (spec §9.3, port of the
//! reference project's `fetch_remote_image`).
//!
//! - http/https only; redirects followed manually with a per-hop IP recheck
//!   (max 3 hops) — defends against cloud-metadata (169.254.169.254) and
//!   internal-network scans;
//! - content-type must start with `image/`; 20MB cap;
//! - when a socks5 proxy is configured the private-IP check is skipped
//!   (outbound already leaves through the proxy, the client cannot reach
//!   the caller's internal network from there).

use std::net::IpAddr;
use std::time::Duration;

const MAX_REDIRECTS: usize = 3;
const MAX_IMAGE_BYTES: usize = 20 * 1024 * 1024;

fn blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_unspecified()
                || v.is_multicast()
                || v.octets()[0] >= 240 // reserved 240.0.0.0/4 incl. broadcast
        }
        IpAddr::V6(v) => {
            v.is_loopback()
                || v.is_unspecified()
                || v.is_multicast()
                || (v.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 unique local
                || (v.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
        }
    }
}

async fn host_ip_blocked(url: &reqwest::Url) -> Result<bool, String> {
    let Some(host) = url.host_str() else {
        return Err("URL has no host".into());
    };
    if host.starts_with('[') {
        // IPv6 literal.
        let ip = host.trim_matches(['[', ']']);
        let ip: IpAddr = ip.parse().map_err(|_| format!("bad IPv6 literal {ip:?}"))?;
        return Ok(blocked_ip(ip));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(blocked_ip(ip));
    }
    // DNS name: resolve and check every answer.
    let addrs: Vec<IpAddr> = tokio::net::lookup_host((host, 443u16))
        .await
        .map_err(|e| format!("DNS resolution failed for {host:?}: {e}"))?
        .map(|s| s.ip())
        .collect();
    if addrs.is_empty() {
        return Err(format!("no addresses resolved for {host:?}"));
    }
    Ok(addrs.iter().any(|ip| blocked_ip(*ip)))
}

fn deny(msg: &str) -> String {
    format!("remote image rejected: {msg}")
}

/// Fetch one remote image; returns (mime, base64). Errors are reported to
/// the caller which drops the part with a warning (spec §9.3).
/// `proxied` = a socks5 proxy is configured for outbound traffic; in that
/// mode the private-IP check is skipped (spec §9.3).
pub async fn fetch_remote_image(
    client: &reqwest::Client,
    proxied: bool,
    url: &str,
) -> Result<(String, String), String> {
    // reqwest is built with auto-redirect off for this client; follow hops
    // manually to re-check every destination (per-hop SSRF recheck).
    let mut current = reqwest::Url::parse(url).map_err(|e| deny(&format!("bad URL: {e}")))?;

    for _hop in 0..=MAX_REDIRECTS {
        match current.scheme() {
            "http" | "https" => {}
            other => return Err(deny(&format!("scheme {other:?} not allowed"))),
        }
        // With a configured proxy the outbound connection leaves from the
        // proxy host, so the caller's private network is not reachable
        // anyway — skip the private-IP check (spec §9.3).
        if !proxied && host_ip_blocked(&current).await? {
            return Err(deny("host resolves to a private/reserved address"));
        }
        let resp = client
            .get(current.clone())
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| deny(&format!("request failed: {e}")))?;
        let status = resp.status();
        if status.is_redirection() {
            let loc = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| deny("redirect without Location"))?;
            current = current
                .join(loc)
                .map_err(|e| deny(&format!("bad redirect target: {e}")))?;
            continue;
        }
        if !status.is_success() {
            return Err(deny(&format!("HTTP {status}")));
        }
        let mime = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_lowercase();
        if !mime.starts_with("image/") {
            return Err(deny(&format!("content-type {mime:?} is not an image")));
        }
        if let Some(len) = resp.content_length() {
            if len as usize > MAX_IMAGE_BYTES {
                return Err(deny("image exceeds the 20MB limit"));
            }
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| deny(&format!("body read failed: {e}")))?;
        if body.len() > MAX_IMAGE_BYTES {
            return Err(deny("image exceeds the 20MB limit"));
        }
        let b64 = use_base64(&body);
        return Ok((mime, b64));
    }
    Err(deny("too many redirects"))
}

fn use_base64(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_and_reserved_ips_are_blocked() {
        assert!(blocked_ip("127.0.0.1".parse().unwrap()));
        assert!(blocked_ip("10.0.0.5".parse().unwrap()));
        assert!(blocked_ip("192.168.1.1".parse().unwrap()));
        assert!(blocked_ip("172.16.0.1".parse().unwrap()));
        assert!(blocked_ip("169.254.169.254".parse().unwrap()));
        assert!(blocked_ip("0.0.0.0".parse().unwrap()));
        assert!(blocked_ip("224.0.0.1".parse().unwrap()));
        assert!(blocked_ip("250.1.1.1".parse().unwrap()));
        assert!(!blocked_ip("8.8.8.8".parse().unwrap()));
        assert!(blocked_ip("::1".parse().unwrap()));
        assert!(blocked_ip("fe80::1".parse().unwrap()));
        assert!(blocked_ip("fd00::1".parse().unwrap()));
        assert!(!blocked_ip("2606:4700::1111".parse().unwrap()));
    }
}
