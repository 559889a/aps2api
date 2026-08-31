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

use futures_util::StreamExt;
use serde_json::Value;

const MAX_REDIRECTS: usize = 3;
const MAX_IMAGE_BYTES: usize = 20 * 1024 * 1024;
/// Cumulative cap on the inline image data ONE request may accumulate through
/// remoteFetch resolution (base64 characters, spec §9.3): every fetched image
/// stays in the payload simultaneously, so per-image caps alone still let a
/// request with many remoteFetch parts grow without bound (20 images × 20MB ×
/// the 4/3 base64 expansion ≈ 500MB — memory red line, closed 2026-08-31).
/// Matching the request-body cap keeps the expanded payload in the order the
/// ports already accept.
const MAX_TOTAL_IMAGE_BYTES: usize = 64 * 1024 * 1024;

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
        // Read the body STREAMING and stop at the cap: a content-length
        // precheck only stops honest servers — a lying/omitting source must
        // be caught on the read side (memory red line, 2026-08-31).
        let mut body: Vec<u8> = Vec::new();
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| deny(&format!("body read failed: {e}")))?;
            body.extend_from_slice(&chunk);
            if body.len() > MAX_IMAGE_BYTES {
                return Err(deny("image exceeds the 20MB limit"));
            }
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

/// Walk `parts` in place, replacing `remoteFetch` placeholders with inlineData
/// parts (spec §9.3); a failed fetch drops the part. The walk advances the
/// index EXPLICITLY and never after a `remove`: a removal shifts the next
/// part into the current slot, so a naive `for i in 0..len` loop both skips
/// the part after a dropped one and eventually indexes out of bounds (panic).
/// `fetch` receives an owned URL and returns a self-contained future (capture
/// whatever it needs by value — e.g. clone the shared client into itself).
pub async fn resolve_remote_parts<F, Fut>(parts: &mut Vec<Value>, fetch: F)
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Result<(String, String), String>>,
{
    resolve_remote_parts_with_limit(parts, fetch, MAX_TOTAL_IMAGE_BYTES).await
}

/// Cap-bounded core of [`resolve_remote_parts`]: once the accumulated inline
/// image data reaches `max_total`, further fetches are treated as failures
/// (part dropped with a warning — the same semantics as a 404), which bounds
/// the expanded payload instead of silently changing it.
pub async fn resolve_remote_parts_with_limit<F, Fut>(
    parts: &mut Vec<Value>,
    fetch: F,
    max_total: usize,
) where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Result<(String, String), String>>,
{
    let mut total = 0usize;
    let mut i = 0;
    while i < parts.len() {
        let Some(url) = parts[i]
            .get("remoteFetch")
            .and_then(Value::as_str)
            .map(str::to_string)
        else {
            i += 1;
            continue;
        };
        match fetch(url.clone()).await {
            Ok((mime, b64)) => {
                total += b64.len();
                if total > max_total {
                    tracing::warn!(
                        url = %url,
                        total_bytes = total,
                        limit = max_total,
                        "remote image dropped: cumulative inline image data exceeded the request limit"
                    );
                    parts.remove(i);
                    continue;
                }
                parts[i] = serde_json::json!({
                    "inlineData": { "mimeType": mime, "data": b64 }
                });
                i += 1;
            }
            Err(e) => {
                tracing::warn!(url = %url, error = %e, "remote image fetch failed; part dropped");
                parts.remove(i);
            }
        }
    }
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

    #[tokio::test]
    async fn failed_fetch_drops_part_without_skipping_or_panicking() {
        // Regression: the previous `for i in 0..parts.len()` loop panicked
        // (index out of bounds) whenever a fetch failed and more parts
        // followed, and skipped the part that slid into the freed slot.
        let mut parts = vec![
            serde_json::json!({ "text": "hi" }),
            serde_json::json!({ "remoteFetch": "http://x/fail.png" }),
            serde_json::json!({ "remoteFetch": "http://x/ok.png" }),
            serde_json::json!({ "text": "bye" }),
        ];
        resolve_remote_parts(&mut parts, |url| async move {
            if url.ends_with("fail.png") {
                Err("remote image rejected: HTTP 404".to_string())
            } else {
                Ok(("image/png".to_string(), "QQ==".to_string()))
            }
        })
        .await;
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0]["text"], "hi");
        assert_eq!(parts[1]["inlineData"]["data"], "QQ==");
        assert_eq!(parts[2]["text"], "bye");
    }

    #[tokio::test]
    async fn all_parts_failing_leaves_empty_without_panic() {
        let mut parts = vec![
            serde_json::json!({ "remoteFetch": "http://x/a.png" }),
            serde_json::json!({ "remoteFetch": "http://x/b.png" }),
        ];
        resolve_remote_parts(&mut parts, |_url| async { Err("nope".to_string()) }).await;
        assert!(parts.is_empty());
    }

    #[tokio::test]
    async fn cumulative_cap_drops_excess_images_keeps_earlier_ones() {
        // Two images, cumulative cap set between them: the first stays, the
        // second is dropped with the limit warning — same semantics as a
        // failed fetch (memory red line: per-image caps alone left the total
        // unbounded).
        let mut parts = vec![
            serde_json::json!({ "remoteFetch": "http://x/a.png" }),
            serde_json::json!({ "remoteFetch": "http://x/b.png" }),
            serde_json::json!({ "remoteFetch": "http://x/c.png" }),
        ];
        resolve_remote_parts_with_limit(
            &mut parts,
            |url| async move {
                let n = url.rsplit('/').next().unwrap().chars().next().unwrap();
                Ok(("image/png".to_string(), n.to_string().repeat(10)))
            },
            25,
        )
        .await;
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0]["inlineData"]["data"], "a".repeat(10));
        assert_eq!(parts[1]["inlineData"]["data"], "c".repeat(10));
    }
}
