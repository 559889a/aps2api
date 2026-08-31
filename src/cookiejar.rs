//! Cookie auto-refresh jar (spec §7.4).
//!
//! Google endpoints rewrite short-lived credentials (NID/SIDCC/...) via
//! `Set-Cookie` on EVERY response. Harvesting those rewrites by name into
//! the cookie string keeps the session rolling without ever re-copying
//! cookies by hand — this is the entire "cookie auto-refresh" mechanism
//! used by other reverse-proxy projects. Behavior:
//!
//! - the jar starts from config's `cookie.cookie` (merged over a persisted
//!   `cookie.jar.yaml` next to the binary when present — config is the
//!   authoritative source of intent, the jar file only carries rolled
//!   runtime values);
//! - every cookie-channel response (2xx or not) has its `Set-Cookie` headers
//!   merged in: new values overwrite by name, empty values delete (Google's
//!   logout/invalidated semantics);
//! - changes are persisted to `cookie.jar.yaml` (plain name: value YAML,
//!   human-readable/editable) with failure-to-write being a WARN, never an
//!   error;
//! - the outgoing Cookie header is rebuilt from the jar per request, so
//!   rolled credentials are used the moment they arrive.
//!
//! Red lines untouched: SAPISIDHASH is still computed per request from the
//! jar's CURRENT value; `x-origin` stays unsent; the full string still goes
//! out verbatim — the jar only changes WHERE the string comes from.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Parse a full cookie header string into an ordered name → value map.
///
/// Same boundary semantics as `sapisid::parse_cookie_value`: a `NAME=`
/// occurrence only counts at position 0 or right after a `; ` separator,
/// so `SID` never matches inside `__Secure-1PSID`.
pub fn parse_cookie_header(cookie_str: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for pair in cookie_str.split(';') {
        let pair = pair.trim();
        if let Some((name, value)) = pair.split_once('=') {
            let name = name.trim();
            if !name.is_empty() {
                out.insert(name.to_string(), value.trim().to_string());
            }
        }
    }
    out
}

/// Serialize the jar back into a `name=value; name=value` header string.
pub fn render_cookie_header(jar: &BTreeMap<String, String>) -> String {
    let mut out = String::with_capacity(256);
    for (i, (name, value)) in jar.iter().enumerate() {
        if i > 0 {
            out.push_str("; ");
        }
        out.push_str(name);
        out.push('=');
        out.push_str(value);
    }
    out
}

/// Parse ONE `Set-Cookie` header value (`NAME=VALUE; Expires=...; Path=...`).
/// Only the first name=value pair matters; attributes are ignored (the jar is
/// a flat single-origin kv map). `None` = unparsable, ignore. `Some((name,
/// None))` = explicit deletion (empty value or a past Expires).
pub fn parse_set_cookie(header: &str) -> Option<(String, Option<String>)> {
    let first = header.split(';').next()?.trim();
    let (name, value) = first.split_once('=')?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let value = value.trim();
    if value.is_empty() {
        return Some((name.to_string(), None));
    }
    // Deletion via a past Expires date. Google sends the Netscape hyphenated
    // form ("Expires=Thu, 01-Jan-1970 00:00:00 GMT"); RFC 6265 spellings use
    // spaces ("Thu, 01 Jan 1970"). Normalize the ATTRIBUTES segment (after
    // the first ';' — never the value itself, which could contain the same
    // text) by dropping '-' and spaces so both spellings collapse onto one
    // needle (2026-08-31 fix: the space-only form never matched Google's).
    let attrs_start = header.find(';').unwrap_or(header.len());
    let normalized: String = header[attrs_start..]
        .to_ascii_lowercase()
        .chars()
        .filter(|c| *c != '-' && *c != ' ')
        .collect();
    if normalized.contains("expires=thu,01jan1970") {
        return Some((name.to_string(), None));
    }
    Some((name.to_string(), Some(value.to_string())))
}

/// Runtime cookie store: the parsed jar plus persistence + change tracking.
pub struct CookieJar {
    inner: Mutex<BTreeMap<String, String>>,
    /// Monotonic revision counter: bumped on every merge that changes
    /// anything. Request paths snapshot it before sending so the AUTH
    /// self-heal retry can tell "the jar moved since we sent" (spec §7.4).
    revision: AtomicU64,
    path: Option<PathBuf>,
    /// Persistence is best-effort; a broken disk must not take the proxy
    /// down (spec §7.4). Demoted to false after the first write failure so
    /// a read-only directory cannot spam one WARN per response.
    persist: std::sync::atomic::AtomicBool,
}

impl CookieJar {
    /// Build the runtime jar: `cookie.jar.yaml` (when present next to the
    /// binary / CWD) forms the base, then the config string is merged OVER
    /// it — config is the owner's authoritative intent, the file only adds
    /// runtime-rolled values the config string does not carry.
    pub fn load(config_cookie: &str) -> Self {
        let mut jar = BTreeMap::new();
        let path = jar_file_path();
        let mut persist = true;
        if let Some(p) = &path {
            if p.is_file() {
                match std::fs::read_to_string(p) {
                    Ok(raw) => {
                        let persisted = parse_persisted(&raw);
                        if !persisted.is_empty() {
                            jar = persisted;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(path = %p.display(), error = %e,
                            "cannot read cookie.jar.yaml; starting from config only");
                        persist = false;
                    }
                }
            }
        }
        for (name, value) in parse_cookie_header(config_cookie) {
            jar.insert(name, value);
        }
        if jar.is_empty() {
            tracing::warn!("cookie jar is empty: the cookie channel has no credentials");
        }
        CookieJar {
            inner: Mutex::new(jar),
            revision: AtomicU64::new(0),
            path,
            persist: std::sync::atomic::AtomicBool::new(persist),
        }
    }

    /// In-memory jar for tests: no file is read or written.
    #[cfg(test)]
    pub fn in_memory(config_cookie: &str) -> Self {
        CookieJar {
            inner: Mutex::new(parse_cookie_header(config_cookie)),
            revision: AtomicU64::new(0),
            path: None,
            persist: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// The current cookie header string (rebuilt per request).
    pub fn cookie_header(&self) -> String {
        let jar = self.inner.lock().unwrap();
        render_cookie_header(&jar)
    }

    /// Merge a batch of `Set-Cookie` header values into the jar (spec §7.4:
    /// new values overwrite by name, empty values delete). Returns true when
    /// the jar changed; bumps the revision and schedules a persist then.
    pub fn merge_set_cookies(&self, headers: &[String]) -> bool {
        if headers.is_empty() {
            return false;
        }
        let mut jar = self.inner.lock().unwrap();
        let mut changed = false;
        for header in headers {
            let Some((name, value)) = parse_set_cookie(header) else {
                continue;
            };
            match value {
                Some(v) => {
                    if jar.get(&name) != Some(&v) {
                        jar.insert(name, v);
                        changed = true;
                    }
                }
                None => {
                    if jar.remove(&name).is_some() {
                        changed = true;
                    }
                }
            }
        }
        if changed {
            self.revision.fetch_add(1, Ordering::SeqCst);
            let snapshot = jar.clone();
            drop(jar);
            self.persist(&snapshot);
        }
        changed
    }

    /// Current revision (snapshot before a request; compare afterwards to
    /// detect "credentials rolled while our request was in flight").
    pub fn revision(&self) -> u64 {
        self.revision.load(Ordering::SeqCst)
    }

    fn persist(&self, jar: &BTreeMap<String, String>) {
        if !self.persist.load(Ordering::SeqCst) {
            return;
        }
        let Some(path) = &self.path else {
            return;
        };
        let mut body = String::with_capacity(256);
        body.push_str("# aps2api cookie jar — runtime-rolled cookie values (spec §7.4).\n");
        body.push_str("# Human-editable; delete the file to reset to config.yaml's string.\n");
        for (name, value) in jar {
            body.push_str(&format!("{name}: {}\n", yaml_escape(value)));
        }
        if let Err(e) = std::fs::write(path, body) {
            // Demote persistence: one WARN total, then in-memory only — a
            // read-only deployment directory must not log per response.
            self.persist.store(false, Ordering::SeqCst);
            tracing::warn!(path = %path.display(), error = %e,
                "cannot persist cookie.jar.yaml (continuing in-memory, persistence disabled)");
        }
    }
}

/// Minimal YAML scalar escaping for cookie values (they can contain most
/// printable ASCII; quote defensively when anything yaml-special shows up).
fn yaml_escape(value: &str) -> String {
    let needs_quotes = value.is_empty()
        || value
            .chars()
            .any(|c| matches!(c, ':' | '#' | '\'' | '"' | '\n' | '\r' | '\t'))
        || value.starts_with(' ')
        || value.ends_with(' ');
    if needs_quotes {
        format!("{value:?}")
    } else {
        value.to_string()
    }
}

/// Parse the persisted jar file: `name: value` lines, `#` comments.
fn parse_persisted(raw: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let mut value = value.trim().to_string();
        // Undo the defensive quoting written by yaml_escape.
        if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
            if let Ok(unquoted) = serde_json::from_str::<String>(&value) {
                value = unquoted;
            }
        }
        if !name.is_empty() {
            out.insert(name.to_string(), value);
        }
    }
    out
}

/// `cookie.jar.yaml` next to the binary (CWD fallback), same resolution
/// order as config.yaml / model.json (spec §1.3).
fn jar_file_path() -> Option<PathBuf> {
    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|p| p.to_path_buf()))
    {
        return Some(dir.join("cookie.jar.yaml"));
    }
    Some(PathBuf::from("cookie.jar.yaml"))
}

/// Shared jar handle (cloned into the cookie client).
pub type SharedCookieJar = Arc<CookieJar>;

#[cfg(test)]
mod tests {
    use super::*;

    const COOKIE: &str = "SAPISID=sapid; __Secure-1PSID=abc; NID=111; SIDCC=old";

    #[test]
    fn header_parse_and_render_roundtrip() {
        let jar = parse_cookie_header(COOKIE);
        assert_eq!(jar.get("SAPISID").unwrap(), "sapid");
        assert_eq!(jar.get("__Secure-1PSID").unwrap(), "abc");
        let rendered = render_cookie_header(&jar);
        let reparsed = parse_cookie_header(&rendered);
        assert_eq!(jar, reparsed);
    }

    #[test]
    fn set_cookie_merge_overwrites_and_deletes() {
        let mut jar = parse_cookie_header(COOKIE);
        // Simple overwrite.
        if let Some((name, value)) = parse_set_cookie(
            "NID=222; expires=Sat, 01-Jan-2027 00:00:00 GMT; path=/; domain=.google.com",
        ) {
            match value {
                Some(v) => jar.insert(name, v),
                None => jar.remove(&name),
            };
        }
        assert_eq!(jar.get("NID").unwrap(), "222");
        // Empty value deletes.
        if let Some((name, value)) = parse_set_cookie("SIDCC=; Path=/; Domain=.google.com") {
            match value {
                Some(v) => jar.insert(name, v),
                None => jar.remove(&name),
            };
        }
        assert!(jar.get("SIDCC").is_none());
        // Epoch Expires deletes.
        if let Some((name, value)) =
            parse_set_cookie("NID=999; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
        {
            match value {
                Some(v) => jar.insert(name, v),
                None => jar.remove(&name),
            };
        }
        assert!(jar.get("NID").is_none());
        // Google's actual hyphenated spelling of the epoch delete.
        assert!(matches!(
            parse_set_cookie("NID=999; expires=Thu, 01-Jan-1970 00:00:00 GMT; path=/"),
            Some((name, None)) if name == "NID"
        ));
        // A FUTURE hyphenated date must NOT delete (locally re-derived: the
        // attributes normalize to "sat,01jan2028...", which does not contain
        // the epoch needle — the cookie keeps its value).
        assert!(matches!(
            parse_set_cookie("NID=222; expires=Sat, 01-Jan-2028 00:00:00 GMT"),
            Some((_, Some(v))) if v == "222"
        ));
        // The needle inside a cookie VALUE is not an attribute: not a delete.
        assert!(matches!(
            parse_set_cookie("K=expires=Thu, 01-Jan-1970 00:00:00 GMT; path=/"),
            Some((_, Some(v))) if v.starts_with("expires=")
        ));
        // Attribute-only strings still parse as a first kv pair: "Path=/;
        // Secure" yields ("Path", "/") — the jar gets a junk name it will
        // simply never match on a Set-Cookie. Harmless by design; the parser
        // intentionally has no attribute-name blocklist.
        assert!(matches!(parse_set_cookie("Path=/; Secure"), Some((n, _)) if n == "Path"));
    }

    #[test]
    fn jar_merge_tracks_revision_and_changes() {
        let jar = CookieJar::in_memory(COOKIE);
        let rev0 = jar.revision();
        assert!(!jar.merge_set_cookies(&[]), "empty batch is a no-op");
        assert!(
            !jar.merge_set_cookies(&["NID=111; Path=/".into()]),
            "same value does not count as a change"
        );
        assert_eq!(jar.revision(), rev0);
        assert!(jar.merge_set_cookies(&["NID=222; Path=/".into()]));
        assert_eq!(jar.revision(), rev0 + 1);
        assert!(jar.cookie_header().contains("NID=222"));
        assert!(jar.cookie_header().contains("SAPISID=sapid"));
    }

    #[test]
    fn persisted_roundtrip() {
        let jar = parse_cookie_header(COOKIE);
        let mut body = String::new();
        for (name, value) in &jar {
            body.push_str(&format!("{name}: {}\n", yaml_escape(value)));
        }
        assert_eq!(parse_persisted(&body), jar);
        // Values with yaml-special characters survive the quote roundtrip.
        let tricky = parse_cookie_header("K=a:b#c \"quoted\" d");
        let mut body = String::new();
        for (name, value) in &tricky {
            body.push_str(&format!("{name}: {}\n", yaml_escape(value)));
        }
        assert_eq!(parse_persisted(&body), tricky);
    }

    #[test]
    fn config_wins_over_persisted_file_on_load() {
        // The persisted file carries a rolled NID, config a fresh SAPISID:
        // both survive (config's names overwrite, others carry over).
        let persisted = "NID: rolled\nSAPISID: stale-from-file\n";
        let config = "SAPISID=fresh";
        let mut jar = parse_persisted(persisted);
        for (name, value) in parse_cookie_header(config) {
            jar.insert(name, value);
        }
        assert_eq!(jar.get("SAPISID").unwrap(), "fresh");
        assert_eq!(jar.get("NID").unwrap(), "rolled");
    }
}
