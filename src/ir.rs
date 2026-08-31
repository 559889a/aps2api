//! Internal representation (ir): a Gemini-shaped payload plus request meta.
//! Both client-facing ports (OAI / Gemini) parse into this shape; both
//! upstream channels consume it after applying the §8 rewrite rules.

use serde_json::Value;

/// Which upstream channel a request is forced to (model-name prefix), or the
/// resolved default when no prefix was given (spec §2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Express,
    Cookie,
}

/// Channel name prefixes (spec §2.2): `express/...` and `cookie/...` force a
/// channel; `fake-streaming/express/...` (bypass / fake streaming, §9.5)
/// forces express AND flags the request for the bypass pipeline. The prefix
/// is stripped before any other model handling. Any OTHER `fake-streaming/...`
/// shape keeps its full name (bypass = false) so the dispatch gate can reject
/// it with a precise message (the cookie upstream has no non-streaming
/// endpoint to fake-stream onto).
pub const FAKE_STREAMING_PREFIX: &str = "fake-streaming/";
const FAKE_STREAMING_EXPRESS: &str = "fake-streaming/express/";

pub fn split_model_name(model: &str) -> (String, Option<Channel>, bool) {
    if let Some(rest) = model.strip_prefix(FAKE_STREAMING_EXPRESS) {
        (rest.to_string(), Some(Channel::Express), true)
    } else if let Some(rest) = model.strip_prefix("express/") {
        (rest.to_string(), Some(Channel::Express), false)
    } else if let Some(rest) = model.strip_prefix("cookie/") {
        (rest.to_string(), Some(Channel::Cookie), false)
    } else {
        (model.to_string(), None, false)
    }
}

/// Parsed, normalized client request (pre-rewrite; §8 cleaning happens in the
/// channel layer right before serialization).
#[derive(Debug, Clone)]
pub struct Ir {
    /// Model name with any channel/bypass prefix stripped (display name).
    pub model: String,
    /// Some(...) when the model name carried an express//cookie/ prefix.
    pub forced_channel: Option<Channel>,
    /// True when the name carried the `fake-streaming/express/` bypass prefix
    /// (spec §9.5): streaming requests run the upstream non-streaming and
    /// replay the complete answer over a heartbeat-bridged SSE stream.
    pub bypass: bool,
    pub stream: bool,
    /// Gemini content objects: {"role": "user"|"model", "parts": [...]}.
    pub contents: Vec<Value>,
    /// systemInstruction in camelCase shape, when present.
    pub system: Option<Value>,
    /// Client-provided sampling knobs (camelCase, cleaned of forbidden keys);
    /// the §8.2 whitelist is enforced at rewrite time.
    pub generation_config: Value,
    /// Prefill text detected by `prefill::apply_request` (empty = none).
    pub prefill: String,
    /// OAI stream_options.include_usage (Gemini port always leaves false;
    /// usage is part of the native protocol there).
    pub include_usage: bool,
}

impl Ir {
    pub fn new(model: String, stream: bool) -> Self {
        Ir {
            model,
            forced_channel: None,
            bypass: false,
            stream,
            contents: Vec::new(),
            system: None,
            generation_config: serde_json::Map::new().into(),
            prefill: String::new(),
            include_usage: false,
        }
    }

    /// Dispatch gate (spec §9.5): a request naming any `fake-streaming/...`
    /// model is rejected when bypass is disabled or when the alias does not
    /// target the express channel. `None` = proceed.
    pub fn bypass_violation(&self, bypass_enabled: bool) -> Option<String> {
        if !self.bypass && !self.model.starts_with(FAKE_STREAMING_PREFIX) {
            return None;
        }
        if !bypass_enabled {
            return Some(
                "bypass mode is disabled: set `bypass: true` in config.yaml to enable \
                 the fake-streaming model aliases"
                    .into(),
            );
        }
        if !self.bypass {
            return Some(
                "fake-streaming aliases support the express channel only (the cookie \
                 upstream has no non-streaming endpoint); use \
                 `fake-streaming/express/<model>`"
                    .into(),
            );
        }
        None
    }

    /// Resolve the channel to use: explicit prefix wins, otherwise express
    /// when configured, else cookie (spec §2.2).
    pub fn resolve_channel(&self, express_enabled: bool, cookie_enabled: bool) -> Option<Channel> {
        match self.forced_channel {
            Some(c) => Some(c),
            None if express_enabled => Some(Channel::Express),
            None if cookie_enabled => Some(Channel::Cookie),
            None => None,
        }
    }
}

/// Port-layer parse failure: HTTP status + message; each port formats it in
/// its own wire shape (spec §14.3).
#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: u16,
    pub message: String,
}

impl ApiError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        ApiError {
            status: 400,
            message: message.into(),
        }
    }
}

/// Error classification for upstream failures (spec §12/§14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Retryable: 429/5xx/quota keywords.
    RateLimit,
    /// Cookie expired / permission denied (not retryable).
    Auth,
    /// Project-level problem (billing/permission; not retryable).
    Project,
    Invalid,
    NotFound,
    Server,
    /// Connect failures / timeouts / dropped connections (retryable).
    Transport,
}

#[derive(Debug, Clone)]
pub struct UpstreamError {
    pub kind: ErrorKind,
    /// Upstream HTTP status when known (retries exhausted -> pass through).
    pub status: Option<u16>,
    pub message: String,
    /// Cookie auto-refresh self-heal hint (spec §7.4): true when the cookie
    /// jar rolled (Set-Cookie rewrites merged) after the failed request was
    /// sent — the credentials that request used are stale, so one retry with
    /// the fresh jar is likely to succeed. Set by the cookie channel on AUTH
    /// failures; consumed by the pipeline's one-shot self-heal retry.
    pub jar_refreshed_since_send: bool,
}

impl UpstreamError {
    /// Retryable kinds (spec §12.1): 429, 5xx, quota keywords, transport
    /// failures. Auth / project / invalid / not-found are terminal.
    pub fn retryable(&self) -> bool {
        matches!(
            self.kind,
            ErrorKind::RateLimit | ErrorKind::Server | ErrorKind::Transport
        )
    }
}

/// Unified internal event stream: both channels parse upstream bytes into
/// these; both ports format them for the client (spec §4).
#[derive(Debug, Clone)]
pub enum Ev {
    Text(String),
    Thought(String),
    Image {
        mime: String,
        b64: String,
    },
    /// Raw finishReason, `*_UNSPECIFIED` already filtered.
    Finish(String),
    /// usageMetadata (may be absent from some chunks).
    Usage(Value),
    /// promptFeedback.blockReason, `*_UNSPECIFIED` already filtered.
    Blocked(String),
    Error(UpstreamError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_prefixes_split() {
        assert_eq!(
            split_model_name("express/gem"),
            ("gem".to_string(), Some(Channel::Express), false)
        );
        assert_eq!(
            split_model_name("cookie/gem"),
            ("gem".to_string(), Some(Channel::Cookie), false)
        );
        assert_eq!(split_model_name("gem"), ("gem".to_string(), None, false));
    }

    #[test]
    fn fake_streaming_express_flagged_and_stripped() {
        let (name, ch, bypass) = split_model_name("fake-streaming/express/gemini-3.7-flash");
        assert_eq!(name, "gemini-3.7-flash");
        assert_eq!(ch, Some(Channel::Express));
        assert!(bypass);
    }

    #[test]
    fn other_fake_streaming_shapes_stay_untouched_for_the_gate() {
        // Not the express form: name kept whole, gate decides the rejection.
        let (name, ch, bypass) = split_model_name("fake-streaming/cookie/gem");
        assert_eq!(name, "fake-streaming/cookie/gem");
        assert_eq!(ch, None);
        assert!(!bypass);
        let ir = Ir::new(name, true);
        assert!(ir.bypass_violation(true).is_some());
        assert!(ir.bypass_violation(false).is_some());
    }

    #[test]
    fn bypass_gate_rejects_only_alias_requests() {
        // Valid bypass alias: passes when enabled, rejected when disabled.
        let mut ir = Ir::new("gemini-3.7-flash".into(), true);
        ir.bypass = true;
        assert!(ir.bypass_violation(true).is_none());
        assert!(ir.bypass_violation(false).is_some());
        // Plain requests never trip the gate, whatever the switch says.
        let plain = Ir::new("gemini-3.7-flash".into(), false);
        assert!(plain.bypass_violation(true).is_none());
        assert!(plain.bypass_violation(false).is_none());
    }
}
