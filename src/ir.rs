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
/// channel; the prefix is stripped before any other model handling.
pub fn split_channel_prefix(model: &str) -> (String, Option<Channel>) {
    if let Some(rest) = model.strip_prefix("express/") {
        (rest.to_string(), Some(Channel::Express))
    } else if let Some(rest) = model.strip_prefix("cookie/") {
        (rest.to_string(), Some(Channel::Cookie))
    } else {
        (model.to_string(), None)
    }
}

/// Parsed, normalized client request (pre-rewrite; §8 cleaning happens in the
/// channel layer right before serialization).
#[derive(Debug, Clone)]
pub struct Ir {
    /// Model name with any channel prefix stripped (display name).
    pub model: String,
    /// Some(...) when the model name carried an express//cookie/ prefix.
    pub forced_channel: Option<Channel>,
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
            stream,
            contents: Vec::new(),
            system: None,
            generation_config: serde_json::Map::new().into(),
            prefill: String::new(),
            include_usage: false,
        }
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
