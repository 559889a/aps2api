//! Configuration loading and validation (spec §2).
//!
//! `config.yaml` and `model.json` are read from the directory the binary
//! lives in (Termux-friendly: no /etc, no /opt). As a development
//! convenience, when the file is not found next to the executable the
//! current working directory is consulted as a fallback (`cargo run` from
//! the repo root).

use std::collections::HashMap;
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Local auth key; clients send `Authorization: Bearer <key>` or `x-goog-api-key`.
    pub api_key: String,
    /// Listen port (must be > 1024 to stay usable on Android/Termux).
    pub port: u16,
    /// Global outbound SOCKS5 proxy, e.g. `socks5://user:pass@host:port`.
    /// Commented out / absent = direct connection (a first-class mode).
    #[serde(default)]
    pub socks5: Option<String>,
    #[serde(default)]
    pub express: ExpressConfig,
    #[serde(default)]
    pub cookie: CookieConfig,
    /// Forced thinking level: minimal | low | medium | high, empty = not forced.
    #[serde(default)]
    pub thinking_level: String,
    /// Bypass (fake streaming) switch: when true, the
    /// `fake-streaming/express/<model>` aliases are listed and served
    /// (spec §9.5). Default false.
    #[serde(default)]
    pub bypass: bool,
    #[serde(default)]
    pub retry: RetryConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ExpressConfig {
    #[serde(default)]
    pub api_key: String,
    #[serde(default)]
    pub project_id: String,
    #[serde(default = "default_location")]
    pub location: String,
}

fn default_location() -> String {
    "global".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct CookieConfig {
    #[serde(default)]
    pub cookie: String,
    #[serde(default)]
    pub project_id: String,
    #[serde(default)]
    pub experiment_flags: String,
    /// Cookie auto-refresh switch (spec §7.4): harvest Set-Cookie rewrites
    /// into the runtime jar + persist to cookie.jar.yaml + one self-heal
    /// retry on AUTH failures. Default true (opt-out).
    #[serde(default = "default_true")]
    pub auto_refresh: bool,
}

impl Default for CookieConfig {
    fn default() -> Self {
        // Keep the derive-equivalent struct default in sync with the serde
        // default (auto_refresh on) so both construction paths agree.
        CookieConfig {
            cookie: String::new(),
            project_id: String::new(),
            experiment_flags: String::new(),
            auto_refresh: true,
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct RetryConfig {
    /// Retries after a failure; total attempts = max + 1 (max=0 still tries once).
    #[serde(default = "default_retry_max")]
    pub max: u32,
    /// "fixed" = wait `interval` seconds each time;
    /// "backoff" = linear growth: wait n seconds before retry n (1s, 2s, 3s, ...).
    #[serde(default = "default_retry_strategy")]
    pub strategy: String,
    #[serde(default = "default_retry_interval")]
    pub interval: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        RetryConfig {
            max: default_retry_max(),
            strategy: default_retry_strategy(),
            interval: default_retry_interval(),
        }
    }
}

fn default_retry_max() -> u32 {
    3
}

fn default_retry_strategy() -> String {
    "backoff".to_string()
}

fn default_retry_interval() -> u64 {
    2
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ModelFile {
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default)]
    pub alias_map: HashMap<String, String>,
}

impl Config {
    /// A channel is enabled iff its credential fields are filled in (spec §2.2).
    pub fn express_enabled(&self) -> bool {
        !self.express.api_key.trim().is_empty()
    }

    pub fn cookie_enabled(&self) -> bool {
        !self.cookie.cookie.trim().is_empty()
    }

    fn validate(&mut self) -> Result<(), String> {
        if self.api_key.trim().is_empty() {
            return Err("`api_key` must not be empty".to_string());
        }
        if self.port == 0 {
            return Err("`port` must be a positive number".to_string());
        }
        if let Some(url) = &self.socks5 {
            let lower = url.to_lowercase();
            if !(lower.starts_with("socks5://") || lower.starts_with("socks5h://")) {
                return Err(format!(
                    "`socks5` must start with socks5:// or socks5h:// (got {url:?})"
                ));
            }
        }
        if self.express_enabled() && self.express.project_id.trim().is_empty() {
            return Err("express channel is enabled but `express.project_id` is empty".to_string());
        }
        if self.cookie_enabled() && self.cookie.project_id.trim().is_empty() {
            return Err("cookie channel is enabled but `cookie.project_id` is empty".to_string());
        }
        if self.express_enabled() && self.express.location.trim().is_empty() {
            self.express.location = "global".to_string();
        }
        if !self.thinking_level.is_empty()
            && !matches!(
                self.thinking_level.as_str(),
                "minimal" | "low" | "medium" | "high"
            )
        {
            return Err(
                "`thinking_level` must be one of minimal | low | medium | high (or empty)"
                    .to_string(),
            );
        }
        match self.retry.strategy.as_str() {
            "fixed" | "backoff" => {}
            other => {
                return Err(format!(
                    "`retry.strategy` must be fixed or backoff (got {other:?})"
                ))
            }
        }
        if self.cookie_enabled() || self.express_enabled() {
            return Ok(());
        }
        Err(
            "no upstream channel is enabled: fill in `express.api_key` (+ project_id) \
             or `cookie.cookie` (+ project_id) in config.yaml"
                .to_string(),
        )
    }
}

fn resolve_data_file(name: &str) -> Result<PathBuf, String> {
    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|p| p.to_path_buf()))
    {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    let candidate = PathBuf::from(name);
    if candidate.is_file() {
        return Ok(candidate);
    }
    Err(format!(
        "{name} not found: expected next to the executable or in the current working directory"
    ))
}

/// Load and validate `config.yaml`. Fatal on any problem: prints a message
/// naming the offending field and exits the process (spec §1.3).
pub fn load_config() -> Config {
    let path = resolve_data_file("config.yaml").unwrap_or_else(|e| fatal(&e));
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| fatal(&format!("cannot read {path:?}: {e}")));
    let mut cfg: Config = serde_yaml::from_str(&raw)
        .unwrap_or_else(|e| fatal(&format!("invalid config.yaml ({path:?}): {e}")));
    cfg.validate()
        .unwrap_or_else(|e| fatal(&format!("invalid config.yaml: {e}")));
    cfg
}

/// Load `model.json` (spec §2.3). `models` must be non-empty.
pub fn load_models() -> ModelFile {
    let path = resolve_data_file("model.json").unwrap_or_else(|e| fatal(&e));
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| fatal(&format!("cannot read {path:?}: {e}")));
    let mf: ModelFile = serde_json::from_str(&raw)
        .unwrap_or_else(|e| fatal(&format!("invalid model.json ({path:?}): {e}")));
    if mf.models.is_empty() {
        fatal("model.json: `models` must not be empty");
    }
    mf
}

fn fatal(msg: &str) -> ! {
    eprintln!("aps2api: {msg}");
    std::process::exit(1);
}
