//! Express upstream channel (spec §5): native Gemini REST endpoint with an
//! Express API key. No masquerade needed — this is the official surface.

use serde_json::Value;
use tokio::sync::mpsc;

use crate::channels::EvStream;
use crate::config::ExpressConfig;
use crate::errs;
use crate::ir::{ErrorKind, Ev, UpstreamError};

#[derive(Clone)]
pub struct ExpressClient {
    http: reqwest::Client,
    project_id: String,
    location: String,
    api_key: String,
}

impl ExpressClient {
    pub fn new(http: reqwest::Client, cfg: &ExpressConfig, api_key: &str) -> Self {
        ExpressClient {
            http,
            project_id: cfg.project_id.trim().to_string(),
            location: if cfg.location.trim().is_empty() {
                "global".to_string()
            } else {
                cfg.location.trim().to_string()
            },
            api_key: api_key.to_string(),
        }
    }

    /// `projects/{p}/locations/{l}/publishers/google/models/{model}` — the
    /// location-pinned full path (spec trap 12: bare names 404 on routing).
    fn model_path(&self, model: &str) -> String {
        format!(
            "projects/{}/locations/{}/publishers/google/models/{}",
            self.project_id, self.location, model
        )
    }

    fn url(&self, model: &str, stream: bool) -> String {
        if stream {
            format!(
                "https://aiplatform.googleapis.com/v1/{}:streamGenerateContent?alt=sse",
                self.model_path(model)
            )
        } else {
            format!(
                "https://aiplatform.googleapis.com/v1/{}:generateContent",
                self.model_path(model)
            )
        }
    }

    pub async fn start(
        &self,
        payload: &Value,
        model: &str,
        stream: bool,
    ) -> Result<EvStream, UpstreamError> {
        let url = self.url(model, stream);
        let mut req = self
            .http
            .post(&url)
            .header("x-goog-api-key", &self.api_key)
            .header("content-type", "application/json")
            .json(payload);
        if self.location == "global" {
            // Priority PayGo internal routing headers (spec §5.1).
            req = req
                .header("X-Vertex-AI-LLM-Request-Type", "shared")
                .header("X-Vertex-AI-LLM-Shared-Request-Type", "priority");
        }
        let resp = req.send().await.map_err(map_send_err)?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            let msg = error_message(&body);
            return Err(errs::classify_error(Some(status.as_u16()), msg));
        }
        let (tx, rx) = mpsc::channel::<Ev>(64);
        if stream {
            tokio::spawn(crate::channels::pump_sse(resp.bytes_stream(), tx));
        } else {
            tokio::spawn(crate::channels::pump_single(resp.bytes(), tx));
        }
        Ok(EvStream::new(rx))
    }
}

/// Transport failures before/while the request runs are retryable (§12.1).
fn map_send_err(e: reqwest::Error) -> UpstreamError {
    let message = e.to_string();
    if e.is_connect() || e.is_timeout() || message.to_lowercase().contains("timeout") {
        UpstreamError {
            kind: ErrorKind::Transport,
            status: None,
            message,
        }
    } else {
        errs::classify_error(None, message)
    }
}

/// Upstream error body: `{"error":{"code":N,"message":"...","status":"..."}}`.
/// Fall back to a truncated raw body when the shape does not match.
pub fn error_message(body: &str) -> String {
    if let Ok(v) = serde_json::from_str::<Value>(body) {
        if let Some(msg) = v
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(Value::as_str)
        {
            return msg.to_string();
        }
    }
    let truncated: String = body.chars().take(300).collect();
    if truncated.is_empty() {
        "(empty error body)".to_string()
    } else {
        truncated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_shape_and_priority_headers_condition() {
        let cfg = ExpressConfig {
            api_key: String::new(),
            project_id: "proj".into(),
            location: "global".into(),
        };
        let http = reqwest::Client::new();
        let c = ExpressClient::new(http, &cfg, "key");
        assert_eq!(
            c.url("gemini-3.1-pro", false),
            "https://aiplatform.googleapis.com/v1/projects/proj/locations/global/publishers/google/models/gemini-3.1-pro:generateContent"
        );
        assert_eq!(
            c.url("gemini-3.1-pro", true),
            "https://aiplatform.googleapis.com/v1/projects/proj/locations/global/publishers/google/models/gemini-3.1-pro:streamGenerateContent?alt=sse"
        );
        assert_eq!(
            c.model_path("m"),
            "projects/proj/locations/global/publishers/google/models/m"
        );
    }

    #[test]
    fn error_message_extracts_nested_field() {
        assert_eq!(
            error_message(
                r#"{"error":{"code":429,"message":"quota","status":"RESOURCE_EXHAUSTED"}}"#
            ),
            "quota"
        );
        assert_eq!(error_message("not json"), "not json");
        assert_eq!(error_message(""), "(empty error body)");
    }
}
