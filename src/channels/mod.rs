//! Upstream channels (spec §4): enum-dispatched express / cookie clients.
//!
//! Both channels parse upstream bytes into the unified internal event stream
//! (`Ev`), so the port layers format one shared shape.

pub mod cookie;
pub mod express;

use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use serde_json::Value;
use tokio::sync::mpsc;

use crate::errs;
use crate::ir::{ErrorKind, Ev, UpstreamError};

/// Started upstream attempt: a live event stream plus the ability to detect
/// that the upstream closed without any error event.
pub struct EvStream {
    rx: mpsc::Receiver<Ev>,
}

impl EvStream {
    pub fn new(rx: mpsc::Receiver<Ev>) -> Self {
        EvStream { rx }
    }

    /// Next event, or None when the upstream stream ended.
    pub async fn next(&mut self) -> Option<Ev> {
        self.rx.recv().await
    }
}

#[derive(Clone)]
pub enum UpstreamClient {
    Express(express::ExpressClient),
    Cookie(cookie::CookieClient),
}

impl UpstreamClient {
    /// Send one request attempt and return the event stream. Transport /
    /// HTTP-status failures surface as Err (retryable ones before any client
    /// output allow the retry loop to run again); in-stream failures arrive
    /// as `Ev::Error`.
    pub async fn start(
        &self,
        payload: &Value,
        model: &str,
        stream: bool,
    ) -> Result<EvStream, UpstreamError> {
        match self {
            UpstreamClient::Express(c) => c.start(payload, model, stream).await,
            UpstreamClient::Cookie(c) => c.start(payload, model, stream).await,
        }
    }
}

fn ends_with_unspecified(s: &str) -> bool {
    s.ends_with("_UNSPECIFIED")
}

// ---------------------------------------------------------------------------
// Byte-stream pumps (shared by both channels; generic over the HTTP client).
// ---------------------------------------------------------------------------

async fn emit_json(tx: &mpsc::Sender<Ev>, data: &str) {
    match serde_json::from_str::<Value>(data) {
        Ok(chunk) => {
            let mut events = Vec::new();
            extract_from_chunk(&chunk, &mut events);
            for ev in events {
                if tx.send(ev).await.is_err() {
                    return;
                }
            }
        }
        Err(e) => {
            let _ = tx
                .send(Ev::Error(errs::classify_error(
                    None,
                    format!("upstream returned invalid JSON: {e}"),
                )))
                .await;
        }
    }
}

fn transport_err(message: String) -> Ev {
    Ev::Error(UpstreamError {
        kind: ErrorKind::Transport,
        status: None,
        message,
    })
}

/// SSE pump (spec §13.3): one `data: <json>` per event; comment and empty
/// lines ignored; no `[DONE]` marker in the Gemini protocol.
pub(crate) async fn pump_sse<S, E>(mut stream: S, tx: mpsc::Sender<Ev>)
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: std::fmt::Display,
{
    let mut buf = String::new();
    loop {
        match stream.next().await {
            Some(Ok(bytes)) => {
                buf.push_str(&String::from_utf8_lossy(&bytes));
                while let Some(pos) = buf.find('\n') {
                    let line: String = buf.drain(..=pos).collect();
                    let line = line.trim_end_matches(['\n', '\r']);
                    if let Some(data) = line.strip_prefix("data:") {
                        let data = data.trim();
                        if data.is_empty() || data == "[DONE]" {
                            continue;
                        }
                        emit_json(&tx, data).await;
                    }
                    // comment lines (`: ...`) and blank lines: ignored
                }
            }
            Some(Err(e)) => {
                let _ = tx
                    .send(transport_err(format!("upstream stream interrupted: {e}")))
                    .await;
                return;
            }
            None => break,
        }
    }
}

/// Concatenated-JSON pump (spec §13.1): batchGraphql streams consecutive
/// top-level JSON objects; a bracket-balancing scanner extracts them and the
/// channel-specific `extract` callback turns each object into events.
pub(crate) async fn pump_concat<S, E, F>(mut stream: S, tx: mpsc::Sender<Ev>, mut extract: F)
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: std::fmt::Display,
    F: FnMut(&Value, &mut Vec<Ev>),
{
    let mut scanner = crate::streamscan::JsonStreamScanner::new();
    loop {
        match stream.next().await {
            Some(Ok(bytes)) => {
                for obj in scanner.feed(&String::from_utf8_lossy(&bytes)) {
                    match serde_json::from_str::<Value>(&obj) {
                        Ok(v) => {
                            let mut events = Vec::new();
                            extract(&v, &mut events);
                            for ev in events {
                                if tx.send(ev).await.is_err() {
                                    return;
                                }
                            }
                        }
                        Err(e) => {
                            let _ = tx
                                .send(Ev::Error(errs::classify_error(
                                    None,
                                    format!("upstream returned invalid JSON: {e}"),
                                )))
                                .await;
                        }
                    }
                }
            }
            Some(Err(e)) => {
                let _ = tx
                    .send(transport_err(format!("upstream stream interrupted: {e}")))
                    .await;
                return;
            }
            None => break,
        }
    }
    scanner.finish();
}

/// Single-JSON pump: the whole body is one GenerateContentResponse.
pub(crate) async fn pump_single<Fut, B, E>(read_all: Fut, tx: mpsc::Sender<Ev>)
where
    Fut: std::future::Future<Output = Result<B, E>>,
    B: AsRef<[u8]>,
    E: std::fmt::Display,
{
    match read_all.await {
        Ok(bytes) => emit_json(&tx, &String::from_utf8_lossy(bytes.as_ref())).await,
        Err(e) => {
            let _ = tx
                .send(transport_err(format!(
                    "failed to read upstream response: {e}"
                )))
                .await;
        }
    }
}

/// `part.thought` may arrive as bool or as the STRING "true"/"True"/"false"
/// (spec trap 6: a string "false" is falsy — compare by content).
fn thought_flag(part: &Value) -> bool {
    match part.get("thought") {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => matches!(s.as_str(), "true" | "True"),
        _ => false,
    }
}

/// Unified chunk extraction (spec §13.2): one standard Gemini chunk ->
/// zero or more events. `*_UNSPECIFIED` proto defaults are filtered.
pub fn extract_from_chunk(chunk: &Value, out: &mut Vec<Ev>) {
    // promptFeedback.blockReason (+ optional blockReasonMessage).
    if let Some(pf) = chunk.get("promptFeedback") {
        if let Some(reason) = pf.get("blockReason").and_then(Value::as_str) {
            if !reason.is_empty() && !ends_with_unspecified(reason) {
                let mut msg = reason.to_string();
                if let Some(extra) = pf.get("blockReasonMessage").and_then(Value::as_str) {
                    if !extra.is_empty() {
                        msg = format!("{msg}: {extra}");
                    }
                }
                out.push(Ev::Blocked(msg));
            }
        }
    }

    if let Some(candidates) = chunk.get("candidates").and_then(Value::as_array) {
        for cand in candidates {
            if let Some(parts) = cand
                .get("content")
                .and_then(|c| c.get("parts"))
                .and_then(Value::as_array)
            {
                for part in parts {
                    if let Some(name) = part.get("functionCall").and_then(|fc| fc.get("name")) {
                        tracing::debug!(function = %name, "dropped functionCall part (no tool support)");
                        continue;
                    }
                    if part.get("executableCode").is_some()
                        || part.get("codeExecutionResult").is_some()
                    {
                        tracing::debug!("dropped code-execution part (no tool support)");
                        continue;
                    }
                    if let Some(text) = part.get("text").and_then(Value::as_str) {
                        if !text.is_empty() {
                            if thought_flag(part) {
                                out.push(Ev::Thought(text.to_string()));
                            } else {
                                out.push(Ev::Text(text.to_string()));
                            }
                        }
                    }
                    if let Some(inline) = part.get("inlineData") {
                        if let (Some(mime), Some(data)) = (
                            inline.get("mimeType").and_then(Value::as_str),
                            inline.get("data").and_then(Value::as_str),
                        ) {
                            out.push(Ev::Image {
                                mime: mime.to_string(),
                                b64: data.to_string(),
                            });
                        }
                    }
                }
            }
            if let Some(finish) = cand.get("finishReason").and_then(Value::as_str) {
                if !finish.is_empty() && !ends_with_unspecified(finish) {
                    out.push(Ev::Finish(finish.to_string()));
                }
            }
        }
    }

    if let Some(usage) = chunk.get("usageMetadata") {
        if usage.is_object() && !usage.as_object().unwrap().is_empty() {
            out.push(Ev::Usage(usage.clone()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn text_thought_and_finish_extracted() {
        let chunk = json!({
            "candidates": [{
                "content": { "role": "model", "parts": [
                    { "text": "thinking out loud", "thought": true },
                    { "text": "answer" }
                ]},
                "finishReason": "STOP"
            }],
            "usageMetadata": { "promptTokenCount": 1, "candidatesTokenCount": 2, "totalTokenCount": 3 }
        });
        let mut out = Vec::new();
        extract_from_chunk(&chunk, &mut out);
        assert!(matches!(&out[0], Ev::Thought(t) if t == "thinking out loud"));
        assert!(matches!(&out[1], Ev::Text(t) if t == "answer"));
        assert!(matches!(&out[2], Ev::Finish(f) if f == "STOP"));
        assert!(matches!(&out[3], Ev::Usage(_)));
    }

    #[test]
    fn unspecified_defaults_are_filtered() {
        let chunk = json!({
            "candidates": [{ "content": {"parts": [{"text": "x"}]}, "finishReason": "FINISH_REASON_UNSPECIFIED" }],
            "promptFeedback": { "blockReason": "BLOCK_REASON_UNSPECIFIED" }
        });
        let mut out = Vec::new();
        extract_from_chunk(&chunk, &mut out);
        assert_eq!(out.len(), 1);
        assert!(matches!(&out[0], Ev::Text(_)));
    }

    #[test]
    fn thought_string_false_is_falsy_but_true_strings_accepted() {
        let chunk = json!({
            "candidates": [{ "content": { "parts": [
                { "text": "a", "thought": "true" },
                { "text": "b", "thought": "True" },
                { "text": "c", "thought": "false" }
            ]}}]
        });
        let mut out = Vec::new();
        extract_from_chunk(&chunk, &mut out);
        assert!(matches!(&out[0], Ev::Thought(_)));
        assert!(matches!(&out[1], Ev::Thought(_)));
        assert!(matches!(&out[2], Ev::Text(_)));
    }

    #[test]
    fn function_call_and_code_parts_dropped() {
        let chunk = json!({
            "candidates": [{ "content": { "parts": [
                { "functionCall": { "name": "f", "args": {} } },
                { "executableCode": { "code": "x" } },
                { "text": "keep" }
            ]}}]
        });
        let mut out = Vec::new();
        extract_from_chunk(&chunk, &mut out);
        assert_eq!(out.len(), 1);
        assert!(matches!(&out[0], Ev::Text(t) if t == "keep"));
    }

    #[test]
    fn blocked_with_message() {
        let chunk = json!({
            "promptFeedback": { "blockReason": "SAFETY", "blockReasonMessage": "blocked" }
        });
        let mut out = Vec::new();
        extract_from_chunk(&chunk, &mut out);
        assert!(matches!(&out[0], Ev::Blocked(m) if m.contains("SAFETY") && m.contains("blocked")));
    }

    #[test]
    fn image_part_extracted() {
        let chunk = json!({
            "candidates": [{ "content": { "parts": [
                { "inlineData": { "mimeType": "image/png", "data": "AAA" } }
            ]}}]
        });
        let mut out = Vec::new();
        extract_from_chunk(&chunk, &mut out);
        assert!(matches!(&out[0], Ev::Image { mime, b64 } if mime == "image/png" && b64 == "AAA"));
    }
}
