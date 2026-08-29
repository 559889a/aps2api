//! Gemini-native response emission (spec §10.3): events become SSE chunks of
//! GenerateContentResponse (no [DONE]; the protocol ends with the connection
//! plus finishReason) or one aggregated non-streaming response. Thought
//! flags are preserved for Gemini clients.

use bytes::Bytes;
use serde_json::{json, Map, Value};

use crate::ir::{ErrorKind, Ev, UpstreamError};
use crate::prefill::{strip_overlap, PrefillDeduper};

/// ErrorKind -> UPPER_SNAKE status for the Gemini error shape (§14.3).
pub fn status_name(kind: ErrorKind) -> &'static str {
    status_upper(kind)
}

fn status_upper(kind: ErrorKind) -> &'static str {
    match kind {
        ErrorKind::RateLimit => "RESOURCE_EXHAUSTED",
        ErrorKind::Auth => "UNAUTHENTICATED",
        ErrorKind::Project => "FAILED_PRECONDITION",
        ErrorKind::Invalid => "INVALID_ARGUMENT",
        ErrorKind::NotFound => "NOT_FOUND",
        ErrorKind::Server => "INTERNAL",
        ErrorKind::Transport => "UNAVAILABLE",
    }
}

pub struct GeminiEmitter {
    pub stream: bool,
    model_version: String,
    prefill: String,
    deduper: PrefillDeduper,
    sent_role: bool,
    saw_content: bool,
    finish_reason: Option<String>,
    usage: Option<Value>,
    blocked: Option<String>,
    // Non-streaming aggregation.
    parts: Vec<Value>,
}

impl GeminiEmitter {
    pub fn new(model: &str, prefill: &str, stream: bool) -> Self {
        GeminiEmitter {
            stream,
            model_version: model.to_string(),
            prefill: prefill.to_string(),
            deduper: PrefillDeduper::new(prefill),
            sent_role: false,
            saw_content: false,
            finish_reason: None,
            usage: None,
            blocked: None,
            parts: Vec::new(),
        }
    }

    fn with_model(v: Value) -> Bytes {
        Bytes::from(format!("data: {v}\n\n"))
    }

    fn content_chunk(&self, parts: Vec<Value>) -> Value {
        json!({
            "candidates": [{
                "content": { "role": "model", "parts": parts },
                "index": 0,
            }],
            "modelVersion": self.model_version,
        })
    }

    /// Ensure the leading role/content chunks (incl. prefill part).
    fn ensure_role(&mut self, out: &mut Vec<Bytes>) {
        if self.sent_role {
            return;
        }
        self.sent_role = true;
        let mut lead = Vec::new();
        if !self.prefill.is_empty() {
            self.saw_content = true;
            lead.push(json!({ "text": self.prefill }));
        }
        out.push(Self::with_model(self.content_chunk(lead)));
    }

    pub fn on_event(&mut self, ev: &Ev) -> Vec<Bytes> {
        if !self.stream {
            self.aggregate(ev);
            return Vec::new();
        }
        let mut out = Vec::new();
        match ev {
            Ev::Text(t) => {
                self.ensure_role(&mut out);
                let text = self.deduper.feed(t);
                if !text.is_empty() {
                    self.saw_content = true;
                    out.push(Self::with_model(
                        self.content_chunk(vec![json!({ "text": text })]),
                    ));
                }
            }
            Ev::Thought(t) => {
                self.ensure_role(&mut out);
                self.saw_content = true;
                out.push(Self::with_model(
                    self.content_chunk(vec![json!({ "text": t, "thought": true })]),
                ));
            }
            Ev::Image { mime, b64 } => {
                self.ensure_role(&mut out);
                self.saw_content = true;
                out.push(Self::with_model(self.content_chunk(vec![json!({
                    "inlineData": { "mimeType": mime, "data": b64 }
                })])));
            }
            Ev::Finish(f) => {
                self.finish_reason = Some(f.clone());
                out.push(Self::with_model(json!({
                    "candidates": [{ "finishReason": f, "index": 0 }],
                    "modelVersion": self.model_version,
                })));
            }
            Ev::Usage(u) => {
                self.usage = Some(u.clone());
                out.push(Self::with_model(json!({
                    "usageMetadata": u,
                    "modelVersion": self.model_version,
                })));
            }
            Ev::Blocked(b) => {
                self.blocked = Some(b.clone());
                out.push(Self::with_model(json!({
                    "promptFeedback": { "blockReason": b },
                    "modelVersion": self.model_version,
                })));
            }
            Ev::Error(_) => unreachable!("errors routed through on_error"),
        }
        out
    }

    /// Stream end: flush deduper; empty responses get a visible diagnostic
    /// part (§13.4). No [DONE] — the connection closes (§10.3).
    pub fn on_stream_end(&mut self) -> Vec<Bytes> {
        let mut out = Vec::new();
        let flushed = self.deduper.flush();
        if !flushed.is_empty() {
            self.saw_content = true;
            out.push(Self::with_model(
                self.content_chunk(vec![json!({ "text": flushed })]),
            ));
        }
        if !self.saw_content && self.finish_reason.is_none() && self.blocked.is_none() {
            let note = "\n\n[aps2api] 上游流已结束但未输出任何正文。请检查上游凭据或稍后重试。";
            out.push(Self::with_model(
                self.content_chunk(vec![json!({ "text": note })]),
            ));
        }
        out
    }

    pub fn on_error(&mut self, e: &UpstreamError) -> Vec<Bytes> {
        vec![Self::with_model(json!({
            "error": {
                "code": e.status.unwrap_or(502),
                "message": crate::errs::client_message(e),
                "status": status_upper(e.kind),
            }
        }))]
    }

    fn aggregate(&mut self, ev: &Ev) {
        match ev {
            Ev::Text(t) => {
                self.saw_content = true;
                // merge adjacent text parts (spec §7.2 aggregation note)
                if let Some(Value::String(last)) =
                    self.parts.last_mut().and_then(|p| p.get_mut("text"))
                {
                    last.push_str(t);
                } else {
                    self.parts.push(json!({ "text": t }));
                }
            }
            Ev::Thought(t) => {
                self.saw_content = true;
                self.parts.push(json!({ "text": t, "thought": true }));
            }
            Ev::Image { mime, b64 } => {
                self.saw_content = true;
                self.parts
                    .push(json!({ "inlineData": { "mimeType": mime, "data": b64 } }));
            }
            Ev::Finish(f) => self.finish_reason = Some(f.clone()),
            Ev::Usage(u) => self.usage = Some(u.clone()),
            Ev::Blocked(b) => self.blocked = Some(b.clone()),
            Ev::Error(_) => {}
        }
    }

    /// Non-streaming: one aggregated GenerateContentResponse.
    pub fn take_result(&mut self) -> Value {
        let mut root = Map::new();
        let mut parts = self.parts.clone();
        if !self.prefill.is_empty() {
            let stitched = strip_overlap(&self.prefill, &{
                let merged: String = parts
                    .iter()
                    .filter_map(|p| p.get("text").and_then(Value::as_str))
                    .collect();
                merged
            });
            // Rebuild the parts list as: prefill part + stitched remainder
            // (preserving any image/thought parts that followed).
            parts.clear();
            self.saw_content = true;
            parts.push(json!({ "text": self.prefill }));
            if !stitched.is_empty() {
                parts.push(json!({ "text": stitched }));
            }
        }
        if parts.is_empty() && self.saw_content {
            // nothing to add
        } else if parts.is_empty() {
            let note = "\n\n[aps2api] 上游结束但未输出正文(可能被拦截或上游异常)。";
            parts.push(json!({ "text": note }));
        }
        let mut candidate = Map::new();
        candidate.insert("content".into(), json!({ "role": "model", "parts": parts }));
        candidate.insert("index".into(), json!(0));
        if let Some(f) = &self.finish_reason {
            candidate.insert("finishReason".into(), json!(f));
        }
        root.insert("candidates".into(), json!([Value::Object(candidate)]));
        if let Some(u) = &self.usage {
            root.insert("usageMetadata".into(), u.clone());
        }
        if let Some(b) = &self.blocked {
            root.insert("promptFeedback".into(), json!({ "blockReason": b }));
        }
        root.insert("modelVersion".into(), json!(self.model_version));
        Value::Object(root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_chunks_are_data_lines_without_done() {
        let mut em = GeminiEmitter::new("gemini-3.1-pro", "", true);
        let out = em.on_event(&Ev::Text("hi".into()));
        assert_eq!(out.len(), 2); // role chunk + text chunk
        let s = String::from_utf8_lossy(&out[1]);
        assert!(s.starts_with("data: "));
        assert!(s.contains(r#""text":"hi""#));
        assert!(s.contains(r#""modelVersion":"gemini-3.1-pro""#));
        let end = em.on_stream_end();
        assert!(end.is_empty()); // no [DONE], nothing left to flush
    }

    #[test]
    fn thought_flag_preserved() {
        let mut em = GeminiEmitter::new("m", "", true);
        let out = em.on_event(&Ev::Thought("deep".into()));
        assert_eq!(out.len(), 2); // leading role chunk + thought chunk
        let s = String::from_utf8_lossy(&out[1]);
        assert!(s.contains(r#""thought":true"#));
    }

    #[test]
    fn finish_and_usage_emitted_verbatim() {
        let mut em = GeminiEmitter::new("m", "", true);
        let o1 = em.on_event(&Ev::Finish("STOP".into()));
        assert!(String::from_utf8_lossy(&o1[0]).contains(r#""finishReason":"STOP""#));
        let o2 = em.on_event(&Ev::Usage(json!({"totalTokenCount": 9})));
        assert!(String::from_utf8_lossy(&o2[0]).contains(r#""usageMetadata""#));
    }

    #[test]
    fn error_shape_upper_status() {
        let mut em = GeminiEmitter::new("m", "", true);
        let e = UpstreamError {
            kind: ErrorKind::Auth,
            status: Some(403),
            message: "permission denied".into(),
        };
        let out = em.on_error(&e);
        let s = String::from_utf8_lossy(&out[0]);
        assert!(s.contains(r#""status":"UNAUTHENTICATED""#));
        assert!(s.contains("403"));
    }

    #[test]
    fn nonstream_aggregates_adjacent_text() {
        let mut em = GeminiEmitter::new("m", "", false);
        em.on_event(&Ev::Text("a".into()));
        em.on_event(&Ev::Text("b".into()));
        em.on_event(&Ev::Finish("STOP".into()));
        em.on_event(&Ev::Usage(
            json!({"promptTokenCount": 3, "candidatesTokenCount": 4, "totalTokenCount": 7}),
        ));
        let v = em.take_result();
        let parts = v["candidates"][0]["content"]["parts"].as_array().unwrap();
        assert_eq!(parts.len(), 1); // adjacent text merged
        assert_eq!(parts[0]["text"], "ab");
        assert_eq!(v["candidates"][0]["finishReason"], "STOP");
        assert_eq!(v["usageMetadata"]["totalTokenCount"], 7);
        assert_eq!(v["modelVersion"], "m");
    }

    #[test]
    fn blocked_recorded() {
        let mut em = GeminiEmitter::new("m", "", false);
        em.on_event(&Ev::Blocked("SAFETY".into()));
        let v = em.take_result();
        assert_eq!(v["promptFeedback"]["blockReason"], "SAFETY");
    }
}
