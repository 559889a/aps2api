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
    /// part (§13.4, three-branch like the OAI port). No [DONE] — the
    /// connection closes (§10.3).
    pub fn on_stream_end(&mut self) -> Vec<Bytes> {
        let mut out = Vec::new();
        let flushed = self.deduper.flush();
        if !flushed.is_empty() {
            self.saw_content = true;
            out.push(Self::with_model(
                self.content_chunk(vec![json!({ "text": flushed })]),
            ));
        }
        if !self.saw_content && self.blocked.is_none() {
            // §13.4: never close silently. The finishReason chunk (if any)
            // already went out when the event arrived, so the note is
            // appended at stream end as the visible hint; a Blocked stream
            // already emitted its promptFeedback chunk, which is visible by
            // itself. Thought-only streams are not silent either.
            let note = self.empty_diagnosis();
            out.push(Self::with_model(
                self.content_chunk(vec![json!({ "text": note })]),
            ));
        }
        out
    }

    /// §13.4 three-branch empty-response diagnosis (mirrors oai::emit).
    fn empty_diagnosis(&self) -> String {
        if self.blocked.is_some() {
            return "\n\n[aps2api] 上游拦截了本次回复(promptFeedback.blockReason),没有正文输出。"
                .to_string();
        }
        match &self.finish_reason {
            Some(f) => format!("\n\n[aps2api] 上游结束但未输出正文(finishReason={f})。"),
            None => {
                "\n\n[aps2api] 上游流已结束但未输出任何正文。请检查上游凭据或稍后重试。".to_string()
            }
        }
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
                // Merge adjacent BODY text parts only (spec §7.2 aggregation
                // note): the previous part may be a thought part
                // ({text, thought:true}) — appending body text there would
                // corrupt the thought text AND flag the merged body as a
                // thought. Thought streams end with a body turn, so without
                // this guard every thinking model's non-streaming reply
                // tripped it (2026-08-30 fix).
                let mergeable = self.parts.last().is_some_and(|p| {
                    p.get("text").is_some()
                        && p.get("thought").is_none()
                        && p.get("inlineData").is_none()
                });
                if mergeable {
                    if let Some(Value::String(last)) =
                        self.parts.last_mut().and_then(|p| p.get_mut("text"))
                    {
                        last.push_str(t);
                    }
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
        let mut parts = std::mem::take(&mut self.parts);
        if !self.prefill.is_empty() {
            // Stitch the prefill onto the BODY text only (parts without the
            // thought flag); thought parts keep their flag and image parts
            // pass through untouched — mirroring the OAI port's
            // reasoning/content split. Rebuilt order: prefill part first,
            // every non-body part in event order, the deduped body text at
            // the last body-text position (upstream order is usually
            // thoughts -> text, which also matches the streaming replay:
            // prefill, then thoughts, then text).
            let body: String = parts
                .iter()
                .filter(|p| p.get("thought").is_none())
                .filter_map(|p| p.get("text").and_then(Value::as_str))
                .collect();
            let stitched = strip_overlap(&self.prefill, &body);
            self.saw_content = true;
            let last_body = parts
                .iter()
                .rposition(|p| p.get("thought").is_none() && p.get("text").is_some());
            let mut rebuilt = vec![json!({ "text": self.prefill })];
            for (i, p) in parts.into_iter().enumerate() {
                let is_body_text = p.get("thought").is_none() && p.get("text").is_some();
                if !is_body_text {
                    rebuilt.push(p);
                } else if Some(i) == last_body && !stitched.is_empty() {
                    // Matches at most once (unique position): move the stitched
                    // body text in place of the last body part.
                    rebuilt.push(json!({ "text": std::mem::take(&mut stitched) }));
                }
            }
            parts = rebuilt;
        }
        if parts.is_empty() {
            // §13.4 three-branch diagnosis (same texts as the OAI port).
            let note = self.empty_diagnosis();
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
            jar_refreshed_since_send: false,
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

    #[test]
    fn nonstream_prefill_preserves_thought_and_image_parts() {
        // Regression: the prefill rebuild used to clear the parts list and
        // re-push text only — thought parts (flag AND text) and image parts
        // were silently dropped, and thought text leaked into the body.
        let mut em = GeminiEmitter::new("m", "The capital of France is", false);
        em.on_event(&Ev::Thought("thinking".into()));
        em.on_event(&Ev::Text(" Paris.".into()));
        em.on_event(&Ev::Image {
            mime: "image/png".into(),
            b64: "AA".into(),
        });
        em.on_event(&Ev::Finish("STOP".into()));
        let v = em.take_result();
        let parts = v["candidates"][0]["content"]["parts"].as_array().unwrap();
        // prefill part, thought part (flag kept, text NOT merged into the
        // body), deduped body text, image part — all four survive.
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0]["text"], "The capital of France is");
        assert_eq!(parts[1]["text"], "thinking");
        assert_eq!(parts[1]["thought"], true);
        assert_eq!(parts[2]["text"], " Paris.");
        assert_eq!(parts[3]["inlineData"]["mimeType"], "image/png");
    }

    #[test]
    fn nonstream_prefill_cuts_full_restatement() {
        let mut em = GeminiEmitter::new("m", "The capital of France is", false);
        // Model restated the whole prefill plus its continuation.
        em.on_event(&Ev::Text("The capital of France is Paris.".into()));
        let v = em.take_result();
        let parts = v["candidates"][0]["content"]["parts"].as_array().unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0]["text"], "The capital of France is");
        assert_eq!(parts[1]["text"], " Paris.");
    }

    #[test]
    fn nonstream_prefill_without_body_keeps_thoughts() {
        // Prefill present, upstream produced only thoughts: the response is
        // the prefill plus the thought parts — no phantom body part.
        let mut em = GeminiEmitter::new("m", "half-written", false);
        em.on_event(&Ev::Thought("pondering".into()));
        let v = em.take_result();
        let parts = v["candidates"][0]["content"]["parts"].as_array().unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0]["text"], "half-written");
        assert_eq!(parts[1]["text"], "pondering");
        assert_eq!(parts[1]["thought"], true);
    }

    #[test]
    fn nonstream_body_text_never_merges_into_thought_part() {
        // Regression (2026-08-30): aggregate() appended body text onto
        // parts.last_mut()'s "text" field unconditionally — when the last
        // part was a thought part, the body landed inside the thought text
        // and was flagged as a thought itself. Thinking models always emit
        // thoughts first, so every non-streaming reply tripped this.
        let mut em = GeminiEmitter::new("m", "", false);
        em.on_event(&Ev::Thought("thinking".into()));
        em.on_event(&Ev::Text("answer".into()));
        em.on_event(&Ev::Text(" continues".into()));
        let v = em.take_result();
        let parts = v["candidates"][0]["content"]["parts"].as_array().unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0]["text"], "thinking");
        assert_eq!(parts[0]["thought"], true);
        assert_eq!(parts[1]["text"], "answer continues");
        assert!(parts[1].get("thought").is_none());
    }

    #[test]
    fn empty_response_diagnosis_is_three_branch() {
        // Blocked -> interception note; finishReason -> note carrying the
        // reason; nothing at all -> generic hint (§13.4, aligned with OAI).
        let mut em = GeminiEmitter::new("m", "", false);
        em.on_event(&Ev::Blocked("SAFETY".into()));
        let v = em.take_result();
        let text = v["candidates"][0]["content"]["parts"][0]["text"]
            .as_str()
            .unwrap();
        assert!(text.contains("拦截"));

        let mut em = GeminiEmitter::new("m", "", true);
        let _ = em.on_event(&Ev::Finish("MAX_TOKENS".into()));
        let end = em.on_stream_end();
        let joined = end
            .iter()
            .map(|b| String::from_utf8_lossy(b).to_string())
            .collect::<String>();
        assert!(
            joined.contains("finishReason=MAX_TOKENS"),
            "note must carry the finish reason: {joined}"
        );
        // Stream that produced nothing at all: generic hint.
        let mut em = GeminiEmitter::new("m", "", true);
        let end = em.on_stream_end();
        let joined = end
            .iter()
            .map(|b| String::from_utf8_lossy(b).to_string())
            .collect::<String>();
        assert!(joined.contains("未输出任何正文"));
    }
}
