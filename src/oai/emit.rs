//! OAI response emission (spec §9.4): internal events -> SSE chunks or a
//! non-streaming chat.completion JSON. Prefill stitching (role chunk +
//! prefill content, then the Deduper) happens here.

use bytes::Bytes;
use serde_json::{json, Value};

use crate::ir::{Ev, UpstreamError};
use crate::prefill::{strip_overlap, PrefillDeduper};

fn map_finish_reason(reason: &str) -> &'static str {
    match reason {
        "MAX_TOKENS" => "length",
        "SAFETY" | "PROHIBITED_CONTENT" | "RECITATION" | "BLOCKLIST" | "SPII" | "IMAGE_SAFETY" => {
            "content_filter"
        }
        // STOP and absent reason both mean a normal stop.
        _ => "stop",
    }
}

fn map_usage(usage: &Value) -> Value {
    let pick = |k: &str| usage.get(k).and_then(Value::as_i64).unwrap_or(0);
    json!({
        "prompt_tokens": pick("promptTokenCount"),
        "completion_tokens": pick("candidatesTokenCount"),
        "total_tokens": pick("totalTokenCount"),
    })
}

/// Internal events -> wire output, in streaming or aggregated mode.
pub struct OaiEmitter {
    pub stream: bool,
    id: String,
    created: i64,
    model: String,
    include_usage: bool,
    prefill: String,
    deduper: PrefillDeduper,
    sent_role: bool,
    saw_content: bool,
    finish_reason: Option<&'static str>,
    usage: Option<Value>,
    blocked_seen: bool,
    // Non-streaming aggregation.
    content: String,
    reasoning: String,
}

impl OaiEmitter {
    pub fn new(model: &str, include_usage: bool, prefill: &str, stream: bool) -> Self {
        OaiEmitter {
            stream,
            id: format!(
                "chatcmpl-{}-{:08x}",
                chrono::Utc::now().timestamp(),
                rand::random::<u32>()
            ),
            created: chrono::Utc::now().timestamp(),
            model: model.to_string(),
            include_usage,
            prefill: prefill.to_string(),
            deduper: PrefillDeduper::new(prefill),
            sent_role: false,
            saw_content: false,
            finish_reason: None,
            usage: None,
            blocked_seen: false,
            content: String::new(),
            reasoning: String::new(),
        }
    }

    fn chunk_bytes(&self, delta: &Value, finish_reason: Option<&str>) -> Bytes {
        let mut choices = json!({ "index": 0, "delta": delta, "finish_reason": finish_reason });
        if finish_reason.is_some() {
            choices["delta"] = json!({});
        }
        Bytes::from(format!(
            "data: {}\n\n",
            json!({
                "id": self.id,
                "object": "chat.completion.chunk",
                "created": self.created,
                "model": self.model,
                "choices": [choices],
            })
        ))
    }

    fn data_prefix(v: Value) -> Bytes {
        Bytes::from(format!("data: {v}\n\n"))
    }

    /// Ensure the leading role chunk (and the prefill content chunk) are out.
    fn ensure_role(&mut self, out: &mut Vec<Bytes>) {
        if self.sent_role {
            return;
        }
        self.sent_role = true;
        out.push(self.chunk_bytes(&json!({ "role": "assistant" }), None));
        if !self.prefill.is_empty() {
            self.saw_content = true;
            out.push(self.chunk_bytes(&json!({ "content": self.prefill }), None));
        }
    }

    /// Stream mode: bytes to emit for one event.
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
                    out.push(self.chunk_bytes(&json!({ "content": text }), None));
                }
            }
            Ev::Thought(t) => {
                self.ensure_role(&mut out);
                self.saw_content = true;
                out.push(self.chunk_bytes(&json!({ "reasoning_content": t }), None));
            }
            Ev::Image { mime, b64 } => {
                self.ensure_role(&mut out);
                self.saw_content = true;
                out.push(self.chunk_bytes(
                    &json!({ "content": format!("![Generated Image](data:{mime};base64,{b64})") }),
                    None,
                ));
            }
            Ev::Finish(f) => {
                self.finish_reason = Some(map_finish_reason(f));
            }
            Ev::Usage(u) => self.usage = Some(map_usage(u)),
            Ev::Blocked(_) => {
                // finalize as content_filter in on_stream_end
            }
            Ev::Error(_) => unreachable!("errors routed through on_error"),
        }
        out
    }

    /// Stream mode: flush the deduper, emit the finish chunk (+ usage tail),
    /// and [DONE]. Also implements §13.4: an empty response gets a visible
    /// diagnostic instead of a silent close.
    pub fn on_stream_end(&mut self) -> Vec<Bytes> {
        let mut out = Vec::new();
        let flushed = self.deduper.flush();
        if !flushed.is_empty() {
            self.saw_content = true;
            out.push(self.chunk_bytes(&json!({ "content": flushed }), None));
        }
        if !self.saw_content {
            // No text/image at all: surface a diagnostic (§13.4).
            let note = self.empty_diagnosis();
            out.push(self.chunk_bytes(&json!({ "content": note }), None));
        }
        let finish = self.finish_reason.unwrap_or(if self.blocked_seen {
            "content_filter"
        } else {
            "stop"
        });
        out.push(self.chunk_bytes(&json!({}), Some(finish)));
        if self.include_usage {
            let usage = self.usage.clone().unwrap_or_else(
                || json!({"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}),
            );
            out.push(Self::data_prefix(json!({
                "id": self.id,
                "object": "chat.completion.chunk",
                "created": self.created,
                "model": self.model,
                "choices": [],
                "usage": usage,
            })));
        }
        out.push(Bytes::from_static(b"data: [DONE]\n\n"));
        out
    }

    /// Stream mode: terminal error -> error event + [DONE] (§14.3).
    pub fn on_error(&mut self, e: &UpstreamError) -> Vec<Bytes> {
        let mut out = self.dedup_flush_pending();
        out.push(Self::data_prefix(json!({
            "error": {
                "message": crate::errs::client_message(e),
                "type": "upstream_error",
                "code": e.status.unwrap_or(502),
            }
        })));
        out.push(Bytes::from_static(b"data: [DONE]\n\n"));
        out
    }

    fn dedup_flush_pending(&mut self) -> Vec<Bytes> {
        let mut out = Vec::new();
        let flushed = self.deduper.flush();
        if !flushed.is_empty() {
            self.saw_content = true;
            out.push(self.chunk_bytes(&json!({ "content": flushed }), None));
        }
        out
    }

    fn aggregate(&mut self, ev: &Ev) {
        match ev {
            Ev::Text(t) => {
                self.saw_content = true;
                self.content.push_str(t);
            }
            Ev::Thought(t) => self.reasoning.push_str(t),
            Ev::Image { mime, b64 } => {
                self.saw_content = true;
                self.content
                    .push_str(&format!("![Generated Image](data:{mime};base64,{b64})"));
            }
            Ev::Finish(f) => self.finish_reason = Some(map_finish_reason(f)),
            Ev::Usage(u) => self.usage = Some(map_usage(u)),
            Ev::Blocked(_) => self.blocked_seen = true,
            Ev::Error(_) => {}
        }
    }

    fn empty_diagnosis(&self) -> String {
        if self.blocked_seen {
            return "\n\n[aps2api] 上游拦截了本次回复(promptFeedback.blockReason),没有正文输出。"
                .to_string();
        }
        match self.finish_reason {
            Some(f) => format!("\n\n[aps2api] 上游结束但未输出正文(finishReason={f})。"),
            None => {
                "\n\n[aps2api] 上游流已结束但未输出任何正文。请检查上游凭据或稍后重试。".to_string()
            }
        }
    }

    /// Non-streaming: final chat.completion JSON (spec §9.4) with prefill
    /// stitched back (final = prefill + deduped continuation, spec §11.3) and
    /// a §13.4 diagnostic when empty.
    pub fn take_result(&mut self) -> Value {
        // Prefill always leads the body; the continuation has the prefill's
        // overlap removed. When the model restated the whole prefill,
        // strip_overlap cuts it back to just the remainder.
        let mut content = format!(
            "{}{}",
            self.prefill,
            strip_overlap(&self.prefill, &self.content)
        );
        if content.is_empty() && self.reasoning.is_empty() {
            content = self.empty_diagnosis();
        } else if content.is_empty() && !self.reasoning.is_empty() {
            // Thought only: keep it as reasoning_content, body stays empty.
        }
        let mut message = json!({ "role": "assistant", "content": content });
        if !self.reasoning.is_empty() {
            message["reasoning_content"] = json!(self.reasoning);
        }
        let finish = self.finish_reason.unwrap_or(if self.blocked_seen {
            "content_filter"
        } else {
            "stop"
        });
        let usage = self.usage.clone().unwrap_or_else(
            || json!({"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}),
        );
        json!({
            "id": self.id,
            "object": "chat.completion",
            "created": self.created,
            "model": self.model,
            "choices": [{ "index": 0, "message": message, "finish_reason": finish }],
            "usage": usage,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finish_reason_mapping() {
        assert_eq!(map_finish_reason("STOP"), "stop");
        assert_eq!(map_finish_reason("MAX_TOKENS"), "length");
        assert_eq!(map_finish_reason("SAFETY"), "content_filter");
        assert_eq!(map_finish_reason("RECITATION"), "content_filter");
        assert_eq!(map_finish_reason(""), "stop");
    }

    #[test]
    fn streaming_role_then_text_then_done() {
        let mut em = OaiEmitter::new("gemini-3.1-pro", false, "", true);
        let out = em.on_event(&Ev::Text("hello".into()));
        assert_eq!(out.len(), 2); // role chunk + content chunk
        let s = String::from_utf8_lossy(&out[0]);
        assert!(s.starts_with("data: "));
        assert!(s.contains(r#""role":"assistant""#));
        assert!(s.contains(r#""model":"gemini-3.1-pro""#));
        let s2 = String::from_utf8_lossy(&out[1]);
        assert!(s2.contains(r#""content":"hello""#));

        let _ = em.on_event(&Ev::Finish("STOP".into()));
        let end = em.on_stream_end();
        let joined = end
            .iter()
            .map(|b| String::from_utf8_lossy(b).to_string())
            .collect::<String>();
        assert!(joined.contains(r#""finish_reason":"stop""#));
        assert!(joined.ends_with("data: [DONE]\n\n"));
    }

    #[test]
    fn prefill_content_replayed_and_dedup_cuts_restatement() {
        let mut em = OaiEmitter::new("m", false, "Once upon", true);
        let out = em.on_event(&Ev::Text("Once upon a time".into()));
        // role chunk, prefill content chunk, then deduper resolve
        let joined = out
            .iter()
            .map(|b| String::from_utf8_lossy(b).to_string())
            .collect::<String>();
        assert!(joined.contains(r#""content":"Once upon""#));
        assert!(joined.contains("a time"));
        assert!(!joined.contains("Once upon a timeOnce"));
    }

    #[test]
    fn include_usage_adds_tail() {
        let mut em = OaiEmitter::new("m", true, "", true);
        let _ = em.on_event(&Ev::Usage(
            json!({"promptTokenCount": 5, "candidatesTokenCount": 7, "totalTokenCount": 12}),
        ));
        let _ = em.on_event(&Ev::Finish("STOP".into()));
        let end = em.on_stream_end();
        let joined = end
            .iter()
            .map(|b| String::from_utf8_lossy(b).to_string())
            .collect::<String>();
        assert!(joined.contains(r#""prompt_tokens":5"#));
        assert!(joined.contains(r#""choices":[]"#));
    }

    #[test]
    fn nonstream_aggregates_reasoning_and_usage() {
        let mut em = OaiEmitter::new("m", false, "", false);
        em.on_event(&Ev::Thought("thinking".into()));
        em.on_event(&Ev::Text("answer".into()));
        em.on_event(&Ev::Finish("MAX_TOKENS".into()));
        em.on_event(&Ev::Usage(
            json!({"promptTokenCount": 1, "candidatesTokenCount": 2, "totalTokenCount": 3}),
        ));
        let v = em.take_result();
        assert_eq!(v["choices"][0]["message"]["content"], "answer");
        assert_eq!(v["choices"][0]["message"]["reasoning_content"], "thinking");
        assert_eq!(v["choices"][0]["finish_reason"], "length");
        assert_eq!(v["usage"]["total_tokens"], 3);
    }

    #[test]
    fn nonstream_prefill_is_stitched_before_continuation() {
        let mut em = OaiEmitter::new("m", false, "The capital of France is", false);
        em.on_event(&Ev::Text(" Paris.".into()));
        let v = em.take_result();
        assert_eq!(
            v["choices"][0]["message"]["content"],
            "The capital of France is Paris."
        );
    }

    #[test]
    fn nonstream_full_restatement_keeps_single_prefill() {
        let mut em = OaiEmitter::new("m", false, "The capital of France is", false);
        // Model restated the whole prefill plus its continuation.
        em.on_event(&Ev::Text("The capital of France is Paris.".into()));
        let v = em.take_result();
        assert_eq!(
            v["choices"][0]["message"]["content"],
            "The capital of France is Paris."
        );
    }

    #[test]
    fn error_tail_has_message_and_done() {
        let mut em = OaiEmitter::new("m", false, "", true);
        let e = UpstreamError {
            kind: crate::ir::ErrorKind::RateLimit,
            status: Some(429),
            message: "quota".into(),
            jar_refreshed_since_send: false,
        };
        let out = em.on_error(&e);
        let joined = out
            .iter()
            .map(|b| String::from_utf8_lossy(b).to_string())
            .collect::<String>();
        assert!(joined.contains(r#""error""#));
        assert!(joined.contains("429"));
        assert!(joined.ends_with("data: [DONE]\n\n"));
    }
}
