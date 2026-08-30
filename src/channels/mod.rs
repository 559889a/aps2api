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

/// Cap for one buffered SSE line: a `data:` payload carrying a base64 image
/// can reach ~27MB, so 64MB leaves headroom. A longer line means the peer is
/// not speaking the protocol — fail the stream instead of growing memory.
pub(crate) const MAX_SSE_LINE: usize = 64 * 1024 * 1024;

/// SSE pump (spec §13.3): one `data: <json>` per event; comment and empty
/// lines ignored; no `[DONE]` marker in the Gemini protocol. Lines are
/// decoded from COMPLETE line bytes only (byte-level buffering — a
/// multi-byte UTF-8 sequence split across chunk boundaries must never be
/// lossy-decoded per chunk; see the buffer note below).
pub(crate) async fn pump_sse<S, E>(stream: S, tx: mpsc::Sender<Ev>)
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: std::fmt::Display,
{
    pump_sse_with_limit(stream, tx, MAX_SSE_LINE).await
}

pub(crate) async fn pump_sse_with_limit<S, E>(mut stream: S, tx: mpsc::Sender<Ev>, max_line: usize)
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: std::fmt::Display,
{
    // BYTE buffer, never a String: a multi-byte UTF-8 sequence split across
    // TCP chunk boundaries must not be decoded per chunk — lossy-decoding a
    // fragment plants U+FFFD into the text (2026-08-30 live bug, occasional
    // `�` in upstream text). Complete lines only: b'\n' can never occur
    // inside a multi-byte sequence (continuation bytes are >= 0x80), so
    // line-wise decoding is boundary-safe, and a trailing partial line stays
    // raw bytes until its next chunk completes it.
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match stream.next().await {
            Some(Ok(bytes)) => {
                buf.extend_from_slice(&bytes);
                // Walk every complete line in place via a cursor, then reclaim
                // them all with ONE drain: draining per line memmoves the rest
                // of the chunk on each iteration — O(chunk^2) for line-heavy
                // chunks (many small SSE events coalesced by TCP).
                let mut consumed = 0usize;
                while let Some(rel) = buf[consumed..].iter().position(|&b| b == b'\n') {
                    let pos = consumed + rel;
                    let line = String::from_utf8_lossy(&buf[consumed..pos]);
                    if let Some(data) = line.strip_prefix("data:") {
                        let data = data.trim();
                        if !data.is_empty() && data != "[DONE]" {
                            emit_json(&tx, data).await;
                        }
                    }
                    // comment lines (`: ...`) and blank lines: ignored
                    consumed = pos + 1;
                }
                if consumed > 0 {
                    buf.drain(..consumed);
                }
                if buf.len() > max_line {
                    // No newline within the cap: protocol garbage, not SSE.
                    // Invalid (non-retryable): re-reading would flood again.
                    let _ = tx
                        .send(Ev::Error(UpstreamError {
                            kind: ErrorKind::Invalid,
                            status: None,
                            message: format!(
                                "upstream SSE line exceeded the buffer limit ({max_line} bytes)"
                            ),
                        }))
                        .await;
                    return;
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
/// top-level JSON objects; the bracket-balancing scanner extracts them as
/// borrowed slices and the channel-specific `extract` callback turns each
/// object into events. Raw bytes go in untouched — the scanner is
/// byte-native, and each yielded object is decoded from its COMPLETE byte
/// range, so multi-byte chars split across chunks survive intact.
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
                for range in scanner.feed(&bytes) {
                    match serde_json::from_slice::<Value>(scanner.object(range)) {
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
                if scanner.overflowed() {
                    let _ = tx
                        .send(Ev::Error(errs::classify_error(
                            None,
                            format!(
                                "upstream JSON object exceeded the scan buffer limit \
                                 ({} bytes)",
                                crate::streamscan::MAX_SCAN_BUFFER
                            ),
                        )))
                        .await;
                    return;
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

/// True when `part[key]` exists and carries any non-empty value at any depth
/// (batchGraphql proto3 shells hold empty strings/objects for every field).
fn shell_part_nonempty(part: &Value, key: &str) -> bool {
    fn any_nonempty(v: &Value) -> bool {
        match v {
            Value::Null => false,
            Value::String(s) => !s.is_empty(),
            Value::Object(m) => m.values().any(any_nonempty),
            Value::Array(a) => a.iter().any(any_nonempty),
            _ => true,
        }
    }
    part.get(key).is_some_and(any_nonempty)
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
                    // batchGraphql parts are proto3-style: EVERY field is
                    // present with an empty value (functionCall.name="",
                    // inlineData:{mimeType:"",data:""}, executableCode with
                    // enum-default strings, ...). Text extraction runs FIRST
                    // so shell fields can never swallow real content;
                    // tool/code/image fields only count when they carry
                    // actual content (live-tested 2026-08-30).
                    if let Some(text) = part.get("text").and_then(Value::as_str) {
                        if !text.is_empty() {
                            if thought_flag(part) {
                                out.push(Ev::Thought(text.to_string()));
                            } else {
                                out.push(Ev::Text(text.to_string()));
                            }
                            continue;
                        }
                    }
                    if part
                        .get("functionCall")
                        .and_then(|fc| fc.get("name"))
                        .and_then(Value::as_str)
                        .is_some_and(|n| !n.is_empty())
                    {
                        tracing::debug!("dropped functionCall part (no tool support)");
                        continue;
                    }
                    if let Some(inline) = part.get("inlineData") {
                        if let (Some(mime), Some(data)) = (
                            inline.get("mimeType").and_then(Value::as_str),
                            inline.get("data").and_then(Value::as_str),
                        ) {
                            if !mime.is_empty() && !data.is_empty() {
                                out.push(Ev::Image {
                                    mime: mime.to_string(),
                                    b64: data.to_string(),
                                });
                                continue;
                            }
                        }
                    }
                    if shell_part_nonempty(part, "executableCode")
                        || shell_part_nonempty(part, "codeExecutionResult")
                    {
                        tracing::debug!("dropped code-execution part (no tool support)");
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

    #[tokio::test]
    async fn sse_lines_parse_in_place() {
        let (tx, mut rx) = mpsc::channel::<Ev>(8);
        let payload = r#"{"candidates":[{"content":{"parts":[{"text":"hi"}]}}]}"#;
        let stream = futures_util::stream::iter(vec![Ok::<Bytes, std::convert::Infallible>(
            Bytes::from(format!(": comment\n\ndata: {payload}\n\ndata: [DONE]\n\n")),
        )]);
        pump_sse_with_limit(stream, tx, 1024).await;
        assert!(matches!(rx.recv().await, Some(Ev::Text(t)) if t == "hi"));
        assert!(rx.recv().await.is_none(), "comment/[DONE] produce nothing");
    }

    #[tokio::test]
    async fn oversized_sse_line_fails_the_stream_without_retry() {
        let (tx, mut rx) = mpsc::channel::<Ev>(8);
        let stream = futures_util::stream::iter(vec![Ok::<Bytes, std::convert::Infallible>(
            Bytes::from(format!("data: {}", "x".repeat(64))),
        )]);
        pump_sse_with_limit(stream, tx, 16).await;
        match rx.recv().await {
            Some(Ev::Error(e)) => {
                assert_eq!(e.kind, ErrorKind::Invalid, "floods must not be retryable");
            }
            other => panic!("expected error event, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn many_lines_in_one_chunk_all_parse() {
        // TCP coalesces several SSE events into one read; the cursor-based
        // line walk must emit every event exactly once, in order.
        let (tx, mut rx) = mpsc::channel::<Ev>(128);
        let body: String = (0..50)
            .map(|i| {
                format!(
                    "data: {{\"candidates\":[{{\"content\":{{\"parts\":[{{\"text\":\"{i}\"}}]}}}}]}}\n\n"
                )
            })
            .collect();
        let stream = futures_util::stream::iter(vec![Ok::<Bytes, std::convert::Infallible>(
            Bytes::from(body),
        )]);
        pump_sse_with_limit(stream, tx, 1 << 20).await;
        let mut seen = Vec::new();
        while let Some(Ev::Text(t)) = rx.recv().await {
            seen.push(t);
        }
        assert_eq!(seen.len(), 50);
        for (i, t) in seen.iter().enumerate() {
            assert_eq!(t, &i.to_string());
        }
    }

    #[tokio::test]
    async fn multibyte_chars_survive_any_chunk_split_sse() {
        // U+FFFD regression (2026-08-30): the pumps used to lossy-decode each
        // TCP chunk separately, corrupting a multi-byte char cut by the chunk
        // boundary into U+FFFD. Brute force: cut the SSE body at EVERY byte
        // offset (inside "你" = 3 bytes and "😀" = 4 bytes included).
        let body = format!(
            "data: {}\n\n",
            r#"{"candidates":[{"content":{"parts":[{"text":"你😀好"}]}}]}"#
        );
        let bytes = body.as_bytes().to_vec();
        for split in 1..bytes.len() {
            let (tx, mut rx) = mpsc::channel::<Ev>(8);
            let stream = futures_util::stream::iter(vec![
                Ok::<Bytes, std::convert::Infallible>(Bytes::copy_from_slice(&bytes[..split])),
                Ok::<Bytes, std::convert::Infallible>(Bytes::copy_from_slice(&bytes[split..])),
            ]);
            pump_sse_with_limit(stream, tx, 1 << 20).await;
            match rx.recv().await {
                Some(Ev::Text(t)) => assert_eq!(t, "你😀好", "split at byte {split}"),
                other => panic!("split at byte {split}: expected text event, got {other:?}"),
            }
            assert!(rx.recv().await.is_none(), "split at byte {split}");
        }
    }

    #[tokio::test]
    async fn multibyte_chars_survive_any_chunk_split_concat() {
        // Same regression through the cookie channel's real extractor
        // (batchGraphql wrapper -> extract_from_chunk).
        let body =
            r#"{"results":[{"data":{"candidates":[{"content":{"parts":[{"text":"你😀好"}]}}]}}]}"#;
        let bytes = body.as_bytes().to_vec();
        for split in 1..bytes.len() {
            let (tx, mut rx) = mpsc::channel::<Ev>(8);
            let stream = futures_util::stream::iter(vec![
                Ok::<Bytes, std::convert::Infallible>(Bytes::copy_from_slice(&bytes[..split])),
                Ok::<Bytes, std::convert::Infallible>(Bytes::copy_from_slice(&bytes[split..])),
            ]);
            pump_concat(stream, tx, cookie::cookie_extract).await;
            match rx.recv().await {
                Some(Ev::Text(t)) => assert_eq!(t, "你😀好", "split at byte {split}"),
                other => panic!("split at byte {split}: expected text event, got {other:?}"),
            }
            assert!(rx.recv().await.is_none(), "split at byte {split}");
        }
    }

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
    fn batchgraphql_proto3_shells_do_not_swallow_text() {
        // Live shape (2026-08-30): every field present with an empty value.
        // Text parts must survive; empty shells must not become drops/images.
        let chunk = json!({
            "candidates": [{ "content": { "role": "model", "parts": [
                {
                    "data": "text", "text": "PONG", "thought": false,
                    "thoughtSignature": "",
                    "inlineData": { "mimeType": "", "data": "" },
                    "fileData": { "mimeType": "", "fileUri": "" },
                    "functionCall": { "name": "", "args": "" }
                },
                {
                    "data": "text", "text": "-COOKIE", "thought": false,
                    "thoughtSignature": "",
                    "inlineData": { "mimeType": "", "data": "" },
                    "fileData": { "mimeType": "", "fileUri": "" },
                    "functionCall": { "name": "", "args": "" },
                    "executableCode": { "code": "", "language": "" },
                    "codeExecutionResult": { "outcome": "", "content": "" }
                }
            ]}, "finishReason": "FINISH_REASON_UNSPECIFIED" }],
            "promptFeedback": {}
        });
        let mut out = Vec::new();
        extract_from_chunk(&chunk, &mut out);
        assert_eq!(
            out.len(),
            2,
            "exactly two text events, no drops/images: {out:?}"
        );
        assert!(matches!(&out[0], Ev::Text(t) if t == "PONG"));
        assert!(matches!(&out[1], Ev::Text(t) if t == "-COOKIE"));
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
