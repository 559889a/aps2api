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
        Ok(chunk) => emit_chunk(tx, chunk).await,
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

/// Extraction over one parsed upstream chunk (both pumps converge here).
async fn emit_chunk(tx: &mpsc::Sender<Ev>, mut chunk: Value) {
    let mut events = Vec::new();
    extract_from_chunk(&mut chunk, &mut events);
    for ev in events {
        if tx.send(ev).await.is_err() {
            return;
        }
    }
}

fn transport_err(message: String) -> Ev {
    Ev::Error(UpstreamError {
        kind: ErrorKind::Transport,
        status: None,
        message,
        jar_refreshed_since_send: false,
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
                            jar_refreshed_since_send: false,
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
    F: FnMut(&mut Value, &mut Vec<Ev>),
{
    let mut scanner = crate::streamscan::JsonStreamScanner::new();
    loop {
        match stream.next().await {
            Some(Ok(bytes)) => {
                for range in scanner.feed(&bytes) {
                    match serde_json::from_slice::<Value>(scanner.object(range)) {
                        Ok(mut v) => {
                            let mut events = Vec::new();
                            extract(&mut v, &mut events);
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

/// Single-JSON pump: the whole body is one GenerateContentResponse. The body
/// is accumulated STREAMING with the same 64MB cap as the SSE line buffer —
/// `resp.bytes()` (unbounded whole-body read) would let a runaway upstream
/// allocate without limit (2026-08-31 GC hardening); crossing the cap fails
/// the attempt as non-retryable Invalid.
pub(crate) async fn pump_single<S, E>(stream: S, tx: mpsc::Sender<Ev>)
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: std::fmt::Display,
{
    pump_single_with_limit(stream, tx, MAX_SSE_LINE).await
}

pub(crate) async fn pump_single_with_limit<S, E>(
    mut stream: S,
    tx: mpsc::Sender<Ev>,
    max_bytes: usize,
) where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: std::fmt::Display,
{
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match stream.next().await {
            Some(Ok(bytes)) => {
                buf.extend_from_slice(&bytes);
                if buf.len() > max_bytes {
                    let _ = tx
                        .send(Ev::Error(UpstreamError {
                            kind: ErrorKind::Invalid,
                            status: None,
                            message: format!(
                                "upstream response body exceeded the buffer limit \
                                 ({max_bytes} bytes)"
                            ),
                            jar_refreshed_since_send: false,
                        }))
                        .await;
                    return;
                }
            }
            Some(Err(e)) => {
                let _ = tx
                    .send(transport_err(format!(
                        "failed to read upstream response: {e}"
                    )))
                    .await;
                return;
            }
            None => break,
        }
    }
    match serde_json::from_slice::<Value>(&buf) {
        Ok(chunk) => emit_chunk(&tx, chunk).await,
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

/// Byte cap for one upstream ERROR body (spec §13.2): error bodies carry a
/// short JSON message for logs and the client-facing hint — a hostile or
/// broken peer must not be able to grow proxy memory through an error
/// response (the fourth member of the unbounded-read family closed on
/// 2026-08-31, after the pump buffers, single-JSON bodies and image reads).
pub(crate) const MAX_ERROR_BODY: usize = 64 * 1024;

/// Read an error-response body as a lossy string, stopping hard at `cap`
/// bytes: the read is abandoned mid-stream once the cap is reached, so a
/// runaway error body can never allocate without bound. 64KB is orders of
/// magnitude beyond any real error message (which is truncated to 300 chars
/// for the client anyway).
pub(crate) async fn read_error_body<S, E>(stream: S) -> String
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: std::fmt::Display,
{
    read_error_body_with_limit(stream, MAX_ERROR_BODY).await
}

pub(crate) async fn read_error_body_with_limit<S, E>(mut stream: S, cap: usize) -> String
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: std::fmt::Display,
{
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(bytes) => {
                buf.extend_from_slice(&bytes);
                if buf.len() >= cap {
                    buf.truncate(cap);
                    break;
                }
            }
            Err(_) => break, // best-effort read: report what we got
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
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
///
/// Takes `&mut Value` and MOVES the fields it consumes (remove, not clone):
/// this runs once per streamed event — a `to_string()` per text part is a
/// heap allocation + copy on the hottest path in the process. The chunk is
/// parsed and dropped right after; nobody re-reads it.
pub fn extract_from_chunk(chunk: &mut Value, out: &mut Vec<Ev>) {
    // promptFeedback.blockReason (+ optional blockReasonMessage).
    if let Some(pf) = chunk
        .get_mut("promptFeedback")
        .and_then(Value::as_object_mut)
    {
        let reason = match pf.remove("blockReason") {
            Some(Value::String(r)) => Some(r),
            _ => None,
        };
        if let Some(reason) = reason {
            if !reason.is_empty() && !ends_with_unspecified(&reason) {
                let mut msg = reason;
                if let Some(Value::String(extra)) = pf.remove("blockReasonMessage") {
                    if !extra.is_empty() {
                        msg = format!("{msg}: {extra}");
                    }
                }
                out.push(Ev::Blocked(msg));
            }
        }
    }

    if let Some(candidates) = chunk.get_mut("candidates").and_then(Value::as_array_mut) {
        for cand in candidates {
            if let Some(content) = cand.get_mut("content").and_then(Value::as_object_mut) {
                if let Some(Value::Array(parts)) = content.get_mut("parts") {
                    for part in parts.iter_mut() {
                        // batchGraphql parts are proto3-style: EVERY field is
                        // present with an empty value (functionCall.name="",
                        // inlineData:{mimeType:"",data:""}, executableCode with
                        // enum-default strings, ...). Text extraction runs FIRST
                        // so shell fields can never swallow real content;
                        // tool/code/image fields only count when they carry
                        // actual content (live-tested 2026-08-30).
                        if let Some(Value::String(text)) = part.get_mut("text").map(Value::take) {
                            if !text.is_empty() {
                                if thought_flag(part) {
                                    out.push(Ev::Thought(text));
                                } else {
                                    out.push(Ev::Text(text));
                                }
                                continue;
                            }
                            // Empty shell text falls through to the field checks.
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
                        let (mime, data) =
                            match part.get_mut("inlineData").and_then(Value::as_object_mut) {
                                Some(inline) => {
                                    let mime = match inline.remove("mimeType") {
                                        Some(Value::String(m)) if !m.is_empty() => Some(m),
                                        _ => None,
                                    };
                                    let data = match inline.remove("data") {
                                        Some(Value::String(d)) if !d.is_empty() => Some(d),
                                        _ => None,
                                    };
                                    (mime, data)
                                }
                                None => (None, None),
                            };
                        if let (Some(mime), Some(data)) = (mime, data) {
                            out.push(Ev::Image { mime, b64: data });
                            continue;
                        }
                        if shell_part_nonempty(part, "executableCode")
                            || shell_part_nonempty(part, "codeExecutionResult")
                        {
                            tracing::debug!("dropped code-execution part (no tool support)");
                        }
                    }
                }
            }
            if let Some(Value::String(finish)) = cand.get_mut("finishReason").map(Value::take) {
                if !finish.is_empty() && !ends_with_unspecified(&finish) {
                    out.push(Ev::Finish(finish));
                }
            }
        }
    }

    // usageMetadata: move the whole object out when it is a non-empty map.
    if let Some(Value::Object(map)) = chunk.get_mut("usageMetadata").map(Value::take) {
        if !map.is_empty() {
            out.push(Ev::Usage(Value::Object(map)));
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
    async fn single_json_pump_parses_and_respects_the_cap() {
        // Split across chunks: streaming accumulation must reassemble and
        // parse the complete single-JSON body.
        let body = r#"{"candidates":[{"content":{"parts":[{"text":"hi"}]}}]}"#;
        let bytes = body.as_bytes();
        let (tx, mut rx) = mpsc::channel::<Ev>(8);
        let stream = futures_util::stream::iter(vec![
            Ok::<Bytes, std::convert::Infallible>(Bytes::copy_from_slice(&bytes[..10])),
            Ok::<Bytes, std::convert::Infallible>(Bytes::copy_from_slice(&bytes[10..])),
        ]);
        pump_single(stream, tx).await;
        assert!(matches!(rx.recv().await, Some(Ev::Text(t)) if t == "hi"));
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn single_json_pump_over_the_cap_fails_without_retry() {
        let (tx, mut rx) = mpsc::channel::<Ev>(8);
        let stream = futures_util::stream::iter(vec![
            Ok::<Bytes, std::convert::Infallible>(Bytes::from_static(b"{\"pad\":\"")),
            Ok::<Bytes, std::convert::Infallible>(Bytes::from("x".repeat(32))),
        ]);
        pump_single_with_limit(stream, tx, 16).await;
        match rx.recv().await {
            Some(Ev::Error(e)) => {
                assert_eq!(e.kind, ErrorKind::Invalid, "floods must not be retryable");
            }
            other => panic!("expected error event, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn single_json_pump_invalid_json_is_classified() {
        let (tx, mut rx) = mpsc::channel::<Ev>(8);
        let stream = futures_util::stream::iter(vec![Ok::<Bytes, std::convert::Infallible>(
            Bytes::from_static(b"not json at all"),
        )]);
        pump_single(stream, tx).await;
        match rx.recv().await {
            Some(Ev::Error(_)) => {}
            other => panic!("expected error event, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn error_body_read_stops_at_the_cap() {
        // A runaway error body must be abandoned mid-stream at the cap, not
        // buffered whole (memory red line; the follow-up chunk never lands).
        let stream = futures_util::stream::iter(vec![
            Ok::<Bytes, std::convert::Infallible>(Bytes::from("A".repeat(10))),
            Ok::<Bytes, std::convert::Infallible>(Bytes::from("B".repeat(10))),
        ]);
        let body = read_error_body_with_limit(stream, 12).await;
        assert_eq!(body.len(), 12);
        assert!(body.starts_with("AAAAAAAAAA"));
    }

    #[tokio::test]
    async fn error_body_read_short_and_erroring_bodies() {
        let stream = futures_util::stream::iter(vec![Ok::<Bytes, std::convert::Infallible>(
            Bytes::from_static(b"short"),
        )]);
        assert_eq!(read_error_body_with_limit(stream, 64).await, "short");
        // A transport error mid-read keeps what was received so far.
        let stream = futures_util::stream::iter(vec![
            Ok::<Bytes, String>(Bytes::from_static(b"par")),
            Err("connection reset".to_string()),
        ]);
        assert_eq!(read_error_body_with_limit(stream, 64).await, "par");
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
        let mut chunk = json!({
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
        extract_from_chunk(&mut chunk, &mut out);
        assert!(matches!(&out[0], Ev::Thought(t) if t == "thinking out loud"));
        assert!(matches!(&out[1], Ev::Text(t) if t == "answer"));
        assert!(matches!(&out[2], Ev::Finish(f) if f == "STOP"));
        assert!(matches!(&out[3], Ev::Usage(_)));
    }

    #[test]
    fn unspecified_defaults_are_filtered() {
        let mut chunk = json!({
            "candidates": [{ "content": {"parts": [{"text": "x"}]}, "finishReason": "FINISH_REASON_UNSPECIFIED" }],
            "promptFeedback": { "blockReason": "BLOCK_REASON_UNSPECIFIED" }
        });
        let mut out = Vec::new();
        extract_from_chunk(&mut chunk, &mut out);
        assert_eq!(out.len(), 1);
        assert!(matches!(&out[0], Ev::Text(_)));
    }

    #[test]
    fn thought_string_false_is_falsy_but_true_strings_accepted() {
        let mut chunk = json!({
            "candidates": [{ "content": { "parts": [
                { "text": "a", "thought": "true" },
                { "text": "b", "thought": "True" },
                { "text": "c", "thought": "false" }
            ]}}]
        });
        let mut out = Vec::new();
        extract_from_chunk(&mut chunk, &mut out);
        assert!(matches!(&out[0], Ev::Thought(_)));
        assert!(matches!(&out[1], Ev::Thought(_)));
        assert!(matches!(&out[2], Ev::Text(_)));
    }

    #[test]
    fn function_call_and_code_parts_dropped() {
        let mut chunk = json!({
            "candidates": [{ "content": { "parts": [
                { "functionCall": { "name": "f", "args": {} } },
                { "executableCode": { "code": "x" } },
                { "text": "keep" }
            ]}}]
        });
        let mut out = Vec::new();
        extract_from_chunk(&mut chunk, &mut out);
        assert_eq!(out.len(), 1);
        assert!(matches!(&out[0], Ev::Text(t) if t == "keep"));
    }

    #[test]
    fn batchgraphql_proto3_shells_do_not_swallow_text() {
        // Live shape (2026-08-30): every field present with an empty value.
        // Text parts must survive; empty shells must not become drops/images.
        let mut chunk = json!({
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
        extract_from_chunk(&mut chunk, &mut out);
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
        let mut chunk = json!({
            "promptFeedback": { "blockReason": "SAFETY", "blockReasonMessage": "blocked" }
        });
        let mut out = Vec::new();
        extract_from_chunk(&mut chunk, &mut out);
        assert!(matches!(&out[0], Ev::Blocked(m) if m.contains("SAFETY") && m.contains("blocked")));
    }

    #[test]
    fn image_part_extracted() {
        let mut chunk = json!({
            "candidates": [{ "content": { "parts": [
                { "inlineData": { "mimeType": "image/png", "data": "AAA" } }
            ]}}]
        });
        let mut out = Vec::new();
        extract_from_chunk(&mut chunk, &mut out);
        assert!(matches!(&out[0], Ev::Image { mime, b64 } if mime == "image/png" && b64 == "AAA"));
    }
}
