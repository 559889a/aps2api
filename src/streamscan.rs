//! Bracket-balanced streaming JSON object extractor (spec §13.1).
//!
//! batchGraphql responses are neither SSE nor a JSON array: consecutive JSON
//! objects are simply concatenated, e.g. `{"results":[..]}{"results":[..]}`.
//! An incremental state machine walks each chunk ONCE (O(bytes) per chunk —
//! no rescans, unlike a restart-from-scratch matcher), hands out one
//! top-level object at a time as borrowed slices (zero copy), tolerates
//! objects split across chunks, and handles braces inside strings (with
//! escape handling). One unterminated object is capped at MAX_SCAN_BUFFER
//! bytes: protocol runaway drops the buffer and flags the scanner so the
//! pump can fail the stream instead of growing memory without bound.
//!
//! The scanner is BYTE-native on purpose: a multi-byte UTF-8 sequence split
//! across TCP chunk boundaries must never be decoded per chunk (lossy-
//! decoding a fragment plants U+FFFD into the text — 2026-08-30 live bug).
//! The state machine only inspects ASCII structural bytes (`{ } " \\`);
//! bytes >= 0x80 are inert, so feeding raw bytes is equivalent. A yielded
//! object is COMPLETE (its closing `}` was received), so its byte range
//! always contains whole multi-byte sequences and parses losslessly.

/// Cap for one buffered top-level object (the incomplete object pending
/// across chunks). batchGraphql chunks carry at most a few MB (base64
/// images); 64MB is far beyond anything legitimate.
pub const MAX_SCAN_BUFFER: usize = 64 * 1024 * 1024;

/// Feed raw bytes; yields each complete top-level JSON object as a
/// (start, end) INCLUSIVE byte range into the scanner's buffer — read it
/// zero-copy via [`JsonStreamScanner::object`]. Ranges are valid until the
/// next `feed` call (the drain reclaims consumed bytes); consumed bytes are
/// dropped lazily at the next call.
#[derive(Debug)]
pub struct JsonStreamScanner {
    buf: Vec<u8>,
    /// Bytes before this index are dead (garbage or consumed objects);
    /// drained at the start of the next feed.
    consumed: usize,
    /// Start index of the object currently open (None = none open).
    object_start: Option<usize>,
    depth: i64,
    in_string: bool,
    escape: bool,
    /// Bytes already walked by the state machine; the next scan resumes here.
    scanned: usize,
    overflowed: bool,
    max_buffer: usize,
}

impl Default for JsonStreamScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl JsonStreamScanner {
    pub fn new() -> Self {
        Self::with_limit(MAX_SCAN_BUFFER)
    }

    pub fn with_limit(max_buffer: usize) -> Self {
        JsonStreamScanner {
            buf: String::new(),
            consumed: 0,
            object_start: None,
            depth: 0,
            in_string: false,
            escape: false,
            scanned: 0,
            overflowed: false,
            max_buffer,
        }
    }

    /// True after a buffered object exceeded `max_buffer` (the buffer was
    /// dropped; the scanner resyncs on the next `{`).
    pub fn overflowed(&self) -> bool {
        self.overflowed
    }

    pub fn feed(&mut self, chunk: &[u8]) -> Vec<(usize, usize)> {
        // Drop dead bytes from previous rounds first: the buffer only ever
        // holds live data, bounded by max_buffer + one chunk.
        if self.consumed > 0 {
            self.buf.drain(..self.consumed);
            self.scanned -= self.consumed;
            if let Some(start) = self.object_start {
                self.object_start = Some(start - self.consumed);
            }
            self.consumed = 0;
        }
        self.buf.extend_from_slice(chunk);

        let mut out = Vec::new();
        let bytes = self.buf.as_slice();
        let (mut depth, mut in_string, mut escape) = (self.depth, self.in_string, self.escape);
        let mut object_start = self.object_start;
        let mut consumed = self.consumed;
        // The absolute byte index IS the semantic value (recorded into the
        // yielded ranges), hence enumerate().skip(...) rather than slicing.
        for (i, &b) in bytes.iter().enumerate().skip(self.scanned) {
            if depth == 0 {
                // Outside any object only `{` matters: noise — including
                // stray quotes, braces and backslashes — is skipped verbatim.
                if b == b'{' {
                    object_start = Some(i);
                    depth = 1;
                    in_string = false;
                    escape = false;
                }
                continue;
            }
            if escape {
                escape = false;
            } else if in_string {
                if b == b'\\' {
                    escape = true;
                } else if b == b'"' {
                    in_string = false;
                }
            } else if b == b'"' {
                in_string = true;
            } else if b == b'{' {
                depth += 1;
            } else if b == b'}' {
                depth -= 1;
                if depth == 0 {
                    let start = object_start.take().unwrap_or(0);
                    out.push((start, i));
                    consumed = i + 1;
                }
            }
        }
        self.scanned = bytes.len();
        self.depth = depth;
        self.in_string = in_string;
        self.escape = escape;
        self.object_start = object_start;
        self.consumed = consumed;

        // Nothing pending: only noise lives in the buffer — drop it eagerly
        // so junk streams cannot park bytes here.
        if self.object_start.is_none() {
            self.consumed = bytes.len();
        }

        // Runaway guard on genuinely pending data: one object pending across
        // chunks longer than the cap means the stream is not what the
        // protocol promised. Drop everything and resync; the pump turns the
        // flag into a terminal error.
        if bytes.len() - self.consumed > self.max_buffer {
            self.overflowed = true;
            self.buf.clear();
            self.consumed = 0;
            self.object_start = None;
            self.depth = 0;
            self.in_string = false;
            self.escape = false;
            self.scanned = 0;
            return Vec::new();
        }
        out
    }

    /// Borrow one yielded object's bytes (zero copy) by its (start, end)
    /// range from the last `feed` call. A yielded object is complete by
    /// construction, so the slice is valid UTF-8 end to end — parse it with
    /// `serde_json::from_slice`.
    pub fn object(&self, range: (usize, usize)) -> &[u8] {
        &self.buf[range.0..=range.1]
    }

    /// Call at end of stream; a dangling incomplete object is an error
    /// upstream but is dropped here (spec: parse failure -> skip).
    pub fn finish(self) {
        // Intentionally discard leftovers.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn objs(chunks: &[&str]) -> Vec<Value> {
        let mut s = JsonStreamScanner::new();
        let mut out = Vec::new();
        for c in chunks {
            for range in s.feed(c.as_bytes()) {
                out.push(
                    serde_json::from_slice(s.object(range)).expect("scanner produced invalid JSON"),
                );
            }
        }
        s.finish();
        out
    }

    #[test]
    fn single_object_one_chunk() {
        let v = objs(&[r#"{"results":[]}"#]);
        assert_eq!(v.len(), 1);
        assert!(v[0].get("results").is_some());
    }

    #[test]
    fn consecutive_objects_without_separator() {
        let v = objs(&[r#"{"a":1}{"b":2}{"c":3}"#]);
        assert_eq!(v.len(), 3);
        assert_eq!(v[0]["a"], 1);
        assert_eq!(v[2]["c"], 3);
    }

    #[test]
    fn object_split_across_chunks() {
        let v = objs(&[r#"{"res"#, r#"ults":[{"d"#, r#"ata":{"text":"hi"}}]}"#]);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0]["results"][0]["data"]["text"], "hi");
    }

    #[test]
    fn braces_inside_strings_are_not_structure() {
        let v = objs(&[r#"{"t":"a}b{\"c{d"}{"u":2}"#]);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0]["t"], r#"a}b{"c{d"#);
        assert_eq!(v[1]["u"], 2);
    }

    #[test]
    fn escaped_backslash_before_quote() {
        // The string ends with a literal backslash: `"x\\"` — the quote is real.
        let v = objs(&[r#"{"s":"x\\"}{"y":1}"#]);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0]["s"], "x\\");
    }

    #[test]
    fn noise_between_objects_is_skipped() {
        let v = objs(&[r#"garbage@#!{"a":1}   trailing"#]);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0]["a"], 1);
    }

    #[test]
    fn noise_with_quotes_and_braces_does_not_corrupt_state() {
        // Depth-0 noise may contain anything except a premature `{`; stray
        // quotes/closers in the noise must not leak into the object state.
        let v = objs(&[r#""stray" } quotes {"b":2}"#]);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0]["b"], 2);
    }

    #[test]
    fn nested_objects() {
        let v = objs(&[r#"{"outer":{"inner":{"deep":"}{"}},"after":true}{"z":0}"#]);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0]["outer"]["inner"]["deep"], "}{");
        assert_eq!(v[0]["after"], true);
        assert_eq!(v[1]["z"], 0);
    }

    #[test]
    fn leading_partial_then_complete() {
        let mut s = JsonStreamScanner::new();
        assert!(s.feed(r#"    {"partial":""#.as_bytes()).is_empty()); // incomplete, buffered
        let v: Vec<Value> = s
            .feed(r#"done"}{"next":1}"#.as_bytes())
            .iter()
            .map(|r| serde_json::from_slice(s.object(*r)).expect("valid JSON"))
            .collect();
        s.finish();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0]["partial"], "done");
        assert_eq!(v[1]["next"], 1);
    }

    #[test]
    fn split_escape_across_chunks() {
        // The `\\` escape pair sits exactly on the chunk boundary: feed1
        // carries the first backslash, feed2 the second + the closing quote.
        let mut s = JsonStreamScanner::new();
        assert!(s.feed(r#"{"s":"x\"#.as_bytes()).is_empty());
        let v: Vec<Value> = s
            .feed(r#"\"}{"y":1}"#.as_bytes())
            .iter()
            .map(|r| serde_json::from_slice(s.object(*r)).expect("valid JSON"))
            .collect();
        s.finish();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0]["s"], "x\\");
        assert_eq!(v[1]["y"], 1);
    }

    #[test]
    fn multibyte_char_split_across_chunks_survives() {
        // U+FFFD regression (2026-08-30 live bug): a multi-byte UTF-8
        // sequence cut by the chunk boundary must be buffered at BYTE level
        // and decoded only once complete. "你" is 3 bytes, "😀" is 4 — the
        // brute force below cuts inside both of them (and everywhere else).
        let body =
            r#"{"results":[{"data":{"candidates":[{"content":{"parts":[{"text":"你😀好"}]}}]}}]}"#;
        let bytes = body.as_bytes();
        for split in 1..bytes.len() {
            let mut s = JsonStreamScanner::new();
            let mut out = Vec::new();
            for range in s.feed(&bytes[..split]) {
                out.push(serde_json::from_slice::<Value>(s.object(range)).unwrap());
            }
            for range in s.feed(&bytes[split..]) {
                out.push(serde_json::from_slice::<Value>(s.object(range)).unwrap());
            }
            s.finish();
            assert_eq!(out.len(), 1, "split at byte {split}");
            assert_eq!(
                out[0]["results"][0]["data"]["candidates"][0]["content"]["parts"][0]["text"],
                "你😀好",
                "split at byte {split}"
            );
        }
    }

    #[test]
    fn oversized_incomplete_object_is_capped_and_resyncs() {
        let mut s = JsonStreamScanner::with_limit(16);
        let junk = format!(r#"{{"a":"{}"#, "x".repeat(64));
        assert!(s.feed(junk.as_bytes()).is_empty());
        assert!(s.overflowed());
        // The buffer was dropped; a fresh complete object still parses.
        let v: Vec<Value> = s
            .feed(r#"{"b":2}"#.as_bytes())
            .iter()
            .map(|r| serde_json::from_slice(s.object(*r)).expect("valid JSON"))
            .collect();
        s.finish();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0]["b"], 2);
    }

    #[test]
    fn noise_never_trips_the_overflow_guard() {
        let mut s = JsonStreamScanner::with_limit(16);
        let junk = "n".repeat(256);
        assert!(s.feed(junk.as_bytes()).is_empty());
        assert!(!s.overflowed(), "droppable noise must not trip the cap");
        let v: Vec<Value> = s
            .feed(r#"{"ok":1}"#.as_bytes())
            .iter()
            .map(|r| serde_json::from_slice(s.object(*r)).expect("valid JSON"))
            .collect();
        s.finish();
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn objects_completed_within_a_chunk_never_overflow() {
        let mut s = JsonStreamScanner::with_limit(16);
        let mut out = Vec::new();
        // Each object is bigger than the cap but completes immediately.
        for n in 0..4 {
            let chunk = format!(r#"{{"n":{n},"pad":"{}"}}"#, "p".repeat(64));
            for range in s.feed(chunk.as_bytes()) {
                out.push(serde_json::from_slice::<Value>(s.object(range)).unwrap());
            }
        }
        assert!(!s.overflowed());
        s.finish();
        assert_eq!(out.len(), 4);
        assert_eq!(out[3]["n"], 3);
    }
}
