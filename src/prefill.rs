//! Prefill compatibility (spec §11).
//!
//! Gemini 3.x rejects requests ending with a model turn, but tavern-style
//! frontends rely on a trailing assistant message ("prefill") to pin a
//! chain-of-thought. The prefill model turn is KEPT, a user nudge is appended
//! after it (3.x only), and the response side stitches the prefill back so
//! the client sees one continuous completion.

use serde_json::Value;

/// Detect the LAST tag in `text` that is opened but never closed (spec §11.2).
/// Pattern: `<([A-Za-z][A-Za-z0-9_\-~.:]*)\s*>`; closing form allows
/// whitespace: `</ name >`. No concrete tag names are assumed.
pub fn detect_unclosed_tag(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut last_unclosed: Option<(usize, String)> = None;
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        if j >= bytes.len() || !bytes[j].is_ascii_alphabetic() {
            i += 1;
            continue;
        }
        j += 1;
        while j < bytes.len()
            && (bytes[j].is_ascii_alphanumeric()
                || matches!(bytes[j], b'_' | b'-' | b'~' | b'.' | b':'))
        {
            j += 1;
        }
        let name: String = text[i + 1..j].to_string();
        // Optional whitespace, then '>'.
        let mut k = j;
        while k < bytes.len() && bytes[k].is_ascii_whitespace() {
            k += 1;
        }
        if k >= bytes.len() || bytes[k] != b'>' {
            i += 1;
            continue;
        }
        // Open tag confirmed at i..=k. Is there a matching close tag after k?
        if !has_close_tag(text, k + 1, &name) {
            last_unclosed = Some((i, name));
        }
        i = k + 1;
    }
    last_unclosed.map(|(_, name)| name)
}

fn has_close_tag(text: &str, from: usize, name: &str) -> bool {
    let rest = &text[from..];
    let bytes = rest.as_bytes();
    let mut i = 0usize;
    while let Some(rel) = rest[i..].find("</") {
        let start = i + rel;
        let mut j = start + 2;
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if rest[j..].starts_with(name) {
            let mut k = j + name.len();
            while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                k += 1;
            }
            if k < bytes.len() && bytes[k] == b'>' {
                return true;
            }
        }
        i = start + 1;
    }
    false
}

/// CoT guard appended to the nudge when the prefill stops inside an open tag
/// (verbatim text from spec §11.2).
pub fn build_cot_guard(tag: &str) -> String {
    format!(
        "\n\n（格式硬性要求）你的这条回复当前停在 <{tag}> 内部：请**先**在 <{tag}> 里逐条写完该标签要求的全部思考内容，\
写完后用 </{tag}> 闭合，**然后才**开始写正文。不允许跳过思考直接写正文，也不允许只写一个空标签。"
    )
}

const NUDGE: &str = "[继续] 从你上一条的断点处无缝往下写，不要重复已写内容，不要任何前言或解释。";

fn part_text(part: &Value) -> Option<&str> {
    part.get("text").and_then(Value::as_str)
}

fn part_is_plain_text(part: &Value) -> bool {
    part.get("text").is_some_and(|t| t.is_string())
        && part.get("inlineData").is_none()
        && part.get("functionCall").is_none()
}

fn turn_is_nonempty(turn: &Value) -> bool {
    turn.get("parts")
        .and_then(Value::as_array)
        .is_some_and(|parts| {
            parts.iter().any(|p| {
                part_text(p).is_some_and(|t| !t.trim().is_empty()) || p.get("inlineData").is_some()
            })
        })
}

/// Request-side prefill handling (spec §11.1). Returns the prefill text
/// (empty = no prefill). On 3.x models (`requires_user_last_turn`) the user
/// nudge is appended after the kept model turn; the request mutation happens
/// in place on `ir.contents`.
pub fn apply_request(contents: &mut Vec<Value>, requires_user_last_turn: bool) -> String {
    let Some(idx) = contents.iter().rposition(turn_is_nonempty) else {
        return String::new();
    };
    let last = &contents[idx];
    if last.get("role").and_then(Value::as_str) != Some("model") {
        return String::new();
    }
    let Some(parts) = last.get("parts").and_then(Value::as_array) else {
        return String::new();
    };
    if !parts.iter().all(part_is_plain_text) {
        return String::new();
    }
    let prefill: String = parts
        .iter()
        .filter_map(|p| part_text(p).map(str::to_string))
        .collect::<Vec<_>>()
        .join("");
    let prefill = prefill.trim().to_string();
    if prefill.is_empty() {
        return String::new();
    }

    if requires_user_last_turn {
        let mut nudge = NUDGE.to_string();
        if let Some(tag) = detect_unclosed_tag(&prefill) {
            nudge.push_str(&build_cot_guard(&tag));
        }
        contents.truncate(idx + 1);
        contents.push(serde_json::json!({
            "role": "user",
            "parts": [{ "text": nudge }]
        }));
    }
    prefill
}

/// Non-streaming dedup: if the output restates the whole prefill, cut it;
/// otherwise cut the longest prefill-tail/output-head overlap when it is at
/// least 8 characters (spec §11.3).
pub fn strip_overlap(prefill: &str, output: &str) -> String {
    if prefill.is_empty() {
        return output.to_string();
    }
    if let Some(rest) = output.strip_prefix(prefill) {
        return rest.to_string();
    }
    let pc: Vec<char> = prefill.chars().collect();
    let oc: Vec<char> = output.chars().collect();
    // Longest suffix of `prefill` equal to a prefix of `output` in
    // O(len(prefill)+len(output)) via the KMP failure function. The previous
    // descending-length rescan was O(n^2) on adversarial input — a prefill
    // ending in a long single-char run against an output opening with the
    // same run — and the prefill is client-controlled, so that was a
    // CPU-burn vector on the request path. Identical results, linear cost.
    let k = longest_suffix_prefix(&pc, &oc);
    if k >= 8 {
        let byte_skip: usize = oc[..k].iter().map(|c| c.len_utf8()).sum();
        return output[byte_skip..].to_string();
    }
    output.to_string()
}

/// Longest k with `a[a.len()-k..] == b[..k]` (0 when there is none or
/// either side is empty).
fn longest_suffix_prefix(a: &[char], b: &[char]) -> usize {
    let m = b.len();
    if m == 0 || a.is_empty() {
        return 0;
    }
    // Failure function of pattern `b`.
    let mut fail = vec![0usize; m];
    let mut k = 0usize;
    for i in 1..m {
        while k > 0 && b[i] != b[k] {
            k = fail[k - 1];
        }
        if b[i] == b[k] {
            k += 1;
        }
        fail[i] = k;
    }
    // Stream `a` through the automaton: when it ends, `matched` is the
    // length of the longest prefix of `b` that is a suffix of `a`.
    let mut matched = 0usize;
    for &c in a {
        loop {
            if matched < m && c == b[matched] {
                matched += 1;
                break;
            }
            if matched == 0 {
                break;
            }
            matched = fail[matched - 1];
        }
    }
    matched
}

/// Streaming deduper (spec §11.3, port of the Go `PrefillDeduper`).
///
/// Text events are fed through `feed`; the returned string is what may be
/// emitted to the client (possibly empty while still ambiguous). Once the
/// buffer can no longer be a duplicate of the prefill, everything is resolved
/// at once and all later text passes straight through — this keeps
/// time-to-first-token unaffected.
pub struct PrefillDeduper {
    prefill: String,
    /// max buffered chars before forcing a resolve: min(len(prefill)+32, 600).
    window: usize,
    buffer: String,
    done: bool,
}

impl PrefillDeduper {
    pub fn new(prefill: &str) -> Self {
        let chars = prefill.chars().count();
        let window = if prefill.is_empty() {
            0
        } else {
            (chars + 32).min(600)
        };
        PrefillDeduper {
            prefill: prefill.to_string(),
            window,
            buffer: String::new(),
            done: false,
        }
    }

    /// Feed one text increment; returns the text to emit now ("" = hold).
    pub fn feed(&mut self, text: &str) -> String {
        if self.done || self.prefill.is_empty() {
            return text.to_string();
        }
        self.buffer.push_str(text);
        let buf_chars = self.buffer.chars().count();
        let prefill_chars = self.prefill.chars().count();
        if buf_chars >= self.window
            || buf_chars >= prefill_chars
            || !self.prefill.starts_with(&self.buffer)
        {
            return self.resolve();
        }
        String::new()
    }

    /// Flush before the finish event (spec: 正文必须落在 finish 之前).
    pub fn flush(&mut self) -> String {
        if self.done || self.prefill.is_empty() {
            return String::new();
        }
        self.resolve()
    }

    fn resolve(&mut self) -> String {
        self.done = true;
        let out = strip_overlap(&self.prefill, &self.buffer);
        self.buffer.clear();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn model_turn(text: &str) -> Value {
        json!({ "role": "model", "parts": [{ "text": text }] })
    }

    fn user_turn(text: &str) -> Value {
        json!({ "role": "user", "parts": [{ "text": text }] })
    }

    #[test]
    fn trailing_model_turn_gets_nudge_on_3x() {
        let mut contents = vec![user_turn("hi"), model_turn("<thinking>")];
        let prefill = apply_request(&mut contents, true);
        assert_eq!(prefill, "<thinking>");
        assert_eq!(contents.len(), 3);
        let nudge = contents[2]["parts"][0]["text"].as_str().unwrap();
        assert!(nudge.starts_with("[继续]"));
        // Unclosed <thinking> -> CoT guard present.
        assert!(nudge.contains("格式硬性要求"));
        assert!(nudge.contains("<thinking>"));
    }

    #[test]
    fn trailing_model_turn_passes_through_on_2_5() {
        let mut contents = vec![user_turn("hi"), model_turn("hello wor")];
        let prefill = apply_request(&mut contents, false);
        assert_eq!(prefill, "hello wor");
        // contents unchanged: no nudge appended.
        assert_eq!(contents.len(), 2);
    }

    #[test]
    fn trailing_user_turn_has_no_prefill() {
        let mut contents = vec![user_turn("hi"), user_turn("again")];
        let prefill = apply_request(&mut contents, true);
        assert_eq!(prefill, "");
        assert_eq!(contents.len(), 2);
    }

    #[test]
    fn model_turn_with_image_is_not_prefill() {
        let turn = json!({
            "role": "model",
            "parts": [
                { "text": "look " },
                { "inlineData": { "mimeType": "image/png", "data": "xx" } }
            ]
        });
        let mut contents = vec![user_turn("hi"), turn];
        let prefill = apply_request(&mut contents, true);
        assert_eq!(prefill, "");
    }

    #[test]
    fn blank_trailing_turns_are_skipped_and_dropped() {
        let mut contents = vec![
            user_turn("hi"),
            model_turn("prefill text"),
            user_turn("   "),
            model_turn(""),
        ];
        let prefill = apply_request(&mut contents, true);
        assert_eq!(prefill, "prefill text");
        assert_eq!(contents.len(), 3); // blanks after idx dropped, nudge appended
        assert_eq!(contents[2]["role"], "user");
    }

    #[test]
    fn unclosed_tag_detection() {
        assert_eq!(
            detect_unclosed_tag("ok <thinking> hmm"),
            Some("thinking".into())
        );
        assert_eq!(detect_unclosed_tag("<thinking> x </thinking> y"), None);
        assert_eq!(detect_unclosed_tag("<a> <b> </b>"), Some("a".into()));
        assert_eq!(detect_unclosed_tag("<CoT> text"), Some("CoT".into()));
        assert_eq!(detect_unclosed_tag("<plan_1>"), Some("plan_1".into()));
        // close tag with spaces: `</ name >`
        assert_eq!(detect_unclosed_tag("<t> x </ t >"), None);
        // digits-only start is not a tag
        assert_eq!(detect_unclosed_tag("1 < 2 > 3"), None);
        // last unclosed wins
        assert_eq!(
            detect_unclosed_tag("<a> </a> <b> <c> </c>"),
            Some("b".into())
        );
    }

    #[test]
    fn strip_overlap_cases() {
        // full restatement
        assert_eq!(strip_overlap("ABCD", "ABCDEF"), "EF");
        // overlap >= 8 chars is cut
        let pre = "prefill-12345678";
        assert_eq!(strip_overlap(pre, "12345678NEXT"), "NEXT");
        // overlap < 8 chars is kept
        assert_eq!(
            strip_overlap("prefill-1234567", "1234567NEXT"),
            "1234567NEXT"
        );
        // no overlap
        assert_eq!(strip_overlap("abc", "xyz"), "xyz");
        assert_eq!(strip_overlap("", "xyz"), "xyz");
    }

    #[test]
    fn strip_overlap_adversarial_runs() {
        // Prefill ending in a long single-char run vs an output opening with
        // the same run: every prefill suffix contains the trailing 'b', so
        // the overlap is 0 — the answer must come out of the linear matcher
        // (this shape was the O(n^2) rescan worst case).
        let prefill = format!("{}b", "a".repeat(50_000));
        let output = "a".repeat(50_000);
        assert_eq!(strip_overlap(&prefill, &output), output);

        // Positive shape: prefill = "b" + run, output = run + "c" — the
        // whole run is the overlap and gets cut.
        let prefill = format!("b{}", "a".repeat(50_000));
        let output = format!("{}c", "a".repeat(50_000));
        assert_eq!(strip_overlap(&prefill, &output), "c");

        // Overlap must be a prefill SUFFIX: 8 trailing x's cut, 7 kept.
        assert_eq!(strip_overlap("abxxxxxxxx", "xxxxxxxxy"), "y");
        assert_eq!(strip_overlap("abxxxxxxx", "xxxxxxxy"), "xxxxxxxy");
    }

    #[test]
    fn deduper_emits_immediately_when_not_a_prefix() {
        let mut d = PrefillDeduper::new("The answer is");
        // First chunk diverges from the prefill -> resolve right away.
        let out = d.feed("Nope");
        assert_eq!(out, "Nope");
        assert_eq!(d.feed(" more"), " more"); // passthrough after resolve
        assert_eq!(d.flush(), "");
    }

    #[test]
    fn deduper_holds_then_cuts_full_restatement() {
        let mut d = PrefillDeduper::new("Once upon a time");
        assert_eq!(d.feed("Once"), ""); // still a prefix, held
        assert_eq!(d.feed(" upon a time"), ""); // exact restatement, still ambiguous
        let out = d.feed(" there lived");
        assert_eq!(out, " there lived"); // whole prefill cut
        assert_eq!(d.flush(), "");
    }

    #[test]
    fn deduper_flush_releases_remaining_ambiguity() {
        let mut d = PrefillDeduper::new("abcdef");
        assert_eq!(d.feed("abc"), "");
        assert_eq!(d.flush(), "abc"); // could not decide -> original text passes
    }

    #[test]
    fn deduper_window_forces_resolve() {
        // prefill 10 chars -> window 42; feed more than window -> resolved.
        let pre = "0123456789";
        let mut d = PrefillDeduper::new(pre);
        let big = "x".repeat(50);
        let out = d.feed(&big);
        assert_eq!(out, big); // not a duplicate
    }

    #[test]
    fn deduper_empty_prefill_passthrough() {
        let mut d = PrefillDeduper::new("");
        assert!(d.prefill.is_empty());
        assert_eq!(d.feed("hello"), "hello");
    }

    #[test]
    fn guard_text_is_verbatim() {
        let g = build_cot_guard("thinking");
        assert!(g.starts_with("\n\n（格式硬性要求）"));
        assert!(g.contains("<thinking>"));
        assert!(g.contains("</thinking>"));
    }
}
