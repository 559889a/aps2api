//! Bracket-balanced streaming JSON object extractor (spec §13.1).
//!
//! batchGraphql responses are neither SSE nor a JSON array: consecutive JSON
//! objects are simply concatenated, e.g. `{"results":[..]}{"results":[..]}`.
//! A streaming state machine scans the byte stream and hands out one
//! top-level object at a time, tolerating objects split across chunks and
//! braces inside strings (with escape handling).

/// Feed bytes; yields each complete top-level JSON object (as a string).
#[derive(Debug, Default)]
pub struct JsonStreamScanner {
    buf: String,
}

impl JsonStreamScanner {
    pub fn new() -> Self {
        JsonStreamScanner { buf: String::new() }
    }

    pub fn feed(&mut self, chunk: &str) -> Vec<String> {
        self.buf.push_str(chunk);
        let mut out = Vec::new();
        loop {
            let Some(start_rel) = self.buf.find('{') else {
                // No object start: everything buffered is noise between objects.
                self.buf.clear();
                break;
            };
            let start = start_rel;
            let Some(end) = match_object_end(&self.buf, start) else {
                // Incomplete object: keep from `start` and wait for more bytes.
                self.buf.drain(..start);
                break;
            };
            out.push(self.buf[start..=end].to_string());
            self.buf.drain(..=end);
        }
        out
    }

    /// Call at end of stream; a dangling incomplete object is an error
    /// upstream but is dropped here (spec: parse failure -> skip).
    pub fn finish(self) {
        // Intentionally discard leftovers.
    }
}

/// If a complete `{...}` starts at `start`, return the index of its matching
/// `}`. Handles strings, escapes, and nesting. Returns None when truncated.
fn match_object_end(buf: &str, start: usize) -> Option<usize> {
    let bytes = buf.as_bytes();
    let mut depth = 0i64;
    let mut in_string = false;
    let mut escape = false;
    let mut i = start;
    while i < bytes.len() {
        let b = bytes[i];
        if escape {
            escape = false;
        } else if b == b'\\' && in_string {
            escape = true;
        } else if b == b'"' {
            in_string = !in_string;
        } else if !in_string {
            match b {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn objs(chunks: &[&str]) -> Vec<Value> {
        let mut s = JsonStreamScanner::new();
        let mut out = Vec::new();
        for c in chunks {
            for o in s.feed(c) {
                out.push(serde_json::from_str(&o).expect("scanner produced invalid JSON"));
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
        assert!(s.feed(r#"    {"partial":""#).is_empty()); // incomplete, buffered
        let v: Vec<Value> = s
            .feed(r#"done"}{"next":1}"#)
            .iter()
            .map(|o| serde_json::from_str(o).expect("valid JSON"))
            .collect();
        s.finish();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0]["partial"], "done");
        assert_eq!(v[1]["next"], 1);
    }
}
