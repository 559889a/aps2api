//! Gemini-native request normalization (spec §10.2): the body is a standard
//! GenerateContentRequest, parsed and rebuilt via the §8 matrix — the raw
//! body is never forwarded.

use serde_json::{Map, Value};

use crate::ir::{split_model_name, ApiError, Ir};

pub fn parse(model_in_path: &str, stream: bool, body: &Value) -> Result<Ir, ApiError> {
    let (name, forced, bypass) = split_model_name(model_in_path);
    let mut ir = Ir::new(name, stream);
    ir.forced_channel = forced;
    ir.bypass = bypass;

    // ---- contents ----
    let contents = body
        .get("contents")
        .and_then(Value::as_array)
        .ok_or_else(|| ApiError::bad_request("`contents` must be an array"))?;
    for turn in contents {
        let role = turn
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or("user")
            .to_lowercase();
        let role = if role == "model" { "model" } else { "user" };
        let mut parts = Vec::new();
        if let Some(arr) = turn.get("parts").and_then(Value::as_array) {
            for part in arr {
                if part.get("functionCall").is_some()
                    || part.get("functionResponse").is_some()
                    || part.get("executableCode").is_some()
                    || part.get("codeExecutionResult").is_some()
                {
                    tracing::debug!("dropped tool/code part (not supported)");
                    continue;
                }
                // `thought`/`thoughtSignature` keys have no semantics without
                // tool round-trips — stripped (spec §10.2).
                let mut p = normalize_keys(part.clone());
                if let Value::Object(m) = &mut p {
                    m.remove("thought");
                    m.remove("thoughtSignature");
                    // An empty part (no keys beyond those) is skipped.
                    if m.is_empty() {
                        continue;
                    }
                }
                parts.push(p);
            }
        }
        if !parts.is_empty() {
            ir.contents.push(json_turn(role, parts));
        }
    }
    if ir.contents.is_empty() {
        return Err(ApiError::bad_request("contents cannot be empty"));
    }

    // ---- systemInstruction (snake or camel) ----
    let sys = body
        .get("systemInstruction")
        .or_else(|| body.get("system_instruction"));
    if let Some(s) = sys {
        if !s.is_null() {
            ir.system = Some(normalize_keys(s.clone()));
        }
    }

    // ---- generationConfig (normalized; §8 matrix applied at rewrite) ----
    let gc = body
        .get("generationConfig")
        .or_else(|| body.get("generation_config"));
    if let Some(g) = gc {
        let n = normalize_keys(g.clone());
        if let Value::Object(map) = n {
            ir.generation_config = Value::Object(keep_whitelisted_gc(map));
        }
    }

    Ok(ir)
}

fn json_turn(role: &str, parts: Vec<Value>) -> Value {
    let mut m = Map::new();
    m.insert("role".into(), Value::String(role.to_string()));
    m.insert("parts".into(), Value::Array(parts));
    Value::Object(m)
}

fn keep_whitelisted_gc(map: Map<String, Value>) -> Map<String, Value> {
    let whitelist = [
        "temperature",
        "topP",
        "stopSequences",
        "seed",
        "responseMimeType",
        "responseSchema",
        "responseLogprobs",
        "logprobs",
        "mediaResolution",
        "thinkingConfig",
    ];
    let mut out = Map::new();
    for (k, v) in map {
        // topK is unconditionally dropped (spec §8.1); anything outside the
        // whitelist is dropped too.
        if whitelist.contains(&k.as_str()) && !v.is_null() {
            out.insert(k, v);
        }
    }
    out
}

/// Recursively rewrite snake_case object keys to camelCase (spec §10.2).
/// Non-underscore keys pass through untouched.
pub fn normalize_keys(v: Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, val) in map {
                let camel = if k.contains('_') { to_camel(&k) } else { k };
                out.insert(camel, normalize_keys(val));
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(normalize_keys).collect()),
        other => other,
    }
}

fn to_camel(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut up = false;
    for c in s.chars() {
        if c == '_' {
            up = true;
        } else if up {
            out.extend(c.to_uppercase());
            up = false;
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn roles_normalized_and_parts_filtered() {
        let body = json!({
            "contents": [
                { "role": "USER", "parts": [ { "text": "hi" }, { "inline_data": { "mime_type": "image/png", "data": "AA" } } ] },
                { "role": "model", "parts": [
                    { "text": "ok", "thought": true, "thoughtSignature": "sig" },
                    { "functionCall": { "name": "f" } },
                    { "executableCode": { "code": "x" } }
                ]},
                { "role": "user", "parts": [ { "functionResponse": { "name": "f" } } ] }
            ]
        });
        let ir = parse("gemini-3.1-pro", false, &body).unwrap();
        assert_eq!(ir.contents.len(), 2); // empty final turn dropped
        let parts0 = ir.contents[0]["parts"].as_array().unwrap();
        assert_eq!(parts0.len(), 2);
        assert_eq!(parts0[1]["inlineData"]["mimeType"], "image/png");
        assert_eq!(parts0[1]["inlineData"]["data"], "AA");
        let parts1 = ir.contents[1]["parts"].as_array().unwrap();
        assert_eq!(parts1.len(), 1);
        assert!(parts1[0].get("thought").is_none());
        assert!(parts1[0].get("thoughtSignature").is_none());
    }

    #[test]
    fn empty_contents_is_400() {
        let e = parse("m", false, &json!({ "contents": [] })).unwrap_err();
        assert_eq!(e.status, 400);
        let e = parse("m", false, &json!({})).unwrap_err();
        assert_eq!(e.status, 400);
    }

    #[test]
    fn system_instruction_snake_normalized() {
        let body = json!({
            "contents": [{ "role": "user", "parts": [{ "text": "hi" }] }],
            "system_instruction": { "parts": [{ "text": "sys" }] }
        });
        let ir = parse("gemini-3.1-pro", false, &body).unwrap();
        assert_eq!(ir.system.unwrap()["parts"][0]["text"], "sys");
    }

    #[test]
    fn generation_config_whitelisted_and_camelized() {
        let body = json!({
            "contents": [{ "role": "user", "parts": [{ "text": "hi" }] }],
            "generation_config": {
                "temperature": 0.5,
                "top_k": 40,
                "thinking_config": { "thinking_level": "LOW", "include_thoughts": true },
                "candidate_count": 3
            }
        });
        let ir = parse("gemini-3.1-pro", true, &body).unwrap();
        let gc = ir.generation_config.as_object().unwrap();
        assert_eq!(gc["temperature"], 0.5);
        assert!(gc.get("topK").is_none());
        assert!(gc.get("candidateCount").is_none());
        assert_eq!(gc["thinkingConfig"]["thinkingLevel"], "LOW");
        assert_eq!(gc["thinkingConfig"]["includeThoughts"], true);
    }

    #[test]
    fn channel_prefix_parsed() {
        let body = json!({ "contents": [{ "role": "user", "parts": [{ "text": "x" }] }] });
        let ir = parse("cookie/gemini-3.6-flash", true, &body).unwrap();
        assert_eq!(ir.model, "gemini-3.6-flash");
        assert_eq!(ir.forced_channel, Some(crate::ir::Channel::Cookie));
    }
}
