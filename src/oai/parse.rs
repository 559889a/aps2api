//! OAI chat-completions request -> ir (spec §9.2).
//!
//! Client requests are parsed into the Gemini-shaped ir; the original body is
//! never forwarded upstream. Forbidden parameters are dropped with a DEBUG
//! log; tool-related messages/fields are stripped with a warning.

use serde_json::{Map, Value};

use crate::ir::{split_channel_prefix, ApiError, Ir};

pub fn parse(body: &Value) -> Result<Ir, ApiError> {
    let model = body
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if model.is_empty() {
        return Err(ApiError::bad_request("`model` is required"));
    }

    let (name, forced) = split_channel_prefix(&model);
    let stream = body.get("stream").and_then(Value::as_bool).unwrap_or(false);
    let mut ir = Ir::new(name, stream);
    ir.forced_channel = forced;

    let messages = body
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| ApiError::bad_request("`messages` must be an array"))?;

    let mut system_lines: Vec<String> = Vec::new();
    for msg in messages {
        let role = msg.get("role").and_then(Value::as_str).unwrap_or("");
        match role {
            "system" | "developer" => {
                if let Some(text) = message_text(msg.get("content")) {
                    system_lines.push(text);
                }
            }
            "user" => {
                append_turn(&mut ir, "user", convert_content(msg.get("content")));
            }
            "assistant" => {
                append_turn(&mut ir, "model", convert_content(msg.get("content")));
            }
            "tool" => {
                tracing::warn!("dropped message with role=tool: tool calling is not supported");
            }
            other => {
                tracing::warn!(role = other, "dropped message with unknown role");
            }
        }
    }
    if ir.contents.is_empty() {
        return Err(ApiError::bad_request("messages cannot be empty"));
    }

    if !system_lines.is_empty() {
        ir.system = Some(serde_json::json!({
            "parts": [{ "text": system_lines.join("\n") }]
        }));
    }

    ir.generation_config = parse_generation_config(body);
    ir.include_usage = body
        .get("stream_options")
        .and_then(|so| so.get("include_usage"))
        .and_then(Value::as_bool)
        .unwrap_or(false);

    for key in [
        "top_k",
        "max_tokens",
        "max_completion_tokens",
        "presence_penalty",
        "frequency_penalty",
        "thinking",
        "thinking_budget",
        "tools",
        "tool_choice",
    ] {
        if body.get(key).is_some_and(|v| !v.is_null()) {
            tracing::debug!(field = key, "dropped client parameter (not supported)");
        }
    }
    if let Some(effort) = body.get("reasoning_effort").and_then(Value::as_str) {
        tracing::debug!(
            normalized = %crate::rewrite::normalize_effort_word(effort),
            "dropped reasoning_effort (thinking level is forced by config or family default)"
        );
    }

    Ok(ir)
}

fn append_turn(ir: &mut Ir, role: &str, mut parts: Vec<Value>) {
    if parts.is_empty() {
        return;
    }
    parts.shrink_to_fit();
    ir.contents
        .push(serde_json::json!({ "role": role, "parts": parts }));
}

/// Concatenated text of a message content (string or text-parts array).
fn message_text(content: Option<&Value>) -> Option<String> {
    match content? {
        Value::String(s) => {
            if s.trim().is_empty() {
                None
            } else {
                Some(s.clone())
            }
        }
        Value::Array(parts) => {
            let mut out = Vec::new();
            for part in parts {
                if part.get("type").and_then(Value::as_str) == Some("text") {
                    if let Some(t) = part.get("text").and_then(Value::as_str) {
                        out.push(t.to_string());
                    }
                }
            }
            if out.is_empty() {
                None
            } else {
                Some(out.join("\n"))
            }
        }
        _ => None,
    }
}

/// Convert one OAI message content into Gemini parts (spec §9.2).
fn convert_content(content: Option<&Value>) -> Vec<Value> {
    let Some(content) = content else {
        return Vec::new();
    };
    match content {
        Value::String(s) => {
            if s.is_empty() {
                Vec::new()
            } else {
                vec![serde_json::json!({ "text": s })]
            }
        }
        Value::Array(items) => {
            let mut parts = Vec::new();
            for item in items {
                let ty = item.get("type").and_then(Value::as_str).unwrap_or("");
                match ty {
                    "text" => {
                        if let Some(t) = item.get("text").and_then(Value::as_str) {
                            if !t.is_empty() {
                                parts.push(serde_json::json!({ "text": t }));
                            }
                        }
                    }
                    "image_url" => {
                        let url = item
                            .get("image_url")
                            .and_then(|iu| iu.get("url"))
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        match image_part(url) {
                            Some(p) => parts.push(p),
                            None => tracing::warn!("skipped unsupported image url"),
                        }
                    }
                    other => tracing::debug!(part_type = other, "dropped content part"),
                }
            }
            parts
        }
        _ => Vec::new(),
    }
}

/// data URL -> inlineData part; base64 payload is passed through verbatim
/// (spec trap 14). Remote http(s) URLs become a `remoteFetch` placeholder
/// that the handler resolves via the SSRF-guarded fetcher (§9.3).
fn image_part(url: &str) -> Option<Value> {
    if let Some(rest) = url.strip_prefix("data:") {
        let (mime, data) = rest.split_once(";base64,")?;
        if mime.is_empty() || data.is_empty() {
            return None;
        }
        return Some(serde_json::json!({
            "inlineData": { "mimeType": mime, "data": data }
        }));
    }
    if url.starts_with("http://") || url.starts_with("https://") {
        return Some(serde_json::json!({ "remoteFetch": url }));
    }
    None
}

fn parse_generation_config(body: &Value) -> Value {
    let mut cfg = Map::new();
    if let Some(t) = body.get("temperature").and_then(Value::as_f64) {
        cfg.insert("temperature".into(), serde_json::json!(t));
    }
    if let Some(p) = body.get("top_p").and_then(Value::as_f64) {
        cfg.insert("topP".into(), serde_json::json!(p));
    }
    match body.get("stop") {
        Some(Value::String(s)) if !s.is_empty() => {
            cfg.insert("stopSequences".into(), serde_json::json!([s]));
        }
        Some(Value::Array(items)) => {
            let seqs: Vec<&str> = items
                .iter()
                .filter_map(Value::as_str)
                .filter(|s| !s.is_empty())
                .collect();
            if !seqs.is_empty() {
                cfg.insert("stopSequences".into(), serde_json::json!(seqs));
            }
        }
        _ => {}
    }
    if let Some(seed) = body.get("seed").and_then(Value::as_i64) {
        cfg.insert("seed".into(), serde_json::json!(seed));
    }
    if let Some(rf) = body.get("response_format") {
        match rf.get("type").and_then(Value::as_str) {
            Some("json_object") => {
                cfg.insert("responseMimeType".into(), json_str("application/json"));
            }
            Some("json_schema") => {
                cfg.insert("responseMimeType".into(), json_str("application/json"));
                if let Some(schema) = rf
                    .get("json_schema")
                    .and_then(|js| js.get("schema"))
                    .cloned()
                {
                    let schema = strip_schema_key(schema);
                    cfg.insert("responseSchema".into(), schema);
                }
            }
            _ => {}
        }
    }
    Value::Object(cfg)
}

fn json_str(s: &str) -> Value {
    Value::String(s.to_string())
}

fn strip_schema_key(mut schema: Value) -> Value {
    if let Value::Object(map) = &mut schema {
        map.remove("$schema");
    }
    schema
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn plain_multi_turn_with_system() {
        let body = json!({
            "model": "gemini-3.1-pro",
            "messages": [
                { "role": "system", "content": "be brief" },
                { "role": "user", "content": "hi" },
                { "role": "assistant", "content": "hello" },
                { "role": "user", "content": "bye" }
            ]
        });
        let ir = parse(&body).unwrap();
        assert_eq!(ir.model, "gemini-3.1-pro");
        assert_eq!(ir.contents.len(), 3);
        assert_eq!(ir.contents[0]["role"], "user");
        assert_eq!(ir.contents[1]["role"], "model");
        assert_eq!(ir.contents[1]["parts"][0]["text"], "hello");
        assert_eq!(ir.system.unwrap()["parts"][0]["text"], "be brief");
        assert!(!ir.stream);
    }

    #[test]
    fn data_url_image_becomes_inline_data_verbatim() {
        let b64 = "iVBORw0KGgoAAAANSUhEUg==";
        let body = json!({
            "model": "gemini-3.6-flash",
            "stream": true,
            "messages": [{
                "role": "user",
                "content": [
                    { "type": "text", "text": "what is this?" },
                    { "type": "image_url", "image_url": { "url": format!("data:image/png;base64,{b64}") } }
                ]
            }]
        });
        let ir = parse(&body).unwrap();
        assert!(ir.stream);
        assert_eq!(ir.contents.len(), 1);
        let parts = ir.contents[0]["parts"].as_array().unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[1]["inlineData"]["mimeType"], "image/png");
        assert_eq!(parts[1]["inlineData"]["data"], b64);
    }

    #[test]
    fn empty_messages_is_400() {
        let err = parse(&json!({ "model": "m", "messages": [] })).unwrap_err();
        assert_eq!(err.status, 400);
        let err = parse(&json!({ "model": "m", "messages": [{ "role": "user" }] })).unwrap_err();
        assert_eq!(err.status, 400);
    }

    #[test]
    fn missing_model_is_400() {
        let err = parse(&json!({ "messages": [{ "role": "user", "content": "x" }] })).unwrap_err();
        assert_eq!(err.status, 400);
    }

    #[test]
    fn channel_prefix_split() {
        let body = json!({
            "model": "cookie/gemini-3.1-pro",
            "messages": [{ "role": "user", "content": "hi" }]
        });
        let ir = parse(&body).unwrap();
        assert_eq!(ir.model, "gemini-3.1-pro");
        assert_eq!(ir.forced_channel, Some(crate::ir::Channel::Cookie));
    }

    #[test]
    fn tool_messages_and_tool_fields_are_dropped() {
        let body = json!({
            "model": "gemini-3.1-pro",
            "tools": [{ "function": { "name": "f" } }],
            "tool_choice": "auto",
            "top_k": 40,
            "max_tokens": 100,
            "presence_penalty": 0.5,
            "frequency_penalty": 0.5,
            "messages": [
                { "role": "user", "content": "hi" },
                { "role": "assistant", "tool_calls": [{ "id": "1" }], "content": null },
                { "role": "tool", "content": "result" }
            ]
        });
        let ir = parse(&body).unwrap();
        // assistant with null content but tool_calls yields no parts -> skipped;
        // tool message dropped.
        assert_eq!(ir.contents.len(), 1);
        assert!(ir.generation_config.get("topK").is_none());
        assert!(ir.generation_config.get("maxOutputTokens").is_none());
    }

    #[test]
    fn stop_string_becomes_array_and_json_schema_strips_dollar_schema() {
        let body = json!({
            "model": "gemini-3.1-pro",
            "temperature": 0.7,
            "top_p": 0.9,
            "stop": "END",
            "seed": 42,
            "response_format": {
                "type": "json_schema",
                "json_schema": { "schema": { "$schema": "x", "type": "object" } }
            },
            "messages": [{ "role": "user", "content": "hi" }]
        });
        let ir = parse(&body).unwrap();
        let cfg = &ir.generation_config;
        assert_eq!(cfg["temperature"], 0.7);
        assert_eq!(cfg["topP"], 0.9);
        assert_eq!(cfg["stopSequences"], json!(["END"]));
        assert_eq!(cfg["seed"], 42);
        assert_eq!(cfg["responseMimeType"], "application/json");
        assert_eq!(cfg["responseSchema"]["type"], "object");
        assert!(cfg["responseSchema"].get("$schema").is_none());
    }
}
