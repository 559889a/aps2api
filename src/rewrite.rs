//! Outbound payload rewriting (spec §8) — shared by both channels.
//!
//! RED LINE: a client request body is never forwarded upstream as-is. The
//! payload is always rebuilt from parsed fields: penalty params / maxOutput
//! tokens / topK / tools are unconditionally removed, sampling params follow
//! the model profile, thinkingConfig is overridden per the §8.3 matrix, and a
//! channel-specific safetySettings block is injected.

use serde_json::{Map, Value};

use crate::ir::{Channel, Ir};
use crate::modelcaps::{self, Profile, ThinkingKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortKind {
    Oai,
    Gemini,
}

/// Safety settings for one channel (spec §8.4). Client-provided settings are
/// always ignored.
///
/// cookie channel: 4 text categories + JAILBREAK, threshold OFF (batchGraphql
/// verified: without JAILBREAK, roleplay presets lose their body while
/// thoughts keep flowing).
///
/// express channel: the 4 text categories + 4 IMAGE_* categories, threshold
/// BLOCK_NONE (JAILBREAK's classifier is off by default on that endpoint;
/// CIVIC_INTEGRITY is deprecated everywhere).
pub fn safety_settings(channel: Channel) -> Vec<Value> {
    let text_cats = [
        "HARM_CATEGORY_HARASSMENT",
        "HARM_CATEGORY_HATE_SPEECH",
        "HARM_CATEGORY_SEXUALLY_EXPLICIT",
        "HARM_CATEGORY_DANGEROUS_CONTENT",
    ];
    let (cats, threshold) = match channel {
        Channel::Cookie => {
            let mut cats: Vec<&str> = text_cats.to_vec();
            cats.push("HARM_CATEGORY_JAILBREAK");
            (cats, "OFF")
        }
        Channel::Express => {
            let mut cats: Vec<&str> = text_cats.to_vec();
            cats.extend([
                "HARM_CATEGORY_IMAGE_HARASSMENT",
                "HARM_CATEGORY_IMAGE_HATE",
                "HARM_CATEGORY_IMAGE_SEXUALLY_EXPLICIT",
                "HARM_CATEGORY_IMAGE_DANGEROUS_CONTENT",
            ]);
            (cats, "BLOCK_NONE")
        }
    };
    cats.iter()
        .map(|c| serde_json::json!({ "category": c, "threshold": threshold }))
        .collect()
}

/// Normalize a client thinking-intent word (spec §8.3 alias table).
pub fn normalize_effort_word(w: &str) -> String {
    match w.trim().to_lowercase().as_str() {
        "min" => "minimal".into(),
        "med" => "medium".into(),
        "max" | "xhigh" | "x-high" | "very_high" => "high".into(),
        "none" | "off" => "off".into(),
        "auto" | "" => String::new(),
        other => other.to_string(),
    }
}

fn thinking_config_for(profile: &Profile, forced: &str) -> Option<Value> {
    match profile.thinking {
        ThinkingKind::Level => {
            let level = if forced.is_empty() {
                profile.default_level.clone()
            } else {
                modelcaps::clamp_level(forced, &profile.levels)
            };
            // thinkingLevel values are UPPERCASE (spec §8.3).
            Some(serde_json::json!({
                "thinkingLevel": level.to_uppercase(),
                "includeThoughts": true,
            }))
        }
        ThinkingKind::Budget => {
            // forced does not apply to budget families (spec §8.3).
            if profile.budget_default < 0 {
                // Dynamic budget (2.5 pro): no explicit budget field.
                Some(serde_json::json!({ "includeThoughts": true }))
            } else {
                Some(serde_json::json!({
                    "thinkingBudget": profile.budget_default,
                    "includeThoughts": true,
                }))
            }
        }
        ThinkingKind::None => None,
    }
}

/// True when the contents array has no user turn (§8.5 degradation case).
fn has_user_turn(contents: &[Value]) -> bool {
    contents
        .iter()
        .any(|c| c.get("role").and_then(Value::as_str) == Some("user"))
}

/// Flatten systemInstruction parts into one text (for the §8.5 fallback).
fn system_text(system: &Value) -> String {
    let mut out = Vec::new();
    if let Some(parts) = system.get("parts").and_then(Value::as_array) {
        for p in parts {
            if let Some(t) = p.get("text").and_then(Value::as_str) {
                out.push(t.to_string());
            }
        }
    } else if let Some(t) = system.get("text").and_then(Value::as_str) {
        out.push(t.to_string());
    }
    out.join("\n")
}

/// Build the upstream request body in Gemini GenerateContentRequest shape
/// from the ir (spec §5.2). The cookie channel wraps the returned value in
/// its GraphQL shell; the express channel posts it as-is.
pub fn build_payload(
    ir: &Ir,
    port: PortKind,
    forced_level: &str,
    profile: &Profile,
    channel: Channel,
) -> Value {
    let mut contents = ir.contents.clone();

    // ---- systemInstruction (§8.5) ----
    let mut system = ir.system.clone();
    if system.is_some() && !has_user_turn(&contents) {
        // Some upstreams reject systemInstruction without any user turn;
        // degrade the system text into a first user message.
        let text = system_text(system.as_ref().unwrap());
        if !text.is_empty() {
            contents.insert(
                0,
                serde_json::json!({ "role": "user", "parts": [{ "text": text }] }),
            );
            system = None;
        }
    }

    // ---- generationConfig (§8.1 / §8.2 / §8.3) ----
    let mut gc = Map::new();
    let client = ir
        .generation_config
        .as_object()
        .cloned()
        .unwrap_or_default();
    let sampling_allowed = !profile.sampling_deprecated;
    for key in ["temperature", "topP"] {
        if sampling_allowed {
            if let Some(v) = client.get(key) {
                gc.insert(key.to_string(), v.clone());
            }
        }
    }
    for key in [
        "stopSequences",
        "seed",
        "responseMimeType",
        "responseSchema",
        "responseLogprobs",
        "logprobs",
        "mediaResolution",
    ] {
        if let Some(v) = client.get(key) {
            if !v.is_null() {
                gc.insert(key.to_string(), v.clone());
            }
        }
    }

    // thinkingConfig matrix (§8.3).
    let thinking: Option<Value> = if port == PortKind::Gemini && forced_level.is_empty() {
        // Pass the client's thinkingConfig through untouched (already
        // snake->camel normalized at parse time).
        client.get("thinkingConfig").cloned()
    } else {
        thinking_config_for(profile, forced_level)
    };
    if let Some(t) = thinking {
        gc.insert("thinkingConfig".into(), t);
    }
    // Everything else the client sent (penalties, topK, maxOutputTokens,
    // tools, ...) never leaves this function — it is not copied.

    // ---- assemble ----
    let mut payload = Map::new();
    payload.insert("contents".into(), Value::Array(contents));
    if let Some(sys) = system {
        payload.insert("systemInstruction".into(), sys);
    }
    if !gc.is_empty() {
        payload.insert("generationConfig".into(), Value::Object(gc));
    }
    payload.insert(
        "safetySettings".into(),
        Value::Array(safety_settings(channel)),
    );
    Value::Object(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ir_for(model: &str, gc: Value) -> Ir {
        Ir {
            model: model.into(),
            forced_channel: None,
            stream: false,
            contents: vec![json!({"role": "user", "parts": [{"text": "hi"}]})],
            system: None,
            generation_config: gc,
            prefill: String::new(),
            include_usage: false,
        }
    }

    #[test]
    fn express_safety_is_8_categories_block_none() {
        let s = safety_settings(Channel::Express);
        assert_eq!(s.len(), 8);
        for item in &s {
            assert_eq!(item["threshold"], "BLOCK_NONE");
        }
        let cats: Vec<&str> = s.iter().map(|x| x["category"].as_str().unwrap()).collect();
        assert!(cats.contains(&"HARM_CATEGORY_IMAGE_HARASSMENT"));
        assert!(!cats.contains(&"HARM_CATEGORY_JAILBREAK"));
        assert!(!cats.contains(&"HARM_CATEGORY_CIVIC_INTEGRITY"));
    }

    #[test]
    fn cookie_safety_is_5_categories_off_with_jailbreak() {
        let s = safety_settings(Channel::Cookie);
        assert_eq!(s.len(), 5);
        for item in &s {
            assert_eq!(item["threshold"], "OFF");
        }
        let cats: Vec<&str> = s.iter().map(|x| x["category"].as_str().unwrap()).collect();
        assert!(cats.contains(&"HARM_CATEGORY_JAILBREAK"));
        assert!(!cats.contains(&"HARM_CATEGORY_IMAGE_HATE"));
    }

    #[test]
    fn forbidden_client_fields_never_reach_payload() {
        let gc = json!({
            "topK": 40,
            "maxOutputTokens": 100,
            "presencePenalty": 0.1,
            "frequencyPenalty": 0.1,
            "temperature": 0.7,
            "stopSequences": ["END"]
        });
        let ir = ir_for("gemini-3.1-pro", gc);
        let p = build_payload(
            &ir,
            PortKind::Oai,
            "",
            &modelcaps::profile("gemini-3.1-pro"),
            Channel::Express,
        );
        let g = &p["generationConfig"];
        assert_eq!(g["temperature"], 0.7);
        assert!(g.get("topK").is_none());
        assert!(g.get("maxOutputTokens").is_none());
        assert!(g.get("presencePenalty").is_none());
        assert!(g.get("frequencyPenalty").is_none());
        assert_eq!(g["stopSequences"], json!(["END"]));
    }

    #[test]
    fn sampling_deprecated_model_strips_temperature_and_topp() {
        let gc = json!({ "temperature": 0.7, "topP": 0.9 });
        let ir = ir_for("gemini-3.6-flash", gc);
        let p = build_payload(
            &ir,
            PortKind::Oai,
            "",
            &modelcaps::profile("gemini-3.6-flash"),
            Channel::Express,
        );
        let g = &p["generationConfig"];
        assert!(g.get("temperature").is_none());
        assert!(g.get("topP").is_none());
    }

    #[test]
    fn oai_port_thinking_uses_forced_then_family_default() {
        // forced empty -> family default (3.1 pro = HIGH).
        let ir = ir_for("gemini-3.1-pro", json!({}));
        let p = build_payload(
            &ir,
            PortKind::Oai,
            "",
            &modelcaps::profile("gemini-3.1-pro"),
            Channel::Express,
        );
        assert_eq!(
            p["generationConfig"]["thinkingConfig"]["thinkingLevel"],
            "HIGH"
        );
        assert_eq!(
            p["generationConfig"]["thinkingConfig"]["includeThoughts"],
            true
        );

        // forced=minimal on 3.1-pro (no minimal level) -> clamps down to LOW.
        let p = build_payload(
            &ir,
            PortKind::Oai,
            "minimal",
            &modelcaps::profile("gemini-3.1-pro"),
            Channel::Express,
        );
        assert_eq!(
            p["generationConfig"]["thinkingConfig"]["thinkingLevel"],
            "LOW"
        );
    }

    #[test]
    fn gemini_port_passthrough_thinking_when_not_forced() {
        let gc = json!({ "thinkingConfig": { "thinkingLevel": "LOW", "includeThoughts": false } });
        let ir = ir_for("gemini-3.1-pro", gc);
        let p = build_payload(
            &ir,
            PortKind::Gemini,
            "",
            &modelcaps::profile("gemini-3.1-pro"),
            Channel::Express,
        );
        assert_eq!(
            p["generationConfig"]["thinkingConfig"]["includeThoughts"],
            false
        );

        // forced set -> override.
        let p = build_payload(
            &ir,
            PortKind::Gemini,
            "high",
            &modelcaps::profile("gemini-3.1-pro"),
            Channel::Express,
        );
        assert_eq!(
            p["generationConfig"]["thinkingConfig"]["thinkingLevel"],
            "HIGH"
        );
        assert_eq!(
            p["generationConfig"]["thinkingConfig"]["includeThoughts"],
            true
        );
    }

    #[test]
    fn budget_family_gets_budget_not_level() {
        let ir = ir_for("gemini-2.5-pro", json!({}));
        let p = build_payload(
            &ir,
            PortKind::Oai,
            "high",
            &modelcaps::profile("gemini-2.5-pro"),
            Channel::Express,
        );
        let tc = &p["generationConfig"]["thinkingConfig"];
        // Dynamic default (-1) on pro: no explicit budget field.
        assert!(tc.get("thinkingLevel").is_none());
        assert!(tc.get("thinkingBudget").is_none());
        assert_eq!(tc["includeThoughts"], true);

        let ir = ir_for("gemini-2.5-flash-lite", json!({}));
        let p = build_payload(
            &ir,
            PortKind::Oai,
            "",
            &modelcaps::profile("gemini-2.5-flash-lite"),
            Channel::Express,
        );
        assert_eq!(p["generationConfig"]["thinkingConfig"]["thinkingBudget"], 0);
    }

    #[test]
    fn none_family_has_no_thinking_config() {
        let ir = ir_for("gemini-2.0-flash", json!({}));
        let p = build_payload(
            &ir,
            PortKind::Oai,
            "",
            &modelcaps::profile("gemini-2.0-flash"),
            Channel::Express,
        );
        assert!(p["generationConfig"].get("thinkingConfig").is_none());
    }

    #[test]
    fn system_degrades_to_user_when_no_user_turn() {
        let mut ir = ir_for("gemini-3.1-pro", json!({}));
        ir.system = Some(json!({ "parts": [{ "text": "be nice" }] }));
        // Replace the user turn with a model turn: no user turn anywhere.
        ir.contents = vec![json!({"role": "model", "parts": [{"text": "ok"}]})];
        let p = build_payload(
            &ir,
            PortKind::Oai,
            "",
            &modelcaps::profile("gemini-3.1-pro"),
            Channel::Express,
        );
        assert!(p.get("systemInstruction").is_none());
        let first = &p["contents"][0];
        assert_eq!(first["role"], "user");
        assert_eq!(first["parts"][0]["text"], "be nice");
    }

    #[test]
    fn system_kept_when_user_turn_exists() {
        let mut ir = ir_for("gemini-3.1-pro", json!({}));
        ir.system = Some(json!({ "parts": [{ "text": "be nice" }] }));
        let p = build_payload(
            &ir,
            PortKind::Oai,
            "",
            &modelcaps::profile("gemini-3.1-pro"),
            Channel::Express,
        );
        assert_eq!(p["systemInstruction"]["parts"][0]["text"], "be nice");
        assert_eq!(p["contents"][0]["role"], "user");
    }

    #[test]
    fn effort_alias_table() {
        assert_eq!(normalize_effort_word("min"), "minimal");
        assert_eq!(normalize_effort_word("med"), "medium");
        assert_eq!(normalize_effort_word("max"), "high");
        assert_eq!(normalize_effort_word("x-high"), "high");
        assert_eq!(normalize_effort_word("none"), "off");
        assert_eq!(normalize_effort_word("auto"), "");
        assert_eq!(normalize_effort_word(""), "");
        assert_eq!(normalize_effort_word("low"), "low");
    }
}
