//! Cookie upstream channel (spec §6/§7): batchGraphql direct connection to
//! the Vertex AI Studio frontend endpoint, fully disguised as a Chrome
//! session — three layers:
//!   L1 TLS/HTTP2 fingerprint: wreq with the pinned Chrome149 emulation;
//!   L2 header set: full Chrome header collection in fixed order (§6.2);
//!   L3 protocol body: GraphQL shell + requestContext session fingerprint.
//!
//! Auth (SAPISIDHASH x3) is recomputed for EVERY request and retry, with all
//! three segments from one `now()` instant (spec traps 1-2).

use serde_json::{json, Map, Value};
use tokio::sync::mpsc;
use wreq_util::{Emulation, Platform, Profile};

use crate::channels::{extract_from_chunk, EvStream};
use crate::config::CookieConfig;
use crate::errs;
use crate::ir::{ErrorKind, Ev, UpstreamError};
use crate::sapisid;

/// Pinned magic values (spec §6.6): these three rot when Google ships a new
/// frontend build. When the channel fails as a whole (not 429), suspect
/// these first and re-capture from DevTools.
const BATCHGRAPHQL_URL: &str = "https://cloudconsole-pa.clients6.google.com\
/v3/entityServices/AiplatformEntityService/schemas/AIPLATFORM_GRAPHQL:batchGraphql\
?key=AIzaSyCI-zsRP85UVOi0DjtiCwHBwQ1djDy741g&prettyPrint=false";
const QUERY_SIGNATURE: &str = "2/VMwZooA0XN10Wuu2r5N9Hw+S9X+WG4G8k423Pl7/oqw=";
const CLIENT_VERSION: &str = "boq_cloud-boq-clientweb-vertexaistudio_20260609.06_p0";
const ORIGIN: &str = "https://console.cloud.google.com";

/// Chrome149 Windows companion values — copied verbatim from the wreq-util
/// 0.2.0 preset (spec §6.2: never invent, never rotate at runtime). Must be
/// kept in sync with `httpx::EMULATION_VERSION`.
pub const SEC_CH_UA: &str = r#""Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24""#;
pub const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36";

pub fn emulation() -> Emulation {
    // Pinned profile + Windows platform: the UA / sec-ch-ua strings above are
    // copied from exactly this preset's Windows row (§6.2 consistency).
    Emulation::builder()
        .profile(Profile::Chrome149)
        .platform(Platform::Windows)
        .build()
}

#[derive(Clone)]
pub struct CookieClient {
    http: wreq::Client,
    cookie: String,
    project_id: String,
    experiment_flags: String,
}

impl CookieClient {
    pub fn new(http: wreq::Client, cfg: &CookieConfig) -> Self {
        CookieClient {
            http,
            cookie: cfg.cookie.clone(),
            project_id: cfg.project_id.trim().to_string(),
            experiment_flags: cfg.experiment_flags.clone(),
        }
    }

    /// Fresh requestContext per request AND per retry (spec §6.4).
    fn request_context(&self) -> Value {
        let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
        let now_us = now_ms * 1000;
        json!({
            "clientVersion": CLIENT_VERSION,
            "pagePath": "/agent-platform/studio/multimodal",
            "pageViewId": now_ms % 1_000_000_000_000_000,
            "trackingId": format!("{}", now_us % 100_000_000_000_000_000),
            "backendOverrides": {},
            "clientSessionId": uuid::Uuid::new_v4().to_string().to_uppercase(),
            "projectId": self.project_id,
            "selectedPurview": { "projectId": self.project_id },
            "jurisdiction": "global",
            "experimentFlagsBinary": self.experiment_flags,
            "localizationData": { "locale": "zh_CN", "timezone": "Asia/Hong_Kong" },
        })
    }

    /// variables.model: full project path, location pinned to global (§6.5).
    fn model_path(&self, model: &str) -> String {
        format!(
            "projects/{}/locations/global/publishers/google/models/{}",
            self.project_id, model
        )
    }

    /// GraphQL shell (§6.3) around the rewritten Gemini payload. Only the
    /// whitelisted fields (contents/systemInstruction/safetySettings/
    /// generationConfig) are copied into variables.
    fn build_shell(&self, payload: &Value, model: &str) -> Value {
        let mut variables = Map::new();
        variables.insert("model".into(), json!(self.model_path(model)));
        for key in [
            "contents",
            "systemInstruction",
            "safetySettings",
            "generationConfig",
        ] {
            if let Some(v) = payload.get(key) {
                variables.insert(key.to_string(), v.clone());
            }
        }
        json!({
            "requestContext": self.request_context(),
            "querySignature": QUERY_SIGNATURE,
            "operationName": "StreamGenerateContent",
            "variables": Value::Object(variables),
        })
    }

    /// The §6.2 header set, in fixed order, rebuilt for every attempt.
    fn headers(&self) -> wreq::header::HeaderMap {
        use wreq::header::{HeaderMap, HeaderName, HeaderValue};
        let mut m = HeaderMap::new();
        let mut put = |name: &'static str, value: &str| {
            if let Ok(v) = HeaderValue::from_str(value) {
                m.insert(HeaderName::from_static(name), v);
            }
        };
        put("sec-ch-ua", SEC_CH_UA);
        put("sec-ch-ua-mobile", "?0");
        put("sec-ch-ua-platform", r#""Windows""#);
        put("content-type", "application/json");
        put("x-goog-authuser", "0");
        put("x-same-domain", "1");
        put(
            "authorization",
            &sapisid::authorization_header(&self.cookie),
        );
        put("x-origin", ORIGIN);
        put("origin", ORIGIN);
        put("referer", "https://console.cloud.google.com/");
        put("accept", "*/*");
        put("accept-encoding", "gzip, deflate, br, zstd");
        put("accept-language", "zh-CN,zh;q=0.9,en;q=0.8");
        put("cookie", &self.cookie);
        put("user-agent", USER_AGENT);
        put("sec-fetch-site", "same-origin");
        put("sec-fetch-mode", "cors");
        put("sec-fetch-dest", "empty");
        m
    }

    pub async fn start(
        &self,
        payload: &Value,
        model: &str,
        _stream: bool,
    ) -> Result<EvStream, UpstreamError> {
        // batchGraphql has a single operation (StreamGenerateContent);
        // non-streaming is aggregated from the same event stream (§7.2).
        let body = self.build_shell(payload, model).to_string();
        let resp = self
            .http
            .post(BATCHGRAPHQL_URL)
            .headers(self.headers())
            .body(body)
            .send()
            .await
            .map_err(|e| {
                let message = e.to_string();
                if message.to_lowercase().contains("timeout") {
                    UpstreamError {
                        kind: ErrorKind::Transport,
                        status: None,
                        message,
                    }
                } else {
                    errs::classify_error(None, message)
                }
            })?;
        let status = resp.status().as_u16();
        if !(200..300).contains(&status) {
            let text = resp.text().await.unwrap_or_default();
            return Err(errs::classify_error(
                Some(status),
                cookie_error_message(&text),
            ));
        }
        let (tx, rx) = mpsc::channel::<Ev>(64);
        tokio::spawn(crate::channels::pump_concat(
            resp.bytes_stream(),
            tx,
            cookie_extract,
        ));
        Ok(EvStream::new(rx))
    }
}

/// batchGraphql response wrapper -> events (spec §13.2, cookie side):
/// top-level `error` -> Error; `results[]`: item `errors` -> first error,
/// item `data` -> standard Gemini chunk.
pub fn cookie_extract(obj: &Value, out: &mut Vec<Ev>) {
    if let Some(err) = obj.get("error") {
        out.push(Ev::Error(error_from_value(err)));
    }
    if let Some(results) = obj.get("results").and_then(Value::as_array) {
        for r in results {
            if let Some(errs) = r.get("errors").and_then(Value::as_array) {
                if let Some(first) = errs.first() {
                    out.push(Ev::Error(error_from_value(first)));
                    continue;
                }
            }
            if let Some(data) = r.get("data") {
                if data.is_object() {
                    extract_from_chunk(data, out);
                }
            }
        }
    }
}

fn error_from_value(err: &Value) -> UpstreamError {
    let message = err
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("unknown batchGraphql error")
        .to_string();
    let status = err.get("code").and_then(Value::as_u64).map(|c| c as u16);
    errs::classify_error(status, message)
}

fn cookie_error_message(body: &str) -> String {
    match serde_json::from_str::<Value>(body) {
        Ok(v) => error_from_value(&v).message,
        Err(_) => {
            let truncated: String = body.chars().take(300).collect();
            if truncated.is_empty() {
                "(empty error body)".to_string()
            } else {
                truncated
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_wraps_payload_with_whitelist_only() {
        let c = CookieClient::new(
            wreq::Client::builder().build().unwrap(),
            &CookieConfig {
                cookie: "SAPISID=x".into(),
                project_id: "proj".into(),
                experiment_flags: "flags".into(),
            },
        );
        let payload = json!({
            "contents": [{"role": "user", "parts": []}],
            "systemInstruction": {"parts": [{"text": "s"}]},
            "safetySettings": [],
            "generationConfig": {},
            "sneakyExtra": 1
        });
        let shell = c.build_shell(&payload, "gemini-3.1-pro");
        assert_eq!(shell["operationName"], "StreamGenerateContent");
        assert_eq!(shell["querySignature"], QUERY_SIGNATURE);
        let rc = &shell["requestContext"];
        assert_eq!(rc["clientVersion"], CLIENT_VERSION);
        assert_eq!(rc["projectId"], "proj");
        assert_eq!(rc["experimentFlagsBinary"], "flags");
        assert_eq!(rc["jurisdiction"], "global");
        assert!(rc["clientSessionId"].as_str().unwrap().len() == 36);
        let vars = &shell["variables"];
        assert_eq!(
            vars["model"],
            "projects/proj/locations/global/publishers/google/models/gemini-3.1-pro"
        );
        assert!(vars.get("contents").is_some());
        assert!(vars.get("sneakyExtra").is_none());
    }

    #[test]
    fn request_context_is_fresh_every_call() {
        let c = CookieClient::new(
            wreq::Client::builder().build().unwrap(),
            &CookieConfig {
                cookie: String::new(),
                project_id: "p".into(),
                experiment_flags: String::new(),
            },
        );
        let a = c.request_context();
        let b = c.request_context();
        let sa = a["clientSessionId"].as_str().unwrap();
        let sb = b["clientSessionId"].as_str().unwrap();
        assert_ne!(sa, sb, "clientSessionId must be regenerated per request");
    }

    #[test]
    fn cookie_extract_maps_wrapper_to_events() {
        let obj = json!({
            "results": [
                { "errors": [], "data": { "candidates": [ { "content": { "parts": [ { "text": "hi" } ] } } ] } },
                { "errors": [ { "code": 429, "message": "resource exhausted" } ] }
            ]
        });
        let mut out = Vec::new();
        cookie_extract(&obj, &mut out);
        assert!(matches!(&out[0], Ev::Text(t) if t == "hi"));
        assert!(matches!(&out[1], Ev::Error(e) if e.kind == ErrorKind::RateLimit));
    }

    #[test]
    fn cookie_extract_top_level_error() {
        let obj = json!({ "error": { "code": 401, "message": "unauthenticated" } });
        let mut out = Vec::new();
        cookie_extract(&obj, &mut out);
        assert!(matches!(&out[0], Ev::Error(e) if e.kind == ErrorKind::Auth));
    }
}
