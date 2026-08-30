//! Gemini-native port (spec §10): /v1beta/models* routes, dispatched
//! manually because model names may contain channel prefixes (`express/`,
//! `cookie/`) and the `:generateContent` / `:streamGenerateContent` suffix.

pub mod emit;
pub mod parse;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use bytes::Bytes;
use serde_json::{json, Value};

use crate::app::AppState;
use crate::ir::{ApiError, Channel, Ev};
use crate::modelcaps;
use crate::oai;
use crate::pipeline::{self, PortEmitter};
use crate::prefill;
use crate::rewrite::{self, PortKind};

impl PortEmitter for emit::GeminiEmitter {
    fn on_event(&mut self, ev: &Ev) -> Vec<Bytes> {
        emit::GeminiEmitter::on_event(self, ev)
    }
    fn on_stream_end(&mut self) -> Vec<Bytes> {
        emit::GeminiEmitter::on_stream_end(self)
    }
    fn on_error(&mut self, e: &crate::ir::UpstreamError) -> Vec<Bytes> {
        emit::GeminiEmitter::on_error(self, e)
    }
    fn take_result(&mut self) -> Value {
        emit::GeminiEmitter::take_result(self)
    }
}

fn gemini_error(e: ApiError) -> Response {
    let status = StatusCode::from_u16(e.status).unwrap_or(StatusCode::BAD_REQUEST);
    (status, Json(json!({ "error": { "code": e.status, "message": e.message, "status": "INVALID_ARGUMENT" } })))
        .into_response()
}

fn upstream_error_response(e: &crate::ir::UpstreamError) -> Response {
    let status = e.status.unwrap_or(match e.kind {
        crate::ir::ErrorKind::RateLimit => 429,
        crate::ir::ErrorKind::Auth => 403,
        crate::ir::ErrorKind::Project => 400,
        crate::ir::ErrorKind::Transport => 502,
        _ => 500,
    });
    (
        StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
        Json(json!({
            "error": {
                "code": status,
                "message": crate::errs::client_message(e),
                "status": crate::gemini_port::emit::status_name(e.kind),
            }
        })),
    )
        .into_response()
}

/// Unified dispatcher for everything under /v1beta/.
pub async fn dispatch(State(state): State<AppState>, req: Request) -> Response {
    let path = req.uri().path().to_string();
    let Some(rest) = path.strip_prefix("/v1beta/") else {
        return gemini_error(ApiError {
            status: 404,
            message: "not found".into(),
        });
    };
    if rest == "models" {
        return list_models(&state);
    }
    let Some(after) = rest.strip_prefix("models/") else {
        return gemini_error(ApiError {
            status: 404,
            message: format!("unknown path {path}"),
        });
    };

    // Percent-decode (clients may encode the '/' of channel prefixes as %2F),
    // then split "model:operation" (model may itself contain '/').
    let after = percent_encoding::percent_decode_str(after)
        .decode_utf8()
        .map(|c| c.into_owned())
        .unwrap_or_else(|_| after.to_string());
    let (model, op) = match after.rsplit_once(':') {
        Some(pair) => pair,
        None => {
            // GET single model info
            if req.method() != axum::http::Method::GET {
                return gemini_error(ApiError {
                    status: 405,
                    message: "method not allowed for model info".into(),
                });
            }
            return match resolve_and_info(&state, &after) {
                Ok(name) => single_model(&name),
                Err(e) => gemini_error(e),
            };
        }
    };

    // `model` may carry an express//cookie//fake-streaming prefix (spec
    // §2.2/§9.5) — pass it through WHOLE. The prefix must survive to
    // parse::parse (which splits it into forced channel / bypass flag);
    // resolving the alias early and dropping the prefix silently routed
    // every prefixed Gemini request onto the DEFAULT channel.
    let body = match read_json_body(req).await {
        Ok(b) => b,
        Err(e) => return gemini_error(e),
    };

    match op {
        "generateContent" => handle(state, model.to_string(), false, body).await,
        "streamGenerateContent" => handle(state, model.to_string(), true, body).await,
        other => gemini_error(ApiError {
            status: 404,
            message: format!("unsupported operation {other:?}"),
        }),
    }
}

/// Strip any channel prefix, resolve aliases, and 404 on unknown models.
/// Used for GET model-info requests; POST requests keep their prefix (the
/// channel/bypass routing happens in parse::parse).
fn resolve_and_info(state: &AppState, model: &str) -> Result<String, ApiError> {
    let (bare, _forced, _bypass) = crate::ir::split_model_name(model);
    oai::resolve_model_name(&state.models.alias_map, &state.models.models, &bare)
}

async fn read_json_body(req: Request) -> Result<Value, ApiError> {
    let bytes = axum::body::to_bytes(req.into_body(), 64 * 1024 * 1024)
        .await
        .map_err(|e| ApiError {
            status: 400,
            message: format!("failed to read request body: {e}"),
        })?;
    serde_json::from_slice(&bytes).map_err(|e| ApiError {
        status: 400,
        message: format!("invalid JSON body: {e}"),
    })
}

fn list_models(state: &AppState) -> Response {
    let models: Vec<Value> = state
        .models
        .models
        .iter()
        .map(|m| {
            json!({
                "name": format!("models/{m}"),
                "displayName": m,
                "supportedGenerationMethods": ["generateContent", "streamGenerateContent"],
            })
        })
        .collect();
    Json(json!({ "models": models })).into_response()
}

fn single_model(name: &str) -> Response {
    Json(json!({
        "name": format!("models/{name}"),
        "displayName": name,
        "supportedGenerationMethods": ["generateContent", "streamGenerateContent"],
    }))
    .into_response()
}

async fn handle(state: AppState, model: String, stream: bool, body: Value) -> Response {
    match handle_inner(&state, &model, stream, &body).await {
        Ok(resp) => resp,
        Err(e) => gemini_error(e),
    }
}

async fn handle_inner(
    state: &AppState,
    model: &str,
    stream: bool,
    body: &Value,
) -> Result<Response, ApiError> {
    let mut ir = parse::parse(model, stream, body)?;
    // Bypass gate (§9.5): reject fake-streaming aliases when the switch is
    // off or the alias does not target the express channel.
    if let Some(msg) = ir.bypass_violation(state.config.bypass) {
        return Err(ApiError::bad_request(msg));
    }
    let channel = ir
        .resolve_channel(
            state.config.express_enabled(),
            state.config.cookie_enabled(),
        )
        .ok_or_else(|| {
            ApiError::bad_request(
                "no upstream channel is enabled; fill in express or cookie credentials",
            )
        })?;

    // alias_map rewrite, then 404 for models outside model.json — same order
    // as the OAI port (the bypass gate above runs first, so a disabled
    // fake-streaming alias reports the switch instead of a 404).
    ir.model = oai::resolve_model_name(&state.models.alias_map, &state.models.models, &ir.model)?;

    let profile = modelcaps::profile(&ir.model);
    ir.prefill = prefill::apply_request(&mut ir.contents, profile.requires_user_last_turn);
    fetch_remote_parts(state, &mut ir.contents).await;

    let payload = rewrite::build_payload(
        &mut ir,
        PortKind::Gemini,
        &state.config.thinking_level,
        &profile,
        channel,
    );

    tracing::info!(
        model = %ir.model,
        channel = match channel { Channel::Express => "express", Channel::Cookie => "cookie" },
        stream = ir.stream,
        bypass = ir.bypass,
        "gemini generate"
    );

    if stream {
        let em = Box::new(emit::GeminiEmitter::new(&ir.model, &ir.prefill, true));
        // Bypass alias: stream to the client, non-stream to the upstream
        // (spec §9.5). Everything else takes the normal streaming path.
        let rx = if ir.bypass {
            pipeline::run_bypass(&state.ctx, &ir, payload, em).await
        } else {
            pipeline::run_stream(&state.ctx, channel, &ir, payload, em).await
        };
        Ok((
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "text/event-stream"),
                (header::CACHE_CONTROL, "no-cache"),
            ],
            Body::from_stream(pipeline::ReceiverStream::new(rx)),
        )
            .into_response())
    } else {
        let em = emit::GeminiEmitter::new(&ir.model, &ir.prefill, false);
        match pipeline::run_nonstream(&state.ctx, channel, &ir, payload, Box::new(em)).await {
            Ok(v) => Ok((StatusCode::OK, Json(v)).into_response()),
            Err(e) => Ok(upstream_error_response(&e)),
        }
    }
}

async fn fetch_remote_parts(state: &AppState, contents: &mut [Value]) {
    let client = state.ctx.image_client.clone();
    let proxied = state.config.socks5.is_some();
    let fetch = move |url: String| {
        let client = client.clone();
        async move { crate::images::fetch_remote_image(&client, proxied, &url).await }
    };
    for turn in contents.iter_mut() {
        let Some(parts) = turn.get_mut("parts").and_then(Value::as_array_mut) else {
            continue;
        };
        crate::images::resolve_remote_parts(parts, &fetch).await;
    }
}

#[cfg(test)]
mod dispatch_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::any;
    use tower::ServiceExt;

    fn express_only_state(bypass: bool) -> AppState {
        let cfg = crate::config::Config {
            api_key: "k".into(),
            port: 8080,
            socks5: None,
            express: crate::config::ExpressConfig {
                api_key: "AQ.test-key".into(),
                project_id: "p".into(),
                location: "global".into(),
            },
            cookie: crate::config::CookieConfig::default(),
            thinking_level: String::new(),
            bypass,
            retry: Default::default(),
        };
        let models = crate::config::ModelFile {
            models: vec!["m1".to_string()],
            alias_map: Default::default(),
        };
        AppState::build(cfg, models).expect("test state builds")
    }

    async fn post(state: AppState, path: &str, body: &str) -> (StatusCode, String) {
        let app = axum::Router::new()
            .route("/v1beta/{*rest}", any(dispatch))
            .with_state(state);
        let resp = app
            .oneshot(
                Request::post(format!("http://test{path}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    const CHAT: &str = r#"{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}"#;

    #[tokio::test]
    async fn channel_prefix_routes_the_forced_channel() {
        // Regression (2026-08-30): dispatch used to strip the
        // express//cookie/ prefix (resolve_and_info) before parse, silently
        // routing every prefixed request onto the DEFAULT channel — spec
        // §2.2 forces the channel on BOTH ports. With only express
        // configured, `cookie/m1` must fail with the not-configured error
        // instead of falling through to express.
        let state = express_only_state(false);
        let (status, body) = post(state, "/v1beta/models/cookie/m1:generateContent", CHAT).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body.contains("cookie channel"),
            "expected the forced-cookie routing error, got: {body}"
        );
    }

    #[tokio::test]
    async fn bypass_alias_gate_applies_on_the_gemini_port() {
        // `fake-streaming/express/<model>` must hit the §9.5 gate (the prefix
        // has to reach parse), not fall through to a bare-model 404 or a
        // default-channel upstream request.
        let state = express_only_state(false);
        let (status, body) = post(
            state,
            "/v1beta/models/fake-streaming/express/m1:generateContent",
            CHAT,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body.contains("bypass mode is disabled"),
            "expected the bypass gate error, got: {body}"
        );
    }

    #[tokio::test]
    async fn unknown_model_is_404() {
        let state = express_only_state(false);
        let (status, body) = post(state, "/v1beta/models/nope:generateContent", CHAT).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(
            body.contains("not in model.json"),
            "expected the model.json 404, got: {body}"
        );
    }

    #[tokio::test]
    async fn fake_streaming_cookie_shape_is_rejected_by_the_gate() {
        // `fake-streaming/cookie/...` is a gate rejection (§9.5), reachable
        // only when the prefix survives dispatch.
        let state = express_only_state(true);
        let (status, body) = post(
            state,
            "/v1beta/models/fake-streaming/cookie/m1:generateContent",
            CHAT,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body.contains("express channel only"),
            "expected the express-only alias error, got: {body}"
        );
    }
}
