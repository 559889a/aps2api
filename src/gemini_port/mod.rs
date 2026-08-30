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

    let ok_model = match resolve_and_info(&state, model) {
        Ok(m) => m,
        Err(e) => return gemini_error(e),
    };

    let body = match read_json_body(req).await {
        Ok(b) => b,
        Err(e) => return gemini_error(e),
    };

    match op {
        "generateContent" => handle(state, ok_model, false, body).await,
        "streamGenerateContent" => handle(state, ok_model, true, body).await,
        other => gemini_error(ApiError {
            status: 404,
            message: format!("unsupported operation {other:?}"),
        }),
    }
}

/// Strip any channel prefix, resolve aliases, and 404 on unknown models.
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

    let profile = modelcaps::profile(&ir.model);
    ir.prefill = prefill::apply_request(&mut ir.contents, profile.requires_user_last_turn);
    fetch_remote_parts(state, &mut ir.contents).await;

    let payload = rewrite::build_payload(
        &ir,
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
    let client = state
        .ctx
        .image_client
        .clone()
        .expect("image client configured");
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
