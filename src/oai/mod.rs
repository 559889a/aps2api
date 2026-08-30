//! OAI-compatible port: /v1/chat/completions + /v1/models (spec §9).

pub mod emit;
pub mod parse;

use std::collections::HashMap;
use std::time::Instant;

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use bytes::Bytes;
use serde_json::{json, Value};

use crate::app::AppState;
use crate::ir::{ApiError, Channel, Ev};
use crate::modelcaps;
use crate::pipeline::{self, PortEmitter};
use crate::prefill;
use crate::rewrite::{self, PortKind};

impl PortEmitter for emit::OaiEmitter {
    fn on_event(&mut self, ev: &Ev) -> Vec<Bytes> {
        emit::OaiEmitter::on_event(self, ev)
    }
    fn on_stream_end(&mut self) -> Vec<Bytes> {
        emit::OaiEmitter::on_stream_end(self)
    }
    fn on_error(&mut self, e: &crate::ir::UpstreamError) -> Vec<Bytes> {
        emit::OaiEmitter::on_error(self, e)
    }
    fn take_result(&mut self) -> Value {
        emit::OaiEmitter::take_result(self)
    }
}

/// GET /v1/models — model.json list; `express/` and `cookie/` prefixed forms
/// are additionally listed, plus the `fake-streaming/express/` bypass aliases
/// when bypass is enabled (spec §9.1/§9.5).
pub async fn list_models(State(state): State<AppState>) -> impl IntoResponse {
    let mut data = Vec::new();
    for m in &state.models.models {
        data.push(model_entry(m));
    }
    for m in &state.models.models {
        data.push(model_entry(&format!("express/{m}")));
        data.push(model_entry(&format!("cookie/{m}")));
    }
    if state.config.bypass {
        for m in &state.models.models {
            data.push(model_entry(&format!("fake-streaming/express/{m}")));
        }
    }
    Json(json!({ "object": "list", "data": data }))
}

fn model_entry(id: &str) -> Value {
    json!({ "id": id, "object": "model", "created": 0, "owned_by": "google" })
}

pub async fn chat_completions(State(state): State<AppState>, Json(body): Json<Value>) -> Response {
    // Gateway-own cost baseline. The Json extractor has already parsed the
    // body before this line, so prep_us on the OAI port misses that parse
    // (the Gemini port reads the body itself and does include it).
    let received_at = Instant::now();
    match handle_chat(&state, &body, received_at).await {
        Ok(resp) => resp,
        Err(e) => oai_error(e),
    }
}

fn oai_error(e: ApiError) -> Response {
    let status = StatusCode::from_u16(e.status).unwrap_or(StatusCode::BAD_REQUEST);
    (
        status,
        Json(json!({
            "error": { "message": e.message, "type": "invalid_request_error", "code": e.status }
        })),
    )
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
                "message": crate::errs::client_message(e),
                "type": "upstream_error",
                "code": status,
            }
        })),
    )
        .into_response()
}

async fn handle_chat(
    state: &AppState,
    body: &Value,
    received_at: Instant,
) -> Result<Response, ApiError> {
    let mut ir = parse::parse(body)?;
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

    // alias_map rewrite, then 404 for models outside model.json (spec §1.2/§2.3).
    ir.model = resolve_model_name(&state.models.alias_map, &state.models.models, &ir.model)?;

    let profile = modelcaps::profile(&ir.model);
    ir.prefill = prefill::apply_request(&mut ir.contents, profile.requires_user_last_turn);

    // Fetch remote http(s) images inline before building the payload (§9.3).
    fetch_remote_parts(state, &mut ir.contents).await;

    let payload = rewrite::build_payload(
        &mut ir,
        PortKind::Oai,
        &state.config.thinking_level,
        &profile,
        channel,
    );

    tracing::info!(
        model = %ir.model,
        channel = match channel { Channel::Express => "express", Channel::Cookie => "cookie" },
        stream = ir.stream,
        bypass = ir.bypass,
        "chat completion"
    );

    if ir.stream {
        let em = Box::new(emit::OaiEmitter::new(
            &ir.model,
            ir.include_usage,
            &ir.prefill,
            true,
        ));
        // Bypass alias: stream to the client, non-stream to the upstream
        // (spec §9.5). Everything else takes the normal streaming path.
        let rx = if ir.bypass {
            pipeline::run_bypass(&state.ctx, &ir, payload, em).await
        } else {
            pipeline::run_stream(&state.ctx, channel, &ir, payload, received_at, em).await
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
        let em = emit::OaiEmitter::new(&ir.model, ir.include_usage, &ir.prefill, false);
        match pipeline::run_nonstream(&state.ctx, channel, &ir, payload, received_at, Box::new(em))
            .await
        {
            Ok(v) => Ok((StatusCode::OK, Json(v)).into_response()),
            Err(e) => Ok(upstream_error_response(&e)),
        }
    }
}

pub fn resolve_model_name(
    alias_map: &HashMap<String, String>,
    models: &[String],
    requested: &str,
) -> Result<String, ApiError> {
    let name = alias_map
        .get(requested)
        .cloned()
        .unwrap_or_else(|| requested.to_string());
    if models.iter().any(|m| m == &name) {
        Ok(name)
    } else {
        Err(ApiError {
            status: 404,
            message: format!("model {requested:?} is not in model.json"),
        })
    }
}

/// Replace remote-fetch placeholders (produced by oai::parse) with inlineData
/// parts (spec §9.3). Failures log a warning and drop the part.
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
