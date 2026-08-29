//! Local API key authentication (spec M0 / §9.1).
//!
//! Clients authenticate with `Authorization: Bearer <key>` or
//! `x-goog-api-key: <key>`. The comparison against `config.api_key` is strict.

use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::AppState;

pub async fn require_api_key(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if provided_key(req.headers()).is_some_and(|k| k == state.config.api_key) {
        return next.run(req).await;
    }
    unauthorized()
}

fn provided_key(headers: &HeaderMap) -> Option<&str> {
    if let Some(v) = headers.get("x-goog-api-key").and_then(|v| v.to_str().ok()) {
        let v = v.trim();
        if !v.is_empty() {
            return Some(v);
        }
    }
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())?;
    auth.strip_prefix("Bearer ")
        .or_else(|| auth.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "error": {
                "message": "invalid or missing API key; expected Authorization: Bearer <key> or x-goog-api-key header",
                "type": "authentication_error",
                "code": 401,
            }
        })),
    )
        .into_response()
}
