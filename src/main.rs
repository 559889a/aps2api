//! aps2api — Vertex Gemini 2api proxy (express + cookie dual upstream).
//!
//! Boot (spec §1.3/M0): load config.yaml + model.json from the binary's own
//! directory (fallback: CWD for `cargo run` dev) → axum serve. Any config
//! problem prints a field-naming error and exits.

mod auth;
mod config;

use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Request, State};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<config::Config>,
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn log_request(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let started = Instant::now();
    let resp = next.run(req).await;
    tracing::info!(
        method = %method,
        path = %path,
        status = resp.status().as_u16(),
        elapsed_ms = started.elapsed().as_millis() as u64,
        "request"
    );
    resp
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_max_level(tracing::Level::INFO)
        .init();

    let cfg = config::load_config();
    tracing::info!(
        port = cfg.port,
        express = cfg.express_enabled(),
        cookie = cfg.cookie_enabled(),
        proxy = cfg.socks5.is_some(),
        "config loaded"
    );

    let bind_addr = format!("0.0.0.0:{}", cfg.port);
    let state = AppState { config: Arc::new(cfg) };

    let protected = Router::new()
        // API routes are mounted in later milestones (/v1, /v1beta).
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_api_key,
        ));

    let app = Router::new()
        .route("/health", get(health))
        .merge(protected)
        .layer(middleware::from_fn(log_request))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .unwrap_or_else(|e| panic!("cannot bind {bind_addr}: {e}"));
    tracing::info!("listening on http://{bind_addr}");
    axum::serve(listener, app)
        .await
        .expect("server terminated unexpectedly");
}
