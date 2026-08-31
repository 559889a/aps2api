//! aps2api — Vertex Gemini 2api proxy (express + cookie dual upstream).
//!
//! Boot (spec §1.3/M0): load config.yaml + model.json from the binary's own
//! directory (fallback: CWD for `cargo run` dev) → build outbound clients →
//! axum serve. Any config problem prints a field-naming error and exits.

mod app;
mod auth;
mod channels;
mod config;
mod cookiejar;
mod errs;
mod gemini_port;
mod httpx;
mod images;
mod ir;
mod modelcaps;
mod oai;
mod pipeline;
mod prefill;
mod retry;
mod rewrite;
mod sapisid;
mod streamscan;

use std::time::Instant;

use axum::extract::Request;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};

use crate::app::AppState;

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
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cfg = config::load_config();
    let models = config::load_models();
    tracing::info!(
        port = cfg.port,
        express = cfg.express_enabled(),
        cookie = cfg.cookie_enabled(),
        proxy = cfg.socks5.is_some(),
        "config loaded"
    );

    let bind_addr = format!("0.0.0.0:{}", cfg.port);
    let state = AppState::build(cfg, models).unwrap_or_else(|e| {
        eprintln!("aps2api: {e}");
        std::process::exit(1);
    });

    // Advisory socks5 reachability probe (spec §2.2): runs concurrently so a
    // slow/unreachable entry never delays the listener; failures surface as
    // a boot-time WARN naming the three usual causes.
    {
        let state = state.clone();
        tokio::spawn(async move {
            state.probe_outbound().await;
        });
    }

    let protected = Router::new()
        .route("/v1/models", get(oai::list_models))
        .route("/v1/chat/completions", post(oai::chat_completions))
        // Model names may contain '/' prefixes and ':operation' suffixes —
        // dispatched manually inside (spec §10.1).
        .route("/v1beta/{*rest}", any(gemini_port::dispatch))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_api_key,
        ))
        // axum's default body limit is 2MB and would 413 image-bearing
        // requests (base64 data URLs); match the Gemini port's explicit
        // 64MB cap (§9.2/§10.2).
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024 * 1024));

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
