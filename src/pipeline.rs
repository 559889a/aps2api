//! Execution pipeline (spec §12/§13): the shared retry loop driving one
//! upstream client, feeding events to a port emitter.
//!
//! Red lines implemented here:
//! - once ANY content byte was emitted to the client, never retry again;
//!   SSE heartbeat comment lines do not count (§12.3);
//! - first-response budget: 30s to the first semantic event, lifted forever
//!   after it arrives (§5.4);
//! - client disconnect aborts retries and upstream reads (mpsc send failure).

use std::sync::Arc;

use bytes::Bytes;
use serde_json::Value;
use tokio::sync::mpsc;

use crate::channels::UpstreamClient;
use crate::config::Config;
use crate::ir::{ApiError, Channel, ErrorKind, Ev, UpstreamError};
use crate::retry;

/// What the port layer plugs into the pipeline. Streaming methods produce
/// wire bytes; the aggregation methods build the non-streaming result.
pub trait PortEmitter: Send {
    /// Stream mode: bytes for one event.
    fn on_event(&mut self, ev: &Ev) -> Vec<Bytes>;
    /// Stream mode: bytes after the upstream stream ended normally.
    fn on_stream_end(&mut self) -> Vec<Bytes>;
    /// Stream mode: bytes for a terminal error.
    fn on_error(&mut self, e: &UpstreamError) -> Vec<Bytes>;
    /// Non-stream mode: final result JSON.
    fn take_result(&mut self) -> Value;
}

pub struct Ctx {
    pub config: Arc<Config>,
    pub express: Option<UpstreamClient>,
    pub cookie: Option<UpstreamClient>,
    /// Dedicated reqwest client for remote image fetching (redirects off).
    pub image_client: Option<reqwest::Client>,
}

/// Adapter: mpsc receiver as a `Stream` for `Body::from_stream`.
pub struct ReceiverStream(pub tokio::sync::mpsc::Receiver<Result<Bytes, std::convert::Infallible>>);

impl ReceiverStream {
    pub fn new(rx: tokio::sync::mpsc::Receiver<Result<Bytes, std::convert::Infallible>>) -> Self {
        ReceiverStream(rx)
    }
}

impl futures_util::Stream for ReceiverStream {
    type Item = Result<Bytes, std::convert::Infallible>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.0.poll_recv(cx)
    }
}

impl Ctx {
    pub fn client(&self, channel: Channel) -> Result<&UpstreamClient, ApiError> {
        let want = match channel {
            Channel::Express => self.express.as_ref(),
            Channel::Cookie => self.cookie.as_ref(),
        };
        want.ok_or_else(|| {
            ApiError::bad_request(format!(
                "model routes to the {} channel but its credentials are not configured in config.yaml",
                match channel {
                    Channel::Express => "express",
                    Channel::Cookie => "cookie",
                }
            ))
        })
    }
}

async fn backoff_sleep(cfg: &Config, attempt: u32) {
    tokio::time::sleep(std::time::Duration::from_secs(retry::retry_delay(
        &cfg.retry, attempt,
    )))
    .await;
}

/// Streaming execution: spawns the retry pump, returns the receiver the axum
/// body streams from. Each element is a wire-ready byte segment.
pub async fn run_stream(
    ctx: &Ctx,
    channel: Channel,
    ir: &crate::ir::Ir,
    payload: Value,
    mut em: Box<dyn PortEmitter>,
) -> mpsc::Receiver<Result<Bytes, std::convert::Infallible>> {
    let (tx, rx) = mpsc::channel::<Result<Bytes, std::convert::Infallible>>(64);
    let cfg = ctx.config.clone();
    // Resolve to an OWNED client: the spawned pump must not borrow ctx.
    let client_owned = ctx.client(channel).cloned();
    let model = ir.model.clone();
    let stream_flag = ir.stream;
    tokio::spawn(async move {
        let client = match client_owned {
            Ok(c) => c,
            Err(e) => {
                for b in em.on_error(&UpstreamError {
                    kind: ErrorKind::Invalid,
                    status: Some(400),
                    message: e.message,
                }) {
                    if tx.send(Ok(b)).await.is_err() {
                        return;
                    }
                }
                return;
            }
        };
        let mut attempt: u32 = 0; // retries used so far
        let mut emitted = false;
        'outer: loop {
            // Each attempt rebuilds the request inside start(): cookie
            // regenerates requestContext + SAPISIDHASH; express rebuilds the
            // request object (body is time-independent, §12.3).
            let mut stream = match client.start(&payload, &model, stream_flag).await {
                Ok(s) => s,
                Err(e) => {
                    if !emitted && e.retryable() && attempt < cfg.retry.max {
                        attempt += 1;
                        if !retry::wait_with_heartbeat(
                            retry::retry_delay(&cfg.retry, attempt),
                            true,
                            &tx,
                        )
                        .await
                        {
                            return; // client gone
                        }
                        continue 'outer;
                    }
                    for b in em.on_error(&e) {
                        if tx.send(Ok(b)).await.is_err() {
                            return;
                        }
                    }
                    return;
                }
            };

            // First-response budget: 30s to the first semantic event.
            let first = match tokio::time::timeout(retry::FIRST_RESPONSE_BUDGET, stream.next())
                .await
            {
                Ok(v) => v,
                Err(_elapsed) => {
                    if !emitted && attempt < cfg.retry.max {
                        attempt += 1;
                        if !retry::wait_with_heartbeat(
                            retry::retry_delay(&cfg.retry, attempt),
                            true,
                            &tx,
                        )
                        .await
                        {
                            return;
                        }
                        continue 'outer;
                    }
                    let e = UpstreamError {
                        kind: ErrorKind::Transport,
                        status: None,
                        message: "upstream did not produce any content within the first-response budget (30s)".into(),
                    };
                    for b in em.on_error(&e) {
                        if tx.send(Ok(b)).await.is_err() {
                            return;
                        }
                    }
                    return;
                }
            };

            let mut next = first;
            loop {
                let Some(ev) = next else {
                    // Upstream closed the stream normally.
                    for b in em.on_stream_end() {
                        if tx.send(Ok(b)).await.is_err() {
                            return;
                        }
                    }
                    return;
                };
                if let Ev::Error(e) = ev {
                    if !emitted && e.retryable() && attempt < cfg.retry.max {
                        attempt += 1;
                        if !retry::wait_with_heartbeat(
                            retry::retry_delay(&cfg.retry, attempt),
                            true,
                            &tx,
                        )
                        .await
                        {
                            return;
                        }
                        continue 'outer;
                    }
                    for b in em.on_error(&e) {
                        if tx.send(Ok(b)).await.is_err() {
                            return;
                        }
                    }
                    return;
                }
                emitted = true;
                for b in em.on_event(&ev) {
                    if tx.send(Ok(b)).await.is_err() {
                        return; // client disconnected: stop everything
                    }
                }
                // No more budget deadline: first event already seen.
                next = stream.next().await;
            }
        }
    });
    rx
}

/// Non-streaming execution: aggregates events into the port result.
/// Heartbeats do not apply; retryable failures still loop.
pub async fn run_nonstream(
    ctx: &Ctx,
    channel: Channel,
    ir: &crate::ir::Ir,
    payload: Value,
    mut em: Box<dyn PortEmitter>,
) -> Result<Value, UpstreamError> {
    let cfg = ctx.config.clone();
    let client = ctx.client(channel).map_err(|e| UpstreamError {
        kind: ErrorKind::Invalid,
        status: Some(400),
        message: e.message,
    })?;
    let model = ir.model.clone();
    let mut attempt: u32 = 0;
    let mut emitted = false;
    'outer: loop {
        let mut stream = match client.start(&payload, &model, false).await {
            Ok(s) => s,
            Err(e) => {
                if !emitted && e.retryable() && attempt < cfg.retry.max {
                    attempt += 1;
                    backoff_sleep(&cfg, attempt).await;
                    continue 'outer;
                }
                return Err(e);
            }
        };
        // First-response budget on the very first event.
        let first = match tokio::time::timeout(retry::FIRST_RESPONSE_BUDGET, stream.next()).await {
            Ok(v) => v,
            Err(_) => {
                if !emitted && attempt < cfg.retry.max {
                    attempt += 1;
                    backoff_sleep(&cfg, attempt).await;
                    continue 'outer;
                }
                return Err(UpstreamError {
                    kind: ErrorKind::Transport,
                    status: None,
                    message: "upstream did not produce any content within the first-response budget (30s)".into(),
                });
            }
        };
        let mut next = first;
        loop {
            let Some(ev) = next else {
                return Ok(em.take_result());
            };
            if let Ev::Error(e) = ev {
                if !emitted && e.retryable() && attempt < cfg.retry.max {
                    attempt += 1;
                    backoff_sleep(&cfg, attempt).await;
                    continue 'outer;
                }
                return Err(e);
            }
            emitted = true;
            em.on_event(&ev); // aggregates in non-stream mode
            next = stream.next().await;
        }
    }
}

/// Bypass (fake-streaming) execution (spec §9.5): the client streams over the
/// `fake-streaming/express/<model>` alias while the upstream request runs
/// NON-streaming (express `:generateContent`). During every silent stretch
/// the pump emits `: keep-alive` heartbeats — that keeps first-byte-timeout
/// clients alive and doubles as disconnect detection (a failed heartbeat
/// write tears everything down within one cadence step). When the complete
/// upstream response has arrived, the aggregated events are flushed through
/// the normal streaming emitter in one burst (role chunk → content →
/// finish → [DONE]). Heartbeats never count as emitted content (§12.3), so
/// retryable upstream failures keep their full retry budget.
pub async fn run_bypass(
    ctx: &Ctx,
    ir: &crate::ir::Ir,
    payload: Value,
    mut em: Box<dyn PortEmitter>,
) -> mpsc::Receiver<Result<Bytes, std::convert::Infallible>> {
    let (tx, rx) = mpsc::channel::<Result<Bytes, std::convert::Infallible>>(64);
    let cfg = ctx.config.clone();
    // Bypass is hard-wired to the express channel (§9.5); the dispatch gate
    // has already rejected every other routing.
    let client_owned = ctx.client(Channel::Express).cloned();
    let model = ir.model.clone();
    tokio::spawn(async move {
        let client = match client_owned {
            Ok(c) => c,
            Err(e) => {
                for b in em.on_error(&UpstreamError {
                    kind: ErrorKind::Invalid,
                    status: Some(400),
                    message: e.message,
                }) {
                    if tx.send(Ok(b)).await.is_err() {
                        return;
                    }
                }
                return;
            }
        };
        let mut attempt: u32 = 0;
        'outer: loop {
            // Non-streaming upstream: stream=false regardless of the client's
            // SSE request (that is the whole point of bypass).
            //
            // Phase 1: drive start() under the heartbeat cadence. On
            // :generateContent the response HEADERS arrive only when the
            // whole answer is ready, so TTFB is most of the silent window —
            // heartbeats must already flow here (live-measured: a 13.6s
            // generation produced zero heartbeats when only the body phase
            // was monitored). timeout() cancels only its own poll tick, the
            // pinned future keeps its progress (I/O wakes drive it forward).
            let start_fut = client.start(&payload, &model, false);
            tokio::pin!(start_fut);
            let mut waited = std::time::Duration::ZERO;
            let mut stream = loop {
                match tokio::time::timeout(retry::HEARTBEAT_EVERY, start_fut.as_mut()).await {
                    Ok(Ok(s)) => break s,
                    Ok(Err(e)) => {
                        if e.retryable() && attempt < cfg.retry.max {
                            attempt += 1;
                            if !retry::wait_with_heartbeat(
                                retry::retry_delay(&cfg.retry, attempt),
                                true,
                                &tx,
                            )
                            .await
                            {
                                return; // client gone
                            }
                            continue 'outer;
                        }
                        for b in em.on_error(&e) {
                            if tx.send(Ok(b)).await.is_err() {
                                return;
                            }
                        }
                        return;
                    }
                    Err(_elapsed) => {
                        waited += retry::HEARTBEAT_EVERY;
                        if waited >= retry::BYPASS_FIRST_RESPONSE_BUDGET {
                            if attempt < cfg.retry.max {
                                attempt += 1;
                                if !retry::wait_with_heartbeat(
                                    retry::retry_delay(&cfg.retry, attempt),
                                    true,
                                    &tx,
                                )
                                .await
                                {
                                    return;
                                }
                                continue 'outer;
                            }
                            let e = UpstreamError {
                                kind: ErrorKind::Transport,
                                status: None,
                                message: format!(
                                    "upstream did not produce any content within the bypass                                      first-response budget ({}s)",
                                    retry::BYPASS_FIRST_RESPONSE_BUDGET.as_secs()
                                ),
                            };
                            for b in em.on_error(&e) {
                                if tx.send(Ok(b)).await.is_err() {
                                    return;
                                }
                            }
                            return;
                        }
                        // Keep-alive + disconnect detection (3s granularity).
                        if tx
                            .send(Ok(Bytes::from_static(retry::HEARTBEAT)))
                            .await
                            .is_err()
                        {
                            return; // client gone: drop upstream + pump
                        }
                    }
                }
            };

            // Phase 2: collect the complete upstream response, heartbeating
            // through every silent stretch. The budget bounds only the wait
            // for the FIRST event (a non-stream upstream emits everything at
            // once at the end); afterwards the cadence runs unbounded.
            let mut events: Vec<Ev> = Vec::new();
            let outcome = loop {
                match tokio::time::timeout(retry::HEARTBEAT_EVERY, stream.next()).await {
                    Ok(Some(Ev::Error(e))) => break Err(e),
                    Ok(Some(ev)) => {
                        events.push(ev);
                        waited = std::time::Duration::ZERO;
                    }
                    Ok(None) => break Ok(()),
                    Err(_elapsed) => {
                        waited += retry::HEARTBEAT_EVERY;
                        if events.is_empty() && waited >= retry::BYPASS_FIRST_RESPONSE_BUDGET {
                            break Err(UpstreamError {
                                kind: ErrorKind::Transport,
                                status: None,
                                message: format!(
                                    "upstream did not produce any content within the bypass \
                                     first-response budget ({}s)",
                                    retry::BYPASS_FIRST_RESPONSE_BUDGET.as_secs()
                                ),
                            });
                        }
                        // Keep-alive + disconnect detection (3s granularity).
                        if tx
                            .send(Ok(Bytes::from_static(retry::HEARTBEAT)))
                            .await
                            .is_err()
                        {
                            return; // client gone: drop upstream + pump
                        }
                    }
                }
            };

            let e = match outcome {
                Ok(()) => match events.iter().find_map(|ev| match ev {
                    Ev::Error(e) => Some(e.clone()),
                    _ => None,
                }) {
                    Some(e) => e,
                    None => {
                        // Success: one-shot flush of the whole answer.
                        for ev in &events {
                            for b in em.on_event(ev) {
                                if tx.send(Ok(b)).await.is_err() {
                                    return; // client disconnected mid-flush
                                }
                            }
                        }
                        for b in em.on_stream_end() {
                            if tx.send(Ok(b)).await.is_err() {
                                return;
                            }
                        }
                        return;
                    }
                },
                Err(e) => e,
            };

            // Failure path: nothing semantic has been written yet, so the
            // §12.3 red line still allows retrying.
            if e.retryable() && attempt < cfg.retry.max {
                attempt += 1;
                if !retry::wait_with_heartbeat(retry::retry_delay(&cfg.retry, attempt), true, &tx)
                    .await
                {
                    return;
                }
                continue 'outer;
            }
            for b in em.on_error(&e) {
                if tx.send(Ok(b)).await.is_err() {
                    return;
                }
            }
            return;
        }
    });
    rx
}
