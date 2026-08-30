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
use std::time::Instant;

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
    /// Always present (built unconditionally in AppState::build) — a plain
    /// field keeps the port handlers panic-free.
    pub image_client: reqwest::Client,
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

/// Log tag for the channel (the enum has no Display impl).
fn channel_name(channel: Channel) -> &'static str {
    match channel {
        Channel::Express => "express",
        Channel::Cookie => "cookie",
    }
}

/// Retry visibility (owner request 2026-08-30): every retry decision must be
/// plainly visible in the log — which retry of how many, the backoff delay
/// about to run, and why. Without this a silent retry loop is impossible to
/// distinguish from a hung upstream.
fn log_retry(channel: Channel, model: &str, retry_no: u32, max: u32, delay_secs: u64, error: &str) {
    tracing::warn!(
        channel = channel_name(channel),
        model = %model,
        retry = retry_no,
        max = max,
        delay_secs = delay_secs,
        "upstream attempt failed; retrying ({error})"
    );
}

/// Terminal upstream failure about to reach the client (no retry possible or
/// budget gone). `emitted` distinguishes the never-retry-after-output red
/// line (§12.3) from an exhausted budget.
fn log_give_up(
    channel: Channel,
    model: &str,
    retries_used: u32,
    max: u32,
    emitted: bool,
    e: &UpstreamError,
) {
    let why = if !e.retryable() {
        "non-retryable"
    } else if emitted {
        "content already emitted; retry forbidden"
    } else {
        "retry budget exhausted"
    };
    tracing::error!(
        channel = channel_name(channel),
        model = %model,
        retries_used = retries_used,
        max = max,
        error = %e.message,
        "upstream failed ({why}); returning the error to the client"
    );
}

/// Seconds at two-decimal precision for summary fields — a raw f64 printout
/// of a Duration trails garbage digits (13.6123456789 s) that read as noise.
fn secs_f64(d: std::time::Duration) -> f64 {
    (d.as_secs_f64() * 100.0).round() / 100.0
}

/// Output token count from a `usageMetadata` object: candidatesTokenCount
/// plus thoughtsTokenCount when present — thought text is part of the
/// streamed output, so both count toward generation speed. None when the
/// upstream reports no usable counts (the cookie channel never does, §7.2;
/// the summary then logs without tokens/tps instead of a fake 0).
fn usage_output_tokens(usage: &Value) -> Option<u64> {
    match (
        usage.get("candidatesTokenCount").and_then(Value::as_u64),
        usage.get("thoughtsTokenCount").and_then(Value::as_u64),
    ) {
        (Some(c), Some(t)) => Some(c + t),
        (Some(c), None) => Some(c),
        (None, Some(t)) => Some(t),
        (None, None) => None,
    }
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
            // TTFB baseline: reset per attempt (a retry restarts the clock).
            let started = Instant::now();
            // Stream-summary bookkeeping (owner request 2026-08-30), per
            // attempt like the clock: when the first token landed and how
            // many output tokens the usage trailer reported.
            let mut first_token_at: Option<Instant> = None;
            let mut output_tokens: Option<u64> = None;
            // Each attempt rebuilds the request inside start(): cookie
            // regenerates requestContext + SAPISIDHASH; express rebuilds the
            // request object (body is time-independent, §12.3).
            let mut stream = match client.start(&payload, &model, stream_flag).await {
                Ok(s) => s,
                Err(e) => {
                    if !emitted && e.retryable() && attempt < cfg.retry.max {
                        attempt += 1;
                        log_retry(
                            channel,
                            &model,
                            attempt,
                            cfg.retry.max,
                            retry::retry_delay(&cfg.retry, attempt),
                            &e.message,
                        );
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
                    log_give_up(channel, &model, attempt, cfg.retry.max, emitted, &e);
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
                        log_retry(
                            channel,
                            &model,
                            attempt,
                            cfg.retry.max,
                            retry::retry_delay(&cfg.retry, attempt),
                            "no first event within the first-response budget (30s)",
                        );
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
                    log_give_up(channel, &model, attempt, cfg.retry.max, false, &e);
                    for b in em.on_error(&e) {
                        if tx.send(Ok(b)).await.is_err() {
                            return;
                        }
                    }
                    return;
                }
            };

            // TTFB visibility (owner request 2026-08-30): time to the FIRST
            // semantic upstream event, logged for every successful response.
            // Bypass logs none (its upstream is non-streaming — no first
            // token to time). The instant is kept for the end-of-stream
            // summary (generation window + TPS).
            if let Some(ev) = &first {
                if !matches!(ev, Ev::Error(_)) {
                    first_token_at = Some(Instant::now());
                    tracing::info!(
                        channel = channel_name(channel),
                        model = %model,
                        ttfb_ms = started.elapsed().as_millis() as u64,
                        "upstream first response"
                    );
                }
            }

            let mut next = first;
            loop {
                let Some(ev) = next else {
                    // Upstream closed the stream normally.
                    // Stream summary (owner request 2026-08-30): one line per
                    // successful stream — wall clock, generation window, TPS,
                    // output size, retries consumed. Streaming only: the
                    // non-stream path (run_nonstream) and bypass end
                    // differently and log no summary.
                    if emitted {
                        let total_s = secs_f64(started.elapsed());
                        match first_token_at {
                            Some(ft) => {
                                let gen_dur = ft.elapsed();
                                let gen_s = secs_f64(gen_dur);
                                match output_tokens
                                    .filter(|&t| t > 0 && gen_dur.as_secs_f64() > 0.0)
                                {
                                    Some(tokens) => tracing::info!(
                                        channel = channel_name(channel),
                                        model = %model,
                                        total_s = total_s,
                                        gen_s = gen_s,
                                        tokens,
                                        tps = (tokens as f64 / gen_dur.as_secs_f64() * 10.0)
                                            .round()
                                            / 10.0,
                                        retries = attempt,
                                        "stream complete"
                                    ),
                                    None => tracing::info!(
                                        channel = channel_name(channel),
                                        model = %model,
                                        total_s = total_s,
                                        gen_s = gen_s,
                                        retries = attempt,
                                        "stream complete"
                                    ),
                                }
                            }
                            None => tracing::info!(
                                channel = channel_name(channel),
                                model = %model,
                                total_s = total_s,
                                retries = attempt,
                                "stream complete"
                            ),
                        }
                    }
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
                        log_retry(
                            channel,
                            &model,
                            attempt,
                            cfg.retry.max,
                            retry::retry_delay(&cfg.retry, attempt),
                            &e.message,
                        );
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
                    log_give_up(channel, &model, attempt, cfg.retry.max, emitted, &e);
                    for b in em.on_error(&e) {
                        if tx.send(Ok(b)).await.is_err() {
                            return;
                        }
                    }
                    return;
                }
                emitted = true;
                if let Ev::Usage(u) = &ev {
                    output_tokens = usage_output_tokens(u);
                }
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
        // TTFB baseline: reset per attempt (a retry restarts the clock).
        let started = Instant::now();
        let mut stream = match client.start(&payload, &model, false).await {
            Ok(s) => s,
            Err(e) => {
                if !emitted && e.retryable() && attempt < cfg.retry.max {
                    attempt += 1;
                    log_retry(
                        channel,
                        &model,
                        attempt,
                        cfg.retry.max,
                        retry::retry_delay(&cfg.retry, attempt),
                        &e.message,
                    );
                    backoff_sleep(&cfg, attempt).await;
                    continue 'outer;
                }
                log_give_up(channel, &model, attempt, cfg.retry.max, emitted, &e);
                return Err(e);
            }
        };
        // First-response budget on the very first event.
        let first = match tokio::time::timeout(retry::FIRST_RESPONSE_BUDGET, stream.next()).await {
            Ok(v) => v,
            Err(_) => {
                if !emitted && attempt < cfg.retry.max {
                    attempt += 1;
                    log_retry(
                        channel,
                        &model,
                        attempt,
                        cfg.retry.max,
                        retry::retry_delay(&cfg.retry, attempt),
                        "no first event within the first-response budget (30s)",
                    );
                    backoff_sleep(&cfg, attempt).await;
                    continue 'outer;
                }
                let e = UpstreamError {
                    kind: ErrorKind::Transport,
                    status: None,
                    message: "upstream did not produce any content within the first-response budget (30s)".into(),
                };
                log_give_up(channel, &model, attempt, cfg.retry.max, false, &e);
                return Err(e);
            }
        };
        // TTFB visibility (owner request 2026-08-30): even non-streaming
        // replies are aggregated from the upstream's event stream, so the
        // first event IS the first token. Bypass logs none (§9.5).
        if let Some(ev) = &first {
            if !matches!(ev, Ev::Error(_)) {
                tracing::info!(
                    channel = channel_name(channel),
                    model = %model,
                    ttfb_ms = started.elapsed().as_millis() as u64,
                    "upstream first response"
                );
            }
        }
        let mut next = first;
        loop {
            let Some(ev) = next else {
                return Ok(em.take_result());
            };
            if let Ev::Error(e) = ev {
                if !emitted && e.retryable() && attempt < cfg.retry.max {
                    attempt += 1;
                    log_retry(
                        channel,
                        &model,
                        attempt,
                        cfg.retry.max,
                        retry::retry_delay(&cfg.retry, attempt),
                        &e.message,
                    );
                    backoff_sleep(&cfg, attempt).await;
                    continue 'outer;
                }
                log_give_up(channel, &model, attempt, cfg.retry.max, emitted, &e);
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
/// retryable upstream failures keep their full retry budget. Retry
/// decisions are logged like every other path; there is deliberately NO
/// TTFB log here — the upstream request is non-streaming, so there is no
/// first token to time (owner request 2026-08-30).
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
                            log_retry(
                                Channel::Express,
                                &model,
                                attempt,
                                cfg.retry.max,
                                retry::retry_delay(&cfg.retry, attempt),
                                &e.message,
                            );
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
                        log_give_up(Channel::Express, &model, attempt, cfg.retry.max, false, &e);
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
                                log_retry(
                                    Channel::Express,
                                    &model,
                                    attempt,
                                    cfg.retry.max,
                                    retry::retry_delay(&cfg.retry, attempt),
                                    "no response within the bypass first-response budget",
                                );
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
                                    "upstream did not produce any content within the bypass \
                                     first-response budget ({}s)",
                                    retry::BYPASS_FIRST_RESPONSE_BUDGET.as_secs()
                                ),
                            };
                            log_give_up(
                                Channel::Express,
                                &model,
                                attempt,
                                cfg.retry.max,
                                false,
                                &e,
                            );
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
                log_retry(
                    Channel::Express,
                    &model,
                    attempt,
                    cfg.retry.max,
                    retry::retry_delay(&cfg.retry, attempt),
                    &e.message,
                );
                if !retry::wait_with_heartbeat(retry::retry_delay(&cfg.retry, attempt), true, &tx)
                    .await
                {
                    return;
                }
                continue 'outer;
            }
            log_give_up(Channel::Express, &model, attempt, cfg.retry.max, false, &e);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_output_tokens_sums_candidates_and_thoughts() {
        // Live express sample 2026-08-30: 1/5/103 — thoughts are a separate
        // counter and part of the streamed output, so both count for TPS.
        let u = serde_json::json!({
            "promptTokenCount": 1,
            "candidatesTokenCount": 5,
            "thoughtsTokenCount": 97,
            "totalTokenCount": 103
        });
        assert_eq!(usage_output_tokens(&u), Some(102));
        assert_eq!(
            usage_output_tokens(&serde_json::json!({"candidatesTokenCount": 7})),
            Some(7)
        );
        assert_eq!(
            usage_output_tokens(&serde_json::json!({"thoughtsTokenCount": 3})),
            Some(3)
        );
        assert_eq!(usage_output_tokens(&serde_json::json!({})), None);
        // Zero output stays Some(0): the summary then drops tps instead of
        // logging a fake division result.
        assert_eq!(
            usage_output_tokens(&serde_json::json!({"candidatesTokenCount": 0})),
            Some(0)
        );
    }

    #[test]
    fn secs_two_decimals() {
        use std::time::Duration;
        assert_eq!(secs_f64(Duration::from_millis(13_612)), 13.61);
        assert_eq!(secs_f64(Duration::from_millis(13_600)), 13.6);
        assert_eq!(secs_f64(Duration::ZERO), 0.0);
    }
}
