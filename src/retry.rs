//! Retry orchestration (spec §12): fixed/backoff waits, SSE keep-alive
//! heartbeats during waits, first-response budget, and the never-retry-after-
//! emitting guard (enforced by the pipeline that owns the `emitted` flag).

use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::config::RetryConfig;

/// Request start -> first semantic event budget (§5.4). Shell bytes do not
/// count; reaching the first event lifts the deadline for good.
pub const FIRST_RESPONSE_BUDGET: Duration = Duration::from_secs(30);

/// Bypass (fake-streaming) first-response budget (§9.5): the upstream runs
/// NON-streaming, so its single JSON arrives only at completion — a legit
/// generation can far exceed the 30s streaming budget. 300s bounds a hung
/// upstream while heartbeats keep the SSE client alive.
pub const BYPASS_FIRST_RESPONSE_BUDGET: Duration = Duration::from_secs(300);

pub(crate) const HEARTBEAT_EVERY: Duration = Duration::from_secs(3);
pub(crate) const HEARTBEAT: &[u8] = b": keep-alive\n\n";

/// Seconds to wait before retry attempt `n` (1-based): `fixed` waits
/// `interval` every time; `backoff` waits n seconds (linear, no cap).
pub fn retry_delay(cfg: &RetryConfig, attempt: u32) -> u64 {
    match cfg.strategy.as_str() {
        "fixed" => cfg.interval,
        _ => attempt as u64,
    }
}

/// Sleep `seconds`, emitting `: keep-alive` every 3s while waiting (streaming
/// requests only). Returns false when the client connection is gone.
///
/// The wait races the client's hangup instead of only noticing it on the next
/// heartbeat write: a cancel during a long backoff must abandon the retry
/// immediately, or the gateway sends one more upstream request (and burns one
/// more request's worth of quota) for a client that is already gone (spec
/// §12.3, owner bug report 2026-09-02).
pub async fn wait_with_heartbeat(
    seconds: u64,
    heartbeat: bool,
    tx: &mpsc::Sender<Result<Bytes, std::convert::Infallible>>,
) -> bool {
    let mut waited = 0u64;
    while waited < seconds {
        let step = HEARTBEAT_EVERY.as_secs().min(seconds - waited);
        let slept = tokio::select! {
            biased;
            _ = tx.closed() => false,
            _ = tokio::time::sleep(Duration::from_secs(step)) => true,
        };
        if !slept {
            return false;
        }
        waited += step;
        if heartbeat && tx.send(Ok(Bytes::from_static(HEARTBEAT))).await.is_err() {
            return false;
        }
    }
    // A zero-second wait still has to observe an already-gone client.
    !tx.is_closed()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(strategy: &str, interval: u64) -> RetryConfig {
        RetryConfig {
            max: 3,
            strategy: strategy.into(),
            interval,
        }
    }

    #[test]
    fn backoff_is_linear_from_one() {
        let c = cfg("backoff", 2);
        assert_eq!(retry_delay(&c, 1), 1);
        assert_eq!(retry_delay(&c, 2), 2);
        assert_eq!(retry_delay(&c, 5), 5);
    }

    #[test]
    fn fixed_uses_interval() {
        let c = cfg("fixed", 2);
        assert_eq!(retry_delay(&c, 1), 2);
        assert_eq!(retry_delay(&c, 4), 2);
    }

    #[tokio::test]
    async fn a_gone_client_aborts_the_wait_without_sleeping_it_out() {
        // Quota red line (§12.3): a disconnect during a long backoff must end
        // the wait at once instead of running it out and firing one more
        // upstream request. The 600s wait below would hang the test if the
        // hangup were only noticed at the next heartbeat write.
        let (tx, rx) = mpsc::channel::<Result<Bytes, std::convert::Infallible>>(4);
        drop(rx);
        let started = std::time::Instant::now();
        assert!(!wait_with_heartbeat(600, true, &tx).await);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn a_live_client_gets_its_heartbeats() {
        let (tx, mut rx) = mpsc::channel::<Result<Bytes, std::convert::Infallible>>(4);
        assert!(wait_with_heartbeat(0, true, &tx).await, "zero wait is fine");
        // Nothing was emitted for a zero-second wait.
        assert!(rx.try_recv().is_err());
        // One second of waiting is one step and therefore one heartbeat
        // (kept at 1s so the test does not idle for a full cadence step).
        assert!(wait_with_heartbeat(1, true, &tx).await);
        match rx.try_recv() {
            Ok(Ok(b)) => assert_eq!(&b[..], HEARTBEAT),
            other => panic!("expected one heartbeat, got {other:?}"),
        }
        assert!(rx.try_recv().is_err(), "exactly one heartbeat");
    }
}
