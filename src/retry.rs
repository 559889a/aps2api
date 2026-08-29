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

const HEARTBEAT_EVERY: Duration = Duration::from_secs(3);
const HEARTBEAT: &[u8] = b": keep-alive\n\n";

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
pub async fn wait_with_heartbeat(
    seconds: u64,
    heartbeat: bool,
    tx: &mpsc::Sender<Result<Bytes, std::convert::Infallible>>,
) -> bool {
    let mut waited = 0u64;
    while waited < seconds {
        let step = HEARTBEAT_EVERY.as_secs().min(seconds - waited);
        tokio::time::sleep(Duration::from_secs(step)).await;
        waited += step;
        if heartbeat && tx.send(Ok(Bytes::from_static(HEARTBEAT))).await.is_err() {
            return false;
        }
    }
    true
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
}
