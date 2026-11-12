//! Retry, failover, cooldown, and connection-lifetime policy.
//!
//! This module owns the numbers that define data-plane behavior: retry
//! backoff, passive cooldown, node degradation, the first-byte budget, and the
//! idle/half-close/promotion lifetimes used by the relay. [`CooldownTracker`]
//! records passive failures and probe-driven sidelines; the daemon consults it
//! when building candidate lists.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Read a tracker lock, recovering the guard if another task panicked while
/// holding it. A poisoned diagnostic lock must not take the data plane down.
fn read_lock<T>(lock: &std::sync::RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Write counterpart of [`read_lock`].
fn write_lock<T>(lock: &std::sync::RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub const MAX_RETRIES: u32 = 2;
pub const RETRY_BACKOFF: [Duration; 2] = [Duration::from_millis(100), Duration::from_millis(500)];
pub const MAX_FAILOVER_ATTEMPTS: usize = 3;
pub const COOLDOWN_DURATION: Duration = Duration::from_secs(60);
pub const COOLDOWN_FAILURE_THRESHOLD: u32 = 2;
/// Minimum interval between "upstream stalled" warnings for one proxy.
pub const STALLED_WARN_INTERVAL: Duration = Duration::from_secs(30);

/// Max wait for the first response byte from the remote once client data has
/// been forwarded (the deadline re-arms on every forwarded chunk, so this
/// measures pure remote responsiveness). Catches "half-dead" nodes whose
/// Trojan handshake works but whose egress is broken — that failure is
/// otherwise invisible locally (Trojan has no remote-dial acknowledgment).
/// 8s errs toward not killing slow origins; genuinely dead nodes are cheap
/// to abandon anyway because failover replays only safe buffers.
pub const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(8);

/// Cap on client bytes buffered for replay during the first-byte window.
/// Bytes beyond the cap are still forwarded to the remote; only the failover
/// replay is marked unsafe, so a large prompt never stalls the upload.
pub const MAX_REPLAY_BUFFER: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// Relay lifetime policy
// ---------------------------------------------------------------------------

/// Close a connection when neither direction has carried a byte for an hour.
/// Long enough for LLM reasoning gaps, short enough to reclaim truly dead
/// connections (matches Envoy TCP proxy / Istio defaults).
pub const RELAY_IDLE: Duration = Duration::from_hours(1);

/// Half-close inactivity for ordinary traffic. Most protocols do not
/// half-close; a minute is enough to drain a response and reclaim quickly.
pub const HALF_CLOSE_GENERAL: Duration = Duration::from_secs(60);

/// Half-close inactivity after a connection is promoted to long-lived.
/// The `OpenAI` SDK's default read timeout is 10 minutes, so the proxy must not
/// be stricter than the clients it serves.
pub const HALF_CLOSE_STREAMING: Duration = Duration::from_mins(10);

/// Connections still open in both directions after this long are treated as
/// long-lived (SSE, WebSocket, large downloads) and promoted to the streaming
/// pool. A connection that has already half-closed is not promoted: it stays
/// in the general class and is reclaimed by the shorter general drain.
pub const PROMOTE_AFTER: Duration = Duration::from_secs(30);

// A connection that remains open must be promoted before the general drain
// could apply; half-closed connections are deliberately excluded from
// promotion and use HALF_CLOSE_GENERAL directly.
const _: () = {
    assert!(PROMOTE_AFTER.as_secs() < HALF_CLOSE_GENERAL.as_secs());
    assert!(HALF_CLOSE_GENERAL.as_secs() < HALF_CLOSE_STREAMING.as_secs());
};

/// Whether an outbound connect error is a timeout. Timeouts indicate a dead or
/// unreachable node — retrying the same node 100ms later is futile, so callers
/// should fail over instead of retrying. Immediate errors (refused, reset, TLS
/// failure) may be transient and are worth a fast same-node retry.
pub fn is_timeout_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause.is::<tokio::time::error::Elapsed>()
            || cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::TimedOut)
    })
}

/// How long a first-byte failure keeps a node deprioritized in candidate
/// ordering. Ordering-only (the node is never excluded), so a slow origin
/// costs at most a temporary demotion; refreshed while failures continue,
/// cleared by any success.
pub const DEGRADE_DURATION: Duration = Duration::from_secs(120);

pub struct CooldownTracker {
    // proxy_name -> (consecutive_failure_count, last_failure_time)
    failures: std::sync::RwLock<HashMap<String, (u32, Instant)>>,
    // Probe-driven sideline set. Unlike the timed cooldown above, membership
    // does not expire on its own: a node sidelined by a failing health probe
    // stays out of rotation until an explicit record_success (a passing
    // probe). A timed cooldown shorter than the probe interval would
    // re-expose a dead node for most of every probe cycle.
    sidelined: std::sync::RwLock<std::collections::HashSet<String>>,
    // Weak signal from first-byte failures: proxy_name -> when last degraded.
    // Not node-attributable with certainty, so it only demotes the node in
    // candidate ordering (see build_candidate_list) and never excludes it.
    degraded: std::sync::RwLock<HashMap<String, Instant>>,
    // Per-proxy throttle for "upstream stalled" warnings.
    stalled_warns: std::sync::RwLock<HashMap<String, Instant>>,
}

impl CooldownTracker {
    pub fn new() -> Self {
        Self {
            failures: std::sync::RwLock::new(HashMap::new()),
            sidelined: std::sync::RwLock::new(std::collections::HashSet::new()),
            degraded: std::sync::RwLock::new(HashMap::new()),
            stalled_warns: std::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Whether a stalled-upstream warning should be emitted for this proxy.
    /// The counter carries the full rate; the log only carries the story.
    pub fn should_warn_stalled(&self, proxy: &str) -> bool {
        let now = Instant::now();
        let mut warns = write_lock(&self.stalled_warns);
        match warns.get(proxy) {
            Some(last) if now.duration_since(*last) < STALLED_WARN_INTERVAL => false,
            _ => {
                warns.insert(proxy.to_string(), now);
                true
            }
        }
    }

    pub fn is_cooled_down(&self, proxy: &str) -> bool {
        if read_lock(&self.sidelined).contains(proxy) {
            return true;
        }
        let failures = read_lock(&self.failures);
        match failures.get(proxy) {
            Some(&(count, last_failure)) => {
                count >= COOLDOWN_FAILURE_THRESHOLD && last_failure.elapsed() < COOLDOWN_DURATION
            }
            None => false,
        }
    }

    /// Whether the proxy was sidelined by a health probe (persistent, cleared
    /// only by `record_success`). Used by the probe scheduler to re-check
    /// unhealthy nodes at a faster cadence.
    pub fn is_sidelined(&self, proxy: &str) -> bool {
        read_lock(&self.sidelined).contains(proxy)
    }

    /// Sideline a proxy until a health probe passes. Used on confirmed probe
    /// failures; data-plane code treats it exactly like a cooldown.
    pub fn sideline(&self, proxy: &str) {
        write_lock(&self.sidelined).insert(proxy.to_string());
    }

    pub fn record_failure(&self, proxy: &str) {
        let mut failures = write_lock(&self.failures);
        let entry = failures
            .entry(proxy.to_string())
            .or_insert((0, Instant::now()));
        entry.0 += 1;
        entry.1 = Instant::now();
    }

    /// Record a passive failure and emit the standard cooldown warning when
    /// this failure pushes the proxy over the threshold.
    ///
    /// Kept next to [`Self::record_failure`] so the counter and its operator
    /// message cannot drift apart; the daemon calls this at every failure site.
    pub fn record_failure_and_warn(&self, proxy: &str) {
        self.record_failure(proxy);
        if self.is_cooled_down(proxy) && !self.is_sidelined(proxy) {
            tracing::warn!(
                proxy = %proxy,
                "proxy entered timed cooldown ({} consecutive failures)",
                COOLDOWN_FAILURE_THRESHOLD
            );
        }
    }

    /// Weak failure signal: demote in candidate ordering for `DEGRADE_DURATION`.
    /// Used for first-byte timeouts/closes, which are probably (not
    /// certainly) node failures.
    pub fn degrade(&self, proxy: &str) {
        write_lock(&self.degraded).insert(proxy.to_string(), Instant::now());
    }

    pub fn is_degraded(&self, proxy: &str) -> bool {
        let degraded = read_lock(&self.degraded);
        match degraded.get(proxy) {
            Some(t) => t.elapsed() < DEGRADE_DURATION,
            None => false,
        }
    }

    pub fn record_success(&self, proxy: &str) {
        write_lock(&self.failures).remove(proxy);
        write_lock(&self.sidelined).remove(proxy);
        write_lock(&self.degraded).remove(proxy);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn below_threshold_not_cooled_down() {
        let tracker = CooldownTracker::new();
        tracker.record_failure("proxy-a");
        assert!(!tracker.is_cooled_down("proxy-a"));
    }

    #[test]
    fn at_threshold_is_cooled_down() {
        let tracker = CooldownTracker::new();
        for _ in 0..COOLDOWN_FAILURE_THRESHOLD {
            tracker.record_failure("proxy-a");
        }
        assert!(tracker.is_cooled_down("proxy-a"));
    }

    #[test]
    fn cooldown_expires() {
        let tracker = CooldownTracker::new();
        for _ in 0..COOLDOWN_FAILURE_THRESHOLD {
            tracker.record_failure("proxy-a");
        }
        {
            let mut failures = tracker.failures.write().unwrap();
            if let Some(entry) = failures.get_mut("proxy-a") {
                entry.1 = Instant::now() - COOLDOWN_DURATION - Duration::from_secs(1);
            }
        }
        assert!(!tracker.is_cooled_down("proxy-a"));
    }

    #[test]
    fn success_resets_failure_count() {
        let tracker = CooldownTracker::new();
        tracker.record_failure("proxy-a");
        tracker.record_failure("proxy-a");
        tracker.record_success("proxy-a");
        for _ in 0..COOLDOWN_FAILURE_THRESHOLD {
            tracker.record_failure("proxy-a");
        }
        assert!(tracker.is_cooled_down("proxy-a"));
    }

    #[test]
    fn independent_proxy_tracking() {
        let tracker = CooldownTracker::new();
        for _ in 0..COOLDOWN_FAILURE_THRESHOLD {
            tracker.record_failure("proxy-a");
        }
        assert!(tracker.is_cooled_down("proxy-a"));
        assert!(!tracker.is_cooled_down("proxy-b"));
    }

    #[test]
    fn unknown_proxy_not_cooled_down() {
        let tracker = CooldownTracker::new();
        assert!(!tracker.is_cooled_down("never-seen"));
    }

    #[test]
    fn sideline_persists_until_success() {
        let tracker = CooldownTracker::new();
        tracker.sideline("proxy-a");
        assert!(tracker.is_sidelined("proxy-a"));
        assert!(tracker.is_cooled_down("proxy-a"));
        // Sidelining does not expire on its own (no timed check involved).
        tracker.record_success("proxy-a");
        assert!(!tracker.is_sidelined("proxy-a"));
        assert!(!tracker.is_cooled_down("proxy-a"));
    }

    #[test]
    fn sideline_does_not_affect_other_proxies() {
        let tracker = CooldownTracker::new();
        tracker.sideline("proxy-a");
        assert!(!tracker.is_cooled_down("proxy-b"));
    }

    #[test]
    fn degrade_is_ordering_only_and_expires() {
        let tracker = CooldownTracker::new();
        tracker.degrade("proxy-a");
        assert!(tracker.is_degraded("proxy-a"));
        // Degrading never excludes the node from rotation.
        assert!(!tracker.is_cooled_down("proxy-a"));
        assert!(!tracker.is_degraded("proxy-b"));

        // Success clears the demotion.
        tracker.record_success("proxy-a");
        assert!(!tracker.is_degraded("proxy-a"));

        // Expiry: backdate beyond the TTL.
        tracker.degrade("proxy-a");
        tracker.degraded.write().unwrap().insert(
            "proxy-a".to_string(),
            Instant::now() - DEGRADE_DURATION - Duration::from_secs(1),
        );
        assert!(!tracker.is_degraded("proxy-a"));
    }

    #[tokio::test]
    async fn is_timeout_error_detects_elapsed() {
        let elapsed = tokio::time::timeout(Duration::from_millis(1), std::future::pending::<()>())
            .await
            .unwrap_err();
        let err = anyhow::Error::new(elapsed).context("Trojan connect/TLS handshake timed out");
        assert!(is_timeout_error(&err));
    }

    #[test]
    fn is_timeout_error_detects_io_timeouts_only() {
        let io_err = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::TimedOut));
        assert!(is_timeout_error(&io_err));

        let refused =
            anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
        assert!(!is_timeout_error(&refused));
    }
    #[test]
    fn stalled_warnings_are_throttled_per_proxy() {
        let tracker = CooldownTracker::new();
        assert!(tracker.should_warn_stalled("a"));
        assert!(!tracker.should_warn_stalled("a"));
        assert!(tracker.should_warn_stalled("b"));
    }
}
