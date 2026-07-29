use std::collections::HashMap;
use std::time::{Duration, Instant};

pub const MAX_RETRIES: u32 = 2;
pub const RETRY_BACKOFF: [Duration; 2] = [Duration::from_millis(100), Duration::from_millis(500)];
pub const MAX_FAILOVER_ATTEMPTS: usize = 3;
pub const COOLDOWN_DURATION: Duration = Duration::from_secs(60);
pub const COOLDOWN_FAILURE_THRESHOLD: u32 = 2;

/// Max wait for the first response byte from the remote once client data has
/// been forwarded (the deadline re-arms on every forwarded chunk, so this
/// measures pure remote responsiveness). Catches "half-dead" nodes whose
/// Trojan handshake works but whose egress is broken — that failure is
/// otherwise invisible locally (Trojan has no remote-dial acknowledgment).
/// 8s errs toward not killing slow origins; genuinely dead nodes are cheap
/// to abandon anyway because failover replays only safe buffers.
pub const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(8);

/// Cap on client bytes buffered for replay during the first-byte window.
/// Once the cap is reached the window stops reading the client and only
/// waits for the remote, bounding memory per pending connection.
pub const MAX_REPLAY_BUFFER: usize = 64 * 1024;

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
}

impl CooldownTracker {
    pub fn new() -> Self {
        Self {
            failures: std::sync::RwLock::new(HashMap::new()),
            sidelined: std::sync::RwLock::new(std::collections::HashSet::new()),
            degraded: std::sync::RwLock::new(HashMap::new()),
        }
    }

    pub fn is_cooled_down(&self, proxy: &str) -> bool {
        if self.sidelined.read().unwrap().contains(proxy) {
            return true;
        }
        let failures = self.failures.read().unwrap();
        match failures.get(proxy) {
            Some(&(count, last_failure)) => {
                count >= COOLDOWN_FAILURE_THRESHOLD && last_failure.elapsed() < COOLDOWN_DURATION
            }
            None => false,
        }
    }

    /// Whether the proxy was sidelined by a health probe (persistent, cleared
    /// only by record_success). Used by the probe scheduler to re-check
    /// unhealthy nodes at a faster cadence.
    pub fn is_sidelined(&self, proxy: &str) -> bool {
        self.sidelined.read().unwrap().contains(proxy)
    }

    /// Sideline a proxy until a health probe passes. Used on confirmed probe
    /// failures; data-plane code treats it exactly like a cooldown.
    pub fn sideline(&self, proxy: &str) {
        self.sidelined.write().unwrap().insert(proxy.to_string());
    }

    pub fn record_failure(&self, proxy: &str) {
        let mut failures = self.failures.write().unwrap();
        let entry = failures
            .entry(proxy.to_string())
            .or_insert((0, Instant::now()));
        entry.0 += 1;
        entry.1 = Instant::now();
    }

    /// Weak failure signal: demote in candidate ordering for DEGRADE_DURATION.
    /// Used for first-byte timeouts/closes, which are probably (not
    /// certainly) node failures.
    pub fn degrade(&self, proxy: &str) {
        self.degraded
            .write()
            .unwrap()
            .insert(proxy.to_string(), Instant::now());
    }

    pub fn is_degraded(&self, proxy: &str) -> bool {
        let degraded = self.degraded.read().unwrap();
        match degraded.get(proxy) {
            Some(t) => t.elapsed() < DEGRADE_DURATION,
            None => false,
        }
    }

    pub fn record_success(&self, proxy: &str) {
        self.failures.write().unwrap().remove(proxy);
        self.sidelined.write().unwrap().remove(proxy);
        self.degraded.write().unwrap().remove(proxy);
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
}
