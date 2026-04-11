use std::collections::HashMap;
use std::time::{Duration, Instant};

pub const MAX_RETRIES: u32 = 2;
pub const RETRY_BACKOFF: [Duration; 2] = [Duration::from_millis(100), Duration::from_millis(500)];
pub const MAX_FAILOVER_ATTEMPTS: usize = 3;
pub const COOLDOWN_DURATION: Duration = Duration::from_secs(30);
pub const COOLDOWN_FAILURE_THRESHOLD: u32 = 3;

pub struct CooldownTracker {
    // proxy_name -> (consecutive_failure_count, last_failure_time)
    failures: std::sync::RwLock<HashMap<String, (u32, Instant)>>,
}

impl CooldownTracker {
    pub fn new() -> Self {
        Self {
            failures: std::sync::RwLock::new(HashMap::new()),
        }
    }

    pub fn is_cooled_down(&self, proxy: &str) -> bool {
        let failures = self.failures.read().unwrap();
        match failures.get(proxy) {
            Some(&(count, last_failure)) => {
                count >= COOLDOWN_FAILURE_THRESHOLD && last_failure.elapsed() < COOLDOWN_DURATION
            }
            None => false,
        }
    }

    pub fn record_failure(&self, proxy: &str) {
        let mut failures = self.failures.write().unwrap();
        let entry = failures
            .entry(proxy.to_string())
            .or_insert((0, Instant::now()));
        entry.0 += 1;
        entry.1 = Instant::now();
    }

    pub fn record_success(&self, proxy: &str) {
        let mut failures = self.failures.write().unwrap();
        failures.remove(proxy);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn below_threshold_not_cooled_down() {
        let tracker = CooldownTracker::new();
        tracker.record_failure("proxy-a");
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
}
