//! TTL-based DNS cache with negative caching and in-flight coalescing.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Notify, RwLock};

/// Max cache entries to prevent unbounded memory growth.
const MAX_CACHE_SIZE: usize = 4096;

/// Minimum TTL to cache (even if the server says 0).
const MIN_TTL_SECS: u32 = 10;

/// Maximum TTL we'll honor from a DNS response. Protects against a hostile
/// upstream returning huge TTLs (e.g., u32::MAX) that would pin cache entries.
const MAX_TTL_SECS: u32 = 3600;

/// Negative cache TTL — how long to remember a DNS lookup failure.
/// Prevents a broken or unreachable hostname from triggering repeated
/// full nameserver-race queries on every connection attempt.
pub(crate) const NEGATIVE_TTL: Duration = Duration::from_secs(10);

#[derive(Clone, Copy)]
pub(crate) enum CacheValue {
    Resolved(IpAddr),
    Failed,
}

struct CacheEntry {
    value: CacheValue,
    expires: Instant,
}

/// TTL-based DNS cache with negative caching and in-flight request coalescing.
/// Thread-safe, bounded size.
pub(crate) struct DnsCache {
    entries: RwLock<HashMap<String, CacheEntry>>,
    /// Hostnames with a resolution currently in flight. Concurrent callers
    /// for the same host share a Notify so only one actually queries upstream.
    inflight: std::sync::Mutex<HashMap<String, Arc<Notify>>>,
}

pub(crate) fn normalize(host: &str) -> std::borrow::Cow<'_, str> {
    if host.bytes().any(|b| b.is_ascii_uppercase()) {
        std::borrow::Cow::Owned(host.to_ascii_lowercase())
    } else {
        std::borrow::Cow::Borrowed(host)
    }
}

impl DnsCache {
    pub(crate) fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            inflight: std::sync::Mutex::new(HashMap::new()),
        }
    }

    pub(crate) async fn lookup(&self, host: &str) -> Option<CacheValue> {
        let key = normalize(host);
        let entries = self.entries.read().await;
        let entry = entries.get(key.as_ref())?;
        if Instant::now() < entry.expires {
            Some(entry.value)
        } else {
            None
        }
    }

    /// Singleflight claim: if no one is resolving `host`, mark it as in-flight
    /// and return Ok. If another task is already resolving it, return Err with
    /// the Notify to wait on. Caller must call `complete_inflight` on Ok path.
    pub(crate) fn claim_inflight(&self, host: &str) -> std::result::Result<(), Arc<Notify>> {
        let key = normalize(host);
        let mut guard = self.inflight.lock().expect("inflight mutex poisoned");
        if let Some(existing) = guard.get(key.as_ref()) {
            return Err(Arc::clone(existing));
        }
        guard.insert(key.into_owned(), Arc::new(Notify::new()));
        Ok(())
    }

    pub(crate) fn complete_inflight(&self, host: &str) {
        let key = normalize(host);
        let mut guard = self.inflight.lock().expect("inflight mutex poisoned");
        if let Some(notify) = guard.remove(key.as_ref()) {
            notify.notify_waiters();
        }
    }

    pub(crate) async fn put(&self, host: &str, ip: IpAddr, ttl_secs: u32) {
        let ttl = ttl_secs.clamp(MIN_TTL_SECS, MAX_TTL_SECS);
        self.insert(
            host,
            CacheValue::Resolved(ip),
            Duration::from_secs(ttl as u64),
        )
        .await;
    }

    /// Record a DNS failure so repeated lookups of the same hostname don't
    /// all trigger fresh nameserver races within the negative-TTL window.
    pub(crate) async fn put_failure(&self, host: &str) {
        self.insert(host, CacheValue::Failed, NEGATIVE_TTL).await;
    }

    /// Remove all cached entries, returning how many were dropped. In-flight
    /// resolutions are left untouched — their results are cached on completion.
    pub(crate) async fn clear(&self) -> usize {
        let mut entries = self.entries.write().await;
        let dropped = entries.len();
        entries.clear();
        dropped
    }

    /// Remove the cached entry for a single hostname (case-insensitive).
    /// Returns true if an entry existed.
    pub(crate) async fn invalidate(&self, host: &str) -> bool {
        let key = normalize(host);
        let mut entries = self.entries.write().await;
        entries.remove(key.as_ref()).is_some()
    }

    async fn insert(&self, host: &str, value: CacheValue, ttl: Duration) {
        let key = normalize(host).into_owned();
        let mut entries = self.entries.write().await;

        if entries.len() >= MAX_CACHE_SIZE {
            let now = Instant::now();
            entries.retain(|_, v| now < v.expires);
        }
        if entries.len() >= MAX_CACHE_SIZE {
            // Still full of unexpired entries: evict the quarter closest to
            // expiry. select_nth avoids a full sort and per-comparison map
            // lookups; only the evicted keys are cloned.
            let k = MAX_CACHE_SIZE / 4;
            let mut by_expiry: Vec<(Instant, &String)> =
                entries.iter().map(|(key, e)| (e.expires, key)).collect();
            by_expiry.select_nth_unstable_by_key(k - 1, |&(expires, _)| expires);
            let evict: Vec<String> = by_expiry[..k].iter().map(|&(_, key)| key.clone()).collect();
            drop(by_expiry);
            for key in &evict {
                entries.remove(key);
            }
        }

        entries.insert(
            key,
            CacheEntry {
                value,
                expires: Instant::now() + ttl,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolved_ip(v: Option<CacheValue>) -> Option<IpAddr> {
        match v {
            Some(CacheValue::Resolved(ip)) => Some(ip),
            _ => None,
        }
    }

    #[tokio::test]
    async fn cache_hit_returns_cached_ip() {
        let cache = DnsCache::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        cache.put("example.com", ip, 60).await;
        assert_eq!(resolved_ip(cache.lookup("example.com").await), Some(ip));
    }

    #[tokio::test]
    async fn cache_miss_returns_none() {
        let cache = DnsCache::new();
        assert!(cache.lookup("unknown.com").await.is_none());
    }

    #[tokio::test]
    async fn cache_expired_returns_none() {
        let cache = DnsCache::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        {
            let mut entries = cache.entries.write().await;
            entries.insert(
                "expired.com".to_string(),
                CacheEntry {
                    value: CacheValue::Resolved(ip),
                    expires: Instant::now() - Duration::from_secs(1),
                },
            );
        }
        assert!(cache.lookup("expired.com").await.is_none());
    }

    #[tokio::test]
    async fn cache_respects_min_ttl() {
        let cache = DnsCache::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        cache.put("example.com", ip, 0).await;
        assert_eq!(resolved_ip(cache.lookup("example.com").await), Some(ip));
    }

    #[tokio::test]
    async fn negative_cache_blocks_repeated_lookup() {
        let cache = DnsCache::new();
        cache.put_failure("broken.example").await;
        assert!(matches!(
            cache.lookup("broken.example").await,
            Some(CacheValue::Failed)
        ));
    }

    #[tokio::test]
    async fn resolved_shadows_failed_on_put() {
        let cache = DnsCache::new();
        cache.put_failure("example.com").await;
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        cache.put("example.com", ip, 60).await;
        assert_eq!(resolved_ip(cache.lookup("example.com").await), Some(ip));
    }

    #[tokio::test]
    async fn clear_drops_all_entries() {
        let cache = DnsCache::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        cache.put("example.com", ip, 60).await;
        cache.put_failure("broken.example").await;
        assert_eq!(cache.clear().await, 2);
        assert!(cache.lookup("example.com").await.is_none());
        assert!(cache.lookup("broken.example").await.is_none());
        assert_eq!(cache.clear().await, 0);
    }

    #[tokio::test]
    async fn invalidate_removes_single_entry() {
        let cache = DnsCache::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        cache.put("example.com", ip, 60).await;
        cache.put("other.example", ip, 60).await;
        assert!(cache.invalidate("example.com").await);
        assert!(cache.lookup("example.com").await.is_none());
        assert_eq!(resolved_ip(cache.lookup("other.example").await), Some(ip));
        assert!(!cache.invalidate("example.com").await);
    }

    #[tokio::test]
    async fn invalidate_is_case_insensitive() {
        let cache = DnsCache::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        cache.put("Example.COM", ip, 60).await;
        assert!(cache.invalidate("example.com").await);
        assert!(cache.lookup("EXAMPLE.com").await.is_none());
    }
}
