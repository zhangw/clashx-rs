//! Top-level resolver: hosts mappings, cache/singleflight, upstream race,
//! system fallback — the mihomo-compatible DNS semantics entry point.

use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clashx_rs_config::types::Config;

use crate::bootstrap::Bootstrap;
use crate::cache::{normalize, CacheValue, DnsCache, NEGATIVE_TTL};
use crate::upstream::{classify, race_first, Upstream};
use crate::wire::DnsResult;
use crate::SYSTEM_RESOLVE_TTL_SECS;

/// Static hosts mappings (mihomo top-level `hosts:`). Exact keys plus
/// `*.suffix` wildcards. Values are IP literals; non-IP values are skipped
/// with a warning at parse time. IPv6 values are honored regardless of the
/// `ipv6` setting.
pub(crate) struct Hosts {
    exact: HashMap<String, IpAddr>,
    /// Suffixes without the leading `*.`.
    wildcard: Vec<(String, IpAddr)>,
}

impl Hosts {
    /// Parse the raw config map. Returns None when nothing usable remains.
    pub(crate) fn parse(map: &HashMap<String, String>) -> Option<Hosts> {
        let mut exact = HashMap::new();
        let mut wildcard = Vec::new();
        for (key, value) in map {
            let ip = match value.trim().parse::<IpAddr>() {
                Ok(ip) => ip,
                Err(_) => {
                    tracing::warn!(key = %key, value = %value, "hosts value is not an IP literal; skipping entry");
                    continue;
                }
            };
            let key = key.to_ascii_lowercase();
            if let Some(suffix) = key.strip_prefix("*.") {
                wildcard.push((suffix.to_string(), ip));
            } else {
                exact.insert(key, ip);
            }
        }
        if exact.is_empty() && wildcard.is_empty() {
            None
        } else {
            Some(Hosts { exact, wildcard })
        }
    }

    fn lookup(&self, host: &str) -> Option<IpAddr> {
        // Borrows when already lowercase — no allocation on the hot path.
        let host = normalize(host);
        if let Some(ip) = self.exact.get(host.as_ref()) {
            return Some(*ip);
        }
        for (suffix, ip) in &self.wildcard {
            // `*.example.com` matches `example.com` itself and any subdomain.
            if host.as_ref() == suffix
                || (host.len() > suffix.len()
                    && host.ends_with(suffix.as_str())
                    && host.as_bytes()[host.len() - suffix.len() - 1] == b'.')
            {
                return Some(*ip);
            }
        }
        None
    }
}

enum ResolverMode {
    /// `dns.enable=false` (or no dns block): everything goes through the
    /// system resolver; hosts mappings do NOT apply.
    System,
    Custom {
        group: Arc<[Upstream]>,
        bootstrap: Arc<Bootstrap>,
        hosts: Option<Arc<Hosts>>,
    },
}

/// The daemon-facing DNS resolver. One instance resolves target hostnames
/// (rules + DIRECT), a second instance resolves proxy server addresses via
/// `proxy-server-nameserver`.
pub struct Resolver {
    mode: ResolverMode,
    cache: DnsCache,
}

impl Resolver {
    pub fn system() -> Self {
        Self {
            mode: ResolverMode::System,
            cache: DnsCache::new(),
        }
    }

    pub(crate) fn custom(
        group: Arc<[Upstream]>,
        bootstrap: Arc<Bootstrap>,
        hosts: Option<Arc<Hosts>>,
    ) -> Self {
        Self {
            mode: ResolverMode::Custom {
                group,
                bootstrap,
                hosts,
            },
            cache: DnsCache::new(),
        }
    }

    /// Resolve `host` to an IP address.
    ///
    /// Custom-mode flow: IP-literal short-circuit → hosts hit (never cached)
    /// → cache/singleflight → upstream race (first success wins) → system
    /// fallback (fail-open, warn) → cache write (TTL clamp / negative cache).
    pub async fn resolve(&self, host: &str) -> Result<IpAddr> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(ip);
        }
        match &self.mode {
            ResolverMode::System => {
                self.cached_resolve(host, || async {
                    crate::system_resolve(host)
                        .await
                        .map(|ip| (ip, SYSTEM_RESOLVE_TTL_SECS))
                })
                .await
            }
            ResolverMode::Custom {
                group,
                bootstrap,
                hosts,
            } => {
                if let Some(ip) = hosts.as_ref().and_then(|h| h.lookup(host)) {
                    tracing::debug!(host, %ip, "resolved via hosts mapping");
                    return Ok(ip);
                }
                self.cached_resolve(host, || async {
                    match race_group(host, group, bootstrap).await {
                        Ok(result) => Ok((result.ip, result.ttl)),
                        Err(e) => {
                            // Fail-open: all configured nameservers failed —
                            // keep connectivity via the system resolver.
                            tracing::warn!(
                                host,
                                err = %e,
                                "all nameservers failed, falling back to system resolver"
                            );
                            crate::system_resolve(host)
                                .await
                                .map(|ip| (ip, SYSTEM_RESOLVE_TTL_SECS))
                        }
                    }
                })
                .await
            }
        }
    }

    /// Cache lookup + singleflight wrapper shared by both modes. The `leader`
    /// future performs the actual resolution and yields (ip, ttl).
    async fn cached_resolve<F, Fut>(&self, host: &str, leader: F) -> Result<IpAddr>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(IpAddr, u32)>>,
    {
        let check = |v: Option<CacheValue>| -> Option<Result<IpAddr>> {
            match v {
                Some(CacheValue::Resolved(ip)) => Some(Ok(ip)),
                Some(CacheValue::Failed) => Some(Err(anyhow::anyhow!(
                    "DNS for {host} failed recently; suppressed for ~{NEGATIVE_TTL:?}"
                ))),
                None => None,
            }
        };

        // Singleflight follower loop: wait for the in-flight leader, then
        // re-read the cache. Normally one pass; if the leader was cancelled
        // mid-resolve (probe/latency timeouts drop the future), the woken
        // follower finds no cache entry and claims leadership itself.
        loop {
            if let Some(res) = check(self.cache.lookup(host).await) {
                return res;
            }
            match self.cache.claim_inflight(host) {
                Ok(()) => break, // we're the leader
                Err(notify) => {
                    // Register as a waiter BEFORE re-checking the cache:
                    // notify_waiters() only wakes already-registered waiters,
                    // so enabling first closes the lost-wakeup window where
                    // the leader completes between claim_inflight and await.
                    let mut notified = std::pin::pin!(notify.notified());
                    notified.as_mut().enable();
                    if let Some(res) = check(self.cache.lookup(host).await) {
                        return res;
                    }
                    notified.await;
                }
            }
        }

        // We're the leader. Ensure the in-flight slot is cleared even on
        // panic/early-return so waiters can proceed.
        struct LeaderGuard<'a> {
            cache: &'a DnsCache,
            host: &'a str,
        }
        impl Drop for LeaderGuard<'_> {
            fn drop(&mut self) {
                self.cache.complete_inflight(self.host);
            }
        }
        let _leader = LeaderGuard {
            cache: &self.cache,
            host,
        };

        match leader().await {
            Ok((ip, ttl)) => {
                self.cache.put(host, ip, ttl).await;
                Ok(ip)
            }
            Err(e) => {
                self.cache.put_failure(host).await;
                Err(e)
            }
        }
    }

    /// `dns flush --host` support: drop one cached entry; true if it existed.
    pub async fn invalidate(&self, host: &str) -> bool {
        self.cache.invalidate(host).await
    }

    /// `dns flush` support: clear the cache, returning the dropped count.
    pub async fn clear(&self) -> usize {
        self.cache.clear().await
    }
}

/// Race all upstreams concurrently via [`race_first`]; the first success
/// wins. Each participant enforces its own deadline inside
/// `Upstream::exchange` (UDP 2s, DoH/DoT 4s); the overall window is the
/// maximum participant timeout plus 100ms of slack.
async fn race_group(
    host: &str,
    group: &Arc<[Upstream]>,
    bootstrap: &Arc<Bootstrap>,
) -> Result<DnsResult> {
    if group.is_empty() {
        anyhow::bail!("no nameservers configured");
    }

    let window = group
        .iter()
        .map(|u| u.participant_timeout())
        .max()
        .expect("group is non-empty")
        + Duration::from_millis(100);

    // Spawned attempts must be 'static — each carries an Arc clone of the
    // group and indexes into it rather than borrowing the upstream.
    let attempts = (0..group.len())
        .map(|idx| {
            let host = host.to_string();
            let bootstrap = Arc::clone(bootstrap);
            let group = Arc::clone(group);
            async move { group[idx].exchange(&host, &bootstrap).await.ok() }
        })
        .collect();

    match race_first(attempts, window).await {
        Some(result) => Ok(result),
        None => anyhow::bail!("all {} nameservers failed for {host}", group.len()),
    }
}

/// Build the (target, proxy-server) resolver pair from the parsed config.
///
/// - `dns` absent or `enable: false` → both System mode (hosts ignored); a
///   configured nameserver list then earns a one-time "ignored" warning.
/// - `ipv6: true` → one-time warning; AAAA is never queried either way.
/// - `enhanced-mode: fake-ip` → one-time warning; without a TUN/DNS entry
///   point it degrades to plain mode (keys still parse, pool unimplemented).
/// - proxy resolver group comes from `proxy-server-nameserver`, falling back
///   to the main `nameserver` group; bootstrap and hosts are shared.
pub fn build_resolvers(config: &Config) -> (Resolver, Resolver) {
    let Some(dns) = config.dns.as_ref() else {
        return (Resolver::system(), Resolver::system());
    };
    if !dns.enable {
        if !dns.nameserver.is_empty() {
            crate::warn_once!(
                "dns.enable=false: configured nameserver list is ignored, using system resolver"
            );
        }
        return (Resolver::system(), Resolver::system());
    }

    if dns.ipv6 {
        crate::warn_once!("dns.ipv6: AAAA queries are not supported yet; behaving as ipv6=false");
    }
    if dns.enhanced_mode.as_deref() == Some("fake-ip") {
        crate::warn_once!(
            "dns.enhanced-mode=fake-ip: no TUN/DNS entry point exists, handling as plain mode (fake-ip pool not implemented)"
        );
    }

    let bootstrap = Arc::new(Bootstrap::from_nameservers(&dns.default_nameserver));
    let hosts = if dns.use_hosts.unwrap_or(true) {
        Hosts::parse(&config.hosts).map(Arc::new)
    } else {
        None
    };

    let group: Arc<[Upstream]> = build_group(&dns.nameserver).into();
    let proxy_group = if dns.proxy_server_nameserver.is_empty() {
        // Same upstream instances — shares DoH client state with the main
        // resolver instead of rebuilding it.
        Arc::clone(&group)
    } else {
        let g: Arc<[Upstream]> = build_group(&dns.proxy_server_nameserver).into();
        tracing::info!(
            count = g.len(),
            "using proxy-server-nameserver for proxy server resolution"
        );
        g
    };

    // Background warm-up: resolve every DoH/DoT server hostname through the
    // bootstrap path so the first real query doesn't pay the bootstrap cost.
    // Skipped when there is no runtime (plain unit tests).
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        let mut warm_hosts: Vec<String> = group
            .iter()
            .chain(proxy_group.iter())
            .filter_map(|u| u.bootstrap_host().map(str::to_string))
            .collect();
        warm_hosts.sort();
        warm_hosts.dedup();
        for host in warm_hosts {
            let bootstrap = Arc::clone(&bootstrap);
            handle.spawn(async move {
                if let Err(e) = bootstrap.resolve(&host).await {
                    tracing::debug!(host, err = %e, "bootstrap warm-up failed (will retry on demand)");
                }
            });
        }
    }

    let main = Resolver::custom(group, Arc::clone(&bootstrap), hosts.clone());
    let proxy = Resolver::custom(proxy_group, bootstrap, hosts);
    (main, proxy)
}

fn build_group(entries: &[String]) -> Vec<Upstream> {
    entries.iter().filter_map(|e| classify(e)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::spawn_mock_dns_server;
    use std::sync::atomic::Ordering;

    fn hosts(entries: &[(&str, &str)]) -> Option<Arc<Hosts>> {
        let map: HashMap<String, String> = entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Hosts::parse(&map).map(Arc::new)
    }

    #[test]
    fn hosts_exact_and_wildcard() {
        let h = hosts(&[
            ("example.com", "1.2.3.4"),
            ("*.internal.example.com", "10.0.0.1"),
        ])
        .unwrap();
        assert_eq!(h.lookup("example.com"), Some("1.2.3.4".parse().unwrap()));
        assert_eq!(
            h.lookup("EXAMPLE.com"),
            Some("1.2.3.4".parse().unwrap()),
            "case-insensitive"
        );
        assert_eq!(
            h.lookup("a.internal.example.com"),
            Some("10.0.0.1".parse().unwrap())
        );
        assert_eq!(
            h.lookup("internal.example.com"),
            Some("10.0.0.1".parse().unwrap()),
            "wildcard matches the bare suffix too"
        );
        assert_eq!(h.lookup("notinternal.example.com"), None);
        assert_eq!(h.lookup("other.com"), None);
    }

    #[test]
    fn hosts_skips_non_ip_values() {
        let h = hosts(&[
            ("good.example.com", "::1"),
            ("bad.example.com", "not-an-ip"),
        ])
        .unwrap();
        assert_eq!(h.lookup("bad.example.com"), None);
        // IPv6 values are honored regardless of the ipv6 setting.
        assert_eq!(h.lookup("good.example.com"), Some("::1".parse().unwrap()));
    }

    #[test]
    fn hosts_empty_or_all_invalid_is_none() {
        assert!(Hosts::parse(&HashMap::new()).is_none());
        assert!(hosts(&[("bad.example.com", "nope")]).is_none());
    }

    #[tokio::test]
    async fn hosts_hit_never_touches_network() {
        // Unreachable nameserver — a hosts hit must still resolve instantly.
        let group = build_group(&["udp://127.0.0.1:1".to_string()]);
        let resolver = Resolver::custom(
            group.into(),
            Arc::new(Bootstrap::system_only_for_test()),
            hosts(&[("pinned.example.com", "203.0.113.99")]),
        );
        let ip = resolver.resolve("pinned.example.com").await.unwrap();
        assert_eq!(ip, "203.0.113.99".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn ip_literal_short_circuits() {
        let resolver = Resolver::system();
        let ip = resolver.resolve("192.0.2.1").await.unwrap();
        assert_eq!(ip, "192.0.2.1".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn system_mode_resolves_localhost() {
        let resolver = Resolver::system();
        let ip = resolver.resolve("localhost").await.unwrap();
        assert!(ip.is_loopback());
    }

    #[tokio::test]
    async fn race_returns_first_success() {
        // Fast server answers 203.0.113.1; slow server would answer a
        // different IP after 300ms — the fast one must win.
        let fast = spawn_mock_dns_server([203, 0, 113, 1]).await;
        let (slow, _) =
            spawn_counting_dns_server([203, 0, 113, 2], Duration::from_millis(300)).await;

        let group = build_group(&[format!("udp://{slow}"), format!("udp://{fast}")]);
        let resolver = Resolver::custom(
            group.into(),
            Arc::new(Bootstrap::system_only_for_test()),
            None,
        );
        let ip = resolver.resolve("example.com").await.unwrap();
        assert_eq!(ip, "203.0.113.1".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn all_nameservers_fail_falls_back_to_system() {
        // Nothing listens on 127.0.0.1:1, so the race must fail and the
        // system resolver (localhost) must carry the lookup.
        let group = build_group(&["udp://127.0.0.1:1".to_string()]);
        let resolver = Resolver::custom(
            group.into(),
            Arc::new(Bootstrap::system_only_for_test()),
            None,
        );
        let ip = resolver.resolve("localhost").await.unwrap();
        assert!(ip.is_loopback());
    }

    /// Mock DNS server that counts queries and answers after `delay`.
    async fn spawn_counting_dns_server(
        answer_ip: [u8; 4],
        delay: Duration,
    ) -> (std::net::SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        use crate::wire::test_util::{build_test_response, make_a_record};
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter_srv = Arc::clone(&counter);
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                counter_srv.fetch_add(1, Ordering::SeqCst);
                let query = buf[..n].to_vec();
                tokio::time::sleep(delay).await;
                let tx_id = u16::from_be_bytes([query[0], query[1]]);
                let answer = make_a_record("example.com", answer_ip);
                let resp = build_test_response(tx_id, 0x8180, &[&query[12..]], &[&answer]);
                let _ = sock.send_to(&resp, peer).await;
            }
        });
        (addr, counter)
    }

    #[tokio::test]
    async fn singleflight_coalesces_concurrent_resolves() {
        let (server, counter) =
            spawn_counting_dns_server([203, 0, 113, 5], Duration::from_millis(100)).await;
        let group = build_group(&[format!("udp://{server}")]);
        let resolver = Arc::new(Resolver::custom(
            group.into(),
            Arc::new(Bootstrap::system_only_for_test()),
            None,
        ));

        let mut handles = Vec::new();
        for _ in 0..8 {
            let resolver = Arc::clone(&resolver);
            handles.push(tokio::spawn(async move {
                resolver.resolve("example.com").await
            }));
        }
        for handle in handles {
            let ip = handle.await.unwrap().unwrap();
            assert_eq!(ip, "203.0.113.5".parse::<IpAddr>().unwrap());
        }
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "8 concurrent resolves must coalesce into one upstream query"
        );
    }

    #[tokio::test]
    async fn follower_recovers_when_leader_is_cancelled() {
        let (server, _counter) =
            spawn_counting_dns_server([203, 0, 113, 6], Duration::from_millis(150)).await;
        let group = build_group(&[format!("udp://{server}")]);
        let resolver = Arc::new(Resolver::custom(
            group.into(),
            Arc::new(Bootstrap::system_only_for_test()),
            None,
        ));

        // Leader: cancelled 50ms in, well before the server's 150ms answer.
        let leader = Arc::clone(&resolver);
        let leader = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_millis(50), leader.resolve("example.com")).await
        });
        // Follower: starts while the leader is in flight, must be woken by
        // the cancelled leader's guard and then claim leadership itself.
        tokio::time::sleep(Duration::from_millis(10)).await;
        let follower = Arc::clone(&resolver);
        let follower = tokio::spawn(async move { follower.resolve("example.com").await });

        assert!(leader.await.unwrap().is_err(), "leader must time out");
        let ip = follower.await.unwrap().unwrap();
        assert_eq!(ip, "203.0.113.6".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn flush_clears_cache() {
        let server = spawn_mock_dns_server([203, 0, 113, 1]).await;
        let group = build_group(&[format!("udp://{server}")]);
        let resolver = Resolver::custom(
            group.into(),
            Arc::new(Bootstrap::system_only_for_test()),
            None,
        );
        resolver.resolve("example.com").await.unwrap();
        assert!(resolver.invalidate("example.com").await);
        assert!(!resolver.invalidate("example.com").await);
        resolver.resolve("example.com").await.unwrap();
        assert_eq!(resolver.clear().await, 1);
    }
}
