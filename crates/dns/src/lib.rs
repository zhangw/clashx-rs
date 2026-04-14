use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio::sync::{Notify, RwLock};
use tokio::task;

static DNS_TX_ID: AtomicU16 = AtomicU16::new(1);

/// Max DNS label length per RFC 1035.
const MAX_LABEL_LEN: usize = 63;

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
const NEGATIVE_TTL: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// DNS cache
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum CacheValue {
    Resolved(IpAddr),
    Failed,
}

struct CacheEntry {
    value: CacheValue,
    expires: Instant,
}

/// TTL-based DNS cache with negative caching and in-flight request coalescing.
/// Thread-safe, bounded size.
pub struct DnsCache {
    entries: RwLock<HashMap<String, CacheEntry>>,
    /// Hostnames with a resolution currently in flight. Concurrent callers
    /// for the same host share a Notify so only one actually queries upstream.
    inflight: std::sync::Mutex<HashMap<String, Arc<tokio::sync::Notify>>>,
}

fn normalize(host: &str) -> std::borrow::Cow<'_, str> {
    if host.bytes().any(|b| b.is_ascii_uppercase()) {
        std::borrow::Cow::Owned(host.to_ascii_lowercase())
    } else {
        std::borrow::Cow::Borrowed(host)
    }
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            inflight: std::sync::Mutex::new(HashMap::new()),
        }
    }

    async fn lookup(&self, host: &str) -> Option<CacheValue> {
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
    fn claim_inflight(&self, host: &str) -> std::result::Result<(), Arc<Notify>> {
        let key = normalize(host).into_owned();
        let mut guard = self.inflight.lock().expect("inflight mutex poisoned");
        match guard.get(&key) {
            Some(existing) => Err(Arc::clone(existing)),
            None => {
                guard.insert(key, Arc::new(Notify::new()));
                Ok(())
            }
        }
    }

    fn complete_inflight(&self, host: &str) {
        let key = normalize(host).into_owned();
        let mut guard = self.inflight.lock().expect("inflight mutex poisoned");
        if let Some(notify) = guard.remove(&key) {
            notify.notify_waiters();
        }
    }

    async fn put(&self, host: &str, ip: IpAddr, ttl_secs: u32) {
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
    async fn put_failure(&self, host: &str) {
        self.insert(host, CacheValue::Failed, NEGATIVE_TTL).await;
    }

    async fn insert(&self, host: &str, value: CacheValue, ttl: Duration) {
        let key = normalize(host).into_owned();
        let mut entries = self.entries.write().await;

        if entries.len() >= MAX_CACHE_SIZE {
            let now = Instant::now();
            entries.retain(|_, v| now < v.expires);
        }
        if entries.len() >= MAX_CACHE_SIZE {
            let mut by_expiry: Vec<_> = entries.keys().cloned().collect();
            by_expiry.sort_by_key(|k| entries.get(k).map(|e| e.expires));
            for key in by_expiry.iter().take(MAX_CACHE_SIZE / 4) {
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

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Resolution functions
// ---------------------------------------------------------------------------

/// Resolve a hostname to an IP address using the system resolver.
pub async fn resolve(host: &str) -> Result<IpAddr> {
    let host = host.to_string();
    let ip = task::spawn_blocking(move || -> Result<IpAddr> {
        let addr = format!("{host}:0")
            .to_socket_addrs()?
            .find(|a| a.is_ipv4())
            .or_else(|| format!("{host}:0").to_socket_addrs().ok()?.next())
            .ok_or_else(|| anyhow::anyhow!("failed to resolve {host}"))?;
        Ok(addr.ip())
    })
    .await??;
    Ok(ip)
}

/// Resolve a hostname by sending a UDP DNS query directly to the given nameserver.
pub async fn resolve_via(host: &str, nameserver: IpAddr) -> Result<DnsResult> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    let ns_addr = SocketAddr::new(nameserver, 53);

    let tx_id = DNS_TX_ID.fetch_add(1, Ordering::Relaxed);
    let query = build_dns_query(host, tx_id)?;
    sock.send_to(&query, ns_addr).await?;

    let mut buf = [0u8; 1024];
    let timeout = tokio::time::timeout(std::time::Duration::from_secs(2), sock.recv_from(&mut buf));
    let (n, _) = timeout
        .await
        .map_err(|_| anyhow::anyhow!("DNS query to {nameserver} timed out"))??;

    parse_dns_response(&buf[..n], host, tx_id)
}

/// Default TTL used when caching system-resolver results. The OS resolver
/// doesn't expose a TTL, so we pick a conservative middle value — long
/// enough to avoid hammering getaddrinfo, short enough to react to DNS
/// changes. Clamped in `put()` anyway.
const SYSTEM_RESOLVE_TTL_SECS: u32 = 300;

/// Call the system resolver, caching the outcome (success or failure) so
/// repeated lookups don't keep paying the getaddrinfo cost.
async fn system_resolve_cached(host: &str, cache: &DnsCache) -> Result<IpAddr> {
    match resolve(host).await {
        Ok(ip) => {
            cache.put(host, ip, SYSTEM_RESOLVE_TTL_SECS).await;
            Ok(ip)
        }
        Err(e) => {
            cache.put_failure(host).await;
            Err(e)
        }
    }
}

/// Resolve by racing all nameservers concurrently with caching.
/// Falls back to the system resolver if nameservers is empty or all fail.
///
/// Concurrent callers for the same host coalesce via a singleflight guard —
/// only one task actually queries upstream; others wait for the result and
/// read it from the cache.
pub async fn resolve_with_nameservers(
    host: &str,
    nameservers: &[IpAddr],
    cache: &DnsCache,
) -> Result<IpAddr> {
    // Fast path: already cached.
    match cache.lookup(host).await {
        Some(CacheValue::Resolved(ip)) => return Ok(ip),
        Some(CacheValue::Failed) => {
            anyhow::bail!("DNS for {host} failed recently; suppressed for ~{NEGATIVE_TTL:?}")
        }
        None => {}
    }

    // Singleflight: if someone else is already resolving, wait and then
    // re-consult the cache. On wake, the cache entry should be present.
    match cache.claim_inflight(host) {
        Ok(()) => {}
        Err(notify) => {
            notify.notified().await;
            return match cache.lookup(host).await {
                Some(CacheValue::Resolved(ip)) => Ok(ip),
                Some(CacheValue::Failed) => {
                    anyhow::bail!(
                        "DNS for {host} failed recently; suppressed for ~{NEGATIVE_TTL:?}"
                    )
                }
                None => {
                    // The leader finished but its entry was already evicted
                    // — rare edge case, fall through and resolve ourselves.
                    // Re-recurse; a new singleflight claim will succeed or
                    // we'll wait on a fresh leader.
                    Box::pin(resolve_with_nameservers(host, nameservers, cache)).await
                }
            };
        }
    }

    // We're the leader. Ensure the in-flight slot is cleared even on panic/
    // early-return so waiters can proceed.
    struct LeaderGuard<'a> {
        cache: &'a DnsCache,
        host: &'a str,
    }
    impl Drop for LeaderGuard<'_> {
        fn drop(&mut self) {
            self.cache.complete_inflight(self.host);
        }
    }
    let _leader = LeaderGuard { cache, host };

    if nameservers.is_empty() {
        return system_resolve_cached(host, cache).await;
    }

    // Race all nameservers concurrently, take the first success.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<DnsResult>(1);

    for ns in nameservers {
        let ns = *ns;
        let host = host.to_string();
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Ok(result) = resolve_via(&host, ns).await {
                let _ = tx.send(result).await;
            }
        });
    }
    drop(tx);

    let timeout = Duration::from_secs(2) + Duration::from_millis(100);
    if let Ok(Some(result)) = tokio::time::timeout(timeout, rx.recv()).await {
        cache.put(host, result.ip, result.ttl).await;
        return Ok(result.ip);
    }

    tracing::debug!(
        host,
        "all nameservers failed, falling back to system resolver"
    );
    system_resolve_cached(host, cache).await
}

// ---------------------------------------------------------------------------
// DNS wire format
// ---------------------------------------------------------------------------

/// Result of a DNS lookup including TTL for caching.
#[derive(Debug)]
pub struct DnsResult {
    pub ip: IpAddr,
    pub ttl: u32,
}

/// Build a minimal DNS A-record query packet.
fn build_dns_query(host: &str, tx_id: u16) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(64);

    buf.extend_from_slice(&tx_id.to_be_bytes()); // ID
    buf.extend_from_slice(&[0x01, 0x00]); // Flags: RD=1
    buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    buf.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
    buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
    buf.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0

    // Encode domain name as DNS labels
    for label in host.split('.') {
        if label.is_empty() {
            continue; // skip empty labels (trailing dot)
        }
        if label.len() > MAX_LABEL_LEN {
            anyhow::bail!(
                "DNS label too long ({} > {MAX_LABEL_LEN}): {label}",
                label.len()
            );
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0x00); // root label

    buf.extend_from_slice(&[0x00, 0x01]); // QTYPE=A
    buf.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN

    Ok(buf)
}

/// Parse a DNS response and extract the first A record with its TTL.
fn parse_dns_response(data: &[u8], host: &str, expected_id: u16) -> Result<DnsResult> {
    if data.len() < 12 {
        anyhow::bail!("DNS response too short");
    }

    let resp_id = u16::from_be_bytes([data[0], data[1]]);
    if resp_id != expected_id {
        anyhow::bail!("DNS response ID mismatch: expected {expected_id}, got {resp_id}");
    }

    let flags = u16::from_be_bytes([data[2], data[3]]);

    // Check TC (truncation) bit — response was too large for UDP
    if flags & 0x0200 != 0 {
        anyhow::bail!("DNS response truncated (TC bit set) for {host}");
    }

    let rcode = flags & 0x000F;
    if rcode != 0 {
        anyhow::bail!("DNS error rcode={rcode} for {host}");
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    if ancount == 0 {
        anyhow::bail!("no answers in DNS response for {host}");
    }

    // Skip all question sections
    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_dns_name(data, pos)?;
        if pos + 4 > data.len() {
            anyhow::bail!("DNS response truncated in question section");
        }
        pos += 4; // skip QTYPE + QCLASS
    }

    // Parse answer records, looking for A (type 1) records.
    // CNAME records (type 5) are skipped — most recursive resolvers include
    // the full CNAME → A chain in the answer section.
    for _ in 0..ancount {
        pos = skip_dns_name(data, pos)?;

        if pos + 10 > data.len() {
            anyhow::bail!("DNS response truncated in answer record");
        }

        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ttl = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlength > data.len() {
            anyhow::bail!("DNS response truncated in RDATA");
        }

        if rtype == 1 && rdlength == 4 {
            // A record
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
            ));
            return Ok(DnsResult { ip, ttl });
        }

        pos += rdlength;
    }

    anyhow::bail!("no A record found in DNS response for {host}")
}

/// Skip a DNS name (handles both label sequences and compressed pointers).
/// Limited to 128 iterations to prevent malformed packets from looping.
fn skip_dns_name(data: &[u8], mut pos: usize) -> Result<usize> {
    let mut iterations = 0;
    loop {
        if iterations > 128 {
            anyhow::bail!("DNS name too many labels (malformed packet)");
        }
        iterations += 1;

        if pos >= data.len() {
            anyhow::bail!("DNS name extends past end of packet");
        }
        let b = data[pos];
        if b == 0 {
            return Ok(pos + 1); // null terminator
        }
        if b & 0xC0 == 0xC0 {
            // Compression pointer (2 bytes)
            if pos + 2 > data.len() {
                anyhow::bail!("DNS compression pointer truncated");
            }
            return Ok(pos + 2);
        }
        let label_len = b as usize;
        if label_len > MAX_LABEL_LEN {
            anyhow::bail!("DNS label length {label_len} exceeds maximum {MAX_LABEL_LEN}");
        }
        if pos + 1 + label_len > data.len() {
            anyhow::bail!("DNS label extends past end of packet");
        }
        pos += 1 + label_len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolve_localhost() {
        let ip = resolve("localhost").await.unwrap();
        assert!(ip.is_loopback());
    }

    #[test]
    fn build_query_encodes_labels() {
        let query = build_dns_query("www.example.com", 0x1234).unwrap();
        assert_eq!(query[12], 3);
        assert_eq!(&query[13..16], b"www");
        assert_eq!(query[16], 7);
        assert_eq!(&query[17..24], b"example");
        assert_eq!(query[24], 3);
        assert_eq!(&query[25..28], b"com");
        assert_eq!(query[28], 0);
    }

    #[test]
    fn build_query_with_tx_id() {
        let query = build_dns_query("test.com", 0xABCD).unwrap();
        assert_eq!(query[0], 0xAB);
        assert_eq!(query[1], 0xCD);
    }

    #[test]
    fn build_query_trailing_dot() {
        let q1 = build_dns_query("example.com.", 1).unwrap();
        let q2 = build_dns_query("example.com", 1).unwrap();
        assert_eq!(q1, q2);
    }

    #[test]
    fn build_query_rejects_long_label() {
        let long_label = "a".repeat(64);
        let host = format!("{long_label}.com");
        assert!(build_dns_query(&host, 1).is_err());
    }

    #[test]
    fn skip_name_handles_pointer() {
        let data = [0xC0, 0x0C, 0x00];
        assert_eq!(skip_dns_name(&data, 0).unwrap(), 2);
    }

    #[test]
    fn skip_name_handles_labels() {
        let data = [3, b'w', b'w', b'w', 0];
        assert_eq!(skip_dns_name(&data, 0).unwrap(), 5);
    }

    #[test]
    fn skip_name_rejects_truncated() {
        let data = [10, b'a', b'b', b'c'];
        assert!(skip_dns_name(&data, 0).is_err());
    }

    #[test]
    fn skip_name_rejects_oversized_label() {
        let mut data = vec![64];
        data.extend(vec![b'a'; 64]);
        data.push(0);
        assert!(skip_dns_name(&data, 0).is_err());
    }

    // --- Test helpers for building synthetic DNS responses ---

    fn build_test_response(
        tx_id: u16,
        flags: u16,
        questions: &[&[u8]],
        answers: &[&[u8]],
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&tx_id.to_be_bytes());
        buf.extend_from_slice(&flags.to_be_bytes());
        buf.extend_from_slice(&(questions.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        buf.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
        for q in questions {
            buf.extend_from_slice(q);
        }
        for a in answers {
            buf.extend_from_slice(a);
        }
        buf
    }

    fn encode_name(name: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        for label in name.split('.') {
            if label.is_empty() {
                continue;
            }
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
        buf
    }

    fn make_question(name: &str) -> Vec<u8> {
        let mut buf = encode_name(name);
        buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        buf
    }

    fn make_a_record_with_ttl(name: &str, ip: [u8; 4], ttl: u32) -> Vec<u8> {
        let mut buf = encode_name(name);
        buf.extend_from_slice(&[0x00, 0x01]); // TYPE=A
        buf.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
        buf.extend_from_slice(&ttl.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x04]); // RDLENGTH=4
        buf.extend_from_slice(&ip);
        buf
    }

    fn make_a_record(name: &str, ip: [u8; 4]) -> Vec<u8> {
        make_a_record_with_ttl(name, ip, 60)
    }

    fn make_cname_record(name: &str, target: &str) -> Vec<u8> {
        let mut buf = encode_name(name);
        buf.extend_from_slice(&[0x00, 0x05]); // TYPE=CNAME
        buf.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL=60
        let target_encoded = encode_name(target);
        buf.extend_from_slice(&(target_encoded.len() as u16).to_be_bytes());
        buf.extend_from_slice(&target_encoded);
        buf
    }

    // --- Response parsing tests ---

    #[test]
    fn parse_simple_a_response() {
        let q = make_question("example.com");
        let a = make_a_record("example.com", [93, 184, 216, 34]);
        let resp = build_test_response(0x1234, 0x8180, &[&q], &[&a]);

        let result = parse_dns_response(&resp, "example.com", 0x1234).unwrap();
        assert_eq!(result.ip, "93.184.216.34".parse::<IpAddr>().unwrap());
        assert_eq!(result.ttl, 60);
    }

    #[test]
    fn parse_response_preserves_ttl() {
        let q = make_question("example.com");
        let a = make_a_record_with_ttl("example.com", [1, 2, 3, 4], 300);
        let resp = build_test_response(0x0001, 0x8180, &[&q], &[&a]);

        let result = parse_dns_response(&resp, "example.com", 0x0001).unwrap();
        assert_eq!(result.ttl, 300);
    }

    #[test]
    fn parse_cname_then_a_response() {
        let q = make_question("www.baidu.com");
        let cname = make_cname_record("www.baidu.com", "www.a.shifen.com");
        let a = make_a_record("www.a.shifen.com", [180, 101, 51, 73]);
        let resp = build_test_response(0x0001, 0x8180, &[&q], &[&cname, &a]);

        let result = parse_dns_response(&resp, "www.baidu.com", 0x0001).unwrap();
        assert_eq!(result.ip, "180.101.51.73".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parse_response_with_pointer_names() {
        let q = make_question("example.com");
        let mut a = vec![0xC0, 0x0C]; // pointer to question name
        a.extend_from_slice(&[0x00, 0x01]); // TYPE=A
        a.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
        a.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL
        a.extend_from_slice(&[0x00, 0x04]); // RDLENGTH=4
        a.extend_from_slice(&[1, 2, 3, 4]);
        let resp = build_test_response(0x0042, 0x8180, &[&q], &[&a]);

        let result = parse_dns_response(&resp, "example.com", 0x0042).unwrap();
        assert_eq!(result.ip, "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parse_response_id_mismatch() {
        let q = make_question("example.com");
        let a = make_a_record("example.com", [1, 2, 3, 4]);
        let resp = build_test_response(0x9999, 0x8180, &[&q], &[&a]);

        let err = parse_dns_response(&resp, "example.com", 0x1111).unwrap_err();
        assert!(err.to_string().contains("ID mismatch"));
    }

    #[test]
    fn parse_response_nxdomain() {
        let q = make_question("nonexistent.example.com");
        let resp = build_test_response(0x0001, 0x8183, &[&q], &[]);

        let err = parse_dns_response(&resp, "nonexistent.example.com", 0x0001).unwrap_err();
        assert!(err.to_string().contains("rcode=3"));
    }

    #[test]
    fn parse_response_truncated_tc_bit() {
        let q = make_question("example.com");
        let resp = build_test_response(0x0001, 0x8380, &[&q], &[]);

        let err = parse_dns_response(&resp, "example.com", 0x0001).unwrap_err();
        assert!(err.to_string().contains("truncated"));
    }

    #[test]
    fn parse_response_no_a_record_only_cname() {
        let q = make_question("alias.example.com");
        let cname = make_cname_record("alias.example.com", "real.example.com");
        let resp = build_test_response(0x0001, 0x8180, &[&q], &[&cname]);

        let err = parse_dns_response(&resp, "alias.example.com", 0x0001).unwrap_err();
        assert!(err.to_string().contains("no A record"));
    }

    #[test]
    fn parse_response_multiple_a_records_returns_first() {
        let q = make_question("multi.example.com");
        let a1 = make_a_record("multi.example.com", [10, 0, 0, 1]);
        let a2 = make_a_record("multi.example.com", [10, 0, 0, 2]);
        let resp = build_test_response(0x0001, 0x8180, &[&q], &[&a1, &a2]);

        let result = parse_dns_response(&resp, "multi.example.com", 0x0001).unwrap();
        assert_eq!(result.ip, "10.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parse_response_too_short() {
        let err = parse_dns_response(&[0u8; 6], "x.com", 0).unwrap_err();
        assert!(err.to_string().contains("too short"));
    }

    // --- Cache tests ---

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
}
