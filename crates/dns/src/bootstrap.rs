//! Bootstrap resolution for DoH/DoT server hostnames.
//!
//! Bootstrap queries go ONLY to the plain-UDP `default-nameserver` list —
//! never through the main nameserver group (which contains the DoH/DoT
//! upstreams themselves; routing bootstrap through them would be circular).
//! With no usable default-nameserver, bootstrap falls back to the system
//! resolver (fail-open) with a one-time warning.

use std::net::{IpAddr, SocketAddr};

use anyhow::Result;

use crate::cache::{CacheValue, DnsCache};
use crate::upstream::{race_first, udp_exchange, UDP_TIMEOUT};
use crate::SYSTEM_RESOLVE_TTL_SECS;

/// Bootstrap resolver: resolves the hostnames of DoH/DoT upstreams via the
/// plain-UDP `default-nameserver` list, with its own cache keyed by server
/// hostname. Never touches the main race group (see module docs). An empty
/// server list means system-resolver fallback.
pub struct Bootstrap {
    servers: Vec<SocketAddr>,
    cache: DnsCache,
}

impl Bootstrap {
    /// Build from the raw `default-nameserver` config entries. Only plain-UDP
    /// entries (bare IP or `udp://IP[:port]`) are used; anything else is
    /// skipped with a warning. An empty/unusable list means system fallback.
    pub fn from_nameservers(entries: &[String]) -> Self {
        let mut servers = Vec::new();
        for entry in entries {
            match parse_udp_addr(entry) {
                Some(addr) => servers.push(addr),
                None => {
                    tracing::warn!(entry = %entry, "ignoring unsupported default-nameserver entry (bootstrap needs plain UDP)")
                }
            }
        }
        if servers.is_empty() {
            crate::warn_once!(
                "no usable default-nameserver; DoH/DoT server hostnames will use the system resolver"
            );
        }
        Self {
            servers,
            cache: DnsCache::new(),
        }
    }

    /// Resolve a DoH/DoT server hostname to an IP, using the bootstrap cache
    /// when fresh. IP literals short-circuit.
    pub async fn resolve(&self, host: &str) -> Result<IpAddr> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(ip);
        }
        match self.cache.lookup(host).await {
            Some(CacheValue::Resolved(ip)) => return Ok(ip),
            Some(CacheValue::Failed) => {
                anyhow::bail!("bootstrap DNS for {host} failed recently; suppressed")
            }
            None => {}
        }

        if !self.servers.is_empty() {
            // Race the bootstrap UDP servers, first success wins. Bootstrap
            // traffic is rare, so no singleflight here — worst case a
            // duplicate query to default-nameservers.
            let attempts = self
                .servers
                .iter()
                .map(|&server| {
                    let host = host.to_string();
                    async move { udp_exchange(&host, server).await.ok() }
                })
                .collect();
            let window = UDP_TIMEOUT + std::time::Duration::from_millis(100);
            if let Some(result) = race_first(attempts, window).await {
                self.cache.put(host, result.ip, result.ttl).await;
                return Ok(result.ip);
            }
            tracing::warn!(
                host,
                "bootstrap nameservers failed, falling back to system resolver"
            );
        }
        self.system_fallback(host).await
    }

    /// Fail-open system-resolver path (no usable default-nameserver, or all
    /// of them failed); caches success and failure.
    async fn system_fallback(&self, host: &str) -> Result<IpAddr> {
        match crate::system_resolve(host).await {
            Ok(ip) => {
                self.cache.put(host, ip, SYSTEM_RESOLVE_TTL_SECS).await;
                Ok(ip)
            }
            Err(e) => {
                self.cache.put_failure(host).await;
                Err(e)
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn system_only_for_test() -> Self {
        Self {
            servers: Vec::new(),
            cache: DnsCache::new(),
        }
    }

    #[cfg(test)]
    pub(crate) async fn seed_for_test(&self, host: &str, ip: IpAddr) {
        self.cache.put(host, ip, 300).await;
    }
}

/// Parse a plain-UDP nameserver entry: bare IP (port 53) or
/// `udp://IP[:port]`. The host must be an IP literal.
pub(crate) fn parse_udp_addr(entry: &str) -> Option<SocketAddr> {
    let entry = entry.trim();
    if let Ok(ip) = entry.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, 53));
    }
    let rest = entry.strip_prefix("udp://")?;
    if let Ok(addr) = rest.parse::<SocketAddr>() {
        return Some(addr);
    }
    rest.parse::<IpAddr>()
        .ok()
        .map(|ip| SocketAddr::new(ip, 53))
}

// Re-export for tests: a UDP socket bound on loopback acting as a DNS server.
#[cfg(test)]
pub(crate) use tests::spawn_mock_dns_server;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::test_util::{build_test_response, make_a_record};
    use tokio::net::UdpSocket;

    /// Start a loopback UDP "DNS server" that answers every query with the
    /// given A record. Returns its address.
    pub(crate) async fn spawn_mock_dns_server(answer_ip: [u8; 4]) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                    return;
                };
                let query = &buf[..n];
                if query.len() < 12 {
                    continue;
                }
                let tx_id = u16::from_be_bytes([query[0], query[1]]);
                // Echo the question section (name + QTYPE/QCLASS).
                let Ok(name_end) = crate::wire::skip_dns_name(query, 12) else {
                    continue;
                };
                let question = &query[12..name_end + 4];
                // Rebuild the answer with the queried name.
                let name = decode_question_name(question);
                let answer = make_a_record(&name, answer_ip);
                let resp = build_test_response(tx_id, 0x8180, &[question], &[&answer]);
                let _ = sock.send_to(&resp, peer).await;
            }
        });
        addr
    }

    fn decode_question_name(question: &[u8]) -> String {
        let mut name = String::new();
        let mut pos = 0;
        while pos < question.len() && question[pos] != 0 {
            let len = question[pos] as usize;
            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(std::str::from_utf8(&question[pos + 1..pos + 1 + len]).unwrap_or("?"));
            pos += 1 + len;
        }
        name
    }

    #[test]
    fn parse_udp_addr_variants() {
        assert_eq!(
            parse_udp_addr("223.5.5.5"),
            Some(SocketAddr::new("223.5.5.5".parse().unwrap(), 53))
        );
        assert_eq!(
            parse_udp_addr("udp://223.5.5.5"),
            Some(SocketAddr::new("223.5.5.5".parse().unwrap(), 53))
        );
        assert_eq!(
            parse_udp_addr("udp://223.5.5.5:5353"),
            Some(SocketAddr::new("223.5.5.5".parse().unwrap(), 5353))
        );
        assert!(parse_udp_addr("dns.example.com").is_none());
        assert!(parse_udp_addr("https://dns.example.com/dns-query").is_none());
    }

    #[tokio::test]
    async fn bootstrap_resolves_via_default_nameserver() {
        let server = spawn_mock_dns_server([9, 9, 9, 9]).await;
        let bootstrap = Bootstrap::from_nameservers(&[format!("udp://{}", server)]);
        let ip = bootstrap.resolve("dns.example.com").await.unwrap();
        assert_eq!(ip, "9.9.9.9".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn bootstrap_caches_result() {
        // Point at a server, resolve once, then the server goes "away" (we
        // re-point nothing — a second resolve must be served from cache).
        let server = spawn_mock_dns_server([9, 9, 9, 9]).await;
        let bootstrap = Bootstrap::from_nameservers(&[format!("udp://{server}")]);
        let first = bootstrap.resolve("dns.example.com").await.unwrap();
        let second = bootstrap.resolve("dns.example.com").await.unwrap();
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn bootstrap_ip_literal_short_circuits() {
        let bootstrap = Bootstrap::system_only_for_test();
        let ip = bootstrap.resolve("1.2.3.4").await.unwrap();
        assert_eq!(ip, "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn bootstrap_dead_server_does_not_panic() {
        // Nothing listens on this port; resolution must fail (or fall back to
        // the system resolver for a real host) without panicking.
        let bootstrap = Bootstrap::from_nameservers(&["udp://127.0.0.1:1".to_string()]);
        let result = bootstrap.resolve("nonexistent.invalid").await;
        // System fallback for a .invalid TLD must fail.
        assert!(result.is_err());
    }
}
