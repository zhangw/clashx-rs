//! Active liveness probing for proxy nodes.
//!
//! Relay-phase failures are invisible for Trojan outbounds (the protocol has
//! no remote-dial acknowledgment), so passive failure tracking alone cannot
//! detect "half-dead" nodes that accept local TLS but cannot reach the
//! outside. This module periodically dials a probe URL *through each node
//! itself* — bypassing the rule engine, selection chains, and failover lists —
//! and expects an exact HTTP status match. Results feed the shared
//! [`CooldownTracker`], so the data plane skips dead nodes without any change
//! to its candidate-list logic.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clashx_rs_proxy::inbound::TargetAddr;
use clashx_rs_proxy::outbound::OutboundStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::RwLock;
use tokio::task::JoinSet;

use crate::daemon::{connect_outbound, DaemonState};
use crate::retry::CooldownTracker;

/// Budget for one probe attempt (outbound connect + HTTP exchange). Must
/// exceed PROXY_CONNECT_TIMEOUT (5s) so a slow-but-alive node still has time
/// for the HTTP exchange after a slow handshake.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
/// Delay before the single confirmation re-probe after a failure, so one
/// transient blip does not sideline a node for a whole cooldown period.
const CONFIRM_BACKOFF: Duration = Duration::from_secs(2);
/// Hard cap on response bytes read while looking for the header terminator.
const MAX_HEADER_BYTES: usize = 8192;

/// Parsed probe URL (plain HTTP only — the probe measures node egress
/// liveness, not content confidentiality, and skipping TLS keeps the check
/// cheap and free of certificate-related false negatives).
struct ProbeTarget {
    host: String,
    port: u16,
    path: String,
}

fn parse_probe_url(url: &str) -> Result<ProbeTarget> {
    let rest = url
        .strip_prefix("http://")
        .context("only http:// probe URLs are supported")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().context("invalid probe URL port")?),
        None => (authority, 80),
    };
    if host.is_empty() {
        bail!("probe URL has an empty host");
    }
    Ok(ProbeTarget {
        host: host.to_string(),
        port,
        path: path.to_string(),
    })
}

/// Extract the status code from the first line of an HTTP response.
fn parse_status_code(buf: &[u8]) -> Result<u16> {
    let end = buf.iter().position(|&b| b == b'\n').unwrap_or(buf.len());
    let line = std::str::from_utf8(&buf[..end])
        .context("response status line is not UTF-8")?
        .trim_end();
    let mut parts = line.split_whitespace();
    match parts.next() {
        Some(v) if v.starts_with("HTTP/") => {}
        _ => bail!("malformed HTTP status line: {line:?}"),
    }
    parts
        .next()
        .context("missing status code")?
        .parse::<u16>()
        .context("invalid status code")
}

/// Send the probe request and read just enough of the response to parse the
/// status line. The body (if any) is never consumed.
async fn http_status_exchange<S>(stream: &mut S, target: &ProbeTarget) -> Result<u16>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: clashx-rs\r\nConnection: close\r\n\r\n",
        target.path, target.host
    );
    stream.write_all(request.as_bytes()).await?;

    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() >= MAX_HEADER_BYTES {
            break;
        }
    }
    parse_status_code(&buf)
}

/// One probe attempt: connect through the node, exchange HTTP, require an
/// exact status match. Returns the round-trip latency on success.
async fn probe_once(
    proxy: &clashx_rs_config::types::Proxy,
    target: &ProbeTarget,
    expected_status: u16,
) -> Result<Duration> {
    let start = Instant::now();
    tokio::time::timeout(PROBE_TIMEOUT, async {
        let addr = TargetAddr::Domain(target.host.clone(), target.port);
        let stream = connect_outbound(proxy, &addr).await?;
        let status = match stream {
            OutboundStream::Tcp(mut s) => http_status_exchange(&mut s, target).await?,
            OutboundStream::Tls(mut s) => http_status_exchange(&mut *s, target).await?,
            OutboundStream::Rejected => bail!("outbound rejected"),
        };
        if status != expected_status {
            bail!("unexpected probe status {status}, expected {expected_status}");
        }
        Ok(start.elapsed())
    })
    .await
    .context("health probe timed out")?
}

/// Probe a node, with one confirmation retry on failure. Returns healthy.
async fn probe_with_confirm(
    name: &str,
    proxy: &clashx_rs_config::types::Proxy,
    target: &ProbeTarget,
    expected_status: u16,
) -> bool {
    for attempt in 0..2 {
        if attempt > 0 {
            tokio::time::sleep(CONFIRM_BACKOFF).await;
        }
        match probe_once(proxy, target, expected_status).await {
            Ok(latency) => {
                tracing::debug!(proxy = %name, latency_ms = %latency.as_millis(), "health probe succeeded");
                return true;
            }
            Err(e) => {
                tracing::warn!(proxy = %name, attempt = attempt + 1, err = %e, "health probe failed");
            }
        }
    }
    false
}

/// Re-probe cadence for sidelined (unhealthy) nodes — much faster than the
/// healthy-node interval so recovery is detected quickly.
const UNHEALTHY_RECHECK_SECS: u64 = 60;

/// Lower bound for any configured probe interval.
const MIN_INTERVAL_SECS: u64 = 30;

/// Max concurrent probes in one round — bounds the TLS-handshake burst at
/// startup (when every node is due) the same way latency.rs does.
const MAX_CONCURRENT_PROBES: usize = 10;

/// Per-node jitter factor in [0.9, 1.1), stable across rounds (derived from
/// the node name; the crate has no RNG dependency). Applied to each node's
/// due interval so nodes drift apart even after sharing a first-round
/// timestamp.
fn node_jitter(name: &str) -> f64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    name.hash(&mut h);
    0.9 + 0.2 * (h.finish() % 1000) as f64 / 1000.0
}

/// Whether a node is due for a probe: never probed, or its last probe is
/// older than the applicable cadence (fast recheck for sidelined nodes, the
/// node's own configured interval for healthy ones) scaled by its stable
/// jitter factor.
fn probe_due(
    last: Option<Instant>,
    sidelined: bool,
    interval: Duration,
    recheck: Duration,
    jitter: f64,
    now: Instant,
) -> bool {
    match last {
        None => true,
        Some(t) => {
            let base = if sidelined { recheck } else { interval };
            now.duration_since(t) >= base.mul_f64(jitter)
        }
    }
}

/// Scheduler tick with ±10% jitter (derived from the system clock) so the
/// loop does not resonate with external timers.
fn jittered_interval(secs: u64) -> Duration {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let frac = nanos as f64 / 1_000_000_000.0; // [0, 1)
    let scale = 0.9 + 0.2 * frac; // [0.9, 1.1)
    Duration::from_secs_f64(secs as f64 * scale)
}

/// Extract the server address of a proxy node.
fn proxy_server(proxy: &clashx_rs_config::types::Proxy) -> Option<&str> {
    match proxy {
        clashx_rs_config::types::Proxy::Trojan(t) => Some(t.server.as_str()),
        clashx_rs_config::types::Proxy::Socks5(s) => Some(s.server.as_str()),
        clashx_rs_config::types::Proxy::Unknown => None,
    }
}

/// Whether an IP is publicly routable. Covers RFC 1918, loopback, link-local,
/// CGNAT (100.64.0.0/10), IPv6 ULA/link-local, and IPv4-mapped IPv6.
fn is_public_ip(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || (o[0] == 100 && (o[1] & 0xC0) == 64)) // 100.64.0.0/10 CGNAT
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(v4));
            }
            let seg0 = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || (seg0 & 0xfe00) == 0xfc00 // fc00::/7 unique local
                || (seg0 & 0xffc0) == 0xfe80) // fe80::/10 link-local
        }
    }
}

/// Whether probing this server against a public URL makes sense. Servers
/// whose addresses are all non-public are intranet relays; probing them
/// against e.g. gstatic would fail forever and permanently sideline them,
/// silently gutting the cooldown mechanism for their group. IP literals are
/// checked directly; domains are resolved once (cached by the caller).
/// Unresolvable domains are treated as probeable — the probe path itself
/// will surface the failure.
async fn server_is_probeable(server: &str) -> bool {
    if let Ok(ip) = server.parse::<std::net::IpAddr>() {
        return is_public_ip(ip);
    }
    match tokio::net::lookup_host((server, 80)).await {
        Ok(addrs) => {
            let ips: Vec<std::net::IpAddr> = addrs.map(|a| a.ip()).collect();
            ips.is_empty() || ips.iter().any(|&ip| is_public_ip(ip))
        }
        Err(_) => true,
    }
}

/// Supervisor loop: probe every due member node of health-check-enabled
/// groups, then sleep until the next scheduler tick. Reads a fresh config
/// snapshot each round, so config reloads take effect without task lifecycle
/// management.
pub async fn run(state: Arc<RwLock<DaemonState>>) {
    let mut last_probe: std::collections::HashMap<String, Instant> =
        std::collections::HashMap::new();
    // Nodes whose probe URL failed to parse — warned once, then skipped
    // silently. An invalid URL must never mark a node unhealthy.
    let mut warned_invalid: std::collections::HashSet<String> = std::collections::HashSet::new();
    // Server -> probeable decision, resolved at most once per config
    // generation.
    let mut server_probeable: std::collections::HashMap<String, bool> =
        std::collections::HashMap::new();
    // Detect config reloads: reload_state swaps in a fresh tracker.
    let mut prev_cooldown: Option<Arc<CooldownTracker>> = None;

    loop {
        let (schedule, interval_secs, cooldown) = {
            let st = state.read().await;
            (
                st.probe_schedule(),
                st.probe_interval_secs(),
                st.cooldown_handle(),
            )
        };
        let recheck = Duration::from_secs(UNHEALTHY_RECHECK_SECS);
        let now = Instant::now();

        // Config reload discarded all health state along with the old
        // tracker — forget our bookkeeping too, so every node is re-probed
        // immediately instead of waiting out a stale full interval.
        if prev_cooldown
            .as_ref()
            .is_some_and(|p| !Arc::ptr_eq(p, &cooldown))
        {
            last_probe.clear();
            warned_invalid.clear();
            server_probeable.clear();
        }
        prev_cooldown = Some(Arc::clone(&cooldown));

        // Drop bookkeeping for nodes no longer in any enabled group.
        let current: std::collections::HashSet<&str> =
            schedule.iter().map(|(n, _)| n.as_str()).collect();
        last_probe.retain(|n, _| current.contains(n.as_str()));
        warned_invalid.retain(|n| current.contains(n.as_str()));

        // Filter due nodes from the cheap schedule snapshot first; Proxy
        // configs are cloned on demand (one short read lock) only for nodes
        // that are actually due this round.
        let mut due = Vec::new();
        for (name, hc) in schedule {
            let interval = Duration::from_secs(hc.interval.max(MIN_INTERVAL_SECS));
            let jitter = node_jitter(&name);
            if !probe_due(
                last_probe.get(&name).copied(),
                cooldown.is_sidelined(&name),
                interval,
                recheck,
                jitter,
                now,
            ) {
                continue;
            }

            // Invalid URLs (e.g. the https:// variant common in mihomo
            // subscription configs) disable probing for that node with a
            // one-time warning — they must not sideline it.
            let target = match parse_probe_url(&hc.url) {
                Ok(t) => t,
                Err(e) => {
                    if warned_invalid.insert(name.clone()) {
                        tracing::warn!(
                            proxy = %name,
                            url = %hc.url,
                            err = %e,
                            "invalid health-check URL; probing disabled for this node"
                        );
                    }
                    continue;
                }
            };

            let Some(proxy) = state.read().await.proxy_named(&name) else {
                continue;
            };

            // Skip intranet relays (servers with only non-public addresses).
            if let Some(server) = proxy_server(&proxy) {
                let probeable = match server_probeable.get(server) {
                    Some(&v) => v,
                    None => {
                        let v = server_is_probeable(server).await;
                        if !v {
                            tracing::info!(
                                proxy = %name,
                                server = %server,
                                "server is not publicly routable; probing disabled for this node"
                            );
                        }
                        server_probeable.insert(server.to_string(), v);
                        v
                    }
                };
                if !probeable {
                    continue;
                }
            }

            due.push((name, proxy, target, hc.expected_status));
        }

        if !due.is_empty() {
            let sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_PROBES));
            let mut set: JoinSet<(String, bool, bool)> = JoinSet::new();
            for (name, proxy, target, expected_status) in due {
                let cd: Arc<CooldownTracker> = Arc::clone(&cooldown);
                let sem = Arc::clone(&sem);
                set.spawn(async move {
                    let _permit = sem.acquire().await;
                    let was_sidelined = cd.is_sidelined(&name);
                    let healthy = probe_with_confirm(&name, &proxy, &target, expected_status).await;
                    (name, healthy, was_sidelined)
                });
            }
            while let Some(res) = set.join_next().await {
                let Ok((name, healthy, was_sidelined)) = res else {
                    continue;
                };
                last_probe.insert(name.clone(), Instant::now());
                if healthy {
                    cooldown.record_success(&name);
                    if was_sidelined {
                        tracing::info!(proxy = %name, "node recovered (health probe)");
                    }
                } else {
                    cooldown.sideline(&name);
                    if !was_sidelined {
                        tracing::warn!(
                            proxy = %name,
                            "node sidelined until a health probe passes (recheck every {}s)",
                            UNHEALTHY_RECHECK_SECS
                        );
                    }
                }
            }
        }

        let tick = interval_secs.min(UNHEALTHY_RECHECK_SECS);
        tokio::time::sleep(jittered_interval(tick)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_probe_url_with_path() {
        let t = parse_probe_url("http://www.gstatic.com/generate_204").unwrap();
        assert_eq!(t.host, "www.gstatic.com");
        assert_eq!(t.port, 80);
        assert_eq!(t.path, "/generate_204");
    }

    #[test]
    fn parse_probe_url_without_path_defaults_to_root() {
        let t = parse_probe_url("http://example.com").unwrap();
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, 80);
        assert_eq!(t.path, "/");
    }

    #[test]
    fn parse_probe_url_with_explicit_port() {
        let t = parse_probe_url("http://127.0.0.1:8080/health").unwrap();
        assert_eq!(t.host, "127.0.0.1");
        assert_eq!(t.port, 8080);
        assert_eq!(t.path, "/health");
    }

    #[test]
    fn parse_probe_url_rejects_https_and_empty_host() {
        assert!(parse_probe_url("https://www.gstatic.com/generate_204").is_err());
        assert!(parse_probe_url("http://").is_err());
        assert!(parse_probe_url("http://:8080/x").is_err());
    }

    #[test]
    fn parse_status_code_ok() {
        assert_eq!(
            parse_status_code(b"HTTP/1.1 204 No Content\r\nServer: x\r\n").unwrap(),
            204
        );
        assert_eq!(parse_status_code(b"HTTP/1.0 200 OK\r\n").unwrap(), 200);
    }

    #[test]
    fn parse_status_code_rejects_garbage() {
        assert!(parse_status_code(b"").is_err());
        assert!(parse_status_code(b"<html>hijacked</html>").is_err());
        assert!(parse_status_code(b"HTTP/1.1 abc\r\n").is_err());
    }

    #[test]
    fn probe_due_rules() {
        let now = Instant::now();
        let interval = Duration::from_secs(300);
        let recheck = Duration::from_secs(60);
        let jitter = 1.0;

        // Never probed -> always due.
        assert!(probe_due(None, false, interval, recheck, jitter, now));
        assert!(probe_due(None, true, interval, recheck, jitter, now));

        // Healthy node: not due before interval, due after.
        let recent = now - Duration::from_secs(120);
        assert!(!probe_due(
            Some(recent),
            false,
            interval,
            recheck,
            jitter,
            now
        ));
        let old = now - Duration::from_secs(301);
        assert!(probe_due(Some(old), false, interval, recheck, jitter, now));

        // Sidelined node: due once the fast recheck cadence has passed.
        let very_recent = now - Duration::from_secs(30);
        assert!(!probe_due(
            Some(very_recent),
            true,
            interval,
            recheck,
            jitter,
            now
        ));
        assert!(probe_due(
            Some(recent),
            true,
            interval,
            recheck,
            jitter,
            now
        ));

        // Per-node interval is honored: a node with a long configured
        // interval is not due on a shorter global cadence.
        let long_interval = Duration::from_secs(3600);
        assert!(!probe_due(
            Some(old),
            false,
            long_interval,
            recheck,
            jitter,
            now
        ));

        // Jitter scales the effective interval.
        assert!(probe_due(Some(recent), false, interval, recheck, 0.3, now));
        assert!(!probe_due(Some(old), false, interval, recheck, 1.1, now));
    }

    #[test]
    fn node_jitter_is_stable_and_in_range() {
        let a = node_jitter("🇸🇬 新加坡 01");
        assert_eq!(a, node_jitter("🇸🇬 新加坡 01"));
        for name in ["a", "b", "c", "node-x", "🇭🇰 香港 01"] {
            let j = node_jitter(name);
            assert!(
                (0.9..1.1).contains(&j),
                "jitter {j} out of range for {name}"
            );
        }
    }

    #[test]
    fn public_ip_classification() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        assert!(is_public_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(is_public_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))));
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8))));
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
        // CGNAT 100.64.0.0/10 (carrier NAT / intranet relays).
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::new(100, 127, 255, 254))));
        assert!(is_public_ip(IpAddr::V4(Ipv4Addr::new(100, 128, 0, 1))));
        assert!(is_public_ip(IpAddr::V6(
            "2606:4700:4700::1111".parse().unwrap()
        )));
        assert!(!is_public_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!is_public_ip(IpAddr::V6("fd00::1".parse().unwrap())));
        assert!(!is_public_ip(IpAddr::V6("fe80::1".parse().unwrap())));
        // IPv4-mapped IPv6 inherits the v4 classification.
        assert!(!is_public_ip(IpAddr::V6(
            "::ffff:10.0.0.1".parse().unwrap()
        )));
        assert!(is_public_ip(IpAddr::V6("::ffff:1.1.1.1".parse().unwrap())));
    }

    #[tokio::test]
    async fn server_probeability() {
        // IP literals: no DNS involved.
        assert!(!server_is_probeable("10.8.2.1").await);
        assert!(!server_is_probeable("127.0.0.1").await);
        assert!(server_is_probeable("203.0.113.7").await);
        // Domain resolving only to loopback is treated as an intranet relay.
        assert!(!server_is_probeable("localhost").await);
    }

    /// End-to-end HTTP exchange against a local loopback listener (no proxy,
    /// no external network — safe to run alongside a live daemon).
    #[tokio::test]
    async fn http_status_exchange_reads_status() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            // Consume the request headers.
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).await;
            s.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let target = ProbeTarget {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            path: "/generate_204".to_string(),
        };
        let status = http_status_exchange(&mut stream, &target).await.unwrap();
        assert_eq!(status, 204);
    }

    /// A hijacked/intercepted response (HTML instead of HTTP) must fail.
    #[tokio::test]
    async fn http_status_exchange_rejects_hijacked_response() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).await;
            s.write_all(b"<html>portal</html>").await.unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let target = ProbeTarget {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            path: "/".to_string(),
        };
        assert!(http_status_exchange(&mut stream, &target).await.is_err());
    }
}
