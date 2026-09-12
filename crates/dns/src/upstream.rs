//! Nameserver upstreams: plain UDP, DNS-over-HTTPS, DNS-over-TLS.
//!
//! Classification of config strings lives here (the config crate stays pure
//! data). Unknown/unsupported entries are warned about and skipped, matching
//! the repo's "ignore, don't reject" config style.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::bootstrap::{parse_udp_addr, Bootstrap};
use crate::wire::{build_dns_query, next_tx_id, parse_dns_response, DnsResult, QType};

/// Per-participant timeout for plain-UDP upstreams.
pub(crate) const UDP_TIMEOUT: Duration = Duration::from_secs(2);

/// Per-participant timeout for DoH/DoT upstreams — they pay a TCP/TLS
/// handshake (and possibly a bootstrap lookup) on top of the query itself.
pub(crate) const DOH_DOT_TIMEOUT: Duration = Duration::from_secs(4);

/// A single nameserver upstream.
pub enum Upstream {
    /// Plain UDP/53 (or `udp://IP:port`).
    Udp { addr: SocketAddr },
    /// DNS-over-HTTPS (RFC 8484, POST application/dns-message).
    Doh(DohUpstream),
    /// DNS-over-TLS (RFC 7858).
    Dot(DotUpstream),
}

impl Upstream {
    /// Per-participant timeout used by the resolver race.
    pub(crate) fn participant_timeout(&self) -> Duration {
        match self {
            Upstream::Udp { .. } => UDP_TIMEOUT,
            Upstream::Doh(_) | Upstream::Dot(_) => DOH_DOT_TIMEOUT,
        }
    }

    /// Send one A-query for `host` to this upstream. Each variant enforces
    /// its own participant deadline here in one layer: UDP inside
    /// `udp_exchange`, the handshake-heavy DoH/DoT paths via an explicit
    /// timeout (they have no inner one).
    pub(crate) async fn exchange(&self, host: &str, bootstrap: &Bootstrap) -> Result<DnsResult> {
        match self {
            Upstream::Udp { addr } => udp_exchange(host, *addr).await,
            Upstream::Doh(doh) => {
                tokio::time::timeout(DOH_DOT_TIMEOUT, doh.exchange(host, bootstrap))
                    .await
                    .map_err(|_| anyhow::anyhow!("DoH query via {} timed out", doh.host))?
            }
            Upstream::Dot(dot) => {
                tokio::time::timeout(DOH_DOT_TIMEOUT, dot.exchange(host, bootstrap))
                    .await
                    .map_err(|_| anyhow::anyhow!("DoT query via {} timed out", dot.host))?
            }
        }
    }

    /// Hostname this upstream needs bootstrap resolution for (DoH/DoT server
    /// domains only; IP literals and UDP upstreams return None).
    pub(crate) fn bootstrap_host(&self) -> Option<&str> {
        let host = match self {
            Upstream::Udp { .. } => return None,
            Upstream::Doh(d) => d.host.as_str(),
            Upstream::Dot(d) => d.host.as_str(),
        };
        (host.parse::<IpAddr>().is_err()).then_some(host)
    }
}

/// Race a set of independent lookup attempts; the first success wins. Each
/// attempt resolves to `Some` on success and enforces its own deadline;
/// `window` bounds the whole race. Shared by the resolver's nameserver race
/// and the bootstrap UDP race.
pub(crate) async fn race_first<T, F>(attempts: Vec<F>, window: Duration) -> Option<T>
where
    T: Send + 'static,
    F: std::future::Future<Output = Option<T>> + Send + 'static,
{
    let (tx, mut rx) = tokio::sync::mpsc::channel::<T>(1);
    for attempt in attempts {
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Some(v) = attempt.await {
                let _ = tx.send(v).await;
            }
        });
    }
    drop(tx);
    match tokio::time::timeout(window, rx.recv()).await {
        Ok(Some(v)) => Some(v),
        _ => None,
    }
}

/// Classify one `nameserver`/`proxy-server-nameserver` config entry.
/// Returns None (with a warning) for unsupported or malformed entries.
pub(crate) fn classify(entry: &str) -> Option<Upstream> {
    let entry = entry.trim();
    if let Some(addr) = parse_udp_addr(entry) {
        return Some(Upstream::Udp { addr });
    }
    if entry.starts_with("https://") {
        return classify_doh(entry);
    }
    if let Some(rest) = entry.strip_prefix("tls://") {
        return classify_dot(rest);
    }
    tracing::warn!(entry, "ignoring unsupported nameserver entry");
    None
}

/// Classify a `https://host[:port]/path` DoH entry.
fn classify_doh(entry: &str) -> Option<Upstream> {
    let url = match reqwest::Url::parse(entry) {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(entry, err = %e, "ignoring malformed DoH nameserver entry");
            return None;
        }
    };
    let Some(host) = url.host_str().map(|s| s.to_string()) else {
        tracing::warn!(entry, "ignoring DoH entry without a host");
        return None;
    };
    let port = url.port_or_known_default().unwrap_or(443);
    Some(Upstream::Doh(DohUpstream {
        url: url.to_string(),
        host,
        port,
        state: tokio::sync::RwLock::new(None),
    }))
}

/// Classify a `tls://host[:port]` DoT entry (default port 853).
fn classify_dot(rest: &str) -> Option<Upstream> {
    let (host, port) = match rest.split_once(':') {
        // Split on the FIRST ':' — IPv6 literals (bracketed or bare) fail the
        // port parse below and are skipped with a warning; v1 supports IPv4
        // addresses and domain names as DoT hosts only.
        Some((h, p)) if !h.is_empty() => match p.parse::<u16>() {
            Ok(port) => (h.trim_matches(['[', ']']).to_string(), port),
            Err(_) => {
                tracing::warn!(entry = %format!("tls://{rest}"), "ignoring DoT entry with invalid port");
                return None;
            }
        },
        _ => (rest.trim_matches(['[', ']']).to_string(), 853),
    };
    if host.is_empty() {
        tracing::warn!(entry = %format!("tls://{rest}"), "ignoring DoT entry without a host");
        return None;
    }
    Some(Upstream::Dot(DotUpstream::new(host, port)))
}

// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------

/// One A-query over UDP with a fixed timeout. `addr` includes the port.
pub(crate) async fn udp_exchange(host: &str, addr: SocketAddr) -> Result<DnsResult> {
    udp_exchange_with_timeout(host, addr, UDP_TIMEOUT).await
}

async fn udp_exchange_with_timeout(
    host: &str,
    addr: SocketAddr,
    timeout: Duration,
) -> Result<DnsResult> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    // Connect the socket so the kernel drops datagrams from any other source
    // address — an off-path spoofer must then forge the server address on top
    // of guessing the ephemeral port and transaction ID.
    sock.connect(addr).await?;

    let tx_id = next_tx_id();
    let query = build_dns_query(host, tx_id, QType::A)?;
    sock.send(&query).await?;

    let mut buf = [0u8; 2048];
    let n = tokio::time::timeout(timeout, sock.recv(&mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("DNS query to {addr} timed out"))??;

    parse_dns_response(&buf[..n], host, tx_id, QType::A)
}

// ---------------------------------------------------------------------------
// DoH
// ---------------------------------------------------------------------------

/// DNS-over-HTTPS upstream. The reqwest client is pinned to the
/// bootstrap-resolved IP via `resolve_to_addrs`, so reqwest itself never
/// touches the system resolver. On bootstrap TTL expiry the client is
/// rebuilt if the IP changed; on bootstrap failure the old client (old IP)
/// keeps serving — stale-if-error.
pub struct DohUpstream {
    /// Full request URL, e.g. `https://dns.example.com/dns-query`.
    url: String,
    /// URL host — also the `resolve_to_addrs` pin key and TLS SNI.
    host: String,
    port: u16,
    state: tokio::sync::RwLock<Option<DohState>>,
}

struct DohState {
    ip: IpAddr,
    client: reqwest::Client,
}

impl DohUpstream {
    /// Get (or lazily build/rebuild) the pinned reqwest client.
    async fn client(&self, bootstrap: &Bootstrap) -> Result<reqwest::Client> {
        // Fresh lookup: IP-literal hosts short-circuit inside bootstrap and
        // cached entries are cheap. On bootstrap failure this is None and we
        // fall back to the stale pinned IP.
        let fresh_ip = bootstrap.resolve(&self.host).await.ok();

        {
            let guard = self.state.read().await;
            if let Some(st) = guard.as_ref() {
                match fresh_ip {
                    Some(ip) if ip != st.ip => {} // IP changed — rebuild below
                    // Same IP, or bootstrap failed (stale-if-error): reuse.
                    _ => return Ok(st.client.clone()),
                }
            }
        }

        let ip = fresh_ip.ok_or_else(|| {
            anyhow::anyhow!(
                "bootstrap for DoH server {} failed and no stale address is pinned",
                self.host
            )
        })?;
        let mut guard = self.state.write().await;
        if let Some(st) = guard.as_ref() {
            if st.ip == ip {
                return Ok(st.client.clone());
            }
        }
        let client = build_doh_client(&self.host, ip, self.port)?;
        *guard = Some(DohState {
            ip,
            client: client.clone(),
        });
        Ok(client)
    }

    async fn exchange(&self, host: &str, bootstrap: &Bootstrap) -> Result<DnsResult> {
        let client = self.client(bootstrap).await?;
        let tx_id = next_tx_id();
        let query = build_dns_query(host, tx_id, QType::A)?;
        let resp = client
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, "application/dns-message")
            .header(reqwest::header::ACCEPT, "application/dns-message")
            .body(query)
            .send()
            .await
            .context("DoH request failed")?;
        if !resp.status().is_success() {
            anyhow::bail!("DoH server {} returned HTTP {}", self.host, resp.status());
        }
        let body = resp
            .bytes()
            .await
            .context("DoH response body read failed")?;
        parse_dns_response(&body, host, tx_id, QType::A)
    }

    /// Test constructor: plain-HTTP URL against a loopback mock with a
    /// literal-IP host, so bootstrap short-circuits.
    #[cfg(test)]
    fn new_for_test(url: &str, port: u16) -> Self {
        let url = reqwest::Url::parse(url).unwrap();
        Self {
            url: url.to_string(),
            host: url.host_str().unwrap().to_string(),
            port,
            state: tokio::sync::RwLock::new(None),
        }
    }
}

/// Build the per-upstream DoH client pinned to `ip`.
fn build_doh_client(host: &str, ip: IpAddr, port: u16) -> Result<reqwest::Client> {
    let client = reqwest::Client::builder()
        // CRITICAL: never let DoH honor HTTP(S)_PROXY env vars — with
        // clashx-rs configured as the system proxy, that would loop DNS
        // right back into our own inbound listener. `.no_proxy()` must stay
        // even though the workspace reqwest currently lacks the
        // `system-proxy` feature: a feature change must not reintroduce
        // the loop.
        .no_proxy()
        // Pin the server hostname to the bootstrap-resolved IP so reqwest
        // never invokes the system resolver itself.
        .resolve_to_addrs(host, &[SocketAddr::new(ip, port)])
        .build()?;
    Ok(client)
}

// ---------------------------------------------------------------------------
// DoT
// ---------------------------------------------------------------------------

/// DNS-over-TLS upstream (RFC 7858). One fresh TCP+TLS connection per query;
/// no connection reuse.
pub struct DotUpstream {
    host: String,
    port: u16,
    tls_config: Arc<rustls::ClientConfig>,
}

/// One webpki-roots client config shared by every DoT upstream — the configs
/// never differ, so don't rebuild the root store per upstream.
fn dot_tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    Arc::clone(CONFIG.get_or_init(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        // Pin the ring provider explicitly: the workspace unifies rustls
        // with both ring and aws-lc-rs (via reqwest), so the auto-detecting
        // builder() panics unless a process default was installed.
        Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .expect("ring provider supports the default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth(),
        )
    }))
}

impl DotUpstream {
    fn new(host: String, port: u16) -> Self {
        Self {
            host,
            port,
            tls_config: dot_tls_config(),
        }
    }

    #[cfg(test)]
    fn with_tls_config(host: String, port: u16, tls_config: Arc<rustls::ClientConfig>) -> Self {
        Self {
            host,
            port,
            tls_config,
        }
    }

    async fn exchange(&self, host: &str, bootstrap: &Bootstrap) -> Result<DnsResult> {
        // IP-literal hosts short-circuit inside bootstrap.
        let ip = bootstrap.resolve(&self.host).await?;
        let tcp = TcpStream::connect(SocketAddr::new(ip, self.port))
            .await
            .context("DoT TCP connect failed")?;

        let server_name = rustls::pki_types::ServerName::try_from(self.host.clone())
            .map_err(|e| anyhow::anyhow!("invalid DoT server name {}: {e}", self.host))?;
        let connector = tokio_rustls::TlsConnector::from(Arc::clone(&self.tls_config));
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .context("DoT TLS handshake failed")?;

        let tx_id = next_tx_id();
        let query = build_dns_query(host, tx_id, QType::A)?;
        tls.write_all(&frame_message(&query)).await?;

        let mut len_buf = [0u8; 2];
        tls.read_exact(&mut len_buf).await?;
        let len = frame_len(len_buf);
        let mut buf = vec![0u8; len];
        tls.read_exact(&mut buf).await?;

        parse_dns_response(&buf, host, tx_id, QType::A)
    }
}

/// RFC 7858 §3.3 framing: 2-byte big-endian length prefix + DNS message.
pub(crate) fn frame_message(msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(msg.len() + 2);
    out.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    out.extend_from_slice(msg);
    out
}

/// Decode the 2-byte frame-length prefix.
pub(crate) fn frame_len(prefix: [u8; 2]) -> usize {
    u16::from_be_bytes(prefix) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::spawn_mock_dns_server;

    #[test]
    fn classify_bare_ip_is_udp() {
        let up = classify("223.5.5.5").unwrap();
        assert!(matches!(
            up,
            Upstream::Udp { addr } if addr == SocketAddr::new("223.5.5.5".parse().unwrap(), 53)
        ));
    }

    #[test]
    fn classify_udp_scheme_with_port() {
        let up = classify("udp://223.5.5.5:5353").unwrap();
        assert!(matches!(
            up,
            Upstream::Udp { addr } if addr == SocketAddr::new("223.5.5.5".parse().unwrap(), 5353)
        ));
    }

    #[test]
    fn classify_doh_with_port_and_path() {
        let up = classify("https://dns.example.com:8443/query").unwrap();
        let Upstream::Doh(d) = up else {
            panic!("expected DoH");
        };
        assert_eq!(d.host, "dns.example.com");
        assert_eq!(d.port, 8443);
        assert!(d.url.ends_with("/query"));
    }

    #[test]
    fn classify_doh_default_port() {
        let up = classify("https://1.1.1.1/dns-query").unwrap();
        let Upstream::Doh(d) = up else {
            panic!("expected DoH");
        };
        assert_eq!(d.port, 443);
    }

    #[test]
    fn classify_dot_default_port() {
        let up = classify("tls://dot.example.com").unwrap();
        let Upstream::Dot(d) = up else {
            panic!("expected DoT");
        };
        assert_eq!(d.host, "dot.example.com");
        assert_eq!(d.port, 853);
    }

    #[test]
    fn classify_dot_with_port() {
        let up = classify("tls://8.8.8.8:8853").unwrap();
        let Upstream::Dot(d) = up else {
            panic!("expected DoT");
        };
        assert_eq!(d.host, "8.8.8.8");
        assert_eq!(d.port, 8853);
    }

    #[test]
    fn classify_unsupported_and_invalid_are_skipped() {
        assert!(classify("dhcp://auto").is_none());
        assert!(classify("quic://dns.example.com").is_none());
        assert!(classify("https://dns.example.com/dns-query#h3").is_some()); // fragment dropped by URL parse
        assert!(classify("tls://").is_none());
        assert!(classify("not-a-nameserver").is_none());
    }

    #[test]
    fn classify_doh_bootstrap_host() {
        let up = classify("https://dns.example.com/dns-query").unwrap();
        assert_eq!(up.bootstrap_host(), Some("dns.example.com"));
        let up = classify("https://1.1.1.1/dns-query").unwrap();
        assert_eq!(up.bootstrap_host(), None);
        let up = classify("tls://dot.example.com").unwrap();
        assert_eq!(up.bootstrap_host(), Some("dot.example.com"));
        let up = classify("223.5.5.5").unwrap();
        assert_eq!(up.bootstrap_host(), None);
    }

    #[tokio::test]
    async fn udp_exchange_success() {
        let server = spawn_mock_dns_server([203, 0, 113, 7]).await;
        let result = udp_exchange("example.com", server).await.unwrap();
        assert_eq!(result.ip, "203.0.113.7".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn udp_exchange_timeout() {
        // Mock that never replies.
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let _ = sock.recv_from(&mut buf).await; // swallow, never respond
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let err = udp_exchange_with_timeout("example.com", addr, Duration::from_millis(50))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("timed out"));
    }

    #[tokio::test]
    async fn udp_exchange_id_mismatch() {
        // Server that always answers with a wrong transaction ID.
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                    return;
                };
                let mut resp = buf[..n].to_vec();
                resp[0] ^= 0xFF; // corrupt the ID
                resp[2] = 0x81;
                resp[3] = 0x80;
                let _ = sock.send_to(&resp, peer).await;
            }
        });
        let err = udp_exchange("example.com", addr).await.unwrap_err();
        assert!(err.to_string().contains("ID mismatch"));
    }

    #[test]
    fn dot_framing_roundtrip() {
        let msg = b"\x12\x34hello-dns";
        let framed = frame_message(msg);
        assert_eq!(&framed[..2], &(msg.len() as u16).to_be_bytes());
        assert_eq!(&framed[2..], msg);
        assert_eq!(frame_len([framed[0], framed[1]]), msg.len());
    }

    #[test]
    fn dot_frame_len_bounds() {
        assert_eq!(frame_len([0x00, 0x00]), 0);
        assert_eq!(frame_len([0xFF, 0xFF]), 65535);
    }

    // --- DoH over loopback plain HTTP ---

    /// Minimal HTTP/1.1 server: reads one request, replies 200 with a DNS
    /// response body echoing the query's transaction ID.
    async fn spawn_mock_doh_server(answer_ip: [u8; 4]) -> SocketAddr {
        use crate::wire::test_util::{build_test_response, make_a_record};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut conn, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = Vec::with_capacity(1024);
                    let mut chunk = [0u8; 1024];
                    // Read headers + body (Content-Length driven).
                    let (body_start, content_len) = loop {
                        let n = conn.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                            let headers = String::from_utf8_lossy(&buf[..pos]).to_lowercase();
                            let content_len = headers
                                .lines()
                                .find_map(|l| l.strip_prefix("content-length:"))
                                .and_then(|v| v.trim().parse::<usize>().ok())
                                .unwrap_or(0);
                            let body_start = pos + 4;
                            if buf.len() >= body_start + content_len {
                                break (body_start, content_len);
                            }
                        }
                        if buf.len() > 16 * 1024 {
                            return;
                        }
                    };
                    let query = &buf[body_start..body_start + content_len];
                    if query.len() < 12 {
                        return;
                    }
                    let tx_id = u16::from_be_bytes([query[0], query[1]]);
                    let answer = make_a_record("example.com", answer_ip);
                    let resp = build_test_response(tx_id, 0x8180, &[&query[12..]], &[&answer]);
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        resp.len()
                    );
                    let _ = conn.write_all(head.as_bytes()).await;
                    let _ = conn.write_all(&resp).await;
                });
            }
        });
        addr
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    #[tokio::test]
    async fn doh_exchange_over_loopback_http() {
        let server = spawn_mock_doh_server([192, 0, 2, 55]).await;
        let url = format!("http://127.0.0.1:{}/dns-query", server.port());
        let doh = DohUpstream::new_for_test(&url, server.port());
        let bootstrap = Bootstrap::system_only_for_test();
        let result = doh.exchange("example.com", &bootstrap).await.unwrap();
        assert_eq!(result.ip, "192.0.2.55".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn doh_exchange_http_error_fails() {
        // Server that always replies 500.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut conn, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let _ = conn.read(&mut buf).await;
                    let _ = conn
                        .write_all(
                            b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n",
                        )
                        .await;
                });
            }
        });
        let url = format!("http://127.0.0.1:{}/dns-query", addr.port());
        let doh = DohUpstream::new_for_test(&url, addr.port());
        let bootstrap = Bootstrap::system_only_for_test();
        let err = doh.exchange("example.com", &bootstrap).await.unwrap_err();
        assert!(err.to_string().contains("500"));
    }

    // --- DoT over loopback TLS (rcgen self-signed cert pinned as root) ---

    #[tokio::test]
    async fn dot_exchange_over_loopback_tls() {
        use crate::wire::test_util::{build_test_response, make_a_record};

        let certified =
            rcgen::generate_simple_self_signed(vec!["dot.example.com".to_string()]).unwrap();
        let server_config = rustls::ServerConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certified.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into()),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(conn).await.unwrap();
            let mut len_buf = [0u8; 2];
            tls.read_exact(&mut len_buf).await.unwrap();
            let len = frame_len(len_buf);
            let mut query = vec![0u8; len];
            tls.read_exact(&mut query).await.unwrap();
            let tx_id = u16::from_be_bytes([query[0], query[1]]);
            let answer = make_a_record("example.com", [198, 51, 100, 9]);
            let resp = build_test_response(tx_id, 0x8180, &[&query[12..]], &[&answer]);
            tls.write_all(&frame_message(&resp)).await.unwrap();
        });

        let mut roots = rustls::RootCertStore::empty();
        roots.add(certified.cert.der().clone()).unwrap();
        let client_config = rustls::ClientConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();

        let dot = DotUpstream::with_tls_config(
            "dot.example.com".to_string(),
            addr.port(),
            Arc::new(client_config),
        );
        // Host "dot.example.com" must resolve without bootstrap: override by
        // pointing at loopback via a Bootstrap whose cache is pre-seeded.
        let bootstrap = Bootstrap::system_only_for_test();
        bootstrap
            .seed_for_test("dot.example.com", "127.0.0.1".parse().unwrap())
            .await;
        let result = dot.exchange("example.com", &bootstrap).await.unwrap();
        assert_eq!(result.ip, "198.51.100.9".parse::<IpAddr>().unwrap());
    }
}
