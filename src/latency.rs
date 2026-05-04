use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clashx_rs_config::types::Proxy;
use clashx_rs_proxy::inbound::TargetAddr;
use clashx_rs_proxy::outbound::OutboundStream;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use unicode_width::UnicodeWidthStr;

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONCURRENT: usize = 10;
const TCP_DEADLINE: Duration = Duration::from_secs(30);
const FULL_DEADLINE: Duration = Duration::from_secs(60);

const PROBE_HOST_IP: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
const PROBE_PORT: u16 = 80;

fn probe_http_request() -> &'static [u8] {
    static REQ: OnceLock<Vec<u8>> = OnceLock::new();
    REQ.get_or_init(|| format!("HEAD / HTTP/1.0\r\nHost: {PROBE_HOST_IP}\r\n\r\n").into_bytes())
}

/// Global lock — at most one latency measurement runs at a time across all CLI
/// invocations, preventing probe storms from concurrent `clashx-rs latency` calls.
fn global_latency_lock() -> &'static Semaphore {
    static LOCK: OnceLock<Semaphore> = OnceLock::new();
    LOCK.get_or_init(|| Semaphore::new(1))
}

fn dummy_target() -> Arc<TargetAddr> {
    Arc::new(TargetAddr::Ip(IpAddr::V4(PROBE_HOST_IP), PROBE_PORT))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyLatencyResult {
    pub name: String,
    pub proxy_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Measure raw TCP connect latency to all proxies.
/// Uses TcpStream::connect(SocketAddr) — raw TCP, bypasses all HTTP/SOCKS proxy settings.
pub async fn measure_tcp(proxies: &[Proxy]) -> Vec<ProxyLatencyResult> {
    let _global = global_latency_lock().acquire().await;
    let deadline = Instant::now() + TCP_DEADLINE;

    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT));
    let mut set = JoinSet::new();

    for proxy in proxies {
        let (name, server, port, proxy_type) = match proxy_info(proxy) {
            Some((n, s, p, t)) => (n.to_string(), s.to_string(), p, t.to_string()),
            None => continue,
        };
        let sem = sem.clone();

        set.spawn(async move {
            let _permit = sem.acquire().await;

            let start = Instant::now();
            let result = tokio::time::timeout(PROBE_TIMEOUT, async {
                let addr: SocketAddr = tokio::net::lookup_host((server.as_str(), port))
                    .await
                    .ok()
                    .and_then(|mut iter| iter.next())
                    .ok_or_else(|| "dns failed".to_string())?;
                TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
                Ok::<_, String>(())
            })
            .await;

            match result {
                Ok(Ok(())) => ProxyLatencyResult {
                    name,
                    proxy_type,
                    tcp_ms: Some(start.elapsed().as_millis() as u64),
                    full_ms: None,
                    error: None,
                },
                Ok(Err(e)) => ProxyLatencyResult {
                    name,
                    proxy_type,
                    tcp_ms: None,
                    full_ms: None,
                    error: Some(e),
                },
                Err(_) => ProxyLatencyResult {
                    name,
                    proxy_type,
                    tcp_ms: None,
                    full_ms: None,
                    error: Some("timeout".to_string()),
                },
            }
        });
    }

    let mut results: Vec<ProxyLatencyResult> = Vec::with_capacity(proxies.len());
    while let Some(Ok(r)) = set.join_next().await {
        results.push(r);
        if Instant::now() > deadline {
            break;
        }
    }
    results.sort_by_key(|r| r.tcp_ms.unwrap_or(u64::MAX));
    results
}

/// Measure full protocol setup latency using actual outbound connectors.
pub async fn measure_full(proxies: Vec<Proxy>) -> Vec<ProxyLatencyResult> {
    let _global = global_latency_lock().acquire().await;
    let deadline = Instant::now() + FULL_DEADLINE;
    let count = proxies.len();
    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT));
    let mut set = JoinSet::new();
    let target = dummy_target();

    for proxy in proxies.into_iter() {
        let (name, proxy_type) = match proxy_info(&proxy) {
            Some((n, _, _, t)) => (n.to_string(), t.to_string()),
            None => continue,
        };
        let sem = sem.clone();
        let target = target.clone();

        set.spawn(async move {
            let _permit = sem.acquire().await;

            let start = Instant::now();
            let res: Result<()> = async {
                let mut stream = crate::daemon::connect_outbound(&proxy, &target).await?;
                probe_through_tunnel(&mut stream).await
            }
            .await;

            match res {
                Ok(()) => ProxyLatencyResult {
                    name,
                    proxy_type,
                    tcp_ms: None,
                    full_ms: Some(start.elapsed().as_millis() as u64),
                    error: None,
                },
                Err(e) => ProxyLatencyResult {
                    name,
                    proxy_type,
                    tcp_ms: None,
                    full_ms: None,
                    error: Some(format!("{e:#}")),
                },
            }
        });
    }

    let mut results: Vec<ProxyLatencyResult> = Vec::with_capacity(count);
    while let Some(Ok(r)) = set.join_next().await {
        results.push(r);
        if Instant::now() > deadline {
            break;
        }
    }
    results.sort_by_key(|r| r.full_ms.unwrap_or(u64::MAX));
    results
}

/// Send a small HTTP HEAD request through an established tunnel and require
/// at least one response byte. Errors if the remote closes/RSTs without
/// responding or the read deadline elapses — surfacing nodes whose handshake
/// succeeds but whose actual relay is broken (e.g. Trojan auth-rejected).
async fn probe_through_tunnel(stream: &mut OutboundStream) -> Result<()> {
    tokio::time::timeout(PROBE_TIMEOUT, async {
        match stream {
            OutboundStream::Tcp(s) => probe_io(s).await,
            OutboundStream::Tls(s) => probe_io(s.as_mut()).await,
            OutboundStream::Rejected => bail!("rejected"),
        }
    })
    .await
    .context("probe response timed out")?
}

async fn probe_io<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S) -> Result<()> {
    s.write_all(probe_http_request())
        .await
        .context("write probe request")?;
    let mut buf = [0u8; 16];
    let n = s.read(&mut buf).await.context("read probe response")?;
    if n == 0 {
        bail!("server closed connection without response (likely auth-rejected)");
    }
    Ok(())
}

fn proxy_info(proxy: &Proxy) -> Option<(&str, &str, u16, &'static str)> {
    let name = proxy.name()?;
    match proxy {
        Proxy::Trojan(t) => Some((name, &t.server, t.port, "trojan")),
        Proxy::Socks5(s) => Some((name, &s.server, s.port, "socks5")),
        Proxy::Unknown => None,
    }
}

fn display_len(s: &str) -> usize {
    UnicodeWidthStr::width(s)
}

pub fn print_table(results: &[ProxyLatencyResult], full: bool) {
    if results.is_empty() {
        println!("no proxies to measure");
        return;
    }

    fn latency_val(ms: u64) -> String {
        format!("{}ms", ms)
    }

    fn latency_display_len(ms: u64) -> usize {
        if ms == 0 {
            3
        } else {
            (ms.ilog10() as usize) + 3
        }
    }

    let mut name_width = display_len("NAME");
    let mut type_width = display_len("TYPE");
    let mut tcp_width = display_len("LATENCY");
    let mut full_width = display_len("FULL");
    for r in results {
        name_width = name_width.max(display_len(&r.name));
        type_width = type_width.max(display_len(&r.proxy_type));
        if let Some(ms) = r.tcp_ms {
            tcp_width = tcp_width.max(latency_display_len(ms));
        } else if let Some(ref e) = r.error {
            tcp_width = tcp_width.max(display_len(e));
        }
        if full {
            if let Some(ms) = r.full_ms {
                full_width = full_width.max(latency_display_len(ms));
            } else if let Some(ref e) = r.error {
                full_width = full_width.max(display_len(e));
            }
        }
    }

    // Print header
    if full {
        println!(
            "  NAME{}  TYPE{}  {}FULL",
            pad(display_len("NAME"), name_width),
            pad(display_len("TYPE"), type_width),
            pad(display_len("FULL"), full_width),
        );
    } else {
        println!(
            "  NAME{}  TYPE{}  {}LATENCY",
            pad(display_len("NAME"), name_width),
            pad(display_len("TYPE"), type_width),
            pad(display_len("LATENCY"), tcp_width),
        );
    }

    // Print rows
    for r in results {
        let name_pad = pad(display_len(&r.name), name_width);
        let type_pad = pad(display_len(&r.proxy_type), type_width);
        if full {
            let full_val = match r.full_ms {
                Some(ms) => latency_val(ms),
                None => r.error.as_deref().unwrap_or("N/A").to_string(),
            };
            let full_val_w = display_len(&full_val);
            let full_pad = pad(full_val_w, full_width);
            println!(
                "  {name}{name_pad}  {type}{type_pad}  {full_pad}{full_val}",
                name = r.name,
                type = r.proxy_type,
            );
        } else {
            let tcp_val = match r.tcp_ms {
                Some(ms) => latency_val(ms),
                None => r.error.as_deref().unwrap_or("N/A").to_string(),
            };
            let tcp_val_w = display_len(&tcp_val);
            let tcp_pad = pad(tcp_val_w, tcp_width);
            println!(
                "  {name}{name_pad}  {type}{type_pad}  {tcp_pad}{tcp_val}",
                name = r.name,
                type = r.proxy_type,
            );
        }
    }
}

fn pad(current: usize, target: usize) -> String {
    if current >= target {
        String::new()
    } else {
        " ".repeat(target - current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trojan_proxy() -> Proxy {
        Proxy::Trojan(clashx_rs_config::types::TrojanProxy {
            name: "hk-01".into(),
            server: "1.2.3.4".into(),
            port: 443,
            password: "secret".into(),
            sni: Some("example.com".into()),
            skip_cert_verify: false,
        })
    }

    fn socks5_proxy() -> Proxy {
        Proxy::Socks5(clashx_rs_config::types::Socks5Proxy {
            name: "local".into(),
            server: "127.0.0.1".into(),
            port: 1080,
            username: Some("alice".into()),
            password: Some("pass".into()),
        })
    }

    #[test]
    fn proxy_info_trojan() {
        let p = trojan_proxy();
        let (name, server, port, ptype) = proxy_info(&p).unwrap();
        assert_eq!(name, "hk-01");
        assert_eq!(server, "1.2.3.4");
        assert_eq!(port, 443);
        assert_eq!(ptype, "trojan");
    }

    #[test]
    fn proxy_info_socks5() {
        let p = socks5_proxy();
        let (name, server, port, ptype) = proxy_info(&p).unwrap();
        assert_eq!(name, "local");
        assert_eq!(server, "127.0.0.1");
        assert_eq!(port, 1080);
        assert_eq!(ptype, "socks5");
    }

    #[test]
    fn proxy_info_unknown_returns_none() {
        assert!(proxy_info(&Proxy::Unknown).is_none());
    }

    #[test]
    fn dummy_target_is_cloudflare_dns() {
        let t = dummy_target();
        assert_eq!(t.host_string(), "1.1.1.1");
        assert_eq!(t.port(), 80);
    }

    #[test]
    fn serialize_success_result() {
        let r = ProxyLatencyResult {
            name: "hk-01".into(),
            proxy_type: "trojan".into(),
            tcp_ms: Some(45),
            full_ms: None,
            error: None,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains(r#""tcp_ms":45"#));
        assert!(json.contains(r#""name":"hk-01""#));
        // full_ms and error should be absent
        assert!(!json.contains("full_ms"));
        assert!(!json.contains("error"));
    }

    #[test]
    fn serialize_error_result() {
        let r = ProxyLatencyResult {
            name: "sg-01".into(),
            proxy_type: "trojan".into(),
            tcp_ms: None,
            full_ms: None,
            error: Some("timeout".into()),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains(r#""error":"timeout""#));
        assert!(!json.contains("tcp_ms"));
        assert!(!json.contains("full_ms"));
    }

    #[test]
    fn serialize_full_result() {
        let r = ProxyLatencyResult {
            name: "hk-01".into(),
            proxy_type: "trojan".into(),
            tcp_ms: Some(45),
            full_ms: Some(156),
            error: None,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains(r#""tcp_ms":45"#));
        assert!(json.contains(r#""full_ms":156"#));
        assert!(!json.contains("error"));
    }

    #[test]
    fn sort_fastest_first() {
        let mut results = [
            ProxyLatencyResult {
                name: "slow".into(),
                proxy_type: "trojan".into(),
                tcp_ms: Some(300),
                full_ms: None,
                error: None,
            },
            ProxyLatencyResult {
                name: "fast".into(),
                proxy_type: "trojan".into(),
                tcp_ms: Some(10),
                full_ms: None,
                error: None,
            },
            ProxyLatencyResult {
                name: "timeout".into(),
                proxy_type: "trojan".into(),
                tcp_ms: None,
                full_ms: None,
                error: Some("timeout".into()),
            },
        ];
        results.sort_by_key(|r| r.tcp_ms.unwrap_or(u64::MAX));
        assert_eq!(results[0].name, "fast");
        assert_eq!(results[1].name, "slow");
        assert_eq!(results[2].name, "timeout");
    }

    #[test]
    fn display_len_ascii() {
        assert_eq!(display_len("hello"), 5);
        assert_eq!(display_len(""), 0);
    }

    #[test]
    fn display_len_emoji_flag() {
        // Regional indicator pairs (flag emoji) are 2 display columns each
        assert_eq!(display_len("🇭🇰"), 2);
        assert_eq!(display_len("🇨🇳"), 2);
    }

    #[test]
    fn display_len_cjk() {
        // CJK characters are 2 display columns each
        assert_eq!(display_len("香港"), 4);
        assert_eq!(display_len("台湾"), 4);
    }

    #[test]
    fn display_len_mixed() {
        // 🇭🇰(2) + space(1) + 香港(4) + space(1) + 01(2) = 10
        assert_eq!(display_len("🇭🇰 香港 01"), 10);
    }

    #[test]
    fn pad_adds_spaces() {
        assert_eq!(pad(5, 10), "     "); // 5 spaces
        assert_eq!(pad(10, 10), ""); // no padding needed
        assert_eq!(pad(12, 10), ""); // wider than target, no padding
    }

    #[test]
    fn pad_with_emoji_field() {
        // display_len("🇭🇰") = 2, target width = 6, need 4 spaces
        assert_eq!(pad(display_len("🇭🇰"), 6), "    ");
    }

    #[test]
    fn alignment_width_accounts_for_emoji() {
        // If max name width is computed with display_len,
        // ASCII names get correct padding to align with emoji-heavy names
        let names = ["hk-01", "🇭🇰 香港 01"];
        let max_w = names.iter().map(|n| display_len(n)).max().unwrap();
        assert_eq!(max_w, 10); // emoji name is wider in display, not bytes
        assert_eq!(display_len("hk-01"), 5);
        assert_eq!(pad(5, max_w), "     "); // 5 spaces to align with 10-wide name
    }

    use tokio::net::TcpListener;

    /// Shuts down the write half so the client sees EOF deterministically.
    async fn run_test_server(listener: TcpListener, reply: Option<&'static [u8]>) {
        let (mut conn, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 64];
        let _ = conn.read(&mut buf).await;
        if let Some(bytes) = reply {
            let _ = conn.write_all(bytes).await;
        }
        let _ = conn.shutdown().await;
    }

    #[tokio::test]
    async fn probe_detects_silent_close() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(run_test_server(listener, None));

        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut stream = OutboundStream::Tcp(tcp);
        let err = probe_through_tunnel(&mut stream)
            .await
            .expect_err("expected probe to fail when server closes silently");
        assert!(
            format!("{err:#}").contains("server closed"),
            "unexpected error: {err:#}"
        );
    }

    #[tokio::test]
    async fn probe_succeeds_when_response_received() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(run_test_server(listener, Some(b"HTTP/1.0 200 OK\r\n\r\n")));

        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut stream = OutboundStream::Tcp(tcp);
        probe_through_tunnel(&mut stream)
            .await
            .expect("probe should succeed when bytes flow back");
    }

    #[tokio::test]
    async fn probe_rejects_rejected_stream() {
        let mut stream = OutboundStream::Rejected;
        let err = probe_through_tunnel(&mut stream).await.err().unwrap();
        assert!(format!("{err:#}").contains("rejected"));
    }
}
