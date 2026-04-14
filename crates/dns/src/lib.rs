use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicU16, Ordering};

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio::task;

static DNS_TX_ID: AtomicU16 = AtomicU16::new(1);

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

/// Resolve a hostname by sending a UDP DNS query directly to the given nameserver,
/// bypassing the system resolver. This avoids DNS queries being routed through the
/// system proxy, which is critical for GEOIP accuracy.
pub async fn resolve_via(host: &str, nameserver: IpAddr) -> Result<IpAddr> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    let ns_addr = SocketAddr::new(nameserver, 53);

    let tx_id = DNS_TX_ID.fetch_add(1, Ordering::Relaxed);
    let query = build_dns_query(host, tx_id);
    sock.send_to(&query, ns_addr).await?;

    let mut buf = [0u8; 512];
    let timeout = tokio::time::timeout(std::time::Duration::from_secs(2), sock.recv_from(&mut buf));
    let (n, _) = timeout
        .await
        .map_err(|_| anyhow::anyhow!("DNS query to {nameserver} timed out"))??;

    parse_dns_response(&buf[..n], host, tx_id)
}

/// Resolve by racing all nameservers concurrently — first successful response wins.
/// Falls back to the system resolver if nameservers is empty or all fail.
pub async fn resolve_with_nameservers(host: &str, nameservers: &[IpAddr]) -> Result<IpAddr> {
    if nameservers.is_empty() {
        return resolve(host).await;
    }

    // Race all nameservers concurrently, take the first success.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<IpAddr>(1);

    for ns in nameservers {
        let ns = *ns;
        let host = host.to_string();
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Ok(ip) = resolve_via(&host, ns).await {
                let _ = tx.send(ip).await;
            }
        });
    }
    drop(tx); // drop our sender so rx closes when all spawned tasks finish

    // Wait for the first result, or timeout if all fail.
    let timeout = std::time::Duration::from_secs(2) + std::time::Duration::from_millis(100);
    if let Ok(Some(ip)) = tokio::time::timeout(timeout, rx.recv()).await {
        return Ok(ip);
    }

    tracing::debug!(
        host,
        "all nameservers failed, falling back to system resolver"
    );
    resolve(host).await
}

/// Build a minimal DNS A-record query packet.
fn build_dns_query(host: &str, tx_id: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);

    buf.extend_from_slice(&tx_id.to_be_bytes()); // ID
    buf.extend_from_slice(&[0x01, 0x00]); // Flags: RD=1
    buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    buf.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
    buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
    buf.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0

    // Encode domain name as DNS labels
    for label in host.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0x00); // root label

    buf.extend_from_slice(&[0x00, 0x01]); // QTYPE=A
    buf.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN

    buf
}

/// Parse a DNS response and extract the first A record.
fn parse_dns_response(data: &[u8], host: &str, expected_id: u16) -> Result<IpAddr> {
    if data.len() < 12 {
        anyhow::bail!("DNS response too short");
    }

    let resp_id = u16::from_be_bytes([data[0], data[1]]);
    if resp_id != expected_id {
        anyhow::bail!("DNS response ID mismatch: expected {expected_id}, got {resp_id}");
    }

    let flags = u16::from_be_bytes([data[2], data[3]]);
    let rcode = flags & 0x000F;
    if rcode != 0 {
        anyhow::bail!("DNS error rcode={rcode} for {host}");
    }

    let ancount = u16::from_be_bytes([data[6], data[7]]);
    if ancount == 0 {
        anyhow::bail!("no answers in DNS response for {host}");
    }

    // Skip the question section
    let mut pos = 12;
    pos = skip_dns_name(data, pos)?;
    if pos + 4 > data.len() {
        anyhow::bail!("DNS response truncated after question name");
    }
    pos += 4; // skip QTYPE + QCLASS

    // Parse answer records, looking for A (type 1) records
    for _ in 0..ancount {
        pos = skip_dns_name(data, pos)?;

        if pos + 10 > data.len() {
            anyhow::bail!("DNS response truncated in answer record");
        }

        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlength > data.len() {
            anyhow::bail!("DNS response truncated in RDATA");
        }

        if rtype == 1 && rdlength == 4 {
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
            ));
            return Ok(ip);
        }

        pos += rdlength;
    }

    anyhow::bail!("no A record found in DNS response for {host}")
}

/// Skip a DNS name (handles both label sequences and compressed pointers).
fn skip_dns_name(data: &[u8], mut pos: usize) -> Result<usize> {
    loop {
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
    fn ip_passthrough() {
        let addr: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(addr.is_loopback());
    }

    #[test]
    fn build_query_encodes_labels() {
        let query = build_dns_query("www.example.com", 0x1234);
        // Header is 12 bytes, then labels
        assert_eq!(query[12], 3); // "www" length
        assert_eq!(&query[13..16], b"www");
        assert_eq!(query[16], 7); // "example" length
        assert_eq!(&query[17..24], b"example");
        assert_eq!(query[24], 3); // "com" length
        assert_eq!(&query[25..28], b"com");
        assert_eq!(query[28], 0); // root
    }

    #[test]
    fn tx_id_in_query() {
        let query = build_dns_query("test.com", 0xABCD);
        assert_eq!(query[0], 0xAB);
        assert_eq!(query[1], 0xCD);
    }

    #[test]
    fn skip_name_handles_pointer() {
        // A pointer: 0xC0 0x0C (points to offset 12)
        let data = [0xC0, 0x0C, 0x00];
        assert_eq!(skip_dns_name(&data, 0).unwrap(), 2);
    }

    #[test]
    fn skip_name_handles_labels() {
        // "www" (3 bytes) + null
        let data = [3, b'w', b'w', b'w', 0];
        assert_eq!(skip_dns_name(&data, 0).unwrap(), 5);
    }
}
