use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio::task;

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

    let query = build_dns_query(host);
    sock.send_to(&query, ns_addr).await?;

    let mut buf = [0u8; 512];
    let timeout = tokio::time::timeout(std::time::Duration::from_secs(3), sock.recv_from(&mut buf));
    let (n, _) = timeout
        .await
        .map_err(|_| anyhow::anyhow!("DNS query to {nameserver} timed out"))??;

    parse_dns_response(&buf[..n], host)
}

/// Resolve using the first responding nameserver from the list.
/// Falls back to the system resolver if nameservers is empty.
pub async fn resolve_with_nameservers(host: &str, nameservers: &[IpAddr]) -> Result<IpAddr> {
    if nameservers.is_empty() {
        return resolve(host).await;
    }

    // Try the first nameserver; fall back to system resolver on failure.
    for ns in nameservers {
        match resolve_via(host, *ns).await {
            Ok(ip) => return Ok(ip),
            Err(e) => {
                tracing::debug!(nameserver = %ns, err = %e, host, "nameserver failed, trying next");
            }
        }
    }

    tracing::debug!(
        host,
        "all nameservers failed, falling back to system resolver"
    );
    resolve(host).await
}

/// Build a minimal DNS A-record query packet.
fn build_dns_query(host: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);

    // Header: ID=0x1234, flags=0x0100 (standard query, recursion desired)
    buf.extend_from_slice(&[0x12, 0x34]); // ID
    buf.extend_from_slice(&[0x01, 0x00]); // Flags: RD=1
    buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    buf.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
    buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
    buf.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0

    // Question: encode domain name as labels
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
fn parse_dns_response(data: &[u8], host: &str) -> Result<IpAddr> {
    if data.len() < 12 {
        anyhow::bail!("DNS response too short");
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
    // Skip QNAME
    while pos < data.len() && data[pos] != 0 {
        if data[pos] & 0xC0 == 0xC0 {
            pos += 2;
            break;
        }
        pos += 1 + data[pos] as usize;
    }
    if pos < data.len() && data[pos] == 0 {
        pos += 1; // skip null terminator
    }
    pos += 4; // skip QTYPE + QCLASS

    // Parse answer records, looking for A (type 1) records
    for _ in 0..ancount {
        if pos + 2 > data.len() {
            break;
        }

        // Skip NAME (may be a pointer)
        if data[pos] & 0xC0 == 0xC0 {
            pos += 2;
        } else {
            while pos < data.len() && data[pos] != 0 {
                pos += 1 + data[pos] as usize;
            }
            pos += 1;
        }

        if pos + 10 > data.len() {
            break;
        }

        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;

        if rtype == 1 && rdlength == 4 && pos + 4 <= data.len() {
            // A record: 4 bytes IPv4
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
        let query = build_dns_query("www.example.com");
        // Header is 12 bytes, then labels
        assert_eq!(query[12], 3); // "www" length
        assert_eq!(&query[13..16], b"www");
        assert_eq!(query[16], 7); // "example" length
        assert_eq!(&query[17..24], b"example");
        assert_eq!(query[24], 3); // "com" length
        assert_eq!(&query[25..28], b"com");
        assert_eq!(query[28], 0); // root
    }
}
