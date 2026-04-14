use anyhow::{bail, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use super::TargetAddr;

/// Max length of a single HTTP request line or header line (bytes).
/// Well above typical browser headers; bounds malicious slowloris-style
/// unbounded-line attacks.
const MAX_LINE_LEN: usize = 8 * 1024;

/// Max number of header lines in one HTTP request.
/// Real browsers send 20-40; 128 gives headroom without permitting DoS.
const MAX_HEADERS: usize = 128;

/// Read a single line, bailing if it exceeds MAX_LINE_LEN bytes.
/// Guards against slowloris-style unbounded-line DoS attacks.
async fn read_bounded_line<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    out: &mut String,
) -> Result<()> {
    out.clear();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            break;
        }
        let (consumed, done) = match available.iter().position(|&b| b == b'\n') {
            Some(idx) => (idx + 1, true),
            None => (available.len(), false),
        };
        if out.len() + consumed > MAX_LINE_LEN {
            bail!("HTTP line exceeded {MAX_LINE_LEN} bytes");
        }
        let s = std::str::from_utf8(&available[..consumed])
            .map_err(|_| anyhow::anyhow!("invalid UTF-8 in HTTP line"))?;
        out.push_str(s);
        reader.consume(consumed);
        if done {
            break;
        }
    }
    Ok(())
}

/// Parse "host:port" where port is required.
fn parse_host_port(s: &str) -> Result<TargetAddr> {
    // Try to split off the last ":port" component, handling IPv6 bracketed addresses.
    let (host, port_str) = if s.starts_with('[') {
        // IPv6 bracket form: [::1]:443
        let bracket_end = s
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("invalid IPv6 address: {s}"))?;
        let rest = &s[bracket_end + 1..];
        let port_str = rest
            .strip_prefix(':')
            .ok_or_else(|| anyhow::anyhow!("missing port in: {s}"))?;
        (&s[1..bracket_end], port_str)
    } else {
        let pos = s
            .rfind(':')
            .ok_or_else(|| anyhow::anyhow!("missing port in: {s}"))?;
        (&s[..pos], &s[pos + 1..])
    };

    let port: u16 = port_str
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid port: {port_str}"))?;

    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => Ok(TargetAddr::Ip(ip, port)),
        Err(_) => Ok(TargetAddr::Domain(host.to_string(), port)),
    }
}

/// Parse "host" or "host:port"; use `default_port` when no port is present.
fn parse_host_port_default(s: &str, default_port: u16) -> Result<TargetAddr> {
    // If it contains a colon (and it's not an IPv6-only address) try to find port.
    // Bracketed IPv6 always has port syntax; bare IPv6 without brackets has no port.
    if s.starts_with('[')
        || s.rfind(':')
            .is_some_and(|pos| s[pos + 1..].parse::<u16>().is_ok() && !s.contains("::"))
    {
        // Check if the part after the last colon is a valid port number.
        if let Some(pos) = s.rfind(':') {
            if let Ok(_port) = s[pos + 1..].parse::<u16>() {
                // Avoid treating IPv6 colons as port separators when not bracketed.
                if !s[..pos].contains(':') || s.starts_with('[') {
                    return parse_host_port(s);
                }
            }
        }
    }
    // No port found — use default.
    match s.parse::<std::net::IpAddr>() {
        Ok(ip) => Ok(TargetAddr::Ip(ip, default_port)),
        Err(_) => Ok(TargetAddr::Domain(s.to_string(), default_port)),
    }
}

/// Perform an HTTP proxy handshake.
///
/// Supports:
/// - `CONNECT host:port HTTP/1.x` — returns `(target, None)` after sending 200.
/// - Plain HTTP methods (`GET`, `POST`, etc.) — returns `(target, Some(raw_request_bytes))`.
pub async fn handshake(stream: &mut TcpStream) -> Result<(TargetAddr, Option<Vec<u8>>)> {
    let mut reader = BufReader::new(stream);

    // Read the request line.
    let mut request_line = String::new();
    read_bounded_line(&mut reader, &mut request_line).await?;
    let trimmed = request_line.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() {
        bail!("empty HTTP request");
    }

    let mut parts = trimmed.splitn(3, ' ');
    let method = parts.next().unwrap_or("").to_uppercase();
    let uri = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();

    if method == "CONNECT" {
        // CONNECT host:port HTTP/1.x
        let target = parse_host_port(&uri)?;

        // Read and discard headers until we see an empty line.
        let mut line = String::new();
        let mut header_count = 0usize;
        loop {
            if header_count >= MAX_HEADERS {
                bail!("HTTP headers exceeded {MAX_HEADERS}");
            }
            read_bounded_line(&mut reader, &mut line).await?;
            let l = line.trim_end_matches(['\r', '\n']);
            if l.is_empty() {
                break;
            }
            header_count += 1;
        }

        // Preserve any bytes the BufReader read ahead (early client data).
        let initial_data = if reader.buffer().is_empty() {
            None
        } else {
            Some(reader.buffer().to_vec())
        };
        let inner = reader.into_inner();

        inner
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        Ok((target, initial_data))
    } else {
        // Plain HTTP request.
        // Collect all headers.
        let mut headers: Vec<String> = Vec::new();
        let mut host_header: Option<String> = None;
        let mut line = String::new();
        loop {
            if headers.len() >= MAX_HEADERS {
                bail!("HTTP headers exceeded {MAX_HEADERS}");
            }
            read_bounded_line(&mut reader, &mut line).await?;
            let trimmed_line = line.trim_end_matches(['\r', '\n']).to_string();
            if trimmed_line.is_empty() {
                break;
            }
            if host_header.is_none() {
                let lower = trimmed_line.to_lowercase();
                if let Some(rest) = lower.strip_prefix("host:") {
                    host_header = Some(rest.trim().to_string());
                }
            }
            headers.push(trimmed_line);
        }

        // Preserve any body bytes the BufReader read ahead of the header boundary.
        let body_prefix = if reader.buffer().is_empty() {
            Vec::new()
        } else {
            reader.buffer().to_vec()
        };
        drop(reader);

        // Determine the target.
        // First try to extract from absolute URI: http://host[:port]/path
        let target = if uri.starts_with("http://") || uri.starts_with("https://") {
            let without_scheme = if let Some(s) = uri.strip_prefix("http://") {
                s
            } else {
                uri.strip_prefix("https://").unwrap_or(&uri)
            };
            // The authority is everything up to the first '/'.
            let authority = without_scheme.split('/').next().unwrap_or(without_scheme);
            parse_host_port_default(authority, 80)?
        } else if let Some(host) = host_header.as_deref() {
            parse_host_port_default(host, 80)?
        } else {
            bail!("could not determine target host from HTTP request");
        };

        // Reconstruct the raw request bytes to forward upstream.
        // Use the original request line verbatim, then append any buffered body bytes.
        let mut raw: Vec<u8> = Vec::new();
        raw.extend_from_slice(format!("{method} {uri} {version}\r\n").as_bytes());
        for h in &headers {
            raw.extend_from_slice(h.as_bytes());
            raw.extend_from_slice(b"\r\n");
        }
        raw.extend_from_slice(b"\r\n");
        raw.extend_from_slice(&body_prefix);

        Ok((target, Some(raw)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    /// Helper: bind a listener, send bytes from a client, and return the server-side stream.
    async fn server_stream_with_client_bytes(bytes: Vec<u8>) -> TcpStream {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let mut client = TcpStream::connect(addr).await.unwrap();
            client.write_all(&bytes).await.unwrap();
            // Keep the client alive so the server stream doesn't see EOF prematurely.
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        });

        let (stream, _) = listener.accept().await.unwrap();
        stream
    }

    #[tokio::test]
    async fn http_plain_preserves_body() {
        // The client sends headers + body in a single write.  The BufReader may
        // pull the body bytes into its internal buffer while parsing headers; we
        // must not lose them.
        let raw = b"POST http://example.com/api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello";
        let mut stream = server_stream_with_client_bytes(raw.to_vec()).await;

        let (target, initial_data) = handshake(&mut stream).await.unwrap();

        match target {
            TargetAddr::Domain(host, port) => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 80);
            }
            other => panic!("expected Domain, got {other:?}"),
        }

        let data = initial_data.expect("expected initial_data for plain HTTP POST");
        // The reconstructed headers must be present.
        assert!(
            data.starts_with(b"POST http://example.com/api HTTP/1.1\r\n"),
            "request line missing from initial_data"
        );
        // The body bytes must be appended after the blank line.
        assert!(
            data.ends_with(b"\r\nhello"),
            "body bytes missing from initial_data: {:?}",
            String::from_utf8_lossy(&data)
        );
    }

    #[tokio::test]
    async fn http_connect_request() {
        let raw = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        let mut stream = server_stream_with_client_bytes(raw.to_vec()).await;

        let (target, body) = handshake(&mut stream).await.unwrap();

        assert!(body.is_none(), "CONNECT should return no forwarded body");
        match target {
            TargetAddr::Domain(host, port) => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 443);
            }
            other => panic!("expected Domain, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn http_connect_preserves_early_data() {
        // The client sends CONNECT headers immediately followed by early data bytes
        // (like a TLS ClientHello) in a single write. The BufReader may pull the
        // early data bytes into its internal buffer while parsing headers; we must
        // not lose them.
        let early_bytes = b"early-tls-data";
        let mut raw = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".to_vec();
        raw.extend_from_slice(early_bytes);

        let mut stream = server_stream_with_client_bytes(raw).await;

        let (target, initial_data) = handshake(&mut stream).await.unwrap();

        match target {
            TargetAddr::Domain(host, port) => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 443);
            }
            other => panic!("expected Domain, got {other:?}"),
        }

        let data = initial_data.expect("expected initial_data for CONNECT with early data");
        assert_eq!(
            data, early_bytes,
            "early data bytes must be preserved in initial_data"
        );
    }

    #[test]
    fn parse_host_port_domain() {
        let target = parse_host_port("example.com:443").unwrap();
        match target {
            TargetAddr::Domain(host, port) => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 443);
            }
            other => panic!("expected Domain, got {other:?}"),
        }
    }

    #[test]
    fn parse_host_port_ip() {
        let target = parse_host_port("1.2.3.4:80").unwrap();
        match target {
            TargetAddr::Ip(ip, port) => {
                assert_eq!(ip, "1.2.3.4".parse::<IpAddr>().unwrap());
                assert_eq!(port, 80);
            }
            other => panic!("expected Ip, got {other:?}"),
        }
    }
}
