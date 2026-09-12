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

/// Hop-by-hop headers a proxy must not forward to the origin server
/// (RFC 9112 §7.6.1), plus the non-standard `Proxy-Connection` that clients
/// such as curl still emit.
///
/// `Transfer-Encoding` is deliberately absent: the body is relayed verbatim,
/// so the header that frames it has to survive.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
];

/// Header line a proxy appends to pin one request per connection.
const CONNECTION_CLOSE: &str = "Connection: close\r\n";

/// Split an absolute-form request-target into `(authority, origin-form path)`.
///
/// Clients address a proxy with absolute-form (`http://host:port/path`,
/// RFC 9112 §3.2.2), but the origin server has to be routed to by the
/// authority and has to receive origin-form (`/path`) — servers that treat the
/// request-target as a literal path, the h11/ASGI family among them, answer 404
/// otherwise. Both halves come from this one split so routing and rewriting can
/// never disagree about what counts as absolute-form.
///
/// Returns `None` for origin-form (`/path`) and asterisk-form (`*`). Testing
/// `/` first also stops a `://` inside a query string from being mistaken for a
/// scheme separator, and matching on `://` rather than a literal `http://`
/// prefix keeps the scheme comparison case-insensitive (RFC 3986 §3.1).
fn split_absolute_form(uri: &str) -> Option<(&str, &str)> {
    if uri.starts_with('/') {
        return None;
    }
    let (_scheme, rest) = uri.split_once("://")?;
    match rest.find('/') {
        Some(idx) => Some((&rest[..idx], &rest[idx..])),
        // `http://host` with no path at all.
        None => Some((rest, "/")),
    }
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
    let method = parts.next().unwrap_or("");
    let uri = parts.next().unwrap_or("");

    if method.eq_ignore_ascii_case("CONNECT") {
        // CONNECT host:port HTTP/1.x
        let target = parse_host_port(uri)?;

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
        let version = parts.next().unwrap_or("HTTP/1.1");
        let (target, raw) = read_plain_request(&mut reader, method, uri, version).await?;
        Ok((target, Some(raw)))
    }
}

/// Read a plain (non-CONNECT) proxy request and rebuild it for the origin.
///
/// The request line and headers are rebuilt rather than forwarded verbatim: the
/// origin server must see origin-form and must not see this hop's headers.
async fn read_plain_request(
    reader: &mut BufReader<&mut TcpStream>,
    method: &str,
    uri: &str,
    version: &str,
) -> Result<(TargetAddr, Vec<u8>)> {
    let mut headers: Vec<String> = Vec::new();
    let mut host_header: Option<String> = None;
    let mut line = String::new();
    loop {
        if headers.len() >= MAX_HEADERS {
            bail!("HTTP headers exceeded {MAX_HEADERS}");
        }
        read_bounded_line(reader, &mut line).await?;
        let trimmed_line = line.trim_end_matches(['\r', '\n']);
        if trimmed_line.is_empty() {
            break;
        }
        if host_header.is_none() {
            if let Some((name, rest)) = trimmed_line.split_once(':') {
                if name.eq_ignore_ascii_case("host") {
                    host_header = Some(rest.trim().to_string());
                }
            }
        }
        headers.push(trimmed_line.to_string());
    }

    // Both the routing target and the rewritten path come from this one split.
    // An absolute-form authority wins over the Host header (RFC 9112 §3.2.2);
    // Host is the fallback for origin-form.
    let absolute = split_absolute_form(uri);
    let target = if let Some((authority, _)) = absolute {
        parse_host_port_default(authority, 80)?
    } else if let Some(host) = host_header.as_deref() {
        parse_host_port_default(host, 80)?
    } else {
        bail!("could not determine target host from HTTP request");
    };
    let path = absolute.map_or(uri, |(_, path)| path);

    // An upgrade request (plain-HTTP WebSocket and friends) has to keep its
    // `Connection` / `Upgrade` pair for the handshake to succeed, and must not
    // be told to close — once upgraded, the raw byte relay downstream is
    // exactly the right behaviour.
    let is_upgrade = headers.iter().any(|h| {
        h.split_once(':')
            .is_some_and(|(name, _)| name.trim().eq_ignore_ascii_case("upgrade"))
    });
    // RFC 9112 §7.6.1: a `Connection` field nominates further headers that are
    // hop-by-hop for this connection only, so those names have to be stripped
    // alongside the fixed set in HOP_BY_HOP.
    let nominated: Vec<&str> = headers
        .iter()
        .filter_map(|h| h.split_once(':'))
        .filter(|(name, _)| name.trim().eq_ignore_ascii_case("connection"))
        .flat_map(|(_, value)| value.split(','))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .collect();

    let forwarded = |header: &str| -> bool {
        let Some((name, _)) = header.split_once(':') else {
            return false;
        };
        let name = name.trim();
        if is_upgrade
            && (name.eq_ignore_ascii_case("connection") || name.eq_ignore_ascii_case("upgrade"))
        {
            return true;
        }
        if HOP_BY_HOP.iter().any(|hop| name.eq_ignore_ascii_case(hop)) {
            return false;
        }
        !nominated
            .iter()
            .any(|token| name.eq_ignore_ascii_case(token))
    };

    // Over-estimate: headers that get filtered out only leave slack. The
    // trailing bytes are whatever the client pipelined past the header
    // boundary, still sitting in the reader's buffer.
    let capacity = method.len()
        + path.len()
        + version.len()
        + 4
        + headers.iter().map(|h| h.len() + 2).sum::<usize>()
        + CONNECTION_CLOSE.len()
        + 2
        + reader.buffer().len();

    let mut raw = Vec::with_capacity(capacity);
    raw.extend_from_slice(method.as_bytes());
    raw.push(b' ');
    raw.extend_from_slice(path.as_bytes());
    raw.push(b' ');
    raw.extend_from_slice(version.as_bytes());
    raw.extend_from_slice(b"\r\n");
    for header in headers.iter().filter(|h| forwarded(h)) {
        raw.extend_from_slice(header.as_bytes());
        raw.extend_from_slice(b"\r\n");
    }
    if !is_upgrade {
        // The relay is a blind byte pump: once this connection is bound to an
        // outbound it stays bound, so a second request arriving on it would be
        // delivered to the first request's host without being re-matched
        // against the rules. Asking the origin to close after the response
        // forces the client to open a fresh connection, which is routed from
        // scratch.
        raw.extend_from_slice(CONNECTION_CLOSE.as_bytes());
    }
    raw.extend_from_slice(b"\r\n");
    // Preserve body bytes the BufReader read ahead of the header boundary.
    raw.extend_from_slice(reader.buffer());

    Ok((target, raw))
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

    /// Helper: drive `handshake` over a plain-HTTP request and return the
    /// target plus the bytes rebuilt for the origin.
    async fn handshake_plain(raw: &[u8]) -> (TargetAddr, String) {
        let mut stream = server_stream_with_client_bytes(raw.to_vec()).await;
        let (target, initial_data) = handshake(&mut stream).await.unwrap();
        let data = String::from_utf8(initial_data.expect("expected initial_data")).unwrap();
        (target, data)
    }

    #[tokio::test]
    async fn http_plain_preserves_body() {
        // The client sends headers + body in a single write.  The BufReader may
        // pull the body bytes into its internal buffer while parsing headers; we
        // must not lose them.
        let raw = b"POST http://example.com/api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello";
        let (target, data) = handshake_plain(raw).await;

        match target {
            TargetAddr::Domain(host, port) => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 80);
            }
            other => panic!("expected Domain, got {other:?}"),
        }

        // The request line must have been rewritten to origin-form.
        assert!(
            data.starts_with("POST /api HTTP/1.1\r\n"),
            "request line not rewritten: {data:?}"
        );
        // The body bytes must be appended after the blank line.
        assert!(data.ends_with("\r\nhello"), "body bytes missing: {data:?}");
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

    #[tokio::test]
    async fn http_plain_rewrites_absolute_form() {
        // The defect this guards: forwarding the absolute-form request-target
        // verbatim makes servers that treat it as a literal path answer 404.
        let raw = b"GET http://192.0.2.10:9100/health HTTP/1.1\r\nHost: 192.0.2.10:9100\r\n\r\n";
        let (target, data) = handshake_plain(raw).await;

        match target {
            TargetAddr::Ip(ip, port) => {
                assert_eq!(ip, "192.0.2.10".parse::<IpAddr>().unwrap());
                assert_eq!(port, 9100);
            }
            other => panic!("expected Ip, got {other:?}"),
        }

        assert!(
            data.starts_with("GET /health HTTP/1.1\r\n"),
            "request line not rewritten: {data:?}"
        );
        assert!(
            data.contains("Host: 192.0.2.10:9100\r\n"),
            "Host header must be preserved: {data:?}"
        );
    }

    #[tokio::test]
    async fn http_plain_strips_hop_by_hop_and_closes() {
        let raw = b"GET http://example.com/ HTTP/1.1\r\n                    Host: example.com\r\n                    Proxy-Connection: Keep-Alive\r\n                    Proxy-Authorization: Basic c2VjcmV0\r\n                    Keep-Alive: timeout=5\r\n                    Connection: keep-alive\r\n                    Accept: */*\r\n\r\n";
        let (_target, data) = handshake_plain(raw).await;

        for leaked in [
            "Proxy-Connection",
            "Proxy-Authorization",
            "Keep-Alive",
            "keep-alive",
        ] {
            assert!(
                !data.contains(leaked),
                "hop-by-hop header {leaked:?} leaked to origin: {data:?}"
            );
        }
        // End-to-end headers survive.
        assert!(data.contains("Host: example.com\r\n"), "{data:?}");
        assert!(data.contains("Accept: */*\r\n"), "{data:?}");
        // The connection must not be left open for a second, unrouted request.
        assert!(data.contains("Connection: close\r\n"), "{data:?}");
    }

    #[tokio::test]
    async fn http_plain_preserves_upgrade_handshake() {
        let raw = b"GET http://example.com/ws HTTP/1.1\r\n                    Host: example.com\r\n                    Connection: Upgrade\r\n                    Upgrade: websocket\r\n\r\n";
        let (_target, data) = handshake_plain(raw).await;

        assert!(data.starts_with("GET /ws HTTP/1.1\r\n"), "{data:?}");
        assert!(data.contains("Connection: Upgrade\r\n"), "{data:?}");
        assert!(data.contains("Upgrade: websocket\r\n"), "{data:?}");
        assert!(
            !data.contains("Connection: close"),
            "an upgrade must not be forced closed: {data:?}"
        );
    }

    #[tokio::test]
    async fn http_plain_strips_connection_nominated_headers() {
        // RFC 9112 §7.6.1: a header named by a `Connection` token is hop-by-hop
        // for this connection only and must not reach the origin.
        let raw = b"GET http://example.com/ HTTP/1.1\r\n\
                    Host: example.com\r\n\
                    Connection: X-Internal, close\r\n\
                    X-Internal: should-not-reach-origin\r\n\
                    X-Public: keep-me\r\n\r\n";
        let (_target, data) = handshake_plain(raw).await;

        assert!(
            !data.contains("X-Internal"),
            "header nominated by Connection leaked to origin: {data:?}"
        );
        assert!(data.contains("X-Public: keep-me\r\n"), "{data:?}");
        assert!(data.contains("Connection: close\r\n"), "{data:?}");
    }

    #[tokio::test]
    async fn http_plain_routes_uppercase_scheme_by_uri_authority() {
        // URI schemes are case-insensitive; the absolute-form authority must
        // still win over a conflicting Host header.
        let raw = b"GET HTTP://192.0.2.10:9100/health HTTP/1.1\r\n\
                    Host: 198.51.100.7:8080\r\n\r\n";
        let (target, data) = handshake_plain(raw).await;

        match target {
            TargetAddr::Ip(ip, port) => {
                assert_eq!(ip, "192.0.2.10".parse::<IpAddr>().unwrap());
                assert_eq!(port, 9100);
            }
            other => panic!("expected the URI authority, got {other:?}"),
        }

        assert!(data.starts_with("GET /health HTTP/1.1\r\n"), "{data:?}");
    }

    #[test]
    fn split_absolute_form_conversions() {
        // Absolute-form yields both halves from one split.
        assert_eq!(
            split_absolute_form("http://example.com/a/b?q=1"),
            Some(("example.com", "/a/b?q=1"))
        );
        assert_eq!(
            split_absolute_form("https://example.com:8443/x"),
            Some(("example.com:8443", "/x"))
        );
        // Case-insensitive scheme.
        assert_eq!(
            split_absolute_form("HTTP://example.com:9100/a"),
            Some(("example.com:9100", "/a"))
        );
        // No path component at all.
        assert_eq!(
            split_absolute_form("http://example.com"),
            Some(("example.com", "/"))
        );
        // Origin-form has no authority, and a `://` in the query must not be
        // mistaken for a scheme separator.
        assert_eq!(split_absolute_form("/health"), None);
        assert_eq!(
            split_absolute_form("/redirect?to=http://evil.example/x"),
            None
        );
        // Asterisk-form, for server-wide OPTIONS.
        assert_eq!(split_absolute_form("*"), None);
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
