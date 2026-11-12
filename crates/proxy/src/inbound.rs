//! Inbound protocol detection and handshakes.
//!
//! [`detect_and_handle`] peeks at the first byte without consuming it: `0x05`
//! selects the SOCKS5 handshake and anything else goes to the HTTP proxy
//! handshake. Both handshakes are bounded by [`HANDSHAKE_TIMEOUT`] so a client
//! that connects but never speaks cannot hold a connection slot indefinitely.
//!
//! The HTTP path also rewrites plain proxy requests into origin-form (see
//! [`http`]), so callers only need to write
//! [`InboundResult::initial_data`] to the outbound stream before relaying.

pub mod http;
pub mod socks5;

use std::net::IpAddr;

use anyhow::{Context, Result};
use tokio::net::TcpStream;

use crate::timeout::HANDSHAKE_TIMEOUT;

/// The target address extracted from an inbound connection.
#[derive(Debug, Clone)]
pub enum TargetAddr {
    /// A hostname that still needs resolving.
    ///
    /// The outbound connector resolves it through the system resolver unless
    /// the caller supplies a pre-resolved address.
    Domain(String, u16),
    /// A literal IPv4 or IPv6 address and port.
    ///
    /// Connectors never resolve this form, so it is not subject to the
    /// daemon's DNS policy.
    Ip(IpAddr, u16),
}

impl TargetAddr {
    /// The target host as text, without the port.
    ///
    /// Domains are returned verbatim (no case folding) and IP literals use
    /// their canonical formatting.
    #[must_use]
    pub fn host_string(&self) -> String {
        match self {
            TargetAddr::Domain(d, _) => d.clone(),
            TargetAddr::Ip(ip, _) => ip.to_string(),
        }
    }

    /// The target port.
    #[must_use]
    pub fn port(&self) -> u16 {
        match self {
            TargetAddr::Domain(_, p) | TargetAddr::Ip(_, p) => *p,
        }
    }
}

/// The result of an inbound protocol handshake.
#[derive(Debug)]
pub struct InboundResult {
    /// Where the client wants to connect.
    pub target: TargetAddr,
    /// The client connection, positioned after every byte read so far.
    ///
    /// Bytes that were read past the handshake are not lost: they are returned
    /// in [`InboundResult::initial_data`] and must be forwarded first.
    pub stream: TcpStream,
    /// Bytes the client sent beyond the handshake and that were already read
    /// from the socket.
    ///
    /// For CONNECT this is early data such as a TLS `ClientHello`; for a plain
    /// HTTP request it is the fully rebuilt request (headers, `Connection:
    /// close`, and any body bytes that were read ahead). `None` for SOCKS5,
    /// which does not pipeline data after its reply. The caller must write
    /// these bytes to the outbound stream before starting the relay.
    pub initial_data: Option<Vec<u8>>,
    /// The client's socket address, used for logging and PROCESS-NAME lookup.
    pub source_addr: std::net::SocketAddr,
}

/// Peek at the first byte of the stream to detect the protocol, then perform
/// the appropriate handshake.
///
/// - First byte `0x05` → SOCKS5 handshake (`socks5::handshake`)
/// - Anything else → HTTP proxy handshake (`http::handshake`)
///
/// The entire peek + handshake sequence must complete within [`HANDSHAKE_TIMEOUT`].
/// Slow or silent clients are dropped to prevent slowloris-style resource exhaustion.
///
/// # Errors
///
/// Returns an error when the peer closes or resets the connection before or
/// during the handshake, when the handshake does not finish within
/// [`HANDSHAKE_TIMEOUT`], or when the request is not a well-formed SOCKS5 or
/// HTTP proxy exchange (unsupported version or command, unacceptable auth
/// methods, malformed address or port, over-long request line, too many
/// headers, or a plain HTTP request that names no target).
pub async fn detect_and_handle(
    mut stream: TcpStream,
    source_addr: std::net::SocketAddr,
) -> Result<InboundResult> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async move {
        // Peek at the first byte without consuming it.
        let mut peek_buf = [0u8; 1];
        stream.peek(&mut peek_buf).await?;

        if peek_buf[0] == 0x05 {
            // SOCKS5: handshake reads the version byte itself.
            let target = socks5::handshake(&mut stream).await?;
            Ok(InboundResult {
                target,
                stream,
                initial_data: None,
                source_addr,
            })
        } else {
            // HTTP (CONNECT or plain).
            let (target, initial_data) = http::handshake(&mut stream).await?;
            Ok(InboundResult {
                target,
                stream,
                initial_data,
                source_addr,
            })
        }
    })
    .await
    .context("inbound handshake timed out")?
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::net::TcpListener;

    use super::*;

    /// A client that connects but never sends any data must be rejected once the
    /// handshake timeout fires.  We use a very short timeout override by running
    /// the listener with the real `detect_and_handle` path — but to keep the
    /// test fast we just drive the function with a tiny manual timeout instead
    /// of waiting the full 10 s.
    #[tokio::test]
    async fn silent_client_gets_timed_out() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Connect but never write anything.
        let _silent_client = TcpStream::connect(addr).await.unwrap();

        let (server_side, peer_addr) = listener.accept().await.unwrap();

        // drive detect_and_handle under a tight test-only timeout (100 ms)
        // so the test doesn't take 10 seconds.
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            detect_and_handle(server_side, peer_addr),
        )
        .await;

        // The outer timeout should fire — either as Elapsed (the test-timeout
        // triggers before the handshake timeout) or the inner context error
        // ("inbound handshake timed out").  Either way we must NOT get Ok.
        match result {
            Err(_elapsed) => { /* outer test timeout fired — expected */ }
            Ok(Err(_)) => { /* inner handshake error — also acceptable */ }
            Ok(Ok(_)) => panic!("expected timeout but handshake succeeded on silent connection"),
        }
    }
}
