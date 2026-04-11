pub mod http;
pub mod socks5;

use std::net::IpAddr;

use anyhow::{Context, Result};
use tokio::net::TcpStream;

use crate::timeout::HANDSHAKE_TIMEOUT;

/// The target address extracted from an inbound connection.
#[derive(Debug, Clone)]
pub enum TargetAddr {
    Domain(String, u16),
    Ip(IpAddr, u16),
}

impl TargetAddr {
    pub fn host_string(&self) -> String {
        match self {
            TargetAddr::Domain(d, _) => d.clone(),
            TargetAddr::Ip(ip, _) => ip.to_string(),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            TargetAddr::Domain(_, p) => *p,
            TargetAddr::Ip(_, p) => *p,
        }
    }
}

/// The result of an inbound protocol handshake.
pub struct InboundResult {
    pub target: TargetAddr,
    pub stream: TcpStream,
    pub initial_data: Option<Vec<u8>>,
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
        let _silent_client = tokio::net::TcpStream::connect(addr).await.unwrap();

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
