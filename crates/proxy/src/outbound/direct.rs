//! The DIRECT outbound connector.
//!
//! [`connect`] dials the target itself, preferring a caller-supplied
//! pre-resolved IP over the system resolver. Resolution policy lives in the
//! daemon and `crates/dns`; this module only opens the TCP connection and
//! applies the shared socket options.

use std::net::{IpAddr, SocketAddr};

use anyhow::{Context, Result};
use tokio::net::TcpStream;

use crate::inbound::TargetAddr;
use crate::outbound::OutboundStream;
use crate::timeout::CONNECT_TIMEOUT;

/// Establish a direct TCP connection to the target.
///
/// If `resolved_ip` is provided, connects directly to that IP — bypassing
/// the system resolver (getaddrinfo). This is critical: without it, tokio's
/// `TcpStream::connect((host, port))` invokes getaddrinfo which on systems
/// with the proxy set as system proxy can route DNS queries back through
/// clashx-rs itself, creating recursive lookups and significant latency.
///
/// `TCP_NODELAY` and keepalive use the same settings as the proxy dials. The
/// returned stream is owned by the caller.
///
/// # Errors
///
/// Returns an error when the connection is refused, unreachable, or reset, when
/// hostname resolution fails in the fallback path, or when the attempt does not
/// complete within [`CONNECT_TIMEOUT`].
pub async fn connect(target: &TargetAddr, resolved_ip: Option<IpAddr>) -> Result<OutboundStream> {
    let connect = async {
        match (resolved_ip, target) {
            (Some(ip), _) => TcpStream::connect(SocketAddr::new(ip, target.port())).await,
            (None, TargetAddr::Ip(ip, port)) => {
                TcpStream::connect(SocketAddr::new(*ip, *port)).await
            }
            // Domain target with no pre-resolve → fallback to system resolver.
            (None, TargetAddr::Domain(host, port)) => {
                TcpStream::connect((host.as_str(), *port)).await
            }
        }
    };
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, connect)
        .await
        .context("direct connect timed out")??;
    let peer = format!("{}:{}", target.host_string(), target.port());
    crate::socket::configure_tcp(&stream, &peer);
    Ok(OutboundStream::Tcp(stream))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn connect_to_ip_target() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let target = TargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port());
        let result = connect(&target, None).await.unwrap();
        assert!(matches!(result, OutboundStream::Tcp(_)));
    }

    #[tokio::test]
    async fn resolved_ip_wins_over_domain() {
        // Verifies the (Some(ip), _) arm is taken: domain is bogus and would
        // fail if system resolver were used; connection succeeds because we
        // connect to the provided SocketAddr directly.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let target = TargetAddr::Domain(
            "this.domain.does.not.exist.invalid".to_string(),
            addr.port(),
        );
        let result = connect(&target, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)))
            .await
            .unwrap();
        assert!(matches!(result, OutboundStream::Tcp(_)));
    }
}
