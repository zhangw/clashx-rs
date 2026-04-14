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
pub async fn connect(target: &TargetAddr, resolved_ip: Option<IpAddr>) -> Result<OutboundStream> {
    let stream = match (resolved_ip, target) {
        // Prefer the caller-provided resolved IP (from DNS pre-resolve)
        (Some(ip), _) => {
            let addr = SocketAddr::new(ip, target.port());
            tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
                .await
                .context("direct connect timed out")??
        }
        (None, TargetAddr::Ip(ip, port)) => {
            let addr = SocketAddr::new(*ip, *port);
            tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
                .await
                .context("direct connect timed out")??
        }
        // Fallback: domain target without pre-resolved IP → system resolver
        (None, TargetAddr::Domain(host, port)) => {
            tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host.as_str(), *port)))
                .await
                .context("direct connect timed out")??
        }
    };
    Ok(OutboundStream::Tcp(stream))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn direct_connect_with_ip_target() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let target = TargetAddr::Ip(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            addr.port(),
        );
        let result = connect(&target, None).await.unwrap();
        assert!(matches!(result, OutboundStream::Tcp(_)));
    }

    #[tokio::test]
    async fn direct_connect_with_resolved_ip_skips_getaddrinfo() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        // Target is a bogus domain that would fail getaddrinfo — proves we used resolved_ip
        let target = TargetAddr::Domain(
            "this.domain.does.not.exist.invalid".to_string(),
            addr.port(),
        );
        let result = connect(
            &target,
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
        )
        .await
        .unwrap();
        assert!(matches!(result, OutboundStream::Tcp(_)));
    }
}
