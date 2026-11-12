//! Outbound connectors and the stream type they return.
//!
//! Each connector takes the [`crate::inbound::TargetAddr`] parsed from the
//! inbound handshake and dials the destination. A matched REJECT rule is
//! handled by the daemon before a connector runs:
//!
//! - [`direct`] connects straight to the target.
//! - [`socks5`] tunnels through a SOCKS5 proxy, optionally with RFC 1929
//!   username/password authentication.
//! - [`trojan`] tunnels through a Trojan server over TLS.
//!
//! `dial_server` is the shared TCP dial for proxy servers. It prefers a
//! pre-resolved IP so the daemon's proxy resolver, not the system resolver,
//! decides how a proxy hostname is resolved.

pub mod direct;
pub mod socks5;
pub mod trojan;

use std::net::{IpAddr, SocketAddr};

use tokio::net::TcpStream;

/// A connected outbound stream ready for data relay.
#[derive(Debug)]
pub enum OutboundStream {
    /// A plain TCP stream to the destination (DIRECT) or to a SOCKS5 proxy
    /// that has already accepted the CONNECT request.
    Tcp(TcpStream),
    /// A TLS stream to a Trojan server; the Trojan request header has already
    /// been written, so the next bytes belong to the tunneled connection.
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

/// Dial a proxy server over TCP: connect to the pre-resolved IP when one is
/// provided, otherwise let the system resolver handle the hostname.
///
/// `TCP_NODELAY` is enabled because proxy handshakes are small latency-sensitive
/// writes, and TCP keepalive is applied as a best-effort backstop (failure is
/// logged at debug level and does not fail the dial). The caller owns the
/// returned stream.
pub(crate) async fn dial_server(
    server: &str,
    port: u16,
    resolved_ip: Option<IpAddr>,
) -> std::io::Result<TcpStream> {
    let stream = match resolved_ip {
        Some(ip) => TcpStream::connect(SocketAddr::new(ip, port)).await?,
        None => TcpStream::connect((server, port)).await?,
    };
    crate::socket::configure_tcp(&stream, server);
    Ok(stream)
}
