pub mod direct;
pub mod reject;
pub mod socks5;
pub mod trojan;

use std::net::{IpAddr, SocketAddr};

use tokio::net::TcpStream;

/// A connected outbound stream ready for data relay.
pub enum OutboundStream {
    Tcp(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    Rejected,
}

/// Dial a proxy server over TCP: connect to the pre-resolved IP when one is
/// provided, otherwise let the system resolver handle the hostname.
pub(crate) async fn dial_server(
    server: &str,
    port: u16,
    resolved_ip: Option<IpAddr>,
) -> std::io::Result<TcpStream> {
    match resolved_ip {
        Some(ip) => TcpStream::connect(SocketAddr::new(ip, port)).await,
        None => TcpStream::connect((server, port)).await,
    }
}
