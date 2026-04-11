pub mod direct;
pub mod reject;
pub mod socks5;
pub mod trojan;

use tokio::net::TcpStream;

/// A connected outbound stream ready for data relay.
pub enum OutboundStream {
    Tcp(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    Rejected,
}
