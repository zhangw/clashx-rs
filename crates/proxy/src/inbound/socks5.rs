use anyhow::{bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::TargetAddr;

const SOCKS5_VERSION: u8 = 0x05;
const NO_AUTH: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REP_SUCCESS: u8 = 0x00;

/// Perform a SOCKS5 handshake on the given stream and return the target address.
pub async fn handshake<S>(stream: &mut S) -> Result<TargetAddr>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // --- Greeting ---
    let version = stream.read_u8().await?;
    if version != SOCKS5_VERSION {
        bail!("unsupported SOCKS version: {version}");
    }

    let nmethods = stream.read_u8().await?;
    let mut methods = vec![0u8; nmethods as usize];
    stream.read_exact(&mut methods).await?;

    if !methods.contains(&NO_AUTH) {
        // Send "no acceptable methods"
        stream.write_all(&[SOCKS5_VERSION, 0xFF]).await?;
        bail!("no acceptable auth methods offered by client");
    }

    // Select NO_AUTH
    stream.write_all(&[SOCKS5_VERSION, NO_AUTH]).await?;

    // --- Request ---
    let ver = stream.read_u8().await?;
    if ver != SOCKS5_VERSION {
        bail!("expected SOCKS5 version in request, got {ver}");
    }

    let cmd = stream.read_u8().await?;
    if cmd != CMD_CONNECT {
        bail!("unsupported SOCKS5 command: {cmd}");
    }

    let _rsv = stream.read_u8().await?; // reserved

    let atyp = stream.read_u8().await?;

    let target = match atyp {
        ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            let port = stream.read_u16().await?;
            let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::from(addr));
            TargetAddr::Ip(ip, port)
        }
        ATYP_DOMAIN => {
            let len = stream.read_u8().await? as usize;
            let mut domain_bytes = vec![0u8; len];
            stream.read_exact(&mut domain_bytes).await?;
            let domain = String::from_utf8(domain_bytes)?;
            let port = stream.read_u16().await?;
            TargetAddr::Domain(domain, port)
        }
        ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            let port = stream.read_u16().await?;
            let ip = std::net::IpAddr::V6(std::net::Ipv6Addr::from(addr));
            TargetAddr::Ip(ip, port)
        }
        other => bail!("unsupported SOCKS5 ATYP: {other}"),
    };

    // --- Reply: success, bound address 0.0.0.0:0 ---
    // VER REP RSV ATYP BND.ADDR(4) BND.PORT(2)
    stream
        .write_all(&[
            SOCKS5_VERSION,
            REP_SUCCESS,
            0x00,      // RSV
            ATYP_IPV4, // bound addr type: IPv4
            0,
            0,
            0,
            0, // 0.0.0.0
            0,
            0, // port 0
        ])
        .await?;

    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::net::{TcpListener, TcpStream};

    /// Helper: connect to a listener, send raw bytes, and return the stream.
    async fn connect_with_bytes(listener_addr: &str, bytes: Vec<u8>) -> TcpStream {
        let mut stream = TcpStream::connect(listener_addr).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
        stream
    }

    #[tokio::test]
    async fn socks5_connect_domain() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let server_handle = tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            handshake(&mut conn).await.unwrap()
        });

        // Build raw SOCKS5 CONNECT for example.com:443
        let domain = b"example.com";
        let mut packet = vec![
            // Greeting
            SOCKS5_VERSION,
            1, // nmethods
            NO_AUTH,
            // Request
            SOCKS5_VERSION,
            CMD_CONNECT,
            0x00, // RSV
            ATYP_DOMAIN,
            domain.len() as u8,
        ];
        packet.extend_from_slice(domain);
        packet.extend_from_slice(&443u16.to_be_bytes());

        let mut client = connect_with_bytes(&addr, packet).await;

        // Read server greeting response + reply (discard)
        let mut buf = [0u8; 12];
        client.read_exact(&mut buf).await.unwrap();

        let target = server_handle.await.unwrap();
        match target {
            TargetAddr::Domain(host, port) => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 443);
            }
            other => panic!("expected Domain, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn socks5_connect_ipv4() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let server_handle = tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            handshake(&mut conn).await.unwrap()
        });

        // Build raw SOCKS5 CONNECT for 127.0.0.1:80
        let packet = vec![
            // Greeting
            SOCKS5_VERSION,
            1, // nmethods
            NO_AUTH,
            // Request
            SOCKS5_VERSION,
            CMD_CONNECT,
            0x00, // RSV
            ATYP_IPV4,
            127,
            0,
            0,
            1, // IPv4 address
            0,
            80, // port 80
        ];

        let mut client = connect_with_bytes(&addr, packet).await;

        // Read server greeting response + reply (discard)
        let mut buf = [0u8; 12];
        client.read_exact(&mut buf).await.unwrap();

        let target = server_handle.await.unwrap();
        match target {
            TargetAddr::Ip(ip, port) => {
                assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
                assert_eq!(port, 80);
            }
            other => panic!("expected Ip, got {other:?}"),
        }
    }
}
