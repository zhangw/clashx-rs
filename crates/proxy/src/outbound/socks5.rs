use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::inbound::TargetAddr;
use crate::outbound::OutboundStream;
use crate::timeout::CONNECT_TIMEOUT;

const SOCKS5_VERSION: u8 = 0x05;
const NO_AUTH: u8 = 0x00;
const USERNAME_PASSWORD_AUTH: u8 = 0x02;
const USERNAME_PASSWORD_VERSION: u8 = 0x01;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REP_SUCCESS: u8 = 0x00;

/// Connect through a SOCKS5 proxy server to the given target address.
///
/// If `username` and `password` are both `Some`, the client will offer both
/// NO_AUTH (0x00) and USERNAME/PASSWORD (0x02) methods and perform RFC 1929
/// authentication if the server selects method 0x02.
///
/// If no credentials are provided, only NO_AUTH is offered (original behaviour).
///
/// The full SOCKS5 setup (TCP connect, method negotiation, optional auth, and
/// CONNECT reply) must complete within [`CONNECT_TIMEOUT`].
pub async fn connect(
    server: &str,
    port: u16,
    target: &TargetAddr,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<OutboundStream> {
    connect_with_timeout(server, port, target, username, password, CONNECT_TIMEOUT).await
}

async fn connect_with_timeout(
    server: &str,
    port: u16,
    target: &TargetAddr,
    username: Option<&str>,
    password: Option<&str>,
    timeout: std::time::Duration,
) -> Result<OutboundStream> {
    let stream = tokio::time::timeout(timeout, async {
        let mut stream = TcpStream::connect((server, port)).await?;

        // --- Method negotiation ---
        let have_creds = username.is_some() && password.is_some();
        if have_creds {
            // Offer NO_AUTH and USERNAME/PASSWORD
            stream
                .write_all(&[SOCKS5_VERSION, 0x02, NO_AUTH, USERNAME_PASSWORD_AUTH])
                .await?;
        } else {
            // Offer only NO_AUTH
            stream.write_all(&[SOCKS5_VERSION, 0x01, NO_AUTH]).await?;
        }

        let mut method_resp = [0u8; 2];
        stream.read_exact(&mut method_resp).await?;
        if method_resp[0] != SOCKS5_VERSION {
            bail!(
                "SOCKS5 server returned unexpected version: {}",
                method_resp[0]
            );
        }

        match method_resp[1] {
            NO_AUTH => {
                // No authentication required — proceed to CONNECT request.
            }
            USERNAME_PASSWORD_AUTH => {
                // RFC 1929 sub-negotiation
                let user = username.unwrap(); // safe: have_creds guarantees Some
                let pass = password.unwrap();

                if user.len() > 255 {
                    bail!("SOCKS5 username exceeds 255 bytes");
                }
                if pass.len() > 255 {
                    bail!("SOCKS5 password exceeds 255 bytes");
                }

                let mut auth_msg: Vec<u8> = Vec::with_capacity(3 + user.len() + pass.len());
                auth_msg.push(USERNAME_PASSWORD_VERSION);
                auth_msg.push(user.len() as u8);
                auth_msg.extend_from_slice(user.as_bytes());
                auth_msg.push(pass.len() as u8);
                auth_msg.extend_from_slice(pass.as_bytes());
                stream.write_all(&auth_msg).await?;

                let mut auth_resp = [0u8; 2];
                stream.read_exact(&mut auth_resp).await?;
                if auth_resp[0] != USERNAME_PASSWORD_VERSION {
                    bail!(
                        "SOCKS5 auth response has unexpected version: {}",
                        auth_resp[0]
                    );
                }
                if auth_resp[1] != 0x00 {
                    bail!("SOCKS5 authentication failed, status={}", auth_resp[1]);
                }
            }
            other => bail!("SOCKS5 server chose unsupported auth method: {other}"),
        }

        // --- Build CONNECT request ---
        let mut req: Vec<u8> = vec![SOCKS5_VERSION, CMD_CONNECT, 0x00];
        match target {
            TargetAddr::Domain(domain, tport) => {
                let domain_bytes = domain.as_bytes();
                req.push(ATYP_DOMAIN);
                req.push(domain_bytes.len() as u8);
                req.extend_from_slice(domain_bytes);
                req.extend_from_slice(&tport.to_be_bytes());
            }
            TargetAddr::Ip(std::net::IpAddr::V4(ip), tport) => {
                req.push(ATYP_IPV4);
                req.extend_from_slice(&ip.octets());
                req.extend_from_slice(&tport.to_be_bytes());
            }
            TargetAddr::Ip(std::net::IpAddr::V6(ip), tport) => {
                req.push(ATYP_IPV6);
                req.extend_from_slice(&ip.octets());
                req.extend_from_slice(&tport.to_be_bytes());
            }
        }
        stream.write_all(&req).await?;

        // --- Read 4-byte response header: VER REP RSV ATYP ---
        let mut resp_header = [0u8; 4];
        stream.read_exact(&mut resp_header).await?;

        if resp_header[1] != REP_SUCCESS {
            bail!("SOCKS5 CONNECT failed, REP={}", resp_header[1]);
        }

        // --- Skip bound address ---
        let atyp = resp_header[3];
        match atyp {
            ATYP_IPV4 => {
                let mut buf = [0u8; 4 + 2];
                stream.read_exact(&mut buf).await?;
            }
            ATYP_DOMAIN => {
                let len = stream.read_u8().await? as usize;
                let mut buf = vec![0u8; len + 2];
                stream.read_exact(&mut buf).await?;
            }
            ATYP_IPV6 => {
                let mut buf = [0u8; 16 + 2];
                stream.read_exact(&mut buf).await?;
            }
            other => bail!("unexpected ATYP in SOCKS5 reply: {other}"),
        }

        Ok::<TcpStream, anyhow::Error>(stream)
    })
    .await
    .context("SOCKS5 connect/setup timed out")??;

    Ok(OutboundStream::Tcp(stream))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Send the standard success CONNECT reply (IPv4 0.0.0.0:0).
    async fn send_connect_success(conn: &mut tokio::net::TcpStream) {
        // Read CONNECT request header
        let _ver = conn.read_u8().await.unwrap();
        let _cmd = conn.read_u8().await.unwrap();
        let _rsv = conn.read_u8().await.unwrap();
        let atyp = conn.read_u8().await.unwrap();
        // Drain the address
        match atyp {
            ATYP_IPV4 => {
                let mut buf = [0u8; 4 + 2];
                conn.read_exact(&mut buf).await.unwrap();
            }
            ATYP_DOMAIN => {
                let len = conn.read_u8().await.unwrap() as usize;
                let mut buf = vec![0u8; len + 2];
                conn.read_exact(&mut buf).await.unwrap();
            }
            ATYP_IPV6 => {
                let mut buf = [0u8; 16 + 2];
                conn.read_exact(&mut buf).await.unwrap();
            }
            _ => {}
        }

        // Send success reply: VER=5 REP=0 RSV=0 ATYP=1 BND.ADDR=0.0.0.0 BND.PORT=0
        conn.write_all(&[
            SOCKS5_VERSION,
            REP_SUCCESS,
            0x00,
            ATYP_IPV4,
            0,
            0,
            0,
            0,
            0,
            0,
        ])
        .await
        .unwrap();
    }

    /// Minimal SOCKS5 server stub that accepts NO_AUTH and replies with success.
    async fn run_stub_server(listener: TcpListener) {
        let (mut conn, _) = listener.accept().await.unwrap();

        // Read method negotiation
        let _ver = conn.read_u8().await.unwrap();
        let nmethods = conn.read_u8().await.unwrap();
        let mut methods = vec![0u8; nmethods as usize];
        conn.read_exact(&mut methods).await.unwrap();
        // Reply with NO_AUTH
        conn.write_all(&[SOCKS5_VERSION, NO_AUTH]).await.unwrap();

        send_connect_success(&mut conn).await;
    }

    /// SOCKS5 server stub that requires USERNAME/PASSWORD auth.
    /// Expects username="user" password="pass"; rejects anything else.
    async fn run_auth_stub_server(
        listener: TcpListener,
        expected_user: &'static str,
        expected_pass: &'static str,
    ) {
        let (mut conn, _) = listener.accept().await.unwrap();

        // Read method negotiation — must include USERNAME_PASSWORD_AUTH
        let _ver = conn.read_u8().await.unwrap();
        let nmethods = conn.read_u8().await.unwrap();
        let mut methods = vec![0u8; nmethods as usize];
        conn.read_exact(&mut methods).await.unwrap();
        assert!(
            methods.contains(&USERNAME_PASSWORD_AUTH),
            "client did not offer USERNAME_PASSWORD method"
        );
        // Select USERNAME/PASSWORD
        conn.write_all(&[SOCKS5_VERSION, USERNAME_PASSWORD_AUTH])
            .await
            .unwrap();

        // Read RFC 1929 auth sub-negotiation
        let ver = conn.read_u8().await.unwrap();
        assert_eq!(ver, USERNAME_PASSWORD_VERSION);
        let ulen = conn.read_u8().await.unwrap() as usize;
        let mut user_bytes = vec![0u8; ulen];
        conn.read_exact(&mut user_bytes).await.unwrap();
        let plen = conn.read_u8().await.unwrap() as usize;
        let mut pass_bytes = vec![0u8; plen];
        conn.read_exact(&mut pass_bytes).await.unwrap();

        let user = std::str::from_utf8(&user_bytes).unwrap();
        let pass = std::str::from_utf8(&pass_bytes).unwrap();

        if user == expected_user && pass == expected_pass {
            conn.write_all(&[USERNAME_PASSWORD_VERSION, 0x00])
                .await
                .unwrap();
        } else {
            conn.write_all(&[USERNAME_PASSWORD_VERSION, 0x01])
                .await
                .unwrap();
            return; // close connection — auth failed
        }

        send_connect_success(&mut conn).await;
    }

    #[tokio::test]
    async fn socks5_connect_domain_target() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        tokio::spawn(run_stub_server(listener));

        let target = TargetAddr::Domain("example.com".to_string(), 443);
        let result = connect("127.0.0.1", server_addr.port(), &target, None, None)
            .await
            .unwrap();
        assert!(matches!(result, OutboundStream::Tcp(_)));
    }

    #[tokio::test]
    async fn socks5_connect_ipv4_target() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        tokio::spawn(run_stub_server(listener));

        let target = TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 80);
        let result = connect("127.0.0.1", server_addr.port(), &target, None, None)
            .await
            .unwrap();
        assert!(matches!(result, OutboundStream::Tcp(_)));
    }

    #[tokio::test]
    async fn socks5_connect_with_username_password_auth() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        tokio::spawn(run_auth_stub_server(listener, "user", "pass"));

        let target = TargetAddr::Domain("example.com".to_string(), 443);
        let result = connect(
            "127.0.0.1",
            server_addr.port(),
            &target,
            Some("user"),
            Some("pass"),
        )
        .await
        .unwrap();
        assert!(matches!(result, OutboundStream::Tcp(_)));
    }

    #[tokio::test]
    async fn socks5_connect_auth_wrong_password_fails() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        tokio::spawn(run_auth_stub_server(listener, "user", "correct"));

        let target = TargetAddr::Domain("example.com".to_string(), 443);
        let result = connect(
            "127.0.0.1",
            server_addr.port(),
            &target,
            Some("user"),
            Some("wrong"),
        )
        .await;
        assert!(result.is_err(), "expected auth failure but got success");
        let err = result.err().unwrap();
        let msg = err.to_string();
        assert!(
            msg.contains("authentication failed"),
            "unexpected error: {msg}"
        );
    }

    /// Server that selects NO_AUTH even though the client offered both methods.
    async fn run_no_auth_preferred_server(listener: TcpListener) {
        let (mut conn, _) = listener.accept().await.unwrap();

        let _ver = conn.read_u8().await.unwrap();
        let nmethods = conn.read_u8().await.unwrap();
        let mut methods = vec![0u8; nmethods as usize];
        conn.read_exact(&mut methods).await.unwrap();
        // Deliberately choose NO_AUTH even though client offered both
        conn.write_all(&[SOCKS5_VERSION, NO_AUTH]).await.unwrap();

        send_connect_success(&mut conn).await;
    }

    #[tokio::test]
    async fn socks5_connect_server_picks_no_auth_despite_creds() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        tokio::spawn(run_no_auth_preferred_server(listener));

        let target = TargetAddr::Domain("example.com".to_string(), 80);
        // Client provides creds but server picks NO_AUTH — should succeed
        let result = connect(
            "127.0.0.1",
            server_addr.port(),
            &target,
            Some("user"),
            Some("pass"),
        )
        .await
        .unwrap();
        assert!(matches!(result, OutboundStream::Tcp(_)));
    }

    #[tokio::test]
    async fn socks5_connect_times_out_during_setup() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (_conn, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        });

        let target = TargetAddr::Domain("example.com".to_string(), 80);
        let err = connect_with_timeout(
            "127.0.0.1",
            server_addr.port(),
            &target,
            None,
            None,
            Duration::from_millis(50),
        )
        .await
        .err()
        .expect("expected stalled SOCKS5 setup to time out");
        assert!(
            err.to_string().contains("timed out"),
            "unexpected error: {err}"
        );
    }
}
