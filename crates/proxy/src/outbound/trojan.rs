use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use sha2::{Digest, Sha224};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::inbound::TargetAddr;
use crate::outbound::OutboundStream;
use crate::timeout::CONNECT_TIMEOUT;

const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const CRLF: &[u8] = b"\r\n";

// ---------------------------------------------------------------------------
// NoCertVerifier — skips all TLS certificate validation
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct NoCertVerifier;

impl ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// TLS config builder
// ---------------------------------------------------------------------------

fn build_tls_config(skip_cert_verify: bool) -> ClientConfig {
    if skip_cert_verify {
        tracing::warn!(
            "Trojan: certificate verification is disabled (skip-cert-verify=true) — \
             connections are vulnerable to MITM; only use with trusted networks"
        );
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
            .with_no_client_auth()
    } else {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    }
}

// ---------------------------------------------------------------------------
// Cached TLS connectors (built once per verify mode, then reused)
// ---------------------------------------------------------------------------

static CONNECTOR_VERIFY: OnceLock<TlsConnector> = OnceLock::new();
static CONNECTOR_SKIP: OnceLock<TlsConnector> = OnceLock::new();

fn get_connector(skip_cert_verify: bool) -> &'static TlsConnector {
    if skip_cert_verify {
        CONNECTOR_SKIP.get_or_init(|| {
            let config = build_tls_config(true);
            TlsConnector::from(Arc::new(config))
        })
    } else {
        CONNECTOR_VERIFY.get_or_init(|| {
            let config = build_tls_config(false);
            TlsConnector::from(Arc::new(config))
        })
    }
}

// ---------------------------------------------------------------------------
// Trojan header builder
// ---------------------------------------------------------------------------

fn build_trojan_header(password: &str, target: &TargetAddr) -> Result<Vec<u8>> {
    let mut header = Vec::with_capacity(128);

    // SHA-224 of password, hex-encoded (56 ASCII bytes)
    let mut hasher = Sha224::new();
    hasher.update(password.as_bytes());
    let hash_bytes = hasher.finalize();
    header.extend_from_slice(hex::encode(hash_bytes).as_bytes());

    // CRLF
    header.extend_from_slice(CRLF);

    // CMD CONNECT
    header.push(CMD_CONNECT);

    // ATYP + address + port
    match target {
        TargetAddr::Domain(domain, port) => {
            let domain_bytes = domain.as_bytes();
            if domain_bytes.len() > 255 {
                anyhow::bail!(
                    "Trojan domain address exceeds 255 bytes: {} bytes",
                    domain_bytes.len()
                );
            }
            header.push(ATYP_DOMAIN);
            header.push(domain_bytes.len() as u8);
            header.extend_from_slice(domain_bytes);
            header.extend_from_slice(&port.to_be_bytes());
        }
        TargetAddr::Ip(IpAddr::V4(ip), port) => {
            header.push(ATYP_IPV4);
            header.extend_from_slice(&ip.octets());
            header.extend_from_slice(&port.to_be_bytes());
        }
        TargetAddr::Ip(IpAddr::V6(ip), port) => {
            header.push(ATYP_IPV6);
            header.extend_from_slice(&ip.octets());
            header.extend_from_slice(&port.to_be_bytes());
        }
    }

    // Trailing CRLF
    header.extend_from_slice(CRLF);

    Ok(header)
}

// ---------------------------------------------------------------------------
// Public connect function
// ---------------------------------------------------------------------------

/// Connect to a Trojan proxy server and return a ready-to-relay TLS stream.
///
/// Both the TCP connect and the TLS handshake must complete within [`CONNECT_TIMEOUT`].
pub async fn connect(
    server: &str,
    port: u16,
    password: &str,
    sni: Option<&str>,
    skip_cert_verify: bool,
    target: &TargetAddr,
) -> Result<OutboundStream> {
    let connector = get_connector(skip_cert_verify).clone();

    let sni_host = sni.unwrap_or(server);
    let server_name = ServerName::try_from(sni_host.to_string())?;

    // Wrap both TCP connect and TLS handshake under a single timeout budget.
    let mut tls_stream = tokio::time::timeout(CONNECT_TIMEOUT, async {
        // 1. TCP connect
        let tcp_stream = TcpStream::connect((server, port)).await?;

        // 2. TLS handshake
        let tls = connector.connect(server_name, tcp_stream).await?;
        Ok::<_, anyhow::Error>(tls)
    })
    .await
    .context("Trojan connect/TLS handshake timed out")??;

    // 3. Send Trojan header
    let header = build_trojan_header(password, target)?;
    tls_stream.write_all(&header).await?;

    Ok(OutboundStream::Tls(Box::new(tls_stream)))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use sha2::{Digest, Sha224};

    use super::*;

    /// Helper: compute expected 56-byte hex hash of the password.
    fn expected_hash_hex(password: &str) -> Vec<u8> {
        let mut hasher = Sha224::new();
        hasher.update(password.as_bytes());
        hex::encode(hasher.finalize()).into_bytes()
    }

    #[test]
    fn trojan_header_domain() {
        let password = "test-password";
        let target = TargetAddr::Domain("example.com".to_string(), 443);
        let header = build_trojan_header(password, &target).unwrap();

        let hash_hex = expected_hash_hex(password);

        // Bytes 0..56 = SHA-224 hex
        assert_eq!(&header[0..56], hash_hex.as_slice());
        // Bytes 56-57 = CRLF
        assert_eq!(&header[56..58], CRLF);
        // Byte 58 = CMD_CONNECT
        assert_eq!(header[58], CMD_CONNECT);
        // Byte 59 = ATYP_DOMAIN
        assert_eq!(header[59], ATYP_DOMAIN);
        // Byte 60 = domain length (11 for "example.com")
        assert_eq!(header[60], 11);
        // Bytes 61..72 = "example.com"
        assert_eq!(&header[61..72], b"example.com");
        // Bytes 72-73 = port 443 big-endian
        assert_eq!(&header[72..74], &443u16.to_be_bytes());
        // Bytes 74-75 = CRLF
        assert_eq!(&header[74..76], CRLF);
        assert_eq!(header.len(), 76);
    }

    #[test]
    fn trojan_header_ipv4() {
        let password = "test-password";
        let target = TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 80);
        let header = build_trojan_header(password, &target).unwrap();

        // After hash (56) + CRLF (2) + CMD (1) = byte index 59
        assert_eq!(header[59], ATYP_IPV4);
        // Bytes 60-63 = IPv4 octets
        assert_eq!(&header[60..64], &[1u8, 2, 3, 4]);
        // Bytes 64-65 = port 80 big-endian
        assert_eq!(&header[64..66], &80u16.to_be_bytes());
        // Bytes 66-67 = CRLF
        assert_eq!(&header[66..68], CRLF);
        assert_eq!(header.len(), 68);
    }

    /// Verify that `get_connector` returns the same cached instance on repeated calls.
    #[test]
    fn connector_is_cached() {
        // Ensure the process-level crypto provider is installed (no-op if already done).
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();

        // Each call must return the same static reference (pointer equality).
        let a = get_connector(false) as *const TlsConnector;
        let b = get_connector(false) as *const TlsConnector;
        assert_eq!(a, b, "normal-verify connector should be the same instance");

        let c = get_connector(true) as *const TlsConnector;
        let d = get_connector(true) as *const TlsConnector;
        assert_eq!(c, d, "skip-verify connector should be the same instance");

        // The two modes must produce distinct connectors.
        assert_ne!(a, c, "skip-verify and normal-verify connectors must differ");
    }
}
