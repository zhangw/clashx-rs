use anyhow::{Context, Result};
use tokio::net::TcpStream;

use crate::inbound::TargetAddr;
use crate::outbound::OutboundStream;
use crate::timeout::CONNECT_TIMEOUT;

/// Establish a direct TCP connection to the target address.
///
/// The connect attempt must complete within [`CONNECT_TIMEOUT`].
pub async fn connect(target: &TargetAddr) -> Result<OutboundStream> {
    let stream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((target.host_string().as_str(), target.port())),
    )
    .await
    .context("direct connect timed out")??;
    Ok(OutboundStream::Tcp(stream))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn direct_connect_succeeds() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Accept in background so the connect doesn't hang.
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let target = TargetAddr::Ip(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            addr.port(),
        );

        let result = connect(&target).await.unwrap();
        assert!(matches!(result, OutboundStream::Tcp(_)));
    }
}
