use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};

/// Bidirectional copy between two async streams.
/// Returns when either direction completes or errors.
pub async fn relay<A, B>(mut a: A, mut b: B) -> Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (a_to_b, b_to_a) = tokio::io::copy_bidirectional(&mut a, &mut b).await?;
    Ok((a_to_b, b_to_a))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn relay_echoes_data() {
        let (client, relay_a) = duplex(1024);
        let (relay_b, server) = duplex(1024);

        let relay_handle = tokio::spawn(async move { relay(relay_a, relay_b).await });

        let (mut client_read, mut client_write) = tokio::io::split(client);
        let (mut server_read, mut server_write) = tokio::io::split(server);

        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        client_write.write_all(b"hello").await.unwrap();
        client_write.shutdown().await.unwrap();

        let mut buf = Vec::new();
        server_read.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"hello");

        server_write.write_all(b"world").await.unwrap();
        server_write.shutdown().await.unwrap();

        let mut buf2 = Vec::new();
        client_read.read_to_end(&mut buf2).await.unwrap();
        assert_eq!(buf2, b"world");

        relay_handle.await.unwrap().unwrap();
    }
}
