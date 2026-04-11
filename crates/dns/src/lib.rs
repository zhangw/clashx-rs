use anyhow::Result;
use std::net::{IpAddr, ToSocketAddrs};
use tokio::task;

/// Resolve a hostname to an IP address using the system resolver.
pub async fn resolve(host: &str) -> Result<IpAddr> {
    let host = host.to_string();
    let ip = task::spawn_blocking(move || -> Result<IpAddr> {
        let addr = format!("{host}:0")
            .to_socket_addrs()?
            .find(|a| a.is_ipv4())
            .or_else(|| format!("{host}:0").to_socket_addrs().ok()?.next())
            .ok_or_else(|| anyhow::anyhow!("failed to resolve {host}"))?;
        Ok(addr.ip())
    })
    .await??;
    Ok(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolve_localhost() {
        let ip = resolve("localhost").await.unwrap();
        assert!(ip.is_loopback());
    }

    #[test]
    fn ip_passthrough() {
        let addr: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(addr.is_loopback());
    }
}
