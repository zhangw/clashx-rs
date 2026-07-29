use std::time::Duration;

/// Timeout for inbound protocol handshake (SOCKS5/HTTP).
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for outbound connection establishment (DIRECT).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for outbound connection establishment through a proxy node
/// (Trojan/SOCKS5). Shorter than [`CONNECT_TIMEOUT`] so a dead node fails
/// fast and failover can move on; a healthy node handshakes in well under 1s.
pub const PROXY_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_timeout_is_reasonable() {
        assert!(HANDSHAKE_TIMEOUT.as_secs() >= 5);
        assert!(HANDSHAKE_TIMEOUT.as_secs() <= 30);
    }

    #[test]
    fn connect_timeout_is_reasonable() {
        assert!(CONNECT_TIMEOUT.as_secs() >= 5);
        assert!(CONNECT_TIMEOUT.as_secs() <= 30);
    }

    #[test]
    fn proxy_connect_timeout_is_reasonable() {
        assert!(PROXY_CONNECT_TIMEOUT.as_secs() >= 3);
        assert!(PROXY_CONNECT_TIMEOUT <= CONNECT_TIMEOUT);
    }
}
