use std::time::Duration;

/// Timeout for inbound protocol handshake (SOCKS5/HTTP).
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for outbound connection establishment.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

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
}
