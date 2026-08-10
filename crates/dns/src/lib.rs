//! mihomo-compatible DNS resolution for clashx-rs.
//!
//! - `Resolver` (via [`build_resolvers`]) is the daemon-facing entry point:
//!   hosts mappings, upstream race (UDP/DoH/DoT), negative caching,
//!   singleflight, and fail-open system fallback.
//! - `Bootstrap` resolves DoH/DoT server hostnames exclusively through the
//!   plain-UDP `default-nameserver` list (never the main group).
//! - `wire`/`upstream`/`cache` are the building blocks.
//!
//! Only A records are queried; `dns.ipv6` currently behaves as `false`
//! (see docs/dns-resolver-design.md).

mod bootstrap;
mod cache;
mod resolver;
mod upstream;
mod wire;

use std::net::{IpAddr, ToSocketAddrs};

use anyhow::Result;
use tokio::task;

pub use resolver::{build_resolvers, Resolver};

/// TTL used when caching results from the system resolver — getaddrinfo
/// doesn't expose a real TTL, so pick a conservative middle value: long
/// enough to avoid hammering it, short enough to react to DNS changes.
/// Clamped in `DnsCache::put` anyway.
pub(crate) const SYSTEM_RESOLVE_TTL_SECS: u32 = 300;

/// Log a warning once per process — degraded-feature notices emitted from
/// `build_resolvers`, which may run repeatedly (config reload).
macro_rules! warn_once {
    ($($arg:tt)*) => {{
        static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
            tracing::warn!($($arg)*);
        }
    }};
}
pub(crate) use warn_once;

/// Resolve a hostname via the system resolver (getaddrinfo), A records only.
///
/// `dns.ipv6` is effectively `false` in this build: results that are
/// exclusively IPv6 are treated as resolution failure (callers negative-cache
/// the outcome).
pub async fn system_resolve(host: &str) -> Result<IpAddr> {
    let host = host.to_string();
    task::spawn_blocking(move || -> Result<IpAddr> {
        format!("{host}:0")
            .to_socket_addrs()?
            .map(|a| a.ip())
            .find(IpAddr::is_ipv4)
            .ok_or_else(|| anyhow::anyhow!("failed to resolve {host}"))
    })
    .await?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn system_resolve_localhost() {
        let ip = system_resolve("localhost").await.unwrap();
        assert!(ip.is_loopback());
    }
}
