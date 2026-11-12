//! Portable system-proxy management for clashx-rs.
//!
//! [`SysProxy`] installs and removes the system HTTP/HTTPS/SOCKS proxy settings
//! that point at the local mixed inbound listener.
//!
//! # Snapshot and restore semantics
//!
//! On macOS the pre-existing settings of every active network service are
//! recorded in a JSON snapshot before the first change. [`SysProxy::disable`]
//! restores that snapshot, but only when this port owns it and the service
//! still points at this instance's listener; settings installed by someone else
//! are left untouched. [`SysProxy::turn_off`] is the explicit `sysproxy off`
//! request: it disables the proxies outright and drops the snapshot instead of
//! restoring it.
//!
//! # Platform behavior
//!
//! - **macOS** drives `networksetup` and persists both the snapshot and the
//!   system settings.
//! - **Linux** prints the corresponding shell `export` (enable) or `unset`
//!   (disable) lines on stdout. That is the documented contract: the caller
//!   evaluates or sources the output, and this crate never modifies the
//!   process environment or any persistent state.
//! - **Other platforms** return `Ok(())` without doing anything, logging a
//!   warning for enable.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unchecked_time_subtraction
    )
)]

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

use anyhow::Result;
use std::path::PathBuf;

/// Default bypass entries applied when no explicit `skip-proxy` list is set.
///
/// The CIDR subset is exposed separately because callers that analyze IP rules
/// only need the subnet entries (the host entries cannot swallow an IP-CIDR
/// rule).
pub const DEFAULT_BYPASS: &[&str] = &[
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "127.0.0.1",
    "localhost",
    "*.local",
];

/// The CIDR entries of [`DEFAULT_BYPASS`], in configuration order.
pub const DEFAULT_BYPASS_CIDRS: &[&str] = &["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"];

/// Facade over the platform system-proxy implementation.
#[derive(Debug)]
pub struct SysProxy {
    port: u16,
    /// Where the pre-enable settings are recorded so `disable` can restore
    /// them. Only macOS mutates persistent state, so only macOS reads it.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    snapshot_path: PathBuf,
}

impl SysProxy {
    /// Create a facade for the local proxy `port`, storing the macOS snapshot
    /// at `snapshot_path`.
    ///
    /// Linux never reads `snapshot_path`; it only prints environment lines.
    #[must_use]
    pub fn new(port: u16, snapshot_path: PathBuf) -> Self {
        SysProxy {
            port,
            snapshot_path,
        }
    }

    /// Install the system proxy with `bypass` as the bypass list.
    ///
    /// `bypass` entries are host names, domains, or CIDR ranges. An empty list
    /// means the platform default: macOS applies [`DEFAULT_BYPASS`], while
    /// Linux logs a warning that bypass lists are unsupported and prints the
    /// usual `export` lines.
    ///
    /// # Errors
    ///
    /// On macOS returns an error when the active services cannot be listed or
    /// when applying the proxy or bypass settings fails for any service.
    /// Linux only prints `export` lines and cannot fail; other platforms return
    /// `Ok(())`.
    pub fn enable_with_bypass(&self, bypass: &[String]) -> Result<()> {
        #[cfg(target_os = "macos")]
        return macos::enable(self.port, bypass, &self.snapshot_path);
        #[cfg(target_os = "linux")]
        {
            if !bypass.is_empty() {
                tracing::warn!("proxy bypass list is not yet supported on Linux");
            }
            linux::enable(self.port);
            Ok(())
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = bypass;
            tracing::warn!("system proxy not supported on this platform");
            Ok(())
        }
    }

    /// Undo the settings installed by [`Self::enable_with_bypass`].
    ///
    /// macOS restores the recorded snapshot. It does nothing when no snapshot
    /// exists, when the snapshot belongs to another port, or when a service no
    /// longer points at this instance's port — those settings belong to another
    /// owner. The snapshot is removed after a complete restore; a partial one
    /// keeps it and reports the stranded services so a retry can use it.
    ///
    /// Linux prints `unset` lines on stdout, the documented counterpart to
    /// [`Self::enable_with_bypass`]'s `export` lines, and changes no persistent state.
    ///
    /// # Errors
    ///
    /// On macOS returns an error when restoring any service fails or when a
    /// service's proxy state cannot be read; the message names the services
    /// that were not restored and the snapshot is kept. Linux cannot fail;
    /// other platforms return `Ok(())`.
    pub fn disable(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        return macos::disable(self.port, &self.snapshot_path);
        #[cfg(target_os = "linux")]
        return {
            linux::disable();
            Ok(())
        };
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        Ok(())
    }

    /// Switch the system proxy off outright, whoever set it — the explicit
    /// `sysproxy off` request, as opposed to [`Self::disable`]'s cleanup.
    ///
    /// This does not restore previous settings: on macOS every active
    /// service's web, secure web, and SOCKS proxies are turned off, and once
    /// that succeeds any snapshot is dropped. Linux prints the same `unset`
    /// lines as [`Self::disable`].
    ///
    /// # Errors
    ///
    /// On macOS returns an error when the active services cannot be listed or
    /// when disabling a service's proxies fails. Linux cannot fail; other
    /// platforms return `Ok(())`.
    pub fn turn_off(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        return macos::turn_off(&self.snapshot_path);
        #[cfg(target_os = "linux")]
        return {
            linux::disable();
            Ok(())
        };
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        Ok(())
    }

    /// Report the current system proxy configuration as human-readable text.
    ///
    /// macOS prints the web-proxy block first for compatibility, then the
    /// secure-web and SOCKS blocks for each active service. Linux compares
    /// `http_proxy`, `https_proxy`, and `all_proxy` (upper- or lower-case)
    /// against the values [`Self::enable_with_bypass`] would print for this port.
    ///
    /// # Errors
    ///
    /// On macOS returns an error when the active services cannot be listed or
    /// a service's proxy status cannot be read. Linux always succeeds; other
    /// platforms return a fixed "unsupported platform" string.
    pub fn status(&self) -> Result<String> {
        #[cfg(target_os = "macos")]
        return macos::status();
        #[cfg(target_os = "linux")]
        return Ok(linux::status(self.port));
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        Ok("unsupported platform".to_string())
    }
}
