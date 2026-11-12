//! Runtime filesystem paths and defaults.
//!
//! Keeps the config, PID, control socket, log, and `GeoIP` locations in one
//! place so the daemon, CLI, and `LaunchAgent` agree on the same files.

use std::path::PathBuf;

pub const DEFAULT_MIXED_PORT: u16 = 7890;
/// Daily runtime log files kept before the oldest is removed.
pub const LOG_RETENTION_FILES: usize = 7;

/// User's home directory, falling back to the literal `~` when the platform
/// cannot resolve one.
#[must_use]
pub fn home_dir() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("~"))
}

pub fn runtime_dir() -> PathBuf {
    home_dir().join(".config/clashx-rs")
}

/// Runtime log directory. On macOS this matches the `LaunchAgent`'s existing
/// log directory; other platforms keep logs beside the runtime state.
pub fn log_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        home_dir().join("Library/Logs/clashx-rs")
    }
    #[cfg(not(target_os = "macos"))]
    {
        runtime_dir().join("logs")
    }
}

pub fn socket_path(port: u16) -> PathBuf {
    runtime_dir().join(format!("clashx-rs-{port}.sock"))
}

pub fn pid_path(port: u16) -> PathBuf {
    runtime_dir().join(format!("clashx-rs-{port}.pid"))
}

/// Previous system proxy settings, recorded when the proxy is enabled so it
/// can be restored on shutdown. Not port-scoped: the system proxy is global.
pub fn sysproxy_snapshot_path() -> PathBuf {
    runtime_dir().join("sysproxy-snapshot.json")
}

pub fn default_mmdb_path() -> PathBuf {
    runtime_dir().join("Country.mmdb")
}
