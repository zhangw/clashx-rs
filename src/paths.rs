use std::path::PathBuf;

pub const DEFAULT_MIXED_PORT: u16 = 7890;

pub fn runtime_dir() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("~"));
    home.join(".config/clashx-rs")
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
