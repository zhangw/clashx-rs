use std::path::PathBuf;

pub const DEFAULT_MIXED_PORT: u16 = 7890;

pub fn runtime_dir() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("~"));
    home.join(".config/clashx-rs")
}

pub fn socket_path() -> PathBuf {
    runtime_dir().join("clashx-rs.sock")
}

pub fn pid_path() -> PathBuf {
    runtime_dir().join("clashx-rs.pid")
}
