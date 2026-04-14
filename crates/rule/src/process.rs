use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::sync::Notify;

/// TTL for the port → process_name table snapshot.
/// Short-lived because a port can be reused by a different process after close.
const SNAPSHOT_TTL: Duration = Duration::from_secs(2);

struct Snapshot {
    port_to_name: HashMap<u16, String>,
    expires: Instant,
}

static SNAPSHOT: Mutex<Option<Snapshot>> = Mutex::new(None);

/// Set when a rebuild is in flight; concurrent misses wait on this instead
/// of each spawning their own scan.
static REBUILD_NOTIFY: once_cell::sync::Lazy<Notify> = once_cell::sync::Lazy::new(Notify::new);
static REBUILDING: Mutex<bool> = Mutex::new(false);

/// Look up the process name that owns the TCP connection from `source_addr`.
///
/// Uses a 2-second port→process table snapshot. Cache hits are O(1) sync
/// HashMap lookups. Cache misses trigger a full system scan which is offloaded
/// to a blocking thread so the async runtime is not stalled. Concurrent
/// misses coalesce — only one scan runs at a time.
pub async fn lookup_process_name(source_addr: SocketAddr) -> Option<String> {
    if let Some(hit) = fast_path_lookup(&source_addr) {
        return hit;
    }

    // Coalesce concurrent rebuilds: only one task scans, others wait.
    let should_rebuild = {
        let mut flag = REBUILDING.lock().ok()?;
        if *flag {
            false
        } else {
            *flag = true;
            true
        }
    };

    if should_rebuild {
        let fresh = tokio::task::spawn_blocking(build_snapshot).await.ok();
        if let Ok(mut guard) = SNAPSHOT.lock() {
            *guard = fresh;
        }
        if let Ok(mut flag) = REBUILDING.lock() {
            *flag = false;
        }
        REBUILD_NOTIFY.notify_waiters();
    } else {
        REBUILD_NOTIFY.notified().await;
    }

    fast_path_lookup(&source_addr).flatten()
}

fn fast_path_lookup(source_addr: &SocketAddr) -> Option<Option<String>> {
    let port = source_addr.port();
    let guard = SNAPSHOT.lock().ok()?;
    let snap = guard.as_ref()?;
    if Instant::now() >= snap.expires {
        return None;
    }
    Some(snap.port_to_name.get(&port).cloned())
}

fn build_snapshot() -> Snapshot {
    Snapshot {
        port_to_name: scan_all_tcp_sockets(),
        expires: Instant::now() + SNAPSHOT_TTL,
    }
}

#[cfg(target_os = "macos")]
fn scan_all_tcp_sockets() -> HashMap<u16, String> {
    use libproc::bsd_info::BSDInfo;
    use libproc::file_info::{pidfdinfo, ListFDs, ProcFDType};
    use libproc::net_info::{SocketFDInfo, SocketInfoKind};
    use libproc::proc_pid::{listpidinfo, name, pidinfo};
    use libproc::processes::{pids_by_type, ProcFilter};

    let mut map: HashMap<u16, String> = HashMap::new();
    let pids = match pids_by_type(ProcFilter::All) {
        Ok(p) => p,
        Err(_) => return map,
    };

    for pid in pids {
        let pid = pid as i32;
        let info: BSDInfo = match pidinfo(pid, 0) {
            Ok(i) => i,
            Err(_) => continue,
        };
        let fds = match listpidinfo::<ListFDs>(pid, info.pbi_nfiles as usize) {
            Ok(f) => f,
            Err(_) => continue,
        };

        let mut proc_name: Option<String> = None;

        for fd in fds {
            if !matches!(ProcFDType::from(fd.proc_fdtype), ProcFDType::Socket) {
                continue;
            }
            let sock: SocketFDInfo = match pidfdinfo(pid, fd.proc_fd) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let kind = SocketInfoKind::from(sock.psi.soi_kind);
            let local_port = match kind {
                SocketInfoKind::Tcp => unsafe { sock.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport },
                SocketInfoKind::In => unsafe { sock.psi.soi_proto.pri_in.insi_lport },
                _ => continue,
            };
            // insi_lport is in network byte order stored as i32.
            let port = u16::from_be(local_port as u16);
            if port == 0 {
                continue;
            }

            if proc_name.is_none() {
                proc_name = name(pid).ok();
            }
            if let Some(ref n) = proc_name {
                map.entry(port).or_insert_with(|| n.clone());
            }
        }
    }

    map
}

#[cfg(target_os = "linux")]
fn scan_all_tcp_sockets() -> HashMap<u16, String> {
    let mut map: HashMap<u16, String> = HashMap::new();

    // Parse both /proc/net/tcp and /proc/net/tcp6 to build inode → port map
    let mut inode_to_port: HashMap<String, u16> = HashMap::new();
    for file in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let content = match std::fs::read_to_string(file) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }
            let local = fields[1];
            let inode = fields[9];
            if inode == "0" {
                continue;
            }
            // local = "HEXADDR:HEXPORT"
            let port_hex = match local.rsplit_once(':') {
                Some((_, p)) => p,
                None => continue,
            };
            if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                inode_to_port.insert(inode.to_string(), port);
            }
        }
    }

    if inode_to_port.is_empty() {
        return map;
    }

    // Scan /proc/*/fd/ to match inodes to PIDs
    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return map,
    };

    for entry in proc_dir.flatten() {
        let pid_name = entry.file_name();
        let pid_str = match pid_name.to_str() {
            Some(s) if s.chars().all(|c| c.is_ascii_digit()) => s,
            _ => continue,
        };
        let fd_dir = format!("/proc/{pid_str}/fd");
        let fds = match std::fs::read_dir(&fd_dir) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let mut proc_name: Option<String> = None;
        for fd_entry in fds.flatten() {
            let link = match std::fs::read_link(fd_entry.path()) {
                Ok(l) => l,
                Err(_) => continue,
            };
            let link_str = link.to_string_lossy();
            let inode = match link_str
                .strip_prefix("socket:[")
                .and_then(|s| s.strip_suffix(']'))
            {
                Some(i) => i,
                None => continue,
            };
            if let Some(&port) = inode_to_port.get(inode) {
                if proc_name.is_none() {
                    let comm_path = format!("/proc/{pid_str}/comm");
                    proc_name = std::fs::read_to_string(comm_path)
                        .ok()
                        .map(|s| s.trim().to_string());
                }
                if let Some(ref n) = proc_name {
                    map.entry(port).or_insert_with(|| n.clone());
                }
            }
        }
    }

    map
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn scan_all_tcp_sockets() -> HashMap<u16, String> {
    HashMap::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn lookup_returns_option() {
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let _ = lookup_process_name(addr).await;
    }

    #[tokio::test]
    async fn second_lookup_uses_cached_snapshot() {
        let addr: SocketAddr = "127.0.0.1:54321".parse().unwrap();
        let start = Instant::now();
        let _ = lookup_process_name(addr).await;
        let first_call = start.elapsed();

        let start = Instant::now();
        let _ = lookup_process_name(addr).await;
        let second_call = start.elapsed();

        assert!(
            second_call < first_call / 10 || second_call < Duration::from_micros(500),
            "cached lookup ({second_call:?}) should be much faster than first call ({first_call:?})"
        );
    }
}
