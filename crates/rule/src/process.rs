use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

/// How long a port → process snapshot is trusted before a rebuild is triggered.
///
/// This is a deliberate stale-tolerance window: within the TTL, "port not in
/// snapshot" is treated as a definitive miss (no rebuild). Consequences:
///
/// - Connections from a target process that starts within 2s of the snapshot
///   can be routed WITHOUT matching their PROCESS-NAME rule, until the next
///   rebuild brings their port into the snapshot.
/// - Ports that have been reused by a different process can match the OLD
///   process's PROCESS-NAME rule for up to 2s.
///
/// This is the tradeoff chosen to keep per-connection cost at essentially zero
/// in the common case. PROCESS-NAME rules are best-effort — for hard routing
/// requirements, prefer DOMAIN-based, IP-CIDR, or GEOIP rules.
const SNAPSHOT_TTL: Duration = Duration::from_secs(2);

struct Snapshot {
    port_to_name: HashMap<u16, String>,
    expires: Instant,
    target_gen: u64,
}

/// Per-engine cache of port → process_name lookups. Owning this on
/// `RuleEngine` (instead of process-globals) means each test or daemon
/// instance has isolated state — no cross-test pollution.
pub struct ProcessLookup {
    snapshot: Mutex<Option<Snapshot>>,
    rebuilding: Mutex<bool>,
    rebuild_notify: Notify,
    targets: Mutex<Option<HashSet<String>>>,
    target_gen: AtomicU64,
}

impl ProcessLookup {
    pub fn new() -> Self {
        Self {
            snapshot: Mutex::new(None),
            rebuilding: Mutex::new(false),
            rebuild_notify: Notify::new(),
            targets: Mutex::new(None),
            target_gen: AtomicU64::new(0),
        }
    }

    /// Record the set of process names referenced by PROCESS-NAME rules.
    /// The scanner uses this to skip all non-matching processes' socket lists.
    pub fn set_targets<I, S>(&self, names: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let set: HashSet<String> = names.into_iter().map(Into::into).collect();
        if let Ok(mut guard) = self.targets.lock() {
            *guard = if set.is_empty() { None } else { Some(set) };
        }
        self.target_gen.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut guard) = self.snapshot.lock() {
            *guard = None;
        }
    }

    fn targets_snapshot(&self) -> Option<HashSet<String>> {
        self.targets.lock().ok().and_then(|g| g.clone())
    }

    /// Look up the process name that owns the TCP connection from `source_addr`.
    ///
    /// Uses a 2-second port→process table snapshot restricted to processes whose
    /// names appear in any PROCESS-NAME rule. Cache hits are O(1) sync HashMap
    /// lookups. Cache misses trigger a scan offloaded to a blocking thread.
    /// Concurrent misses coalesce — only one scan runs at a time.
    pub async fn lookup(self: &Arc<Self>, source_addr: SocketAddr) -> Option<String> {
        if let Some(hit) = self.fast_path_lookup(&source_addr) {
            return hit;
        }

        let should_rebuild = {
            let mut flag = self.rebuilding.lock().ok()?;
            if *flag {
                false
            } else {
                *flag = true;
                true
            }
        };

        if should_rebuild {
            // Drop guard ensures `rebuilding` is reset and waiters are
            // notified even if this future is cancelled mid-await — without
            // it, a cancelled rebuild would deadlock all other lookups
            // forever (flag stuck true, no notify fired).
            struct RebuildGuard<'a>(&'a ProcessLookup);
            impl Drop for RebuildGuard<'_> {
                fn drop(&mut self) {
                    if let Ok(mut flag) = self.0.rebuilding.lock() {
                        *flag = false;
                    }
                    self.0.rebuild_notify.notify_waiters();
                }
            }
            let _guard = RebuildGuard(self);

            let me = Arc::clone(self);
            let fresh = tokio::task::spawn_blocking(move || me.build_snapshot())
                .await
                .ok();
            if let Ok(mut guard) = self.snapshot.lock() {
                // Discard a stale-by-target_gen snapshot: if set_targets
                // bumped the generation while we were scanning, the result
                // was built with stale filter criteria.
                let current_gen = self.target_gen.load(Ordering::SeqCst);
                *guard = fresh.filter(|s| s.target_gen == current_gen);
            }
            // RebuildGuard runs here, clearing the flag and notifying.
        } else {
            self.rebuild_notify.notified().await;
        }

        self.fast_path_lookup(&source_addr).flatten()
    }

    /// Returns `Some(Some(name))` for a hit, `Some(None)` for a known miss
    /// within the snapshot, and `None` when the snapshot is stale or absent
    /// (caller should trigger a rebuild).
    fn fast_path_lookup(&self, source_addr: &SocketAddr) -> Option<Option<String>> {
        let port = source_addr.port();
        let guard = self.snapshot.lock().ok()?;
        let snap = guard.as_ref()?;
        if Instant::now() >= snap.expires {
            return None;
        }
        Some(snap.port_to_name.get(&port).cloned())
    }

    fn build_snapshot(&self) -> Snapshot {
        let target_gen = self.target_gen.load(Ordering::SeqCst);
        let targets = self.targets_snapshot();
        Snapshot {
            port_to_name: scan_tcp_sockets(targets.as_ref()),
            expires: Instant::now() + SNAPSHOT_TTL,
            target_gen,
        }
    }
}

impl Default for ProcessLookup {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "macos")]
fn scan_tcp_sockets(targets: Option<&HashSet<String>>) -> HashMap<u16, String> {
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

        // Filter by process name first — skip fd walk for non-matches.
        let proc_name = match name(pid) {
            Ok(n) => n,
            Err(_) => continue,
        };
        if let Some(targets) = targets {
            if !targets.contains(&proc_name) {
                continue;
            }
        }

        let info: BSDInfo = match pidinfo(pid, 0) {
            Ok(i) => i,
            Err(_) => continue,
        };
        let fds = match listpidinfo::<ListFDs>(pid, info.pbi_nfiles as usize) {
            Ok(f) => f,
            Err(_) => continue,
        };

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
            map.entry(port).or_insert_with(|| proc_name.clone());
        }
    }

    map
}

#[cfg(target_os = "linux")]
fn scan_tcp_sockets(targets: Option<&HashSet<String>>) -> HashMap<u16, String> {
    let mut map: HashMap<u16, String> = HashMap::new();

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

        // Read comm first so we can skip non-matching processes before the
        // expensive fd walk. Reading /proc/{pid}/comm is a single small file.
        let comm_path = format!("/proc/{pid_str}/comm");
        let proc_name = match std::fs::read_to_string(&comm_path) {
            Ok(s) => s.trim().to_string(),
            Err(_) => continue,
        };
        if let Some(targets) = targets {
            if !targets.contains(&proc_name) {
                continue;
            }
        }

        let fd_dir = format!("/proc/{pid_str}/fd");
        let fds = match std::fs::read_dir(&fd_dir) {
            Ok(d) => d,
            Err(_) => continue,
        };
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
                map.entry(port).or_insert_with(|| proc_name.clone());
            }
        }
    }

    map
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn scan_tcp_sockets(_targets: Option<&HashSet<String>>) -> HashMap<u16, String> {
    HashMap::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn lookup_returns_option() {
        let lookup = Arc::new(ProcessLookup::new());
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let _ = lookup.lookup(addr).await;
    }

    #[tokio::test]
    async fn first_lookup_populates_snapshot() {
        let lookup = Arc::new(ProcessLookup::new());
        lookup.set_targets(["nonexistent_process_xyz"]);

        {
            let guard = lookup.snapshot.lock().unwrap();
            assert!(guard.is_none(), "snapshot should start empty");
        }

        let addr: SocketAddr = "127.0.0.1:54321".parse().unwrap();
        let _ = lookup.lookup(addr).await;

        let guard = lookup.snapshot.lock().unwrap();
        let snap = guard.as_ref().expect("snapshot should be populated");
        assert!(
            Instant::now() < snap.expires,
            "fresh snapshot must not be already-expired"
        );
    }

    #[tokio::test]
    async fn second_lookup_reuses_snapshot() {
        let lookup = Arc::new(ProcessLookup::new());
        lookup.set_targets(["nonexistent_process_xyz"]);
        let addr: SocketAddr = "127.0.0.1:54322".parse().unwrap();

        let _ = lookup.lookup(addr).await;
        let first_expires = {
            let g = lookup.snapshot.lock().unwrap();
            g.as_ref().expect("snapshot populated").expires
        };

        let _ = lookup.lookup(addr).await;
        let second_expires = {
            let g = lookup.snapshot.lock().unwrap();
            g.as_ref().expect("snapshot populated").expires
        };

        assert_eq!(
            first_expires, second_expires,
            "second lookup within TTL must not rebuild the snapshot"
        );
    }
}
