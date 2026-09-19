//! Process-wide socket budget, independent of configuration reloads.
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, OnceLock,
};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

const TARGET: u64 = 8192;
// Listeners, runtime, logs, four control requests (including latency probes),
// DNS, subscription downloads and ten background health probes.
const RESERVED: u64 = 128;
// Two tunnel sockets plus headroom for connection establishment.
const PER_CONNECTION: u64 = 3;
pub const CONTROL_LIMIT: usize = 4;
static BUDGET: OnceLock<Budget> = OnceLock::new();

pub struct Budget {
    soft: u64,
    hard: u64,
    limit: usize,
    pub connections: Arc<Semaphore>,
    pub controls: Arc<Semaphore>,
    overloads: AtomicU64,
}

fn capacity(soft: u64) -> usize {
    (soft.saturating_sub(RESERVED) / PER_CONNECTION).min(2048) as usize
}

pub fn initialize() -> anyhow::Result<&'static Budget> {
    if let Some(budget) = BUDGET.get() {
        return Ok(budget);
    }
    let mut limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: limits points to a valid writable rlimit structure.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let desired = (TARGET as libc::rlim_t).min(limits.rlim_max);
    if limits.rlim_cur < desired {
        let raised = libc::rlimit {
            rlim_cur: desired,
            rlim_max: limits.rlim_max,
        };
        // SAFETY: valid structure; only the soft limit is raised within hard limit.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } != 0 {
            tracing::warn!(error = %std::io::Error::last_os_error(), "could not raise file descriptor limit");
        }
        // Read back rather than assuming the requested limit took effect.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    let soft = limits.rlim_cur;
    let hard = limits.rlim_max;
    let limit = capacity(soft);
    anyhow::ensure!(
        limit > 0,
        "file descriptor limit {soft} is too small (reserve {RESERVED})"
    );
    let _ = BUDGET.set(Budget {
        soft,
        hard,
        limit,
        connections: Arc::new(Semaphore::new(limit)),
        controls: Arc::new(Semaphore::new(CONTROL_LIMIT)),
        overloads: AtomicU64::new(0),
    });
    tracing::info!(
        soft,
        hard,
        connection_limit = limit,
        reserved = RESERVED,
        "file descriptor budget"
    );
    Ok(BUDGET.get().expect("budget initialized"))
}

pub fn status() -> serde_json::Value {
    BUDGET
        .get()
        .map(|b| {
            serde_json::json!({
                "fd_soft_limit": b.soft, "fd_hard_limit": b.hard,
                "connection_limit": b.limit,
                "active_connections": b.limit - b.connections.available_permits(),
                "active_control_connections": CONTROL_LIMIT - b.controls.available_permits(),
                "overload_count": b.overloads.load(Ordering::Relaxed),
            })
        })
        .unwrap_or(serde_json::Value::Null)
}

/// A separate limiter per listener; every occurrence is still counted.
#[derive(Default)]
pub struct OverloadLog(Option<Instant>);
impl OverloadLog {
    pub fn record(&mut self, reason: &str) {
        if let Some(b) = BUDGET.get() {
            b.overloads.fetch_add(1, Ordering::Relaxed);
        }
        let now = Instant::now();
        if self
            .0
            .is_none_or(|last| now.duration_since(last) >= Duration::from_secs(5))
        {
            tracing::warn!(reason, "proxy resource pressure");
            self.0 = Some(now);
        }
    }
    pub async fn accept_error(&mut self, error: &std::io::Error) {
        self.record(&format!("accept: {error}"));
        // Includes EMFILE/ENFILE; also prevents other persistent accept errors
        // from spinning. No established connections are closed here.
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn budgets_leave_headroom() {
        assert_eq!(capacity(256), 42);
        assert_eq!(capacity(8192), 2048);
        assert_eq!(capacity(128), 0);
        assert_eq!(capacity(u64::MAX), 2048);
    }

    #[test]
    fn exhausted_accept_recovers_in_child() {
        const CHILD: &str = "CLASHX_FD_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "resources::tests::exhausted_accept_recovers_in_child",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stdout)
            );
            return;
        }
        // Only this isolated child changes its process limits.
        let limits = libc::rlimit {
            rlim_cur: 256,
            rlim_max: 256,
        };
        // SAFETY: valid rlimit pointer, no other process is affected.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limits) }, 0);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let _client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let mut files = Vec::new();
            loop {
                match std::fs::File::open("/dev/null") {
                    Ok(file) => files.push(file),
                    Err(error) => {
                        assert_eq!(error.raw_os_error(), Some(libc::EMFILE));
                        break;
                    }
                }
            }
            let error = listener.accept().await.unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EMFILE));
            let mut log = OverloadLog::default();
            let start = Instant::now();
            log.accept_error(&error).await;
            assert!(start.elapsed() >= Duration::from_millis(250));
            drop(files);
            // Some kernels discard the queued connection on failed accept.
            // Recovery means a fresh connection can be accepted.
            let _fresh = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(2), listener.accept())
                .await
                .unwrap()
                .unwrap();
        });
    }
}
