//! Process-wide connection budgets, independent of configuration reloads.
//!
//! Two class pools sit under one global fd budget:
//!
//! - `general`: every new connection starts here.
//! - `streaming`: connections promoted after [`crate::retry::PROMOTE_AFTER`]
//!   because they proved long-lived (LLM SSE, WebSocket, large downloads).
//!
//! The caps overlap deliberately: with a global limit of 2048 and per-class
//! caps of 1536, each class is guaranteed at least 512 permits. A class
//! cannot exceed 1536 even when the other is idle; the unused headroom is the
//! other class's guarantee.
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const TARGET: libc::rlim_t = 8192;
// Listeners, runtime, logs, four control requests (including latency probes),
// DNS, subscription downloads and ten background health probes.
const RESERVED: u64 = 128;
// Two tunnel sockets plus headroom for connection establishment.
const PER_CONNECTION: u64 = 3;
pub const CONTROL_LIMIT: usize = 4;

/// Ceiling for long-lived connections. With the global limit at 2048 this
/// leaves general traffic at least 512 permits even when the pool is full.
pub const STREAMING_LIMIT: usize = 1536;
/// Ceiling for short-lived traffic; symmetric with [`STREAMING_LIMIT`].
pub const GENERAL_LIMIT: usize = 1536;

static BUDGET: OnceLock<Budget> = OnceLock::new();

pub struct Budget {
    soft: u64,
    hard: u64,
    limit: usize,
    streaming_limit: usize,
    general_limit: usize,
    /// Global admission: every connection holds one permit here.
    pub global: Arc<Semaphore>,
    /// Long-lived class pool, acquired by promotion.
    pub streaming: Arc<Semaphore>,
    /// Short-lived class pool, acquired at accept.
    pub general: Arc<Semaphore>,
    pub controls: Arc<Semaphore>,
    overloads: AtomicU64,
    general_overloads: AtomicU64,
    promotions: AtomicU64,
    promotion_failures: AtomicU64,
    completed_count: AtomicU64,
    idle_reaped: AtomicU64,
    half_closed_reaped: AtomicU64,
    admitted: AtomicU64,
    stalled: AtomicU64,
    relay_errors: AtomicU64,
    half_closed_current: AtomicU64,
    peer_closed: AtomicU64,
    last_relay_error: std::sync::Mutex<Option<LastRelayError>>,
    relay_error_warned: std::sync::Mutex<Option<Instant>>,
    promotion_failure_warned: std::sync::Mutex<Option<Instant>>,
}

#[derive(Debug, Clone)]
struct LastRelayError {
    at: Instant,
    target: String,
    proxy: String,
    message: String,
}

fn capacity(soft: u64) -> usize {
    (soft.saturating_sub(RESERVED) / PER_CONNECTION).min(2048) as usize
}

#[expect(
    unsafe_code,
    reason = "libc getrlimit/setrlimit calls with inline SAFETY notes"
)]
pub fn initialize() -> anyhow::Result<&'static Budget> {
    if let Some(budget) = BUDGET.get() {
        return Ok(budget);
    }
    let mut limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: limits points to a valid writable rlimit structure.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limits) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let desired = TARGET.min(limits.rlim_max);
    if limits.rlim_cur < desired {
        let raised = libc::rlimit {
            rlim_cur: desired,
            rlim_max: limits.rlim_max,
        };
        // SAFETY: valid structure; only the soft limit is raised within hard limit.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const raised) } != 0 {
            tracing::warn!(error = %std::io::Error::last_os_error(), "could not raise file descriptor limit");
        }
        // Read back rather than assuming the requested limit took effect.
        // SAFETY: `limits` is a valid writable rlimit structure.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limits) } != 0 {
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
    let streaming_limit = STREAMING_LIMIT.min(limit);
    let general_limit = GENERAL_LIMIT.min(limit);
    let _ = BUDGET.set(Budget {
        soft,
        hard,
        limit,
        streaming_limit,
        general_limit,
        global: Arc::new(Semaphore::new(limit)),
        streaming: Arc::new(Semaphore::new(streaming_limit)),
        general: Arc::new(Semaphore::new(general_limit)),
        controls: Arc::new(Semaphore::new(CONTROL_LIMIT)),
        overloads: AtomicU64::new(0),
        general_overloads: AtomicU64::new(0),
        promotions: AtomicU64::new(0),
        promotion_failures: AtomicU64::new(0),
        completed_count: AtomicU64::new(0),
        idle_reaped: AtomicU64::new(0),
        half_closed_reaped: AtomicU64::new(0),
        admitted: AtomicU64::new(0),
        stalled: AtomicU64::new(0),
        relay_errors: AtomicU64::new(0),
        half_closed_current: AtomicU64::new(0),
        peer_closed: AtomicU64::new(0),
        last_relay_error: std::sync::Mutex::new(None),
        relay_error_warned: std::sync::Mutex::new(None),
        promotion_failure_warned: std::sync::Mutex::new(None),
    });
    tracing::info!(
        soft,
        hard,
        connection_limit = limit,
        streaming_limit,
        general_limit,
        reserved = RESERVED,
        "file descriptor budget"
    );
    BUDGET
        .get()
        .ok_or_else(|| anyhow::anyhow!("connection budget was not initialized"))
}

fn last_relay_error(budget: &Budget) -> serde_json::Value {
    budget
        .last_relay_error
        .lock()
        .ok()
        .and_then(|last| {
            last.as_ref().map(|error| {
                serde_json::json!({
                    "age_secs": error.at.elapsed().as_secs(),
                    "target": error.target,
                    "proxy": error.proxy,
                    "message": error.message,
                })
            })
        })
        .unwrap_or(serde_json::Value::Null)
}

pub fn status() -> serde_json::Value {
    BUDGET.get().map_or(serde_json::Value::Null, |b| {
        serde_json::json!({
            "fd_soft_limit": b.soft, "fd_hard_limit": b.hard,
            "connection_limit": b.limit,
            "active_connections": b.limit.saturating_sub(b.global.available_permits()),
            "streaming_limit": b.streaming_limit,
            "active_streaming": b.streaming_limit.saturating_sub(b.streaming.available_permits()),
            "general_limit": b.general_limit,
            "active_general": b.general_limit.saturating_sub(b.general.available_permits()),
            "active_control_connections": CONTROL_LIMIT - b.controls.available_permits(),
            "overload_count": b.overloads.load(Ordering::Relaxed),
            "general_overload_count": b.general_overloads.load(Ordering::Relaxed),
            "promotion_count": b.promotions.load(Ordering::Relaxed),
            "promotion_failure_count": b.promotion_failures.load(Ordering::Relaxed),
            "completed_count": b.completed_count.load(Ordering::Relaxed),
            "idle_reaped_count": b.idle_reaped.load(Ordering::Relaxed),
            "half_closed_reaped_count": b.half_closed_reaped.load(Ordering::Relaxed),
            "admitted_count": b.admitted.load(Ordering::Relaxed),
            "stalled_count": b.stalled.load(Ordering::Relaxed),
            "relay_error_count": b.relay_errors.load(Ordering::Relaxed),
            "peer_closed_count": b.peer_closed.load(Ordering::Relaxed),
            "current_half_closed": b.half_closed_current.load(Ordering::Relaxed),
            "last_relay_error": last_relay_error(b),
        })
    })
}

/// Point-in-time pool occupancy, included in pressure/saturation warnings so
/// an operator can tell which class is full without polling status.
#[derive(Debug, Default, Clone, Copy)]
pub struct Occupancy {
    pub global_limit: usize,
    pub global_active: usize,
    pub general_limit: usize,
    pub general_active: usize,
    pub streaming_limit: usize,
    pub streaming_active: usize,
}

fn occupancy_from(budget: &Budget) -> Occupancy {
    Occupancy {
        global_limit: budget.limit,
        global_active: budget
            .limit
            .saturating_sub(budget.global.available_permits()),
        general_limit: budget.general_limit,
        general_active: budget
            .general_limit
            .saturating_sub(budget.general.available_permits()),
        streaming_limit: budget.streaming_limit,
        streaming_active: budget
            .streaming_limit
            .saturating_sub(budget.streaming.available_permits()),
    }
}

pub fn occupancy() -> Occupancy {
    BUDGET.get().map(occupancy_from).unwrap_or_default()
}

/// Cumulative counters for the hourly heartbeat and external polling.
#[derive(Debug, Default, Clone, Copy)]
pub struct Counters {
    pub admitted: u64,
    pub completed: u64,
    pub idle_reaped: u64,
    pub half_closed_reaped: u64,
    pub relay_errors: u64,
    pub peer_closed: u64,
    pub stalled: u64,
    pub overloads: u64,
    pub general_overloads: u64,
    pub promotions: u64,
    pub promotion_failures: u64,
}

impl Counters {
    pub fn since(&self, previous: &Counters) -> Counters {
        Counters {
            admitted: self.admitted.saturating_sub(previous.admitted),
            completed: self.completed.saturating_sub(previous.completed),
            idle_reaped: self.idle_reaped.saturating_sub(previous.idle_reaped),
            half_closed_reaped: self
                .half_closed_reaped
                .saturating_sub(previous.half_closed_reaped),
            relay_errors: self.relay_errors.saturating_sub(previous.relay_errors),
            peer_closed: self.peer_closed.saturating_sub(previous.peer_closed),
            stalled: self.stalled.saturating_sub(previous.stalled),
            overloads: self.overloads.saturating_sub(previous.overloads),
            general_overloads: self
                .general_overloads
                .saturating_sub(previous.general_overloads),
            promotions: self.promotions.saturating_sub(previous.promotions),
            promotion_failures: self
                .promotion_failures
                .saturating_sub(previous.promotion_failures),
        }
    }
}

pub fn counters() -> Counters {
    BUDGET
        .get()
        .map(|b| Counters {
            admitted: b.admitted.load(Ordering::Relaxed),
            completed: b.completed_count.load(Ordering::Relaxed),
            idle_reaped: b.idle_reaped.load(Ordering::Relaxed),
            half_closed_reaped: b.half_closed_reaped.load(Ordering::Relaxed),
            relay_errors: b.relay_errors.load(Ordering::Relaxed),
            peer_closed: b.peer_closed.load(Ordering::Relaxed),
            stalled: b.stalled.load(Ordering::Relaxed),
            overloads: b.overloads.load(Ordering::Relaxed),
            general_overloads: b.general_overloads.load(Ordering::Relaxed),
            promotions: b.promotions.load(Ordering::Relaxed),
            promotion_failures: b.promotion_failures.load(Ordering::Relaxed),
        })
        .unwrap_or_default()
}

pub fn record_stalled() {
    if let Some(budget) = BUDGET.get() {
        budget.stalled.fetch_add(1, Ordering::Relaxed);
    }
}

/// Record a genuine relay error (not a peer reset/abort, which the relay
/// classifies as `RelayEnd::PeerClosed`). Keeps the most recent error for
/// remote diagnosis via `status` and emits a throttled warning.
pub fn record_relay_error(error: &anyhow::Error, target: &str, proxy: &str) {
    let Some(budget) = BUDGET.get() else {
        return;
    };
    budget.relay_errors.fetch_add(1, Ordering::Relaxed);
    let message = format!("{error:#}");
    if let Ok(mut last) = budget.last_relay_error.lock() {
        *last = Some(LastRelayError {
            at: Instant::now(),
            target: target.to_string(),
            proxy: proxy.to_string(),
            message: message.clone(),
        });
    }

    let now = Instant::now();
    let mut warned = budget
        .relay_error_warned
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if warned.is_none_or(|previous| now.duration_since(previous) >= Duration::from_secs(60)) {
        tracing::warn!(target, proxy, error = %message, "relay error");
        *warned = Some(now);
    }
}

/// Count how a relay ended, so `status.resources` shows the reclamation
/// policy working rather than only the admission counters.
pub fn record_relay_end(end: clashx_rs_proxy::relay::RelayEnd) {
    let Some(budget) = BUDGET.get() else {
        return;
    };
    match end {
        clashx_rs_proxy::relay::RelayEnd::Completed => {
            budget.completed_count.fetch_add(1, Ordering::Relaxed);
        }
        clashx_rs_proxy::relay::RelayEnd::Idle => {
            budget.idle_reaped.fetch_add(1, Ordering::Relaxed);
        }
        clashx_rs_proxy::relay::RelayEnd::HalfClosed => {
            budget.half_closed_reaped.fetch_add(1, Ordering::Relaxed);
        }
        clashx_rs_proxy::relay::RelayEnd::PeerClosed => {
            budget.peer_closed.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionClass {
    General,
    Streaming,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquireError {
    /// Global connection limit is exhausted.
    Global,
    /// The general class pool is exhausted (the global pool had room).
    General,
}

/// Admission permit set for one connection.
///
/// Starts in the general pool and may be promoted to the streaming pool once
/// the connection proves long-lived. Dropping it releases every permit it
/// still holds.
pub struct ConnectionSlot {
    budget: &'static Budget,
    _global: OwnedSemaphorePermit,
    class_permit: Option<OwnedSemaphorePermit>,
    class: ConnectionClass,
}

impl ConnectionSlot {
    /// Acquire a global permit plus a general-class permit.
    pub fn try_acquire() -> Result<Self, AcquireError> {
        let budget = BUDGET.get().ok_or(AcquireError::Global)?;
        Self::try_acquire_from(budget)
    }

    fn try_acquire_from(budget: &'static Budget) -> Result<Self, AcquireError> {
        let global = budget
            .global
            .clone()
            .try_acquire_owned()
            .map_err(|_| AcquireError::Global)?;
        let class_permit = budget
            .general
            .clone()
            .try_acquire_owned()
            .map_err(|_| AcquireError::General)?;
        budget.admitted.fetch_add(1, Ordering::Relaxed);
        Ok(Self {
            budget,
            _global: global,
            class_permit: Some(class_permit),
            class: ConnectionClass::General,
        })
    }

    /// Promote to the streaming pool and return the streaming half-close
    /// timeout.
    ///
    /// The timeout change is applied even when the streaming pool is full:
    /// the connection has already proved it is long-lived, so cutting it at
    /// the general 60s half-close would be wrong. The failed pool upgrade is
    /// counted so saturation is visible.
    pub fn try_promote(&mut self) -> Duration {
        if self.class == ConnectionClass::General {
            if let Ok(permit) = self.budget.streaming.clone().try_acquire_owned() {
                self.class_permit = Some(permit);
                self.class = ConnectionClass::Streaming;
                self.budget.promotions.fetch_add(1, Ordering::Relaxed);
            } else {
                self.budget
                    .promotion_failures
                    .fetch_add(1, Ordering::Relaxed);
                warn_promotion_saturated(self.budget);
            }
        }
        crate::retry::HALF_CLOSE_STREAMING
    }

    pub fn class(&self) -> ConnectionClass {
        self.class
    }
}

/// Warn at most once per 10 minutes when a long-lived connection cannot enter
/// the streaming pool. The counter carries the exact rate; the log explains
/// the consequence (squatting in general) before admission starts failing.
fn warn_promotion_saturated(budget: &Budget) {
    let now = Instant::now();
    let mut last = budget
        .promotion_failure_warned
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if last.is_none_or(|previous| now.duration_since(previous) >= Duration::from_secs(600)) {
        let occupancy = occupancy_from(budget);
        tracing::warn!(
            global_active = occupancy.global_active,
            global_limit = occupancy.global_limit,
            general_active = occupancy.general_active,
            general_limit = occupancy.general_limit,
            streaming_active = occupancy.streaming_active,
            streaming_limit = occupancy.streaming_limit,
            "streaming pool saturated; long-lived connections stay in the general class"
        );
        *last = Some(now);
    }
}

impl clashx_rs_proxy::relay::RelayPromotion for ConnectionSlot {
    fn promote(&mut self) -> Option<Duration> {
        Some(self.try_promote())
    }

    fn on_half_closed(&mut self, half_closed: bool) {
        if half_closed {
            self.budget
                .half_closed_current
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.budget
                .half_closed_current
                .fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// A separate limiter per listener; every occurrence is still counted.
///
/// Global and general-class pressure have independent throttle keys so a
/// global warning cannot hide a class transition within the same 5s window.
#[derive(Default)]
pub struct OverloadLog {
    accept: Option<Instant>,
    global: Option<Instant>,
    general: Option<Instant>,
}

impl OverloadLog {
    fn throttled(slot: &mut Option<Instant>, log: impl FnOnce()) {
        let now = Instant::now();
        if slot.is_none_or(|last| now.duration_since(last) >= Duration::from_secs(5)) {
            log();
            *slot = Some(now);
        }
    }

    fn warn_pressure(reason: &str) {
        let occupancy = occupancy();
        tracing::warn!(
            reason,
            global_active = occupancy.global_active,
            global_limit = occupancy.global_limit,
            general_active = occupancy.general_active,
            general_limit = occupancy.general_limit,
            streaming_active = occupancy.streaming_active,
            streaming_limit = occupancy.streaming_limit,
            "proxy resource pressure"
        );
    }

    pub fn record(&mut self, reason: &str) {
        if let Some(b) = BUDGET.get() {
            b.overloads.fetch_add(1, Ordering::Relaxed);
        }
        Self::throttled(&mut self.accept, || Self::warn_pressure(reason));
    }

    /// Global admission failed: no connection permit at all.
    pub fn record_global(&mut self, reason: &str) {
        if let Some(b) = BUDGET.get() {
            b.overloads.fetch_add(1, Ordering::Relaxed);
        }
        Self::throttled(&mut self.global, || Self::warn_pressure(reason));
    }

    /// General class pool is full while the global pool still has room.
    pub fn record_general(&mut self, reason: &str) {
        if let Some(b) = BUDGET.get() {
            b.general_overloads.fetch_add(1, Ordering::Relaxed);
            b.overloads.fetch_add(1, Ordering::Relaxed);
        }
        Self::throttled(&mut self.general, || Self::warn_pressure(reason));
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
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unchecked_time_subtraction,
        unsafe_code
    )]

    use super::*;

    fn test_budget(global: usize, streaming: usize, general: usize) -> &'static Budget {
        Box::leak(Box::new(Budget {
            soft: 0,
            hard: 0,
            limit: global,
            streaming_limit: streaming,
            general_limit: general,
            global: Arc::new(Semaphore::new(global)),
            streaming: Arc::new(Semaphore::new(streaming)),
            general: Arc::new(Semaphore::new(general)),
            controls: Arc::new(Semaphore::new(CONTROL_LIMIT)),
            overloads: AtomicU64::new(0),
            general_overloads: AtomicU64::new(0),
            promotions: AtomicU64::new(0),
            promotion_failures: AtomicU64::new(0),
            completed_count: AtomicU64::new(0),
            idle_reaped: AtomicU64::new(0),
            half_closed_reaped: AtomicU64::new(0),
            admitted: AtomicU64::new(0),
            stalled: AtomicU64::new(0),
            relay_errors: AtomicU64::new(0),
            half_closed_current: AtomicU64::new(0),
            peer_closed: AtomicU64::new(0),
            last_relay_error: std::sync::Mutex::new(None),
            relay_error_warned: std::sync::Mutex::new(None),
            promotion_failure_warned: std::sync::Mutex::new(None),
        }))
    }

    #[test]
    fn budgets_leave_headroom() {
        assert_eq!(capacity(256), 42);
        assert_eq!(capacity(8192), 2048);
        assert_eq!(capacity(128), 0);
        assert_eq!(capacity(u64::MAX), 2048);
    }

    #[test]
    fn class_caps_leave_a_floor() {
        // 2048 - 1536 = 512 permits are always available to each class while
        // the other is at its ceiling.
        assert_eq!(2048 - STREAMING_LIMIT, 512);
        assert_eq!(2048 - GENERAL_LIMIT, 512);
        const { assert!(STREAMING_LIMIT + GENERAL_LIMIT > 2048) };
    }

    #[test]
    fn promotion_swaps_pool_and_keeps_floor() {
        let budget = test_budget(3, 1, 2);
        let mut first = ConnectionSlot::try_acquire_from(budget).unwrap();
        let mut second = ConnectionSlot::try_acquire_from(budget).unwrap();
        assert!(matches!(
            ConnectionSlot::try_acquire_from(budget),
            Err(AcquireError::General)
        ));

        assert_eq!(first.class(), ConnectionClass::General);
        assert_eq!(first.try_promote(), crate::retry::HALF_CLOSE_STREAMING);
        assert_eq!(first.class(), ConnectionClass::Streaming);

        // Streaming is full; the connection keeps its general permit but still
        // gets the long half-close timeout.
        assert_eq!(second.try_promote(), crate::retry::HALF_CLOSE_STREAMING);
        assert_eq!(second.class(), ConnectionClass::General);
        assert_eq!(budget.promotion_failures.load(Ordering::Relaxed), 1);

        drop(first);
        drop(second);
        assert_eq!(budget.global.available_permits(), 3);
        assert_eq!(budget.streaming.available_permits(), 1);
        assert_eq!(budget.general.available_permits(), 2);
    }

    #[test]
    fn half_closed_gauge_is_balanced() {
        use clashx_rs_proxy::relay::RelayPromotion;

        let budget = test_budget(4, 2, 4);
        let mut slot = ConnectionSlot::try_acquire_from(budget).unwrap();
        slot.on_half_closed(true);
        assert_eq!(budget.half_closed_current.load(Ordering::Relaxed), 1);
        slot.on_half_closed(false);
        assert_eq!(budget.half_closed_current.load(Ordering::Relaxed), 0);
    }

    #[test]
    #[allow(unsafe_code)] // test child lowers its own RLIMIT_NOFILE
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
        let rc = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const limits) };
        assert_eq!(rc, 0);
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
