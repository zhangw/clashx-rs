use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::{self, MissedTickBehavior};

/// Upper bound on a graceful half-close (`shutdown`) so a peer that never
/// drains its receive window cannot pin the relay task forever.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
/// Deadline checks are cheap and only read atomics; 5s is precise enough for
/// minute-scale timeouts while keeping the per-connection wake rate low.
const MAX_TICK: Duration = Duration::from_secs(5);
const MIN_TICK: Duration = Duration::from_millis(50);

/// Lifetime policy for one relayed connection.
///
/// All timeouts are *inactivity* based: every byte read from either side
/// refreshes the clock. There is deliberately no total-duration cap, because
/// LLM completions and other long-lived streams may legitimately run for
/// minutes or hours.
#[derive(Debug, Clone, Copy)]
pub struct RelayPolicy {
    /// Close when neither direction has carried a byte for this long.
    pub idle: Duration,
    /// Once one direction reaches EOF, close when the remaining direction has
    /// carried no byte for this long. Long enough for slow first tokens, short
    /// enough to reclaim cancelled streams.
    pub half_close_idle: Duration,
    /// After this long, ask the caller whether the connection should be
    /// promoted to the long-lived profile. `None` disables promotion.
    pub promote_after: Option<Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayEnd {
    /// Both directions reached EOF.
    Completed,
    /// No bytes in either direction within `idle`.
    Idle,
    /// One direction reached EOF and the other went idle within
    /// `half_close_idle`.
    HalfClosed,
}

#[derive(Debug)]
pub struct RelayStats {
    pub a_to_b: u64,
    pub b_to_a: u64,
    pub end: RelayEnd,
    /// The promotion callback was invoked. The resource-pool upgrade may
    /// still have been denied; use the connection class for the actual state.
    pub promoted: bool,
}

/// Callback used to promote a connection after it has proven long-lived.
pub trait RelayPromotion {
    /// Called at most once. Returning `Some(timeout)` switches the relay to
    /// the streaming half-close timeout; the caller may also upgrade its
    /// resource pool here.
    fn promote(&mut self) -> Option<Duration>;
}

/// No-op promotion for callers that do not need lifetime classification.
pub struct NoPromotion;

impl RelayPromotion for NoPromotion {
    fn promote(&mut self) -> Option<Duration> {
        None
    }
}

struct Activity {
    start: Instant,
    last_ms: AtomicU64,
}

impl Activity {
    fn new() -> Arc<Self> {
        let activity = Arc::new(Self {
            start: Instant::now(),
            last_ms: AtomicU64::new(0),
        });
        activity.touch();
        activity
    }

    fn touch(&self) {
        self.last_ms
            .store(self.start.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    fn last(&self) -> Duration {
        Duration::from_millis(self.last_ms.load(Ordering::Relaxed))
    }

    fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
}

/// AsyncRead wrapper that refreshes the activity clock on every non-empty read.
struct ActivityReader<R> {
    inner: R,
    activity: Arc<Activity>,
    bytes: Arc<AtomicU64>,
}

impl<R: AsyncRead + Unpin> AsyncRead for ActivityReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let read = buf.filled().len().saturating_sub(before);
                if read > 0 {
                    this.activity.touch();
                    this.bytes.fetch_add(read as u64, Ordering::Relaxed);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

fn tick_interval(policy: &RelayPolicy) -> Duration {
    let mut tick = MAX_TICK;
    for duration in [policy.idle, policy.half_close_idle] {
        if !duration.is_zero() {
            tick = tick.min(duration / 4);
        }
    }
    // Promotion is checked on the regular tick. 5s of precision is well
    // below the 60s general half-close floor, and tying the tick to a
    // near-term promotion age would leave late-starting relays on a
    // millisecond ticker for their whole life.
    tick.max(MIN_TICK)
}

/// Bidirectional copy with activity-based idle and half-close reclamation.
///
/// Unlike [`tokio::io::copy_bidirectional`], this returns when the *remaining*
/// direction has been idle for `half_close_idle` instead of waiting for a peer
/// that may never send FIN. Every successful read refreshes both deadlines;
/// actively streaming connections are never cut by a timer.
pub async fn relay_with_policy<A, B, P>(
    a: A,
    b: B,
    policy: RelayPolicy,
    promotion: &mut P,
) -> Result<RelayStats>
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
    B: AsyncRead + AsyncWrite + Unpin + Send,
    P: RelayPromotion + Send,
{
    let activity = Activity::new();
    let (mut a_reader, mut a_writer) = tokio::io::split(a);
    let (mut b_reader, mut b_writer) = tokio::io::split(b);

    let mut half_close_idle = policy.half_close_idle;
    let promote_at = policy.promote_after.map(|after| activity.start + after);
    let mut ticker = time::interval(tick_interval(&policy));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let mut a_to_b_done = false;
    let mut b_to_a_done = false;
    // Incremented on every read, so the counters are meaningful even when a
    // connection is reaped before either copy future completes.
    let a_to_b_count = Arc::new(AtomicU64::new(0));
    let b_to_a_count = Arc::new(AtomicU64::new(0));
    let mut promoted = false;

    // Both futures borrow their own halves; replacing a finished future with
    // `pending` releases the borrow so the writer can be shut down.
    let mut a_to_b: Pin<Box<dyn Future<Output = io::Result<u64>> + Send + '_>> = Box::pin(async {
        let mut reader = ActivityReader {
            inner: &mut a_reader,
            activity: activity.clone(),
            bytes: a_to_b_count.clone(),
        };
        tokio::io::copy(&mut reader, &mut b_writer).await
    });
    let mut b_to_a: Pin<Box<dyn Future<Output = io::Result<u64>> + Send + '_>> = Box::pin(async {
        let mut reader = ActivityReader {
            inner: &mut b_reader,
            activity: activity.clone(),
            bytes: b_to_a_count.clone(),
        };
        tokio::io::copy(&mut reader, &mut a_writer).await
    });

    loop {
        tokio::select! {
            result = &mut a_to_b, if !a_to_b_done => {
                a_to_b_done = true;
                a_to_b = Box::pin(std::future::pending());
                match result {
                    Ok(_) => {
                        // The remaining direction starts its half-close clock
                        // now, not at the last data byte.
                        activity.touch();
                        let _ = time::timeout(SHUTDOWN_TIMEOUT, b_writer.shutdown()).await;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            result = &mut b_to_a, if !b_to_a_done => {
                b_to_a_done = true;
                b_to_a = Box::pin(std::future::pending());
                match result {
                    Ok(_) => {
                        activity.touch();
                        let _ = time::timeout(SHUTDOWN_TIMEOUT, a_writer.shutdown()).await;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            _ = ticker.tick() => {
                if !promoted {
                    if let Some(at) = promote_at {
                        if Instant::now() >= at {
                            promoted = true;
                            if let Some(next) = promotion.promote() {
                                half_close_idle = next;
                            }
                        }
                    }
                }

                let idle_for = activity.elapsed().saturating_sub(activity.last());
                if !policy.idle.is_zero() && idle_for >= policy.idle {
                    return Ok(RelayStats {
                        a_to_b: a_to_b_count.load(Ordering::Relaxed),
                        b_to_a: b_to_a_count.load(Ordering::Relaxed),
                        end: RelayEnd::Idle,
                        promoted,
                    });
                }
                if (a_to_b_done || b_to_a_done)
                    && !half_close_idle.is_zero()
                    && idle_for >= half_close_idle
                {
                    return Ok(RelayStats {
                        a_to_b: a_to_b_count.load(Ordering::Relaxed),
                        b_to_a: b_to_a_count.load(Ordering::Relaxed),
                        end: RelayEnd::HalfClosed,
                        promoted,
                    });
                }
            }
        }

        if a_to_b_done && b_to_a_done {
            return Ok(RelayStats {
                a_to_b: a_to_b_count.load(Ordering::Relaxed),
                b_to_a: b_to_a_count.load(Ordering::Relaxed),
                end: RelayEnd::Completed,
                promoted,
            });
        }
    }
}

/// Bidirectional copy with no lifetime limits.
///
/// Kept for callers that only need byte forwarding; daemon traffic uses
/// [`relay_with_policy`].
pub async fn relay<A, B>(a: A, b: B) -> Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
    B: AsyncRead + AsyncWrite + Unpin + Send,
{
    let policy = RelayPolicy {
        idle: Duration::ZERO,
        half_close_idle: Duration::ZERO,
        promote_after: None,
    };
    let stats = relay_with_policy(a, b, policy, &mut NoPromotion).await?;
    Ok((stats.a_to_b, stats.b_to_a))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    fn policy(half_close: Duration) -> RelayPolicy {
        RelayPolicy {
            idle: Duration::from_secs(30),
            half_close_idle: half_close,
            promote_after: None,
        }
    }

    #[tokio::test]
    async fn relay_echoes_data() {
        let (client, relay_a) = duplex(1024);
        let (relay_b, server) = duplex(1024);

        let relay_handle = tokio::spawn(async move {
            let mut promotion = NoPromotion;
            relay_with_policy(
                relay_a,
                relay_b,
                policy(Duration::from_secs(5)),
                &mut promotion,
            )
            .await
        });

        let (mut client_read, mut client_write) = tokio::io::split(client);
        let (mut server_read, mut server_write) = tokio::io::split(server);

        client_write.write_all(b"hello").await.unwrap();
        client_write.shutdown().await.unwrap();

        let mut buf = Vec::new();
        server_read.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"hello");

        server_write.write_all(b"world").await.unwrap();
        server_write.shutdown().await.unwrap();

        let mut buf2 = Vec::new();
        client_read.read_to_end(&mut buf2).await.unwrap();
        assert_eq!(buf2, b"world");

        let stats = relay_handle.await.unwrap().unwrap();
        assert_eq!(stats.end, RelayEnd::Completed);
    }

    #[tokio::test]
    async fn half_close_reaps_silent_peer() {
        let (mut client, relay_a) = duplex(1024);
        let (relay_b, mut server) = duplex(1024);

        let handle = tokio::spawn(async move {
            let mut promotion = NoPromotion;
            relay_with_policy(
                relay_a,
                relay_b,
                policy(Duration::from_millis(150)),
                &mut promotion,
            )
            .await
        });

        client.write_all(b"hello").await.unwrap();
        client.shutdown().await.unwrap();

        let mut buf = [0u8; 5];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        let stats = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("half-close timeout must fire")
            .unwrap()
            .unwrap();
        assert_eq!(stats.end, RelayEnd::HalfClosed);
        assert_eq!(stats.a_to_b, 5);
    }

    #[tokio::test]
    async fn idle_reaps_silent_connection() {
        let (_client, relay_a) = duplex(1024);
        let (relay_b, _server) = duplex(1024);

        let handle = tokio::spawn(async move {
            let mut promotion = NoPromotion;
            relay_with_policy(
                relay_a,
                relay_b,
                RelayPolicy {
                    idle: Duration::from_millis(150),
                    half_close_idle: Duration::from_secs(10),
                    promote_after: None,
                },
                &mut promotion,
            )
            .await
        });

        let stats = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("idle timeout must fire")
            .unwrap()
            .unwrap();
        assert_eq!(stats.end, RelayEnd::Idle);
    }

    #[tokio::test]
    async fn activity_extends_half_close() {
        let (mut client, relay_a) = duplex(1024);
        let (relay_b, mut server) = duplex(1024);

        let handle = tokio::spawn(async move {
            let mut promotion = NoPromotion;
            relay_with_policy(
                relay_a,
                relay_b,
                policy(Duration::from_millis(150)),
                &mut promotion,
            )
            .await
        });

        client.write_all(b"x").await.unwrap();
        client.shutdown().await.unwrap();
        let mut buf = [0u8; 1];
        server.read_exact(&mut buf).await.unwrap();

        // The client has half-closed. Tokens keep arriving every 50ms, which
        // must keep resetting the 150ms half-close clock.
        let writer = tokio::spawn(async move {
            for _ in 0..6 {
                tokio::time::sleep(Duration::from_millis(50)).await;
                server.write_all(b"t").await.unwrap();
            }
            server.shutdown().await.unwrap();
        });

        let stats = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("active stream must not be reaped")
            .unwrap()
            .unwrap();
        writer.await.unwrap();
        assert_eq!(stats.end, RelayEnd::Completed);
        assert_eq!(stats.b_to_a, 6);
    }

    struct TestPromotion {
        calls: Arc<AtomicUsize>,
        next: Duration,
    }

    impl RelayPromotion for TestPromotion {
        fn promote(&mut self) -> Option<Duration> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Some(self.next)
        }
    }

    #[tokio::test]
    async fn promotion_with_zero_age_happens_on_first_tick() {
        let (mut client, relay_a) = duplex(1024);
        let (relay_b, mut server) = duplex(1024);
        let calls = Arc::new(AtomicUsize::new(0));

        let promotion = TestPromotion {
            calls: calls.clone(),
            next: Duration::from_secs(10),
        };
        let handle = tokio::spawn(async move {
            let mut promotion = promotion;
            relay_with_policy(
                relay_a,
                relay_b,
                RelayPolicy {
                    idle: Duration::from_secs(30),
                    half_close_idle: Duration::from_millis(150),
                    promote_after: Some(Duration::ZERO),
                },
                &mut promotion,
            )
            .await
        });

        client.write_all(b"x").await.unwrap();
        client.shutdown().await.unwrap();
        let mut buf = [0u8; 1];
        server.read_exact(&mut buf).await.unwrap();

        // Without promotion the 150ms half-close would fire; a zero-age
        // promotion must extend it immediately.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !handle.is_finished(),
            "zero-age promotion must extend half-close"
        );

        server.shutdown().await.unwrap();
        let stats = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(stats.promoted);
        assert_eq!(stats.end, RelayEnd::Completed);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn promotion_extends_half_close_once() {
        let (mut client, relay_a) = duplex(1024);
        let (relay_b, mut server) = duplex(1024);
        let calls = Arc::new(AtomicUsize::new(0));

        let promotion = TestPromotion {
            calls: calls.clone(),
            next: Duration::from_secs(10),
        };
        let handle = tokio::spawn(async move {
            let mut promotion = promotion;
            relay_with_policy(
                relay_a,
                relay_b,
                RelayPolicy {
                    idle: Duration::from_secs(30),
                    half_close_idle: Duration::from_millis(150),
                    promote_after: Some(Duration::from_millis(50)),
                },
                &mut promotion,
            )
            .await
        });

        client.write_all(b"x").await.unwrap();
        client.shutdown().await.unwrap();
        let mut buf = [0u8; 1];
        server.read_exact(&mut buf).await.unwrap();

        // Without promotion the half-close clock would fire at ~150ms.
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(!handle.is_finished(), "promotion must extend half-close");

        server.shutdown().await.unwrap();
        let stats = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(stats.promoted);
        assert_eq!(stats.end, RelayEnd::Completed);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }
}
