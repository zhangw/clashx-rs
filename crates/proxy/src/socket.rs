//! Socket options shared by the inbound and outbound paths.

use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::time::Duration;

use tokio::net::TcpStream;

/// Enable TCP keepalive with a bounded idle/interval/retry profile.
///
/// This is a backstop for peers that vanish without FIN/RST (sleep/wake,
/// network change). It does not replace the relay's activity-based idle and
/// half-close timers: keepalive only detects a dead peer, not a live peer who
/// simply never closes.
///
/// Idle and interval are truncated to whole seconds with a minimum of 1, and
/// `count` is clamped to the platform's `c_int` range. On platforms other than
/// macOS and Linux only `SO_KEEPALIVE` is enabled, with the system default
/// profile; the other three arguments are ignored there.
///
/// # Errors
///
/// Returns the OS error from `setsockopt` when the option is unsupported or
/// the socket is no longer valid. Callers usually treat failure as a
/// best-effort degradation rather than a connection failure.
pub fn set_keepalive(
    stream: &TcpStream,
    idle: Duration,
    interval: Duration,
    count: u32,
) -> io::Result<()> {
    let fd = stream.as_raw_fd();
    set_opt(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1)?;

    let idle = seconds(idle);
    let interval = seconds(interval);
    let count = count.min(i32::MAX as u32) as libc::c_int;

    #[cfg(target_os = "macos")]
    {
        set_opt(fd, libc::IPPROTO_TCP, libc::TCP_KEEPALIVE, idle)?;
        set_opt(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, interval)?;
        set_opt(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT, count)?;
    }
    #[cfg(target_os = "linux")]
    {
        set_opt(fd, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, idle)?;
        set_opt(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, interval)?;
        set_opt(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT, count)?;
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (idle, interval, count);
    }

    Ok(())
}

fn seconds(duration: Duration) -> libc::c_int {
    duration.as_secs().clamp(1, i32::MAX as u64) as libc::c_int
}

fn set_opt(fd: RawFd, level: libc::c_int, name: libc::c_int, value: libc::c_int) -> io::Result<()> {
    // SAFETY: `fd` is a live socket owned by the caller and `value` points to
    // a c_int that outlives this call.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn keepalive_applies_to_loopback_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (_server, _) = listener.accept().await.unwrap();
        set_keepalive(&client, Duration::from_secs(60), Duration::from_secs(15), 3).unwrap();
    }
}
