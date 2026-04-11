use std::net::SocketAddr;

/// Look up the process name that owns the TCP connection from `source_addr`.
/// Returns None if the lookup fails (best-effort).
pub fn lookup_process_name(source_addr: &SocketAddr) -> Option<String> {
    #[cfg(target_os = "macos")]
    return macos_lookup(source_addr);
    #[cfg(target_os = "linux")]
    return linux_lookup(source_addr);
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = source_addr;
        None
    }
}

#[cfg(target_os = "macos")]
fn macos_lookup(source_addr: &SocketAddr) -> Option<String> {
    use std::process::Command;
    // Use lsof to find process by source port
    let port = source_addr.port();
    let output = Command::new("lsof")
        .args(["-iTCP", "-sTCP:ESTABLISHED", "-nP", &format!("-i:{port}")])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Parse lsof output: first column is process name
    for line in stdout.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() > 1 {
            return Some(parts[0].to_string());
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn linux_lookup(source_addr: &SocketAddr) -> Option<String> {
    let (proc_file, hex_addr, hex_port) = match source_addr {
        SocketAddr::V4(v4) => {
            let ip_bytes = v4.ip().octets();
            // /proc/net/tcp uses little-endian hex for IPv4
            let hex = format!(
                "{:02X}{:02X}{:02X}{:02X}",
                ip_bytes[3], ip_bytes[2], ip_bytes[1], ip_bytes[0]
            );
            let port = format!("{:04X}", v4.port());
            ("/proc/net/tcp", hex, port)
        }
        SocketAddr::V6(v6) => {
            let octets = v6.ip().octets();
            // /proc/net/tcp6 uses 32 hex chars in 4-word little-endian groups
            let hex = format!(
                "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                octets[3], octets[2], octets[1], octets[0],
                octets[7], octets[6], octets[5], octets[4],
                octets[11], octets[10], octets[9], octets[8],
                octets[15], octets[14], octets[13], octets[12],
            );
            let port = format!("{:04X}", v6.port());
            ("/proc/net/tcp6", hex, port)
        }
    };

    // Step 1: Find the inode for this source addr:port in /proc/net/tcp
    let tcp_content = std::fs::read_to_string(proc_file).ok()?;
    let local_addr_port = format!("{hex_addr}:{hex_port}");

    let mut inode: Option<String> = None;
    for line in tcp_content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 10 && fields[1] == local_addr_port {
            inode = Some(fields[9].to_string());
            break;
        }
    }
    let inode = inode?;
    if inode == "0" {
        return None;
    }

    // Step 2: Scan /proc/*/fd/ to find which PID owns this inode
    let socket_needle = format!("socket:[{inode}]");
    let proc_dir = std::fs::read_dir("/proc").ok()?;
    for entry in proc_dir.flatten() {
        let pid_str = entry.file_name();
        let pid_str = pid_str.to_str()?;
        if !pid_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
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
            if link.to_string_lossy().contains(&socket_needle) {
                let comm_path = format!("/proc/{pid_str}/comm");
                return std::fs::read_to_string(comm_path)
                    .ok()
                    .map(|s| s.trim().to_string());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_returns_option() {
        // Just verify the function doesn't panic with a random address
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let _ = lookup_process_name(&addr); // Should return None or Some, but not panic
    }
}
