use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

fn run_networksetup(args: &[&str]) -> Result<String> {
    let output = Command::new("networksetup")
        .args(args)
        .output()
        .context("failed to execute networksetup")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "networksetup command failed with status {}: {}",
            output.status,
            stderr.trim()
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn get_active_services() -> Result<Vec<String>> {
    let stdout = run_networksetup(&["-listallnetworkservices"])?;

    let services = stdout
        .lines()
        .skip(1) // skip the header line
        .filter(|line| !line.starts_with('*')) // skip disabled services
        .map(|line| line.to_string())
        .collect();

    Ok(services)
}

/// Default bypass entries applied when no explicit bypass list is provided.
const DEFAULT_BYPASS: &[&str] = &[
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "127.0.0.1",
    "localhost",
    "*.local",
];

/// `networksetup` sentinel that clears a service's bypass list.
const CLEAR_BYPASS: &str = "Empty";

/// The `-set…` / `-set…state` command pair for each kind of proxy, in the same
/// order as the fields of [`ServiceState`].
const PROXY_KINDS: [(&str, &str); 3] = [
    ("-setwebproxy", "-setwebproxystate"),
    ("-setsecurewebproxy", "-setsecurewebproxystate"),
    ("-setsocksfirewallproxy", "-setsocksfirewallproxystate"),
];

/// One proxy setting (web, secure web or SOCKS) as `networksetup` reports it.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
struct ProxyEntry {
    enabled: bool,
    server: String,
    port: String,
}

/// Everything [`enable`] overwrites for one network service, recorded so
/// [`disable`] can put the previous settings back instead of blanket-disabling
/// configuration it never created.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct ServiceState {
    service: String,
    web: ProxyEntry,
    secure: ProxyEntry,
    socks: ProxyEntry,
    bypass: Vec<String>,
}

impl ServiceState {
    /// Whether any of this service's proxies points at our own listener.
    ///
    /// This is what keeps one instance from tearing down another's settings:
    /// a proxy aimed at a different port was not installed by us.
    fn points_at(&self, port: u16) -> bool {
        let port = port.to_string();
        [&self.web, &self.secure, &self.socks]
            .iter()
            .any(|entry| entry.enabled && entry.server == "127.0.0.1" && entry.port == port)
    }
}

/// The recorded settings plus who replaced them.
///
/// Ownership is what separates "put back what we overwrote" from "switch off
/// whatever happens to be configured": a proxy pointing at our port may just as
/// easily have been set by hand, and is not ours to undo.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct Snapshot {
    /// Port the system proxy was pointed at when these settings were replaced.
    port: u16,
    /// Process that replaced them. It survives a crash, so this is a
    /// diagnostic, not a liveness check.
    pid: u32,
    services: Vec<ServiceState>,
}

/// Parse the `Enabled` / `Server` / `Port` block every `-get*proxy` query prints.
fn parse_proxy_entry(out: &str) -> ProxyEntry {
    let mut entry = ProxyEntry::default();
    for line in out.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "Enabled" => entry.enabled = value.eq_ignore_ascii_case("yes"),
            "Server" => entry.server = value.to_string(),
            "Port" => entry.port = value.to_string(),
            // "Authenticated Proxy Enabled" and anything else is not ours to restore.
            _ => {}
        }
    }
    entry
}

/// Parse `-getproxybypassdomains`, which prints one entry per line — or a
/// sentence saying there are none.
fn parse_bypass(out: &str) -> Vec<String> {
    out.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.contains("aren't any"))
        .map(str::to_string)
        .collect()
}

fn read_service_state(service: &str) -> Result<ServiceState> {
    Ok(ServiceState {
        service: service.to_string(),
        web: parse_proxy_entry(&run_networksetup(&["-getwebproxy", service])?),
        secure: parse_proxy_entry(&run_networksetup(&["-getsecurewebproxy", service])?),
        socks: parse_proxy_entry(&run_networksetup(&["-getsocksfirewallproxy", service])?),
        bypass: parse_bypass(&run_networksetup(&["-getproxybypassdomains", service])?),
    })
}

fn restore_service(state: &ServiceState) -> Result<()> {
    let entries = [&state.web, &state.secure, &state.socks];
    for ((set, set_state), entry) in PROXY_KINDS.iter().zip(entries) {
        // `-set…proxy` also switches the proxy on, so the state command has to
        // follow it to reinstate a server that was configured but disabled.
        if !entry.server.is_empty() {
            run_networksetup(&[set, &state.service, &entry.server, &entry.port])?;
        }
        let on_off = if entry.enabled { "on" } else { "off" };
        run_networksetup(&[set_state, &state.service, on_off])?;
    }

    let mut args = vec!["-setproxybypassdomains", &state.service];
    if state.bypass.is_empty() {
        args.push(CLEAR_BYPASS);
    } else {
        args.extend(state.bypass.iter().map(String::as_str));
    }
    run_networksetup(&args)?;
    Ok(())
}

/// Switch every proxy kind off for one service, regardless of what it points
/// at. Only for an explicit "turn it off" request, never for cleanup.
fn turn_off_service(service: &str) -> Result<()> {
    for (_, set_state) in PROXY_KINDS {
        run_networksetup(&[set_state, service, "off"])?;
    }
    Ok(())
}

fn load_snapshot(path: &Path) -> Option<Snapshot> {
    let raw = std::fs::read_to_string(path).ok()?;
    match serde_json::from_str(&raw) {
        Ok(states) => Some(states),
        Err(e) => {
            tracing::warn!(
                "ignoring unreadable system proxy snapshot {}: {e}",
                path.display()
            );
            None
        }
    }
}

fn save_snapshot(path: &Path, snapshot: &Snapshot) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(snapshot)?)?;
    Ok(())
}

pub fn enable(port: u16, bypass: &[String], snapshot_path: &Path) -> Result<()> {
    let services = get_active_services()?;
    let host = "127.0.0.1";
    let port_str = port.to_string();

    let bypass_list: Vec<&str> = if bypass.is_empty() {
        DEFAULT_BYPASS.to_vec()
    } else {
        bypass.iter().map(|s| s.as_str()).collect()
    };

    // Record what was there first. A second enable must not overwrite the
    // snapshot, or the settings we are about to install become the thing
    // `disable` restores.
    if !snapshot_path.exists() {
        let states: Vec<ServiceState> = services
            .iter()
            .filter_map(|service| match read_service_state(service) {
                Ok(state) => Some(state),
                Err(e) => {
                    tracing::warn!("failed to read proxy state for {service}: {e}");
                    None
                }
            })
            .collect();
        let snapshot = Snapshot {
            port,
            pid: std::process::id(),
            services: states,
        };
        if let Err(e) = save_snapshot(snapshot_path, &snapshot) {
            tracing::warn!("failed to record previous system proxy state: {e}");
        }
    }

    for service in &services {
        run_networksetup(&["-setwebproxy", service, host, &port_str])
            .with_context(|| format!("failed to set web proxy for {service}"))?;

        run_networksetup(&["-setsecurewebproxy", service, host, &port_str])
            .with_context(|| format!("failed to set secure web proxy for {service}"))?;

        run_networksetup(&["-setsocksfirewallproxy", service, host, &port_str])
            .with_context(|| format!("failed to set SOCKS proxy for {service}"))?;

        // Set proxy bypass domains/subnets
        let mut args = vec!["-setproxybypassdomains", service];
        args.extend(&bypass_list);
        run_networksetup(&args)
            .with_context(|| format!("failed to set proxy bypass for {service}"))?;
    }

    Ok(())
}

/// Undo what [`enable`] did, restoring the settings it recorded.
///
/// Does nothing unless this port owns the snapshot: with no snapshot we never
/// replaced anything, so the current settings belong to whoever did set them.
pub fn disable(port: u16, snapshot_path: &Path) -> Result<()> {
    let Some(snapshot) = load_snapshot(snapshot_path) else {
        tracing::info!("no system proxy snapshot; leaving the system settings alone");
        return Ok(());
    };
    if snapshot.port != port {
        tracing::info!(
            "system proxy snapshot belongs to port {} (pid {}); leaving it to that instance",
            snapshot.port,
            snapshot.pid
        );
        return Ok(());
    }

    let mut stranded: Vec<&str> = Vec::new();
    for state in &snapshot.services {
        match read_service_state(&state.service) {
            // Something has pointed this service elsewhere since we set it.
            // That newer setting is not ours to overwrite.
            Ok(current) if !current.points_at(port) => {
                tracing::info!(
                    service = %state.service,
                    "system proxy no longer points at port {port}; leaving it untouched"
                );
            }
            Ok(_) => {
                if let Err(e) = restore_service(state) {
                    tracing::warn!("failed to restore proxy state for {}: {e}", state.service);
                    stranded.push(&state.service);
                }
            }
            Err(e) => {
                tracing::warn!("failed to read proxy state for {}: {e}", state.service);
                stranded.push(&state.service);
            }
        }
    }

    if !stranded.is_empty() {
        // The snapshot is the only copy of the settings we overwrote, so it has
        // to outlive a failed restore or a retry has nothing to work from.
        anyhow::bail!(
            "system proxy not fully restored for {}; the previous settings are kept in {}",
            stranded.join(", "),
            snapshot_path.display()
        );
    }

    let _ = std::fs::remove_file(snapshot_path);
    Ok(())
}

/// Switch the system proxy off outright, whoever set it.
///
/// This is the explicit `sysproxy off` request: the user is asking for no
/// system proxy, not for the previous one back, so any snapshot we were holding
/// is dropped along with it.
pub fn turn_off(snapshot_path: &Path) -> Result<()> {
    let services = get_active_services()?;
    for service in &services {
        turn_off_service(service)
            .with_context(|| format!("failed to disable system proxy for {service}"))?;
    }
    let _ = std::fs::remove_file(snapshot_path);
    Ok(())
}

pub fn status() -> Result<String> {
    let services = get_active_services()?;
    let mut result = String::new();

    for service in &services {
        let info = run_networksetup(&["-getwebproxy", service])
            .with_context(|| format!("failed to get web proxy status for {service}"))?;

        result.push_str(&format!("[{service}]\n{info}\n"));
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real `networksetup -getwebproxy` output.
    const WEB_PROXY_OUT: &str =
        "Enabled: Yes\nServer: 127.0.0.1\nPort: 7890\nAuthenticated Proxy Enabled: 0\n";

    #[test]
    fn parses_proxy_entry() {
        let entry = parse_proxy_entry(WEB_PROXY_OUT);
        assert!(entry.enabled);
        assert_eq!(entry.server, "127.0.0.1");
        assert_eq!(entry.port, "7890");
    }

    #[test]
    fn parses_disabled_proxy_entry() {
        let out = "Enabled: No\nServer:\nPort: 0\nAuthenticated Proxy Enabled: 0\n";
        let entry = parse_proxy_entry(out);
        assert!(!entry.enabled);
        assert_eq!(entry.server, "");
    }

    #[test]
    fn parses_bypass_list() {
        let out = "192.0.2.0/24\n198.51.100.0/24\nlocalhost\n*.local\n";
        assert_eq!(
            parse_bypass(out),
            vec!["192.0.2.0/24", "198.51.100.0/24", "localhost", "*.local"]
        );
    }

    #[test]
    fn parses_empty_bypass_list() {
        let out = "There aren't any bypass domains set on this network service.\n";
        assert!(parse_bypass(out).is_empty());
    }

    #[test]
    fn points_at_only_matches_our_own_listener() {
        let state = ServiceState {
            service: "Wi-Fi".to_string(),
            web: parse_proxy_entry(WEB_PROXY_OUT),
            secure: ProxyEntry::default(),
            socks: ProxyEntry::default(),
            bypass: Vec::new(),
        };
        assert!(state.points_at(7890));
        // Another instance's port must be left alone.
        assert!(!state.points_at(7899));

        // A disabled proxy is not ours to undo either.
        let mut off = state.clone();
        off.web.enabled = false;
        assert!(!off.points_at(7890));

        // Neither is a proxy on another host.
        let mut remote = state.clone();
        remote.web.server = "10.0.0.1".to_string();
        assert!(!remote.points_at(7890));
    }

    fn sample_snapshot(port: u16) -> Snapshot {
        Snapshot {
            port,
            pid: 4242,
            services: vec![ServiceState {
                service: "Wi-Fi".to_string(),
                web: parse_proxy_entry(WEB_PROXY_OUT),
                secure: ProxyEntry::default(),
                socks: ProxyEntry::default(),
                bypass: vec!["127.0.0.1".to_string(), "*.local".to_string()],
            }],
        }
    }

    /// A test dir that cleans itself up, so a failing assert cannot leave
    /// stray snapshots behind.
    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("clashx-sysproxy-{tag}-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    #[test]
    fn disable_without_snapshot_touches_nothing() {
        // The defect this guards: a daemon that never set the system proxy
        // switching off one the user configured by hand.
        let dir = TempDir::new("nosnap");
        let path = dir.0.join("snapshot.json");
        // No snapshot, so there is nothing of ours to undo and no networksetup
        // call to make — this must succeed without touching the machine.
        disable(7890, &path).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn disable_ignores_another_ports_snapshot() {
        let dir = TempDir::new("otherport");
        let path = dir.0.join("snapshot.json");
        save_snapshot(&path, &sample_snapshot(7890)).unwrap();

        // Our port does not own this snapshot, so it is left for whoever does.
        disable(7899, &path).unwrap();
        assert!(path.exists(), "another owner's snapshot must survive");
        assert_eq!(load_snapshot(&path).unwrap().port, 7890);
    }

    #[test]
    fn snapshot_records_its_owner() {
        let snapshot = sample_snapshot(7890);
        assert_eq!(snapshot.port, 7890);
        let dir = TempDir::new("owner");
        let path = dir.0.join("snapshot.json");
        save_snapshot(&path, &snapshot).unwrap();
        let loaded = load_snapshot(&path).unwrap();
        assert_eq!(loaded.port, 7890);
        assert_eq!(loaded.pid, 4242);
    }

    #[test]
    fn snapshot_round_trips() {
        let snapshot = sample_snapshot(7890);
        let dir = TempDir::new("roundtrip");
        let path = dir.0.join("snapshot.json");
        save_snapshot(&path, &snapshot).unwrap();
        assert_eq!(load_snapshot(&path).unwrap(), snapshot);

        // A corrupt snapshot reads as absent, which means "leave things alone"
        // rather than "switch everything off".
        std::fs::write(&path, "not json").unwrap();
        assert!(load_snapshot(&path).is_none());
    }

    #[test]
    fn missing_snapshot_loads_as_none() {
        assert!(load_snapshot(Path::new("/nonexistent/clashx-rs/snapshot.json")).is_none());
    }

    #[test]
    fn get_active_services_returns_list() {
        // On macOS, this should return at least one service
        let services = get_active_services().unwrap();
        assert!(
            !services.is_empty(),
            "expected at least one network service"
        );
    }
}
