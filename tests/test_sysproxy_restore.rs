#![cfg(target_os = "macos")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

fn exercise(
    action: &str,
    snapshot_exists: bool,
    current_server: &str,
    fail: bool,
) -> (bool, String, bool) {
    let dir = tempfile::tempdir().unwrap();
    let config_dir = dir.path().join(".config/clashx-rs");
    fs::create_dir_all(&config_dir).unwrap();
    let snapshot = config_dir.join("sysproxy-snapshot.json");
    if snapshot_exists {
        let entry =
            serde_json::json!({"enabled": true, "server": "original.proxy", "port": "8080"});
        let state = serde_json::json!({
            "port": 7890, "pid": 123,
            "services": [{"service": "Wi-Fi", "web": entry, "secure": entry,
                          "socks": entry, "bypass": ["*.internal"]}]
        });
        fs::write(&snapshot, state.to_string()).unwrap();
    }
    let mock = dir.path().join("networksetup");
    fs::write(
        &mock,
        r#"#!/bin/sh
printf '%s\n' "$*" >> "$TEST_NETWORK_LOG"
case "$1" in
    -listallnetworkservices) printf 'Header\nWi-Fi\n' ;;
    -getwebproxy|-getsecurewebproxy|-getsocksfirewallproxy)
        printf 'Enabled: Yes\nServer: %s\nPort: 7890\n' "$TEST_CURRENT_SERVER" ;;
    -getproxybypassdomains) printf 'localhost\n' ;;
    -set*) if [ "$TEST_FAIL_RESTORE" = yes ]; then exit 1; fi ;;
    *) exit 2 ;;
esac
"#,
    )
    .unwrap();
    fs::set_permissions(&mock, fs::Permissions::from_mode(0o755)).unwrap();
    let log = dir.path().join("network.log");
    let output = Command::new(env!("CARGO_BIN_EXE_clashx-rs"))
        .args(["--port", "7890", "sysproxy", action])
        .env("HOME", dir.path())
        // Only our mock can be invoked; never use the machine's networksetup.
        .env("PATH", dir.path())
        .env("TEST_NETWORK_LOG", &log)
        .env("TEST_CURRENT_SERVER", current_server)
        .env("TEST_FAIL_RESTORE", if fail { "yes" } else { "no" })
        .output()
        .unwrap();
    (
        output.status.success(),
        fs::read_to_string(log).unwrap_or_default(),
        snapshot.exists(),
    )
}

#[test]
fn restore_without_snapshot_does_not_touch_system_settings() {
    let (success, calls, _) = exercise("restore", false, "original.proxy", false);
    assert!(success);
    assert!(calls.is_empty());
}

#[test]
fn restore_reinstates_saved_settings() {
    let (success, calls, snapshot_exists) = exercise("restore", true, "127.0.0.1", false);
    assert!(success);
    for kind in ["web", "secureweb", "socksfirewall"] {
        assert!(calls.contains(&format!("-set{kind}proxy Wi-Fi original.proxy 8080\n")));
        assert!(calls.contains(&format!("-set{kind}proxystate Wi-Fi on\n")));
    }
    assert!(calls.contains("-setproxybypassdomains Wi-Fi *.internal\n"));
    assert!(!snapshot_exists);
}

#[test]
fn restore_preserves_settings_changed_by_someone_else() {
    let (success, calls, _) = exercise("restore", true, "another.proxy", false);
    assert!(success);
    assert!(!calls.contains("-set"));
}

#[test]
fn restore_failure_preserves_snapshot() {
    let (success, _, snapshot_exists) = exercise("restore", true, "127.0.0.1", true);
    assert!(!success);
    assert!(snapshot_exists);
}

#[test]
fn explicit_off_still_disables_proxies() {
    let (success, calls, snapshot_exists) = exercise("off", true, "another.proxy", false);
    assert!(success);
    for kind in ["web", "secureweb", "socksfirewall"] {
        assert!(calls.contains(&format!("-set{kind}proxystate Wi-Fi off\n")));
    }
    assert!(!snapshot_exists);
}
