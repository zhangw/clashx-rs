# clashx-rs Network Proxy Review

Date: 2026-04-11
Scope: architecture, runtime behavior, control plane, and operator-facing proxy behavior
Evidence:
- source inspection
- `cargo test`
- `cargo clippy --all-targets -- -D warnings`
- `cargo audit` started, but did not complete in this environment

## Executive Summary

`clashx-rs` is structurally coherent as an early local proxy daemon: the packet path is readable, listener setup is simple, and the routing state is isolated behind a single `DaemonState`. The main architectural weaknesses are now around lifecycle correctness rather than basic forwarding.

The most important current issues are:

1. `reload` replaces config state without rebinding the live listener, so runtime behavior can diverge from reported status.
2. `sysproxy` still uses the default port instead of the daemon's effective port.
3. macOS system proxy teardown is destructive because it disables all active proxy settings instead of restoring prior state.
4. DNS remains parsed configuration rather than a real runtime subsystem.

## Findings

### High

#### 1. Reload changes reported config, but not the live listener

References:
- `src/daemon.rs:259-319`
- `src/daemon.rs:670-697`
- `src/daemon.rs:720-735`

Impact:
- `mixed-port`, `allow-lan`, and `bind-address` are captured when the daemon binds the TCP listener.
- `reload` only swaps `DaemonState`, so status can report a new port or LAN setting while the process is still listening on the old address and port.
- operator actions that trust `status` after reload can misconfigure clients or assume a trust boundary changed when it did not.

Recommendation:
- treat listener-affecting config as restart-required, or make reload rebuild the listener and control the handoff explicitly.

### Medium

#### 2. `sysproxy` commands still hardcode port `7890`

References:
- `src/main.rs:127-140`
- `src/paths.rs:3`

Impact:
- `clashx-rs sysproxy on|status` ignores the configured runtime port.
- a daemon running on a custom `mixed-port` will be paired with the wrong local system proxy endpoint.

Recommendation:
- resolve the effective port from the running daemon status, not from `DEFAULT_MIXED_PORT`.

#### 3. macOS system proxy lifecycle does not preserve prior user state

References:
- `src/daemon.rs:367-369`
- `src/daemon.rs:706-710`
- `crates/sysproxy/src/macos.rs:35-68`

Impact:
- startup and shutdown logic treat system proxy as disposable global state.
- stop and Ctrl-C cleanup disable web, secure web, and SOCKS proxy settings for every active service.
- users who already had a corporate or custom proxy configured will lose it on shutdown instead of getting their prior state restored.

Recommendation:
- persist previous proxy settings before enabling, and restore those exact values on disable.

#### 4. DNS is still a config-only surface, not a runtime subsystem

References:
- `crates/config/src/types.rs:19-29`
- `crates/config/src/types.rs:52-67`
- `crates/dns/src/lib.rs:5-17`
- `crates/proxy/src/outbound/direct.rs:11-18`

Impact:
- DNS config is accepted and typed, but the runtime path never consults it.
- outbound resolution still depends on implicit resolver behavior inside `TcpStream::connect`.
- this creates a gap between the Clash-compatible config surface and actual data-plane behavior.

Recommendation:
- either make DNS policy first-class, or mark it clearly as parsed but inactive.

### Low

#### 5. Background daemon mode is still advertised but not implemented

References:
- `src/main.rs:27-36`
- `src/daemon.rs:250-252`

Impact:
- the CLI advertises `run -d`, but it only prints a placeholder message.

Recommendation:
- remove or de-emphasize the flag until the daemonization path exists, or implement it with clear lifecycle semantics.

## Positive Notes

- the runtime directory and control socket are owner-only on Unix.
- the routing lock is dropped before outbound network I/O begins.
- group selection overrides are validated and preserved across reload.

## Verification Notes

Successful:
- `cargo test`
- `cargo clippy --all-targets -- -D warnings`

Incomplete:
- `cargo audit`

Reason:
- the audit run loaded the advisory DB and started the registry/index update, but did not terminate cleanly within the review window.
