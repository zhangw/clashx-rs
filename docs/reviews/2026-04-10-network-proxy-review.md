# clashx-rs Network Proxy Review

Date: 2026-04-10
Scope: architecture, runtime behavior, CLI operability, and current proxy behavior on macOS/Linux
Evidence:
- source inspection
- `cargo test`
- `cargo clippy --all-targets -- -D warnings`
- `cargo audit`

## Executive Summary

`clashx-rs` is now a credible early-stage local proxy daemon: the core mixed-port listener, rule engine, proxy-group selection, timeouts, fail-closed routing, and process-aware rule path are all present and readable. The codebase is still tilted toward workstation use rather than hardened/shared deployment.

The most important current issues are:

1. `sysproxy` still hardcodes port `7890`, which can misconfigure system proxy settings when the daemon runs on a custom `mixed-port`.
2. `allow-lan` still creates an unauthenticated open proxy on the configured bind address.
3. DNS config is parsed but still not part of the real data plane.
4. `PROCESS-NAME` routing is best-effort and relatively expensive on both supported platforms.

## Findings

### High

#### 1. `sysproxy` subcommands still hardcode port `7890`

References:
- `src/main.rs:126-139`
- `src/paths.rs:3`

Impact:
- `clashx-rs sysproxy on|off|status` always targets the default port instead of the daemon’s configured `mixed-port`
- if the daemon is running on a non-default port, the CLI can point system traffic at a dead local proxy endpoint

Why it matters:
- this is not just cosmetic; it can blackhole browser and OS-level traffic for users who rely on `sysproxy` with a custom config

Recommendation:
- make `sysproxy` resolve the effective port from config or from the running daemon status instead of using `DEFAULT_MIXED_PORT`

### Medium

#### 2. `allow-lan` still exposes an unauthenticated open proxy

References:
- `src/daemon.rs:195-204`
- `src/daemon.rs:240-243`
- `crates/proxy/src/inbound/http.rs:67-168`
- `crates/proxy/src/inbound/socks5.rs:14-96`

Impact:
- when `allow-lan` is enabled, the daemon listens on a non-loopback address with no inbound auth or ACL
- any reachable host on that network can use the proxy if the port is reachable

Recommendation:
- keep the current loopback default
- document the risk clearly
- if LAN mode is meant to be safe, add authentication or source allowlisting

#### 3. DNS config is still mostly configuration-only

References:
- `crates/config/src/types.rs:19-21`
- `crates/dns/src/lib.rs:5-17`
- `crates/proxy/src/outbound/direct.rs:11-18`

Impact:
- `dns`, `nameserver`, `default-nameserver`, and `enhanced-mode` are parsed but do not drive actual outbound resolution policy
- the direct path still relies on implicit resolver behavior inside `TcpStream::connect`

Recommendation:
- either wire DNS policy into the real routing/data path or explicitly mark DNS config as parsed-but-inactive

#### 4. `PROCESS-NAME` lookup is likely to be a hot-path bottleneck when used

References:
- `src/daemon.rs:328-344`
- `crates/rule/src/process.rs:18-35`
- `crates/rule/src/process.rs:67-112`

Impact:
- macOS lookup shells out to `lsof` for each eligible connection
- Linux lookup scans `/proc/net/tcp*` and then walks `/proc/*/fd`
- this cost is paid on the connection path whenever `PROCESS-NAME` rules exist and mode is `rule`

Recommendation:
- treat `PROCESS-NAME` routing as a slower path in docs
- add measurement/benchmark coverage
- consider caching or a more direct kernel/API strategy if this becomes a core feature

### Low

#### 5. Rule evaluation still does per-rule string allocation for domain matches

References:
- `crates/rule/src/lib.rs:26-30`
- `crates/rule/src/lib.rs:36-39`

Impact:
- domain checks currently lowercase the host and build suffix strings repeatedly during scanning
- this is fine for modest rule sets, but it is unnecessary work on the steady-state path

Recommendation:
- lowercase once per request and/or precompute suffix shapes if rule counts grow

#### 6. Background daemon mode is still advertised but not implemented

References:
- `src/main.rs:30-35`
- `src/daemon.rs:174-176`

Impact:
- CLI surface over-promises relative to runtime behavior

Recommendation:
- implement `run -d` or remove/de-emphasize the flag until it exists

## Positive Notes

- routing no longer fails open to `DIRECT` on missing/invalid targets
- setup phases are bounded by explicit handshake/connect timeouts
- CONNECT early data and plain HTTP buffered body bytes are preserved
- startup proxy-group selection overrides are now supported and re-applied on reload
- runtime dir and control socket are now owner-only on Unix

## Verification Notes

Successful:
- `cargo test`
- `cargo clippy --all-targets -- -D warnings`
- `cargo audit` with no advisories reported

Blocked:
- `cargo deny check advisories`
- `cargo deny check`

Blocker:
- in the current environment, `cargo deny` could not acquire a writable advisory DB lock under `/Users/vincent/.cargo/advisory-dbs/db.lock`
- before clearing proxy env, it also inherited dead proxy settings pointing at `127.0.0.1:7890`
