# clashx-rs Security Risk Review

Date: 2026-04-10
Scope: trust boundaries, local control, LAN exposure, TLS handling, config/runtime risk
Evidence:
- source inspection
- `cargo test`
- `cargo clippy --all-targets -- -D warnings`
- `cargo audit`

## Risk Summary

Current risk rating:
- high for LAN/shared-host deployment
- medium for localhost-only single-user workstation usage

The project is materially safer than earlier snapshots because:
- control socket and runtime dir permissions are now owner-only
- fail-open routing has been removed
- shutdown cleanup disables system proxy

The largest remaining security issue is still unauthenticated LAN exposure via `allow-lan`.

## Findings

### High

#### 1. `allow-lan` still creates an unauthenticated open proxy

References:
- `crates/config/src/types.rs:11-13`
- `src/daemon.rs:195-204`
- `src/daemon.rs:240-243`
- `crates/proxy/src/inbound/http.rs:67-168`
- `crates/proxy/src/inbound/socks5.rs:14-96`

Why it matters:
- the daemon can bind to a non-loopback address
- inbound HTTP and SOCKS5 handlers do not authenticate clients

Likely outcome:
- any reachable host on the same network can use the machine as a proxy if the bind address is reachable

Mitigation:
- keep loopback as the default
- document LAN exposure as unsafe by default
- add inbound auth or source allowlists if LAN use is intended

### Medium

#### 2. Trojan `skip-cert-verify` still disables upstream authentication completely

References:
- `crates/config/src/types.rs:97-100`
- `crates/proxy/src/outbound/trojan.rs:24-41`
- `crates/proxy/src/outbound/trojan.rs:66-78`

Why it matters:
- the current `NoCertVerifier` accepts any certificate and signature

Likely outcome:
- active MITM of the Trojan upstream remains possible on hostile networks

Mitigation:
- prefer valid certificates and keep `skip-cert-verify` as an explicit escape hatch only
- document it as a real security tradeoff, not a harmless compatibility option

#### 3. `sysproxy` CLI still targets the default port instead of the configured daemon port

References:
- `src/main.rs:126-139`
- `src/paths.rs:3`

Why it matters:
- system proxy management can be pointed at the wrong local endpoint when the daemon runs on a non-default `mixed-port`

Likely outcome:
- local denial of service against the user’s own traffic rather than a remote exploit

Mitigation:
- read the active port from config or daemon status before applying system proxy settings

### Low

#### 4. Linux `PROCESS-NAME` matching is best-effort and heuristic-driven

References:
- `crates/rule/src/process.rs:38-112`
- `src/daemon.rs:328-344`

Why it matters:
- `/proc`-based ownership matching can vary across containers, namespaces, and permission boundaries

Likely outcome:
- occasional misclassification or missed process matches

Mitigation:
- document the best-effort nature clearly
- add Linux-targeted validation

#### 5. Control socket request parsing is still line-based and unbounded

References:
- `src/daemon.rs:431-446`

Why it matters:
- the socket is now owner-only, but a same-user client can still send arbitrarily long lines before newline termination

Likely outcome:
- local-only memory pressure / nuisance DoS

Mitigation:
- add a maximum control request size before deserialization

## Dependency Notes

Successful:
- `cargo audit` did not report advisories for the current `Cargo.lock`

Blocked:
- `cargo deny check advisories`
- `cargo deny check`

Environment blockers:
- dead proxy env initially pointed to `127.0.0.1:7890`
- advisory DB lock acquisition failed on a read-only path under `~/.cargo/advisory-dbs`

## Security Readiness Verdict

Reasonable for localhost-only personal use on macOS/Linux.

Not ready for:
- exposed LAN use
- shared-user machines where proxy access should be restricted by policy
- environments that require stronger guarantees around upstream TLS trust and process-attribution accuracy
