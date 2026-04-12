# clashx-rs Security Risk Review

Date: 2026-04-11
Scope: trust boundaries, inbound exposure, local control, and upstream TLS trust
Evidence:
- source inspection
- `cargo test`
- `cargo clippy --all-targets -- -D warnings`
- `cargo audit` started, but did not complete in this environment

## Risk Summary

Current risk rating:
- high for LAN/shared-host deployment
- medium for single-user localhost use

The codebase is materially safer than a naive local proxy because the control socket is owner-only and the default listener stays on loopback. The largest remaining risk is still that turning on LAN exposure creates an unauthenticated open proxy.

## Findings

### High

#### 1. `allow-lan` still creates an unauthenticated open proxy

References:
- `src/daemon.rs:261-280`
- `src/daemon.rs:316-319`
- `crates/proxy/src/inbound/http.rs:67-168`
- `crates/proxy/src/inbound/socks5.rs:19-96`

Why it matters:
- the daemon binds a non-loopback address when `allow-lan` is enabled.
- neither inbound HTTP nor SOCKS5 requires authentication or source allowlisting.

Likely outcome:
- any reachable host can use the machine as a proxy if the port is exposed.

Mitigation:
- keep loopback as the default.
- document LAN mode as unsafe-by-default.
- add inbound auth or source ACLs before treating it as supported deployment.

### Medium

#### 2. Trojan `skip-cert-verify` disables upstream authentication completely

References:
- `crates/config/src/types.rs:92-100`
- `crates/proxy/src/outbound/trojan.rs:27-83`
- `crates/proxy/src/outbound/trojan.rs:153-171`

Why it matters:
- the custom verifier accepts any certificate and any handshake signature.

Likely outcome:
- active MITM remains possible whenever the flag is enabled.

Mitigation:
- keep it as an explicit break-glass option only.
- document it as insecure.
- consider certificate pinning or strict CA validation for expected deployments.

#### 3. Inbound parsing has no size caps and connection admission is unbounded

References:
- `crates/proxy/src/inbound/mod.rs:48-80`
- `crates/proxy/src/inbound/http.rs:111-168`
- `src/daemon.rs:343-359`

Why it matters:
- each accepted socket gets its own spawned task.
- HTTP parsing accumulates request lines and headers into owned buffers without a maximum size.
- the timeout protects against silence, not against fast oversized requests.

Likely outcome:
- memory and scheduler pressure under hostile or accidental burst traffic.

Mitigation:
- cap request line bytes, header bytes, and concurrent handshakes/connections.

### Low

#### 4. Control socket commands are same-user powerful and still unbounded

References:
- `src/daemon.rs:287-308`
- `src/daemon.rs:631-649`
- `src/daemon.rs:700-738`

Why it matters:
- the permissions are correct, but any compromised process running as the same user can send arbitrarily large newline-delimited JSON and issue `Stop` or `Reload`.

Likely outcome:
- local-only denial of service or control-plane abuse.

Mitigation:
- add a maximum request size and keep same-user trust assumptions explicit in docs.

## Security Readiness Verdict

Reasonable for:
- localhost-only personal use

Not ready for:
- exposed LAN use
- shared-user machines
- deployments that require strong guarantees around upstream TLS verification or bounded ingress abuse
