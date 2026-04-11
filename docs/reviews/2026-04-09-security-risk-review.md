# clashx-rs Security Risk Review

Date: 2026-04-09
Updated against current `HEAD`
Scope: security posture of the current macOS/Linux proxy implementation

## Risk Rating

Current rating:
- high for shared hosts or any `allow-lan` deployment
- medium for a single-user, localhost-only development setup

The security posture is improved from the initial review because the proxy no longer fails open to `DIRECT`, control-path shutdown now cleans up system proxy state, and owner-only permissions are now applied to the runtime dir and control socket. The largest remaining security concerns are now LAN exposure by configuration and the continued availability of Trojan `skip_cert_verify`.

## Open Risk Register

### High

#### 1. `allow-lan` still exposes an unauthenticated open proxy

References:
- `crates/config/src/types.rs:11-13`
- `src/daemon.rs:121-132`
- `crates/proxy/src/inbound/http.rs:67-169`
- `crates/proxy/src/inbound/socks5.rs:14-88`

Why it matters:
- `allow-lan` still maps to a `0.0.0.0` listener
- inbound HTTP and SOCKS5 still have no auth or ACL
- `bind-address` is parsed but ignored, so exposure cannot be narrowed

Likely outcome:
- any reachable host on the local network can use the machine as a proxy

Mitigation:
- honor `bind-address`
- require stronger opt-in and source restrictions
- add auth or allowlists if LAN mode is intended to be supported safely

### Medium

#### 2. TLS verification can still be fully disabled for Trojan

References:
- `crates/proxy/src/outbound/trojan.rs:24-41`
- `crates/proxy/src/outbound/trojan.rs:66-78`

Why it matters:
- `skip_cert_verify` still accepts any certificate and signature

Likely outcome:
- upstream MITM remains possible on hostile networks

Mitigation:
- keep the option only if necessary
- surface stronger warnings in logs/CLI
- prefer pinning or explicit CA bundles over full verification bypass

### Low

#### 3. Linux `PROCESS-NAME` lookup still relies on a best-effort `/proc` heuristic

References:
- `crates/rule/src/process.rs:38-108`
- `src/daemon.rs:291-307`

Why it matters:
- the feature is now implemented, but accuracy may vary across namespaces, privilege boundaries, and kernel behavior

Likely outcome:
- occasional misclassification rather than a systematic security failure

Mitigation:
- add Linux-targeted integration coverage and document the best-effort behavior

#### 4. macOS sysproxy operations remain subprocess-driven

References:
- `crates/sysproxy/src/macos.rs:31-68`

Why it matters:
- operational complexity remains, even though non-zero exit status is now checked

Likely outcome:
- noisy failures or slow toggles on some systems

Mitigation:
- acceptable unless sysproxy management becomes a recurring support issue

## Resolved Since The Initial Review

### Control socket permission hardening

References:
- `src/daemon.rs:147-168`

Update:
- fixed; runtime dir and socket now use owner-only permissions

### Fail-open routing leaks

References:
- `src/daemon.rs:290-297`

Update:
- fixed; missing/invalid proxy targets now reject instead of silently routing direct

### Control-path shutdown bypassed sysproxy cleanup

References:
- `src/daemon.rs:394-410`

Update:
- fixed; `Stop` now disables system proxy before exit

### No connect/handshake timeouts

References:
- `crates/proxy/src/inbound/mod.rs:43-73`
- `crates/proxy/src/outbound/direct.rs:11-16`
- `crates/proxy/src/outbound/socks5.rs:20-23`
- `crates/proxy/src/outbound/trojan.rs:159-172`

Update:
- fixed; slow or stalled setup phases now have bounded timeout windows

### macOS sysproxy exit-status handling

References:
- `crates/sysproxy/src/macos.rs:4-17`

Update:
- fixed; `networksetup` failures are now surfaced when the subprocess exits non-zero

### Config mode enforcement and `PROCESS-NAME` routing

References:
- `src/daemon.rs:90-106`
- `src/daemon.rs:291-309`
- `crates/rule/src/process.rs:38-108`

Update:
- fixed; routing now respects config mode, and Linux/macOS process lookup is wired into live rule evaluation

## Security Readiness Verdict

Not ready for shared-host or LAN-exposed deployment.

Reasonable as a localhost-only developer tool on a trusted single-user machine, provided the operator understands that:
- Trojan `skip_cert_verify` is still dangerous
- LAN exposure is still unauthenticated by design
