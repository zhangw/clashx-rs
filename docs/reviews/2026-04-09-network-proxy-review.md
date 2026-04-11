# clashx-rs Network Proxy Review

Date: 2026-04-09
Updated against current `HEAD`
Scope: repository review for the macOS/Linux network proxy implementation
Evidence: source inspection, `cargo test`, `cargo clippy --all-targets -- -D warnings`

## Executive Summary

The project is in a better state than the initial review snapshot. Several high-impact correctness and safety problems have been fixed:

- HTTP inbound now preserves buffered bytes that were read ahead during header parsing.
- `stop` now disables system proxy before exit.
- invalid proxy targets no longer silently fail open to `DIRECT`.
- inbound and outbound setup now has connect/handshake timeouts.
- Trojan TLS connector setup is cached instead of rebuilt on every connection.
- runtime dir/socket permissions are now tightened to owner-only.
- `bind-address` is now honored for LAN mode.
- config mode is now enforced in live routing.
- Linux `PROCESS-NAME` lookup is now implemented.
- SOCKS5 upstream username/password auth is now implemented.

At this point the review is mostly down to lower-severity residual risks and coverage gaps rather than missing core functionality.

## Findings

### Medium

#### 1. DNS config is still mostly configuration-only

References:
- `crates/config/src/types.rs:20-21`
- `crates/dns/src/lib.rs:5-17`
- `crates/proxy/src/outbound/direct.rs:11-16`

Impact:
- a DNS crate exists, but the main data path still relies on implicit resolution in connect calls
- nameserver/default-nameserver/enhanced-mode settings are not driving runtime behavior

Status:
- still open

Recommendation:
- either wire DNS policy into the real data path or explicitly treat these fields as unsupported/inactive

### Low

#### 2. Missing targeted automated coverage for `Mode::Global` and `Mode::Direct`

References:
- `src/daemon.rs:90-106`
- `src/daemon.rs:309-317`

Impact:
- the routing logic is now implemented, but there is no focused test proving non-`rule` modes behave correctly under the live selection path

Status:
- residual gap

Recommendation:
- add small focused tests for `resolve_routing_target()` or daemon-level routing behavior in `global` and `direct` modes

#### 3. Linux `PROCESS-NAME` lookup is implemented but not covered end-to-end

References:
- `crates/rule/src/process.rs:38-108`
- `src/daemon.rs:291-307`

Impact:
- the feature is now wired in, but the current test only proves the lookup helper does not panic
- real `/proc` matching behavior may still vary across kernels, namespaces, and privilege boundaries

Status:
- residual gap

Recommendation:
- add Linux-targeted integration coverage or at least a more realistic unit harness around `/proc` parsing logic

#### 4. macOS sysproxy operations remain serial subprocess chains

References:
- `crates/sysproxy/src/macos.rs:31-68`

Impact:
- operational overhead only; not a data-path problem

Status:
- low priority

Recommendation:
- acceptable unless sysproxy UX becomes a bottleneck

#### 5. Background daemon mode is still advertised but not implemented

References:
- `src/main.rs:30-32`
- `src/daemon.rs:127-129`

Impact:
- CLI surface still over-promises relative to runtime behavior

Status:
- still open

Recommendation:
- implement background mode or remove the flag until it exists

## Resolved Since The Initial Review

### HTTP buffered-byte loss in inbound handling

References:
- `crates/proxy/src/inbound/http.rs:97-109`
- `crates/proxy/src/inbound/http.rs:132-168`
- `src/daemon.rs:307-324`

Update:
- fixed for both CONNECT early-data preservation and plain HTTP body-prefix preservation

Residual risk:
- there is still no dedicated regression test for CONNECT with immediate post-header client data

### `stop` cleanup asymmetry

References:
- `src/daemon.rs:394-410`

Update:
- fixed; `Stop` now disables system proxy before removing runtime files and exiting

### Fail-open routing to `DIRECT`

References:
- `src/daemon.rs:290-297`

Update:
- fixed; invalid proxy resolution now rejects instead of silently connecting direct

### Missing handshake/connect timeouts

References:
- `crates/proxy/src/inbound/mod.rs:43-73`
- `crates/proxy/src/outbound/direct.rs:11-16`
- `crates/proxy/src/outbound/socks5.rs:20-23`
- `crates/proxy/src/outbound/trojan.rs:159-172`
- `crates/proxy/src/timeout.rs:1-22`

Update:
- fixed; inbound handshake and outbound connect/TLS setup now run under explicit timeout budgets

### Rebuilding Trojan TLS connector on every connection

References:
- `crates/proxy/src/outbound/trojan.rs:87-98`
- `crates/proxy/src/outbound/trojan.rs:155-168`

Update:
- fixed; connectors are now cached per verify mode via `OnceLock`

### Control socket permission hardening

References:
- `src/daemon.rs:147-168`

Update:
- fixed; runtime dir and socket are now restricted to owner-only permissions

### LAN bind address handling

References:
- `src/daemon.rs:132-141`

Update:
- fixed; `bind-address` is now honored when LAN mode is enabled

### Config mode enforcement

References:
- `src/daemon.rs:90-106`
- `src/daemon.rs:309-317`

Update:
- fixed; routing now respects `rule`, `global`, and `direct` modes

### Linux `PROCESS-NAME` routing support

References:
- `crates/rule/src/process.rs:38-108`
- `src/daemon.rs:291-307`

Update:
- fixed; Linux now has a `/proc`-based best-effort lookup path and the daemon passes the result into rule matching

### SOCKS5 upstream username/password auth

References:
- `crates/proxy/src/outbound/socks5.rs:17-91`

Update:
- fixed; RFC 1929 username/password auth is now supported when credentials are configured

## Suggested Next Order

1. Decide whether DNS config should become part of the real data path.
2. Add focused coverage for mode enforcement and Linux process lookup.
3. Add higher-fidelity integration tests for daemon + inbound + outbound behavior.
4. Implement background daemon mode or remove the flag.
