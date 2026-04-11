# AGENTS.md

This file governs the repository root and all child paths.

## Project Summary

`clashx-rs` is a pure Rust, headless Clash-compatible proxy CLI for macOS and Linux.

Current implemented shape:

- single binary with daemon + CLI control flow
- mixed inbound listener:
  - HTTP proxy
  - SOCKS5 proxy
- outbound connectors:
  - Trojan
  - SOCKS5
  - DIRECT
  - REJECT
- rule types:
  - `DOMAIN-SUFFIX`
  - `IP-CIDR`
  - `PROCESS-NAME`
  - `MATCH`
- config modes:
  - `rule`
  - `global`
  - `direct`
- startup proxy-group selection overrides:
  - `clashx-rs run --select GROUP=PROXY`

## Current Caveats

- `clashx-rs run -d` is not implemented
- DNS config is parsed, but DNS policy is not yet a first-class data-plane subsystem
- `PROCESS-NAME` lookup is best-effort and relatively expensive
- `allow-lan` exposes an unauthenticated proxy on the configured bind address
- `sysproxy` CLI currently hardcodes the default port `7890` instead of resolving the daemon’s configured port

## Repo Layout

- `src/main.rs`
  CLI entrypoint
- `src/daemon.rs`
  daemon startup, routing, control socket, runtime state
- `src/client.rs`
  CLI client to local Unix socket
- `src/control.rs`
  control request/response types
- `src/paths.rs`
  runtime paths and default port

- `crates/config`
  Clash YAML parsing and typed config
- `crates/rule`
  rule parsing/evaluation and process lookup helpers
- `crates/dns`
  system resolver helper
- `crates/proxy`
  inbound protocol handling, outbound connectors, relay, timeouts
- `crates/sysproxy`
  macOS/Linux system proxy helpers

- `tests/`
  integration-style config/rule coverage
- `docs/reviews/`
  dated review outputs

## Working Rules

- Prefer small, reviewable changes.
- Do not add dependencies unless clearly justified.
- Reuse existing crate boundaries and patterns before inventing new abstractions.
- Treat local worktree changes as user-owned unless you made them in this session.
- Do not overwrite or rewrite existing review docs; add new dated docs instead.

## Verification Expectations

For code changes, run at least:

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

Useful extra checks:

```bash
cargo audit
cargo deny check advisories
cargo deny check
```

Notes:

- `cargo audit` currently works in this repo environment.
- `cargo deny` may fail if the shell has dead proxy env vars set (`http_proxy`, `https_proxy`, `all_proxy`) or if the advisory DB path is not writable.

## Review Guidance

When reviewing this repo, prioritize:

1. routing correctness
2. security of LAN exposure and TLS handling
3. operability of system proxy management
4. performance cost of `PROCESS-NAME` matching
5. the gap between parsed config and actually enforced runtime behavior

Typical review outputs should be written to:

- `docs/reviews/YYYY-MM-DD-network-proxy-review.md`
- `docs/reviews/YYYY-MM-DD-security-risk-review.md`
- `docs/reviews/YYYY-MM-DD-performance-evaluation.md`

## Avoid Wrong Assumptions

- Do not assume GUI, TUN, REST API, or fake-IP support exists.
- Do not assume DNS config actively controls outbound resolution.
- Do not assume background daemon mode works.
- Do not assume `sysproxy` follows the daemon’s configured port unless that behavior has been explicitly changed and verified.
