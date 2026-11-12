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
  - `DOMAIN`
  - `DOMAIN-SUFFIX`
  - `DOMAIN-KEYWORD`
  - `IP-CIDR`
  - `GEOIP`
  - `PROCESS-NAME`
  - `MATCH`
- config modes:
  - `rule`
  - `global`
  - `direct`
- port selection:
  - `--port` overrides the run listener, control socket/PID, and system-proxy port; the override survives config reload
  - without `--port`, the config `mixed-port` is used, then the default `7890`
- DNS as a first-class data-plane subsystem (mihomo-compatible keys):
  - `dns.nameserver` supports plain UDP (bare IP / `udp://`), DoH (`https://`), DoT (`tls://`); unknown schemes are warned about and skipped
  - all nameservers failing falls back to the system resolver (fail-open)
  - top-level `hosts:` mappings (exact + `*.suffix`, IP-literal values) honored unless `use-hosts: false`
  - `proxy-server-nameserver` resolves proxy server domains via a dedicated resolver (bootstrap shared, hosts apply); falls back to the main nameserver group
  - `default-nameserver` bootstraps DoH/DoT server hostnames (plain UDP only, never the main group)
  - `dns flush [--host]` clears both resolver caches (see docs/dns-resolver-design.md)
- startup proxy-group selection overrides:
  - `clashx-rs run --select GROUP=PROXY`
- routing diagnostics:
  - `clashx-rs test <domain>` (rule mode) resolves the domain through the daemon resolver and evaluates `IP-CIDR`/`GEOIP` rules lazily
  - `PROCESS-NAME` rules are skipped because a control request has no client source address; the control response reports `process_rules_skipped`
- active node-liveness probes:
  - per-group `health-check` block (mihomo-compatible keys: `enable`, `url`, `interval`, `expected-status`)
  - absent block = enabled with defaults (`http://www.gstatic.com/generate_204`, 300s, expect 204)
  - probes dial the probe URL (plain `http://` only; `https://` URLs are skipped with a one-time warning) through each node itself
  - servers with only non-public addresses (private/loopback/CGNAT/ULA, domains resolved once) are never probed — intranet relays stay untouched
  - probe-sidelined nodes stay out of rotation until a probe passes (re-checked every 60s), unless every candidate is out of rotation (fallback keeps connectivity); a data-plane success also clears the sideline
  - per-node interval honored (floor 30s) with stable per-node jitter; at most 10 concurrent probes per round; config reload forces an immediate full re-probe
- failover/retry tuning:
  - proxy-node connect timeout 5s (DIRECT stays 10s)
  - timeout errors skip same-node retries and fail over immediately
  - first-byte window: phase 1 is bounded by the 1h relay idle budget; after client data is sent the remote must answer within 8s (re-armed per chunk). On timeout, safely replayable bytes (TLS handshake / bodiless idempotent HTTP) fail over; non-replayable requests keep the connection and fall back to plain relay. If even the last candidate times out, the connection relays on instead of failing (all nodes answering alike implies a slow origin)
  - connection lifetime: 1h with no bytes in either direction; after the first EOF, 60s (general) / 10m (streaming) inactivity. Connections still open in both directions after 30s are promoted to the streaming class; connections already half-closed stay general and use the 60s drain. Global cap is fd-derived (at most 2048); class caps are `min(1536, global)`, with a 512-permit guarantee each at the full budget
  - first-byte timeout and remote close are not node-attributable: they never feed cooldown, only a 120s ordering-only degradation (never excluded)
  - an upstream stall or a tunnel error to the node feeds passive cooldown; passive cooldown is 2 consecutive failures → 60s timed cooldown, and reload resets the tracker

## Current Caveats

- `clashx-rs run -d` is not implemented; it exits non-zero with an error and the help text says so
- `dns.enable=false` → system resolver for everything, `hosts:` ignored
- `ipv6: true` behaves as `false` (AAAA never queried); pure-IPv6 system results are discarded
- `enhanced-mode: fake-ip` parses but degrades to plain mode with a one-time warning
- health-probe reachability pre-check (`server_is_probeable`) and the `latency` default TCP mode still use the system resolver, so they can disagree with the configured DNS policy
- `PROCESS-NAME` lookup is best-effort and relatively expensive
- `allow-lan` exposes an unauthenticated proxy on the configured bind address

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
- `src/latency.rs`
  latency probes and table rendering for `latency`
- `src/probe.rs`
  active node-liveness probes (per-node HTTP status check through the node itself)
- `src/resources.rs`
  fd budget, admission control, and the connection class pools
- `src/retry.rs`
  retry/backoff/failover constants and the cooldown tracker

- `crates/config`
  Clash YAML parsing and typed config
- `crates/rule`
  rule parsing/evaluation and process lookup helpers
- `crates/dns`
  mihomo-compatible resolver: UDP/DoH/DoT upstreams, bootstrap, hosts, caches (see docs/dns-resolver-design.md)
- `crates/geoip`
  MaxMind mmdb loading and download for `GEOIP` rules
- `crates/subscribe`
  subscription download/refresh and on-disk state
- `crates/proxy`
  inbound protocol handling, outbound connectors, relay, timeouts
- `crates/sysproxy`
  macOS/Linux system proxy helpers

- `tests/`
  integration-style config/rule coverage plus fd-budget and packaging scripts
- `docs/reviews/`
  dated architecture, security, and performance reviews (style findings go in the commit message or change description)

## Working Rules

- Follow `docs/rust-style-guide.md`; record style review findings in the commit message or change description (dated style review docs are not retained).
- Prefer small, reviewable changes.
- Do not add dependencies unless clearly justified.
- Reuse existing crate boundaries and patterns before inventing new abstractions.
- Treat local worktree changes as user-owned unless you made them in this session.
- Do not overwrite or rewrite existing review docs; add new dated docs instead.

## Verification Expectations

For code changes, run at least:

```bash
cargo fmt --check
cargo test
cargo clippy --workspace --all-targets -- -D warnings
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
- Do not assume `dns.ipv6` issues AAAA queries — it currently behaves as `false`; see docs/dns-resolver-design.md for the resolver design.
- Do not assume background daemon mode works.
