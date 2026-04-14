# clashx-rs Performance Evaluation

Date: 2026-04-11 (refreshed 2026-04-14)
Scope: routing hot path, concurrency model, rule evaluation, and resolution architecture
Evidence:
- source inspection
- `cargo test`
- `cargo clippy --all-targets -- -D warnings`
- live benchmark against https://www.163.com/dy/article/KQGCRM5T051481US.html

## Summary

For a desktop local-proxy workload, the current implementation is acceptable for typical browsing. Several high-impact issues identified in the original evaluation have since been fixed. The remaining performance constraints are:

1. unbounded task-per-connection handling with no admission control
2. outbound SOCKS5 setup is only partially timeout-bounded
3. plain HTTP forwarding still buffers request bytes before relay

## Findings

### Medium

#### 1. Connection handling is still unbounded task-per-connection

References:
- `src/daemon.rs` proxy accept loop

Impact:
- normal workstation usage is fine.
- bursty traffic or abuse can amplify file descriptor use, memory usage, and scheduler load because every accepted socket immediately spawns a task.

Recommendation:
- add a semaphore or connection cap, and expose live connection counts in status.

#### 2. Outbound SOCKS5 only times out the TCP dial, not the full setup

References:
- `crates/proxy/src/outbound/socks5.rs`

Impact:
- the initial TCP connect is bounded by `CONNECT_TIMEOUT`.
- the subsequent method negotiation, optional auth exchange, and CONNECT reply read are not wrapped in the same timeout budget.
- a slow or broken upstream SOCKS5 server can still pin connection setup longer than intended.

Recommendation:
- wrap the full SOCKS5 setup under one timeout budget, matching the Trojan connector shape.

### Low

#### 3. Plain HTTP forwarding still rebuilds request bytes into a new buffer

References:
- `crates/proxy/src/inbound/http.rs`

Impact:
- correctness is fine, but plain HTTP requests are recopied before relay rather than forwarded with a more streaming-oriented path.

Recommendation:
- low priority unless plain HTTP throughput becomes a focus.

## Positive Notes

- the daemon drops the read lock before outbound connect and relay work.
- handshake and connect timeouts bound the slowest setup phases.
- retry and cooldown logic limit repeated immediate use of failing proxies.
- concurrent connection handling scales: 100 concurrent requests complete in ~2s, comparable to direct.

## Fixed Since 2026-04-11

The following findings from the original evaluation have been resolved:

### `PROCESS-NAME` lookup dominated connection setup (originally #2)

**Impact before fix:** `lsof` subprocess per connection took ~60ms on macOS. For a browser page load of 400+ requests, this added 24+ seconds of overhead, matching the user-reported 50s vs 10s slowdown.

**Fix (`crates/rule/src/process.rs`):**
- Replaced `lsof` subprocess with native `libproc` API — no fork/exec.
- Added 2-second port → process table snapshot cache. First connection in a burst triggers one full-system scan; subsequent connections hit the O(1) cache.
- Concurrent misses coalesce via a `REBUILDING` flag + `tokio::sync::Notify`, so a burst of parallel connections triggers exactly one rescan.
- Snapshot rebuild is offloaded to `spawn_blocking` so the async runtime is not stalled.
- Process lookup moved outside the `DaemonState` read lock so concurrent connections don't serialize behind it.

### No DNS subsystem (originally #3)

**Impact before fix:** DNS resolution was implicit via `TcpStream::connect`, which routed through the system resolver. On macOS with system proxy enabled, this returned overseas CDN IPs for Chinese domains, defeating GEOIP-based routing.

**Fix (`crates/dns/src/lib.rs`):**
- Added `DnsCache` — TTL-keyed, case-insensitive, bounded at 4096 entries with expire-first eviction.
- Added direct UDP DNS queries (`resolve_via`) that bypass the system resolver.
- `resolve_with_nameservers` races multiple configured nameservers concurrently and takes the first success, falling back to the system resolver if all fail.
- Hardened wire-format parsing: TC-bit check, bounds-checked name traversal, randomized and validated transaction IDs, label-length validation.
- Integrated in `src/daemon.rs` — DNS pre-resolve happens before rule evaluation, gated on `RuleEngine::needs_resolved_ip()` to skip the call entirely when no GEOIP/IP-CIDR rules exist.

### DOMAIN-SUFFIX allocated on every check (originally #5)

**Partial fix (`crates/rule/src/lib.rs`):**
- `host_lower` is computed once per call in `evaluate()` and reused across all rules.
- Suffix check uses a zero-allocation dot-boundary comparison, no `format!`.

Not yet done: precomputing suffix forms if rule counts grow.

## Other Improvements Since 2026-04-11 (not in original report)

- **Multi-instance safety**: control socket and pid file are now port-keyed (`clashx-rs-{port}.sock`), so concurrent daemons on different ports don't collide.
- **System proxy bypass**: `sysproxy on --bypass` and config `skip-proxy` let local subnets (e.g., 192.168.42.0/24) skip clashx-rs entirely at the OS level.
- **GEOIP rule matching**: full implementation with maxminddb + auto-download, replacing the previous stub.
- **Matched rule in routing log**: logs now show which rule triggered (`rule=Some("GEOIP,CN")`) for easier debugging.
- **`evaluate_verbose` split from `evaluate`**: the fast path no longer pays for rule description formatting it discards.

## Verification

Successful:
- `cargo test` (24 daemon + 4 config parse + 43 rule engine + 29 rule unit + 23 dns + 6 geoip)
- `cargo clippy --all-targets -- -D warnings`
- live test: Chinese CDN traffic routes DIRECT via GEOIP,CN with per-request DNS cache hits; 100 concurrent HTTPS requests complete in ~2s.
