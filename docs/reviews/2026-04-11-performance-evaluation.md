# clashx-rs Performance Evaluation

Date: 2026-04-11
Scope: routing hot path, concurrency model, rule evaluation, and resolution architecture
Evidence:
- source inspection
- `cargo test`
- `cargo clippy --all-targets -- -D warnings`

## Summary

For a desktop local-proxy workload, the current implementation is acceptable. The main remaining performance costs are not in relay correctness, but in connection setup and routing policy evaluation.

The most important current constraints are:

1. unbounded task-per-connection handling with no admission control
2. expensive `PROCESS-NAME` lookup when those rules exist
3. outbound SOCKS5 setup is only partially timeout-bounded
4. linear rule scanning with repeated string allocation
5. no active DNS cache or policy layer

## Findings

### Medium

#### 1. Connection handling is still unbounded task-per-connection

References:
- `src/daemon.rs:343-359`

Impact:
- normal workstation usage should be fine.
- bursty traffic or abuse can amplify file descriptor use, memory usage, and scheduler load because every accepted socket immediately spawns a task.

Recommendation:
- add a semaphore or connection cap, and expose live connection counts in status.

#### 2. `PROCESS-NAME` lookup can dominate connection setup cost

References:
- `src/daemon.rs:405-420`
- `crates/rule/src/process.rs:18-110`

Impact:
- macOS shells out to `lsof`.
- Linux scans procfs tables and then walks `/proc/*/fd`.
- the guard that only enables this when process rules exist is good, but the cost is still on the connection path when active.

Recommendation:
- treat process matching as a slow path.
- add measurement coverage.
- consider caching or a lower-cost attribution strategy if the feature becomes important.

#### 3. DNS is not part of the runtime fast path

References:
- `crates/config/src/types.rs:52-67`
- `crates/dns/src/lib.rs:5-17`
- `crates/proxy/src/outbound/direct.rs:11-18`

Impact:
- there is no shared DNS cache, no configured nameserver use, and no explicit place to optimize or reason about resolution behavior.

Recommendation:
- either keep DNS intentionally implicit and document that, or promote it into a real subsystem with caching and policy.

#### 4. Outbound SOCKS5 only times out the TCP dial, not the full setup

References:
- `crates/proxy/src/outbound/socks5.rs:27-120`

Impact:
- the initial TCP connect is bounded by `CONNECT_TIMEOUT`.
- the subsequent method negotiation, optional auth exchange, and CONNECT reply read are not wrapped in the same timeout budget.
- a slow or broken upstream SOCKS5 server can still pin connection setup longer than intended.

Recommendation:
- wrap the full SOCKS5 setup under one timeout budget, matching the Trojan connector shape.

### Low

#### 5. Domain-suffix matching still allocates on every rule check

References:
- `crates/rule/src/lib.rs:26-39`

Impact:
- each suffix check lowercases the host and formats a new `.{suffix}` string during scanning.
- this is small for modest rule sets, but it is avoidable steady-state work.

Recommendation:
- lowercase the host once per request.
- precompute suffix forms if rule counts grow.

#### 6. Plain HTTP forwarding still rebuilds request bytes into a new buffer

References:
- `crates/proxy/src/inbound/http.rs:157-168`

Impact:
- correctness is fine, but plain HTTP requests are recopied before relay rather than forwarded with a more streaming-oriented path.

Recommendation:
- low priority unless plain HTTP throughput becomes a focus.

## Positive Notes

- the daemon drops the read lock before outbound connect and relay work.
- handshake and connect timeouts bound the slowest setup phases.
- retry and cooldown logic limit repeated immediate use of failing proxies.

## Verification

Successful:
- `cargo test`
- `cargo clippy --all-targets -- -D warnings`
