# clashx-rs Performance Evaluation

Date: 2026-04-10
Scope: routing hot path, concurrency model, DNS integration, process lookup cost, runtime operability
Evidence:
- source inspection
- `cargo test`
- `cargo clippy --all-targets -- -D warnings`

## Summary

For a local desktop proxy workload, the current implementation is acceptable and meaningfully better than the earlier snapshots:

- setup timeouts are in place
- fail-open routing is gone
- Trojan connector setup is cached
- buffered HTTP bytes are preserved correctly

The main remaining performance constraints are:

1. one task per connection with no admission control
2. expensive `PROCESS-NAME` lookup paths
3. linear rule evaluation with repeated allocation
4. no explicit DNS subsystem or cache

## Findings

### Medium

#### 1. Connection handling is still unbounded task-per-connection

References:
- `src/daemon.rs:248-284`

Impact:
- normal workstation usage is fine
- bursts or hostile traffic can still grow scheduler pressure and FD usage without a guardrail

Recommendation:
- add connection caps or a semaphore
- expose connection counts in status output

#### 2. `PROCESS-NAME` lookup can dominate connection setup cost

References:
- `src/daemon.rs:328-344`
- `crates/rule/src/process.rs:18-35`
- `crates/rule/src/process.rs:67-112`

Impact:
- macOS shells out to `lsof`
- Linux walks procfs and file-descriptor trees
- this is only gated by the presence of process rules, which is good, but still expensive when active

Recommendation:
- keep the current guard
- measure the cost on realistic workloads
- consider caching / lower-cost lookup strategies if the feature becomes common

#### 3. DNS is still not a first-class data-plane subsystem

References:
- `crates/dns/src/lib.rs:5-17`
- `crates/proxy/src/outbound/direct.rs:11-18`
- `crates/config/src/types.rs:52-66`

Impact:
- no shared DNS cache
- no runtime use of configured nameservers
- no explicit resolution layer for rule interactions

Recommendation:
- either keep DNS intentionally implicit and document that
- or make DNS policy/caching a real subsystem

### Low

#### 4. Rule evaluation still allocates unnecessarily for domain matches

References:
- `crates/rule/src/lib.rs:26-30`
- `crates/rule/src/lib.rs:36-39`

Impact:
- each domain lookup lowercases the host and formats suffix strings during scanning

Recommendation:
- lowercase once per request
- precompute suffix representations if rule counts grow materially

#### 5. Plain HTTP requests are still reconstructed into a new buffer

References:
- `crates/proxy/src/inbound/http.rs:157-168`

Impact:
- correctness is fine now, but the plain HTTP path still copies and rebuilds headers instead of streaming the already-read bytes more directly

Recommendation:
- low priority unless throughput on plain HTTP becomes important

#### 6. macOS sysproxy operations remain subprocess-driven and serial

References:
- `crates/sysproxy/src/macos.rs:31-68`

Impact:
- not a packet-path issue
- still a source of operational latency and failure surface

Recommendation:
- acceptable for now

## Positive Notes

- `PROCESS-NAME` lookup is skipped unless rules actually require it
- the daemon drops the read lock before outbound network work
- reload now preserves startup `--select` overrides

## Verification

Successful:
- `cargo test`
- `cargo clippy --all-targets -- -D warnings`
