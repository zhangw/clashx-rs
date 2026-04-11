# clashx-rs Performance Evaluation

Date: 2026-04-09
Updated against current `HEAD`
Scope: network hot paths, concurrency model, DNS/rule evaluation, and likely bottlenecks

## Summary

The current implementation is materially better than the initial review snapshot:

- inbound handshakes now time out
- direct/SOCKS5/Trojan outbound setup now has connect timeout coverage
- Trojan connector construction is cached instead of rebuilt per connection
- HTTP inbound no longer drops buffered plain-request body bytes

For a local desktop proxy workload, the architecture is now reasonably efficient. The main remaining performance limits are still task fan-out, linear rule evaluation, and the lack of integrated DNS policy/caching.

## Current Hot Path Assessment

### Good

#### Relay path remains lean

References:
- `crates/proxy/src/relay.rs:6-12`
- `src/daemon.rs:307-324`

Notes:
- `copy_bidirectional` is still the right primitive here
- state locks are not held across outbound connect/relay work

#### Trojan connector reuse is now in place

References:
- `crates/proxy/src/outbound/trojan.rs:87-98`
- `crates/proxy/src/outbound/trojan.rs:155-168`

Impact:
- avoids rebuilding TLS config and root store on every Trojan connection

#### Setup timeouts now bound slow setup phases

References:
- `crates/proxy/src/inbound/mod.rs:43-73`
- `crates/proxy/src/outbound/direct.rs:11-16`
- `crates/proxy/src/outbound/socks5.rs:20-23`
- `crates/proxy/src/outbound/trojan.rs:159-172`

Impact:
- reduces long-tail resource retention from silent or stuck clients/upstreams

## Remaining Performance Findings

### Medium

#### 1. Connection handling is still unbounded task-per-connection

References:
- `src/daemon.rs:160-177`
- `src/daemon.rs:179-196`

Impact:
- normal workstation use is fine
- bursty or hostile traffic can still create scheduler pressure, FD pressure, and memory growth

Recommendation:
- add a connection semaphore or bounded accept policy
- expose active connection counts

#### 2. Rule evaluation is still linear and allocation-heavy for domain matches

References:
- `crates/rule/src/lib.rs:23-27`
- `crates/rule/src/lib.rs:33-36`

Impact:
- every request scans rules in order
- each `DOMAIN-SUFFIX` check lowercases the host again and builds a dot-prefixed suffix string

Recommendation:
- lowercase the host once per request
- precompute suffix match structures if rule counts are expected to grow

#### 3. DNS is still not a first-class data-plane component

References:
- `crates/dns/src/lib.rs:5-17`
- `crates/proxy/src/outbound/direct.rs:11-16`

Impact:
- no shared DNS cache
- no policy-aware resolution
- DNS config fields still do not drive runtime behavior

Recommendation:
- decide whether DNS remains intentionally implicit or becomes an integrated subsystem
- if integrated, add caching and clear ownership of resolution policy

### Low

#### 4. Missing targeted coverage for `Mode::Global` / `Mode::Direct`

References:
- `src/daemon.rs:90-106`
- `src/daemon.rs:309-317`

Impact:
- implementation is now present, but the current suite does not specifically exercise non-`rule` routing modes

Recommendation:
- add focused tests around `resolve_routing_target()` and daemon routing behavior for `global` and `direct`

#### 5. Linux process lookup is best-effort and not performance-profiled

References:
- `crates/rule/src/process.rs:38-108`
- `src/daemon.rs:291-297`

Impact:
- the `/proc` scan is only performed when process rules exist, which is the right guard
- however, its cost and behavior under high process counts are not currently measured

Recommendation:
- acceptable for now
- add profiling or more realistic tests if process-based routing becomes common

#### 6. HTTP inbound still reconstructs request headers into a new buffer

References:
- `crates/proxy/src/inbound/http.rs:157-168`

Impact:
- correctness is improved, but plain HTTP still does extra copying and string allocation

Recommendation:
- acceptable for now
- if throughput becomes a concern, move toward a more byte-oriented parser

#### 7. macOS sysproxy operations are still serial subprocess chains

References:
- `crates/sysproxy/src/macos.rs:21-65`

Impact:
- operational overhead only, not packet-path overhead

Recommendation:
- low priority unless sysproxy UX becomes a bottleneck

## Resolved Since The Initial Review

### No setup timeouts

Update:
- fixed via `HANDSHAKE_TIMEOUT` and `CONNECT_TIMEOUT`

### Trojan TLS config rebuilt every connection

Update:
- fixed via cached `TlsConnector` instances

### HTTP plain-request body-prefix loss

Update:
- fixed for the plain HTTP path, with regression coverage in `http_plain_preserves_body`

### Config mode enforcement

Update:
- fixed in the routing path; residual work is now mainly around targeted tests rather than missing implementation

### Linux `PROCESS-NAME` support

Update:
- fixed in the routing path; residual work is validation/profiling rather than missing functionality

## Priority Performance Work

1. Add connection caps / backpressure.
2. Remove repeated per-rule allocations in the rule engine.
3. Decide whether DNS should be explicit and cached.
4. Add focused tests for routing modes and more realistic validation for process lookup.
5. Add end-to-end load-style validation once the daemon surface stabilizes.
