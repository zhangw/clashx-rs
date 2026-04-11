# Retry & Failover Design

## Goal

Add connection retry with backoff and group-scoped failover to outbound proxy connections, with a global per-proxy cooldown to avoid hammering dead nodes.

## Background

clashx-rs routes connections through proxy groups. When the selected proxy in a group is unreachable (TLS handshake failure, TCP timeout, connection refused), the connection fails immediately. Users must manually `switch` to another node. This design adds automatic retry and failover so transient and sustained outages are handled without manual intervention.

## Scope

- **In scope:** connect-phase retry, group-scoped failover, per-proxy global cooldown
- **Out of scope:** mid-stream relay reconnect, health checking, sticky failover, config file fields for tuning

## Configuration Constants

All values are compile-time constants in `src/retry.rs`. No config file changes.

| Constant | Type | Value | Purpose |
|---|---|---|---|
| `MAX_RETRIES` | `u32` | `2` | Retries per proxy before failover (3 total attempts) |
| `RETRY_BACKOFF` | `[Duration; 2]` | `[100ms, 500ms]` | Delay before each retry, indexed by attempt - 1 |
| `MAX_FAILOVER_ATTEMPTS` | `usize` | `3` | Max different proxies tried during failover |
| `COOLDOWN_DURATION` | `Duration` | `30s` | How long a failed proxy is skipped |
| `COOLDOWN_FAILURE_THRESHOLD` | `u32` | `3` | Consecutive exhausted-retry rounds before cooldown activates |

These are conservative defaults. If runtime tuning is needed later, promote to config fields.

## Architecture

### New Files

- **`src/retry.rs`** — Constants and `CooldownTracker` struct

### Modified Files

- **`src/daemon.rs`** — `DaemonState` gains a `CooldownTracker` field; `handle_connection` gains retry/failover loop
- **`src/main.rs`** — Add `mod retry;` declaration (no other changes)

### CooldownTracker

```rust
pub struct CooldownTracker {
    // proxy_name -> (consecutive_failure_count, last_failure_time)
    failures: RwLock<HashMap<String, (u32, Instant)>>,
}
```

Methods:

- **`is_cooled_down(&self, proxy: &str) -> bool`** — Returns true if proxy has hit the failure threshold and cooldown has not expired. Also lazily cleans up expired entries.
- **`record_failure(&self, proxy: &str)`** — Increments failure count and updates timestamp. Called once per proxy when all retries for that proxy are exhausted (not per individual attempt).
- **`record_success(&self, proxy: &str)`** — Resets failure count to zero (proxy has recovered).

`CooldownTracker` uses interior mutability — its `RwLock` is inside the struct, not behind the `DaemonState` `RwLock`. This means `record_failure` and `record_success` can be called without holding the `DaemonState` write lock. The tracker is stored as a field of `DaemonState` but accessed via `&self` (shared reference) after the `DaemonState` read lock is dropped.

In practice: `handle_connection` acquires the `DaemonState` read lock to build the candidate list and clone the `CooldownTracker` `Arc`, drops the lock, then calls `record_failure`/`record_success` on the tracker directly. To support this, `DaemonState` stores `Arc<CooldownTracker>` so the tracker outlives the lock scope.

### Connection Flow

The updated `handle_connection` flow:

```
1. Inbound detect (unchanged)
2. Route resolution → get group_name + selected proxy name (unchanged)
3. Build candidate list:
   a. DIRECT → retry with backoff, no failover (no group to fail over to)
   b. REJECT → no retry, drop immediately
   c. Group target → candidates = [selected_proxy, ...remaining group proxies]
      - Filter out cooled-down proxies
      - If ALL are cooled down, ignore cooldown and try all (better than instant failure)
      - Truncate to MAX_FAILOVER_ATTEMPTS candidates
4. Drop DaemonState read lock (same as today — before any network I/O)
5. For each candidate proxy:
   a. Attempt connect (up to MAX_RETRIES + 1 attempts with backoff)
   b. Success → record_success(proxy), proceed to relay, done
   c. All retries exhausted → record_failure(proxy), try next candidate
6. All candidates exhausted → return error to client
```

The candidate list preserves the user's selected proxy as the first entry. Failover order is the group's proxy list order (same as config file order), skipping the already-tried selected proxy.

## Retry Behavior by Route Type

| Route | Retry | Failover | Cooldown |
|---|---|---|---|
| Proxy via group | Yes (3 attempts) | Yes (group's proxy list) | Yes |
| DIRECT | Yes (3 attempts) | No (nothing to fail over to) | No |
| REJECT | No | No | No |

## What Is Retryable

Only **connect-phase** errors are retryable:

- TCP connection timeout or refused
- DNS resolution failure
- TLS handshake failure or timeout
- SOCKS5 handshake failure (upstream proxy unreachable)

**Not retryable:**

- Relay errors (mid-stream TCP drop) — data may have been sent, cannot transparently retry
- Inbound detect errors — client protocol error, not a proxy issue

## Logging

| Event | Level | Example |
|---|---|---|
| Retry attempt | `debug` | `retry attempt 2/3 for 新加坡 01 targeting google.com` |
| Failover to next proxy | `info` | `failover from 新加坡 01 to 新加坡 02 targeting google.com` |
| Cooldown triggered | `warn` | `proxy 新加坡 01 entered cooldown for 30s (3 consecutive failures)` |
| All candidates exhausted | `error` | `all proxies failed for google.com via @singapo` |
| Cooldown recovery | `debug` | `proxy 新加坡 01 cooldown expired, available again` |

## Edge Cases

- **Single-proxy group** (e.g., `@acmecorp-corpnet`): Retry the one proxy up to 3 times, no failover candidates, return error if exhausted.
- **All proxies cooled down**: Ignore cooldown, try all candidates anyway. A cooled-down proxy is better than no attempt.
- **Proxy appears in multiple groups**: Cooldown is global per proxy name. If `新加坡 01` enters cooldown from `@singapo`, it is also skipped in `🚀 节点选择`.
- **Config reload**: `CooldownTracker` state persists across reload (it tracks runtime network state, not config state). Cleared only on daemon restart.
- **`switch` command during retry**: The retry loop uses a snapshot of the candidate list taken before connecting. A concurrent `switch` affects future connections, not in-flight ones.

## Testing

### Unit tests in `src/retry.rs`

- `record_failure` increments count, `is_cooled_down` returns false below threshold
- `record_failure` at threshold triggers cooldown, `is_cooled_down` returns true
- Cooldown expires after duration, `is_cooled_down` returns false
- `record_success` resets failure count
- Concurrent access safety (basic test with multiple proxies)

### Unit tests in `src/daemon.rs`

- Candidate list building: selected proxy is first, remaining follow in group order
- Candidate list with cooled-down proxy: cooled-down proxy is filtered out
- Candidate list with all cooled down: all proxies included (cooldown ignored)
- Candidate list truncated to `MAX_FAILOVER_ATTEMPTS`
- DIRECT route: no candidate list (retry only, no failover)

### Not tested

- Actual network retry (would require mock TCP servers). The retry loop is simple sequential logic; correctness is covered by testing `CooldownTracker` and candidate list building independently.
