# Retry & Failover Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add connection retry with backoff, group-scoped failover, and global per-proxy cooldown to outbound proxy connections.

**Architecture:** New `src/retry.rs` module with constants and `CooldownTracker` struct. `handle_connection` in `src/daemon.rs` gains a retry/failover loop that builds a candidate list from the matched group, retries each candidate with backoff, and falls over to the next on exhaustion. A new `resolve_routing_with_group` method on `DaemonState` returns the group name alongside the resolved proxy so the candidate list can be built.

**Tech Stack:** Rust, tokio (async runtime, RwLock, time::sleep), anyhow

**Spec:** `docs/superpowers/specs/2026-04-10-retry-failover-design.md`

---

### Task 1: Create `src/retry.rs` with constants and `CooldownTracker`

**Files:**
- Create: `src/retry.rs`
- Modify: `src/main.rs:1` (add `mod retry;`)

- [ ] **Step 1: Write failing tests for CooldownTracker**

Create `src/retry.rs` with tests only (struct and methods not yet implemented):

```rust
use std::collections::HashMap;
use std::time::{Duration, Instant};

// --- Constants ---

pub const MAX_RETRIES: u32 = 2;
pub const RETRY_BACKOFF: [Duration; 2] = [
    Duration::from_millis(100),
    Duration::from_millis(500),
];
pub const MAX_FAILOVER_ATTEMPTS: usize = 3;
pub const COOLDOWN_DURATION: Duration = Duration::from_secs(30);
pub const COOLDOWN_FAILURE_THRESHOLD: u32 = 3;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn below_threshold_not_cooled_down() {
        let tracker = CooldownTracker::new();
        tracker.record_failure("proxy-a");
        tracker.record_failure("proxy-a");
        assert!(!tracker.is_cooled_down("proxy-a"));
    }

    #[test]
    fn at_threshold_is_cooled_down() {
        let tracker = CooldownTracker::new();
        for _ in 0..COOLDOWN_FAILURE_THRESHOLD {
            tracker.record_failure("proxy-a");
        }
        assert!(tracker.is_cooled_down("proxy-a"));
    }

    #[test]
    fn cooldown_expires() {
        let tracker = CooldownTracker::new();
        for _ in 0..COOLDOWN_FAILURE_THRESHOLD {
            tracker.record_failure("proxy-a");
        }
        // Manually backdate the entry
        {
            let mut failures = tracker.failures.write().unwrap();
            if let Some(entry) = failures.get_mut("proxy-a") {
                entry.1 = Instant::now() - COOLDOWN_DURATION - Duration::from_secs(1);
            }
        }
        assert!(!tracker.is_cooled_down("proxy-a"));
    }

    #[test]
    fn success_resets_failure_count() {
        let tracker = CooldownTracker::new();
        tracker.record_failure("proxy-a");
        tracker.record_failure("proxy-a");
        tracker.record_success("proxy-a");
        // After reset, threshold failures needed again
        for _ in 0..COOLDOWN_FAILURE_THRESHOLD {
            tracker.record_failure("proxy-a");
        }
        assert!(tracker.is_cooled_down("proxy-a"));
        // But before those new failures, it was not cooled down
    }

    #[test]
    fn independent_proxy_tracking() {
        let tracker = CooldownTracker::new();
        for _ in 0..COOLDOWN_FAILURE_THRESHOLD {
            tracker.record_failure("proxy-a");
        }
        assert!(tracker.is_cooled_down("proxy-a"));
        assert!(!tracker.is_cooled_down("proxy-b"));
    }

    #[test]
    fn unknown_proxy_not_cooled_down() {
        let tracker = CooldownTracker::new();
        assert!(!tracker.is_cooled_down("never-seen"));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p clashx-rs retry::tests -- --nocapture 2>&1`
Expected: FAIL — `CooldownTracker` struct not defined

- [ ] **Step 3: Implement CooldownTracker**

Add above the `#[cfg(test)]` block in `src/retry.rs`:

```rust
pub struct CooldownTracker {
    // proxy_name -> (consecutive_failure_count, last_failure_time)
    failures: std::sync::RwLock<HashMap<String, (u32, Instant)>>,
}

impl CooldownTracker {
    pub fn new() -> Self {
        Self {
            failures: std::sync::RwLock::new(HashMap::new()),
        }
    }

    pub fn is_cooled_down(&self, proxy: &str) -> bool {
        let failures = self.failures.read().unwrap();
        match failures.get(proxy) {
            Some(&(count, last_failure)) => {
                count >= COOLDOWN_FAILURE_THRESHOLD
                    && last_failure.elapsed() < COOLDOWN_DURATION
            }
            None => false,
        }
    }

    pub fn record_failure(&self, proxy: &str) {
        let mut failures = self.failures.write().unwrap();
        let entry = failures
            .entry(proxy.to_string())
            .or_insert((0, Instant::now()));
        entry.0 += 1;
        entry.1 = Instant::now();
    }

    pub fn record_success(&self, proxy: &str) {
        let mut failures = self.failures.write().unwrap();
        failures.remove(proxy);
    }
}
```

Note: uses `std::sync::RwLock` (not tokio) since all operations are non-async and fast (HashMap lookups). This avoids needing `.await` at call sites.

- [ ] **Step 4: Add `mod retry;` to `src/main.rs`**

Add after the existing mod declarations at the top of `src/main.rs`:

```rust
mod retry;
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p clashx-rs retry::tests -- --nocapture 2>&1`
Expected: 6 tests PASS

- [ ] **Step 6: Run clippy**

Run: `cargo clippy --all-targets -- -D warnings 2>&1`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add src/retry.rs src/main.rs
git commit -m "feat: add CooldownTracker and retry constants"
```

---

### Task 2: Add `resolve_routing_with_group` to DaemonState

**Files:**
- Modify: `src/daemon.rs`

Currently `resolve_routing_target` resolves a group all the way to a concrete proxy name, losing the group name. For failover we need both.

- [ ] **Step 1: Write failing tests**

Add these tests to the existing `mod tests` block in `src/daemon.rs`:

```rust
    #[test]
    fn resolve_with_group_returns_group_for_group_target() {
        let mut config = test_config();
        config.rules = vec!["DOMAIN-SUFFIX,example.com,🚀 节点选择".to_string()];
        config.mode = Mode::Rule;
        let state = DaemonState::from_config(config, PathBuf::from("/tmp/test.yaml"));
        let input = MatchInput {
            host: Some("test.example.com"),
            ip: None,
            process_name: None,
        };
        let (group, proxy) = state.resolve_routing_with_group(&input);
        assert_eq!(group, Some("🚀 节点选择"));
        assert_eq!(proxy, "🇭🇰 香港 01"); // first proxy = default selection
    }

    #[test]
    fn resolve_with_group_returns_none_for_direct() {
        let mut config = test_config();
        config.mode = Mode::Direct;
        let state = DaemonState::from_config(config, PathBuf::from("/tmp/test.yaml"));
        let input = MatchInput {
            host: Some("anything.com"),
            ip: None,
            process_name: None,
        };
        let (group, proxy) = state.resolve_routing_with_group(&input);
        assert_eq!(group, None);
        assert_eq!(proxy, "DIRECT");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p clashx-rs daemon::tests::resolve_with_group -- --nocapture 2>&1`
Expected: FAIL — method not found

- [ ] **Step 3: Implement `resolve_routing_with_group`**

Add this method to `impl DaemonState` in `src/daemon.rs`, next to `resolve_routing_target`:

```rust
    /// Like `resolve_routing_target`, but also returns the group name if the
    /// route resolved through a proxy group (needed for failover candidate list).
    fn resolve_routing_with_group<'a>(
        &'a self,
        input: &MatchInput<'_>,
    ) -> (Option<&'a str>, &'a str) {
        match self.config.mode {
            Mode::Direct => (None, "DIRECT"),
            Mode::Global => {
                let group = self.config.proxy_groups.first();
                let proxy = group
                    .and_then(|g| self.selections.get(&g.name).map(|s| s.as_str()))
                    .unwrap_or("DIRECT");
                (group.map(|g| g.name.as_str()), proxy)
            }
            Mode::Rule => {
                let rule_target = self.rule_engine.evaluate(input);
                match rule_target {
                    Some(target) => {
                        if target == "DIRECT" || target == "REJECT" {
                            return (None, target);
                        }
                        // target is a group name
                        if let Some(selected) = self.selections.get(target) {
                            return (Some(target), selected.as_str());
                        }
                        // target is a direct proxy name (no group)
                        if self.proxies.contains_key(target) {
                            return (None, target);
                        }
                        (None, "DIRECT")
                    }
                    None => (None, "DIRECT"),
                }
            }
        }
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p clashx-rs daemon::tests::resolve_with_group -- --nocapture 2>&1`
Expected: 2 tests PASS

- [ ] **Step 5: Run clippy and all tests**

Run: `cargo clippy --all-targets -- -D warnings 2>&1 && cargo test 2>&1`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/daemon.rs
git commit -m "feat: add resolve_routing_with_group for failover support"
```

---

### Task 3: Add candidate list building to DaemonState

**Files:**
- Modify: `src/daemon.rs`

- [ ] **Step 1: Write failing tests**

Add to `mod tests` in `src/daemon.rs`. First add `use crate::retry::CooldownTracker;` to the test imports.

```rust
    #[test]
    fn build_candidates_selected_first_then_rest() {
        let config = test_config();
        let mut state = DaemonState::from_config(config, PathBuf::from("/tmp/test.yaml"));
        // Select 新加坡 01 in the group
        state
            .selections
            .insert("🚀 节点选择".to_string(), "🇸🇬 新加坡 01".to_string());
        let tracker = CooldownTracker::new();
        let candidates = state.build_candidate_list("🚀 节点选择", &tracker);
        assert_eq!(candidates[0].0, "🇸🇬 新加坡 01");
        assert!(!candidates[1..].iter().any(|(n, _)| n == "🇸🇬 新加坡 01"));
        assert!(candidates.len() <= 3); // MAX_FAILOVER_ATTEMPTS
    }

    #[test]
    fn build_candidates_filters_cooled_down() {
        let config = test_config();
        let state = DaemonState::from_config(config, PathBuf::from("/tmp/test.yaml"));
        let tracker = CooldownTracker::new();
        // Cool down the default selection (香港 01)
        for _ in 0..crate::retry::COOLDOWN_FAILURE_THRESHOLD {
            tracker.record_failure("🇭🇰 香港 01");
        }
        let candidates = state.build_candidate_list("🚀 节点选择", &tracker);
        assert!(
            !candidates.iter().any(|(n, _)| n == "🇭🇰 香港 01"),
            "cooled-down proxy should be filtered"
        );
    }

    #[test]
    fn build_candidates_all_cooled_down_tries_anyway() {
        let mut config = test_config();
        // Use @hk which only has 2 proxies
        config.proxy_groups.retain(|g| g.name == "@hk");
        let state = DaemonState::from_config(config, PathBuf::from("/tmp/test.yaml"));
        let tracker = CooldownTracker::new();
        for _ in 0..crate::retry::COOLDOWN_FAILURE_THRESHOLD {
            tracker.record_failure("🇭🇰 香港 01");
            tracker.record_failure("🇭🇰 香港 02");
        }
        let candidates = state.build_candidate_list("@hk", &tracker);
        assert_eq!(candidates.len(), 2, "all-cooled-down should still include all");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p clashx-rs daemon::tests::build_candidates -- --nocapture 2>&1`
Expected: FAIL — `build_candidate_list` not found

- [ ] **Step 3: Implement `build_candidate_list`**

Add this method to `impl DaemonState` in `src/daemon.rs`:

```rust
    /// Build a list of (proxy_name, Proxy) candidates for retry/failover.
    /// The selected proxy is first, followed by remaining group members in config order.
    /// Cooled-down proxies are filtered out unless ALL are cooled down.
    fn build_candidate_list(
        &self,
        group_name: &str,
        cooldown: &crate::retry::CooldownTracker,
    ) -> Vec<(String, Proxy)> {
        let group = match self.config.proxy_groups.iter().find(|g| g.name == group_name) {
            Some(g) => g,
            None => return Vec::new(),
        };
        let selected = self
            .selections
            .get(group_name)
            .map(|s| s.as_str())
            .unwrap_or("");

        // Build ordered list: selected first, then remaining in config order
        let mut ordered: Vec<&str> = Vec::with_capacity(group.proxies.len());
        if group.proxies.iter().any(|p| p == selected) {
            ordered.push(selected);
        }
        for p in &group.proxies {
            if p != selected && p != "DIRECT" && p != "REJECT" {
                ordered.push(p);
            }
        }

        // Filter cooled-down proxies
        let filtered: Vec<&str> = ordered
            .iter()
            .filter(|&&name| !cooldown.is_cooled_down(name))
            .copied()
            .collect();

        // If all filtered out, ignore cooldown
        let final_list = if filtered.is_empty() { &ordered } else { &filtered };

        // Resolve to Proxy configs, truncate to MAX_FAILOVER_ATTEMPTS
        final_list
            .iter()
            .filter_map(|&name| {
                self.proxies.get(name).map(|p| (name.to_string(), p.clone()))
            })
            .take(crate::retry::MAX_FAILOVER_ATTEMPTS)
            .collect()
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p clashx-rs daemon::tests::build_candidates -- --nocapture 2>&1`
Expected: 3 tests PASS

- [ ] **Step 5: Run clippy and all tests**

Run: `cargo clippy --all-targets -- -D warnings 2>&1 && cargo test 2>&1`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/daemon.rs
git commit -m "feat: add build_candidate_list for failover"
```

---

### Task 4: Add `CooldownTracker` to `DaemonState`

**Files:**
- Modify: `src/daemon.rs`

- [ ] **Step 1: Add `Arc<CooldownTracker>` field to `DaemonState`**

In `src/daemon.rs`, update the struct:

```rust
struct DaemonState {
    config: Config,
    config_path: PathBuf,
    rule_engine: RuleEngine,
    proxies: HashMap<String, Proxy>,
    selections: HashMap<String, String>,
    startup_overrides: Vec<(String, String)>,
    cooldown: Arc<crate::retry::CooldownTracker>,
}
```

Update `from_config` to initialize it:

```rust
            startup_overrides: Vec::new(),
            cooldown: Arc::new(crate::retry::CooldownTracker::new()),
        }
```

- [ ] **Step 2: Preserve cooldown across reload**

In the `ControlRequest::Reload` handler, save and restore the cooldown tracker (same pattern as `startup_overrides`):

```rust
        ControlRequest::Reload => {
            let mut st = state.write().await;
            let path = st.config_path.clone();
            let overrides = std::mem::take(&mut st.startup_overrides);
            let cooldown = Arc::clone(&st.cooldown);
            match load_config(&path) {
                Ok(new_config) => {
                    let mut new_state = DaemonState::from_config(new_config, path);
                    if let Err(e) = new_state.reapply_overrides(overrides) {
                        return ControlResponse::error(format!(
                            "reload succeeded but --select overrides failed: {e}"
                        ));
                    }
                    new_state.cooldown = cooldown;
                    *st = new_state;
                    ControlResponse::ok()
                }
                Err(e) => ControlResponse::error(format!("reload failed: {e}")),
            }
        }
```

- [ ] **Step 3: Run clippy and all tests**

Run: `cargo clippy --all-targets -- -D warnings 2>&1 && cargo test 2>&1`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/daemon.rs
git commit -m "feat: add CooldownTracker to DaemonState"
```

---

### Task 5: Rewrite `handle_connection` with retry/failover loop

**Files:**
- Modify: `src/daemon.rs`

This is the core change. Extract the outbound connect logic into a helper, then wrap it in the retry/failover loop.

- [ ] **Step 1: Add `connect_outbound` helper function**

Add this function in `src/daemon.rs` after `relay_streams`:

```rust
/// Attempt a single outbound connection to the given proxy.
async fn connect_outbound(
    proxy: &Proxy,
    target: &clashx_rs_proxy::inbound::TargetAddr,
) -> Result<OutboundStream> {
    match proxy {
        Proxy::Trojan(tp) => {
            outbound::trojan::connect(
                &tp.server,
                tp.port,
                &tp.password,
                tp.sni.as_deref(),
                tp.skip_cert_verify,
                target,
            )
            .await
        }
        Proxy::Socks5(sp) => {
            outbound::socks5::connect(
                &sp.server,
                sp.port,
                target,
                sp.username.as_deref(),
                sp.password.as_deref(),
            )
            .await
        }
        Proxy::Unknown => {
            anyhow::bail!("unsupported proxy type");
        }
    }
}
```

- [ ] **Step 2: Add `try_connect_with_retry` helper function**

Add this function in `src/daemon.rs`:

```rust
/// Try connecting to a single proxy with retries and backoff.
/// Returns Ok(OutboundStream) on success, Err on all retries exhausted.
async fn try_connect_with_retry(
    proxy_name: &str,
    proxy: &Proxy,
    target: &clashx_rs_proxy::inbound::TargetAddr,
    target_host: &str,
) -> Result<OutboundStream> {
    let max_attempts = crate::retry::MAX_RETRIES + 1;
    let mut last_err = None;

    for attempt in 0..max_attempts {
        if attempt > 0 {
            let backoff = crate::retry::RETRY_BACKOFF[(attempt - 1) as usize];
            tracing::debug!(
                proxy = %proxy_name,
                target = %target_host,
                attempt = attempt + 1,
                max = max_attempts,
                "retry attempt after {}ms backoff",
                backoff.as_millis()
            );
            tokio::time::sleep(backoff).await;
        }

        match connect_outbound(proxy, target).await {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                tracing::debug!(
                    proxy = %proxy_name,
                    target = %target_host,
                    attempt = attempt + 1,
                    error = %e,
                    "connect attempt failed"
                );
                last_err = Some(e);
            }
        }
    }

    Err(last_err.unwrap())
}
```

- [ ] **Step 3: Rewrite `handle_connection` to use retry/failover**

Replace the current `handle_connection` function body:

```rust
async fn handle_connection(
    stream: TcpStream,
    source_addr: std::net::SocketAddr,
    state: Arc<RwLock<DaemonState>>,
) -> Result<()> {
    let InboundResult {
        target,
        stream: inbound_stream,
        initial_data,
        source_addr: _,
    } = inbound::detect_and_handle(stream, source_addr).await?;

    let target_host = target.host_string();
    let target_port = target.port();

    let ip: Option<std::net::IpAddr> = target_host.parse().ok();

    // --- Phase 1: Route resolution (under read lock) ---
    let group_name: Option<String>;
    let proxy_name: String;
    let candidates: Vec<(String, Proxy)>;
    let cooldown: Arc<crate::retry::CooldownTracker>;
    {
        let st = state.read().await;

        let process_name = if st.config.mode == Mode::Rule && st.has_process_rules() {
            lookup_process_name(&source_addr)
        } else {
            None
        };

        let match_input = MatchInput {
            host: if ip.is_some() {
                None
            } else {
                Some(&target_host)
            },
            ip,
            process_name: process_name.as_deref(),
        };

        let (grp, resolved) = st.resolve_routing_with_group(&match_input);
        group_name = grp.map(|s| s.to_string());
        proxy_name = resolved.to_string();

        tracing::info!(
            target = %target_host,
            port = target_port,
            mode = ?st.config.mode,
            proxy = %proxy_name,
            group = ?group_name,
            "routing connection"
        );

        // Build candidate list for failover
        candidates = if let Some(ref gn) = group_name {
            st.build_candidate_list(gn, &st.cooldown)
        } else {
            // No group — single proxy or DIRECT/REJECT
            if proxy_name != "DIRECT" && proxy_name != "REJECT" {
                st.proxies
                    .get(&proxy_name)
                    .map(|p| vec![(proxy_name.clone(), p.clone())])
                    .unwrap_or_default()
            } else {
                Vec::new()
            }
        };

        cooldown = Arc::clone(&st.cooldown);
    }
    // State read lock is dropped here, before any async connect/relay calls.

    // --- Phase 2: Connect with retry/failover ---
    match proxy_name.as_str() {
        "REJECT" => {
            tracing::debug!(target = %target_host, "connection rejected");
            drop(inbound_stream);
            return Ok(());
        }
        "DIRECT" => {
            // Retry DIRECT connections but no failover
            let mut last_err = None;
            let max_attempts = crate::retry::MAX_RETRIES + 1;
            for attempt in 0..max_attempts {
                if attempt > 0 {
                    let backoff = crate::retry::RETRY_BACKOFF[(attempt - 1) as usize];
                    tracing::debug!(
                        target = %target_host,
                        attempt = attempt + 1,
                        max = max_attempts,
                        "DIRECT retry after {}ms backoff",
                        backoff.as_millis()
                    );
                    tokio::time::sleep(backoff).await;
                }
                match outbound::direct::connect(&target).await {
                    Ok(outbound) => {
                        relay_streams(inbound_stream, outbound, initial_data).await?;
                        return Ok(());
                    }
                    Err(e) => {
                        tracing::debug!(
                            target = %target_host,
                            attempt = attempt + 1,
                            error = %e,
                            "DIRECT connect failed"
                        );
                        last_err = Some(e);
                    }
                }
            }
            return Err(last_err.unwrap());
        }
        _ => {
            if candidates.is_empty() {
                anyhow::bail!("proxy not found: {proxy_name}");
            }

            let mut last_err = None;
            for (i, (cand_name, cand_proxy)) in candidates.iter().enumerate() {
                if i > 0 {
                    tracing::info!(
                        from = %candidates[i - 1].0,
                        to = %cand_name,
                        target = %target_host,
                        "failover to next proxy"
                    );
                }

                match try_connect_with_retry(cand_name, cand_proxy, &target, &target_host).await {
                    Ok(outbound) => {
                        cooldown.record_success(cand_name);
                        relay_streams(inbound_stream, outbound, initial_data).await?;
                        return Ok(());
                    }
                    Err(e) => {
                        cooldown.record_failure(cand_name);
                        if cooldown.is_cooled_down(cand_name) {
                            tracing::warn!(
                                proxy = %cand_name,
                                "proxy entered cooldown for {}s ({} consecutive failures)",
                                crate::retry::COOLDOWN_DURATION.as_secs(),
                                crate::retry::COOLDOWN_FAILURE_THRESHOLD
                            );
                        }
                        last_err = Some(e);
                    }
                }
            }

            let group_label = group_name.as_deref().unwrap_or(&proxy_name);
            tracing::error!(
                target = %target_host,
                group = %group_label,
                "all proxies failed"
            );
            return Err(last_err.unwrap());
        }
    }
}
```

- [ ] **Step 4: Remove the old `connect_outbound` dispatch from `handle_connection`**

The old match arms for `Proxy::Trojan`, `Proxy::Socks5`, etc. inside `handle_connection` are now replaced by the code in Step 3. Ensure the old code is fully removed and the new function compiles.

- [ ] **Step 5: Run clippy and all tests**

Run: `cargo clippy --all-targets -- -D warnings 2>&1 && cargo test 2>&1`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/daemon.rs
git commit -m "feat: implement retry/failover loop in handle_connection"
```

---

### Task 6: Manual smoke test

**Files:** none (runtime verification)

- [ ] **Step 1: Build release**

Run: `cargo build --release 2>&1`
Expected: PASS

- [ ] **Step 2: Start daemon with select override**

Run:
```bash
RUST_LOG=debug cargo run -- run \
  --config ~/.config/clashx-rs/config.yaml \
  --select "🚀 节点选择=🇸🇬 新加坡 01"
```

Verify in logs:
- `startup selection override applied` for the select
- `starting clashx-rs` with correct port

- [ ] **Step 3: Test normal connection**

In another terminal:
```bash
curl -x http://127.0.0.1:17890 https://www.google.com -v 2>&1 | head -20
```

Verify: connection succeeds, logs show `routing connection` with expected proxy.

- [ ] **Step 4: Test retry logging**

Set `RUST_LOG=debug` and observe retry behavior when a proxy is slow/failing. Verify `debug` level retry messages appear.

- [ ] **Step 5: Verify status shows selections**

```bash
cargo run -- status
```

Verify: JSON output includes `selections` map with current proxy selections.

- [ ] **Step 6: Commit plan completion note**

No code changes. Verify all tests pass one final time:

Run: `cargo clippy --all-targets -- -D warnings 2>&1 && cargo test 2>&1`
Expected: All tests PASS, no warnings
