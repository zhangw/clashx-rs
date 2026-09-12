use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clashx_rs_config::load_config;
use clashx_rs_config::types::{Config, Mode, Proxy};
use clashx_rs_geoip::GeoIpDb;
use clashx_rs_proxy::inbound::{self, InboundResult};
use clashx_rs_proxy::outbound::{self, OutboundStream};
use clashx_rs_proxy::relay::relay;
use clashx_rs_rule::{MatchInput, RuleEngine};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UnixListener};
use tokio::sync::{RwLock, Semaphore};

use crate::control::{ControlRequest, ControlResponse};
use crate::paths::{self, DEFAULT_MIXED_PORT};

/// Build a MatchInput from a host string.
/// If the string is a valid IP, set `ip` and leave `host` as None
/// so that DOMAIN-SUFFIX rules don't try to match an IP string.
fn match_input_from_host(host: &str) -> MatchInput<'_> {
    let ip: Option<IpAddr> = host.parse().ok();
    MatchInput {
        host: if ip.is_some() { None } else { Some(host) },
        ip,
        process_name: None,
        ..Default::default()
    }
}

/// Max concurrent connections before admission control starts rejecting.
/// For a desktop local proxy this is far above normal browser workloads
/// (hundreds of parallel fetches). Abusive/buggy clients are bounded here.
const MAX_CONCURRENT_CONNECTIONS: usize = 2048;

struct MatchedRuleDebug<'a>(Option<&'a clashx_rs_config::rule::RuleEntry>);

impl fmt::Debug for MatchedRuleDebug<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(rule) => write!(f, "Some(\"{}\")", rule.display()),
            None => f.write_str("None"),
        }
    }
}

pub(crate) struct DaemonState {
    config: Config,
    config_path: PathBuf,
    rule_engine: Arc<RuleEngine>,
    proxies: HashMap<String, Proxy>,
    selections: HashMap<String, String>,
    startup_overrides: Vec<(String, String)>,
    cooldown: Arc<crate::retry::CooldownTracker>,
    mmdb_path: PathBuf,
    /// Resolver for target hostnames (rule pre-resolve + DIRECT).
    resolver: Arc<clashx_rs_dns::Resolver>,
    /// Resolver for proxy server addresses (proxy-server-nameserver group,
    /// falling back to the main nameserver group).
    proxy_resolver: Arc<clashx_rs_dns::Resolver>,
}

impl DaemonState {
    fn from_config(config: Config, config_path: PathBuf, mmdb_path: PathBuf) -> Self {
        let (resolver, proxy_resolver) = clashx_rs_dns::build_resolvers(&config);
        let (resolver, proxy_resolver) = (Arc::new(resolver), Arc::new(proxy_resolver));

        let geoip_db = match GeoIpDb::open(&mmdb_path) {
            Ok(db) => {
                tracing::info!(path = %mmdb_path.display(), "GeoIP database loaded");
                Some(Arc::new(db))
            }
            Err(e) => {
                tracing::warn!(path = %mmdb_path.display(), err = %e, "failed to load GeoIP database");
                None
            }
        };

        let rule_engine = Arc::new(RuleEngine::new(&config.rules, geoip_db));

        let mut proxies = HashMap::new();
        for p in &config.proxies {
            if let Some(name) = p.name() {
                proxies.insert(name.to_string(), p.clone());
            }
        }

        let mut selections = HashMap::new();
        for group in &config.proxy_groups {
            if let Some(first) = group.proxies.first() {
                selections.insert(group.name.clone(), first.clone());
            }
        }

        Self {
            config,
            config_path,
            rule_engine,
            proxies,
            selections,
            startup_overrides: Vec::new(),
            cooldown: Arc::new(crate::retry::CooldownTracker::new()),
            mmdb_path,
            resolver,
            proxy_resolver,
        }
    }

    /// Shared proxy-server resolver, for the probe/latency paths.
    pub(crate) fn proxy_resolver_handle(&self) -> Arc<clashx_rs_dns::Resolver> {
        Arc::clone(&self.proxy_resolver)
    }

    /// Validate that `group` exists and `proxy` is a member, then set the selection.
    fn validate_and_set_selection(&mut self, group: &str, proxy: &str) -> Result<(), String> {
        let pg = self
            .config
            .proxy_groups
            .iter()
            .find(|g| g.name == group)
            .ok_or_else(|| format!("group not found: {group}"))?;
        if !pg.proxies.iter().any(|p| p == proxy) {
            return Err(format!("proxy '{proxy}' not found in group '{group}'"));
        }
        self.selections.insert(group.to_string(), proxy.to_string());
        Ok(())
    }

    /// Parse `--select GROUP=PROXY` args, validate, and apply as selection overrides.
    fn parse_and_apply_overrides(&mut self, raw: &[String]) -> Result<()> {
        let mut parsed = Vec::with_capacity(raw.len());
        for entry in raw {
            let (group, proxy) = entry.split_once('=').ok_or_else(|| {
                anyhow::anyhow!(
                    "invalid --select format: expected GROUP=PROXY, got {:?}",
                    entry
                )
            })?;
            self.validate_and_set_selection(group, proxy)
                .map_err(|e| anyhow::anyhow!("--select: {e}"))?;
            tracing::info!(group = %group, proxy = %proxy, "startup selection override applied");
            parsed.push((group.to_string(), proxy.to_string()));
        }
        self.startup_overrides = parsed;
        Ok(())
    }

    /// Re-apply previously parsed startup overrides (used on config reload).
    fn reapply_overrides(&mut self, overrides: Vec<(String, String)>) -> Result<()> {
        for (group, proxy) in &overrides {
            self.validate_and_set_selection(group, proxy)
                .map_err(|e| anyhow::anyhow!("--select: {e}"))?;
        }
        self.startup_overrides = overrides;
        Ok(())
    }

    fn validate(&self) {
        for p in &self.config.proxies {
            if matches!(p, Proxy::Unknown) {
                tracing::warn!("config contains unsupported proxy type (skipped)");
            }
        }
        for rule in &self.config.rules {
            let parts: Vec<&str> = rule.splitn(3, ',').collect();
            if let Some(target) = parts.last() {
                // Strip no-resolve suffix
                let target = target.split(',').next().unwrap_or(target).trim();
                if target != "DIRECT"
                    && target != "REJECT"
                    && !self.selections.contains_key(target)
                    && !self.proxies.contains_key(target)
                {
                    tracing::warn!(rule = %rule, target = %target, "rule target not found in proxies or groups");
                }
            }
        }
    }

    /// Walk the selection chain from `start`, jumping through proxy groups
    /// until a leaf proxy, `DIRECT`, or `REJECT` is reached. Returns
    /// `(innermost_group, resolved)` — the innermost group is what callers
    /// should use as the failover pool so sibling leaves of the selected one
    /// can be tried on failure. A cycle, an unknown name, or a chain longer
    /// than `MAX_SELECTION_DEPTH` falls back to `(None, "DIRECT")` so the
    /// connection is not dropped post-handshake.
    fn resolve_selection_chain<'a>(&'a self, start: &'a str) -> (Option<&'a str>, &'a str) {
        if start == "DIRECT" || start == "REJECT" {
            return (None, start);
        }

        // Stack-allocated visited set: chain depth is 1-3 in practice, and
        // this runs under the state read lock on every connection.
        const MAX_SELECTION_DEPTH: usize = 8;
        let mut visited: [&'a str; MAX_SELECTION_DEPTH] = [""; MAX_SELECTION_DEPTH];
        let mut depth = 0usize;
        let mut cur: &'a str = start;
        let mut last_group: Option<&'a str> = None;

        loop {
            if depth == MAX_SELECTION_DEPTH || visited[..depth].contains(&cur) {
                return (None, "DIRECT");
            }
            visited[depth] = cur;
            depth += 1;

            let Some(selected) = self.selections.get(cur) else {
                return if self.proxies.contains_key(cur) {
                    (last_group, cur)
                } else {
                    (None, "DIRECT")
                };
            };
            last_group = Some(cur);
            let next: &'a str = selected.as_str();
            if next == "DIRECT" || next == "REJECT" {
                return (last_group, next);
            }
            cur = next;
        }
    }

    /// Resolve routing for a given input. Returns (group_name, proxy_name, matched_rule).
    fn resolve_routing_with_group<'a>(
        &'a self,
        input: &MatchInput<'_>,
    ) -> (Option<&'a str>, &'a str, Option<String>) {
        match self.config.mode {
            Mode::Direct => (None, "DIRECT", None),
            Mode::Global => match self.config.proxy_groups.first() {
                Some(g) => {
                    let (grp, proxy) = self.resolve_selection_chain(&g.name);
                    (grp, proxy, None)
                }
                None => (None, "DIRECT", None),
            },
            Mode::Rule => match self.rule_engine.evaluate_verbose(input) {
                Some((target, rule_desc)) => {
                    let (grp, proxy) = self.resolve_selection_chain(target);
                    (grp, proxy, Some(rule_desc))
                }
                None => (None, "DIRECT", None),
            },
        }
    }

    /// Build a list of (proxy_name, Proxy) candidates for retry/failover.
    /// Selected proxy first, remaining in config order. Cooled-down proxies filtered unless all are.
    fn build_candidate_list(
        &self,
        group_name: &str,
        cooldown: &crate::retry::CooldownTracker,
    ) -> Vec<(String, Proxy)> {
        let group = match self
            .config
            .proxy_groups
            .iter()
            .find(|g| g.name == group_name)
        {
            Some(g) => g,
            None => return Vec::new(),
        };
        let selected = self
            .selections
            .get(group_name)
            .map(|s| s.as_str())
            .unwrap_or("");

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
        let mut final_list: Vec<&str> = if filtered.is_empty() {
            ordered
        } else {
            filtered
        };

        // Demote degraded nodes (weak first-byte signal) to the end,
        // preserving relative order (stable sort). Ordering-only: degraded
        // nodes are never excluded. Cached key: one lock acquisition per
        // element instead of O(n log n).
        final_list.sort_by_cached_key(|&name| cooldown.is_degraded(name));

        // Resolve to Proxy configs, truncate to MAX_FAILOVER_ATTEMPTS
        final_list
            .iter()
            .filter_map(|&name| {
                self.proxies
                    .get(name)
                    .map(|p| (name.to_string(), p.clone()))
            })
            .take(crate::retry::MAX_FAILOVER_ATTEMPTS)
            .collect()
    }

    /// Lightweight probe schedule: (node_name, health-check) pairs for every
    /// health-check-enabled group member, *without* cloning Proxy configs.
    /// The scheduler filters due nodes from this cheap snapshot and fetches
    /// Proxy configs on demand via [`Self::proxy_named`], avoiding a full
    /// node-table deep copy on every tick. `DIRECT`/`REJECT` pseudo-members
    /// and nested group names are skipped.
    pub(crate) fn probe_schedule(&self) -> Vec<(String, clashx_rs_config::types::HealthCheck)> {
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for group in &self.config.proxy_groups {
            let hc = group.effective_health_check();
            if !hc.enable {
                continue;
            }
            for member in &group.proxies {
                if member == "DIRECT" || member == "REJECT" || !seen.insert(member.clone()) {
                    continue;
                }
                if self.proxies.contains_key(member) {
                    out.push((member.clone(), hc.clone()));
                }
            }
        }
        out
    }

    /// Fetch a node's Proxy config by name (on-demand clone for due probes).
    pub(crate) fn proxy_named(&self, name: &str) -> Option<Proxy> {
        self.proxies.get(name).cloned()
    }

    /// Shortest probe interval across enabled groups — used only as the
    /// scheduler tick cadence; per-node probing cadence comes from each
    /// node's own health-check interval.
    pub(crate) fn probe_interval_secs(&self) -> u64 {
        self.config
            .proxy_groups
            .iter()
            .map(|g| g.effective_health_check())
            .filter(|hc| hc.enable)
            .map(|hc| hc.interval)
            .min()
            .unwrap_or(clashx_rs_config::types::DEFAULT_HEALTH_CHECK_INTERVAL_SECS)
            .max(30)
    }

    pub(crate) fn cooldown_handle(&self) -> Arc<crate::retry::CooldownTracker> {
        Arc::clone(&self.cooldown)
    }
}

pub fn start_foreground(
    config_path: &Path,
    selections: &[String],
    mmdb_path: PathBuf,
    mmdb_auto_download: bool,
) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(run_daemon(
        config_path,
        selections,
        mmdb_path,
        mmdb_auto_download,
    ))
}

pub fn start_background(
    _config_path: &Path,
    _selections: &[String],
    _mmdb_path: PathBuf,
    _mmdb_auto_download: bool,
) -> Result<()> {
    println!("background daemon mode is not yet implemented");
    Ok(())
}

// ---------------------------------------------------------------------------
// Core daemon loop
// ---------------------------------------------------------------------------

async fn run_daemon(
    config_path: &Path,
    selections: &[String],
    mmdb_path: PathBuf,
    mmdb_auto_download: bool,
) -> Result<()> {
    let config = load_config(config_path)?;
    let port = config.mixed_port.unwrap_or(DEFAULT_MIXED_PORT);
    let allow_lan = config.allow_lan.unwrap_or(false);

    tracing::info!(
        path = %config_path.display(),
        mixed_port = port,
        mode = ?config.mode,
        "starting clashx-rs"
    );

    let bind_addr: String = if allow_lan {
        config
            .bind_address
            .as_deref()
            .map(|b| if b == "*" { "0.0.0.0" } else { b })
            .unwrap_or("0.0.0.0")
            .to_string()
    } else {
        "127.0.0.1".to_string()
    };

    let mut daemon_state =
        DaemonState::from_config(config, config_path.to_path_buf(), mmdb_path.clone());
    daemon_state.parse_and_apply_overrides(selections)?;
    daemon_state.validate();
    let geoip_loaded = daemon_state.rule_engine.has_geoip_db();
    let state = Arc::new(RwLock::new(daemon_state));

    let rt_dir = paths::runtime_dir();
    std::fs::create_dir_all(&rt_dir)
        .with_context(|| format!("failed to create runtime dir: {}", rt_dir.display()))?;
    // Restrict runtime dir to owner only (prevents other local users from
    // accessing the control socket or PID file).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&rt_dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to chmod runtime dir: {}", rt_dir.display()))?;
    }

    let sock = paths::socket_path(port);
    let _ = std::fs::remove_file(&sock);
    let control_listener = UnixListener::bind(&sock)
        .with_context(|| format!("failed to bind control socket: {}", sock.display()))?;
    // Restrict socket to owner only.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to chmod control socket: {}", sock.display()))?;
    }
    tracing::info!(path = %sock.display(), "control socket bound");

    let pid_file = paths::pid_path(port);
    std::fs::write(&pid_file, std::process::id().to_string())
        .with_context(|| format!("failed to write PID file: {}", pid_file.display()))?;

    let proxy_listener = TcpListener::bind((bind_addr.as_str(), port))
        .await
        .with_context(|| format!("failed to bind proxy listener on {bind_addr}:{port}"))?;
    tracing::info!(addr = %bind_addr, port = port, "proxy listener bound");

    println!("clashx-rs started on {bind_addr}:{port}");
    println!("press Ctrl-C to stop");

    // Auto-download mmdb in background if requested and not already loaded.
    if mmdb_auto_download && !geoip_loaded {
        let dl_state = Arc::clone(&state);
        let dl_mmdb_path = mmdb_path;
        let dl_port = port;
        tokio::spawn(async move {
            // Wait for proxy to fully start before downloading through it.
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            let proxy_url = format!("socks5://127.0.0.1:{dl_port}");
            let backoff = [10u64, 30, 90];

            for (attempt, delay) in backoff.iter().enumerate() {
                tracing::info!(
                    attempt = attempt + 1,
                    max = backoff.len(),
                    "auto-downloading mmdb"
                );
                match clashx_rs_geoip::download::download_mmdb(
                    None,
                    Some(&proxy_url),
                    &dl_mmdb_path,
                )
                .await
                {
                    Ok(()) => {
                        match GeoIpDb::open(&dl_mmdb_path) {
                            Ok(db) => {
                                let mut st = dl_state.write().await;
                                let new_engine =
                                    RuleEngine::new(&st.config.rules, Some(Arc::new(db)));
                                st.rule_engine = Arc::new(new_engine);
                                tracing::info!(
                                    "GeoIP database hot-swapped, GEOIP rules now active"
                                );
                            }
                            Err(e) => {
                                tracing::warn!(err = %e, "downloaded mmdb but failed to load");
                            }
                        }
                        return;
                    }
                    Err(e) => {
                        tracing::warn!(
                            attempt = attempt + 1,
                            err = %e,
                            retry_in_secs = delay,
                            "mmdb download failed"
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(*delay)).await;
                    }
                }
            }

            tracing::warn!(
                "failed to auto-download mmdb after {} attempts, GEOIP rules remain inactive",
                backoff.len()
            );
        });
    }

    let ctrl_state = Arc::clone(&state);
    tokio::spawn(async move {
        loop {
            match control_listener.accept().await {
                Ok((stream, _addr)) => {
                    let s = Arc::clone(&ctrl_state);
                    tokio::spawn(async move {
                        if let Err(e) = handle_control(stream, s).await {
                            tracing::warn!(error = %e, "control handler error");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "control accept error");
                }
            }
        }
    });

    // Active node-liveness probes (see probe.rs). Feeds the shared cooldown
    // tracker so the data plane sidesteps half-dead nodes.
    let probe_state = Arc::clone(&state);
    tokio::spawn(async move {
        crate::probe::run(probe_state).await;
    });

    let proxy_state = Arc::clone(&state);
    let connection_limit = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    tokio::spawn(async move {
        loop {
            match proxy_listener.accept().await {
                Ok((stream, addr)) => {
                    // Admission control: cap concurrent connections. If exhausted,
                    // drop the new connection with a log line — a bursty/abusive
                    // client cannot blow fd/memory budget.
                    let permit = match connection_limit.clone().try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            tracing::warn!(
                                peer = %addr,
                                limit = MAX_CONCURRENT_CONNECTIONS,
                                "connection limit reached, dropping incoming connection"
                            );
                            drop(stream);
                            continue;
                        }
                    };
                    let s = Arc::clone(&proxy_state);
                    tokio::spawn(async move {
                        let _permit = permit; // released on task exit
                        if let Err(e) = handle_connection(stream, addr, s).await {
                            tracing::debug!(error = %e, peer = %addr, "connection handler error");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "proxy accept error");
                }
            }
        }
    });

    let sub_state = Arc::clone(&state);
    tokio::spawn(async move {
        subscription_auto_update(sub_state).await;
    });

    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl-c");
    println!("\nshutting down");

    let sysproxy = clashx_rs_sysproxy::SysProxy::new(port);
    if let Err(e) = sysproxy.disable() {
        tracing::warn!("failed to disable system proxy: {e}");
    }
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_file(&pid_file);
    tracing::info!("cleanup complete");

    Ok(())
}

// ---------------------------------------------------------------------------
// Connection handler
// ---------------------------------------------------------------------------

async fn handle_connection(
    stream: TcpStream,
    source_addr: std::net::SocketAddr,
    state: Arc<RwLock<DaemonState>>,
) -> Result<()> {
    let InboundResult {
        target,
        stream: mut inbound_stream,
        initial_data,
        source_addr: _,
    } = inbound::detect_and_handle(stream, source_addr).await?;

    let target_host = target.host_string();
    let target_port = target.port();

    let parsed_ip: Option<std::net::IpAddr> = target_host.parse().ok();

    let (resolver, proxy_resolver, rule_engine, mode) = {
        let st = state.read().await;
        (
            Arc::clone(&st.resolver),
            Arc::clone(&st.proxy_resolver),
            Arc::clone(&st.rule_engine),
            st.config.mode,
        )
    };

    let host_field: Option<&str> = if parsed_ip.is_some() {
        None
    } else {
        Some(&target_host)
    };

    let (matched_rule, resolved_ip, _process_name): (
        Option<&clashx_rs_config::rule::RuleEntry>,
        Option<IpAddr>,
        Option<String>,
    ) = if mode == Mode::Rule {
        use clashx_rs_rule::EvalStep;
        let mut owned_process: Option<String> = None;
        let mut ip = parsed_ip;
        // A literal-IP target counts as already-attempted-and-satisfied, so
        // IP/GEOIP rules evaluate against it without triggering a DNS fetch.
        let mut ip_attempted = parsed_ip.is_some();
        let mut process_attempted = false;

        let mut start = 0usize;
        let mut matched_rule = None;
        loop {
            let input = MatchInput {
                host: host_field,
                ip,
                process_name: owned_process.as_deref(),
                ip_attempted,
                process_attempted,
            };
            match rule_engine.evaluate_from(&input, start) {
                EvalStep::Matched(rule) => {
                    matched_rule = Some(rule);
                    break;
                }
                EvalStep::NoMatch => break,
                EvalStep::NeedsData {
                    resume_from,
                    need_ip,
                    need_process,
                } => {
                    if need_ip {
                        ip = match resolver.resolve(&target_host).await {
                            Ok(r) => {
                                tracing::debug!(host = %target_host, resolved = %r, "DNS pre-resolved");
                                Some(r)
                            }
                            Err(e) => {
                                tracing::debug!(
                                    host = %target_host,
                                    err = %e,
                                    "DNS pre-resolve failed, IP-based rules will skip"
                                );
                                None
                            }
                        };
                        ip_attempted = true;
                    }
                    if need_process {
                        owned_process = rule_engine.process_lookup().lookup(source_addr).await;
                        process_attempted = true;
                    }
                    start = resume_from;
                }
            }
        }

        (matched_rule, ip, owned_process)
    } else {
        (None, parsed_ip, None)
    };

    // Selection-chain + candidate-list resolution (brief read lock — O(1) lookups).
    let group_name: Option<String>;
    let proxy_name: String;
    let candidates: Vec<(String, Proxy)>;
    let cooldown: Arc<crate::retry::CooldownTracker>;
    {
        let st = state.read().await;

        let chain_start: Option<&str> = match mode {
            Mode::Direct => None,
            Mode::Global => st.config.proxy_groups.first().map(|g| g.name.as_str()),
            Mode::Rule => matched_rule.map(|r| r.target()),
        };
        let (grp, resolved): (Option<String>, String) = match chain_start {
            Some(target) => {
                let (gg, p) = st.resolve_selection_chain(target);
                (gg.map(|s| s.to_string()), p.to_string())
            }
            None => (None, "DIRECT".to_string()),
        };
        group_name = grp;
        proxy_name = resolved;

        tracing::info!(
            target = %target_host,
            port = target_port,
            mode = ?mode,
            rule = ?MatchedRuleDebug(matched_rule),
            proxy = %proxy_name,
            group = ?group_name,
            "routing connection"
        );

        // Build candidate list for failover
        candidates = if let Some(ref gn) = group_name {
            st.build_candidate_list(gn, &st.cooldown)
        } else if proxy_name != "DIRECT" && proxy_name != "REJECT" {
            st.proxies
                .get(&proxy_name)
                .map(|p| vec![(proxy_name.clone(), p.clone())])
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        cooldown = Arc::clone(&st.cooldown);
    }

    // --- Phase 2: Connect with retry/failover ---
    match proxy_name.as_str() {
        "REJECT" => {
            tracing::debug!(target = %target_host, "connection rejected");
            drop(inbound_stream);
            Ok(())
        }
        "DIRECT" => {
            // Unified DIRECT resolution: when the rule phase didn't need an
            // IP (no IP/GEOIP rule matched), resolve the domain through the
            // configured resolver now so direct::connect can dial a literal
            // SocketAddr. On failure, direct::connect falls back to tokio's
            // getaddrinfo.
            let mut direct_ip = resolved_ip;
            if direct_ip.is_none() {
                direct_ip = resolve_server(&resolver, &target_host).await;
            }
            let outbound = connect_with_retry("DIRECT", &target_host, || {
                outbound::direct::connect(&target, direct_ip)
            })
            .await?;
            relay_streams(inbound_stream, outbound, initial_data, None).await?;
            Ok(())
        }
        _ => {
            if candidates.is_empty() {
                anyhow::bail!("proxy not found: {proxy_name}");
            }

            let mut last_err = None;
            // Client bytes buffered during the first-byte window, replayed to
            // the next candidate on failover. Starts as the HTTP plain-proxy
            // initial data (if any); grows with the client's first chunk(s).
            let mut replay: Vec<u8> = initial_data.unwrap_or_default();

            for (i, (cand_name, cand_proxy)) in candidates.iter().enumerate() {
                if i > 0 {
                    tracing::info!(
                        from = %candidates[i - 1].0,
                        to = %cand_name,
                        target = %target_host,
                        "failover to next proxy"
                    );
                }

                let mut outbound = match connect_with_retry(cand_name, &target_host, || {
                    connect_outbound(cand_proxy, &target, &proxy_resolver)
                })
                .await
                {
                    Ok(o) => o,
                    Err(e) => {
                        cooldown.record_failure(cand_name);
                        if cooldown.is_cooled_down(cand_name) && !cooldown.is_sidelined(cand_name) {
                            tracing::warn!(
                                proxy = %cand_name,
                                "proxy entered timed cooldown ({} consecutive failures)",
                                crate::retry::COOLDOWN_FAILURE_THRESHOLD
                            );
                        }
                        last_err = Some(e);
                        continue;
                    }
                };

                // Connect succeeded — but for Trojan that only proves the
                // node itself is alive. Wait for the remote's first response
                // bytes before committing (see first_byte_window).
                match first_byte_window(
                    &mut outbound,
                    &mut inbound_stream,
                    &mut replay,
                    crate::retry::FIRST_BYTE_TIMEOUT,
                )
                .await
                {
                    Ok(prefix) => {
                        cooldown.record_success(cand_name);
                        relay_streams(inbound_stream, outbound, None, Some(prefix)).await?;
                        return Ok(());
                    }
                    Err(FirstByteError::ClientClosed) => {
                        tracing::debug!(
                            target = %target_host,
                            "client closed during first-byte window"
                        );
                        return Ok(());
                    }
                    Err(FirstByteError::TimedOut) => {
                        // Not node-attributable: the origin may simply be
                        // slow. Never feed passive cooldown from here — the
                        // health probe owns that.
                        if replay_is_safe(&replay) {
                            if i + 1 == candidates.len() {
                                // Every candidate gave the same answer — far
                                // more likely a slow origin than N nodes dead
                                // in the same way. Preserve pre-window
                                // behavior: keep relaying rather than fail a
                                // connection that used to succeed eventually.
                                tracing::debug!(
                                    proxy = %cand_name,
                                    target = %target_host,
                                    "no response on last candidate; continuing relay"
                                );
                                relay_streams(inbound_stream, outbound, None, None).await?;
                                return Ok(());
                            }
                            cooldown.degrade(cand_name);
                            tracing::warn!(
                                proxy = %cand_name,
                                target = %target_host,
                                "no response after sending data, failing over (replay is safe)"
                            );
                            last_err = Some(anyhow::anyhow!(
                                "no response from remote via {cand_name} (first-byte timeout)"
                            ));
                        } else {
                            // Replaying could duplicate a non-idempotent
                            // request at the origin — the first node may well
                            // have delivered it. Keep this connection: drop
                            // the window and relay, preserving pre-window
                            // behavior for slow origins and large uploads.
                            tracing::debug!(
                                proxy = %cand_name,
                                target = %target_host,
                                "no response after sending data; not replayable, continuing relay"
                            );
                            relay_streams(inbound_stream, outbound, None, None).await?;
                            return Ok(());
                        }
                    }
                    Err(FirstByteError::RemoteClosed) => {
                        // The remote definitely hung up. Not node-attributable
                        // either (the origin may RST this specific request),
                        // but there is nothing to continue with here.
                        if replay_is_safe(&replay) {
                            cooldown.degrade(cand_name);
                            tracing::warn!(
                                proxy = %cand_name,
                                target = %target_host,
                                "remote closed before responding, failing over (replay is safe)"
                            );
                            last_err = Some(anyhow::anyhow!(
                                "remote closed connection via {cand_name} before responding"
                            ));
                        } else {
                            tracing::warn!(
                                proxy = %cand_name,
                                target = %target_host,
                                "remote closed before responding; request not safely replayable"
                            );
                            return Err(anyhow::anyhow!(
                                "remote closed connection via {cand_name}; request not replayable"
                            ));
                        }
                    }
                    Err(FirstByteError::Outbound(e)) => {
                        // The tunnel to the node itself broke — this *is*
                        // node-attributable.
                        cooldown.record_failure(cand_name);
                        if cooldown.is_cooled_down(cand_name) && !cooldown.is_sidelined(cand_name) {
                            tracing::warn!(
                                proxy = %cand_name,
                                "proxy entered timed cooldown ({} consecutive failures)",
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
            Err(last_err.unwrap())
        }
    }
}

/// Attempt a single outbound connection to the given proxy.
///
/// The proxy server address is resolved through the proxy resolver
/// (`proxy-server-nameserver` group, falling back to the main nameserver
/// group; hosts mappings apply). On resolution failure the connectors fall
/// back to tokio's getaddrinfo — never fail the connection over DNS.
pub(crate) async fn connect_outbound(
    proxy: &Proxy,
    target: &clashx_rs_proxy::inbound::TargetAddr,
    proxy_resolver: &clashx_rs_dns::Resolver,
) -> Result<OutboundStream> {
    match proxy {
        Proxy::Trojan(tp) => {
            let resolved_server_ip = resolve_server(proxy_resolver, &tp.server).await;
            outbound::trojan::connect(
                &tp.server,
                tp.port,
                &tp.password,
                tp.sni.as_deref(),
                tp.skip_cert_verify,
                target,
                resolved_server_ip,
            )
            .await
        }
        Proxy::Socks5(sp) => {
            let resolved_server_ip = resolve_server(proxy_resolver, &sp.server).await;
            outbound::socks5::connect(
                &sp.server,
                sp.port,
                target,
                sp.username.as_deref(),
                sp.password.as_deref(),
                resolved_server_ip,
            )
            .await
        }
        Proxy::Unknown => {
            anyhow::bail!("unsupported proxy type");
        }
    }
}

/// Resolve the address we're about to dial via `resolver`. Failures yield
/// None — the connector then falls back to the system resolver rather than
/// failing the connection over DNS. IP literals short-circuit inside
/// `Resolver::resolve`.
async fn resolve_server(
    resolver: &clashx_rs_dns::Resolver,
    server: &str,
) -> Option<std::net::IpAddr> {
    match resolver.resolve(server).await {
        Ok(ip) => Some(ip),
        Err(e) => {
            tracing::debug!(
                server,
                err = %e,
                "resolve failed, connector will use the system resolver"
            );
            None
        }
    }
}

/// Retry an async connect function with backoff.
///
/// Timeout errors break the retry loop immediately: a node that just timed out
/// will not recover within a 100-500ms backoff, so the caller should fail over
/// to the next candidate instead of burning another full timeout budget here.
async fn connect_with_retry<F, Fut>(
    label: &str,
    target_host: &str,
    connect_fn: F,
) -> Result<OutboundStream>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<OutboundStream>>,
{
    let max_attempts = crate::retry::MAX_RETRIES + 1;
    let mut last_err = None;

    for attempt in 0..max_attempts {
        if attempt > 0 {
            let backoff = crate::retry::RETRY_BACKOFF[(attempt - 1) as usize];
            tracing::debug!(
                proxy = %label,
                target = %target_host,
                attempt = attempt + 1,
                max = max_attempts,
                "retry after {}ms backoff",
                backoff.as_millis()
            );
            tokio::time::sleep(backoff).await;
        }

        match connect_fn().await {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                let is_timeout = crate::retry::is_timeout_error(&e);
                tracing::debug!(
                    proxy = %label,
                    target = %target_host,
                    attempt = attempt + 1,
                    error = %e,
                    "connect attempt failed"
                );
                last_err = Some(e);
                if is_timeout {
                    tracing::debug!(
                        proxy = %label,
                        target = %target_host,
                        "connect timed out, skipping same-node retries"
                    );
                    break;
                }
            }
        }
    }

    Err(last_err.unwrap())
}

/// Failure modes of the post-connect first-byte window.
#[derive(Debug)]
enum FirstByteError {
    /// The remote sent nothing within the deadline *after client data was
    /// forwarded*. Not node-attributable (the origin may simply be slow), so
    /// callers must not feed this into passive cooldown.
    TimedOut,
    /// The remote closed the tunnel before sending any data. Same attribution
    /// caveat as `TimedOut` (the origin may RST specific requests).
    RemoteClosed,
    /// The client went away before anything was exchanged; nothing to salvage.
    ClientClosed,
    /// The tunnel itself errored mid-write/mid-read — the connection *to the
    /// node* broke, which is node-attributable and may feed passive cooldown.
    Outbound(anyhow::Error),
}

/// Whether the buffered client bytes may be replayed to another candidate
/// after a first-byte timeout. Replaying bytes that were already sent to one
/// node duplicates them at the origin, so this is only allowed when the
/// bytes cannot produce a duplicated side effect:
///
/// - TLS handshake (ClientHello, record type 0x16, version 0x03xx): replaying
///   starts a fresh handshake on a new TCP connection; no application data is
///   duplicated. This covers HTTPS over CONNECT/SOCKS5.
/// - Plain HTTP via the HTTP-proxy path: an RFC 7231 idempotent method *and*
///   nothing after the header terminator — anything following it could be a
///   request body or a pipelined second request (e.g. a POST), which must
///   never be duplicated. Phase 2 appends chunks as they arrive, so a
///   `starts_with` check alone is not sufficient.
fn replay_is_safe(replay: &[u8]) -> bool {
    if replay.is_empty() {
        return true;
    }
    if replay.len() >= 3 && replay[0] == 0x16 && replay[1] == 0x03 {
        return true;
    }
    const IDEMPOTENT: [&[u8]; 5] = [b"GET ", b"HEAD ", b"OPTIONS ", b"PUT ", b"DELETE "];
    if !IDEMPOTENT.iter().any(|m| replay.starts_with(m)) {
        return false;
    }
    match replay.windows(4).position(|w| w == b"\r\n\r\n") {
        // Headers not even complete yet — certainly nothing beyond them.
        None => true,
        // Safe only if the buffer ends exactly at the header terminator.
        Some(end) => replay.len() == end + 4,
    }
}

/// Post-connect "first byte" window. Two phases:
///
/// 1. Nothing forwarded yet — wait *without a deadline* for either the
///    client to send data or the remote to speak first (SSH/SMTP banners).
///    An idle pre-connected tunnel is indistinguishable from a half-dead
///    node at this point, so we must not time out and misjudge the node.
/// 2. Client data has been forwarded — a response is now expected. Wait up
///    to `timeout` for the remote's first byte; the deadline re-arms on
///    every forwarded chunk so a late client request still gets the full
///    budget.
///
/// Returns the remote's first bytes, which the caller splices into the
/// relay. Buffered client bytes stay in `replay` for the caller's failover
/// decision (see [`replay_is_safe`]).
async fn first_byte_window(
    outbound: &mut OutboundStream,
    inbound: &mut TcpStream,
    replay: &mut Vec<u8>,
    timeout: Duration,
) -> Result<Vec<u8>, FirstByteError> {
    match outbound {
        OutboundStream::Tcp(s) => first_byte_window_io(s, inbound, replay, timeout).await,
        OutboundStream::Tls(s) => first_byte_window_io(&mut **s, inbound, replay, timeout).await,
        OutboundStream::Rejected => Err(FirstByteError::Outbound(anyhow::anyhow!(
            "outbound rejected"
        ))),
    }
}

async fn first_byte_window_io<S>(
    outbound: &mut S,
    inbound: &mut TcpStream,
    replay: &mut Vec<u8>,
    timeout: Duration,
) -> Result<Vec<u8>, FirstByteError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut out_buf = vec![0u8; 8192];
    let mut in_buf = vec![0u8; 16384];
    // Set once the client half-closes (FIN) after sending data: stop reading
    // the client but keep waiting for the remote — the response may still be
    // on its way and the client can still receive it.
    let mut client_eof = false;

    // Phase 1: nothing sent yet — wait indefinitely for someone to speak.
    if replay.is_empty() {
        tokio::select! {
            res = outbound.read(&mut out_buf) => {
                match res {
                    Err(e) => return Err(FirstByteError::Outbound(e.into())),
                    Ok(0) => return Err(FirstByteError::RemoteClosed),
                    Ok(n) => return Ok(out_buf[..n].to_vec()),
                }
            }
            res = inbound.read(&mut in_buf) => {
                match res {
                    Err(_) => return Err(FirstByteError::ClientClosed),
                    Ok(0) => return Err(FirstByteError::ClientClosed),
                    Ok(n) => {
                        replay.extend_from_slice(&in_buf[..n]);
                        outbound
                            .write_all(&in_buf[..n])
                            .await
                            .map_err(|e| FirstByteError::Outbound(e.into()))?;
                    }
                }
            }
        }
    } else {
        outbound
            .write_all(replay)
            .await
            .map_err(|e| FirstByteError::Outbound(e.into()))?;
    }

    // Phase 2: client data sent — expect a response within `timeout`,
    // re-armed on every forwarded chunk.
    loop {
        let deadline = tokio::time::Instant::now() + timeout;
        let read_client = !client_eof && replay.len() < crate::retry::MAX_REPLAY_BUFFER;
        tokio::select! {
            res = tokio::time::timeout_at(deadline, outbound.read(&mut out_buf)) => {
                match res {
                    Err(_) => return Err(FirstByteError::TimedOut),
                    Ok(Err(e)) => return Err(FirstByteError::Outbound(e.into())),
                    Ok(Ok(0)) => return Err(FirstByteError::RemoteClosed),
                    Ok(Ok(n)) => return Ok(out_buf[..n].to_vec()),
                }
            }
            res = inbound.read(&mut in_buf), if read_client => {
                match res {
                    Err(_) => return Err(FirstByteError::ClientClosed),
                    Ok(0) => client_eof = true,
                    Ok(n) => {
                        replay.extend_from_slice(&in_buf[..n]);
                        outbound
                            .write_all(&in_buf[..n])
                            .await
                            .map_err(|e| FirstByteError::Outbound(e.into()))?;
                        // Keep waiting; the deadline re-arms next iteration.
                    }
                }
            }
        }
    }
}

/// Write any initial data from HTTP plain proxy plus any already-consumed
/// remote prefix bytes, then relay between inbound and the appropriate
/// outbound stream variant.
async fn relay_streams(
    mut inbound: TcpStream,
    outbound: OutboundStream,
    initial_data: Option<Vec<u8>>,
    remote_prefix: Option<Vec<u8>>,
) -> Result<()> {
    match outbound {
        OutboundStream::Tcp(mut tcp) => {
            if let Some(data) = initial_data {
                tcp.write_all(&data).await?;
            }
            if let Some(prefix) = remote_prefix {
                inbound.write_all(&prefix).await?;
            }
            relay(inbound, tcp).await?;
        }
        OutboundStream::Tls(mut tls) => {
            if let Some(data) = initial_data {
                tls.write_all(&data).await?;
            }
            if let Some(prefix) = remote_prefix {
                inbound.write_all(&prefix).await?;
            }
            relay(&mut inbound, &mut *tls).await?;
        }
        OutboundStream::Rejected => {
            drop(inbound);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Control socket handler
// ---------------------------------------------------------------------------

async fn handle_control(
    stream: tokio::net::UnixStream,
    state: Arc<RwLock<DaemonState>>,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let request: ControlRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = ControlResponse::error(format!("invalid request: {e}"));
                send_response(&mut writer, &resp).await?;
                continue;
            }
        };

        let response = dispatch_control(request, &state).await;
        send_response(&mut writer, &response).await?;
    }

    Ok(())
}

async fn send_response(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    resp: &ControlResponse,
) -> Result<()> {
    let mut payload = serde_json::to_string(resp)?;
    payload.push('\n');
    writer.write_all(payload.as_bytes()).await?;
    Ok(())
}

async fn dispatch_control(
    request: ControlRequest,
    state: &Arc<RwLock<DaemonState>>,
) -> ControlResponse {
    match request {
        ControlRequest::Status => {
            let st = state.read().await;
            let port = st.config.mixed_port.unwrap_or(DEFAULT_MIXED_PORT);
            let mode = format!("{:?}", st.config.mode);
            let allow_lan = st.config.allow_lan.unwrap_or(false);
            let proxy_count = st.proxies.len();
            let rule_count = st.config.rules.len();
            let group_count = st.config.proxy_groups.len();
            let selections: serde_json::Map<String, serde_json::Value> = st
                .config
                .proxy_groups
                .iter()
                .filter_map(|g| {
                    st.selections
                        .get(&g.name)
                        .map(|sel| (g.name.clone(), json!(sel)))
                })
                .collect();
            ControlResponse::success(json!({
                "port": port,
                "mode": mode,
                "allow_lan": allow_lan,
                "config_path": st.config_path.display().to_string(),
                "proxy_count": proxy_count,
                "rule_count": rule_count,
                "group_count": group_count,
                "selections": selections,
            }))
        }

        ControlRequest::Stop => {
            let resp = ControlResponse::ok();
            let port = {
                let st = state.read().await;
                st.config.mixed_port.unwrap_or(DEFAULT_MIXED_PORT)
            };
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                let sysproxy = clashx_rs_sysproxy::SysProxy::new(port);
                if let Err(e) = sysproxy.disable() {
                    tracing::warn!("failed to disable system proxy on stop: {e}");
                }
                let _ = std::fs::remove_file(paths::socket_path(port));
                let _ = std::fs::remove_file(paths::pid_path(port));
                tracing::info!("cleanup complete");
                std::process::exit(0);
            });
            resp
        }

        ControlRequest::Reload => match reload_state(state).await {
            Ok(()) => ControlResponse::ok(),
            Err(e) => ControlResponse::error(format!("reload failed: {e}")),
        },

        ControlRequest::Switch { group, proxy } => {
            let mut st = state.write().await;
            match st.validate_and_set_selection(&group, &proxy) {
                Ok(()) => ControlResponse::success(json!({
                    "group": group,
                    "selected": proxy,
                })),
                Err(e) => ControlResponse::error(e),
            }
        }

        ControlRequest::Proxies => {
            let st = state.read().await;
            let names: Vec<&str> = st.proxies.keys().map(|s| s.as_str()).collect();
            ControlResponse::success(json!(names))
        }

        ControlRequest::Groups => {
            let st = state.read().await;
            let groups: Vec<serde_json::Value> = st
                .config
                .proxy_groups
                .iter()
                .map(|g| {
                    let selected = st.selections.get(&g.name).cloned().unwrap_or_default();
                    json!({
                        "name": g.name,
                        "type": format!("{:?}", g.group_type),
                        "proxies": g.proxies,
                        "selected": selected,
                    })
                })
                .collect();
            ControlResponse::success(json!(groups))
        }

        ControlRequest::Rules => {
            let st = state.read().await;
            ControlResponse::success(json!(st.config.rules))
        }

        ControlRequest::Test { domain } => {
            let st = state.read().await;
            let input = match_input_from_host(&domain);
            let (group, resolved_name, matched_rule) = st.resolve_routing_with_group(&input);
            ControlResponse::success(json!({
                "domain": domain,
                "mode": format!("{:?}", st.config.mode),
                "matched_rule": matched_rule,
                "resolved_proxy": resolved_name,
                "group": group,
            }))
        }

        ControlRequest::Latency { full } => {
            let (proxies, proxy_resolver) = {
                let st = state.read().await;
                (
                    st.proxies.values().cloned().collect::<Vec<Proxy>>(),
                    st.proxy_resolver_handle(),
                )
            };
            let results = if full {
                crate::latency::measure_full(proxies, proxy_resolver).await
            } else {
                crate::latency::measure_tcp(&proxies).await
            };
            ControlResponse::success(serde_json::to_value(&results).unwrap_or_default())
        }

        ControlRequest::DnsFlush { host } => {
            let st = state.read().await;
            // Flush both resolvers (target + proxy-server). The bootstrap
            // cache is intentionally not exposed — a reload clears it.
            match host {
                Some(host) => {
                    let hit_target = st.resolver.invalidate(&host).await;
                    let hit_proxy = st.proxy_resolver.invalidate(&host).await;
                    ControlResponse::success(json!({
                        "host": host,
                        "hit": hit_target || hit_proxy,
                    }))
                }
                None => {
                    let flushed = st.resolver.clear().await + st.proxy_resolver.clear().await;
                    ControlResponse::success(json!({ "flushed": flushed }))
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Subscription auto-update
// ---------------------------------------------------------------------------

/// Minimum sleep between periodic checks (clamps against absurdly small intervals).
const MIN_CHECK_SECS: u64 = 60;
/// Default sleep when no subscriptions are configured.
const IDLE_CHECK_SECS: u64 = 3600;
/// Upper bound on per-tick sleep so newly added subscriptions get picked up within an hour.
const MAX_CHECK_SECS: u64 = 3600;

async fn subscription_auto_update(state: Arc<RwLock<DaemonState>>) {
    loop {
        let config = run_subscription_cycle(&state).await;
        let sleep_secs = compute_sleep_secs(config.as_ref());
        tokio::time::sleep(std::time::Duration::from_secs(sleep_secs)).await;
    }
}

/// Load config, build new DaemonState, reapply overrides — all outside any
/// lock. Swap under a brief write lock so in-flight connections aren't blocked
/// by disk I/O or YAML parsing. On failure, live state is untouched.
///
/// The cooldown tracker is intentionally *not* carried over: the fresh state
/// gets a fresh tracker, so nodes removed or renamed by a subscription update
/// don't leave stale sideline/failure entries behind. Failure memory rebuilds
/// within COOLDOWN_FAILURE_THRESHOLD connections, and the probe supervisor
/// re-reads the new tracker on its next tick.
async fn reload_state(state: &Arc<RwLock<DaemonState>>) -> anyhow::Result<()> {
    let (path, mmdb_path, overrides) = {
        let st = state.read().await;
        (
            st.config_path.clone(),
            st.mmdb_path.clone(),
            st.startup_overrides.clone(),
        )
    };

    let path_for_state = path.clone();
    let new_config = tokio::task::spawn_blocking(move || load_config(&path))
        .await
        .map_err(|e| anyhow::anyhow!("config load task panicked: {e}"))??;

    let mut new_state = DaemonState::from_config(new_config, path_for_state, mmdb_path);
    new_state
        .reapply_overrides(overrides)
        .map_err(|e| anyhow::anyhow!("--select overrides failed: {e}"))?;

    let mut st = state.write().await;
    *st = new_state;
    Ok(())
}

/// Run one download-and-reload pass. Returns the post-cycle config (reused by
/// `compute_sleep_secs`) or None if the subscriptions file couldn't be loaded.
async fn run_subscription_cycle(
    state: &Arc<RwLock<DaemonState>>,
) -> Option<clashx_rs_subscribe::SubscriptionConfig> {
    let mut config =
        match tokio::task::spawn_blocking(clashx_rs_subscribe::load_subscriptions).await {
            Ok(Ok(cfg)) => cfg,
            Ok(Err(e)) => {
                tracing::debug!(err = %e, "skipping subscription cycle: failed to load");
                return None;
            }
            Err(e) => {
                tracing::warn!(err = %e, "subscription load task panicked");
                return None;
            }
        };

    if config.subscriptions.is_empty() {
        return Some(config);
    }

    let results = clashx_rs_subscribe::update_due_subscriptions(&mut config).await;
    if results.is_empty() {
        return Some(config);
    }

    let mut any_success = false;
    for (name, result) in &results {
        match result {
            Ok(()) => {
                tracing::info!(name = %name, "subscription updated");
                any_success = true;
            }
            Err(e) => {
                tracing::warn!(name = %name, err = %e, "subscription update failed");
            }
        }
    }

    if !any_success {
        return Some(config);
    }

    let save_config = config.clone();
    let save_result =
        tokio::task::spawn_blocking(move || clashx_rs_subscribe::save_subscriptions(&save_config))
            .await;
    match save_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::warn!(err = %e, "failed to save subscription state"),
        Err(e) => tracing::warn!(err = %e, "subscription save task panicked"),
    }

    match reload_state(state).await {
        Ok(()) => tracing::info!("daemon reloaded after subscription update"),
        Err(e) => tracing::warn!(err = %e, "reload after subscription update failed"),
    }
    Some(config)
}

/// Sleep duration for the next subscription check: min remaining time across
/// subscriptions, clamped to [MIN_CHECK_SECS, MAX_CHECK_SECS].
fn compute_sleep_secs(config: Option<&clashx_rs_subscribe::SubscriptionConfig>) -> u64 {
    let Some(config) = config else {
        return IDLE_CHECK_SECS;
    };

    if config.subscriptions.is_empty() {
        return IDLE_CHECK_SECS;
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // `None` => no enabled subscriptions to track; idle until one is added/re-enabled.
    config
        .subscriptions
        .iter()
        .filter(|s| s.enabled)
        .map(|s| {
            if s.last_updated == 0 {
                0
            } else {
                (s.last_updated.saturating_add(s.interval)).saturating_sub(now)
            }
        })
        .min()
        .map(|remaining| remaining.clamp(MIN_CHECK_SECS, MAX_CHECK_SECS))
        .unwrap_or(IDLE_CHECK_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clashx_rs_config::types::{GroupType, Proxy, ProxyGroup, Socks5Proxy};
    use clashx_rs_rule::MatchInput;

    use crate::retry::CooldownTracker;

    fn test_config() -> Config {
        Config {
            proxies: vec![
                Proxy::Socks5(Socks5Proxy {
                    name: "🇭🇰 香港 01".to_string(),
                    server: "127.0.0.1".to_string(),
                    port: 1080,
                    username: None,
                    password: None,
                }),
                Proxy::Socks5(Socks5Proxy {
                    name: "🇸🇬 新加坡 01".to_string(),
                    server: "127.0.0.1".to_string(),
                    port: 1081,
                    username: None,
                    password: None,
                }),
                Proxy::Socks5(Socks5Proxy {
                    name: "🇸🇬 新加坡 02".to_string(),
                    server: "127.0.0.1".to_string(),
                    port: 1082,
                    username: None,
                    password: None,
                }),
                Proxy::Socks5(Socks5Proxy {
                    name: "🇭🇰 香港 02".to_string(),
                    server: "127.0.0.1".to_string(),
                    port: 1083,
                    username: None,
                    password: None,
                }),
            ],
            proxy_groups: vec![
                ProxyGroup {
                    name: "🚀 节点选择".to_string(),
                    group_type: GroupType::Select,
                    proxies: vec![
                        "🇭🇰 香港 01".to_string(),
                        "🇸🇬 新加坡 01".to_string(),
                        "🇸🇬 新加坡 02".to_string(),
                        "DIRECT".to_string(),
                    ],
                    health_check: None,
                },
                ProxyGroup {
                    name: "@hk".to_string(),
                    group_type: GroupType::Select,
                    proxies: vec!["🇭🇰 香港 01".to_string(), "🇭🇰 香港 02".to_string()],
                    health_check: None,
                },
            ],
            ..Config::default()
        }
    }

    #[test]
    fn default_selection_is_first_proxy() {
        let state = DaemonState::from_config(
            test_config(),
            PathBuf::from("/tmp/test.yaml"),
            PathBuf::from("/tmp/nonexistent.mmdb"),
        );
        assert_eq!(
            state.selections.get("🚀 节点选择").map(|s| s.as_str()),
            Some("🇭🇰 香港 01")
        );
        assert_eq!(
            state.selections.get("@hk").map(|s| s.as_str()),
            Some("🇭🇰 香港 01")
        );
    }

    #[test]
    fn override_valid_selection() {
        let mut state = DaemonState::from_config(
            test_config(),
            PathBuf::from("/tmp/test.yaml"),
            PathBuf::from("/tmp/nonexistent.mmdb"),
        );
        let overrides = vec!["🚀 节点选择=🇸🇬 新加坡 01".to_string()];
        state.parse_and_apply_overrides(&overrides).unwrap();
        assert_eq!(
            state.selections.get("🚀 节点选择").map(|s| s.as_str()),
            Some("🇸🇬 新加坡 01")
        );
        // Other groups unchanged
        assert_eq!(
            state.selections.get("@hk").map(|s| s.as_str()),
            Some("🇭🇰 香港 01")
        );
    }

    #[test]
    fn override_multiple_groups() {
        let mut state = DaemonState::from_config(
            test_config(),
            PathBuf::from("/tmp/test.yaml"),
            PathBuf::from("/tmp/nonexistent.mmdb"),
        );
        let overrides = vec![
            "🚀 节点选择=🇸🇬 新加坡 02".to_string(),
            "@hk=🇭🇰 香港 02".to_string(),
        ];
        state.parse_and_apply_overrides(&overrides).unwrap();
        assert_eq!(
            state.selections.get("🚀 节点选择").map(|s| s.as_str()),
            Some("🇸🇬 新加坡 02")
        );
        assert_eq!(
            state.selections.get("@hk").map(|s| s.as_str()),
            Some("🇭🇰 香港 02")
        );
    }

    #[test]
    fn override_unknown_group_errors() {
        let mut state = DaemonState::from_config(
            test_config(),
            PathBuf::from("/tmp/test.yaml"),
            PathBuf::from("/tmp/nonexistent.mmdb"),
        );
        let overrides = vec!["nonexistent=🇸🇬 新加坡 01".to_string()];
        let err = state.parse_and_apply_overrides(&overrides).unwrap_err();
        assert!(err.to_string().contains("group not found"));
        assert!(err.to_string().contains("nonexistent"));
    }

    #[test]
    fn override_unknown_proxy_errors() {
        let mut state = DaemonState::from_config(
            test_config(),
            PathBuf::from("/tmp/test.yaml"),
            PathBuf::from("/tmp/nonexistent.mmdb"),
        );
        let overrides = vec!["🚀 节点选择=🇺🇲 美国 01".to_string()];
        let err = state.parse_and_apply_overrides(&overrides).unwrap_err();
        assert!(err.to_string().contains("proxy"));
        assert!(err.to_string().contains("not found in group"));
    }

    #[test]
    fn override_missing_separator_errors() {
        let mut state = DaemonState::from_config(
            test_config(),
            PathBuf::from("/tmp/test.yaml"),
            PathBuf::from("/tmp/nonexistent.mmdb"),
        );
        let overrides = vec!["no-separator-here".to_string()];
        let err = state.parse_and_apply_overrides(&overrides).unwrap_err();
        assert!(err.to_string().contains("invalid --select format"));
    }

    #[test]
    fn override_empty_list_is_noop() {
        let mut state = DaemonState::from_config(
            test_config(),
            PathBuf::from("/tmp/test.yaml"),
            PathBuf::from("/tmp/nonexistent.mmdb"),
        );
        let original = state.selections.clone();
        state.parse_and_apply_overrides(&[]).unwrap();
        assert_eq!(state.selections, original);
    }

    #[test]
    fn resolve_with_group_returns_group_for_group_target() {
        let mut config = test_config();
        config.rules = vec!["DOMAIN-SUFFIX,example.com,🚀 节点选择".to_string()];
        config.mode = Mode::Rule;
        let state = DaemonState::from_config(
            config,
            PathBuf::from("/tmp/test.yaml"),
            PathBuf::from("/tmp/nonexistent.mmdb"),
        );
        let input = MatchInput {
            host: Some("test.example.com"),
            ip: None,
            process_name: None,
            ..Default::default()
        };
        let (group, proxy, _rule) = state.resolve_routing_with_group(&input);
        assert_eq!(group, Some("🚀 节点选择"));
        assert_eq!(proxy, "🇭🇰 香港 01"); // first proxy = default selection
    }

    #[test]
    fn resolve_with_group_returns_none_for_direct() {
        let mut config = test_config();
        config.mode = Mode::Direct;
        let state = DaemonState::from_config(
            config,
            PathBuf::from("/tmp/test.yaml"),
            PathBuf::from("/tmp/nonexistent.mmdb"),
        );
        let input = MatchInput {
            host: Some("anything.com"),
            ip: None,
            process_name: None,
            ..Default::default()
        };
        let (group, proxy, _rule) = state.resolve_routing_with_group(&input);
        assert_eq!(group, None);
        assert_eq!(proxy, "DIRECT");
    }

    #[test]
    fn build_candidates_selected_first_then_rest() {
        let config = test_config();
        let mut state = DaemonState::from_config(
            config,
            PathBuf::from("/tmp/test.yaml"),
            PathBuf::from("/tmp/nonexistent.mmdb"),
        );
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
    fn build_candidates_demotes_degraded_but_keeps_them() {
        let config = test_config();
        let mut state = DaemonState::from_config(
            config,
            PathBuf::from("/tmp/test.yaml"),
            PathBuf::from("/tmp/nonexistent.mmdb"),
        );
        state
            .selections
            .insert("🚀 节点选择".to_string(), "🇸🇬 新加坡 01".to_string());
        let tracker = CooldownTracker::new();
        tracker.degrade("🇸🇬 新加坡 01");
        let candidates = state.build_candidate_list("🚀 节点选择", &tracker);
        // Degraded selected node sinks to the end but is never excluded.
        assert_eq!(candidates[0].0, "🇭🇰 香港 01");
        assert_eq!(candidates.last().unwrap().0, "🇸🇬 新加坡 01");
    }

    #[test]
    fn probe_schedule_lists_unique_members_without_direct() {
        let state = DaemonState::from_config(
            test_config(),
            PathBuf::from("/tmp/test.yaml"),
            PathBuf::from("/tmp/nonexistent.mmdb"),
        );
        let schedule = state.probe_schedule();
        let names: Vec<&str> = schedule.iter().map(|(n, _)| n.as_str()).collect();
        // 🇭🇰 香港 01 appears in both groups but is listed once; DIRECT is excluded.
        assert_eq!(names.len(), 4);
        assert!(names.contains(&"🇭🇰 香港 01"));
        assert!(names.contains(&"🇭🇰 香港 02"));
        assert!(names.contains(&"🇸🇬 新加坡 01"));
        assert!(names.contains(&"🇸🇬 新加坡 02"));
        assert!(!names.contains(&"DIRECT"));
        // Every scheduled node has a fetchable config and an enabled hc.
        for (name, hc) in &schedule {
            assert!(hc.enable);
            assert!(state.proxy_named(name).is_some());
        }
        assert!(state.proxy_named("no-such-node").is_none());
    }

    #[test]
    fn build_candidates_filters_cooled_down() {
        let config = test_config();
        let state = DaemonState::from_config(
            config,
            PathBuf::from("/tmp/test.yaml"),
            PathBuf::from("/tmp/nonexistent.mmdb"),
        );
        let tracker = CooldownTracker::new();
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
        config.proxy_groups.retain(|g| g.name == "@hk");
        let state = DaemonState::from_config(
            config,
            PathBuf::from("/tmp/test.yaml"),
            PathBuf::from("/tmp/nonexistent.mmdb"),
        );
        let tracker = CooldownTracker::new();
        for _ in 0..crate::retry::COOLDOWN_FAILURE_THRESHOLD {
            tracker.record_failure("🇭🇰 香港 01");
            tracker.record_failure("🇭🇰 香港 02");
        }
        let candidates = state.build_candidate_list("@hk", &tracker);
        assert_eq!(
            candidates.len(),
            2,
            "all-cooled-down should still include all"
        );
    }

    /// Outer Select group whose first member is another Select group.
    fn nested_group_config() -> Config {
        let mut config = test_config();
        config.proxy_groups.push(ProxyGroup {
            name: "🐟 漏网之鱼".to_string(),
            group_type: GroupType::Select,
            proxies: vec!["🚀 节点选择".to_string(), "DIRECT".to_string()],
            health_check: None,
        });
        config.mode = Mode::Rule;
        config.rules = vec!["MATCH,🐟 漏网之鱼".to_string()];
        config
    }

    #[test]
    fn nested_group_resolves_to_inner_leaf() {
        let mut state = DaemonState::from_config(
            nested_group_config(),
            PathBuf::from("/tmp/test.yaml"),
            PathBuf::from("/tmp/nonexistent.mmdb"),
        );
        // Pin the inner selection so the expectation doesn't depend on the
        // default "first proxy" rule.
        state
            .parse_and_apply_overrides(&["🚀 节点选择=🇸🇬 新加坡 01".to_string()])
            .unwrap();

        let input = MatchInput {
            host: Some("bun.com"),
            ip: None,
            process_name: None,
            ..Default::default()
        };
        let (group, proxy, _rule) = state.resolve_routing_with_group(&input);

        // The innermost group is returned so failover tries siblings of the
        // selected leaf, not members of the outer fallback group.
        assert_eq!(group, Some("🚀 节点选择"));
        assert_eq!(proxy, "🇸🇬 新加坡 01");
    }

    #[test]
    fn nested_group_candidate_list_is_non_empty() {
        let mut state = DaemonState::from_config(
            nested_group_config(),
            PathBuf::from("/tmp/test.yaml"),
            PathBuf::from("/tmp/nonexistent.mmdb"),
        );
        state
            .parse_and_apply_overrides(&["🚀 节点选择=🇸🇬 新加坡 01".to_string()])
            .unwrap();

        let input = MatchInput {
            host: Some("bun.com"),
            ip: None,
            process_name: None,
            ..Default::default()
        };
        let (group, _proxy, _rule) = state.resolve_routing_with_group(&input);
        let tracker = CooldownTracker::new();
        let candidates = state.build_candidate_list(group.unwrap(), &tracker);

        assert!(
            !candidates.is_empty(),
            "nested-group resolution must yield a non-empty candidate pool"
        );
        assert_eq!(candidates[0].0, "🇸🇬 新加坡 01");
    }

    #[test]
    fn selection_chain_cycle_does_not_hang() {
        let mut config = test_config();
        config.proxy_groups = vec![
            ProxyGroup {
                name: "A".to_string(),
                group_type: GroupType::Select,
                proxies: vec!["B".to_string()],
                health_check: None,
            },
            ProxyGroup {
                name: "B".to_string(),
                group_type: GroupType::Select,
                proxies: vec!["A".to_string()],
                health_check: None,
            },
        ];
        config.mode = Mode::Rule;
        config.rules = vec!["MATCH,A".to_string()];
        let state = DaemonState::from_config(
            config,
            PathBuf::from("/tmp/test.yaml"),
            PathBuf::from("/tmp/nonexistent.mmdb"),
        );

        let input = MatchInput {
            host: Some("example.com"),
            ip: None,
            process_name: None,
            ..Default::default()
        };
        let (_group, proxy, _rule) = state.resolve_routing_with_group(&input);
        assert_eq!(proxy, "DIRECT");
    }

    #[tokio::test]
    async fn latency_handler_returns_empty_array_with_no_proxies() {
        let config = Config::default();
        let state = Arc::new(RwLock::new(DaemonState::from_config(
            config,
            PathBuf::from("/tmp/test.yaml"),
            PathBuf::from("/tmp/nonexistent.mmdb"),
        )));
        let resp = dispatch_control(ControlRequest::Latency { full: false }, &state).await;
        assert!(resp.ok);
        let data = resp.data.unwrap();
        let arr = data.as_array().unwrap();
        assert!(arr.is_empty());
    }

    #[tokio::test]
    async fn latency_handler_returns_results_with_proxies() {
        let state = Arc::new(RwLock::new(DaemonState::from_config(
            test_config(),
            PathBuf::from("/tmp/test.yaml"),
            PathBuf::from("/tmp/nonexistent.mmdb"),
        )));
        let resp = dispatch_control(ControlRequest::Latency { full: false }, &state).await;
        assert!(resp.ok);
        let data = resp.data.unwrap();
        let arr = data.as_array().unwrap();
        // test_config has 4 proxies, all targeting 127.0.0.1 (should succeed fast)
        assert!(!arr.is_empty());
        for entry in arr {
            // All local connections should have a latency or an error
            let obj = entry.as_object().unwrap();
            assert!(obj.contains_key("name"));
            assert!(obj.contains_key("proxy_type"));
            assert!(obj.contains_key("tcp_ms") || obj.contains_key("error"));
        }
    }

    // -----------------------------------------------------------------------
    // first_byte_window tests (loopback only — no external network, no ports
    // used by a live daemon).
    // -----------------------------------------------------------------------

    async fn loopback_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn first_byte_remote_speaks_first() {
        let (outbound, mut remote) = loopback_pair().await;
        let (mut inbound, _client) = loopback_pair().await;

        tokio::spawn(async move {
            remote.write_all(b"SERVER-HELLO").await.unwrap();
        });

        let mut os = OutboundStream::Tcp(outbound);
        let mut replay = Vec::new();
        let prefix = first_byte_window(&mut os, &mut inbound, &mut replay, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(prefix, b"SERVER-HELLO");
        assert!(replay.is_empty());
    }

    #[tokio::test]
    async fn first_byte_silent_remote_no_deadline_before_client_data() {
        // Idle tunnel (nothing sent): the window must NOT time out — an idle
        // pre-connected tunnel is indistinguishable from a half-dead node.
        let (outbound, _remote) = loopback_pair().await;
        let (mut inbound, _client) = loopback_pair().await;

        let mut os = OutboundStream::Tcp(outbound);
        let mut replay = Vec::new();
        let res = tokio::time::timeout(
            Duration::from_millis(300),
            first_byte_window(
                &mut os,
                &mut inbound,
                &mut replay,
                Duration::from_millis(100),
            ),
        )
        .await;
        assert!(
            res.is_err(),
            "window must stay pending while nothing is sent"
        );
    }

    #[tokio::test]
    async fn first_byte_silent_remote_times_out_after_data_sent() {
        // Initial data (HTTP plain-proxy path) counts as sent: the remote
        // must respond within the budget.
        let (outbound, _remote) = loopback_pair().await;
        let (mut inbound, _client) = loopback_pair().await;

        let mut os = OutboundStream::Tcp(outbound);
        let mut replay = b"GET / HTTP/1.1\r\n\r\n".to_vec();
        let err = first_byte_window(
            &mut os,
            &mut inbound,
            &mut replay,
            Duration::from_millis(200),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, FirstByteError::TimedOut));
    }

    #[tokio::test]
    async fn first_byte_deadline_rearms_on_client_write() {
        // Client sends at ~150ms; remote answers 150ms after that. With a
        // 200ms budget armed only after the client write, this must succeed —
        // a fixed window from connect time would have timed out at 200ms.
        let (outbound, mut remote) = loopback_pair().await;
        let (mut inbound, mut client) = loopback_pair().await;

        tokio::spawn(async move {
            let mut buf = [0u8; 4];
            remote.read_exact(&mut buf).await.unwrap();
            tokio::time::sleep(Duration::from_millis(150)).await;
            remote.write_all(b"RESP").await.unwrap();
        });
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            client.write_all(b"PING").await.unwrap();
        });

        let mut os = OutboundStream::Tcp(outbound);
        let mut replay = Vec::new();
        let prefix = first_byte_window(
            &mut os,
            &mut inbound,
            &mut replay,
            Duration::from_millis(200),
        )
        .await
        .unwrap();
        assert_eq!(prefix, b"RESP");
        assert_eq!(replay, b"PING");
    }

    #[tokio::test]
    async fn first_byte_forwards_client_data_and_replays() {
        let (outbound, mut remote) = loopback_pair().await;
        let (mut inbound, mut client) = loopback_pair().await;

        // Remote: expect the buffered replay bytes, then the client's chunk,
        // then respond.
        tokio::spawn(async move {
            let mut buf = [0u8; 4];
            remote.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"INIT");
            let mut buf = [0u8; 6];
            remote.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"CLIENT");
            remote.write_all(b"RESP").await.unwrap();
        });

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            client.write_all(b"CLIENT").await.unwrap();
        });

        let mut os = OutboundStream::Tcp(outbound);
        let mut replay = b"INIT".to_vec();
        let prefix = first_byte_window(&mut os, &mut inbound, &mut replay, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(prefix, b"RESP");
        // Both chunks are buffered for a potential failover replay.
        assert_eq!(replay, b"INITCLIENT");
    }

    #[tokio::test]
    async fn first_byte_client_close_aborts() {
        let (outbound, _remote) = loopback_pair().await;
        let (mut inbound, client) = loopback_pair().await;
        drop(client);

        let mut os = OutboundStream::Tcp(outbound);
        let mut replay = Vec::new();
        let err = first_byte_window(&mut os, &mut inbound, &mut replay, Duration::from_secs(2))
            .await
            .unwrap_err();
        assert!(matches!(err, FirstByteError::ClientClosed));
    }

    #[tokio::test]
    async fn first_byte_remote_close_is_remote_closed() {
        let (outbound, remote) = loopback_pair().await;
        let (mut inbound, _client) = loopback_pair().await;
        drop(remote);

        let mut os = OutboundStream::Tcp(outbound);
        let mut replay = Vec::new();
        let err = first_byte_window(&mut os, &mut inbound, &mut replay, Duration::from_secs(2))
            .await
            .unwrap_err();
        assert!(matches!(err, FirstByteError::RemoteClosed));
    }

    #[test]
    fn replay_safety_rules() {
        assert!(replay_is_safe(b""));
        // TLS ClientHello (record type 0x16, version 0x0301).
        assert!(replay_is_safe(&[0x16, 0x03, 0x01, 0x00, 0x2a]));
        // Idempotent HTTP methods, headers only.
        assert!(replay_is_safe(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"));
        assert!(replay_is_safe(b"HEAD /h HTTP/1.0\r\n\r\n"));
        assert!(replay_is_safe(b"OPTIONS * HTTP/1.1\r\n\r\n"));
        // Incomplete headers — nothing beyond them can exist.
        assert!(replay_is_safe(b"GET / HTTP/1.1\r\nHost: x\r\n"));
        // Anything after the header terminator (body or pipelined request)
        // makes the buffer non-replayable, even for idempotent methods.
        assert!(!replay_is_safe(b"PUT /x HTTP/1.1\r\n\r\n{\"a\":1}"));
        assert!(!replay_is_safe(
            b"GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\n\r\n"
        ));
        assert!(!replay_is_safe(
            b"DELETE /x HTTP/1.1\r\n\r\nPOST /y HTTP/1.1\r\n\r\n"
        ));
        // Non-idempotent / non-replayable.
        assert!(!replay_is_safe(b"POST /submit HTTP/1.1\r\n\r\n"));
        assert!(!replay_is_safe(b"PATCH /x HTTP/1.1\r\n\r\n"));
        assert!(!replay_is_safe(&[0x05, 0x01, 0x00])); // SOCKS5 greeting
    }
}
