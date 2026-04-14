use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use clashx_rs_config::load_config;
use clashx_rs_config::types::{Config, Mode, Proxy};
use clashx_rs_geoip::GeoIpDb;
use clashx_rs_proxy::inbound::{self, InboundResult};
use clashx_rs_proxy::outbound::{self, OutboundStream};
use clashx_rs_proxy::relay::relay;
use clashx_rs_rule::{process::lookup_process_name, MatchInput, RuleEngine};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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
    }
}

/// Max concurrent connections before admission control starts rejecting.
/// For a desktop local proxy this is far above normal browser workloads
/// (hundreds of parallel fetches). Abusive/buggy clients are bounded here.
const MAX_CONCURRENT_CONNECTIONS: usize = 2048;

struct DaemonState {
    config: Config,
    config_path: PathBuf,
    rule_engine: Arc<RuleEngine>,
    proxies: HashMap<String, Proxy>,
    selections: HashMap<String, String>,
    startup_overrides: Vec<(String, String)>,
    cooldown: Arc<crate::retry::CooldownTracker>,
    mmdb_path: PathBuf,
    nameservers: Arc<[IpAddr]>,
    dns_cache: Arc<clashx_rs_dns::DnsCache>,
    /// Cached at construction: true iff any PROCESS-NAME rule exists.
    has_process_rules: bool,
}

impl DaemonState {
    fn from_config(config: Config, config_path: PathBuf, mmdb_path: PathBuf) -> Self {
        // Extract plain IP nameservers from dns config for direct DNS queries.
        // Skip DoH/DoT URLs — only use plain IPs (e.g., 223.5.5.5, 119.29.29.29).
        let nameservers: Arc<[IpAddr]> = config
            .dns
            .as_ref()
            .map(|d| {
                d.nameserver
                    .iter()
                    .chain(d.default_nameserver.iter())
                    .filter_map(|s| s.parse::<IpAddr>().ok())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
            .into();
        if !nameservers.is_empty() {
            tracing::info!(?nameservers, "using config nameservers for DNS pre-resolve");
        }

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

        let has_process_rules = config.rules.iter().any(|r| r.starts_with("PROCESS-NAME,"));
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
            nameservers,
            dns_cache: Arc::new(clashx_rs_dns::DnsCache::new()),
            has_process_rules,
        }
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
        let final_list = if filtered.is_empty() {
            &ordered
        } else {
            &filtered
        };

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
        stream: inbound_stream,
        initial_data,
        source_addr: _,
    } = inbound::detect_and_handle(stream, source_addr).await?;

    let target_host = target.host_string();
    let target_port = target.port();

    let parsed_ip: Option<std::net::IpAddr> = target_host.parse().ok();

    let (nameservers, dns_cache, need_process, rule_engine, mode) = {
        let st = state.read().await;
        (
            Arc::clone(&st.nameservers),
            Arc::clone(&st.dns_cache),
            st.config.mode == Mode::Rule && st.has_process_rules,
            Arc::clone(&st.rule_engine),
            st.config.mode,
        )
    };

    // Process lookup runs concurrently with the first rule-eval pass —
    // independent work.
    let process_fut = async {
        if need_process {
            lookup_process_name(source_addr).await
        } else {
            None
        }
    };

    let process_name = process_fut.await;

    let host_field: Option<&str> = if parsed_ip.is_some() {
        None
    } else {
        Some(&target_host)
    };

    let (rule_target, matched_rule, resolved_ip): (Option<&str>, Option<String>, Option<IpAddr>) =
        if mode == Mode::Rule {
            use clashx_rs_rule::EvalStep;
            let mut input = MatchInput {
                host: host_field,
                ip: parsed_ip,
                process_name: process_name.as_deref(),
            };
            match rule_engine.evaluate_until_ip_needed(&input) {
                EvalStep::Matched(rule) => {
                    (Some(rule.target()), Some(rule.description()), parsed_ip)
                }
                EvalStep::NoMatch => (None, None, parsed_ip),
                EvalStep::NeedsIp { resume_from } => {
                    // Only pay DNS when rule eval actually reaches an IP-dependent
                    // rule. Domain/process rules before it have already been checked.
                    let ip = match clashx_rs_dns::resolve_with_nameservers(
                        &target_host,
                        &nameservers,
                        &dns_cache,
                    )
                    .await
                    {
                        Ok(ip) => {
                            tracing::debug!(host = %target_host, resolved = %ip, "DNS pre-resolved");
                            Some(ip)
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
                    input.ip = ip;
                    match rule_engine.resume_from(&input, resume_from) {
                        Some(rule) => (Some(rule.target()), Some(rule.description()), ip),
                        None => (None, None, ip),
                    }
                }
            }
        } else {
            (None, None, parsed_ip)
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
            Mode::Rule => rule_target,
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
            rule = ?matched_rule,
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
            let outbound = connect_with_retry("DIRECT", &target_host, || {
                outbound::direct::connect(&target, resolved_ip)
            })
            .await?;
            relay_streams(inbound_stream, outbound, initial_data).await?;
            Ok(())
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

                match connect_with_retry(cand_name, &target_host, || {
                    connect_outbound(cand_proxy, &target)
                })
                .await
                {
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
            Err(last_err.unwrap())
        }
    }
}

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

/// Retry an async connect function with backoff.
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
                tracing::debug!(
                    proxy = %label,
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

/// Write any initial data from HTTP plain proxy, then relay between inbound and
/// the appropriate outbound stream variant.
async fn relay_streams(
    mut inbound: TcpStream,
    outbound: OutboundStream,
    initial_data: Option<Vec<u8>>,
) -> Result<()> {
    match outbound {
        OutboundStream::Tcp(mut tcp) => {
            if let Some(data) = initial_data {
                tcp.write_all(&data).await?;
            }
            relay(inbound, tcp).await?;
        }
        OutboundStream::Tls(mut tls) => {
            if let Some(data) = initial_data {
                tls.write_all(&data).await?;
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

        ControlRequest::Reload => {
            let mut st = state.write().await;
            let path = st.config_path.clone();
            let mmdb_path = st.mmdb_path.clone();
            let overrides = std::mem::take(&mut st.startup_overrides);
            let cooldown = Arc::clone(&st.cooldown);
            match load_config(&path) {
                Ok(new_config) => {
                    let mut new_state = DaemonState::from_config(new_config, path, mmdb_path);
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
    }
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
                },
                ProxyGroup {
                    name: "@hk".to_string(),
                    group_type: GroupType::Select,
                    proxies: vec!["🇭🇰 香港 01".to_string(), "🇭🇰 香港 02".to_string()],
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
            },
            ProxyGroup {
                name: "B".to_string(),
                group_type: GroupType::Select,
                proxies: vec!["A".to_string()],
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
        };
        let (_group, proxy, _rule) = state.resolve_routing_with_group(&input);
        assert_eq!(proxy, "DIRECT");
    }
}
