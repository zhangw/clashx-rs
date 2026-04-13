# GEOIP Rule Support Design Spec

## 1. Context

clashx-rs parses Clash-compatible YAML configs with a top-to-bottom rule engine. GEOIP rules (`GEOIP,CN,DIRECT`) are already parsed into `RuleEntry::GeoIp { country, target }` but matching is stubbed to always return `false`. Most real-world Clash configs contain GEOIP rules, so without a working implementation traffic gets silently mis-routed — those rules are skipped and connections fall through to later rules or the catch-all.

This change implements real GEOIP matching by loading a MaxMind-format mmdb database, looking up the country code for each connection's IP, and comparing it against the rule's country field. It also provides two ways to obtain the mmdb file, solving the chicken-and-egg problem where the proxy itself is needed to download the database.

**Critical prerequisite**: GEOIP rules need an IP address to look up, but most proxy traffic arrives as domain names (e.g., `baidu.com`). Currently `MatchInput.ip` is only set for IP-literal targets — domain targets have `ip: None`. Without DNS resolution before rule evaluation, GEOIP rules would never match domain-based traffic, making them effectively useless. This spec includes pre-resolve DNS integration to fix this.

## 2. Architecture

### New crate: `crates/geoip`

Isolates all mmdb concerns (file loading, IP-to-country lookup, HTTP download) from the rule engine. Keeps the `rule` crate free of network/IO dependencies.

### Dependency diagram

```
src/main.rs  (adds mmdb-download subcommand, --mmdb/--mmdb-auto-download flags)
    |
    v
src/daemon.rs  (loads mmdb, pre-resolves DNS, passes GeoIpDb to RuleEngine)
    |
    +---> crates/geoip  (GeoIpDb, download_mmdb)
    |         |
    |         +---> maxminddb   (mmdb parsing)
    |         +---> reqwest     (HTTP download, with socks feature)
    |
    +---> crates/dns    (resolve host → IP before rule evaluation)
    |
    +---> crates/rule   (RuleEngine gains Option<Arc<GeoIpDb>> field)
              |
              +---> crates/geoip  (for GeoIpDb lookup)
```

### New workspace dependencies

```toml
maxminddb = "0.24"
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "socks"] }
```

## 3. GeoIpDb API

File: `crates/geoip/src/lib.rs`

```rust
pub struct GeoIpDb {
    reader: maxminddb::Reader<Vec<u8>>,
}

impl GeoIpDb {
    /// Load an mmdb file from disk.
    pub fn open(path: &Path) -> Result<Self, GeoIpError>;

    /// Look up ISO 3166-1 alpha-2 country code for an IP address.
    /// Returns None if the IP is not in the database (e.g., private ranges).
    pub fn lookup_country(&self, ip: IpAddr) -> Option<String>;
}

pub enum GeoIpError {
    Open(PathBuf, maxminddb::MaxMindDBError),
    Download(String),
}
```

Key points:
- `GeoIpDb` is `Send + Sync` — wrapped in `Arc` for shared ownership
- `lookup_country` returns `Option`, not `Result` — missing entry is not an error
- Country codes are uppercased to match config parse behavior (`rule.rs` uppercases during parse)

## 4. Download Logic

File: `crates/geoip/src/download.rs`

```rust
pub const DEFAULT_MMDB_URL: &str =
    "https://github.com/Dreamacro/maxmind-geoip/releases/latest/download/Country.mmdb";

pub async fn download_mmdb(
    url: Option<&str>,
    proxy: Option<&str>,
    output_path: &Path,
) -> Result<(), GeoIpError>;
```

### Behavior

1. Build `reqwest::Client` with optional proxy via `reqwest::Proxy::all(proxy_url)`
2. GET the URL, follow redirects
3. Stream response body to `{output_path}.tmp`
4. Atomically rename `.tmp` to final path (prevents partial file from being loaded concurrently)
5. On failure, delete temp file, return `GeoIpError::Download`

### Retry strategy

- **CLI `mmdb-download`**: no auto-retry — user re-runs manually. Clear error message with URL and failure reason.
- **Daemon `--mmdb-auto-download`**: 3 attempts with exponential backoff (10s, 30s, 90s). On final failure, log warning and continue without GEOIP.

## 5. CLI Changes

### New subcommand: `mmdb-download` (Priority 1)

```
clashx-rs mmdb-download [--proxy URL] [--url URL] [--output PATH]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--proxy` | none | SOCKS5/HTTP proxy URL for the download |
| `--url` | `DEFAULT_MMDB_URL` | Override download URL |
| `--output` | `~/.config/clashx-rs/Country.mmdb` | Output file path |

Examples:
```bash
# Download through the running daemon
clashx-rs mmdb-download --proxy socks5://127.0.0.1:7890

# Custom mirror
clashx-rs mmdb-download --url https://my-mirror.example.com/Country.mmdb
```

### New flags on `run` subcommand (Priority 2)

| Flag | Default | Description |
|------|---------|-------------|
| `--mmdb PATH` | `~/.config/clashx-rs/Country.mmdb` | Override mmdb file path |
| `--mmdb-auto-download` | false | If mmdb missing, download in background after proxy starts |

## 6. DNS Pre-Resolution for Rule Evaluation

### The problem

Currently `MatchInput.host` and `MatchInput.ip` are mutually exclusive — if the target is a domain, `ip` is `None`. GEOIP (and IP-CIDR) rules need an IP to match against. Without DNS resolution, GEOIP rules are useless for domain-based traffic (which is ~99% of real traffic).

### Solution: pre-resolve in daemon before rule evaluation

The daemon resolves the domain to an IP **before** calling `rule_engine.evaluate()`. Both `host` and `ip` are populated on `MatchInput`. The rule engine stays synchronous — no async changes needed.

The existing `crates/dns` crate provides `pub async fn resolve(host: &str) -> Result<IpAddr>` (currently unused). This is exactly what we need.

### MatchInput changes

File: `crates/rule/src/lib.rs`

`host` and `ip` are **no longer mutually exclusive**:

```rust
pub struct MatchInput<'a> {
    pub host: Option<&'a str>,       // domain name (if target is a domain)
    pub ip: Option<IpAddr>,          // IP address (parsed directly OR resolved from domain)
    pub process_name: Option<&'a str>,
}
```

### Daemon connection handling changes

File: `src/daemon.rs`

Before rule evaluation, the daemon now resolves domains:

```rust
// Before (current):
let ip: Option<IpAddr> = target_host.parse().ok();
let match_input = MatchInput {
    host: if ip.is_some() { None } else { Some(&target_host) },
    ip,
    process_name: ...,
};

// After (new):
let parsed_ip: Option<IpAddr> = target_host.parse().ok();
let resolved_ip = if parsed_ip.is_some() {
    parsed_ip
} else {
    // Domain target: resolve DNS to get IP for GEOIP/IP-CIDR rules
    match clashx_rs_dns::resolve(&target_host).await {
        Ok(ip) => Some(ip),
        Err(e) => {
            tracing::debug!(host = %target_host, err = %e, "DNS pre-resolve failed, IP-based rules will skip");
            None
        }
    }
};

let match_input = MatchInput {
    host: if parsed_ip.is_some() { None } else { Some(&target_host) },
    ip: resolved_ip,  // populated for BOTH IP literals and resolved domains
    process_name: ...,
};
```

**Key behaviors:**
- IP-literal target: `host=None`, `ip=Some(parsed)` — same as before
- Domain target, DNS succeeds: `host=Some("baidu.com")`, `ip=Some(resolved)` — **new: both set**
- Domain target, DNS fails: `host=Some("baidu.com")`, `ip=None` — GEOIP/IP-CIDR rules skip, domain rules still work
- DNS failure is **not fatal** — just means IP-based rules won't match this connection

### `no-resolve` support (future)

Clash supports a `no-resolve` suffix on GEOIP and IP-CIDR rules to skip DNS resolution. With pre-resolve, DNS happens unconditionally. A `no-resolve` flag could be parsed and stored on the rule entry to mean "only match if the original target was an IP literal, not a DNS-resolved domain". This is deferred — the current implementation always resolves and always checks.

## 7. Rule Engine Integration

### RuleEngine changes

File: `crates/rule/src/lib.rs`

```rust
pub struct RuleEngine {
    rules: Vec<RuleEntry>,
    geoip_db: Option<Arc<GeoIpDb>>,
}

impl RuleEngine {
    pub fn new(raw_rules: &[String], geoip_db: Option<Arc<GeoIpDb>>) -> Self;

    /// Hot-swap the GeoIP database after background download completes.
    pub fn set_geoip_db(&mut self, db: Arc<GeoIpDb>);
}
```

### Matching logic

The existing `matches_rule` function gains a `geoip_db: Option<&GeoIpDb>` parameter:

```rust
RuleEntry::GeoIp { country, .. } => {
    let Some(db) = geoip_db else { return false };
    let Some(ip) = input.ip else { return false };
    db.lookup_country(ip)
        .map(|c| c == *country)
        .unwrap_or(false)
}
```

The rule engine itself stays fully synchronous. It just reads whatever `ip` value the daemon put into `MatchInput` — it doesn't care whether that IP was parsed from a literal or resolved from DNS.

## 8. Daemon Startup Flow

```
1. Load config, parse rules                          (existing)
2. Load mmdb from --mmdb path or default:
   - GeoIpDb::open(path) -> Ok(db) => Some(Arc::new(db))
   -                      -> Err(_) => log warning, None
3. Create RuleEngine::new(&rules, geoip_db)          (modified)
4. Start proxy listener                              (existing, non-GEOIP rules work immediately)
5. If --mmdb-auto-download AND geoip_db is None:
   a. Spawn background tokio task
   b. Wait 2s for proxy to fully start
   c. Download through own proxy: socks5://127.0.0.1:{mixed_port}
   d. Up to 3 attempts: 10s/30s/90s backoff
   e. On success: load mmdb, call rule_engine.set_geoip_db()
   f. On failure: log warning, continue without GEOIP
```

### Reload behavior

On `Reload` control command, the daemon re-opens the mmdb from `mmdb_path`. If it fails, reload still succeeds for config changes — GEOIP remains in its previous state.

## 9. Graceful Degradation

| Scenario | Behavior |
|----------|----------|
| mmdb missing at startup | Warning logged, GEOIP rules skip, all other rules work |
| mmdb corrupt/invalid | Same as missing |
| mmdb missing + `--mmdb-auto-download` | Proxy starts immediately, background download spawned, GEOIP activates when download completes |
| Auto-download fails all retries | Warning logged, GEOIP rules remain inactive, proxy fully functional |
| IP not in mmdb (private range) | `lookup_country` returns None, GEOIP rule doesn't match, next rule evaluated |
| DNS pre-resolve fails (domain target) | `ip` stays None, GEOIP/IP-CIDR rules skip, domain rules still work, connection proceeds |
| DNS pre-resolve succeeds | `ip` populated, GEOIP matches against resolved IP |

**Key principles:**
- **GEOIP is always optional.** The proxy never fails to start due to GEOIP issues.
- **DNS failure is not fatal.** If pre-resolve fails, IP-based rules skip but domain rules and the connection itself still work (outbound `TcpStream::connect` does its own resolution).

## 10. Testing Strategy

### Unit tests (automated, CI)

**`crates/geoip`**: tests with a bundled test mmdb fixture (~20KB, committed to `crates/geoip/tests/fixtures/`):
- `test_lookup_known_ip` — verify known IP → country code mapping
- `test_lookup_private_ip_returns_none` — 192.168.1.1 → None
- `test_lookup_ipv6` — IPv6 lookup works
- `test_open_nonexistent_file` — returns GeoIpError::Open
- `test_open_invalid_file` — non-mmdb file → error

**`crates/rule`**: GEOIP matching integration:
- `test_geoip_matches_when_db_present` — RuleEngine with test GeoIpDb, verify match
- `test_geoip_no_match_wrong_country` — IP in db but different country
- `test_geoip_no_match_when_db_absent` — RuleEngine with None, verify false (update existing stub test)
- `test_geoip_no_match_when_ip_none` — MatchInput with ip: None
- `test_geoip_rule_ordering` — GEOIP between other rules, first-match-wins

### Network-dependent tests (gated, `#[ignore]`)

- `test_download_to_temp_dir` — downloads from real URL, verifies valid mmdb

### Manual testing

- Start daemon → `clashx-rs mmdb-download --proxy socks5://127.0.0.1:7890` → verify file appears
- Start daemon with `--mmdb-auto-download` → observe hot-swap in logs
- Config with `GEOIP,CN,DIRECT` + `MATCH,Proxy` → visit `baidu.com` → verify DNS pre-resolves to CN IP → DIRECT routing
- Config with `GEOIP,CN,DIRECT` + `MATCH,Proxy` → visit `google.com` → verify DNS resolves to non-CN IP → Proxy routing
- Start without mmdb → verify warning and proxy works for other rules

## 11. Files to Modify

### New files

| File | Purpose |
|------|---------|
| `crates/geoip/Cargo.toml` | Crate manifest: `maxminddb`, `reqwest`, `tracing`, `anyhow`, `tokio` |
| `crates/geoip/src/lib.rs` | `GeoIpDb`, `GeoIpError`, `open()`, `lookup_country()` |
| `crates/geoip/src/download.rs` | `download_mmdb()`, `DEFAULT_MMDB_URL` |
| `crates/geoip/tests/fixtures/` | Test mmdb fixture file |

### Existing files

| File | Changes |
|------|---------|
| `Cargo.toml` (root) | Add `crates/geoip` to members, `maxminddb`/`reqwest` to workspace deps, `clashx-rs-geoip` to binary deps |
| `crates/rule/Cargo.toml` | Add `clashx-rs-geoip` dependency |
| `crates/rule/src/lib.rs` | Add `geoip_db` field to `RuleEngine`, change `new()` signature, add `set_geoip_db()`, update `matches_rule()` GEOIP arm, update tests |
| `src/main.rs` | Add `MmdbDownload` subcommand, add `--mmdb`/`--mmdb-auto-download` to `Run`, implement download handler |
| `src/daemon.rs` | Add `mmdb_path` to `DaemonState`, load mmdb in startup, pass to `RuleEngine::new`, spawn auto-download task, update reload, **add DNS pre-resolve before rule evaluation** (use `clashx_rs_dns::resolve`), populate `MatchInput.ip` for domain targets |
| `src/paths.rs` | Add `default_mmdb_path()` |
