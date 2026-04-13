# GEOIP Rule Support Design Spec

## 1. Context

clashx-rs parses Clash-compatible YAML configs with a top-to-bottom rule engine. GEOIP rules (`GEOIP,CN,DIRECT`) are already parsed into `RuleEntry::GeoIp { country, target }` but matching is stubbed to always return `false`. Most real-world Clash configs contain GEOIP rules, so without a working implementation traffic gets silently mis-routed — those rules are skipped and connections fall through to later rules or the catch-all.

This change implements real GEOIP matching by loading a MaxMind-format mmdb database, looking up the country code for each connection's IP, and comparing it against the rule's country field. It also provides two ways to obtain the mmdb file, solving the chicken-and-egg problem where the proxy itself is needed to download the database.

## 2. Architecture

### New crate: `crates/geoip`

Isolates all mmdb concerns (file loading, IP-to-country lookup, HTTP download) from the rule engine. Keeps the `rule` crate free of network/IO dependencies.

### Dependency diagram

```
src/main.rs  (adds mmdb-download subcommand, --mmdb/--mmdb-auto-download flags)
    |
    v
src/daemon.rs  (loads mmdb, passes GeoIpDb to RuleEngine, spawns auto-download)
    |
    +---> crates/geoip  (GeoIpDb, download_mmdb)
    |         |
    |         +---> maxminddb   (mmdb parsing)
    |         +---> reqwest     (HTTP download, with socks feature)
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

## 6. Rule Engine Integration

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

### No changes to MatchInput

`ip: Option<IpAddr>` already exists. GEOIP rules only match when IP is known (IP literal targets or post-DNS-resolution). This matches Clash behavior.

## 7. Daemon Startup Flow

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

## 8. Graceful Degradation

| Scenario | Behavior |
|----------|----------|
| mmdb missing at startup | Warning logged, GEOIP rules skip, all other rules work |
| mmdb corrupt/invalid | Same as missing |
| mmdb missing + `--mmdb-auto-download` | Proxy starts immediately, background download spawned, GEOIP activates when download completes |
| Auto-download fails all retries | Warning logged, GEOIP rules remain inactive, proxy fully functional |
| IP not in mmdb (private range) | GEOIP rule doesn't match, next rule evaluated |
| `input.ip` is None (domain target) | GEOIP rule doesn't match, next rule evaluated |

**Key principle: GEOIP is always optional. The proxy never fails to start due to GEOIP issues.**

## 9. Testing Strategy

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
- Config with `GEOIP,CN,DIRECT` → connect to CN IP → verify DIRECT routing
- Start without mmdb → verify warning and proxy works for other rules

## 10. Files to Modify

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
| `src/daemon.rs` | Add `mmdb_path` to `DaemonState`, load mmdb in startup, pass to `RuleEngine::new`, spawn auto-download task, update reload |
| `src/paths.rs` | Add `default_mmdb_path()` |
