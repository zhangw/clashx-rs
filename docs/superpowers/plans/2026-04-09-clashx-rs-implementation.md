# clashx-rs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a pure Rust CLI proxy tool that parses Clash YAML configs and proxies traffic through Trojan/SOCKS5 outbound connections, with CLI-first control.

**Architecture:** Single binary with daemon mode (proxy engine + Unix socket control server) and client mode (CLI commands to control the daemon). Cargo workspace with 5 internal crates: config, proxy, rule, dns, sysproxy. Inbound mixed-port listener auto-detects HTTP/SOCKS5 protocol. Rule engine routes traffic to proxy groups, which resolve to outbound connectors (Trojan, SOCKS5, DIRECT, REJECT).

**Tech Stack:** Rust 1.92+, tokio (async runtime), serde + serde_yaml (config), tokio-rustls (TLS), clap (CLI), sha2 (Trojan auth), tracing (logging)

---

## File Structure

```
clashx-rs/
├── Cargo.toml                          # workspace root
├── crates/
│   ├── config/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # re-exports
│   │       ├── types.rs                # Config, Proxy, ProxyGroup, DnsConfig structs
│   │       ├── rule.rs                 # RuleEntry parsing (DOMAIN-SUFFIX, IP-CIDR, etc.)
│   │       └── parse.rs               # load_config() from file path
│   ├── rule/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # RuleEngine struct, evaluate()
│   │       └── process.rs              # process name lookup (macOS/Linux)
│   ├── dns/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── lib.rs                  # Resolver trait + system resolver
│   ├── proxy/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # re-exports, ProxyEngine
│   │       ├── inbound/
│   │       │   ├── mod.rs              # MixedPortListener
│   │       │   ├── http.rs             # HTTP CONNECT + plain HTTP proxy
│   │       │   └── socks5.rs           # SOCKS5 inbound handshake
│   │       ├── outbound/
│   │       │   ├── mod.rs              # OutboundConnector trait + dispatch
│   │       │   ├── trojan.rs           # Trojan TLS connector
│   │       │   ├── socks5.rs           # SOCKS5 client connector
│   │       │   ├── direct.rs           # Direct TCP connector
│   │       │   └── reject.rs           # Reject (drop) connector
│   │       └── relay.rs               # bidirectional async copy
│   └── sysproxy/
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs                  # SysProxy trait + platform dispatch
│           ├── macos.rs                # networksetup implementation
│           └── linux.rs                # env var print implementation
├── src/
│   ├── main.rs                         # CLI entry point (clap derive)
│   ├── daemon.rs                       # daemon mode: engine + control socket
│   ├── client.rs                       # client mode: send commands to daemon
│   └── control.rs                      # ControlRequest/ControlResponse types
└── tests/
    └── integration/
        ├── config_parse.rs             # end-to-end config parsing tests
        └── rule_engine.rs              # rule matching integration tests
```

---

### Task 1: Scaffold Cargo Workspace

**Files:**
- Create: `Cargo.toml` (workspace root)
- Create: `crates/config/Cargo.toml`
- Create: `crates/config/src/lib.rs`
- Create: `crates/rule/Cargo.toml`
- Create: `crates/rule/src/lib.rs`
- Create: `crates/dns/Cargo.toml`
- Create: `crates/dns/src/lib.rs`
- Create: `crates/proxy/Cargo.toml`
- Create: `crates/proxy/src/lib.rs`
- Create: `crates/sysproxy/Cargo.toml`
- Create: `crates/sysproxy/src/lib.rs`
- Create: `src/main.rs`

- [ ] **Step 1: Create workspace root Cargo.toml**

```toml
[workspace]
members = [
    "crates/config",
    "crates/rule",
    "crates/dns",
    "crates/proxy",
    "crates/sysproxy",
]
resolver = "2"

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "MIT"

[workspace.dependencies]
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_yaml = "0.9"
serde_json = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
anyhow = "1"
sha2 = "0.10"
tokio-rustls = "0.26"
rustls = { version = "0.23", default-features = false, features = ["ring", "logging", "std"] }
clap = { version = "4", features = ["derive"] }

[package]
name = "clashx-rs"
version.workspace = true
edition.workspace = true

[dependencies]
clashx-rs-config = { path = "crates/config" }
clashx-rs-rule = { path = "crates/rule" }
clashx-rs-dns = { path = "crates/dns" }
clashx-rs-proxy = { path = "crates/proxy" }
clashx-rs-sysproxy = { path = "crates/sysproxy" }
tokio.workspace = true
serde.workspace = true
serde_json.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
clap.workspace = true
anyhow.workspace = true
```

- [ ] **Step 2: Create config crate**

`crates/config/Cargo.toml`:
```toml
[package]
name = "clashx-rs-config"
version.workspace = true
edition.workspace = true

[dependencies]
serde.workspace = true
serde_yaml.workspace = true
anyhow.workspace = true
```

`crates/config/src/lib.rs`:
```rust
pub mod parse;
pub mod rule;
pub mod types;

pub use parse::load_config;
pub use types::Config;
```

- [ ] **Step 3: Create rule crate**

`crates/rule/Cargo.toml`:
```toml
[package]
name = "clashx-rs-rule"
version.workspace = true
edition.workspace = true

[dependencies]
clashx-rs-config = { path = "../config" }
tracing.workspace = true
anyhow.workspace = true
```

`crates/rule/src/lib.rs`:
```rust
pub struct RuleEngine;
```

- [ ] **Step 4: Create dns crate**

`crates/dns/Cargo.toml`:
```toml
[package]
name = "clashx-rs-dns"
version.workspace = true
edition.workspace = true

[dependencies]
tokio.workspace = true
anyhow.workspace = true
tracing.workspace = true
```

`crates/dns/src/lib.rs`:
```rust
pub struct Resolver;
```

- [ ] **Step 5: Create proxy crate**

`crates/proxy/Cargo.toml`:
```toml
[package]
name = "clashx-rs-proxy"
version.workspace = true
edition.workspace = true

[dependencies]
clashx-rs-config = { path = "../config" }
clashx-rs-dns = { path = "../dns" }
tokio.workspace = true
tokio-rustls.workspace = true
rustls.workspace = true
sha2.workspace = true
serde.workspace = true
tracing.workspace = true
anyhow.workspace = true
```

`crates/proxy/src/lib.rs`:
```rust
pub struct ProxyEngine;
```

- [ ] **Step 6: Create sysproxy crate**

`crates/sysproxy/Cargo.toml`:
```toml
[package]
name = "clashx-rs-sysproxy"
version.workspace = true
edition.workspace = true

[dependencies]
tokio.workspace = true
tracing.workspace = true
anyhow.workspace = true
```

`crates/sysproxy/src/lib.rs`:
```rust
pub struct SysProxy;
```

- [ ] **Step 7: Create binary entry point**

`src/main.rs`:
```rust
fn main() {
    println!("clashx-rs v0.1.0");
}
```

- [ ] **Step 8: Verify workspace builds**

Run: `cargo build`
Expected: Compiles all 5 crates + binary successfully

- [ ] **Step 9: Verify formatting and lints**

Run: `cargo fmt --check && cargo clippy --all-targets -- -D warnings`
Expected: Both pass with no errors

- [ ] **Step 10: Commit**

```bash
git add Cargo.toml Cargo.lock crates/ src/
git commit -m "feat: scaffold Cargo workspace with 5 internal crates"
```

---

### Task 2: Config Types and Parsing

**Files:**
- Create: `crates/config/src/types.rs`
- Create: `crates/config/src/rule.rs`
- Create: `crates/config/src/parse.rs`
- Modify: `crates/config/src/lib.rs`

- [ ] **Step 1: Write tests for config types deserialization**

Create `crates/config/src/types.rs` with types AND tests in the same file:

```rust
use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    #[serde(default = "default_mixed_port")]
    pub mixed_port: u16,
    #[serde(default)]
    pub allow_lan: bool,
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub log_level: LogLevel,
    pub external_controller: Option<String>,
    pub dns: Option<DnsConfig>,
    #[serde(default)]
    pub proxies: Vec<Proxy>,
    #[serde(default, rename = "proxy-groups")]
    pub proxy_groups: Vec<ProxyGroup>,
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

fn default_mixed_port() -> u16 {
    7890
}

fn default_bind_address() -> String {
    "*".to_string()
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Rule,
    Global,
    Direct,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Silent,
    Error,
    Warning,
    #[default]
    Info,
    Debug,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DnsConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub ipv6: bool,
    #[serde(default)]
    pub enhanced_mode: Option<String>,
    #[serde(default)]
    pub nameserver: Vec<String>,
    #[serde(default)]
    pub default_nameserver: Vec<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Proxy {
    Trojan(TrojanProxy),
    Socks5(Socks5Proxy),
    #[serde(other)]
    Unknown,
}

impl Proxy {
    pub fn name(&self) -> Option<&str> {
        match self {
            Proxy::Trojan(p) => Some(&p.name),
            Proxy::Socks5(p) => Some(&p.name),
            Proxy::Unknown => None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TrojanProxy {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub skip_cert_verify: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Socks5Proxy {
    pub name: String,
    pub server: String,
    pub port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ProxyGroup {
    pub name: String,
    #[serde(rename = "type")]
    pub group_type: GroupType,
    #[serde(default)]
    pub proxies: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum GroupType {
    Select,
    #[serde(other)]
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_config() {
        let yaml = r#"
mixed-port: 7890
mode: rule
log-level: info
proxies: []
proxy-groups: []
rules: []
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.mixed_port, 7890);
        assert_eq!(config.mode, Mode::Rule);
        assert_eq!(config.log_level, LogLevel::Info);
    }

    #[test]
    fn parse_trojan_proxy() {
        let yaml = r#"
mixed-port: 7890
proxies:
  - name: "hk-01"
    type: trojan
    server: 1.2.3.4
    port: 443
    password: "my-password"
    sni: "example.com"
    skip-cert-verify: true
proxy-groups: []
rules: []
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.proxies.len(), 1);
        match &config.proxies[0] {
            Proxy::Trojan(t) => {
                assert_eq!(t.name, "hk-01");
                assert_eq!(t.server, "1.2.3.4");
                assert_eq!(t.port, 443);
                assert_eq!(t.password, "my-password");
                assert_eq!(t.sni.as_deref(), Some("example.com"));
                assert!(t.skip_cert_verify);
            }
            _ => panic!("Expected Trojan proxy"),
        }
    }

    #[test]
    fn parse_socks5_proxy() {
        let yaml = r#"
mixed-port: 7890
proxies:
  - name: "local-socks"
    type: socks5
    server: 127.0.0.1
    port: 1080
proxy-groups: []
rules: []
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        match &config.proxies[0] {
            Proxy::Socks5(s) => {
                assert_eq!(s.name, "local-socks");
                assert_eq!(s.port, 1080);
            }
            _ => panic!("Expected SOCKS5 proxy"),
        }
    }

    #[test]
    fn parse_proxy_group_select() {
        let yaml = r#"
mixed-port: 7890
proxies: []
proxy-groups:
  - name: "node-select"
    type: select
    proxies:
      - "hk-01"
      - "sg-01"
      - DIRECT
rules: []
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.proxy_groups.len(), 1);
        assert_eq!(config.proxy_groups[0].name, "node-select");
        assert_eq!(config.proxy_groups[0].group_type, GroupType::Select);
        assert_eq!(config.proxy_groups[0].proxies.len(), 3);
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let yaml = r#"
mixed-port: 7890
tun:
  enable: true
  stack: system
some-future-field: true
proxies: []
proxy-groups: []
rules: []
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.mixed_port, 7890);
    }

    #[test]
    fn unknown_proxy_type_is_skipped() {
        let yaml = r#"
mixed-port: 7890
proxies:
  - name: "vmess-node"
    type: vmess
    server: 1.2.3.4
    port: 443
proxy-groups: []
rules: []
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.proxies.len(), 1);
        assert!(matches!(config.proxies[0], Proxy::Unknown));
    }
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test -p clashx-rs-config`
Expected: All 6 tests pass

- [ ] **Step 3: Write rule entry parsing**

Create `crates/config/src/rule.rs`:

```rust
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq)]
pub enum RuleEntry {
    DomainSuffix { suffix: String, target: String },
    IpCidr { ip: IpAddr, prefix_len: u8, target: String },
    ProcessName { name: String, target: String },
    Match { target: String },
}

impl RuleEntry {
    pub fn parse(raw: &str) -> Option<RuleEntry> {
        let parts: Vec<&str> = raw.splitn(3, ',').collect();
        match parts.as_slice() {
            ["DOMAIN-SUFFIX", suffix, target] => Some(RuleEntry::DomainSuffix {
                suffix: suffix.to_lowercase(),
                target: target.to_string(),
            }),
            ["IP-CIDR", cidr, target] => {
                let cidr_parts: Vec<&str> = cidr.splitn(2, '/').collect();
                if cidr_parts.len() != 2 {
                    return None;
                }
                let ip: IpAddr = cidr_parts[0].parse().ok()?;
                let prefix_len: u8 = cidr_parts[1].parse().ok()?;
                Some(RuleEntry::IpCidr {
                    ip,
                    prefix_len,
                    target: target.to_string(),
                })
            }
            ["PROCESS-NAME", name, target] => Some(RuleEntry::ProcessName {
                name: name.to_string(),
                target: target.to_string(),
            }),
            ["MATCH", target] => Some(RuleEntry::Match {
                target: target.to_string(),
            }),
            _ => None,
        }
    }

    pub fn target(&self) -> &str {
        match self {
            RuleEntry::DomainSuffix { target, .. } => target,
            RuleEntry::IpCidr { target, .. } => target,
            RuleEntry::ProcessName { target, .. } => target,
            RuleEntry::Match { target } => target,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_domain_suffix() {
        let entry = RuleEntry::parse("DOMAIN-SUFFIX,google.com,@proxy").unwrap();
        assert_eq!(
            entry,
            RuleEntry::DomainSuffix {
                suffix: "google.com".to_string(),
                target: "@proxy".to_string(),
            }
        );
    }

    #[test]
    fn parse_ip_cidr() {
        let entry = RuleEntry::parse("IP-CIDR,172.16.0.0/16,@corpnet").unwrap();
        assert_eq!(
            entry,
            RuleEntry::IpCidr {
                ip: "172.16.0.0".parse().unwrap(),
                prefix_len: 16,
                target: "@corpnet".to_string(),
            }
        );
    }

    #[test]
    fn parse_process_name() {
        let entry = RuleEntry::parse("PROCESS-NAME,FortiClientAgent,@direct").unwrap();
        assert_eq!(
            entry,
            RuleEntry::ProcessName {
                name: "FortiClientAgent".to_string(),
                target: "@direct".to_string(),
            }
        );
    }

    #[test]
    fn parse_match_rule() {
        let entry = RuleEntry::parse("MATCH,DIRECT").unwrap();
        assert_eq!(
            entry,
            RuleEntry::Match {
                target: "DIRECT".to_string(),
            }
        );
    }

    #[test]
    fn parse_unknown_returns_none() {
        assert!(RuleEntry::parse("GEOIP,CN,DIRECT").is_none());
    }

    #[test]
    fn domain_suffix_lowercased() {
        let entry = RuleEntry::parse("DOMAIN-SUFFIX,Google.COM,@proxy").unwrap();
        match entry {
            RuleEntry::DomainSuffix { suffix, .. } => assert_eq!(suffix, "google.com"),
            _ => panic!("expected DomainSuffix"),
        }
    }
}
```

- [ ] **Step 4: Run rule parsing tests**

Run: `cargo test -p clashx-rs-config`
Expected: All 12 tests pass

- [ ] **Step 5: Write config file loading**

Create `crates/config/src/parse.rs`:

```rust
use crate::types::Config;
use anyhow::{Context, Result};
use std::path::Path;

pub fn load_config(path: &Path) -> Result<Config> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let config: Config =
        serde_yaml::from_str(&content).with_context(|| format!("Failed to parse {}", path.display()))?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn load_from_file() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"
mixed-port: 9999
mode: direct
proxies: []
proxy-groups: []
rules: []
"#
        )
        .unwrap();

        let config = load_config(f.path()).unwrap();
        assert_eq!(config.mixed_port, 9999);
    }

    #[test]
    fn load_nonexistent_file_errors() {
        let result = load_config(Path::new("/nonexistent/config.yaml"));
        assert!(result.is_err());
    }
}
```

- [ ] **Step 6: Add tempfile dev-dependency**

In `crates/config/Cargo.toml`, add:
```toml
[dev-dependencies]
tempfile = "3"
```

- [ ] **Step 7: Update lib.rs**

`crates/config/src/lib.rs`:
```rust
pub mod parse;
pub mod rule;
pub mod types;

pub use parse::load_config;
pub use types::Config;
```

- [ ] **Step 8: Run all config tests**

Run: `cargo test -p clashx-rs-config`
Expected: All 14 tests pass

- [ ] **Step 9: Commit**

```bash
git add crates/config/
git commit -m "feat(config): Clash YAML config types and parser"
```

---

### Task 3: Rule Engine

**Files:**
- Create: `crates/rule/src/lib.rs` (replace stub)

- [ ] **Step 1: Write rule engine with tests**

Replace `crates/rule/src/lib.rs`:

```rust
use clashx_rs_config::rule::RuleEntry;
use std::net::IpAddr;

/// Target address information used for rule matching.
#[derive(Debug, Clone)]
pub struct MatchInput<'a> {
    pub host: Option<&'a str>,
    pub ip: Option<IpAddr>,
    pub process_name: Option<&'a str>,
}

pub struct RuleEngine {
    rules: Vec<RuleEntry>,
}

impl RuleEngine {
    pub fn new(raw_rules: &[String]) -> Self {
        let rules: Vec<RuleEntry> = raw_rules.iter().filter_map(|r| RuleEntry::parse(r)).collect();
        RuleEngine { rules }
    }

    /// Evaluate rules top-to-bottom, return the target of the first match.
    pub fn evaluate(&self, input: &MatchInput<'_>) -> Option<&str> {
        for rule in &self.rules {
            if self.matches(rule, input) {
                return Some(rule.target());
            }
        }
        None
    }

    fn matches(&self, rule: &RuleEntry, input: &MatchInput<'_>) -> bool {
        match rule {
            RuleEntry::DomainSuffix { suffix, .. } => {
                if let Some(host) = input.host {
                    let host_lower = host.to_lowercase();
                    host_lower == *suffix || host_lower.ends_with(&format!(".{suffix}"))
                } else {
                    false
                }
            }
            RuleEntry::IpCidr {
                ip, prefix_len, ..
            } => {
                if let Some(target_ip) = input.ip {
                    ip_in_cidr(target_ip, *ip, *prefix_len)
                } else {
                    false
                }
            }
            RuleEntry::ProcessName { name, .. } => {
                input.process_name.map_or(false, |p| p == name)
            }
            RuleEntry::Match { .. } => true,
        }
    }
}

fn ip_in_cidr(addr: IpAddr, network: IpAddr, prefix_len: u8) -> bool {
    match (addr, network) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            if prefix_len > 32 {
                return false;
            }
            if prefix_len == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - prefix_len);
            (u32::from(a) & mask) == (u32::from(n) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            if prefix_len > 128 {
                return false;
            }
            if prefix_len == 0 {
                return true;
            }
            let mask = u128::MAX << (128 - prefix_len);
            (u128::from(a) & mask) == (u128::from(n) & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine(rules: &[&str]) -> RuleEngine {
        let raw: Vec<String> = rules.iter().map(|s| s.to_string()).collect();
        RuleEngine::new(&raw)
    }

    #[test]
    fn domain_suffix_exact_match() {
        let e = engine(&["DOMAIN-SUFFIX,google.com,@proxy"]);
        let input = MatchInput {
            host: Some("google.com"),
            ip: None,
            process_name: None,
        };
        assert_eq!(e.evaluate(&input), Some("@proxy"));
    }

    #[test]
    fn domain_suffix_subdomain_match() {
        let e = engine(&["DOMAIN-SUFFIX,google.com,@proxy"]);
        let input = MatchInput {
            host: Some("www.google.com"),
            ip: None,
            process_name: None,
        };
        assert_eq!(e.evaluate(&input), Some("@proxy"));
    }

    #[test]
    fn domain_suffix_no_partial_match() {
        let e = engine(&["DOMAIN-SUFFIX,oogle.com,@proxy", "MATCH,DIRECT"]);
        let input = MatchInput {
            host: Some("google.com"),
            ip: None,
            process_name: None,
        };
        // "google.com" does NOT end with ".oogle.com" and is not equal to "oogle.com"
        assert_eq!(e.evaluate(&input), Some("DIRECT"));
    }

    #[test]
    fn domain_suffix_case_insensitive() {
        let e = engine(&["DOMAIN-SUFFIX,Google.COM,@proxy"]);
        let input = MatchInput {
            host: Some("WWW.GOOGLE.COM"),
            ip: None,
            process_name: None,
        };
        assert_eq!(e.evaluate(&input), Some("@proxy"));
    }

    #[test]
    fn ip_cidr_match() {
        let e = engine(&["IP-CIDR,172.16.0.0/16,@corpnet"]);
        let input = MatchInput {
            host: None,
            ip: Some("172.16.55.3".parse().unwrap()),
            process_name: None,
        };
        assert_eq!(e.evaluate(&input), Some("@corpnet"));
    }

    #[test]
    fn ip_cidr_no_match() {
        let e = engine(&["IP-CIDR,172.16.0.0/16,@corpnet", "MATCH,DIRECT"]);
        let input = MatchInput {
            host: None,
            ip: Some("10.2.0.1".parse().unwrap()),
            process_name: None,
        };
        assert_eq!(e.evaluate(&input), Some("DIRECT"));
    }

    #[test]
    fn process_name_match() {
        let e = engine(&["PROCESS-NAME,FortiClientAgent,@direct"]);
        let input = MatchInput {
            host: None,
            ip: None,
            process_name: Some("FortiClientAgent"),
        };
        assert_eq!(e.evaluate(&input), Some("@direct"));
    }

    #[test]
    fn match_catch_all() {
        let e = engine(&["MATCH,DIRECT"]);
        let input = MatchInput {
            host: Some("anything.com"),
            ip: None,
            process_name: None,
        };
        assert_eq!(e.evaluate(&input), Some("DIRECT"));
    }

    #[test]
    fn first_match_wins() {
        let e = engine(&[
            "DOMAIN-SUFFIX,example.com,@first",
            "DOMAIN-SUFFIX,example.com,@second",
            "MATCH,DIRECT",
        ]);
        let input = MatchInput {
            host: Some("example.com"),
            ip: None,
            process_name: None,
        };
        assert_eq!(e.evaluate(&input), Some("@first"));
    }

    #[test]
    fn no_rules_returns_none() {
        let e = engine(&[]);
        let input = MatchInput {
            host: Some("example.com"),
            ip: None,
            process_name: None,
        };
        assert_eq!(e.evaluate(&input), None);
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p clashx-rs-rule`
Expected: All 10 tests pass

- [ ] **Step 3: Commit**

```bash
git add crates/rule/
git commit -m "feat(rule): rule engine with domain-suffix, IP-CIDR, process-name, match"
```

---

### Task 4: DNS Resolver

**Files:**
- Create: `crates/dns/src/lib.rs` (replace stub)

- [ ] **Step 1: Write DNS resolver**

Replace `crates/dns/src/lib.rs`:

```rust
use anyhow::Result;
use std::net::{IpAddr, ToSocketAddrs};
use tokio::task;

/// Resolve a hostname to an IP address using the system resolver.
/// Runs the blocking resolution on a dedicated thread via `spawn_blocking`.
pub async fn resolve(host: &str) -> Result<IpAddr> {
    let host = host.to_string();
    let ip = task::spawn_blocking(move || -> Result<IpAddr> {
        let addr = format!("{host}:0")
            .to_socket_addrs()?
            .find(|a| a.is_ipv4())
            .or_else(|| format!("{host}:0").to_socket_addrs().ok()?.next())
            .ok_or_else(|| anyhow::anyhow!("failed to resolve {host}"))?;
        Ok(addr.ip())
    })
    .await??;
    Ok(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolve_localhost() {
        let ip = resolve("localhost").await.unwrap();
        assert!(ip.is_loopback());
    }

    #[test]
    fn ip_passthrough() {
        // If the host is already an IP, ToSocketAddrs just parses it
        let addr: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(addr.is_loopback());
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p clashx-rs-dns`
Expected: 2 tests pass

- [ ] **Step 3: Commit**

```bash
git add crates/dns/
git commit -m "feat(dns): system DNS resolver with async spawn_blocking"
```

---

### Task 5: Bidirectional Relay

**Files:**
- Create: `crates/proxy/src/relay.rs`
- Modify: `crates/proxy/src/lib.rs`

- [ ] **Step 1: Write relay module**

Create `crates/proxy/src/relay.rs`:

```rust
use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};

/// Bidirectional copy between two async streams.
/// Returns when either direction completes or errors.
pub async fn relay<A, B>(mut a: A, mut b: B) -> Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (a_to_b, b_to_a) = tokio::io::copy_bidirectional(&mut a, &mut b).await?;
    Ok((a_to_b, b_to_a))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn relay_echoes_data() {
        // Create two duplex pairs: client<->relay_a and relay_b<->server
        let (client, relay_a) = duplex(1024);
        let (relay_b, server) = duplex(1024);

        // Spawn relay between relay_a and relay_b
        let relay_handle = tokio::spawn(async move { relay(relay_a, relay_b).await });

        // Client writes, server reads
        let (mut client_read, mut client_write) = tokio::io::split(client);
        let (mut server_read, mut server_write) = tokio::io::split(server);

        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        client_write.write_all(b"hello").await.unwrap();
        client_write.shutdown().await.unwrap();

        let mut buf = Vec::new();
        server_read.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"hello");

        // Server writes back, client reads
        server_write.write_all(b"world").await.unwrap();
        server_write.shutdown().await.unwrap();

        let mut buf2 = Vec::new();
        client_read.read_to_end(&mut buf2).await.unwrap();
        assert_eq!(buf2, b"world");

        relay_handle.await.unwrap().unwrap();
    }
}
```

- [ ] **Step 2: Update proxy lib.rs**

Replace `crates/proxy/src/lib.rs`:
```rust
pub mod relay;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p clashx-rs-proxy`
Expected: 1 test passes

- [ ] **Step 4: Commit**

```bash
git add crates/proxy/
git commit -m "feat(proxy): bidirectional relay using tokio copy_bidirectional"
```

---

### Task 6: SOCKS5 Inbound Handler

**Files:**
- Create: `crates/proxy/src/inbound/mod.rs`
- Create: `crates/proxy/src/inbound/socks5.rs`
- Modify: `crates/proxy/src/lib.rs`

- [ ] **Step 1: Define inbound types**

Create `crates/proxy/src/inbound/mod.rs`:

```rust
pub mod socks5;
pub mod http;

use std::net::IpAddr;

/// The target address extracted from an inbound connection.
#[derive(Debug, Clone)]
pub enum TargetAddr {
    Domain(String, u16),
    Ip(IpAddr, u16),
}

impl TargetAddr {
    pub fn host_string(&self) -> String {
        match self {
            TargetAddr::Domain(d, _) => d.clone(),
            TargetAddr::Ip(ip, _) => ip.to_string(),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            TargetAddr::Domain(_, p) => *p,
            TargetAddr::Ip(_, p) => *p,
        }
    }
}
```

- [ ] **Step 2: Write SOCKS5 inbound handshake**

Create `crates/proxy/src/inbound/socks5.rs`:

```rust
use super::TargetAddr;
use anyhow::{bail, Result};
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const SOCKS5_VERSION: u8 = 0x05;
const NO_AUTH: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REP_SUCCESS: u8 = 0x00;

/// Perform the SOCKS5 handshake on an already-accepted TCP stream.
/// Returns the target address the client wants to connect to.
/// The stream is left ready for data relay after this returns.
pub async fn handshake(stream: &mut TcpStream) -> Result<TargetAddr> {
    // --- Method negotiation ---
    let version = stream.read_u8().await?;
    if version != SOCKS5_VERSION {
        bail!("invalid SOCKS5 version: {version}");
    }
    let nmethods = stream.read_u8().await?;
    let mut methods = vec![0u8; nmethods as usize];
    stream.read_exact(&mut methods).await?;

    if !methods.contains(&NO_AUTH) {
        // Send "no acceptable methods"
        stream.write_all(&[SOCKS5_VERSION, 0xFF]).await?;
        bail!("client does not support NO_AUTH");
    }
    stream.write_all(&[SOCKS5_VERSION, NO_AUTH]).await?;

    // --- Connect request ---
    let ver = stream.read_u8().await?;
    if ver != SOCKS5_VERSION {
        bail!("invalid SOCKS5 version in request: {ver}");
    }
    let cmd = stream.read_u8().await?;
    if cmd != CMD_CONNECT {
        send_reply(stream, 0x07).await?; // command not supported
        bail!("unsupported SOCKS5 command: {cmd}");
    }
    let _rsv = stream.read_u8().await?;
    let atyp = stream.read_u8().await?;

    let target = match atyp {
        ATYP_IPV4 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            let port = stream.read_u16().await?;
            TargetAddr::Ip(Ipv4Addr::from(ip).into(), port)
        }
        ATYP_DOMAIN => {
            let len = stream.read_u8().await? as usize;
            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).await?;
            let port = stream.read_u16().await?;
            let domain = String::from_utf8(domain)?;
            TargetAddr::Domain(domain, port)
        }
        ATYP_IPV6 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            let port = stream.read_u16().await?;
            TargetAddr::Ip(Ipv6Addr::from(ip).into(), port)
        }
        _ => {
            send_reply(stream, 0x08).await?; // address type not supported
            bail!("unsupported address type: {atyp}");
        }
    };

    // Send success reply with bound address 0.0.0.0:0
    send_reply(stream, REP_SUCCESS).await?;
    Ok(target)
}

async fn send_reply(stream: &mut TcpStream, rep: u8) -> Result<()> {
    let reply = [
        SOCKS5_VERSION,
        rep,
        0x00,       // reserved
        ATYP_IPV4,  // bound address type
        0, 0, 0, 0, // bound address: 0.0.0.0
        0, 0,       // bound port: 0
    ];
    stream.write_all(&reply).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn setup_socks5_test(client_data: Vec<u8>) -> Result<TargetAddr> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let client = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            stream.write_all(&client_data).await.unwrap();
            // Read method response (2 bytes) + connect reply (10 bytes)
            let mut buf = [0u8; 12];
            stream.read_exact(&mut buf).await.unwrap();
            buf
        });

        let (mut server_stream, _) = listener.accept().await?;
        // Read the first 0x05 byte since handshake expects it was already peeked
        // Actually our handshake reads it itself, so just call it directly
        let target = handshake(&mut server_stream).await?;
        client.await?;
        Ok(target)
    }

    #[tokio::test]
    async fn socks5_connect_domain() {
        // Version=5, 1 method, NO_AUTH
        // Then: Version=5, CMD=CONNECT, RSV=0, ATYP=DOMAIN, len=11, "example.com", port=443
        let mut data = vec![0x05, 0x01, 0x00]; // method negotiation
        data.extend_from_slice(&[0x05, 0x01, 0x00, 0x03]); // connect request header
        data.push(11); // domain length
        data.extend_from_slice(b"example.com");
        data.extend_from_slice(&443u16.to_be_bytes());

        let target = setup_socks5_test(data).await.unwrap();
        match target {
            TargetAddr::Domain(d, p) => {
                assert_eq!(d, "example.com");
                assert_eq!(p, 443);
            }
            _ => panic!("expected domain target"),
        }
    }

    #[tokio::test]
    async fn socks5_connect_ipv4() {
        let mut data = vec![0x05, 0x01, 0x00];
        data.extend_from_slice(&[0x05, 0x01, 0x00, 0x01]); // ATYP_IPV4
        data.extend_from_slice(&[127, 0, 0, 1]);
        data.extend_from_slice(&80u16.to_be_bytes());

        let target = setup_socks5_test(data).await.unwrap();
        match target {
            TargetAddr::Ip(ip, p) => {
                assert_eq!(ip.to_string(), "127.0.0.1");
                assert_eq!(p, 80);
            }
            _ => panic!("expected IP target"),
        }
    }
}
```

- [ ] **Step 3: Update lib.rs**

```rust
pub mod inbound;
pub mod relay;
```

- [ ] **Step 4: Create empty http module placeholder**

Create `crates/proxy/src/inbound/http.rs`:
```rust
// HTTP proxy inbound handler - implemented in Task 7
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p clashx-rs-proxy`
Expected: 3 tests pass (1 relay + 2 socks5 inbound)

- [ ] **Step 6: Commit**

```bash
git add crates/proxy/
git commit -m "feat(proxy): SOCKS5 inbound handshake handler"
```

---

### Task 7: HTTP Proxy Inbound Handler

**Files:**
- Modify: `crates/proxy/src/inbound/http.rs`

- [ ] **Step 1: Write HTTP proxy handler**

Replace `crates/proxy/src/inbound/http.rs`:

```rust
use super::TargetAddr;
use anyhow::{bail, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Handle an HTTP proxy request (CONNECT or plain HTTP).
/// For CONNECT: sends 200 response, returns target, stream is ready for relay.
/// For plain HTTP: returns target extracted from request URI / Host header.
///   The raw request bytes are returned so they can be forwarded to the upstream.
pub async fn handshake(stream: &mut TcpStream) -> Result<(TargetAddr, Option<Vec<u8>>)> {
    let mut buf_reader = BufReader::new(&mut *stream);
    let mut request_line = String::new();
    buf_reader.read_line(&mut request_line).await?;
    let request_line = request_line.trim_end();

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 {
        bail!("invalid HTTP request line: {request_line}");
    }

    let method = parts[0];
    let uri = parts[1];

    if method.eq_ignore_ascii_case("CONNECT") {
        // CONNECT host:port HTTP/1.1
        let target = parse_host_port(uri)?;

        // Read and discard remaining headers until empty line
        loop {
            let mut line = String::new();
            buf_reader.read_line(&mut line).await?;
            if line.trim().is_empty() {
                break;
            }
        }

        // Send 200 Connection Established
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        Ok((target, None))
    } else {
        // Plain HTTP proxy: GET http://host:port/path HTTP/1.1
        // Read all headers, extract Host, reconstruct full request to forward
        let mut headers = String::new();
        let mut host_header = None;
        loop {
            let mut line = String::new();
            buf_reader.read_line(&mut line).await?;
            if line.trim().is_empty() {
                break;
            }
            if line.to_lowercase().starts_with("host:") {
                host_header = Some(line.trim()[5..].trim().to_string());
            }
            headers.push_str(&line);
        }

        let target = if uri.starts_with("http://") {
            // Extract host:port from absolute URI
            let without_scheme = &uri[7..];
            let host_part = without_scheme.split('/').next().unwrap_or(without_scheme);
            parse_host_port_default(host_part, 80)?
        } else if let Some(ref host) = host_header {
            parse_host_port_default(host, 80)?
        } else {
            bail!("cannot determine target from HTTP request");
        };

        // Reconstruct the request to forward
        let mut raw_request = format!("{request_line}\r\n{headers}\r\n").into_bytes();
        Ok((target, Some(raw_request)))
    }
}

fn parse_host_port(s: &str) -> Result<TargetAddr> {
    if let Some(colon_pos) = s.rfind(':') {
        let host = &s[..colon_pos];
        let port: u16 = s[colon_pos + 1..].parse()?;
        if let Ok(ip) = host.parse() {
            Ok(TargetAddr::Ip(ip, port))
        } else {
            Ok(TargetAddr::Domain(host.to_string(), port))
        }
    } else {
        bail!("missing port in CONNECT target: {s}");
    }
}

fn parse_host_port_default(s: &str, default_port: u16) -> Result<TargetAddr> {
    if let Some(colon_pos) = s.rfind(':') {
        let host = &s[..colon_pos];
        let port: u16 = s[colon_pos + 1..].parse().unwrap_or(default_port);
        if let Ok(ip) = host.parse() {
            Ok(TargetAddr::Ip(ip, port))
        } else {
            Ok(TargetAddr::Domain(host.to_string(), port))
        }
    } else if let Ok(ip) = s.parse() {
        Ok(TargetAddr::Ip(ip, default_port))
    } else {
        Ok(TargetAddr::Domain(s.to_string(), default_port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn http_connect_request() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client_handle = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            stream
                .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
                .await
                .unwrap();
            let mut buf = [0u8; 256];
            let n = stream.read(&mut buf).await.unwrap();
            let response = String::from_utf8_lossy(&buf[..n]);
            assert!(response.contains("200"));
        });

        let (mut server_stream, _) = listener.accept().await.unwrap();
        let (target, raw) = handshake(&mut server_stream).await.unwrap();
        assert!(raw.is_none()); // CONNECT has no forwarded body
        match target {
            TargetAddr::Domain(d, p) => {
                assert_eq!(d, "example.com");
                assert_eq!(p, 443);
            }
            _ => panic!("expected domain"),
        }
        client_handle.await.unwrap();
    }

    #[test]
    fn parse_host_port_domain() {
        let t = parse_host_port("example.com:443").unwrap();
        match t {
            TargetAddr::Domain(d, p) => {
                assert_eq!(d, "example.com");
                assert_eq!(p, 443);
            }
            _ => panic!("expected domain"),
        }
    }

    #[test]
    fn parse_host_port_ip() {
        let t = parse_host_port("1.2.3.4:80").unwrap();
        match t {
            TargetAddr::Ip(ip, p) => {
                assert_eq!(ip.to_string(), "1.2.3.4");
                assert_eq!(p, 80);
            }
            _ => panic!("expected ip"),
        }
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p clashx-rs-proxy`
Expected: 6 tests pass (1 relay + 2 socks5 + 3 http)

- [ ] **Step 3: Commit**

```bash
git add crates/proxy/src/inbound/http.rs
git commit -m "feat(proxy): HTTP CONNECT and plain HTTP proxy inbound handler"
```

---

### Task 8: Mixed-Port Listener (protocol auto-detect)

**Files:**
- Modify: `crates/proxy/src/inbound/mod.rs`

- [ ] **Step 1: Add mixed-port listener**

Add to `crates/proxy/src/inbound/mod.rs`:

```rust
pub mod http;
pub mod socks5;

use std::net::IpAddr;
use anyhow::Result;
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub enum TargetAddr {
    Domain(String, u16),
    Ip(IpAddr, u16),
}

impl TargetAddr {
    pub fn host_string(&self) -> String {
        match self {
            TargetAddr::Domain(d, _) => d.clone(),
            TargetAddr::Ip(ip, _) => ip.to_string(),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            TargetAddr::Domain(_, p) => *p,
            TargetAddr::Ip(_, p) => *p,
        }
    }
}

/// Result of detecting and handling the inbound protocol.
pub struct InboundResult {
    pub target: TargetAddr,
    pub stream: TcpStream,
    /// For plain HTTP proxy, the raw request bytes to forward.
    pub initial_data: Option<Vec<u8>>,
    /// The source address of the connecting client.
    pub source_addr: std::net::SocketAddr,
}

/// Detect whether the incoming connection is SOCKS5 or HTTP by peeking the first byte.
/// 0x05 -> SOCKS5, anything else -> HTTP proxy.
pub async fn detect_and_handle(mut stream: TcpStream, source_addr: std::net::SocketAddr) -> Result<InboundResult> {
    let mut peek_buf = [0u8; 1];
    stream.peek(&mut peek_buf).await?;

    if peek_buf[0] == 0x05 {
        // SOCKS5: read the version byte that we peeked
        let target = socks5::handshake(&mut stream).await?;
        Ok(InboundResult {
            target,
            stream,
            initial_data: None,
            source_addr,
        })
    } else {
        // HTTP proxy
        let (target, initial_data) = http::handshake(&mut stream).await?;
        Ok(InboundResult {
            target,
            stream,
            initial_data,
            source_addr,
        })
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p clashx-rs-proxy`
Expected: All 6 tests still pass

- [ ] **Step 3: Commit**

```bash
git add crates/proxy/src/inbound/
git commit -m "feat(proxy): mixed-port protocol auto-detection (SOCKS5/HTTP)"
```

---

### Task 9: Outbound Connectors (DIRECT, REJECT, SOCKS5)

**Files:**
- Create: `crates/proxy/src/outbound/mod.rs`
- Create: `crates/proxy/src/outbound/direct.rs`
- Create: `crates/proxy/src/outbound/reject.rs`
- Create: `crates/proxy/src/outbound/socks5.rs`
- Modify: `crates/proxy/src/lib.rs`

- [ ] **Step 1: Define outbound trait and DIRECT connector**

Create `crates/proxy/src/outbound/mod.rs`:

```rust
pub mod direct;
pub mod reject;
pub mod socks5;
pub mod trojan;

use crate::inbound::TargetAddr;
use anyhow::Result;
use tokio::net::TcpStream;

/// A connected outbound stream ready for data relay.
pub enum OutboundStream {
    Tcp(TcpStream),
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
    /// Connection was rejected — no stream to relay.
    Rejected,
}
```

Create `crates/proxy/src/outbound/direct.rs`:

```rust
use super::OutboundStream;
use crate::inbound::TargetAddr;
use anyhow::Result;
use tokio::net::TcpStream;

pub async fn connect(target: &TargetAddr) -> Result<OutboundStream> {
    let addr = format!("{}:{}", target.host_string(), target.port());
    let stream = TcpStream::connect(&addr).await?;
    Ok(OutboundStream::Tcp(stream))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn direct_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let target = TargetAddr::Ip(addr.ip(), addr.port());
        let handle = tokio::spawn(async move {
            let _ = listener.accept().await.unwrap();
        });

        let result = connect(&target).await;
        assert!(result.is_ok());
        handle.await.unwrap();
    }
}
```

- [ ] **Step 2: Write REJECT connector**

Create `crates/proxy/src/outbound/reject.rs`:

```rust
use super::OutboundStream;

pub fn reject() -> OutboundStream {
    OutboundStream::Rejected
}
```

- [ ] **Step 3: Write SOCKS5 outbound connector**

Create `crates/proxy/src/outbound/socks5.rs`:

```rust
use super::OutboundStream;
use crate::inbound::TargetAddr;
use anyhow::{bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const SOCKS5_VERSION: u8 = 0x05;
const NO_AUTH: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_IPV6: u8 = 0x04;

/// Connect to a SOCKS5 proxy server and request a connection to the target.
pub async fn connect(
    server: &str,
    port: u16,
    target: &TargetAddr,
) -> Result<OutboundStream> {
    let mut stream = TcpStream::connect(format!("{server}:{port}")).await?;

    // Method negotiation: version=5, 1 method, NO_AUTH
    stream.write_all(&[SOCKS5_VERSION, 0x01, NO_AUTH]).await?;

    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != SOCKS5_VERSION || resp[1] != NO_AUTH {
        bail!(
            "SOCKS5 method negotiation failed: version={}, method={}",
            resp[0],
            resp[1]
        );
    }

    // Build connect request
    let mut req = vec![SOCKS5_VERSION, CMD_CONNECT, 0x00]; // ver, cmd, rsv

    match target {
        TargetAddr::Domain(domain, port) => {
            req.push(ATYP_DOMAIN);
            req.push(domain.len() as u8);
            req.extend_from_slice(domain.as_bytes());
            req.extend_from_slice(&port.to_be_bytes());
        }
        TargetAddr::Ip(std::net::IpAddr::V4(ip), port) => {
            req.push(ATYP_IPV4);
            req.extend_from_slice(&ip.octets());
            req.extend_from_slice(&port.to_be_bytes());
        }
        TargetAddr::Ip(std::net::IpAddr::V6(ip), port) => {
            req.push(ATYP_IPV6);
            req.extend_from_slice(&ip.octets());
            req.extend_from_slice(&port.to_be_bytes());
        }
    }

    stream.write_all(&req).await?;

    // Read response: version, rep, rsv, atyp, then bound addr
    let mut resp_header = [0u8; 4];
    stream.read_exact(&mut resp_header).await?;
    if resp_header[1] != 0x00 {
        bail!("SOCKS5 connect failed with rep={}", resp_header[1]);
    }

    // Skip bound address based on atyp
    match resp_header[3] {
        ATYP_IPV4 => {
            let mut skip = [0u8; 6]; // 4 IP + 2 port
            stream.read_exact(&mut skip).await?;
        }
        ATYP_DOMAIN => {
            let len = stream.read_u8().await? as usize;
            let mut skip = vec![0u8; len + 2]; // domain + 2 port
            stream.read_exact(&mut skip).await?;
        }
        ATYP_IPV6 => {
            let mut skip = [0u8; 18]; // 16 IP + 2 port
            stream.read_exact(&mut skip).await?;
        }
        _ => bail!("unknown SOCKS5 bound address type: {}", resp_header[3]),
    }

    Ok(OutboundStream::Tcp(stream))
}
```

- [ ] **Step 4: Create empty trojan placeholder**

Create `crates/proxy/src/outbound/trojan.rs`:
```rust
// Trojan outbound connector - implemented in Task 10
```

- [ ] **Step 5: Update lib.rs**

```rust
pub mod inbound;
pub mod outbound;
pub mod relay;
```

- [ ] **Step 6: Run tests**

Run: `cargo test -p clashx-rs-proxy`
Expected: 7 tests pass (6 prior + 1 direct)

- [ ] **Step 7: Commit**

```bash
git add crates/proxy/
git commit -m "feat(proxy): DIRECT, REJECT, and SOCKS5 outbound connectors"
```

---

### Task 10: Trojan Outbound Connector

**Files:**
- Modify: `crates/proxy/src/outbound/trojan.rs`

- [ ] **Step 1: Write Trojan connector**

Replace `crates/proxy/src/outbound/trojan.rs`:

```rust
use super::OutboundStream;
use crate::inbound::TargetAddr;
use anyhow::Result;
use rustls::pki_types::ServerName;
use sha2::{Digest, Sha224};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const CRLF: &[u8] = b"\r\n";

/// Connect to a Trojan proxy server.
pub async fn connect(
    server: &str,
    port: u16,
    password: &str,
    sni: Option<&str>,
    skip_cert_verify: bool,
    target: &TargetAddr,
) -> Result<OutboundStream> {
    // 1. TCP connect
    let tcp_stream = TcpStream::connect(format!("{server}:{port}")).await?;

    // 2. TLS handshake
    let tls_config = build_tls_config(skip_cert_verify)?;
    let connector = TlsConnector::from(Arc::new(tls_config));
    let server_name = ServerName::try_from(sni.unwrap_or(server).to_string())?;
    let mut tls_stream = connector.connect(server_name, tcp_stream).await?;

    // 3. Send Trojan header
    let header = build_trojan_header(password, target);
    tls_stream.write_all(&header).await?;

    Ok(OutboundStream::Tls(tls_stream))
}

fn build_tls_config(skip_cert_verify: bool) -> Result<rustls::ClientConfig> {
    if skip_cert_verify {
        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
            .with_no_client_auth();
        Ok(config)
    } else {
        let root_store = rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        );
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        Ok(config)
    }
}

fn build_trojan_header(password: &str, target: &TargetAddr) -> Vec<u8> {
    let mut buf = Vec::new();

    // SHA224 hex-encoded password
    let hash = Sha224::digest(password.as_bytes());
    let hex_hash = hex::encode(hash);
    buf.extend_from_slice(hex_hash.as_bytes());
    buf.extend_from_slice(CRLF);

    // CMD + address
    buf.push(CMD_CONNECT);
    match target {
        TargetAddr::Domain(domain, port) => {
            buf.push(ATYP_DOMAIN);
            buf.push(domain.len() as u8);
            buf.extend_from_slice(domain.as_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
        }
        TargetAddr::Ip(std::net::IpAddr::V4(ip), port) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&ip.octets());
            buf.extend_from_slice(&port.to_be_bytes());
        }
        TargetAddr::Ip(std::net::IpAddr::V6(ip), port) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&ip.octets());
            buf.extend_from_slice(&port.to_be_bytes());
        }
    }
    buf.extend_from_slice(CRLF);

    buf
}

/// Certificate verifier that accepts any certificate (for skip-cert-verify: true).
#[derive(Debug)]
struct NoCertVerifier;

impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trojan_header_domain() {
        let target = TargetAddr::Domain("example.com".to_string(), 443);
        let header = build_trojan_header("test-password", &target);

        // SHA224("test-password") hex-encoded = 56 bytes
        let hash_hex = &header[..56];
        let expected_hash = hex::encode(Sha224::digest(b"test-password"));
        assert_eq!(hash_hex, expected_hash.as_bytes());

        // CRLF after hash
        assert_eq!(&header[56..58], b"\r\n");

        // CMD = CONNECT
        assert_eq!(header[58], CMD_CONNECT);

        // ATYP = DOMAIN
        assert_eq!(header[59], ATYP_DOMAIN);

        // Domain length
        assert_eq!(header[60], 11); // "example.com".len()

        // Domain
        assert_eq!(&header[61..72], b"example.com");

        // Port 443 big-endian
        assert_eq!(&header[72..74], &443u16.to_be_bytes());

        // CRLF at end
        assert_eq!(&header[74..76], b"\r\n");
    }

    #[test]
    fn trojan_header_ipv4() {
        let target = TargetAddr::Ip("1.2.3.4".parse().unwrap(), 80);
        let header = build_trojan_header("pass", &target);

        // After hash (56) + CRLF (2) + CMD (1) = byte 59
        assert_eq!(header[59], ATYP_IPV4);
        assert_eq!(&header[60..64], &[1, 2, 3, 4]);
        assert_eq!(&header[64..66], &80u16.to_be_bytes());
    }
}
```

- [ ] **Step 2: Add hex and webpki-roots dependencies**

In `crates/proxy/Cargo.toml`, add:
```toml
hex = "0.4"
webpki-roots = "0.26"
```

And in `[workspace.dependencies]` of root `Cargo.toml`:
```toml
hex = "0.4"
webpki-roots = "0.26"
```

Update `crates/proxy/Cargo.toml` dependencies:
```toml
hex.workspace = true
webpki-roots.workspace = true
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p clashx-rs-proxy`
Expected: 9 tests pass (7 prior + 2 trojan header)

- [ ] **Step 4: Commit**

```bash
git add crates/proxy/ Cargo.toml
git commit -m "feat(proxy): Trojan outbound connector with TLS and SHA-224 auth"
```

---

### Task 11: System Proxy Management

**Files:**
- Modify: `crates/sysproxy/src/lib.rs` (replace stub)
- Create: `crates/sysproxy/src/macos.rs`
- Create: `crates/sysproxy/src/linux.rs`

- [ ] **Step 1: Write sysproxy trait and platform dispatch**

Replace `crates/sysproxy/src/lib.rs`:

```rust
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "linux")]
mod linux;

use anyhow::Result;

pub struct SysProxy {
    port: u16,
}

impl SysProxy {
    pub fn new(port: u16) -> Self {
        SysProxy { port }
    }

    pub fn enable(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        return macos::enable(self.port);
        #[cfg(target_os = "linux")]
        return linux::enable(self.port);
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            tracing::warn!("system proxy not supported on this platform");
            Ok(())
        }
    }

    pub fn disable(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        return macos::disable();
        #[cfg(target_os = "linux")]
        return linux::disable();
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        Ok(())
    }

    pub fn status(&self) -> Result<String> {
        #[cfg(target_os = "macos")]
        return macos::status();
        #[cfg(target_os = "linux")]
        return linux::status(self.port);
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        Ok("unsupported platform".to_string())
    }
}
```

- [ ] **Step 2: Write macOS implementation**

Create `crates/sysproxy/src/macos.rs`:

```rust
use anyhow::{Context, Result};
use std::process::Command;

pub fn enable(port: u16) -> Result<()> {
    let services = get_active_services()?;
    for service in &services {
        run_networksetup(&["-setwebproxy", service, "127.0.0.1", &port.to_string()])?;
        run_networksetup(&["-setsecurewebproxy", service, "127.0.0.1", &port.to_string()])?;
        run_networksetup(&["-setsocksfirewallproxy", service, "127.0.0.1", &port.to_string()])?;
        tracing::info!("enabled system proxy on {service}");
    }
    Ok(())
}

pub fn disable() -> Result<()> {
    let services = get_active_services()?;
    for service in &services {
        run_networksetup(&["-setwebproxystate", service, "off"])?;
        run_networksetup(&["-setsecurewebproxystate", service, "off"])?;
        run_networksetup(&["-setsocksfirewallproxystate", service, "off"])?;
        tracing::info!("disabled system proxy on {service}");
    }
    Ok(())
}

pub fn status() -> Result<String> {
    let services = get_active_services()?;
    let mut output = String::new();
    for service in &services {
        let result = Command::new("networksetup")
            .args(["-getwebproxy", service])
            .output()
            .context("failed to run networksetup")?;
        output.push_str(&format!("--- {service} ---\n"));
        output.push_str(&String::from_utf8_lossy(&result.stdout));
    }
    Ok(output)
}

fn get_active_services() -> Result<Vec<String>> {
    let output = Command::new("networksetup")
        .args(["-listallnetworkservices"])
        .output()
        .context("failed to run networksetup")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let services: Vec<String> = stdout
        .lines()
        .skip(1) // skip header line "An asterisk (*) denotes..."
        .filter(|line| !line.starts_with('*')) // skip disabled services
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect();
    Ok(services)
}

fn run_networksetup(args: &[&str]) -> Result<()> {
    let output = Command::new("networksetup")
        .args(args)
        .output()
        .with_context(|| format!("failed to run networksetup {}", args.join(" ")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("networksetup failed: {stderr}");
    }
    Ok(())
}
```

- [ ] **Step 3: Write Linux implementation**

Create `crates/sysproxy/src/linux.rs`:

```rust
use anyhow::Result;

pub fn enable(port: u16) -> Result<()> {
    println!("# Run the following to enable system proxy:");
    println!("export http_proxy=http://127.0.0.1:{port}");
    println!("export https_proxy=http://127.0.0.1:{port}");
    println!("export all_proxy=socks5://127.0.0.1:{port}");
    println!("export no_proxy=localhost,127.0.0.1,::1");
    Ok(())
}

pub fn disable() -> Result<()> {
    println!("# Run the following to disable system proxy:");
    println!("unset http_proxy");
    println!("unset https_proxy");
    println!("unset all_proxy");
    println!("unset no_proxy");
    Ok(())
}

pub fn status(port: u16) -> Result<String> {
    let http = std::env::var("http_proxy").unwrap_or_else(|_| "(not set)".to_string());
    let https = std::env::var("https_proxy").unwrap_or_else(|_| "(not set)".to_string());
    Ok(format!(
        "http_proxy={http}\nhttps_proxy={https}\nexpected=http://127.0.0.1:{port}"
    ))
}
```

- [ ] **Step 4: Run build**

Run: `cargo build -p clashx-rs-sysproxy`
Expected: Compiles successfully

- [ ] **Step 5: Commit**

```bash
git add crates/sysproxy/
git commit -m "feat(sysproxy): macOS networksetup and Linux env var system proxy"
```

---

### Task 12: Control Protocol Types

**Files:**
- Create: `src/control.rs`

- [ ] **Step 1: Define control messages**

Create `src/control.rs`:

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "lowercase")]
pub enum ControlRequest {
    Status,
    Stop,
    Reload,
    Switch { group: String, proxy: String },
    Proxies,
    Groups,
    Rules,
    Test { domain: String },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ControlResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ControlResponse {
    pub fn success(data: serde_json::Value) -> Self {
        ControlResponse {
            ok: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn error(msg: impl Into<String>) -> Self {
        ControlResponse {
            ok: false,
            data: None,
            error: Some(msg.into()),
        }
    }

    pub fn ok() -> Self {
        ControlResponse {
            ok: true,
            data: None,
            error: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_switch_request() {
        let req = ControlRequest::Switch {
            group: "@singapo".to_string(),
            proxy: "新加坡 01".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"command\":\"switch\""));
        assert!(json.contains("@singapo"));
    }

    #[test]
    fn deserialize_status_request() {
        let json = r#"{"command":"status"}"#;
        let req: ControlRequest = serde_json::from_str(json).unwrap();
        assert!(matches!(req, ControlRequest::Status));
    }

    #[test]
    fn serialize_response() {
        let resp = ControlResponse::error("not found");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"ok\":false"));
        assert!(json.contains("not found"));
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test --lib control`
Expected: 3 tests pass

- [ ] **Step 3: Commit**

```bash
git add src/control.rs
git commit -m "feat: control protocol request/response types"
```

---

### Task 13: CLI Entry Point (clap)

**Files:**
- Modify: `src/main.rs`
- Create: `src/client.rs`
- Create: `src/daemon.rs`

- [ ] **Step 1: Write CLI argument parser**

Replace `src/main.rs`:

```rust
mod client;
mod control;
mod daemon;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "clashx-rs", version, about = "CLI proxy tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the proxy daemon
    Run {
        /// Path to config file
        #[arg(short, long, default_value = "~/.config/clashx-rs/config.yaml")]
        config: String,
        /// Run in background (detached)
        #[arg(short, long)]
        daemon: bool,
    },
    /// Stop the running daemon
    Stop,
    /// Reload configuration
    Reload,
    /// Show daemon status
    Status,
    /// List all proxy nodes
    Proxies,
    /// List proxy groups and current selections
    Groups,
    /// Switch active proxy in a group
    Switch {
        /// Proxy group name
        group: String,
        /// Proxy name to switch to
        proxy: String,
    },
    /// List active rules
    Rules,
    /// Test which rule matches a domain
    Test {
        /// Domain to test
        domain: String,
    },
    /// Manage system proxy
    Sysproxy {
        #[command(subcommand)]
        action: SysproxyAction,
    },
}

#[derive(Subcommand)]
enum SysproxyAction {
    /// Enable system proxy
    On,
    /// Disable system proxy
    Off,
    /// Show system proxy status
    Status,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    match cli.command {
        Commands::Run { config, daemon: bg } => {
            let config_path = expand_tilde(&config);
            if bg {
                daemon::start_background(&config_path)?;
            } else {
                daemon::start_foreground(&config_path)?;
            }
        }
        Commands::Stop => client::send_command(control::ControlRequest::Stop)?,
        Commands::Reload => client::send_command(control::ControlRequest::Reload)?,
        Commands::Status => client::send_command(control::ControlRequest::Status)?,
        Commands::Proxies => client::send_command(control::ControlRequest::Proxies)?,
        Commands::Groups => client::send_command(control::ControlRequest::Groups)?,
        Commands::Switch { group, proxy } => {
            client::send_command(control::ControlRequest::Switch { group, proxy })?
        }
        Commands::Rules => client::send_command(control::ControlRequest::Rules)?,
        Commands::Test { domain } => {
            client::send_command(control::ControlRequest::Test { domain })?
        }
        Commands::Sysproxy { action } => match action {
            SysproxyAction::On => {
                let sysproxy = clashx_rs_sysproxy::SysProxy::new(7890);
                sysproxy.enable()?;
                println!("System proxy enabled");
            }
            SysproxyAction::Off => {
                let sysproxy = clashx_rs_sysproxy::SysProxy::new(7890);
                sysproxy.disable()?;
                println!("System proxy disabled");
            }
            SysproxyAction::Status => {
                let sysproxy = clashx_rs_sysproxy::SysProxy::new(7890);
                println!("{}", sysproxy.status()?);
            }
        },
    }

    Ok(())
}

fn expand_tilde(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(&path[2..]);
        }
    }
    PathBuf::from(path)
}
```

- [ ] **Step 2: Add dirs dependency**

In root `Cargo.toml` `[workspace.dependencies]`:
```toml
dirs = "6"
```

In root `Cargo.toml` `[dependencies]`:
```toml
dirs.workspace = true
```

- [ ] **Step 3: Write client stub**

Create `src/client.rs`:

```rust
use crate::control::{ControlRequest, ControlResponse};
use anyhow::{Context, Result};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

fn socket_path() -> std::path::PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".config/clashx-rs/clashx-rs.sock")
}

pub fn send_command(request: ControlRequest) -> Result<()> {
    let path = socket_path();
    let mut stream =
        UnixStream::connect(&path).with_context(|| format!("cannot connect to daemon at {}", path.display()))?;

    let json = serde_json::to_string(&request)?;
    writeln!(stream, "{json}")?;
    stream.flush()?;

    let reader = BufReader::new(&stream);
    let mut line = String::new();
    let mut reader = reader;
    reader.read_line(&mut line)?;

    let response: ControlResponse = serde_json::from_str(line.trim())?;
    if response.ok {
        if let Some(data) = response.data {
            println!("{}", serde_json::to_string_pretty(&data)?);
        } else {
            println!("OK");
        }
    } else {
        eprintln!("Error: {}", response.error.unwrap_or_default());
        std::process::exit(1);
    }

    Ok(())
}
```

- [ ] **Step 4: Write daemon stub**

Create `src/daemon.rs`:

```rust
use anyhow::Result;
use std::path::Path;

pub fn start_foreground(config_path: &Path) -> Result<()> {
    tracing::info!("starting daemon with config: {}", config_path.display());

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async { run_daemon(config_path).await })
}

pub fn start_background(config_path: &Path) -> Result<()> {
    // For now, just print instructions
    println!(
        "Background mode not yet implemented. Run in foreground:\n  clashx-rs run --config {}",
        config_path.display()
    );
    Ok(())
}

async fn run_daemon(config_path: &Path) -> Result<()> {
    let config = clashx_rs_config::load_config(config_path)?;
    tracing::info!(
        "loaded config: mixed-port={}, {} proxies, {} rules",
        config.mixed_port,
        config.proxies.len(),
        config.rules.len()
    );

    println!("Daemon loaded on port {} (engine wiring in Task 14)", config.mixed_port);
    tokio::signal::ctrl_c().await?;
    Ok(())
}
```

- [ ] **Step 5: Verify it builds and CLI help works**

Run: `cargo build && cargo run -- --help`
Expected: Builds successfully and prints help text showing all subcommands

- [ ] **Step 6: Commit**

```bash
git add src/ Cargo.toml
git commit -m "feat: CLI entry point with clap, client stub, daemon stub"
```

---

### Task 14: Proxy Engine Integration

**Files:**
- Modify: `src/daemon.rs`

This is the core task: wire everything together so the daemon accepts connections, runs the rule engine, and connects outbound.

- [ ] **Step 1: Write the full proxy engine in daemon.rs**

Replace `src/daemon.rs`:

```rust
use crate::control::{ControlRequest, ControlResponse};
use anyhow::{Context, Result};
use clashx_rs_config::types::{Config, Proxy};
use clashx_rs_config::rule::RuleEntry;
use clashx_rs_proxy::inbound::{self, TargetAddr};
use clashx_rs_proxy::outbound;
use clashx_rs_proxy::relay;
use clashx_rs_rule::{MatchInput, RuleEngine};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::RwLock;

struct DaemonState {
    config: Config,
    config_path: PathBuf,
    rule_engine: RuleEngine,
    proxies: HashMap<String, Proxy>,
    /// group_name -> currently selected proxy name
    selections: HashMap<String, String>,
}

impl DaemonState {
    fn from_config(config: Config, config_path: PathBuf) -> Self {
        let rule_engine = RuleEngine::new(&config.rules);

        let proxies: HashMap<String, Proxy> = config
            .proxies
            .iter()
            .filter_map(|p| p.name().map(|n| (n.to_string(), p.clone())))
            .collect();

        let selections: HashMap<String, String> = config
            .proxy_groups
            .iter()
            .filter_map(|g| {
                g.proxies.first().map(|first| (g.name.clone(), first.clone()))
            })
            .collect();

        DaemonState {
            config,
            config_path,
            rule_engine,
            proxies,
            selections,
        }
    }

    fn resolve_target_proxy(&self, rule_target: &str) -> Option<&str> {
        // Check if it's a direct action
        match rule_target {
            "DIRECT" | "REJECT" => return Some(rule_target),
            _ => {}
        }
        // Check if it's a group name -> resolve to selected proxy
        if let Some(selected) = self.selections.get(rule_target) {
            // The selected proxy might itself be DIRECT
            if selected == "DIRECT" || selected == "REJECT" {
                return Some(selected);
            }
            return Some(selected);
        }
        // Check if it's a direct proxy name
        if self.proxies.contains_key(rule_target) {
            return Some(rule_target);
        }
        None
    }
}

pub fn start_foreground(config_path: &Path) -> Result<()> {
    tracing::info!("starting daemon with config: {}", config_path.display());
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async { run_daemon(config_path).await })
}

pub fn start_background(config_path: &Path) -> Result<()> {
    println!(
        "Background mode not yet implemented. Run in foreground:\n  clashx-rs run --config {}",
        config_path.display()
    );
    Ok(())
}

async fn run_daemon(config_path: &Path) -> Result<()> {
    let config = clashx_rs_config::load_config(config_path)?;
    let bind_addr = if config.allow_lan {
        format!("{}:{}", config.bind_address.replace('*', "0.0.0.0"), config.mixed_port)
    } else {
        format!("127.0.0.1:{}", config.mixed_port)
    };

    let state = Arc::new(RwLock::new(DaemonState::from_config(
        config.clone(),
        config_path.to_path_buf(),
    )));

    // Ensure runtime directory exists
    let runtime_dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config/clashx-rs");
    std::fs::create_dir_all(&runtime_dir)?;

    // Start control socket
    let sock_path = runtime_dir.join("clashx-rs.sock");
    // Remove stale socket
    let _ = std::fs::remove_file(&sock_path);
    let control_listener = UnixListener::bind(&sock_path)?;
    tracing::info!("control socket: {}", sock_path.display());

    // Write PID file
    let pid_path = runtime_dir.join("clashx-rs.pid");
    std::fs::write(&pid_path, std::process::id().to_string())?;

    // Start proxy listener
    let proxy_listener = TcpListener::bind(&bind_addr).await?;
    tracing::info!(
        "listening on {} ({} proxies, {} rules)",
        bind_addr,
        config.proxies.len(),
        config.rules.len()
    );

    // Spawn control socket handler
    let control_state = state.clone();
    let control_handle = tokio::spawn(async move {
        loop {
            match control_listener.accept().await {
                Ok((stream, _)) => {
                    let state = control_state.clone();
                    tokio::spawn(handle_control(stream, state));
                }
                Err(e) => tracing::warn!("control accept error: {e}"),
            }
        }
    });

    // Spawn proxy connection handler
    let proxy_state = state.clone();
    let proxy_handle = tokio::spawn(async move {
        loop {
            match proxy_listener.accept().await {
                Ok((stream, addr)) => {
                    let state = proxy_state.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, addr, state).await {
                            tracing::debug!("connection error from {addr}: {e}");
                        }
                    });
                }
                Err(e) => tracing::warn!("accept error: {e}"),
            }
        }
    });

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down...");

    // Cleanup
    let _ = std::fs::remove_file(&sock_path);
    let _ = std::fs::remove_file(&pid_path);

    Ok(())
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    source_addr: std::net::SocketAddr,
    state: Arc<RwLock<DaemonState>>,
) -> Result<()> {
    let result = inbound::detect_and_handle(stream, source_addr).await?;
    let target = &result.target;

    let host = target.host_string();
    let input = MatchInput {
        host: Some(&host),
        ip: host.parse().ok(),
        process_name: None, // Process name lookup deferred
    };

    let state_read = state.read().await;
    let rule_target = state_read
        .rule_engine
        .evaluate(&input)
        .unwrap_or("DIRECT");

    let proxy_name = state_read
        .resolve_target_proxy(rule_target)
        .unwrap_or("DIRECT");

    tracing::info!(
        "{} -> {} (rule: {}, proxy: {})",
        host,
        target.port(),
        rule_target,
        proxy_name
    );

    match proxy_name {
        "DIRECT" => {
            drop(state_read);
            let outbound = outbound::direct::connect(target).await?;
            if let outbound::OutboundStream::Tcp(upstream) = outbound {
                relay::relay(result.stream, upstream).await?;
            }
        }
        "REJECT" => {
            drop(state_read);
            // Just drop the connection
        }
        name => {
            let proxy = state_read.proxies.get(name).cloned();
            drop(state_read);

            match proxy {
                Some(Proxy::Trojan(t)) => {
                    let outbound = outbound::trojan::connect(
                        &t.server,
                        t.port,
                        &t.password,
                        t.sni.as_deref(),
                        t.skip_cert_verify,
                        target,
                    )
                    .await?;
                    if let outbound::OutboundStream::Tls(upstream) = outbound {
                        relay::relay(result.stream, upstream).await?;
                    }
                }
                Some(Proxy::Socks5(s)) => {
                    let outbound =
                        outbound::socks5::connect(&s.server, s.port, target).await?;
                    if let outbound::OutboundStream::Tcp(upstream) = outbound {
                        relay::relay(result.stream, upstream).await?;
                    }
                }
                Some(Proxy::Unknown) | None => {
                    tracing::warn!("unknown proxy: {name}, using DIRECT");
                    let outbound = outbound::direct::connect(target).await?;
                    if let outbound::OutboundStream::Tcp(upstream) = outbound {
                        relay::relay(result.stream, upstream).await?;
                    }
                }
            }
        }
    }

    Ok(())
}

async fn handle_control(
    stream: tokio::net::UnixStream,
    state: Arc<RwLock<DaemonState>>,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    reader.read_line(&mut line).await?;

    let request: ControlRequest = serde_json::from_str(line.trim())?;
    let response = match request {
        ControlRequest::Status => {
            let state = state.read().await;
            ControlResponse::success(serde_json::json!({
                "running": true,
                "config": state.config_path.display().to_string(),
                "mixed_port": state.config.mixed_port,
                "proxy_count": state.proxies.len(),
                "rule_count": state.config.rules.len(),
            }))
        }
        ControlRequest::Switch { group, proxy } => {
            let mut state = state.write().await;
            if !state.selections.contains_key(&group) {
                ControlResponse::error(format!("group not found: {group}"))
            } else {
                state.selections.insert(group.clone(), proxy.clone());
                ControlResponse::success(serde_json::json!({
                    "group": group,
                    "selected": proxy,
                }))
            }
        }
        ControlRequest::Proxies => {
            let state = state.read().await;
            let names: Vec<&String> = state.proxies.keys().collect();
            ControlResponse::success(serde_json::json!({ "proxies": names }))
        }
        ControlRequest::Groups => {
            let state = state.read().await;
            let groups: Vec<serde_json::Value> = state
                .config
                .proxy_groups
                .iter()
                .map(|g| {
                    serde_json::json!({
                        "name": g.name,
                        "type": format!("{:?}", g.group_type),
                        "selected": state.selections.get(&g.name),
                        "proxies": g.proxies,
                    })
                })
                .collect();
            ControlResponse::success(serde_json::json!({ "groups": groups }))
        }
        ControlRequest::Rules => {
            let state = state.read().await;
            ControlResponse::success(serde_json::json!({ "rules": state.config.rules }))
        }
        ControlRequest::Test { domain } => {
            let state = state.read().await;
            let input = MatchInput {
                host: Some(&domain),
                ip: domain.parse().ok(),
                process_name: None,
            };
            let matched = state.rule_engine.evaluate(&input);
            ControlResponse::success(serde_json::json!({
                "domain": domain,
                "matched_target": matched,
            }))
        }
        ControlRequest::Reload => {
            let mut state = state.write().await;
            match clashx_rs_config::load_config(&state.config_path) {
                Ok(new_config) => {
                    let new_state =
                        DaemonState::from_config(new_config, state.config_path.clone());
                    *state = new_state;
                    ControlResponse::ok()
                }
                Err(e) => ControlResponse::error(format!("reload failed: {e}")),
            }
        }
        ControlRequest::Stop => {
            // Send response before exiting
            let resp = ControlResponse::ok();
            let json = serde_json::to_string(&resp)?;
            writer.write_all(json.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;
            std::process::exit(0);
        }
    };

    let json = serde_json::to_string(&response)?;
    writer.write_all(json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}
```

- [ ] **Step 2: Verify it builds**

Run: `cargo build`
Expected: Compiles successfully

- [ ] **Step 3: Test with real config**

Run: `cargo run -- run --config ~/.config/clash/WgetCloud.yaml`
Expected: Prints "listening on 0.0.0.0:7890 (35 proxies, 134 rules)" (numbers may vary), then waits for Ctrl+C

- [ ] **Step 4: Test CLI commands in a separate terminal**

Run (in another terminal):
```bash
cargo run -- status
cargo run -- groups
cargo run -- test google.com
```
Expected: `status` shows running info, `groups` lists proxy groups, `test` shows which rule matches google.com

- [ ] **Step 5: Commit**

```bash
git add src/daemon.rs
git commit -m "feat: proxy engine integration - full daemon with inbound/rule/outbound pipeline"
```

---

### Task 15: End-to-End Testing

**Files:**
- Create: `tests/integration/config_parse.rs`
- Create: `tests/integration/rule_engine.rs`

- [ ] **Step 1: Create integration test for real config parsing**

Create `tests/integration/config_parse.rs`:

```rust
use clashx_rs_config::load_config;
use clashx_rs_config::types::Proxy;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn parse_real_world_config() {
    let yaml = r#"
mixed-port: 7890
allow-lan: true
bind-address: '*'
mode: rule
log-level: info
external-controller: 127.0.0.1:9090
dns:
  enable: false
  ipv6: false
proxies:
  - name: "hk-01"
    type: trojan
    server: 1.2.3.4
    port: 4005
    password: "test-password-uuid"
    sni: baidu.com
    skip-cert-verify: true
  - name: "corpnet-proxy"
    type: socks5
    server: proxy.example.com
    port: 1081
  - name: "vmess-node"
    type: vmess
    server: 5.6.7.8
    port: 443
proxy-groups:
  - name: "main-select"
    type: select
    proxies:
      - "hk-01"
      - DIRECT
  - name: "@corpnet"
    type: select
    proxies:
      - "corpnet-proxy"
rules:
  - IP-CIDR,172.16.0.0/16,@corpnet
  - DOMAIN-SUFFIX,google.com,main-select
  - PROCESS-NAME,FortiClient,@corpnet
  - MATCH,DIRECT
"#;
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(yaml.as_bytes()).unwrap();

    let config = load_config(f.path()).unwrap();

    assert_eq!(config.mixed_port, 7890);
    assert!(config.allow_lan);

    // Trojan parsed correctly
    assert!(matches!(&config.proxies[0], Proxy::Trojan(t) if t.name == "hk-01"));

    // SOCKS5 parsed correctly
    assert!(matches!(&config.proxies[1], Proxy::Socks5(s) if s.name == "corpnet-proxy"));

    // VMess becomes Unknown (unsupported)
    assert!(matches!(&config.proxies[2], Proxy::Unknown));

    // Groups
    assert_eq!(config.proxy_groups.len(), 2);
    assert_eq!(config.proxy_groups[0].name, "main-select");

    // Rules as raw strings
    assert_eq!(config.rules.len(), 4);
}
```

- [ ] **Step 2: Create integration test for rule engine**

Create `tests/integration/rule_engine.rs`:

```rust
use clashx_rs_rule::{MatchInput, RuleEngine};

#[test]
fn real_world_rule_evaluation() {
    let rules = vec![
        "IP-CIDR,172.16.0.0/16,@corpnet".to_string(),
        "IP-CIDR,172.17.0.0/16,@corpnet".to_string(),
        "DOMAIN-SUFFIX,google.com,@singapo".to_string(),
        "DOMAIN-SUFFIX,claude.ai,@singapo".to_string(),
        "DOMAIN-SUFFIX,anthropic.com,@singapo".to_string(),
        "DOMAIN-SUFFIX,acmecorptrade.com,@direct-only".to_string(),
        "PROCESS-NAME,FortiClientAgent,@direct-only".to_string(),
        "PROCESS-NAME,DingTalk,@direct-only".to_string(),
        "MATCH,DIRECT".to_string(),
    ];

    let engine = RuleEngine::new(&rules);

    // Google -> @singapo
    let input = MatchInput {
        host: Some("www.google.com"),
        ip: None,
        process_name: None,
    };
    assert_eq!(engine.evaluate(&input), Some("@singapo"));

    // Claude -> @singapo
    let input = MatchInput {
        host: Some("claude.ai"),
        ip: None,
        process_name: None,
    };
    assert_eq!(engine.evaluate(&input), Some("@singapo"));

    // Corporate IP -> @corpnet
    let input = MatchInput {
        host: None,
        ip: Some("172.16.5.3".parse().unwrap()),
        process_name: None,
    };
    assert_eq!(engine.evaluate(&input), Some("@corpnet"));

    // FortiClient -> @direct-only
    let input = MatchInput {
        host: None,
        ip: None,
        process_name: Some("FortiClientAgent"),
    };
    assert_eq!(engine.evaluate(&input), Some("@direct-only"));

    // Unknown domain -> MATCH -> DIRECT
    let input = MatchInput {
        host: Some("random-site.xyz"),
        ip: None,
        process_name: None,
    };
    assert_eq!(engine.evaluate(&input), Some("DIRECT"));
}
```

- [ ] **Step 3: Add tempfile to workspace dev-dependencies**

In root `Cargo.toml`:
```toml
[dev-dependencies]
tempfile = "3"
```

- [ ] **Step 4: Run all tests**

Run: `cargo test`
Expected: All tests pass across all crates and integration tests

- [ ] **Step 5: Commit**

```bash
git add tests/ Cargo.toml
git commit -m "test: integration tests for config parsing and rule engine"
```

---

### Task 16: Signal Handling and System Proxy Cleanup

**Files:**
- Modify: `src/daemon.rs`

- [ ] **Step 1: Add signal handling for graceful shutdown with sysproxy cleanup**

In `src/daemon.rs`, modify the `run_daemon` function's shutdown section. Find the section after `tokio::signal::ctrl_c().await?;` and update it:

```rust
    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down...");

    // Disable system proxy if it was enabled
    let sysproxy = clashx_rs_sysproxy::SysProxy::new(config.mixed_port);
    if let Err(e) = sysproxy.disable() {
        tracing::warn!("failed to disable system proxy: {e}");
    }

    // Cleanup files
    let _ = std::fs::remove_file(&sock_path);
    let _ = std::fs::remove_file(&pid_path);
```

- [ ] **Step 2: Verify it builds**

Run: `cargo build`
Expected: Compiles successfully

- [ ] **Step 3: Commit**

```bash
git add src/daemon.rs
git commit -m "feat: graceful shutdown with system proxy cleanup on SIGINT"
```

---

### Task 17: Final Verification

- [ ] **Step 1: Run full test suite**

Run: `cargo test`
Expected: All tests pass

- [ ] **Step 2: Run lints**

Run: `cargo clippy --all-targets -- -D warnings`
Expected: No warnings

- [ ] **Step 3: Run format check**

Run: `cargo fmt --check`
Expected: No formatting issues

- [ ] **Step 4: Build release binary**

Run: `cargo build --release`
Expected: Binary at `target/release/clashx-rs`

- [ ] **Step 5: Verify CLI help**

Run: `./target/release/clashx-rs --help`
Expected: Shows all subcommands (run, stop, reload, status, proxies, groups, switch, rules, test, sysproxy)

- [ ] **Step 6: Test with real config**

Run: `./target/release/clashx-rs run --config ~/.config/clash/WgetCloud.yaml`
Expected: Starts successfully, shows listening message with correct proxy/rule counts

- [ ] **Step 7: Commit any final fixes and tag**

```bash
git tag v0.1.0
```
