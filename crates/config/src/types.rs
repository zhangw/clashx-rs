//! Typed representation of a Clash/mihomo YAML configuration.
//!
//! Every type mirrors the YAML keys and is a pure data-transfer struct with
//! public fields; parsing performs no validation beyond what `serde` enforces.
//! The daemon and the DNS/rule/proxy crates decide what an absent or
//! unrecognized value means, and the docs on each field state the default
//! that applies when the key is absent.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Top-level configuration document, usually `~/.config/clashx-rs/config.yaml`.
///
/// Keys use `kebab-case` in YAML. Unknown keys are preserved in
/// [`Config::extra`] and otherwise ignored, so configs for newer mihomo
/// versions still load.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    /// `mixed-port`: TCP port of the inbound mixed HTTP/SOCKS5 listener.
    ///
    /// Absent means `7890`, the daemon's default port.
    #[serde(default)]
    pub mixed_port: Option<u16>,
    /// `allow-lan`: expose the mixed listener beyond loopback.
    ///
    /// Absent means `false`, which binds `127.0.0.1` only. When `true` the
    /// listener binds `0.0.0.0` unless [`Config::bind_address`] says
    /// otherwise. The listener has no authentication, so enabling this
    /// exposes an open proxy to the local network.
    #[serde(default)]
    pub allow_lan: Option<bool>,
    /// `bind-address`: listener address used when `allow-lan` is `true`.
    ///
    /// Absent, or the literal `*`, means `0.0.0.0`. Ignored when `allow-lan`
    /// is `false`, where the daemon always binds `127.0.0.1`.
    #[serde(default)]
    pub bind_address: Option<String>,
    /// `mode`: routing mode. Absent means [`Mode::Rule`].
    #[serde(default)]
    pub mode: Mode,
    /// `log-level`: tracing verbosity. Absent means [`LogLevel::Info`].
    #[serde(default)]
    pub log_level: LogLevel,
    /// `external-controller`: mihomo REST API address.
    ///
    /// Parsed for config compatibility only. Absent leaves the key unset. No
    /// REST API is implemented, so the value is never read at runtime.
    #[serde(default)]
    pub external_controller: Option<String>,
    /// `dns`: DNS subsystem settings. Absent means every lookup uses the
    /// system resolver and [`Config::hosts`] is ignored.
    #[serde(default)]
    pub dns: Option<DnsConfig>,
    /// Static host-to-IP mappings (mihomo `hosts:`).
    ///
    /// Keys are exact hostnames or `*.suffix` wildcards and matching is
    /// case-insensitive. Values must be IP literals; invalid values are
    /// warned about and skipped. The mappings apply only when DNS is enabled
    /// and [`DnsConfig::use_hosts`] is not `false`.
    #[serde(default)]
    pub hosts: HashMap<String, String>,
    /// `proxies`: outbound proxy nodes.
    ///
    /// The entry's `type` selects the [`Proxy`] variant. Unrecognized types
    /// deserialize as [`Proxy::Unknown`] and are left out of the daemon's node
    /// table. Empty when absent.
    #[serde(default)]
    pub proxies: Vec<Proxy>,
    /// `proxy-groups`: ordered proxy groups.
    ///
    /// Group names are the targets rules route to; [`Mode::Global`] uses the
    /// first group. Empty when absent.
    #[serde(default)]
    pub proxy_groups: Vec<ProxyGroup>,
    /// `rules`: raw rule lines in Clash syntax.
    ///
    /// Order matters: the first match wins, and `MATCH` is the usual
    /// catch-all. Entries are parsed with [`RuleEntry`](crate::rule::RuleEntry);
    /// unrecognized lines are warned about and skipped. Empty when absent.
    #[serde(default)]
    pub rules: Vec<String>,
    /// `skip-proxy`: system-proxy bypass list.
    ///
    /// Used by `clashx-rs sysproxy on` and by the daemon when
    /// [`Config::sysproxy`] is enabled. On macOS, entries are CIDR or domain
    /// strings passed to the OS bypass setting, and an empty list applies the
    /// sysproxy crate's built-in defaults (private ranges, `localhost`,
    /// `*.local`). Linux currently ignores the list and warns when it is
    /// non-empty.
    #[serde(default)]
    pub skip_proxy: Vec<String>,

    /// `sysproxy`: set the macOS system proxy while the daemon runs.
    ///
    /// Absent means `false`; the `--sysproxy` CLI flag overrides it. Enabling
    /// snapshots the previous settings and restores them on exit, but a crash
    /// can leave global network settings pointing at the daemon.
    #[serde(default)]
    pub sysproxy: Option<bool>,
    /// Unknown top-level keys, preserved verbatim.
    ///
    /// They are never interpreted and never fail the parse.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

/// Routing mode selected by the top-level `mode` key.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// `rule`: evaluate `rules` top-to-bottom and route to the first matching
    /// target. This is the default.
    #[default]
    Rule,
    /// `global`: route everything through the first proxy group, ignoring
    /// rules.
    Global,
    /// `direct`: route everything direct, ignoring rules and groups.
    Direct,
}

/// Tracing verbosity selected by the top-level `log-level` key.
///
/// YAML values are lowercase. Invalid values fail the parse.
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// `silent`: disable logging.
    Silent,
    /// `error`: log errors only.
    Error,
    /// `warning`: log errors and warnings. The CLI maps it to the `warn`
    /// tracing level.
    Warning,
    /// `info`: log lifecycle messages. This is the default.
    #[default]
    Info,
    /// `debug`: log per-connection detail.
    Debug,
}

/// The `dns:` block.
///
/// Keys mirror mihomo. Missing keys use the defaults documented per field;
/// unknown keys (for example `fake-ip-range`) are preserved in
/// [`DnsConfig::extra`].
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct DnsConfig {
    /// `dns.enable`: use the configured resolver instead of the system one.
    ///
    /// Absent means `false`: every lookup uses the system resolver, `hosts:`
    /// is ignored, and a configured [`DnsConfig::nameserver`] list triggers a
    /// one-time warning that it is ignored.
    #[serde(default)]
    pub enable: bool,
    /// `dns.ipv6`: request AAAA records.
    ///
    /// Absent means `false`. This build never sends AAAA queries, so `true`
    /// warns once and behaves as `false`.
    #[serde(default)]
    pub ipv6: bool,
    /// `dns.enhanced-mode`: mihomo DNS mode.
    ///
    /// Only `fake-ip` is recognized: it parses but warns once and degrades to
    /// plain mode, because no TUN/DNS entry point and no fake-IP pool exist.
    /// Absent means plain mode.
    #[serde(default)]
    pub enhanced_mode: Option<String>,
    /// `dns.nameserver`: upstream resolvers for normal lookups.
    ///
    /// Upstreams are raced concurrently and the first success wins. Entries
    /// are a bare IP or `udp://host[:port]` (plain UDP, port 53), an
    /// `https://` URL (DNS-over-HTTPS, port 443), or `tls://host[:port]`
    /// (DNS-over-TLS, port 853).
    /// Unsupported or malformed entries are warned about and skipped. When no
    /// usable upstream remains, lookups fall back to the system resolver with
    /// a warning.
    #[serde(default)]
    pub nameserver: Vec<String>,
    /// `dns.default-nameserver`: bootstrap resolvers for DoH/DoT hostnames.
    ///
    /// Only plain-UDP entries are accepted; anything else is warned about and
    /// skipped. When no usable entry remains, bootstrap resolution falls back
    /// to the system resolver. The main [`DnsConfig::nameserver`] group is
    /// never used for bootstrap.
    #[serde(default)]
    pub default_nameserver: Vec<String>,
    /// `dns.proxy-server-nameserver`: upstreams for resolving proxy server
    /// domains, using the same entry schemes as [`DnsConfig::nameserver`].
    ///
    /// Empty falls back to the main `nameserver` group. Bootstrap and `hosts:`
    /// apply to both resolvers.
    #[serde(default)]
    pub proxy_server_nameserver: Vec<String>,
    /// `dns.use-hosts`: whether the top-level `hosts:` mappings apply.
    ///
    /// Absent means enabled; `None` is treated as `true`.
    #[serde(default)]
    pub use_hosts: Option<bool>,
    /// Unknown `dns` keys, preserved verbatim.
    ///
    /// They are never interpreted; for example `fake-ip-range` and
    /// `fake-ip-filter` parse but have no effect.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

/// One entry of the top-level `proxies` list, tagged by its `type` key.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum Proxy {
    /// A `type: trojan` node; see [`TrojanProxy`].
    #[serde(rename = "trojan")]
    Trojan(TrojanProxy),
    /// A `type: socks5` node; see [`Socks5Proxy`].
    #[serde(rename = "socks5")]
    Socks5(Socks5Proxy),
    /// Any unrecognized `type` value.
    ///
    /// The entry carries no settings and is skipped by [`Proxy::name`] and by
    /// the daemon's node table.
    #[serde(other)]
    Unknown,
}

impl Proxy {
    /// Node name used to reference this proxy from `proxy-groups` and rule
    /// targets.
    ///
    /// Returns `None` for [`Proxy::Unknown`].
    pub fn name(&self) -> Option<&str> {
        match self {
            Proxy::Trojan(p) => Some(&p.name),
            Proxy::Socks5(p) => Some(&p.name),
            Proxy::Unknown => None,
        }
    }
}

/// A Trojan outbound node (`type: trojan`).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct TrojanProxy {
    /// `name`: unique node name referenced by groups and rule targets.
    pub name: String,
    /// `server`: upstream hostname or IP address.
    pub server: String,
    /// `port`: upstream TCP port.
    pub port: u16,
    /// `password`: Trojan authentication password. It is hashed with SHA-224
    /// before transmission.
    pub password: String,
    /// `sni`: TLS server name. Absent means use [`TrojanProxy::server`] as the
    /// SNI hostname.
    #[serde(default)]
    pub sni: Option<String>,
    /// `skip-cert-verify`: disable TLS certificate verification.
    ///
    /// Absent means `false`. `true` accepts any certificate and warns once
    /// per process.
    #[serde(default)]
    pub skip_cert_verify: bool,
}

/// A SOCKS5 outbound node (`type: socks5`).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Socks5Proxy {
    /// `name`: unique node name referenced by groups and rule targets.
    pub name: String,
    /// `server`: upstream hostname or IP address.
    pub server: String,
    /// `port`: upstream TCP port.
    pub port: u16,
    /// `username`: SOCKS5 username. Authentication is offered only when both
    /// `username` and `password` are set; absent means no authentication.
    #[serde(default)]
    pub username: Option<String>,
    /// `password`: SOCKS5 password. Absent means no authentication is offered.
    #[serde(default)]
    pub password: Option<String>,
}

/// Default health-check probe URL (`http://www.gstatic.com/generate_204`).
pub const DEFAULT_HEALTH_CHECK_URL: &str = "http://www.gstatic.com/generate_204";
/// Default probe interval in seconds (`300`).
pub const DEFAULT_HEALTH_CHECK_INTERVAL_SECS: u64 = 300;
/// Default HTTP status a health probe must return (`204`).
pub const DEFAULT_HEALTH_CHECK_EXPECTED_STATUS: u16 = 204;

fn default_true() -> bool {
    true
}

fn default_health_check_url() -> String {
    DEFAULT_HEALTH_CHECK_URL.to_string()
}

fn default_health_check_interval() -> u64 {
    DEFAULT_HEALTH_CHECK_INTERVAL_SECS
}

fn default_health_check_expected_status() -> u16 {
    DEFAULT_HEALTH_CHECK_EXPECTED_STATUS
}

/// Active liveness probe settings for a proxy group (mihomo-compatible keys).
///
/// Probing dials the probe URL through each member node itself and expects an
/// exact HTTP status match; it detects "half-dead" nodes that accept local
/// connections but cannot reach the outside.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct HealthCheck {
    /// `health-check.enable`: run probes for the group's members.
    ///
    /// Defaults to `true`. `false` disables active probes for the group.
    #[serde(default = "default_true")]
    pub enable: bool,
    /// `health-check.url`: probe URL dialed through each node.
    ///
    /// Defaults to [`DEFAULT_HEALTH_CHECK_URL`]. Only plain `http://` is
    /// supported; an `https://` URL disables probing for that node with a
    /// one-time warning.
    #[serde(default = "default_health_check_url")]
    pub url: String,
    /// `health-check.interval`: probe interval in seconds.
    ///
    /// Defaults to [`DEFAULT_HEALTH_CHECK_INTERVAL_SECS`]. The daemon enforces
    /// a 30-second floor and adds stable per-node jitter.
    #[serde(default = "default_health_check_interval")]
    pub interval: u64,
    /// `health-check.expected-status`: exact HTTP status the probe must
    /// return.
    ///
    /// Defaults to [`DEFAULT_HEALTH_CHECK_EXPECTED_STATUS`].
    #[serde(default = "default_health_check_expected_status")]
    pub expected_status: u16,
}

impl Default for HealthCheck {
    fn default() -> Self {
        Self {
            enable: true,
            url: default_health_check_url(),
            interval: DEFAULT_HEALTH_CHECK_INTERVAL_SECS,
            expected_status: DEFAULT_HEALTH_CHECK_EXPECTED_STATUS,
        }
    }
}

/// One entry of the top-level `proxy-groups` list.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ProxyGroup {
    /// `name`: group name referenced by rule targets and group lookups.
    pub name: String,
    /// `type`: group strategy; see [`GroupType`].
    #[serde(rename = "type")]
    pub group_type: GroupType,
    /// `proxies`: ordered member names.
    ///
    /// Members are node names, nested group names, or `DIRECT`/`REJECT`. The
    /// first member is the initial selection. Empty when absent.
    #[serde(default)]
    pub proxies: Vec<String>,
    /// `health-check`: probe settings for this group.
    ///
    /// Absent means probing is enabled with the [`HealthCheck`] defaults; see
    /// [`ProxyGroup::effective_health_check`].
    #[serde(default)]
    pub health_check: Option<HealthCheck>,
}

impl ProxyGroup {
    /// Effective health-check settings for this group.
    ///
    /// An absent `health-check` block yields the default [`HealthCheck`],
    /// which has probing enabled.
    pub fn effective_health_check(&self) -> HealthCheck {
        self.health_check.clone().unwrap_or_default()
    }
}

/// Proxy-group strategy selected by `proxy-groups[].type`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GroupType {
    /// `select`: a manual selection group. The daemon starts on the first
    /// member; `--select GROUP=PROXY` can override it at startup.
    Select,
    /// Any unrecognized strategy, preserved so the config still parses.
    ///
    /// Group handling does not branch on the variant, so an unknown strategy
    /// behaves like a selection group; the status output shows the parsed
    /// variant name.
    #[serde(other)]
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_config() {
        let yaml = "mixed-port: 7890\n";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.mixed_port, Some(7890));
        assert_eq!(config.mode, Mode::Rule);
        assert_eq!(config.log_level, LogLevel::Info);
    }

    #[test]
    fn parse_trojan_proxy() {
        let yaml = r#"
proxies:
  - name: my-trojan
    type: trojan
    server: example.com
    port: 443
    password: secret
    sni: example.com
    skip-cert-verify: true
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.proxies.len(), 1);
        if let Proxy::Trojan(p) = &config.proxies[0] {
            assert_eq!(p.name, "my-trojan");
            assert_eq!(p.server, "example.com");
            assert_eq!(p.port, 443);
            assert_eq!(p.password, "secret");
            assert_eq!(p.sni, Some("example.com".to_string()));
            assert!(p.skip_cert_verify);
        } else {
            panic!("expected Trojan proxy");
        }
    }

    #[test]
    fn parse_socks5_proxy() {
        let yaml = r#"
proxies:
  - name: my-socks5
    type: socks5
    server: 127.0.0.1
    port: 1080
    username: user
    password: pass
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.proxies.len(), 1);
        if let Proxy::Socks5(p) = &config.proxies[0] {
            assert_eq!(p.name, "my-socks5");
            assert_eq!(p.server, "127.0.0.1");
            assert_eq!(p.port, 1080);
            assert_eq!(p.username, Some("user".to_string()));
            assert_eq!(p.password, Some("pass".to_string()));
        } else {
            panic!("expected Socks5 proxy");
        }
    }

    #[test]
    fn parse_proxy_group_select() {
        let yaml = r#"
proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - my-trojan
      - my-socks5
      - DIRECT
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.proxy_groups.len(), 1);
        let group = &config.proxy_groups[0];
        assert_eq!(group.name, "Proxy");
        assert_eq!(group.group_type, GroupType::Select);
        assert_eq!(group.proxies, vec!["my-trojan", "my-socks5", "DIRECT"]);
    }

    #[test]
    fn proxy_group_without_health_check_uses_defaults() {
        let yaml = r#"
proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - my-trojan
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let hc = config.proxy_groups[0].effective_health_check();
        assert!(hc.enable);
        assert_eq!(hc.url, DEFAULT_HEALTH_CHECK_URL);
        assert_eq!(hc.interval, DEFAULT_HEALTH_CHECK_INTERVAL_SECS);
        assert_eq!(hc.expected_status, DEFAULT_HEALTH_CHECK_EXPECTED_STATUS);
    }

    #[test]
    fn parse_proxy_group_health_check() {
        let yaml = r#"
proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - my-trojan
    health-check:
      enable: false
      url: http://cp.cloudflare.com/generate_204
      interval: 60
      expected-status: 204
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let hc = config.proxy_groups[0].effective_health_check();
        assert!(!hc.enable);
        assert_eq!(hc.url, "http://cp.cloudflare.com/generate_204");
        assert_eq!(hc.interval, 60);
        assert_eq!(hc.expected_status, 204);
    }

    #[test]
    fn parse_dns_config_full_keys() {
        let yaml = r#"
dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - "*.lan"
  nameserver:
    - 223.5.5.5
    - https://dns.example.com/dns-query
    - tls://dot.example.com
  default-nameserver:
    - 119.29.29.29
  proxy-server-nameserver:
    - https://doh.example.net/dns-query
  use-hosts: false
hosts:
  example.com: 1.2.3.4
  "*.internal.example.com": 10.0.0.1
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let dns = config.dns.as_ref().unwrap();
        assert!(dns.enable);
        assert!(!dns.ipv6);
        assert_eq!(dns.enhanced_mode.as_deref(), Some("fake-ip"));
        assert_eq!(dns.nameserver.len(), 3);
        assert_eq!(dns.default_nameserver, vec!["119.29.29.29"]);
        assert_eq!(
            dns.proxy_server_nameserver,
            vec!["https://doh.example.net/dns-query"]
        );
        assert_eq!(dns.use_hosts, Some(false));
        // fake-ip keys stay in extra — parsed but not interpreted.
        assert!(dns.extra.contains_key("fake-ip-range"));
        assert!(dns.extra.contains_key("fake-ip-filter"));
        assert_eq!(
            config.hosts.get("example.com").map(String::as_str),
            Some("1.2.3.4")
        );
        assert_eq!(
            config
                .hosts
                .get("*.internal.example.com")
                .map(String::as_str),
            Some("10.0.0.1")
        );
    }

    #[test]
    fn dns_config_defaults_when_keys_absent() {
        let yaml = "dns:\n  enable: true\n";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let dns = config.dns.as_ref().unwrap();
        assert!(dns.nameserver.is_empty());
        assert!(dns.proxy_server_nameserver.is_empty());
        // Absent use-hosts means enabled (dns crate treats None as true).
        assert_eq!(dns.use_hosts, None);
        assert!(config.hosts.is_empty());
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let yaml = r#"
mixed-port: 7890
tun:
  enable: true
  stack: system
some-future-field: whatever
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.mixed_port, Some(7890));
        assert!(config.extra.contains_key("tun"));
        assert!(config.extra.contains_key("some-future-field"));
    }

    #[test]
    fn unknown_proxy_type_is_skipped() {
        let yaml = r#"
proxies:
  - name: my-vmess
    type: vmess
    server: example.com
    port: 443
    uuid: some-uuid
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.proxies.len(), 1);
        assert!(matches!(config.proxies[0], Proxy::Unknown));
        assert_eq!(config.proxies[0].name(), None);
    }
}
