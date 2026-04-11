use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    #[serde(default)]
    pub mixed_port: Option<u16>,
    #[serde(default)]
    pub allow_lan: Option<bool>,
    #[serde(default)]
    pub bind_address: Option<String>,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub log_level: LogLevel,
    #[serde(default)]
    pub external_controller: Option<String>,
    #[serde(default)]
    pub dns: Option<DnsConfig>,
    #[serde(default)]
    pub proxies: Vec<Proxy>,
    #[serde(default)]
    pub proxy_groups: Vec<ProxyGroup>,
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Rule,
    Global,
    Direct,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Silent,
    Error,
    Warning,
    #[default]
    Info,
    Debug,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum Proxy {
    #[serde(rename = "trojan")]
    Trojan(TrojanProxy),
    #[serde(rename = "socks5")]
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

#[derive(Debug, Clone, Deserialize, Serialize)]
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

#[derive(Debug, Clone, Deserialize, Serialize)]
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ProxyGroup {
    pub name: String,
    #[serde(rename = "type")]
    pub group_type: GroupType,
    #[serde(default)]
    pub proxies: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
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
