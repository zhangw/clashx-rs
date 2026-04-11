use std::io::Write;

use clashx_rs_config::load_config;
use clashx_rs_config::types::{GroupType, Proxy};
use tempfile::NamedTempFile;

const REALISTIC_CONFIG: &str = r#"
mixed-port: 7890
allow-lan: false
mode: rule
log-level: info

proxies:
  - name: sg-trojan
    type: trojan
    server: sg.example.com
    port: 443
    password: supersecret
    sni: sg.example.com
    skip-cert-verify: false

  - name: local-socks5
    type: socks5
    server: 127.0.0.1
    port: 1080
    username: alice
    password: hunter2

  - name: sg-vmess
    type: vmess
    server: sg2.example.com
    port: 8443
    uuid: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
    alterId: 0
    cipher: auto

proxy-groups:
  - name: singapo
    type: select
    proxies:
      - sg-trojan
      - local-socks5
      - DIRECT

  - name: corpnet
    type: select
    proxies:
      - local-socks5
      - DIRECT

  - name: direct-only
    type: select
    proxies:
      - DIRECT

rules:
  - DOMAIN-SUFFIX,google.com,singapo
  - DOMAIN-SUFFIX,claude.ai,singapo
  - IP-CIDR,172.16.0.0/16,corpnet
  - PROCESS-NAME,FortiClientAgent,direct-only
  - MATCH,DIRECT
"#;

fn write_temp_config(content: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("failed to create temp file");
    f.write_all(content.as_bytes())
        .expect("failed to write temp file");
    f
}

#[test]
fn parse_realistic_config_proxies() {
    let f = write_temp_config(REALISTIC_CONFIG);
    let config = load_config(f.path()).expect("load_config failed");

    // Three proxies total
    assert_eq!(config.proxies.len(), 3);

    // --- Trojan ---
    let trojan = &config.proxies[0];
    if let Proxy::Trojan(p) = trojan {
        assert_eq!(p.name, "sg-trojan");
        assert_eq!(p.server, "sg.example.com");
        assert_eq!(p.port, 443);
        assert_eq!(p.password, "supersecret");
        assert_eq!(p.sni, Some("sg.example.com".to_string()));
        assert!(!p.skip_cert_verify);
    } else {
        panic!("expected Proxy::Trojan at index 0, got {:?}", trojan);
    }

    // --- SOCKS5 ---
    let socks5 = &config.proxies[1];
    if let Proxy::Socks5(p) = socks5 {
        assert_eq!(p.name, "local-socks5");
        assert_eq!(p.server, "127.0.0.1");
        assert_eq!(p.port, 1080);
        assert_eq!(p.username, Some("alice".to_string()));
        assert_eq!(p.password, Some("hunter2".to_string()));
    } else {
        panic!("expected Proxy::Socks5 at index 1, got {:?}", socks5);
    }

    // --- VMess -> Unknown ---
    let vmess = &config.proxies[2];
    assert!(
        matches!(vmess, Proxy::Unknown),
        "expected Proxy::Unknown for vmess, got {:?}",
        vmess
    );
    assert_eq!(vmess.name(), None);
}

#[test]
fn parse_realistic_config_proxy_groups() {
    let f = write_temp_config(REALISTIC_CONFIG);
    let config = load_config(f.path()).expect("load_config failed");

    assert_eq!(config.proxy_groups.len(), 3);

    let singapo = &config.proxy_groups[0];
    assert_eq!(singapo.name, "singapo");
    assert_eq!(singapo.group_type, GroupType::Select);
    assert_eq!(singapo.proxies, vec!["sg-trojan", "local-socks5", "DIRECT"]);

    let corpnet = &config.proxy_groups[1];
    assert_eq!(corpnet.name, "corpnet");
    assert_eq!(corpnet.group_type, GroupType::Select);
    assert_eq!(corpnet.proxies, vec!["local-socks5", "DIRECT"]);

    let direct_only = &config.proxy_groups[2];
    assert_eq!(direct_only.name, "direct-only");
    assert_eq!(direct_only.group_type, GroupType::Select);
    assert_eq!(direct_only.proxies, vec!["DIRECT"]);
}

#[test]
fn parse_realistic_config_rules() {
    let f = write_temp_config(REALISTIC_CONFIG);
    let config = load_config(f.path()).expect("load_config failed");

    assert_eq!(config.rules.len(), 5);
    assert_eq!(config.rules[0], "DOMAIN-SUFFIX,google.com,singapo");
    assert_eq!(config.rules[1], "DOMAIN-SUFFIX,claude.ai,singapo");
    assert_eq!(config.rules[2], "IP-CIDR,172.16.0.0/16,corpnet");
    assert_eq!(config.rules[3], "PROCESS-NAME,FortiClientAgent,direct-only");
    assert_eq!(config.rules[4], "MATCH,DIRECT");
}

#[test]
fn parse_realistic_config_top_level_fields() {
    let f = write_temp_config(REALISTIC_CONFIG);
    let config = load_config(f.path()).expect("load_config failed");

    assert_eq!(config.mixed_port, Some(7890));
    assert_eq!(config.allow_lan, Some(false));
}
