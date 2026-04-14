use std::net::IpAddr;

use clashx_rs_rule::{MatchInput, RuleEngine};

fn make_engine(rules: &[&str]) -> RuleEngine {
    let raw: Vec<String> = rules.iter().map(|s| s.to_string()).collect();
    RuleEngine::new(&raw, None)
}

/// Rule set derived from the real WgetCloud.yaml config.
/// Covers: IP-CIDR (corporate networks), DOMAIN-SUFFIX (work/proxy/reject),
/// PROCESS-NAME (VPN/apps), and MATCH catch-all.
fn config_engine() -> RuleEngine {
    make_engine(&[
        // Corporate networks (IP-CIDR)
        "IP-CIDR,172.16.0.0/16,@acmecorp-corpnet",
        "IP-CIDR,172.17.0.0/16,@acmecorp-corpnet",
        "IP-CIDR,172.18.0.0/16,@acmecorp-corpnet-2",
        "IP-CIDR,192.168.99.0/24,@acmecorp-corpnet-2",
        // Work domains -> direct
        "DOMAIN-SUFFIX,gitrepo-ce.local,@acmecorp-corpnet-2",
        "DOMAIN-SUFFIX,portal.acmecorp.com,@direct-only",
        "DOMAIN-SUFFIX,logstack.acmecorp.com,@direct-only",
        "DOMAIN-SUFFIX,dashmon.acmecorp.com,@direct-only",
        "DOMAIN-SUFFIX,authsvc.acmecorp.com,@direct-only",
        "DOMAIN-SUFFIX,usauthsvc.acmecorp.com,@direct-only",
        "DOMAIN-SUFFIX,acmecorptrade.com,@direct-only",
        "DOMAIN-SUFFIX,acmecorpwallet.com,@direct-only",
        // Work domains -> US proxy
        "DOMAIN-SUFFIX,acmecorp.com,@us",
        "DOMAIN-SUFFIX,acmecorpfintech.com,@us",
        // Direct
        "DOMAIN-SUFFIX,gitee.com,@direct-only",
        // Singapore proxy
        "DOMAIN-SUFFIX,google.com,@singapo",
        "DOMAIN-SUFFIX,claude.ai,@singapo",
        "DOMAIN-SUFFIX,anthropic.com,@singapo",
        "DOMAIN-SUFFIX,claude.com,@singapo",
        "DOMAIN-SUFFIX,slack.com,@singapo",
        "DOMAIN-SUFFIX,openai.com,@singapo",
        "DOMAIN-SUFFIX,chatgpt.com,@singapo",
        // US proxy
        "DOMAIN-SUFFIX,cmegroup.com,@us",
        // VPN and work apps -> direct
        "PROCESS-NAME,com.fortinet.forticlient.macos.vpn.nwextension,@direct-only",
        "PROCESS-NAME,FortiClientAgent,@direct-only",
        "PROCESS-NAME,FortiTray,@direct-only",
        "PROCESS-NAME,DingTalk,@direct-only",
        // AWS China -> direct
        "DOMAIN-SUFFIX,cn-north-1.amazonaws.com.cn,@direct-only",
        "DOMAIN-SUFFIX,cn-northwest-1.amazonaws.com.cn,@direct-only",
        // Tracker reject
        "DOMAIN-SUFFIX,tracker.opentrackr.org,REJECT",
        "DOMAIN-SUFFIX,open.demonii.com,REJECT",
        "DOMAIN-SUFFIX,tracker.openbittorrent.com,REJECT",
        "DOMAIN-SUFFIX,tracker.torrent.eu.org,REJECT",
        // Streaming -> node select group
        "DOMAIN-SUFFIX,temu.com,🚀 节点选择",
        "DOMAIN-SUFFIX,dazn.com,🚀 节点选择",
        // Catch-all
        "MATCH,🐟 漏网之鱼",
    ])
}

fn input_host(host: &str) -> MatchInput<'_> {
    MatchInput {
        host: Some(host),
        ip: host.parse().ok(),
        process_name: None,
    }
}

fn input_ip(ip: &str) -> MatchInput<'_> {
    MatchInput {
        host: None,
        ip: Some(ip.parse::<IpAddr>().unwrap()),
        process_name: None,
    }
}

fn input_process(name: &str) -> MatchInput<'_> {
    MatchInput {
        host: None,
        ip: None,
        process_name: Some(name),
    }
}

// ===========================================================================
// IP-CIDR: Corporate network routing
// ===========================================================================

#[test]
fn ip_10_1_x_routes_to_acmecorp_internal() {
    let e = config_engine();
    assert_eq!(
        e.evaluate(&input_ip("172.16.0.1")),
        Some("@acmecorp-corpnet")
    );
    assert_eq!(
        e.evaluate(&input_ip("172.16.255.254")),
        Some("@acmecorp-corpnet")
    );
    assert_eq!(
        e.evaluate(&input_ip("172.16.100.50")),
        Some("@acmecorp-corpnet")
    );
}

#[test]
fn ip_10_70_x_routes_to_acmecorp_internal() {
    let e = config_engine();
    assert_eq!(
        e.evaluate(&input_ip("172.17.0.1")),
        Some("@acmecorp-corpnet")
    );
    assert_eq!(
        e.evaluate(&input_ip("172.17.200.5")),
        Some("@acmecorp-corpnet")
    );
}

#[test]
fn ip_10_60_x_routes_to_acmecorp_internal_2() {
    let e = config_engine();
    assert_eq!(
        e.evaluate(&input_ip("172.18.0.1")),
        Some("@acmecorp-corpnet-2")
    );
    assert_eq!(
        e.evaluate(&input_ip("172.18.128.1")),
        Some("@acmecorp-corpnet-2")
    );
}

#[test]
fn ip_192_168_40_x_routes_to_acmecorp_internal_2() {
    let e = config_engine();
    assert_eq!(
        e.evaluate(&input_ip("192.168.99.1")),
        Some("@acmecorp-corpnet-2")
    );
    assert_eq!(
        e.evaluate(&input_ip("192.168.99.73")),
        Some("@acmecorp-corpnet-2")
    );
    assert_eq!(
        e.evaluate(&input_ip("192.168.99.254")),
        Some("@acmecorp-corpnet-2")
    );
}

#[test]
fn ip_192_168_41_is_outside_24_cidr() {
    let e = config_engine();
    // 192.168.100.x is outside 192.168.99.0/24
    assert_eq!(e.evaluate(&input_ip("192.168.100.1")), Some("🐟 漏网之鱼"));
}

#[test]
fn ip_10_2_x_not_in_any_cidr() {
    let e = config_engine();
    assert_eq!(e.evaluate(&input_ip("10.2.0.1")), Some("🐟 漏网之鱼"));
}

// ===========================================================================
// DOMAIN-SUFFIX: Work domains -> @direct-only
// ===========================================================================

#[test]
fn acmecorp_portal_direct() {
    let e = config_engine();
    assert_eq!(
        e.evaluate(&input_host("portal.acmecorp.com")),
        Some("@direct-only")
    );
}

#[test]
fn acmecorp_logstack_direct() {
    let e = config_engine();
    assert_eq!(
        e.evaluate(&input_host("logstack.acmecorp.com")),
        Some("@direct-only")
    );
}

#[test]
fn acmecorp_dashmon_direct() {
    let e = config_engine();
    assert_eq!(
        e.evaluate(&input_host("dashmon.acmecorp.com")),
        Some("@direct-only")
    );
}

#[test]
fn acmecorptrade_direct() {
    let e = config_engine();
    assert_eq!(
        e.evaluate(&input_host("acmecorptrade.com")),
        Some("@direct-only")
    );
    assert_eq!(
        e.evaluate(&input_host("api.acmecorptrade.com")),
        Some("@direct-only")
    );
}

#[test]
fn acmecorpwallet_direct() {
    let e = config_engine();
    assert_eq!(
        e.evaluate(&input_host("acmecorpwallet.com")),
        Some("@direct-only")
    );
}

// ===========================================================================
// DOMAIN-SUFFIX: acmecorp.com -> @us (comes AFTER more specific acmecorp subdomains)
// ===========================================================================

#[test]
fn acmecorp_com_routes_to_us() {
    let e = config_engine();
    assert_eq!(e.evaluate(&input_host("acmecorp.com")), Some("@us"));
    assert_eq!(e.evaluate(&input_host("www.acmecorp.com")), Some("@us"));
}

#[test]
fn acmecorpfintech_routes_to_us() {
    let e = config_engine();
    assert_eq!(e.evaluate(&input_host("acmecorpfintech.com")), Some("@us"));
}

#[test]
fn portal_acmecorp_matches_direct_not_us_because_it_comes_first() {
    // portal.acmecorp.com matches DOMAIN-SUFFIX,portal.acmecorp.com,@direct-only
    // BEFORE it could match DOMAIN-SUFFIX,acmecorp.com,@us
    let e = config_engine();
    assert_eq!(
        e.evaluate(&input_host("portal.acmecorp.com")),
        Some("@direct-only")
    );
}

// ===========================================================================
// DOMAIN-SUFFIX: Singapore proxy
// ===========================================================================

#[test]
fn google_routes_to_singapo() {
    let e = config_engine();
    assert_eq!(e.evaluate(&input_host("google.com")), Some("@singapo"));
    assert_eq!(e.evaluate(&input_host("www.google.com")), Some("@singapo"));
    assert_eq!(e.evaluate(&input_host("mail.google.com")), Some("@singapo"));
}

#[test]
fn claude_ai_routes_to_singapo() {
    let e = config_engine();
    assert_eq!(e.evaluate(&input_host("claude.ai")), Some("@singapo"));
    assert_eq!(e.evaluate(&input_host("api.claude.ai")), Some("@singapo"));
}

#[test]
fn anthropic_routes_to_singapo() {
    let e = config_engine();
    assert_eq!(e.evaluate(&input_host("anthropic.com")), Some("@singapo"));
    assert_eq!(
        e.evaluate(&input_host("docs.anthropic.com")),
        Some("@singapo")
    );
}

#[test]
fn claude_com_routes_to_singapo() {
    let e = config_engine();
    assert_eq!(e.evaluate(&input_host("claude.com")), Some("@singapo"));
}

#[test]
fn slack_routes_to_singapo() {
    let e = config_engine();
    assert_eq!(e.evaluate(&input_host("slack.com")), Some("@singapo"));
    assert_eq!(e.evaluate(&input_host("app.slack.com")), Some("@singapo"));
}

#[test]
fn openai_chatgpt_routes_to_singapo() {
    let e = config_engine();
    assert_eq!(e.evaluate(&input_host("openai.com")), Some("@singapo"));
    assert_eq!(e.evaluate(&input_host("chatgpt.com")), Some("@singapo"));
    assert_eq!(e.evaluate(&input_host("api.openai.com")), Some("@singapo"));
}

// ===========================================================================
// DOMAIN-SUFFIX: US proxy
// ===========================================================================

#[test]
fn cmegroup_routes_to_us() {
    let e = config_engine();
    assert_eq!(e.evaluate(&input_host("cmegroup.com")), Some("@us"));
    assert_eq!(e.evaluate(&input_host("www.cmegroup.com")), Some("@us"));
}

// ===========================================================================
// DOMAIN-SUFFIX: Direct only
// ===========================================================================

#[test]
fn gitee_routes_to_direct() {
    let e = config_engine();
    assert_eq!(e.evaluate(&input_host("gitee.com")), Some("@direct-only"));
}

#[test]
fn gitrepo_ce_local_routes_to_internal() {
    let e = config_engine();
    assert_eq!(
        e.evaluate(&input_host("gitrepo-ce.local")),
        Some("@acmecorp-corpnet-2")
    );
    assert_eq!(
        e.evaluate(&input_host("repo.gitrepo-ce.local")),
        Some("@acmecorp-corpnet-2")
    );
}

// ===========================================================================
// DOMAIN-SUFFIX: AWS China -> direct
// ===========================================================================

#[test]
fn aws_china_routes_to_direct() {
    let e = config_engine();
    assert_eq!(
        e.evaluate(&input_host("s3.cn-north-1.amazonaws.com.cn")),
        Some("@direct-only")
    );
    assert_eq!(
        e.evaluate(&input_host("ec2.cn-northwest-1.amazonaws.com.cn")),
        Some("@direct-only")
    );
}

// ===========================================================================
// DOMAIN-SUFFIX: Tracker reject
// ===========================================================================

#[test]
fn torrent_trackers_rejected() {
    let e = config_engine();
    assert_eq!(
        e.evaluate(&input_host("tracker.opentrackr.org")),
        Some("REJECT")
    );
    assert_eq!(e.evaluate(&input_host("open.demonii.com")), Some("REJECT"));
    assert_eq!(
        e.evaluate(&input_host("tracker.openbittorrent.com")),
        Some("REJECT")
    );
    assert_eq!(
        e.evaluate(&input_host("tracker.torrent.eu.org")),
        Some("REJECT")
    );
}

#[test]
fn tracker_subdomain_also_rejected() {
    let e = config_engine();
    assert_eq!(
        e.evaluate(&input_host("udp.tracker.opentrackr.org")),
        Some("REJECT")
    );
}

// ===========================================================================
// DOMAIN-SUFFIX: Streaming -> 节点选择
// ===========================================================================

#[test]
fn temu_routes_to_node_select() {
    let e = config_engine();
    assert_eq!(e.evaluate(&input_host("temu.com")), Some("🚀 节点选择"));
    assert_eq!(e.evaluate(&input_host("www.temu.com")), Some("🚀 节点选择"));
}

#[test]
fn dazn_routes_to_node_select() {
    let e = config_engine();
    assert_eq!(e.evaluate(&input_host("dazn.com")), Some("🚀 节点选择"));
}

// ===========================================================================
// PROCESS-NAME: VPN and work apps
// ===========================================================================

#[test]
fn forticlient_vpn_extension_direct() {
    let e = config_engine();
    assert_eq!(
        e.evaluate(&input_process(
            "com.fortinet.forticlient.macos.vpn.nwextension"
        )),
        Some("@direct-only")
    );
}

#[test]
fn forticlient_agent_direct() {
    let e = config_engine();
    assert_eq!(
        e.evaluate(&input_process("FortiClientAgent")),
        Some("@direct-only")
    );
}

#[test]
fn fortitray_direct() {
    let e = config_engine();
    assert_eq!(
        e.evaluate(&input_process("FortiTray")),
        Some("@direct-only")
    );
}

#[test]
fn dingtalk_direct() {
    let e = config_engine();
    assert_eq!(e.evaluate(&input_process("DingTalk")), Some("@direct-only"));
}

#[test]
fn unknown_process_falls_through() {
    let e = config_engine();
    assert_eq!(e.evaluate(&input_process("Safari")), Some("🐟 漏网之鱼"));
}

// ===========================================================================
// MATCH: Catch-all
// ===========================================================================

#[test]
fn unknown_domain_falls_to_catch_all() {
    let e = config_engine();
    assert_eq!(
        e.evaluate(&input_host("random-unknown-site.xyz")),
        Some("🐟 漏网之鱼")
    );
}

#[test]
fn empty_input_falls_to_catch_all() {
    let e = config_engine();
    let input = MatchInput {
        host: None,
        ip: None,
        process_name: None,
    };
    assert_eq!(e.evaluate(&input), Some("🐟 漏网之鱼"));
}

// ===========================================================================
// DOMAIN-SUFFIX: dot-boundary correctness
// ===========================================================================

#[test]
fn partial_suffix_does_not_match() {
    let e = config_engine();
    // "noogle.com" should NOT match "google.com" rule
    assert_eq!(e.evaluate(&input_host("noogle.com")), Some("🐟 漏网之鱼"));
}

#[test]
fn similar_domain_does_not_match() {
    let e = config_engine();
    // "notacmecorp.com" should NOT match "acmecorp.com"
    assert_eq!(
        e.evaluate(&input_host("notacmecorp.com")),
        Some("🐟 漏网之鱼")
    );
}

#[test]
fn case_insensitive_domain_match() {
    let e = config_engine();
    assert_eq!(e.evaluate(&input_host("WWW.GOOGLE.COM")), Some("@singapo"));
    assert_eq!(e.evaluate(&input_host("Claude.AI")), Some("@singapo"));
}

// ===========================================================================
// Combined: host + IP both set (as in real proxy connections)
// ===========================================================================

#[test]
fn host_with_resolved_ip_matches_domain_rule_first() {
    let e = config_engine();
    // When a domain resolves to an IP, host rule comes before IP rule
    let input = MatchInput {
        host: Some("google.com"),
        ip: Some("142.250.80.46".parse().unwrap()),
        process_name: None,
    };
    assert_eq!(e.evaluate(&input), Some("@singapo"));
}

#[test]
fn ip_string_as_host_matches_cidr() {
    // When connecting directly to an IP (no domain), it should still match IP-CIDR
    let e = config_engine();
    let input = MatchInput {
        host: Some("172.16.5.3"),
        ip: Some("172.16.5.3".parse().unwrap()),
        process_name: None,
    };
    assert_eq!(e.evaluate(&input), Some("@acmecorp-corpnet"));
}

// ===========================================================================
// Fail-closed: engine returns None when no rules match (no MATCH catch-all)
// ===========================================================================

#[test]
fn no_catch_all_returns_none_for_unknown_domain() {
    // Without a MATCH rule, unmatched traffic should return None (fail closed)
    let e = make_engine(&[
        "DOMAIN-SUFFIX,google.com,@proxy",
        "IP-CIDR,10.0.0.0/8,@corpnet",
    ]);
    assert_eq!(e.evaluate(&input_host("unknown.xyz")), None);
}

#[test]
fn no_catch_all_returns_none_for_unknown_ip() {
    let e = make_engine(&["IP-CIDR,10.0.0.0/8,@corpnet"]);
    assert_eq!(e.evaluate(&input_ip("192.168.1.1")), None);
}

#[test]
fn no_rules_returns_none() {
    let e = make_engine(&[]);
    assert_eq!(e.evaluate(&input_host("anything.com")), None);
}
