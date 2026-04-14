pub mod process;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use clashx_rs_config::rule::RuleEntry;
use clashx_rs_geoip::GeoIpDb;

pub struct MatchInput<'a> {
    pub host: Option<&'a str>,
    pub ip: Option<IpAddr>,
    pub process_name: Option<&'a str>,
}

pub struct RuleEngine {
    rules: Vec<RuleEntry>,
    geoip_db: Option<Arc<GeoIpDb>>,
    has_ip_rules: bool,
}

impl RuleEngine {
    pub fn new(raw_rules: &[String], geoip_db: Option<Arc<GeoIpDb>>) -> Self {
        let rules: Vec<RuleEntry> = raw_rules
            .iter()
            .filter_map(|s| match RuleEntry::parse(s) {
                Some(rule) => Some(rule),
                None => {
                    let rule_type = s.split(',').next().unwrap_or("unknown");
                    tracing::warn!(rule_type = %rule_type, raw = %s, "unrecognized rule type, skipping");
                    None
                }
            })
            .collect();

        let geoip_count = rules
            .iter()
            .filter(|r| matches!(r, RuleEntry::GeoIp { .. }))
            .count();
        if geoip_count > 0 && geoip_db.is_none() {
            tracing::warn!(
                count = geoip_count,
                "GEOIP rules present but no mmdb loaded — rules will not match"
            );
        }

        let has_ip_rules = rules
            .iter()
            .any(|r| matches!(r, RuleEntry::GeoIp { .. } | RuleEntry::IpCidr { .. }));

        Self {
            rules,
            geoip_db,
            has_ip_rules,
        }
    }

    /// Hot-swap the GeoIP database (called after background download completes).
    pub fn set_geoip_db(&mut self, db: Arc<GeoIpDb>) {
        self.geoip_db = Some(db);
        self.has_ip_rules = true;
        tracing::info!("GeoIP database hot-swapped, GEOIP rules now active");
    }

    /// Whether the config has any GEOIP or IP-CIDR rules that need a resolved IP.
    pub fn needs_resolved_ip(&self) -> bool {
        self.has_ip_rules
    }

    /// Whether a GeoIP database is currently loaded.
    pub fn has_geoip_db(&self) -> bool {
        self.geoip_db.is_some()
    }

    pub fn evaluate<'a>(&'a self, input: &MatchInput<'_>) -> Option<&'a str> {
        let host_lower = input.host.map(|h| h.to_lowercase());
        self.rules
            .iter()
            .find(|rule| matches_rule(rule, input, host_lower.as_deref(), self.geoip_db.as_deref()))
            .map(|rule| rule.target())
    }
}

fn matches_rule(
    rule: &RuleEntry,
    input: &MatchInput<'_>,
    host_lower: Option<&str>,
    geoip_db: Option<&GeoIpDb>,
) -> bool {
    match rule {
        RuleEntry::Domain { domain, .. } => host_lower.is_some_and(|h| h == domain.as_str()),
        RuleEntry::DomainSuffix { suffix, .. } => host_lower.is_some_and(|h| {
            h == suffix.as_str()
                || (h.len() > suffix.len()
                    && h.ends_with(suffix.as_str())
                    && h.as_bytes()[h.len() - suffix.len() - 1] == b'.')
        }),
        RuleEntry::DomainKeyword { keyword, .. } => {
            host_lower.is_some_and(|h| h.contains(keyword.as_str()))
        }
        RuleEntry::IpCidr {
            ip: network,
            prefix_len,
            ..
        } => {
            if let Some(addr) = input.ip {
                ip_in_cidr(addr, *network, *prefix_len)
            } else {
                false
            }
        }
        RuleEntry::ProcessName { name, .. } => {
            if let Some(proc) = input.process_name {
                proc == name
            } else {
                false
            }
        }
        RuleEntry::GeoIp { country, .. } => {
            let Some(db) = geoip_db else { return false };
            let Some(ip) = input.ip else { return false };
            db.lookup_country(ip)
                .map(|c| c.eq_ignore_ascii_case(country))
                .unwrap_or(false)
        }
        RuleEntry::Match { .. } => true,
    }
}

fn ip_in_cidr(addr: IpAddr, network: IpAddr, prefix_len: u8) -> bool {
    match (addr, network) {
        (IpAddr::V4(a), IpAddr::V4(n)) => ipv4_in_cidr(a, n, prefix_len),
        (IpAddr::V6(a), IpAddr::V6(n)) => ipv6_in_cidr(a, n, prefix_len),
        _ => false,
    }
}

fn ipv4_in_cidr(addr: Ipv4Addr, network: Ipv4Addr, prefix_len: u8) -> bool {
    if prefix_len > 32 {
        return false;
    }
    if prefix_len == 0 {
        return true;
    }
    let mask = u32::MAX << (32 - prefix_len);
    (u32::from(addr) & mask) == (u32::from(network) & mask)
}

fn ipv6_in_cidr(addr: Ipv6Addr, network: Ipv6Addr, prefix_len: u8) -> bool {
    if prefix_len > 128 {
        return false;
    }
    if prefix_len == 0 {
        return true;
    }
    let addr_bits = u128::from(addr);
    let net_bits = u128::from(network);
    let mask = u128::MAX << (128 - prefix_len);
    (addr_bits & mask) == (net_bits & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_engine(rules: &[&str]) -> RuleEngine {
        let raw: Vec<String> = rules.iter().map(|s| s.to_string()).collect();
        RuleEngine::new(&raw, None)
    }

    fn make_engine_with_geoip(rules: &[&str], db: Arc<GeoIpDb>) -> RuleEngine {
        let raw: Vec<String> = rules.iter().map(|s| s.to_string()).collect();
        RuleEngine::new(&raw, Some(db))
    }

    fn test_geoip_db() -> Arc<GeoIpDb> {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../geoip/tests/fixtures/GeoIP2-Country-Test.mmdb");
        Arc::new(GeoIpDb::open(&path).unwrap())
    }

    #[test]
    fn domain_suffix_exact_match() {
        let engine = make_engine(&["DOMAIN-SUFFIX,google.com,DIRECT"]);
        let input = MatchInput {
            host: Some("google.com"),
            ip: None,
            process_name: None,
        };
        assert_eq!(engine.evaluate(&input), Some("DIRECT"));
    }

    #[test]
    fn domain_suffix_subdomain_match() {
        let engine = make_engine(&["DOMAIN-SUFFIX,google.com,DIRECT"]);
        let input = MatchInput {
            host: Some("www.google.com"),
            ip: None,
            process_name: None,
        };
        assert_eq!(engine.evaluate(&input), Some("DIRECT"));
    }

    #[test]
    fn domain_suffix_no_partial_match() {
        let engine = make_engine(&["DOMAIN-SUFFIX,google.com,DIRECT"]);
        let input = MatchInput {
            host: Some("oogle.com"),
            ip: None,
            process_name: None,
        };
        assert_eq!(engine.evaluate(&input), None);
    }

    #[test]
    fn domain_suffix_case_insensitive() {
        let engine = make_engine(&["DOMAIN-SUFFIX,google.com,DIRECT"]);
        let input = MatchInput {
            host: Some("WWW.GOOGLE.COM"),
            ip: None,
            process_name: None,
        };
        assert_eq!(engine.evaluate(&input), Some("DIRECT"));
    }

    #[test]
    fn ip_cidr_match() {
        let engine = make_engine(&["IP-CIDR,192.168.0.0/16,DIRECT"]);
        let input = MatchInput {
            host: None,
            ip: Some("192.168.1.100".parse().unwrap()),
            process_name: None,
        };
        assert_eq!(engine.evaluate(&input), Some("DIRECT"));
    }

    #[test]
    fn ip_cidr_no_match() {
        let engine = make_engine(&["IP-CIDR,192.168.0.0/16,DIRECT"]);
        let input = MatchInput {
            host: None,
            ip: Some("10.0.0.1".parse().unwrap()),
            process_name: None,
        };
        assert_eq!(engine.evaluate(&input), None);
    }

    #[test]
    fn process_name_match() {
        let engine = make_engine(&["PROCESS-NAME,curl,Proxy"]);
        let input = MatchInput {
            host: None,
            ip: None,
            process_name: Some("curl"),
        };
        assert_eq!(engine.evaluate(&input), Some("Proxy"));
    }

    #[test]
    fn match_catch_all() {
        let engine = make_engine(&["MATCH,DIRECT"]);
        let input = MatchInput {
            host: None,
            ip: None,
            process_name: None,
        };
        assert_eq!(engine.evaluate(&input), Some("DIRECT"));
    }

    #[test]
    fn first_match_wins() {
        let engine = make_engine(&["DOMAIN-SUFFIX,google.com,Proxy", "MATCH,DIRECT"]);
        let input = MatchInput {
            host: Some("google.com"),
            ip: None,
            process_name: None,
        };
        assert_eq!(engine.evaluate(&input), Some("Proxy"));
    }

    #[test]
    fn no_rules_returns_none() {
        let engine = make_engine(&[]);
        let input = MatchInput {
            host: Some("google.com"),
            ip: None,
            process_name: None,
        };
        assert_eq!(engine.evaluate(&input), None);
    }

    #[test]
    fn domain_exact_match() {
        let engine = make_engine(&["DOMAIN,mtalk.google.com,Proxy"]);
        let input = MatchInput {
            host: Some("mtalk.google.com"),
            ip: None,
            process_name: None,
        };
        assert_eq!(engine.evaluate(&input), Some("Proxy"));
    }

    #[test]
    fn domain_no_subdomain_match() {
        let engine = make_engine(&["DOMAIN,google.com,Proxy"]);
        let input = MatchInput {
            host: Some("www.google.com"),
            ip: None,
            process_name: None,
        };
        assert_eq!(engine.evaluate(&input), None);
    }

    #[test]
    fn domain_case_insensitive() {
        let engine = make_engine(&["DOMAIN,mtalk.google.com,Proxy"]);
        let input = MatchInput {
            host: Some("MTALK.GOOGLE.COM"),
            ip: None,
            process_name: None,
        };
        assert_eq!(engine.evaluate(&input), Some("Proxy"));
    }

    #[test]
    fn domain_keyword_match() {
        let engine = make_engine(&["DOMAIN-KEYWORD,youtube,Proxy"]);
        let input = MatchInput {
            host: Some("www.youtube.com"),
            ip: None,
            process_name: None,
        };
        assert_eq!(engine.evaluate(&input), Some("Proxy"));
    }

    #[test]
    fn domain_keyword_no_match() {
        let engine = make_engine(&["DOMAIN-KEYWORD,youtube,Proxy"]);
        let input = MatchInput {
            host: Some("www.google.com"),
            ip: None,
            process_name: None,
        };
        assert_eq!(engine.evaluate(&input), None);
    }

    #[test]
    fn domain_keyword_case_insensitive() {
        let engine = make_engine(&["DOMAIN-KEYWORD,youtube,Proxy"]);
        let input = MatchInput {
            host: Some("WWW.YOUTUBE.COM"),
            ip: None,
            process_name: None,
        };
        assert_eq!(engine.evaluate(&input), Some("Proxy"));
    }

    #[test]
    fn domain_keyword_partial_match() {
        let engine = make_engine(&["DOMAIN-KEYWORD,ali,DIRECT"]);
        let input = MatchInput {
            host: Some("cdn.alicdn.com"),
            ip: None,
            process_name: None,
        };
        assert_eq!(engine.evaluate(&input), Some("DIRECT"));
    }

    #[test]
    fn ip_cidr6_match() {
        let engine = make_engine(&["IP-CIDR6,fd00::/8,DIRECT"]);
        let input = MatchInput {
            host: None,
            ip: Some("fd00::1".parse().unwrap()),
            process_name: None,
        };
        assert_eq!(engine.evaluate(&input), Some("DIRECT"));
    }

    #[test]
    fn ip_cidr6_no_match() {
        let engine = make_engine(&["IP-CIDR6,fd00::/8,DIRECT"]);
        let input = MatchInput {
            host: None,
            ip: Some("2001:db8::1".parse().unwrap()),
            process_name: None,
        };
        assert_eq!(engine.evaluate(&input), None);
    }

    #[test]
    fn ip_cidr6_loopback() {
        let engine = make_engine(&["IP-CIDR6,::1/128,DIRECT"]);
        let input = MatchInput {
            host: None,
            ip: Some("::1".parse().unwrap()),
            process_name: None,
        };
        assert_eq!(engine.evaluate(&input), Some("DIRECT"));
    }

    #[test]
    fn unrecognized_rules_are_skipped() {
        let engine = make_engine(&[
            "SRC-IP-CIDR,192.168.0.0/16,DIRECT",
            "DOMAIN-SUFFIX,google.com,Proxy",
            "MATCH,DIRECT",
        ]);
        let input = MatchInput {
            host: Some("google.com"),
            ip: None,
            process_name: None,
        };
        assert_eq!(engine.evaluate(&input), Some("Proxy"));
    }

    #[test]
    fn geoip_no_match_when_db_absent() {
        let engine = make_engine(&["GEOIP,GB,DIRECT", "MATCH,Proxy"]);
        let input = MatchInput {
            host: None,
            ip: Some("2.125.160.216".parse().unwrap()),
            process_name: None,
        };
        // Without a db, GEOIP rules always return false → falls through to MATCH
        assert_eq!(engine.evaluate(&input), Some("Proxy"));
    }

    #[test]
    fn geoip_matches_when_db_present() {
        let db = test_geoip_db();
        let engine = make_engine_with_geoip(&["GEOIP,GB,DIRECT", "MATCH,Proxy"], db);
        let input = MatchInput {
            host: None,
            // 2.125.160.216 → GB in MaxMind test data
            ip: Some("2.125.160.216".parse().unwrap()),
            process_name: None,
        };
        assert_eq!(engine.evaluate(&input), Some("DIRECT"));
    }

    #[test]
    fn geoip_no_match_wrong_country() {
        let db = test_geoip_db();
        let engine = make_engine_with_geoip(&["GEOIP,CN,DIRECT", "MATCH,Proxy"], db);
        let input = MatchInput {
            host: None,
            // 2.125.160.216 → GB, not CN
            ip: Some("2.125.160.216".parse().unwrap()),
            process_name: None,
        };
        assert_eq!(engine.evaluate(&input), Some("Proxy"));
    }

    #[test]
    fn geoip_no_match_when_ip_none() {
        let db = test_geoip_db();
        let engine = make_engine_with_geoip(&["GEOIP,GB,DIRECT", "MATCH,Proxy"], db);
        let input = MatchInput {
            host: Some("example.com"),
            ip: None,
            process_name: None,
        };
        // ip is None → GEOIP can't match → falls through to MATCH
        assert_eq!(engine.evaluate(&input), Some("Proxy"));
    }

    #[test]
    fn geoip_rule_ordering() {
        let db = test_geoip_db();
        let engine = make_engine_with_geoip(
            &[
                "DOMAIN-SUFFIX,example.com,Proxy",
                "GEOIP,GB,DIRECT",
                "MATCH,Fallback",
            ],
            db,
        );

        // Domain rule matches first
        let input1 = MatchInput {
            host: Some("example.com"),
            ip: Some("2.125.160.216".parse().unwrap()),
            process_name: None,
        };
        assert_eq!(engine.evaluate(&input1), Some("Proxy"));

        // GEOIP matches for non-domain-matched traffic
        let input2 = MatchInput {
            host: Some("other.co.uk"),
            ip: Some("2.125.160.216".parse().unwrap()),
            process_name: None,
        };
        assert_eq!(engine.evaluate(&input2), Some("DIRECT"));

        // Falls through to MATCH for non-GB IP
        let input3 = MatchInput {
            host: Some("other.se"),
            ip: Some("192.168.1.1".parse().unwrap()),
            process_name: None,
        };
        assert_eq!(engine.evaluate(&input3), Some("Fallback"));
    }

    #[test]
    fn geoip_ipv6_match() {
        let db = test_geoip_db();
        let engine = make_engine_with_geoip(&["GEOIP,JP,DIRECT", "MATCH,Proxy"], db);
        let input = MatchInput {
            host: None,
            // 2001:218::1 → JP in MaxMind test data
            ip: Some("2001:218::1".parse().unwrap()),
            process_name: None,
        };
        assert_eq!(engine.evaluate(&input), Some("DIRECT"));
    }
}
