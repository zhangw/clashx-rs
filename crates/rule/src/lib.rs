pub mod process;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use clashx_rs_config::rule::RuleEntry;

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
        let rules = raw_rules
            .iter()
            .filter_map(|s| RuleEntry::parse(s))
            .collect();
        Self { rules }
    }

    pub fn evaluate<'a>(&'a self, input: &MatchInput<'_>) -> Option<&'a str> {
        self.rules
            .iter()
            .find(|rule| matches_rule(rule, input))
            .map(|rule| rule.target())
    }
}

fn matches_rule(rule: &RuleEntry, input: &MatchInput<'_>) -> bool {
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
        RuleEntry::Domain { domain, .. } => {
            if let Some(host) = input.host {
                host.to_lowercase() == *domain
            } else {
                false
            }
        }
        RuleEntry::DomainKeyword { keyword, .. } => {
            if let Some(host) = input.host {
                host.to_lowercase().contains(keyword.as_str())
            } else {
                false
            }
        }
        RuleEntry::Match { .. } => true,
        RuleEntry::GeoIp { .. } => false,
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
        RuleEngine::new(&raw)
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
    fn geoip_stub_never_matches() {
        let engine = make_engine(&["GEOIP,CN,DIRECT", "MATCH,Proxy"]);
        let input = MatchInput {
            host: Some("baidu.com"),
            ip: Some("114.114.114.114".parse().unwrap()),
            process_name: None,
        };
        // GEOIP stub is a no-op, so MATCH catches it
        assert_eq!(engine.evaluate(&input), Some("Proxy"));
    }
}
