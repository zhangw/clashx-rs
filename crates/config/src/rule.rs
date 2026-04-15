use std::fmt;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleEntry {
    Domain {
        domain: String,
        target: String,
    },
    DomainSuffix {
        suffix: String,
        target: String,
    },
    DomainKeyword {
        keyword: String,
        target: String,
    },
    IpCidr {
        ip: IpAddr,
        prefix_len: u8,
        target: String,
    },
    ProcessName {
        name: String,
        target: String,
    },
    GeoIp {
        country: String,
        target: String,
    },
    Match {
        target: String,
    },
}

impl RuleEntry {
    pub fn parse(raw: &str) -> Option<RuleEntry> {
        let parts: Vec<&str> = raw.splitn(3, ',').collect();
        match parts.as_slice() {
            ["DOMAIN", domain, target] => Some(RuleEntry::Domain {
                domain: domain.trim().to_lowercase(),
                target: target.trim().to_string(),
            }),
            ["DOMAIN-SUFFIX", suffix, target] => Some(RuleEntry::DomainSuffix {
                suffix: suffix.trim().to_lowercase(),
                target: target.trim().to_string(),
            }),
            ["DOMAIN-KEYWORD", keyword, target] => Some(RuleEntry::DomainKeyword {
                keyword: keyword.trim().to_lowercase(),
                target: target.trim().to_string(),
            }),
            ["IP-CIDR" | "IP-CIDR6", cidr, target] => {
                let cidr = cidr.trim();
                let (ip_str, prefix_str) = cidr.split_once('/')?;
                let ip: IpAddr = ip_str.parse().ok()?;
                let prefix_len: u8 = prefix_str.parse().ok()?;
                Some(RuleEntry::IpCidr {
                    ip,
                    prefix_len,
                    target: target.trim().to_string(),
                })
            }
            ["PROCESS-NAME", name, target] => Some(RuleEntry::ProcessName {
                name: name.trim().to_string(),
                target: target.trim().to_string(),
            }),
            ["GEOIP", country, target] => Some(RuleEntry::GeoIp {
                country: country.trim().to_uppercase(),
                target: target.trim().to_string(),
            }),
            ["MATCH", target] => Some(RuleEntry::Match {
                target: target.trim().to_string(),
            }),
            _ => None,
        }
    }

    /// Short description of the rule for logging (e.g., "GEOIP,CN", "DOMAIN-SUFFIX,google.com").
    pub fn description(&self) -> String {
        self.display().to_string()
    }

    pub fn target(&self) -> &str {
        match self {
            RuleEntry::Domain { target, .. }
            | RuleEntry::DomainSuffix { target, .. }
            | RuleEntry::DomainKeyword { target, .. }
            | RuleEntry::IpCidr { target, .. }
            | RuleEntry::ProcessName { target, .. }
            | RuleEntry::GeoIp { target, .. }
            | RuleEntry::Match { target } => target,
        }
    }

    pub fn display(&self) -> RuleDisplay<'_> {
        RuleDisplay(self)
    }

    fn write_description(&self, f: &mut impl fmt::Write) -> fmt::Result {
        match self {
            RuleEntry::Domain { domain, .. } => write!(f, "DOMAIN,{domain}"),
            RuleEntry::DomainSuffix { suffix, .. } => write!(f, "DOMAIN-SUFFIX,{suffix}"),
            RuleEntry::DomainKeyword { keyword, .. } => write!(f, "DOMAIN-KEYWORD,{keyword}"),
            RuleEntry::IpCidr { ip, prefix_len, .. } => write!(f, "IP-CIDR,{ip}/{prefix_len}"),
            RuleEntry::ProcessName { name, .. } => write!(f, "PROCESS-NAME,{name}"),
            RuleEntry::GeoIp { country, .. } => write!(f, "GEOIP,{country}"),
            RuleEntry::Match { .. } => f.write_str("MATCH"),
        }
    }
}

pub struct RuleDisplay<'a>(&'a RuleEntry);

impl fmt::Display for RuleDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.write_description(f)
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;

    #[test]
    fn parse_domain_suffix() {
        let entry = RuleEntry::parse("DOMAIN-SUFFIX,example.com,DIRECT").unwrap();
        assert_eq!(
            entry,
            RuleEntry::DomainSuffix {
                suffix: "example.com".to_string(),
                target: "DIRECT".to_string(),
            }
        );
    }

    #[test]
    fn parse_ip_cidr() {
        let entry = RuleEntry::parse("IP-CIDR,192.168.0.0/16,DIRECT").unwrap();
        assert_eq!(
            entry,
            RuleEntry::IpCidr {
                ip: "192.168.0.0".parse::<IpAddr>().unwrap(),
                prefix_len: 16,
                target: "DIRECT".to_string(),
            }
        );
    }

    #[test]
    fn parse_process_name() {
        let entry = RuleEntry::parse("PROCESS-NAME,curl,Proxy").unwrap();
        assert_eq!(
            entry,
            RuleEntry::ProcessName {
                name: "curl".to_string(),
                target: "Proxy".to_string(),
            }
        );
    }

    #[test]
    fn parse_match_rule() {
        let entry = RuleEntry::parse("MATCH,DIRECT").unwrap();
        assert_eq!(
            entry,
            RuleEntry::Match {
                target: "DIRECT".to_string()
            }
        );
    }

    #[test]
    fn parse_unknown_returns_none() {
        assert!(RuleEntry::parse("SRC-IP-CIDR,192.168.0.0/16,DIRECT").is_none());
    }

    #[test]
    fn parse_geoip() {
        let entry = RuleEntry::parse("GEOIP,CN,DIRECT").unwrap();
        assert_eq!(
            entry,
            RuleEntry::GeoIp {
                country: "CN".to_string(),
                target: "DIRECT".to_string(),
            }
        );
    }

    #[test]
    fn domain_suffix_lowercased() {
        let entry = RuleEntry::parse("DOMAIN-SUFFIX,Example.COM,Proxy").unwrap();
        if let RuleEntry::DomainSuffix { suffix, .. } = entry {
            assert_eq!(suffix, "example.com");
        } else {
            panic!("expected DomainSuffix");
        }
    }

    #[test]
    fn parse_domain() {
        let entry = RuleEntry::parse("DOMAIN,mtalk.google.com,Proxy").unwrap();
        assert_eq!(
            entry,
            RuleEntry::Domain {
                domain: "mtalk.google.com".to_string(),
                target: "Proxy".to_string(),
            }
        );
    }

    #[test]
    fn domain_lowercased() {
        let entry = RuleEntry::parse("DOMAIN,MTALK.Google.COM,Proxy").unwrap();
        if let RuleEntry::Domain { domain, .. } = entry {
            assert_eq!(domain, "mtalk.google.com");
        } else {
            panic!("expected Domain");
        }
    }

    #[test]
    fn parse_domain_keyword() {
        let entry = RuleEntry::parse("DOMAIN-KEYWORD,youtube,Proxy").unwrap();
        assert_eq!(
            entry,
            RuleEntry::DomainKeyword {
                keyword: "youtube".to_string(),
                target: "Proxy".to_string(),
            }
        );
    }

    #[test]
    fn domain_keyword_lowercased() {
        let entry = RuleEntry::parse("DOMAIN-KEYWORD,YouTube,Proxy").unwrap();
        if let RuleEntry::DomainKeyword { keyword, .. } = entry {
            assert_eq!(keyword, "youtube");
        } else {
            panic!("expected DomainKeyword");
        }
    }

    #[test]
    fn parse_ip_cidr6() {
        let entry = RuleEntry::parse("IP-CIDR6,::1/128,DIRECT").unwrap();
        assert_eq!(
            entry,
            RuleEntry::IpCidr {
                ip: "::1".parse::<IpAddr>().unwrap(),
                prefix_len: 128,
                target: "DIRECT".to_string(),
            }
        );
    }

    #[test]
    fn parse_ip_cidr6_ula() {
        let entry = RuleEntry::parse("IP-CIDR6,fd00::/8,DIRECT").unwrap();
        assert_eq!(
            entry,
            RuleEntry::IpCidr {
                ip: "fd00::".parse::<IpAddr>().unwrap(),
                prefix_len: 8,
                target: "DIRECT".to_string(),
            }
        );
    }
}
