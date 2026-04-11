use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleEntry {
    DomainSuffix {
        suffix: String,
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
    Match {
        target: String,
    },
}

impl RuleEntry {
    pub fn parse(raw: &str) -> Option<RuleEntry> {
        let parts: Vec<&str> = raw.splitn(3, ',').collect();
        match parts.as_slice() {
            ["DOMAIN-SUFFIX", suffix, target] => Some(RuleEntry::DomainSuffix {
                suffix: suffix.trim().to_lowercase(),
                target: target.trim().to_string(),
            }),
            ["IP-CIDR", cidr, target] => {
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
            ["MATCH", target] => Some(RuleEntry::Match {
                target: target.trim().to_string(),
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
        assert!(RuleEntry::parse("GEOIP,CN,DIRECT").is_none());
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
}
