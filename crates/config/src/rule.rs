//! Parsed rule entries shared by the config and rule crates.
//!
//! [`RuleEntry::parse`] accepts the comma-separated Clash rule syntax used in
//! the top-level `rules` list. Matching semantics live in the
//! `clashx-rs-rule` crate; this module only parses, normalizes, and renders
//! entries.

use std::fmt;
use std::net::IpAddr;

/// One parsed Clash rule.
///
/// The variant names mirror the rule type in the config (for example
/// `DOMAIN-SUFFIX`); the rule crate evaluates variants in config order and
/// routes to the first match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleEntry {
    /// `DOMAIN`: match one exact hostname.
    Domain {
        /// Hostname to match, lowercased at parse time.
        domain: String,
        /// Rule target: a proxy or group name, `DIRECT`, or `REJECT`.
        target: String,
    },
    /// `DOMAIN-SUFFIX`: match a hostname suffix on a dot boundary.
    DomainSuffix {
        /// Suffix to match, lowercased at parse time. It matches `example.com`
        /// itself and `a.example.com`, but not `aexample.com`.
        suffix: String,
        /// Rule target: a proxy or group name, `DIRECT`, or `REJECT`.
        target: String,
    },
    /// `DOMAIN-KEYWORD`: match a substring of the hostname.
    DomainKeyword {
        /// Substring to search for, lowercased at parse time and compared
        /// against the lowercased hostname.
        keyword: String,
        /// Rule target: a proxy or group name, `DIRECT`, or `REJECT`.
        target: String,
    },
    /// `IP-CIDR` or `IP-CIDR6`: match a resolved address against a CIDR block.
    IpCidr {
        /// Network address parsed from the rule's CIDR.
        ip: IpAddr,
        /// Prefix length in bits; the rule crate compares only these leading
        /// bits of the address.
        prefix_len: u8,
        /// Rule target: a proxy or group name, `DIRECT`, or `REJECT`.
        target: String,
    },
    /// `PROCESS-NAME`: match the exact name of the originating process.
    ProcessName {
        /// Process name to match. Lookup is best-effort and comparatively
        /// expensive.
        name: String,
        /// Rule target: a proxy or group name, `DIRECT`, or `REJECT`.
        target: String,
    },
    /// `GEOIP`: match the resolved address's country in the loaded database.
    GeoIp {
        /// Country code to match, uppercased at parse time. Without a loaded
        /// database the rule never matches.
        country: String,
        /// Rule target: a proxy or group name, `DIRECT`, or `REJECT`.
        target: String,
    },
    /// `MATCH`: catch-all rule that always matches.
    Match {
        /// Rule target: a proxy or group name, `DIRECT`, or `REJECT`.
        target: String,
    },
}

impl RuleEntry {
    /// Parse one rule line.
    ///
    /// The type is matched case-sensitively; domains and keywords are
    /// lowercased, and `GEOIP` countries are uppercased. Leading and trailing
    /// whitespace around every component is trimmed. `IP-CIDR` and
    /// `IP-CIDR6` share one variant and must carry an `address/prefix` CIDR.
    ///
    /// Returns `None` for an unrecognized type or a malformed entry (missing
    /// components, unparsable address, or unparsable prefix), which callers
    /// log and skip.
    #[must_use]
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

    /// Short description of the rule for logging (e.g., `GEOIP,CN`,
    /// `DOMAIN-SUFFIX,google.com`).
    ///
    /// Returns the same text as [`RuleEntry::display`], allocated as a
    /// `String` for log fields.
    #[must_use]
    pub fn description(&self) -> String {
        self.display().to_string()
    }

    /// Rule target: a proxy or group name, `DIRECT`, or `REJECT`.
    #[must_use]
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

    /// Borrowed renderer for the rule's normalized description.
    ///
    /// The output names the rule type and its match pattern but omits the
    /// target, for example `DOMAIN-SUFFIX,example.com`.
    #[must_use]
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

/// Borrowed [`RuleEntry`] renderer returned by [`RuleEntry::display`].
#[derive(Debug)]
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
