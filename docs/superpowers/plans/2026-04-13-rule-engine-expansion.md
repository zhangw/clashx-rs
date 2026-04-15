# Rule Engine Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add DOMAIN, DOMAIN-KEYWORD, IP-CIDR6 rule types, a GEOIP warn stub, and parse-time warnings for unrecognized rules — recovering 146 silently dropped rules from the user's live config.

**Architecture:** Extend `RuleEntry` enum in `crates/config/src/rule.rs` with three new variants (`Domain`, `DomainKeyword`, `GeoIp`). IP-CIDR6 reuses the existing `IpCidr` variant (just a second parse label). Add matching logic in `crates/rule/src/lib.rs`. GEOIP parses but never matches (warn stub). Unrecognized rule types are logged at warn level during engine construction.

**Tech Stack:** Rust, tracing (already a dep of `clashx-rs-rule` crate). No new dependencies.

**Execution note:** Implementation MUST happen in an isolated git worktree — the user's local clashx-rs daemon must not be affected until the PR is ready.

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `crates/config/src/rule.rs` | Modify | Add `Domain`, `DomainKeyword`, `GeoIp` enum variants + parse arms + `target()` arms. Add `IP-CIDR6` as a parse alias for existing `IpCidr` variant. |
| `crates/rule/src/lib.rs` | Modify | Add `matches_rule` arms for `Domain` (exact match), `DomainKeyword` (substring), `GeoIp` (always false). Add warn logging in `RuleEngine::new` for unrecognized rules and GEOIP stub notice. |

Two files total. No new files, no new crate dependencies.

---

## Task 1: Add DOMAIN rule type

**Files:**
- Modify: `crates/config/src/rule.rs` (enum + parse + target + tests)
- Modify: `crates/rule/src/lib.rs` (match arm + tests)

- [ ] **Step 1: Write failing test in config crate**

Add to `crates/config/src/rule.rs` inside `mod tests`:

```rust
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p clashx-rs-config parse_domain`
Expected: FAIL — `Domain` variant doesn't exist yet.

- [ ] **Step 3: Add Domain variant + parse arm + target arm**

In `crates/config/src/rule.rs`, add the enum variant after `DomainSuffix`:

```rust
Domain {
    domain: String,
    target: String,
},
```

Add parse arm in `RuleEntry::parse` before the `_ => None` arm:

```rust
["DOMAIN", domain, target] => Some(RuleEntry::Domain {
    domain: domain.trim().to_lowercase(),
    target: target.trim().to_string(),
}),
```

Add target arm in `RuleEntry::target()`:

```rust
RuleEntry::Domain { target, .. } => target,
```

- [ ] **Step 4: Run config crate tests**

Run: `cargo test -p clashx-rs-config`
Expected: PASS (config tests pass; rule crate will have compile errors due to non-exhaustive match — that's expected, we fix it next).

- [ ] **Step 5: Write failing test in rule crate**

Add to `crates/rule/src/lib.rs` inside `mod tests`:

```rust
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
```

- [ ] **Step 6: Add matches_rule arm for Domain**

In `crates/rule/src/lib.rs`, add arm in `matches_rule`:

```rust
RuleEntry::Domain { domain, .. } => {
    if let Some(host) = input.host {
        host.to_lowercase() == *domain
    } else {
        false
    }
}
```

- [ ] **Step 7: Run all tests**

Run: `cargo test`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add crates/config/src/rule.rs crates/rule/src/lib.rs
git commit -m "feat(rule): add DOMAIN exact-match rule type"
```

---

## Task 2: Add DOMAIN-KEYWORD rule type

**Files:**
- Modify: `crates/config/src/rule.rs` (enum + parse + target + tests)
- Modify: `crates/rule/src/lib.rs` (match arm + tests)

- [ ] **Step 1: Write failing test in config crate**

Add to `crates/config/src/rule.rs` inside `mod tests`:

```rust
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p clashx-rs-config parse_domain_keyword`
Expected: FAIL — `DomainKeyword` variant doesn't exist.

- [ ] **Step 3: Add DomainKeyword variant + parse arm + target arm**

In `crates/config/src/rule.rs`, add the enum variant:

```rust
DomainKeyword {
    keyword: String,
    target: String,
},
```

Add parse arm:

```rust
["DOMAIN-KEYWORD", keyword, target] => Some(RuleEntry::DomainKeyword {
    keyword: keyword.trim().to_lowercase(),
    target: target.trim().to_string(),
}),
```

Add target arm:

```rust
RuleEntry::DomainKeyword { target, .. } => target,
```

- [ ] **Step 4: Run config crate tests**

Run: `cargo test -p clashx-rs-config`
Expected: PASS

- [ ] **Step 5: Write failing test in rule crate**

Add to `crates/rule/src/lib.rs` inside `mod tests`:

```rust
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
```

- [ ] **Step 6: Add matches_rule arm for DomainKeyword**

In `crates/rule/src/lib.rs`, add arm in `matches_rule`:

```rust
RuleEntry::DomainKeyword { keyword, .. } => {
    if let Some(host) = input.host {
        host.to_lowercase().contains(keyword.as_str())
    } else {
        false
    }
}
```

- [ ] **Step 7: Run all tests**

Run: `cargo test`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add crates/config/src/rule.rs crates/rule/src/lib.rs
git commit -m "feat(rule): add DOMAIN-KEYWORD substring rule type"
```

---

## Task 3: Add IP-CIDR6 parse support

IP-CIDR6 reuses the existing `IpCidr` variant — `IpAddr::parse()` already handles IPv6, and `ip_in_cidr` already dispatches to v4/v6. This is purely a parse-label alias.

**Files:**
- Modify: `crates/config/src/rule.rs` (parse arm + tests)
- Modify: `crates/rule/src/lib.rs` (tests only — matching already works via `IpCidr`)

- [ ] **Step 1: Write failing test in config crate**

Add to `crates/config/src/rule.rs` inside `mod tests`:

```rust
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p clashx-rs-config parse_ip_cidr6`
Expected: FAIL — returns None (no parse arm for "IP-CIDR6").

- [ ] **Step 3: Add IP-CIDR6 parse arm**

In `crates/config/src/rule.rs`, add parse arm right after the `"IP-CIDR"` arm (duplicate the body, change only the label):

```rust
["IP-CIDR6", cidr, target] => {
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
```

- [ ] **Step 4: Run config crate tests**

Run: `cargo test -p clashx-rs-config`
Expected: PASS

- [ ] **Step 5: Write integration test in rule crate**

Add to `crates/rule/src/lib.rs` inside `mod tests`:

```rust
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
```

- [ ] **Step 6: Run all tests**

Run: `cargo test`
Expected: PASS (no new match arm needed — `IpCidr` arm already handles v6).

- [ ] **Step 7: Commit**

```bash
git add crates/config/src/rule.rs crates/rule/src/lib.rs
git commit -m "feat(rule): add IP-CIDR6 parse support (reuses IpCidr)"
```

---

## Task 4: Add GEOIP warn stub

Parses GEOIP rules into a variant that never matches. The warning is emitted in Task 5 alongside the general unrecognized-rule warning.

**Files:**
- Modify: `crates/config/src/rule.rs` (enum + parse + target + tests)
- Modify: `crates/rule/src/lib.rs` (match arm always false + tests)

- [ ] **Step 1: Write failing test in config crate**

Add to `crates/config/src/rule.rs` inside `mod tests`:

```rust
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
```

Also update the existing `parse_unknown_returns_none` test — GEOIP is now recognized:

```rust
#[test]
fn parse_unknown_returns_none() {
    assert!(RuleEntry::parse("SRC-IP-CIDR,192.168.0.0/16,DIRECT").is_none());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p clashx-rs-config parse_geoip`
Expected: FAIL — `GeoIp` variant doesn't exist.

- [ ] **Step 3: Add GeoIp variant + parse arm + target arm**

In `crates/config/src/rule.rs`, add the enum variant:

```rust
GeoIp {
    country: String,
    target: String,
},
```

Add parse arm:

```rust
["GEOIP", country, target] => Some(RuleEntry::GeoIp {
    country: country.trim().to_uppercase(),
    target: target.trim().to_string(),
}),
```

Add target arm:

```rust
RuleEntry::GeoIp { target, .. } => target,
```

- [ ] **Step 4: Run config crate tests**

Run: `cargo test -p clashx-rs-config`
Expected: PASS

- [ ] **Step 5: Write test in rule crate — GEOIP never matches**

Add to `crates/rule/src/lib.rs` inside `mod tests`:

```rust
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
```

- [ ] **Step 6: Add matches_rule arm for GeoIp (always false)**

In `crates/rule/src/lib.rs`, add arm in `matches_rule`:

```rust
RuleEntry::GeoIp { .. } => false,
```

- [ ] **Step 7: Run all tests**

Run: `cargo test`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add crates/config/src/rule.rs crates/rule/src/lib.rs
git commit -m "feat(rule): add GEOIP as parsed-but-stub (always false)"
```

---

## Task 5: Add parse-time warnings for unrecognized rules and GEOIP stub

**Files:**
- Modify: `crates/rule/src/lib.rs` (warn logging in `RuleEngine::new`)

- [ ] **Step 1: Write test for unrecognized rule warning**

Add to `crates/rule/src/lib.rs` inside `mod tests`:

```rust
#[test]
fn unrecognized_rules_are_skipped() {
    // Engine should still work — unrecognized rules are dropped, not fatal
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
```

- [ ] **Step 2: Run test to verify it passes**

Run: `cargo test -p clashx-rs-rule unrecognized_rules_are_skipped`
Expected: PASS (filter_map already skips unrecognized rules — this test confirms current behavior).

- [ ] **Step 3: Add warn logging in RuleEngine::new**

Replace the `RuleEngine::new` method in `crates/rule/src/lib.rs`:

```rust
pub fn new(raw_rules: &[String]) -> Self {
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
    if geoip_count > 0 {
        tracing::warn!(
            count = geoip_count,
            "GEOIP rules parsed but not yet functional (stub), will not match any traffic"
        );
    }

    Self { rules }
}
```

- [ ] **Step 4: Run all tests**

Run: `cargo test`
Expected: PASS

- [ ] **Step 5: Run clippy and fmt**

Run: `cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: PASS — no warnings, formatting clean.

- [ ] **Step 6: Commit**

```bash
git add crates/rule/src/lib.rs
git commit -m "feat(rule): warn on unrecognized rule types and GEOIP stub"
```

---

## Task 6: Final verification

- [ ] **Step 1: Run full test suite**

Run: `cargo test`
Expected: All tests pass.

- [ ] **Step 2: Run clippy**

Run: `cargo clippy --all-targets -- -D warnings`
Expected: No warnings.

- [ ] **Step 3: Run fmt check**

Run: `cargo fmt --check`
Expected: No formatting issues.

- [ ] **Step 4: Review diff**

Run: `git diff main --stat`
Expected: Only two files changed: `crates/config/src/rule.rs`, `crates/rule/src/lib.rs`.

---

## Out of scope (noted for awareness)

- **`no-resolve` flag stripping**: Clash rules like `IP-CIDR,10.0.0.0/8,DIRECT,no-resolve` produce target `"DIRECT,no-resolve"` with the current `splitn(3, ',')` parser. This is a pre-existing issue affecting IP-CIDR as well. Not addressed here — separate fix if needed.
- **GEOIP real implementation (A4b)**: Requires `maxminddb` crate + DNS rewrite design spec.
- **`clashx-rs lint` subcommand**: Deferred follow-up.
- **Performance optimizations (B1/B2/B3)**: Profile-gated, separate PR.
