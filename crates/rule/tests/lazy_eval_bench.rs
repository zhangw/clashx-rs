//! Regression + perf gate for the lazy rule evaluator.
//!
//! Pure compute, no network, no port binding, no system-proxy writes — safe
//! to run alongside a live daemon.
//!
//! Why the time thresholds are loose: they exist to catch an order-of-
//! magnitude regression (e.g., an infinite loop reappearing), not to gate
//! microbenchmark noise.

use std::net::IpAddr;
use std::time::Instant;

use clashx_rs_rule::{EvalStep, MatchInput, RuleEngine};

/// Build a config that resembles the user's ~9000-rule setup: lots of
/// DOMAIN-SUFFIX, a sprinkling of IP-CIDR, one PROCESS-NAME, and a MATCH.
fn big_ruleset() -> Vec<String> {
    let mut rules: Vec<String> = Vec::with_capacity(9000);
    for i in 0..8000 {
        rules.push(format!("DOMAIN-SUFFIX,domain-{i}.example,Proxy-{}", i % 16));
    }
    for i in 0..900 {
        rules.push(format!("IP-CIDR,10.{}.0.0/16,DIRECT", i % 256));
    }
    rules.push("PROCESS-NAME,SomeApp,AppProxy".into());
    rules.push("MATCH,Fallback".into());
    rules
}

/// Drive a full daemon-style lazy-eval loop against `engine`. The two
/// boolean knobs simulate DNS/process-lookup outcomes: when false, the
/// lookup "fails" (value stays None, attempted flag is still set — the
/// exact condition the regression test guards).
fn lazy_eval_once(
    engine: &RuleEngine,
    host: Option<&str>,
    parsed_ip: Option<IpAddr>,
    dns_succeeds: bool,
    process_found: bool,
) -> (Option<String>, usize) {
    let mut ip = parsed_ip;
    let mut process_name: Option<String> = None;
    let mut ip_attempted = parsed_ip.is_some();
    let mut process_attempted = false;
    let mut start = 0usize;
    let mut iters = 0usize;
    loop {
        iters += 1;
        assert!(iters < 1000, "lazy-eval loop did not terminate");
        let input = MatchInput {
            host,
            ip,
            process_name: process_name.as_deref(),
            ip_attempted,
            process_attempted,
        };
        match engine.evaluate_from(&input, start) {
            EvalStep::Matched(rule) => return (Some(rule.target().to_string()), iters),
            EvalStep::NoMatch => return (None, iters),
            EvalStep::NeedsData {
                resume_from,
                need_ip,
                need_process,
            } => {
                if need_ip {
                    if dns_succeeds {
                        ip = Some("198.51.100.1".parse().unwrap());
                    }
                    ip_attempted = true;
                }
                if need_process {
                    if process_found {
                        process_name = Some("SomeApp".into());
                    }
                    process_attempted = true;
                }
                start = resume_from;
            }
        }
    }
}

fn small_engine(rules: &[&str]) -> RuleEngine {
    let raw: Vec<String> = rules.iter().map(|s| s.to_string()).collect();
    RuleEngine::new(&raw, None)
}

#[test]
fn terminates_when_dns_fails_small() {
    let engine = small_engine(&[
        "DOMAIN-SUFFIX,example.com,Proxy",
        "IP-CIDR,10.0.0.0/8,DIRECT",
        "MATCH,Fallback",
    ]);
    let (target, iters) = lazy_eval_once(&engine, Some("broken.host"), None, false, false);
    assert_eq!(target.as_deref(), Some("Fallback"));
    assert!(
        iters < 5,
        "expected termination in a few iters, got {iters}"
    );
}

#[test]
fn terminates_when_process_not_found_small() {
    let engine = small_engine(&[
        "DOMAIN-SUFFIX,example.com,Proxy",
        "PROCESS-NAME,SomeApp,DIRECT",
        "MATCH,Fallback",
    ]);
    let (target, iters) = lazy_eval_once(&engine, Some("other.host"), None, false, false);
    assert_eq!(target.as_deref(), Some("Fallback"));
    assert!(
        iters < 5,
        "expected termination in a few iters, got {iters}"
    );
}

#[test]
fn uses_ip_when_dns_succeeds() {
    let engine = small_engine(&[
        "DOMAIN-SUFFIX,example.com,Proxy",
        "IP-CIDR,198.51.100.0/24,DIRECT",
        "MATCH,Fallback",
    ]);
    let (target, _) = lazy_eval_once(&engine, Some("other.host"), None, true, false);
    assert_eq!(target.as_deref(), Some("DIRECT"));
}

#[test]
fn domain_match_skips_data_fetch() {
    // Domain rule matches before any NeedsData is emitted → single pass.
    let engine = small_engine(&[
        "DOMAIN-SUFFIX,example.com,Proxy",
        "IP-CIDR,10.0.0.0/8,DIRECT",
        "MATCH,Fallback",
    ]);
    let (target, iters) = lazy_eval_once(&engine, Some("www.example.com"), None, false, false);
    assert_eq!(target.as_deref(), Some("Proxy"));
    assert_eq!(iters, 1, "domain match should need no data round-trips");
}

#[test]
fn lazy_eval_terminates_on_dns_failure_big() {
    let engine = RuleEngine::new(&big_ruleset(), None);
    let (target, _) = lazy_eval_once(&engine, Some("broken.host"), None, false, false);
    assert_eq!(target.as_deref(), Some("Fallback"));
}

#[test]
fn lazy_eval_terminates_on_missing_process_big() {
    let engine = RuleEngine::new(&big_ruleset(), None);
    // DNS succeeds but IP doesn't match any CIDR, process isn't a target →
    // must fall through to MATCH.
    let (target, _) = lazy_eval_once(&engine, Some("unrelated.host"), None, true, false);
    assert_eq!(target.as_deref(), Some("Fallback"));
}

#[test]
fn lazy_eval_bench_domain_match_hot_path() {
    let engine = RuleEngine::new(&big_ruleset(), None);
    const ITERS: usize = 10_000;

    let mut total_inner_iters = 0usize;
    let start = Instant::now();
    for i in 0..ITERS {
        let host = format!("sub.domain-{}.example", i % 8000);
        let (_target, inner) = lazy_eval_once(&engine, Some(&host), None, false, false);
        total_inner_iters += inner;
    }
    let elapsed = start.elapsed();

    eprintln!(
        "[bench] hot-path domain-match: {ITERS} iters in {:?} ({:?}/iter); inner_iters={total_inner_iters}",
        elapsed,
        elapsed / ITERS as u32
    );
    assert!(
        elapsed.as_secs() < 5,
        "hot-path eval far slower than expected: {elapsed:?}"
    );
}

#[test]
fn lazy_eval_bench_dns_fail_fallthrough() {
    // Formerly an infinite loop; now one walk with attempted flags set.
    let engine = RuleEngine::new(&big_ruleset(), None);
    const ITERS: usize = 1_000;

    let start = Instant::now();
    for _ in 0..ITERS {
        let (target, inner) = lazy_eval_once(&engine, Some("broken.host"), None, false, false);
        assert_eq!(target.as_deref(), Some("Fallback"));
        assert!(inner <= 3, "fallthrough took {inner} inner iterations");
    }
    let elapsed = start.elapsed();

    eprintln!(
        "[bench] dns-fail fallthrough: {ITERS} iters in {:?} ({:?}/iter)",
        elapsed,
        elapsed / ITERS as u32
    );
    assert!(
        elapsed.as_secs() < 5,
        "fallthrough eval far slower than expected: {elapsed:?}"
    );
}
