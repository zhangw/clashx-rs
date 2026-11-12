//! Clash/mihomo-compatible configuration parsing for `clashx-rs`.
//!
//! The crate turns a Clash YAML document into typed data: the top-level
//! [`Config`], its [`types::DnsConfig`] block, proxies, proxy groups, and raw
//! rule strings. It only reads the file; it does not validate runtime
//! semantics, and the daemon, DNS, and rule crates interpret the result.
//!
//! Entry points:
//!
//! - [`load_config`] reads and deserializes a full configuration file.
//! - [`load_log_level`] reads only `log-level`, so logging can be configured
//!   before the full parse reports problems.
//!
//! Invariants:
//!
//! - Unknown keys never fail the parse. Top-level and `dns` unknown keys are
//!   preserved in their respective `extra` maps, and unrecognized proxy types
//!   become [`types::Proxy::Unknown`].
//! - Absent keys keep their Clash defaults; the field docs state them.
//! - Targets, node names, and DNS entries are not validated here. Consumers
//!   warn about and skip unusable entries instead of rejecting the config.
//!
//! DNS keys and their runtime semantics are documented in the
//! [DNS resolver design](../../../docs/dns-resolver-design.md); rule matching
//! lives in the `clashx-rs-rule` crate.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unchecked_time_subtraction
    )
)]

pub mod parse;
pub mod rule;
pub mod types;

pub use parse::{load_config, load_log_level, warn_if_group_or_world_readable};
pub use types::{Config, LogLevel};
