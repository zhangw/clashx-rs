//! Subscription management for clashx-rs.
//!
//! Downloads Clash-compatible YAML configs from subscription URLs and writes
//! them to configured output paths. Uses `User-Agent: clash` so providers
//! return the full YAML format instead of base64-encoded URIs.
//!
//! # On-disk state
//!
//! Subscriptions are recorded in `~/.config/clashx-rs/subscriptions.yaml` as a
//! single `subscriptions:` list. [`load_subscriptions`] returns an empty
//! [`SubscriptionConfig`] when the file is absent, and [`save_subscriptions`]
//! writes it atomically (`.yaml.tmp` plus rename) with `0600` permissions,
//! because subscription URLs frequently embed access tokens.
//!
//! # Intervals and defaults
//!
//! `interval` is the minimum number of seconds between automatic downloads
//! (default `86400`, i.e. one day). [`needs_update`](manager::needs_update)
//! treats `last_updated == 0` as "never downloaded" and otherwise compares
//! `now >= last_updated + interval`. `last_updated` is a Unix timestamp in
//! seconds and is only advanced when a download succeeds. Missing optional
//! fields keep working for older files: absent `interval` means `86400`, absent
//! `last_updated` means `0`, and absent `enabled` means `true`.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Downloading subscription configs over HTTP.
pub mod download;
/// Managing subscriptions: due/forced updates and add/remove/enable.
pub mod manager;
/// Loading and saving the on-disk subscription list.
pub mod state;

pub use manager::{
    add_subscription, remove_subscription, set_subscription_enabled, update_all_subscriptions,
    update_due_subscriptions, update_subscription_by_name,
};
pub use state::{load_subscriptions, save_subscriptions};

/// The subscription list as stored in `subscriptions.yaml`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SubscriptionConfig {
    /// All configured subscriptions, in file order.
    #[serde(default)]
    pub subscriptions: Vec<Subscription>,
}

/// One subscription entry: where to fetch the config from and where to write it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    /// Human-readable name and the key used by the by-name operations.
    pub name: String,
    /// Subscription URL; may embed an access token, so treat it as a secret.
    pub url: String,
    /// Output path for the downloaded YAML. A leading `~/` is expanded.
    pub output: String,
    /// Minimum seconds between automatic downloads; defaults to `86400` when
    /// the field is absent from an older state file.
    #[serde(default = "default_interval")]
    pub interval: u64,
    /// Unix timestamp (seconds) of the last successful download; `0` means
    /// never downloaded and defaults to `0` when absent.
    #[serde(default)]
    pub last_updated: u64,
    /// Whether this subscription participates in automatic and bulk updates.
    /// Missing in older config files means enabled, for backward compatibility.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_interval() -> u64 {
    86400
}

fn default_enabled() -> bool {
    true
}

pub(crate) fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("~"));
        home.join(rest)
    } else if path == "~" {
        dirs::home_dir().unwrap_or_else(|| PathBuf::from("~"))
    } else {
        PathBuf::from(path)
    }
}
