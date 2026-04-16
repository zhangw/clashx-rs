//! Subscription management for clashx-rs.
//!
//! Downloads Clash-compatible YAML configs from subscription URLs and writes
//! them to configured output paths. Uses `User-Agent: clash` so providers
//! return the full YAML format instead of base64-encoded URIs.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub mod download;
pub mod manager;
pub mod state;

pub use manager::{
    add_subscription, remove_subscription, update_all_subscriptions, update_due_subscriptions,
    update_subscription_by_name,
};
pub use state::{load_subscriptions, save_subscriptions};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SubscriptionConfig {
    #[serde(default)]
    pub subscriptions: Vec<Subscription>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub name: String,
    pub url: String,
    pub output: String,
    #[serde(default = "default_interval")]
    pub interval: u64,
    #[serde(default)]
    pub last_updated: u64,
}

fn default_interval() -> u64 {
    86400
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
