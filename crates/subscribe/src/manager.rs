use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Result};

use crate::{
    download::{build_client, download_subscription},
    Subscription, SubscriptionConfig,
};

/// Current unix timestamp in seconds.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Returns true if the subscription has never been downloaded or its interval has elapsed.
pub fn needs_update(sub: &Subscription) -> bool {
    if sub.last_updated == 0 {
        return true;
    }
    now_unix() >= sub.last_updated.saturating_add(sub.interval)
}

async fn update_filtered<F>(
    config: &mut SubscriptionConfig,
    should_update: F,
) -> Vec<(String, Result<()>)>
where
    F: Fn(&Subscription) -> bool,
{
    let client = match build_client() {
        Ok(c) => c,
        Err(e) => {
            let err_msg = e.to_string();
            return config
                .subscriptions
                .iter()
                .filter(|s| should_update(s))
                .map(|s| (s.name.clone(), Err(anyhow::anyhow!("{err_msg}"))))
                .collect();
        }
    };

    let mut results = Vec::new();
    for sub in config.subscriptions.iter_mut() {
        if !should_update(sub) {
            continue;
        }
        let result = download_subscription(&client, sub).await;
        if result.is_ok() {
            sub.last_updated = now_unix();
        }
        results.push((sub.name.clone(), result));
    }
    results
}

/// Download all subscriptions whose interval has elapsed. Updates `last_updated`
/// timestamps in place on success. Returns per-subscription results.
pub async fn update_due_subscriptions(
    config: &mut SubscriptionConfig,
) -> Vec<(String, Result<()>)> {
    update_filtered(config, needs_update).await
}

/// Download all subscriptions regardless of interval.
pub async fn update_all_subscriptions(
    config: &mut SubscriptionConfig,
) -> Vec<(String, Result<()>)> {
    update_filtered(config, |_| true).await
}

/// Download a specific subscription by name.
pub async fn update_subscription_by_name(
    config: &mut SubscriptionConfig,
    name: &str,
) -> Result<()> {
    let client = build_client()?;
    let sub = config
        .subscriptions
        .iter_mut()
        .find(|s| s.name == name)
        .ok_or_else(|| anyhow::anyhow!("subscription '{name}' not found"))?;
    let result = download_subscription(&client, sub).await;
    if result.is_ok() {
        sub.last_updated = now_unix();
    }
    result
}

/// Add a subscription. Fails if a subscription with the same name already exists.
pub fn add_subscription(config: &mut SubscriptionConfig, sub: Subscription) -> Result<()> {
    if config.subscriptions.iter().any(|s| s.name == sub.name) {
        bail!("subscription '{}' already exists", sub.name);
    }
    config.subscriptions.push(sub);
    Ok(())
}

/// Remove a subscription by name. Fails if not found.
pub fn remove_subscription(config: &mut SubscriptionConfig, name: &str) -> Result<()> {
    let initial_len = config.subscriptions.len();
    config.subscriptions.retain(|s| s.name != name);
    if config.subscriptions.len() == initial_len {
        bail!("subscription '{name}' not found");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(last_updated: u64, interval: u64) -> Subscription {
        Subscription {
            name: "t".into(),
            url: "https://example.com".into(),
            output: "/tmp/t.yaml".into(),
            interval,
            last_updated,
        }
    }

    #[test]
    fn never_updated_needs_update() {
        assert!(needs_update(&sample(0, 3600)));
    }

    #[test]
    fn recently_updated_does_not_need_update() {
        // last_updated = now, interval = 1 hour → should not need update
        let now = now_unix();
        assert!(!needs_update(&sample(now, 3600)));
    }

    #[test]
    fn elapsed_interval_needs_update() {
        // last_updated far in the past, 1 sec interval → needs update
        assert!(needs_update(&sample(1, 1)));
    }

    #[test]
    fn add_subscription_duplicate_fails() {
        let mut config = SubscriptionConfig::default();
        let sub = sample(0, 3600);
        add_subscription(&mut config, sub.clone()).unwrap();
        assert!(add_subscription(&mut config, sub).is_err());
    }

    #[test]
    fn remove_subscription_missing_fails() {
        let mut config = SubscriptionConfig::default();
        assert!(remove_subscription(&mut config, "nope").is_err());
    }

    #[test]
    fn remove_subscription_ok() {
        let mut config = SubscriptionConfig::default();
        add_subscription(&mut config, sample(0, 3600)).unwrap();
        remove_subscription(&mut config, "t").unwrap();
        assert!(config.subscriptions.is_empty());
    }
}
