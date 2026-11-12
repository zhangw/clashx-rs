//! Loading and saving the on-disk subscription list.
//!
//! The state file is `~/.config/clashx-rs/subscriptions.yaml`. Writes go
//! through a sibling `.yaml.tmp` file that is renamed into place, and on Unix
//! the file is restricted to `0600` because subscription URLs may embed tokens.
//! A missing file is not an error: it loads as an empty configuration. Older
//! files that omit `interval`, `last_updated`, or `enabled` keep their
//! documented defaults.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::SubscriptionConfig;

/// Path to the subscriptions.yaml file.
#[must_use]
pub fn subscriptions_path() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("~"));
    home.join(".config/clashx-rs/subscriptions.yaml")
}

/// Load subscriptions from disk. Returns an empty config if the file doesn't exist.
///
/// # Errors
///
/// Returns an error when the file exists but cannot be read, or when its
/// contents are not valid YAML for [`SubscriptionConfig`].
pub fn load_subscriptions() -> Result<SubscriptionConfig> {
    load_subscriptions_from(&subscriptions_path())
}

/// Load subscriptions from an explicit path.
///
/// A missing file yields [`SubscriptionConfig::default`]. On Unix a warning is
/// logged when the file is readable by group or others, since it may contain
/// subscription tokens.
///
/// # Errors
///
/// Returns an error when the file exists but cannot be read, or when its
/// contents are not valid YAML for [`SubscriptionConfig`].
pub fn load_subscriptions_from(path: &Path) -> Result<SubscriptionConfig> {
    clashx_rs_config::warn_if_group_or_world_readable(
        path,
        "subscriptions file",
        "it may contain subscription tokens",
    );

    let content = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(SubscriptionConfig::default())
        }
        Err(e) => {
            return Err(anyhow::Error::new(e))
                .with_context(|| format!("failed to read {}", path.display()))
        }
    };
    let config: SubscriptionConfig = serde_yaml::from_str(&content)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(config)
}

/// Save subscriptions to disk atomically (.tmp + rename).
///
/// # Errors
///
/// Returns an error when the parent directory cannot be created, the config
/// cannot be serialized, the temp file cannot be written, the rename fails, or
/// the final permissions cannot be set.
pub fn save_subscriptions(config: &SubscriptionConfig) -> Result<()> {
    save_subscriptions_to(&subscriptions_path(), config)
}

/// Save subscriptions to an explicit path, atomically.
///
/// The parent directory is created if needed; on Unix the resulting file is
/// restricted to `0600`.
///
/// # Errors
///
/// Returns an error when the parent directory cannot be created, the config
/// cannot be serialized, the temp file cannot be written, the rename fails, or
/// the final permissions cannot be set.
pub fn save_subscriptions_to(path: &Path, config: &SubscriptionConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let yaml = serde_yaml::to_string(config).context("failed to serialize subscriptions")?;
    crate::fsutil::write_atomic_sync(path, yaml.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Subscription;

    #[test]
    fn load_missing_file_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.yaml");
        let config = load_subscriptions_from(&path).unwrap();
        assert!(config.subscriptions.is_empty());
    }

    #[test]
    fn save_then_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subs.yaml");
        let mut config = SubscriptionConfig::default();
        config.subscriptions.push(Subscription {
            name: "wgetcloud".into(),
            url: "https://example.com/sub".into(),
            output: "~/.config/clash/wgetcloud.yaml".into(),
            interval: 864_000,
            last_updated: 1_700_000_000,
            enabled: false,
        });
        save_subscriptions_to(&path, &config).unwrap();

        let loaded = load_subscriptions_from(&path).unwrap();
        assert_eq!(loaded.subscriptions.len(), 1);
        assert_eq!(loaded.subscriptions[0].name, "wgetcloud");
        assert_eq!(loaded.subscriptions[0].interval, 864_000);
        assert_eq!(loaded.subscriptions[0].last_updated, 1_700_000_000);
        assert!(!loaded.subscriptions[0].enabled);
    }

    #[test]
    fn default_interval_applied_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subs.yaml");
        std::fs::write(
            &path,
            r"
subscriptions:
  - name: foo
    url: https://example.com/sub
    output: /tmp/foo.yaml
",
        )
        .unwrap();
        let loaded = load_subscriptions_from(&path).unwrap();
        assert_eq!(loaded.subscriptions[0].interval, 86400);
        assert_eq!(loaded.subscriptions[0].last_updated, 0);
        // Missing `enabled` defaults to true for backward compatibility.
        assert!(loaded.subscriptions[0].enabled);
    }
}
