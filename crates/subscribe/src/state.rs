use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::SubscriptionConfig;

/// Path to the subscriptions.yaml file.
pub fn subscriptions_path() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("~"));
    home.join(".config/clashx-rs/subscriptions.yaml")
}

/// Load subscriptions from disk. Returns an empty config if the file doesn't exist.
pub fn load_subscriptions() -> Result<SubscriptionConfig> {
    load_subscriptions_from(&subscriptions_path())
}

pub fn load_subscriptions_from(path: &Path) -> Result<SubscriptionConfig> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                tracing::warn!(
                    path = %path.display(),
                    mode = format!("{mode:o}"),
                    "subscriptions file has group/other read permissions — it may contain subscription tokens; chmod 600 recommended"
                );
            }
        }
    }

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
pub fn save_subscriptions(config: &SubscriptionConfig) -> Result<()> {
    save_subscriptions_to(&subscriptions_path(), config)
}

pub fn save_subscriptions_to(path: &Path, config: &SubscriptionConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let yaml = serde_yaml::to_string(config).context("failed to serialize subscriptions")?;
    let tmp = path.with_extension("yaml.tmp");
    write_restricted_file(&tmp, yaml.as_bytes())
        .with_context(|| format!("failed to write {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| {
        let _ = std::fs::remove_file(&tmp);
        format!("failed to rename {} -> {}", tmp.display(), path.display())
    })?;
    set_owner_only_permissions(path)
        .with_context(|| format!("failed to secure {}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn write_restricted_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_restricted_file(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes)?;
    Ok(())
}

#[cfg(unix)]
fn set_owner_only_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_owner_only_permissions(_path: &Path) -> Result<()> {
    Ok(())
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
            interval: 864000,
            last_updated: 1_700_000_000,
        });
        save_subscriptions_to(&path, &config).unwrap();

        let loaded = load_subscriptions_from(&path).unwrap();
        assert_eq!(loaded.subscriptions.len(), 1);
        assert_eq!(loaded.subscriptions[0].name, "wgetcloud");
        assert_eq!(loaded.subscriptions[0].interval, 864000);
        assert_eq!(loaded.subscriptions[0].last_updated, 1_700_000_000);
    }

    #[test]
    fn default_interval_applied_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subs.yaml");
        std::fs::write(
            &path,
            r#"
subscriptions:
  - name: foo
    url: https://example.com/sub
    output: /tmp/foo.yaml
"#,
        )
        .unwrap();
        let loaded = load_subscriptions_from(&path).unwrap();
        assert_eq!(loaded.subscriptions[0].interval, 86400);
        assert_eq!(loaded.subscriptions[0].last_updated, 0);
    }
}
