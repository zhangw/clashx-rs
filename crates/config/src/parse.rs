use std::path::Path;

use anyhow::{Context, Result};

use crate::types::{Config, LogLevel};

/// Read just `log-level` from the config file.
///
/// Logging has to be configured before [`load_config`] runs, because that
/// function reports problems through `tracing` itself. Deserialising into a
/// one-field struct skips building the proxy and rule lists, which is the
/// expensive part of a real config.
pub fn load_log_level(path: &Path) -> LogLevel {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "kebab-case")]
    struct LogLevelOnly {
        #[serde(default)]
        log_level: LogLevel,
    }

    std::fs::read_to_string(path)
        .ok()
        .and_then(|content| serde_yaml::from_str::<LogLevelOnly>(&content).ok())
        .map(|parsed| parsed.log_level)
        .unwrap_or_default()
}

pub fn load_config(path: &Path) -> Result<Config> {
    // Warn if config file is world/group-readable. It typically contains
    // proxy passwords, so recommend 0600 or 0400.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                tracing::warn!(
                    path = %path.display(),
                    mode = format!("{mode:o}"),
                    "config file has group/other read permissions — it may contain proxy passwords; chmod 600 recommended"
                );
            }
        }
    }

    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file: {}", path.display()))?;
    let config: Config = serde_yaml::from_str(&content)
        .with_context(|| format!("failed to parse config file: {}", path.display()))?;
    Ok(config)
}

#[cfg(test)]
mod tests {

    #[test]
    fn log_level_read_without_full_parse() {
        let dir = std::env::temp_dir().join(format!("clashx-loglevel-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.yaml");

        // A config whose proxy list would fail a full parse still yields its
        // log level, because only that one field is deserialised.
        std::fs::write(
            &path,
            "log-level: debug\nproxies:\n  - {type: nonsense-protocol, bogus: 1}\n",
        )
        .unwrap();
        assert_eq!(load_log_level(&path), LogLevel::Debug);

        // Every level maps through.
        for (text, expected) in [
            ("silent", LogLevel::Silent),
            ("error", LogLevel::Error),
            ("warning", LogLevel::Warning),
            ("info", LogLevel::Info),
        ] {
            std::fs::write(&path, format!("log-level: {text}\n")).unwrap();
            assert_eq!(load_log_level(&path), expected);
        }

        // Absent key falls back to the default rather than to silence.
        std::fs::write(&path, "mixed-port: 7890\n").unwrap();
        assert_eq!(load_log_level(&path), LogLevel::Info);

        // An unreadable or unparseable file must not make the daemon silent.
        assert_eq!(load_log_level(&dir.join("missing.yaml")), LogLevel::Info);
        std::fs::write(&path, "\t not: [valid: yaml").unwrap();
        assert_eq!(load_log_level(&path), LogLevel::Info);

        std::fs::remove_dir_all(&dir).ok();
    }
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn load_from_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            "mixed-port: 7890\nallow-lan: true\nmode: rule\nlog-level: info"
        )
        .unwrap();
        let config = load_config(file.path()).unwrap();
        assert_eq!(config.mixed_port, Some(7890));
        assert_eq!(config.allow_lan, Some(true));
    }

    #[test]
    fn load_nonexistent_file_errors() {
        let result = load_config(Path::new("/nonexistent/path/config.yaml"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("failed to read config file"));
    }
}
