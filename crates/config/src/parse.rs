use std::path::Path;

use anyhow::{Context, Result};

use crate::types::Config;

pub fn load_config(path: &Path) -> Result<Config> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file: {}", path.display()))?;
    let config: Config = serde_yaml::from_str(&content)
        .with_context(|| format!("failed to parse config file: {}", path.display()))?;
    Ok(config)
}

#[cfg(test)]
mod tests {
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
