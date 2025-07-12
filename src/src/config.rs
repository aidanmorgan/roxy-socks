use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::rules::Rule;

/// Configuration for the proxy
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Config {
    /// Access control rules
    pub rules: Vec<Rule>,
    /// Timeout in seconds for network operations
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

/// Default timeout value in seconds
fn default_timeout() -> u64 {
    5
}

/// Load configuration from the specified path
pub fn load_config<P: AsRef<Path>>(path: P) -> Result<Config> {
    let path = path.as_ref();
    info!("Loading configuration from {}", path.display());

    // Open the file
    let mut file = File::open(path)
        .with_context(|| format!("Failed to open config file: {}", path.display()))?;

    // Read the file content
    let mut content = String::new();
    file.read_to_string(&mut content)
        .with_context(|| format!("Failed to read config file: {}", path.display()))?;

    // Parse YAML
    let config: Config = serde_yaml::from_str(&content)
        .with_context(|| format!("Failed to parse config file: {}", path.display()))?;

    debug!("Loaded {} rules from configuration", config.rules.len());
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_valid_config() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "rules:").unwrap();
        writeln!(file, "  - endpoint: /containers/json").unwrap();
        writeln!(file, "    methods: [GET]").unwrap();
        writeln!(file, "    allow: true").unwrap();

        let config = load_config(file.path()).unwrap();
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].endpoint, "/containers/json");
        assert_eq!(config.rules[0].methods, vec!["GET"]);
        assert!(config.rules[0].allow);
    }

    #[test]
    fn test_load_invalid_config() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "invalid: yaml").unwrap();

        let result = load_config(file.path());
        assert!(result.is_err());
    }
}
