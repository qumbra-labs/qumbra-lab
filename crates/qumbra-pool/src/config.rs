//! TOML service config.
//!
//! `form` is a field of `[template]` — a fact about the tip the operator
//! (or a later node-RPC source) built — not a top-level switch that
//! could desync from the genesis hash (H1).

use qlab_devnet::forms::GenesisForm;
use serde::Deserialize;

use crate::hexutil;
use crate::template::{header_from_parts, parse_form, HeldTemplateSource, Template, TemplateError};

#[derive(Debug, Clone, Deserialize)]
pub struct PoolConfig {
    /// `host:port` the stratum TCP listener binds.
    pub listen_addr: String,
    /// Assigned share difficulty. Encoded as 8-byte raw LE target.
    pub share_difficulty: u64,
    pub template: TemplateFile,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TemplateFile {
    /// `"v4"` or `"v5"` — the form the *template was built under*.
    pub form: String,
    pub prev: String,
    pub height: u64,
    pub timestamp: u64,
    pub difficulty: u64,
    pub tx_body_commitment: String,
    pub seed_hash: String,
    #[serde(default)]
    pub next_seed_hash: Option<String>,
}

#[derive(Debug)]
pub enum ConfigError {
    Io(String),
    Toml(String),
    Template(TemplateError),
    ZeroDifficulty,
    EmptyListen,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(s) => write!(f, "config io: {s}"),
            ConfigError::Toml(s) => write!(f, "config toml: {s}"),
            ConfigError::Template(e) => write!(f, "config template: {e}"),
            ConfigError::ZeroDifficulty => write!(f, "share_difficulty must be ≥ 1"),
            ConfigError::EmptyListen => write!(f, "listen_addr must be non-empty"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl PoolConfig {
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let cfg: Self = toml::from_str(text).map_err(|e| ConfigError::Toml(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Io(e.to_string()))?;
        Self::from_toml(&text)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.listen_addr.trim().is_empty() {
            return Err(ConfigError::EmptyListen);
        }
        if self.share_difficulty == 0 {
            return Err(ConfigError::ZeroDifficulty);
        }
        let _ = self.template_source()?;
        Ok(())
    }

    pub fn form(&self) -> Result<GenesisForm, ConfigError> {
        parse_form(&self.template.form).map_err(ConfigError::Template)
    }

    pub fn into_template(&self) -> Result<Template, ConfigError> {
        let form = self.form()?;
        let header = header_from_parts(
            &self.template.prev,
            self.template.height,
            self.template.timestamp,
            self.template.difficulty,
            &self.template.tx_body_commitment,
        )
        .map_err(ConfigError::Template)?;
        let seed_hash = hexutil::decode_exact(&self.template.seed_hash)
            .map_err(|e| ConfigError::Template(TemplateError::Hex(e)))?;
        let next_seed_hash = match &self.template.next_seed_hash {
            Some(s) => Some(
                hexutil::decode_exact(s)
                    .map_err(|e| ConfigError::Template(TemplateError::Hex(e)))?,
            ),
            None => None,
        };
        Ok(Template {
            form,
            header,
            seed_hash,
            next_seed_hash,
        })
    }

    pub fn template_source(&self) -> Result<HeldTemplateSource, ConfigError> {
        Ok(HeldTemplateSource::new(self.into_template()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
listen_addr = "127.0.0.1:3333"
share_difficulty = 1024

[template]
form = "v5"
prev = "1111111111111111111111111111111111111111111111111111111111111111"
height = 100
timestamp = 1785000000
difficulty = 256
tx_body_commitment = "2222222222222222222222222222222222222222222222222222222222222222"
seed_hash = "3333333333333333333333333333333333333333333333333333333333333333"
"#;

    #[test]
    fn parses_v5_template_and_refuses_zero_difficulty() {
        let cfg = PoolConfig::from_toml(SAMPLE).unwrap();
        assert_eq!(cfg.form().unwrap(), GenesisForm::V5);
        let t = cfg.into_template().unwrap();
        assert!(t.serves_stock_xmrig());
        assert_eq!(t.header.height, 100);

        let bad = SAMPLE.replace("1024", "0");
        assert!(matches!(
            PoolConfig::from_toml(&bad),
            Err(ConfigError::ZeroDifficulty)
        ));
    }
}
