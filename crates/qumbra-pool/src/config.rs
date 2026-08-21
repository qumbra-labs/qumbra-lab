//! TOML service config.
//!
//! `form` is a field of `[template]` — a fact about the tip the operator
//! (or a later node-RPC source) built — not a top-level switch that
//! could desync from the genesis hash (H1).

use qlab_devnet::forms::GenesisForm;
use serde::Deserialize;

use crate::hexutil;
use crate::template::{header_from_parts, parse_form, HeldTemplateSource, Template, TemplateError};

/// Default template poll interval. The stall age default is derived from
/// this × [`DEFAULT_TEMPLATE_STALL_POLLS`] so the two bounds cannot
/// silently disagree.
pub const DEFAULT_POLL_MS: u64 = 1000;
/// Consecutive failed polls (and, when age is unset, the age bound in
/// poll intervals) before work is suspended. Public-endpoint default:
/// three seconds at the default poll cadence.
pub const DEFAULT_TEMPLATE_STALL_POLLS: u64 = 3;

#[derive(Debug, Clone, Deserialize)]
pub struct PoolConfig {
    /// `host:port` the stratum TCP listener binds.
    pub listen_addr: String,
    /// Assigned share difficulty. Encoded as 8-byte raw LE target.
    pub share_difficulty: u64,
    /// Static `[template]` table. Required unless [`Self::node_rpc`] is set.
    #[serde(default)]
    pub template: Option<TemplateFile>,
    /// `http://host:port` of this pool's own node (lab #511). When set,
    /// jobs come from `GET /v1/mine/template` and block finds POST
    /// `/v1/mine/block`. The static table is ignored.
    #[serde(default)]
    pub node_rpc: Option<String>,
    /// How often to re-fetch the live template, milliseconds.
    /// Default [`DEFAULT_POLL_MS`].
    #[serde(default)]
    pub poll_ms: Option<u64>,
    /// Consecutive failed template polls before work is suspended.
    /// Default [`DEFAULT_TEMPLATE_STALL_POLLS`].
    #[serde(default)]
    pub template_max_poll_failures: Option<u64>,
    /// Wall-clock milliseconds without a successful template poll before
    /// work is suspended. When unset, derived as stall-polls × poll_ms.
    #[serde(default)]
    pub template_max_age_ms: Option<u64>,
    /// Public coinbase-payee identity for pool fallback payouts, encoded as
    /// 64 hex characters (32 bytes, lane-major little-endian).
    ///
    /// There is deliberately no usable default: a service that does not know
    /// which wallet owns its coinbase must refuse before accepting miners.
    #[serde(default)]
    pub payout_rkm: Option<String>,
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
    MissingPayoutRkm,
    InvalidPayoutRkm(hexutil::HexError),
    /// `payout_rkm` is the node's unconfigured-miner placeholder (lab #547).
    /// Refused by name here as well as at the payee gate: the config is
    /// where an operator can still fix it before any miner connects.
    PlaceholderPayoutRkm,
    StaticTemplateSource,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(s) => write!(f, "config io: {s}"),
            ConfigError::Toml(s) => write!(f, "config toml: {s}"),
            ConfigError::Template(e) => write!(f, "config template: {e}"),
            ConfigError::ZeroDifficulty => write!(f, "share_difficulty must be ≥ 1"),
            ConfigError::EmptyListen => write!(f, "listen_addr must be non-empty"),
            ConfigError::MissingPayoutRkm => write!(
                f,
                "missing-payout-rkm: payout_rkm must name the wallet that can spend the pool's coinbase"
            ),
            ConfigError::InvalidPayoutRkm(hexutil::HexError::ZeroRkm) => write!(
                f,
                "all-zero-payout-rkm: payout_rkm must name a real wallet; an all-zero coinbase payee is unspendable"
            ),
            ConfigError::InvalidPayoutRkm(e) => write!(f, "invalid-payout-rkm: {e}"),
            ConfigError::PlaceholderPayoutRkm => write!(
                f,
                "placeholder-payout-rkm: payout_rkm is the node's UNCONFIGURED_MINER_RKM \
                 placeholder, which NOBODY can spend — name the wallet that owns the pool's \
                 coinbase, not the value a node prints when it was never told where to pay"
            ),
            ConfigError::StaticTemplateSource => write!(
                f,
                "static-template-source-refused: a serving pool requires node_rpc; static [template] jobs can never track the live chain"
            ),
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
        let _ = self.payout_rkm_lanes()?;
        if self
            .node_rpc
            .as_ref()
            .map(|s| s.trim().is_empty())
            .unwrap_or(true)
        {
            if self.template.is_none() {
                return Err(ConfigError::Toml(
                    "need [template] or node_rpc = \"http://host:port\"".into(),
                ));
            }
            let _ = self.template_source()?;
        }
        Ok(())
    }

    /// The first-service gate. Static templates remain parseable for fixtures,
    /// but no CLI service path may accept miners over one.
    pub fn ensure_service_ready(&self) -> Result<(), ConfigError> {
        if self
            .node_rpc
            .as_ref()
            .map(|s| s.trim().is_empty())
            .unwrap_or(true)
        {
            return Err(ConfigError::StaticTemplateSource);
        }
        let _ = self.payout_rkm_lanes()?;
        Ok(())
    }

    pub fn poll_interval_ms(&self) -> u64 {
        self.poll_ms.unwrap_or(DEFAULT_POLL_MS).max(1)
    }

    pub fn stall_poll_failures(&self) -> u64 {
        self.template_max_poll_failures
            .unwrap_or(DEFAULT_TEMPLATE_STALL_POLLS)
            .max(1)
    }

    /// Age bound in milliseconds. Unset → stall-polls × poll interval, so
    /// the wall-clock bound tracks the poll cadence rather than a second
    /// literal (`derived-not-duplicated.md` §4).
    pub fn stall_age_ms(&self) -> u64 {
        self.template_max_age_ms
            .unwrap_or_else(|| {
                self.poll_interval_ms()
                    .saturating_mul(self.stall_poll_failures())
            })
            .max(1)
    }

    /// Decode the configured public payout identity into the coinbase lanes.
    pub fn payout_rkm_lanes(&self) -> Result<[u64; 4], ConfigError> {
        let value = self
            .payout_rkm
            .as_deref()
            .ok_or(ConfigError::MissingPayoutRkm)?;
        let lanes = hexutil::rkm_lanes_from_hex(value).map_err(ConfigError::InvalidPayoutRkm)?;
        if lanes == crate::payee::UNCONFIGURED_NODE_RKM {
            return Err(ConfigError::PlaceholderPayoutRkm);
        }
        Ok(lanes)
    }

    pub fn form(&self) -> Result<GenesisForm, ConfigError> {
        let t = self.template.as_ref().ok_or_else(|| {
            ConfigError::Toml("no [template] (live node_rpc has no static form)".into())
        })?;
        parse_form(&t.form).map_err(ConfigError::Template)
    }

    pub fn into_template(&self) -> Result<Template, ConfigError> {
        let t = self
            .template
            .as_ref()
            .ok_or_else(|| ConfigError::Toml("no [template]".into()))?;
        let form = parse_form(&t.form).map_err(ConfigError::Template)?;
        let header = header_from_parts(
            &t.prev,
            t.height,
            t.timestamp,
            t.difficulty,
            &t.tx_body_commitment,
        )
        .map_err(ConfigError::Template)?;
        let seed_hash = hexutil::decode_exact(&t.seed_hash)
            .map_err(|e| ConfigError::Template(TemplateError::Hex(e)))?;
        let next_seed_hash = match &t.next_seed_hash {
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
            body: None,
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
payout_rkm = "0100000000000000020000000000000003000000000000000400000000000000"

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

    #[test]
    fn serving_refuses_a_static_template_by_name() {
        let cfg = PoolConfig::from_toml(SAMPLE).unwrap();
        let err = cfg.ensure_service_ready().unwrap_err();
        assert!(matches!(&err, ConfigError::StaticTemplateSource));
        assert!(err.to_string().contains("static-template-source-refused"));
    }

    #[test]
    fn serving_refuses_an_all_zero_payout_by_name() {
        let live = r#"
listen_addr = "127.0.0.1:3333"
share_difficulty = 1024
node_rpc = "http://node:9420"
payout_rkm = "0000000000000000000000000000000000000000000000000000000000000000"
"#;
        let err = PoolConfig::from_toml(live).unwrap_err();
        assert!(matches!(
            &err,
            ConfigError::InvalidPayoutRkm(hexutil::HexError::ZeroRkm)
        ));
        assert!(err.to_string().contains("all-zero-payout-rkm"));
    }

    /// Lab #547. The all-zero shape was already refused; this one is the
    /// shape that actually reached the chain, and an operator who copies a
    /// payee off a block explorer to "match what the node pays" would
    /// otherwise configure it and be refused nowhere.
    #[test]
    fn serving_refuses_the_node_placeholder_payout_by_name() {
        let live = format!(
            r#"
listen_addr = "127.0.0.1:3333"
share_difficulty = 1024
node_rpc = "http://node:9420"
payout_rkm = "{}"
"#,
            "0111011101110111".repeat(4)
        );
        let err = PoolConfig::from_toml(&live).unwrap_err();
        assert!(matches!(&err, ConfigError::PlaceholderPayoutRkm));
        let msg = err.to_string();
        assert!(msg.contains("placeholder-payout-rkm"), "got: {msg}");
        assert!(
            msg.contains("NOBODY can spend"),
            "the refusal must say what is wrong with it, got: {msg}"
        );
    }

    #[test]
    fn live_service_uses_the_configured_payout_lanes() {
        let live = r#"
listen_addr = "127.0.0.1:3333"
share_difficulty = 1024
node_rpc = "http://node:9420"
payout_rkm = "0100000000000000020000000000000003000000000000000400000000000000"
"#;
        let cfg = PoolConfig::from_toml(live).unwrap();
        cfg.ensure_service_ready().unwrap();
        assert_eq!(cfg.payout_rkm_lanes().unwrap(), [1, 2, 3, 4]);
    }

    #[test]
    fn stall_age_default_tracks_poll_cadence() {
        let live = r#"
listen_addr = "127.0.0.1:3333"
share_difficulty = 1024
node_rpc = "http://node:9420"
poll_ms = 2000
payout_rkm = "0100000000000000020000000000000003000000000000000400000000000000"
"#;
        let cfg = PoolConfig::from_toml(live).unwrap();
        assert_eq!(cfg.poll_interval_ms(), 2000);
        assert_eq!(cfg.stall_poll_failures(), DEFAULT_TEMPLATE_STALL_POLLS);
        assert_eq!(
            cfg.stall_age_ms(),
            cfg.poll_interval_ms() * cfg.stall_poll_failures()
        );

        let explicit = r#"
listen_addr = "127.0.0.1:3333"
share_difficulty = 1024
node_rpc = "http://node:9420"
poll_ms = 2000
template_max_poll_failures = 5
template_max_age_ms = 15000
payout_rkm = "0100000000000000020000000000000003000000000000000400000000000000"
"#;
        let cfg = PoolConfig::from_toml(explicit).unwrap();
        assert_eq!(cfg.stall_poll_failures(), 5);
        assert_eq!(cfg.stall_age_ms(), 15000);
    }
}
