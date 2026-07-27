//! The node's TOML configuration (issue #62 item 1).
//!
//! A `qumbra-node` process is configured by a single TOML file:
//!
//! ```toml
//! # where the block log + snapshot live (created if absent)
//! data_dir = "./data"
//! # the TCP address this node listens on
//! listen_addr = "127.0.0.1:9333"
//! # peers to dial on startup (may be empty for the bootstrap node)
//! dial_peers = ["127.0.0.1:9334", "127.0.0.1:9335"]
//! # the versioned genesis file every node in the net shares
//! genesis_file = "./genesis.qmb"
//! # committee signing-key files THIS node holds (0..21 of the 21 T0 keys —
//! # the honestly-labelled rehearsal "federation-of-one" arrangement, item 4)
//! committee_key_paths = ["./keys/committee-00.key"]
//! # produce blocks (real RandomX PoW) when true
//! mining = true
//!
//! # OPTIONAL — refuse to start unless the loaded genesis hashes to this
//! # (hex-encoded keccak256 of the genesis file). The safety pin item 2 asks for.
//! # expected_genesis_hash = "…64 hex chars…"
//! ```
//!
//! Everything here is process/deployment config — NOT consensus. The frozen
//! consensus constants live only in the genesis file ([`crate::genesis`]).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// A parsed node configuration. Deployment/process settings only; consensus
/// constants are in the genesis file, never here.
///
/// `deny_unknown_fields` is deliberate (issue #74, H1). The halt-height upgrade
/// mechanism has **no runtime override**: the halt height is a release constant,
/// reachable from nothing but a rebuild. An unknown key that parsed and was then
/// silently ignored would let an operator write `halt_height = 999`, watch the node
/// start cleanly, and believe they had moved where consensus pauses. Rejecting the
/// key outright is the difference between "you cannot do that" and "that did
/// nothing" — and the same protection covers every other typo'd key here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// Directory backing the append-only block log + atomic snapshot.
    pub data_dir: PathBuf,
    /// TCP address this node binds and listens on (`host:port`).
    pub listen_addr: String,
    /// Peer addresses to dial on startup.
    #[serde(default)]
    pub dial_peers: Vec<String>,
    /// The shared, versioned genesis file (baked frozen constants + committee₀ +
    /// genesis block). Byte-verified on startup.
    pub genesis_file: PathBuf,
    /// Committee signing-key files this node holds (the T0 rehearsal distributes
    /// the frozen 21 ML-DSA keys across the operator's nodes — item 4). Empty for
    /// a non-signing (verify-only) node.
    #[serde(default)]
    pub committee_key_paths: Vec<PathBuf>,
    /// Whether this node produces blocks (real RandomX PoW).
    #[serde(default)]
    pub mining: bool,
    /// Optional startup safety pin: the expected hex-encoded genesis hash. If set
    /// and the loaded genesis file hashes differently, the node refuses to start
    /// (item 2 negative: "wrong-genesis-hash node refuses to start").
    #[serde(default)]
    pub expected_genesis_hash: Option<String>,
}

/// Why a config failed to load.
#[derive(Debug)]
pub enum ConfigError {
    /// The file could not be read.
    Io(std::io::Error),
    /// The TOML did not parse / was missing a required field.
    Parse(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "config io: {e}"),
            ConfigError::Parse(e) => write!(f, "config parse: {e}"),
        }
    }
}
impl std::error::Error for ConfigError {}

impl NodeConfig {
    /// Parse a config from TOML text.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    /// Load and parse a config file from disk.
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(ConfigError::Io)?;
        Self::from_toml(&text)
    }

    /// Serialize back to TOML (used by tooling / tests).
    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).expect("NodeConfig is always TOML-serializable")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
        data_dir = "./data"
        listen_addr = "127.0.0.1:9333"
        dial_peers = ["127.0.0.1:9334", "127.0.0.1:9335"]
        genesis_file = "./genesis.qmb"
        committee_key_paths = ["./keys/committee-00.key", "./keys/committee-01.key"]
        mining = true
        expected_genesis_hash = "abc123"
    "#;

    #[test]
    fn parses_a_full_config() {
        let c = NodeConfig::from_toml(SAMPLE).expect("parse");
        assert_eq!(c.data_dir, PathBuf::from("./data"));
        assert_eq!(c.listen_addr, "127.0.0.1:9333");
        assert_eq!(c.dial_peers, vec!["127.0.0.1:9334", "127.0.0.1:9335"]);
        assert_eq!(c.genesis_file, PathBuf::from("./genesis.qmb"));
        assert_eq!(c.committee_key_paths.len(), 2);
        assert!(c.mining);
        assert_eq!(c.expected_genesis_hash.as_deref(), Some("abc123"));
    }

    #[test]
    fn optional_fields_default() {
        // Only the required fields; the rest default (empty peers/keys, no
        // mining, no hash pin).
        let c = NodeConfig::from_toml(
            r#"
            data_dir = "d"
            listen_addr = "127.0.0.1:0"
            genesis_file = "g"
            "#,
        )
        .expect("parse minimal");
        assert!(c.dial_peers.is_empty());
        assert!(c.committee_key_paths.is_empty());
        assert!(!c.mining);
        assert_eq!(c.expected_genesis_hash, None);
    }

    #[test]
    fn round_trips_through_toml() {
        let c = NodeConfig::from_toml(SAMPLE).unwrap();
        let back = NodeConfig::from_toml(&c.to_toml()).unwrap();
        assert_eq!(c, back);
    }

    /// H1 at the config surface: an unknown key is a hard error, never a silent
    /// no-op. In particular there is no config path to a halt height.
    #[test]
    fn an_unknown_key_is_rejected_not_ignored() {
        let err = NodeConfig::from_toml(
            r#"
            data_dir = "d"
            listen_addr = "127.0.0.1:0"
            genesis_file = "g"
            halt_height = 999
            "#,
        );
        assert!(matches!(err, Err(ConfigError::Parse(_))), "unknown key must not parse");
    }

    #[test]
    fn missing_required_field_is_an_error() {
        // `listen_addr` omitted → parse error, not a silent default.
        let err = NodeConfig::from_toml(
            r#"data_dir = "d"
            genesis_file = "g""#,
        );
        assert!(matches!(err, Err(ConfigError::Parse(_))));
    }
}
