//! The explorer's own TOML config, and the observer posture it enforces.
//!
//! Three refusals, all named, all before anything binds (same order-discipline as
//! the faucet's `load`): the node must be **keyless** (§6.2 decision 1 — a
//! publicly reachable process must hold no committee keys), it must **not mine**
//! (an explorer that mines is a participant describing itself as an observer,
//! and its own coinbase would appear in the supply rows it publishes), and its
//! config must open **no telemetry/metrics listener** from this process — the
//! page is this binary's only HTTP surface, because §6.2 keeps `/v1/telemetry`
//! off the public internet and a listener started here would be public by
//! construction.

use std::path::{Path, PathBuf};

use qumbra_node::config::NodeConfig;
use serde::Deserialize;

/// `qumbra-explorer.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct ExplorerConfig {
    /// Path to the observer node's `NodeConfig` TOML.
    pub node_config: PathBuf,
    /// Where the page listens, e.g. `127.0.0.1:9480` (put TLS in front for the
    /// public form — this binary speaks plain HTTP, deliberately).
    pub listen_addr: String,
    /// Browser auto-refresh interval (a `<meta http-equiv="refresh">`, no JS).
    #[serde(default = "default_refresh_secs")]
    pub refresh_secs: u64,
}

fn default_refresh_secs() -> u64 {
    30
}

/// A named configuration refusal. Every variant says what to change, because the
/// operator reading it is not the person who wrote the config.
#[derive(Debug)]
pub enum ConfigRefusal {
    Io(String),
    Parse(String),
    BadListenAddr(String),
    /// §6.2 decision 1: the observer must hold no committee keys.
    NotKeyless(usize),
    /// The observer must not mine — see the module docs.
    Mining,
    /// The node config would open a telemetry or metrics listener from this
    /// process; the explorer's page must be its only HTTP surface.
    ExtraListener(&'static str),
}

impl std::fmt::Display for ConfigRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigRefusal::Io(e) => write!(f, "config: {e}"),
            ConfigRefusal::Parse(e) => write!(f, "config: {e}"),
            ConfigRefusal::BadListenAddr(a) => {
                write!(f, "listen_addr `{a}` does not parse as host:port")
            }
            ConfigRefusal::NotKeyless(n) => write!(
                f,
                "the observer node's config lists {n} committee key path(s). A publicly \
                 reachable explorer must hold NO committee keys (§6.2 decision 1) — point \
                 node_config at a keyless config."
            ),
            ConfigRefusal::Mining => write!(
                f,
                "the observer node's config sets mining = true. The explorer is a read-only \
                 observer: it must not mine (set mining = false)."
            ),
            ConfigRefusal::ExtraListener(which) => write!(
                f,
                "the observer node's config sets {which}. The explorer's page is this \
                 process's only HTTP surface — fleet telemetry stays private (§6.2); remove \
                 {which} from the node config."
            ),
        }
    }
}

impl std::error::Error for ConfigRefusal {}

impl ExplorerConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigRefusal> {
        let text = std::fs::read_to_string(path.as_ref())
            .map_err(|e| ConfigRefusal::Io(format!("{}: {e}", path.as_ref().display())))?;
        Self::from_toml(&text)
    }

    pub fn from_toml(text: &str) -> Result<Self, ConfigRefusal> {
        let cfg: ExplorerConfig =
            toml::from_str(text).map_err(|e| ConfigRefusal::Parse(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), ConfigRefusal> {
        // `host:port` — `0` ports are fine (tests), names are fine (docker).
        if !self.listen_addr.contains(':') {
            return Err(ConfigRefusal::BadListenAddr(self.listen_addr.clone()));
        }
        Ok(())
    }

    /// The observer posture, refused in a fixed order so `check` and `run` fail
    /// identically: keyless, non-mining, no extra listeners.
    pub fn check_observer(&self, node: &NodeConfig) -> Result<(), ConfigRefusal> {
        if !node.committee_key_paths.is_empty() {
            return Err(ConfigRefusal::NotKeyless(node.committee_key_paths.len()));
        }
        if node.mining {
            return Err(ConfigRefusal::Mining);
        }
        if node.telemetry_addr.is_some() {
            return Err(ConfigRefusal::ExtraListener("telemetry_addr"));
        }
        if node.metrics_addr.is_some() {
            return Err(ConfigRefusal::ExtraListener("metrics_addr"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_cfg() -> NodeConfig {
        NodeConfig {
            data_dir: "/tmp/x".into(),
            listen_addr: "127.0.0.1:0".into(),
            dial_peers: vec![],
            advertise_addr: None,
            genesis_file: "/tmp/g".into(),
            committee_key_paths: vec![],
            mining: false,
            expected_genesis_hash: None,
            metrics_addr: None,
            telemetry_addr: None,
            discovery_addr: None,
            miner_rkm: None,
        }
    }

    #[test]
    fn a_clean_observer_config_passes() {
        let cfg = ExplorerConfig::from_toml(
            "node_config = \"/tmp/node.toml\"\nlisten_addr = \"127.0.0.1:0\"\n",
        )
        .unwrap();
        assert_eq!(cfg.refresh_secs, 30, "default refresh");
        cfg.check_observer(&node_cfg()).unwrap();
    }

    #[test]
    fn a_node_with_committee_keys_is_refused_by_name() {
        let cfg = ExplorerConfig::from_toml(
            "node_config = \"/tmp/node.toml\"\nlisten_addr = \"127.0.0.1:0\"\n",
        )
        .unwrap();
        let mut node = node_cfg();
        node.committee_key_paths = vec!["/tmp/k0.key".into()];
        let e = cfg.check_observer(&node).unwrap_err();
        assert!(matches!(e, ConfigRefusal::NotKeyless(1)), "{e}");
        assert!(e.to_string().contains("NO committee keys"), "{e}");
    }

    #[test]
    fn a_mining_node_is_refused_by_name() {
        let cfg = ExplorerConfig::from_toml(
            "node_config = \"/tmp/node.toml\"\nlisten_addr = \"127.0.0.1:0\"\n",
        )
        .unwrap();
        let mut node = node_cfg();
        node.mining = true;
        let e = cfg.check_observer(&node).unwrap_err();
        assert!(matches!(e, ConfigRefusal::Mining), "{e}");
    }

    #[test]
    fn a_config_that_would_open_a_telemetry_or_metrics_listener_is_refused() {
        let cfg = ExplorerConfig::from_toml(
            "node_config = \"/tmp/node.toml\"\nlisten_addr = \"127.0.0.1:0\"\n",
        )
        .unwrap();
        let mut node = node_cfg();
        node.telemetry_addr = Some("127.0.0.1:9410".into());
        let e = cfg.check_observer(&node).unwrap_err();
        assert!(matches!(e, ConfigRefusal::ExtraListener("telemetry_addr")), "{e}");

        let mut node = node_cfg();
        node.metrics_addr = Some("127.0.0.1:9420".into());
        let e = cfg.check_observer(&node).unwrap_err();
        assert!(matches!(e, ConfigRefusal::ExtraListener("metrics_addr")), "{e}");
    }
}
