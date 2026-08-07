//! The explorer's own TOML config, and the observer posture it enforces.
//!
//! **Four** refusals, all named, all before anything binds (same order-discipline
//! as the faucet's `load`): the node must be **keyless** (§6.2 decision 1 — a
//! publicly reachable process must hold no committee keys), it must **not mine**
//! (an explorer that mines is a participant describing itself as an observer,
//! and its own coinbase would appear in the supply rows it publishes), its config
//! must open **no telemetry/metrics listener** from this process — the projection
//! is this binary's only HTTP surface, because §6.2 keeps `/v1/telemetry` off the
//! public internet and a listener started here would be public by construction —
//! and a **non-loopback `discovery_addr`** is refused by name, which is the
//! reason svc0 runs a separate `cbnode` for `/v1/compact` rather than letting
//! this process serve it.
//!
//! *(Said "three" until 2026-08-07. The fourth arrived with `PR #236`'s review
//! (`fba4d04`) and this count was not updated — the same drift shape the tree
//! keeps paying for, in the doc comment of the file that enforces them.)*

use std::path::{Path, PathBuf};

use qumbra_node::config::NodeConfig;
use serde::Deserialize;

/// `qumbra-explorer.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct ExplorerConfig {
    /// Path to the observer node's `NodeConfig` TOML.
    pub node_config: PathBuf,
    /// Where the projection listens — `/v1/health.json` + `/healthz`, and since
    /// issue #281 **no HTML at all**. This binary speaks plain HTTP, deliberately;
    /// TLS belongs to whatever fronts it.
    ///
    /// 🔴 In a container this must be `0.0.0.0:9480`, not `127.0.0.1:9480`:
    /// "loopback" inside a container is the *container's* loopback, so a reverse
    /// proxy on the compose bridge could not reach it. That is not a public bind —
    /// the port is `expose`d and never published, and svc0's only public port is
    /// caddy's 443. Loopback is still right when running this binary on a host
    /// directly.
    pub listen_addr: String,
    /// The refresh cadence the operator chose, **carried in the document** at
    /// `refresh_secs` so the reader honours it instead of hardcoding one.
    ///
    /// *(Until issue #281 this was a `<meta http-equiv="refresh">` in a page this
    /// binary rendered. The page moved to `qumbra-explorer-web`; without carrying
    /// the value into the projection this config knob would have silently become
    /// dead.)*
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
    /// `discovery_addr` is set and not obviously loopback. Loopback and unset
    /// both pass (the #188 2/4 default is a loopback bind and stays untouched);
    /// anything else — a public IP, `0.0.0.0`, a hostname, an unparseable value —
    /// is refused, because this is a startup refusal: a false refusal is loud
    /// and a false accept is a silent second public surface.
    PublicDiscoveryAddr(String),
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
            ConfigRefusal::PublicDiscoveryAddr(addr) => write!(
                f,
                "the observer node's config sets discovery_addr = `{addr}`, which is not \
                 obviously loopback. The explorer's page must be this process's only public \
                 HTTP surface — bind discovery to 127.0.0.1/[::1]/localhost, or remove \
                 discovery_addr to keep the loopback default."
            ),
        }
    }
}

/// Whether `host:port` is *obviously* loopback: `localhost`, a loopback IPv4, or
/// a bracketed loopback IPv6. No DNS resolution — a name that merely resolves to
/// loopback is not obvious, and a startup check must not depend on a resolver.
fn is_loopback_hostport(hostport: &str) -> bool {
    use std::net::IpAddr;
    let host = if let Some(rest) = hostport.strip_prefix('[') {
        match rest.split_once(']') {
            Some((h, _)) => h,
            None => return false,
        }
    } else {
        match hostport.rsplit_once(':') {
            Some((h, _)) => h,
            None => return false,
        }
    };
    host == "localhost" || host.parse::<IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false)
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
        // The same claim as the two above, enforced rather than inherited from
        // another crate's default: not obviously loopback ⇒ refuse.
        if let Some(d) = node.discovery_addr.as_deref() {
            if !is_loopback_hostport(d) {
                return Err(ConfigRefusal::PublicDiscoveryAddr(d.to_string()));
            }
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
    fn a_publicly_bound_discovery_addr_is_refused_by_name() {
        let cfg = ExplorerConfig::from_toml(
            "node_config = \"/tmp/node.toml\"\nlisten_addr = \"127.0.0.1:0\"\n",
        )
        .unwrap();
        // Not obviously loopback ⇒ refused: a public bind, a LAN address, a
        // hostname (no resolver at startup), and an unparseable value alike.
        for bad in ["0.0.0.0:8645", "10.0.0.5:8645", "node0:8645", "garbage"] {
            let mut node = node_cfg();
            node.discovery_addr = Some(bad.to_string());
            let e = cfg.check_observer(&node).unwrap_err();
            assert!(matches!(e, ConfigRefusal::PublicDiscoveryAddr(_)), "{bad}: {e}");
            assert!(e.to_string().contains(bad), "{bad} named in the refusal");
        }
        // Obviously loopback (and unset) both pass — the #188 2/4 default stands.
        for ok in ["127.0.0.1:8645", "[::1]:8645", "localhost:8645"] {
            let mut node = node_cfg();
            node.discovery_addr = Some(ok.to_string());
            cfg.check_observer(&node).unwrap_or_else(|e| panic!("{ok} must pass: {e}"));
        }
        cfg.check_observer(&node_cfg()).expect("None passes");
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
