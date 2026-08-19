//! The explorer's own TOML config, and the observer posture it enforces.
//!
//! **Five** refusals, all named, all before anything binds (same order-discipline
//! as the faucet's `load`): the node must be **keyless** (§6.2 decision 1 — a
//! publicly reachable process must hold no committee keys), it must **not mine**
//! (an explorer that mines is a participant describing itself as an observer,
//! and its own coinbase would appear in the supply rows it publishes), its config
//! must open **no telemetry listener and no public metrics listener** from this
//! process — §6.2 keeps `/v1/telemetry` off the public internet outright, while
//! for metrics the OTel baton's coordinator ruling narrowed the old categorical
//! refusal to its actual grounds: it was against PUBLIC listeners, so a
//! **loopback-only** `metrics_addr` now passes and anything else is refused by
//! name (see [`crate::metrics_server`] for the ruling in full) — and a
//! **non-loopback `discovery_addr`** is refused by name, which is the reason
//! svc0 runs a separate `cbnode` for `/v1/compact` rather than letting this
//! process serve it.
//!
//! *(Said "three" until 2026-08-07, and "four" until the OTel baton split the
//! telemetry/metrics refusal into its two different rules. The count keeps
//! moving because the posture keeps being refined; the tests below are the
//! ledger that cannot drift.)*

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
    /// Where the explorer's own OpenMetrics scrape endpoint binds — the
    /// request-latency histogram with trace exemplars (observability-plan §C.1
    /// piece 3). `None` = not served, the same off-by-default posture every
    /// scrape endpoint in the tree takes: setting it opens a port.
    ///
    /// **Loopback only**, enforced as a startup refusal in [`Self::validate`]
    /// AND at bind ([`crate::metrics_server::MetricsServer::start`]) — the §6.2
    /// coordinator ruling for the OTel baton, cited in full in
    /// [`crate::metrics_server`]'s module docs.
    #[serde(default)]
    pub metrics_addr: Option<String>,
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
    /// The node config would open a telemetry listener from this process —
    /// refused for ANY value: `/v1/telemetry` is fleet-internal state and §6.2
    /// keeps it private outright. The OTel baton's ruling relaxed metrics, not
    /// this.
    ExtraListener(&'static str),
    /// The node config sets a `metrics_addr` that is not obviously loopback.
    ///
    /// 🔴 **The §6.2 seam the OTel baton's coordinator ruling re-drew.** The old
    /// check refused `metrics_addr` for any value; the ruling: that refusal was
    /// against PUBLIC listeners, a loopback-only bind exposes nothing public and
    /// is compatible with §6.2's intent, so loopback now PASSES and only a
    /// non-loopback value is refused — by name, with the address in the message.
    PublicNodeMetricsAddr(String),
    /// The explorer's own `metrics_addr` (the §C.1 exemplar-histogram endpoint)
    /// is not obviously loopback — same ruling, same two halves, this binary's
    /// own key. The message is [`crate::metrics_server::non_loopback_refusal`],
    /// shared with the bind path so the two cannot drift.
    PublicMetricsAddr(String),
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
                "the observer node's config sets {which}. Fleet telemetry stays private \
                 (§6.2) — this refusal is for ANY value, loopback included: /v1/telemetry \
                 is fleet-internal state, and the OTel baton's loopback ruling covered \
                 metrics only. Remove {which} from the node config."
            ),
            ConfigRefusal::PublicNodeMetricsAddr(addr) => write!(
                f,
                "the observer node's config sets metrics_addr = `{addr}`, which is not \
                 obviously loopback. The §6.2 refusal of metrics listeners from this \
                 process was against PUBLIC listeners; the OTel baton's coordinator ruling \
                 allows a loopback-only bind (nothing public is exposed) — bind to \
                 127.0.0.1/[::1]/localhost, or remove metrics_addr."
            ),
            ConfigRefusal::PublicMetricsAddr(addr) => {
                write!(f, "{}", crate::metrics_server::non_loopback_refusal(addr))
            }
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

// "Obviously loopback" — one copy for every check in this crate, owned by the
// module whose refusal message cites the rule. It moved there (from a private
// copy here) when the OTel baton gave the crate a second and third caller.
use crate::metrics_server::is_loopback_hostport;

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
        // 🔴 Checked at LOAD, not only at bind: `check` validates a deployment
        // without binding anything, and a `metrics_addr` this process would
        // refuse to bind must fail that check too — otherwise `check` says
        // "fine" and `run` refuses (the faucet's `PublicMetricsAddr` argument,
        // verbatim).
        if let Some(addr) = self.metrics_addr.as_deref() {
            if !is_loopback_hostport(addr) {
                return Err(ConfigRefusal::PublicMetricsAddr(addr.to_string()));
            }
        }
        Ok(())
    }

    /// The observer posture, refused in a fixed order so `check` and `run` fail
    /// identically: keyless, non-mining, no telemetry listener, loopback-only
    /// metrics (the OTel baton's ruling), loopback-only discovery.
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
        // 🔴 The §6.2 seam the OTel baton re-drew (coordinator ruling, cited in
        // full in `crate::metrics_server`): the categorical refusal of
        // `metrics_addr` was against PUBLIC listeners, so a loopback-only bind —
        // which `RunningNode` serves for real, node-local scrape only — now
        // passes, and a non-loopback value is refused by name. `telemetry_addr`
        // above is NOT relaxed: the ruling named metrics only.
        if let Some(m) = node.metrics_addr.as_deref() {
            if !is_loopback_hostport(m) {
                return Err(ConfigRefusal::PublicNodeMetricsAddr(m.to_string()));
            }
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
            template_serving: false,
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

    /// `telemetry_addr` is refused for ANY value — loopback included. The OTel
    /// baton's ruling relaxed metrics only; `/v1/telemetry` is fleet-internal
    /// state and stays refused outright, and the message says so.
    #[test]
    fn a_config_that_would_open_a_telemetry_listener_is_refused_for_any_value() {
        let cfg = ExplorerConfig::from_toml(
            "node_config = \"/tmp/node.toml\"\nlisten_addr = \"127.0.0.1:0\"\n",
        )
        .unwrap();
        for addr in ["127.0.0.1:9410", "0.0.0.0:9410"] {
            let mut node = node_cfg();
            node.telemetry_addr = Some(addr.into());
            let e = cfg.check_observer(&node).unwrap_err();
            assert!(matches!(e, ConfigRefusal::ExtraListener("telemetry_addr")), "{addr}: {e}");
            assert!(e.to_string().contains("ANY value"), "{e}");
        }
    }

    /// 🔴 The two halves the OTel baton's coordinator ruling names, at the node
    /// key: a loopback `metrics_addr` is now ACCEPTED (the old categorical
    /// refusal was against public listeners), and a non-loopback one is refused
    /// BY NAME, the address in the message.
    #[test]
    fn a_node_metrics_addr_is_loopback_only_accepted_and_refused_by_halves() {
        let cfg = ExplorerConfig::from_toml(
            "node_config = \"/tmp/node.toml\"\nlisten_addr = \"127.0.0.1:0\"\n",
        )
        .unwrap();
        // Loopback (and unset) pass — the half the ruling opened.
        for ok in ["127.0.0.1:9420", "[::1]:9420", "localhost:9420"] {
            let mut node = node_cfg();
            node.metrics_addr = Some(ok.to_string());
            cfg.check_observer(&node).unwrap_or_else(|e| panic!("{ok} must pass: {e}"));
        }
        cfg.check_observer(&node_cfg()).expect("None passes");
        // Non-loopback stays refused by name — the half that did not move.
        for bad in ["0.0.0.0:9420", "10.0.0.5:9420", "node0:9420", "garbage"] {
            let mut node = node_cfg();
            node.metrics_addr = Some(bad.to_string());
            let e = cfg.check_observer(&node).unwrap_err();
            assert!(matches!(e, ConfigRefusal::PublicNodeMetricsAddr(_)), "{bad}: {e}");
            assert!(e.to_string().contains(bad), "{bad} named in the refusal: {e}");
            assert!(e.to_string().contains("PUBLIC"), "{e}");
        }
    }

    /// The explorer's OWN `metrics_addr` (the §C.1 histogram endpoint): off by
    /// default, loopback accepted, non-loopback refused at LOAD so `check` and
    /// `run` agree — the same two halves, this binary's key.
    #[test]
    fn the_explorers_own_metrics_addr_is_loopback_only_and_off_by_default() {
        let base = "node_config = \"/tmp/node.toml\"\nlisten_addr = \"127.0.0.1:0\"\n";
        let cfg = ExplorerConfig::from_toml(base).unwrap();
        assert!(cfg.metrics_addr.is_none(), "metrics stays off unless asked for");

        for ok in ["127.0.0.1:9481", "[::1]:9481", "localhost:9481"] {
            let cfg =
                ExplorerConfig::from_toml(&format!("{base}metrics_addr = \"{ok}\"\n"));
            assert!(cfg.is_ok(), "{ok} must be accepted");
        }
        for bad in ["0.0.0.0:9481", "[::]:9481", "203.0.113.10:9481", "explorer.example:9481"] {
            let e = ExplorerConfig::from_toml(&format!("{base}metrics_addr = \"{bad}\"\n"))
                .expect_err("must refuse");
            assert!(matches!(e, ConfigRefusal::PublicMetricsAddr(_)), "{bad}: {e}");
            assert!(e.to_string().contains(bad), "the refusal must name the address: {e}");
            assert!(e.to_string().contains("§6.2"), "{e}");
        }
    }
}
