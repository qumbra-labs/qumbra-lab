//! The node's TOML configuration (issue #62 item 1).
//!
//! A `qumbra-node` process is configured by a single TOML file:
//!
//! ```toml
//! # where the block log + snapshot live (created if absent)
//! data_dir = "./data"
//! # the TCP address this node listens on
//! listen_addr = "127.0.0.1:9333"
//! # SEED peers: dialed at startup and never evicted from the address book.
//! # Discovery (issue #83) fills the rest of the book from Addr gossip.
//! dial_peers = ["127.0.0.1:9334", "127.0.0.1:9335"]
//! # OPTIONAL — this node's own publicly dialable address. Set it ONLY if
//! # inbound connections really reach here; it is the only way peers are told
//! # about us. Behind a router without a forwarded port, leave it unset: you
//! # will sync, mine and transact but will not serve peers, and that is expected.
//! # advertise_addr = "203.0.113.10:9333"
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
//!
//! # NOTE — note-discovery serving is ON by default at 127.0.0.1:9420. Omitting
//! # the key does NOT turn it off; `discovery_addr = "off"` does. Recipients
//! # cannot find their outputs on a node that serves nothing, so this is the one
//! # listener here whose default is on. See `discovery_addr` below.
//! # discovery_addr = "0.0.0.0:9420"
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
    /// **Seed** peer addresses (issue #83 scope 4). Dialed at startup and kept as
    /// the never-evicted recovery path when everything learned has gone stale:
    /// once discovery is on, the address book also fills from `Addr` gossip, and
    /// these are simply the entries that can never be dropped. The field name is
    /// unchanged so every deployed config and `deploy/deploy.sh` keep working.
    #[serde(default)]
    pub dial_peers: Vec<String>,
    /// This node's own **publicly dialable** address, if it has one (issue #83
    /// scope 3). Set it only when inbound connections actually reach this node —
    /// it is the sole basis on which peers are told about us, because a node
    /// cannot discover its own public address without being told, and being told
    /// is a wire change (S1).
    ///
    /// Leaving it unset is the **normal, expected** case for a participant behind
    /// a router: that node syncs, mines and transacts, but is never gossiped and
    /// serves no peers. T1 accepts this (Larry's NAT decision, 2026-07-26).
    #[serde(default)]
    pub advertise_addr: Option<String>,
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
    /// OPTIONAL — bind address for the `/metrics` scrape endpoint (issue #87).
    ///
    /// **Unset = no listener at all**, which is the default and the right one for
    /// any node that is not being scraped: an endpoint that exists only where
    /// somebody asked for it is an endpoint that cannot be forgotten open.
    /// `127.0.0.1:9090` keeps it host-local; `0.0.0.0:9090` exposes it to whatever
    /// the host firewall admits, and on the T0 hosts that means pairing it with a
    /// **source-restricted** inbound security-group rule (standalone
    /// `aws_security_group_rule` resources only — the inline-rule incident of
    /// 2026-07-26 is why).
    ///
    /// Deployment ordering caveat: `deny_unknown_fields` is deliberate here, so a
    /// config carrying this key will be REFUSED by a binary built before this
    /// change. Ship the binary first, then the config — never the other way round.
    #[serde(default)]
    pub metrics_addr: Option<String>,
    /// OPTIONAL — bind address for the `/v1/telemetry` read endpoint (issue #117).
    ///
    /// **Unset = no listener at all**, the default and the right one for any node
    /// nobody is polling. Set it and the node serves exactly one route,
    /// `GET /v1/telemetry`, returning [`qlab_node::Telemetry`]'s versioned bytes —
    /// the wire the T0 operator agreement view reads. See
    /// [`crate::telemetry_server`] for why it is a separate, single-route surface
    /// rather than the wallet-facing RPC (and therefore not called `rpc_addr`).
    ///
    /// Same exposure rule as `metrics_addr`: `127.0.0.1:9410` keeps it host-local,
    /// `0.0.0.0:9410` exposes it to whatever the host firewall admits, and on the
    /// T0 hosts that means pairing it with a **source-restricted** inbound
    /// security-group rule (standalone `aws_security_group_rule` resources only —
    /// the inline-rule incident of 2026-07-26 is why). Nothing here authenticates;
    /// the wire carries no key material, no transaction contents and no peer
    /// addresses, but it is node-operational data.
    ///
    /// Deployment ordering caveat, same as `metrics_addr`: `deny_unknown_fields` is
    /// deliberate, so a config carrying this key is REFUSED by a binary built
    /// before this change. Ship the binary first, then the config.
    #[serde(default)]
    pub telemetry_addr: Option<String>,
    /// Bind address for the `/v1/compact` note-discovery endpoint (issue #188
    /// baton 2) — **on by default**, unlike every other listener here.
    ///
    /// Absent from the config ⇒ [`crate::discovery_server::DEFAULT_DISCOVERY_ADDR`]
    /// (`127.0.0.1:9420`). `discovery_addr = "off"` is the only way to have no
    /// listener at all. This is the one decision in this file that inverts
    /// `metrics_addr`'s default, and the reasoning is worth having here rather
    /// than only in the PR:
    ///
    /// - **`metrics_addr` is off-by-default because setting it opens a port.** A
    ///   loopback default opens nothing an off-host attacker can reach, so the
    ///   argument that makes `/metrics` opt-in does not transfer to this one.
    /// - **`testnet-plan` §6.2 — a committee-key host "exposes nothing beyond
    ///   P2P" — is honoured literally** by a loopback bind, and the bytes are
    ///   public chain data regardless: every one of them is inside a block body
    ///   any peer can already ask for. No key material, no mempool, no peer list,
    ///   no write surface.
    /// - **A chain whose recipients cannot find their money by default is not a
    ///   chain.** An opt-in most operators leave off reproduces
    ///   `t1-discovery-serving-decision.md`'s option 2a with extra steps: the
    ///   chain commits discovery correctly and hands it to nobody, which from a
    ///   wallet's side is indistinguishable from having no discovery at all.
    ///
    /// So **serving is the default and exposure is the operator's act**:
    /// `0.0.0.0:9420` exposes it to whatever the host firewall admits, and on a
    /// real host that means pairing it with a source-restricted inbound rule
    /// (standalone `aws_security_group_rule` resources only — the inline-rule
    /// incident of 2026-07-26 is why). Nothing here authenticates.
    ///
    /// Deployment ordering caveat, same as `metrics_addr`: `deny_unknown_fields`
    /// is deliberate, so a config carrying this key is REFUSED by a binary built
    /// before this change. Ship the binary first, then the config. Note the
    /// asymmetry this default creates — a **new** binary reading an **old**
    /// config starts serving on loopback without the config mentioning it, which
    /// is the intent.
    #[serde(default = "default_discovery_addr")]
    pub discovery_addr: Option<String>,
    /// OPTIONAL — where this node's mined coinbase notes are paid (issue #101):
    /// the miner's raw `rkm`, hex-encoded as **64 hex characters** = 32 bytes,
    /// lane-major little-endian (`qlab_wallet::Wallet::rkm(d)` under the node's
    /// own `Hash32` convention).
    ///
    /// **Unset means mined coins are burned.** With no payout key the node mines
    /// to `qlab_p2p::adapter::UNCONFIGURED_MINER_RKM`, a fixed constant nobody
    /// holds a spend key for; the blocks are valid and the issuance is
    /// unrecoverable. That is the honest behaviour for a node that was never told
    /// where to pay itself — a zero key would be rejected outright and a
    /// self-invented one would be a lie — and [`crate::run`] says so loudly at
    /// startup whenever `mining = true` and this is unset.
    ///
    /// Deployment ordering caveat, same as `metrics_addr`: `deny_unknown_fields`
    /// is deliberate, so a config carrying this key is REFUSED by a binary built
    /// before this change. Ship the binary first, then the config.
    #[serde(default)]
    pub miner_rkm: Option<String>,
    /// Serve `GET /v1/mine/template` and `POST /v1/mine/block` on the discovery
    /// listener (lab #511). **Off by default** — this is a serving surface a
    /// pool points at its own node, not something every node should expose.
    ///
    /// The issue wrote this as `mining.template_serving`. TOML cannot nest a
    /// table under the existing `mining = true` bool without breaking every
    /// deployed config, so the flag is a sibling. Same meaning: the mining
    /// template RPC, gated, default off.
    #[serde(default)]
    pub template_serving: bool,
}

/// The serde default behind [`NodeConfig::discovery_addr`]: **on, loopback**.
///
/// A function rather than `Option::default` because the whole point is that the
/// absence of the key is not the absence of the listener. Read that field's note
/// before changing it — it is a decision, not a convenience.
fn default_discovery_addr() -> Option<String> {
    Some(crate::discovery_server::DEFAULT_DISCOVERY_ADDR.to_string())
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

    /// The address discovery serving should bind, or `None` for *serve nothing*.
    ///
    /// The one place `"off"` is interpreted, so no caller has to remember that a
    /// `Some("off")` is not an address. `None` in the field means the same thing —
    /// a struct built in code says what it wants, while a config file that omits
    /// the key gets the on-by-default value from
    /// [`default_discovery_addr`].
    pub fn discovery_bind(&self) -> Option<&str> {
        match self.discovery_addr.as_deref() {
            None => None,
            Some(a) if a.trim().eq_ignore_ascii_case(crate::discovery_server::DISCOVERY_OFF) => {
                None
            }
            Some(a) => Some(a),
        }
    }

    /// The configured payout key as circuit lanes, or an error describing why the
    /// string is not one. `Ok(None)` = not configured (see [`Self::miner_rkm`]).
    ///
    /// Thin over [`rkm_lanes_from_hex`] since lab #143's instrument gap: the same
    /// string has to be parsed by `audit-emission --payee`, and a second copy of
    /// this arithmetic is the wrong-in-the-detail this repo keeps paying for.
    pub fn miner_rkm_lanes(&self) -> Result<Option<[u64; 4]>, ConfigError> {
        let Some(hex) = self.miner_rkm.as_deref() else { return Ok(None) };
        rkm_lanes_from_hex(hex).map(Some)
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

    /// 🔴 **The decision, as a test rather than as a paragraph** (issue #188 baton
    /// 2, scope item 3). A config that never mentions discovery serves it, on
    /// loopback. Every other listener in this file is off in exactly this
    /// situation, and this one is not, because a chain whose recipients cannot find
    /// their money by default is not a chain.
    #[test]
    fn discovery_default_is_on_and_loopback_when_the_config_is_silent() {
        let c = NodeConfig::from_toml(SAMPLE).expect("parse");
        assert!(
            !SAMPLE.contains("discovery"),
            "the fixture must not mention discovery — that is the whole point"
        );
        assert_eq!(
            c.discovery_bind(),
            Some(crate::discovery_server::DEFAULT_DISCOVERY_ADDR),
            "silence means serve, on loopback"
        );
        assert!(
            c.discovery_bind().unwrap().starts_with("127.0.0.1:"),
            "the default must not be reachable off-host: exposure is the operator's act"
        );
        // The contrast that makes the asymmetry deliberate rather than accidental.
        assert!(c.metrics_addr.is_none(), "metrics stays off unless asked for");
        assert!(c.telemetry_addr.is_none(), "telemetry stays off unless asked for");
    }

    /// The only way to have no listener, and it has to be written down. A missing
    /// key cannot mean this, or the default above would be unreachable.
    #[test]
    fn discovery_off_is_the_explicit_opt_out_and_case_insensitive() {
        for value in ["off", "OFF", " Off "] {
            let toml = format!("{SAMPLE}\ndiscovery_addr = \"{value}\"\n");
            let c = NodeConfig::from_toml(&toml).expect("parse");
            assert_eq!(c.discovery_bind(), None, "{value:?} means serve nothing");
        }
        let c = NodeConfig::from_toml(&format!("{SAMPLE}\ndiscovery_addr = \"0.0.0.0:9420\"\n"))
            .expect("parse");
        assert_eq!(c.discovery_bind(), Some("0.0.0.0:9420"), "an address is an address");
    }

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
        assert!(!c.template_serving, "template RPC is off unless asked for");
        assert_eq!(c.expected_genesis_hash, None);
        assert_eq!(c.miner_rkm, None);
        assert_eq!(c.miner_rkm_lanes().expect("unset is fine"), None);
    }

    #[test]
    fn template_serving_is_off_by_default_and_parses_when_set() {
        let silent = NodeConfig::from_toml(SAMPLE).expect("parse");
        assert!(
            !SAMPLE.contains("template_serving"),
            "the fixture must not mention the flag — that is the default"
        );
        assert!(!silent.template_serving);
        let on = NodeConfig::from_toml(&format!("{SAMPLE}\ntemplate_serving = true\n"))
            .expect("parse");
        assert!(on.template_serving);
    }

    /// The payout key round-trips through the node's lane-major LE convention,
    /// and the two ways to get it wrong are refused rather than mined against.
    #[test]
    fn miner_rkm_parses_and_rejects_the_two_wrong_shapes() {
        let with = |v: &str| {
            NodeConfig::from_toml(&format!(
                "data_dir = \"d\"\nlisten_addr = \"127.0.0.1:0\"\ngenesis_file = \"g\"\nminer_rkm = \"{v}\"\n"
            ))
            .expect("parse")
        };
        // Lane-major little-endian: byte 0 is the low byte of lane 0.
        let hex = "0100000000000000020000000000000003000000000000000400000000000000";
        assert_eq!(with(hex).miner_rkm_lanes().expect("valid"), Some([1, 2, 3, 4]));

        // Too short — a truncated paste is the likely operator error.
        assert!(with("dead").miner_rkm_lanes().is_err());
        // All zero — the shape a forgotten/placeholder value takes, and the one
        // value every node rejects at block validation. Refuse it here, where the
        // operator can still see the message.
        assert!(with(&"0".repeat(64)).miner_rkm_lanes().is_err());
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

/// Parse a 64-hex-character rkm into circuit lanes (32 bytes, **lane-major LE**) —
/// byte-for-byte the form `qumbra-wallet miner-rkm` and `qumbra-faucet keygen`
/// print and `miner_rkm` in a node config carries.
///
/// Free rather than a method because two callers need it and neither should own
/// it: `NodeConfig::miner_rkm_lanes` (the running node's payout key) and
/// `audit-emission --payee` (the question "which blocks paid this key", which had
/// no read-only answer at all — `qumbra-deploy` #143).
///
/// All-zero is refused rather than accepted: `validate_body` rejects a block with
/// `coinbase > 0 && coinbase_rkm == [0; 4]` (`BodyError::MissingCoinbasePayee`), so
/// a caller asking about it is asking about a key no block can carry.
pub fn rkm_lanes_from_hex(hex: &str) -> Result<[u64; 4], ConfigError> {
    let hex = hex.trim();
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ConfigError::Parse(format!(
            "miner_rkm must be 64 hex characters (32 bytes, lane-major LE); got {} chars",
            hex.len()
        )));
    }
    let mut lanes = [0u64; 4];
    for (i, lane) in lanes.iter_mut().enumerate() {
        let mut bytes = [0u8; 8];
        for (j, b) in bytes.iter_mut().enumerate() {
            let at = (i * 8 + j) * 2;
            *b = u8::from_str_radix(&hex[at..at + 2], 16).expect("checked ascii hex");
        }
        *lane = u64::from_le_bytes(bytes);
    }
    if lanes == [0u64; 4] {
        return Err(ConfigError::Parse(
            "miner_rkm is all zero, which no wallet can derive and which every node \
             rejects (BodyError::MissingCoinbasePayee). Omit the key to mine to the \
             unconfigured burn address, or set a real one."
                .to_string(),
        ));
    }
    Ok(lanes)
}
