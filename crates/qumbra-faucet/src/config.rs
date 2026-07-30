//! The faucet service's TOML configuration — and the two things it **refuses to
//! start** over.
//!
//! ```toml
//! # Where the listener binds. OMITTED = 127.0.0.1:9450, and that default is the
//! # decision, not a convenience: a faucet holds a hot spending key, and one that
//! # becomes internet-reachable the moment somebody sets a config key is the shape
//! # testnet-plan.md §6.2 exists to prevent. Making it public is a deployment act,
//! # taken once, with a reason — and it is logged loudly when it happens.
//! # listen_addr = "127.0.0.1:9450"
//!
//! # The node this faucet runs IN-PROCESS with. An ordinary `qumbra-node` config —
//! # and it MUST name no committee key files (§6.2 decision 1, enforced below).
//! node_config = "./faucet-node.toml"
//!
//! # 32 bytes of raw HD entropy. Never printed, never logged, never in a Debug.
//! # `qumbra-faucet keygen` writes one with 0600 and prints only the public parts.
//! seed_file = "./faucet.seed"
//!
//! # 32 bytes: the ticket MAC secret. Same posture as the seed.
//! ticket_secret_file = "./faucet-tickets.secret"
//!
//! # OPTIONAL — grant value in bessel. Default 10 QMB (qlab_faucet's
//! # DEFAULT_GRANT_BESSEL, whose ground is "1,000 transactions of runway").
//! # grant_value = 1000000000
//!
//! # OPTIONAL — the HD account the spending key is derived at. Default 1.
//! # Account 0 is conventionally the primary wallet, and sharing an account with a
//! # treasury turns a service compromise into a treasury compromise. Zero is
//! # REFUSED here rather than warned about.
//! # hd_account = 1
//!
//! # OPTIONAL — require an operator-issued ticket. Default true, which is the
//! # recommended T1 posture while "how public is public" is undecided.
//! # tickets_required = true
//! ```
//!
//! `deny_unknown_fields`, for the same reason `NodeConfig` has it: a typo'd key that
//! parsed and was silently ignored would let an operator write `listen_addr` under a
//! misspelling, see the service start, and believe it was bound where it is not.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The listener's default bind address. **Loopback, deliberately** — see the module
/// docs and `qumbra_node::config::NodeConfig::metrics_addr`, whose shape this
/// follows.
pub const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:9450";

/// A parsed faucet-service configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaucetServiceConfig {
    /// Where the HTTP listener binds. Defaults to [`DEFAULT_LISTEN_ADDR`].
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    /// The in-process node's own config file.
    pub node_config: PathBuf,
    /// 32 bytes of HD master entropy.
    pub seed_file: PathBuf,
    /// 32 bytes of ticket MAC secret.
    pub ticket_secret_file: PathBuf,
    /// Grant value in bessel. `None` = `qlab_faucet::DEFAULT_GRANT_BESSEL`.
    #[serde(default)]
    pub grant_value: Option<u64>,
    /// HD account for the spending key. `None` = 1. Zero is refused.
    #[serde(default)]
    pub hd_account: Option<u32>,
    /// Require an operator-issued ticket. `None` = true.
    #[serde(default)]
    pub tickets_required: Option<bool>,
}

fn default_listen_addr() -> String {
    DEFAULT_LISTEN_ADDR.to_string()
}

/// Why a faucet-service config failed to load, or refused to be used.
#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(String),
    /// 🔴 §6.2 decision 1: the node this faucet composes holds committee signing
    /// keys. The whole point of running the faucet on a keyless node is that a hot
    /// spending key and the committee's signing keys are never on one host.
    CommitteeKeysPresent(usize),
    /// The HD account is 0, which is conventionally the primary wallet.
    AccountZero,
    /// A secret file is not the expected 32 bytes. Refused rather than padded — a
    /// short seed is a weak key, and a long one is a paste error.
    SecretLength { path: PathBuf, len: usize },
    /// `mining = true` with no `miner_rkm`, or with one that is not this faucet's:
    /// the node would mine to a key the faucet cannot spend, so the faucet could
    /// never be funded and would never say why.
    PayoutMismatch(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "faucet config io: {e}"),
            ConfigError::Parse(e) => write!(f, "faucet config parse: {e}"),
            ConfigError::CommitteeKeysPresent(n) => write!(
                f,
                "the node config names {n} committee signing key file(s). A faucet runs on a \
                 KEYLESS node (testnet-plan.md §6.2): a node that holds committee keys exposes \
                 nothing beyond P2P, so the faucet's hot spending key must not share a host with \
                 them. Point `node_config` at a node with `committee_key_paths = []`."
            ),
            ConfigError::AccountZero => write!(
                f,
                "hd_account = 0 is refused. Account 0 is conventionally the primary wallet, and \
                 the faucet's loss bound depends on its key reaching the faucet's notes and \
                 nothing else derived from the same seed."
            ),
            ConfigError::SecretLength { path, len } => write!(
                f,
                "{} is {len} bytes; 32 are required. Refused rather than padded or truncated — \
                 a short secret is a weak key and a long one is a paste error.",
                path.display()
            ),
            ConfigError::PayoutMismatch(msg) => write!(f, "{msg}"),
        }
    }
}
impl std::error::Error for ConfigError {}

impl FaucetServiceConfig {
    /// Parse from TOML text.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    /// Load and parse from disk.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(ConfigError::Io)?;
        Self::from_toml(&text)
    }

    /// Grant value in bessel, defaulted.
    pub fn grant_value(&self) -> u64 {
        self.grant_value.unwrap_or(qlab_faucet::DEFAULT_GRANT_BESSEL)
    }

    /// HD account, defaulted.
    pub fn hd_account(&self) -> u32 {
        self.hd_account.unwrap_or(1)
    }

    /// Whether tickets are required, defaulted to **true**.
    pub fn tickets_required(&self) -> bool {
        self.tickets_required.unwrap_or(true)
    }

    /// Whether the configured bind address is a loopback one. Used to decide whether
    /// startup prints the exposure warning.
    ///
    /// A host name that is not an IP literal answers `false`: this is a warning
    /// gate, and the safe direction for "I cannot tell" is to warn.
    pub fn binds_loopback(&self) -> bool {
        let host = match self.listen_addr.rsplit_once(':') {
            Some((h, _)) => h.trim_start_matches('[').trim_end_matches(']'),
            None => self.listen_addr.as_str(),
        };
        host.parse::<std::net::IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false)
    }

    /// 🔴 §6.2 decision 1: refuse a node that holds committee keys.
    pub fn check_keyless(&self, node: &qumbra_node::config::NodeConfig) -> Result<(), ConfigError> {
        if node.committee_key_paths.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::CommitteeKeysPresent(node.committee_key_paths.len()))
        }
    }

    /// Refuse a node whose mining payout is not this faucet's `rkm`.
    ///
    /// Three cases, and the two that are fatal are fatal because the failure is
    /// otherwise **silent for hours**: a faucet mining to a burn address or to
    /// somebody else's key looks healthy, mines valid blocks, and simply never
    /// becomes funded. `qumbra-node` already warns loudly about an unset `miner_rkm`
    /// (#101); for a faucet, the warning is not enough.
    pub fn check_payout(
        &self,
        node: &qumbra_node::config::NodeConfig,
        faucet_rkm: [u64; 4],
    ) -> Result<(), ConfigError> {
        if !node.mining {
            return Ok(());
        }
        match node.miner_rkm_lanes().map_err(|e| ConfigError::Parse(e.to_string()))? {
            Some(rkm) if rkm == faucet_rkm => Ok(()),
            Some(_) => Err(ConfigError::PayoutMismatch(
                "the node config's `miner_rkm` is not this faucet's receive key. The node would \
                 mine valid blocks whose coinbase notes this faucet cannot spend, and the faucet \
                 would never become funded — silently, for as long as it ran. Run \
                 `qumbra-faucet address --config <this file>` and set `miner_rkm` to the rkm it \
                 prints."
                    .to_string(),
            )),
            None => Err(ConfigError::PayoutMismatch(
                "the node config has `mining = true` and no `miner_rkm`, so every coin it mines \
                 is BURNED (qumbra-node's own warning). A faucet whose only funding source burns \
                 its own income is not a faucet: this is fatal here rather than a warning. Run \
                 `qumbra-faucet address --config <this file>` and set `miner_rkm`."
                    .to_string(),
            )),
        }
    }

    /// Read a 32-byte secret file. **The bytes are returned, never logged, and no
    /// error message quotes them** — a length error names the length only.
    pub fn read_secret(path: &Path) -> Result<[u8; 32], ConfigError> {
        let bytes = std::fs::read(path).map_err(ConfigError::Io)?;
        if bytes.len() != 32 {
            return Err(ConfigError::SecretLength {
                path: path.to_path_buf(),
                len: bytes.len(),
            });
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    /// Validate everything that does not need the node config or the key files.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.hd_account() == 0 {
            return Err(ConfigError::AccountZero);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
        node_config = "./faucet-node.toml"
        seed_file = "./faucet.seed"
        ticket_secret_file = "./faucet-tickets.secret"
    "#;

    fn node_cfg(extra: &str) -> qumbra_node::config::NodeConfig {
        qumbra_node::config::NodeConfig::from_toml(&format!(
            "data_dir = \"d\"\nlisten_addr = \"127.0.0.1:0\"\ngenesis_file = \"g\"\n{extra}"
        ))
        .expect("node config parses")
    }

    /// 🔴 The nailed-down default: omit `listen_addr` and the listener is on
    /// loopback. This is the test that would fail if someone "helpfully" defaulted
    /// it to 0.0.0.0.
    #[test]
    fn the_listener_defaults_to_loopback() {
        let c = FaucetServiceConfig::from_toml(MINIMAL).expect("parse");
        assert_eq!(c.listen_addr, "127.0.0.1:9450");
        assert_eq!(c.listen_addr, DEFAULT_LISTEN_ADDR);
        assert!(c.binds_loopback(), "the default must be loopback");
        // …and the defaults the rest of the service runs on.
        assert_eq!(c.grant_value(), qlab_faucet::DEFAULT_GRANT_BESSEL);
        assert_eq!(c.hd_account(), 1);
        assert!(c.tickets_required(), "tickets are required unless turned off");
    }

    /// The exposure gate: every non-loopback form is recognised as such, including
    /// the two that are easy to mistake for local.
    #[test]
    fn non_loopback_binds_are_recognised_as_exposure() {
        let with = |addr: &str| {
            FaucetServiceConfig::from_toml(&format!("{MINIMAL}\nlisten_addr = \"{addr}\"\n"))
                .expect("parse")
        };
        assert!(with("127.0.0.1:9450").binds_loopback());
        assert!(with("[::1]:9450").binds_loopback());
        assert!(!with("0.0.0.0:9450").binds_loopback());
        assert!(!with("[::]:9450").binds_loopback());
        assert!(!with("203.0.113.10:9450").binds_loopback());
        // A hostname is not resolvable here, and the safe direction for "cannot
        // tell" is to warn.
        assert!(!with("faucet.example:9450").binds_loopback());
    }

    /// 🔴 §6.2 decision 1, as a startup refusal.
    #[test]
    fn a_node_holding_committee_keys_is_refused() {
        let c = FaucetServiceConfig::from_toml(MINIMAL).expect("parse");
        assert!(c.check_keyless(&node_cfg("")).is_ok(), "a keyless node is the supported shape");
        let err = c
            .check_keyless(&node_cfg("committee_key_paths = [\"./keys/committee-00.key\"]"))
            .unwrap_err();
        assert!(matches!(err, ConfigError::CommitteeKeysPresent(1)));
        // The message has to say what to do, not just what is wrong.
        let text = err.to_string();
        assert!(text.contains("KEYLESS"), "{text}");
        assert!(text.contains("committee_key_paths = []"), "{text}");
    }

    /// A mining node that pays somebody else — or nobody — never funds the faucet,
    /// and does so silently. Both are fatal.
    #[test]
    fn a_payout_that_is_not_the_faucets_is_fatal() {
        let c = FaucetServiceConfig::from_toml(MINIMAL).expect("parse");
        let mine = [1u64, 2, 3, 4];
        let hex_of = |l: [u64; 4]| {
            let mut s = String::new();
            for lane in l {
                for b in lane.to_le_bytes() {
                    s.push_str(&format!("{b:02x}"));
                }
            }
            s
        };

        // Not mining: the operator funds the faucet from other miners' payouts, so
        // there is nothing to check here.
        assert!(c.check_payout(&node_cfg("mining = false"), mine).is_ok());
        // Mining to us: fine.
        let ours = format!("mining = true\nminer_rkm = \"{}\"\n", hex_of(mine));
        assert!(c.check_payout(&node_cfg(&ours), mine).is_ok());
        // Mining to someone else.
        let theirs = format!("mining = true\nminer_rkm = \"{}\"\n", hex_of([9, 9, 9, 9]));
        let err = c.check_payout(&node_cfg(&theirs), mine).unwrap_err();
        assert!(err.to_string().contains("cannot spend"), "{err}");
        // Mining to nobody — #101's burn address.
        let err = c.check_payout(&node_cfg("mining = true"), mine).unwrap_err();
        assert!(err.to_string().contains("BURNED"), "{err}");
    }

    /// Account 0 is the primary wallet by convention; the loss bound depends on the
    /// faucet not sharing it.
    #[test]
    fn hd_account_zero_is_refused() {
        let c = FaucetServiceConfig::from_toml(&format!("{MINIMAL}\nhd_account = 0\n"))
            .expect("parse");
        assert!(matches!(c.validate(), Err(ConfigError::AccountZero)));
        let c = FaucetServiceConfig::from_toml(&format!("{MINIMAL}\nhd_account = 3\n"))
            .expect("parse");
        assert!(c.validate().is_ok());
    }

    /// An unknown key is a hard error, so a misspelled `listen_addr` cannot leave a
    /// service bound somewhere its operator does not think it is.
    #[test]
    fn an_unknown_key_is_rejected_not_ignored() {
        let bad = format!("{MINIMAL}\nlisten_address = \"0.0.0.0:9450\"\n");
        assert!(matches!(FaucetServiceConfig::from_toml(&bad), Err(ConfigError::Parse(_))));
    }

    #[test]
    fn missing_required_fields_are_errors() {
        assert!(matches!(
            FaucetServiceConfig::from_toml("seed_file = \"s\"\nticket_secret_file = \"t\"\n"),
            Err(ConfigError::Parse(_))
        ));
    }

    /// A wrong-length secret is refused, and the error names the length and nothing
    /// else — never the bytes.
    #[test]
    fn a_short_secret_file_is_refused_without_quoting_it() {
        let dir = std::env::temp_dir().join(format!("qmb-i123-secret-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("short.secret");
        std::fs::write(&path, b"not-32-bytes").expect("write");
        let err = FaucetServiceConfig::read_secret(&path).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("12 bytes"), "{text}");
        assert!(!text.contains("not-32"), "the error must not quote the secret: {text}");

        std::fs::write(&path, [0xAB; 32]).expect("write");
        assert_eq!(FaucetServiceConfig::read_secret(&path).expect("32 bytes"), [0xAB; 32]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
