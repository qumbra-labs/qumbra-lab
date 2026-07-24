//! Genesis tooling (issue #62 item 2 + 4): a versioned genesis file that bakes
//! the **FROZEN v1.0 constant table** (consensus-parameters, GENESIS FREEZE v1.0
//! 2026-07-23), **committee₀** (the frozen N=21 ML-DSA-65 verifying keys), and
//! the **genesis block**. Every node loads and byte-verifies the same file; the
//! genesis hash (keccak256 over the file's canonical bincode) is printed on
//! `genesis init` and asserted on startup — a wrong hash refuses to start.
//!
//! ## Frozen vs not-frozen
//! The FROZEN v1.0 table ([`FrozenParams`]) is the binding consensus constant
//! set. The genesis **file format itself** is `[devnet-placeholder]` shape —
//! protocol-spec §9 marks the byte format `[full-M8]`, so this layout is NOT
//! frozen and will be re-cut at full-M8 (annotated on the struct). The T0
//! rehearsal fields ([`GenesisFile::network`], [`GenesisFile::genesis_difficulty`])
//! are `[devnet-placeholder]`, not consensus.
//!
//! ## Committee keys — the T0 rehearsal arrangement (item 4)
//! Genesis committee₀ is the frozen N=21 / quorum 15. For the T0 rehearsal the
//! 21 ML-DSA signing keys are derived from deterministic seeds (byte-identical to
//! `qlab_devnet::committee::devnet_committee(21)`) and distributed across the
//! operator's nodes as key files — the honestly-labelled "federation-of-one"
//! that mirrors M11. Real validators generate their own keys off-band; only the
//! verifying keys are baked here.

use ml_dsa::{EncodedVerifyingKey, MlDsa65, VerifyingKey};
use serde::{Deserialize, Serialize};

use qlab_consensus::{CONSENSUS_CFG, LOG_HEIGHT};
use qlab_devnet::committee::{quorum_threshold, Committee, MemberKey, Validator};
use qlab_devnet::fees::{posted_fee, ArityBucket};
use qlab_devnet::header::Hash32;
use qlab_devnet::params_devnet as pd;
use qlab_node::emission as em;
use qlab_node::{genesis_block, StoredBlock};

/// Genesis-file format version. **NOT frozen** — protocol-spec §9 marks the
/// genesis byte format `[full-M8]`; this is the T0 `[devnet-placeholder]` shape.
/// Bumped on any incompatible change to [`GenesisFile`] / [`FrozenParams`].
pub const GENESIS_FORMAT_VERSION: u32 = 1;

/// The FROZEN v1.0 consensus wire size in bytes (qlab-consensus
/// `consensus_wire_is_145609_bytes`; consensus-parameters §1). Baked so the
/// genesis file records the measured wire the net commits to.
pub const CONSENSUS_WIRE_BYTES: u64 = 145_609;

/// T0 genesis PoW difficulty — `[devnet-placeholder]`, NOT frozen. Chosen low so
/// a real-RandomX rehearsal net mines on laptop hardware; the real launch
/// difficulty is an open tokenomics/consensus question (params_devnet
/// `GENESIS_DIFFICULTY`). Baked into the genesis block so every node agrees.
pub const T0_GENESIS_DIFFICULTY: u64 = 256;

/// The frozen self-bond ramp (consensus-parameters §4), in **QMB**: at each
/// epoch boundary the minimum self-bond steps up. `(epoch, bond_qmb)`.
pub const BOND_RAMP_QMB: [(u64, u64); 4] = [(0, 0), (90, 100), (180, 1_000), (360, 10_000)];

/// The FROZEN v1.0 constant table (consensus-parameters, 2026-07-23). Every
/// field is a versioned consensus parameter — changeable henceforth ONLY via a
/// halt-height upgrade carrying its own revision doc, never silently.
///
/// Values are sourced from the single-source code constants
/// ([`crate::params_audit`] asserts this struct equals them); the fields the
/// genesis file *introduces* (bond ramp, slash %, retained roots, the not-frozen
/// annotations) are pinned as literals with their §-reference.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FrozenParams {
    // ── §1 proof / consensus ────────────────────────────────────────────────
    /// Consensus FRI point label — FROZEN "b16/q21/g22/fp16/a16".
    pub consensus_fri: String,
    /// log2 of the 2×2 bucket trace height (18).
    pub log_height: u32,
    /// Measured consensus wire size (145,609 B).
    pub consensus_wire_bytes: u64,
    /// Aggregation leaf lane label — FROZEN "b4/q43/g22".
    pub agg_leaf_lane: String,
    /// Aggregation interior lane label — FROZEN "b2/q86/g22".
    pub agg_interior_lane: String,
    /// The consensus hash everywhere in the commitment layer.
    pub consensus_hash: String,
    /// Commitment-tree depth (32).
    pub tree_depth: u32,

    // ── §2 emission ─────────────────────────────────────────────────────────
    /// Target block time in seconds (75) — FROZEN.
    pub block_time_secs: u64,
    /// Atomic units per coin (1 QMB = 10⁸ bessel).
    pub bessel_per_qmb: u64,
    /// Initial reward r0 in QMB (50).
    pub r0_qmb: f64,
    /// Per-block geometric decay d (8.237e-7).
    pub decay_d: f64,
    /// Perpetual tail floor in QMB/block (1.22441).
    pub tail_qmb: f64,
    /// Coinbase maturity delay in blocks (144).
    pub coinbase_maturity_blocks: u64,
    /// Whether there is a hard supply cap (false — "no hard cap").
    pub hard_cap: bool,

    // ── §3 reward split ─────────────────────────────────────────────────────
    /// Miner share % (65).
    pub split_miner_pct: u64,
    /// Finality-committee share % (15).
    pub split_committee_pct: u64,
    /// Treasury share % (20).
    pub split_treasury_pct: u64,

    // ── §4 committee / staking ──────────────────────────────────────────────
    /// Genesis committee size N (21).
    pub committee_size: u32,
    /// ⅔-quorum threshold (15).
    pub quorum: u32,
    /// Epoch length in blocks (1,152 = 24 h at 75 s).
    pub epoch_length_blocks: u64,
    /// Steady-state self-bond minimum in QMB (10⁴).
    pub self_bond_qmb_steady: u64,
    /// The frozen genesis self-bond ramp: `(epoch, bond_qmb)`.
    pub bond_ramp_qmb: Vec<(u64, u64)>,
    /// Equivocation slash, in percent of the member's bond (10) + tombstone.
    pub equivocation_slash_pct: u64,
    /// Downtime-jail participation threshold in percent (33).
    pub downtime_jail_threshold_pct: u64,
    /// Downtime-jail window in checkpoint rounds (100).
    pub downtime_jail_window: u64,

    // ── §5 fees (bessel) ────────────────────────────────────────────────────
    /// 2×2 bucket posted fee (10⁶ bessel = 0.01 QMB).
    pub fee_2x2_bessel: u64,
    /// 4×4 bucket posted fee (2×10⁶ bessel = 0.02 QMB).
    pub fee_4x4_bessel: u64,
    /// 8×8 bucket posted fee (4×10⁶ bessel = 0.04 QMB).
    pub fee_8x8_bessel: u64,

    // ── §6 block-weight anti-spam ───────────────────────────────────────────
    /// Penalty-free-zone floor in bytes (10 MB).
    pub weight_free_zone_bytes: u64,
    /// Hard block-weight cap as a multiple of the effective median (2×).
    pub weight_hard_cap_multiple: u64,
    /// Long-term median window in blocks (100,000) — the CONSENSUS value the node
    /// enforces (the params_devnet 5,000 is a sim knob; see [`crate::params_audit`]).
    pub weight_long_window: u64,
    /// Long-term weight-cap factor numerator (7) / denominator (5) = 1.4×.
    pub weight_lt_cap_num: u64,
    pub weight_lt_cap_den: u64,
    /// Short-term median ceiling multiple (50).
    pub weight_st_cap: u64,

    // ── §7 anchors ──────────────────────────────────────────────────────────
    /// Anchor validity window in blocks (1,152 = 24 h).
    pub anchor_max_age_blocks: u64,
    /// Anchor quantization bucket in blocks (8 = one 10-min bucket).
    pub anchor_bucket_blocks: u64,
    /// Retained historical roots (~144).
    pub anchor_retained_roots: u64,

    // ── §8 denomination ─────────────────────────────────────────────────────
    /// Ticker (QMB).
    pub ticker: String,

    // ── NOT FROZEN — recorded for the rehearsal, freeze at full-M8 v1.1 ───────
    /// Checkpoint cadence in blocks (8). **Testnet-tunable, NOT frozen**
    /// (protocol-spec §7 flags cadence `[full-M8]`); recorded so the rehearsal
    /// net agrees on it, not because it is frozen.
    pub checkpoint_cadence_blocks_not_frozen: u64,
}

impl FrozenParams {
    /// The FROZEN v1.0 table, sourced from the single-source code constants where
    /// they exist and pinned as `[FROZEN §n]` literals where the genesis file is
    /// the source. [`crate::params_audit`] asserts every code-sourced field.
    pub fn v1_0() -> Self {
        Self {
            // §1
            consensus_fri: CONSENSUS_CFG.label(),
            log_height: LOG_HEIGHT as u32,
            consensus_wire_bytes: CONSENSUS_WIRE_BYTES,
            agg_leaf_lane: "b4/q43/g22".to_string(),
            agg_interior_lane: "b2/q86/g22".to_string(),
            consensus_hash: "keccak-256".to_string(),
            tree_depth: 32,
            // §2
            block_time_secs: pd::POW_TARGET_BLOCK_TIME_SECS,
            bessel_per_qmb: em::BESSEL_PER_QMB,
            r0_qmb: em::R0_QMB,
            decay_d: em::DECAY_D,
            tail_qmb: em::TAIL_QMB,
            coinbase_maturity_blocks: em::COINBASE_MATURITY_BLOCKS,
            hard_cap: false,
            // §3
            split_miner_pct: em::SPLIT_MINER_PCT,
            split_committee_pct: em::SPLIT_COMMITTEE_PCT,
            split_treasury_pct: em::SPLIT_TREASURY_PCT,
            // §4
            committee_size: pd::FROZEN_COMMITTEE_SIZE as u32,
            quorum: pd::FROZEN_QUORUM as u32,
            epoch_length_blocks: pd::EPOCH_LENGTH_BLOCKS,
            self_bond_qmb_steady: 10_000,
            bond_ramp_qmb: BOND_RAMP_QMB.to_vec(),
            equivocation_slash_pct: 10,
            downtime_jail_threshold_pct: pd::DOWNTIME_JAIL_THRESHOLD_PCT,
            downtime_jail_window: pd::DOWNTIME_JAIL_WINDOW as u64,
            // §5
            fee_2x2_bessel: posted_fee(ArityBucket::TwoByTwo),
            fee_4x4_bessel: posted_fee(ArityBucket::FourByFour),
            fee_8x8_bessel: posted_fee(ArityBucket::EightByEight),
            // §6
            weight_free_zone_bytes: pd::WEIGHT_MIN_BYTES,
            weight_hard_cap_multiple: pd::WEIGHT_MAX_MULTIPLE,
            weight_long_window: 100_000,
            weight_lt_cap_num: pd::WEIGHT_LT_CAP_NUM,
            weight_lt_cap_den: pd::WEIGHT_LT_CAP_DEN,
            weight_st_cap: pd::WEIGHT_ST_CAP,
            // §7
            anchor_max_age_blocks: pd::MAX_ANCHOR_AGE_BLOCKS,
            anchor_bucket_blocks: pd::CHECKPOINT_CADENCE_BLOCKS,
            anchor_retained_roots: 144,
            // §8
            ticker: "QMB".to_string(),
            // not frozen
            checkpoint_cadence_blocks_not_frozen: pd::CHECKPOINT_CADENCE_BLOCKS,
        }
    }

    /// The equivocation slash amount, in QMB, for a member holding `bond_qmb`:
    /// **10 % of bond** (item 5 convergence). Integer floor.
    pub fn equivocation_slash_qmb(&self, bond_qmb: u64) -> u64 {
        bond_qmb * self.equivocation_slash_pct / 100
    }
}

/// A committee signing-key file (T0 rehearsal — deterministic seed, honestly
/// labelled). Real validators store their own secret key off-band; the devnet
/// rehearsal keys are seed-derived so the operator can regenerate them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyFile {
    /// This key's committee index (0..N).
    pub index: usize,
    /// The 32-byte ML-DSA seed, hex-encoded.
    pub seed_hex: String,
    /// Human note that this is a devnet rehearsal key.
    #[serde(default)]
    pub note: String,
}

impl KeyFile {
    /// The seed bytes.
    pub fn seed(&self) -> Result<[u8; 32], GenesisError> {
        let bytes = hex_decode(&self.seed_hex).ok_or(GenesisError::BadHex)?;
        bytes.try_into().map_err(|_| GenesisError::BadSeedLen)
    }

    /// The [`Validator`] this key file loads.
    pub fn validator(&self) -> Result<Validator, GenesisError> {
        Ok(Validator::from_seed(self.index, self.seed()?))
    }

    /// Serialize to TOML.
    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).expect("KeyFile is always TOML-serializable")
    }

    /// Parse from TOML.
    pub fn from_toml(text: &str) -> Result<Self, GenesisError> {
        toml::from_str(text).map_err(|e| GenesisError::Parse(e.to_string()))
    }
}

/// The versioned genesis file. `[devnet-placeholder]` shape (protocol-spec §9
/// format is `[full-M8]`, NOT frozen); the [`frozen`](Self::frozen) table it
/// carries IS the binding FROZEN v1.0 consensus set.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GenesisFile {
    /// Genesis-file format version (NOT frozen).
    pub format_version: u32,
    /// Network label — `[devnet-placeholder]`, not consensus.
    pub network: String,
    /// The FROZEN v1.0 constant table.
    pub frozen: FrozenParams,
    /// committee₀: the ordered N=21 ML-DSA-65 verifying keys (encoded bytes).
    pub committee_keys: Vec<Vec<u8>>,
    /// The genesis PoW difficulty baked into the genesis block (`[devnet-placeholder]`).
    pub genesis_difficulty: u64,
    /// The genesis block (empty body — no premine, fair launch; protocol-spec §9).
    pub genesis_block: StoredBlock,
}

/// Genesis tooling errors.
#[derive(Debug)]
pub enum GenesisError {
    Io(std::io::Error),
    /// bincode decode of the genesis file failed.
    Decode(String),
    /// TOML parse (key file) failed.
    Parse(String),
    /// Genesis format version is not [`GENESIS_FORMAT_VERSION`].
    WrongFormatVersion { got: u32, want: u32 },
    /// The committee-key count does not match the frozen committee size.
    WrongCommitteeSize { got: usize, want: u32 },
    /// The baked quorum does not equal ⌊2N/3⌋+1.
    WrongQuorum { got: u32, want: usize },
    /// A committee verifying key failed to decode.
    BadCommitteeKey { index: usize },
    /// The genesis hash does not match the expected pin (node refuses to start).
    WrongGenesisHash { got: String, want: String },
    /// A key file's hex seed was malformed.
    BadHex,
    /// A key file's seed was not 32 bytes.
    BadSeedLen,
    /// A loaded signing key's verifying key does not match committee₀ at its index.
    KeyDoesNotMatchCommittee { index: usize },
}

impl std::fmt::Display for GenesisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GenesisError::Io(e) => write!(f, "genesis io: {e}"),
            GenesisError::Decode(e) => write!(f, "genesis decode: {e}"),
            GenesisError::Parse(e) => write!(f, "key-file parse: {e}"),
            GenesisError::WrongFormatVersion { got, want } => {
                write!(f, "genesis format version {got} != expected {want}")
            }
            GenesisError::WrongCommitteeSize { got, want } => {
                write!(f, "committee has {got} keys, frozen size is {want}")
            }
            GenesisError::WrongQuorum { got, want } => {
                write!(f, "baked quorum {got} != ⅔+1 = {want}")
            }
            GenesisError::BadCommitteeKey { index } => {
                write!(f, "committee key #{index} failed to decode")
            }
            GenesisError::WrongGenesisHash { got, want } => {
                write!(f, "genesis hash {got} != expected {want} — refusing to start")
            }
            GenesisError::BadHex => write!(f, "key file: malformed hex seed"),
            GenesisError::BadSeedLen => write!(f, "key file: seed is not 32 bytes"),
            GenesisError::KeyDoesNotMatchCommittee { index } => {
                write!(f, "signing key #{index} does not match committee₀")
            }
        }
    }
}
impl std::error::Error for GenesisError {}

/// The deterministic T0 rehearsal seed for committee index `i` — **byte-identical
/// to `qlab_devnet::committee::devnet_committee`'s scheme** (tag `0x9c` + index
/// little-endian), so the genesis committee and `devnet_committee(21)` produce the
/// same 21 verifying keys.
pub fn committee_seed(i: usize) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[0] = 0x9c;
    seed[1..9].copy_from_slice(&(i as u64).to_le_bytes());
    seed
}

impl GenesisFile {
    /// Build the T0 devnet genesis: the FROZEN v1.0 table, committee₀ = the
    /// frozen 21 seed-derived verifying keys, and the empty-body genesis block at
    /// `T0_GENESIS_DIFFICULTY`.
    pub fn new_devnet_t0() -> Self {
        let n = pd::FROZEN_COMMITTEE_SIZE;
        let committee_keys: Vec<Vec<u8>> = (0..n)
            .map(|i| Validator::from_seed(i, committee_seed(i)).verifying_key().encode().to_vec())
            .collect();
        GenesisFile {
            format_version: GENESIS_FORMAT_VERSION,
            network: "qumbra-devnet-t0".to_string(),
            frozen: FrozenParams::v1_0(),
            committee_keys,
            genesis_difficulty: T0_GENESIS_DIFFICULTY,
            genesis_block: genesis_block(T0_GENESIS_DIFFICULTY, 0),
        }
    }

    /// The genesis hash: keccak256 over the file's canonical bincode. This is the
    /// value printed on `genesis init` and asserted on startup.
    pub fn hash(&self) -> Hash32 {
        let bytes = bincode::serialize(self).expect("GenesisFile is always serializable");
        qlab_devnet::hash::keccak256(&bytes)
    }

    /// Hex-encoded [`hash`](Self::hash).
    pub fn hash_hex(&self) -> String {
        hex_encode(&self.hash())
    }

    /// Serialize the genesis file to its canonical on-disk bytes (bincode).
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("GenesisFile is always serializable")
    }

    /// Decode a genesis file from its on-disk bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GenesisError> {
        bincode::deserialize(bytes).map_err(|e| GenesisError::Decode(e.to_string()))
    }

    /// Write the genesis file to `path`.
    pub fn write(&self, path: impl AsRef<std::path::Path>) -> Result<(), GenesisError> {
        std::fs::write(path, self.to_bytes()).map_err(GenesisError::Io)
    }

    /// Load a genesis file from `path`.
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self, GenesisError> {
        let bytes = std::fs::read(path).map_err(GenesisError::Io)?;
        Self::from_bytes(&bytes)
    }

    /// committee₀ reconstructed from the baked verifying keys — the set a
    /// verify-only node validates checkpoints against.
    pub fn committee(&self) -> Result<Committee, GenesisError> {
        let mut keys: Vec<MemberKey> = Vec::with_capacity(self.committee_keys.len());
        for (i, enc) in self.committee_keys.iter().enumerate() {
            let e = EncodedVerifyingKey::<MlDsa65>::try_from(enc.as_slice())
                .map_err(|_| GenesisError::BadCommitteeKey { index: i })?;
            keys.push(VerifyingKey::<MlDsa65>::decode(&e));
        }
        Ok(Committee::from_keys(keys))
    }

    /// Structural + safety verification run on startup (item 2). Checks the
    /// format version, committee size/quorum, that every committee key decodes,
    /// and — if `expected_hex` is set — that the genesis hash matches (else the
    /// node refuses to start).
    pub fn verify_startup(&self, expected_hex: Option<&str>) -> Result<(), GenesisError> {
        if self.format_version != GENESIS_FORMAT_VERSION {
            return Err(GenesisError::WrongFormatVersion {
                got: self.format_version,
                want: GENESIS_FORMAT_VERSION,
            });
        }
        let want_n = self.frozen.committee_size;
        if self.committee_keys.len() != want_n as usize {
            return Err(GenesisError::WrongCommitteeSize {
                got: self.committee_keys.len(),
                want: want_n,
            });
        }
        let want_q = quorum_threshold(want_n as usize);
        if self.frozen.quorum as usize != want_q {
            return Err(GenesisError::WrongQuorum { got: self.frozen.quorum, want: want_q });
        }
        // Every committee key must decode (this also proves committee() succeeds).
        self.committee()?;
        if let Some(want) = expected_hex {
            let got = self.hash_hex();
            if !got.eq_ignore_ascii_case(want) {
                return Err(GenesisError::WrongGenesisHash { got, want: want.to_string() });
            }
        }
        Ok(())
    }

    /// Load the signing [`Validator`]s from the given key-file paths, and
    /// cross-check each against committee₀ (a key file for the wrong committee, or
    /// at the wrong index, is rejected — item 4 negative surface).
    pub fn load_validators(
        &self,
        paths: &[std::path::PathBuf],
    ) -> Result<Vec<Validator>, GenesisError> {
        let mut out = Vec::with_capacity(paths.len());
        for p in paths {
            let text = std::fs::read_to_string(p).map_err(GenesisError::Io)?;
            let kf = KeyFile::from_toml(&text)?;
            let v = kf.validator()?;
            // Cross-check: this signing key's verifying key must equal committee₀
            // at its claimed index.
            let expected = self
                .committee_keys
                .get(kf.index)
                .ok_or(GenesisError::KeyDoesNotMatchCommittee { index: kf.index })?;
            if v.verifying_key().encode().to_vec() != *expected {
                return Err(GenesisError::KeyDoesNotMatchCommittee { index: kf.index });
            }
            out.push(v);
        }
        Ok(out)
    }

    /// Write the 21 T0 committee signing-key files into `dir` (item 4). Returns
    /// their paths. Real validators would generate keys themselves; these are the
    /// honestly-labelled deterministic rehearsal keys.
    pub fn write_committee_key_files(
        &self,
        dir: impl AsRef<std::path::Path>,
    ) -> Result<Vec<std::path::PathBuf>, GenesisError> {
        let dir = dir.as_ref();
        std::fs::create_dir_all(dir).map_err(GenesisError::Io)?;
        let mut paths = Vec::new();
        for i in 0..self.committee_keys.len() {
            let kf = KeyFile {
                index: i,
                seed_hex: hex_encode(&committee_seed(i)),
                note: "devnet T0 rehearsal key (deterministic seed) — NOT a real validator key"
                    .to_string(),
            };
            let path = dir.join(format!("committee-{i:02}.key"));
            std::fs::write(&path, kf.to_toml()).map_err(GenesisError::Io)?;
            paths.push(path);
        }
        Ok(paths)
    }
}

// ── minimal hex (no `hex` crate in the tree) ───────────────────────────────

/// Lower-case hex encode.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

/// Hex decode; `None` on any non-hex char or odd length.
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hi = (b[i] as char).to_digit(16)?;
        let lo = (b[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_devnet::committee::devnet_committee;

    #[test]
    fn hex_round_trips() {
        let bytes = [0x00u8, 0x9c, 0xff, 0x10, 0xab];
        assert_eq!(hex_encode(&bytes), "009cff10ab");
        assert_eq!(hex_decode("009cff10ab").unwrap(), bytes);
        assert_eq!(hex_decode("zz"), None);
        assert_eq!(hex_decode("abc"), None); // odd length
    }

    #[test]
    fn committee_matches_devnet_committee_21() {
        // The genesis committee is byte-identical to devnet_committee(21) — the
        // seed scheme is shared, so the rest of the stack (soak, tests) and the
        // genesis file agree on the same 21 keys.
        let gf = GenesisFile::new_devnet_t0();
        let (dc, _v) = devnet_committee(21);
        assert_eq!(gf.committee_keys.len(), 21);
        for i in 0..21 {
            assert_eq!(
                gf.committee_keys[i],
                dc.member(i).unwrap().encode().to_vec(),
                "committee key {i} matches devnet_committee(21)"
            );
        }
    }

    #[test]
    fn genesis_hash_is_deterministic_and_stable() {
        // Two independent builds of the T0 genesis produce byte-identical files
        // and therefore the same hash — every node computes the same value.
        let a = GenesisFile::new_devnet_t0();
        let b = GenesisFile::new_devnet_t0();
        assert_eq!(a.to_bytes(), b.to_bytes());
        assert_eq!(a.hash(), b.hash());
        assert_eq!(a.hash_hex().len(), 64);
    }

    /// Strongest test-lock: the T0 genesis hash is pinned. It is a function of the
    /// entire baked FROZEN v1.0 table + committee₀ (21 ML-DSA keys, `ml-dsa`=0.1.1)
    /// + genesis block + the bincode layout — so any drift in a frozen constant,
    /// the key encoding, or the file shape is caught here (a deliberate change bumps
    /// this pin and `GENESIS_FORMAT_VERSION`). Every node computes this same value.
    #[test]
    fn genesis_hash_is_pinned() {
        assert_eq!(
            GenesisFile::new_devnet_t0().hash_hex(),
            "4a75b3b8a80122cbbc35867df17bd14f19054658b511dbc45bcfa67053cfc2c3",
        );
    }

    #[test]
    fn genesis_round_trips_through_bytes() {
        let gf = GenesisFile::new_devnet_t0();
        let back = GenesisFile::from_bytes(&gf.to_bytes()).expect("decode");
        assert_eq!(gf, back);
        assert_eq!(gf.hash(), back.hash());
    }

    #[test]
    fn verify_startup_accepts_a_good_genesis_and_matching_hash() {
        let gf = GenesisFile::new_devnet_t0();
        assert!(gf.verify_startup(None).is_ok());
        let h = gf.hash_hex();
        assert!(gf.verify_startup(Some(&h)).is_ok());
        // Case-insensitive hex accepted.
        assert!(gf.verify_startup(Some(&h.to_uppercase())).is_ok());
    }

    #[test]
    fn verify_startup_refuses_a_wrong_hash() {
        // item 2 negative: a wrong-genesis-hash node refuses to start.
        let gf = GenesisFile::new_devnet_t0();
        let wrong = "00".repeat(32);
        assert!(matches!(
            gf.verify_startup(Some(&wrong)),
            Err(GenesisError::WrongGenesisHash { .. })
        ));
    }

    #[test]
    fn verify_startup_rejects_tampered_committee_size() {
        let mut gf = GenesisFile::new_devnet_t0();
        gf.committee_keys.pop(); // 20 keys, frozen size 21
        assert!(matches!(
            gf.verify_startup(None),
            Err(GenesisError::WrongCommitteeSize { got: 20, want: 21 })
        ));
    }

    #[test]
    fn frozen_committee_is_21_quorum_15() {
        let f = FrozenParams::v1_0();
        assert_eq!(f.committee_size, 21);
        assert_eq!(f.quorum, 15);
        assert_eq!(f.epoch_length_blocks, 1_152);
    }

    #[test]
    fn key_file_round_trips_and_loads_a_validator() {
        let gf = GenesisFile::new_devnet_t0();
        let kf = KeyFile {
            index: 3,
            seed_hex: hex_encode(&committee_seed(3)),
            note: "test".to_string(),
        };
        let back = KeyFile::from_toml(&kf.to_toml()).unwrap();
        assert_eq!(kf, back);
        let v = kf.validator().unwrap();
        // The loaded validator's verifying key matches committee₀ at index 3.
        assert_eq!(v.verifying_key().encode().to_vec(), gf.committee_keys[3]);
    }

    #[test]
    fn load_validators_rejects_a_key_for_the_wrong_index() {
        // A key file claiming index 0 but carrying index 1's seed is rejected.
        let dir = std::env::temp_dir().join("qmb_t01_keyfile_neg");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let gf = GenesisFile::new_devnet_t0();
        let bad = KeyFile {
            index: 0,
            seed_hex: hex_encode(&committee_seed(1)), // wrong seed for index 0
            note: String::new(),
        };
        let p = dir.join("bad.key");
        std::fs::write(&p, bad.to_toml()).unwrap();
        assert!(matches!(
            gf.load_validators(&[p]),
            Err(GenesisError::KeyDoesNotMatchCommittee { index: 0 })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_and_load_committee_key_files_round_trips_all_21() {
        let dir = std::env::temp_dir().join("qmb_t01_keyfiles");
        let _ = std::fs::remove_dir_all(&dir);
        let gf = GenesisFile::new_devnet_t0();
        let paths = gf.write_committee_key_files(&dir).unwrap();
        assert_eq!(paths.len(), 21);
        let validators = gf.load_validators(&paths).unwrap();
        assert_eq!(validators.len(), 21);
        for (i, v) in validators.iter().enumerate() {
            assert_eq!(v.verifying_key().encode().to_vec(), gf.committee_keys[i]);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
