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
//! ## ✅ Paid at the 2026-07-31 mint — issue #115, closing issue #77 F1
//! The genesis header used to pin `tx_body_commitment = ZERO_HASH` while its
//! empty body committed to `keccak256(coinbase_le ‖ rkm_le)`, so **genesis was
//! the one block that did not satisfy the header/body binding** every other block
//! is held to, and `qlab_node::node::check_stored_binding` carried a height-0
//! exemption for it. That was safe only because a *stronger* check covered the
//! same ground: every node pins `expected_genesis_hash` and refuses to start
//! against a different genesis. Fixing it moved the genesis hash and therefore
//! the network identity, so it waited for a mint — and this is that mint. The
//! header now commits to the real body commitment, the exemption is **deleted**
//! rather than special-cased, and the config pin is a second independent gate
//! rather than the only one.
//!
//! ## Committee keys — the T0/T2 rehearsal arrangement (item 4), plus the T2 launch path
//! Genesis committee₀ is the frozen N=21 / quorum 15. For rehearsal the 21 ML-DSA
//! signing keys are derived from deterministic seeds (byte-identical to
//! `qlab_devnet::committee::devnet_committee(21)`) and distributed across the
//! operator's nodes as key files — the honestly-labelled "federation-of-one"
//! that mirrors M11. **Lab #506** adds `genesis init --t2 --launch`: same v5
//! shape, but the 21 seeds come from OS randomness through the existing
//! [`Validator::from_seed`] seam (so [`KeyFile`] still stores `seed_hex` and
//! [`GenesisFile::load_validators`] is unchanged). Without `--launch` the
//! rehearsal path is byte-identical to before. Real validators generate their
//! own keys off-band; only the verifying keys are baked here.

use ml_dsa::{EncodedVerifyingKey, MlDsa65, VerifyingKey};
use serde::{Deserialize, Serialize};

use qlab_consensus::{CONSENSUS_CFG, LOG_HEIGHT};
use qlab_devnet::committee::{quorum_threshold, Committee, MemberKey, Validator};
use qlab_devnet::fees::{posted_fee, ArityBucket};
use qlab_devnet::forms::GenesisForm;
use qlab_devnet::header::Hash32;
use qlab_devnet::params_devnet as pd;
use qlab_node::emission as em;
use qlab_node::{genesis_block, StoredBlock};

/// Genesis-file format version. **NOT frozen** — protocol-spec §9 marks the
/// genesis byte format `[full-M8]`; this is the T0 `[devnet-placeholder]` shape.
/// Bumped on any incompatible change to [`GenesisFile`] / [`FrozenParams`].
///
/// **2** since issue #101. The bump is not cosmetic: [`GenesisFile`] embeds the
/// genesis block as a [`StoredBlock`], which gained `coinbase_rkm`, so the file's
/// bytes — and therefore **the genesis hash, which is the network identity** —
/// changed. See [`GenesisFile`]'s docs.
///
/// **3** since issue #188. Judgement call, recorded rather than assumed: the
/// struct *shape* is unchanged — genesis carries no transactions, so
/// [`StoredTx`]'s new `discovery` field never appears in these bytes, and #115
/// moved the hash without a bump on exactly that reasoning. It is bumped anyway
/// because a v2 file is **semantically** incompatible now: its embedded header
/// commits to a v1 body preimage, so a #188 binary that loaded one would pass
/// the hash check (the file hashes to what it hashes to) and only fail later, at
/// the height-0 header/body binding, with a much worse error. #81's rule is that
/// an incompatible artifact is refused with a reason and never migrated by
/// guesswork; the bump is what makes that refusal happen at load.
///
/// **4 since the mint** (issue #215 (i) / #219). Same judgement as #188's, and it
/// applies for the same reason rather than by pattern-match: the struct shape is
/// again unchanged — only `CONSENSUS_WIRE_BYTES` moved, 145,609 → 148,625 — but
/// `expected_genesis_hash` lives in the **operator's config**, not in this binary.
/// So an operator carrying a stale config *and* a stale file onto a mint binary
/// would **pass** the hash check (the file hashes to what its own config pins) and
/// only fail later, when a transaction's proof is 148,625 B against a genesis
/// recording 145,609. That is the "much worse error" #188's bump exists to
/// prevent, and the same remedy applies.
pub const GENESIS_FORMAT_VERSION: u32 = 4;

/// **5 — the T2 genesis format** (lab #470): the version whose form set is
/// [`GenesisForm::V5`] — stratum-compatible 97-byte header, one body form
/// carrying the C3 hygiene batch, payee-list coinbase (cap 1 at birth), exact
/// emission + the name rule native from height ≥ 1. One binary serves both
/// formats; the loaded file's version selects the net (`GenesisFile::form`,
/// the Q1 ruling). The devnet-placeholder shape note above applies unchanged.
pub const GENESIS_FORMAT_VERSION_T2: u32 = 5;

/// The FROZEN consensus wire size in bytes (qlab-consensus
/// `consensus_wire_is_148625_bytes`; consensus-parameters §1). Baked so the
/// genesis file records the measured wire the net commits to.
///
/// 🔴 **Moved 145,609 → 148,625 by the mint** (issue #215 (i) / #219, the
/// combination baton). It is **a measurement on ONE tree**, 5/5 byte-exact at
/// width 643 / 84 perms — not the 148,161 B that circulated earlier, which was a
/// sum of measurements on *different* trees and, as #219's sequencing ruling put
/// it, *"a sum mints nothing"*. The 22 columns that sum assumed were QUM-62's
/// probe bank; the real construction is 26 (23 for option 4 + 3 for the latch).
///
/// Changing this value **re-mints genesis** — it is inside `FrozenParams`, which
/// is serialized into the genesis file and therefore inside the genesis hash. The
/// two changes that move it both went unconditional in this baton, so there is no
/// feature that returns the old wire.
pub const CONSENSUS_WIRE_BYTES: u64 = 148_625;

/// T0 genesis PoW difficulty — `[devnet-placeholder]`, NOT frozen. Chosen low so
/// a real-RandomX rehearsal net mines on laptop hardware; the real launch
/// difficulty is an open tokenomics/consensus question (params_devnet
/// `GENESIS_DIFFICULTY`). Baked into the genesis block so every node agrees.
///
/// Lab #506: `--t2 --launch --difficulty <u64>` overrides this; the default
/// **stays** this placeholder (coordinator ruling: LWMA fodder, not ceremony
/// friction).
pub const T0_GENESIS_DIFFICULTY: u64 = 256;

/// Banner line for `genesis init --t2 --launch` (lab #506). A ceremony operator
/// reading stdout must be able to tell this mint is **not** the pinned rehearsal.
pub const LAUNCH_MODE_BANNER: &str = "LAUNCH — keys from OS randomness, hash NOT reproducible";

/// Banner line for the rehearsal path (`genesis init` / `genesis init --t2`
/// without `--launch`). The `[devnet-placeholder]` tag is the pre-#506 note.
pub const REHEARSAL_MODE_BANNER: &str =
    "rehearsal — deterministic committee seeds [devnet-placeholder]";

/// [`KeyFile::note`] for rehearsal keys — **byte-identical** to the pre-#506
/// string, so `--t2` without `--launch` writes the same files as today.
pub const REHEARSAL_KEY_NOTE: &str =
    "devnet T0 rehearsal key (deterministic seed) — NOT a real validator key";

/// [`KeyFile::note`] for launch keys. The files are still seed-hex TOML (the
/// existing load path); the note is what tells an operator these seeds are
/// **not** `committee_seed(i)`.
pub const LAUNCH_KEY_NOTE: &str =
    "LAUNCH committee key (OS-random seed) — NOT recoverable from source";

/// Which mode minted this genesis — the string printed on `genesis init`.
pub fn mode_banner(launch: bool) -> &'static str {
    if launch {
        LAUNCH_MODE_BANNER
    } else {
        REHEARSAL_MODE_BANNER
    }
}

/// Parsed `genesis init` flags (lab #506). Lives next to the constructors it
/// selects so the CLI glue in `main.rs` stays a write + a banner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisInitPlan {
    /// `--out DIR`, default `.`.
    pub out: std::path::PathBuf,
    /// `--t2` — mint the v5 T2 genesis rather than the T1 file.
    pub t2: bool,
    /// `--launch` — OS-random committee keys. Requires [`Self::t2`].
    pub launch: bool,
    /// `--difficulty <u64>`, default [`T0_GENESIS_DIFFICULTY`]. Honoured only
    /// on the launch path; the parser refuses the flag without `--launch` so a
    /// fat-finger cannot move the rehearsal pin.
    pub difficulty: u64,
}

impl GenesisInitPlan {
    /// Parse the args after `genesis init`. Unknown flags are skipped — today's
    /// command only looked at `--out` / `--t2`, and refusing unknowns here would
    /// turn every future additive flag into a surprise break of old scripts.
    pub fn parse(args: &[String]) -> Result<Self, String> {
        let mut out = std::path::PathBuf::from(".");
        let mut t2 = false;
        let mut launch = false;
        let mut difficulty: Option<u64> = None;
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--out" => {
                    let v = args.get(i + 1).ok_or("--out requires a directory")?;
                    out = std::path::PathBuf::from(v);
                    i += 2;
                }
                "--t2" => {
                    t2 = true;
                    i += 1;
                }
                "--launch" => {
                    launch = true;
                    i += 1;
                }
                "--difficulty" => {
                    let v = args.get(i + 1).ok_or("--difficulty requires a u64")?;
                    difficulty = Some(v.parse::<u64>().map_err(|_| {
                        format!("--difficulty expects a non-negative integer, got `{v}`")
                    })?);
                    i += 2;
                }
                _ => i += 1,
            }
        }
        if launch && !t2 {
            return Err(
                "`--launch` requires `--t2` (T1 genesis is a live network identity; launch is the T2 ceremony path)"
                    .into(),
            );
        }
        if difficulty.is_some() && !launch {
            return Err(
                "`--difficulty` requires `--launch` (rehearsal genesis stays byte-identical without it)"
                    .into(),
            );
        }
        Ok(Self {
            out,
            t2,
            launch,
            difficulty: difficulty.unwrap_or(T0_GENESIS_DIFFICULTY),
        })
    }
}

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
/// **This file's hash is the network identity, and it has moved twice.**
///
/// The genesis hash is `keccak256` over this file's bincode, and the file embeds
/// the genesis block as a [`StoredBlock`]:
///
/// ```text
///   pre-#101:  4a75b3b8a80122cbbc35867df17bd14f19054658b511dbc45bcfa67053cfc2c3
///   post-#101: 8811d4e0ccdee702bafd4c92afad768495dc43360778072338aa140d87a73cff
///   post-#115: bd3604804aade38ece989d87e72e3541cede939512f513840c5cdcf13986a66f
///   post-#188: 566d4ed01426ece7a10ffa41829b6ec43d19a8bbb51b3d11aba7048192f0f80f
///   post-mint: 138e1524ba889bd49644f0eeafafa53533584caa2c0c851330cd27965223addb
/// ```
///
/// **#101 — `coinbase_rkm`, a consequence rather than a decision.** [`StoredBlock`]
/// gained the field, so the embedded genesis block's bytes changed. (Both
/// `coinbase_rkm` and the `format_version` bump fed that value; the intermediate
/// `44f7d464…` — the field alone, before the version bump — is not an identity any
/// build produces and is named here only so the two causes are not mistaken for
/// one.) A node built from that revision could not join the pre-#101 T0 net
/// whatever the genesis hash said: the block-body commitment preimage changed
/// (`qlab_devnet::body`), so #79's header/body binding rejects every block across
/// the boundary in both directions. The identity change did not create that
/// incompatibility — it made it fail at **startup**, with `WrongGenesisHash`,
/// instead of silently at the first block.
///
/// **#115 — genesis binds its own body, and this one IS a decision.** The genesis
/// header's `tx_body_commitment` moved from `ZERO_HASH` to the genesis body's real
/// commitment, so the embedded block's bytes — and this file's hash — moved again.
/// It was deliberately held for a mint (see issue #115): the identity is changing
/// at the mint anyway, so the change costs nothing here and would be a gratuitous
/// network-identity change at any other time. What it buys is that "this genesis
/// is not the body it claims to be" became an expressible, checked property; while
/// the height-0 exemption stood, it was not.
///
/// Note the two are different *kinds* of move. #101 changed the **body preimage**,
/// so every block's commitment changed. #115 changed **only what the genesis
/// header commits to** — the body preimage is untouched, and
/// `qlab_devnet::body::tests::golden_body_commitment_bytes` and
/// `golden_empty_body_commitment_bytes` both pass unmodified across it.
///
/// A running net crosses either of these the way `committee-and-governance` §4
/// says: the halt-height mechanism (#74/PR #76), which is drilled but has never
/// been used in anger. That is a deployment question, and it is not this baton's —
/// the operator-side pin moves in the same act as the mint.
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
    WrongFormatVersion {
        got: u32,
        want: u32,
    },
    /// The committee-key count does not match the frozen committee size.
    WrongCommitteeSize {
        got: usize,
        want: u32,
    },
    /// The baked quorum does not equal ⌊2N/3⌋+1.
    WrongQuorum {
        got: u32,
        want: usize,
    },
    /// A committee verifying key failed to decode.
    BadCommitteeKey {
        index: usize,
    },
    /// The genesis hash does not match the expected pin (node refuses to start).
    WrongGenesisHash {
        got: String,
        want: String,
    },
    /// A key file's hex seed was malformed.
    BadHex,
    /// A key file's seed was not 32 bytes.
    BadSeedLen,
    /// A loaded signing key's verifying key does not match committee₀ at its index.
    KeyDoesNotMatchCommittee {
        index: usize,
    },
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
                write!(
                    f,
                    "genesis hash {got} != expected {want} — refusing to start"
                )
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
            .map(|i| {
                Validator::from_seed(i, committee_seed(i))
                    .verifying_key()
                    .encode()
                    .to_vec()
            })
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

    /// Build the **T2** genesis (lab #470 stage 4b): format v5, the v5-form
    /// genesis block (its header binds the empty body's `commitment_v5` — the
    /// stage-3 pre-registered `82c2707b…7ea5`), the SAME FrozenParams v1.0
    /// table (nothing in this mint reaches the circuit; `CONSENSUS_WIRE_BYTES`
    /// stays 148,625 and the fee rows carry the current values marked
    /// *pending launch re-ratification* — C6 stamps at LAUNCH, not at merge),
    /// and the same 21 rehearsal committee keys (C5 explicitly deferred; the
    /// T-ops launch ceremony re-mints with real keys and the launch difficulty
    /// — both `[devnet-placeholder]` here exactly as they were for T0).
    pub fn new_t2() -> Self {
        let n = pd::FROZEN_COMMITTEE_SIZE;
        let committee_keys: Vec<Vec<u8>> = (0..n)
            .map(|i| {
                Validator::from_seed(i, committee_seed(i))
                    .verifying_key()
                    .encode()
                    .to_vec()
            })
            .collect();
        Self::t2_from_committee_keys(committee_keys, T0_GENESIS_DIFFICULTY)
    }

    /// Shared T2 shape: format v5, network `qumbra-t2`, FrozenParams v1.0, v5
    /// genesis block. Rehearsal and launch differ **only** in the 21 keys and
    /// the difficulty baked into the file + header.
    fn t2_from_committee_keys(committee_keys: Vec<Vec<u8>>, difficulty: u64) -> Self {
        GenesisFile {
            format_version: GENESIS_FORMAT_VERSION_T2,
            network: "qumbra-t2".to_string(),
            frozen: FrozenParams::v1_0(),
            committee_keys,
            genesis_difficulty: difficulty,
            genesis_block: qlab_node::genesis_block_for(GenesisForm::V5, difficulty, 0),
        }
    }

    /// T2 genesis from caller-supplied 32-byte seeds, run through the existing
    /// [`Validator::from_seed`] seam. Launch draws the seeds from OS randomness;
    /// tests inject known-distinct seeds so the anti-determinism property is
    /// locked without depending on the host CSPRNG happening to differ.
    ///
    /// Panics if `seeds.len()` is not the frozen committee size — a constructor
    /// bug, not an operator input.
    pub fn new_t2_with_committee_seeds(difficulty: u64, seeds: &[[u8; 32]]) -> Self {
        let n = pd::FROZEN_COMMITTEE_SIZE;
        assert_eq!(
            seeds.len(),
            n,
            "T2 committee is frozen at N={n}; got {} seeds",
            seeds.len()
        );
        let committee_keys: Vec<Vec<u8>> = seeds
            .iter()
            .enumerate()
            .map(|(i, seed)| {
                Validator::from_seed(i, *seed)
                    .verifying_key()
                    .encode()
                    .to_vec()
            })
            .collect();
        Self::t2_from_committee_keys(committee_keys, difficulty)
    }

    /// T2 **launch** genesis (lab #506): same v5 shape as [`Self::new_t2`], but
    /// the 21 committee seeds come from the OS CSPRNG (`rand::rng()`, the house
    /// OsRng-class path) through [`Validator::from_seed`]. Returns the seeds so
    /// the caller can write key files that actually open this genesis — they
    /// cannot be re-derived from `committee_seed`.
    pub fn new_t2_launch(difficulty: u64) -> (Self, Vec<[u8; 32]>) {
        use rand::Rng;
        let n = pd::FROZEN_COMMITTEE_SIZE;
        let mut seeds = vec![[0u8; 32]; n];
        for seed in &mut seeds {
            rand::rng().fill_bytes(seed);
        }
        (Self::new_t2_with_committee_seeds(difficulty, &seeds), seeds)
    }

    /// The genesis hash: keccak256 over the file's canonical bincode. This is the
    /// value printed on `genesis init` and asserted on startup.
    ///
    /// **This is "the genesis hash" in the operational sense** — the number
    /// pinned as `expected_genesis_hash` in every node config, quoted in
    /// `qumbra-deploy/OPERATOR.md` and in every roll task book, and the one that
    /// answers *is this host on the same net*. It covers the whole file:
    /// network name, the FROZEN v1.0 table, all 21 committee keys, **and** the
    /// genesis block.
    ///
    /// 🔴 **A second, different value also identifies genesis, and comparing the
    /// two is meaningless** (issue #206). The genesis **block header** hash —
    /// `qlab_devnet::ChainState::genesis_block_hash()`, persisted as
    /// `qlab_node::persist::Snapshot::genesis_block_hash` inside `snapshot.bin`
    /// — hashes only the height-0 header. This file *contains* that block, so
    /// the two values are structurally guaranteed to differ; a mismatch between
    /// a decoded snapshot and the runbook is the expected state, not a net
    /// mismatch. If you are here because a number did not match, that is
    /// probably why — stop looking.
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

    /// The consensus form set this file selects — the lab #470 T2 keying's
    /// single mapping point: `format_version` → [`GenesisForm`], asked once at
    /// load and threaded from there (never re-derived per call site).
    ///
    /// Stage 0: no caller consumes this yet, and [`Self::verify_startup`]
    /// still refuses everything but v4 — a v5 file remains unloadable until
    /// stage 4 mints one and flips that gate deliberately. The version this
    /// maps and the version the startup gate accepts are the same fact in two
    /// places on purpose: the gate is the refusal, this is the fan-out.
    pub fn form(&self) -> Result<GenesisForm, GenesisError> {
        GenesisForm::from_genesis_format_version(self.format_version).ok_or(
            GenesisError::WrongFormatVersion {
                got: self.format_version,
                want: GENESIS_FORMAT_VERSION,
            },
        )
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
        // Lab #470 stage 4b: the gate accepts exactly the versions this tree
        // serves — the same mapping `form()` fans out from. One binary, two
        // nets; WHICH net is still pinned by `expected_genesis_hash`, so this
        // widening moves no operator decision.
        self.form()?;
        let want_n = self.frozen.committee_size;
        if self.committee_keys.len() != want_n as usize {
            return Err(GenesisError::WrongCommitteeSize {
                got: self.committee_keys.len(),
                want: want_n,
            });
        }
        let want_q = quorum_threshold(want_n as usize);
        if self.frozen.quorum as usize != want_q {
            return Err(GenesisError::WrongQuorum {
                got: self.frozen.quorum,
                want: want_q,
            });
        }
        // Every committee key must decode (this also proves committee() succeeds).
        self.committee()?;
        if let Some(want) = expected_hex {
            let got = self.hash_hex();
            if !got.eq_ignore_ascii_case(want) {
                return Err(GenesisError::WrongGenesisHash {
                    got,
                    want: want.to_string(),
                });
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

    /// Write the 21 T0/T2 **rehearsal** committee signing-key files into `dir`
    /// (item 4). Returns their paths. Seeds are `committee_seed(i)` — the same
    /// bytes as before lab #506, so `--t2` without `--launch` is byte-identical.
    pub fn write_committee_key_files(
        &self,
        dir: impl AsRef<std::path::Path>,
    ) -> Result<Vec<std::path::PathBuf>, GenesisError> {
        let seeds: Vec<[u8; 32]> = (0..self.committee_keys.len()).map(committee_seed).collect();
        self.write_committee_key_files_from_seeds(dir, &seeds, REHEARSAL_KEY_NOTE)
    }

    /// Write committee signing-key files from caller-supplied seeds.
    ///
    /// Each seed is run through [`Validator::from_seed`] and the derived
    /// verifying key **must** equal committee₀ at that index — so a launch
    /// ceremony cannot write key files that do not open the genesis they just
    /// minted. Verification runs **before** any write, so a mismatch leaves
    /// `dir` untouched rather than half-populated.
    pub fn write_committee_key_files_from_seeds(
        &self,
        dir: impl AsRef<std::path::Path>,
        seeds: &[[u8; 32]],
        note: &str,
    ) -> Result<Vec<std::path::PathBuf>, GenesisError> {
        if seeds.len() != self.committee_keys.len() {
            return Err(GenesisError::WrongCommitteeSize {
                got: seeds.len(),
                want: self.committee_keys.len() as u32,
            });
        }
        for (i, seed) in seeds.iter().enumerate() {
            let v = Validator::from_seed(i, *seed);
            if v.verifying_key().encode().to_vec() != self.committee_keys[i] {
                return Err(GenesisError::KeyDoesNotMatchCommittee { index: i });
            }
        }
        let dir = dir.as_ref();
        std::fs::create_dir_all(dir).map_err(GenesisError::Io)?;
        // 0700 on the directory, 0600 on each file (below). `deploy.sh` moves these
        // with `rsync -a`, which **preserves** permissions — so whatever mode is set
        // here is the mode they land with on four public-IP hosts, and the default
        // from umask is 755/644.
        //
        // Rehearsal keys are derived from a deterministic seed (`committee_seed`)
        // and each file says so in as many words, so a 644 mode is not the exposure
        // it looks like — anyone with the source regenerates them. **That is exactly
        // why this is worth fixing now rather than later:** the mode has to be right
        // *before* the seeds stop being derivable (lab #506 `--launch`), and a
        // permission bug is hardest to notice in the window where it does not
        // matter yet.
        set_mode(dir, 0o700)?;
        let mut paths = Vec::new();
        for (i, seed) in seeds.iter().enumerate() {
            let kf = KeyFile {
                index: i,
                seed_hex: hex_encode(seed),
                note: note.to_string(),
            };
            let path = dir.join(format!("committee-{i:02}.key"));
            std::fs::write(&path, kf.to_toml()).map_err(GenesisError::Io)?;
            // After the write, not via `OpenOptions::mode`: that is ignored when the
            // file already exists, so a re-run into a populated dir would silently
            // keep the old mode.
            set_mode(&path, 0o600)?;
            paths.push(path);
        }
        // Lab #478: on a platform without modes, `set_mode` above did nothing —
        // 22 times, silently. That is fine for the joiner path (a public joiner
        // holds no committee keys at all) and NOT fine for whoever mints a net,
        // because these files land wherever the parent directory's ACL puts them.
        // Warned once, after the loop, rather than 22 times inside it.
        #[cfg(not(unix))]
        eprintln!(
            "⚠️  committee keys written WITHOUT owner-only permissions: this platform has no \
             file modes and this build sets no ACL. {} key files in {} inherit that folder's \
             permissions. If this is a net anyone will actually run, restrict the folder before \
             the keys stop being derivable from the source (see the comment above this line).",
            self.committee_keys.len(),
            dir.display(),
        );
        Ok(paths)
    }
}

/// Set a path's permission bits. No-op off Unix, where the concept does not
/// apply and the deploy path (`rsync` over ssh to Debian hosts) does not exist
/// either.
///
/// 🔴 Since lab #478 that no-op is REACHABLE — `qumbra-node genesis init` runs on
/// Windows now. It is still a no-op (Windows protection is an ACL, not a mode),
/// but its caller says so out loud rather than leaving the absence silent.
#[cfg(unix)]
fn set_mode(path: impl AsRef<std::path::Path>, mode: u32) -> Result<(), GenesisError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(GenesisError::Io)
}

#[cfg(not(unix))]
fn set_mode(_path: impl AsRef<std::path::Path>, _mode: u32) -> Result<(), GenesisError> {
    Ok(())
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
    ///
    /// 🔴 **Changed again by issue #188** — body format v2. The genesis header's
    /// `tx_body_commitment` **is** the empty body's commitment (#115), and #188
    /// moves the empty body's preimage (`BODY_PREIMAGE_DOMAIN`), so the embedded
    /// `StoredBlock`'s header bytes move and with them this file's hash. This is
    /// the T1 rider `t1-discovery-serving-decision.md` §10 stamped; **T0's four
    /// hosts are not upgraded by this baton** and none of T0's four drills
    /// involves a transaction, so discovery is never reached there.
    ///
    /// 🔴 **Changed by issue #115** — the genesis header now commits to its own
    /// body (`tx_body_commitment` moved off `ZERO_HASH`), so the embedded
    /// `StoredBlock`'s bytes moved and with them this file's hash. That is the
    /// intended outcome of the mint, not a regression: **a PR that changes how the
    /// genesis header is formed and leaves this constant standing has not changed
    /// it.** Previously changed by issue #101 (`coinbase_rkm` on `StoredBlock`).
    ///
    /// The two superseded values are kept visible so each break is a fact in the
    /// tree rather than a deleted line in a diff. `4a75b3b8…c2c3` is the identity
    /// of the T0 net that ran on `t0-wan-2`; a node built from this revision
    /// refuses to start against either older net, which is the loud, intended
    /// outcome (see [`GenesisFile`]'s docs for why they were already incompatible
    /// before the hash moved).

    /// Issue: committee key files land on four public-IP hosts via `rsync -a`,
    /// which preserves permissions — so the mode set here is the mode they get.
    /// 0700 on the directory and 0600 on each key, asserted rather than assumed.
    ///
    /// Deliberately checks a **re-run into a populated directory** too: `fs::write`
    /// does not change an existing file's mode, and `OpenOptions::mode` is ignored
    /// when the file exists, so a fix applied only at creation would pass a
    /// first-run test and leave a stale 0644 behind on every regeneration.
    #[cfg(unix)]
    #[test]
    fn committee_key_files_are_not_world_readable_even_on_a_re_run() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = std::env::temp_dir().join(format!("qumbra-keyperm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let dir = tmp.join("keys");
        // Pre-create one key at a deliberately wrong mode: this is the re-run case.
        std::fs::create_dir_all(&dir).unwrap();
        let stale = dir.join("committee-00.key");
        std::fs::write(&stale, "stale").unwrap();
        std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o644)).unwrap();

        let gf = GenesisFile::new_devnet_t0();
        let paths = gf.write_committee_key_files(&dir).expect("write keys");
        assert_eq!(paths.len(), 21, "21 committee keys");

        let dmode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dmode, 0o700, "keys/ must be 0700, got {dmode:o}");
        for p in &paths {
            let m = std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(m, 0o600, "{} must be 0600, got {m:o}", p.display());
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }
    #[test]
    fn genesis_hash_is_pinned() {
        assert_eq!(
            GenesisFile::new_devnet_t0().hash_hex(),
            "138e1524ba889bd49644f0eeafafa53533584caa2c0c851330cd27965223addb",
        );
        for superseded in [
            // pre-#101 — the T0 net on t0-wan-2.
            "4a75b3b8a80122cbbc35867df17bd14f19054658b511dbc45bcfa67053cfc2c3",
            // post-#101 / pre-#115 — never deployed.
            "8811d4e0ccdee702bafd4c92afad768495dc43360778072338aa140d87a73cff",
            // post-#115 / pre-#188 — the identity t0-wan-3..5 run on.
            "bd3604804aade38ece989d87e72e3541cede939512f513840c5cdcf13986a66f",
        ] {
            assert_ne!(
                GenesisFile::new_devnet_t0().hash_hex(),
                superseded,
                "superseded identity — see this test's doc comment"
            );
        }
    }

    /// 🔴 **The two values both called "the genesis hash" are different values,
    /// and each is what it claims to be** (issue #206). This is the assertion
    /// that stops the next person collapsing them back together, and it sits
    /// beside [`GenesisFile::hash`] because that is where a reader chasing a
    /// mismatched number is most likely to be standing.
    ///
    /// - [`GenesisFile::hash`] — keccak256 over the **whole file's** canonical
    ///   bincode. Printed by `genesis init`, pinned as `expected_genesis_hash`,
    ///   quoted in `qumbra-deploy/OPERATOR.md`. Operationally *the* genesis hash.
    /// - `Snapshot::genesis_block_hash` (inside `snapshot.bin`) — the genesis
    ///   **block header** hash, from `ChainState::genesis_block_hash()`.
    ///
    /// The file *contains* the block, so the two are structurally guaranteed to
    /// differ — asserted here by locating the block's own bincode inside the
    /// file's. The `assert_ne!` is therefore not an incidental fact about two
    /// hashes that happen not to collide; it is a consequence of the containment
    /// this test also checks.
    ///
    /// The snapshot side is taken from a **real snapshot written by a real
    /// node and decoded off disk**, not from a hand-built struct — the same act
    /// an operator performs on a host that has come back wrong, which is the
    /// situation #206 was filed from.
    #[test]
    fn the_file_hash_and_the_genesis_block_hash_are_different_values() {
        let gf = GenesisFile::new_devnet_t0();

        // (1) The file hash is keccak256 over the whole file's bincode.
        let file_hash = gf.hash();
        assert_eq!(
            file_hash,
            qlab_devnet::hash::keccak256(&gf.to_bytes()),
            "GenesisFile::hash() must be keccak256 over the file's canonical bincode"
        );

        // (2) The block hash is the height-0 header's hash, and nothing else.
        let block_hash = gf.genesis_block.header().header_hash();
        assert_eq!(
            gf.genesis_block.header.height, 0,
            "the baked block is genesis"
        );

        // (3) They differ — and they differ *because* the file contains the block.
        assert_ne!(
            file_hash, block_hash,
            "issue #206: the genesis FILE hash and the genesis BLOCK hash are \
             different values; comparing them is meaningless"
        );
        let file_bytes = gf.to_bytes();
        let block_bytes = bincode::serialize(&gf.genesis_block).expect("block serializes");
        assert!(
            file_bytes
                .windows(block_bytes.len())
                .any(|w| w == block_bytes.as_slice()),
            "the genesis file's bincode must contain the genesis block's bincode — \
             that containment is why the two hashes can never be equal"
        );

        // (4) A real node's snapshot carries the BLOCK hash, decoded off disk the
        //     way an operator decodes it.
        let dir = std::env::temp_dir().join(format!("qumbra-i206-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let node = qlab_node::Node::open(&dir, gf.genesis_block.clone()).expect("open node");
        node.save_snapshot().expect("write snapshot");
        let raw = std::fs::read(dir.join(qlab_node::SNAPSHOT)).expect("read snapshot.bin");
        let snap: qlab_node::Snapshot = bincode::deserialize(&raw).expect("decode snapshot.bin");
        assert_eq!(
            snap.genesis_block_hash, block_hash,
            "Snapshot::genesis_block_hash is the genesis BLOCK header hash"
        );
        assert_ne!(
            snap.genesis_block_hash, file_hash,
            "issue #206: snapshot.bin does NOT carry the value in OPERATOR.md — \
             an operator comparing the two always sees a mismatch, and it means nothing"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The genesis block inside the file **satisfies the header/body binding**
    /// (issue #115). This is the mint-time statement of the property: the file
    /// every node loads carries a genesis that is its own body, so the binding
    /// check `qlab_node` now applies at height 0 passes on the real artifact and
    /// not merely on a test fixture.
    #[test]
    fn the_baked_genesis_block_binds_its_own_body() {
        let gf = GenesisFile::new_devnet_t0();
        let g = &gf.genesis_block;
        assert_eq!(g.header.height, 0);
        assert_eq!(
            g.header.tx_body_commitment,
            g.body().commitment(),
            "the baked genesis block must bind its own body"
        );
        assert_ne!(
            g.header.tx_body_commitment,
            qlab_devnet::header::ZERO_HASH,
            "ZERO_HASH is the pre-#115 value the height-0 exemption existed for"
        );
        // It survives the round-trip every node performs on startup.
        let back = GenesisFile::from_bytes(&gf.to_bytes()).expect("decode");
        assert_eq!(
            back.genesis_block.header.tx_body_commitment,
            back.genesis_block.body().commitment()
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

    /// The lab #470 keying's mapping point: the devnet (v4) file selects the
    /// V4 form set; v5 maps (for the loader stage 4 builds); v1–v3 and
    /// anything above 5 refuse with the same error the startup gate uses.
    #[test]
    fn form_maps_the_format_version_and_refuses_the_rest() {
        let mut gf = GenesisFile::new_devnet_t0();
        assert_eq!(gf.form().unwrap(), GenesisForm::V4);
        gf.format_version = 5;
        assert_eq!(gf.form().unwrap(), GenesisForm::V5);
        for v in [0u32, 1, 2, 3, 6] {
            gf.format_version = v;
            assert!(
                matches!(gf.form(), Err(GenesisError::WrongFormatVersion { got, .. }) if got == v),
                "format_version {v} must refuse by name"
            );
        }
    }

    /// 🔒 **The T2 genesis hash** (lab #470 stage 4b) — minted through the
    /// real CLI (`genesis init --t2`), reproduced byte-identical twice by the
    /// builder (file sha256 `682d50bd…`), coordinator reproduction owed at
    /// acceptance. Beside — never instead of — the T1 pin below: two nets,
    /// two identities, one tree.
    #[test]
    fn t2_genesis_hash_is_pinned() {
        assert_eq!(
            GenesisFile::new_t2().hash_hex(),
            "0e55ccb316ea5dab39c16e0d7db056a1ccf06b167050244dc610a22ca1771df0",
        );
        assert_ne!(
            GenesisFile::new_t2().hash_hex(),
            GenesisFile::new_devnet_t0().hash_hex(),
            "T2 and T1 are different networks"
        );
    }

    #[test]
    fn t2_genesis_is_deterministic_and_v5() {
        let a = GenesisFile::new_t2();
        let b = GenesisFile::new_t2();
        assert_eq!(a.to_bytes(), b.to_bytes());
        assert_eq!(a.form().unwrap(), GenesisForm::V5);
        assert_eq!(a.format_version, GENESIS_FORMAT_VERSION_T2);
        assert_eq!(a.network, "qumbra-t2");
    }

    /// The stage-3 pre-registered tripwire, discharged at the file level: the
    /// baked T2 genesis header binds the empty body's v5 commitment.
    #[test]
    fn t2_genesis_binds_its_own_v5_body() {
        let gf = GenesisFile::new_t2();
        let g = &gf.genesis_block;
        assert_eq!(g.header.height, 0);
        assert_eq!(g.header.tx_body_commitment, g.body().commitment_v5());
        let hex: String = g
            .header
            .tx_body_commitment
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            hex,
            "82c2707bdf9790b25ef44355cb44cfd7faa6aba28d5db184b57edf83e7ba7ea5"
        );
        assert_ne!(
            g.header.tx_body_commitment,
            g.body().commitment(),
            "the v5 binding is not the v2 one"
        );
    }

    /// The widened startup gate: both served formats verify; the unserved
    /// refuse by name exactly as before.
    #[test]
    fn verify_startup_accepts_both_formats_and_refuses_the_rest() {
        assert!(GenesisFile::new_devnet_t0().verify_startup(None).is_ok());
        assert!(GenesisFile::new_t2().verify_startup(None).is_ok());
        let mut gf = GenesisFile::new_t2();
        gf.format_version = 6;
        assert!(matches!(
            gf.verify_startup(None),
            Err(GenesisError::WrongFormatVersion { got: 6, .. })
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

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_string()).collect()
    }

    /// Lab #506: two independent launch mints MUST produce different hashes —
    /// that is the whole point of OS randomness. Locked against two real
    /// `new_t2_launch` draws, not injected seeds: a constructor that silently
    /// fell back to `committee_seed` would fail this.
    #[test]
    fn t2_launch_two_runs_produce_distinct_hashes() {
        let (a, a_seeds) = GenesisFile::new_t2_launch(T0_GENESIS_DIFFICULTY);
        let (b, b_seeds) = GenesisFile::new_t2_launch(T0_GENESIS_DIFFICULTY);
        assert_ne!(a.hash(), b.hash(), "launch hashes must not be reproducible");
        assert_ne!(a_seeds, b_seeds, "two OsRng draws must not collide");
        assert_ne!(
            a.hash_hex(),
            GenesisFile::new_t2().hash_hex(),
            "a launch mint is not the rehearsal pin"
        );
    }

    #[test]
    fn t2_launch_verify_startup_accepts() {
        let (gf, _) = GenesisFile::new_t2_launch(T0_GENESIS_DIFFICULTY);
        assert!(gf.verify_startup(None).is_ok());
        let h = gf.hash_hex();
        assert!(gf.verify_startup(Some(&h)).is_ok());
        assert_eq!(gf.form().unwrap(), GenesisForm::V5);
        assert_eq!(gf.network, "qumbra-t2");
        assert_eq!(gf.format_version, GENESIS_FORMAT_VERSION_T2);
        assert_eq!(gf.genesis_difficulty, T0_GENESIS_DIFFICULTY);
    }

    /// Lab #506: launch key files parse back through the existing
    /// [`KeyFile::validator`] / [`GenesisFile::load_validators`] path — same
    /// seed-hex TOML, different seeds.
    #[test]
    fn t2_launch_key_files_parse_back_through_validator_load_path() {
        let dir = std::env::temp_dir().join(format!("qmb_t2_launch_keys_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (gf, seeds) = GenesisFile::new_t2_launch(T0_GENESIS_DIFFICULTY);
        let paths = gf
            .write_committee_key_files_from_seeds(&dir, &seeds, LAUNCH_KEY_NOTE)
            .expect("write launch keys");
        assert_eq!(paths.len(), 21);
        let validators = gf
            .load_validators(&paths)
            .expect("load through existing path");
        assert_eq!(validators.len(), 21);
        for (i, v) in validators.iter().enumerate() {
            assert_eq!(v.verifying_key().encode().to_vec(), gf.committee_keys[i]);
            let text = std::fs::read_to_string(&paths[i]).unwrap();
            let kf = KeyFile::from_toml(&text).unwrap();
            assert_eq!(kf.note, LAUNCH_KEY_NOTE);
            assert_eq!(kf.seed().unwrap(), seeds[i]);
            assert_eq!(
                kf.validator().unwrap().verifying_key().encode().to_vec(),
                gf.committee_keys[i]
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn t2_launch_is_v5_and_not_the_rehearsal_committee() {
        let (gf, _) = GenesisFile::new_t2_launch(T0_GENESIS_DIFFICULTY);
        let rehearsal = GenesisFile::new_t2();
        assert_eq!(gf.form().unwrap(), GenesisForm::V5);
        assert_ne!(gf.committee_keys, rehearsal.committee_keys);
        for i in 0..gf.committee_keys.len() {
            for j in (i + 1)..gf.committee_keys.len() {
                assert_ne!(
                    gf.committee_keys[i], gf.committee_keys[j],
                    "launch committee keys {i} and {j} collided"
                );
            }
        }
        // Empty-body v5 commitment is independent of committee keys / difficulty.
        assert_eq!(
            gf.genesis_block.header.tx_body_commitment,
            rehearsal.genesis_block.header.tx_body_commitment
        );
    }

    #[test]
    fn t2_launch_honours_difficulty() {
        let seeds = [[0x5eu8; 32]; 21];
        let gf = GenesisFile::new_t2_with_committee_seeds(7_777, &seeds);
        assert_eq!(gf.genesis_difficulty, 7_777);
        assert_eq!(gf.genesis_block.header.difficulty, 7_777);
        assert_ne!(gf.hash_hex(), GenesisFile::new_t2().hash_hex());
        // Same keys, default difficulty, is a different file from 7777.
        let at_default = GenesisFile::new_t2_with_committee_seeds(T0_GENESIS_DIFFICULTY, &seeds);
        assert_ne!(gf.hash(), at_default.hash());
    }

    #[test]
    fn launch_key_write_refuses_seeds_that_do_not_match_committee() {
        let dir =
            std::env::temp_dir().join(format!("qmb_t2_launch_mismatch_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let gf = GenesisFile::new_t2(); // rehearsal keys
        let seeds = vec![[0x11u8; 32]; 21];
        assert!(matches!(
            gf.write_committee_key_files_from_seeds(&dir, &seeds, LAUNCH_KEY_NOTE),
            Err(GenesisError::KeyDoesNotMatchCommittee { index: 0 })
        ));
        assert!(!dir.exists(), "a mismatch must not write any key file");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn genesis_init_parse_launch_requires_t2() {
        let err = GenesisInitPlan::parse(&args(&["--launch"])).unwrap_err();
        assert!(err.contains("`--launch` requires `--t2`"), "{err}");
    }

    #[test]
    fn genesis_init_parse_difficulty_requires_launch() {
        let err = GenesisInitPlan::parse(&args(&["--t2", "--difficulty", "1"])).unwrap_err();
        assert!(err.contains("`--difficulty` requires `--launch`"), "{err}");
        // `--difficulty` without `--t2` is the same refusal: it would move T1.
        let err = GenesisInitPlan::parse(&args(&["--difficulty", "1"])).unwrap_err();
        assert!(err.contains("`--difficulty` requires `--launch`"), "{err}");
    }

    #[test]
    fn genesis_init_parse_launch_defaults_placeholder_difficulty() {
        let plan = GenesisInitPlan::parse(&args(&["--t2", "--launch"])).unwrap();
        assert!(plan.t2 && plan.launch);
        assert_eq!(plan.difficulty, T0_GENESIS_DIFFICULTY);
        assert_eq!(plan.out, std::path::PathBuf::from("."));
    }

    #[test]
    fn genesis_init_parse_launch_accepts_difficulty_and_out() {
        let plan = GenesisInitPlan::parse(&args(&[
            "--t2",
            "--launch",
            "--difficulty",
            "4096",
            "--out",
            "/tmp/t2-ceremony",
        ]))
        .unwrap();
        assert_eq!(plan.difficulty, 4096);
        assert_eq!(plan.out, std::path::PathBuf::from("/tmp/t2-ceremony"));
    }

    #[test]
    fn genesis_mode_banner_names_the_mode() {
        assert_eq!(
            mode_banner(true),
            "LAUNCH — keys from OS randomness, hash NOT reproducible"
        );
        assert_eq!(
            mode_banner(false),
            "rehearsal — deterministic committee seeds [devnet-placeholder]"
        );
        // Rehearsal still carries the pre-#506 placeholder tag; launch does not
        // pretend to be one.
        assert!(mode_banner(false).contains("[devnet-placeholder]"));
        assert!(!mode_banner(true).contains("[devnet-placeholder]"));
    }
}
