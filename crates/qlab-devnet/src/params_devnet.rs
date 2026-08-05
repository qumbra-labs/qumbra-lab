//! ```text
//! ╔═══════════════════════════════════════════════════════════════════════╗
//! ║  DEVNET PLACEHOLDERS — NOT DESIGN DECISIONS                             ║
//! ║                                                                         ║
//! ║  Every constant here is a stand-in for an OPEN design question. The     ║
//! ║  consensus-parameters appendix does not exist yet. Emission schedule,   ║
//! ║  bond/slash amounts, fee-tier values, epoch length, block time, and     ║
//! ║  the PoW algorithm are all UNDECIDED. These values let the devnet run;  ║
//! ║  they are NOT proposals and must never be cited as decided.             ║
//! ╚═══════════════════════════════════════════════════════════════════════╝
//! ```
//!
//! This is the ONE place placeholder constants live. Never scatter magic numbers
//! through the code; add them here with a note pointing at the open question.

// ─── PoW / block production (棒 0–1; real RandomX + LWMA-120 @ M9-N3) ─────────
//
// The PoW algorithm is now DECIDED in prototype form: real RandomX
// (`pow::RandomXPow` over `qlab-pow`) with an LWMA-120 retarget. The **block time
// (75 s) is FROZEN** (consensus-parameters §2). The retarget *algorithm*
// parameters (LWMA window, key-block cadence) are **testnet-tunable and NOT
// frozen** — protocol-spec §10 freezes them at v1.1 with full M8. Monero/Zawy
// provenance is quoted; these are prototype choices, not Qumbra proposals.

/// Genesis difficulty for the accelerated in-process sim. **[devnet-placeholder]
/// — NOT frozen.** Chosen low so the sim/tests mine quickly. This constant is a
/// *sim knob*: the deployable `qumbra-node` binary does NOT read it — it bakes
/// the genesis file's own T0 difficulty (`qumbra_node::genesis::T0_GENESIS_DIFFICULTY`,
/// itself a `[devnet-placeholder]`) into the genesis block, and that is the
/// authoritative T0 value every node agrees on. The **real launch difficulty is
/// an open consensus/tokenomics question and is deliberately NOT chosen here**
/// (M10-T0-4, issue #68: "launch difficulty stays open — do NOT invent one").
pub const GENESIS_DIFFICULTY: u64 = 1_000;

/// The **FROZEN** target block time (consensus-parameters §2; Zcash ZIP-208
/// precedent). This is the `T` LWMA-120 retargets toward on a real testnet. The
/// devnet does NOT run at wall-clock scale — it drives LWMA with the accelerated
/// [`SIM_BLOCK_TIME_SECS`] via `SimConfig::block_time_secs` — but the algorithm is
/// identical; only `T` differs between the sim and a real net.
pub const POW_TARGET_BLOCK_TIME_SECS: u64 = 75;

/// The accelerated per-block time the sim clock advances by (and the LWMA `T` the
/// sim retargets toward). PLACEHOLDER sim knob — NOT the real 75 s
/// ([`POW_TARGET_BLOCK_TIME_SECS`]).
pub const SIM_BLOCK_TIME_SECS: u64 = 2;

/// LWMA difficulty-retarget window, in blocks (`N`). Testnet-tunable, NOT frozen
/// (Zawy's LWMA-1 recommends N in the 60–120 band for CPU chains; we take 120).
pub const LWMA_WINDOW_BLOCKS: usize = qlab_pow::lwma::LWMA_WINDOW;

/// RandomX key-block epoch length, in blocks: the key rotates every this many
/// blocks. Testnet-tunable, NOT frozen (Monero `RANDOMX_SEEDHASH_EPOCH_BLOCKS`).
pub const SEEDHASH_EPOCH_BLOCKS: u64 = qlab_pow::keyblock::KeyBlockSchedule::MONERO_EPOCH_BLOCKS;

/// RandomX key-block lag, in blocks: how deeply the seed block is buried before
/// its key takes effect. Testnet-tunable, NOT frozen (Monero
/// `RANDOMX_SEEDHASH_EPOCH_LAG`).
pub const SEEDHASH_EPOCH_LAG: u64 = qlab_pow::keyblock::KeyBlockSchedule::MONERO_EPOCH_LAG;

// ─── Committee / finality (棒 2–3; M9-N5 committee-over-network) ─────────────

/// Genesis committee size N. Design says N≈20–50 (consensus §4/§5;
/// committee-and-governance §1 uses N≈20). PLACEHOLDER — the M6 sim used 20; the
/// **frozen** genesis size is [`FROZEN_COMMITTEE_SIZE`] = 21 (consensus-parameters
/// §4). Kept for M6 back-compat; new committee-over-network code uses the frozen N.
pub const COMMITTEE_SIZE: usize = 20;

/// **FROZEN** genesis committee size N = 21 (consensus-parameters §4; odd N eases
/// ⅔ quorum arithmetic). The epoch-boundary membership machinery
/// ([`crate::epoch`]) seeds the genesis set at this N.
pub const FROZEN_COMMITTEE_SIZE: usize = 21;

/// **FROZEN** ⅔ quorum at the frozen N = ⌊2·21/3⌋+1 = 15 (consensus-parameters
/// §4). Asserted equal to [`crate::committee::quorum_threshold`] of the frozen N.
pub const FROZEN_QUORUM: usize = 15;

/// **FROZEN** epoch length: membership changes apply only at boundaries that are
/// multiples of this (committee-and-governance §2; consensus-parameters §4 = 1,152
/// blocks = 24 h at the frozen 75 s block time — also exactly the anchor window).
/// The accelerated sim drives the machinery with [`SIM_EPOCH_LENGTH_BLOCKS`]; the
/// boundary *rule* is identical, only the length differs.
pub const EPOCH_LENGTH_BLOCKS: u64 = 1_152;

/// Accelerated epoch length for the in-process sim/tests — small so a run crosses
/// several epoch boundaries in bounded time. PLACEHOLDER sim knob, NOT the frozen
/// 1,152 ([`EPOCH_LENGTH_BLOCKS`]).
pub const SIM_EPOCH_LENGTH_BLOCKS: u64 = 16;

/// Checkpoint cadence: propose a finality checkpoint every this many blocks =
/// **one 10-min anchor bucket (8 blocks at 75 s)** (consensus §4/§7, protocol-spec
/// §7 anchors row). **Testnet-tunable, NOT frozen** — protocol-spec §7 flags the
/// cadence `[full-M8]`; N5 pins the 8-block bucket as the prototype cadence, to be
/// frozen with the full-M8 P2P section. Sets the "minutes-class" finality latency.
pub const CHECKPOINT_CADENCE_BLOCKS: u64 = 8;

/// Sign-hysteresis for checkpoint slots (issue #269): a committee member does not
/// propose/sign slot S until its tip is at least `S + this`, so the slot's block
/// has settled before any key commits to a variant. Signing at `tip == S` — the
/// exact tip-race window — is issue #223's burn mechanism, and on 2026-08-05 a
/// mesh-degraded roll turned it into three consecutively burned slots and a
/// 51-minute finality outage. Cost: this × 75 s of added finality latency,
/// constant. **Waived at the halt boundary** (`halt_at == S`): a halted chain
/// never grows past S, so the boundary checkpoint — which issue #74 requires to
/// exist — would otherwise never be signed. Devnet-grade, testnet-tunable, NOT
/// frozen.
pub const CHECKPOINT_SIGN_HYSTERESIS_BLOCKS: u64 = 2;

/// Per-validator self-bond, in **bessel** (1 QMB = 10⁸ bessel, frozen §8).
///
/// **CONVERGED to the FROZEN v1.0 genesis steady-state self-bond (M10-T0-4,
/// issue #68).** The genesis file bakes a 10⁴ QMB steady-state minimum
/// (`FrozenParams::self_bond_qmb_steady`) reached via the epoch ramp
/// `BOND_RAMP_QMB = [(0,0),(90,100),(180,1_000),(360,10_000)]` QMB; in bessel the
/// steady bond is 10⁴ × 10⁸ = 10¹² (this value). Same convergence act as the
/// PR #45 anchor-window / M9-N4 fee-scale fixes — only the absolute scale was
/// pinned; the M6-sim behaviour (bond initialised at this amount) is unchanged in
/// shape. **The ramp itself lives in the genesis file** (the frozen source of
/// truth); this flat constant is the steady-state endpoint the accelerated sim
/// and committee code initialise bonds to.
pub const BOND_AMOUNT: u64 = 10_000 * 100_000_000; // 10⁴ QMB × 10⁸ bessel/QMB = 10¹²

/// Bond slashed on equivocation (committee-governance §3: tombstone + slash).
/// **CONVERGED: 10 % of the standard bond** (frozen §4 = "10 % of bond"), derived
/// from [`BOND_AMOUNT`] so the invariant holds by construction. The real path (the
/// qlab-p2p `NodeAdapter`) already slashes 10 % of each member's *own* bond; this
/// flat constant is the M6-sim equivalent at the standard bond. Downtime is
/// jail-NO-slash.
pub const EQUIVOCATION_SLASH_AMOUNT: u64 = BOND_AMOUNT / 10;

/// Downtime jail term, in blocks (jail-no-slash; auto-readmit after). PLACEHOLDER.
pub const JAIL_BLOCKS: u64 = 32;

/// **FROZEN** downtime-jail detection window, in checkpoint rounds: a member is
/// jailed if it signed fewer than [`DOWNTIME_JAIL_THRESHOLD_PCT`]% of the trailing
/// this-many finalized checkpoints (consensus-parameters §4: "< 33 % signed of the
/// trailing 100"). The window counts *checkpoint rounds*, not raw blocks — a round
/// is one finalized checkpoint (cadence [`CHECKPOINT_CADENCE_BLOCKS`]).
pub const DOWNTIME_JAIL_WINDOW: usize = 100;

/// **FROZEN** downtime-jail participation threshold, in percent: signing strictly
/// below this fraction of a full [`DOWNTIME_JAIL_WINDOW`] window jails the member
/// (no slash). consensus-parameters §4 = 33 %. Compared in integer form
/// (`signed·100 < 33·window`) so there is no float in consensus.
pub const DOWNTIME_JAIL_THRESHOLD_PCT: u64 = 33;

/// Finality lag (tip height − finalized height) beyond which the node is in
/// degraded probabilistic mode (Ebb-and-Flow, consensus §4). PLACEHOLDER —
/// tied to the open checkpoint cadence.
pub const DEGRADED_MODE_LAG_BLOCKS: u64 = 2 * CHECKPOINT_CADENCE_BLOCKS;

/// §8 anchor-age ceiling (consensus §6 / performance-budget §8): a transaction
/// may anchor only to a finalized commitment root no older than 24 h. Expressed
/// in blocks at the DECIDED 75 s block time (consensus-parameters §2, B2 adopted
/// 2026-07-22): 24·3600/75 = 1,152 — which is also exactly the epoch length.
/// (Coordinator acceptance fix on PR #45: the original 24·3600/60 = 1,440 used
/// the pre-decision 60 s end of the band and would be a 30 h window at 75 s,
/// violating the ≤24 h policy.) Beyond this the anchor is *expired* and the tx
/// is rejected — this is the window that lets a node retire old roots. The
/// 10-min-bucket quantization that snaps *which* finalized roots are offered (a
/// privacy knob layered on top of this ceiling) remains a consensus-parameters
/// item. The tracker takes the window as a parameter so the accelerated sim can
/// pass a smaller one.
pub const MAX_ANCHOR_AGE_BLOCKS: u64 = 24 * 3600 / 75;


// ─── Fees (棒 4) ─────────────────────────────────────────────────────────────

/// Marginal fee per logical action, in **bessel** (1 QMB = 10⁸ bessel, frozen
/// §8), ZIP-317-shape posted price (consensus §8).
///
/// **CONVERGED to the FROZEN §5 fee table (consensus-parameters, decided
/// 2026-07-22; wired 2026-07-23, M9-N4).** With `FEE_GRACE_ACTIONS = 2`,
/// `posted_fee = marginal × max(2, logical_actions)` yields the frozen absolutes
/// exactly: 2×2 → 0.01 QMB (10⁶), 4×4 → 0.02 QMB (2×10⁶), 8×8 → 0.04 QMB
/// (4×10⁶) — the ratio 1/2/4 is unchanged from the M6 placeholder; only the
/// absolute scale was pinned to §5. (CLAUDE.md: "params_devnet placeholders
/// should converge to [the frozen table]" — same act as the anchor-window fix on
/// PR #45.) The fee is a deterministic public function of the bucket, single
/// native fee asset; the frozen table is a versioned consensus parameter.
pub const FEE_MARGINAL_UNITS: u64 = 500_000;

/// Grace action count: fee = marginal × max(grace, logical_actions), ZIP-317's
/// `max(2, logical_actions)` (frozen §5 shape).
pub const FEE_GRACE_ACTIONS: u32 = 2;

// ─── Block-weight anti-spam governor (issue #42) ─────────────────────────────
//
// Two-median + quadratic penalty (consensus-and-network §8; consensus-parameters
// §6 `[open]`). EVERY constant below is an OPEN design question deferred to M6
// devnet load-testing — these are placeholder DEFAULTS the load harness sweeps
// candidate sets over. Monero's launched values are quoted for provenance; they
// are NOT Qumbra proposals.

/// Short-term median window, in blocks. PLACEHOLDER (Monero: 100).
pub const WEIGHT_SHORT_WINDOW: usize = 100;

/// Long-term median window, in blocks. PLACEHOLDER (Monero: 100_000). Kept far
/// smaller here so a sweep run covers several long-windows in bounded time.
pub const WEIGHT_LONG_WINDOW: usize = 5_000;

/// Penalty-free-zone floor, in bytes. PLACEHOLDER (Monero: 300_000). Sized so a
/// launch-realistic block (~1 TPS × 75 s ≈ 75 × 136 KB ≈ 10 MB) sits well inside
/// the free zone; the exact floor is the swept `[open]` constant.
pub const WEIGHT_MIN_BYTES: u64 = 10_000_000;

/// Long-term weight cap factor = num/den. PLACEHOLDER (Monero: 1.4 = 7/5).
pub const WEIGHT_LT_CAP_NUM: u64 = 7;
pub const WEIGHT_LT_CAP_DEN: u64 = 5;

/// Short-term median ceiling as a multiple of the long-term effective median.
/// PLACEHOLDER (Monero: 50).
pub const WEIGHT_ST_CAP: u64 = 50;

/// Hard block-weight limit as a multiple of the effective median (blocks past
/// this are invalid). PLACEHOLDER (Monero: 2).
pub const WEIGHT_MAX_MULTIPLE: u64 = 2;
