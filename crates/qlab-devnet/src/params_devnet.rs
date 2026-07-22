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

// ─── PoW / block production (棒 0–1) ────────────────────────────────────────

/// Genesis difficulty. PLACEHOLDER — chosen low so the sim mines quickly; the
/// real launch difficulty is an open tokenomics/consensus question.
pub const GENESIS_DIFFICULTY: u64 = 1_000;

/// The **real** decided block time is **60–75 s** (consensus-and-network.md §7,
/// Zcash ZIP-208 precedent). The devnet does NOT simulate at wall-clock scale;
/// it uses an accelerated per-block time as a pure sim knob. PLACEHOLDER.
pub const SIM_BLOCK_TIME_SECS: u64 = 2;

/// Difficulty-retarget window, in blocks. PLACEHOLDER (Bitcoin uses 2016).
pub const DIFFICULTY_WINDOW_BLOCKS: u64 = 16;

/// Max per-retarget difficulty change factor (Bitcoin-style clamp against
/// timestamp manipulation / wild swings). PLACEHOLDER.
pub const MAX_DIFFICULTY_ADJUST_FACTOR: u64 = 4;

// ─── Committee / finality (棒 2–3) ──────────────────────────────────────────

/// Genesis committee size N. Design says N≈20–50 (consensus §4/§5;
/// committee-and-governance §1 uses N≈20). PLACEHOLDER — exact N is open.
pub const COMMITTEE_SIZE: usize = 20;

/// Checkpoint cadence: propose a finality checkpoint every this many blocks.
/// PLACEHOLDER — real cadence sets the "minutes-class" finality latency
/// (consensus §4/§7); the exact value is open (consensus-parameters appendix).
pub const CHECKPOINT_CADENCE_BLOCKS: u64 = 8;

/// Per-validator self-bond (native-token units). PLACEHOLDER — the bond
/// minimum is open (committee-governance §3 / consensus-parameters appendix).
pub const BOND_AMOUNT: u64 = 1_000_000;

/// Bond slashed on equivocation (committee-governance §3: tombstone + slash).
/// PLACEHOLDER — the slash constant is explicitly open. Downtime is jail-NO-slash.
pub const EQUIVOCATION_SLASH_AMOUNT: u64 = 100_000;

/// Downtime jail term, in blocks (jail-no-slash; auto-readmit after). PLACEHOLDER.
pub const JAIL_BLOCKS: u64 = 32;

/// Finality lag (tip height − finalized height) beyond which the node is in
/// degraded probabilistic mode (Ebb-and-Flow, consensus §4). PLACEHOLDER —
/// tied to the open checkpoint cadence.
pub const DEGRADED_MODE_LAG_BLOCKS: u64 = 2 * CHECKPOINT_CADENCE_BLOCKS;

// Later stages will add here, still as placeholders:
//   - EPOCH_LENGTH_BLOCKS (membership boundary — committee-gov §2)

// ─── Fees (棒 4) ─────────────────────────────────────────────────────────────

/// Marginal fee per logical action (native-token units), ZIP-317-shape posted
/// price (consensus §8). PLACEHOLDER — the fee-tier values are explicitly open
/// (consensus §8 → consensus-parameters appendix). Single native fee asset.
pub const FEE_MARGINAL_UNITS: u64 = 5_000;

/// Grace action count: fee = marginal × max(grace, logical_actions), ZIP-317's
/// `max(2, logical_actions)`. PLACEHOLDER.
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
