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

// Later stages (棒 3+) will add here, still as placeholders:
//   - EPOCH_LENGTH_BLOCKS (membership boundary — committee-gov §2)
//   - BOND_AMOUNT / EQUIVOCATION_SLASH_AMOUNT (committee-gov §3)
