//! The shared honesty vocabulary for anything that reports money.
//!
//! Lives here rather than in a shell so the CLI, the FFI and any later surface
//! spell a refusal the same way — the property lab #136 pinned for `UNAVAILABLE`
//! and #314 established for spend coverage.

/// The stable refused-figures token — same spelling as opview's and the
/// explorer's, deliberately.
pub const UNAVAILABLE: &str = "UNAVAILABLE";

/// How far the spend-subtraction reached — a report-level fact, because the
/// nullifier stream is fetched once for the whole scan and covers every address
/// in it (lab issue #314).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpentCoverage {
    /// The chain's nullifiers are in hand for `range`, so every figure below has
    /// had this wallet's spends subtracted. `None` means the endpoint held **no**
    /// main-chain block in the requested range at all — which is a covered state,
    /// not a failed one, because a range with no blocks has no outputs in it
    /// either.
    Covered { range: Option<(u64, u64)> },
    /// The stream could not be read or did not reach far enough. **No figure is
    /// quotable** — carries the reason, verbatim.
    Unavailable { why: String },
}

