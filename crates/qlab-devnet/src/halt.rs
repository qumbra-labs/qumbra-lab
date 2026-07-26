//! **Halt-height upgrade mechanism** — the only sanctioned path by which a FROZEN
//! v1.0 constant can ever change (issue #74).
//!
//! The governing spec is `qumbra-design/committee-and-governance.md` §4:
//!
//! > Execution is Cosmos x/upgrade-style: a halt-height is set in advance, the
//! > finality committee stops checkpointing at exactly that height, ≥⅔ restarts on
//! > the new binary, and finality resumes on the new rules. One hybrid-specific
//! > honesty note: unlike pure BFT, where the chain simply stops, old-binary PoW
//! > miners *can* keep producing blocks past the halt-height — but those blocks can
//! > never finalize, so the fork resolves to the checkpointed branch as soon as
//! > miners follow the finality signal; **the committee is what makes upgrades
//! > clean, not miner unanimity.** … a scheduled upgrade can be cancelled before the
//! > height if review turns something up.
//!
//! This module carries the **mechanism**; it holds no release values. The actual
//! halt height / revision / digest a shipped binary carries are release constants
//! in `qumbra_node::release` — H1: baked into the binary, never config, never
//! genesis, and with **no runtime override at all**.
//!
//! ## What is enforced here
//!
//! - [`HaltPlan`] — armed / cancelled / none, the release-level schedule object.
//! - **H MUST sit on the checkpoint-cadence grid** ([`HaltPlan::validate`]).
//!   "The committee stops checkpointing at exactly that height" is only
//!   well-defined if H is a cadence multiple; the consequence is the valuable part
//!   — the upgrade boundary is a *finalized* boundary, so everything pre-halt is
//!   final by construction rather than by convention.
//! - [`halt_regime`] — the `Halting` → `Halted` regime derivation (H2).
//! - [`PostHaltRules`] — the post-halt rule domain. The **inert** rule change the
//!   drill exercises is a PoW-value domain separation above the boundary
//!   ([`pow_value`]): old-binary blocks above H are mined against the pre-halt
//!   value, so under the post-halt rules their PoW does not meet the target. That
//!   is what makes "those blocks can never finalize" structural rather than
//!   accidental — see the module note below.
//!
//! ## Why the post-halt rule domain exists (and why it is the *inert* change)
//!
//! §4's honesty note only holds if the upgraded population can tell a pre-halt
//! block from a post-halt one. If the post-halt rules were byte-identical to the
//! pre-halt rules, an old miner's branch above H would be perfectly valid to the
//! upgraded net, heaviest-chain would arbitrate, and the old branch could finalize
//! — the opposite of what §4 promises. A real upgrade changes some rule; the drill
//! must therefore also change *some* rule, or it proves nothing.
//!
//! The smallest such change that touches **no** FROZEN v1.0 value (H5) is to
//! domain-separate the PoW value above the boundary with the revision's own digest:
//! the revision identifier itself becomes the rule delta. Nothing else moves — no
//! header layout, no genesis, no frozen constant, no emission, no fee.
//!
//! ## What is NOT here
//!
//! Cancellation, the revision digest, and the halt height itself are **release**
//! objects (`qumbra_node::release`), not chain objects. There is deliberately no
//! way to reach any of them from a config file, a CLI flag, or an environment
//! variable: any runtime path that changes where a node pauses is a path by which
//! a node can be made to disagree with its peers about where consensus pauses.

use crate::ebbflow::{finality_status, FinalityStatus};
use crate::hash::keccak256;
use crate::header::Hash32;
use crate::params_devnet::CHECKPOINT_CADENCE_BLOCKS;

/// Domain tag mixed into a post-halt PoW value, so a post-halt value can never
/// collide with a raw engine hash.
pub const POST_HALT_POW_TAG: &[u8] = b"qumbra:post-halt-pow:v1";

/// Why a release's halt schedule is not startable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HaltError {
    /// H is not a multiple of [`CHECKPOINT_CADENCE_BLOCKS`] (H2). "The committee
    /// stops checkpointing at exactly that height" is undefined off the grid, and
    /// the upgrade boundary would not be a finalized boundary.
    NotOnCadenceGrid { height: u64, cadence: u64 },
    /// H = 0 — genesis is not an upgrade boundary.
    ZeroHeight,
    /// The release declares post-halt rules whose boundary is not the height it
    /// resumes from (a rule domain that starts somewhere other than the halt).
    RuleBoundaryMismatch { post_halt_from: u64, halt_or_resume: u64 },
}

impl std::fmt::Display for HaltError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HaltError::NotOnCadenceGrid { height, cadence } => write!(
                f,
                "halt height {height} is not a multiple of the checkpoint cadence {cadence} — \
                 the committee cannot stop checkpointing at exactly that height, so the upgrade \
                 boundary would not be a finalized boundary"
            ),
            HaltError::ZeroHeight => write!(f, "halt height 0 is not an upgrade boundary"),
            HaltError::RuleBoundaryMismatch { post_halt_from, halt_or_resume } => write!(
                f,
                "post-halt rules start at {post_halt_from} but this release's halt/resume \
                 boundary is {halt_or_resume}"
            ),
        }
    }
}
impl std::error::Error for HaltError {}

/// A release's halt schedule (H1). One of exactly three states, and the state is a
/// property of the **binary**, chosen at compile time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum HaltPlan {
    /// No upgrade is scheduled in this release.
    #[default]
    None,
    /// This release halts at `height`: it applies block `height` and then stops
    /// mining above it, stops accepting blocks above it, and — the load-bearing act
    /// — stops signing checkpoints above it.
    Armed { height: u64 },
    /// The upgrade scheduled for `height` was **stood down** by this release (N1).
    ///
    /// Cancellation is deliberately the same *kind* of object as arming: a new
    /// release, not a runtime switch. The cancelled height is kept (rather than
    /// reverting to [`HaltPlan::None`]) so the stand-down is an explicit, auditable,
    /// diffable act — an operator can read "this binary cancels the upgrade at H"
    /// straight off the startup banner and check it against the announcement.
    Cancelled { height: u64, reason: &'static str },
}

impl HaltPlan {
    /// The height this release actually stops at, if any. A cancelled plan stops
    /// nowhere — that is the whole point of cancelling it.
    pub fn halt_at(&self) -> Option<u64> {
        match self {
            HaltPlan::Armed { height } => Some(*height),
            HaltPlan::None | HaltPlan::Cancelled { .. } => None,
        }
    }

    /// The height named by this plan (armed or cancelled), for logging/audit.
    pub fn named_height(&self) -> Option<u64> {
        match self {
            HaltPlan::Armed { height } | HaltPlan::Cancelled { height, .. } => Some(*height),
            HaltPlan::None => None,
        }
    }

    /// H2's grid rule. A binary whose halt height is not a multiple of the
    /// checkpoint cadence MUST refuse to start — with this error, not a panic.
    ///
    /// A **cancelled** height is validated too: a stand-down that names an
    /// impossible height is a typo, and a typo in the cancellation is exactly as
    /// dangerous as a typo in the arming.
    pub fn validate(&self) -> Result<(), HaltError> {
        let Some(height) = self.named_height() else { return Ok(()) };
        if height == 0 {
            return Err(HaltError::ZeroHeight);
        }
        if height % CHECKPOINT_CADENCE_BLOCKS != 0 {
            return Err(HaltError::NotOnCadenceGrid {
                height,
                cadence: CHECKPOINT_CADENCE_BLOCKS,
            });
        }
        Ok(())
    }

    /// A one-line operator description for the startup banner.
    pub fn describe(&self) -> String {
        match self {
            HaltPlan::None => "no halt scheduled".to_string(),
            HaltPlan::Armed { height } => format!("ARMED — halts at height {height}"),
            HaltPlan::Cancelled { height, reason } => {
                format!("CANCELLED — the upgrade at height {height} was stood down ({reason})")
            }
        }
    }
}

/// The post-halt rule set a resumed release runs above the upgrade boundary.
///
/// `domain` is the resuming revision's digest; above `from_height` it is mixed
/// into the PoW value ([`pow_value`]). Blocks mined under the pre-halt rules
/// above the boundary therefore fail PoW under the post-halt rules, and vice
/// versa — a clean bilateral fork at exactly the announced height, arbitrated by
/// finality rather than by luck.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PostHaltRules {
    /// The upgrade boundary: rules change for heights **strictly greater** than
    /// this. `from_height` is the halt height H, which is itself a pre-halt block
    /// (H2: "apply block H, then stop") and is finalized before the swap.
    pub from_height: u64,
    /// The active revision's frozen-parameter digest, used as the rule domain.
    pub domain: Hash32,
}

/// The complete rule schedule a running node enforces: where it stops, and which
/// rules apply above the upgrade boundary. Assembled from the release constants
/// and handed to the node once at startup — there is no setter reachable from
/// config, CLI, or environment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct RuleSchedule {
    /// This release's halt schedule.
    pub halt: HaltPlan,
    /// The post-halt rule domain, if this release resumes past an upgrade boundary.
    pub post_halt: Option<PostHaltRules>,
}

impl RuleSchedule {
    /// The v1.0 rules: no halt scheduled, no post-halt domain. This is what every
    /// in-process sim, every test, and the pre-announcement release run under, so
    /// the whole existing stack is unchanged by construction.
    pub const V1_0: RuleSchedule = RuleSchedule { halt: HaltPlan::None, post_halt: None };

    /// The height this node stops at, if any.
    pub fn halt_at(&self) -> Option<u64> {
        self.halt.halt_at()
    }

    /// Whether a block at `height` may be mined/accepted under this schedule (H2:
    /// an armed node applies block H and accepts nothing above it).
    pub fn accepts_height(&self, height: u64) -> bool {
        self.halt_at().is_none_or(|h| height <= h)
    }

    /// Whether the committee may sign a checkpoint at `height` (H2: the committee
    /// stops signing checkpoints **above** H; the checkpoint *at* H is exactly the
    /// one that must be produced, since it is what makes the boundary final).
    pub fn may_checkpoint(&self, height: u64) -> bool {
        self.accepts_height(height)
    }

    /// The rule domain in force at `height`, if any.
    pub fn domain_at(&self, height: u64) -> Option<&Hash32> {
        self.post_halt.as_ref().filter(|p| height > p.from_height).map(|p| &p.domain)
    }

    /// Structural validation (startup gate): the halt plan sits on the cadence
    /// grid, and any declared post-halt boundary sits on it too.
    pub fn validate(&self) -> Result<(), HaltError> {
        self.halt.validate()?;
        if let Some(p) = &self.post_halt {
            if p.from_height == 0 {
                return Err(HaltError::ZeroHeight);
            }
            if p.from_height % CHECKPOINT_CADENCE_BLOCKS != 0 {
                return Err(HaltError::NotOnCadenceGrid {
                    height: p.from_height,
                    cadence: CHECKPOINT_CADENCE_BLOCKS,
                });
            }
        }
        Ok(())
    }
}

/// The **PoW value** a block at `height` is mined against and validated against,
/// under `rules` — i.e. the value compared to the difficulty target.
///
/// At and below the upgrade boundary this is the engine's raw PoW hash,
/// byte-identical to the pre-halt rules — so **no pre-halt block changes meaning**,
/// ever. Above the boundary it is `keccak256(tag ‖ revision-digest ‖ raw)`.
///
/// **Why the domain is mixed into the PoW *value* and not the RandomX key seed.**
/// Mixing it into the seed was the first design, and it is wrong: the
/// [`crate::pow::KeccakPow`] placeholder engine documents that it *ignores* the
/// seed, so a seed-level domain would be a rule change under RandomX and a no-op
/// under Keccak. A consensus rule whose force depends on which PoW engine is
/// compiled in is not a consensus rule. Mixing the output keeps the rule at the
/// consensus layer, identical for every engine behind the [`crate::pow::PowEngine`]
/// trait — including any future one.
///
/// The work cost is unchanged (one extra Keccak per nonce trial), and the
/// difficulty target is untouched: this changes *which* hashes count, not how many
/// are needed.
pub fn pow_value(raw: Hash32, height: u64, rules: &RuleSchedule) -> Hash32 {
    match rules.domain_at(height) {
        None => raw,
        Some(domain) => {
            let mut buf = Vec::with_capacity(POST_HALT_POW_TAG.len() + 64);
            buf.extend_from_slice(POST_HALT_POW_TAG);
            buf.extend_from_slice(domain);
            buf.extend_from_slice(&raw);
            keccak256(&buf)
        }
    }
}

/// The finality regime of a node running under a halt schedule (H2).
///
/// Returns `None` when the halt does not (yet) govern the reported regime, in
/// which case the caller uses the ordinary Ebb-and-Flow rule. Otherwise:
///
/// - [`FinalityStatus::Halting`] — the tip has reached H but H's checkpoint has
///   not finalized yet. If finality cannot close at H the net stays visibly in
///   `Halting`; that is the honest outcome and a reason **not** to swap binaries
///   yet.
/// - [`FinalityStatus::Halted`] — H is finalized. The upgrade boundary is a
///   finalized boundary: everything pre-halt is final by construction, and it is
///   now safe to swap binaries.
pub fn halt_regime(
    tip_height: u64,
    finalized_height: Option<u64>,
    halt_at: Option<u64>,
) -> Option<FinalityStatus> {
    let h = halt_at?;
    if tip_height < h {
        return None; // not there yet — ordinary Final/Degraded
    }
    match finalized_height {
        Some(f) if f >= h => Some(FinalityStatus::Halted),
        _ => Some(FinalityStatus::Halting),
    }
}

/// The regime a node reports: the halt regime when a halt governs, else the
/// ordinary Ebb-and-Flow rule. This is the single derivation the whole stack uses
/// — telemetry never re-defines it.
pub fn regime(
    tip_height: u64,
    finalized_height: Option<u64>,
    max_lag: u64,
    halt_at: Option<u64>,
) -> FinalityStatus {
    halt_regime(tip_height, finalized_height, halt_at)
        .unwrap_or_else(|| finality_status(tip_height, finalized_height, max_lag))
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: u64 = 16; // on the cadence grid (8)

    #[test]
    fn grid_rule_accepts_multiples_and_rejects_everything_else() {
        assert_eq!(HaltPlan::Armed { height: 8 }.validate(), Ok(()));
        assert_eq!(HaltPlan::Armed { height: 16 }.validate(), Ok(()));
        assert_eq!(HaltPlan::Armed { height: 1_152 }.validate(), Ok(()));
        // Off-grid: refuse to start, with a clear error (NOT a panic).
        assert_eq!(
            HaltPlan::Armed { height: 17 }.validate(),
            Err(HaltError::NotOnCadenceGrid { height: 17, cadence: CHECKPOINT_CADENCE_BLOCKS })
        );
        assert_eq!(HaltPlan::Armed { height: 0 }.validate(), Err(HaltError::ZeroHeight));
        // A cancellation naming an impossible height is a typo, and is caught too.
        assert_eq!(
            HaltPlan::Cancelled { height: 17, reason: "x" }.validate(),
            Err(HaltError::NotOnCadenceGrid { height: 17, cadence: CHECKPOINT_CADENCE_BLOCKS })
        );
        // No plan is always valid.
        assert_eq!(HaltPlan::None.validate(), Ok(()));
    }

    #[test]
    fn a_cancelled_plan_halts_nowhere_but_still_names_its_height() {
        let c = HaltPlan::Cancelled { height: H, reason: "review found something" };
        assert_eq!(c.halt_at(), None, "cancelled ⇒ this node does not stop");
        assert_eq!(c.named_height(), Some(H), "…but the stand-down stays auditable");
        assert!(c.describe().contains("CANCELLED"));
        assert!(c.describe().contains("16"));
    }

    #[test]
    fn armed_release_accepts_up_to_h_and_nothing_above() {
        let r = RuleSchedule { halt: HaltPlan::Armed { height: H }, post_halt: None };
        assert!(r.accepts_height(H - 1));
        assert!(r.accepts_height(H), "block H itself IS applied (H2: apply H, then stop)");
        assert!(!r.accepts_height(H + 1), "nothing above H");
        assert!(r.may_checkpoint(H), "the checkpoint AT H is the one that must be produced");
        assert!(!r.may_checkpoint(H + 8), "the committee stops signing ABOVE H");
    }

    #[test]
    fn v1_0_rules_accept_every_height_and_never_change_a_pow_value() {
        let r = RuleSchedule::V1_0;
        for h in [0, 1, H, H + 1, 1_000_000] {
            assert!(r.accepts_height(h));
            assert_eq!(r.domain_at(h), None);
            assert_eq!(pow_value([7; 32], h, &r), [7; 32]);
        }
    }

    #[test]
    fn post_halt_domain_changes_pow_values_only_strictly_above_the_boundary() {
        let rules = RuleSchedule {
            halt: HaltPlan::None,
            post_halt: Some(PostHaltRules { from_height: H, domain: [0xAB; 32] }),
        };
        let raw: Hash32 = [9u8; 32];
        // At and below the boundary the PoW value is byte-identical to the pre-halt
        // rules — no pre-halt block ever changes meaning.
        assert_eq!(pow_value(raw, H - 1, &rules), raw);
        assert_eq!(pow_value(raw, H, &rules), raw);
        // Above it, the value is domain-separated.
        let post = pow_value(raw, H + 1, &rules);
        assert_ne!(post, raw, "post-halt PoW value must differ — this is the rule change");
        // Deterministic, and distinct per revision domain.
        assert_eq!(post, pow_value(raw, H + 1, &rules));
        let other = RuleSchedule {
            halt: HaltPlan::None,
            post_halt: Some(PostHaltRules { from_height: H, domain: [0xCD; 32] }),
        };
        assert_ne!(post, pow_value(raw, H + 1, &other), "distinct revisions ⇒ distinct rules");
    }

    #[test]
    fn regime_walks_final_then_halting_then_halted() {
        let lag = 16;
        // Before H: ordinary Ebb-and-Flow.
        assert_eq!(regime(10, Some(8), lag, Some(H)), FinalityStatus::Final);
        assert_eq!(regime(10, None, lag, Some(H)), FinalityStatus::Degraded);
        // Tip reaches H but H is not finalized yet ⇒ Halting.
        assert_eq!(regime(H, Some(8), lag, Some(H)), FinalityStatus::Halting);
        assert_eq!(regime(H, None, lag, Some(H)), FinalityStatus::Halting);
        // H finalized ⇒ Halted.
        assert_eq!(regime(H, Some(H), lag, Some(H)), FinalityStatus::Halted);
    }

    #[test]
    fn a_stuck_halt_stays_visibly_halting_not_degraded() {
        // If finality cannot close at H, the honest report is Halting — an operator
        // must be able to tell "paused, waiting for the boundary to finalize" from
        // "paused and stuck". A long stall at H would otherwise read as Degraded and
        // send the operator to the wrong runbook section.
        let lag = 16;
        assert_eq!(regime(H, Some(0), lag, Some(H)), FinalityStatus::Halting);
        // …even when the lag alone would say Degraded.
        assert_eq!(finality_status(H, Some(0), lag), FinalityStatus::Final);
        assert_eq!(regime(H, Some(0), 1, Some(H)), FinalityStatus::Halting);
        assert_eq!(finality_status(H, Some(0), 1), FinalityStatus::Degraded);
    }

    #[test]
    fn a_node_with_no_halt_never_reports_a_halt_regime() {
        assert_eq!(halt_regime(1_000, Some(992), None), None);
        assert_eq!(regime(1_000, Some(992), 16, None), FinalityStatus::Final);
    }

    #[test]
    fn rule_schedule_validates_its_post_halt_boundary_too() {
        let bad = RuleSchedule {
            halt: HaltPlan::None,
            post_halt: Some(PostHaltRules { from_height: 17, domain: [0; 32] }),
        };
        assert!(matches!(bad.validate(), Err(HaltError::NotOnCadenceGrid { height: 17, .. })));
        let ok = RuleSchedule {
            halt: HaltPlan::None,
            post_halt: Some(PostHaltRules { from_height: H, domain: [0; 32] }),
        };
        assert_eq!(ok.validate(), Ok(()));
    }
}
