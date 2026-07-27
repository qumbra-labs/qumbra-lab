//! **Release constants** — what *this binary* is, in the halt-height upgrade
//! mechanism (issue #74, H1/H4/N1).
//!
//! ## H1: the halt height is a property of the release, not of the deployment
//!
//! [`RELEASE`] is a `const`. It is selected at **compile time** by cargo feature,
//! and there is deliberately **no runtime override at all** — not a config key, not
//! a CLI flag, not an environment variable. The draft task-book allowed a
//! downward-only override "for testing"; that was struck, because any runtime path
//! that changes where a node pauses is a path by which a node can be made to
//! disagree with its peers about where consensus pauses. The asymmetry that made
//! downward-only tempting is real (halting early is safe, halting late forks) — but
//! a footgun that only misfires safely is still a footgun, and this one is free to
//! remove. The drill therefore builds **purpose-built binaries**, which is also
//! what a real upgrade is: a binary swap an operator can be drilled on.
//!
//! [`crate::config::NodeConfig`] carries no halt field, and a test in this module
//! asserts that a config file mentioning one is not silently honoured.
//!
//! ## N1: cancellation is a release, not a switch
//!
//! Standing an upgrade down before H is a **new release** carrying
//! [`HaltPlan::Cancelled`] — the same kind of object as arming it, for exactly H1's
//! reason. Grounds for keeping the cancelled height rather than reverting to
//! `HaltPlan::None`:
//!
//! 1. **Auditability.** `CANCELLED — the upgrade at height 16 was stood down
//!    (reason)` on the startup banner is something an operator can diff against the
//!    announcement. A silent revert to "no halt scheduled" is indistinguishable
//!    from the pre-announcement release, so an operator cannot tell whether they
//!    deployed the stand-down or forgot to deploy the arming.
//! 2. **Typos are still caught.** A cancelled height is grid-validated exactly like
//!    an armed one; a stand-down naming an impossible height is as dangerous as an
//!    arming naming one, because it means somebody cancelled a different upgrade
//!    than the one that is armed.
//! 3. **It composes with the marker.** A node that already halted at H has a halt
//!    marker on disk; a cancellation for H is then obviously the wrong binary to
//!    deploy, and the resume gate says so instead of silently resuming.
//!
//! ## H4: the resume gate
//!
//! A node that reaches its halt height writes a [`HaltMarker`] into its data dir.
//! Any later binary that would carry that node **past** the marked height must
//! declare that it is doing so ([`Release::resumes_from`]) and must carry a
//! [`Revision`] whose digest describes its own frozen constants — otherwise it
//! refuses to start. The marker is what makes this non-dodgeable: the gate does not
//! depend on the resuming binary volunteering anything, because the halted binary
//! already wrote the fact down.

use qlab_devnet::halt::{HaltError, HaltPlan, PostHaltRules, RuleSchedule};
use serde::{Deserialize, Serialize};

use crate::genesis::GenesisError;
use crate::revision::{own_frozen_digest_hex, Revision, RevisionError};

/// The halt height the **drill** binaries use. On the cadence grid (16 = 2 × 8) and
/// deliberately low, so each drill run is minutes of docker wall-clock rather than
/// hours. Not a production value — production halt heights are chosen per upgrade
/// and announced in advance.
pub const DRILL_HALT_HEIGHT: u64 = 16;

/// The baseline v1.0 revision every un-upgraded binary carries. Its digest is the
/// digest of the FROZEN v1.0 table — asserted at startup and in tests, so this
/// string cannot drift away from the constants it claims to describe.
pub const REVISION_V1_0: Revision = Revision {
    id: "v1.0",
    frozen_digest_hex: "19564ecaffd8f78e69b31840cf465b3b34553968813f7fcaff83194077534571",
};

/// The **deliberately inert** revision the drill upgrades to (H5). It moves **no**
/// FROZEN v1.0 value — its frozen digest is byte-identical to [`REVISION_V1_0`]'s —
/// and changes only the revision identifier. Building the road is not permission to
/// drive on it.
pub const REVISION_V1_0_1_DRILL: Revision = Revision {
    id: "v1.0.1-drill",
    frozen_digest_hex: "19564ecaffd8f78e69b31840cf465b3b34553968813f7fcaff83194077534571",
};

/// What this binary is: its name, its halt schedule, the revision it carries, and
/// the upgrade boundary it resumes past (if any).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Release {
    /// Human release name for the startup banner and the run doc.
    pub name: &'static str,
    /// This release's halt schedule (H1/N1).
    pub plan: HaltPlan,
    /// The revision this release carries. `None` is legal only for a release that
    /// neither resumes past a halt nor is asked to (H4).
    pub revision: Option<Revision>,
    /// The upgrade boundary this release resumes past. `Some(H)` means "this is the
    /// binary that follows the halt at H"; above H it enforces the post-halt rules.
    pub resumes_from: Option<u64>,
}

/// Why a release refuses to start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReleaseError {
    /// The halt schedule is structurally invalid (off the cadence grid, height 0).
    Halt(HaltError),
    /// The carried revision does not describe this binary's frozen constants.
    Revision(RevisionError),
    /// **H4.** This release would resume past an upgrade boundary but carries no
    /// revision. A binary that can resume without one honours the revision-doc rule
    /// by discipline alone, which is the state this mechanism exists to end.
    ResumeWithoutRevision { height: u64 },
    /// This node halted at `marked` (there is a halt marker on disk) and this binary
    /// would carry it past that height, but does not declare that it resumes from
    /// it. Deploying an arbitrary later binary onto a halted node is exactly the
    /// mistake the marker exists to catch.
    UndeclaredResume { marked: u64, declared: Option<u64> },
    /// A halt marker exists at `marked` and this binary is armed to halt at the
    /// same height while also claiming to resume past it — contradictory.
    ContradictoryPlan { marked: u64 },
}

impl std::fmt::Display for ReleaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReleaseError::Halt(e) => write!(f, "{e}"),
            ReleaseError::Revision(e) => write!(f, "{e}"),
            ReleaseError::ResumeWithoutRevision { height } => write!(
                f,
                "this release resumes past the halt at height {height} but carries NO revision \
                 identifier or frozen-parameter digest — refusing to start (H4: the revision \
                 document is part of the mechanism, not paperwork around it)"
            ),
            ReleaseError::UndeclaredResume { marked, declared } => write!(
                f,
                "this node halted at height {marked} (halt marker on disk) and this binary would \
                 carry it past that height, but it declares resumes_from={declared:?} — refusing \
                 to start. Deploy the release that follows the halt at {marked}."
            ),
            ReleaseError::ContradictoryPlan { marked } => write!(
                f,
                "this binary is armed to halt at {marked} AND claims to resume past it — refusing \
                 to start"
            ),
        }
    }
}
impl std::error::Error for ReleaseError {}
impl From<HaltError> for ReleaseError {
    fn from(e: HaltError) -> Self {
        ReleaseError::Halt(e)
    }
}
impl From<RevisionError> for ReleaseError {
    fn from(e: RevisionError) -> Self {
        ReleaseError::Revision(e)
    }
}

impl Release {
    /// Structural startup validation, independent of any on-disk state:
    /// grid rule (H2), the carried revision describes this binary (H4), and a
    /// declared resume carries a revision (H4).
    pub fn validate(&self) -> Result<(), ReleaseError> {
        self.plan.validate()?;
        if let Some(r) = &self.revision {
            r.verify()?;
        }
        if let Some(height) = self.resumes_from {
            if self.revision.is_none() {
                return Err(ReleaseError::ResumeWithoutRevision { height });
            }
            if self.plan.halt_at() == Some(height) {
                return Err(ReleaseError::ContradictoryPlan { marked: height });
            }
        }
        self.rule_schedule().map(|_| ())
    }

    /// The [`RuleSchedule`] this release enforces: where it halts, and the post-halt
    /// rule domain above the boundary it resumes past.
    pub fn rule_schedule(&self) -> Result<RuleSchedule, ReleaseError> {
        let post_halt = match (self.resumes_from, &self.revision) {
            (Some(from_height), Some(rev)) => {
                Some(PostHaltRules { from_height, domain: rev.digest() })
            }
            (Some(height), None) => return Err(ReleaseError::ResumeWithoutRevision { height }),
            (None, _) => None,
        };
        let schedule = RuleSchedule { halt: self.plan, post_halt };
        schedule.validate()?;
        Ok(schedule)
    }

    /// The height above which this node will not produce or accept blocks.
    pub fn halt_at(&self) -> Option<u64> {
        self.plan.halt_at()
    }

    /// **The resume gate (H4).** Check this release against the halt marker (if any)
    /// found in the node's data dir.
    ///
    /// The marker is written by the binary that actually halted, so this check
    /// cannot be dodged by a resuming binary that simply says nothing.
    pub fn check_against_marker(&self, marker: Option<&HaltMarker>) -> Result<(), ReleaseError> {
        let Some(m) = marker else { return Ok(()) };
        // Would this binary carry the node past the marked height?
        let goes_past = self.plan.halt_at().is_none_or(|h| h > m.height);
        if !goes_past {
            return Ok(()); // still halted at (or before) the boundary — nothing to gate
        }
        if self.revision.is_none() {
            return Err(ReleaseError::ResumeWithoutRevision { height: m.height });
        }
        if self.resumes_from != Some(m.height) {
            return Err(ReleaseError::UndeclaredResume {
                marked: m.height,
                declared: self.resumes_from,
            });
        }
        Ok(())
    }

    /// The **loud** startup banner (H4: "logged loudly at startup"). Multi-line; the
    /// caller prints it verbatim.
    pub fn banner(&self, marker: Option<&HaltMarker>) -> String {
        let mut s = String::new();
        s.push_str(&format!("  release:      {}\n", self.name));
        s.push_str(&format!("  halt plan:    {}\n", self.plan.describe()));
        match &self.revision {
            Some(r) => {
                s.push_str(&format!("  revision:     {}\n", r.id));
                s.push_str(&format!("  frozen digest: {}\n", r.frozen_digest_hex));
                s.push_str(&format!("  rule domain:  {}\n", r.digest_hex()));
            }
            None => s.push_str("  revision:     ⚠️  NONE — this binary carries no revision\n"),
        }
        if let Some(h) = self.resumes_from {
            s.push_str(&format!("  resumes past: height {h} (post-halt rules apply above it)\n"));
        }
        match marker {
            Some(m) => s.push_str(&format!(
                "  halt marker:  height {} written under revision `{}` (frozen digest {})\n",
                m.height, m.revision_id, m.frozen_digest_hex
            )),
            None => s.push_str("  halt marker:  none on disk (this node has never halted)\n"),
        }
        s
    }
}

/// The durable record a node writes when it reaches its halt height.
///
/// This is the object that makes the resume gate real: it is written by the binary
/// that halted, so a later binary cannot resume past the boundary by simply
/// declaring nothing. It is also the operator's evidence that the halt happened,
/// under which revision, over which frozen set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HaltMarker {
    /// The halt height reached.
    pub height: u64,
    /// The revision the halting binary carried (`"-"` if it carried none).
    pub revision_id: String,
    /// The frozen-parameter digest of the halting binary.
    pub frozen_digest_hex: String,
    /// Whether H's checkpoint was finalized when the marker was written/updated —
    /// i.e. whether the node reached `Halted` or was still `Halting`.
    pub boundary_finalized: bool,
}

/// File name of the halt marker inside a node's data dir.
pub const HALT_MARKER_FILE: &str = "halt.marker";

impl HaltMarker {
    /// The marker a binary running `release` writes on reaching `height`.
    pub fn for_release(release: &Release, height: u64, boundary_finalized: bool) -> Self {
        HaltMarker {
            height,
            revision_id: release.revision.map(|r| r.id.to_string()).unwrap_or_else(|| "-".into()),
            frozen_digest_hex: release
                .revision
                .map(|r| r.frozen_digest_hex.to_string())
                .unwrap_or_else(own_frozen_digest_hex),
            boundary_finalized,
        }
    }

    /// Path of the marker inside `data_dir`.
    pub fn path(data_dir: &std::path::Path) -> std::path::PathBuf {
        data_dir.join(HALT_MARKER_FILE)
    }

    /// Load the marker from `data_dir`, if one exists. A malformed marker is an
    /// error, never a silent "no marker" — a node that halted must not be able to
    /// resume just because its marker got corrupted.
    pub fn load(data_dir: &std::path::Path) -> Result<Option<Self>, GenesisError> {
        let p = Self::path(data_dir);
        if !p.exists() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(&p).map_err(GenesisError::Io)?;
        toml::from_str(&text).map(Some).map_err(|e| GenesisError::Parse(e.to_string()))
    }

    /// Write the marker durably (fsync) into `data_dir`.
    pub fn write(&self, data_dir: &std::path::Path) -> Result<(), GenesisError> {
        use std::io::Write;
        std::fs::create_dir_all(data_dir).map_err(GenesisError::Io)?;
        let text = toml::to_string_pretty(self).expect("HaltMarker is always TOML-serializable");
        let mut f = std::fs::File::create(Self::path(data_dir)).map_err(GenesisError::Io)?;
        f.write_all(text.as_bytes()).map_err(GenesisError::Io)?;
        f.sync_all().map_err(GenesisError::Io)
    }
}

// ---------------------------------------------------------------------------
// THE release constant — compile-time selected. Exactly one arm is live in any
// given binary; there is no runtime path to any of the others.
// ---------------------------------------------------------------------------

/// This binary's release (H1). Compile-time constant, no runtime override.
#[cfg(not(any(
    feature = "drill-arm",
    feature = "drill-resume",
    feature = "drill-resume-norev",
    feature = "drill-cancel",
)))]
pub const RELEASE: Release = Release {
    name: "qumbra-node v1.0 (no upgrade scheduled)",
    plan: HaltPlan::None,
    revision: Some(REVISION_V1_0),
    resumes_from: None,
};

/// Drill binary **A** — the armed pre-upgrade release. Halts at
/// [`DRILL_HALT_HEIGHT`].
#[cfg(feature = "drill-arm")]
pub const RELEASE: Release = Release {
    name: "qumbra-node v1.0 [DRILL: armed]",
    plan: HaltPlan::Armed { height: DRILL_HALT_HEIGHT },
    revision: Some(REVISION_V1_0),
    resumes_from: None,
};

/// Drill binary **B** — the post-upgrade release. Carries the inert
/// `v1.0.1-drill` revision and resumes past [`DRILL_HALT_HEIGHT`].
#[cfg(feature = "drill-resume")]
pub const RELEASE: Release = Release {
    name: "qumbra-node v1.0.1 [DRILL: resume]",
    plan: HaltPlan::None,
    revision: Some(REVISION_V1_0_1_DRILL),
    resumes_from: Some(DRILL_HALT_HEIGHT),
};

/// Drill binary **C** — drill (c)'s negative: resumes past the halt but carries no
/// revision at all. It must refuse to start.
#[cfg(feature = "drill-resume-norev")]
pub const RELEASE: Release = Release {
    name: "qumbra-node v1.0.1 [DRILL: resume WITHOUT a revision — must refuse]",
    plan: HaltPlan::None,
    revision: None,
    resumes_from: Some(DRILL_HALT_HEIGHT),
};

/// Drill binary **D** — drill (d)'s: the stand-down. The upgrade at
/// [`DRILL_HALT_HEIGHT`] is cancelled, so this node does not halt there.
#[cfg(feature = "drill-cancel")]
pub const RELEASE: Release = Release {
    name: "qumbra-node v1.0 [DRILL: cancelled]",
    plan: HaltPlan::Cancelled {
        height: DRILL_HALT_HEIGHT,
        reason: "drill (d): review stood the upgrade down before the height",
    },
    revision: Some(REVISION_V1_0),
    resumes_from: None,
};

#[cfg(test)]
mod tests {
    use super::*;

    fn armed() -> Release {
        Release {
            name: "test-armed",
            plan: HaltPlan::Armed { height: DRILL_HALT_HEIGHT },
            revision: Some(REVISION_V1_0),
            resumes_from: None,
        }
    }
    fn resume() -> Release {
        Release {
            name: "test-resume",
            plan: HaltPlan::None,
            revision: Some(REVISION_V1_0_1_DRILL),
            resumes_from: Some(DRILL_HALT_HEIGHT),
        }
    }
    fn marker_at(h: u64) -> HaltMarker {
        HaltMarker::for_release(&armed(), h, true)
    }

    /// The pinned revision strings must actually describe this binary's constants —
    /// if a FROZEN v1.0 value ever moves, this is one of the places that fails.
    #[test]
    fn both_shipped_revisions_describe_this_binary() {
        assert_eq!(REVISION_V1_0.verify(), Ok(()));
        assert_eq!(REVISION_V1_0_1_DRILL.verify(), Ok(()));
        assert_eq!(REVISION_V1_0.frozen_digest_hex, own_frozen_digest_hex());
    }

    /// H5, asserted: the drill's revision moves **no** frozen value. Its frozen
    /// digest is identical to v1.0's; only the identifier differs — and that alone
    /// is enough to make it a distinct rule set.
    #[test]
    fn the_drill_revision_is_inert() {
        assert_eq!(REVISION_V1_0.frozen_digest_hex, REVISION_V1_0_1_DRILL.frozen_digest_hex);
        assert_ne!(REVISION_V1_0.id, REVISION_V1_0_1_DRILL.id);
        assert_ne!(REVISION_V1_0.digest(), REVISION_V1_0_1_DRILL.digest());
    }

    /// Whatever this binary was compiled as, its own RELEASE must be startable.
    #[test]
    fn the_compiled_in_release_validates() {
        // The one exception is the deliberately-broken drill (c) binary, whose whole
        // purpose is to refuse (asserted in its own test below).
        if cfg!(feature = "drill-resume-norev") {
            assert!(matches!(
                RELEASE.validate(),
                Err(ReleaseError::ResumeWithoutRevision { .. })
            ));
        } else {
            assert_eq!(RELEASE.validate(), Ok(()), "compiled-in RELEASE must be startable");
        }
    }

    #[test]
    fn an_armed_release_halts_at_h_and_declares_no_post_halt_rules() {
        let r = armed();
        assert_eq!(r.validate(), Ok(()));
        let s = r.rule_schedule().unwrap();
        assert_eq!(s.halt_at(), Some(DRILL_HALT_HEIGHT));
        assert!(s.accepts_height(DRILL_HALT_HEIGHT));
        assert!(!s.accepts_height(DRILL_HALT_HEIGHT + 1));
        assert_eq!(s.post_halt, None);
    }

    #[test]
    fn a_resume_release_halts_nowhere_and_applies_post_halt_rules_above_the_boundary() {
        let r = resume();
        assert_eq!(r.validate(), Ok(()));
        let s = r.rule_schedule().unwrap();
        assert_eq!(s.halt_at(), None, "the resumed binary does not halt");
        assert!(s.accepts_height(DRILL_HALT_HEIGHT + 1_000));
        assert_eq!(s.domain_at(DRILL_HALT_HEIGHT), None, "rules unchanged at and below H");
        assert_eq!(
            s.domain_at(DRILL_HALT_HEIGHT + 1),
            Some(&REVISION_V1_0_1_DRILL.digest()),
            "post-halt rule domain = the resuming revision's digest"
        );
    }

    /// **The domain separation is a property of the MECHANISM, not a drill prop**
    /// (coordinator ratification, 2026-07-26). Any release that resumes past an
    /// upgrade boundary necessarily carries a post-halt rule domain — there is no
    /// constructible release that resumes with the pre-halt rules still in force.
    /// Without this, a real upgrade would lack the very property the drill proves,
    /// which would make the drill evidence about a path production never takes.
    #[test]
    fn resuming_always_carries_a_post_halt_rule_domain() {
        for h in [8u64, 16, 1_152] {
            let r = Release {
                name: "test",
                plan: HaltPlan::None,
                revision: Some(REVISION_V1_0_1_DRILL),
                resumes_from: Some(h),
            };
            let s = r.rule_schedule().expect("a declared resume is startable");
            let p = s.post_halt.expect("resuming ⇒ post-halt rules, always");
            assert_eq!(p.from_height, h, "the domain starts at exactly the boundary");
            assert_eq!(p.domain, REVISION_V1_0_1_DRILL.digest());
            // Rules are unchanged at and below the boundary, changed above it.
            assert_eq!(s.domain_at(h), None);
            assert_eq!(s.domain_at(h + 1), Some(&p.domain));
        }
        // The only way to resume WITHOUT a domain is to carry no revision — which
        // is refused outright (H4), so the escape hatch does not exist.
        let no_rev = Release {
            name: "test",
            plan: HaltPlan::None,
            revision: None,
            resumes_from: Some(16),
        };
        assert!(no_rev.rule_schedule().is_err());
    }

    /// **DRILL (c)** — a binary that would resume past a halt but carries no
    /// revision digest refuses to start. Both at plain validation…
    #[test]
    fn drill_c_resume_without_a_revision_refuses_to_start() {
        let bad = Release {
            name: "test-resume-norev",
            plan: HaltPlan::None,
            revision: None,
            resumes_from: Some(DRILL_HALT_HEIGHT),
        };
        assert_eq!(
            bad.validate(),
            Err(ReleaseError::ResumeWithoutRevision { height: DRILL_HALT_HEIGHT })
        );
        assert!(bad.rule_schedule().is_err());
        // …and against a halt marker, where it cannot even be dodged by declaring
        // nothing: the halted binary already wrote the boundary down.
        let silent = Release {
            name: "test-silent",
            plan: HaltPlan::None,
            revision: None,
            resumes_from: None,
        };
        assert_eq!(silent.validate(), Ok(()), "no marker ⇒ a plain v1.0-shaped release is fine");
        assert_eq!(
            silent.check_against_marker(Some(&marker_at(DRILL_HALT_HEIGHT))),
            Err(ReleaseError::ResumeWithoutRevision { height: DRILL_HALT_HEIGHT }),
            "but on a HALTED node it must refuse — the marker is what makes the gate real"
        );
    }

    #[test]
    fn resume_gate_accepts_the_matching_release_and_rejects_an_undeclared_one() {
        let m = marker_at(DRILL_HALT_HEIGHT);
        // The right binary: declares exactly this boundary.
        assert_eq!(resume().check_against_marker(Some(&m)), Ok(()));
        // Some other later binary that carries a revision but does not declare the
        // boundary — refused rather than silently resumed.
        let wrong = Release {
            name: "test-wrong",
            plan: HaltPlan::None,
            revision: Some(REVISION_V1_0),
            resumes_from: None,
        };
        assert_eq!(
            wrong.check_against_marker(Some(&m)),
            Err(ReleaseError::UndeclaredResume { marked: DRILL_HALT_HEIGHT, declared: None })
        );
        // A binary declaring the WRONG boundary is refused too.
        let mismatched = Release { resumes_from: Some(DRILL_HALT_HEIGHT + 8), ..resume() };
        assert!(matches!(
            mismatched.check_against_marker(Some(&m)),
            Err(ReleaseError::UndeclaredResume { .. })
        ));
    }

    #[test]
    fn restarting_the_same_halted_binary_is_not_a_resume() {
        // The halted node's own binary restarting must NOT trip the resume gate —
        // an operator has to be able to stop and inspect a halted node.
        let m = marker_at(DRILL_HALT_HEIGHT);
        assert_eq!(armed().check_against_marker(Some(&m)), Ok(()));
        // A binary armed BELOW the marked height also never goes past it.
        let earlier = Release { plan: HaltPlan::Armed { height: 8 }, ..armed() };
        assert_eq!(earlier.check_against_marker(Some(&m)), Ok(()));
    }

    #[test]
    fn a_release_armed_at_the_height_it_claims_to_resume_past_is_contradictory() {
        let r = Release {
            name: "test-contradiction",
            plan: HaltPlan::Armed { height: DRILL_HALT_HEIGHT },
            revision: Some(REVISION_V1_0_1_DRILL),
            resumes_from: Some(DRILL_HALT_HEIGHT),
        };
        assert_eq!(
            r.validate(),
            Err(ReleaseError::ContradictoryPlan { marked: DRILL_HALT_HEIGHT })
        );
    }

    /// H2's grid rule, through the release surface: an off-grid halt height refuses
    /// to start with a clear error, not a panic.
    #[test]
    fn an_off_grid_release_refuses_to_start() {
        let r = Release { plan: HaltPlan::Armed { height: 17 }, ..armed() };
        assert!(matches!(
            r.validate(),
            Err(ReleaseError::Halt(HaltError::NotOnCadenceGrid { height: 17, cadence: 8 }))
        ));
    }

    /// **DRILL (d)** — a cancelled upgrade halts nowhere, so the net does not pause
    /// at the cancelled height.
    #[test]
    fn drill_d_a_cancelled_release_does_not_halt() {
        let r = Release {
            name: "test-cancelled",
            plan: HaltPlan::Cancelled { height: DRILL_HALT_HEIGHT, reason: "review" },
            revision: Some(REVISION_V1_0),
            resumes_from: None,
        };
        assert_eq!(r.validate(), Ok(()));
        assert_eq!(r.halt_at(), None);
        let s = r.rule_schedule().unwrap();
        for h in [DRILL_HALT_HEIGHT, DRILL_HALT_HEIGHT + 1, DRILL_HALT_HEIGHT + 100] {
            assert!(s.accepts_height(h), "a cancelled upgrade does not stop the chain at {h}");
            assert!(s.may_checkpoint(h), "…and the committee keeps checkpointing");
        }
        // …but the stand-down is still on the banner, and still grid-validated.
        assert!(r.banner(None).contains("CANCELLED"));
    }

    #[test]
    fn halt_marker_round_trips_on_disk_and_a_corrupt_one_is_an_error() {
        let dir = std::env::temp_dir().join("qmb_i74_marker");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(HaltMarker::load(&dir).unwrap(), None, "no marker on a fresh node");

        let m = HaltMarker::for_release(&armed(), DRILL_HALT_HEIGHT, true);
        m.write(&dir).unwrap();
        assert_eq!(HaltMarker::load(&dir).unwrap(), Some(m.clone()));
        assert_eq!(m.revision_id, "v1.0");
        assert_eq!(m.frozen_digest_hex, own_frozen_digest_hex());

        // A corrupted marker must NOT read as "never halted" — a halted node cannot
        // be allowed to resume just because its evidence got mangled.
        std::fs::write(HaltMarker::path(&dir), "this is not toml {{{").unwrap();
        assert!(HaltMarker::load(&dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// H1, asserted at the config surface: there is no runtime path to the halt
    /// height. A config file that tries to set one is rejected outright by the
    /// deny-unknown-fields parser, rather than being silently ignored (which would
    /// let an operator believe they had moved the halt).
    #[test]
    fn no_config_key_can_set_a_halt_height() {
        let toml = r#"
            data_dir = "/tmp/x"
            listen_addr = "127.0.0.1:9401"
            dial_peers = []
            genesis_file = "/tmp/g.qmb"
            committee_key_paths = []
            mining = true
            halt_height = 999
        "#;
        let err = crate::config::NodeConfig::from_toml(toml);
        assert!(err.is_err(), "a config key that looks like a halt override must not parse");
    }
}
