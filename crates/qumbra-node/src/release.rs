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
//! The marker is what makes the gate non-dodgeable: it does not depend on the
//! resuming binary volunteering anything, because the halted binary already wrote
//! the fact down.
//!
//! ## #81: the marker records the revision IN FORCE, and the gate keys on it
//!
//! The gate originally asked *"does this binary declare `resumes_from ==
//! marker.height`?"*. That was serviceable for exactly one upgrade, because after it
//! the marked height recedes into the past and never moves again — so **every**
//! later release had to declare `resumes_from = 16` forever, including a routine
//! release months later with no halt of its own. It bit on the *second* use of the
//! mechanism, which is the thing halt heights exist to make repeatable.
//!
//! The gate's real question was never which height this node halted at. It is
//! **"is this binary's parameter set the one this chain is running?"** So:
//!
//! - the marker records the revision **currently in force** on the data dir — its
//!   identifier and frozen digest, i.e. its [`Revision::digest`] — keeping the halt
//!   height as the audit record of the boundary rather than as the key;
//! - a binary carrying that same revision starts freely, no declaration;
//! - a binary carrying any other revision must declare the transition
//!   ([`Release::resumes_from`]), or refuse;
//! - a binary that declares and starts **rewrites** the marker, so the next routine
//!   release after the upgrade matches and needs no ceremony of its own.
//!
//! **The digest key applies only once the boundary has been PASSED**
//! ([`HaltMarker::resumed`]), and that qualification is load-bearing. While a node is
//! halted *at* the boundary, the chain has been deliberately paused there and the
//! operative question is not "is this the parameter set in force?" — the pre-halt
//! revision is trivially still in force, so the pre-announcement binary would match
//! and sail through, losing precisely the refusal the marker exists for. So:
//!
//! | data dir state | key |
//! |---|---|
//! | halted at the boundary, not yet resumed | the transition must be **declared** — unchanged from #74 |
//! | passed the boundary | **digest equality** against the revision in force |
//!
//! Height was, as #81 puts it, "a serviceable proxy for exactly one upgrade". That
//! one upgrade is exactly the still-halted row, and it keeps the height. What #81
//! fixes is every release *after* it, which is the row below.
//!
//! **Why the revision digest and not the bare frozen digest.** The drill's upgrade
//! is *inert*: `REVISION_V1_0_1_DRILL`'s frozen digest is byte-identical to
//! `REVISION_V1_0`'s. Keyed on the frozen digest alone, handing a node that resumed
//! under `v1.0.1-drill` the pre-announcement v1.0 binary would **match and start** —
//! losing the refusal the marker exists for. [`Revision::digest`] binds the
//! identifier too (H5's reason, `revision.rs`), so inert upgrades keep a real
//! boundary. A routine release still starts freely because it carries the *same*
//! revision: a revision names the frozen parameter set's document, not the binary
//! ([`Release::name`] is the binary), so a bug-fix release bumps the name and leaves
//! the revision alone.
//!
//! ## #81: the post-halt rule domain comes from the marker too
//!
//! This half is a **precondition**, not a separate feature. [`PostHaltRules::domain`]
//! is mixed into the PoW value above the boundary (`qlab_devnet::halt::pow_value`),
//! and it was derived *only* from this binary's own `resumes_from`. A routine
//! release — same revision, `resumes_from: None` — would therefore get
//! `post_halt: None`, reject every block the resumed population mined above the
//! boundary, and mine a branch they reject. Letting it "start freely" without the
//! domain would trade a clear `UndeclaredResume` refusal for a silently forking
//! node, which is strictly worse than the defect being fixed.
//!
//! So [`Release::rule_schedule_on`] reads the boundary and the domain off the marker
//! when this binary is the in-force revision and the data dir has already passed the
//! boundary. `resumes_from` keeps its two real jobs: authorising a transition, and
//! setting the domain when this binary *is* the transitioning one.
//!
//! **Known limit, stated plainly:** one marker records one boundary and one in-force
//! revision, so it cannot express domain *history*. After a second upgrade, a node
//! syncing from genesis would compute the first upgrade's blocks under the second
//! revision's domain. That is pre-existing and orthogonal — a release carries
//! exactly one `resumes_from`, so it is equally broken under the height scheme — and
//! the fix is the "releases carry boundary history" alternative #81 rejected as
//! unbounded. Reported on #81, deliberately not built here.

use qlab_devnet::halt::{HaltError, HaltPlan, PostHaltRules, RuleSchedule};
use serde::{Deserialize, Serialize};

use crate::genesis::GenesisError;
use crate::revision::{own_frozen_digest_hex, revision_digest, Revision, RevisionError};
use qlab_devnet::header::Hash32;

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
    /// **#81.** This data dir is running `in_force_revision` (the halt marker says
    /// so) and this binary carries a *different* revision that would carry the node
    /// past the boundary at `marked`, but it does not declare the transition.
    /// Deploying an arbitrary binary onto a halted or upgraded node is exactly the
    /// mistake the marker exists to catch — and a downgrade to the pre-announcement
    /// binary lands here too, which is the point.
    UndeclaredResume {
        marked: u64,
        declared: Option<u64>,
        in_force_revision: String,
        carried_revision: String,
    },
    /// A halt marker exists at `marked` and this binary is armed to halt at the
    /// same height while also claiming to resume past it — contradictory.
    ContradictoryPlan { marked: u64 },
    /// **#81.** The marker on disk was written under a schema this binary does not
    /// understand. Schema 0 is the pre-#81 height-keyed marker: it records which
    /// revision *halted*, which on a data dir that has already resumed is not the
    /// revision in force — and nothing on disk distinguishes the two cases. Refused
    /// with a reason rather than guessed at, and never treated as "no marker".
    UnknownMarkerSchema { found: u32, expected: u32, marked: u64 },
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
            ReleaseError::UndeclaredResume {
                marked,
                declared,
                in_force_revision,
                carried_revision,
            } => write!(
                f,
                "this data dir is running revision `{in_force_revision}` (halt marker on disk, \
                 upgrade boundary height {marked}) and this binary carries `{carried_revision}`, \
                 which is a DIFFERENT parameter set — but it declares \
                 resumes_from={declared:?}. Refusing to start. Either deploy the release that \
                 carries `{in_force_revision}`, or, if this binary really is the upgrade (or a \
                 deliberate downgrade), it must declare resumes_from={marked}."
            ),
            ReleaseError::ContradictoryPlan { marked } => write!(
                f,
                "this binary is armed to halt at {marked} AND claims to resume past it — refusing \
                 to start"
            ),
            ReleaseError::UnknownMarkerSchema { found, expected, marked } => write!(
                f,
                "the halt marker in this data dir has schema {found}, and this binary understands \
                 {expected}. Schema 0 is the pre-#81 height-keyed marker: it records which \
                 revision HALTED at height {marked}, not which revision is in force, so on a data \
                 dir that already resumed past {marked} the two differ and nothing on disk says \
                 which case this is. Refusing to start rather than guess — guessing wrong would \
                 silently admit a downgrade. Remedy: deploy the release that follows the halt at \
                 {marked} (it declares resumes_from={marked}, which restates the revision in \
                 force), or remove the marker deliberately if this data dir never resumed."
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

    /// **The resume gate (H4, rekeyed by #81).** Check this release against the halt
    /// marker (if any) found in the node's data dir.
    ///
    /// The marker is written by the binary that actually halted (and rewritten by the
    /// one that resumed), so this check cannot be dodged by a binary that simply says
    /// nothing. The question it asks is **"is this binary's revision the one in force
    /// on this data dir?"** — not "which height did this node halt at".
    ///
    /// This function is **read-only**: `check` and `halt-status` run it as a
    /// pre-flight, and a pre-flight that mutated the data dir would be a trap. The
    /// marker rewrite that follows a permitted transition is
    /// [`HaltMarker::superseded_by`], applied on the real start path only.
    pub fn check_against_marker(&self, marker: Option<&HaltMarker>) -> Result<(), ReleaseError> {
        let Some(m) = marker else { return Ok(()) };
        // (0) A marker we cannot interpret is refused with a reason — never read as
        //     "no marker", and never allowed to fall through to a fresh start.
        if m.schema != MARKER_SCHEMA {
            return Err(ReleaseError::UnknownMarkerSchema {
                found: m.schema,
                expected: MARKER_SCHEMA,
                marked: m.height,
            });
        }
        // (1) A binary that cannot go past the boundary cannot change the rules above
        //     it, so it needs no declaration. This is the "restart the halted binary
        //     to inspect it" case, and it must keep working.
        let goes_past = self.plan.halt_at().is_none_or(|h| h > m.height);
        if !goes_past {
            return Ok(());
        }
        // (2) **The #81 key** — and note it is gated on `resumed`. Once the boundary
        //     has been passed, carrying the revision in force means running the
        //     parameter set the chain is running, so start freely: this is the routine
        //     later release the height-keyed gate refused forever. While the node is
        //     still halted AT the boundary the pre-halt revision is trivially in
        //     force, so matching on it there would let the pre-announcement binary
        //     through — the one refusal this gate exists for.
        if m.resumed && self.revision.map(|r| r.digest()) == Some(m.in_force_digest()) {
            return Ok(());
        }
        // (3) Either the boundary is still closed — a halted node is resumed
        //     deliberately, never incidentally — or this binary carries a different
        //     parameter set. Both require a declared transition.
        if self.revision.is_none() {
            return Err(ReleaseError::ResumeWithoutRevision { height: m.height });
        }
        if self.resumes_from != Some(m.height) {
            return Err(ReleaseError::UndeclaredResume {
                marked: m.height,
                declared: self.resumes_from,
                in_force_revision: m.revision_id.clone(),
                carried_revision: self.revision.map(|r| r.id.to_string()).unwrap_or_default(),
            });
        }
        Ok(())
    }

    /// **#81.** Whether starting this release advances the marker — i.e. whether it
    /// got past the boundary by *declaring the transition* rather than by already
    /// carrying the revision in force.
    ///
    /// Only meaningful after [`Self::check_against_marker`] has passed; it re-tests
    /// the same conditions rather than trusting a flag, so the two cannot drift.
    /// Restarting a binary whose transition is already recorded returns `false`, so an
    /// ordinary restart costs no fsync and no log line.
    pub fn supersedes(&self, m: &HaltMarker) -> bool {
        if m.schema != MARKER_SCHEMA {
            return false;
        }
        if !self.plan.halt_at().is_none_or(|h| h > m.height) {
            return false; // cannot go past the boundary ⇒ changes nothing above it
        }
        if self.resumes_from != Some(m.height) {
            return false; // not a declared transition
        }
        // Already on the record: this exact revision in force, boundary marked passed.
        !(m.resumed && self.revision.map(|r| r.digest()) == Some(m.in_force_digest()))
    }

    /// **The rule schedule this release enforces on *this data dir*** (#81).
    ///
    /// [`Self::rule_schedule`] knows only what the binary declares. That is enough
    /// for the binary that performs a transition, and **not** enough for every
    /// release after it: a routine release carries the same revision and no
    /// `resumes_from`, so on its own it would run with no post-halt domain and fork
    /// from the population that upgraded (the domain is mixed into the PoW value).
    ///
    /// The marker is the durable record of what the data dir is running, so when this
    /// binary *is* the in-force revision and the data dir has already passed the
    /// boundary, the domain is read from there. A transitioning binary's own
    /// declaration wins, because it is the one changing the rules.
    pub fn rule_schedule_on(
        &self,
        marker: Option<&HaltMarker>,
    ) -> Result<RuleSchedule, ReleaseError> {
        let mut schedule = self.rule_schedule()?;
        if schedule.post_halt.is_some() {
            return Ok(schedule); // this binary declares the boundary itself
        }
        if let Some(m) = marker.filter(|m| m.schema == MARKER_SCHEMA && m.resumed) {
            if self.revision.map(|r| r.digest()) == Some(m.in_force_digest()) {
                schedule.post_halt =
                    Some(PostHaltRules { from_height: m.height, domain: m.in_force_digest() });
                schedule.validate()?;
            }
        }
        Ok(schedule)
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
            // #81: a rewritten marker must not read as "halted here" — after a resume
            // the height is the boundary this data dir PASSED, and the revision is the
            // one now in force, which is a different sentence.
            Some(m) if m.resumed => s.push_str(&format!(
                "  halt marker:  PASSED the upgrade boundary at height {}; revision in force `{}` \
                 (frozen digest {}, rule domain {})\n",
                m.height,
                m.revision_id,
                m.frozen_digest_hex,
                crate::genesis::hex_encode(&m.in_force_digest())
            )),
            Some(m) => s.push_str(&format!(
                "  halt marker:  HALTED at height {} under revision `{}` (frozen digest {}, \
                 boundary finalized: {}, marker schema {})\n",
                m.height, m.revision_id, m.frozen_digest_hex, m.boundary_finalized, m.schema
            )),
            None => s.push_str("  halt marker:  none on disk (this node has never halted)\n"),
        }
        s
    }
}

/// The durable record of **what this data dir is running, and across which upgrade
/// boundary** (#74's marker, rekeyed by #81).
///
/// This is the object that makes the resume gate real: it is written by the binary
/// that halted, so a later binary cannot get past the boundary by simply declaring
/// nothing. Since #81 it is also *rewritten* by the binary that legitimately resumes,
/// so it names the revision **in force** rather than only the one that halted — which
/// is what lets the release after the upgrade start with no ceremony while still
/// refusing a downgrade.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HaltMarker {
    /// Marker schema (#81). Absent on disk ⇒ 0 ⇒ the pre-#81 height-keyed marker,
    /// which is refused with a reason rather than reinterpreted: it records the
    /// revision that *halted*, and on a resumed data dir that is not the revision in
    /// force.
    #[serde(default)]
    pub schema: u32,
    /// The upgrade boundary height: the halt height reached. Since #81 this is the
    /// **audit record** and the `from_height` of the post-halt rule domain — it is no
    /// longer what the gate keys on.
    pub height: u64,
    /// The revision **in force** on this data dir (`"-"` if the binary that wrote it
    /// carried none). Written by the halting binary, rewritten by the one that
    /// legitimately resumes past the boundary.
    pub revision_id: String,
    /// The frozen-parameter digest of the in-force revision.
    pub frozen_digest_hex: String,
    /// Whether the boundary's checkpoint was finalized when the marker was written —
    /// i.e. whether the node reached `Halted` or was still `Halting`.
    pub boundary_finalized: bool,
    /// Whether this data dir has **passed** the boundary under the in-force revision.
    /// `false` = halted at it; `true` = resumed past it. Load-bearing twice over: it
    /// keeps the banner honest (a resumed marker must not read as "halted here"), and
    /// it is what tells a routine release that a post-halt rule domain applies above
    /// `height`.
    #[serde(default)]
    pub resumed: bool,
}

/// File name of the halt marker inside a node's data dir.
pub const HALT_MARKER_FILE: &str = "halt.marker";

/// The marker schema this binary writes and understands (#81). Bumped from the
/// implicit 0 of the height-keyed marker, whose `revision_id` meant something else.
pub const MARKER_SCHEMA: u32 = 1;

impl HaltMarker {
    /// The marker a binary running `release` writes on reaching `height`.
    pub fn for_release(release: &Release, height: u64, boundary_finalized: bool) -> Self {
        HaltMarker {
            schema: MARKER_SCHEMA,
            height,
            revision_id: release.revision.map(|r| r.id.to_string()).unwrap_or_else(|| "-".into()),
            frozen_digest_hex: release
                .revision
                .map(|r| r.frozen_digest_hex.to_string())
                .unwrap_or_else(own_frozen_digest_hex),
            boundary_finalized,
            resumed: false,
        }
    }

    /// **The #81 rewrite.** The marker this data dir carries once `release` has been
    /// permitted to carry it past the boundary: same boundary height (the audit
    /// record does not move), new revision in force, and `resumed` set.
    ///
    /// This is what stops the boundary from having to be re-declared forever. Without
    /// it the marker keeps naming the pre-upgrade revision, and every release after
    /// the upgrade is refused — the defect #81 was filed for.
    pub fn superseded_by(&self, release: &Release) -> Self {
        HaltMarker {
            schema: MARKER_SCHEMA,
            height: self.height,
            revision_id: release.revision.map(|r| r.id.to_string()).unwrap_or_else(|| "-".into()),
            frozen_digest_hex: release
                .revision
                .map(|r| r.frozen_digest_hex.to_string())
                .unwrap_or_else(own_frozen_digest_hex),
            boundary_finalized: self.boundary_finalized,
            resumed: true,
        }
    }

    /// The digest of the revision **in force** on this data dir — what the resume
    /// gate compares a binary's own [`Revision::digest`] against, and the post-halt
    /// rule domain above [`Self::height`].
    pub fn in_force_digest(&self) -> Hash32 {
        revision_digest(&self.revision_id, &self.frozen_digest_hex)
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
    /// A marker for a node **halted at** `h` under v1.0 and not yet resumed.
    fn marker_at(h: u64) -> HaltMarker {
        HaltMarker::for_release(&armed(), h, true)
    }
    /// A marker for a data dir that has **passed** the boundary at `h` under
    /// `release` — i.e. what the disk looks like after a successful upgrade (#81).
    fn resumed_marker_at(h: u64, release: &Release) -> HaltMarker {
        marker_at(h).superseded_by(release)
    }
    /// A plain later release: carries `rev`, halts nowhere, declares nothing. This is
    /// the shape of every routine bug-fix release after an upgrade.
    fn routine(rev: Revision) -> Release {
        Release {
            name: "test-routine (a later release, no halt of its own)",
            plan: HaltPlan::None,
            revision: Some(rev),
            resumes_from: None,
        }
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

    /// **A node HALTED at the boundary is resumed deliberately or not at all.** #81
    /// moved the *later* releases onto digest equality; the still-halted row keeps the
    /// declaration, because at that point the pre-halt revision is trivially the one
    /// in force and matching on it would admit the pre-announcement binary.
    #[test]
    fn resume_gate_accepts_the_matching_release_and_rejects_an_undeclared_one() {
        let m = marker_at(DRILL_HALT_HEIGHT);
        assert!(!m.resumed, "halted AT the boundary, not past it");
        // The right binary: declares exactly this boundary.
        assert_eq!(resume().check_against_marker(Some(&m)), Ok(()));
        // Some other later binary that carries a revision but does not declare the
        // boundary — refused rather than silently resumed. Note it carries the SAME
        // revision the marker records, so a gate keyed on digest equality ALONE would
        // have let it through: this is the assertion that pins the `resumed` gating.
        let wrong = routine(REVISION_V1_0);
        assert_eq!(wrong.revision.unwrap().digest(), m.in_force_digest(), "same revision");
        assert!(matches!(
            wrong.check_against_marker(Some(&m)),
            Err(ReleaseError::UndeclaredResume { marked, declared: None, .. })
                if marked == DRILL_HALT_HEIGHT
        ));
        // A binary declaring the WRONG boundary is refused too.
        let mismatched = Release { resumes_from: Some(DRILL_HALT_HEIGHT + 8), ..resume() };
        assert!(matches!(
            mismatched.check_against_marker(Some(&m)),
            Err(ReleaseError::UndeclaredResume { .. })
        ));
    }

    /// **🎯 #81, THE DEFECT AS FILED.** A routine release with no halt of its own, no
    /// relation to the boundary, and no declaration starts cleanly on a data dir that
    /// previously halted and was upgraded — because it carries the revision in force.
    ///
    /// Under the height-keyed gate this was `UndeclaredResume { marked: 16 }` forever,
    /// for every release after the upgrade, for the life of the data dir.
    #[test]
    fn a_routine_later_release_starts_on_a_data_dir_that_already_resumed() {
        let m = resumed_marker_at(DRILL_HALT_HEIGHT, &resume());
        assert!(m.resumed);
        assert_eq!(m.height, DRILL_HALT_HEIGHT, "the boundary is kept as the audit record");
        assert_eq!(m.revision_id, "v1.0.1-drill", "…and the revision in force has advanced");

        // The release after the upgrade: same revision, brand-new binary, declares
        // NOTHING about height 16 — which it has no business knowing about.
        let later = routine(REVISION_V1_0_1_DRILL);
        assert_eq!(later.resumes_from, None);
        assert_eq!(
            later.check_against_marker(Some(&m)),
            Ok(()),
            "a release that moves no frozen constant needs no ceremony (#81)"
        );
        // Still true after a SECOND routine release, and a third — the marker does not
        // need to be touched again, so this does not decay with time.
        assert_eq!(
            Release { name: "v1.0.3", ..later }.check_against_marker(Some(&m)),
            Ok(())
        );
        assert!(!later.supersedes(&m), "…and a matching release rewrites nothing");
    }

    /// **🎯 #81, THE OTHER HALF — the marker is still a gate.** An arbitrary binary is
    /// refused on a halted node *and* on a resumed one. The second case is the one a
    /// gate keyed on the bare **frozen** digest would have lost, because the drill's
    /// upgrade is inert: `v1.0` and `v1.0.1-drill` share a frozen digest, so only
    /// binding the identifier (`Revision::digest`) keeps the refusal.
    #[test]
    fn an_arbitrary_binary_is_refused_on_a_halted_node_and_on_a_resumed_one() {
        // (a) halted at the boundary, awaiting the upgrade.
        let halted = marker_at(DRILL_HALT_HEIGHT);
        for r in [routine(REVISION_V1_0), routine(REVISION_V1_0_1_DRILL)] {
            assert!(
                matches!(
                    r.check_against_marker(Some(&halted)),
                    Err(ReleaseError::UndeclaredResume { .. })
                ),
                "an undeclared binary must not carry a HALTED node past its boundary: {}",
                r.name
            );
        }

        // (b) resumed past the boundary under the inert v1.0.1-drill. Handing it the
        //     pre-announcement v1.0 binary is a DOWNGRADE and must be refused — the
        //     frozen digests are byte-identical here, so this is exactly the case
        //     `frozen_digest_hex` equality could not distinguish.
        let resumed = resumed_marker_at(DRILL_HALT_HEIGHT, &resume());
        assert_eq!(
            REVISION_V1_0.frozen_digest_hex, REVISION_V1_0_1_DRILL.frozen_digest_hex,
            "precondition: the upgrade is inert, so the FROZEN digests match"
        );
        let downgrade = routine(REVISION_V1_0);
        assert!(matches!(
            downgrade.check_against_marker(Some(&resumed)),
            Err(ReleaseError::UndeclaredResume { marked, in_force_revision, carried_revision, .. })
                if marked == DRILL_HALT_HEIGHT
                    && in_force_revision == "v1.0.1-drill"
                    && carried_revision == "v1.0"
        ));
        // …and a binary carrying no revision at all is refused on both.
        let norev = Release { revision: None, ..routine(REVISION_V1_0) };
        for m in [&halted, &resumed] {
            assert_eq!(
                norev.check_against_marker(Some(m)),
                Err(ReleaseError::ResumeWithoutRevision { height: DRILL_HALT_HEIGHT })
            );
        }
        // A deliberate downgrade is still possible — it just has to say so out loud.
        let deliberate = Release {
            name: "test-deliberate-downgrade",
            resumes_from: Some(DRILL_HALT_HEIGHT),
            ..routine(REVISION_V1_0)
        };
        assert_eq!(deliberate.check_against_marker(Some(&resumed)), Ok(()));
        assert!(deliberate.supersedes(&resumed), "and it records itself as now in force");
    }

    /// **🎯 #81 point 2 — pre-existing markers.** A marker written under the
    /// height-keyed scheme carries no statement of which revision is *in force*, only
    /// which one halted, and on a resumed data dir those differ with nothing on disk
    /// to say which case applies. It is refused with a reason that names the height and
    /// the remedy — never migrated by guesswork, never read as "no marker", and never
    /// allowed to fall through to a fresh start.
    #[test]
    fn a_pre_81_height_scheme_marker_is_refused_with_a_reason() {
        // Exactly what #74 wrote: the four original fields, no `schema`, no `resumed`.
        let old = r#"
            height = 16
            revision_id = "v1.0"
            frozen_digest_hex = "19564ecaffd8f78e69b31840cf465b3b34553968813f7fcaff83194077534571"
            boundary_finalized = true
        "#;
        let m: HaltMarker = toml::from_str(old).expect("a pre-#81 marker still PARSES");
        assert_eq!(m.schema, 0, "absent schema reads as 0, not as the current one");
        assert!(!m.resumed);

        // Every binary is refused, including the one that would otherwise match.
        for r in [armed(), resume(), routine(REVISION_V1_0), routine(REVISION_V1_0_1_DRILL)] {
            let err = r.check_against_marker(Some(&m));
            assert!(
                matches!(
                    err,
                    Err(ReleaseError::UnknownMarkerSchema { found: 0, expected: 1, marked: 16 })
                ),
                "{}: expected a schema refusal, got {err:?}",
                r.name
            );
            let msg = err.unwrap_err().to_string();
            assert!(msg.contains("schema 0"), "the message names the schema: {msg}");
            assert!(msg.contains("resumes_from=16"), "…and the remedy: {msg}");
            assert!(!r.supersedes(&m), "an uninterpretable marker is never rewritten");
        }
        // And it never silently becomes a fresh start: a schema-0 marker is refused
        // even where a MISSING marker would have been fine.
        assert_eq!(routine(REVISION_V1_0).check_against_marker(None), Ok(()));
    }

    /// **🎯 #81's precondition.** The post-halt rule domain is mixed into the PoW
    /// value, so a routine release that started freely must apply the SAME domain as
    /// the binary that performed the upgrade — otherwise it rejects every block above
    /// the boundary and forks. It reads the boundary and the domain off the marker.
    #[test]
    fn a_routine_release_inherits_the_post_halt_domain_from_the_marker() {
        let up = resume();
        let m = resumed_marker_at(DRILL_HALT_HEIGHT, &up);
        let later = routine(REVISION_V1_0_1_DRILL);

        // On its own the later release knows of no boundary at all — this is the fork.
        assert_eq!(later.rule_schedule().unwrap().post_halt, None);
        // Against the marker it reconstructs the upgrading binary's schedule exactly.
        let inherited = later.rule_schedule_on(Some(&m)).unwrap();
        let upgraders = up.rule_schedule_on(Some(&m)).unwrap();
        assert_eq!(
            inherited.post_halt,
            Some(PostHaltRules {
                from_height: DRILL_HALT_HEIGHT,
                domain: REVISION_V1_0_1_DRILL.digest(),
            })
        );
        assert_eq!(
            inherited.post_halt, upgraders.post_halt,
            "the routine release and the upgrade binary must agree block-for-block \
             above the boundary, or the PoW domain forks them"
        );
        assert_eq!(inherited.halt_at(), None, "…while still halting nowhere itself");
        assert_eq!(inherited.domain_at(DRILL_HALT_HEIGHT), None, "rules unchanged at/below H");
        assert_eq!(
            inherited.domain_at(DRILL_HALT_HEIGHT + 1),
            Some(&REVISION_V1_0_1_DRILL.digest())
        );

        // A marker that has NOT been resumed grants no domain: nothing above the
        // boundary exists yet, and the halted binary's rules still stand.
        assert_eq!(later.rule_schedule_on(Some(&marker_at(DRILL_HALT_HEIGHT))).unwrap().post_halt, None);
        // Nor does a marker naming a revision this binary does not carry.
        assert_eq!(routine(REVISION_V1_0).rule_schedule_on(Some(&m)).unwrap().post_halt, None);
        // A schema-0 marker grants no domain either (it is refused upstream anyway).
        assert_eq!(
            later.rule_schedule_on(Some(&HaltMarker { schema: 0, ..m.clone() })).unwrap().post_halt,
            None
        );
        // And a transitioning binary's OWN declaration wins — it is the one changing
        // the rules, so the marker cannot pin it to the revision it is replacing.
        let second = Release {
            name: "test-second-upgrade",
            plan: HaltPlan::None,
            revision: Some(REVISION_V1_0),
            resumes_from: Some(DRILL_HALT_HEIGHT),
        };
        assert_eq!(
            second.rule_schedule_on(Some(&m)).unwrap().post_halt,
            Some(PostHaltRules {
                from_height: DRILL_HALT_HEIGHT,
                domain: REVISION_V1_0.digest(),
            })
        );
    }

    /// The marker rewrite is the mechanism's memory, so pin exactly when it fires:
    /// on a declared transition, and never on an ordinary restart.
    #[test]
    fn the_marker_is_rewritten_on_a_transition_and_not_on_a_restart() {
        let halted = marker_at(DRILL_HALT_HEIGHT);
        let up = resume();
        assert!(up.supersedes(&halted), "the declared upgrade advances the marker");

        let advanced = halted.superseded_by(&up);
        assert_eq!(advanced.height, halted.height, "the boundary height never moves");
        assert_eq!(advanced.boundary_finalized, halted.boundary_finalized, "audit preserved");
        assert!(advanced.resumed);
        assert_eq!(advanced.in_force_digest(), REVISION_V1_0_1_DRILL.digest());

        // Restarting the upgraded binary is not a second transition.
        assert!(!up.supersedes(&advanced), "no redundant fsync, no second log line");
        assert_eq!(up.check_against_marker(Some(&advanced)), Ok(()));
        // Neither is restarting the halted binary on the halted marker (it cannot go
        // past the boundary at all).
        assert!(!armed().supersedes(&halted));
        // Idempotence: advancing twice with the same release is a fixed point.
        assert_eq!(advanced.superseded_by(&up), advanced);
    }

    /// The banner must not read a **resumed** marker as "halted here" — after an
    /// upgrade the height is the boundary the data dir PASSED, which is a different
    /// sentence, and the operator reads this line to decide whether to swap binaries.
    #[test]
    fn the_banner_distinguishes_halted_at_from_passed_through() {
        let halted = armed().banner(Some(&marker_at(DRILL_HALT_HEIGHT)));
        assert!(halted.contains("HALTED at height 16"), "{halted}");
        assert!(!halted.contains("PASSED"), "{halted}");

        let passed = routine(REVISION_V1_0_1_DRILL)
            .banner(Some(&resumed_marker_at(DRILL_HALT_HEIGHT, &resume())));
        assert!(passed.contains("PASSED the upgrade boundary at height 16"), "{passed}");
        assert!(passed.contains("revision in force `v1.0.1-drill`"), "{passed}");
        assert!(!passed.contains("HALTED at"), "{passed}");
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
