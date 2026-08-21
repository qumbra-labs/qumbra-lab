//! Genesis-format keying — the value type of the ONE selection point (lab #470,
//! T2 mint combo stage 0).
//!
//! ## The law this type encodes
//!
//! `main` serves two nets from one tree: **T1** (live, public, genesis format
//! v4) and **T2** (the mint this baton builds, genesis format v5). Every T2
//! consensus format — header layout, body-commitment form, coinbase form, rule
//! schedule — is keyed off **the genesis file's format version**, selected
//! exactly once at genesis load and fanned out from there. Per-call-site
//! version sniffing is a stop-point by the task book; call sites receive this
//! value (or a rules object carrying it) as an argument, the way the `_above`
//! seams already receive their boundary.
//!
//! ## Why the selector is sound against H1
//!
//! H1 (`run.rs`, `release.rs`) says consensus boundaries are unreachable from
//! config/CLI/environment. The genesis format version does not weaken that: it
//! is a field of the genesis file, which is inside the genesis hash — the
//! network identity every node pins as `expected_genesis_hash` and refuses to
//! start without. An operator cannot select forms any more freely than they
//! can select which network they are on, because it is the same choice.
//!
//! ## Stage 0 status
//!
//! This type and its mapping are the whole stage-0 plumbing: no consumer reads
//! it yet, and no behavior changes on a v4 genesis. Consumers arrive per
//! stage — header form (stage 1), coinbase form (stage 2), body form + rule
//! schedule (stage 3), the v5 loader itself (stage 4). The coordinator reviews
//! the keying design before stage 1 begins.

use crate::halt::RuleSchedule;

/// The consensus form set a genesis file selects. One value, chosen at genesis
/// load, fanning out to header-form, body-form, coinbase-form and
/// rule-schedule choices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenesisForm {
    /// Genesis format **v4** — the live T1 net (`138e1524…addb`): 98-byte
    /// header (nonce at offset 56), body v2 below/at the name boundary and v3
    /// above it, single-`rkm` coinbase, f64 emission below the emission
    /// boundary with the glibc pins and the height-1377 scar above genesis.
    /// Byte-identical to today's `main` — every existing golden is the lock.
    V4,
    /// Genesis format **v5** — T2 (lab #470): stratum-compatible header
    /// (version byte + u48 height at 32–38, nonce u64 at 39–46), one body
    /// form from height 0 carrying the C3 hygiene batch, payee-list coinbase
    /// with the cap at 1, and exact emission + the name rule native from
    /// height 0 — no boundary, no pins, no scar.
    V5,
}

impl GenesisForm {
    /// Map a genesis file's `format_version` to its form set. `None` for
    /// versions this tree does not serve (v1–v3 are refused-with-a-reason
    /// history; anything above 5 is a later tree's business).
    pub fn from_genesis_format_version(v: u32) -> Option<GenesisForm> {
        match v {
            4 => Some(GenesisForm::V4),
            5 => Some(GenesisForm::V5),
            _ => None,
        }
    }

    /// The genesis-file `format_version` this form set is keyed to.
    pub fn genesis_format_version(self) -> u32 {
        match self {
            GenesisForm::V4 => 4,
            GenesisForm::V5 => 5,
        }
    }

    /// The height at and above which the name-service rules are in force on this
    /// form — the single honest source for the `boundary_height` an observer
    /// serves.
    ///
    /// - **V4** (T1): the name rule is halt-keyed, active only above
    ///   [`crate::names::NAME_RULE_BOUNDARY_HEIGHT`] — that constant, verbatim.
    /// - **V5** (T2): the name rule is **native from height 0**; there is no
    ///   boundary. `None` is the honest answer — the "future net" the explorer's
    ///   `boundary_height` field was documented to render as `null`, never a
    ///   fabricated height carried over from T1's lineage.
    pub fn name_boundary(self) -> Option<u64> {
        match self {
            GenesisForm::V4 => crate::names::NAME_RULE_BOUNDARY_HEIGHT,
            GenesisForm::V5 => None,
        }
    }

    /// The `boundary` the **mempool** passes to
    /// [`crate::names::names_admit_op_above`] — the admission twin of the body
    /// rule in [`crate::body::validate_body_form`], and it must match it exactly:
    ///
    /// - **V4**: [`crate::names::NAME_RULE_BOUNDARY_HEIGHT`], as `validate_body`'s
    ///   v4 arm uses.
    /// - **V5**: `Some(0)`, NOT `None`. The v5 body rule is `header.height > 0`
    ///   (`body.rs`, C4: names native from height ≥ 1), which is exactly
    ///   [`crate::names::riders_active_above`]`(Some(0), h)`. `None` would mean
    ///   "riders never active" and refuse every T2 name op with
    ///   `RiderBeforeBoundary` — the bug this method exists to prevent.
    ///
    /// **This differs deliberately from [`Self::name_boundary`]**, which answers
    /// the *observer/display* question ("what boundary height to show", `None`
    /// on a native net → `null`). Admission needs the *rule*, not the label.
    pub fn rider_admit_boundary(self) -> Option<u64> {
        match self {
            GenesisForm::V4 => crate::names::NAME_RULE_BOUNDARY_HEIGHT,
            GenesisForm::V5 => Some(0),
        }
    }
}

/// The complete rule/form context a running node enforces — **the carrier of
/// the one selection point** (lab #470 stage 1, coordinator ruling Q2: a
/// sibling beside [`RuleSchedule`], not a widening of it).
///
/// Two fields, two sources, one installation:
///
/// - [`form`](Self::form) ← **the network identity**: the genesis file's
///   `format_version`, inside the genesis hash, pinned by
///   `expected_genesis_hash`. Selecting a form IS selecting a net.
/// - [`halt`](Self::halt) ← **the release constant + the halt marker**
///   (#74/#81), exactly as before — its semantics are untouched.
///
/// Assembled once in `qumbra-node`'s startup and handed to the node in the
/// same act that installed [`RuleSchedule`] alone before; there is still no
/// setter reachable from config, CLI, or environment (H1 — see the Q1 ruling
/// on lab #470 for why a genesis-keyed form does not weaken it).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ChainRules {
    /// The genesis-format-keyed consensus form set. Defaults to [`GenesisForm::V4`]
    /// so every existing sim/test — none of which loads a genesis file — keeps
    /// today's forms by construction, the same way [`RuleSchedule::V1_0`] keeps
    /// them on the v1.0 rules.
    pub form: GenesisForm,
    /// The halt/upgrade schedule (#74/#81), unchanged in meaning.
    pub halt: RuleSchedule,
}

impl Default for GenesisForm {
    fn default() -> Self {
        GenesisForm::V4
    }
}

impl ChainRules {
    /// The v1.0 context: v4 forms, no halt scheduled, no post-halt domain —
    /// what every in-process sim and test runs under.
    pub const V1_0: ChainRules = ChainRules { form: GenesisForm::V4, halt: RuleSchedule::V1_0 };

    /// A v4-form context over an explicit halt schedule — the shape every
    /// pre-T2 caller (drills included) means.
    pub fn v4(halt: RuleSchedule) -> Self {
        ChainRules { form: GenesisForm::V4, halt }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_context_is_v4_v1_0() {
        assert_eq!(ChainRules::default(), ChainRules::V1_0);
        assert_eq!(ChainRules::V1_0.form, GenesisForm::V4);
        assert_eq!(ChainRules::V1_0.halt, RuleSchedule::V1_0);
        assert_eq!(ChainRules::v4(RuleSchedule::V1_0), ChainRules::V1_0);
    }

    #[test]
    fn maps_exactly_v4_and_v5_and_nothing_else() {
        assert_eq!(GenesisForm::from_genesis_format_version(4), Some(GenesisForm::V4));
        assert_eq!(GenesisForm::from_genesis_format_version(5), Some(GenesisForm::V5));
        for v in [0u32, 1, 2, 3, 6, 7, u32::MAX] {
            assert_eq!(GenesisForm::from_genesis_format_version(v), None, "v{v} must not map");
        }
    }

    #[test]
    fn rider_admit_boundary_mirrors_the_body_rule_v5_is_some_zero_not_none() {
        // The mempool admission boundary must equal what validate_body_form
        // enforces: V4 → the shipped boundary; V5 → Some(0) (≡ height > 0), so
        // riders_active_above agrees with the v5 body's `header.height > 0`.
        assert_eq!(GenesisForm::V4.rider_admit_boundary(), crate::names::NAME_RULE_BOUNDARY_HEIGHT);
        assert_eq!(GenesisForm::V5.rider_admit_boundary(), Some(0));
        // The exact rule equivalence, and the bug it prevents: Some(0) admits a
        // rider above genesis; None (the display boundary) would refuse it.
        assert!(crate::names::riders_active_above(GenesisForm::V5.rider_admit_boundary(), 1));
        assert!(!crate::names::riders_active_above(GenesisForm::V5.name_boundary(), 1));
    }

    #[test]
    fn name_boundary_is_the_t1_constant_on_v4_and_native_on_v5() {
        // V4 serves T1's halt-keyed boundary verbatim; V5 (T2, names native
        // from height 0) has no boundary and must answer None so an observer
        // renders `null`, never T1's 19,008 carried onto a native-names net.
        assert_eq!(GenesisForm::V4.name_boundary(), crate::names::NAME_RULE_BOUNDARY_HEIGHT);
        assert_eq!(GenesisForm::V5.name_boundary(), None);
    }

    #[test]
    fn round_trips_through_the_format_version() {
        for form in [GenesisForm::V4, GenesisForm::V5] {
            assert_eq!(
                GenesisForm::from_genesis_format_version(form.genesis_format_version()),
                Some(form)
            );
        }
    }
}
