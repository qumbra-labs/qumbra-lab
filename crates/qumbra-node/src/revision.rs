//! **The revision digest** (issue #74, H4) — the machine-checkable half of Larry's
//! standing rule that the FROZEN v1.0 set changes *only* via a halt-height upgrade
//! carrying its own revision doc, **never silently**.
//!
//! Before this module the rule was honoured by discipline: two prose comments
//! (`qlab-consensus/src/lib.rs`, `genesis.rs`) and a coordinator's memory. A
//! free-text revision identifier would not have fixed that — a string can be copied
//! across a change it does not describe. A **digest over the frozen parameter set**
//! cannot: alter a frozen constant without minting a new revision and the binary
//! reports a mismatch, at every startup, in every log.
//!
//! # Exactly which constants the digest covers, and why
//!
//! The digest input is [`crate::genesis::FrozenParams`] — the FROZEN v1.0 constant
//! table baked into the genesis file (consensus-parameters, GENESIS FREEZE v1.0
//! 2026-07-23) — **minus one deliberately excluded field**:
//!
//! | Covered | Fields |
//! |---|---|
//! | §1 proof/consensus | `consensus_fri`, `log_height`, `consensus_wire_bytes`, `agg_leaf_lane`, `agg_interior_lane`, `consensus_hash`, `tree_depth` |
//! | §2 emission | `block_time_secs`, `bessel_per_qmb`, `r0_qmb`, `decay_d`, `tail_qmb`, `coinbase_maturity_blocks`, `hard_cap` |
//! | §3 reward split | `split_miner_pct`, `split_committee_pct`, `split_treasury_pct` |
//! | §4 committee/staking | `committee_size`, `quorum`, `epoch_length_blocks`, `self_bond_qmb_steady`, `bond_ramp_qmb`, `equivocation_slash_pct`, `downtime_jail_threshold_pct`, `downtime_jail_window` |
//! | §5 fees | `fee_2x2_bessel`, `fee_4x4_bessel`, `fee_8x8_bessel` |
//! | §6 block weight | `weight_free_zone_bytes`, `weight_hard_cap_multiple`, `weight_long_window`, `weight_lt_cap_num`, `weight_lt_cap_den`, `weight_st_cap` |
//! | §7 anchors | `anchor_max_age_blocks`, `anchor_bucket_blocks`, `anchor_retained_roots` |
//! | §8 denomination | `ticker` |
//!
//! **Excluded, on purpose: `checkpoint_cadence_blocks_not_frozen`.** It is the one
//! field of `FrozenParams` that is explicitly *not* frozen — protocol-spec §7 flags
//! the cadence `[full-M8]`, and `genesis.rs` records it only so a rehearsal net
//! agrees on it. Covering it would make the digest claim frozenness the value does
//! not have, and would demand a revision document for a legitimately tunable knob —
//! which is precisely how digest discipline dies: an operator who has to bump the
//! revision for routine changes learns that bumping the revision means nothing.
//! (The cadence is not unguarded: [`qlab_devnet::halt::HaltPlan::validate`] binds
//! the halt height to it at every startup.)
//!
//! **Also NOT covered, and deliberately so — this is the "worse than none" list:**
//!
//! - **committee₀'s 21 verifying keys, the genesis block, the genesis difficulty,
//!   and the network label.** These are covered by a different and already-existing
//!   pin, the genesis hash (`138e1524…addb` since the mint — see `genesis.rs`),
//!   which every node asserts on startup.
//!   Two overlapping pins on the same bytes would be redundancy, not assurance.
//! - **Every `params_devnet` knob annotated testnet-tunable** (LWMA window/clamps,
//!   key-epoch schedule, degraded-mode lag, jail blocks, the tally caps). Not
//!   frozen; same reasoning as the cadence.
//! - **Code.** The digest covers the frozen *constant table*, not the logic that
//!   consumes it. A binary that keeps every frozen value and changes how it applies
//!   them produces an identical digest. That is a real limit, stated plainly: this
//!   mechanism makes an undocumented **parameter** change impossible-by-construction;
//!   it does not and cannot make an undocumented **rule** change impossible. The
//!   rule-change guard is the halt itself (a rule change must ship as an upgrade
//!   with its own halt height), not the digest.
//!
//! # 🔴 The code exclusion is a CONSTRAINT TO DEFEND, not a gap to close later
//!
//! The bullet above reads like a weakness waiting to be fixed. It is not. That same
//! property is what makes the gate usable, and the two jobs are inseparable:
//!
//! - as a **scoping limit** — the digest cannot catch an undocumented rule change;
//! - as an **enabling property** — a release that changes only code produces an
//!   *identical* digest, so it starts with no ceremony at all.
//!
//! Extending the digest over the consuming logic would look like a strengthening.
//! What it would actually do is make **every** release produce a different digest,
//! so every release would demand a declared transition — and the declaration would
//! stop meaning "the frozen parameter set moved" and start meaning "a release
//! happened". At that point an operator bumps the revision as routine paperwork, and
//! learns that bumping it means nothing.
//!
//! That is the same death this module already refuses on the other side: the
//! checkpoint cadence is excluded precisely because demanding a revision document
//! for a legitimately tunable knob teaches operators the ceremony is empty.
//! **Widening the digest kills it the same way, from the opposite direction.**
//!
//! So: if you are here to make the digest cover more, the burden is not "does this
//! close a gap" — it is "does the thing I am adding move *only* when the frozen
//! parameter set moves". If it moves on ordinary releases, it does not belong,
//! however much it looks like extra safety.
//!
//! (Coordinator decision, 2026-07-26, issue #74 review; carried into
//! [#81](https://github.com/qumbra-labs/qumbra-lab/issues/81), which makes the resume gate
//! key on digest equality — a change that depends on exactly this property, because
//! it is what lets an ordinary bug-fix release start without a declared transition.)
//!
//! # Why the encoder is exhaustive-by-construction
//!
//! [`frozen_digest`] destructures `FrozenParams` with **no `..` rest pattern**, so
//! adding a field to the frozen table fails to compile until an author decides,
//! explicitly, whether it belongs in the digest. A digest whose coverage can drift
//! silently is exactly the "looks like a guarantee" failure the task-book warns
//! about, and a compile error is the only guard that cannot be forgotten.

use qlab_devnet::hash::keccak256;
use qlab_devnet::header::Hash32;

use crate::genesis::{hex_encode, FrozenParams};

/// Domain tag for the frozen-parameter digest preimage.
pub const DIGEST_TAG: &[u8] = b"qumbra:frozen-params-digest:v1";

/// How many fields of [`FrozenParams`] the digest covers. Asserted against the
/// preimage below, so the two cannot drift apart.
pub const COVERED_FIELDS: usize = 38;

/// A canonical, self-describing encoder: every value is preceded by its field name,
/// and every variable-length item is length-prefixed, so no two distinct tables can
/// share a preimage by field-boundary ambiguity.
struct Preimage {
    buf: Vec<u8>,
    fields: usize,
}

impl Preimage {
    fn new() -> Self {
        let mut buf = Vec::with_capacity(1024);
        buf.extend_from_slice(DIGEST_TAG);
        Preimage { buf, fields: 0 }
    }
    /// Field header: name length, name bytes.
    fn name(&mut self, name: &str) {
        self.fields += 1;
        self.buf.extend_from_slice(&(name.len() as u64).to_le_bytes());
        self.buf.extend_from_slice(name.as_bytes());
    }
    fn u64(&mut self, name: &str, v: u64) {
        self.name(name);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, name: &str, v: u32) {
        self.name(name);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn bool(&mut self, name: &str, v: bool) {
        self.name(name);
        self.buf.push(v as u8);
    }
    /// f64 by exact bit pattern — no float formatting anywhere in the preimage.
    fn f64(&mut self, name: &str, v: f64) {
        self.name(name);
        self.buf.extend_from_slice(&v.to_bits().to_le_bytes());
    }
    fn str(&mut self, name: &str, v: &str) {
        self.name(name);
        self.buf.extend_from_slice(&(v.len() as u64).to_le_bytes());
        self.buf.extend_from_slice(v.as_bytes());
    }
    fn pairs(&mut self, name: &str, v: &[(u64, u64)]) {
        self.name(name);
        self.buf.extend_from_slice(&(v.len() as u64).to_le_bytes());
        for (a, b) in v {
            self.buf.extend_from_slice(&a.to_le_bytes());
            self.buf.extend_from_slice(&b.to_le_bytes());
        }
    }
}

/// The canonical digest preimage over the covered FROZEN v1.0 fields.
///
/// The destructuring below has **no `..`**: adding a field to [`FrozenParams`]
/// breaks this function's compilation until someone decides whether the new field
/// is frozen (add a line) or not (bind it to an `_excluded_*` name and say why).
///
/// **Before adding anything here, read the "constraint to defend" section in the
/// module doc.** The test is not "would covering this catch more"; it is "does this
/// value move *only* when the frozen parameter set moves". Anything that also moves
/// on an ordinary release turns the revision declaration into paperwork, and
/// paperwork is how this gate stops being a gate.
fn preimage(p: &FrozenParams) -> Preimage {
    let FrozenParams {
        // §1 proof / consensus
        consensus_fri,
        log_height,
        consensus_wire_bytes,
        agg_leaf_lane,
        agg_interior_lane,
        consensus_hash,
        tree_depth,
        // §2 emission
        block_time_secs,
        bessel_per_qmb,
        r0_qmb,
        decay_d,
        tail_qmb,
        coinbase_maturity_blocks,
        hard_cap,
        // §3 reward split
        split_miner_pct,
        split_committee_pct,
        split_treasury_pct,
        // §4 committee / staking
        committee_size,
        quorum,
        epoch_length_blocks,
        self_bond_qmb_steady,
        bond_ramp_qmb,
        equivocation_slash_pct,
        downtime_jail_threshold_pct,
        downtime_jail_window,
        // §5 fees
        fee_2x2_bessel,
        fee_4x4_bessel,
        fee_8x8_bessel,
        // §6 block-weight anti-spam
        weight_free_zone_bytes,
        weight_hard_cap_multiple,
        weight_long_window,
        weight_lt_cap_num,
        weight_lt_cap_den,
        weight_st_cap,
        // §7 anchors
        anchor_max_age_blocks,
        anchor_bucket_blocks,
        anchor_retained_roots,
        // §8 denomination
        ticker,
        // ── EXCLUDED — explicitly NOT frozen (protocol-spec §7 `[full-M8]`). See
        //    the module doc: covering a tunable value would teach operators that a
        //    revision bump means nothing. Guarded instead by the cadence-grid rule.
        checkpoint_cadence_blocks_not_frozen: _excluded_not_frozen_cadence,
    } = p;

    let mut w = Preimage::new();
    // §1
    w.str("consensus_fri", consensus_fri);
    w.u32("log_height", *log_height);
    w.u64("consensus_wire_bytes", *consensus_wire_bytes);
    w.str("agg_leaf_lane", agg_leaf_lane);
    w.str("agg_interior_lane", agg_interior_lane);
    w.str("consensus_hash", consensus_hash);
    w.u32("tree_depth", *tree_depth);
    // §2
    w.u64("block_time_secs", *block_time_secs);
    w.u64("bessel_per_qmb", *bessel_per_qmb);
    w.f64("r0_qmb", *r0_qmb);
    w.f64("decay_d", *decay_d);
    w.f64("tail_qmb", *tail_qmb);
    w.u64("coinbase_maturity_blocks", *coinbase_maturity_blocks);
    w.bool("hard_cap", *hard_cap);
    // §3
    w.u64("split_miner_pct", *split_miner_pct);
    w.u64("split_committee_pct", *split_committee_pct);
    w.u64("split_treasury_pct", *split_treasury_pct);
    // §4
    w.u32("committee_size", *committee_size);
    w.u32("quorum", *quorum);
    w.u64("epoch_length_blocks", *epoch_length_blocks);
    w.u64("self_bond_qmb_steady", *self_bond_qmb_steady);
    w.pairs("bond_ramp_qmb", bond_ramp_qmb);
    w.u64("equivocation_slash_pct", *equivocation_slash_pct);
    w.u64("downtime_jail_threshold_pct", *downtime_jail_threshold_pct);
    w.u64("downtime_jail_window", *downtime_jail_window);
    // §5
    w.u64("fee_2x2_bessel", *fee_2x2_bessel);
    w.u64("fee_4x4_bessel", *fee_4x4_bessel);
    w.u64("fee_8x8_bessel", *fee_8x8_bessel);
    // §6
    w.u64("weight_free_zone_bytes", *weight_free_zone_bytes);
    w.u64("weight_hard_cap_multiple", *weight_hard_cap_multiple);
    w.u64("weight_long_window", *weight_long_window);
    w.u64("weight_lt_cap_num", *weight_lt_cap_num);
    w.u64("weight_lt_cap_den", *weight_lt_cap_den);
    w.u64("weight_st_cap", *weight_st_cap);
    // §7
    w.u64("anchor_max_age_blocks", *anchor_max_age_blocks);
    w.u64("anchor_bucket_blocks", *anchor_bucket_blocks);
    w.u64("anchor_retained_roots", *anchor_retained_roots);
    // §8
    w.str("ticker", ticker);
    w
}

/// The digest over the covered FROZEN v1.0 constants of `p`.
pub fn frozen_digest(p: &FrozenParams) -> Hash32 {
    keccak256(&preimage(p).buf)
}

/// [`frozen_digest`] over **this binary's own compiled-in** frozen constants — the
/// value every gate compares against. `FrozenParams::v1_0()` sources its fields
/// from the single-source code constants, so this is a digest of the binary, not of
/// a file it happens to have loaded.
pub fn own_frozen_digest() -> Hash32 {
    frozen_digest(&FrozenParams::v1_0())
}

/// Hex form of [`own_frozen_digest`].
pub fn own_frozen_digest_hex() -> String {
    hex_encode(&own_frozen_digest())
}

/// A revision this binary carries: the identifier that names its revision document,
/// bound to the digest of the frozen set that revision describes.
///
/// Both halves matter and neither substitutes for the other. The identifier is what
/// an operator reads and what the revision document is filed under; the digest is
/// what makes the identifier *true*.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Revision {
    /// Human identifier naming the revision document, e.g. `"v1.0.1-drill"`.
    pub id: &'static str,
    /// Hex digest of the frozen parameter set this revision describes. Checked
    /// against [`own_frozen_digest`] at every startup.
    pub frozen_digest_hex: &'static str,
}

/// Why a revision does not describe the binary carrying it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevisionError {
    /// The revision's digest does not match this binary's frozen constants — a
    /// frozen value moved without a corresponding revision, or a revision was
    /// copied across a change it does not describe. Either way the binary refuses.
    DigestMismatch { id: String, declared: String, actual: String },
    /// A revision with an empty identifier is not a revision.
    EmptyId,
}

impl std::fmt::Display for RevisionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RevisionError::DigestMismatch { id, declared, actual } => write!(
                f,
                "revision `{id}` declares frozen-parameter digest {declared} but this binary's \
                 frozen constants digest to {actual} — a FROZEN v1.0 value changed without a \
                 revision that describes it (or the revision was copied across a change it does \
                 not describe)"
            ),
            RevisionError::EmptyId => write!(f, "revision identifier is empty"),
        }
    }
}
impl std::error::Error for RevisionError {}

/// Domain tag for [`Revision::digest`].
pub const REVISION_TAG: &[u8] = b"qumbra:revision:v1";

/// The revision digest over a borrowed `(id, frozen_digest_hex)` pair.
///
/// [`Revision`] holds `&'static str`s because it is a compile-time constant, but the
/// halt marker holds the same two values as `String`s read back from disk (issue
/// #81: the marker records the revision **in force** on the data dir). Both must
/// produce the identical 32 bytes or the resume gate would compare a binary against
/// a re-encoding of itself, so there is exactly one preimage definition and
/// [`Revision::digest`] delegates to it.
pub fn revision_digest(id: &str, frozen_digest_hex: &str) -> Hash32 {
    let mut buf = Vec::with_capacity(REVISION_TAG.len() + 8 + id.len() + 64);
    buf.extend_from_slice(REVISION_TAG);
    buf.extend_from_slice(&(id.len() as u64).to_le_bytes());
    buf.extend_from_slice(id.as_bytes());
    buf.extend_from_slice(frozen_digest_hex.to_ascii_lowercase().as_bytes());
    keccak256(&buf)
}

impl Revision {
    /// The **revision digest**: this revision's identity as a 32-byte value,
    /// binding *both* the identifier and the frozen-parameter digest it claims.
    ///
    /// This — not the bare frozen digest — is what a resumed release uses as its
    /// post-halt rule domain ([`qlab_devnet::halt::PostHaltRules`]), and (since
    /// #81) what the resume gate compares against the marker. The reason is the
    /// same in both places, H5: an *inert* revision changes no frozen value, so
    /// consecutive inert revisions share a frozen digest. Binding the identifier as
    /// well guarantees distinct revisions are distinct rule sets, which is what the
    /// upgrade boundary needs in order to be a boundary at all — and what lets the
    /// gate still refuse the pre-announcement binary after an inert upgrade.
    pub fn digest(&self) -> Hash32 {
        revision_digest(self.id, self.frozen_digest_hex)
    }

    /// Hex form of [`Self::digest`].
    pub fn digest_hex(&self) -> String {
        hex_encode(&self.digest())
    }

    /// The gate: this revision must describe *this* binary's frozen constants.
    pub fn verify(&self) -> Result<(), RevisionError> {
        if self.id.is_empty() {
            return Err(RevisionError::EmptyId);
        }
        let actual = own_frozen_digest_hex();
        if !self.frozen_digest_hex.eq_ignore_ascii_case(&actual) {
            return Err(RevisionError::DigestMismatch {
                id: self.id.to_string(),
                declared: self.frozen_digest_hex.to_string(),
                actual,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The digest is pinned. This value is a function of the entire covered FROZEN
    /// v1.0 table; any drift in a frozen constant lands here, at every startup of
    /// every binary, and a deliberate change must bump this pin **and** mint a
    /// revision that names the delta. That pairing is the whole mechanism.
    #[test]
    fn frozen_digest_is_pinned() {
        // 🔴 Moved by the mint (issue #215 (i) / #219): `CONSENSUS_WIRE_BYTES`
        // 145,609 → 148,625 is a covered field, so the digest MUST move — this
        // test firing is the evidence the frozen set actually changed, exactly as
        // `sensitivity` below says every covered field should behave.
        //   pre-mint: 19564ecaffd8f78e69b31840cf465b3b34553968813f7fcaff83194077534571
        // 🔴 Moved again by the The security re-mint: wire 148,625 →
        // 182,745 and `consensus_fri` + "/zk". From the named `halt-status` runs ×2.
        //   pre-re-mint: a54e73ce3d1c4fe9984d06b08f99b7577ed1db452b87abd712cf85ce5f3e7b5b
        // 🔴 Moved by re-genesis batch 2 (lab #747): rc 4 → 0 — wire 182,745 →
        // 178,681 and `consensus_fri` "/zk" → "/zk/rc0". From this tree's
        // `halt-status` (recomputed line), the named runs.
        //   batch 1: 22ae5ad93a1208ae5d312492ad34de168e11beca5b69ba74339fbf17da4bbd6e
        assert_eq!(
            own_frozen_digest_hex(),
            "ead6e181afc5ef1c309cb3abd1021ca9a82e750ac51d8090fa4923956d37aba4",
        );
    }

    #[test]
    fn digest_is_deterministic_and_covers_the_declared_field_count() {
        let p = FrozenParams::v1_0();
        assert_eq!(frozen_digest(&p), frozen_digest(&p));
        assert_eq!(
            preimage(&p).fields,
            COVERED_FIELDS,
            "COVERED_FIELDS must equal the number of fields actually written into \
             the preimage — if this fails, a field was added to the encoder without \
             updating the documented coverage table"
        );
    }

    /// Sensitivity: **every covered field** moves the digest. A digest that ignored
    /// even one frozen value would be worse than none — it would look like a
    /// guarantee over the whole table while silently exempting a constant.
    #[test]
    fn every_covered_field_changes_the_digest() {
        let base = FrozenParams::v1_0();
        let d0 = frozen_digest(&base);

        macro_rules! moved {
            ($field:ident, $new:expr) => {{
                let mut p = base.clone();
                p.$field = $new;
                assert_ne!(p.$field, base.$field, concat!(stringify!($field), ": test mutation is a no-op"));
                assert_ne!(
                    frozen_digest(&p),
                    d0,
                    concat!("digest must move when ", stringify!($field), " changes")
                );
            }};
        }

        // §1
        moved!(consensus_fri, "b16/q22/g22/fp16/a16".to_string());
        moved!(log_height, 19);
        moved!(consensus_wire_bytes, 145_610);
        moved!(agg_leaf_lane, "b4/q44/g22".to_string());
        moved!(agg_interior_lane, "b2/q87/g22".to_string());
        moved!(consensus_hash, "sha3-256".to_string());
        moved!(tree_depth, 33);
        // §2
        moved!(block_time_secs, 76);
        moved!(bessel_per_qmb, 10_000_000);
        moved!(r0_qmb, 50.000_000_1);
        moved!(decay_d, 8.238e-7);
        moved!(tail_qmb, 1.224_42);
        moved!(coinbase_maturity_blocks, 145);
        moved!(hard_cap, true);
        // §3
        moved!(split_miner_pct, 66);
        moved!(split_committee_pct, 14);
        moved!(split_treasury_pct, 21);
        // §4
        moved!(committee_size, 22);
        moved!(quorum, 16);
        moved!(epoch_length_blocks, 1_153);
        moved!(self_bond_qmb_steady, 10_001);
        moved!(bond_ramp_qmb, vec![(0, 0), (90, 100), (180, 1_000), (360, 10_001)]);
        moved!(equivocation_slash_pct, 11);
        moved!(downtime_jail_threshold_pct, 34);
        moved!(downtime_jail_window, 101);
        // §5
        moved!(fee_2x2_bessel, 1_000_001);
        moved!(fee_4x4_bessel, 2_000_001);
        moved!(fee_8x8_bessel, 4_000_001);
        // §6
        moved!(weight_free_zone_bytes, 10_000_001);
        moved!(weight_hard_cap_multiple, 3);
        moved!(weight_long_window, 100_001);
        moved!(weight_lt_cap_num, 8);
        moved!(weight_lt_cap_den, 6);
        moved!(weight_st_cap, 51);
        // §7
        moved!(anchor_max_age_blocks, 1_153);
        moved!(anchor_bucket_blocks, 9);
        moved!(anchor_retained_roots, 145);
        // §8
        moved!(ticker, "QMX".to_string());
    }

    /// The one deliberate exclusion, asserted as such: moving the explicitly
    /// NOT-frozen cadence field does **not** move the digest. If someone freezes the
    /// cadence later, this test is the place that must change — deliberately.
    #[test]
    fn the_not_frozen_cadence_field_is_excluded() {
        let base = FrozenParams::v1_0();
        let mut p = base.clone();
        p.checkpoint_cadence_blocks_not_frozen = 16;
        assert_ne!(p.checkpoint_cadence_blocks_not_frozen, base.checkpoint_cadence_blocks_not_frozen);
        assert_eq!(
            frozen_digest(&p),
            frozen_digest(&base),
            "the cadence is explicitly NOT frozen (protocol-spec §7 [full-M8]); the digest \
             must not claim frozenness it does not have"
        );
    }

    /// Field-boundary ambiguity: two tables that differ only in *which* field holds
    /// a value must not share a preimage. The name-prefixed encoding is what buys
    /// this; the test pins it.
    #[test]
    fn swapping_two_equal_width_fields_changes_the_digest() {
        let base = FrozenParams::v1_0();
        let mut p = base.clone();
        std::mem::swap(&mut p.fee_2x2_bessel, &mut p.fee_4x4_bessel);
        assert_ne!(frozen_digest(&p), frozen_digest(&base));
        let mut q = base.clone();
        std::mem::swap(&mut q.split_miner_pct, &mut q.split_treasury_pct);
        assert_ne!(frozen_digest(&q), frozen_digest(&base));
    }

    /// #81: the borrowed-`&str` digest and the `Revision` digest are the same 32
    /// bytes, including across ASCII-case differences in the hex. The resume gate
    /// compares a compile-time `Revision` against two `String`s read off disk, so a
    /// divergence here would make a binary fail to recognise its own revision.
    #[test]
    fn the_borrowed_revision_digest_matches_the_constants_digest() {
        assert_eq!(
            revision_digest(REVISION_V1_0_ID_FOR_TEST, &own_frozen_digest_hex()),
            Revision {
                id: REVISION_V1_0_ID_FOR_TEST,
                frozen_digest_hex: Box::leak(own_frozen_digest_hex().into_boxed_str()),
            }
            .digest(),
        );
        // The marker stores whatever hex the halting binary carried; case must not
        // change the identity.
        assert_eq!(
            revision_digest("v1.0", &own_frozen_digest_hex().to_uppercase()),
            revision_digest("v1.0", &own_frozen_digest_hex()),
        );
        // …but the identifier is part of the identity, so inert revisions differ.
        assert_ne!(
            revision_digest("v1.0", &own_frozen_digest_hex()),
            revision_digest("v1.0.1-drill", &own_frozen_digest_hex()),
        );
    }
    const REVISION_V1_0_ID_FOR_TEST: &str = "v1.0";

    /// The rule-domain property H5 depends on: two **inert** revisions (same frozen
    /// digest, different identifier) must still be distinct rule sets, or a second
    /// no-op upgrade would have no boundary at all.
    #[test]
    fn distinct_identifiers_are_distinct_rule_domains_even_when_inert() {
        let frozen: &'static str = Box::leak(own_frozen_digest_hex().into_boxed_str());
        let a = Revision { id: "v1.0", frozen_digest_hex: frozen };
        let b = Revision { id: "v1.0.1-drill", frozen_digest_hex: frozen };
        assert_eq!(a.frozen_digest_hex, b.frozen_digest_hex, "inert: no frozen value moved");
        assert_ne!(a.digest(), b.digest(), "…but the revisions are still distinct rule sets");
        assert_eq!(a.digest(), a.digest(), "deterministic");
        // A frozen change moves the revision digest too, at a fixed identifier.
        let zeros: &'static str = Box::leak("00".repeat(32).into_boxed_str());
        let c = Revision { id: "v1.0", frozen_digest_hex: zeros };
        assert_ne!(a.digest(), c.digest());
    }

    #[test]
    fn a_revision_whose_digest_matches_this_binary_verifies() {
        let hex: &'static str = Box::leak(own_frozen_digest_hex().into_boxed_str());
        let r = Revision { id: "v1.0", frozen_digest_hex: hex };
        assert_eq!(r.verify(), Ok(()));
        // Case-insensitive hex accepted.
        let up: &'static str = Box::leak(hex.to_uppercase().into_boxed_str());
        assert_eq!(Revision { id: "v1.0", frozen_digest_hex: up }.verify(), Ok(()));
    }

    /// H4's negative, at the revision level: a revision copied across a change it
    /// does not describe is rejected — the binary refuses to start.
    #[test]
    fn a_revision_that_does_not_describe_this_binary_is_rejected() {
        let zeros: &'static str = Box::leak("00".repeat(32).into_boxed_str());
        let stale = Revision { id: "v1.0", frozen_digest_hex: zeros };
        assert!(matches!(stale.verify(), Err(RevisionError::DigestMismatch { .. })));
        let empty = Revision { id: "", frozen_digest_hex: zeros };
        assert_eq!(empty.verify(), Err(RevisionError::EmptyId));
    }
}
