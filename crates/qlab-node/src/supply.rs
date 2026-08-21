//! Public supply attestation, grouped by committee epoch (issue #121).
//!
//! The value being attested is the block body's scheduled-emission counter:
//! `Σ body.coinbase_total()`. Fees are reported beside it but are not subtracted, because
//! they are transfers paid to the miner. *(Corrected, lab #367: fees WERE never
//! burned; the name-service fee split now burns the name-fee half of a
//! registering tx's declared fee — reported as its own `burned` column below,
//! still never entering the issuance comparison.)* In the current
//! body payee totals already exclude fees; subtracting them would make
//! an honest fee-paying block look inflationary/deflationary.
//!
//! The expected side is integer throughout. [`crate::emission::coinbase`] is
//! defined as `s_atomic(h + 1) - s_atomic(h)`, so a contiguous epoch interval
//! telescopes exactly. The tolerance is therefore **zero bessel**: any non-zero
//! divergence is genuine, not accumulated floating-point error.
//!
//! # The expected side has three cases now, and the middle one is a finding
//! (lab #299 + #303, riders 1 and 2 of the boundary stamp)
//!
//! `RULE_BOUNDARY_HEIGHT` splits the chain into a grandfathered half and a
//! rule-bound half, and an epoch row can sit in either — or across the cut:
//!
//! 1. **Wholly at or below the boundary** — expected is the value the live chain
//!    *attested*, taken from [`PINNED_EPOCH_EXPECTED`] when activation supplied it
//!    and from the historical closed form otherwise. **Pinned, never recomputed**
//!    (#303 ruling clause 3): recomputing these under the exact schedule would
//!    shift 3,988 historical epoch endpoints and make every past attestation
//!    disagree with itself. Epoch 1 therefore keeps reading DIVERGENT −4114 on this
//!    chain forever, which is #299 ruling item 2 and a deliberate scar, not a bug.
//! 2. **Wholly above the boundary** — expected is the exact schedule's endpoints,
//!    full stop. This is the only regime in which the row is a real audit of a rule
//!    that consensus enforces.
//! 3. **Straddling the boundary — exactly one epoch, always.** An epoch ends at
//!    `1152·N − 1`, which is always **odd**, while a legal halt height must be a
//!    multiple of the checkpoint cadence (8). So no boundary can ever be an epoch
//!    end and *some* epoch always straddles it — here, epoch 7 (`[8_064,
//!    9_215]`, boundary at 8,640, re-stamped 2026-08-11 from 18,000 by
//!    [Larry's ruling on lab #299](https://github.com/qumbra-labs/qumbra-lab/issues/299#issuecomment-5248469483)).
//!    That is rider 1 of the stamp: a finding, not an oversight, and not worth a
//!    round trip trying to design away.
//!
//! For the straddling row the expected side is **piecewise**: the recorded value of
//! the pre-boundary prefix plus the *exact* walk of the suffix. It is emphatically
//! not `s_atomic_exact` across the whole row — that would recompute heights the
//! ruling forbids recomputing, and against a **zero-bessel** tolerance a single
//! grandfathered ±1 in the prefix would raise a false DIVERGENT on epoch 7. This
//! surface exists to make a supply violation legible; an alarm that fires on
//! grandfathered history trains its reader to ignore red, which is exactly what
//! #299 ruling item 2 forbids.
//!
//! **The honest cost of that, stated rather than buried:** because the prefix
//! contributes `expected == measured` by construction, a genuine pre-boundary defect
//! inside `8_064..=8_640` is invisible in epoch 7's row. It is visible in every
//! other pre-boundary epoch's row, and it is visible per-block to
//! `qumbra-node audit-emission`, which is the instrument for per-block defects.
//! Reported on #303 as the reading this baton took of rider 2.
//!
//! # The expected side is now form-aware (lab #520)
//!
//! The three-case rule above is a **v4-only** concern. It encodes T1's mid-chain
//! switch at [`RULE_BOUNDARY_HEIGHT`]. A v5-form net (T2) is born exact: consensus
//! dispatches on [`GenesisForm`] to `check_scheduled_coinbase_payees`, which has
//! no boundary at all — height 0 mints nothing, every height ≥ 1 is
//! [`s_atomic_exact`]. The auditor must agree with that **by construction**, from
//! the same [`GenesisForm`] consensus loaded out of genesis, never a config flag
//! or a height heuristic. Without that, a T2 chain whose money is exact reads
//! DIVERGENT against the float endpoints for ~8,640 blocks, and a permanently-red
//! row cannot report a real divergence.
//!
//! The v4 paths are not deleted. T1's archived history still audits under the
//! grandfathered rules (pins, `s_atomic_pre_boundary`, the 1377 `KNOWN_SCAR`).
//! This is a fork in the expectation, not a replacement.

use crate::emission::{s_atomic_exact, s_atomic_pre_boundary, RULE_BOUNDARY_HEIGHT};
use qlab_devnet::forms::GenesisForm;
use qlab_devnet::header::Hash32;

/// One activation pin: the expected issuance of an epoch that lies **wholly** at or
/// below [`RULE_BOUNDARY_HEIGHT`].
///
/// 🔴 **The height range is part of the key, not documentation.** A pin keyed on the
/// epoch number alone would be applied to a *partial* row of that epoch — the shape a
/// node has while it is still catching up through it — and hand it the whole epoch's
/// expected value against a fraction of the measured one, i.e. a large false
/// DIVERGENT on exactly the surface that must not cry wolf. Matching both endpoints
/// makes a partial row simply unpinned, which falls back to the closed form over the
/// range it actually covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochPin {
    pub epoch: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub expected_coinbase: u64,
}

/// **The pinned expected issuance of every wholly-pre-boundary epoch** (#303 ruling
/// clause 3).
///
/// # 🔴 T-ops step at activation
///
/// Empty means "not yet pinned", and the fallback is the historical closed form —
/// i.e. exactly what the live chain attests today, so merging this changes no row on
/// the glibc fleet. Produce the literals on a Linux/glibc host with
/// `qumbra-node emission-pins` and paste them here.
///
/// The stamp put the boundary at 18,000 (15 epochs, 0..=14); **re-stamped
/// 2026-08-11 to 8,640** by [Larry's ruling on lab #299](https://github.com/qumbra-labs/qumbra-lab/issues/299#issuecomment-5248469483),
/// which shrinks this to **7 epochs** (0..=6). Epoch 7 straddles and is handled
/// piecewise; see the module docs.
pub const PINNED_EPOCH_EXPECTED: &[EpochPin] = &[
    // Re-activated 2026-08-11 (lab #299/#303, re-stamp to 8,640): `qumbra-node
    // emission-pins` on a linux/aarch64 host. Epoch 7 straddles the boundary
    // (8_064..=9_215) and is handled piecewise — it is NOT pinned.
    EpochPin { epoch: 0, start_height: 0, end_height: 1151, expected_coinbase: 5752270395189 },
    EpochPin { epoch: 1, start_height: 1152, end_height: 2303, expected_coinbase: 5751809896394 },
    EpochPin { epoch: 2, start_height: 2304, end_height: 3455, expected_coinbase: 5746354576625 },
    EpochPin { epoch: 3, start_height: 3456, end_height: 4607, expected_coinbase: 5740904430968 },
    EpochPin { epoch: 4, start_height: 4608, end_height: 5759, expected_coinbase: 5735459454517 },
    EpochPin { epoch: 5, start_height: 5760, end_height: 6911, expected_coinbase: 5730019642369 },
    EpochPin { epoch: 6, start_height: 6912, end_height: 8063, expected_coinbase: 5724584989626 },
];

/// The public accounting inputs from one canonical block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SupplyBlock {
    pub height: u64,
    /// This block's header hash — the ledger's identity for the height (#299 §4).
    pub hash: Hash32,
    /// This block's parent hash. The ledger refuses a block that is not a child of
    /// what it last absorbed, which is what makes a reorg a **named error** instead
    /// of a silently wrong sum.
    pub prev: Hash32,
    /// The scheduled-emission counter committed by the block body.
    pub coinbase: u64,
    /// Transaction fees in the block. Reported, never subtracted from issuance.
    pub fees: u64,
    /// The burned name-fee portion of those fees (lab #367) —
    /// `BlockBody::total_name_burn`. Zero on every pre-boundary block.
    pub name_burn: u64,
}

/// One epoch's independently checkable supply relation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupplyEpoch {
    pub epoch: u64,
    /// First canonical height covered (genesis is height 0 and mints nothing).
    pub start_height: u64,
    /// Last canonical height covered, inclusive.
    pub end_height: u64,
    /// `Σ body.coinbase_total()` over the covered interval, in bessel.
    pub measured_coinbase: u64,
    /// Closed-form scheduled issuance over the same interval, in bessel.
    pub expected_coinbase: u64,
    /// `Σ tx.fee`, in bessel. Fees are transfers, not issuance — except the
    /// burned column below, reported separately.
    pub fees: u64,
    /// `Σ name_burn`, in bessel (lab #367): supply destroyed by name fees in
    /// this epoch. Cumulative destruction = Σ over rows.
    pub burned: u64,
}

/// One grandfathered supply scar this chain is **known** to carry, with its
/// citation (#299 ruling item 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KnownScar {
    pub epoch: u64,
    pub start_height: u64,
    pub end_height: u64,
    /// The exact divergence this scar produces. Exact, not a tolerance: a *different*
    /// number in the same epoch is a different fact and must still read DIVERGENT.
    pub divergence_bessel: i128,
    pub citation: &'static str,
}

/// **The scars this chain carries, as recorded history** (#299 ruling item 2).
///
/// # Why an alarm surface needs a list of known-red rows
///
/// The #299 sequencing ruling grandfathered height 1377's under-emission rather than
/// re-minting over it, and accepted the consequence explicitly: *"epoch 1 reads
/// DIVERGENT −4114 on this chain forever."* It also named the cost — **"a tool built
/// to catch supply violations must not train its readers to ignore red"** — and
/// required the annotation. Without it, every operator view on the live net shows a
/// standing 🔴 that everyone learns to scroll past, and the first *real* violation
/// arrives looking exactly like the noise.
///
/// The match is deliberately **tight**: epoch, both endpoints, and the exact
/// divergence. A partial epoch-1 row (state lag) does not match, and a defect that
/// happens to land in epoch 1 with any other total still reads DIVERGENT.
///
/// 🔴 **Platform note.** Until the T-ops pins land ([`PINNED_EPOCH_EXPECTED`]) the
/// expected side of a pre-boundary epoch is the historical `f64` closed form, so a
/// non-glibc attester can compute this row's endpoints ±1 apart and would show
/// DIVERGENT −4113/−4115 rather than the annotated scar. That is honest — it is a
/// different number — and it disappears the moment the epoch is pinned, which is one
/// more reason the pins are the activation step and not paperwork.
pub const KNOWN_SUPPLY_SCARS: &[KnownScar] = &[KnownScar {
    epoch: 1,
    start_height: 1_152,
    end_height: 2_303,
    divergence_bessel: -4_114,
    citation: "lab #299 §5 — block 1377 committed coinbase(1378); grandfathered as \
               recorded history by the sequencing ruling, never re-minted",
}];

impl SupplyEpoch {
    /// The known, grandfathered scar this row *is*, if it is one.
    pub fn known_scar(&self) -> Option<&'static KnownScar> {
        KNOWN_SUPPLY_SCARS.iter().find(|scar| {
            scar.epoch == self.epoch
                && scar.start_height == self.start_height
                && scar.end_height == self.end_height
                && scar.divergence_bessel == self.divergence_bessel()
        })
    }

    /// **The alarm predicate**: this row diverges *and* it is not a scar the chain is
    /// known to carry. This — not [`Self::agrees`] — is what an operator surface
    /// should escalate on, so that a standing grandfathered red does not train its
    /// reader to ignore the next one.
    pub fn is_unexplained_divergence(&self) -> bool {
        !self.agrees() && self.known_scar().is_none()
    }

    /// Exact signed divergence in bessel. Zero is the only passing value.
    pub fn divergence_bessel(&self) -> i128 {
        self.measured_coinbase as i128 - self.expected_coinbase as i128
    }

    /// Relative divergence for display only. Pass/fail always uses the exact
    /// integer [`Self::divergence_bessel`].
    pub fn relative_divergence(&self) -> f64 {
        if self.expected_coinbase == 0 {
            if self.measured_coinbase == 0 {
                0.0
            } else {
                f64::INFINITY
            }
        } else {
            self.divergence_bessel() as f64 / self.expected_coinbase as f64
        }
    }

    pub fn agrees(&self) -> bool {
        self.divergence_bessel() == 0
    }
}

/// Why a canonical block sequence could not be attested.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupplyError {
    ZeroEpochLength,
    DoesNotStartAtGenesis { got: u64 },
    NonContiguous { expected: u64, got: u64 },
    SumOverflow { epoch: u64 },
    /// **The reorg refusal** (#299 §4). The pushed block sits at the expected height
    /// but is not a child of the block the ledger last absorbed — i.e. fork choice
    /// moved off the branch this ledger has been summing.
    ///
    /// Before this existed, such a push was accepted and the orphaned block's
    /// coinbase stayed in the epoch's `measured_coinbase` **forever**, so the row
    /// read DIVERGENT by the difference between the two branches' rewards. With the
    /// #299 validity rule active, DIVERGENT is a real alarm; a reorg that can
    /// manufacture one is a cry-wolf generator, and the one thing this surface must
    /// never do is train its reader to ignore red.
    ///
    /// The remedy is the caller's: rebuild from the canonical chain
    /// ([`SupplyLedger::from_blocks`]). The ledger deliberately does **not** rewind
    /// itself — it keeps no per-height measured history, so a rewind could not
    /// recompute the partial row it lands in, and a ledger that pretended otherwise
    /// would be the same defect one layer down.
    ForkedFromLedgerHead { height: u64, expected_prev: Hash32, got_prev: Hash32 },
}

/// Incremental supply accounting: rebuild once from the persisted canonical
/// chain at startup, then append only newly accepted heights.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupplyLedger {
    epoch_length: u64,
    next_height: u64,
    rows: Vec<SupplyEpoch>,
    /// The genesis form this ledger audits under (lab #520). Same value
    /// consensus dispatches on; v4 keeps the three-case boundary rule, v5 is
    /// the exact schedule at every height ≥ 1.
    form: GenesisForm,
    /// Activation pins for wholly-pre-boundary epochs. A field rather than a
    /// straight read of [`PINNED_EPOCH_EXPECTED`] so the pin *mechanism* is
    /// test-locked with synthetic literals before activation supplies real ones.
    /// Consulted only on [`GenesisForm::V4`].
    pins: &'static [EpochPin],
    /// `Σ body.coinbase_total()` over the straddling epoch's pre-boundary prefix. Exactly
    /// one epoch can straddle [`RULE_BOUNDARY_HEIGHT`] (see the module docs), so one
    /// accumulator covers it. Consulted only on [`GenesisForm::V4`].
    straddle_prefix: u64,
    /// The header hash of the highest block absorbed — the ledger's own view of
    /// which branch it is summing (#299 §4).
    head_hash: Option<Hash32>,
}

impl SupplyLedger {
    /// A v4 ledger — T1's grandfathered three-case rule. The live node never
    /// calls this: it uses [`Self::new_for`] with the [`GenesisForm`] loaded
    /// from genesis (lab #520). Existing tests and the pins generator stay here
    /// because they *are* v4.
    pub fn new(epoch_length: u64) -> Result<Self, SupplyError> {
        Self::new_for(GenesisForm::V4, epoch_length)
    }

    /// [`Self::new`] keyed on the genesis form consensus dispatches on
    /// (lab #520). A v5 ledger never consults pins or the emission boundary.
    pub fn new_for(form: GenesisForm, epoch_length: u64) -> Result<Self, SupplyError> {
        let pins = match form {
            GenesisForm::V4 => PINNED_EPOCH_EXPECTED,
            // V5 has no grandfathered history and no pins. An empty table
            // makes a mistaken pin-read unrepresentable rather than ignored.
            GenesisForm::V5 => &[],
        };
        Self::with_pins_for(form, epoch_length, pins)
    }

    /// [`Self::new`] with an explicit pin table — the seam the pin tests use.
    pub fn with_pins(
        epoch_length: u64,
        pins: &'static [EpochPin],
    ) -> Result<Self, SupplyError> {
        Self::with_pins_for(GenesisForm::V4, epoch_length, pins)
    }

    /// [`Self::with_pins`] under an explicit genesis form.
    pub fn with_pins_for(
        form: GenesisForm,
        epoch_length: u64,
        pins: &'static [EpochPin],
    ) -> Result<Self, SupplyError> {
        if epoch_length == 0 {
            return Err(SupplyError::ZeroEpochLength);
        }
        Ok(Self {
            epoch_length,
            next_height: 0,
            rows: Vec::new(),
            form,
            pins,
            straddle_prefix: 0,
            head_hash: None,
        })
    }

    pub fn from_blocks<I>(blocks: I, epoch_length: u64) -> Result<Self, SupplyError>
    where
        I: IntoIterator<Item = SupplyBlock>,
    {
        Self::from_blocks_for(GenesisForm::V4, blocks, epoch_length)
    }

    /// [`Self::from_blocks`] keyed on the genesis form (lab #520).
    pub fn from_blocks_for<I>(
        form: GenesisForm,
        blocks: I,
        epoch_length: u64,
    ) -> Result<Self, SupplyError>
    where
        I: IntoIterator<Item = SupplyBlock>,
    {
        let mut ledger = Self::new_for(form, epoch_length)?;
        for block in blocks {
            ledger.push(block)?;
        }
        Ok(ledger)
    }

    /// The genesis form this ledger's expected side is computed under.
    pub fn form(&self) -> GenesisForm {
        self.form
    }

    /// The next canonical height this ledger expects.
    pub fn next_height(&self) -> u64 {
        self.next_height
    }

    pub fn rows(&self) -> &[SupplyEpoch] {
        &self.rows
    }

    /// The header hash of the highest block this ledger absorbed, if any.
    ///
    /// **The reorg check the consumer owes** (#299 §4): a ledger whose head is no
    /// longer the canonical block at that height is summing an abandoned branch, and
    /// no amount of appending fixes it — the fork may be entirely *below*
    /// [`Self::next_height`], in which case appending is a no-op and the stale sums
    /// simply persist. Compare this against the canonical chain before catching up,
    /// and rebuild when it differs.
    pub fn head_hash(&self) -> Option<Hash32> {
        self.head_hash
    }

    /// Whether this ledger is still summing `canonical` — i.e. its head is the
    /// canonical block at its own highest height.
    ///
    /// `canonical` is indexed by height (`main_chain()`'s shape). An empty ledger is
    /// trivially in sync; a ledger taller than the canonical chain is not.
    pub fn is_in_sync_with(&self, canonical: &[Hash32]) -> bool {
        match (self.next_height.checked_sub(1), self.head_hash) {
            (None, _) => true,
            (Some(h), Some(head)) => canonical.get(h as usize) == Some(&head),
            (Some(_), None) => false,
        }
    }

    /// Append one canonical block. Heights must be contiguous from genesis.
    pub fn push(&mut self, block: SupplyBlock) -> Result<(), SupplyError> {
        if self.next_height == 0 && self.rows.is_empty() && block.height != 0 {
            return Err(SupplyError::DoesNotStartAtGenesis { got: block.height });
        }
        if block.height != self.next_height {
            return Err(SupplyError::NonContiguous {
                expected: self.next_height,
                got: block.height,
            });
        }
        // #299 §4: the right height is not enough — it must be the right *block*.
        if let Some(head) = self.head_hash {
            if block.prev != head {
                return Err(SupplyError::ForkedFromLedgerHead {
                    height: block.height,
                    expected_prev: head,
                    got_prev: block.prev,
                });
            }
        }
        self.next_height =
            self.next_height
                .checked_add(1)
                .ok_or(SupplyError::SumOverflow {
                    epoch: block.height / self.epoch_length,
                })?;

        let epoch = block.height / self.epoch_length;
        if self.rows.last().is_none_or(|row| row.epoch != epoch) {
            self.rows.push(SupplyEpoch {
                epoch,
                start_height: block.height,
                end_height: block.height,
                measured_coinbase: 0,
                expected_coinbase: 0,
                fees: 0,
                burned: 0,
            });
            // The prefix accumulator belongs to the row being built, so it starts
            // over with every row. Only the row that straddles the boundary ever
            // reads it.
            self.straddle_prefix = 0;
        }
        let row = self.rows.last_mut().expect("the epoch row was inserted above");
        row.end_height = block.height;
        row.measured_coinbase = row
            .measured_coinbase
            .checked_add(block.coinbase)
            .ok_or(SupplyError::SumOverflow { epoch })?;
        row.fees = row
            .fees
            .checked_add(block.fees)
            .ok_or(SupplyError::SumOverflow { epoch })?;
        row.burned = row
            .burned
            .checked_add(block.name_burn)
            .ok_or(SupplyError::SumOverflow { epoch })?;

        // The prefix accumulator is a v4-only input to the straddling case.
        // A v5 net has no boundary and must not consult this number.
        if self.form == GenesisForm::V4 && block.height <= RULE_BOUNDARY_HEIGHT {
            self.straddle_prefix = self
                .straddle_prefix
                .checked_add(block.coinbase)
                .ok_or(SupplyError::SumOverflow { epoch })?;
        }
        self.head_hash = Some(block.hash);
        let straddle_prefix = self.straddle_prefix;
        let pins = self.pins;
        let form = self.form;
        let row = self.rows.last_mut().expect("the epoch row was inserted above");
        row.expected_coinbase = expected_for_row(form, row, pins, straddle_prefix);
        Ok(())
    }
}

/// The pinned expected issuance for this exact row, if activation supplied one. The
/// whole key must match — see [`EpochPin`] for why the endpoints are part of it.
fn pinned_expected(pins: &[EpochPin], row: &SupplyEpoch) -> Option<u64> {
    pins.iter()
        .find(|pin| {
            pin.epoch == row.epoch
                && pin.start_height == row.start_height
                && pin.end_height == row.end_height
        })
        .map(|pin| pin.expected_coinbase)
}

/// The expected issuance of one epoch row — one function so no caller can pick
/// the wrong case, and **form-keyed** so the auditor agrees with consensus by
/// construction (lab #520).
///
/// `straddle_prefix` is `Σ body.coinbase_total()` over the row's pre-boundary prefix and is
/// read **only** in the v4 straddling case.
fn expected_for_row(
    form: GenesisForm,
    row: &SupplyEpoch,
    pins: &[EpochPin],
    straddle_prefix: u64,
) -> u64 {
    // Genesis mints nothing and is inside epoch 0's range; the first mined block is
    // height 1. Same exemption on both forms.
    let first_mint = row.start_height.max(1);
    if row.end_height < first_mint {
        return 0;
    }
    match form {
        GenesisForm::V5 => {
            // Born exact: no boundary, no pins, no scar. Exactly what
            // `check_scheduled_coinbase_payees` enforces at every height ≥ 1.
            s_atomic_exact(row.end_height + 1) - s_atomic_exact(first_mint)
        }
        GenesisForm::V4 => {
            if row.end_height <= RULE_BOUNDARY_HEIGHT {
                // (1) Wholly grandfathered: the attested value, pinned or historical.
                return pinned_expected(pins, row).unwrap_or_else(|| {
                    s_atomic_pre_boundary(row.end_height + 1) - s_atomic_pre_boundary(first_mint)
                });
            }
            if first_mint > RULE_BOUNDARY_HEIGHT {
                // (2) Wholly rule-bound: the exact schedule's endpoints, and this
                // row is a real audit of a rule consensus enforces.
                return s_atomic_exact(row.end_height + 1) - s_atomic_exact(first_mint);
            }
            // (3) The one straddling epoch: the recorded prefix plus the exact
            // suffix. The prefix contributes `expected == measured`, so a
            // grandfathered ±1 below the boundary cannot raise a false DIVERGENT
            // on this row.
            straddle_prefix
                + (s_atomic_exact(row.end_height + 1) - s_atomic_exact(RULE_BOUNDARY_HEIGHT + 1))
        }
    }
}

/// Group a contiguous canonical chain into epoch attestations.
///
/// Genesis is part of epoch 0's covered range but contributes zero expected
/// issuance: this implementation's genesis body is empty, and the first mined
/// block is height 1. For a row covering `[start, end]`, expected issuance comes
/// from [`expected_for_row`] — v4's three-case rule, or v5's exact schedule.
/// This wrapper is v4; the live node uses [`supply_by_epoch_for`].
pub fn supply_by_epoch<I>(
    blocks: I,
    epoch_length: u64,
) -> Result<Vec<SupplyEpoch>, SupplyError>
where
    I: IntoIterator<Item = SupplyBlock>,
{
    supply_by_epoch_for(GenesisForm::V4, blocks, epoch_length)
}

/// [`supply_by_epoch`] keyed on the genesis form consensus dispatches on
/// (lab #520).
pub fn supply_by_epoch_for<I>(
    form: GenesisForm,
    blocks: I,
    epoch_length: u64,
) -> Result<Vec<SupplyEpoch>, SupplyError>
where
    I: IntoIterator<Item = SupplyBlock>,
{
    Ok(SupplyLedger::from_blocks_for(form, blocks, epoch_length)?.rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emission::{coinbase, coinbase_exact};

    /// A deterministic stand-in for a header hash: branch tag + height, so two
    /// branches at the same height are distinguishable and a child's `prev`
    /// reproduces its parent's `hash` by construction.
    fn h(branch: u8, height: u64) -> Hash32 {
        let mut out = [branch; 32];
        out[1..9].copy_from_slice(&height.to_le_bytes());
        out
    }

    /// One block of branch `branch` at `height`, carrying `coinbase`.
    fn block_on(branch: u8, height: u64, coinbase: u64, fees: u64) -> SupplyBlock {
        SupplyBlock {
            height,
            hash: h(branch, height),
            prev: if height == 0 { [0u8; 32] } else { h(branch, height - 1) },
            coinbase,
            fees,
            name_burn: 0,
        }
    }

    fn known_chain(tip: u64, epoch_length: u64) -> Vec<SupplyBlock> {
        (0..=tip)
            .map(|height| {
                block_on(
                    1,
                    height,
                    if height == 0 { 0 } else { coinbase(height) },
                    if height % epoch_length == 2 { 123 } else { 0 },
                )
            })
            .collect()
    }

    /// **Acceptance (#121), honest half:** a known canonical chain agrees exactly
    /// with the integer closed form in every complete and partial epoch.
    #[test]
    fn known_chain_supply_is_inside_zero_bessel_tolerance_per_epoch() {
        let rows = supply_by_epoch(known_chain(10, 4), 4).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!((rows[0].start_height, rows[0].end_height), (0, 3));
        assert_eq!((rows[1].start_height, rows[1].end_height), (4, 7));
        assert_eq!((rows[2].start_height, rows[2].end_height), (8, 10));
        assert!(rows.iter().all(SupplyEpoch::agrees));
        assert!(rows.iter().all(|row| row.divergence_bessel() == 0));
        assert_eq!(rows.iter().map(|row| row.fees).sum::<u64>(), 3 * 123);
    }

    /// **Acceptance (#121), teeth half:** one deliberately wrong scheduled sum is
    /// distinguishable from float error because there is no float comparison and
    /// the exact divergence is non-zero.
    #[test]
    fn deliberately_wrong_supply_is_outside_zero_bessel_tolerance() {
        let mut blocks = known_chain(7, 4);
        blocks[5].coinbase += 1;
        let rows = supply_by_epoch(blocks, 4).unwrap();
        assert!(rows[0].agrees());
        assert_eq!(rows[1].divergence_bessel(), 1);
        assert!(!rows[1].agrees());
    }

    #[test]
    fn incremental_append_matches_one_shot_rebuild() {
        let blocks = known_chain(10, 4);
        let rebuilt = supply_by_epoch(blocks.clone(), 4).unwrap();
        let mut incremental = SupplyLedger::new(4).unwrap();
        for block in blocks {
            incremental.push(block).unwrap();
        }
        assert_eq!(incremental.next_height(), 11);
        assert_eq!(incremental.rows(), rebuilt);
    }

    // --- the boundary: riders 1 and 2 of the #299/#303 stamp ------------------

    const EPOCH: u64 = qlab_devnet::params_devnet::EPOCH_LENGTH_BLOCKS;
    /// The straddling epoch, derived rather than written: `8_640 / 1_152 = 7`.
    const STRADDLE_EPOCH: u64 = RULE_BOUNDARY_HEIGHT / EPOCH;

    /// An honest chain (every block commits the canonical schedule) up to `tip`,
    /// under the real epoch length and the real boundary.
    fn honest_chain(tip: u64) -> Vec<SupplyBlock> {
        (0..=tip)
            .map(|height| block_on(1, height, if height == 0 { 0 } else { coinbase(height) }, 0))
            .collect()
    }

    /// **Rider 1, restated as a property of the parameters**: exactly one epoch
    /// straddles the boundary, and it is epoch 7 — because no legal halt height can
    /// ever be an epoch end.
    #[test]
    fn exactly_one_epoch_straddles_the_boundary_and_it_is_epoch_7() {
        assert_eq!(STRADDLE_EPOCH, 7);
        let start = STRADDLE_EPOCH * EPOCH;
        let end = start + EPOCH - 1;
        assert_eq!((start, end), (8_064, 9_215));
        assert!(start <= RULE_BOUNDARY_HEIGHT && RULE_BOUNDARY_HEIGHT < end);
        // And the count is one, not "one so far": a row straddles iff its start is
        // at or below the boundary and its end is above it, which is one epoch.
        let straddling = (0..64u64)
            .filter(|e| {
                let (s, t) = (e * EPOCH, e * EPOCH + EPOCH - 1);
                s <= RULE_BOUNDARY_HEIGHT && t > RULE_BOUNDARY_HEIGHT
            })
            .count();
        assert_eq!(straddling, 1);
    }

    /// **Rider 2, the load-bearing test.** A grandfathered ±1 planted in the
    /// straddling epoch's PRE-boundary prefix must not move the row's divergence:
    /// the prefix is recorded, not recomputed, so epoch 7 still reads zero bessel.
    ///
    /// Without the piecewise rule this row would read DIVERGENT ±1 — a false alarm
    /// on grandfathered history, which is the cry-wolf failure the attestation
    /// exists to avoid.
    #[test]
    fn a_planted_delta_in_the_straddle_prefix_still_reads_zero_bessel() {
        let tip = (STRADDLE_EPOCH + 1) * EPOCH - 1; // 9,215, the epoch's own end
        let mut blocks = honest_chain(tip);
        // Two plants, opposite signs, both strictly inside 8_064..=8_640.
        blocks[8_200].coinbase += 1;
        blocks[8_640].coinbase -= 1;
        let rows = supply_by_epoch(blocks, EPOCH).expect("contiguous from genesis");
        let straddle = rows
            .iter()
            .find(|r| r.epoch == STRADDLE_EPOCH)
            .expect("epoch 7 is covered");
        assert_eq!((straddle.start_height, straddle.end_height), (8_064, 9_215));
        assert_eq!(
            straddle.divergence_bessel(),
            0,
            "a grandfathered delta below the boundary must not raise DIVERGENT"
        );
        assert!(straddle.agrees());
    }

    /// The teeth of the same row: a delta in the straddling epoch's **suffix** —
    /// where the rule binds — is caught exactly. The row is not blind, it is
    /// piecewise.
    #[test]
    fn a_planted_delta_above_the_boundary_is_caught_in_the_same_row() {
        let tip = (STRADDLE_EPOCH + 1) * EPOCH - 1;
        let mut blocks = honest_chain(tip);
        blocks[8_641].coinbase += 7;
        let rows = supply_by_epoch(blocks, EPOCH).unwrap();
        let straddle = rows.iter().find(|r| r.epoch == STRADDLE_EPOCH).unwrap();
        assert_eq!(straddle.divergence_bessel(), 7);
        assert!(!straddle.agrees());
    }

    /// A wholly-above-boundary epoch audits the **exact** schedule's endpoints, and
    /// nothing about it can depend on a float.
    #[test]
    fn a_wholly_post_boundary_epoch_audits_the_exact_schedule() {
        let epoch = STRADDLE_EPOCH + 1; // 8 — starts at 9,216, above the boundary
        let tip = (epoch + 1) * EPOCH - 1;
        let rows = supply_by_epoch(honest_chain(tip), EPOCH).unwrap();
        let row = rows.iter().find(|r| r.epoch == epoch).unwrap();
        assert!(row.start_height > RULE_BOUNDARY_HEIGHT);
        assert_eq!(
            row.expected_coinbase,
            s_atomic_exact(row.end_height + 1) - s_atomic_exact(row.start_height),
            "expected must be the exact endpoints, with no historical term"
        );
        assert_eq!(row.divergence_bessel(), 0);
    }

    /// **Pins replace recomputation for wholly-pre-boundary epochs** (#303 clause
    /// 3). Locked with a synthetic pin so the mechanism is proved before activation
    /// supplies the real literals — and the pin's value, not the closed form, is
    /// what the row reports.
    #[test]
    fn a_pinned_pre_boundary_epoch_uses_the_pin_not_the_closed_form() {
        const PINS: &[EpochPin] = &[EpochPin {
            epoch: 3,
            start_height: 3 * EPOCH,
            end_height: 4 * EPOCH - 1,
            expected_coinbase: 777_777_777,
        }];
        let mut ledger = SupplyLedger::with_pins(EPOCH, PINS).unwrap();
        for block in honest_chain(4 * EPOCH - 1) {
            ledger.push(block).unwrap();
        }
        let pinned = ledger.rows().iter().find(|r| r.epoch == 3).unwrap();
        assert_eq!(pinned.expected_coinbase, 777_777_777, "the pin wins");
        // Its neighbours are unpinned and keep the historical closed form.
        let unpinned = ledger.rows().iter().find(|r| r.epoch == 2).unwrap();
        assert_eq!(
            unpinned.expected_coinbase,
            s_atomic_pre_boundary(unpinned.end_height + 1)
                - s_atomic_pre_boundary(unpinned.start_height),
        );
    }

    /// **Activated 2026-08-10 (lab #299/#303) at 18,000; re-stamped 2026-08-11 to
    /// 8,640** by [Larry's ruling on lab #299](https://github.com/qumbra-labs/qumbra-lab/issues/299#issuecomment-5248469483).
    /// The shipped table now carries the 7 wholly-pre-boundary epochs (0..=6),
    /// generated by `qumbra-node emission-pins` on a linux/aarch64 host. This locks
    /// the table's *shape* — 7 contiguous rows covering `0..=8_063`, every one
    /// strictly below `RULE_BOUNDARY_HEIGHT` (epoch 7 straddles and is deliberately
    /// NOT pinned). Values were coordinator-verified against issue #299's body
    /// (epochs 0/1/2) and an independent evaluation (epoch 3); a regeneration that
    /// changes any literal fails the golden below and demands re-review.
    #[test]
    fn the_activated_pin_table_is_seven_contiguous_pre_boundary_epochs() {
        assert_eq!(PINNED_EPOCH_EXPECTED.len(), 7, "epochs 0..=6 pin, epoch 7 straddles");
        assert_eq!(PINNED_EPOCH_EXPECTED[0].start_height, 0);
        for (i, p) in PINNED_EPOCH_EXPECTED.iter().enumerate() {
            assert_eq!(p.epoch, i as u64, "epochs in order");
            assert_eq!(p.start_height, i as u64 * EPOCH, "start = epoch·EPOCH");
            assert_eq!(p.end_height, (i as u64 + 1) * EPOCH - 1, "end = next start − 1");
            assert!(p.end_height < RULE_BOUNDARY_HEIGHT, "every pinned epoch is pre-boundary");
        }
        // Golden literals for the three the coordinator cross-checked independently.
        assert_eq!(PINNED_EPOCH_EXPECTED[0].expected_coinbase, 5752270395189);
        assert_eq!(PINNED_EPOCH_EXPECTED[1].expected_coinbase, 5751809896394);
        assert_eq!(PINNED_EPOCH_EXPECTED[6].expected_coinbase, 5724584989626);
    }

    /// **A PARTIAL row of a pinned epoch must not take the pin.** This is the shape a
    /// node has while it is still catching up through the epoch, and handing it the
    /// whole epoch's expected value against a fraction of the measured one would print
    /// a large false DIVERGENT — on the surface whose entire job is to make a real
    /// violation legible.
    #[test]
    fn a_partial_row_of_a_pinned_epoch_falls_back_to_its_own_range() {
        const PINS: &[EpochPin] = &[EpochPin {
            epoch: 3,
            start_height: 3 * EPOCH,
            end_height: 4 * EPOCH - 1,
            expected_coinbase: 777_777_777,
        }];
        // Stop one block short of epoch 3's end, so its row is partial.
        let tip = 4 * EPOCH - 2;
        let mut ledger = SupplyLedger::with_pins(EPOCH, PINS).unwrap();
        for block in honest_chain(tip) {
            ledger.push(block).unwrap();
        }
        let partial = ledger.rows().last().unwrap();
        assert_eq!((partial.epoch, partial.end_height), (3, tip));
        assert_ne!(partial.expected_coinbase, 777_777_777, "the pin must not apply");
        assert_eq!(
            partial.expected_coinbase,
            s_atomic_pre_boundary(tip + 1) - s_atomic_pre_boundary(partial.start_height),
        );
        assert_eq!(partial.divergence_bessel(), 0, "and an honest partial row agrees");
    }

    // --- #299 §4: the reorg gap ----------------------------------------------

    /// **The gap, and the fix.** Branch 1 mines height 5 with a *different* coinbase
    /// than branch 2 does. The ledger absorbs branch 1 up to 5, then fork choice
    /// picks branch 2. Before this fix, pushing branch 2's height 6 succeeded — the
    /// heights were contiguous — and branch 1's orphaned coinbase stayed in the row
    /// forever, so the epoch read DIVERGENT by the difference.
    ///
    /// Now the push is refused by name, and a rebuild from the canonical chain
    /// re-derives the row exactly. **A reorg can no longer produce a DIVERGENT.**
    #[test]
    fn a_reorg_cannot_leave_an_orphaned_coinbase_in_the_sum() {
        let epoch_length = 8;
        // Branch 1: honest up to 4, then height 5 pays 1,000 bessel too much.
        let mut ledger = SupplyLedger::new(epoch_length).unwrap();
        for height in 0..=4u64 {
            ledger
                .push(block_on(1, height, if height == 0 { 0 } else { coinbase(height) }, 0))
                .unwrap();
        }
        ledger.push(block_on(1, 5, coinbase(5) + 1_000, 0)).unwrap();
        assert_eq!(ledger.rows()[0].divergence_bessel(), 1_000, "branch 1 is off by 1,000");
        assert_eq!(ledger.head_hash(), Some(h(1, 5)));

        // Fork choice moves to branch 2, which shares 0..=4 and mines an honest 5.
        let canonical: Vec<Hash32> = (0..=6u64)
            .map(|height| if height <= 4 { h(1, height) } else { h(2, height) })
            .collect();
        assert!(
            !ledger.is_in_sync_with(&canonical),
            "the ledger's head is no longer canonical — this is the check the consumer owes"
        );

        // The stale ledger REFUSES branch 2's height 6 rather than absorbing it.
        assert_eq!(
            ledger.push(block_on(2, 6, coinbase(6), 0)),
            Err(SupplyError::ForkedFromLedgerHead {
                height: 6,
                expected_prev: h(1, 5),
                got_prev: h(2, 5),
            }),
        );

        // Rebuild from the canonical chain: the row re-derives to zero divergence.
        let rebuilt = SupplyLedger::from_blocks(
            canonical.iter().enumerate().map(|(height, hash)| SupplyBlock {
                height: height as u64,
                hash: *hash,
                prev: if height == 0 {
                    [0u8; 32]
                } else {
                    canonical[height - 1]
                },
                coinbase: if height == 0 { 0 } else { coinbase(height as u64) },
                fees: 0,
                name_burn: 0,
            }),
            epoch_length,
        )
        .expect("the canonical chain is contiguous from genesis");
        assert_eq!(rebuilt.rows()[0].divergence_bessel(), 0);
        assert!(rebuilt.is_in_sync_with(&canonical));
        assert_eq!(rebuilt.next_height(), 7);
    }

    /// The reorg may be entirely **below** `next_height`, in which case appending is
    /// a no-op and the stale sums would simply persist — which is why the consumer's
    /// check is `is_in_sync_with` and not "did a push fail".
    #[test]
    fn a_reorg_below_next_height_is_still_detected() {
        let mut ledger = SupplyLedger::new(8).unwrap();
        for height in 0..=5u64 {
            ledger
                .push(block_on(1, height, if height == 0 { 0 } else { coinbase(height) }, 0))
                .unwrap();
        }
        // Fork choice replaced heights 3..=5 with a shorter-or-equal branch 2, and
        // the new tip is 5 — so `next_height() == 6` and there is nothing to append.
        let canonical: Vec<Hash32> = (0..=5u64)
            .map(|height| if height <= 2 { h(1, height) } else { h(2, height) })
            .collect();
        assert_eq!(ledger.next_height(), 6);
        assert!(!ledger.is_in_sync_with(&canonical));
        // …and a chain SHORTER than the ledger is out of sync too.
        assert!(!ledger.is_in_sync_with(&canonical[..3]));
    }

    /// An honest extension is in sync at every step, and an empty ledger is
    /// trivially in sync — so the check cannot fire spuriously on the common path.
    #[test]
    fn the_sync_check_does_not_fire_on_an_honest_extension() {
        let blocks = known_chain(10, 4);
        let canonical: Vec<Hash32> = blocks.iter().map(|b| b.hash).collect();
        let mut ledger = SupplyLedger::new(4).unwrap();
        assert!(ledger.is_in_sync_with(&canonical), "an empty ledger is in sync");
        for block in blocks {
            ledger.push(block).unwrap();
            assert!(ledger.is_in_sync_with(&canonical));
        }
        assert_eq!(ledger.head_hash(), Some(h(1, 10)));
    }

    // --- #299 ruling item 2: the known-scar annotation ------------------------

    /// The epoch-1 row this chain actually carries: measured 4,114 bessel under the
    /// closed form, over the full epoch.
    fn epoch_one_scar_row(divergence: i128) -> SupplyEpoch {
        let expected = 1_000_000_000u64;
        SupplyEpoch {
            epoch: 1,
            start_height: 1_152,
            end_height: 2_303,
            measured_coinbase: (expected as i128 + divergence) as u64,
            expected_coinbase: expected,
            fees: 0,
            burned: 0,
        }
    }

    /// **The annotation, and its teeth.** The recorded scar is recognised and is not
    /// an unexplained divergence; *any other* number in the same epoch still is.
    #[test]
    fn the_epoch_one_scar_is_annotated_and_nothing_else_is() {
        let scar = epoch_one_scar_row(-4_114);
        assert!(!scar.agrees(), "the scar stays VISIBLE — it is not made to pass");
        let known = scar.known_scar().expect("the recorded scar is known");
        assert!(known.citation.contains("#299"));
        assert!(!scar.is_unexplained_divergence(), "and it is not a new alarm");

        // A different total in the same epoch is a different fact.
        for other in [-4_113i128, -4_115, -1, 1, 4_114] {
            let row = epoch_one_scar_row(other);
            assert!(row.known_scar().is_none(), "divergence {other} is not the scar");
            assert!(row.is_unexplained_divergence(), "divergence {other} must alarm");
        }
        // A PARTIAL epoch-1 row (state lag) is not the scar either, even at −4114.
        let partial = SupplyEpoch { end_height: 2_000, ..epoch_one_scar_row(-4_114) };
        assert!(partial.known_scar().is_none());
        assert!(partial.is_unexplained_divergence());
        // And an honest row is neither.
        let honest = epoch_one_scar_row(0);
        assert!(honest.agrees());
        assert!(honest.known_scar().is_none());
        assert!(!honest.is_unexplained_divergence());
    }

    #[test]
    fn refuses_a_gapped_or_non_genesis_sequence() {
        assert_eq!(
            supply_by_epoch(
                [block_on(1, 1, coinbase(1), 0)],
                4,
            ),
            Err(SupplyError::DoesNotStartAtGenesis { got: 1 }),
        );
        let mut blocks = known_chain(3, 4);
        blocks[2].height = 3;
        assert_eq!(
            supply_by_epoch(blocks, 4),
            Err(SupplyError::NonContiguous {
                expected: 2,
                got: 3,
            }),
        );
    }

    // --- lab #520: the expected side is form-aware ----------------------------

    /// An honest v5 chain: genesis mints nothing, every later block commits
    /// `coinbase_exact(height)` — what `check_scheduled_coinbase_payees` demands.
    fn honest_v5_chain(tip: u64) -> Vec<SupplyBlock> {
        (0..=tip)
            .map(|height| {
                block_on(
                    1,
                    height,
                    if height == 0 { 0 } else { coinbase_exact(height) },
                    0,
                )
            })
            .collect()
    }

    /// **#520, the missing regression.** A v5 chain of N blocks minted at the
    /// exact schedule audits MATCH. T2's live explorer reported DIVERGENT at
    /// tip 36 because the expected side still took the v4 float branch.
    #[test]
    fn a_v5_chain_minted_at_the_exact_schedule_audits_match() {
        let tip = 36u64; // the live T2 height at the defect report
        let blocks = honest_v5_chain(tip);
        let rows = supply_by_epoch_for(GenesisForm::V5, blocks.clone(), EPOCH).unwrap();
        assert_eq!(rows.len(), 1, "tip 36 is still epoch 0");
        assert_eq!((rows[0].start_height, rows[0].end_height), (0, tip));
        assert_eq!(
            rows[0].expected_coinbase,
            s_atomic_exact(tip + 1) - s_atomic_exact(1),
            "v5 expected is the exact endpoints, genesis exempt"
        );
        assert!(rows[0].agrees(), "correct money must not read DIVERGENT");
        assert_eq!(rows[0].divergence_bessel(), 0);
        assert!(!rows[0].is_unexplained_divergence());

        // The same chain under the v4 expectation is the false alarm T2 shipped.
        // The residue is platform-dependent (the float side), so we assert only
        // that the two schedules disagree — a MATCH here would mean the live
        // bug was unobservable on this host, which is itself a finding.
        let v4 = supply_by_epoch(blocks, EPOCH).unwrap();
        let v4_expected =
            s_atomic_pre_boundary(tip + 1) - s_atomic_pre_boundary(1);
        assert_eq!(v4[0].expected_coinbase, v4_expected);
        assert_ne!(
            v4[0].expected_coinbase, rows[0].expected_coinbase,
            "the v4 float endpoints and the exact schedule differ at T2's live heights — \
             that difference is the false DIVERGENT"
        );
        assert!(!v4[0].agrees());
    }

    /// **#520, the teeth.** A v5 chain with one deliberately wrong coinbase
    /// audits DIVERGENT with the right delta — the alarm must still fire, or we
    /// have traded a false positive for a false negative.
    #[test]
    fn a_v5_chain_with_one_wrong_coinbase_audits_divergent_with_the_right_delta() {
        let mut blocks = honest_v5_chain(10);
        blocks[7].coinbase += 11;
        let rows = supply_by_epoch_for(GenesisForm::V5, blocks, 4).unwrap();
        assert!(rows[0].agrees(), "epoch 0 is clean");
        assert_eq!(rows[1].divergence_bessel(), 11);
        assert!(!rows[1].agrees());
        assert!(
            rows[1].is_unexplained_divergence(),
            "a real v5 defect is not the T1 scar"
        );
        assert!(rows[2].agrees());
    }

    /// **#520, v4 must not regress.** A v4 chain below the boundary still audits
    /// under the grandfathered expectation, and the 1377 scar stays annotated.
    #[test]
    fn a_v4_chain_below_the_boundary_still_audits_under_the_grandfathered_expectation() {
        let rows = supply_by_epoch(honest_chain(10), 4).unwrap();
        assert!(
            rows.iter().all(SupplyEpoch::agrees),
            "an honest v4 chain below the boundary matches the float endpoints"
        );
        // The scar annotation is unchanged — epoch, both endpoints, exact delta.
        let scar = epoch_one_scar_row(-4_114);
        assert!(!scar.agrees(), "the scar stays VISIBLE");
        assert!(scar.known_scar().is_some());
        assert!(!scar.is_unexplained_divergence());
    }

    /// **#520, genesis exemption.** Height 0 contributes 0 expected issuance on
    /// both forms — genesis mints nothing, and `coinbase_exact(0)` is never
    /// compared against the committed 0.
    #[test]
    fn genesis_contributes_zero_expected_on_both_forms() {
        for form in [GenesisForm::V4, GenesisForm::V5] {
            let rows = supply_by_epoch_for(form, [block_on(1, 0, 0, 0)], 4).unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].expected_coinbase, 0, "{form:?}");
            assert_eq!(rows[0].measured_coinbase, 0, "{form:?}");
            assert!(rows[0].agrees(), "{form:?}");
        }
    }

    /// Pins, the boundary, and the straddle prefix are v4 machinery. A v5
    /// ledger with a planted pin table still audits the exact schedule.
    #[test]
    fn a_v5_ledger_does_not_consult_pins_or_the_boundary() {
        const PINS: &[EpochPin] = &[EpochPin {
            epoch: 0,
            start_height: 0,
            end_height: 3,
            expected_coinbase: 1,
        }];
        let mut ledger = SupplyLedger::with_pins_for(GenesisForm::V5, 4, PINS).unwrap();
        assert_eq!(ledger.form(), GenesisForm::V5);
        for block in honest_v5_chain(3) {
            ledger.push(block).unwrap();
        }
        let row = &ledger.rows()[0];
        assert_ne!(row.expected_coinbase, 1, "the pin must not apply on v5");
        assert_eq!(
            row.expected_coinbase,
            s_atomic_exact(4) - s_atomic_exact(1)
        );
        assert!(row.agrees());
    }
}
