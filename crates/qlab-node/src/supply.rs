//! Public supply attestation, grouped by committee epoch (issue #121).
//!
//! The value being attested is the block body's scheduled-emission counter:
//! `Σ body.coinbase`. Fees are reported beside it but are not subtracted, because
//! they are transfers paid to the miner and are never burned. In the current
//! body format `body.coinbase` already excludes fees; subtracting them would make
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
//!    end and *some* epoch always straddles it — here, epoch 15 (`[17_280,
//!    18_431]`, boundary at 18,000). That is rider 1 of the stamp: a finding, not an
//!    oversight, and not worth a round trip trying to design away.
//!
//! For the straddling row the expected side is **piecewise**: the recorded value of
//! the pre-boundary prefix plus the *exact* walk of the suffix. It is emphatically
//! not `s_atomic_exact` across the whole row — that would recompute heights the
//! ruling forbids recomputing, and against a **zero-bessel** tolerance a single
//! grandfathered ±1 in the prefix would raise a false DIVERGENT on epoch 15. This
//! surface exists to make a supply violation legible; an alarm that fires on
//! grandfathered history trains its reader to ignore red, which is exactly what
//! #299 ruling item 2 forbids.
//!
//! **The honest cost of that, stated rather than buried:** because the prefix
//! contributes `expected == measured` by construction, a genuine pre-boundary defect
//! inside `17_280..=18_000` is invisible in epoch 15's row. It is visible in every
//! other pre-boundary epoch's row, and it is visible per-block to
//! `qumbra-node audit-emission`, which is the instrument for per-block defects.
//! Reported on #303 as the reading this baton took of rider 2.

use crate::emission::{s_atomic_exact, s_atomic_pre_boundary, RULE_BOUNDARY_HEIGHT};

/// One activation pin: `(epoch, expected_coinbase_bessel)` for an epoch that ends
/// at or below [`RULE_BOUNDARY_HEIGHT`].
pub type EpochPin = (u64, u64);

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
/// The stamp puts the boundary at 18,000, so this covers **15 epochs** (0..=14),
/// not the "~5–9" the ruling estimated at the time — six more literals and nothing
/// else. Epoch 15 straddles and is handled piecewise; see the module docs.
pub const PINNED_EPOCH_EXPECTED: &[EpochPin] = &[];

/// The public accounting inputs from one canonical block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SupplyBlock {
    pub height: u64,
    /// The scheduled-emission counter committed by the block body.
    pub coinbase: u64,
    /// Transaction fees in the block. Reported, never subtracted from issuance.
    pub fees: u64,
}

/// One epoch's independently checkable supply relation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupplyEpoch {
    pub epoch: u64,
    /// First canonical height covered (genesis is height 0 and mints nothing).
    pub start_height: u64,
    /// Last canonical height covered, inclusive.
    pub end_height: u64,
    /// `Σ body.coinbase` over the covered interval, in bessel.
    pub measured_coinbase: u64,
    /// Closed-form scheduled issuance over the same interval, in bessel.
    pub expected_coinbase: u64,
    /// `Σ tx.fee`, in bessel. Fees are transfers, not issuance or burning.
    pub fees: u64,
}

impl SupplyEpoch {
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
}

/// Incremental supply accounting: rebuild once from the persisted canonical
/// chain at startup, then append only newly accepted heights.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupplyLedger {
    epoch_length: u64,
    next_height: u64,
    rows: Vec<SupplyEpoch>,
    /// Activation pins for wholly-pre-boundary epochs. A field rather than a
    /// straight read of [`PINNED_EPOCH_EXPECTED`] so the pin *mechanism* is
    /// test-locked with synthetic literals before activation supplies real ones.
    pins: &'static [EpochPin],
    /// `Σ body.coinbase` over the straddling epoch's pre-boundary prefix. Exactly
    /// one epoch can straddle [`RULE_BOUNDARY_HEIGHT`] (see the module docs), so one
    /// accumulator covers it.
    straddle_prefix: u64,
}

impl SupplyLedger {
    pub fn new(epoch_length: u64) -> Result<Self, SupplyError> {
        Self::with_pins(epoch_length, PINNED_EPOCH_EXPECTED)
    }

    /// [`Self::new`] with an explicit pin table — the seam the pin tests use.
    pub fn with_pins(
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
            pins,
            straddle_prefix: 0,
        })
    }

    pub fn from_blocks<I>(blocks: I, epoch_length: u64) -> Result<Self, SupplyError>
    where
        I: IntoIterator<Item = SupplyBlock>,
    {
        let mut ledger = Self::new(epoch_length)?;
        for block in blocks {
            ledger.push(block)?;
        }
        Ok(ledger)
    }

    /// The next canonical height this ledger expects.
    pub fn next_height(&self) -> u64 {
        self.next_height
    }

    pub fn rows(&self) -> &[SupplyEpoch] {
        &self.rows
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

        if block.height <= RULE_BOUNDARY_HEIGHT {
            self.straddle_prefix = self
                .straddle_prefix
                .checked_add(block.coinbase)
                .ok_or(SupplyError::SumOverflow { epoch })?;
        }
        let straddle_prefix = self.straddle_prefix;
        let pins = self.pins;
        let row = self.rows.last_mut().expect("the epoch row was inserted above");
        row.expected_coinbase = expected_for_row(row, pins, straddle_prefix);
        Ok(())
    }
}

/// The pinned expected issuance for `epoch`, if activation supplied one.
fn pinned_expected(pins: &[EpochPin], epoch: u64) -> Option<u64> {
    pins.iter().find(|(e, _)| *e == epoch).map(|(_, v)| *v)
}

/// The expected issuance of one epoch row — the three-case rule the module docs
/// describe, in one place so no caller can pick the wrong case.
///
/// `straddle_prefix` is `Σ body.coinbase` over the row's pre-boundary prefix and is
/// read **only** in the straddling case.
fn expected_for_row(row: &SupplyEpoch, pins: &[EpochPin], straddle_prefix: u64) -> u64 {
    // Genesis mints nothing and is inside epoch 0's range; the first mined block is
    // height 1.
    let first_mint = row.start_height.max(1);
    if row.end_height < first_mint {
        return 0;
    }
    if row.end_height <= RULE_BOUNDARY_HEIGHT {
        // (1) Wholly grandfathered: the attested value, pinned or historical.
        return pinned_expected(pins, row.epoch).unwrap_or_else(|| {
            s_atomic_pre_boundary(row.end_height + 1) - s_atomic_pre_boundary(first_mint)
        });
    }
    if first_mint > RULE_BOUNDARY_HEIGHT {
        // (2) Wholly rule-bound: the exact schedule's endpoints, and this row is a
        // real audit of a rule consensus enforces.
        return s_atomic_exact(row.end_height + 1) - s_atomic_exact(first_mint);
    }
    // (3) The one straddling epoch: the recorded prefix plus the exact suffix. The
    // prefix contributes `expected == measured`, so a grandfathered ±1 below the
    // boundary cannot raise a false DIVERGENT on this row.
    straddle_prefix
        + (s_atomic_exact(row.end_height + 1) - s_atomic_exact(RULE_BOUNDARY_HEIGHT + 1))
}

/// Group a contiguous canonical chain into epoch attestations.
///
/// Genesis is part of epoch 0's covered range but contributes zero expected
/// issuance: this implementation's genesis body is empty, and the first mined
/// block is height 1. For a row covering `[start, end]`, expected issuance comes
/// from [`expected_for_row`]'s three-case rule — see the module docs.
pub fn supply_by_epoch<I>(
    blocks: I,
    epoch_length: u64,
) -> Result<Vec<SupplyEpoch>, SupplyError>
where
    I: IntoIterator<Item = SupplyBlock>,
{
    Ok(SupplyLedger::from_blocks(blocks, epoch_length)?.rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emission::coinbase;

    fn known_chain(tip: u64, epoch_length: u64) -> Vec<SupplyBlock> {
        (0..=tip)
            .map(|height| SupplyBlock {
                height,
                coinbase: if height == 0 { 0 } else { coinbase(height) },
                fees: if height % epoch_length == 2 { 123 } else { 0 },
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
    /// The straddling epoch, derived rather than written: `18_000 / 1_152 = 15`.
    const STRADDLE_EPOCH: u64 = RULE_BOUNDARY_HEIGHT / EPOCH;

    /// An honest chain (every block commits the canonical schedule) up to `tip`,
    /// under the real epoch length and the real boundary.
    fn honest_chain(tip: u64) -> Vec<SupplyBlock> {
        (0..=tip)
            .map(|height| SupplyBlock {
                height,
                coinbase: if height == 0 { 0 } else { coinbase(height) },
                fees: 0,
            })
            .collect()
    }

    /// **Rider 1, restated as a property of the parameters**: exactly one epoch
    /// straddles the boundary, and it is epoch 15 — because no legal halt height can
    /// ever be an epoch end.
    #[test]
    fn exactly_one_epoch_straddles_the_boundary_and_it_is_epoch_15() {
        assert_eq!(STRADDLE_EPOCH, 15);
        let start = STRADDLE_EPOCH * EPOCH;
        let end = start + EPOCH - 1;
        assert_eq!((start, end), (17_280, 18_431));
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
    /// the prefix is recorded, not recomputed, so epoch 15 still reads zero bessel.
    ///
    /// Without the piecewise rule this row would read DIVERGENT ±1 — a false alarm
    /// on grandfathered history, which is the cry-wolf failure the attestation
    /// exists to avoid.
    #[test]
    fn a_planted_delta_in_the_straddle_prefix_still_reads_zero_bessel() {
        let tip = (STRADDLE_EPOCH + 1) * EPOCH - 1; // 18,431, the epoch's own end
        let mut blocks = honest_chain(tip);
        // Two plants, opposite signs, both strictly inside 17,280..=18,000.
        blocks[17_500].coinbase += 1;
        blocks[18_000].coinbase -= 1;
        let rows = supply_by_epoch(blocks, EPOCH).expect("contiguous from genesis");
        let straddle = rows
            .iter()
            .find(|r| r.epoch == STRADDLE_EPOCH)
            .expect("epoch 15 is covered");
        assert_eq!((straddle.start_height, straddle.end_height), (17_280, 18_431));
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
        blocks[18_001].coinbase += 7;
        let rows = supply_by_epoch(blocks, EPOCH).unwrap();
        let straddle = rows.iter().find(|r| r.epoch == STRADDLE_EPOCH).unwrap();
        assert_eq!(straddle.divergence_bessel(), 7);
        assert!(!straddle.agrees());
    }

    /// A wholly-above-boundary epoch audits the **exact** schedule's endpoints, and
    /// nothing about it can depend on a float.
    #[test]
    fn a_wholly_post_boundary_epoch_audits_the_exact_schedule() {
        let epoch = STRADDLE_EPOCH + 1; // 16 — starts at 18,432, above the boundary
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
        const PINS: &[EpochPin] = &[(3, 777_777_777)];
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
        // And the shipped table is empty at merge, so no live row moves.
        assert!(PINNED_EPOCH_EXPECTED.is_empty(), "unpinned at merge (T-ops step)");
    }

    #[test]
    fn refuses_a_gapped_or_non_genesis_sequence() {
        assert_eq!(
            supply_by_epoch(
                [SupplyBlock {
                    height: 1,
                    coinbase: coinbase(1),
                    fees: 0,
                }],
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
}
