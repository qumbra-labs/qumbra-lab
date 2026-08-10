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
/// The stamp puts the boundary at 18,000, so this covers **15 epochs** (0..=14),
/// not the "~5–9" the ruling estimated at the time — six more literals and nothing
/// else. Epoch 15 straddles and is handled piecewise; see the module docs.
pub const PINNED_EPOCH_EXPECTED: &[EpochPin] = &[
    // Activated 2026-08-10 (lab #299/#303): `qumbra-node emission-pins` on a
    // linux/aarch64 host; epochs 0/1/2 cross-checked against issue #299's body
    // and epoch 3 against an independent evaluation. Epoch 15 straddles the
    // boundary (17_280..=18_431) and is handled piecewise — it is NOT pinned.
    EpochPin { epoch: 0, start_height: 0, end_height: 1151, expected_coinbase: 5752270395189 },
    EpochPin { epoch: 1, start_height: 1152, end_height: 2303, expected_coinbase: 5751809896394 },
    EpochPin { epoch: 2, start_height: 2304, end_height: 3455, expected_coinbase: 5746354576625 },
    EpochPin { epoch: 3, start_height: 3456, end_height: 4607, expected_coinbase: 5740904430968 },
    EpochPin { epoch: 4, start_height: 4608, end_height: 5759, expected_coinbase: 5735459454517 },
    EpochPin { epoch: 5, start_height: 5760, end_height: 6911, expected_coinbase: 5730019642369 },
    EpochPin { epoch: 6, start_height: 6912, end_height: 8063, expected_coinbase: 5724584989626 },
    EpochPin { epoch: 7, start_height: 8064, end_height: 9215, expected_coinbase: 5719155491393 },
    EpochPin { epoch: 8, start_height: 9216, end_height: 10367, expected_coinbase: 5713731142784 },
    EpochPin { epoch: 9, start_height: 10368, end_height: 11519, expected_coinbase: 5708311938911 },
    EpochPin { epoch: 10, start_height: 11520, end_height: 12671, expected_coinbase: 5702897874899 },
    EpochPin { epoch: 11, start_height: 12672, end_height: 13823, expected_coinbase: 5697488945869 },
    EpochPin { epoch: 12, start_height: 13824, end_height: 14975, expected_coinbase: 5692085146953 },
    EpochPin { epoch: 13, start_height: 14976, end_height: 16127, expected_coinbase: 5686686473285 },
    EpochPin { epoch: 14, start_height: 16128, end_height: 17279, expected_coinbase: 5681292920005 },
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
    /// Activation pins for wholly-pre-boundary epochs. A field rather than a
    /// straight read of [`PINNED_EPOCH_EXPECTED`] so the pin *mechanism* is
    /// test-locked with synthetic literals before activation supplies real ones.
    pins: &'static [EpochPin],
    /// `Σ body.coinbase` over the straddling epoch's pre-boundary prefix. Exactly
    /// one epoch can straddle [`RULE_BOUNDARY_HEIGHT`] (see the module docs), so one
    /// accumulator covers it.
    straddle_prefix: u64,
    /// The header hash of the highest block absorbed — the ledger's own view of
    /// which branch it is summing (#299 §4).
    head_hash: Option<Hash32>,
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
            head_hash: None,
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
        self.head_hash = Some(block.hash);
        let straddle_prefix = self.straddle_prefix;
        let pins = self.pins;
        let row = self.rows.last_mut().expect("the epoch row was inserted above");
        row.expected_coinbase = expected_for_row(row, pins, straddle_prefix);
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
        return pinned_expected(pins, row).unwrap_or_else(|| {
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
    /// The straddling epoch, derived rather than written: `18_000 / 1_152 = 15`.
    const STRADDLE_EPOCH: u64 = RULE_BOUNDARY_HEIGHT / EPOCH;

    /// An honest chain (every block commits the canonical schedule) up to `tip`,
    /// under the real epoch length and the real boundary.
    fn honest_chain(tip: u64) -> Vec<SupplyBlock> {
        (0..=tip)
            .map(|height| block_on(1, height, if height == 0 { 0 } else { coinbase(height) }, 0))
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

    /// **Activated 2026-08-10 (lab #299/#303).** The shipped table now carries the
    /// 15 wholly-pre-boundary epochs (0..=14), generated by `qumbra-node
    /// emission-pins` on a linux/aarch64 host. This locks the table's *shape* — 15
    /// contiguous rows covering `0..=17_279`, every one strictly below
    /// `RULE_BOUNDARY_HEIGHT` (epoch 15 straddles and is deliberately NOT pinned).
    /// Values were coordinator-verified against issue #299's body (epochs 0/1/2)
    /// and an independent evaluation (epoch 3); a regeneration that changes any
    /// literal fails the golden below and demands re-review.
    #[test]
    fn the_activated_pin_table_is_fifteen_contiguous_pre_boundary_epochs() {
        assert_eq!(PINNED_EPOCH_EXPECTED.len(), 15, "epochs 0..=14 pin, epoch 15 straddles");
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
        assert_eq!(PINNED_EPOCH_EXPECTED[14].expected_coinbase, 5681292920005);
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
}
