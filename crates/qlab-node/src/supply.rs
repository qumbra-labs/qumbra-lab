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

use crate::emission::s_atomic;

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
}

impl SupplyLedger {
    pub fn new(epoch_length: u64) -> Result<Self, SupplyError> {
        if epoch_length == 0 {
            return Err(SupplyError::ZeroEpochLength);
        }
        Ok(Self {
            epoch_length,
            next_height: 0,
            rows: Vec::new(),
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

        let first_mint = row.start_height.max(1);
        row.expected_coinbase = if row.end_height < first_mint {
            0
        } else {
            s_atomic(row.end_height + 1) - s_atomic(first_mint)
        };
        Ok(())
    }
}

/// Group a contiguous canonical chain into epoch attestations.
///
/// Genesis is part of epoch 0's covered range but contributes zero expected
/// issuance: this implementation's genesis body is empty, and the first mined
/// block is height 1. For a row covering `[start, end]`, expected issuance is
/// therefore `s_atomic(end + 1) - s_atomic(max(start, 1))`.
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
