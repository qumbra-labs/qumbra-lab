//! **The wallet's per-asset note index on an Annulet net** (lab #718, L2 C1).
//!
//! The wallet keeps no note store: every `scan` recomputes what it owns (the
//! wallet dir is a seed and an index cursor). So this is the in-memory index
//! over one scan's result. [`OwnedL2Note`] is the record, keyed by asset and
//! split spendable/spent by the same nullifier subtraction the L1 balance uses.
//!
//! [`OwnedL2Note`] is also **the record C2's spend path adopts**: with the
//! wallet's spending key and the note's diversifier index it yields the
//! circuit input ([`OwnedL2Note::spend_input`]), which is what the
//! served-witness spend assembly consumes. There is no second representation.
//!
//! **One key hierarchy serves both chains.** `qlab_wallet`'s
//! `rkm = H(nk ‖ D_R ‖ d)` and `nf = H(nk ‖ ρ)` are lane-for-lane the L2
//! circuit's (`qlab_air::l2::derive_input_l2`), so an existing wallet address
//! receives spendable L2 notes. The nullifier here is computed by the
//! circuit's own derivation, never a copy of it.

use std::collections::BTreeMap;

use qlab_air::l2::{derive_input_l2, L2TxInput};
use qlab_cbserver::client::LocatedNote;
use qlab_note::hash::digest_bytes;
use qlab_note::l2note::L2Note;
use qlab_wallet::Wallet;

use crate::spent::SpentSet;

/// An L2 note this wallet owns, located on the chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedL2Note {
    pub note: L2Note,
    /// The registry index of the note's asset (0 is the fee unit).
    pub asset: u16,
    /// The wallet address index the note was paid to.
    pub div_index: u64,
    /// Where it was committed: a block height, or 0 for a genesis note.
    pub height: u64,
    /// The transaction within that block; `None` for a genesis note.
    pub tx_index: Option<u64>,
    /// The committed commitment (from the served stream, not recomputed).
    pub cm: [u8; 32],
}

/// Why a served note could not become an [`OwnedL2Note`] — by name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssetError {
    /// The note's asset lane is ≥ 2^16, which no registry index can be (the
    /// note twin refuses it at parse; this is the same rule at the record).
    AssetOutOfRange { asset: u64 },
    /// The note's `rkm` is not this address's: it is not this wallet's note.
    NotThisAddress { div_index: u64 },
}

impl std::fmt::Display for AssetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssetError::AssetOutOfRange { asset } => {
                write!(f, "asset {asset} is outside the 16-bit registry index range")
            }
            AssetError::NotThisAddress { div_index } => {
                write!(f, "the note's rkm is not address {div_index}'s")
            }
        }
    }
}

impl std::error::Error for AssetError {}

fn asset_u16(asset: u64) -> Result<u16, AssetError> {
    u16::try_from(asset).map_err(|_| AssetError::AssetOutOfRange { asset })
}

impl OwnedL2Note {
    /// A note an L2 scan opened at address `div_index`.
    pub fn from_located(
        wallet: &Wallet,
        div_index: u64,
        located: &LocatedNote<L2Note>,
    ) -> Result<Self, AssetError> {
        Self::checked(wallet, div_index, located.detected.note, located.height, Some(located.tx_index), located.cm)
    }

    /// A genesis note (served on `/v1/genesis/notes`, not on `/v1/compact`)
    /// whose `rkm` is address `div_index`'s.
    pub fn from_genesis(wallet: &Wallet, div_index: u64, cm: [u8; 32], note: L2Note) -> Result<Self, AssetError> {
        Self::checked(wallet, div_index, note, 0, None, cm)
    }

    fn checked(
        wallet: &Wallet,
        div_index: u64,
        note: L2Note,
        height: u64,
        tx_index: Option<u64>,
        cm: [u8; 32],
    ) -> Result<Self, AssetError> {
        let asset = asset_u16(note.asset)?;
        if wallet.rkm(wallet.diversifier_at_index(div_index)) != note.rkm {
            return Err(AssetError::NotThisAddress { div_index });
        }
        Ok(Self { note, asset, div_index, height, tx_index, cm })
    }

    /// The circuit input spending this note — the wallet's `sk`, the note's
    /// fields, and its address diversifier. What C2's spend assembly takes.
    pub fn spend_input(&self, wallet: &Wallet) -> L2TxInput {
        let d = wallet.diversifier_at_index(self.div_index);
        let l1 = wallet.spend_input(self.note.value, self.note.rho, self.note.rseed, d);
        L2TxInput {
            sk: l1.sk,
            value: self.note.value,
            asset: self.note.asset,
            rho: self.note.rho,
            rseed: self.note.rseed,
            d: l1.d,
        }
    }

    /// The nullifier spending this note publishes — the circuit's own
    /// derivation (`derive_input_l2`), as served bytes.
    pub fn nullifier(&self, wallet: &Wallet) -> [u8; 32] {
        digest_bytes(&derive_input_l2(&self.spend_input(wallet)).1)
    }
}

/// One asset's notes, split by the nullifier stream.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AssetNotes {
    pub spendable: Vec<OwnedL2Note>,
    /// Spent notes, each with the height that published its nullifier.
    pub spent: Vec<(OwnedL2Note, u64)>,
}

impl AssetNotes {
    /// The sum of the spendable notes, in the asset's own units (`u128`: a sum
    /// of `u64`s is not a `u64`).
    pub fn spendable_value(&self) -> u128 {
        self.spendable.iter().map(|n| u128::from(n.note.value)).sum()
    }
}

/// **The per-asset index** over one scan: every owned note, keyed by asset,
/// split spendable/spent against `spent`.
///
/// 🔴 The rule is the L1's (lab #314): a figure exists only where both the
/// outputs and the nullifier stream are known, so this is built **only** from
/// a [`SpentSet`]; a caller without one has no index to show, not an index of
/// unsubtracted notes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AssetIndex {
    pub by_asset: BTreeMap<u16, AssetNotes>,
}

impl AssetIndex {
    pub fn build(wallet: &Wallet, notes: Vec<OwnedL2Note>, spent: &SpentSet) -> Self {
        let mut by_asset: BTreeMap<u16, AssetNotes> = BTreeMap::new();
        for note in notes {
            let entry = by_asset.entry(note.asset).or_default();
            match spent.height_of(&note.nullifier(wallet)) {
                Some(h) => entry.spent.push((note, h)),
                None => entry.spendable.push(note),
            }
        }
        Self { by_asset }
    }

    /// `(asset, spendable value)` per asset held, ascending by asset.
    pub fn balances(&self) -> Vec<(u16, u128)> {
        self.by_asset.iter().map(|(a, n)| (*a, n.spendable_value())).collect()
    }

    /// The spendable notes of one asset (empty when none).
    pub fn spendable(&self, asset: u16) -> &[OwnedL2Note] {
        self.by_asset.get(&asset).map(|n| n.spendable.as_slice()).unwrap_or(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_wallet::seed::{MasterSeed, ENTROPY_LEN};

    fn wallet() -> Wallet {
        Wallet::from_master_seed(&MasterSeed::from_entropy([7u8; ENTROPY_LEN]), 0)
    }

    fn note_to(w: &Wallet, idx: u64, value: u64, asset: u64, k: u64) -> L2Note {
        L2Note { value, asset, rkm: w.rkm(w.diversifier_at_index(idx)), rho: [k; 4], rseed: [k + 1; 4] }
    }

    /// 🔴 **P4, proved at the key layer** (lab #718): for an existing wallet
    /// address, the L2 circuit's own derivations (`derive_input_l2`,
    /// `l2p::derive_rkm_l2`) reproduce the wallet's `rkm` and its L1
    /// nullifier lane for lane — so an L1 address receives spendable L2 notes.
    #[test]
    fn an_existing_wallet_address_is_an_l2_spendable_address() {
        let w = wallet();
        for idx in [0u64, 1, 7] {
            let n = OwnedL2Note::from_genesis(&w, idx, [0; 32], note_to(&w, idx, 5, 1, 40 + idx)).expect("its own note");
            let input = n.spend_input(&w);
            assert_eq!(qlab_air::l2p::derive_rkm_l2(&input), w.address_at_index(idx).rkm_lanes(), "rkm, address {idx}");
            assert_eq!(n.nullifier(&w), digest_bytes(&w.nullifier(&n.note.rho)), "nf, address {idx}");
            let (_, _, cm) = derive_input_l2(&input);
            assert_eq!(cm, n.note.commitment(), "the circuit's commitment is the note's");
        }
    }

    #[test]
    fn the_index_splits_by_asset_and_by_the_nullifier_stream() {
        let w = wallet();
        let notes: Vec<OwnedL2Note> = [(0u64, 3u64, 0u64, 1u64), (0, 2, 0, 2), (1, 1_000_000, 1, 3), (1, 5, 1, 4)]
            .iter()
            .map(|&(idx, v, a, k)| OwnedL2Note::from_genesis(&w, idx, [k as u8; 32], note_to(&w, idx, v, a, k)).unwrap())
            .collect();
        let spent_nf = notes[3].nullifier(&w);
        let spent = SpentSet::from_parts(Some((0, 9)), [(9, spent_nf)]);
        let index = AssetIndex::build(&w, notes.clone(), &spent);
        assert_eq!(index.balances(), vec![(0, 5), (1, 1_000_000)]);
        assert_eq!(index.by_asset[&1].spent, vec![(notes[3].clone(), 9)]);
        assert_eq!(index.spendable(0).len(), 2);
        assert!(index.spendable(2).is_empty());
    }

    #[test]
    fn a_foreign_note_and_an_out_of_range_asset_are_refused_by_name() {
        let w = wallet();
        let other = Wallet::from_master_seed(&MasterSeed::from_entropy([8u8; ENTROPY_LEN]), 0);
        assert_eq!(
            OwnedL2Note::from_genesis(&w, 0, [0; 32], note_to(&other, 0, 1, 0, 1)),
            Err(AssetError::NotThisAddress { div_index: 0 })
        );
        assert_eq!(
            OwnedL2Note::from_genesis(&w, 0, [0; 32], note_to(&w, 0, 1, 1 << 16, 1)),
            Err(AssetError::AssetOutOfRange { asset: 1 << 16 })
        );
    }
}
