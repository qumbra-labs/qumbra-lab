//! The faucet's spendable note set — and the conservation law that governs it.
//!
//! ## Why this module exists, and why it is not a "denomination strategy"
//!
//! The obvious faucet design pre-cuts the treasury into many small notes of exact
//! denominations so each disbursement is a tidy "spend one exact note, hand it
//! over". **That design cannot be built on this chain**, and the reason is
//! arithmetic rather than taste.
//!
//! In an *n*×*n* bucket the faucet consumes *n* of its own notes and creates *n*
//! outputs, of which *g* go to recipients and *n − g* return as change:
//!
//! ```text
//!   Δ(faucet note count) = −n + (n − g) = −g
//! ```
//!
//! Three consequences, all load-bearing here:
//!
//! 1. **Every grant costs exactly one note**, in every bucket size. Larger buckets
//!    (the frozen §5 fee table prices 4×4 and 8×8; only 2×2 has an AIR) amortise
//!    *proofs*, never the note budget.
//! 2. **No transaction can increase the count.** A self-transaction is 2-in/2-out,
//!    i.e. Δ0. So a "split one big note into fifty small ones" step is
//!    unrepresentable — 1→N requires more outputs than inputs, which a fixed equal
//!    arity forbids. A **recut** can freely reassign note *values* (sum-preserving)
//!    but never their *count*.
//! 3. Therefore [`Inventory::grants_available`] is `count − 1` (two notes are
//!    needed to build one transaction), and the only inflow is a coinbase note —
//!    one per block the faucet wins.
//!
//! So there is no denomination *strategy* to choose; there is a **note-count
//! budget** to spend and report honestly. What is left to choose is which pair to
//! spend, and that choice cannot affect the budget at all (Δ is −1 either way) —
//! only which values survive. [`Inventory::select_pair`] therefore optimises the
//! only thing still free: it takes the **smallest-sum pair that covers the outlay**,
//! which minimises value moved through a proof, retires the two smallest notes
//! (so value does not fragment into a growing tail), and leaves the largest note
//! intact as the reserve that keeps a feasible pair available for as long as *any*
//! single note covers `grant + fee`.
//!
//! ## Anchored vs held — the distinction an operator actually needs
//!
//! A note is spendable only when it is a leaf of the **prefix the anchor pins**.
//! A change note from the grant three seconds ago is *held* but not yet *anchored*:
//! its block may be unmined, unfinalized, or finalized after the anchor in hand.
//! Conflating the two is how a faucet reports "funded" while being unable to pay,
//! so every query here takes the tree and the anchor's leaf count, and
//! [`InventoryError`] distinguishes "I have no notes" from "my notes are not yet
//! anchored" from "my notes are anchored but too small".

use qlab_air::narrow::{derive_input, TxInput};
use qlab_cbserver::tree::CommitmentTree;
use qlab_wallet::address::Diversifier;
use qlab_wallet::Wallet;

/// One note the faucet owns and can spend.
///
/// `cm` is cached rather than re-derived on every query: locating a note in the
/// tree is a `position_of` lookup keyed on the commitment, and a faucet does that
/// once per candidate per selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedNote {
    /// Note value in bessel (1 QMB = 10⁸ bessel, frozen §8).
    pub value: u64,
    /// Orchard-style uniqueness seed ρ — also what the nullifier binds.
    pub rho: [u64; 4],
    /// Randomness seed.
    pub rseed: [u64; 4],
    /// The address diversifier this note was paid to. The circuit re-derives
    /// `rkm = H(nk ‖ D_R ‖ d)`, so spending needs the *same* `d` (issue #32) —
    /// carrying it is not optional bookkeeping.
    pub d: Diversifier,
    /// The leaf commitment `cm = H(value ‖ rkm ‖ ρ ‖ rseed)`.
    pub cm: [u64; 4],
    /// If this note came from a coinbase, the **coinbase-note commitment** the node
    /// registered for the block that minted it
    /// (`qlab_node::coinbase_note_commitment`).
    ///
    /// Carried so a grant can *declare* the coinbase notes it consumes, which is
    /// what `Mempool::admit` needs to run the frozen §2 144-block maturity gate. The
    /// faucet's real funding is coinbase, so this is the field that binds constraint
    /// four to the code path that enforces it — and it is `Option` because the lab
    /// funds the faucet from a seeded note set (a coinbase note is not a tree leaf in
    /// this prototype; see the crate docs).
    pub coinbase_note: Option<[u8; 32]>,
}

impl OwnedNote {
    /// Build the record for a note this wallet owns at diversifier `d`, deriving
    /// the leaf commitment through the *same* path the circuit binds
    /// ([`derive_input`] on a real spend witness) rather than recomputing the
    /// packing here — a fork of that layout is exactly the class of drift the
    /// repo's "never fork" rule exists to stop.
    pub fn new(wallet: &Wallet, value: u64, rho: [u64; 4], rseed: [u64; 4], d: Diversifier) -> Self {
        let input = wallet.spend_input(value, rho, rseed, d);
        let (_nk, _nf, cm) = derive_input(&input);
        Self { value, rho, rseed, d, cm, coinbase_note: None }
    }

    /// The same, for a note whose origin is the coinbase of the block whose
    /// coinbase-note commitment is `coinbase_note`. Spending it must clear the
    /// 144-block maturity gate.
    pub fn from_coinbase(
        wallet: &Wallet,
        value: u64,
        rho: [u64; 4],
        rseed: [u64; 4],
        d: Diversifier,
        coinbase_note: [u8; 32],
    ) -> Self {
        Self { coinbase_note: Some(coinbase_note), ..Self::new(wallet, value, rho, rseed, d) }
    }

    /// The circuit spend witness for this note (the spend capability lives only on
    /// [`Wallet`]/`SpendingKey`).
    pub fn spend_input(&self, wallet: &Wallet) -> TxInput {
        wallet.spend_input(self.value, self.rho, self.rseed, self.d)
    }
}

/// Why the faucet cannot build a transaction from what it holds.
///
/// The three variants are deliberately distinct: they call for three different
/// operator actions (mine more blocks / wait for finality / re-fund), and a faucet
/// that collapses them into one "insufficient funds" is a faucet nobody can debug.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InventoryError {
    /// Fewer than two notes are leaves of the anchor's prefix. `held` is the total
    /// note count; `anchored` is how many of them the anchor can actually witness.
    ///
    /// `held ≥ 2` with `anchored < 2` means **wait**: change notes exist but the
    /// chain has not finalized a root that contains them. `held < 2` means the
    /// note budget is spent — see the module docs; only coinbase refills it.
    OutOfNotes { held: usize, anchored: usize },
    /// Two or more anchored notes, but no pair sums to the outlay. `best_pair` is
    /// the largest available pair sum, so the shortfall is `need − best_pair`.
    InsufficientValue { need: u64, best_pair: u64 },
}

impl std::fmt::Display for InventoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InventoryError::OutOfNotes { held, anchored } => write!(
                f,
                "out of spendable notes: {held} held, {anchored} anchored (a transaction needs 2; \
                 every grant costs exactly one note and only coinbase refills the count)"
            ),
            InventoryError::InsufficientValue { need, best_pair } => write!(
                f,
                "insufficient value: need {need} bessel, best available pair is {best_pair}"
            ),
        }
    }
}

impl std::error::Error for InventoryError {}

/// The faucet's spendable note set.
#[derive(Clone, Debug, Default)]
pub struct Inventory {
    notes: Vec<OwnedNote>,
}

impl Inventory {
    /// An empty inventory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a note the faucet owns. Newly-added notes are *held*; they become
    /// *anchored* only once a valid anchor's prefix contains their leaf.
    pub fn insert(&mut self, note: OwnedNote) {
        self.notes.push(note);
    }

    /// Total notes held (anchored or not).
    pub fn len(&self) -> usize {
        self.notes.len()
    }

    /// Whether nothing is held.
    pub fn is_empty(&self) -> bool {
        self.notes.is_empty()
    }

    /// Total value held in bessel, anchored or not.
    pub fn total_value(&self) -> u64 {
        self.notes.iter().map(|n| n.value).sum()
    }

    /// All held notes, in insertion order (ops/reporting).
    pub fn notes(&self) -> &[OwnedNote] {
        &self.notes
    }

    /// **The note-count budget**: how many grants the current holding can serve
    /// before it wedges, ignoring value. `count − 1`, because each grant consumes
    /// two notes and returns one, and a transaction needs two inputs.
    ///
    /// This is the number a faucet operator should watch, and it is the reason the
    /// throughput ceiling is note inflow rather than proof time (module docs).
    pub fn grants_available(&self) -> usize {
        self.notes.len().saturating_sub(1)
    }

    /// Indices of the notes the anchor's prefix can witness: a leaf of the tree at
    /// a position **strictly below** `anchor_leaf_count`. A note appended after the
    /// anchor's prefix exists in the tree but folds to a *different* root, so
    /// witnessing it against this anchor is not possible.
    pub fn anchored(&self, tree: &CommitmentTree, anchor_leaf_count: u64) -> Vec<usize> {
        self.notes
            .iter()
            .enumerate()
            .filter(|(_, n)| {
                tree.position_of(&n.cm).is_some_and(|pos| pos < anchor_leaf_count)
            })
            .map(|(i, _)| i)
            .collect()
    }

    /// Choose the two input notes for a transaction whose outputs plus fee come to
    /// `need` bessel: the **smallest-sum anchored pair with `sum ≥ need`** (see the
    /// module docs for why that is the only free choice left).
    ///
    /// Ties break on the lower index pair, so selection is deterministic and a
    /// replayed faucet makes the same choices.
    pub fn select_pair(
        &self,
        need: u64,
        tree: &CommitmentTree,
        anchor_leaf_count: u64,
    ) -> Result<[usize; 2], InventoryError> {
        let anchored = self.anchored(tree, anchor_leaf_count);
        if anchored.len() < 2 {
            return Err(InventoryError::OutOfNotes {
                held: self.notes.len(),
                anchored: anchored.len(),
            });
        }
        let mut best: Option<([usize; 2], u64)> = None;
        let mut best_pair_seen = 0u64;
        for (a, &i) in anchored.iter().enumerate() {
            for &j in &anchored[a + 1..] {
                let sum = self.notes[i].value.saturating_add(self.notes[j].value);
                best_pair_seen = best_pair_seen.max(sum);
                if sum >= need && best.is_none_or(|(_, b)| sum < b) {
                    best = Some(([i, j], sum));
                }
            }
        }
        match best {
            Some((pair, _)) => Ok(pair),
            None => Err(InventoryError::InsufficientValue { need, best_pair: best_pair_seen }),
        }
    }

    /// Remove two notes by index and return them (highest index first, so the
    /// second removal is not shifted). Panics if an index is out of range — the
    /// indices come from [`Self::select_pair`] against this same inventory.
    pub fn take_pair(&mut self, pair: [usize; 2]) -> [OwnedNote; 2] {
        let (lo, hi) = if pair[0] < pair[1] { (pair[0], pair[1]) } else { (pair[1], pair[0]) };
        assert_ne!(lo, hi, "a transaction cannot spend the same note twice");
        let high = self.notes.remove(hi);
        let low = self.notes.remove(lo);
        [low, high]
    }

    /// Put two notes back — the rollback path when a built grant is not accepted.
    ///
    /// Rollback is safe against the one race it has: if the transaction *was* in
    /// fact accepted while the faucet believed otherwise, the restored notes are
    /// already spent and the next attempt to use them is refused by the node's
    /// permanent nullifier set (`MempoolError::AlreadySpent`) rather than
    /// double-spending. The faucet loses a proof, not consensus safety.
    pub fn restore_pair(&mut self, notes: [OwnedNote; 2]) {
        self.notes.extend(notes);
    }

    /// Drop a note by its commitment (e.g. it was observed spent out-of-band).
    /// Returns whether it was held.
    pub fn forget(&mut self, cm: &[u64; 4]) -> bool {
        let before = self.notes.len();
        self.notes.retain(|n| &n.cm != cm);
        self.notes.len() != before
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_wallet::Wallet;

    fn wallet() -> Wallet {
        Wallet::from_seed_lanes([0xFA0C_E700_0000_0001; 4])
    }

    fn note(w: &Wallet, value: u64, tag: u64) -> OwnedNote {
        OwnedNote::new(w, value, [tag; 4], [tag ^ 0xFF; 4], Diversifier::default())
    }

    /// A tree holding every note in `notes`, plus `filler` unrelated leaves first
    /// so positions are not trivially 0,1,2… Returns the tree and its leaf count.
    fn tree_with(notes: &[OwnedNote], filler: u64) -> (CommitmentTree, u64) {
        let mut t = CommitmentTree::new();
        for i in 0..filler {
            t.append([i.wrapping_mul(0x9E37_79B9), i + 1, i + 2, i + 3]);
        }
        for n in notes {
            t.append(n.cm);
        }
        let c = t.len();
        (t, c)
    }

    #[test]
    fn cm_matches_the_circuit_derivation() {
        // OwnedNote must carry the leaf the circuit will bind, or the witness
        // fetched for it folds to nothing.
        let w = wallet();
        let n = note(&w, 50_000, 7);
        let input = w.spend_input(n.value, n.rho, n.rseed, n.d);
        assert_eq!(n.cm, derive_input(&input).2, "cached cm == circuit leaf");
    }

    #[test]
    fn grants_available_is_count_minus_one() {
        // The conservation law's headline number: two notes buy exactly one grant.
        let w = wallet();
        let mut inv = Inventory::new();
        assert_eq!(inv.grants_available(), 0);
        inv.insert(note(&w, 10, 1));
        assert_eq!(inv.grants_available(), 0, "one note cannot fund a 2-input tx");
        inv.insert(note(&w, 10, 2));
        assert_eq!(inv.grants_available(), 1);
        for tag in 3..10 {
            inv.insert(note(&w, 10, tag));
        }
        assert_eq!(inv.len(), 9);
        assert_eq!(inv.grants_available(), 8);
    }

    #[test]
    fn selection_takes_the_smallest_covering_pair() {
        let w = wallet();
        let mut inv = Inventory::new();
        // Values 5, 7, 100, 1_000 (insertion order deliberately unsorted).
        for (i, v) in [100u64, 5, 1_000, 7].into_iter().enumerate() {
            inv.insert(note(&w, v, i as u64 + 1));
        }
        let (tree, count) = tree_with(inv.notes(), 3);

        // need 12 ⇒ (5,7) = 12 is the smallest covering pair, not (5,100).
        let pair = inv.select_pair(12, &tree, count).expect("pair exists");
        let mut got: Vec<u64> = pair.iter().map(|&i| inv.notes()[i].value).collect();
        got.sort();
        assert_eq!(got, vec![5, 7], "smallest covering pair");

        // need 13 ⇒ (5,7) no longer covers; smallest covering is (5,100).
        let pair = inv.select_pair(13, &tree, count).expect("pair exists");
        let mut got: Vec<u64> = pair.iter().map(|&i| inv.notes()[i].value).collect();
        got.sort();
        assert_eq!(got, vec![5, 100]);

        // The largest note stays as reserve: nothing selects (100, 1000) until it
        // must.
        let pair = inv.select_pair(1_050, &tree, count).expect("pair exists");
        let mut got: Vec<u64> = pair.iter().map(|&i| inv.notes()[i].value).collect();
        got.sort();
        assert_eq!(got, vec![100, 1_000]);
    }

    #[test]
    fn out_of_notes_names_held_and_anchored_separately() {
        // The distinction an operator needs: two notes held, but only one of them
        // is a leaf of the anchor's prefix ⇒ "wait", not "re-fund".
        let w = wallet();
        let mut inv = Inventory::new();
        inv.insert(note(&w, 10_000, 1));
        inv.insert(note(&w, 10_000, 2));
        let (tree, full) = tree_with(inv.notes(), 2);
        // An anchor pinned one leaf short of the tree: the last note is held but
        // cannot be witnessed against it.
        let err = inv.select_pair(1, &tree, full - 1).unwrap_err();
        assert_eq!(err, InventoryError::OutOfNotes { held: 2, anchored: 1 });
        // With the full prefix it resolves.
        assert!(inv.select_pair(1, &tree, full).is_ok());
    }

    #[test]
    fn a_note_absent_from_the_tree_is_never_selected() {
        let w = wallet();
        let mut inv = Inventory::new();
        inv.insert(note(&w, 10_000, 1));
        inv.insert(note(&w, 10_000, 2));
        // Tree contains the fillers only — neither note has a leaf.
        let mut tree = CommitmentTree::new();
        tree.append([1, 2, 3, 4]);
        let count = tree.len();
        assert_eq!(
            inv.select_pair(1, &tree, count).unwrap_err(),
            InventoryError::OutOfNotes { held: 2, anchored: 0 }
        );
    }

    #[test]
    fn insufficient_value_reports_the_best_pair() {
        let w = wallet();
        let mut inv = Inventory::new();
        inv.insert(note(&w, 10, 1));
        inv.insert(note(&w, 20, 2));
        inv.insert(note(&w, 30, 3));
        let (tree, count) = tree_with(inv.notes(), 1);
        assert_eq!(
            inv.select_pair(1_000, &tree, count).unwrap_err(),
            InventoryError::InsufficientValue { need: 1_000, best_pair: 50 }
        );
    }

    #[test]
    fn take_and_restore_are_inverse() {
        let w = wallet();
        let mut inv = Inventory::new();
        for tag in 1..=4 {
            inv.insert(note(&w, 100 * tag, tag));
        }
        let before = inv.total_value();
        let taken = inv.take_pair([1, 3]);
        assert_eq!(inv.len(), 2);
        assert_eq!(taken[0].value, 200, "lower index first");
        assert_eq!(taken[1].value, 400);
        inv.restore_pair(taken);
        assert_eq!(inv.len(), 4);
        assert_eq!(inv.total_value(), before, "rollback conserves value");
    }

    #[test]
    fn a_recut_preserves_the_count_a_grant_costs_one() {
        // The conservation law, exercised as bookkeeping rather than as prose.
        let w = wallet();
        let mut inv = Inventory::new();
        for tag in 1..=6 {
            inv.insert(note(&w, 1_000_000_000, tag));
        }
        let start = inv.len();

        // A recut: 2 in, 2 out, both ours ⇒ Δ0.
        let taken = inv.take_pair([0, 1]);
        let sum = taken[0].value + taken[1].value - 1_000_000; // fee
        inv.insert(note(&w, sum / 2, 100));
        inv.insert(note(&w, sum - sum / 2, 101));
        assert_eq!(inv.len(), start, "a recut can never grow the note count");

        // A grant: 2 in, 1 output back to us ⇒ Δ−1.
        let taken = inv.take_pair([0, 1]);
        let change = taken[0].value + taken[1].value - 500_000_000 - 1_000_000;
        inv.insert(note(&w, change, 102));
        assert_eq!(inv.len(), start - 1, "every grant costs exactly one note");
    }
}
