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
//! 1. **A two-real grant costs exactly one note**, in every bucket size. Larger
//!    buckets (the frozen §5 fee table prices 4×4 and 8×8; only 2×2 has an AIR)
//!    amortise *proofs*, never the note budget.
//! 2. **No transaction can increase the count.** A self-transaction is 2-in/2-out,
//!    i.e. Δ0. So a "split one big note into fifty small ones" step is
//!    unrepresentable — 1→N requires more outputs than inputs, which a fixed equal
//!    arity forbids. A **recut** can freely reassign note *values* (sum-preserving)
//!    but never their *count*.
//! 3. So there is no denomination *strategy* to choose. What is left to choose is
//!    which pair to spend, and that choice cannot affect the budget at all (Δ is
//!    −1 either way) — only which values survive. [`Inventory::select_pair`]
//!    therefore optimises the only thing still free: it takes the **smallest-sum
//!    pair that covers the outlay**, which minimises value moved through a proof,
//!    retires the two smallest notes (so value does not fragment into a growing
//!    tail), and leaves the largest note intact as the reserve that keeps a
//!    feasible pair available for as long as *any* single note covers
//!    `grant + fee`.
//!
//! ## The last note is spendable — issue #292's fallback (2026-08-11)
//!
//! Everything above describes a **two-real** grant, which is what this faucet built
//! unconditionally until now. Its arithmetic left one thing stranded: with
//! `count − 1` grants available, the final note could never be spent at all. Not
//! "spent later" — *never*, at any value, including at shutdown. The mint
//! ([PR #252](https://github.com/qumbra-labs/qumbra-lab/pull/252)) made the #219
//! latch unconditional and single-note spends legal, and nothing here was re-shaped
//! to use it.
//!
//! [`Inventory::select_inputs`] now spends **one real note plus a dummy slot** when
//! the anchor can witness exactly one note:
//!
//! ```text
//!   Δ(faucet note count) = −1 + 1 = 0
//! ```
//!
//! **It is a fallback, not the default** — Larry's ruling on #292, 2026-08-11.
//! Always-prefer-the-dummy maximises grants per matured note, but it makes the
//! count monotonically non-decreasing, so every drawn-down note leaves a remnant
//! below `grant + fee` that only a two-real spend can reclaim: it needs a
//! consolidation policy that this does not.
//!
//! The ground for deferring that is an **estimate, and labelled as one** — the
//! fleet's ~48 blk/h at the re-stamp, node3 the only host paying the faucet's rkm
//! (`qumbra-deploy` OPERATOR §9.5.2), and an assumed equal share of the four
//! hosts' hashrate: ≈288 notes/day of inflow, against ⌊50 QMB ÷ 10.01 QMB⌋ ≈ 5
//! grants of *value* per note, i.e. a value ceiling near 1,400/day. Nobody has
//! measured node3's actual share. The claim it supports is only the ordering —
//! count binds well before value does, and neither is near a testnet faucet's real
//! demand — so a fallback buys the wedge-safety without buying the policy. Re-open
//! #292 with evidence that grants/day is approaching inflow.
//!
//! **The two shapes are indistinguishable on the wire** and that is a property, not
//! a hope: `build_bucket_dummy1`'s program is byte-identical to the two-real one
//! (same 83 perms, same role word, same trace height, same public-value layout),
//! `dv` is a witness that never reaches a constraint constant, and `PV_NF2` is a
//! real nullifier of an invented note still bound by `ROLE_BNF2`. `qumbra-wallet`'s
//! `send` has spent this way since the mint — a granted user's *first* spend is a
//! one-real spend, so the anonymity set already contains them.
//!
//! **What the fallback does not fix: value still declines.** Each grant costs
//! `grant + fee` whatever its arity, so the tail is bounded by the last note's own
//! value — which is why [`Inventory::grants_available`] now takes the outlay and
//! reports the value bound rather than `count − 1`, a number that is no longer a
//! ceiling in either direction.
//!
//! ## Anchored vs held — the distinction an operator actually needs
//!
//! A note is spendable only when it is a leaf of the **prefix the anchor pins**.
//! A change note from the grant two seconds ago is *held* but not yet *anchored*:
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
    /// If this note came from a coinbase, the **height of the block that minted
    /// it**; `None` for an ordinary note.
    ///
    /// This used to be the coinbase-note *commitment*, carried so a grant could
    /// declare the coinbase notes it consumes for `Mempool::admit`'s maturity gate.
    /// Issue #102 deleted that declaration — it was the §6 privacy leak — and made
    /// maturity structural, so a commitment has nothing left to feed. The height
    /// does: maturity is a function of height, so this is what lets a holder ask
    /// [`qlab_node::coinbase_maturity`] whether a note with no membership witness is
    /// immature or nonexistent, and it is what the faucet's funding threshold is
    /// computed from.
    pub coinbase_minted_at: Option<u64>,
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
        Self { value, rho, rseed, d, cm, coinbase_minted_at: None }
    }

    /// The same, for a note minted as the coinbase of the block at
    /// `coinbase_minted_at`. Its leaf enters the commitment tree 144 blocks later
    /// (frozen §2, enforced by the append schedule since issue #102), so it has no
    /// membership witness and cannot be spent before then.
    pub fn from_coinbase(
        wallet: &Wallet,
        value: u64,
        rho: [u64; 4],
        rseed: [u64; 4],
        d: Diversifier,
        coinbase_minted_at: u64,
    ) -> Self {
        Self { coinbase_minted_at: Some(coinbase_minted_at), ..Self::new(wallet, value, rho, rseed, d) }
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
    /// **No** note is a leaf of the anchor's prefix. `held` is the total note
    /// count; `anchored` is how many of them the anchor can actually witness, and
    /// reaching this variant means it is zero.
    ///
    /// `held ≥ 1` here means **wait**: notes exist but the chain has not finalized
    /// a root that contains them. `held == 0` means the faucet is unfunded — only
    /// a coinbase note refills it.
    ///
    /// The threshold was `anchored < 2` until the #292 fallback: one anchored note
    /// is now a spendable inventory (module docs), so a single note is no longer
    /// reported as being out of them.
    OutOfNotes { held: usize, anchored: usize },
    /// At least one anchored note, but no legal input set reaches the outlay.
    /// `best_inputs` is the largest sum one can reach — the best pair when two or
    /// more are anchored, the note itself when exactly one is — so the shortfall
    /// is `need − best_inputs`.
    InsufficientValue { need: u64, best_inputs: u64 },
}

impl std::fmt::Display for InventoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InventoryError::OutOfNotes { held, anchored } => write!(
                f,
                "out of spendable notes: {held} held, {anchored} anchored (a transaction needs at \
                 least one anchored note, and only coinbase refills an empty faucet)"
            ),
            InventoryError::InsufficientValue { need, best_inputs } => write!(
                f,
                "insufficient value: need {need} bessel, best available inputs are {best_inputs}"
            ),
        }
    }
}

/// Which of the faucet's own notes one grant will spend.
///
/// The two variants are the two legal input shapes of the frozen 2×2 bucket, and
/// they differ in exactly one operational way — what they do to the note count
/// (module docs). Indices are into [`Inventory::notes`] and are only valid against
/// the inventory that produced them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selection {
    /// Two real anchored notes. `Δ(note count) = −1`.
    Pair([usize; 2]),
    /// One real anchored note; slot 1 is a prover-invented dummy (#219's latch).
    /// `Δ(note count) = 0` — the #292 fallback, taken only when the anchor can
    /// witness exactly one note.
    Single(usize),
}

/// The faucet's own notes that a built grant has consumed — two on the ordinary
/// path, one on the dummy path.
///
/// A typed pair-or-single rather than a `Vec`: a grant that spent zero notes, or
/// three, is not a state this faucet can reach, and making it unrepresentable is
/// cheaper than asserting it at every rollback site.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpentInputs {
    /// Both slots were real notes.
    Pair([OwnedNote; 2]),
    /// Slot 0 was real; slot 1 was the dummy, which is nobody's note.
    Single(OwnedNote),
}

impl SpentInputs {
    /// The real notes, in slot order.
    pub fn as_slice(&self) -> &[OwnedNote] {
        match self {
            SpentInputs::Pair(notes) => notes.as_slice(),
            SpentInputs::Single(note) => std::slice::from_ref(note),
        }
    }

    /// Iterate the real notes, in slot order.
    pub fn iter(&self) -> std::slice::Iter<'_, OwnedNote> {
        self.as_slice().iter()
    }

    /// Total value of the real inputs — what the balance was built from.
    pub fn total_value(&self) -> u64 {
        self.iter().map(|n| n.value).fold(0u64, u64::saturating_add)
    }

    /// Whether slot 1 was a dummy (#219's latch), i.e. this grant was
    /// note-count-neutral.
    pub fn used_dummy(&self) -> bool {
        matches!(self, SpentInputs::Single(_))
    }
}

impl IntoIterator for SpentInputs {
    type Item = OwnedNote;
    type IntoIter = std::vec::IntoIter<OwnedNote>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            SpentInputs::Pair([a, b]) => vec![a, b].into_iter(),
            SpentInputs::Single(a) => vec![a].into_iter(),
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

    /// **The budget**: how many more grants of `need` bessel (`grant + fee`) this
    /// holding can serve.
    ///
    /// `⌊total_value / need⌋`, and it is an **upper bound rather than a schedule**.
    /// Every grant removes exactly `need` from the faucet's total value whatever
    /// its arity, so no future sequence can beat this figure; it is reached when
    /// the value can actually be assembled, which two-real grants drive towards by
    /// consolidating (`−1` note each) until one note holds everything. It
    /// overstates when value is fragmented — many notes, no pair covering `need` —
    /// and that is the `InsufficientValue` state, which the caller reports
    /// separately rather than folding into this number.
    ///
    /// Counts *held* notes, anchored or not, exactly as the count-based figure it
    /// replaces did: an unanchored note is value the faucet will get to spend, and
    /// the wait is [`Self::anchored`]'s story, not this one.
    ///
    /// 🔴 **This was `count − 1` until issue #292's fallback**, and that number is
    /// now wrong in both directions — the dummy path serves the last note's value
    /// repeatedly at `Δcount = 0` (so `count − 1` understates), while value can run
    /// out first (so it overstates). An operator acts on this figure, so it could
    /// not be left stale; it takes `need` now because a value bound without the
    /// outlay is not computable.
    pub fn grants_available(&self, need: u64) -> usize {
        if need == 0 {
            return 0;
        }
        (self.total_value() / need) as usize
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
            None => Err(InventoryError::InsufficientValue { need, best_inputs: best_pair_seen }),
        }
    }

    /// **The input-shape policy, in one place** — choose what one grant of `need`
    /// bessel spends.
    ///
    /// Two real notes whenever the anchor can witness two; one real note plus a
    /// dummy slot when it can witness exactly one. That ordering is issue #292's
    /// **fallback** reading, ruled by Larry on 2026-08-11, and the module docs
    /// carry the grounds for preferring it over always-dummy.
    ///
    /// The trigger needs no value test of its own, and that is worth stating
    /// because a reader will look for one: a pair's sum is never smaller than
    /// either note alone, so "no pair covers `need`" already implies "no single
    /// note covers `need`". There is therefore **no value-wedge the fallback could
    /// rescue** — it exists purely for the count-wedge, where the anchor witnesses
    /// one note that is perfectly able to pay.
    ///
    /// Note the direction is deliberately **opposite** to `qumbra_wallet::send`'s,
    /// which sorts largest-first and takes the single-note path whenever one note
    /// suffices. Neither is a bug: a wallet minimises the notes it moves per spend,
    /// while a faucet maximises how long it keeps a feasible pair (`select_pair`'s
    /// smallest-covering rule, module docs). Changing either to match the other is
    /// a policy change, not a cleanup.
    pub fn select_inputs(
        &self,
        need: u64,
        tree: &CommitmentTree,
        anchor_leaf_count: u64,
    ) -> Result<Selection, InventoryError> {
        let anchored = self.anchored(tree, anchor_leaf_count);
        match anchored.len() {
            0 => Err(InventoryError::OutOfNotes { held: self.notes.len(), anchored: 0 }),
            1 => {
                let i = anchored[0];
                let value = self.notes[i].value;
                if value >= need {
                    Ok(Selection::Single(i))
                } else {
                    Err(InventoryError::InsufficientValue { need, best_inputs: value })
                }
            }
            _ => self.select_pair(need, tree, anchor_leaf_count).map(Selection::Pair),
        }
    }

    /// Remove the selected notes and return them, ready for `build_grant`.
    /// Panics if an index is out of range — the selection comes from
    /// [`Self::select_inputs`] against this same inventory.
    pub fn take_selected(&mut self, selection: Selection) -> SpentInputs {
        match selection {
            Selection::Pair(pair) => SpentInputs::Pair(self.take_pair(pair)),
            Selection::Single(i) => SpentInputs::Single(self.notes.remove(i)),
        }
    }

    /// Put spent inputs back — the rollback path when a built grant is not
    /// accepted. See [`Self::restore_pair`] for why restoring is safe against the
    /// one race it has.
    pub fn restore(&mut self, notes: SpentInputs) {
        self.notes.extend(notes);
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
    fn the_budget_is_value_not_count() {
        // The headline number after #292. It used to be `count − 1`; the case that
        // proves the difference is one note worth many grants.
        let w = wallet();
        let mut inv = Inventory::new();
        assert_eq!(inv.grants_available(10), 0, "an empty faucet serves nothing");

        // ONE note of 50 ⇒ five grants of 10, where `count − 1` said zero. This is
        // the whole fix in one assertion.
        inv.insert(note(&w, 50, 1));
        assert_eq!(inv.grants_available(10), 5);

        // A second note adds its value and nothing else — count is not a term.
        inv.insert(note(&w, 30, 2));
        assert_eq!(inv.grants_available(10), 8);

        // Nine more notes too small to matter on their own still contribute value:
        // 80 + 9 = 89 ⇒ 8 grants, and NOT 8 because there are 11 notes.
        for tag in 3..12 {
            inv.insert(note(&w, 1, tag));
        }
        assert_eq!(inv.len(), 11);
        assert_eq!(inv.grants_available(10), 8);

        // Rounding is down, and a zero outlay is not a division.
        assert_eq!(inv.grants_available(89), 1);
        assert_eq!(inv.grants_available(90), 0);
        assert_eq!(inv.grants_available(0), 0);
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

    /// The #292 policy, at its two boundaries: one anchored note is served by the
    /// dummy path, two are served by a pair, and neither decision consults
    /// anything but how many notes the anchor can witness.
    #[test]
    fn one_anchored_note_takes_the_dummy_path_and_two_take_the_pair() {
        let w = wallet();
        let mut inv = Inventory::new();
        inv.insert(note(&w, 10_000, 1));
        inv.insert(note(&w, 10_000, 2));
        let (tree, full) = tree_with(inv.notes(), 2);

        // Exactly one witnessable ⇒ Single, on the note the anchor can reach.
        // Under the old rule this was `OutOfNotes` and the faucet stalled here.
        assert_eq!(
            inv.select_inputs(9_000, &tree, full - 1),
            Ok(Selection::Single(0)),
            "one anchored note is a spendable inventory"
        );
        // Both witnessable ⇒ the ordinary two-real path.
        assert_eq!(inv.select_inputs(9_000, &tree, full), Ok(Selection::Pair([0, 1])));
        // None witnessable ⇒ still out of notes, and it names both counts.
        assert_eq!(
            inv.select_inputs(9_000, &tree, 2),
            Err(InventoryError::OutOfNotes { held: 2, anchored: 0 })
        );
    }

    /// The single note has to cover the outlay on its own — the fallback rescues a
    /// *count* shortage and never invents value.
    #[test]
    fn the_fallback_still_refuses_a_note_that_cannot_pay() {
        let w = wallet();
        let mut inv = Inventory::new();
        inv.insert(note(&w, 100, 1));
        inv.insert(note(&w, 100, 2));
        let (tree, full) = tree_with(inv.notes(), 1);

        assert_eq!(inv.select_inputs(100, &tree, full - 1), Ok(Selection::Single(0)));
        assert_eq!(
            inv.select_inputs(101, &tree, full - 1).unwrap_err(),
            InventoryError::InsufficientValue { need: 101, best_inputs: 100 },
            "the shortfall is reported against the one note, not a phantom pair"
        );

        // And the property that makes the trigger need no value test: a pair's sum
        // is never below either note, so a value-wedge the fallback could rescue
        // does not exist. With both anchored and 150 needed, the pair covers it —
        // there is no state where a single note pays and no pair does.
        assert_eq!(inv.select_inputs(150, &tree, full), Ok(Selection::Pair([0, 1])));
        assert!(matches!(
            inv.select_inputs(201, &tree, full).unwrap_err(),
            InventoryError::InsufficientValue { best_inputs: 200, .. }
        ));
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
            InventoryError::InsufficientValue { need: 1_000, best_inputs: 50 }
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

        // The same, through the shape-carrying pair — and through the single, whose
        // rollback is the one a wedged faucet depends on. (Values are read back
        // rather than hard-coded: a restore appends, so the order after the round
        // trip above is not the insertion order.)
        let expected = inv.notes()[1].value + inv.notes()[3].value;
        let taken = inv.take_selected(Selection::Pair([1, 3]));
        assert_eq!(inv.len(), 2);
        assert!(!taken.used_dummy());
        assert_eq!(taken.total_value(), expected);
        inv.restore(taken);
        assert_eq!(inv.total_value(), before);

        let taken = inv.take_selected(Selection::Single(2));
        assert_eq!(inv.len(), 3);
        assert!(taken.used_dummy(), "one real input means slot 1 was the dummy");
        assert_eq!(taken.as_slice().len(), 1, "a dummy is nobody's note and is not carried");
        inv.restore(taken);
        assert_eq!(inv.len(), 4);
        assert_eq!(inv.total_value(), before, "rollback conserves value on both shapes");
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

        // A two-real grant: 2 in, 1 output back to us ⇒ Δ−1.
        let taken = inv.take_selected(Selection::Pair([0, 1]));
        let change = taken.total_value() - 500_000_000 - 1_000_000;
        inv.insert(note(&w, change, 102));
        assert_eq!(inv.len(), start - 1, "a two-real grant costs exactly one note");

        // A dummy-path grant: 1 real in, 1 output back to us ⇒ Δ0. This is the
        // arithmetic #292 turns on, and the reason the last note is no longer
        // stranded — repeat it and the count never falls.
        let at_zero_delta = inv.len();
        for round in 0..3 {
            let taken = inv.take_selected(Selection::Single(0));
            let change = taken.total_value() - 500_000_000 - 1_000_000;
            inv.insert(note(&w, change, 200 + round));
            assert_eq!(inv.len(), at_zero_delta, "the dummy path is note-count-neutral");
        }
        // …and what it costs instead is value. Reconciled to the bessel: six notes
        // of 1 QMB-scale value, less the recut's fee, less four grants (the
        // two-real one and the three dummy ones) at 500_000_000 + 1_000_000 each.
        assert_eq!(inv.total_value(), 6 * 1_000_000_000 - 1_000_000 - 501_000_000 * 4);
    }
}
