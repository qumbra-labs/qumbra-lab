//! The coinbase note (issue #101) — how a mined coin becomes a spendable note.
//!
//! ## What this replaces
//!
//! Before this module the block's coinbase had a "commitment" that was not a note
//! commitment: `keccak256(b"qumbra:devnet:coinbase-note:v1" ‖ height ‖ total)`,
//! domain-separated *precisely so it could never collide with a real note*. It
//! went into a registry and never into the commitment tree — and appending it
//! would not have helped, because the 2×2 circuit cannot open it. That function
//! is deleted, not deprecated: there is one kind of coinbase note now, and after
//! this module it is an ordinary note.
//!
//! A real note is `(value, rkm, ρ, rseed)` with `cm = H(value ‖ rkm ‖ ρ ‖ rseed)`
//! in the circuit's exact lane packing and **no domain string**
//! ([`qlab_note::note::note_commitment`]). To mint one for a miner you need the
//! miner's `rkm`, which no block carried — hence [`BlockBody::coinbase_rkm`].
//!
//! ## The derivation (consensus rules, ratified on issue #101)
//!
//! ```text
//!   value = RewardSplit::of(body.coinbase).miner + body.total_fees()
//!   rkm   = body.coinbase_rkm                                (raw, from the block)
//!   ρ     = H(b"qumbra:coinbase-note-rho:v1"   ‖ height_le ‖ rkm_le)
//!   rseed = H(b"qumbra:coinbase-note-rseed:v1" ‖ height_le ‖ rkm_le)
//!   cm    = note_commitment(value, rkm, ρ, rseed)            ← the tree leaf
//! ```
//!
//! Everything here is a **pure function of `(height, body)`**. That is the
//! property `open == replay` needs: a replaying node recomputes the identical
//! leaf from the identical block, with no access to node state, no clock and no
//! randomness.
//!
//! ### Why the opening is public, and why that is not a leak
//!
//! `tokenomics-and-issuance.md:116` — the coinbase note *"carries public value at
//! creation and enters the pool as an ordinary note after a maturity delay …
//! one-hop transparency, then gone."* A publicly reconstructible opening is
//! therefore the **supply-audit anchor** (`performance-budget` §9), not a privacy
//! defect. Privacy arrives when the note is spent into the pool, not when it is
//! created. Determinism also buys wallet-loss recovery: a miner who lost
//! everything but their spend key can rebuild the note from chain data, whereas a
//! random `rseed` would leave coins permanently unspendable that still count
//! against the audit equation.
//!
//! ### ρ: "tx-position derivation", for a thing with no tx position
//!
//! `transaction-model-and-anonymity-set.md:61` fixes ρ *"with tx-position
//! derivation for coinbase-like issuance"* and stops. A coinbase has no tx slot,
//! so its position **is** its height — exactly one coinbase per height, per
//! branch. `rkm` is in the preimage because `nf = Keccak(nk ‖ ρ)`
//! ([`qlab_air::narrow::derive_input`]) binds only `nk` and ρ: including `rkm`
//! makes a miner's coinbase nullifier depend on the address they were paid at
//! rather than on the height alone.
//!
//! ### The uniqueness claim, stated at the strength that actually holds
//!
//! One coinbase per height **per branch** — not per height. Two sibling blocks at
//! the same height may carry the same `coinbase_rkm` (a miner that finds two
//! nonces; an attacker that pays the honest miner's `rkm` to grief them), and
//! then the two preimages are equal. Because `nf` binds only `(nk, ρ)`, two
//! siblings paying the same miner with *different fee totals* yield **different
//! commitments and the same nullifier**.
//!
//! This is harmless and is left as-is deliberately: only one branch is canonical,
//! and the losing branch's issuance was never spendable. It is written down
//! because the ratification's "exactly one coinbase per height" is a stronger
//! claim than what holds, and the next reader should not build on it. Killing it
//! outright would mean binding the block hash into the preimage, which would make
//! the note underivable from the body and move it behind PoW grinding — a bad
//! trade for a collision confined to branches that lose.
//!
//! ## Value: what the note is worth, and one honest divergence
//!
//! [`coinbase_note_value`] is the miner's frozen §3 share (65 %, absorbing the
//! rounding remainder) plus the block's fees, which are paid to the miner and
//! never burned. The committee (15 %) and treasury (20 %) shares are **not**
//! minted: no payout path for them exists (they are accrual accounting —
//! `recovery::committee_accrual_finalized`), so minting them would require naming
//! recipients this baton has none for. The consequence is stated rather than
//! hidden: `Σ minted notes = 0.65·S(h) + fees`, not `S(h)`, so the §9 supply
//! attestation balances against a stated relation and not against `S(h)` directly
//! until those payout paths exist.
//!
//! **The divergence:** this is *not* [`crate::mempool::BlockTemplate::miner_take`],
//! which additionally subtracts the §6 quadratic weight penalty. The penalty
//! depends on the governor's effective median — node state the *applier* does not
//! reconstruct — and using it here would make block application depend on the
//! weight governor, or force the body to declare the penalty (another format
//! change). The penalty is 0 everywhere inside the 10 MB free zone, so on any net
//! we run the two agree; they are still not the same expression, and
//! [`crate::mempool::BlockTemplate`] carries the same note this module derives so
//! the assembler and the applier can never disagree about the leaf.

use qlab_devnet::body::BlockBody;
use qlab_devnet::hash::keccak256;
use qlab_note::hash::{digest_bytes, digest_from_bytes};
use qlab_note::note::Note;

use crate::emission::RewardSplit;
use crate::store::Hash32;

/// Domain string for a coinbase note's ρ. **Fresh** — deliberately not
/// `qumbra:devnet:coinbase-note:v1`, which belonged to the deleted placeholder
/// commitment; reusing it would make the two indistinguishable in exactly the
/// situation where telling them apart matters.
pub const COINBASE_RHO_DOMAIN: &[u8] = b"qumbra:coinbase-note-rho:v1";

/// Domain string for a coinbase note's `rseed`. See [`COINBASE_RHO_DOMAIN`].
pub const COINBASE_RSEED_DOMAIN: &[u8] = b"qumbra:coinbase-note-rseed:v1";

/// `H(domain ‖ height_le ‖ rkm_le)` as circuit lanes — the shared shape of both
/// the ρ and the `rseed` rule.
fn derive_lanes(domain: &[u8], height: u64, rkm: &[u64; 4]) -> [u64; 4] {
    let mut buf = Vec::with_capacity(domain.len() + 8 + 32);
    buf.extend_from_slice(domain);
    buf.extend_from_slice(&height.to_le_bytes());
    for lane in rkm {
        buf.extend_from_slice(&lane.to_le_bytes());
    }
    digest_from_bytes(&keccak256(&buf))
}

/// The coinbase note's ρ at `height` for payee `rkm`.
pub fn coinbase_rho(height: u64, rkm: &[u64; 4]) -> [u64; 4] {
    derive_lanes(COINBASE_RHO_DOMAIN, height, rkm)
}

/// The coinbase note's `rseed` at `height` for payee `rkm`.
pub fn coinbase_rseed(height: u64, rkm: &[u64; 4]) -> [u64; 4] {
    derive_lanes(COINBASE_RSEED_DOMAIN, height, rkm)
}

/// The value the coinbase note carries: the miner's frozen §3 share of the
/// block's scheduled emission plus the block's fees. See the module docs for why
/// the committee/treasury shares are not minted and why the §6 weight penalty is
/// not subtracted here.
pub fn coinbase_note_value(body: &BlockBody) -> u64 {
    RewardSplit::of(body.coinbase).miner.saturating_add(body.total_fees())
}

/// The coinbase note minted by `body` at `height`, or `None` if the block mints
/// nothing (`coinbase == 0` — genesis, and synthetic bodies in tests).
///
/// A block with `coinbase > 0` and no payee never reaches here: `validate_body`
/// rejects it (`BodyError::MissingCoinbasePayee`). The `rkm == [0; 4]` guard is
/// kept anyway so this function cannot mint an unspendable leaf even if it is
/// ever called off that path.
pub fn coinbase_note(height: u64, body: &BlockBody) -> Option<Note> {
    if body.coinbase == 0 || body.coinbase_rkm == [0u64; 4] {
        return None;
    }
    let rkm = body.coinbase_rkm;
    Some(Note {
        value: coinbase_note_value(body),
        rkm,
        rho: coinbase_rho(height, &rkm),
        rseed: coinbase_rseed(height, &rkm),
    })
}

/// The commitment-tree leaf for `body`'s coinbase note at `height` — the real
/// `note_commitment`, on-wire lane-major bytes, ready for
/// `CommitmentStore::append`. `None` exactly when [`coinbase_note`] is `None`.
///
/// **This is the leaf `height` *mints*, not the leaf `height` *appends*.** Since
/// issue #102 those are different heights: see [`matures_coinbase_minted_at`].
pub fn coinbase_note_leaf(height: u64, body: &BlockBody) -> Option<Hash32> {
    coinbase_note(height, body).map(|n| digest_bytes(&n.commitment()))
}

// ---------------------------------------------------------------------------
// The maturity append schedule (issue #102, option (b))
// ---------------------------------------------------------------------------

/// The height whose coinbase note a block at `height` appends to the commitment
/// tree, or `None` when the block is younger than the maturity delay and so
/// matures nothing.
///
/// **This is the single statement of the frozen §2 rule's enforcement.** Before
/// issue #102 the schedule was the identity — a block appended its *own*
/// coinbase leaf — and maturity was a mempool policy check against a submitter's
/// declaration, which was bypassable three separate ways (an honest-but-silent
/// `vec![]`, the hardcoded `vec![]` on the P2P path, and an in-memory registry
/// that is empty after every restart). None of those is a hole any more, because
/// there is nothing left to declare: an immature coinbase note **has no leaf in
/// any anchor this chain will accept**, therefore no membership witness against
/// one, therefore no spend that verifies. That beats `refused-by-policy` because it
/// holds against a submitter who lies, a peer that bypasses the mempool, and a node
/// that just restarted — none of which is being asked anything.
///
/// **Stated that way on purpose, because the short version is false.** "An immature
/// spend is unprovable" is not true in general: an attacker can append the leaf to a
/// tree of their own, take a genuine witness against it, and produce a perfectly
/// valid proof of a true statement about *that* tree — and the production verifier
/// accepts it. `qumbra-node`'s
/// `a_forged_anchor_carrying_a_real_proof_is_rejected_at_the_block_path` does exactly
/// this and asserts the acceptance. What is actually true is narrower and stronger:
/// **their proof is fine and their anchor is the lie**, and the anchor is checked by
/// `validate_body` on every block from every peer, with no mempool involved. Anyone
/// reading "unprovable rather than refused-by-policy" anywhere in this tree should
/// read that test — it is the difference between the slogan and the property.
///
/// Every consumer of the schedule calls this rather than restating `height − 144`:
/// [`crate::node::Node::apply_state`] to append, [`crate::rpc::NodeRpc`]'s anchor
/// reconstruction to count, and `qumbra_faucet::NodeView`'s to do the same for a
/// node that composes no RPC. That third one was a live off-by-144 until the full
/// suite caught it — restating a *sliding* rule is the shape issue #116 was filed
/// about, and #116 named only the first two because it was written about the RPC.
pub fn matures_coinbase_minted_at(height: u64) -> Option<u64> {
    height.checked_sub(crate::emission::COINBASE_MATURITY_BLOCKS)
}

/// The height at whose application the coinbase minted at `minted_height` enters
/// the commitment tree — the inverse of [`matures_coinbase_minted_at`], and the
/// first height whose root can serve as an anchor for spending it.
pub fn coinbase_leaf_appears_at(minted_height: u64) -> u64 {
    minted_height + crate::emission::COINBASE_MATURITY_BLOCKS
}

/// The coinbase leaf a block at `height` appends, given a lookup for the body of
/// its own ancestor at a given height. `None` when the block matures nothing —
/// it is below the delay, its ancestor is unreachable, or that ancestor minted
/// nothing (genesis).
///
/// The `ancestor_body` closure is what keeps this replay-identical: it must
/// resolve heights against **this block's own ancestry**, never against a
/// height-indexed side table, so the answer follows whichever chain the block is
/// on. See `Node::apply_state` for why nothing may be persisted here.
pub fn matured_coinbase_leaf<F>(height: u64, ancestor_body: F) -> Option<Hash32>
where
    F: FnOnce(u64) -> Option<BlockBody>,
{
    let minted_at = matures_coinbase_minted_at(height)?;
    coinbase_note_leaf(minted_at, &ancestor_body(minted_at)?)
}

/// Whether a coinbase note minted at a given height has entered the commitment
/// tree yet — and if not, when it will.
///
/// **This type exists because option (b) would otherwise make an immature
/// coinbase indistinguishable from a note that never existed.** Before #102 a
/// holder got `MempoolError::ImmatureCoinbase` — a wrong answer, but a legible
/// one. Under (b) the leaf is simply absent, and "absent" is the same signal a
/// wallet gets for a commitment that was never minted at all. An absence that
/// reads as a healthy empty state is this repository's most-repeated defect
/// (#104, #106, #113, #130, and #102's own fail-open), so the absence is given a
/// reason at the one place a holder can ask.
///
/// Asking costs nothing in privacy, and that is the whole difference from the
/// declaration this replaces. The declaration leaked because it bound a *spend*
/// to a *coinbase*; this names only a block height, which every node already has
/// in plaintext along with the payee's `coinbase_rkm`. Nothing about a spend is
/// stated, or even implied — the question is identical whether or not the asker
/// intends to spend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoinbaseMaturity {
    /// The leaf entered the tree when `leaf_at` was applied, so every root from
    /// that height onward contains it and a membership witness exists. If a
    /// witness still cannot be built, the note genuinely does not exist.
    Matured {
        /// The height whose application appended the leaf.
        leaf_at: u64,
    },
    /// The leaf does not exist yet. Its absence is the maturity rule, not a
    /// missing note, and it will be appended when `leaf_at` is applied.
    Immature {
        /// The height whose application will append the leaf.
        leaf_at: u64,
        /// Blocks the tip must still advance before then.
        blocks_remaining: u64,
    },
}

/// Answer [`CoinbaseMaturity`] for a coinbase minted at `minted_height` against
/// a chain whose tip is `tip_height`. Pure — both inputs are public chain facts.
pub fn coinbase_maturity(minted_height: u64, tip_height: u64) -> CoinbaseMaturity {
    let leaf_at = coinbase_leaf_appears_at(minted_height);
    match leaf_at.checked_sub(tip_height) {
        None | Some(0) => CoinbaseMaturity::Matured { leaf_at },
        Some(blocks_remaining) => CoinbaseMaturity::Immature { leaf_at, blocks_remaining },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emission::coinbase;
    use qlab_devnet::body::{TxEntry, TxPublic};
    use qlab_devnet::fees::{posted_fee, ArityBucket};

    const RKM_A: [u64; 4] = [0x1111, 0x2222, 0x3333, 0x4444];
    const RKM_B: [u64; 4] = [0x5555, 0x6666, 0x7777, 0x8888];

    fn fee_tx(nf: u8) -> TxEntry {
        TxEntry::with_placeholder_discovery(vec![0u8; 8], TxPublic {
            anchor: [0x0F; 32],
            nullifiers: vec![[nf; 32]],
            commitments: vec![[nf.wrapping_add(1); 32]],
            bucket: ArityBucket::TwoByTwo,
            fee: posted_fee(ArityBucket::TwoByTwo),
            })
    }

    fn body_at(height: u64, rkm: [u64; 4], n_txs: u8) -> BlockBody {
        BlockBody {
            txs: (0..n_txs).map(fee_tx).collect(),
            coinbase: coinbase(height),
            coinbase_rkm: rkm,
        }
    }

    /// The whole point of the module: what it mints is a **real note**, openable
    /// by the 2×2 circuit — not the deleted placeholder digest. Locked against
    /// `qlab_note::note_commitment`, which is itself regression-locked to
    /// `qlab_air::narrow::build_bucket`'s `cm_out`.
    #[test]
    fn the_minted_leaf_is_a_real_note_commitment() {
        let body = body_at(700, RKM_A, 0);
        let note = coinbase_note(700, &body).expect("a minting block mints a note");
        let leaf = coinbase_note_leaf(700, &body).expect("and therefore has a leaf");
        assert_eq!(leaf, digest_bytes(&note.commitment()));
        assert_eq!(
            note.commitment(),
            qlab_note::note::note_commitment(note.value, &note.rkm, &note.rho, &note.rseed),
        );
    }

    /// Pure function of `(height, body)` — the property `open == replay` rests
    /// on. Same inputs, same leaf, every time and on every node.
    #[test]
    fn derivation_is_deterministic() {
        let body = body_at(700, RKM_A, 2);
        assert_eq!(coinbase_note_leaf(700, &body), coinbase_note_leaf(700, &body));
        let same = body_at(700, RKM_A, 2);
        assert_eq!(coinbase_note_leaf(700, &same), coinbase_note_leaf(700, &body));
    }

    /// Height separates notes, and so does the payee. Both matter: height is what
    /// the uniqueness argument rests on within a branch, and `rkm` is what binds
    /// the note (and, through ρ, its nullifier) to who was paid.
    #[test]
    fn height_and_payee_each_separate_the_note() {
        let a = body_at(700, RKM_A, 0);
        let b = body_at(701, RKM_A, 0);
        let c = body_at(700, RKM_B, 0);
        assert_ne!(coinbase_note_leaf(700, &a), coinbase_note_leaf(701, &b), "height separates");
        assert_ne!(coinbase_note_leaf(700, &a), coinbase_note_leaf(700, &c), "payee separates");
        // ρ and rseed are separate derivations under separate domains — a
        // collision between them would silently weaken the note.
        assert_ne!(coinbase_rho(700, &RKM_A), coinbase_rseed(700, &RKM_A));
        assert_ne!(COINBASE_RHO_DOMAIN, COINBASE_RSEED_DOMAIN);
        // Neither domain reuses the tag of the object #101 deleted.
        for d in [COINBASE_RHO_DOMAIN, COINBASE_RSEED_DOMAIN] {
            assert_ne!(d, b"qumbra:devnet:coinbase-note:v1");
        }
    }

    /// The value rule: frozen §3 miner share of the scheduled emission, plus the
    /// block's fees, which are the miner's and never burned.
    #[test]
    fn value_is_the_miner_share_plus_fees() {
        let h = 700;
        let empty = body_at(h, RKM_A, 0);
        assert_eq!(coinbase_note_value(&empty), RewardSplit::of(coinbase(h)).miner);
        let two = body_at(h, RKM_A, 2);
        assert_eq!(
            coinbase_note_value(&two),
            RewardSplit::of(coinbase(h)).miner + 2 * posted_fee(ArityBucket::TwoByTwo),
        );
        // And it is strictly less than the whole emission — the committee and
        // treasury shares are deliberately not minted (module docs).
        assert!(coinbase_note_value(&empty) < coinbase(h));
    }

    /// A block that mints nothing mints no note — this is what exempts genesis,
    /// which carries `coinbase == 0`. And a payee-less body cannot produce a leaf
    /// even if this function is reached off the validation path.
    #[test]
    fn no_mint_and_no_payee_yield_no_note() {
        let genesis = BlockBody::default();
        assert_eq!(coinbase_note(0, &genesis), None);
        assert_eq!(coinbase_note_leaf(0, &genesis), None);
        let payeeless = BlockBody { coinbase: 5_000, ..BlockBody::default() };
        assert_eq!(coinbase_note(1, &payeeless), None);
    }

    /// The sibling-fork collision, pinned as a *known* property rather than left
    /// to be rediscovered. Two blocks at the same height paying the same miner
    /// with different fee totals: **different commitments, same nullifier**,
    /// because `nf = Keccak(nk ‖ ρ)` binds neither value nor rseed. Harmless —
    /// only one branch is canonical — but the ratified "exactly one coinbase per
    /// height" is not the claim that holds; "per height per branch" is.
    #[test]
    fn siblings_at_one_height_share_rho_and_therefore_a_nullifier() {
        let lean = body_at(700, RKM_A, 0);
        let fat = body_at(700, RKM_A, 3);
        let a = coinbase_note(700, &lean).unwrap();
        let b = coinbase_note(700, &fat).unwrap();
        assert_ne!(a.value, b.value, "different fee totals");
        assert_ne!(a.commitment(), b.commitment(), "so the leaves differ");
        // …but ρ is identical, and the nullifier is a function of (nk, ρ) alone.
        assert_eq!(a.rho, b.rho, "same height + same payee ⇒ same ρ");
        assert_eq!(a.rseed, b.rseed);
    }
}
