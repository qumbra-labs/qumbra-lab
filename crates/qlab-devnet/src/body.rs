//! Block bodies carrying transaction proofs, and the block-body validation rule.
//!
//! A block body is the transaction set. Each transaction is an **opaque STARK
//! proof** plus the public surface consensus checks without opening the proof:
//! the finalized anchor it proves membership against (consensus §6), its
//! nullifiers and output commitments, its arity bucket, and the fee it pays.
//!
//! Block-body validation ties three earlier pieces together:
//!   1. the tx proof verifies — via an injected [`TxVerifier`] (the real M3
//!      verifier lives in `qlab-bench`; this crate stays prover-free, so the
//!      logic is unit-testable with a mock);
//!   2. the anchor is a **finalized root** — the anchors-from-finalized-only rule
//!      (§6), supplied as the `is_anchor_final` predicate (棒 2 `FinalityTracker`);
//!   3. the fee equals the **posted price** for the tx's arity bucket (§8, 棒 4).
//!
//! Plus a within-block nullifier-uniqueness check (no double-spend inside one
//! block). Cross-block nullifier-set tracking (the permanent hot set, §6) is a
//! documented extension, not built here.
//!
//! Ordering: the cheap public checks (anchor, fee, nullifier) run before the
//! expensive proof verify — "block validity checking is nearly free … sub-ms
//! verification is never the bottleneck" (performance §5 / consensus §1).

use std::collections::HashSet;

use crate::fees::{posted_fee, ArityBucket};
use crate::hash::keccak256;
use crate::header::{BlockHeader, Hash32};

/// The public surface of a shielded transaction — everything consensus checks
/// without opening the proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxPublic {
    /// The finalized commitment root this tx proves membership against (§6).
    pub anchor: Hash32,
    /// Spent-note nullifiers.
    pub nullifiers: Vec<Hash32>,
    /// New output commitments.
    pub commitments: Vec<Hash32>,
    /// Arity bucket (→ posted fee).
    pub bucket: ArityBucket,
    /// Fee paid (must equal the posted price for `bucket`).
    pub fee: u64,
}

/// A transaction in a block body: an opaque serialized proof + its public surface.
#[derive(Clone)]
pub struct TxEntry {
    /// Serialized STARK proof bytes — opaque to consensus (verified via [`TxVerifier`]).
    pub proof: Vec<u8>,
    /// The public values the proof binds.
    pub public: TxPublic,
}

/// A block body: the transaction set, the coinbase counter, and the miner's
/// payout key material.
///
/// The coinbase counter is the scheduled emission for the height — **not**
/// emission logic in this crate (the curve lives in `qlab_node::emission`); the
/// epoch supply-attestation header field stays RESERVED (§9).
///
/// ## `coinbase_rkm` (issue #101)
///
/// Raw recipient key material for the block's coinbase note, as the miner's
/// wallet computes it (`rkm = H(nk ‖ D_R ‖ d)`, `qlab_wallet`). It is **raw
/// `rkm`, not an address**: an address needs a derivation step, and a derivation
/// that is subtly wrong yields a syntactically valid note nobody can spend —
/// silently burning the block's whole issuance, undetected until someone tries
/// to spend, possibly thousands of blocks later. Raw `rkm` has no step to get
/// wrong: the value in the block is the value in the commitment preimage.
/// Address ergonomics belong to the wallet layer, where a mistake is recoverable.
///
/// This field is what makes a mined coin spendable at all. Before it, a block
/// named an *amount* and no recipient, so no real note could be minted, so the
/// coinbase had no commitment-tree leaf and no membership witness — see
/// `qlab_node::coinbase`.
#[derive(Clone, Default)]
pub struct BlockBody {
    pub txs: Vec<TxEntry>,
    pub coinbase: u64,
    /// The miner's raw `rkm` for this block's coinbase note (issue #101).
    /// `[0; 4]` means "no payee" and is rejected for any block that mints
    /// (`coinbase > 0`) — see [`BodyError::MissingCoinbasePayee`].
    pub coinbase_rkm: [u64; 4],
}

impl BlockBody {
    /// A deterministic Keccak-256 commitment to the body, for binding into the
    /// header's `tx_body_commitment`. Encodes each tx's public surface and proof
    /// bytes in order, then the coinbase counter, then the coinbase payout key.
    ///
    /// 🔴 **This preimage changed in issue #101** — `coinbase_rkm` was appended
    /// after the coinbase counter, so every block body commits to a different
    /// value than it did before. That is a wire/consensus break, bound into the
    /// header through `tx_body_commitment` (#79). It is locked by
    /// `golden_body_commitment_bytes` below; a later change to this preimage MUST
    /// break that test.
    pub fn commitment(&self) -> Hash32 {
        let mut buf = Vec::new();
        for tx in &self.txs {
            buf.extend_from_slice(&tx.public.anchor);
            for nf in &tx.public.nullifiers {
                buf.extend_from_slice(nf);
            }
            for cm in &tx.public.commitments {
                buf.extend_from_slice(cm);
            }
            buf.push(tx.public.bucket.logical_actions() as u8);
            buf.extend_from_slice(&tx.public.fee.to_le_bytes());
            buf.extend_from_slice(&(tx.proof.len() as u64).to_le_bytes());
            buf.extend_from_slice(&tx.proof);
        }
        buf.extend_from_slice(&self.coinbase.to_le_bytes());
        for lane in &self.coinbase_rkm {
            buf.extend_from_slice(&lane.to_le_bytes());
        }
        keccak256(&buf)
    }

    /// Total fees in the body (posted prices; the miner earns these + coinbase).
    pub fn total_fees(&self) -> u64 {
        self.txs.iter().map(|t| t.public.fee).sum()
    }

    /// Whether this body mints issuance without naming a payee — a block that
    /// pays `coinbase > 0` to `rkm = [0; 4]`. See
    /// [`BodyError::MissingCoinbasePayee`].
    pub fn mints_without_payee(&self) -> bool {
        self.coinbase > 0 && self.coinbase_rkm == [0u64; 4]
    }
}

/// Verifies a transaction's STARK proof against its public surface. The concrete
/// verifier (the real M3 verifier) is injected — this crate carries no prover.
pub trait TxVerifier {
    /// `true` iff `entry.proof` is a valid proof for `entry.public`.
    fn verify_tx(&self, entry: &TxEntry) -> bool;
}

/// Why a block body was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BodyError {
    /// The body is not the body the header committed to: `body.commitment()` does
    /// not equal the header's `tx_body_commitment` (issue #77).
    ///
    /// **This is misbehaviour, not an honest error.** There is no honest way to
    /// produce a header/body pair that fails this — the producer either mutated
    /// the body or relayed something it never checked. Callers on the p2p path
    /// must penalise the sender, not merely drop the object.
    CommitmentMismatch { expected: Hash32, got: Hash32 },
    /// The body mints issuance (`coinbase > 0`) but names no payee
    /// (`coinbase_rkm == [0; 4]`) — issue #101.
    ///
    /// **Why this is a rule and not a shrug.** The whole reason the payout field
    /// carries raw `rkm` rather than an address is that a wrong derivation
    /// produces a syntactically valid note nobody can spend, burning the block's
    /// issuance with nothing to detect it. Raw `rkm` removes the derivation but
    /// not that failure mode: `[0; 4]` is what a `..Default::default()`, a
    /// forgotten field, or an un-upgraded assembler produces, and no `(sk, d)`
    /// yields `rkm = 0`, so the coins are gone. If a block mints, it must name
    /// someone. Genesis is exempt for free — it carries `coinbase == 0`.
    MissingCoinbasePayee,
    /// The tx at `index` references an anchor that is not a finalized root (§6).
    AnchorNotFinal { index: usize },
    /// The tx at `index` pays the wrong fee for its arity bucket (§8).
    WrongFee { index: usize, expected: u64, got: u64 },
    /// A nullifier is repeated within the block (double-spend).
    DoubleSpendInBlock { index: usize },
    /// The tx at `index` has an invalid proof.
    ProofInvalid { index: usize },
}

/// Check that `body` is the body `header` committed to (issue #77).
///
/// `tx_body_commitment` is part of the header's hash preimage
/// ([`BlockHeader::preimage`]), so a header is cryptographically bound to *a*
/// body — this is the function that establishes it is bound to *this* one.
/// Without it a header no longer determines the state it produces: an honest
/// header relayed with a foreign (or empty) body applies foreign state under a
/// valid PoW header, and two honest nodes diverge under an identical header
/// chain.
///
/// Called first by [`validate_body`], so no caller has to remember it.
pub fn check_body_binding(header: &BlockHeader, body: &BlockBody) -> Result<(), BodyError> {
    let got = body.commitment();
    if header.tx_body_commitment != got {
        return Err(BodyError::CommitmentMismatch {
            expected: header.tx_body_commitment,
            got,
        });
    }
    Ok(())
}

/// Validate a block body **against its header**: the body is the one the header
/// committed to, every anchor is finalized, every fee = posted price, no
/// nullifier is repeated in-block, and every proof verifies.
///
/// Ordering is load-bearing (issue #77 P1): the header/body binding
/// ([`check_body_binding`]) runs **before any other body work**. It is the
/// cheapest possible rejection and the most fundamental — if the body is not the
/// header's body, nothing else about it is worth computing. Its cost is
/// O(block bytes) hashing, which the STARK verification immediately after it
/// dwarfs by orders of magnitude, so it is **not** cached, deferred or made
/// conditional on the code path.
///
/// Taking the header is the structural half of the fix: a caller that holds a
/// body cannot validate it without also producing the header it claims to belong
/// to, so a future seam cannot silently skip the binding check.
///
/// `is_anchor_final` is the anchors-from-finalized-only gate (§6) — pass
/// `|r| tracker.is_root_final(r)` from the 棒 2 [`crate::finality::FinalityTracker`].
pub fn validate_body<V, F>(
    header: &BlockHeader,
    body: &BlockBody,
    verifier: &V,
    is_anchor_final: F,
) -> Result<(), BodyError>
where
    V: TxVerifier,
    F: Fn(&Hash32) -> bool,
{
    check_body_binding(header, body)?;
    // A minting block must name a payee (issue #101). Second-cheapest check
    // after the binding, and it guards the block's whole issuance.
    if body.mints_without_payee() {
        return Err(BodyError::MissingCoinbasePayee);
    }
    let mut seen_nf: HashSet<Hash32> = HashSet::new();
    for (i, tx) in body.txs.iter().enumerate() {
        if !is_anchor_final(&tx.public.anchor) {
            return Err(BodyError::AnchorNotFinal { index: i });
        }
        let expected = posted_fee(tx.public.bucket);
        if tx.public.fee != expected {
            return Err(BodyError::WrongFee { index: i, expected, got: tx.public.fee });
        }
        for nf in &tx.public.nullifiers {
            if !seen_nf.insert(*nf) {
                return Err(BodyError::DoubleSpendInBlock { index: i });
            }
        }
        if !verifier.verify_tx(tx) {
            return Err(BodyError::ProofInvalid { index: i });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock verifier: a proof is "valid" iff its bytes are exactly `b"ok"`. Lets
    /// us test the body-validation logic without the real prover.
    struct MockVerifier;
    impl TxVerifier for MockVerifier {
        fn verify_tx(&self, entry: &TxEntry) -> bool {
            entry.proof == b"ok"
        }
    }

    const FINAL_ANCHOR: Hash32 = [0x0F; 32];

    /// A non-zero payout key for bodies that mint (issue #101).
    const MINER_RKM: [u64; 4] = [0xA1, 0xA2, 0xA3, 0xA4];

    fn is_final(r: &Hash32) -> bool {
        *r == FINAL_ANCHOR
    }

    /// An honest header for `body` — one that commits to exactly this body. Every
    /// positive test must produce one; that is the point of the signature.
    fn header_for(body: &BlockBody) -> BlockHeader {
        let genesis = BlockHeader::genesis(1, 0);
        BlockHeader::child_of(&genesis, 75, 1, body.commitment())
    }

    fn good_tx(nf: u8) -> TxEntry {
        TxEntry {
            proof: b"ok".to_vec(),
            public: TxPublic {
                anchor: FINAL_ANCHOR,
                nullifiers: vec![[nf; 32]],
                commitments: vec![[nf.wrapping_add(1); 32]],
                bucket: ArityBucket::TwoByTwo,
                fee: posted_fee(ArityBucket::TwoByTwo),
            },
        }
    }

    #[test]
    fn valid_body_passes_and_commitment_is_deterministic() {
        let body = BlockBody { txs: vec![good_tx(1), good_tx(2)], coinbase: 42, coinbase_rkm: MINER_RKM };
        let header = header_for(&body);
        assert_eq!(validate_body(&header, &body, &MockVerifier, is_final), Ok(()));
        assert_eq!(body.commitment(), body.commitment());
        assert_eq!(body.total_fees(), 2 * posted_fee(ArityBucket::TwoByTwo));
        // A different body ⇒ different commitment.
        let other = BlockBody { txs: vec![good_tx(1)], coinbase: 42, coinbase_rkm: MINER_RKM };
        assert_ne!(body.commitment(), other.commitment());
    }

    #[test]
    fn non_finalized_anchor_is_rejected() {
        let mut tx = good_tx(1);
        tx.public.anchor = [0xEE; 32]; // not the finalized root
        let body = BlockBody { txs: vec![tx], coinbase: 0, coinbase_rkm: [0; 4] };
        assert_eq!(
            validate_body(&header_for(&body), &body, &MockVerifier, is_final),
            Err(BodyError::AnchorNotFinal { index: 0 })
        );
    }

    #[test]
    fn wrong_fee_is_rejected() {
        let mut tx = good_tx(1);
        tx.public.fee += 1;
        let body = BlockBody { txs: vec![tx], coinbase: 0, coinbase_rkm: [0; 4] };
        assert_eq!(
            validate_body(&header_for(&body), &body, &MockVerifier, is_final),
            Err(BodyError::WrongFee {
                index: 0,
                expected: posted_fee(ArityBucket::TwoByTwo),
                got: posted_fee(ArityBucket::TwoByTwo) + 1,
            })
        );
    }

    #[test]
    fn in_block_double_spend_is_rejected() {
        // Two txs sharing a nullifier.
        let a = good_tx(7);
        let mut b = good_tx(9);
        b.public.nullifiers = a.public.nullifiers.clone();
        let body = BlockBody { txs: vec![a, b], coinbase: 0, coinbase_rkm: [0; 4] };
        assert_eq!(
            validate_body(&header_for(&body), &body, &MockVerifier, is_final),
            Err(BodyError::DoubleSpendInBlock { index: 1 })
        );
    }

    #[test]
    fn invalid_proof_is_rejected() {
        let mut tx = good_tx(1);
        tx.proof = b"forged".to_vec();
        let body = BlockBody { txs: vec![tx], coinbase: 0, coinbase_rkm: [0; 4] };
        assert_eq!(
            validate_body(&header_for(&body), &body, &MockVerifier, is_final),
            Err(BodyError::ProofInvalid { index: 0 })
        );
    }

    // --- issue #77: the header/body binding ---------------------------------

    /// A body that is not the one the header committed to is rejected — the
    /// invariant itself, at the validation seam.
    #[test]
    fn body_not_matching_the_header_commitment_is_rejected() {
        let honest = BlockBody { txs: vec![good_tx(1), good_tx(2)], coinbase: 42, coinbase_rkm: MINER_RKM };
        let header = header_for(&honest); // commits to `honest`…
        let swapped = BlockBody { txs: vec![good_tx(3)], coinbase: 42, coinbase_rkm: MINER_RKM }; // …but we hand it this
        assert_eq!(
            validate_body(&header, &swapped, &MockVerifier, is_final),
            Err(BodyError::CommitmentMismatch {
                expected: honest.commitment(),
                got: swapped.commitment(),
            })
        );
    }

    /// **The cheapest exploit (issue #77): an honest header relayed with an empty
    /// body.** Every other body rule passes trivially on an empty body — no tx to
    /// have a bad anchor, a wrong fee, a repeated nullifier or an invalid proof —
    /// so the binding check is the *only* thing that rejects it.
    #[test]
    fn empty_body_under_an_honest_header_is_rejected() {
        let honest = BlockBody { txs: vec![good_tx(1), good_tx(2)], coinbase: 42, coinbase_rkm: MINER_RKM };
        let header = header_for(&honest);
        let empty = BlockBody::default();
        // Everything except the binding is happy with the empty body:
        assert_eq!(validate_body(&header_for(&empty), &empty, &MockVerifier, is_final), Ok(()));
        // …under the honest header it must not be:
        assert_eq!(
            validate_body(&header, &empty, &MockVerifier, is_final),
            Err(BodyError::CommitmentMismatch {
                expected: honest.commitment(),
                got: empty.commitment(),
            })
        );
    }

    /// P1: the binding runs **before** any other body work. A body that is both
    /// unbound *and* internally invalid reports the mismatch — proving nothing
    /// expensive (proof verification) ran first.
    #[test]
    fn binding_is_checked_before_any_other_body_work() {
        let mut tx = good_tx(1);
        tx.proof = b"forged".to_vec(); // would be ProofInvalid…
        tx.public.anchor = [0xEE; 32]; // …and AnchorNotFinal
        let body = BlockBody { txs: vec![tx], coinbase: 0, coinbase_rkm: [0; 4] };
        let foreign = header_for(&BlockBody::default());
        assert_eq!(
            validate_body(&foreign, &body, &MockVerifier, is_final),
            Err(BodyError::CommitmentMismatch {
                expected: BlockBody::default().commitment(),
                got: body.commitment(),
            })
        );
    }

    // --- issue #101: the coinbase payout field ------------------------------

    /// A block that mints issuance but names no payee is rejected. `[0; 4]` is
    /// the shape a `..Default::default()`, a dropped field, or an un-upgraded
    /// assembler produces, and no `(sk, d)` derives `rkm = 0` — so accepting it
    /// burns the block's whole issuance with nothing to detect it.
    #[test]
    fn a_minting_block_with_no_payee_is_rejected() {
        let body = BlockBody { txs: vec![good_tx(1)], coinbase: 5_000, coinbase_rkm: [0; 4] };
        assert_eq!(
            validate_body(&header_for(&body), &body, &MockVerifier, is_final),
            Err(BodyError::MissingCoinbasePayee)
        );
        // Naming a payee is the only difference, and it passes.
        let paid = BlockBody { coinbase_rkm: MINER_RKM, ..body.clone() };
        assert_eq!(validate_body(&header_for(&paid), &paid, &MockVerifier, is_final), Ok(()));
        // A non-minting block needs no payee — this is what exempts genesis,
        // which carries `coinbase == 0`.
        let no_mint = BlockBody { coinbase: 0, ..body };
        assert_eq!(
            validate_body(&header_for(&no_mint), &no_mint, &MockVerifier, is_final),
            Ok(())
        );
    }

    /// The payout key is *inside* the header binding: swapping only `coinbase_rkm`
    /// under an otherwise honest header is caught. Without this the field would be
    /// unauthenticated and any relay could redirect a block's issuance.
    #[test]
    fn redirecting_the_payout_key_breaks_the_header_binding() {
        let honest =
            BlockBody { txs: vec![good_tx(1)], coinbase: 5_000, coinbase_rkm: MINER_RKM };
        let header = header_for(&honest);
        let stolen = BlockBody { coinbase_rkm: [0xBAD; 4], ..honest.clone() };
        assert_ne!(honest.commitment(), stolen.commitment(), "rkm must enter the preimage");
        assert_eq!(
            validate_body(&header, &stolen, &MockVerifier, is_final),
            Err(BodyError::CommitmentMismatch {
                expected: honest.commitment(),
                got: stolen.commitment(),
            })
        );
    }

    /// A fixed body with every field pinned — the input to the golden vector.
    fn golden_body() -> BlockBody {
        BlockBody {
            txs: vec![TxEntry {
                proof: vec![0xAB, 0xCD, 0xEF],
                public: TxPublic {
                    anchor: [0x11; 32],
                    nullifiers: vec![[0x22; 32], [0x33; 32]],
                    commitments: vec![[0x44; 32], [0x55; 32]],
                    bucket: ArityBucket::TwoByTwo,
                    fee: 0x0102_0304_0506_0708,
                },
            }],
            coinbase: 0x1234_5678_9ABC_DEF0,
            coinbase_rkm: [
                0x0011_2233_4455_6677,
                0x8899_AABB_CCDD_EEFF,
                0x0F0E_0D0C_0B0A_0908,
                0x0706_0504_0302_0100,
            ],
        }
    }

    /// 🔴 **The golden vector for `BlockBody::commitment()`** — the thing that did
    /// not exist before issue #101, and whose absence is why the block-body format
    /// could be changed with the whole suite staying green.
    ///
    /// `wire.rs`'s `golden_header_bytes` locks the **p2p envelope header**, not the
    /// block body. `valid_body_passes_and_commitment_is_deterministic` asserts only
    /// `commitment() == commitment()` — determinism, not a fixed value. So nothing
    /// held this preimage, and a body-format change (which is a consensus break,
    /// because #79 binds this value into the header) produced no failing test.
    ///
    /// **This value was deliberately changed by issue #101.** Adding `coinbase_rkm`
    /// to the preimage moved it:
    ///
    /// ```text
    ///   before #101: 02566c7473c06db6c281fe2b90d264956bccd5a4c75c5fa4828a9d1644bf67cf
    ///   after  #101: (the constant below)
    /// ```
    ///
    /// The "before" value is recorded so the break is legible, not so it can be
    /// restored. If you are here because this test failed: you changed the block
    /// body format. That is a consensus break and it needs the halt-height upgrade
    /// path (#74), not a new constant.
    #[test]
    fn golden_body_commitment_bytes() {
        let hex: String =
            golden_body().commitment().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex, "0ac5b4641291df8cbf328ab2c82a83cbb03da8b60a888177791f4ce04a78b613",
            "block-body commitment preimage changed — see this test's doc comment"
        );
    }

    /// The empty body's commitment, pinned for the same reason: since issue #115
    /// it **is the genesis header's `tx_body_commitment`**, so this constant is
    /// now an input to the network identity; and it is the cheapest body an
    /// attacker can substitute (`empty_body_under_an_honest_header_is_rejected`).
    #[test]
    fn golden_empty_body_commitment_bytes() {
        let hex: String =
            BlockBody::default().commitment().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex, "daa77426c30c02a43d9fba4e841a6556c524d47030762eb14dc4af897e605d9b",
            "empty-body commitment changed — see golden_body_commitment_bytes"
        );
    }

    /// **Inverted by issue #115 at the 2026-07-31 genesis mint.** This test used
    /// to read `genesis_header_does_not_bind_its_empty_body` and locked the
    /// opposite fact: the genesis header pinned `tx_body_commitment = ZERO_HASH`
    /// while its empty body commits to `keccak256(coinbase_le ‖ rkm_le)`, so
    /// genesis was the one block that did not satisfy the binding. Its own note
    /// said "if this ever becomes equal the genesis exemption can be dropped" —
    /// it has, and it was.
    ///
    /// Locked in this direction now so the binding cannot be un-done by a later
    /// reader restoring `ZERO_HASH`, which would silently move the network
    /// identity back.
    #[test]
    fn genesis_header_binds_its_empty_body() {
        let g = BlockHeader::genesis(1_000, 0);
        assert_eq!(
            g.tx_body_commitment,
            BlockBody::default().commitment(),
            "genesis binds its own body (issue #115)"
        );
        assert_ne!(
            g.tx_body_commitment,
            crate::header::ZERO_HASH,
            "ZERO_HASH is the pre-#115 value — restoring it re-opens issue #77 F1"
        );
        // …and the binding check agrees, with no height special case.
        assert!(check_body_binding(&g, &BlockBody::default()).is_ok());
    }

    /// The negative half at this crate's seam: a genesis header paired with a
    /// body it does not commit to is rejected by `check_body_binding` exactly
    /// like any other height (issue #115). `qlab_node` locks the same property
    /// at the node's state-mutation funnel.
    #[test]
    fn a_genesis_header_with_a_foreign_body_is_rejected() {
        let g = BlockHeader::genesis(1_000, 0);
        let foreign = BlockBody { txs: Vec::new(), coinbase: 1, coinbase_rkm: [1, 2, 3, 4] };
        assert!(matches!(
            check_body_binding(&g, &foreign),
            Err(BodyError::CommitmentMismatch { .. })
        ));

        // And the pre-#115 genesis header over the honest empty body: the exact
        // pair the height-0 exemption used to wave through.
        let mut pre_115 = g;
        pre_115.tx_body_commitment = crate::header::ZERO_HASH;
        assert!(matches!(
            check_body_binding(&pre_115, &BlockBody::default()),
            Err(BodyError::CommitmentMismatch { .. })
        ));
    }
}

