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

use qlab_note::compact::{
    contents_commitments, decode_group_contents, encode_group_contents, CodecError,
};
use qlab_note::wire::RecipientBundle;

use crate::fees::{posted_fee, ArityBucket};
use crate::hash::keccak256;
use crate::header::{BlockHeader, Hash32};

/// Domain tag leading the block-body preimage — **body format v2**, the
/// body-bound-discovery format (issue #188 / `discovery-on-the-consensus-wire.md`).
///
/// 🔴 **Why a tag exists at all, when the spec's §3 encoding does not ask for
/// one.** §3 appends `discovery_len ‖ discovery` inside each transaction's
/// region. A body with **no transactions** therefore has a byte-identical
/// preimage before and after this change — and since issue #115 the genesis
/// header's `tx_body_commitment` **is** the empty body's commitment, so the
/// genesis hash, and with it the network identity, would not have moved.
///
/// Two nodes on opposite sides of this change would then share a genesis, agree
/// on every coinbase-only block, and diverge silently at the first block
/// carrying a transaction. That is this project's most-repeated defect shape —
/// an absence that reads as a healthy empty state — and §5 of the spec asserts
/// the opposite outcome ("it moves `BlockBody::commitment()`, therefore the
/// header hash, therefore network identity"). The tag makes §5 true for every
/// body including the empty one, and satisfies the baton's acceptance item that
/// a body with no discovery groups "must not collide with a pre-change body's
/// commitment".
///
/// Format v1 (issue #101, `coinbase_rkm` appended) carried no tag; v2 is the
/// first tagged format, so a v1 preimage can never be re-produced by accident.
pub const BODY_PREIMAGE_DOMAIN: &[u8] = b"qumbra:body:v2";

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

/// A transaction in a block body: an opaque serialized proof, its public
/// surface, and its **note-discovery group**.
#[derive(Clone)]
pub struct TxEntry {
    /// Serialized STARK proof bytes — opaque to consensus (verified via [`TxVerifier`]).
    pub proof: Vec<u8>,
    /// The public values the proof binds.
    pub public: TxPublic,
    /// This transaction's discovery group, as the ratified §2 **group contents**
    /// (`n_recipients ‖ [ct ‖ n_outputs ‖ entries]`) — issue #188,
    /// `discovery-on-the-consensus-wire.md` D1/D2/D3.
    ///
    /// Held as bytes, not as a parsed structure, for two reasons. §4 rule 3
    /// states the canonicity rule over *bytes* ("decode, decode canonically, and
    /// re-encode to themselves"), which only a byte field can be checked
    /// against; and D2 wants serving to be a projection of the body rather than
    /// a second encoder, which is literal when the body holds the served bytes.
    ///
    /// **An empty group is `[0x00]`, not an empty `Vec`.** "I attached nothing"
    /// is the `n = 0` case of the binding rule (§4 rule 1), so it still has to
    /// be a well-formed encoding of zero recipients — a zero-length field would
    /// be a second, unparseable way to say the same thing. A transaction with
    /// output commitments and an `n = 0` group is **invalid**, which is the
    /// whole sentence §1 exists to create.
    pub discovery: Vec<u8>,
}

impl TxEntry {
    /// Build a transaction whose discovery group is `recipients`, encoded
    /// canonically. The only constructor callers should need.
    pub fn new(proof: Vec<u8>, public: TxPublic, recipients: &[RecipientBundle]) -> Self {
        Self { proof, public, discovery: encode_group_contents(recipients) }
    }

    /// The canonical encoding of "this transaction attaches no discovery",
    /// i.e. `n_recipients = 0`. Valid only for a transaction with no output
    /// commitments; see [`TxEntry::discovery`].
    pub fn empty_discovery() -> Vec<u8> {
        encode_group_contents(&[])
    }

    /// Decode this transaction's committed discovery bytes (§4 rule 3).
    ///
    /// `index` is only used to label the error — the bytes themselves carry no
    /// index (see [`qlab_note::compact::write_group_contents`]).
    pub fn discovery_group(&self, index: usize) -> Result<Vec<RecipientBundle>, BodyError> {
        decode_group_contents(&self.discovery)
            .map_err(|err| BodyError::DiscoveryMalformed { index, err })
    }
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
    ///
    /// 🔴 **And it changed again in issue #188** — body format **v2**:
    ///
    /// ```text
    /// domain "qumbra:body:v2"
    /// per tx:  anchor(32) ‖ nullifiers* ‖ commitments* ‖ bucket(1) ‖ fee(8 LE)
    ///                     ‖ proof_len(8 LE) ‖ proof
    ///                     ‖ discovery_len(8 LE) ‖ discovery
    /// then:    coinbase(8 LE) ‖ coinbase_rkm(4 × 8 LE)
    /// ```
    ///
    /// `discovery_len` is a `u64` LE **exactly like `proof_len`** — D3 says so,
    /// and it is not optional: discovery is genuinely variable-length
    /// (`n_recipients`, `n_outputs`, and eventually `clue_len` all vary), so the
    /// implicit delimiting that `nullifiers`/`commitments` get from the FROZEN
    /// 2×2 shape does not extend to it. Placement is **after `proof`**, at the
    /// end of the transaction's region, so the existing prefix stays byte-stable.
    ///
    /// The leading domain tag is [`BODY_PREIMAGE_DOMAIN`]; read its note before
    /// concluding it is decoration.
    pub fn commitment(&self) -> Hash32 {
        let mut buf = Vec::new();
        buf.extend_from_slice(BODY_PREIMAGE_DOMAIN);
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
            buf.extend_from_slice(&(tx.discovery.len() as u64).to_le_bytes());
            buf.extend_from_slice(&tx.discovery);
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

    // --- issue #188: body-bound discovery ----------------------------------
    //
    // 🔴 *Cannot parse* and *parses but does not bind* are deliberately two
    // answers, not one. Collapsing them has now cost this project three issues
    // (#134, #164, #181): a peer that sent malformed bytes and a peer that sent
    // well-formed bytes describing the wrong outputs are different peers doing
    // different things, and a caller that scores misbehaviour needs to tell them
    // apart. Neither is a `bool`.
    /// The tx at `index` carries discovery bytes that do not decode as a §2
    /// group's contents — truncated, trailing junk, an unsupported `clue_len`,
    /// or (on the serving side) a non-canonical varint. `err` is the codec's own
    /// verdict, kept rather than flattened.
    DiscoveryMalformed { index: usize, err: CodecError },
    /// The tx at `index` has a well-formed discovery group that describes
    /// different output commitments than the transaction declares —
    /// `discovery-on-the-consensus-wire.md` D4.
    ///
    /// **Omission is this error's `n = 0` case, not a separate branch** (§4 rule
    /// 1): a transaction with two outputs and no discovery reports
    /// `expected: 2, got: 0`. That is the whole of §1 — *"a block whose
    /// transaction carries no discovery group for its own outputs is invalid"* —
    /// and it is why option 3 was chosen over 2a.
    ///
    /// Ordering is part of the rule: recipient-major, then per-output. An
    /// unordered rule would let two orderings of the same content produce two
    /// commitments.
    DiscoveryDoesNotBind {
        index: usize,
        /// How many commitments the transaction declares.
        expected: usize,
        /// How many the discovery group describes.
        got: usize,
        /// The first position at which the two disagree, if both are the same
        /// length. `None` means the lengths differed.
        first_mismatch: Option<usize>,
    },
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
        check_tx_discovery(i, tx)?;
        if !verifier.verify_tx(tx) {
            return Err(BodyError::ProofInvalid { index: i });
        }
    }
    Ok(())
}

/// A single-recipient discovery group that binds exactly `commitments`, with an
/// **all-zero ML-KEM ciphertext and all-zero tags**.
///
/// 🔴 **This is consensus-valid and cryptographically useless, and both halves
/// are deliberate.** §4 rule 4 draws the boundary: consensus checks shape and
/// binding, never payload validity, because a node cannot decrypt a ciphertext
/// addressed to someone else. So a group built here passes every rule in §4 —
/// and no recipient will ever detect the outputs it describes, because there is
/// nothing to decapsulate.
///
/// It exists for two callers and no others: **fixtures**, which need a binding
/// group without a keypair, and the **assembly paths that have no real note
/// material yet** — discovery artifacts still live in `qlab_node::rpc`'s
/// in-memory side table, and moving them onto the transaction is batons 2–4 of
/// issue #188, not this one. Every remaining caller is a `grep` away and should
/// disappear as those batons land.
pub fn placeholder_discovery(commitments: &[Hash32]) -> Vec<u8> {
    if commitments.is_empty() {
        return TxEntry::empty_discovery();
    }
    let entries = commitments
        .iter()
        .map(|cm| qlab_note::wire::CompactEntry {
            cm: *cm,
            tag: [0u8; 8],
            clue: qlab_note::wire::ClueSlot::Empty,
        })
        .collect();
    encode_group_contents(&[RecipientBundle { ct: [0u8; qlab_note::kem::CT_LEN], entries }])
}

/// The `discovery-on-the-consensus-wire.md` §4 checks for one transaction.
///
/// §4 lists its rules as **1 present · 2 binds · 3 canonical**, which is a
/// statement of the rules and not an execution order — rule 2 reads decoded
/// content, so decoding necessarily runs first. The order here is:
///
/// 1. **Decode, exactly** — the bytes are a §2 group's contents and nothing
///    else follows them ([`decode_group_contents`]).
/// 2. **Re-encode to themselves** — §4 rule 3 verbatim. With no varint in the
///    committed region this holds by construction, so it is an assertion of an
///    invariant rather than a filter; it is written out anyway because it is the
///    property the whole option rests on, and a future `clue_len` activation
///    (§7's first open item) reintroduces a variable-length field right here.
/// 3. **Bind** — the group's commitments, recipient-major then per-output, equal
///    the transaction's declared `commitments` exactly and in order (D4).
///
/// **What is deliberately not checked (§4 rule 4, and it is the boundary):**
/// nothing about payload validity. A node cannot decrypt an ML-KEM ciphertext
/// addressed to someone else and must not pretend to judge it. Consensus checks
/// shape and binding; whether a recipient can actually open the ciphertext is
/// between the sender and the recipient. Every step past that line is a rule the
/// chain cannot enforce and would therefore enforce wrongly.
///
/// **The coinbase is not covered, deliberately (D5).** #101 made the coinbase
/// note's `ρ`/`rseed` derivable from chain data, so a miner recovers a mined
/// note with no discovery artifact; transaction outputs have no such derivation,
/// which is the entire reason they need this. Requiring a group for the coinbase
/// would add ~585 B to every empty block on the chain forever, for nothing.
pub fn check_tx_discovery(index: usize, tx: &TxEntry) -> Result<(), BodyError> {
    let recipients = tx.discovery_group(index)?;

    let reencoded = encode_group_contents(&recipients);
    if reencoded != tx.discovery {
        return Err(BodyError::DiscoveryMalformed {
            index,
            err: CodecError::TrailingBytes {
                remaining: tx.discovery.len().saturating_sub(reencoded.len()),
            },
        });
    }

    let described = contents_commitments(&recipients);
    let declared = &tx.public.commitments;
    let first_mismatch = if described.len() == declared.len() {
        described.iter().zip(declared).position(|(a, b)| a != b)
    } else {
        None
    };
    if described.len() != declared.len() || first_mismatch.is_some() {
        return Err(BodyError::DiscoveryDoesNotBind {
            index,
            expected: declared.len(),
            got: described.len(),
            first_mismatch,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_note::kem::CT_LEN;
    use qlab_note::wire::{ClueSlot, CompactEntry};

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
        let public = TxPublic {
            anchor: FINAL_ANCHOR,
            nullifiers: vec![[nf; 32]],
            commitments: vec![[nf.wrapping_add(1); 32]],
            bucket: ArityBucket::TwoByTwo,
            fee: posted_fee(ArityBucket::TwoByTwo),
        };
        let discovery = placeholder_discovery(&public.commitments);
        TxEntry { proof: b"ok".to_vec(), public, discovery }
    }

    fn ct_pattern(base: u8) -> [u8; CT_LEN] {
        core::array::from_fn(|i| base.wrapping_add((i % 251) as u8))
    }

    /// A two-recipient group: recipient A takes the first commitment, recipient
    /// B the second — so the D4 ordering has something to get wrong.
    fn two_recipient_discovery(cms: &[Hash32]) -> Vec<u8> {
        let bundles: Vec<RecipientBundle> = cms
            .iter()
            .enumerate()
            .map(|(i, cm)| RecipientBundle {
                ct: ct_pattern(0x20 + i as u8),
                entries: vec![CompactEntry { cm: *cm, tag: [i as u8; 8], clue: ClueSlot::Empty }],
            })
            .collect();
        encode_group_contents(&bundles)
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
                discovery: two_recipient_discovery(&[[0x44; 32], [0x55; 32]]),
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
    ///   after  #101: 0ac5b4641291df8cbf328ab2c82a83cbb03da8b60a888177791f4ce04a78b613
    ///   after  #188: (the constant below)
    /// ```
    ///
    /// **Deliberately changed again by issue #188** (body format v2:
    /// `BODY_PREIMAGE_DOMAIN` prepended, `discovery_len ‖ discovery` appended to
    /// each transaction region). `discovery-on-the-consensus-wire.md` §6 is
    /// explicit that this test breaking is the evidence the step happened —
    /// *"a step-2 PR whose golden test still passes has not done step 2."*
    /// The golden body's transaction now carries a two-recipient group binding
    /// its two commitments `0x44…` and `0x55…`, one output each.
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
            hex, "aab27621de7f0aabcc398b449bfe1db21c83ee09a8138f926a80119dcd5989c1",
            "block-body commitment preimage changed — see this test's doc comment"
        );
    }

    /// The empty body's commitment, pinned for the same reason: since issue #115
    /// it **is the genesis header's `tx_body_commitment`**, so this constant is
    /// now an input to the network identity; and it is the cheapest body an
    /// attacker can substitute (`empty_body_under_an_honest_header_is_rejected`).
    ///
    /// 🔴 **Moved by issue #188, and that is the whole reason
    /// [`BODY_PREIMAGE_DOMAIN`] exists.** The spec's §3 encoding only touches a
    /// transaction's own region, so it would have left this constant — and
    /// therefore the genesis hash, and therefore the network identity —
    /// unchanged, while every body containing a transaction moved. Two nodes
    /// across the change would have shared a genesis and forked silently at the
    /// first transaction.
    ///
    /// ```text
    ///   before #188: daa77426c30c02a43d9fba4e841a6556c524d47030762eb14dc4af897e605d9b
    ///   after  #188: (the constant below)
    /// ```
    #[test]
    fn golden_empty_body_commitment_bytes() {
        let hex: String =
            BlockBody::default().commitment().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex, "e1487b325a51801bfa6a29849d3a2ce2bfcef7dc85320211ea55d46273dffc3d",
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

