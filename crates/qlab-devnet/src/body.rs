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
    committed_contents_prefix, contents_commitments, decode_committed_discovery,
    encode_committed_discovery, CodecError, PAYLOAD_LEN,
};
use qlab_note::wire::RecipientBundle;

use crate::emission_exact::{coinbase_exact, RULE_BOUNDARY_HEIGHT};
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
    pub fn new(
        proof: Vec<u8>,
        public: TxPublic,
        recipients: &[RecipientBundle],
        payloads: &[Vec<u8>],
    ) -> Self {
        Self {
            proof,
            public,
            discovery: encode_committed_discovery(recipients, payloads),
        }
    }

    /// A transaction whose discovery group is a [`placeholder_discovery`]
    /// binding its own declared commitments — read that function's note before
    /// using this outside a fixture.
    pub fn with_placeholder_discovery(proof: Vec<u8>, public: TxPublic) -> Self {
        let discovery = placeholder_discovery(&public.commitments);
        Self { proof, public, discovery }
    }

    /// The canonical encoding of "this transaction attaches no discovery",
    /// i.e. `n_recipients = 0`. Valid only for a transaction with no output
    /// commitments; see [`TxEntry::discovery`].
    pub fn empty_discovery() -> Vec<u8> {
        encode_committed_discovery(&[], &[])
    }

    /// Decode this transaction's committed discovery bytes (§4 rule 3).
    ///
    /// `index` is only used to label the error — the bytes themselves carry no
    /// index (see [`qlab_note::compact::write_group_contents`]).
    pub fn discovery_group(&self, index: usize) -> Result<Vec<RecipientBundle>, BodyError> {
        self.discovery_parts(index).map(|(r, _)| r)
    }

    /// Both halves of the committed region: the compact bundles and the
    /// relocated AEAD payloads, one per entry in D4 order (issue #188 (a) as
    /// amended). The payloads are **committed**, so a light server serving them
    /// is a projection of the body and cannot withhold one undetectably — which
    /// is the property option 3 was chosen for.
    pub fn discovery_parts(
        &self,
        index: usize,
    ) -> Result<(Vec<RecipientBundle>, Vec<Vec<u8>>), BodyError> {
        decode_committed_discovery(&self.discovery)
            .map_err(|err| BodyError::DiscoveryMalformed { index, err })
    }

    /// The `group_contents` prefix — what `/v1/compact` serves, copied out of the
    /// committed bytes rather than re-encoded.
    pub fn discovery_served_prefix(&self, index: usize) -> Result<&[u8], BodyError> {
        committed_contents_prefix(&self.discovery)
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
    /// **The scheduled-emission rule** (lab #299): the body's `coinbase` counter is
    /// not the schedule's value for the block's height.
    ///
    /// # Why this rule did not exist until now, and why it does now
    ///
    /// `coinbase(h)` was defined by protocol-spec §6 and enforced by **nobody** —
    /// a doc-prose invariant at this file's `BlockBody::coinbase` field. The live T0
    /// chain paid for that: height 1377 committed `coinbase(1378)`, under-emitting
    /// 4,114 bessel, and no validator noticed (#299 §5, found by
    /// `qumbra-node audit-emission`).
    ///
    /// It binds **above [`crate::emission_exact::RULE_BOUNDARY_HEIGHT`] only**, and
    /// the reason is not gentleness: applied retroactively it would invalidate the
    /// running chain, whose one defective block is grandfathered as recorded history
    /// (#299 sequencing ruling clause 1). Above the boundary the schedule is the
    /// exact-decimal one, so the rule is *evaluable identically on every platform* —
    /// which it would not be under the f64 schedule, where the same rule forks a
    /// mixed-libc net (#303).
    ///
    /// **Genesis is exempt structurally, not by a special case.** `coinbase(0)` is
    /// `5×10⁹` while the genesis body commits `0`, so a naive rule rejects genesis
    /// itself (#299's verification comment). The check is `height > boundary`, and no
    /// boundary can be negative, so height 0 can never reach it — the exemption is a
    /// property of the comparison rather than a list of exceptions to maintain.
    WrongScheduledCoinbase { height: u64, expected: u64, got: u64 },
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
    /// The tx at `index` carries discovery bytes that decode but do **not
    /// re-encode to themselves** — `discovery-on-the-consensus-wire.md` §4 rule
    /// 3 stated literally.
    ///
    /// **Unreachable today, and deliberately kept anyway.** With `tx_index`
    /// excluded, every field in the committed region is fixed-width or
    /// single-valued, so decode is injective and this cannot fire. It is a
    /// separate answer rather than a fabricated `DiscoveryMalformed` because
    /// §7's first open item — clue activation — puts a variable-length field
    /// back inside these bytes, and on that day the difference between "these
    /// bytes are not a group" and "these bytes are a second spelling of a group"
    /// is the difference this baton exists to preserve.
    DiscoveryNotCanonical { index: usize },
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

/// **The #299 scheduled-emission rule at the shipped boundary.**
///
/// `body.coinbase == coinbase_exact(height)` for every block above
/// [`RULE_BOUNDARY_HEIGHT`]; at and below it, history is grandfathered as recorded
/// and this returns `Ok` without evaluating the schedule at all.
///
/// Called by [`validate_body`], so no caller has to remember it — and every peer's
/// block goes through `validate_body`, with no mempool and no declaration involved.
pub fn check_scheduled_coinbase(height: u64, committed: u64) -> Result<(), BodyError> {
    check_scheduled_coinbase_above(RULE_BOUNDARY_HEIGHT, height, committed)
}

/// [`check_scheduled_coinbase`] with the boundary as an argument — the **drill**
/// seam, and nothing else.
///
/// The shipped boundary is a compiled-in constant (H1: never config, never genesis,
/// no runtime override), so the only way to exercise the handoff without mining
/// 18,000 blocks is to state the boundary explicitly. The drill
/// (`qumbra-node/tests/rule_boundary_drill.rs`) uses this to prove the property at a
/// test height; consensus uses [`check_scheduled_coinbase`], which is the only
/// caller that reads the real constant.
pub fn check_scheduled_coinbase_above(
    boundary: u64,
    height: u64,
    committed: u64,
) -> Result<(), BodyError> {
    if height <= boundary {
        // Grandfathered. Note this is also the whole of the genesis exemption:
        // `height 0 <= boundary` for every boundary, so `coinbase_exact(0)` is
        // never compared against genesis's committed 0.
        return Ok(());
    }
    let expected = coinbase_exact(height);
    if committed != expected {
        return Err(BodyError::WrongScheduledCoinbase { height, expected, got: committed });
    }
    Ok(())
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
    // And it must mint the SCHEDULED amount (lab #299). Also an integer compare,
    // and it guards the same issuance from the other side: #101 asks "does anyone
    // get paid", this asks "is that the amount the schedule owes".
    check_scheduled_coinbase(header.height, body.coinbase)?;
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
    let n = commitments.len();
    encode_committed_discovery(
        &[RecipientBundle { ct: [0u8; qlab_note::kem::CT_LEN], entries }],
        &vec![vec![0u8; PAYLOAD_LEN]; n],
    )
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
    let (recipients, payloads) = tx.discovery_parts(index)?;

    // Re-encode to itself (§4 rule 3). Since issue #188 (a) that covers BOTH
    // halves of the committed region: the group contents and the relocated
    // fixed-width payload section. `decode_committed_discovery` already refuses a
    // payload section of the wrong total length, so this closes the remaining
    // way two byte strings could mean one group.
    if encode_committed_discovery(&recipients, &payloads) != tx.discovery {
        return Err(BodyError::DiscoveryNotCanonical { index });
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

/// The first nullifier repeated *within* one transaction, if any — the lone-tx
/// projection of [`validate_body`]'s in-block nullifier-uniqueness rule (§4;
/// [`BodyError::DoubleSpendInBlock`] is what the same repeat is called once the
/// tx is inside a block).
///
/// It lives here, beside the block-level rule it projects, since issue #278.
/// It used to live in `qlab-node`'s rpc layer as a surface precheck, on the
/// stated reasoning that the mempool's two nullifier gates compare against
/// state *outside* the candidate — which was true, and which is exactly why
/// the one surface with no precheck (the peer wire) pooled a self-double-spend
/// cleanly, poisoned every assembled template, and wedged the miner. The rule
/// is a consensus fact about a lone transaction, so it belongs to the layer
/// that owns the block-level rule; `Mempool::admit` now runs it on every path
/// into the pool, and the rpc/HTTP surfaces keep calling it early for their
/// own refusal attribution.
pub fn repeated_nullifier_in_tx(p: &TxPublic) -> Option<Hash32> {
    let mut in_tx = HashSet::new();
    p.nullifiers.iter().find(|nf| !in_tx.insert(**nf)).copied()
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

    /// `header_for` at an arbitrary height. Only `height` and
    /// `tx_body_commitment` are read by `validate_body`, so overriding the height is
    /// enough to put a body above or below the rule boundary.
    fn header_at(height: u64, body: &BlockBody) -> BlockHeader {
        BlockHeader { height, ..header_for(body) }
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
        let n = qlab_note::compact::contents_entry_count(&bundles);
        encode_committed_discovery(&bundles, &vec![vec![0u8; PAYLOAD_LEN]; n])
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

    // --- lab #299: the scheduled-emission validity rule ---------------------

    /// **Grandfathering is a property, not prose.** The *same* over- and
    /// under-paying bodies that are refused above the boundary are accepted at and
    /// below it — including the boundary height itself, which is the last block under
    /// the old schedule.
    #[test]
    fn the_same_wrong_coinbase_is_refused_above_the_boundary_and_accepted_below() {
        let b = RULE_BOUNDARY_HEIGHT;
        for delta in [1i64, -1, 1_000_000] {
            let value = (coinbase_exact(b + 1) as i64 + delta) as u64;
            let body = BlockBody {
                txs: vec![good_tx(1)],
                coinbase: value,
                coinbase_rkm: MINER_RKM,
            };
            // Above: refused, by name, with both numbers in the error.
            assert_eq!(
                validate_body(&header_at(b + 1, &body), &body, &MockVerifier, is_final),
                Err(BodyError::WrongScheduledCoinbase {
                    height: b + 1,
                    expected: coinbase_exact(b + 1),
                    got: value,
                }),
                "delta {delta} above the boundary must be refused"
            );
            // Below, and AT the boundary: the identical body is fine.
            for height in [1, b - 1, b] {
                assert_eq!(
                    validate_body(&header_at(height, &body), &body, &MockVerifier, is_final),
                    Ok(()),
                    "delta {delta} at height {height} is grandfathered history"
                );
            }
        }
    }

    /// The honest post-boundary block passes, at the boundary's first height and
    /// well above it — so the rule is not simply "refuse everything up there".
    #[test]
    fn an_honest_post_boundary_block_passes_the_schedule_rule() {
        let b = RULE_BOUNDARY_HEIGHT;
        for height in [b + 1, b + 2, b + 1_000, b + 500_000] {
            let body = BlockBody {
                txs: vec![good_tx(1)],
                coinbase: coinbase_exact(height),
                coinbase_rkm: MINER_RKM,
            };
            assert_eq!(
                validate_body(&header_at(height, &body), &body, &MockVerifier, is_final),
                Ok(()),
                "the scheduled value must be accepted at {height}"
            );
        }
    }

    /// **The live 1377 shape**: a block committing the *adjacent* height's scheduled
    /// value (`k = 1` substitution). Below the boundary this is the defect the chain
    /// actually carries and it is grandfathered; above it, refused. This is the exact
    /// failure the rule exists for, and it is worth its own test because the delta is
    /// small — 4,114 bessel at height 1377 — and an "amount looks plausible" check
    /// would miss it.
    #[test]
    fn the_adjacent_height_substitution_is_refused_above_the_boundary() {
        let b = RULE_BOUNDARY_HEIGHT;
        let height = b + 1;
        let wrong = coinbase_exact(height + 1); // what block 1377 did, one height up
        assert_ne!(wrong, coinbase_exact(height), "the schedule must actually decay");
        let body = BlockBody {
            txs: Vec::new(),
            coinbase: wrong,
            coinbase_rkm: MINER_RKM,
        };
        assert_eq!(
            validate_body(&header_at(height, &body), &body, &MockVerifier, is_final),
            Err(BodyError::WrongScheduledCoinbase {
                height,
                expected: coinbase_exact(height),
                got: wrong,
            })
        );
        // The under-emission is small, which is why nothing noticed it for 1,377
        // blocks: the delta here is the same order as the −4114 of #299.
        assert!(coinbase_exact(height) - wrong < 10_000);
        // And the same body below the boundary is accepted — the grandfathering.
        assert_eq!(
            validate_body(&header_at(1_377, &body), &body, &MockVerifier, is_final),
            Ok(())
        );
    }

    /// **The #299 verification comment's trap, test-locked**: the rule must never
    /// evaluate the schedule at height 0 against genesis's committed `0`. It cannot,
    /// for *any* boundary, because `0 <= boundary` always — so the exemption survives
    /// a re-stamp of the constant.
    #[test]
    fn the_rule_never_evaluates_the_schedule_against_genesis() {
        let genesis_body = BlockBody { txs: Vec::new(), coinbase: 0, coinbase_rkm: [0; 4] };
        assert_ne!(coinbase_exact(0), 0, "coinbase(0) is 5e9; genesis commits 0");
        assert_eq!(
            validate_body(&header_at(0, &genesis_body), &genesis_body, &MockVerifier, is_final),
            Ok(())
        );
        // Structural, not a special case: at every boundary a caller could stamp,
        // height 0 is exempt.
        for boundary in [0u64, 8, 16, RULE_BOUNDARY_HEIGHT, u64::MAX] {
            assert_eq!(check_scheduled_coinbase_above(boundary, 0, 0), Ok(()));
        }
    }

    /// The rule sits **after** the header/body binding and the payee check, and
    /// before any proof work — so a wrong-schedule block costs one integer compare,
    /// and a body that is not the header's body still fails as `CommitmentMismatch`
    /// rather than as a schedule violation.
    #[test]
    fn the_binding_still_wins_over_the_schedule_rule() {
        let b = RULE_BOUNDARY_HEIGHT;
        let honest = BlockBody {
            txs: vec![good_tx(1)],
            coinbase: coinbase_exact(b + 1),
            coinbase_rkm: MINER_RKM,
        };
        let header = header_at(b + 1, &honest);
        // A foreign body with BOTH defects: wrong commitment and wrong schedule.
        let foreign = BlockBody { coinbase: 1, ..honest.clone() };
        assert!(matches!(
            validate_body(&header, &foreign, &MockVerifier, is_final),
            Err(BodyError::CommitmentMismatch { .. }),
        ));
        // And a minting body with no payee is still MissingCoinbasePayee, not a
        // schedule error, even above the boundary.
        let unpaid = BlockBody { coinbase_rkm: [0; 4], ..honest.clone() };
        assert_eq!(
            validate_body(&header_at(b + 1, &unpaid), &unpaid, &MockVerifier, is_final),
            Err(BodyError::MissingCoinbasePayee)
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
    ///   after  #188: aab27621de7f0aabcc398b449bfe1db21c83ee09a8138f926a80119dcd5989c1
    ///   after  #188 (a) payload relocation: (the constant below)
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
    /// 🔴 **And deliberately changed a third time, by #188 (a) as amended**: the
    /// AEAD payloads moved *into* the committed region (`group_contents ‖
    /// payloads`, one fixed 120-byte payload per entry). So this body's preimage
    /// grew by 2 × 120 B and this constant moved with it — **the same evidence
    /// rule applies, and it firing is the proof the relocation happened.**
    ///
    /// The one golden that must **not** move for that change is a different one:
    /// `qlab-cbserver`'s 1177-byte `/v1/compact` vector. Serving projects only the
    /// `group_contents` prefix out of these bytes, so the served wire is
    /// byte-identical and the two goldens move independently by design.
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
            hex, "8ef00f318e7a4517107dfd538ed80b7d7ecf7caa71573085e8d5bdcfb5ad6cdc",
            "block-body commitment preimage changed — see this test's doc comment"
        );
    }

    // --- issue #188: body-bound discovery -----------------------------------

    /// **The round-trip over the new body**, including the empty case.
    ///
    /// Three separate claims, because they fail separately:
    ///   1. a transaction's committed discovery bytes decode back to the group
    ///      that produced them and re-encode to the same bytes;
    ///   2. the commitment is deterministic and sensitive to the discovery
    ///      region alone;
    ///   3. the empty body — no transactions, therefore no discovery groups —
    ///      has a stable encoding that does **not** collide with the pre-change
    ///      empty body. Claim 3 is the one `BODY_PREIMAGE_DOMAIN` exists for;
    ///      without the domain tag §3's encoding leaves it byte-identical.
    /// 🔴 **Stage 4's payload-tamper case — and the mechanism is not the one the
    /// task book names.**
    ///
    /// The book says *"payload tamper → commitment-equality binding refuses the
    /// body."* **It does not, and cannot.** D4's binding compares the discovery
    /// group's `cm` values against the transaction's declared `commitments`; a
    /// flipped payload byte touches neither, so `check_tx_discovery` **passes** on
    /// a tampered payload. That is asserted below rather than glossed, because a
    /// test written to the book's wording would have had to fake its way to green.
    ///
    /// What actually refuses it is **#79's header↔body binding**, and only because
    /// issue #188 (a) moved the payloads *into* the preimage: the tampered byte
    /// changes `BlockBody::commitment()`, so the body no longer matches the header
    /// that committed to it. Before the relocation this tamper was **invisible to
    /// consensus entirely** — the payload lived in a served side table that no
    /// block hash covered. So the relocation is what created the refusal, and this
    /// test is the evidence for that claim rather than for the book's.
    #[test]
    fn a_tampered_payload_byte_is_refused_by_the_header_binding_not_by_d4() {
        let cms = vec![[0x44u8; 32], [0x55u8; 32]];
        let honest = two_recipient_discovery(&cms);
        let mut tx = good_tx(1);
        tx.public.commitments = cms.clone();
        tx.discovery = honest.clone();
        let body = BlockBody { txs: vec![tx.clone()], coinbase: 0, coinbase_rkm: [0; 4] };
        let header = header_for(&body);
        assert_eq!(validate_body(&header, &body, &MockVerifier, is_final), Ok(()));

        // Flip one byte INSIDE the payload section — past the group contents, so
        // no `cm`, no `tag`, no `ct` and no count is touched.
        let prefix_len = committed_contents_prefix(&honest).expect("decodes").len();
        assert!(prefix_len < honest.len(), "there is a payload section to tamper");
        let mut tampered = honest.clone();
        tampered[prefix_len] ^= 0x01;
        let mut bad_tx = tx.clone();
        bad_tx.discovery = tampered;

        // (a) 🔴 D4 does NOT catch it, and that is correct rather than a hole:
        //     consensus checks shape and binding, never payload validity (§4 rule
        //     4), and a node holds no key to judge a payload with.
        assert_eq!(
            check_tx_discovery(0, &bad_tx),
            Ok(()),
            "a payload tamper is invisible to the commitment-equality binding —              D4 compares cm values, and the tamper moved none of them"
        );

        // (b) And the header binding DOES, because the payloads are in the
        //     preimage now. Same header, moved body.
        let bad_body =
            BlockBody { txs: vec![bad_tx], coinbase: 0, coinbase_rkm: [0; 4] };
        assert_ne!(
            bad_body.commitment(),
            body.commitment(),
            "the tampered payload must move the body commitment — if it did not,              the relocation would not have put the payloads in the preimage"
        );
        assert!(
            matches!(
                validate_body(&header, &bad_body, &MockVerifier, is_final),
                Err(BodyError::CommitmentMismatch { .. })
            ),
            "the header↔body binding must refuse a body whose payload moved"
        );
    }

    /// 🔴 Pins the sentence `placeholder_discovery`'s own doc makes:
    /// **consensus-valid and cryptographically useless.** Both halves — "valid"
    /// is what a fixture relies on, "useless" is what stops anyone mistaking it
    /// for a real group.
    ///
    /// The width/count half exists because that is exactly the kind of claim
    /// which is true when written and quietly stops being true: relocating the
    /// payloads (issue #188 (a)) made the placeholder responsible for a second
    /// field, and nothing but this test would notice if it drifted.
    #[test]
    fn placeholder_discovery_is_valid_and_uselessly_zero_at_the_right_width() {
        let cms: Vec<Hash32> = vec![[7u8; 32], [8u8; 32]];
        let d = placeholder_discovery(&cms);
        let (recipients, payloads) =
            decode_committed_discovery(&d).expect("placeholder must DECODE");

        // Valid: it binds exactly the commitments it was given, in D4 order.
        assert_eq!(contents_commitments(&recipients), cms);

        // Useless, at the right shape: one zero payload per entry, each exactly
        // PAYLOAD_LEN. A count drift or a width drift turns this red.
        assert_eq!(payloads.len(), cms.len(), "one payload per entry");
        for (i, p) in payloads.iter().enumerate() {
            assert_eq!(p.len(), PAYLOAD_LEN, "payload {i} width");
            assert!(p.iter().all(|b| *b == 0), "payload {i} must be uselessly zero");
        }
        // Useless: all-zero ct and all-zero tags — nothing to decapsulate.
        assert!(recipients.iter().all(|r| r.ct.iter().all(|b| *b == 0)), "zero ct");
        assert!(
            recipients.iter().flat_map(|r| &r.entries).all(|e| e.tag == [0u8; 8]),
            "zero tags"
        );

        // And it passes the consensus rule it exists to pass.
        let tx = TxEntry {
            proof: b"ok".to_vec(),
            public: TxPublic {
                anchor: FINAL_ANCHOR,
                nullifiers: vec![[0x22; 32], [0x33; 32]],
                commitments: cms,
                bucket: ArityBucket::TwoByTwo,
                fee: posted_fee(ArityBucket::TwoByTwo),
            },
            discovery: d,
        };
        check_tx_discovery(0, &tx).expect("placeholder must be consensus-valid");
    }

    #[test]
    fn discovery_round_trips_and_the_empty_body_does_not_collide_with_v1() {
        let cms = vec![[0x44u8; 32], [0x55u8; 32]];
        let tx = TxEntry {
            proof: b"ok".to_vec(),
            public: TxPublic {
                anchor: FINAL_ANCHOR,
                nullifiers: vec![[0x22; 32], [0x33; 32]],
                commitments: cms.clone(),
                bucket: ArityBucket::TwoByTwo,
                fee: posted_fee(ArityBucket::TwoByTwo),
            },
            discovery: two_recipient_discovery(&cms),
        };
        // 1. decode ∘ encode = id, on the bytes the body commits to.
        let (back, pls) = tx.discovery_parts(0).expect("discovery decodes");
        assert_eq!(encode_committed_discovery(&back, &pls), tx.discovery);
        assert_eq!(contents_commitments(&back), cms, "D4 order, recipient-major");

        // 2. deterministic, and sensitive to the discovery region alone.
        let body = BlockBody { txs: vec![tx.clone()], coinbase: 0, coinbase_rkm: [0; 4] };
        assert_eq!(body.commitment(), body.commitment());
        let mut swapped = tx.clone();
        swapped.discovery = two_recipient_discovery(&[cms[1], cms[0]]);
        let reordered = BlockBody { txs: vec![swapped], coinbase: 0, coinbase_rkm: [0; 4] };
        assert_ne!(
            body.commitment(),
            reordered.commitment(),
            "the discovery region is inside the commitment"
        );

        // 3. the empty body: stable, and distinct from the v1 preimage. The v1
        //    preimage is reconstructed here rather than quoted, so the claim is
        //    "these two functions disagree" and not "this constant differs from
        //    another constant I also wrote".
        let empty = BlockBody::default();
        assert_eq!(empty.commitment(), BlockBody::default().commitment());
        let v1_empty = {
            let mut buf = Vec::new();
            buf.extend_from_slice(&empty.coinbase.to_le_bytes());
            for lane in &empty.coinbase_rkm {
                buf.extend_from_slice(&lane.to_le_bytes());
            }
            keccak256(&buf)
        };
        assert_eq!(
            hex_of(&v1_empty),
            "daa77426c30c02a43d9fba4e841a6556c524d47030762eb14dc4af897e605d9b",
            "this reconstruction IS the pre-#188 empty-body commitment"
        );
        assert_ne!(
            empty.commitment(),
            v1_empty,
            "a body with no discovery groups must not collide with a pre-change body"
        );
    }

    /// 🔴 **The malleability test — the property the whole option rests on.**
    ///
    /// Two byte strings that decode to the same logical body must be
    /// *impossible*, not merely unlikely. The committed discovery region is
    /// fixed-width throughout (`n_recipients` u8, `ct` 1088 B, `n_outputs` u8,
    /// `cm` 32 B, `tag` 8 B, `clue_len` u8 = 0) and length-prefixed by a `u64`
    /// LE, so it contains **no varint at all** — stronger than D6 asked for, and
    /// true only because `tx_index` is excluded (see
    /// `qlab_note::compact::write_group_contents`).
    ///
    /// So this attacks it three ways: a non-canonical varint fed directly into
    /// the region, a padded `tx_index` fed into the serving form that projects
    /// from the same bytes, and trailing junk.
    #[test]
    fn non_canonical_bytes_cannot_reach_a_body_commitment() {
        let cms = vec![[0x44u8; 32], [0x55u8; 32]];
        let honest = two_recipient_discovery(&cms);
        let mut tx = good_tx(1);
        tx.public.commitments = cms.clone();
        tx.discovery = honest.clone();
        let body = BlockBody { txs: vec![tx.clone()], coinbase: 0, coinbase_rkm: [0; 4] };
        assert_eq!(validate_body(&header_for(&body), &body, &MockVerifier, is_final), Ok(()));

        // (a) A padded varint spliced at the region's first byte. `0x82 0x00` is
        //     the LEB128 padding of 2 — the exact shape D6 names. There is no
        //     varint here for it to be accepted by: `0x82` is read as
        //     `n_recipients = 130` and the buffer runs out. It can never be a
        //     second spelling of `n_recipients = 2`, which is the property.
        let mut padded = vec![0x82u8, 0x00];
        padded.extend_from_slice(&honest[1..]);
        let mut bad = tx.clone();
        bad.discovery = padded;
        assert!(
            matches!(check_tx_discovery(0, &bad), Err(BodyError::DiscoveryMalformed { .. })),
            "a padded varint spliced into the committed region is refused"
        );

        // (b) The serving projection over the same bytes — `varint(index) ‖
        //     region`. THIS has a varint, and a padded one is rejected by the
        //     ratified decoder (D6, PR #149). Asserted here because the served
        //     form is what a wallet scans in baton 2.
        // 🔴 Since #188 (a) the served form is `varint(index) ‖ the PREFIX of the
        //     committed region`, not the whole region — serving projects
        //     `group_contents` and leaves the payload section behind. Splicing the
        //     whole committed blob after the index is NOT servable, and asserting
        //     that is what keeps "serving is a projection" a fact rather than a
        //     convention.
        let prefix = committed_contents_prefix(&honest).expect("committed region decodes");
        let mut served = Vec::new();
        qlab_note::compact::write_varint(&mut served, 2);
        served.extend_from_slice(prefix);
        assert!(qlab_note::compact::decode_group(&served).is_ok());
        let mut over = Vec::new();
        qlab_note::compact::write_varint(&mut over, 2);
        over.extend_from_slice(&honest);
        assert!(
            qlab_note::compact::decode_group(&over).is_err(),
            "the committed region is NOT the served group — the payload section \
             must not decode as part of one"
        );
        let mut served_padded = vec![0x82u8, 0x00];
        served_padded.extend_from_slice(&honest);
        assert!(
            matches!(
                qlab_note::compact::decode_group(&served_padded),
                Err(CodecError::NonCanonicalVarint { len: 2 })
            ),
            "a padded tx_index is refused on the serving wire"
        );

        // (c) Trailing junk: a well-formed prefix plus anything would be a
        //     second byte string for one logical group, so it must not decode.
        //
        //     🔴 Since #188 (a) it is refused as `PayloadSectionLen` rather than
        //     `TrailingBytes`, and the sharper error is the point: the payload
        //     section's length is *fully determined* by the group contents that
        //     precede it (`n_entries × PAYLOAD_LEN`), so an extra byte is not
        //     "leftover" — it is a section of the wrong size, and the decoder can
        //     say which size it wanted. Exact consumption is still what canonicity
        //     reduces to; this is the same property with a better name.
        let mut trailing = honest.clone();
        trailing.push(0x00);
        let mut bad = tx.clone();
        bad.discovery = trailing;
        assert!(matches!(
            check_tx_discovery(0, &bad),
            Err(BodyError::DiscoveryMalformed {
                index: 0,
                err: CodecError::PayloadSectionLen { expected: 240, got: 241 }
            })
        ));

        // (d) The positive half of the same property: the accepted encoding
        //     re-encodes to itself, so there is exactly one of it.
        let (r, pls) = tx.discovery_parts(0).unwrap();
        assert_eq!(encode_committed_discovery(&r, &pls), honest);
    }

    /// **The rejection test**: a body whose discovery does not bind is refused
    /// with a typed error, and *cannot parse* stays a different answer from
    /// *parses but does not bind*.
    #[test]
    fn discovery_that_does_not_bind_is_rejected_and_omission_is_its_n_equals_zero_case() {
        let cms = vec![[0x44u8; 32], [0x55u8; 32]];
        let mut tx = good_tx(1);
        tx.public.commitments = cms.clone();
        tx.discovery = two_recipient_discovery(&cms);

        // Wrong commitment, right shape — parses, does not bind.
        let mut wrong = tx.clone();
        wrong.discovery = two_recipient_discovery(&[cms[0], [0xEE; 32]]);
        let body = BlockBody { txs: vec![wrong], coinbase: 0, coinbase_rkm: [0; 4] };
        assert_eq!(
            validate_body(&header_for(&body), &body, &MockVerifier, is_final),
            Err(BodyError::DiscoveryDoesNotBind {
                index: 0,
                expected: 2,
                got: 2,
                first_mismatch: Some(1),
            })
        );

        // Right commitments, wrong ORDER — D4 fixes the order for exactly this.
        let mut reordered = tx.clone();
        reordered.discovery = two_recipient_discovery(&[cms[1], cms[0]]);
        let body = BlockBody { txs: vec![reordered], coinbase: 0, coinbase_rkm: [0; 4] };
        assert_eq!(
            validate_body(&header_for(&body), &body, &MockVerifier, is_final),
            Err(BodyError::DiscoveryDoesNotBind {
                index: 0,
                expected: 2,
                got: 2,
                first_mismatch: Some(0),
            })
        );

        // 🔴 §1, the sentence this baton exists to create: attaching nothing is
        // invalid, and it is the n = 0 case of the same rule, not a branch.
        let mut omitted = tx.clone();
        omitted.discovery = TxEntry::empty_discovery();
        let body = BlockBody { txs: vec![omitted], coinbase: 0, coinbase_rkm: [0; 4] };
        assert_eq!(
            validate_body(&header_for(&body), &body, &MockVerifier, is_final),
            Err(BodyError::DiscoveryDoesNotBind {
                index: 0,
                expected: 2,
                got: 0,
                first_mismatch: None,
            })
        );

        // …and *cannot parse* is a different answer, not the same one.
        let mut garbage = tx.clone();
        garbage.discovery = vec![0x01, 0xFF, 0xFF];
        let body = BlockBody { txs: vec![garbage], coinbase: 0, coinbase_rkm: [0; 4] };
        assert!(matches!(
            validate_body(&header_for(&body), &body, &MockVerifier, is_final),
            Err(BodyError::DiscoveryMalformed { index: 0, err: CodecError::Truncated { .. } })
        ));

        // A zero-length field is not "no discovery" — it is unparseable, and it
        // must not be mistaken for the honest n = 0 encoding.
        let mut nothing = tx.clone();
        nothing.discovery = Vec::new();
        let body = BlockBody { txs: vec![nothing], coinbase: 0, coinbase_rkm: [0; 4] };
        assert!(matches!(
            validate_body(&header_for(&body), &body, &MockVerifier, is_final),
            Err(BodyError::DiscoveryMalformed { index: 0, .. })
        ));
    }

    /// D5: the coinbase carries no discovery and that is not an oversight. A
    /// minting block with no transactions is valid, and nothing in §4 reaches
    /// the coinbase note.
    #[test]
    fn the_coinbase_needs_no_discovery() {
        let body = BlockBody { txs: vec![], coinbase: 5_000, coinbase_rkm: MINER_RKM };
        assert_eq!(validate_body(&header_for(&body), &body, &MockVerifier, is_final), Ok(()));
    }

    /// §4 rule 4, the boundary: consensus judges shape and binding, never
    /// payload validity. An all-zero ML-KEM ciphertext — which no recipient can
    /// ever decapsulate — is **valid**, because a node cannot judge a ciphertext
    /// addressed to someone else and must not pretend to.
    #[test]
    fn consensus_does_not_judge_the_ciphertext() {
        let tx = good_tx(1); // placeholder_discovery: ct = [0; 1088], tag = [0; 8]
        let body = BlockBody { txs: vec![tx], coinbase: 0, coinbase_rkm: [0; 4] };
        assert_eq!(validate_body(&header_for(&body), &body, &MockVerifier, is_final), Ok(()));
    }

    fn hex_of(h: &Hash32) -> String {
        h.iter().map(|b| format!("{b:02x}")).collect()
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

