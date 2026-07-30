//! Issue #101 acceptance: **mine → mature → spend**, end to end.
//!
//! This is the path that did not exist. A mined coin had no commitment-tree leaf,
//! so no Merkle witness, so no real 2×2 proof could spend it — and the old
//! `coinbase_note_commitment` could not have been appended to fix that, because it
//! was a digest under its own domain that the circuit cannot open.
//!
//! Every claim here is made against the **production** verifier
//! ([`qumbra_node::verifier::ConsensusVerifier`], the binary's default since
//! M10-T0-4), never a stand-in. A test that only checks the leaf exists would not
//! close this issue; the question is whether the coin is *spendable*, and only a
//! real STARK verified by the shipping verifier answers it.
//!
//! ## Cost
//!
//! One real 2×2 proof (~2.3 s, ~11.8 GB peak on the reference rig). Proving is
//! serialised behind a gate for the same reason `qlab-faucet`'s acceptance suite
//! does it: cargo's default parallelism would multiply that peak and OOM the rig.
//! Run with `--test-threads=1`.

use qlab_air::narrow::{build_bucket_with_witnesses, derive_input, MerkleWitness, TxInput, TxOutput};
use qlab_consensus::{prove_bucket, LOG_HEIGHT};
use qlab_devnet::body::{BlockBody, BodyError, TxEntry, TxPublic, TxVerifier};
use qlab_devnet::fees::{posted_fee, ArityBucket};
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_devnet::params_devnet::GENESIS_DIFFICULTY;
use qlab_node::{
    coinbase, coinbase_leaf_appears_at, coinbase_maturity, coinbase_note, coinbase_note_leaf,
    genesis_block, ChainStore, CoinbaseMaturity, CommitmentStore, MemCommitmentStore, MemNode,
    Mempool, MempoolError,
    NodeState, COINBASE_MATURITY_BLOCKS,
};
use qlab_note::hash::{digest_bytes, digest_from_bytes};
use qlab_wallet::address::Diversifier;
use qlab_wallet::Wallet;
use qumbra_node::verifier::ConsensusVerifier;

/// One proof at a time in this binary — see the module docs. Poisoning is ignored
/// on purpose so a panicking test cannot wedge the rest.
fn prover_gate() -> std::sync::MutexGuard<'static, ()> {
    static GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    GATE.lock().unwrap_or_else(|e| e.into_inner())
}

/// Blocks in these fixtures carry no transactions, so no proof is ever verified
/// while building the chain — but the node still runs its real body validation.
struct NoTxVerifier;
impl TxVerifier for NoTxVerifier {
    fn verify_tx(&self, _: &TxEntry) -> bool {
        unreachable!("fixture blocks carry no transactions")
    }
}

/// A chain being built block by block: apply, finalize, and remember the payout
/// key each height was mined to.
struct Chain {
    node: MemNode,
    tip: BlockHeader,
}

impl Chain {
    fn new() -> Chain {
        let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
        let tip = genesis.header();
        Chain { node: MemNode::in_memory(genesis), tip }
    }

    /// The stored body at `height`, read back out of the chain — deliberately
    /// re-derived from chain data rather than remembered, because "a miner can
    /// rebuild the note from the chain alone" is the property the deterministic
    /// ρ/rseed rule exists for.
    fn body_at(&self, height: u64) -> BlockBody {
        let hash = self.node.chain().chain().main_chain()[height as usize];
        self.node.chain().block(&hash).expect("block stored").body()
    }

    /// Mine an empty block at `tip + 1` paying `rkm`, and apply it through the
    /// node's real state transition (`apply_block` → `validate_body`).
    fn mine_to(&mut self, rkm: [u64; 4]) -> u64 {
        let height = self.tip.height + 1;
        let body =
            BlockBody { txs: Vec::new(), coinbase: coinbase(height), coinbase_rkm: rkm };
        self.apply(body)
    }

    fn apply(&mut self, body: BlockBody) -> u64 {
        self.apply_with(body, &NoTxVerifier)
    }

    /// Try to apply a block and hand back the node's verdict instead of unwrapping —
    /// for the paths where being *rejected* is the property under test.
    fn try_apply_with<V: TxVerifier>(
        &mut self,
        body: BlockBody,
        verifier: &V,
    ) -> Result<Hash32, qlab_node::NodeError> {
        let height = self.tip.height + 1;
        let header =
            BlockHeader::child_of(&self.tip, height * 75, GENESIS_DIFFICULTY, body.commitment());
        self.node.apply_block(header, body, verifier)
    }

    /// Apply a block through the node's real state transition under an explicit
    /// verifier. The block carrying the spend uses [`ConsensusVerifier`] — the
    /// production one — so "the node accepts it" means the shipping verifier ran.
    fn apply_with<V: TxVerifier>(&mut self, body: BlockBody, verifier: &V) -> u64 {
        let height = self.tip.height + 1;
        let header =
            BlockHeader::child_of(&self.tip, height * 75, GENESIS_DIFFICULTY, body.commitment());
        let hash = self.node.apply_block(header, body, verifier).expect("block applies");
        self.node.finalize(hash).expect("finalize");
        self.tip = header;
        height
    }
}

/// The leaf count of the commitment tree at the end of `height` — the prefix the
/// anchor at that height commits to, and the count witnesses must be cut against.
///
/// Every fixture block mints exactly one coinbase note and carries no txs, so this
/// was `height` (one leaf per block, genesis excluded) until issue #102. It is now
/// `height − 144`: a block appends the leaf minted 144 blocks *back*, so the first
/// 144 blocks of any chain contribute no leaves at all and the tree runs exactly one
/// maturity delay behind the chain.
fn leaves_through(height: u64) -> u64 {
    height.saturating_sub(COINBASE_MATURITY_BLOCKS)
}

/// Fetch a membership witness from the live tree and cross-check it folds to the
/// anchor before spending 2.3 s proving against it.
fn witness_for(node: &MemNode, cm: &[u64; 4], leaf_count: u64, anchor: [u64; 4]) -> MerkleWitness {
    let tree = node.commitments().tree();
    let pos = tree.position_of(cm).expect("the coinbase note must be a leaf of the live tree");
    assert!(pos < leaf_count, "leaf must be inside the anchor's prefix");
    let w = tree.auth_path(pos, leaf_count);
    assert_eq!(w.fold_root(cm), anchor, "witness must fold to the anchor");
    w
}

// ---------------------------------------------------------------------------
// Acceptance 1 — the whole point of the baton.
// ---------------------------------------------------------------------------

/// **Mine a block, wait `COINBASE_MATURITY_BLOCKS`, and spend the coinbase note
/// with a real 2×2 proof that `ConsensusVerifier` accepts.**
///
/// Two coinbase notes are mined, at heights 1 and 2, because the consensus
/// statement is a fixed-shape 2×2 bucket: spending one coinbase note requires a
/// second input, and a second coinbase note is the natural one — it is what a
/// miner actually has.
#[test]
fn a_mined_coin_can_be_spent_after_maturity_with_a_real_proof() {
    let _gate = prover_gate();

    let wallet = Wallet::from_seed_lanes([0x9101_0000_0000_0001; 4]);
    let d = Diversifier::default();
    let miner_rkm = wallet.rkm(d);

    // --- mine ------------------------------------------------------------
    let mut chain = Chain::new();
    let h1 = chain.mine_to(miner_rkm);
    let h2 = chain.mine_to(miner_rkm);
    assert_eq!((h1, h2), (1, 2));

    // The notes the miner now owns, re-derived from chain data alone — which is
    // the recovery property the deterministic ρ/rseed rule buys: nothing here
    // reads a wallet-side secret except the spend key at proving time.
    let note_of = |h: u64| {
        coinbase_note(h, &chain.body_at(h)).expect("a minting block mints a note")
    };
    let n1 = note_of(h1);
    let n2 = note_of(h2);
    assert_eq!(n1.rkm, miner_rkm, "paid to the miner's rkm");
    assert_ne!(n1.commitment(), n2.commitment(), "distinct heights ⇒ distinct notes");

    // Neither note is a leaf yet, and that inversion is issue #102. Under #101 the
    // leaf appeared the moment the block was applied; now the note exists, is fully
    // derivable from chain data, and has **no leaf and therefore no membership
    // witness** until it matures. This is the enforcement mechanism, asserted at the
    // moment it binds.
    fn tree_has(chain: &Chain, cm: [u64; 4]) -> bool {
        chain.node.commitments().tree().position_of(&cm).is_some()
    }
    assert!(!tree_has(&chain, n1.commitment()), "a fresh coinbase note must NOT be in the tree");
    assert!(!tree_has(&chain, n2.commitment()), "a fresh coinbase note must NOT be in the tree");
    assert_eq!(chain.node.commitment_count(), 0, "144 blocks in, the tree is still empty");

    // --- mature ----------------------------------------------------------
    // Grow the chain until BOTH notes have leaves. Note 1 was minted at height 1 so
    // its leaf lands at 145; note 2 at height 2 lands at 146. Spending needs both
    // (the bucket is a fixed 2×2), so the binding height is note 2's.
    let burn = [0xDEAD_BEEFu64, 1, 2, 3]; // later blocks pay someone else
    while chain.tip.height < coinbase_leaf_appears_at(h2) {
        chain.mine_to(burn);
    }
    let tip = chain.tip.height;
    assert_eq!(tip, h2 + COINBASE_MATURITY_BLOCKS);
    assert_eq!(coinbase_leaf_appears_at(h1), 145);
    assert_eq!(coinbase_leaf_appears_at(h2), 146);

    // Now they are leaves — and they are the ONLY leaves. Blocks 3..=146 paid the
    // burn key and their coinbase leaves are all still owed (they land at 147..=290),
    // so the tree holds exactly the two matured notes.
    assert!(tree_has(&chain, n1.commitment()), "note 1 matured at 145");
    assert!(tree_has(&chain, n2.commitment()), "note 2 matured at 146");
    assert_eq!(chain.node.commitment_count(), 2, "only the two matured leaves are in");

    // --- spend -----------------------------------------------------------
    // Anchor: the finalized root at the tip. Everything is finalized as it is
    // applied in this fixture, so the tip's own root is a valid anchor.
    let anchor_height = tip;
    let leaf_count = leaves_through(anchor_height);
    let anchor_lanes = chain.node.commitments().tree().root_at(leaf_count);
    let anchor = digest_bytes(&anchor_lanes);
    assert!(chain.node.is_valid_anchor(&anchor), "the tip's finalized root is a valid anchor");

    let fee = posted_fee(ArityBucket::TwoByTwo);
    let inputs: [TxInput; 2] = [
        wallet.spend_input(n1.value, n1.rho, n1.rseed, d),
        wallet.spend_input(n2.value, n2.rho, n2.rseed, d),
    ];
    // The spend witness the wallet builds must reproduce the exact leaf the node
    // appended. If this fails the note is unspendable and nothing below matters.
    for (inp, note) in inputs.iter().zip([&n1, &n2]) {
        let (_nk, _nf, cm) = derive_input(inp);
        assert_eq!(cm, note.commitment(), "wallet-derived cm must equal the minted leaf");
    }
    let witnesses: [MerkleWitness; 2] = [
        witness_for(&chain.node, &n1.commitment(), leaf_count, anchor_lanes),
        witness_for(&chain.node, &n2.commitment(), leaf_count, anchor_lanes),
    ];

    // Send it somewhere: one output to a recipient, one change note back.
    let recipient = Wallet::from_seed_lanes([0x9101_0000_0000_0002; 4]);
    let total_in = n1.value + n2.value;
    let sent = total_in / 3;
    let change = total_in - sent - fee;
    let outputs = [
        TxOutput { value: sent, rkm: recipient.rkm(d), rho: [11; 4], rseed: [12; 4] },
        TxOutput { value: change, rkm: miner_rkm, rho: [13; 4], rseed: [14; 4] },
    ];

    let inst =
        build_bucket_with_witnesses(LOG_HEIGHT, &inputs, &outputs, fee, &witnesses, anchor_lanes);
    let (_pvs, proof) = prove_bucket(&inst);

    let entry = TxEntry {
        proof: bincode::serialize(&proof).expect("proof serializes"),
        public: TxPublic {
            anchor,
            nullifiers: vec![digest_bytes(&inst.nf[0]), digest_bytes(&inst.nf[1])],
            commitments: vec![digest_bytes(&inst.cm_out[0]), digest_bytes(&inst.cm_out[1])],
            bucket: ArityBucket::TwoByTwo,
            fee,
        },
    };

    // 🔴 THE CLAIM: the production verifier accepts a real spend of a mined coin.
    assert!(
        ConsensusVerifier.verify_tx(&entry),
        "the shipping verifier must accept a real 2×2 spend of a matured coinbase note"
    );

    // …and the node accepts it. The mempool is handed nothing about coinbase origin
    // (issue #102 deleted the declaration and the registry), so admission here rests
    // entirely on the proof verifying against an anchor that really does contain the
    // leaves — which is the enforcement, not a bypass of it.
    let mut mp = Mempool::default();
    mp.admit(entry.clone(), &chain.node, &ConsensusVerifier)
        .expect("a matured, well-proved spend is admitted");

    let spend_body = BlockBody {
        txs: vec![entry],
        coinbase: coinbase(tip + 1),
        coinbase_rkm: miner_rkm,
    };
    let before = chain.node.commitment_count();
    chain.apply_with(spend_body, &ConsensusVerifier);
    assert!(chain.node.is_spent(&digest_bytes(&inst.nf[0])), "input 1 is nullified");
    assert!(chain.node.is_spent(&digest_bytes(&inst.nf[1])), "input 2 is nullified");
    assert_eq!(
        chain.node.commitment_count(),
        before + 3,
        "two spend outputs plus the leaf this block matures — the coinbase minted at \
         height {} (not its own, which is owed until {})",
        tip + 1 - COINBASE_MATURITY_BLOCKS,
        coinbase_leaf_appears_at(tip + 1),
    );
}

// ---------------------------------------------------------------------------
// Acceptance 2 — only the payout key can spend it; maturity is enforced.
// ---------------------------------------------------------------------------

/// **Only the payout key can spend the coinbase note.**
///
/// The binding is cryptographic, not a check: the note's commitment is over
/// `rkm = H(nk ‖ D_R ‖ d)`, and the circuit re-derives `rkm` from the witness
/// `(sk, d)`. A different wallet — or the right wallet at the wrong diversifier —
/// derives a *different* commitment, which is not a leaf of the tree, so there is
/// no membership witness to prove against. No proof is needed to show this, and
/// none is generated: the failure is at the leaf, before proving.
#[test]
fn only_the_payout_key_derives_the_minted_note() {
    let miner = Wallet::from_seed_lanes([0x9101_0000_0000_0011; 4]);
    let d = Diversifier::default();

    let mut chain = Chain::new();
    let h = chain.mine_to(miner.rkm(d));
    let note = coinbase_note(h, &chain.body_at(h)).expect("minting block");

    // Grow past maturity so the leaf exists at all — this test is about *who* can
    // derive the minted note, not about when it lands, so it has to get past the
    // issue #102 delay before "is it a leaf" means anything.
    while chain.tip.height < coinbase_leaf_appears_at(h) {
        chain.mine_to([0x99; 4]);
    }
    let tree = chain.node.commitments().tree();
    assert!(tree.position_of(&note.commitment()).is_some(), "the matured leaf is in the tree");

    // The miner reproduces the leaf exactly.
    let (_, _, mine) = derive_input(&miner.spend_input(note.value, note.rho, note.rseed, d));
    assert_eq!(mine, note.commitment());

    // A thief with the full public opening — value, ρ, rseed, the block, the
    // whole chain — still derives a commitment that is not in the tree.
    let thief = Wallet::from_seed_lanes([0x9101_0000_0000_0012; 4]);
    let (_, _, theirs) =
        derive_input(&thief.spend_input(note.value, note.rho, note.rseed, d));
    assert_ne!(theirs, note.commitment(), "a different spend key derives a different note");
    assert!(
        tree.position_of(&theirs).is_none(),
        "and it is not a leaf, so no membership witness exists — the note is unspendable by them"
    );

    // Same wallet, wrong diversifier: rkm is per-address (issue #32), so this is
    // just as unspendable. This is the mistake a real miner is most likely to
    // make, and it fails closed rather than silently.
    let other_d = miner.diversifier_at_index(7);
    assert_ne!(other_d.lanes(), d.lanes());
    let (_, _, wrong_d) =
        derive_input(&miner.spend_input(note.value, note.rho, note.rseed, other_d));
    assert_ne!(wrong_d, note.commitment());
    assert!(tree.position_of(&wrong_d).is_none());
}

/// 🔴 **THE #102 CLAIM: an immature coinbase spend has no witness against any anchor
/// this chain accepts — it is not merely refused.**
///
/// The name says "unprovable" and that word is imprecise on purpose-of-brevity, so
/// the limit is stated here: an attacker *can* prove a true statement about a tree of
/// their own making, and the production verifier accepts it. See
/// [`a_forged_anchor_carrying_a_real_proof_is_rejected_at_the_block_path`], which
/// asserts that acceptance and then shows the block rejected anyway. What this test
/// establishes is the other half — that against the real chain there is nothing to
/// build a witness from.
///
/// This is the test that distinguishes "we moved the policy" from "it is now
/// consensus", and it replaces `the_maturity_depth_is_enforced_on_the_real_note`,
/// which asserted the policy gate this issue deleted. That test drove
/// `Mempool::admit` directly and hand-fed it the declaration production hardcoded
/// empty, so it passed for the entire life of the defect.
///
/// The property asserted here needs no proof to be generated and no mempool to be
/// consulted, which is precisely what makes it structural: **the leaf is in no
/// anchor the node will ever accept.** The commitment tree is append-only, so a
/// commitment absent from the live tree is absent from every root the tree has ever
/// had — there is no anchor, valid or expired, whose prefix contains it, therefore
/// no membership witness exists, therefore no honest prover and no lying prover can
/// produce a proof that verifies. A submitter who declares nothing, a peer that
/// bypasses this mempool entirely, and a node that just restarted are all bound
/// identically, because none of them is being asked anything.
#[test]
fn an_immature_coinbase_spend_is_unprovable_not_refused() {
    let miner = Wallet::from_seed_lanes([0x9101_0000_0000_0021; 4]);
    let d = Diversifier::default();

    let mut chain = Chain::new();
    let h = chain.mine_to(miner.rkm(d));
    let note = coinbase_note(h, &chain.body_at(h)).expect("a minting block mints a note");

    // Grow the chain to one block short of maturity, finalizing as we go, so the
    // node offers the richest anchor set it can.
    while chain.tip.height < coinbase_leaf_appears_at(h) - 1 {
        chain.mine_to([1, 2, 3, 4]);
    }
    assert_eq!(chain.tip.height, h + COINBASE_MATURITY_BLOCKS - 1);

    // (1) The leaf does not exist. Not "is refused" — does not exist.
    let tree = chain.node.commitments().tree();
    assert!(
        tree.position_of(&note.commitment()).is_none(),
        "the immature coinbase note must not be a leaf"
    );
    assert_eq!(chain.node.commitment_count(), 0, "no leaf has matured yet at all");

    // (2) Therefore no anchor contains it. Every root the node will accept is a
    //     prefix root of this append-only tree, and the leaf is in no prefix — so
    //     this holds for every height, not just the tip, and no witness exists to
    //     build a proof against. Nothing is being trusted here; there is simply
    //     nothing to prove membership in.
    for height in 0..=chain.tip.height {
        let root = digest_bytes(&tree.root_at(leaves_through(height)));
        if chain.node.is_valid_anchor(&root) {
            assert!(
                tree.position_of(&note.commitment()).is_none(),
                "no valid anchor may contain an immature coinbase leaf (height {height})"
            );
        }
    }

    // (3) And the failure is *not* a maturity refusal. A candidate naming a valid
    //     anchor is refused for the proof it cannot have — the same refusal any
    //     other unprovable claim gets. The mempool has no maturity opinion to state:
    //     nothing was declared to it, and there is no variant left to return.
    let mut mp = Mempool::default();
    let anchor = digest_bytes(&tree.root_at(leaves_through(chain.tip.height)));
    assert!(chain.node.is_valid_anchor(&anchor));
    let candidate = TxEntry {
        proof: Vec::new(),
        public: TxPublic {
            anchor,
            nullifiers: vec![[0x21; 32], [0x22; 32]],
            commitments: vec![[0x23; 32], [0x24; 32]],
            bucket: ArityBucket::TwoByTwo,
            fee: posted_fee(ArityBucket::TwoByTwo),
        },
    };
    assert_eq!(
        mp.admit(candidate, &chain.node, &ConsensusVerifier),
        Err(MempoolError::ProofInvalid),
        "an immature spend fails as unprovable, not as a policy refusal"
    );

    // (4) The holder can still tell "immature" from "nonexistent" — the absence has
    //     a reason attached, from public chain facts only (issue #102 position 2).
    assert_eq!(
        chain.node.coinbase_maturity(h),
        CoinbaseMaturity::Immature { leaf_at: coinbase_leaf_appears_at(h), blocks_remaining: 1 },
    );
}

/// 🔴 **THE DISCRIMINATING TEST: a real proof, a forged anchor, a block submitted
/// directly — no mempool anywhere in it.**
///
/// The coordinator named this as "the difference between *we moved the policy* and
/// *it is now consensus*": if it can be made to pass while the mempool is bypassed,
/// option (b) was not implemented. Mempool admission is one node's front door and
/// blocks do not come through it, so a rule enforced only there is enforced nowhere
/// that matters — which was the original finding.
///
/// So this test plays the only move an attacker actually has. Being unable to build a
/// witness against the *real* tree, they build a **side tree containing the immature
/// leaves**, take a genuine membership witness against that, and produce a real 2×2
/// STARK — which the production verifier **accepts**, because it is a valid proof of a
/// true statement about the attacker's tree. Nothing is malformed and nothing is
/// forged in the cryptographic sense.
///
/// It is refused anyway, at the block path, because the anchor it proves against is
/// not a root this chain ever had. That is the shape of consensus enforcement: the
/// attacker's proof is fine and their *anchor* is the lie, and anchors are checked by
/// `validate_body` on every block, from every peer, with no declaration and no
/// mempool involved.
#[test]
fn a_forged_anchor_carrying_a_real_proof_is_rejected_at_the_block_path() {
    let _gate = prover_gate();

    let miner = Wallet::from_seed_lanes([0x9101_0000_0000_0041; 4]);
    let d = Diversifier::default();
    let miner_rkm = miner.rkm(d);

    // Two coinbase notes, both freshly minted and therefore both immature.
    let mut chain = Chain::new();
    let h1 = chain.mine_to(miner_rkm);
    let h2 = chain.mine_to(miner_rkm);
    let n1 = coinbase_note(h1, &chain.body_at(h1)).expect("minting block");
    let n2 = coinbase_note(h2, &chain.body_at(h2)).expect("minting block");

    // Grow a little; nothing matures, so the real tree stays empty.
    while chain.tip.height < 20 {
        chain.mine_to([0x41; 4]);
    }
    assert_eq!(chain.node.commitment_count(), 0, "neither note has a leaf on the real chain");

    // --- the attacker's side tree ----------------------------------------
    // They append the two immature leaves themselves and anchor to *that*.
    let mut forged = MemCommitmentStore::default();
    forged.append(digest_bytes(&n1.commitment()));
    forged.append(digest_bytes(&n2.commitment()));
    let forged_lanes = forged.tree().root_at(2);
    let forged_anchor = digest_bytes(&forged_lanes);
    assert!(
        !chain.node.is_valid_anchor(&forged_anchor),
        "the side-tree root is not, and never was, an anchor of this chain"
    );

    // Real witnesses against the side tree, and a real proof.
    let fee = posted_fee(ArityBucket::TwoByTwo);
    let inputs: [TxInput; 2] = [
        miner.spend_input(n1.value, n1.rho, n1.rseed, d),
        miner.spend_input(n2.value, n2.rho, n2.rseed, d),
    ];
    let witnesses: [MerkleWitness; 2] = [
        forged.tree().auth_path(0, 2),
        forged.tree().auth_path(1, 2),
    ];
    assert_eq!(witnesses[0].fold_root(&n1.commitment()), forged_lanes);
    let total_in = n1.value + n2.value;
    let outputs = [
        TxOutput { value: total_in / 3, rkm: miner_rkm, rho: [41; 4], rseed: [42; 4] },
        TxOutput {
            value: total_in - total_in / 3 - fee,
            rkm: miner_rkm,
            rho: [43; 4],
            rseed: [44; 4],
        },
    ];
    let inst = build_bucket_with_witnesses(
        LOG_HEIGHT,
        &inputs,
        &outputs,
        fee,
        &witnesses,
        forged_lanes,
    );
    let (_pvs, proof) = prove_bucket(&inst);
    let entry = TxEntry {
        proof: bincode::serialize(&proof).expect("proof serializes"),
        public: TxPublic {
            anchor: forged_anchor,
            nullifiers: vec![digest_bytes(&inst.nf[0]), digest_bytes(&inst.nf[1])],
            commitments: vec![digest_bytes(&inst.cm_out[0]), digest_bytes(&inst.cm_out[1])],
            bucket: ArityBucket::TwoByTwo,
            fee,
        },
    };

    // The proof is genuinely valid — the attacker did not fail at cryptography, and
    // the refusal below is therefore not the verifier catching a bad proof.
    assert!(
        ConsensusVerifier.verify_tx(&entry),
        "the proof is a real, verifying proof of membership in the attacker's own tree"
    );

    // 🔴 THE CLAIM: submitted as a block, with no mempool involved, it is rejected.
    let body = BlockBody {
        txs: vec![entry],
        coinbase: coinbase(chain.tip.height + 1),
        coinbase_rkm: miner_rkm,
    };
    let verdict = chain.try_apply_with(body, &ConsensusVerifier);
    assert!(
        matches!(verdict, Err(qlab_node::NodeError::Body(BodyError::AnchorNotFinal { index: 0 }))),
        "a block anchoring an immature spend to a tree the chain never had must be \
         rejected by block validation, not by mempool policy — got {verdict:?}"
    );

    // State is untouched: no nullifier was consumed, no leaf appended.
    assert!(!chain.node.is_spent(&digest_bytes(&inst.nf[0])));
    assert_eq!(chain.node.commitment_count(), 0);
}

/// **The leaf appears at exactly `minted + 144`, and not one block earlier.**
///
/// Reconciliation with the boundary this repo used to pin (task-book acceptance item
/// 2): `qumbra-faucet`'s `spendable_at_tip` returned `minted + 144 − 1`, derived from
/// the mempool policy gate — `admit` compared `prospective_height = tip + 1` against
/// `minted + 144`, so `tip ≥ minted + 143` was enough. That gate is gone, and the
/// boundary genuinely moved **one block later**: the leaf is appended *while applying*
/// block `minted + 144`, so no root before that height contains it. The old value was
/// not wrong for the old rule; it is wrong for this one, and `spendable_at_tip` was
/// changed deliberately rather than edited to make a test pass.
#[test]
fn the_leaf_appears_exactly_at_maturity_and_not_one_block_earlier() {
    let miner = Wallet::from_seed_lanes([0x9101_0000_0000_0031; 4]);
    let d = Diversifier::default();

    let mut chain = Chain::new();
    let h = chain.mine_to(miner.rkm(d));
    let note = coinbase_note(h, &chain.body_at(h)).expect("a minting block mints a note");
    let cm = note.commitment();
    let leaf_at = coinbase_leaf_appears_at(h);

    // One block short: absent.
    while chain.tip.height < leaf_at - 1 {
        chain.mine_to([5, 6, 7, 8]);
    }
    assert_eq!(chain.tip.height, leaf_at - 1);
    assert!(
        chain.node.commitments().tree().position_of(&cm).is_none(),
        "at minted + 143 the leaf must still be absent — the old boundary is one block early"
    );
    assert!(matches!(
        coinbase_maturity(h, chain.tip.height),
        CoinbaseMaturity::Immature { blocks_remaining: 1, .. }
    ));

    // Exactly at maturity: present, and inside the anchor at that height.
    chain.mine_to([5, 6, 7, 8]);
    assert_eq!(chain.tip.height, leaf_at);
    let tree = chain.node.commitments().tree();
    let pos = tree.position_of(&cm).expect("at minted + 144 the leaf is in the tree");
    let leaf_count = leaves_through(leaf_at);
    assert!(pos < leaf_count, "and inside that height's anchor prefix");
    let anchor_lanes = tree.root_at(leaf_count);
    assert_eq!(
        tree.auth_path(pos, leaf_count).fold_root(&cm),
        anchor_lanes,
        "a membership witness now exists and folds to the anchor at minted + 144"
    );
    assert!(
        chain.node.is_valid_anchor(&digest_bytes(&anchor_lanes)),
        "and that anchor is one the node accepts"
    );
    assert_eq!(coinbase_maturity(h, chain.tip.height), CoinbaseMaturity::Matured { leaf_at });

    // `qumbra-faucet`'s `spendable_at_tip` must agree that this is the height, not
    // the one before it. That cross-check lives in that crate's own tests
    // (`the_funding_threshold_is_the_append_schedules_own`) — asserting it here would
    // make `qumbra-node` depend on `qumbra-faucet`, which depends on it.
}

// ---------------------------------------------------------------------------
// Acceptance 3 — a block whose body field is absent or malformed is rejected.
// ---------------------------------------------------------------------------

/// **A block that mints without naming a payee is rejected.** `[0; 4]` is the
/// shape a dropped field takes, and no `(sk, d)` derives it, so accepting one
/// burns the block's whole issuance with nothing to detect it.
#[test]
fn a_minting_block_with_no_payout_key_is_rejected() {
    let mut chain = Chain::new();
    let height = chain.tip.height + 1;
    let body =
        BlockBody { txs: Vec::new(), coinbase: coinbase(height), coinbase_rkm: [0; 4] };
    let header =
        BlockHeader::child_of(&chain.tip, 75, GENESIS_DIFFICULTY, body.commitment());
    let err = chain.node.apply_block(header, body, &NoTxVerifier).unwrap_err();
    assert!(
        matches!(err, qlab_node::NodeError::Body(qlab_devnet::body::BodyError::MissingCoinbasePayee)),
        "expected MissingCoinbasePayee, got {err:?}"
    );
    assert_eq!(chain.node.tip_height(), 0, "and nothing was folded into state");
}

/// **A block whose payout key was altered in flight is rejected**, because the
/// key is inside the header binding (#79). Without this, the field would be
/// unauthenticated and any relay could redirect a block's issuance to itself.
#[test]
fn a_redirected_payout_key_is_rejected_by_the_header_binding() {
    let mut chain = Chain::new();
    let height = chain.tip.height + 1;
    let honest =
        BlockBody { txs: Vec::new(), coinbase: coinbase(height), coinbase_rkm: [0xAA; 4] };
    let header =
        BlockHeader::child_of(&chain.tip, 75, GENESIS_DIFFICULTY, honest.commitment());
    let stolen = BlockBody { coinbase_rkm: [0xBB; 4], ..honest.clone() };
    let err = chain.node.apply_block(header, stolen, &NoTxVerifier).unwrap_err();
    assert!(
        matches!(
            err,
            qlab_node::NodeError::Body(qlab_devnet::body::BodyError::CommitmentMismatch { .. })
        ),
        "expected CommitmentMismatch, got {err:?}"
    );
    assert_eq!(chain.node.tip_height(), 0);
}

/// **A wire announcement missing the payout key does not decode.** This is the
/// "field absent" case as it actually reaches a node: a pre-#101 peer's
/// `BlockAnnounce` is 32 bytes short. It must be refused by the codec, not
/// silently reconstructed into a body with a zero key.
#[test]
fn a_pre_101_block_announcement_does_not_decode() {
    use qlab_p2p::compact::{decode_announce, encode_announce, BlockAnnounce};

    let ann = BlockAnnounce {
        header: BlockHeader::genesis(GENESIS_DIFFICULTY, 0),
        nonce: 0xABCD,
        coinbase: 5_000,
        coinbase_rkm: [1, 2, 3, 4],
        short_ids: Vec::new(),
        prefilled: Vec::new(),
    };
    let bytes = encode_announce(&ann);
    let round = decode_announce(&bytes).expect("current wire round-trips");
    assert_eq!(round.coinbase_rkm, [1, 2, 3, 4]);

    // The same frame as a pre-#101 peer would have sent it: everything except the
    // 32 payout-key bytes. `coinbase` sits immediately before them, so removing
    // them is exactly the old encoding.
    let mut old = Vec::new();
    old.extend_from_slice(&bytes[..bytes.len() - 32 - 2]); // …minus rkm and the two empty varints
    old.extend_from_slice(&bytes[bytes.len() - 2..]);
    assert!(
        decode_announce(&old).is_err(),
        "a pre-#101 announcement must be refused, not reconstructed with a zero payout key"
    );
}

/// Determinism across the whole path: a from-log replay of a chain that mints
/// coinbase notes reproduces the identical commitment tree. `open == replay` is
/// the property the coinbase leaf could most easily have broken, because it is
/// appended by `apply_state` rather than read out of the body — and since issue #102
/// it is appended on behalf of a *different* block, which is strictly more that can
/// go wrong.
///
/// Five distinct miners are paid at heights 1..=5 and the chain is then grown past
/// the maturity delay so all five leaves land, at 145..=149. That the count is right
/// is the weak half; that leaf 0 is the note minted at height 1 by *that* miner is
/// the half that would catch an off-by-one or a misresolved ancestor.
///
/// `qlab-node/tests/maturity_schedule.rs` carries the deeper replay coverage — every
/// prefix root compared, and the snapshot fast path exercised across the delay, which
/// is the case that decided how this mechanism is built.
#[test]
fn replay_reproduces_the_coinbase_leaves() {
    let dir = std::env::temp_dir().join(format!("qmb-i102-replay-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");

    let rkm_at = |height: u64| [height, height + 1, height + 2, height + 3];
    let last_minter = 5u64;
    let burn = [0xBBu64, 0, 0, 0];

    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let mut node = MemNode::open(&dir, genesis.clone()).expect("open");
    let mut tip = genesis.header();
    // Heights 1..=5 pay five different miners; the rest pay a burn key so the only
    // leaves that can land within this fixture are the five under test.
    let final_height = coinbase_leaf_appears_at(last_minter);
    for height in 1..=final_height {
        let coinbase_rkm = if height <= last_minter { rkm_at(height) } else { burn };
        let body = BlockBody { txs: Vec::new(), coinbase: coinbase(height), coinbase_rkm };
        let header =
            BlockHeader::child_of(&tip, height * 75, GENESIS_DIFFICULTY, body.commitment());
        node.apply_block(header, body, &NoTxVerifier).expect("applies");
        tip = header;
    }
    assert_eq!(
        node.commitment_count(),
        last_minter,
        "the five minted notes matured at 145..=149; every later block's coinbase is still owed"
    );
    let live_root = node.commitment_root();

    let replayed = MemNode::replay(&dir, genesis).expect("replay");
    assert_eq!(replayed.commitment_count(), last_minter);
    assert_eq!(replayed.commitment_root(), live_root, "replay must rebuild the same tree");

    // And the leaves are the notes, in mint order — position `i` is the note minted at
    // height `i + 1`, matured at `i + 145`.
    for height in 1..=last_minter {
        let leaf = coinbase_note_leaf(
            height,
            &BlockBody {
                txs: Vec::new(),
                coinbase: coinbase(height),
                coinbase_rkm: rkm_at(height),
            },
        )
        .expect("minting");
        assert_eq!(
            replayed.commitments().tree().position_of(&digest_from_bytes(&leaf)),
            Some(height - 1),
            "the note minted at {height} must be leaf {} — appended when {} was applied",
            height - 1,
            coinbase_leaf_appears_at(height),
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}
