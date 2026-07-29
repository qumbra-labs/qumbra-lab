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
use qlab_devnet::body::{BlockBody, TxEntry, TxPublic, TxVerifier};
use qlab_devnet::fees::{posted_fee, ArityBucket};
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_devnet::params_devnet::GENESIS_DIFFICULTY;
use qlab_node::{
    coinbase, coinbase_note, coinbase_note_leaf, genesis_block, ChainStore, CommitmentStore,
    MemNode, Mempool, MempoolError, NodeState, COINBASE_MATURITY_BLOCKS,
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
/// Every fixture block mints exactly one coinbase note and carries no txs, so it
/// is one leaf per block, genesis excluded.
fn leaves_through(height: u64) -> u64 {
    height
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

    // Each note's commitment really is a leaf of the live tree — the thing that
    // did not exist before this issue.
    let tree_has = |cm: [u64; 4]| chain.node.commitments().tree().position_of(&cm).is_some();
    assert!(tree_has(n1.commitment()), "coinbase note 1 must be in the tree");
    assert!(tree_has(n2.commitment()), "coinbase note 2 must be in the tree");

    // --- mature ----------------------------------------------------------
    // Grow the chain until note 1 is 144 blocks deep. Every block mints its own
    // coinbase note, so the tree keeps growing under the notes we are about to
    // spend — exactly as it would on a live chain.
    let burn = [0xDEAD_BEEFu64, 1, 2, 3]; // later blocks pay someone else
    while chain.tip.height < h1 + COINBASE_MATURITY_BLOCKS {
        chain.mine_to(burn);
    }
    let tip = chain.tip.height;
    assert_eq!(tip, h1 + COINBASE_MATURITY_BLOCKS);

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

    // …and the node accepts it: admitted by the mempool (with the coinbase notes
    // declared, so the frozen §2 maturity gate is actually consulted), then
    // applied as a block through the real state transition.
    let cb1 = digest_bytes(&n1.commitment());
    let cb2 = digest_bytes(&n2.commitment());
    let mut mp = Mempool::default();
    mp.record_coinbase_note(cb1, h1);
    mp.record_coinbase_note(cb2, h2);
    mp.admit(entry.clone(), vec![cb1, cb2], &chain.node, &ConsensusVerifier)
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
        "two spend outputs plus that block's own coinbase-note leaf"
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
    let tree = chain.node.commitments().tree();
    assert!(tree.position_of(&note.commitment()).is_some(), "the minted leaf is in the tree");

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

/// **The maturity depth is enforced**, at the gate the frozen §2 constant lives
/// behind: one block before maturity the spend is refused, and the refusal names
/// the real note commitment (not the deleted placeholder digest). At maturity it
/// is admitted.
///
/// Honest scope: this is the *policy* gate — the mempool consults the coinbase
/// notes a transaction **declares** it spends. It is not, and this baton does not
/// make it, structurally unforgeable; see `qlab_node::mempool`'s module docs and
/// issue #102.
#[test]
fn the_maturity_depth_is_enforced_on_the_real_note() {
    let miner = Wallet::from_seed_lanes([0x9101_0000_0000_0021; 4]);
    let d = Diversifier::default();

    let mut chain = Chain::new();
    let h = chain.mine_to(miner.rkm(d));
    let body = BlockBody {
        txs: Vec::new(),
        coinbase: coinbase(h),
        coinbase_rkm: miner.rkm(d),
    };
    let cb = coinbase_note_leaf(h, &body).expect("minting block");

    let mut mp = Mempool::default();
    mp.record_coinbase_note(cb, h);

    // A syntactically fine candidate; the maturity gate runs before the proof
    // verify, so it is reached regardless of the proof bytes.
    let anchor = chain.node.commitment_root();
    let candidate = |anchor: Hash32| TxEntry {
        proof: Vec::new(),
        public: TxPublic {
            anchor,
            nullifiers: vec![[0x21; 32], [0x22; 32]],
            commitments: vec![[0x23; 32], [0x24; 32]],
            bucket: ArityBucket::TwoByTwo,
            fee: posted_fee(ArityBucket::TwoByTwo),
        },
    };

    // One block short of maturity.
    while chain.tip.height < h + COINBASE_MATURITY_BLOCKS - 2 {
        chain.mine_to([1, 2, 3, 4]);
    }
    let anchor_now = chain.node.commitment_root();
    assert!(chain.node.is_valid_anchor(&anchor_now));
    let err = mp
        .admit(candidate(anchor_now), vec![cb], &chain.node, &ConsensusVerifier)
        .unwrap_err();
    assert_eq!(
        err,
        MempoolError::ImmatureCoinbase {
            commitment: cb,
            created_at: h,
            matures_at: h + COINBASE_MATURITY_BLOCKS,
            prospective_height: chain.tip.height + 1,
        },
        "one block short of maturity the spend is refused, naming the real note"
    );
    let _ = anchor;

    // One more block and the prospective height reaches maturity exactly.
    chain.mine_to([1, 2, 3, 4]);
    let anchor_at = chain.node.commitment_root();
    let err_at_maturity = mp.admit(candidate(anchor_at), vec![cb], &chain.node, &ConsensusVerifier);
    // The maturity gate passes; the proof gate is what refuses these empty bytes.
    assert_eq!(
        err_at_maturity,
        Err(MempoolError::ProofInvalid),
        "at maturity the coinbase gate no longer refuses — only the (absent) proof does"
    );
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
/// appended by `apply_state` rather than read out of the body.
#[test]
fn replay_reproduces_the_coinbase_leaves() {
    let dir = std::env::temp_dir().join(format!("qmb-i101-replay-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");

    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let mut node = MemNode::open(&dir, genesis.clone()).expect("open");
    let mut tip = genesis.header();
    for height in 1..=5u64 {
        let body = BlockBody {
            txs: Vec::new(),
            coinbase: coinbase(height),
            coinbase_rkm: [height, height + 1, height + 2, height + 3],
        };
        let header =
            BlockHeader::child_of(&tip, height * 75, GENESIS_DIFFICULTY, body.commitment());
        node.apply_block(header, body, &NoTxVerifier).expect("applies");
        tip = header;
    }
    assert_eq!(node.commitment_count(), 5, "one coinbase leaf per block");
    let live_root = node.commitment_root();

    let replayed = MemNode::replay(&dir, genesis).expect("replay");
    assert_eq!(replayed.commitment_count(), 5);
    assert_eq!(replayed.commitment_root(), live_root, "replay must rebuild the same tree");
    // And the leaves are the notes, not something merely the same length.
    let leaf1 = coinbase_note_leaf(
        1,
        &BlockBody { txs: Vec::new(), coinbase: coinbase(1), coinbase_rkm: [1, 2, 3, 4] },
    )
    .expect("minting");
    assert!(replayed
        .commitments()
        .tree()
        .position_of(&digest_from_bytes(&leaf1))
        .is_some());

    let _ = std::fs::remove_dir_all(&dir);
}
