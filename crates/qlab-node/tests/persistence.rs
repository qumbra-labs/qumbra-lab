//! Restart-safety + genesis-replay acceptance tests for the node skeleton.
//!
//! The load-bearing invariant: a node resumed from an atomic snapshot
//! (`Node::open`) has byte-for-byte the same consensus state as one rebuilt
//! purely from the log (`Node::replay`). Plus the state-transition rules:
//! commitments accumulate, the nullifier set blocks cross-block double-spends,
//! and anchors must be finalized-and-in-window.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use qlab_devnet::body::{BlockBody, TxEntry, TxPublic};
use qlab_devnet::fees::{posted_fee, ArityBucket};
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_devnet::params_devnet::GENESIS_DIFFICULTY;

use qlab_node::{genesis_block, MemNode, NodeError, NodeState};

/// Mock verifier — a proof is "valid" iff its bytes are `b"ok"` (mirrors the
/// devnet body-validation tests; the node is prover-free by design).
struct MockVerifier;
impl qlab_devnet::body::TxVerifier for MockVerifier {
    fn verify_tx(&self, entry: &TxEntry) -> bool {
        entry.proof == b"ok"
    }
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    p.push(format!("qlab-node-test-{tag}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn tx(anchor: Hash32, nullifiers: Vec<Hash32>, commitments: Vec<Hash32>) -> TxEntry {
    TxEntry {
        proof: b"ok".to_vec(),
        public: TxPublic {
            anchor,
            nullifiers,
            commitments,
            bucket: ArityBucket::TwoByTwo,
            fee: posted_fee(ArityBucket::TwoByTwo),
        },
    }
}

/// A running-tip helper: applies a one-tx block extending `parent`, returns the
/// new header + hash so the caller can chain the next block.
fn apply_one_tx_block(
    node: &mut MemNode,
    parent: &BlockHeader,
    tx: TxEntry,
) -> Result<(BlockHeader, Hash32), NodeError> {
    let body = BlockBody { txs: vec![tx], coinbase: 0, coinbase_rkm: [0; 4] };
    let header = BlockHeader::child_of(parent, parent.height + 1, GENESIS_DIFFICULTY, body.commitment());
    let hash = node.apply_block(header, body, &MockVerifier)?;
    Ok((header, hash))
}

/// Build a two-block chain in `dir` and return the interesting state so tests can
/// compare it after a restart. Genesis finalized ⇒ its empty root anchors block1;
/// block1 finalized ⇒ its root anchors block2's spend.
fn build_chain(dir: &PathBuf) -> (Hash32, u64, usize, Hash32, Option<u64>) {
    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let g_header = genesis.header();
    let mut node = MemNode::open(dir, genesis).unwrap();

    // Finalize genesis so its (empty) root is a valid anchor.
    assert!(node.finalize(g_header.header_hash()).unwrap());
    let g_root = node.commitment_root();

    // block1: two output commitments, anchored to the finalized genesis root.
    let (h1, hash1) =
        apply_one_tx_block(&mut node, &g_header, tx(g_root, vec![], vec![[1u8; 32], [2u8; 32]]))
            .unwrap();
    assert_eq!(node.commitment_count(), 2);
    assert!(node.finalize(hash1).unwrap());
    let r1 = node.commitment_root();

    // block2: a spend (one nullifier) + one new output, anchored to block1's root.
    apply_one_tx_block(&mut node, &h1, tx(r1, vec![[9u8; 32]], vec![[3u8; 32]])).unwrap();
    assert!(node.is_spent(&[9u8; 32]));

    node.save_snapshot().unwrap();
    (
        node.tip_hash(),
        node.commitment_count(),
        node.nullifier_count(),
        node.commitment_root(),
        node.finalized_height(),
    )
}

#[test]
fn open_equals_replay_on_the_finalized_checkpoint_and_state() {
    let dir = temp_dir("restart");
    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);

    let (tip, cc, nc, root, fh) = build_chain(&dir);

    // Restart via the atomic snapshot (fast path).
    let reopened = MemNode::open(&dir, genesis.clone()).unwrap();
    assert_eq!(reopened.tip_hash(), tip, "snapshot restart preserves tip");
    assert_eq!(reopened.commitment_count(), cc);
    assert_eq!(reopened.nullifier_count(), nc);
    assert_eq!(reopened.commitment_root(), root, "commitment root survives restart");
    assert_eq!(reopened.finalized_height(), fh, "finalized head survives restart");
    assert_eq!(reopened.recovery_report().snapshot_height, Some(2));
    assert_eq!(reopened.recovery_report().replayed_records, 0);
    assert!(reopened.is_spent(&[9u8; 32]));

    // Rebuild purely from the log (ignores the snapshot) — the correctness anchor.
    let replayed = MemNode::replay(&dir, genesis).unwrap();
    assert_eq!(replayed.tip_hash(), tip, "genesis replay reaches the same tip");
    assert_eq!(replayed.commitment_count(), cc);
    assert_eq!(replayed.nullifier_count(), nc);
    assert_eq!(replayed.commitment_root(), root);
    assert_eq!(replayed.finalized_height(), fh, "finalized head reconstructed from the log");
    assert_eq!(
        reopened.restored_checkpoint(),
        replayed.restored_checkpoint(),
        "open == replay on the exact checkpoint, including the identity-bearing hash"
    );
    assert!(replayed.is_spent(&[9u8; 32]));

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_snapshot_whose_finalized_block_is_absent_refuses_to_open() {
    let dir = temp_dir("bad-finalized");
    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    build_chain(&dir);

    let path = dir.join(qlab_node::SNAPSHOT);
    let mut snap: qlab_node::Snapshot =
        bincode::deserialize(&std::fs::read(&path).unwrap()).unwrap();
    snap.finalized = Some(([0xEE; 32], 1));
    std::fs::write(&path, bincode::serialize(&snap).unwrap()).unwrap();

    match MemNode::open(&dir, genesis) {
        Err(NodeError::SnapshotFinality(
            qlab_devnet::chain::RestoreFinalizedError::Unknown,
        )) => {}
        Err(other) => panic!("wrong refusal: {other}"),
        Ok(_) => panic!("an inconsistent finalized head must never start fresh"),
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_fresh_datadir_starts_without_finality_quietly() {
    let dir = temp_dir("fresh");
    let node = MemNode::open(&dir, genesis_block(GENESIS_DIFFICULTY, 0)).unwrap();

    assert_eq!(node.finalized_height(), None);
    assert_eq!(node.restored_checkpoint(), None);
    assert_eq!(
        node.recovery_report().to_string(),
        "RECOVERY no snapshot, replayed 0 records, resumed at tip 0"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_finalization_recorded_after_the_snapshot_still_survives() {
    let dir = temp_dir("post-snapshot-finalize");
    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let g_header = genesis.header();
    let mut node = MemNode::open(&dir, genesis.clone()).unwrap();

    assert!(node.finalize(g_header.header_hash()).unwrap());
    let root = node.commitment_root();
    let (_h1, hash1) = apply_one_tx_block(
        &mut node,
        &g_header,
        tx(root, vec![], vec![[1u8; 32]]),
    )
    .unwrap();
    node.save_snapshot().unwrap();
    assert_eq!(node.finalized_height(), Some(0), "snapshot contains genesis finality");

    // This record is appended after the snapshot even though it names a block at
    // the snapshot's applied height. Recovery must judge record order, not assume
    // `height <= applied_height` means the finalization was already snapshotted.
    assert!(node.finalize(hash1).unwrap());
    drop(node);

    let reopened = MemNode::open(&dir, genesis).unwrap();
    assert_eq!(reopened.finalized_height(), Some(1));
    assert_eq!(reopened.recovery_report().snapshot_height, Some(1));
    assert_eq!(
        reopened.recovery_report().replayed_records,
        1,
        "only the post-snapshot finalization advances recovery state"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn open_without_snapshot_full_replays_to_same_state() {
    let dir = temp_dir("nosnap");
    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);

    let (tip, cc, nc, root, fh) = build_chain(&dir);

    // Simulate a snapshot lost to a crash: delete it. `open` must fall back to a
    // full log replay and land in exactly the same state.
    std::fs::remove_file(dir.join(qlab_node::SNAPSHOT)).unwrap();
    let reopened = MemNode::open(&dir, genesis).unwrap();
    assert_eq!(reopened.tip_hash(), tip);
    assert_eq!(reopened.commitment_count(), cc);
    assert_eq!(reopened.nullifier_count(), nc);
    assert_eq!(reopened.commitment_root(), root);
    assert_eq!(reopened.finalized_height(), fh);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn cross_block_double_spend_is_rejected() {
    let dir = temp_dir("dspend");
    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let g_header = genesis.header();
    let mut node = MemNode::open(&dir, genesis).unwrap();

    node.finalize(g_header.header_hash()).unwrap();
    let g_root = node.commitment_root();
    let (h1, hash1) =
        apply_one_tx_block(&mut node, &g_header, tx(g_root, vec![[7u8; 32]], vec![[1u8; 32]]))
            .unwrap();
    node.finalize(hash1).unwrap();
    let r1 = node.commitment_root();

    // A second block re-using nullifier [7;32] (anchored to the finalized r1).
    let err =
        apply_one_tx_block(&mut node, &h1, tx(r1, vec![[7u8; 32]], vec![[2u8; 32]])).unwrap_err();
    assert!(matches!(err, NodeError::NullifierSpent { tx: 0 }), "got {err}");
    // State is untouched by the rejected block.
    assert_eq!(node.tip_hash(), hash1);
    assert_eq!(node.commitment_count(), 1);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn unfinalized_anchor_is_rejected() {
    let dir = temp_dir("anchor");
    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let g_header = genesis.header();
    let mut node = MemNode::open(&dir, genesis).unwrap();

    // Genesis NOT finalized yet → even the genesis root is not a valid anchor.
    let g_root = node.commitment_root();
    assert!(!node.is_valid_anchor(&g_root));
    let err =
        apply_one_tx_block(&mut node, &g_header, tx(g_root, vec![], vec![[1u8; 32]])).unwrap_err();
    assert!(
        matches!(err, NodeError::Body(qlab_devnet::body::BodyError::AnchorNotFinal { index: 0 })),
        "got {err}"
    );

    // After finalizing genesis, the same root becomes a valid anchor.
    node.finalize(g_header.header_hash()).unwrap();
    assert!(node.is_valid_anchor(&g_root));
    assert!(apply_one_tx_block(&mut node, &g_header, tx(g_root, vec![], vec![[1u8; 32]])).is_ok());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn stored_block_round_trips_header_hash() {
    // Persistence must preserve block identity: a header → StoredHeader → header
    // round-trip must reproduce the exact header hash (chain-link integrity).
    let genesis = genesis_block(GENESIS_DIFFICULTY, 42);
    let g_header = genesis.header();
    let child = BlockHeader::child_of(&g_header, 1, GENESIS_DIFFICULTY, [0xAB; 32]);
    let stored = qlab_node::StoredBlock::from_parts(&child, &BlockBody::default());
    assert_eq!(stored.header().header_hash(), child.header_hash());
}
