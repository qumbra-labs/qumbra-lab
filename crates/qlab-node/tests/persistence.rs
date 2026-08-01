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

use qlab_node::{genesis_block, ChainStore as _, MemNode, NodeError, NodeState};

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
    TxEntry::with_placeholder_discovery(b"ok".to_vec(), TxPublic {
            anchor,
            nullifiers,
            commitments,
            bucket: ArityBucket::TwoByTwo,
            fee: posted_fee(ArityBucket::TwoByTwo),
        })
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

// ---------------------------------------------------------------------------
// Issue #162 — the rewind, and the durability it has to keep.
// ---------------------------------------------------------------------------

/// Apply a block extending `parent` carrying one `marker`-tagged transaction, so
/// two calls with different markers produce genuine siblings **whose state
/// differs**: distinct nullifiers and distinct output commitments, i.e. a
/// different tree root and a different spent set on each branch.
///
/// The coinbase note cannot serve here — it matures 144 blocks later, so at the
/// heights a fork test runs at both branches have an identically empty tree, and a
/// rewind that forgot to rebuild anything at all would pass.
fn apply_marked(
    node: &mut MemNode,
    parent: &BlockHeader,
    anchor: Hash32,
    marker: u8,
) -> (BlockHeader, Hash32) {
    let body = BlockBody {
        txs: vec![tx(anchor, vec![[marker; 32]], vec![[marker.wrapping_add(0x40); 32]])],
        coinbase: 0,
        coinbase_rkm: [marker as u64; 4],
    };
    let header =
        BlockHeader::child_of(parent, parent.timestamp + 75, GENESIS_DIFFICULTY, body.commitment());
    let hash = node.apply_block(header, body, &MockVerifier).expect("marked block applies");
    (header, hash)
}

/// A disk-backed node whose genesis root is finalized, so the marked blocks above
/// have a valid anchor. Returns the node, the genesis header and that root.
fn node_with_finalized_genesis(dir: &PathBuf) -> (MemNode, BlockHeader, Hash32) {
    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let g_header = genesis.header();
    let mut node = MemNode::open(dir, genesis).unwrap();
    assert!(node.finalize(g_header.header_hash()).unwrap());
    let root = node.commitment_root();
    (node, g_header, root)
}

/// **A rewound node IS a from-genesis replay of the chain it kept** — the
/// property that lets `rewind_to` re-fold through `apply_state` instead of
/// carrying an inverse of the state transition.
///
/// Checked on state that actually differs across the fork: the two siblings pay
/// their coinbase to different keys, so their matured leaves differ and a rewind
/// that forgot to rebuild the tree would be caught by the root, not just by the
/// tip pointer.
#[test]
fn a_rewound_node_equals_a_replay_of_the_chain_it_kept() {
    let dir = temp_dir("i162-rewind-equals-replay");
    let ref_dir = temp_dir("i162-rewind-reference");

    // Reference: a node that only ever saw the winning branch.
    let (mut reference, g_header, root) = node_with_finalized_genesis(&ref_dir);
    let (w1_ref, _) = apply_marked(&mut reference, &g_header, root, 0xA1);
    apply_marked(&mut reference, &w1_ref, root, 0xA2);

    // Under test: applies the loser, rewinds to genesis, then the winner.
    let (mut node, _, _) = node_with_finalized_genesis(&dir);
    let (l1, l1_hash) = apply_marked(&mut node, &g_header, root, 0xB2);
    assert_eq!(node.tip_hash(), l1_hash);
    let losing_root = node.commitment_root();
    assert!(node.is_spent(&[0xB2; 32]), "the loser's nullifier is in the set");

    let report = node.rewind_to(g_header.header_hash()).expect("rewind to genesis");
    assert_eq!(report.blocks_undone(), 1);
    assert!(!report.is_noop());
    assert_eq!(node.tip_height(), 0, "back at genesis");
    assert_eq!(node.tip_hash(), g_header.header_hash());
    assert!(!node.is_spent(&[0xB2; 32]), "and the nullifier set came back with it");
    assert_eq!(node.commitment_count(), 0, "as did the tree");
    assert_eq!(node.finalized_height(), Some(0), "finality survived the rewind");

    let (w1, _) = apply_marked(&mut node, &g_header, root, 0xA1);
    apply_marked(&mut node, &w1, root, 0xA2);

    assert_eq!(node.tip_hash(), reference.tip_hash(), "same tip as the never-forked node");
    assert_eq!(node.commitment_root(), reference.commitment_root(), "same tree root");
    assert_eq!(node.commitment_count(), reference.commitment_count());
    assert_eq!(node.nullifier_count(), reference.nullifier_count());
    assert_ne!(losing_root, node.commitment_root(), "the two branches really differ");
    assert!(!node.is_spent(&[0xB2; 32]), "the orphan's spend is not on this chain");
    assert!(!node.chain().contains(&l1_hash), "the orphan is out of the block store");
    assert_eq!(l1.height, 1);

    // And the log, which still holds the orphan, replays to the same place.
    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let replayed = MemNode::replay(&dir, genesis.clone()).expect("replay");
    assert_eq!(replayed.tip_hash(), node.tip_hash());
    assert_eq!(replayed.commitment_root(), node.commitment_root());
    assert!(!replayed.is_spent(&[0xB2; 32]));
    assert!(!replayed.chain().contains(&l1_hash), "replay did not resurrect it either");
    let opened = MemNode::open(&dir, genesis).expect("open");
    assert_eq!(opened.tip_hash(), node.tip_hash(), "open == replay");
    assert_eq!(opened.commitment_root(), node.commitment_root());

    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&ref_dir).ok();
}

/// **A snapshot taken on the branch that then lost is not honoured** — it is
/// discarded for a full replay, not read.
///
/// Before #162 the snapshot's agreement with the log held by construction: both
/// the log and the applied chain were append-only, so reconstructing the log
/// prefix at or below `applied_height` could only land on `snap.tip`. A rewind is
/// the first thing that breaks it, and the failure would have been silent and
/// severe: the snapshot's commitment tree and nullifier set are the LOSING
/// branch's, and every anchor answer downstream would have been computed against
/// them.
#[test]
fn a_snapshot_for_a_branch_the_log_abandoned_is_discarded_not_honoured() {
    let dir = temp_dir("i162-stale-branch-snapshot");
    let (mut node, g_header, root) = node_with_finalized_genesis(&dir);

    let (_l1, l1_hash) = apply_marked(&mut node, &g_header, root, 0xB2);
    // The snapshot is written HERE — on the branch that is about to lose.
    node.save_snapshot().expect("snapshot on the losing branch");
    let losing_root = node.commitment_root();

    node.rewind_to(g_header.header_hash()).expect("rewind");
    let (w1, _) = apply_marked(&mut node, &g_header, root, 0xA1);
    apply_marked(&mut node, &w1, root, 0xA2);
    let live_tip = node.tip_hash();
    let live_root = node.commitment_root();
    assert_ne!(live_root, losing_root);
    drop(node);

    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let opened = MemNode::open(&dir, genesis.clone()).expect("open");
    assert_eq!(
        opened.recovery_report().snapshot_height,
        None,
        "the snapshot was not used — its tip is not where this log's prefix ends"
    );
    assert_eq!(opened.tip_hash(), live_tip, "and the resume landed on the winner");
    assert_eq!(opened.commitment_root(), live_root);
    assert!(!opened.is_spent(&[0xB2; 32]), "the losing branch's spend did not come back");
    assert!(!opened.chain().contains(&l1_hash));

    let replayed = MemNode::replay(&dir, genesis).expect("replay");
    assert_eq!(opened.tip_hash(), replayed.tip_hash(), "open == replay");
    assert_eq!(opened.commitment_root(), replayed.commitment_root());
    std::fs::remove_dir_all(&dir).ok();
}

/// **A snapshot that the log DOES corroborate is still used** — the positive half,
/// so "always full replay" cannot pass the test above.
///
/// The rewind happens *inside* the snapshot prefix here: the snapshot is taken
/// after the rejoin, so reconstructing the prefix has to follow the same rewind at
/// the chain-store layer and still land on `snap.tip`.
#[test]
fn a_snapshot_taken_after_a_rewind_is_still_a_fast_path() {
    let dir = temp_dir("i162-post-rewind-snapshot");
    let (mut node, g_header, root) = node_with_finalized_genesis(&dir);

    let (_l1, l1_hash) = apply_marked(&mut node, &g_header, root, 0xB2);
    node.rewind_to(g_header.header_hash()).expect("rewind");
    let (w1, _) = apply_marked(&mut node, &g_header, root, 0xA1);
    let (w2, _) = apply_marked(&mut node, &w1, root, 0xA2);
    node.save_snapshot().expect("snapshot after the rejoin");
    let live_root = node.commitment_root();
    drop(node);

    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let opened = MemNode::open(&dir, genesis.clone()).expect("open");
    assert_eq!(
        opened.recovery_report().snapshot_height,
        Some(2),
        "the snapshot IS honoured — the prefix reconstruction followed the rewind"
    );
    assert_eq!(opened.tip_hash(), w2.header_hash());
    assert_eq!(opened.commitment_root(), live_root);
    assert!(!opened.chain().contains(&l1_hash), "and the orphan stayed out");

    let replayed = MemNode::replay(&dir, genesis).expect("replay");
    assert_eq!(opened.tip_hash(), replayed.tip_hash(), "open == replay");
    assert_eq!(opened.commitment_root(), replayed.commitment_root());
    std::fs::remove_dir_all(&dir).ok();
}

/// **Every rewind refusal leaves the node exactly as it was.**
///
/// The finality crossing is covered at the adapter (where a real committee quorum
/// finalizes); this pins the other two refusals and, for all three, the fact that
/// nothing was mutated on the way to saying no.
#[test]
fn a_refused_rewind_mutates_nothing() {
    use qlab_node::RewindError;

    let dir = temp_dir("i162-refusals");
    let (mut node, g_header, root) = node_with_finalized_genesis(&dir);
    let (h1, hash1) = apply_marked(&mut node, &g_header, root, 0xA1);
    let (_h2, hash2) = apply_marked(&mut node, &h1, root, 0xA2);
    let tree_root = node.commitment_root();

    // Unknown: a hash nobody has ever seen.
    assert!(matches!(
        node.rewind_to([0x77; 32]),
        Err(NodeError::Rewind(RewindError::UnknownTarget))
    ));

    // A real block that this node never applied. `MemNode`'s block store only ever
    // holds one linear chain, so from here a foreign sibling is UNKNOWN rather than
    // not-an-ancestor — the two refusals are reachable from different layers, and
    // `NotAnAncestorOfTip` is pinned where a side branch can actually exist, in
    // `store::tests::a_rewind_refuses_a_target_off_the_tips_own_ancestry`.
    let side_dir = temp_dir("i162-refusals-side");
    let (mut other, _, side_root) = node_with_finalized_genesis(&side_dir);
    let (_s1, side_hash) = apply_marked(&mut other, &g_header, side_root, 0xB2);
    assert_ne!(side_hash, hash1);
    assert!(matches!(
        node.rewind_to(side_hash),
        Err(NodeError::Rewind(RewindError::UnknownTarget))
    ));

    // Every refusal above, and the state is untouched.
    assert_eq!(node.tip_hash(), hash2);
    assert_eq!(node.tip_height(), 2);
    assert_eq!(node.commitment_root(), tree_root);
    assert!(node.chain().contains(&hash1));

    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&side_dir).ok();
}

/// **The measured cost of a rewind** (issue #162) — `#[ignore]`d because it is a
/// measurement, not an assertion, and a timing threshold in the suite is a flake
/// waiting to happen.
///
/// Run it deliberately:
/// `cargo test --release -p qlab-node --test persistence -- --ignored --nocapture`
///
/// What it measures: a **depth-1** rewind (the ordinary sibling race) at several
/// retained heights, because `rewind_to` re-folds the retained path from genesis and
/// so costs `O(retained height)` regardless of how little it undoes. That is the
/// trade the design took — one forward transition function instead of a forward one
/// plus its inverse — and this is the number that says what it costs.
#[test]
#[ignore]
fn measure_the_cost_of_a_rewind() {
    for height in [64u64, 256, 1024] {
        let dir = temp_dir(&format!("i162-cost-{height}"));
        let (mut node, g_header, root) = node_with_finalized_genesis(&dir);
        let mut parent = g_header;
        for i in 0..height {
            // Unique nullifier + commitment per block, so the chain is real work for
            // the re-fold rather than a repeat of one leaf.
            let mut nf = [0u8; 32];
            nf[..8].copy_from_slice(&i.to_le_bytes());
            let mut cm = [0xffu8; 32];
            cm[..8].copy_from_slice(&i.to_le_bytes());
            let body = BlockBody {
                txs: vec![tx(root, vec![nf], vec![cm])],
                coinbase: 0,
                coinbase_rkm: [i; 4],
            };
            let header = BlockHeader::child_of(
                &parent,
                parent.timestamp + 75,
                GENESIS_DIFFICULTY,
                body.commitment(),
            );
            node.apply_block(header, body, &MockVerifier).expect("chain block applies");
            parent = header;
        }
        let target = parent.prev;
        let started = std::time::Instant::now();
        let report = node.rewind_to(target).expect("depth-1 rewind");
        let elapsed = started.elapsed();
        assert_eq!(report.blocks_undone(), 1);

        // The comparison that says where the cost lives: a from-genesis `replay` of
        // the same log. Both re-fold every retained block through `apply_state`, so
        // if the two are the same order of magnitude, the rewind is not paying for
        // anything a restart does not already pay for — and any future work on one
        // is work on the other.
        let started_replay = std::time::Instant::now();
        let replayed = MemNode::replay(&dir, genesis_block(GENESIS_DIFFICULTY, 0)).expect("replay");
        let replay_elapsed = started_replay.elapsed();
        assert_eq!(replayed.commitment_count(), node.commitment_count() + 1);

        println!(
            "REWIND-COST retained_height={height} blocks_undone=1 rewind_us={} \
             replay_us={} leaves={} nullifiers={}",
            elapsed.as_micros(),
            replay_elapsed.as_micros(),
            node.commitment_count(),
            node.nullifier_count()
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
