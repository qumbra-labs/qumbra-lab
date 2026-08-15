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
    assert!(node.finalize(g_header.header_hash()).unwrap().is_recorded());
    let g_root = node.commitment_root();

    // block1: two output commitments, anchored to the finalized genesis root.
    let (h1, hash1) =
        apply_one_tx_block(&mut node, &g_header, tx(g_root, vec![], vec![[1u8; 32], [2u8; 32]]))
            .unwrap();
    assert_eq!(node.commitment_count(), 2);
    assert!(node.finalize(hash1).unwrap().is_recorded());
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

/// Lab #287: a 0-record resume (fresh datadir / tip-aligned snapshot) must not
/// print a progress line — only the final `RECOVERY … resumed at tip` line.
#[test]
fn zero_record_resume_emits_no_progress_line() {
    let dir = temp_dir("i287-zero");
    let (node, progress) = qlab_node::with_progress_capture(|| {
        MemNode::open(&dir, genesis_block(GENESIS_DIFFICULTY, 0)).unwrap()
    });
    assert!(
        progress.is_empty(),
        "0-record open must not emit RECOVERY replaying lines: {progress:?}"
    );
    assert_eq!(
        node.recovery_report().to_string(),
        "RECOVERY no snapshot, replayed 0 records, resumed at tip 0"
    );

    // Tip-aligned snapshot path: build, snapshot at tip, reopen — still 0 to
    // apply, so still silent on the progress channel.
    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    build_chain(&dir);
    let (reopened, progress) =
        qlab_node::with_progress_capture(|| MemNode::open(&dir, genesis).unwrap());
    assert_eq!(reopened.recovery_report().replayed_records, 0);
    assert!(
        progress.is_empty(),
        "tip-aligned snapshot reopen must not emit progress: {progress:?}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// Lab #287: a multi-record full log replay prints a start line (total derived
/// from the already-loaded log) and a percentage line whose denominator matches
/// the records actually applied.
#[test]
fn multi_record_full_replay_emits_progress_before_resume() {
    let dir = temp_dir("i287-full");
    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    build_chain(&dir);
    // Force the from-genesis path so every log record is applied.
    std::fs::remove_file(dir.join(qlab_node::SNAPSHOT)).unwrap();

    let (reopened, progress) =
        qlab_node::with_progress_capture(|| MemNode::open(&dir, genesis).unwrap());
    let applied = reopened.recovery_report().replayed_records;
    assert!(applied > 0, "build_chain must leave a non-empty log");

    assert!(
        !progress.is_empty(),
        "multi-record replay must emit at least one progress line before resume"
    );
    let start = &progress[0];
    assert_eq!(
        start,
        &format!("RECOVERY replaying {applied} records from genesis"),
        "start line total must equal records actually applied (full path)"
    );
    assert!(
        progress.iter().any(|l| {
            l.starts_with("RECOVERY replaying: ")
                && l.contains(&format!("/{applied} records"))
                && l.ends_with("%)")
        }),
        "expected a percentage line over total={applied}; got {progress:?}"
    );
    // Final resume line still uses the existing Display form (printed by the
    // binary after open returns — here we check the report itself).
    assert!(
        reopened
            .recovery_report()
            .to_string()
            .starts_with("RECOVERY no snapshot, replayed "),
        "final resume report must remain: {}",
        reopened.recovery_report()
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// Lab #287: snapshot-assisted tail replay prints progress over the free
/// pre-count of block records above the snapshot (not a fabricated applied
/// total). The final resume line still reports records that advanced state.
#[test]
fn multi_record_snapshot_tail_emits_progress_before_resume() {
    let dir = temp_dir("i287-tail");
    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let g_header = genesis.header();
    let mut node = MemNode::open(&dir, genesis.clone()).unwrap();

    assert!(node.finalize(g_header.header_hash()).unwrap().is_recorded());
    let mut parent = g_header;
    let mut root = node.commitment_root();
    // Snapshot after a few blocks, then append more so reopen has a real tail.
    for i in 0u8..3 {
        let (h, hash) = apply_one_tx_block(
            &mut node,
            &parent,
            tx(root, vec![], vec![[i + 1; 32], [i + 10; 32]]),
        )
        .unwrap();
        assert!(node.finalize(hash).unwrap().is_recorded());
        root = node.commitment_root();
        parent = h;
    }
    node.save_snapshot().unwrap();
    let snap_height = node.tip_height();
    for i in 0u8..4 {
        let (h, hash) = apply_one_tx_block(
            &mut node,
            &parent,
            tx(root, vec![], vec![[i + 50; 32], [i + 60; 32]]),
        )
        .unwrap();
        assert!(node.finalize(hash).unwrap().is_recorded());
        root = node.commitment_root();
        parent = h;
    }
    let tip = node.tip_height();
    drop(node);

    let (reopened, progress) =
        qlab_node::with_progress_capture(|| MemNode::open(&dir, genesis).unwrap());
    let report = reopened.recovery_report();
    assert_eq!(report.snapshot_height, Some(snap_height));
    assert!(report.replayed_records > 0);
    assert_eq!(report.resumed_tip, tip);

    let tail_blocks = (tip - snap_height) as usize;
    assert!(
        !progress.is_empty(),
        "tail replay must emit progress before the resume report"
    );
    assert_eq!(
        progress[0],
        format!("RECOVERY replaying {tail_blocks} records past snapshot at height {snap_height}"),
        "start total is the free pre-count of block records above the snapshot"
    );
    assert!(
        progress.iter().any(|l| {
            l.starts_with("RECOVERY replaying: ")
                && l.contains(&format!("/{tail_blocks} records"))
                && l.ends_with("%)")
        }),
        "expected percentage over tail_blocks={tail_blocks}; got {progress:?}"
    );
    assert!(
        report
            .to_string()
            .starts_with(&format!("RECOVERY restored snapshot at height {snap_height},")),
        "final resume line unchanged: {report}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_finalization_recorded_after_the_snapshot_still_survives() {
    let dir = temp_dir("post-snapshot-finalize");
    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let g_header = genesis.header();
    let mut node = MemNode::open(&dir, genesis.clone()).unwrap();

    assert!(node.finalize(g_header.header_hash()).unwrap().is_recorded());
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
    assert!(node.finalize(hash1).unwrap().is_recorded());
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
    assert!(node.finalize(g_header.header_hash()).unwrap().is_recorded());
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
    // Issue #225: and it now says SO. This fall-through was silent from #162
    // until #225 — `snapshot_height: None` reads identically to a datadir that
    // never had a snapshot at all, which is the whole detection gap.
    assert!(
        matches!(
            opened.recovery_report().snapshot_rejected,
            Some(qlab_node::SnapshotRejection::TipDisagreement { applied_height: 1, .. })
        ),
        "the reason survives: {:?}",
        opened.recovery_report().snapshot_rejected
    );
    assert!(
        opened.recovery_report().to_string().contains("snapshot DISCARDED"),
        "and it reaches the startup line: {}",
        opened.recovery_report()
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

// ---------------------------------------------------------------------------
// Issue #225 — the graceful stop that minted a datadir refusing to start.
// ---------------------------------------------------------------------------

/// **A snapshot whose log implies a rewind it cannot honour opens by full
/// replay, and reaches the state `replay` reaches** (issue #225).
///
/// Not "does not crash" — the SAME state. That is the only claim worth making,
/// because the fall-through's whole justification is that the from-genesis
/// replay is the correctness anchor.
///
/// **The shape, which the two #162 snapshot tests bracket without covering.**
/// They put the orphan *at* `applied_height` (tip disagreement) and *below* it
/// (a prefix-loop rewind). This is the third position and the only one that
/// reaches the failing line: an orphan strictly **above** `applied_height` while
/// `snap.tip` still agrees.
///
/// ```text
/// apply P (h=1) · apply A2 (h=2) · apply A3 (h=3)
/// rewind to P   · apply B2 (h=2)      <- a SAME-HEIGHT sibling: the tip does not pass A3
/// save_snapshot()                     <- applied_height = 2, tip = B2
/// ```
///
/// The prefix loop's rewind to `P` drops `A2`; the beyond-the-snapshot loop then
/// meets `A3`, whose `prev` is `A2`, and asks to rewind onto a block that is no
/// longer stored. Before this fix that `RewindError::UnknownTarget` was an `Err`
/// out of `Node::open` and the process died on it — 19 times on a rolled T0
/// host, with no startup line at all. A same-height (or lower) reorg is
/// **required**: rewinding to an ancestor and walking straight back up does not
/// reproduce it, because the rewind target itself survives.
#[test]
fn a_snapshot_whose_log_implies_a_rewind_it_cannot_honour_opens_by_full_replay() {
    let dir = temp_dir("i225-orphan-above-snapshot");
    let (mut node, g_header, root) = node_with_finalized_genesis(&dir);

    let (p, p_hash) = apply_marked(&mut node, &g_header, root, 0xC1);
    let (a2, a2_hash) = apply_marked(&mut node, &p, root, 0xA2);
    let (_a3, a3_hash) = apply_marked(&mut node, &a2, root, 0xA3);
    assert_eq!(node.tip_height(), 3, "the node really did reach h=3 on branch A");

    node.rewind_to(p_hash).expect("fork choice moves the applied tip back to P");
    let (_b2, b2_hash) = apply_marked(&mut node, &p, root, 0xB2);
    assert_eq!(node.tip_height(), 2, "and ends on a SAME-HEIGHT sibling, not past A3");

    // The graceful-shutdown flush, which is the only place a snapshot is written
    // in the production path — this is the poison being minted.
    node.save_snapshot().expect("the graceful stop writes the snapshot");
    let live_tip = node.tip_hash();
    let live_root = node.commitment_root();
    let live_cms = node.commitment_count();
    let live_nfs = node.nullifier_count();
    assert_eq!(live_tip, b2_hash);
    drop(node);

    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let opened = MemNode::open(&dir, genesis.clone()).expect("open must NOT refuse (issue #225)");

    // (1) The snapshot was rejected, and the reason names the failure exactly.
    let report = opened.recovery_report().clone();
    assert_eq!(report.snapshot_height, None, "the snapshot was not honoured");
    match report.snapshot_rejected {
        Some(qlab_node::SnapshotRejection::RewindRefused {
            applied_height,
            at_height,
            target,
            error,
            above_snapshot,
        }) => {
            assert_eq!(applied_height, 2, "the snapshot the graceful stop wrote");
            assert_eq!(at_height, 3, "A3 is the record that asked for the rewind");
            assert_eq!(target, a2_hash, "onto A2, which the prefix reconstruction dropped");
            assert_eq!(error, qlab_node::RewindError::UnknownTarget);
            assert!(above_snapshot, "the beyond-the-snapshot loop, not the prefix loop");
        }
        other => panic!("expected a rewind refusal on the snapshot path, got {other:?}"),
    }
    assert!(
        report.to_string().contains("snapshot DISCARDED"),
        "and an operator reading the startup line sees it: {report}"
    );

    // (2) The state, which is the claim that matters: open == replay, not merely
    // "open returned Ok".
    let replayed = MemNode::replay(&dir, genesis).expect("the log was always replayable");
    assert_eq!(opened.tip_hash(), replayed.tip_hash(), "open == replay: tip");
    assert_eq!(opened.tip_height(), replayed.tip_height());
    assert_eq!(opened.commitment_root(), replayed.commitment_root(), "open == replay: tree");
    assert_eq!(opened.commitment_count(), replayed.commitment_count());
    assert_eq!(opened.nullifier_count(), replayed.nullifier_count());
    assert_eq!(opened.finalized_height(), replayed.finalized_height());

    // …and both equal the live node that wrote the log.
    assert_eq!(opened.tip_hash(), live_tip, "and equals the state that was flushed");
    assert_eq!(opened.commitment_root(), live_root);
    assert_eq!(opened.commitment_count(), live_cms);
    assert_eq!(opened.nullifier_count(), live_nfs);
    assert!(opened.is_spent(&[0xB2; 32]), "the winner's spend is applied");
    assert!(!opened.is_spent(&[0xA2; 32]), "the abandoned branch's are not");
    assert!(!opened.is_spent(&[0xA3; 32]));
    assert!(!opened.chain().contains(&a3_hash), "and the orphans are out of the store");
    assert!(!opened.chain().contains(&a2_hash));

    std::fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------------------
// Lab #408 — a rejected snapshot on the finalized main chain degrades to a
// near-tip resume, not a genesis fold; and every rejection is reported.
// ---------------------------------------------------------------------------

/// **Lab #408 item (d): a stale-but-on-finalized-chain snapshot does NOT
/// replay from height 0.** The shape is exactly issue #225's (which stays the
/// negative control just above: with no finalization at or past the
/// snapshot's height, it still asserts the full replay), plus the one fact
/// that changes the answer — the chain the snapshot sits on is finalized past
/// it:
///
/// ```text
/// apply P (h=1) · apply A2 (h=2) · apply A3 (h=3)
/// rewind to P   · apply B2 (h=2)      <- same-height sibling
/// save_snapshot()                     <- applied_height = 2, tip = B2
/// apply B3 (h=3, prev = B2) · finalize B3
/// ```
///
/// The resume still rejects the snapshot (A3 asks the beyond-the-snapshot
/// loop for a rewind onto the dropped A2 — the #225 rejection, unchanged and
/// still reported), but `Finalize(B3)` proves `snap.tip = B2` is the
/// finalized main chain's block at height 2, so the snapshot's state is
/// honoured and only the tail is replayed. `replayed_records` is the
/// no-genesis-fold observable: 2 (B3 + its finalization), not the whole log.
#[test]
fn a_rejected_snapshot_on_the_finalized_main_chain_resumes_near_tip_not_from_genesis() {
    let dir = temp_dir("i408-near-tip-degrade");
    let (mut node, g_header, root) = node_with_finalized_genesis(&dir);

    let (p, p_hash) = apply_marked(&mut node, &g_header, root, 0xC1);
    let (a2, a2_hash) = apply_marked(&mut node, &p, root, 0xA2);
    let (_a3, a3_hash) = apply_marked(&mut node, &a2, root, 0xA3);
    node.rewind_to(p_hash).expect("fork choice moves the applied tip back to P");
    let (b2, _b2_hash) = apply_marked(&mut node, &p, root, 0xB2);
    node.save_snapshot().expect("the graceful stop writes the snapshot");
    let (_b3, b3_hash) = apply_marked(&mut node, &b2, root, 0xB3);
    assert!(node.finalize(b3_hash).unwrap().is_recorded(), "B3 finalizes past the snapshot");
    let live_tip = node.tip_hash();
    let live_root = node.commitment_root();
    drop(node);

    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let opened = MemNode::open(&dir, genesis.clone()).expect("open");
    let report = opened.recovery_report().clone();

    // (1) The rejection is still an event — reported, with the #225 reason.
    match &report.snapshot_rejected {
        Some(qlab_node::SnapshotRejection::RewindRefused {
            applied_height, at_height, target, above_snapshot, ..
        }) => {
            assert_eq!(*applied_height, 2);
            assert_eq!(*at_height, 3, "A3 is still the record that asked for the rewind");
            assert_eq!(*target, a2_hash);
            assert!(above_snapshot);
        }
        other => panic!("the rejection must survive the degrade, got {other:?}"),
    }

    // (2) But the resume was near-tip, not the genesis fold: the snapshot's
    // height was honoured and only the tail was replayed. A full replay of
    // this log is 7 records; the degrade replays 2 (B3 + Finalize(B3)).
    assert_eq!(report.snapshot_height, Some(2), "the rejected snapshot WAS honoured (lab #408)");
    assert_eq!(
        report.replayed_records, 2,
        "only the records past the snapshot were folded — height 0..2 never was"
    );
    assert!(
        report.to_string().contains("near-tip resume from height 2"),
        "and the startup line says which recovery this was: {report}"
    );

    // (3) The state is the claim that matters: open == replay == what was live.
    let replayed = MemNode::replay(&dir, genesis).expect("the log always replays");
    assert_eq!(opened.tip_hash(), replayed.tip_hash(), "open == replay: tip");
    assert_eq!(opened.commitment_root(), replayed.commitment_root(), "open == replay: tree");
    assert_eq!(opened.commitment_count(), replayed.commitment_count());
    assert_eq!(opened.nullifier_count(), replayed.nullifier_count());
    assert_eq!(opened.finalized_height(), replayed.finalized_height());
    assert_eq!(opened.restored_checkpoint(), replayed.restored_checkpoint());
    assert_eq!(opened.tip_hash(), live_tip);
    assert_eq!(opened.commitment_root(), live_root);
    assert!(opened.is_spent(&[0xB2; 32]), "the finalized branch's spends are in");
    assert!(opened.is_spent(&[0xB3; 32]));
    assert!(!opened.is_spent(&[0xA2; 32]), "the abandoned branch's are not");
    assert!(!opened.is_spent(&[0xA3; 32]));
    assert!(!opened.chain().contains(&a3_hash), "the orphans are out of the applied store");
    assert!(!opened.chain().contains(&a2_hash));

    std::fs::remove_dir_all(&dir).ok();
}

/// **The degrade's tail is the real beyond-the-snapshot loop, rewinds
/// included** — fork churn ABOVE the snapshot replays through the same
/// rewind-inference the honoured fast path uses, and lands on replay's state.
///
/// Shape: the near-tip shape above, plus a same-height sibling race past the
/// snapshot (`B3` loses to `B3'`, then `B4` finalizes on the winner). The tail
/// must skip the pre-snapshot orphan (`A3`), apply `B3`, follow the logged
/// rewind back onto `B2`, and re-apply forward — any shortcut that only
/// handles linear tails fails here.
#[test]
fn the_near_tip_degrade_replays_tail_rewinds_like_the_honoured_path() {
    let dir = temp_dir("i408-degrade-tail-rewind");
    let (mut node, g_header, root) = node_with_finalized_genesis(&dir);

    let (p, p_hash) = apply_marked(&mut node, &g_header, root, 0xC1);
    let (a2, _a2_hash) = apply_marked(&mut node, &p, root, 0xA2);
    let (_a3, _a3_hash) = apply_marked(&mut node, &a2, root, 0xA3);
    node.rewind_to(p_hash).expect("fork choice moves back to P");
    let (b2, b2_hash) = apply_marked(&mut node, &p, root, 0xB2);
    node.save_snapshot().expect("snapshot at B2");
    // Churn ABOVE the snapshot: B3 loses a same-height race to B3'.
    let (_b3, _b3_hash) = apply_marked(&mut node, &b2, root, 0xB3);
    node.rewind_to(b2_hash).expect("fork choice moves back to B2");
    let (b3p, _) = apply_marked(&mut node, &b2, root, 0xD3);
    let (_b4, b4_hash) = apply_marked(&mut node, &b3p, root, 0xD4);
    assert!(node.finalize(b4_hash).unwrap().is_recorded(), "B4 finalizes on the winner");
    let live_tip = node.tip_hash();
    let live_root = node.commitment_root();
    drop(node);

    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let opened = MemNode::open(&dir, genesis.clone()).expect("open");
    let report = opened.recovery_report().clone();
    assert_eq!(report.snapshot_height, Some(2), "the degrade still fired");
    assert!(report.snapshot_rejected.is_some());

    let replayed = MemNode::replay(&dir, genesis).expect("replay");
    assert_eq!(opened.tip_hash(), replayed.tip_hash(), "open == replay: tip");
    assert_eq!(opened.commitment_root(), replayed.commitment_root(), "open == replay: tree");
    assert_eq!(opened.nullifier_count(), replayed.nullifier_count());
    assert_eq!(opened.finalized_height(), replayed.finalized_height());
    assert_eq!(opened.tip_hash(), live_tip, "and equals what was live");
    assert_eq!(opened.commitment_root(), live_root);
    assert!(opened.is_spent(&[0xD3; 32]), "the winning sibling's spend is in");
    assert!(!opened.is_spent(&[0xB3; 32]), "the losing sibling's is not");
    assert!(!opened.is_spent(&[0xA3; 32]), "the pre-snapshot orphan's is not");

    std::fs::remove_dir_all(&dir).ok();
}

/// **The degrade demands the finality proof — a rejected snapshot on a LOSING
/// branch keeps the full replay even when finality exists past its height.**
///
/// This is the mutation check for the ancestry walk: finalization at h=2
/// exists (so a gate that only checks "is anything finalized at or past
/// `applied_height`" would wrongly degrade), but the finalized chain's block
/// at the snapshot's height is `w1`, not the snapshot's `l1` — the snapshot's
/// derived state is for a branch finality has excluded, and honouring it
/// would resurrect the losing branch's tree and nullifier set.
#[test]
fn the_near_tip_degrade_refuses_a_snapshot_off_the_finalized_chain() {
    let dir = temp_dir("i408-losing-branch-stays-full-replay");
    let (mut node, g_header, root) = node_with_finalized_genesis(&dir);

    let (_l1, _l1_hash) = apply_marked(&mut node, &g_header, root, 0xB2);
    node.save_snapshot().expect("snapshot on the branch that is about to lose");
    node.rewind_to(g_header.header_hash()).expect("rewind");
    let (w1, _) = apply_marked(&mut node, &g_header, root, 0xA1);
    let (_w2, w2_hash) = apply_marked(&mut node, &w1, root, 0xA2);
    assert!(node.finalize(w2_hash).unwrap().is_recorded(), "the WINNER finalizes past h=1");
    drop(node);

    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let opened = MemNode::open(&dir, genesis.clone()).expect("open");
    assert!(
        matches!(
            opened.recovery_report().snapshot_rejected,
            Some(qlab_node::SnapshotRejection::TipDisagreement { applied_height: 1, .. })
        ),
        "still the #162 rejection: {:?}",
        opened.recovery_report().snapshot_rejected
    );
    assert_eq!(
        opened.recovery_report().snapshot_height,
        None,
        "and still the full replay — the finalized chain's block at h=1 is not the snapshot's tip"
    );
    assert!(!opened.is_spent(&[0xB2; 32]), "the losing branch's spend did not come back");

    let replayed = MemNode::replay(&dir, genesis).expect("replay");
    assert_eq!(opened.tip_hash(), replayed.tip_hash(), "open == replay");
    assert_eq!(opened.commitment_root(), replayed.commitment_root());
    std::fs::remove_dir_all(&dir).ok();
}

/// **Lab #408's load-side halves reach the operator**: an undecodable
/// `snapshot.bin`, a version-mismatched one, and one hanging from a foreign
/// genesis were all silent `Ok(None)` fall-throughs before — indistinguishable
/// from a data dir that never had a snapshot. Each is now a typed, reported
/// rejection, and the recovered state is still exactly the replay's.
#[test]
fn an_unusable_snapshot_file_is_a_reported_rejection_not_a_silent_absence() {
    use qlab_node::{SnapshotLoadReject, SnapshotRejection};

    // A healthy two-block datadir whose snapshot we then sabotage three ways.
    let assert_full_replay_with = |tag: &str, sabotage: &dyn Fn(&PathBuf), check: &dyn Fn(&SnapshotRejection)| {
        let dir = temp_dir(tag);
        let (tip, ..) = build_chain(&dir);
        sabotage(&dir);
        let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
        let opened = MemNode::open(&dir, genesis.clone()).expect("open never refuses over this");
        let report = opened.recovery_report();
        let why = report.snapshot_rejected.as_ref().unwrap_or_else(|| {
            panic!("{tag}: the rejection must be reported, not read as absent")
        });
        check(why);
        assert_eq!(report.snapshot_height, None, "{tag}: no snapshot state was honoured");
        assert!(report.to_string().contains("snapshot DISCARDED"), "{tag}: {report}");
        assert_eq!(opened.tip_hash(), tip, "{tag}: the full replay still lands on the tip");
        assert_eq!(
            opened.tip_hash(),
            MemNode::replay(&dir, genesis).expect("replay").tip_hash(),
            "{tag}: open == replay"
        );
        std::fs::remove_dir_all(&dir).ok();
    };

    assert_full_replay_with(
        "i408-undecodable",
        &|dir| std::fs::write(dir.join(qlab_node::SNAPSHOT), b"not a snapshot").unwrap(),
        &|why| {
            assert!(
                matches!(
                    why,
                    SnapshotRejection::NotLoadable {
                        reject: SnapshotLoadReject::Undecodable { .. }
                    }
                ),
                "got {why:?}"
            );
        },
    );

    assert_full_replay_with(
        "i408-version-mismatch",
        &|dir| {
            let path = dir.join(qlab_node::SNAPSHOT);
            let mut snap: qlab_node::Snapshot =
                bincode::deserialize(&std::fs::read(&path).unwrap()).unwrap();
            snap.format_version = qlab_node::FORMAT_VERSION + 7;
            std::fs::write(&path, bincode::serialize(&snap).unwrap()).unwrap();
        },
        &|why| {
            assert_eq!(
                *why,
                SnapshotRejection::NotLoadable {
                    reject: SnapshotLoadReject::VersionMismatch {
                        found: qlab_node::FORMAT_VERSION + 7
                    }
                }
            );
        },
    );

    assert_full_replay_with(
        "i408-genesis-mismatch",
        &|dir| {
            let path = dir.join(qlab_node::SNAPSHOT);
            let mut snap: qlab_node::Snapshot =
                bincode::deserialize(&std::fs::read(&path).unwrap()).unwrap();
            snap.genesis_block_hash = [0xEE; 32];
            std::fs::write(&path, bincode::serialize(&snap).unwrap()).unwrap();
        },
        &|why| {
            assert!(
                matches!(
                    why,
                    SnapshotRejection::GenesisMismatch { snapshot_genesis, .. }
                        if *snapshot_genesis == [0xEE; 32]
                ),
                "got {why:?}"
            );
        },
    );
}

/// **No stop point on a reorg-churning chain mints a datadir that refuses to
/// start** (issue #225's property, the class rather than the one instance).
///
/// `#225` measured the class on the four real T0 logs by simulating a graceful
/// stop after each of the last 200 block records: **6.0 % of node0's stop points
/// produced a datadir that refuses to open**, 5.0 % / 5.0 % / 3.0 % on the other
/// three, and `falls back to full replay` was **0 out of 800** — the safe
/// fall-through was essentially never reached, because it did not exist for this
/// failure. This is that sweep, in-crate and deterministic.
///
/// **What a stop point is here.** The script is replayed from genesis into a
/// fresh datadir and stopped after step `k`, then `save_snapshot()` — which is
/// byte-for-byte what the production graceful-shutdown flush writes, and the only
/// place a snapshot is written. Then `open` must succeed AND equal `replay`.
///
/// **The script has to contain the shape or the sweep proves nothing**: every
/// fourth step is a depth-2 rewind followed by a same-height sibling, so the log
/// carries a block above the applied tip whose parent lost fork choice. The
/// assertion at the end pins that at least one stop point actually rejected its
/// snapshot — without it, a sweep of 24 honoured fast paths would pass while the
/// bug stood.
#[test]
fn no_graceful_stop_point_mints_a_datadir_that_refuses_to_start() {
    const STEPS: usize = 24;
    let mut rejected = 0usize;
    let mut honoured = 0usize;

    for stop_after in 1..=STEPS {
        let dir = temp_dir(&format!("i225-stop-{stop_after}"));
        let (mut node, g_header, root) = node_with_finalized_genesis(&dir);
        let mut marker: u8 = 0;
        let mut parent = g_header;

        for step in 0..stop_after {
            // Fork-choice churn: the applied tip moves BACK two and rejoins on a
            // sibling, so the log keeps a block above the tip whose parent is on
            // the branch this node abandoned.
            if step % 4 == 3 && node.tip_height() >= 2 {
                let tip = node.chain().block(&node.tip_hash()).expect("tip is stored").clone();
                let mid = node.chain().block(&tip.header.prev).expect("parent is stored").clone();
                let target = mid.header.prev;
                node.rewind_to(target).expect("rewind to depth 2");
                parent = node.chain().block(&node.tip_hash()).expect("new tip").header();
            }
            marker += 1;
            let (h, _) = apply_marked(&mut node, &parent, root, marker);
            parent = h;
        }

        // The graceful stop.
        node.save_snapshot().expect("shutdown flush");
        let live_tip = node.tip_hash();
        let live_root = node.commitment_root();
        drop(node);

        let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
        let opened = match MemNode::open(&dir, genesis.clone()) {
            Ok(n) => n,
            Err(e) => panic!("stop point {stop_after} minted a datadir that refuses to start: {e}"),
        };
        let replayed = MemNode::replay(&dir, genesis).expect("the log always replays");
        assert_eq!(opened.tip_hash(), replayed.tip_hash(), "stop {stop_after}: open == replay tip");
        assert_eq!(
            opened.commitment_root(),
            replayed.commitment_root(),
            "stop {stop_after}: open == replay tree"
        );
        assert_eq!(opened.nullifier_count(), replayed.nullifier_count());
        assert_eq!(opened.tip_hash(), live_tip, "stop {stop_after}: and equals what was flushed");
        assert_eq!(opened.commitment_root(), live_root);

        if opened.recovery_report().snapshot_rejected.is_some() {
            rejected += 1;
        } else {
            honoured += 1;
            assert_eq!(
                opened.recovery_report().snapshot_height,
                Some(opened.tip_height()),
                "stop {stop_after}: an honoured snapshot is the fast path it claims to be"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    // Both halves have to be non-zero or the sweep is not measuring anything:
    // all-honoured would pass with the fix reverted, all-rejected would pass with
    // the snapshot path deleted outright.
    assert!(rejected > 0, "no stop point exercised the fall-through — the sweep proves nothing");
    assert!(honoured > 0, "no stop point took the fast path — the snapshot is not being used");
    println!(
        "I225-STOP-SWEEP steps={STEPS} rejected_snapshot={rejected} honoured_snapshot={honoured} \
         refused_to_start=0"
    );
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

// --- lab #367: the names.bin sidecar ----------------------------------------

/// The registry sidecar rides every snapshot: written by `save_snapshot`,
/// restored by `open`'s snapshot path, and — when it cannot be honoured beside
/// its snapshot — the whole resume falls through to the full replay rather
/// than guessing (the #225 fall-through discipline, applied to the new file).
#[test]
fn the_names_sidecar_rides_the_snapshot_and_a_mismatch_falls_through() {
    let dir = temp_dir("names-sidecar");
    build_chain(&dir);

    // The sidecar exists (save_snapshot wrote it) and the reopened node
    // carries an empty registry — no rider has ever existed on this chain,
    // and absence-of-names is a fact here, not a default.
    assert!(dir.join("names.bin").exists(), "save_snapshot writes the sidecar");
    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    // Every open below runs inside a progress capture (discarded): the capture
    // gate serialises against the #287 progress tests, whose assertions read a
    // GLOBAL line stream that a concurrent replaying open would pollute.
    let (node, _) =
        qlab_node::with_progress_capture(|| MemNode::open(&dir, genesis.clone()).unwrap());
    assert!(node.names().is_empty());
    assert!(
        node.recovery_report().snapshot_rejected.is_none(),
        "a matching sidecar resumes cleanly: {}",
        node.recovery_report()
    );
    drop(node);

    // Corrupt the sidecar: the snapshot resume is REJECTED with the named
    // reason and the node still opens — by full replay, which consults no
    // sidecar and rebuilds the registry from the log.
    std::fs::write(dir.join("names.bin"), b"not a sidecar").unwrap();
    let (node, _) =
        qlab_node::with_progress_capture(|| MemNode::open(&dir, genesis.clone()).unwrap());
    assert!(node.names().is_empty(), "replay rebuilt the (empty) registry from the log");
    match &node.recovery_report().snapshot_rejected {
        Some(qlab_node::SnapshotRejection::NamesSidecarDisagreement { reason }) => {
            assert!(reason.contains("does not decode"), "named reason: {reason}");
        }
        other => panic!("expected the sidecar fall-through, got {other:?}"),
    }
    drop(node);

    // A deleted sidecar beside a live snapshot is the pre-#367 shape: exact
    // empty, clean resume, no rejection.
    std::fs::remove_file(dir.join("names.bin")).unwrap();
    let (node, _) = qlab_node::with_progress_capture(|| MemNode::open(&dir, genesis).unwrap());
    assert!(node.names().is_empty());
    assert!(node.recovery_report().snapshot_rejected.is_none());
}
