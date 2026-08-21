//! Issue #102 acceptance: the **coinbase-leaf append schedule** and its replay.
//!
//! Option (b) enforces the frozen §2 maturity delay structurally — a block appends
//! the coinbase leaf minted 144 blocks earlier, so until a coinbase matures no anchor
//! contains its leaf and an immature spend has no witness against one. That
//! moves a rule out of `Mempool::admit` and into the state transition, which buys
//! real enforcement and takes on a real risk: **the tree now depends on a block other
//! than the one being applied.**
//!
//! This file is about that risk. `Node::apply_state` is the single funnel every state
//! mutation passes through, fresh and replayed alike (issue #77), and the whole
//! `open == replay` guarantee rests on it being a pure function of the block. It is
//! no longer *only* the block — so the question is whether every path that rebuilds
//! state can still resolve "which leaf is owed here", and one of those paths
//! deliberately does not run `apply_state` at all:
//!
//! ```text
//! Node::open:  blocks ≤ snapshot.applied_height → put_block ONLY (apply_state skipped)
//!              blocks >  snapshot.applied_height → apply_state
//! Node::replay: every block → apply_state
//! ```
//!
//! A pending-leaf map filled by `apply_state` would therefore be missing every leaf
//! owed *across* the snapshot boundary, and `open` would build a different tree than
//! `replay` — a node forking from itself, silently, with no error anywhere. So the
//! owed leaf is re-derived from the chain store (which both paths populate for every
//! block) and nothing is persisted; `Snapshot`'s format is unchanged.
//!
//! [`the_snapshot_boundary_does_not_lose_owed_leaves`] is the test that would fail if
//! that reasoning were wrong, and it is the reason the mechanism is a derivation
//! rather than a queue.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use qlab_devnet::body::{BlockBody, TxEntry, TxVerifier};
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_devnet::params_devnet::GENESIS_DIFFICULTY;
use qlab_node::{
    coinbase, coinbase_leaf_appears_at, coinbase_note_leaf, genesis_block, CommitmentStore, MemNode,
    NodeState, COINBASE_MATURITY_BLOCKS,
};
use qlab_note::hash::digest_from_bytes;

/// Blocks in these fixtures carry no transactions, so no proof is ever verified.
struct NoTxVerifier;
impl TxVerifier for NoTxVerifier {
    fn verify_tx(&self, _: &TxEntry) -> bool {
        unreachable!("fixtures carry no transactions")
    }
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    p.push(format!("qlab-node-i102-{tag}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// The number of leaves the tree holds at the end of `height`, when every block from
/// 1 upward mints exactly one coinbase note and carries no transactions: one leaf per
/// *matured* block, i.e. the chain minus one maturity delay. Genesis mints nothing,
/// and neither does any height below the delay.
fn expected_leaves(height: u64) -> u64 {
    height.saturating_sub(COINBASE_MATURITY_BLOCKS)
}

/// Mine one empty block paying `rkm` on top of `tip`, apply it through the real state
/// transition, and finalize it. Returns the new header.
fn mine_one(node: &mut MemNode, tip: &BlockHeader, rkm: [u64; 4]) -> BlockHeader {
    let height = tip.height + 1;
    let body = BlockBody::from_single_payee(Vec::new(), coinbase(height), rkm);
    let header = BlockHeader::child_of(tip, height * 75, GENESIS_DIFFICULTY, body.commitment());
    let hash = node.apply_block(header, body, &NoTxVerifier).expect("block applies");
    node.finalize(hash).expect("finalize");
    header
}

/// Every prefix root of two trees, compared. Stronger than comparing the final root:
/// it pins the whole leaf sequence *and* every per-height anchor derived from it, so a
/// tree that ends up right by inserting two leaves in the wrong order still fails.
fn assert_identical_trees(a: &MemNode, b: &MemNode, what: &str) {
    assert_eq!(a.commitment_count(), b.commitment_count(), "{what}: leaf count");
    for k in 0..=a.commitment_count() {
        assert_eq!(
            a.commitments().tree().root_at(k),
            b.commitments().tree().root_at(k),
            "{what}: root over the first {k} leaves"
        );
    }
    assert_eq!(a.tip_hash(), b.tip_hash(), "{what}: tip");
    assert_eq!(a.finalized_height(), b.finalized_height(), "{what}: finalized height");
}

// ---------------------------------------------------------------------------
// The schedule itself
// ---------------------------------------------------------------------------

/// A coinbase leaf lands at exactly `minted + 144`, and the first 144 blocks of a
/// chain contribute no leaves at all.
#[test]
fn a_coinbase_leaf_lands_exactly_one_maturity_delay_later() {
    let rkm = [0xC0FFEEu64, 1, 2, 3];
    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let mut node = MemNode::in_memory(genesis.clone());
    let mut tip = genesis.header();

    // The note minted by block 1, computed the way the schedule computes it.
    let body1 = BlockBody::from_single_payee(Vec::new(), coinbase(1), rkm);
    let cm1 = digest_from_bytes(&coinbase_note_leaf(1, &body1).expect("a minting block"));

    for _ in 0..COINBASE_MATURITY_BLOCKS {
        tip = mine_one(&mut node, &tip, rkm);
    }
    // 144 blocks mined, every one of them minting — and the tree is empty. Block 144
    // matures height 0, which is genesis, which mints nothing.
    assert_eq!(tip.height, COINBASE_MATURITY_BLOCKS);
    assert_eq!(node.commitment_count(), 0, "no leaf may land before the delay elapses");
    assert!(node.commitments().tree().position_of(&cm1).is_none());

    // Block 145 matures block 1.
    tip = mine_one(&mut node, &tip, rkm);
    assert_eq!(tip.height, coinbase_leaf_appears_at(1));
    assert_eq!(node.commitment_count(), 1);
    assert_eq!(
        node.commitments().tree().position_of(&cm1),
        Some(0),
        "block 1's coinbase is the tree's first leaf, and it arrives at height 145"
    );

    // From here the tree tracks the chain exactly one delay behind.
    for _ in 0..10 {
        tip = mine_one(&mut node, &tip, rkm);
    }
    assert_eq!(node.commitment_count(), expected_leaves(tip.height));
}

/// The owed leaf is resolved through the applied block's **own ancestry**, not by
/// height — which is what makes the schedule survive a chain changing its mind.
///
/// This is position 4 of the task book. A leaf promised 144 blocks in advance is a
/// promise made by a *chain*, and the chain is allowed to reorganise underneath it. A
/// queue keyed on height would insert whatever was recorded when the promise was
/// made; a derivation from ancestry inserts whatever the surviving chain actually
/// minted. The two differ exactly when it matters.
///
/// Driven as two chains that agree everywhere except who was paid at height 1, which
/// is the observable consequence: had the leaf been height-keyed rather than
/// ancestry-derived, both would append the same leaf and these roots would collide.
///
/// Honest scope: `apply_block` refuses a block that does not extend the tip, so this
/// node's state machine cannot itself be walked backwards through a reorg — that is a
/// pre-existing tip-only limitation (issue #130), not something (b) introduces. What
/// is asserted here is the property that makes a reorg *safe when the state machine
/// gains one*: no leaf is owed by anything except an ancestor of the block appending
/// it, so there is no stale promise to replay.
#[test]
fn the_owed_leaf_follows_the_blocks_own_ancestry() {
    let alice = [0xA11CEu64, 0, 0, 1];
    let bob = [0xB0Bu64, 0, 0, 2];
    let common = [0xEEu64, 0, 0, 3];

    let build = |first: [u64; 4]| {
        let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
        let mut node = MemNode::in_memory(genesis.clone());
        let mut tip = genesis.header();
        // Height 1 pays whoever `first` names; every later height is identical.
        tip = mine_one(&mut node, &tip, first);
        while tip.height < coinbase_leaf_appears_at(1) {
            tip = mine_one(&mut node, &tip, common);
        }
        node
    };

    let a = build(alice);
    let b = build(bob);

    // Both chains are 145 blocks long and appended exactly one leaf — block 1's.
    assert_eq!(a.commitment_count(), 1);
    assert_eq!(b.commitment_count(), 1);

    // And it is a *different* leaf, because a different miner was paid at height 1.
    // The leaf followed the block, not the height.
    assert_ne!(
        a.commitment_root(),
        b.commitment_root(),
        "the leaf appended at 145 must be the one this chain's height 1 minted"
    );
    let body_alice = BlockBody::from_single_payee(Vec::new(), coinbase(1), alice);
    let body_bob = BlockBody::from_single_payee(Vec::new(), coinbase(1), bob);
    let cm_alice = digest_from_bytes(&coinbase_note_leaf(1, &body_alice).unwrap());
    let cm_bob = digest_from_bytes(&coinbase_note_leaf(1, &body_bob).unwrap());
    assert!(a.commitments().tree().position_of(&cm_alice).is_some());
    assert!(a.commitments().tree().position_of(&cm_bob).is_none(), "not the other chain's leaf");
    assert!(b.commitments().tree().position_of(&cm_bob).is_some());
    assert!(b.commitments().tree().position_of(&cm_alice).is_none());
}

// ---------------------------------------------------------------------------
// Replay — the non-negotiable acceptance item
// ---------------------------------------------------------------------------

/// 🔴 **A chain built across more than one maturity delay, restarted from disk,
/// rebuilds a byte-identical tree and identical per-height roots.**
///
/// `open` (snapshot fast path + log tail) and `replay` (full, from genesis) are
/// compared against the state that was built live, over *every* prefix root — so a
/// disagreement about a single leaf's position fails, not just a disagreement about
/// the final root. A node that replays to a different tree than it built is a
/// consensus split with itself, and it would show up as unbuildable witnesses rather
/// than as an error.
#[test]
fn a_chain_across_the_maturity_delay_replays_identically() {
    let rkm = [0xD00Du64, 4, 5, 6];
    let dir = temp_dir("replay");
    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);

    // Build ~2.2 maturity delays live, on disk.
    let height = COINBASE_MATURITY_BLOCKS * 2 + 32;
    let live = {
        let mut node = MemNode::open(&dir, genesis.clone()).unwrap();
        let mut tip = genesis.header();
        for _ in 0..height {
            tip = mine_one(&mut node, &tip, rkm);
        }
        assert_eq!(tip.height, height);
        assert_eq!(node.commitment_count(), expected_leaves(height));
        node.save_snapshot().unwrap();
        node
    };

    let opened = MemNode::open(&dir, genesis.clone()).unwrap();
    let replayed = MemNode::replay(&dir, genesis).unwrap();

    assert_identical_trees(&live, &opened, "live vs open");
    assert_identical_trees(&live, &replayed, "live vs replay");
    assert_eq!(opened.commitment_count(), expected_leaves(height));
}

/// 🔴 **The case that decides the mechanism: leaves owed across the snapshot
/// boundary.**
///
/// The snapshot is taken mid-chain and the chain then grows by more than a maturity
/// delay. Every leaf appended after the snapshot was minted by a block *at or below*
/// `applied_height` — precisely the blocks whose `apply_state` the `open` fast path
/// skips. If the schedule kept its owed leaves in memory, filled by `apply_state`,
/// they would be gone, and `open` would silently build a shorter tree than `replay`.
///
/// It cannot, because the leaf is re-derived from the chain store, and `open` calls
/// `put_block` for the snapshot-covered blocks even while skipping their state
/// transition. That is the entire reason the mechanism is a derivation.
#[test]
fn the_snapshot_boundary_does_not_lose_owed_leaves() {
    let rkm = [0x5EEDu64, 7, 8, 9];
    let dir = temp_dir("snapboundary");
    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);

    let snapshot_at = COINBASE_MATURITY_BLOCKS + 20; // 164
    let final_height = snapshot_at + COINBASE_MATURITY_BLOCKS + 15; // 323

    let live = {
        let mut node = MemNode::open(&dir, genesis.clone()).unwrap();
        let mut tip = genesis.header();
        for _ in 0..snapshot_at {
            tip = mine_one(&mut node, &tip, rkm);
        }
        // Snapshot here. At this point heights 21..=164 have minted notes whose leaves
        // are still owed, and every one of those leaves is due *after* the snapshot.
        node.save_snapshot().unwrap();
        assert_eq!(node.commitment_count(), expected_leaves(snapshot_at));
        while tip.height < final_height {
            tip = mine_one(&mut node, &tip, rkm);
        }
        node
    };
    assert_eq!(live.commitment_count(), expected_leaves(final_height));

    let opened = MemNode::open(&dir, genesis.clone()).unwrap();
    let replayed = MemNode::replay(&dir, genesis).unwrap();

    // The leaves appended after the snapshot were minted by blocks the fast path did
    // not run `apply_state` for. There are many of them, so this is not a boundary
    // case that could pass by accident.
    let across = expected_leaves(final_height) - expected_leaves(snapshot_at);
    assert_eq!(across, COINBASE_MATURITY_BLOCKS + 15, "the case is genuinely exercised");

    assert_identical_trees(&live, &opened, "snapshot boundary: live vs open");
    assert_identical_trees(&live, &replayed, "snapshot boundary: live vs replay");
}

/// The per-height anchor set survives the round trip too, not just the tree. A root
/// that a live node accepted as an anchor must still be accepted after a restart, or
/// wallets holding witnesses against it are stranded.
#[test]
fn per_height_anchors_survive_the_restart() {
    let rkm = [0xA9C1u64, 1, 1, 1];
    let dir = temp_dir("anchors");
    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let height = COINBASE_MATURITY_BLOCKS + 40;

    let mut roots_live: Vec<Hash32> = Vec::new();
    {
        let mut node = MemNode::open(&dir, genesis.clone()).unwrap();
        let mut tip = genesis.header();
        for _ in 0..height {
            tip = mine_one(&mut node, &tip, rkm);
            roots_live.push(node.commitment_root());
        }
        node.save_snapshot().unwrap();
    }

    let opened = MemNode::open(&dir, genesis.clone()).unwrap();
    let replayed = MemNode::replay(&dir, genesis).unwrap();
    for (i, root) in roots_live.iter().enumerate() {
        assert!(opened.is_valid_anchor(root), "root after height {} lost on open", i + 1);
        assert!(replayed.is_valid_anchor(root), "root after height {} lost on replay", i + 1);
    }
}
