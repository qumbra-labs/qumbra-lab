//! M9-N4 integration: the mempool composes with a real [`MemNode`].
//!
//! The load-bearing coherence property: a transaction the mempool ADMITS
//! assembles into a block body the node ACCEPTS. The mempool reads the same
//! consensus state (`is_valid_anchor`, `is_spent`) and enforces the same
//! posted-price fee (`posted_fee`) that `Node::apply_block` → `validate_body`
//! re-checks, so admission and block validity never disagree.

use qlab_devnet::body::{BlockBody, TxEntry, TxPublic};
use qlab_devnet::fees::{posted_fee, ArityBucket};
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_devnet::params_devnet::GENESIS_DIFFICULTY;

use qlab_node::{coinbase, genesis_block, CommitmentStore, MemNode, Mempool, MempoolError, NodeState};
use qlab_note::hash::digest_from_bytes;

/// The miner's payout key for these fixtures (issue #101) — a minting body must
/// name a payee or the node rejects it.
const MINER_RKM: [u64; 4] = [0xC0FFEE, 2, 3, 4];

struct MockVerifier;
impl qlab_devnet::body::TxVerifier for MockVerifier {
    fn verify_tx(&self, entry: &TxEntry) -> bool {
        entry.proof == b"ok"
    }
}

fn tx(anchor: Hash32, nf: u8) -> TxEntry {
    TxEntry::with_placeholder_discovery(b"ok".to_vec(), TxPublic {
        anchor,
        nullifiers: vec![[nf; 32]],
        commitments: vec![[nf.wrapping_add(1); 32]],
        bucket: ArityBucket::TwoByTwo,
        fee: posted_fee(ArityBucket::TwoByTwo),
        })
}

/// A node with genesis finalized (so the genesis empty root is a valid anchor).
fn node_with_finalized_genesis() -> (MemNode, BlockHeader, Hash32) {
    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let g_header = genesis.header();
    let mut node = MemNode::in_memory(genesis);
    node.finalize(g_header.header_hash()).unwrap();
    let g_root = node.commitment_root();
    (node, g_header, g_root)
}

#[test]
fn admitted_txs_assemble_into_a_block_the_node_accepts() {
    let (mut node, g_header, g_root) = node_with_finalized_genesis();
    let mut mp = Mempool::default();

    // Admit two txs against the real node state (anchor = finalized genesis root).
    mp.admit(tx(g_root, 1), &node, &MockVerifier, &qlab_devnet::names::EmptyNameView).expect("admit 1");
    mp.admit(tx(g_root, 2), &node, &MockVerifier, &qlab_devnet::names::EmptyNameView).expect("admit 2");
    assert_eq!(mp.len(), 2);

    // Genesis has no block-weight history ⇒ effective median = the 10 MB floor,
    // so both small txs fit the free zone.
    let m = mp.effective_median(&[]);
    assert_eq!(m, 10_000_000);
    let template = mp.assemble(&node, m, MINER_RKM);

    assert_eq!(template.height, 1);
    assert_eq!(template.txs.len(), 2);
    assert_eq!(template.coinbase_total, coinbase(1));
    assert_eq!(template.total_fees, 2 * posted_fee(ArityBucket::TwoByTwo));
    assert_eq!(template.weight_penalty, 0, "free-zone block pays no penalty");

    // The assembled body is accepted by the node's state transition — proving the
    // mempool's admission checks == the node's block-validity checks.
    let header = BlockHeader::child_of(&g_header, 1, GENESIS_DIFFICULTY, template.body.commitment());
    let hash = node.apply_block(header, template.body.clone(), &MockVerifier).expect("node accepts");
    assert_eq!(node.tip_hash(), hash);
    // Issue #102 changed this count from 3 to 2, and the missing one is the point.
    // Before, a block appended its own coinbase-note leaf immediately (issue #101).
    // Now the leaf is appended 144 blocks later, so a block at height 1 contributes
    // only its transactions' output commitments — block 1 matures nothing, because
    // there is no height −143.
    assert_eq!(
        node.commitment_count(),
        2,
        "both txs' output commitments landed; the coinbase-note leaf is deferred to \
         height 1 + 144 (issue #102)"
    );

    // Reconcile the pool: the mined txs are evicted. Nothing is recorded about the
    // coinbase note — the registry that used to hold it is deleted.
    mp.on_block_connected(&template.body, &node);
    assert!(mp.is_empty(), "mined txs leave the pool");

    // The note exists and its commitment is known, but it is deliberately NOT a tree
    // leaf yet. This is the whole enforcement mechanism in one assertion: no leaf ⇒
    // no membership witness ⇒ no provable spend, with nothing declared and nothing
    // trusted.
    let cb = template.coinbase_note.expect("a minting template mints a note");
    assert!(
        node.commitments().tree().position_of(&digest_from_bytes(&cb)).is_none(),
        "an immature coinbase note must not be in the tree — its absence IS the \
         frozen §2 maturity rule (issue #102)"
    );
    assert_eq!(qlab_node::coinbase_leaf_appears_at(1), 1 + qlab_node::COINBASE_MATURITY_BLOCKS);
}

#[test]
fn mempool_rejects_what_the_node_would_reject_unfinalized_anchor() {
    // Coherence in the negative direction: a not-yet-finalized anchor the node
    // would reject at apply_block is also refused at mempool admission.
    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let node = MemNode::in_memory(genesis); // genesis NOT finalized
    let mut mp = Mempool::default();
    let g_root = node.commitment_root();
    assert!(!node.is_valid_anchor(&g_root));
    assert_eq!(
        mp.admit(tx(g_root, 1), &node, &MockVerifier, &qlab_devnet::names::EmptyNameView),
        Err(MempoolError::AnchorNotValid)
    );
}

#[test]
fn mempool_rejects_a_tx_double_spending_an_already_applied_nullifier() {
    let (mut node, g_header, g_root) = node_with_finalized_genesis();

    // Apply a block spending nullifier [7;32].
    let spent_tx = tx(g_root, 7);
    let body =
        BlockBody { txs: vec![spent_tx], coinbase: coinbase(1), coinbase_rkm: MINER_RKM };
    let header = BlockHeader::child_of(&g_header, 1, GENESIS_DIFFICULTY, body.commitment());
    node.apply_block(header, body, &MockVerifier).unwrap();
    assert!(node.is_spent(&[7; 32]));

    // The mempool now refuses another tx reusing that nullifier.
    let mut mp = Mempool::default();
    // Anchor still valid (genesis root finalized); the double-spend is the reason.
    assert_eq!(
        mp.admit(tx(g_root, 7), &node, &MockVerifier, &qlab_devnet::names::EmptyNameView),
        Err(MempoolError::AlreadySpent { nullifier: [7; 32] })
    );
}
