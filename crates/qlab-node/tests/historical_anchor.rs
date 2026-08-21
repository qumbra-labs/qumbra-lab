//! Lab #402 — the historical finalized-anchor view, at the state-machine seam.
//!
//! A syncing joiner's finality structurally lags its application, so the live
//! anchor gate ([`NodeState::is_valid_anchor`]: anchor height ≤ **this node's**
//! finalized head, within the age window of **this node's** tip) deadlocks it on
//! the first historical block that carries a transaction: it cannot apply the
//! block without the anchor finalized locally, and cannot finalize past it
//! without applying it. Measured live: two independent joiners pinned at
//! stip=4912 while four peers served body 4913 eighty-one times.
//!
//! [`AnchorGate::SettledHistory`] is the resolution: for a block the CALLER has
//! proven to be settled history (the main-chain block at its own height, at or
//! below a quorum-verified finalized checkpoint — the adapter's
//! `block_is_settled_history`), the anchor rule is evaluated as of the block's
//! OWN height. These tests pin, at this seam:
//!
//! 1. the deadlock and its resolution are the same inputs, differing only in
//!    the gate — the mutation lock for the fix;
//! 2. **S1**: a root this node's own replay never computed — forged, or
//!    computed only by a sibling chain — is refused under BOTH gates;
//! 3. **S2**: the age window is measured at the block's own height, exactly
//!    `MAX_ANCHOR_AGE_BLOCKS` wide, and `h < H` strictly;
//! 4. the default entry point (`apply_block`) is the live gate, unchanged.
//!
//! The adapter-level half — that `SettledHistory` is only ever selected under a
//! quorum-verified finalized checkpoint, and that a sibling block at a settled
//! HEIGHT is not settled history — is `qlab-p2p/src/adapter.rs`'s #402 cluster.

use qlab_devnet::body::{BlockBody, BodyError, TxEntry, TxPublic};
use qlab_devnet::fees::{posted_fee, ArityBucket};
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_devnet::params_devnet::{GENESIS_DIFFICULTY, MAX_ANCHOR_AGE_BLOCKS};
use qlab_node::{genesis_block, AnchorGate, MemNode, NodeError, NodeState};

/// Mock verifier — a proof is "valid" iff its bytes are `b"ok"` (mirrors the
/// devnet body-validation tests; the node is prover-free by design).
struct MockVerifier;
impl qlab_devnet::body::TxVerifier for MockVerifier {
    fn verify_tx(&self, entry: &TxEntry) -> bool {
        entry.proof == b"ok"
    }
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

fn one_tx_block(parent: &BlockHeader, tx: TxEntry) -> (BlockHeader, BlockBody) {
    let body = BlockBody::from_single_payee(vec![tx], 0, [0; 4]);
    let header =
        BlockHeader::child_of(parent, parent.height + 1, GENESIS_DIFFICULTY, body.commitment());
    (header, body)
}

fn empty_block(parent: &BlockHeader) -> (BlockHeader, BlockBody) {
    let body = BlockBody::default();
    let header =
        BlockHeader::child_of(parent, parent.height + 1, GENESIS_DIFFICULTY, body.commitment());
    (header, body)
}

/// Genesis + one finalized-anchored tx block: the smallest chain whose NEXT
/// block can carry a spend anchored at an unfinalized-but-real root — the
/// joiner deadlock's exact shape, two blocks tall.
///
/// Returns the node (tip at height 1, finalized head at genesis), block 1's
/// header, and block 1's root `r1`.
fn chain_with_lagging_finality() -> (MemNode, BlockHeader, Hash32) {
    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let g_header = genesis.header();
    let mut node = MemNode::in_memory(genesis);
    // Genesis is finalized (every real chain's state after slot one); block 1's
    // root is NOT — the node's finality lags its application by one block, which
    // is the deadlock's whole premise, at the smallest scale that has it.
    assert!(node.finalize(g_header.header_hash()).unwrap().is_recorded());
    let g_root = node.commitment_root();
    let (h1, b1) = one_tx_block(&g_header, tx(g_root, vec![], vec![[1u8; 32], [2u8; 32]]));
    node.apply_block(h1, b1, &MockVerifier).expect("block 1 applies live");
    let r1 = node.commitment_root();
    (node, h1, r1)
}

/// 🔴 **The #402 deadlock and its resolution are the same inputs — only the gate
/// differs.** The refusal half IS the mutation check the task book asks for:
/// restore the live gate on this block (that is what `apply_block` does) and the
/// application fails with exactly the live error.
#[test]
fn settled_history_applies_where_the_live_gate_deadlocks() {
    let (mut node, h1, r1) = chain_with_lagging_finality();
    let (h2, b2) = one_tx_block(&h1, tx(r1, vec![[9u8; 32]], vec![[3u8; 32]]));

    // The live gate: r1 is a real root of this chain, in window — and refused,
    // because this node's own finalized head is still at genesis. This is the
    // wall two independent joiners hit at stip=4912.
    let err = node.apply_block(h2, b2.clone(), &MockVerifier).unwrap_err();
    assert!(
        matches!(err, NodeError::Body(BodyError::AnchorNotFinal { index: 0 })),
        "live gate refuses: {err:?}"
    );
    assert_eq!(node.tip_height(), 1, "the refused block mutated nothing");

    // The settled-history gate, same block byte for byte: the anchor rule
    // evaluated as of height 2 — r1 is this chain's own root at h=1 < 2, one
    // block old. Applies.
    node.apply_block_gated(h2, b2, &MockVerifier, AnchorGate::SettledHistory)
        .expect("settled history applies past the lagging local finality");
    assert_eq!(node.tip_height(), 2);
    assert!(node.is_spent(&[9u8; 32]), "the spend was folded in");
}

/// **S1: the settled-history gate still refuses every root this node's own
/// replay never computed.** `roots_by_height` is built from the blocks this node
/// folded into its own state and never taken from a peer — so a forged root, and
/// a root computed only by a sibling chain, are refused under `SettledHistory`
/// exactly as they are live. This is the adversarial test the task book's S1
/// names: 'accept a historical anchor' must never mean 'any root old enough'.
#[test]
fn a_root_this_chain_never_computed_is_refused_even_as_settled_history() {
    let (mut node, h1, _r1) = chain_with_lagging_finality();

    // A root that is on NO chain.
    let (h2_forged, b2_forged) = one_tx_block(&h1, tx([0xEE; 32], vec![[9u8; 32]], vec![]));
    let err = node
        .apply_block_gated(h2_forged, b2_forged, &MockVerifier, AnchorGate::SettledHistory)
        .unwrap_err();
    assert!(
        matches!(err, NodeError::Body(BodyError::AnchorNotFinal { index: 0 })),
        "forged root refused: {err:?}"
    );

    // A REAL root — of the wrong chain: a sibling built from the same genesis
    // whose block 1 commits different outputs, so its root at height 1 is a
    // genuine commitment root that this node's replay never produced.
    let sibling_r1 = {
        let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
        let g_header = genesis.header();
        let mut sibling = MemNode::in_memory(genesis);
        assert!(sibling.finalize(g_header.header_hash()).unwrap().is_recorded());
        let g_root = sibling.commitment_root();
        let (sh1, sb1) = one_tx_block(&g_header, tx(g_root, vec![], vec![[7u8; 32], [8u8; 32]]));
        sibling.apply_block(sh1, sb1, &MockVerifier).expect("sibling block 1");
        sibling.commitment_root()
    };
    let (h2_sib, b2_sib) = one_tx_block(&h1, tx(sibling_r1, vec![[9u8; 32]], vec![]));
    let err = node
        .apply_block_gated(h2_sib, b2_sib, &MockVerifier, AnchorGate::SettledHistory)
        .unwrap_err();
    assert!(
        matches!(err, NodeError::Body(BodyError::AnchorNotFinal { index: 0 })),
        "sibling-chain root refused: {err:?}"
    );
    assert_eq!(node.tip_height(), 1, "nothing adversarial was folded in");
}

/// **S2: the age window under `SettledHistory` is `H − h ≤ MAX_ANCHOR_AGE_BLOCKS`,
/// measured at the block's OWN height** — not at this node's tip, which is what
/// the live gate uses. Genesis's root is exactly at the edge: valid as an anchor
/// for the block at height `MAX_ANCHOR_AGE_BLOCKS`, expired one block later —
/// while a younger root at the same heights still passes (the refusal is the
/// age, nothing else).
///
/// Local finality is deliberately left at genesis throughout: the settled gate
/// reads none of it, which is the property that breaks the deadlock.
#[test]
fn the_age_window_is_measured_at_the_blocks_own_height() {
    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let g_header = genesis.header();
    let mut node = MemNode::in_memory(genesis);
    assert!(node.finalize(g_header.header_hash()).unwrap().is_recorded());
    let g_root = node.commitment_root();

    // Block 1 carries commitments so the chain's root moves off g_root — from
    // here on, g_root exists at height 0 and nowhere else, which is what makes
    // the age assertions below about AGE and not about root collisions.
    let (h1, b1) = one_tx_block(&g_header, tx(g_root, vec![], vec![[1u8; 32], [2u8; 32]]));
    node.apply_block(h1, b1, &MockVerifier).expect("block 1");
    let r1 = node.commitment_root();

    // Empty blocks up to height MAX_ANCHOR_AGE_BLOCKS − 1.
    let mut parent = h1;
    while parent.height < MAX_ANCHOR_AGE_BLOCKS - 1 {
        let (h, b) = empty_block(&parent);
        node.apply_block(h, b, &MockVerifier).expect("empty filler block");
        parent = h;
    }

    // H = MAX_ANCHOR_AGE_BLOCKS: H − 0 = 1,152 — the window's last valid block.
    let (h_edge, b_edge) = one_tx_block(&parent, tx(g_root, vec![[0xA1; 32]], vec![]));
    node.apply_block_gated(h_edge, b_edge, &MockVerifier, AnchorGate::SettledHistory)
        .expect("genesis root anchors the block exactly MAX_ANCHOR_AGE_BLOCKS above it");

    // H = MAX_ANCHOR_AGE_BLOCKS + 1: the same anchor is one block too old…
    let (h_past, b_past) = one_tx_block(&h_edge, tx(g_root, vec![[0xA2; 32]], vec![]));
    let err = node
        .apply_block_gated(h_past, b_past, &MockVerifier, AnchorGate::SettledHistory)
        .unwrap_err();
    assert!(
        matches!(err, NodeError::Body(BodyError::AnchorNotFinal { index: 0 })),
        "expired-at-H anchor refused: {err:?}"
    );

    // …and the refusal was the age: the same block anchored one height younger
    // (r1, at h=1) applies.
    let (h_ok, b_ok) = one_tx_block(&h_edge, tx(r1, vec![[0xA3; 32]], vec![]));
    node.apply_block_gated(h_ok, b_ok, &MockVerifier, AnchorGate::SettledHistory)
        .expect("a root inside the window at H applies");
}

/// **The default entry point IS the live gate** — `apply_block` takes no gate
/// and its behaviour is the pre-#402 one, byte for byte: the same block that the
/// settled gate accepts is refused live while finality lags, and applies live
/// once the anchor's height is finalized. Steady state — where H = tip and the
/// finalized head is current — never needs the settled gate, which is S2's
/// live-behaviour-unchanged stamp at this seam (the rest of the lock is every
/// existing anchor test in this crate, all of which run `apply_block` and none
/// of which changed).
#[test]
fn the_default_entry_point_is_the_live_gate_unchanged() {
    let (mut node, h1, r1) = chain_with_lagging_finality();
    let (h2, b2) = one_tx_block(&h1, tx(r1, vec![[9u8; 32]], vec![[3u8; 32]]));

    // Lagging finality: live refusal (as today).
    assert!(node.apply_block(h2, b2.clone(), &MockVerifier).is_err());

    // Finalize block 1 — the live gate's own remedy — and the same block applies
    // through the default entry point, no gate in sight.
    assert!(node.finalize(h1.header_hash()).unwrap().is_recorded());
    node.apply_block(h2, b2, &MockVerifier).expect("live application once finality caught up");
    assert_eq!(node.tip_height(), 2);
}
