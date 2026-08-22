//! **The `SupplyLedger` reorg gap, against a real store** (lab #299 §4).
//!
//! `supply.rs`'s unit tests prove the ledger's own behaviour with synthetic
//! identities. This one drives the defect through the machinery that actually
//! produces it: a `MemNode`, a real `rewind_to`, and a competing branch whose
//! coinbase differs — because the gap was never in the arithmetic, it was in the
//! assumption that "the next height" and "the next block" are the same thing.
//!
//! Before the fix, the stale ledger absorbed the reorged chain's next block (the
//! heights *were* contiguous) and the orphan's coinbase stayed in
//! `measured_coinbase` forever. With the #299 validity rule active, that row reads
//! DIVERGENT — an alarm manufactured by a reorg, on the one surface that must never
//! cry wolf.

use qlab_devnet::body::{BlockBody, TxEntry};
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_devnet::params_devnet::GENESIS_DIFFICULTY;

use qlab_node::{genesis_block, ChainStore as _, MemNode, SupplyBlock, SupplyError, SupplyLedger};

const EPOCH: u64 = 8;
const MINER_RKM: [u64; 4] = [7, 8, 9, 10];

struct MockVerifier;
impl qlab_devnet::body::TxVerifier for MockVerifier {
    fn verify_tx(&self, entry: &TxEntry) -> bool {
        entry.proof == b"ok"
    }
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("qlab-node-supply-reorg-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// An empty block paying `coinbase`, extending `parent`. The coinbase value is what
/// distinguishes the two branches, and it is also what changes the body commitment,
/// so the two blocks at the same height are genuinely different blocks.
fn apply_empty_block(
    node: &mut MemNode,
    parent: &BlockHeader,
    coinbase: u64,
) -> (BlockHeader, Hash32) {
    let body = BlockBody::from_single_payee(Vec::new(), coinbase, MINER_RKM);
    let header =
        BlockHeader::child_of(parent, parent.height + 1, GENESIS_DIFFICULTY, body.commitment());
    let hash = node.apply_block(header, body, &MockVerifier).expect("empty block applies");
    (header, hash)
}

/// The applied main chain as the supply ledger consumes it.
fn ledger_over(node: &MemNode) -> (Vec<Hash32>, SupplyLedger) {
    let main_chain = node.chain().chain().main_chain();
    let blocks: Vec<SupplyBlock> = main_chain
        .iter()
        .map(|hash| {
            let block = node.chain().block(hash).expect("canonical hash has its body");
            SupplyBlock {
                height: block.header.height,
                hash: *hash,
                prev: block.header.prev,
                coinbase: block.coinbase,
                fees: block.txs.iter().map(|tx| tx.fee).sum(),
                name_burn: 0,
            }
        })
        .collect();
    let ledger = SupplyLedger::from_blocks(blocks, EPOCH).expect("contiguous from genesis");
    (main_chain, ledger)
}

/// **The acceptance test of #299 §4**, in one pass: build, reorg, refuse, rebuild.
#[test]
fn a_reorg_re_derives_the_supply_row_and_cannot_manufacture_a_divergent() {
    let dir = temp_dir("main");
    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let g_header = genesis.header();
    let mut node = MemNode::open(&dir, genesis).unwrap();
    // Genesis is finalized, and `rewind_to(genesis)` is therefore "rewind to
    // finality", which the store permits — rewinding *past* it is what it refuses.
    assert!(node.finalize(g_header.header_hash()).unwrap().is_recorded());

    // Branch A: one block paying 5,000 bessel.
    let (a1_header, a1_hash) = apply_empty_block(&mut node, &g_header, 5_000);
    let (chain_a, ledger_a) = ledger_over(&node);
    assert_eq!(chain_a, vec![g_header.header_hash(), a1_hash]);
    assert_eq!(ledger_a.rows()[0].measured_coinbase, 5_000);
    assert_eq!(ledger_a.head_hash(), Some(a1_hash));
    assert!(ledger_a.is_in_sync_with(&chain_a));

    // Fork choice moves off branch A: rewind and apply a *different* height-1 block.
    node.rewind_to(g_header.header_hash()).expect("rewind to the finalized genesis");
    let (b1_header, b1_hash) = apply_empty_block(&mut node, &g_header, 9_000);
    assert_ne!(b1_hash, a1_hash, "the two branches' height-1 blocks differ");
    let chain_b = node.chain().chain().main_chain();
    assert_eq!(chain_b, vec![g_header.header_hash(), b1_hash]);

    // (1) The stale ledger KNOWS it is stale. This is the check the consumer owes,
    //     and it is the half a push-time guard alone cannot cover: here the reorg is
    //     entirely below `next_height`, so there is nothing to append and the stale
    //     sums would simply persist.
    let mut stale = ledger_a.clone();
    assert_eq!(stale.next_height(), 2);
    assert!(
        !stale.is_in_sync_with(&chain_b),
        "the ledger's head is no longer the canonical block at its own height"
    );

    // (2) And if the chain then extends, the stale ledger REFUSES the new block by
    //     name instead of absorbing it into a row that would read DIVERGENT.
    let (_b2_header, b2_hash) = apply_empty_block(&mut node, &b1_header, 4_000);
    let b2 = node.chain().block(&b2_hash).unwrap();
    assert_eq!(
        stale.push(SupplyBlock {
            height: 2,
            hash: b2_hash,
            prev: b2.header.prev,
            coinbase: b2.coinbase,
            fees: 0,
            name_burn: 0,
        }),
        Err(SupplyError::ForkedFromLedgerHead {
            height: 2,
            expected_prev: a1_hash,
            got_prev: b1_hash,
        }),
        "the right height is not the right block"
    );

    // (3) The rebuild re-derives the row to the canonical chain: branch A's 5,000 is
    //     gone, branch B's 9,000 + 4,000 is what the row measures.
    let (chain_b2, rebuilt) = ledger_over(&node);
    assert_eq!(chain_b2.len(), 3);
    assert!(rebuilt.is_in_sync_with(&chain_b2));
    assert_eq!(rebuilt.next_height(), 3);
    assert_eq!(rebuilt.rows().len(), 1, "heights 0..=2 are all epoch 0");
    assert_eq!(rebuilt.rows()[0].measured_coinbase, 13_000);
    assert_eq!(rebuilt.head_hash(), Some(b2_hash));

    // (4) The orphan is not merely renamed: the stale and rebuilt measurements differ
    //     by exactly the orphaned block's coinbase minus its replacement's, which is
    //     the false divergence this closes.
    assert_eq!(
        rebuilt.rows()[0].measured_coinbase as i128
            - (stale.rows()[0].measured_coinbase as i128 + 4_000),
        4_000,
        "9,000 replaced 5,000; a stale ledger would have carried the 5,000 forever"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
