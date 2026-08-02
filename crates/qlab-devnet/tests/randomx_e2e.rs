//! End-to-end: a devnet node mining/validating a chain under the **real RandomX**
//! engine, with key-block rotation exercised by a deliberately tiny key epoch.
//!
//! This is the integration seam M9-N3 adds — the pure primitives (`qlab_pow`) are
//! unit-tested in that crate; here we prove they compose through the devnet's
//! mining/validation path: real RandomX hashes key the PoW, the seed rotates on
//! schedule, and a peer re-validates the whole chain.
//!
//! It is heavier than a unit test (each distinct RandomX key builds a ~256 MiB
//! cache), so it keeps the block count small and mines at difficulty 1 (one hash
//! per block) on an on-target cadence.

use qlab_devnet::header::Hash32;
use qlab_devnet::node::{Node, SimConfig};
use qlab_devnet::pow::{PowEngine, RandomXPow};
use qlab_devnet::validation::pow_seed;
use qlab_pow::keyblock::KeyBlockSchedule;

/// A config with a tiny RandomX key epoch (epoch 2, lag 1) so the key rotates a
/// couple of times within a short chain; difficulty 1 ⇒ one hash per block.
fn rx_cfg() -> SimConfig {
    SimConfig {
        block_time_secs: 10,
        genesis_difficulty: 1,
        mine_nonce_budget: 1_000,
        key_epoch_blocks: 2,
        key_epoch_lag: 1,
        ..SimConfig::default()
    }
}

#[test]
fn randomx_node_mines_validates_and_rotates_the_key() {
    let mut node = Node::new(RandomXPow::new(), rx_cfg());

    // Mine a short chain; every block must be self-valid (mine_on self-checks
    // via validate_header under the resolved RandomX seed).
    const N: u64 = 6;
    for h in 1..=N {
        node.mine_next([h as u8; 32]).expect("RandomX mine+validate");
        assert_eq!(node.tip_height(), h);
    }

    // The whole chain re-validates on a fresh peer with the same rules — proves
    // cross-node agreement on real RandomX PoW + the seed schedule + LWMA difficulty.
    let mut peer = Node::new(RandomXPow::new(), rx_cfg());
    for hash in node.chain().main_chain().into_iter().skip(1) {
        let header = *node.chain().header(&hash).unwrap();
        peer.submit(header).expect("peer accepts real-RandomX block");
    }
    assert_eq!(peer.tip_hash(), node.tip_hash());
    assert_eq!(peer.tip_height(), N);
}

#[test]
fn randomx_key_block_seed_actually_rotates() {
    let schedule = KeyBlockSchedule::new(2, 1); // matches rx_cfg()
    let mut node = Node::new(RandomXPow::new(), rx_cfg());
    for h in 1..=6u64 {
        node.mine_next([h as u8; 32]).unwrap();
    }
    let chain = node.chain();
    let genesis: Hash32 = chain.genesis_block_hash();
    let tip = chain.tip_hash();

    // Early block (height 1) is bootstrap-keyed from genesis.
    let warmup_seed = pow_seed(chain, &genesis, 1, schedule).unwrap();
    assert_eq!(warmup_seed, genesis.to_vec(), "warmup key is the genesis hash");

    // A block extending the tip (height 7) is past epoch+lag ⇒ non-genesis key.
    let late_seed = pow_seed(chain, &tip, chain.tip_height() + 1, schedule).unwrap();
    assert_ne!(late_seed, genesis.to_vec(), "the RandomX key must have rotated");
}

#[test]
fn randomx_hash_depends_on_the_key_block_seed() {
    // The engine must actually consume the seed as the RandomX key: the same
    // header hashes differently under two different key-block seeds. (This is what
    // makes key rotation a real consensus event, not a no-op.)
    let pow = RandomXPow::new();
    let header = qlab_devnet::header::BlockHeader::genesis(1_000, 0);
    let a = pow.pow_hash(&header, &[1u8; 32]);
    let b = pow.pow_hash(&header, &[2u8; 32]);
    assert_ne!(a, b, "RandomX output must depend on the key-block seed");
    // …and it is deterministic for a fixed (seed, header).
    assert_eq!(a, pow.pow_hash(&header, &[1u8; 32]));
}
