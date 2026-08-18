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
    let a = pow.pow_hash(qlab_devnet::forms::GenesisForm::V4, &header, &[1u8; 32]);
    let b = pow.pow_hash(qlab_devnet::forms::GenesisForm::V4, &header, &[2u8; 32]);
    assert_ne!(a, b, "RandomX output must depend on the key-block seed");
    // …and it is deterministic for a fixed (seed, header).
    assert_eq!(a, pow.pow_hash(qlab_devnet::forms::GenesisForm::V4, &header, &[1u8; 32]));
}

/// 🔒 The **v5 PoW-input vector** (lab #470 stage 1): real RandomX over the
/// pinned 97-byte v5 header preimage under a fixed key. Locks that the engine
/// feeds RandomX exactly the v5 layout — the preimage bytes themselves are
/// golden-locked in `tests/v5_header.rs::golden_v5_preimage_bytes`, and the
/// PoW primitive's bit-identity to rx/0 is re-proven by qlab-pow's official
/// vectors (`randomx.rs`) in every acceptance; this vector is the composition
/// of the two.
#[test]
fn v5_pow_input_vector() {
    use qlab_devnet::forms::GenesisForm;
    use qlab_devnet::header::{AggregateProofSlot, BlockHeader, EpochSupplyAttestation};

    let h = BlockHeader {
        prev: [0x11; 32],
        height: 0x0000_6655_4433_2211,
        timestamp: 0x8877_6655_4433_2211,
        difficulty: 0xAA99_8877_6655_4433,
        nonce: 0xCCBB_AA99_8877_6655,
        tx_body_commitment: [0x22; 32],
        aggregate_proof: AggregateProofSlot,
        epoch_supply_attestation: EpochSupplyAttestation,
    };
    let engine = RandomXPow::new();
    let out = engine.pow_hash(GenesisForm::V5, &h, b"test key 000");
    let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, "fad2770856d515eda2289ce493bbc6cd5c3196506b0b41c929afa34ea86113a5");
    // And it is the RandomX of exactly the v5 preimage bytes, nothing else.
    assert_eq!(
        out,
        qlab_pow::RandomXHasher::new().hash(b"test key 000", &h.preimage_for(GenesisForm::V5)),
        "the engine must feed RandomX the v5 preimage verbatim"
    );
    // The v4 form of the same fields is a different PoW message entirely.
    assert_ne!(out, engine.pow_hash(GenesisForm::V4, &h, b"test key 000"));
}
