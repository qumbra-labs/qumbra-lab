//! Stage-0 owed cross-assert (lab #482 stage 1, first commit).
//!
//! `qlab-stratum::blob` constants were written against the PR #472 ruling
//! while #472 was still in flight. They must equal
//! `qlab_devnet::header`'s v5 constants, and a reconstructed
//! `BlockHeader::preimage_for(V5)` must be byte-identical to the
//! stratum blob helpers' view of the same fields.
//!
//! This test cannot live in `qlab-stratum`: that crate must not depend
//! on `qlab-devnet`. It cannot live in `qlab-devnet`: the consensus
//! crate must not depend on the pool protocol lib. `qumbra-pool` is the
//! first crate that honestly sits on both sides of the seam.
//!
//! Lab #547 adds a second seam of the same shape: the node's
//! `UNCONFIGURED_MINER_RKM` placeholder is a `qlab-p2p` constant that the
//! pool must refuse **by value**, and `qlab-p2p` is a build-time dep this
//! crate does not take. The mirror lives in `payee`; the pin lives here.

use qlab_devnet::forms::GenesisForm;
use qlab_devnet::header::{
    AggregateProofSlot, BlockHeader, EpochSupplyAttestation, HEADER_PREIMAGE_LEN_V5,
    HEADER_VERSION_BYTE_V5,
};
use qlab_stratum::blob::{
    apply_miner_nonce, assemble_nonce, check_v5_blob, extranonce_of, miner_nonce_of,
    set_extranonce, V5_BLOB_LEN, V5_EXTRANONCE_LEN, V5_EXTRANONCE_OFF, V5_HEADER_VERSION,
    V5_MINER_NONCE_LEN, V5_MINER_NONCE_OFF,
};

#[test]
fn blob_constants_equal_devnet_v5_header_constants() {
    assert_eq!(
        V5_BLOB_LEN, HEADER_PREIMAGE_LEN_V5,
        "stratum blob length drifted from header preimage length"
    );
    assert_eq!(
        V5_HEADER_VERSION, HEADER_VERSION_BYTE_V5,
        "stratum version byte drifted from HEADER_VERSION_BYTE_V5"
    );
    // The ruled windows. These numbers are the whole of route A; if they
    // move, stock xmrig stops grinding the nonce.
    assert_eq!(V5_MINER_NONCE_OFF, 39);
    assert_eq!(V5_MINER_NONCE_LEN, 4);
    assert_eq!(V5_EXTRANONCE_OFF, 43);
    assert_eq!(V5_EXTRANONCE_LEN, 4);
    assert_eq!(V5_MINER_NONCE_OFF + V5_MINER_NONCE_LEN, V5_EXTRANONCE_OFF);
    assert_eq!(V5_EXTRANONCE_OFF + V5_EXTRANONCE_LEN, 47);
}

/// Reconstruct the fixture-shaped header the stage-0 blob tests use, and
/// prove `preimage_for(V5)` is the same 97 bytes the stratum helpers
/// read and write.
#[test]
fn preimage_for_v5_is_byte_identical_to_stratum_blob_helpers() {
    let miner = [0xd0, 0x03, 0x00, 0x40];
    let extra = [0x04, 0x03, 0x02, 0x01];
    let nonce = assemble_nonce(&miner, &extra).unwrap();

    let mut prev = [0u8; 32];
    for (i, b) in prev.iter_mut().enumerate() {
        *b = i as u8;
    }
    let header = BlockHeader {
        prev,
        height: 123_456,
        timestamp: 1_785_000_000,
        difficulty: 1024,
        nonce,
        tx_body_commitment: [0xAB; 32],
        aggregate_proof: AggregateProofSlot,
        epoch_supply_attestation: EpochSupplyAttestation,
    };

    let preimage = header.preimage_for(GenesisForm::V5);
    assert_eq!(preimage.len(), HEADER_PREIMAGE_LEN_V5);
    check_v5_blob(&preimage).expect("devnet v5 preimage must pass the stratum blob check");
    assert_eq!(miner_nonce_of(&preimage).unwrap(), miner);
    assert_eq!(extranonce_of(&preimage).unwrap(), extra);
    assert_eq!(
        &preimage[V5_MINER_NONCE_OFF..V5_MINER_NONCE_OFF + 4],
        &miner
    );
    assert_eq!(&preimage[V5_EXTRANONCE_OFF..V5_EXTRANONCE_OFF + 4], &extra);

    // Rebuild from a zero-nonce preimage so we exercise set/apply
    // independently of the header serializer's packing. The helpers
    // must reproduce preimage_for(V5) — that is the partition claim.
    let mut header_zero = header;
    header_zero.nonce = 0;
    let mut blob = header_zero.preimage_for(GenesisForm::V5);
    set_extranonce(&mut blob, &extra).unwrap();
    apply_miner_nonce(&mut blob, &miner).unwrap();
    assert_eq!(blob, preimage, "helpers must reproduce preimage_for(V5)");
}

/// 🔴 Lab #547. `payee::UNCONFIGURED_NODE_RKM` is a mirror, and a mirror
/// that drifts is worse than no mirror at all: the pool would go on
/// refusing a value the node no longer emits while passing the one it
/// does. Three T2 blocks (607, 610, 611) paid this key, and the whole
/// point of naming it is that it is *this* key.
#[test]
fn the_pools_placeholder_mirror_equals_the_nodes_own_constant() {
    assert_eq!(
        qumbra_pool::UNCONFIGURED_NODE_RKM,
        qlab_p2p::adapter::UNCONFIGURED_MINER_RKM,
        "the pool's placeholder mirror drifted from qlab-p2p's constant"
    );
}

/// And the encoding, because the refusal is only useful if it matches what
/// an operator reads off the explorer. Lane-major LE, 64 hex chars — the
/// same encoding `miner_rkm` and `payout_rkm` use in a config file.
#[test]
fn the_nodes_placeholder_is_the_hex_recorded_on_chain() {
    let hex = qumbra_pool::payee::rkm_hex(&qlab_p2p::adapter::UNCONFIGURED_MINER_RKM);
    assert_eq!(hex, "0111011101110111".repeat(4));
}

/// The pool must refuse it, and must refuse it as the placeholder rather
/// than as a generic stranger — the operator fix is on the node, and only
/// the named variant says so.
#[test]
fn the_pool_refuses_the_nodes_placeholder_by_name() {
    let err = qumbra_pool::check_payee(
        qlab_p2p::adapter::UNCONFIGURED_MINER_RKM,
        [9, 0, 0, 0],
        &qumbra_pool::Accounts::default(),
        std::iter::empty(),
    )
    .expect_err("the pool must never accept the node's placeholder");
    assert_eq!(err, qumbra_pool::PayeeRefusal::NodePlaceholder);
    assert_eq!(err.token(), "node-placeholder-coinbase-payee");
}
