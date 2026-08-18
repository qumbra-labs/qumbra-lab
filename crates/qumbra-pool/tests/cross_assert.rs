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
