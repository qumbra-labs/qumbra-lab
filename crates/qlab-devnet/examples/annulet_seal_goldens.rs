//! Print the Annulet seal goldens pinned in `qlab-devnet` (lab #708, a local
//! run named by the stage-0 ruling). One seeded ML-DSA-65 keygen and one
//! signature; no proving; sub-second.
//!
//! ```text
//! cargo run --release -p qlab-devnet --example annulet_seal_goldens
//! ```
//!
//! The last line is the full sealed-header wire unit in hex, for an
//! independent re-hash.

use qlab_devnet::annulet::{AnnuletHeaderFields, HeaderExt, SealedHeader, SequencerKey};
use qlab_devnet::forms::GenesisForm;
use qlab_devnet::hash::keccak256;
use qlab_devnet::header::{AggregateProofSlot, BlockHeader, EpochSupplyAttestation};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    // The fixture of `header::tests::annulet_fixture`, verbatim.
    let h = BlockHeader {
        prev: [0x11; 32],
        height: 0x0000_6655_4433_2211,
        timestamp: 0x8877_6655_4433_2211,
        difficulty: 0,
        nonce: 0,
        tx_body_commitment: [0x22; 32],
        aggregate_proof: AggregateProofSlot,
        epoch_supply_attestation: EpochSupplyAttestation,
        ext: HeaderExt::Annulet(AnnuletHeaderFields {
            l1_anchor_height: 0x0102_0304_0506_0708,
            l1_anchor_root: [0x33; 32],
            registry_root: [0x44; 32],
        }),
    };
    // The fixture genesis's sequencer seed (`AnnuletGenesisFile::fixture`).
    let key = SequencerKey::from_seed([0x5E; 32]);
    let sealed = key.seal(h);
    let wire = sealed.encode();
    let back = SealedHeader::decode(&wire).expect("the wire unit parses");
    assert_eq!(back, sealed, "wire round trip");
    println!("GOLDEN_SEAL_VERIFIES          {}", sealed.verifies_under(&key.verifying_key()));
    println!("GOLDEN_SEAL_VK_DIGEST         {}", hex(&keccak256(key.verifying_key().encode().as_slice())));
    println!("GOLDEN_SEAL_SIG_DIGEST        {}", hex(&keccak256(&sealed.sig[..])));
    println!("GOLDEN_SEAL_WIRE_LEN          {}", wire.len());
    println!("GOLDEN_SEAL_WIRE_DIGEST       {}", hex(&keccak256(&wire)));
    println!("GOLDEN_SEAL_ID                {}", hex(&sealed.id()));
    println!("GOLDEN_SEAL_ID_IS_B1_ID       {}", sealed.id() == h.header_hash_for(GenesisForm::Annulet));
    println!("WIRE_HEX {}", hex(&wire));
}
