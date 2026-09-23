//! Print the Annulet header / body goldens pinned in `qlab-devnet` (lab #706,
//! a local run named by the stage-0 ruling). No proving; sub-second.
//!
//! ```text
//! cargo run --release -p qlab-devnet --example annulet_goldens
//! ```

use qlab_devnet::annulet::{body_commitment_annulet, genesis_body_commitment_annulet, AnnuletHeaderFields, HeaderExt};
use qlab_devnet::body::BlockBody;
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
    println!("GOLDEN_ANNULET_HEADER_ID      {}", hex(&h.header_hash_for(GenesisForm::Annulet)));
    println!("GOLDEN_ANNULET_SIGNING_DIGEST {}", hex(&keccak256(&h.annulet_signing_message())));
    println!("GOLDEN_ANNULET_EMPTY_BODY     {}", hex(&body_commitment_annulet(&BlockBody::default())));
    println!("GOLDEN_ANNULET_EMPTY_GENESIS  {}", hex(&genesis_body_commitment_annulet(&[])));
}
