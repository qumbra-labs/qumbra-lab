//! Stage-1 battery for the **v5 header form** (lab #470, pool-t1-brief §3 C2):
//! the goldens, the mine→validate e2e under v5, the cross-form structural
//! refusals, and the LWMA layout-agnosticism demonstration.
//!
//! The v4 goldens live where they always did (`header.rs`, `codec.rs`,
//! `genesis.rs`) and are untouched — their staying green IS the compat lock.

use qlab_devnet::chain::ChainState;
use qlab_devnet::forms::{ChainRules, GenesisForm};
use qlab_devnet::header::{
    AggregateProofSlot, BlockHeader, EpochSupplyAttestation, HEADER_PREIMAGE_LEN_V5,
};
use qlab_devnet::mining::mine_under;
use qlab_devnet::pow::KeccakPow;
use qlab_devnet::validation::{
    expected_difficulty, pow_seed, validate_header_under, ValidationError,
};
use qlab_pow::keyblock::KeyBlockSchedule;

/// The stage-1 golden fixture: every field byte-distinguishable.
fn golden_header() -> BlockHeader {
    BlockHeader {
        prev: [0x11; 32],
        height: 0x0000_6655_4433_2211,
        timestamp: 0x8877_6655_4433_2211,
        difficulty: 0xAA99_8877_6655_4433,
        nonce: 0xCCBB_AA99_8877_6655,
        tx_body_commitment: [0x22; 32],
        aggregate_proof: AggregateProofSlot,
        epoch_supply_attestation: EpochSupplyAttestation,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 🔒 The v5 header preimage golden — the 97 bytes RandomX is handed, spelled
/// out in full so the layout is checkable by eye against the §3 ruling:
/// prev ×32 ‖ 0x05 ‖ height u48 LE ‖ nonce u64 LE ‖ timestamp ‖ difficulty ‖
/// commitment ×32 ‖ 0xA6 ‖ 0x59.
#[test]
fn golden_v5_preimage_bytes() {
    let p = golden_header().preimage_for(GenesisForm::V5);
    assert_eq!(p.len(), HEADER_PREIMAGE_LEN_V5);
    assert_eq!(
        hex(&p),
        "1111111111111111111111111111111111111111111111111111111111111111\
         05\
         112233445566\
         5566778899aabbcc\
         1122334455667788\
         33445566778899aa\
         2222222222222222222222222222222222222222222222222222222222222222\
         a659"
    );
}

/// 🔒 The v5 header-hash golden (keccak256 of the preimage above), plus the
/// v4 hash of the same fields — pinned so the two identities can never be
/// silently conflated.
#[test]
fn golden_v5_and_v4_header_hashes() {
    let h = golden_header();
    assert_eq!(
        hex(&h.header_hash_for(GenesisForm::V5)),
        "a3801822a8867b4665780e5ae469cdb6b2ec3d388f83a117b99ececf9d86afd9"
    );
    assert_eq!(
        hex(&h.header_hash_for(GenesisForm::V4)),
        "fc5c60a3df8863efaa1f7c482c08365183dd4f1d846439d4b969f01b00d242a9"
    );
    assert_eq!(h.header_hash(), h.header_hash_for(GenesisForm::V4));
}

/// A chain mines and validates end-to-end under the v5 form: v5 identities
/// (`ChainState::new_for`), v5 links (`child_of_for`), v5 PoW messages
/// (`mine_under` / `validate_header_under` with a V5 [`ChainRules`]) — and the
/// LWMA-mandated difficulty is honoured at every height, because
/// [`expected_difficulty`] reads header *fields* and never header *bytes*.
#[test]
fn v5_chain_mines_and_validates_end_to_end() {
    let pow = KeccakPow;
    let rules = ChainRules { form: GenesisForm::V5, halt: Default::default() };
    let sched = KeyBlockSchedule::default();
    let genesis = BlockHeader::genesis(8, 0);
    let mut chain = ChainState::new_for(GenesisForm::V5, genesis);
    assert_eq!(chain.form(), GenesisForm::V5);

    for i in 0..6u64 {
        let parent_hash = chain.tip_hash();
        let parent = *chain.header(&parent_hash).unwrap();
        let difficulty = expected_difficulty(&chain, &parent_hash, 75).unwrap();
        let candidate = BlockHeader::child_of_for(
            GenesisForm::V5,
            &parent,
            parent.timestamp + 70 + (i % 3) * 5, // jittered solvetimes
            difficulty,
            [0u8; 32],
        );
        let seed = pow_seed(&chain, &parent_hash, candidate.height, sched).unwrap();
        let mined = mine_under(&pow, candidate, 1_000_000, &seed, &rules).expect("mine v5");
        validate_header_under(&chain, &pow, &mined, 75, sched, &rules)
            .expect("a v5-mined header validates under the v5 rules");
        chain.insert_header(mined).expect("insert");
    }
    assert_eq!(chain.tip_height(), 6);
}

/// Cross-form structural refusal at the chain layer: a v5-linked header can
/// never resolve its parent in a v4-keyed chain (and vice versa) — the two
/// identity spaces are disjoint, so the wrong-form header is an
/// `UnknownParent`, never a misparse. (The by-name refusal one layer down is
/// the codec's `WrongHeaderLen`, locked in qlab-p2p.)
#[test]
fn a_v5_link_never_resolves_in_a_v4_chain() {
    let pow = KeccakPow;
    let sched = KeyBlockSchedule::default();
    let genesis = BlockHeader::genesis(8, 0);

    let v4_chain = ChainState::new(genesis);
    let v5_rules = ChainRules { form: GenesisForm::V5, halt: Default::default() };
    let child_v5 = BlockHeader::child_of_for(GenesisForm::V5, &genesis, 75, 8, [0u8; 32]);
    let seed = vec![0u8; 32];
    let mined = mine_under(&pow, child_v5, 1_000_000, &seed, &v5_rules).expect("mine");
    assert_eq!(
        validate_header_under(&v4_chain, &pow, &mined, 75, sched, &v5_rules),
        Err(ValidationError::UnknownParent),
        "a v5 link must not resolve against v4 identities"
    );

    let v5_chain = ChainState::new_for(GenesisForm::V5, genesis);
    let child_v4 = BlockHeader::child_of(&genesis, 75, 8, [0u8; 32]);
    assert_eq!(
        validate_header_under(&v5_chain, &pow, &child_v4, 75, sched, &ChainRules::V1_0),
        Err(ValidationError::UnknownParent),
        "a v4 link must not resolve against v5 identities"
    );
}

/// LWMA/difficulty machinery is layout-agnostic, demonstrated rather than
/// asserted: two chains carrying the SAME (timestamp, difficulty) field
/// sequences — one keyed v4, one keyed v5 — mandate the SAME next difficulty
/// at every height. `qlab_pow::lwma` takes `&[u64]` slices and
/// [`expected_difficulty`] reads struct fields; no byte layout is reachable
/// from either.
#[test]
fn lwma_mandates_the_same_difficulty_under_both_forms() {
    let genesis = BlockHeader::genesis(1_000, 0);
    let mut v4 = ChainState::new(genesis);
    let mut v5 = ChainState::new_for(GenesisForm::V5, genesis);

    for i in 0..140u64 {
        // Identical field sequences on both chains; varied solvetimes so LWMA
        // actually moves (a constant clock would pin it — the T0-3 lesson).
        let ts = |parent: &BlockHeader| parent.timestamp + 60 + (i % 7) * 10;

        let p4_hash = v4.tip_hash();
        let p4 = *v4.header(&p4_hash).unwrap();
        let d4 = expected_difficulty(&v4, &p4_hash, 75).unwrap();
        v4.insert_header(BlockHeader::child_of(&p4, ts(&p4), d4, [0u8; 32])).unwrap();

        let p5_hash = v5.tip_hash();
        let p5 = *v5.header(&p5_hash).unwrap();
        let d5 = expected_difficulty(&v5, &p5_hash, 75).unwrap();
        v5.insert_header(BlockHeader::child_of_for(GenesisForm::V5, &p5, ts(&p5), d5, [0u8; 32]))
            .unwrap();

        assert_eq!(d4, d5, "height {}: LWMA must be layout-agnostic", i + 1);
    }
    // And it genuinely retargeted (the demonstration is not vacuous).
    let final_d = v4.header(&v4.tip_hash()).unwrap().difficulty;
    assert_ne!(final_d, 1_000, "LWMA must have moved off the genesis difficulty");
}
