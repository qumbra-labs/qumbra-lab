//! Lab #490: the form-keyed work-value predicate — v4 head-BE byte-locked to
//! today's exact behavior, v5 tail-LE (Monero/xmrig-congruent), the divergence
//! proof, the miner/validator agreement, and the post-halt composition.

use qlab_devnet::chain::ChainState;
use qlab_devnet::forms::{ChainRules, GenesisForm};
use qlab_devnet::halt::{pow_value, PostHaltRules, RuleSchedule};
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_devnet::mining::mine_under;
use qlab_devnet::pow::{
    hash_to_work_value, hash_to_work_value_for, satisfies_target_for, target_threshold,
    KeccakPow, PowEngine,
};
use qlab_devnet::validation::{pow_seed, validate_header_under, ValidationError};
use qlab_pow::keyblock::KeyBlockSchedule;

/// 🔒 The v4 compat lock: today's exact accept/reject boundary, head-BE,
/// including the `u64::MAX / d` edge — and the keyed form's V4 arm is the
/// same function as the unkeyed one.
#[test]
fn v4_predicate_boundary_is_byte_locked() {
    let d = 4u64;
    let threshold = target_threshold(d);
    assert_eq!(threshold, u64::MAX / 4);

    // hash whose LEADING 8 bytes big-endian == threshold exactly → accepted (<=).
    let mut at = [0u8; 32];
    at[..8].copy_from_slice(&threshold.to_be_bytes());
    assert_eq!(hash_to_work_value(&at), threshold);
    assert!(satisfies_target_for(&at, d, GenesisForm::V4));

    // one above → rejected. The boundary is exact.
    let mut above = at;
    above[..8].copy_from_slice(&(threshold + 1).to_be_bytes());
    assert!(!satisfies_target_for(&above, d, GenesisForm::V4));

    // the unkeyed fns ARE the v4 arm, on adversarially-varied bytes.
    for fill in [0x00u8, 0x5A, 0xFF] {
        let mut h = [fill; 32];
        h[7] = 0x01;
        h[24] = 0xEE; // tail noise must not matter on v4
        assert_eq!(hash_to_work_value(&h), hash_to_work_value_for(&h, GenesisForm::V4));
    }

    // difficulty 0 is treated as 1 on both forms (no divide-by-zero).
    assert!(satisfies_target_for(&[0u8; 32], 0, GenesisForm::V4));
    assert!(satisfies_target_for(&[0u8; 32], 0, GenesisForm::V5));
}

/// 🔒 The v5 vector, xmrig-congruent by construction: the value is the
/// TRAILING 8 bytes as little-endian — `hash[24..32]`, the exact window
/// `CpuWorker.cpp` reads (`*reinterpret_cast<uint64_t*>(m_hash + 24)`).
#[test]
fn v5_predicate_reads_the_xmrig_window() {
    // Tail-LE small, head-BE huge: xmrig would submit this; v5 accepts it,
    // v4 rejects it — the share-rejection half of #490's finding.
    let mut tail_wins = [0xFFu8; 32];
    tail_wins[24..32].copy_from_slice(&7u64.to_le_bytes());
    assert_eq!(hash_to_work_value_for(&tail_wins, GenesisForm::V5), 7);
    assert!(satisfies_target_for(&tail_wins, 1_000_000, GenesisForm::V5));
    assert!(!satisfies_target_for(&tail_wins, 1_000_000, GenesisForm::V4));

    // The converse: head-BE small, tail-LE huge — a v4-valid hash xmrig
    // would never surface; v5 rejects it.
    let mut head_wins = [0xFFu8; 32];
    head_wins[..8].copy_from_slice(&7u64.to_be_bytes());
    assert!(satisfies_target_for(&head_wins, 1_000_000, GenesisForm::V4));
    assert!(!satisfies_target_for(&head_wins, 1_000_000, GenesisForm::V5));

    // The window is exactly 24..32: byte 23 is outside it, byte 24 inside.
    let mut h = [0u8; 32];
    h[24..32].copy_from_slice(&100u64.to_le_bytes());
    let v = hash_to_work_value_for(&h, GenesisForm::V5);
    h[23] = 0xFF;
    assert_eq!(hash_to_work_value_for(&h, GenesisForm::V5), v, "byte 23 is outside the window");
    h[24] ^= 0x01;
    assert_ne!(hash_to_work_value_for(&h, GenesisForm::V5), v, "byte 24 is inside it");

    // LE, not BE, within the window: the byte at 31 is the HIGH byte.
    let mut le = [0u8; 32];
    le[31] = 0x01;
    assert_eq!(hash_to_work_value_for(&le, GenesisForm::V5), 1u64 << 56);
}

/// The keying reaches the predicate: one hash, one difficulty, the two forms
/// disagree in both directions.
#[test]
fn the_two_forms_diverge_on_one_hash() {
    let mut h = [0xFFu8; 32];
    h[24..32].copy_from_slice(&1u64.to_le_bytes());
    let d = 2u64;
    assert!(satisfies_target_for(&h, d, GenesisForm::V5));
    assert!(!satisfies_target_for(&h, d, GenesisForm::V4));

    let mut g = [0xFFu8; 32];
    g[..8].copy_from_slice(&1u64.to_be_bytes());
    assert!(satisfies_target_for(&g, d, GenesisForm::V4));
    assert!(!satisfies_target_for(&g, d, GenesisForm::V5));
}

/// Miner/validator agreement on v5 through the real mine.rs path: what
/// `mine_under` accepts under a V5 [`ChainRules`], `validate_header_under`
/// accepts under the same rules — and the mined PoW value satisfies the
/// TAIL-LE predicate specifically (direct evidence the miner ground against
/// the v5 window, not the v4 one).
#[test]
fn v5_miner_and_validator_agree_through_the_real_path() {
    let pow = KeccakPow;
    let rules = ChainRules { form: GenesisForm::V5, halt: RuleSchedule::V1_0 };
    let sched = KeyBlockSchedule::default();
    let genesis = BlockHeader::genesis_for(GenesisForm::V5, 8, 0);
    let mut chain = ChainState::new_for(GenesisForm::V5, genesis);

    for _ in 0..3 {
        let parent_hash = chain.tip_hash();
        let parent = *chain.header(&parent_hash).unwrap();
        let candidate = BlockHeader::child_of_for(
            GenesisForm::V5,
            &parent,
            parent.timestamp + 75,
            parent.difficulty,
            [0u8; 32],
        );
        let seed = pow_seed(&chain, &parent_hash, candidate.height, sched).unwrap();
        let mined = mine_under(&pow, candidate, 1_000_000, &seed, &rules).expect("mine v5");
        // The accepted value satisfies the v5 (tail-LE) read…
        let value = pow_value(
            pow.pow_hash(GenesisForm::V5, &mined, &seed),
            mined.height,
            &rules.halt,
        );
        assert!(satisfies_target_for(&value, mined.difficulty, GenesisForm::V5));
        // …and the validator, keyed off the SAME rules, agrees.
        validate_header_under(&chain, &pow, &mined, 75, sched, &rules)
            .expect("v5 validator accepts what the v5 miner produced");
        chain.insert_header(mined).unwrap();
    }
    assert_eq!(chain.tip_height(), 3);
}

/// Post-halt composition, asserted not cited: `pow_value`'s revision-digest
/// mixing post-processes the engine's output, and the v5 predicate reads the
/// PROCESSED bytes — so a block mined without the domain fails under the
/// domained rules, and one mined with it passes, exactly the v4 halt-drill
/// property replayed on the v5 form.
#[test]
fn v5_predicate_composes_with_the_post_halt_domain() {
    let pow = KeccakPow;
    let sched = KeyBlockSchedule::default();
    let boundary = 0u64; // domain active for every height > 0
    let domain: Hash32 = [0xD0; 32];
    let plain = ChainRules { form: GenesisForm::V5, halt: RuleSchedule::V1_0 };
    let domained = ChainRules {
        form: GenesisForm::V5,
        halt: RuleSchedule {
            post_halt: Some(PostHaltRules { from_height: boundary, domain }),
            ..RuleSchedule::V1_0
        },
    };

    let genesis = BlockHeader::genesis_for(GenesisForm::V5, 8, 0);
    let chain = ChainState::new_for(GenesisForm::V5, genesis);
    let parent_hash = chain.tip_hash();
    let parent = *chain.header(&parent_hash).unwrap();
    let candidate = BlockHeader::child_of_for(
        GenesisForm::V5,
        &parent,
        parent.timestamp + 75,
        parent.difficulty,
        [0u8; 32],
    );
    let seed = pow_seed(&chain, &parent_hash, candidate.height, sched).unwrap();

    // Mined WITHOUT the domain: the domained validator refuses it (PoW).
    let plain_mined = mine_under(&pow, candidate, 1_000_000, &seed, &plain).expect("mine plain");
    assert_eq!(
        validate_header_under(&chain, &pow, &plain_mined, 75, sched, &domained),
        Err(ValidationError::PowUnsatisfied),
        "the domain must bite on v5 exactly as it does on v4"
    );

    // Mined WITH the domain: the same validator accepts.
    let dom_mined = mine_under(&pow, candidate, 1_000_000, &seed, &domained).expect("mine domained");
    validate_header_under(&chain, &pow, &dom_mined, 75, sched, &domained)
        .expect("domained miner + domained validator agree on v5");
}
