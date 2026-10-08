//! Lab #896 seam E2: the `L2AuthForm` axis beside `GenesisForm::Annulet` —
//! the format-33 mapping and the v2 body / genesis-body commitment domains.
//! The v1 goldens these sit beside are in `annulet.rs`'s own tests, unchanged.

use qlab_devnet::annulet::{
    body_commitment_annulet, body_commitment_annulet_for, genesis_body_commitment_annulet,
    genesis_body_commitment_annulet_for, GenesisNote, L2_AUTH_ABSENT,
};
use qlab_devnet::body::{BlockBody, TxEntry, TxPublic};
use qlab_devnet::fees::ArityBucket;
use qlab_devnet::forms::{
    annulet_forms_of_genesis_format_version, GenesisForm, L2AuthForm,
    ANNULET_AUTH_GENESIS_FORMAT_VERSION, ANNULET_AUTH_V3_GENESIS_FORMAT_VERSION,
    ANNULET_GENESIS_FORMAT_VERSION,
};

fn tx(auth: &[u8]) -> TxEntry {
    let public = TxPublic {
        anchor: [0x0F; 32],
        nullifiers: vec![[1; 32], [2; 32]],
        commitments: vec![[3; 32], [4; 32]],
        bucket: ArityBucket::TwoByTwo,
        fee: 2,
    };
    TxEntry {
        auth: auth.to_vec(),
        l2: vec![0x01, 0x02],
        ..TxEntry::with_placeholder_discovery(vec![0xAB; 40], public)
    }
}

fn body(auth: &[u8]) -> BlockBody {
    BlockBody::new(vec![tx(auth)], Vec::new())
}

#[test]
fn format_33_is_annulet_with_candidate_a_and_back() {
    assert_eq!(ANNULET_AUTH_GENESIS_FORMAT_VERSION, 33);
    assert_eq!(
        annulet_forms_of_genesis_format_version(33),
        Some((GenesisForm::Annulet, L2AuthForm::CandidateA))
    );
    assert_eq!(
        annulet_forms_of_genesis_format_version(32),
        Some((GenesisForm::Annulet, L2AuthForm::None))
    );
    assert_eq!(L2AuthForm::CandidateA.annulet_genesis_format_version(), 33);
    assert_eq!(
        L2AuthForm::None.annulet_genesis_format_version(),
        ANNULET_GENESIS_FORMAT_VERSION
    );
    for v in [0u32, 8, 9, 10, 31, 35, u32::MAX] {
        assert_eq!(
            annulet_forms_of_genesis_format_version(v),
            None,
            "v{v} is not an Annulet genesis"
        );
    }
    // Like format 10, 33 is not a bare form: L1-only loaders keyed on the
    // bare form never see it as anything they serve.
    assert_eq!(GenesisForm::from_genesis_format_version(33), None);
    assert_eq!(L2AuthForm::default(), L2AuthForm::None);
    assert_eq!(
        (L2AuthForm::None.label(), L2AuthForm::CandidateA.label()),
        ("none", "candidate-a")
    );
}

/// Lab #937: format 34 is `(Annulet, CandidateAV3)` and back; it carries
/// auth like 33 and three S/P outputs; not a bare form; its constant is the
/// one `qlab-remote-auth`'s intent keys its three commitments to.
#[test]
fn format_34_is_annulet_with_candidate_a_v3_and_back() {
    assert_eq!(ANNULET_AUTH_V3_GENESIS_FORMAT_VERSION, 34);
    assert_eq!(
        annulet_forms_of_genesis_format_version(34),
        Some((GenesisForm::Annulet, L2AuthForm::CandidateAV3))
    );
    assert_eq!(L2AuthForm::CandidateAV3.annulet_genesis_format_version(), 34);
    assert_eq!(GenesisForm::from_genesis_format_version(34), None);
    assert_eq!(L2AuthForm::CandidateAV3.label(), "candidate-a-v3");
    assert_eq!(
        [L2AuthForm::None, L2AuthForm::CandidateA, L2AuthForm::CandidateAV3].map(|f| (f.has_auth(), f.sp_outputs())),
        [(false, 2), (true, 2), (true, 3)]
    );
    // Every axis value round-trips through its format.
    for f in [L2AuthForm::None, L2AuthForm::CandidateA, L2AuthForm::CandidateAV3] {
        assert_eq!(
            annulet_forms_of_genesis_format_version(f.annulet_genesis_format_version()),
            Some((GenesisForm::Annulet, f))
        );
    }
    // The cross-lock: the intent's three-commitment format is this one.
    assert_eq!(
        qlab_remote_auth::annulet::ANNULET_V3_GENESIS_FORMAT,
        ANNULET_AUTH_V3_GENESIS_FORMAT_VERSION
    );
    for f in [L2AuthForm::CandidateA, L2AuthForm::CandidateAV3] {
        for shape in [qlab_remote_auth::annulet::Shape::S, qlab_remote_auth::annulet::Shape::P] {
            assert_eq!(
                qlab_remote_auth::annulet::intent_outputs(f.annulet_genesis_format_version(), shape),
                f.sp_outputs(),
                "{f:?} {shape:?}"
            );
        }
    }
}

/// Lab #937: S/P arity is the axis's, and the other format's spend is
/// refused by name in both directions; R is unchanged on every axis.
#[test]
fn sp_arity_is_keyed_by_the_axis_and_refuses_the_other_format_by_name() {
    use qlab_devnet::annulet::{check_l2_arity, L2ShapeTag};
    use qlab_devnet::body::BodyError;
    let public = |nf: usize, cm: usize| TxPublic {
        anchor: [0x0F; 32],
        nullifiers: vec![[1; 32]; nf],
        commitments: vec![[3; 32]; cm],
        bucket: ArityBucket::TwoByTwo,
        fee: 2,
    };
    for shape in [L2ShapeTag::S, L2ShapeTag::P] {
        // Accepted: three outputs on 34, two on 33 (and on v1).
        assert_eq!(check_l2_arity(&public(3, 3), shape, L2AuthForm::CandidateAV3, 4), Ok(()));
        assert_eq!(check_l2_arity(&public(3, 2), shape, L2AuthForm::CandidateA, 4), Ok(()));
        assert_eq!(check_l2_arity(&public(3, 2), shape, L2AuthForm::None, 4), Ok(()));
        // Refused by name, both directions.
        assert_eq!(
            check_l2_arity(&public(3, 2), shape, L2AuthForm::CandidateAV3, 4),
            Err(BodyError::L2V2SpendOnV3Net { index: 4 })
        );
        assert_eq!(
            check_l2_arity(&public(3, 3), shape, L2AuthForm::CandidateA, 4),
            Err(BodyError::L2V3SpendOnV2Net { index: 4 })
        );
        // Anything else stays the generic refusal.
        assert_eq!(
            check_l2_arity(&public(3, 3), shape, L2AuthForm::None, 4),
            Err(BodyError::L2WrongArity { index: 4 })
        );
        for (nf, cm) in [(3, 4), (2, 3), (3, 1)] {
            assert_eq!(
                check_l2_arity(&public(nf, cm), shape, L2AuthForm::CandidateAV3, 4),
                Err(BodyError::L2WrongArity { index: 4 }),
                "{nf}/{cm}"
            );
        }
    }
    for auth in [L2AuthForm::None, L2AuthForm::CandidateA, L2AuthForm::CandidateAV3] {
        assert_eq!(check_l2_arity(&public(1, 2), L2ShapeTag::R, auth, 0), Ok(()));
        assert_eq!(
            check_l2_arity(&public(1, 3), L2ShapeTag::R, auth, 0),
            Err(BodyError::L2RegistryWriteArity { index: 0 })
        );
    }
}

#[test]
fn the_v1_body_commitment_is_unchanged_and_ignores_auth() {
    let absent = body(L2_AUTH_ABSENT);
    assert_eq!(
        body_commitment_annulet_for(&absent, L2AuthForm::None),
        body_commitment_annulet(&absent)
    );
    let signed = body(&[0x5A; 48]);
    assert_eq!(
        body_commitment_annulet_for(&signed, L2AuthForm::None),
        body_commitment_annulet_for(&absent, L2AuthForm::None),
        "v1 does not commit the auth section (that a v1 body carries none is decode's and seam F's)"
    );
}

#[test]
fn the_v2_body_commitment_moves_when_only_auth_moves() {
    let a = body(&[0x5A; 48]);
    let b = body(&[0x5B; 48]);
    let c = body(&[0x5A; 49]);
    let absent = body(L2_AUTH_ABSENT);
    let v2 = |x: &BlockBody| body_commitment_annulet_for(x, L2AuthForm::CandidateA);
    assert_ne!(v2(&a), v2(&b), "auth bytes are committed");
    assert_ne!(v2(&a), v2(&c), "auth length is committed");
    assert_ne!(v2(&a), v2(&absent));
    // The v2 domain differs from v1 even with no auth anywhere, and on the
    // empty body.
    assert_ne!(v2(&absent), body_commitment_annulet(&absent));
    assert_ne!(
        v2(&BlockBody::default()),
        body_commitment_annulet(&BlockBody::default())
    );
}

#[test]
fn a_v1_and_a_v2_genesis_body_with_equal_notes_differ() {
    let notes = vec![GenesisNote {
        cm: [9; 32],
        payload: vec![7; qlab_note::l2note::L2_PAYLOAD_LEN],
    }];
    assert_eq!(
        genesis_body_commitment_annulet_for(&notes, L2AuthForm::None),
        genesis_body_commitment_annulet(&notes)
    );
    assert_ne!(
        genesis_body_commitment_annulet_for(&notes, L2AuthForm::CandidateA),
        genesis_body_commitment_annulet(&notes)
    );
    assert_ne!(
        genesis_body_commitment_annulet_for(&[], L2AuthForm::CandidateA),
        genesis_body_commitment_annulet(&[])
    );
}

/// The v2 domains pinned to hex. Each value was computed by an independent
/// Python Keccak-256 rebuild of the preimage (domain ‖ fields, u64-LE length
/// prefixes; `e2_goldens.py`, quoted in the PR), calibrated first against
/// main's `GOLDEN_ANNULET_EMPTY_BODY` / `_EMPTY_GENESIS` — not read back from
/// this code.
#[test]
fn the_v2_commitments_are_pinned() {
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    // Every byte of the fixture is literal: no placeholder discovery.
    let tx = TxEntry {
        auth: vec![0x5A; 48],
        proof: vec![0xAB; 40],
        public: TxPublic {
            anchor: [0x0F; 32],
            nullifiers: vec![[1; 32], [2; 32]],
            commitments: vec![[3; 32], [4; 32]],
            bucket: ArityBucket::TwoByTwo,
            fee: 2,
        },
        discovery: vec![0x00],
        rider: TxEntry::absent_rider(),
        l2: vec![0x01, 0x02],
    };
    let body = BlockBody::new(vec![tx], Vec::new());
    assert_eq!(
        hex(&body_commitment_annulet_for(
            &BlockBody::default(),
            L2AuthForm::CandidateA
        )),
        GOLDEN_E2_BODY_V2_EMPTY
    );
    assert_eq!(
        hex(&body_commitment_annulet_for(&body, L2AuthForm::CandidateA)),
        GOLDEN_E2_BODY_V2_ONE_TX
    );
    let note = GenesisNote {
        cm: [9; 32],
        payload: vec![7; 128],
    };
    assert_eq!(
        hex(&genesis_body_commitment_annulet_for(
            &[],
            L2AuthForm::CandidateA
        )),
        GOLDEN_E2_GENESIS_V2_EMPTY
    );
    assert_eq!(
        hex(&genesis_body_commitment_annulet_for(
            &[note],
            L2AuthForm::CandidateA
        )),
        GOLDEN_E2_GENESIS_V2_ONE_NOTE
    );
}

const GOLDEN_E2_BODY_V2_EMPTY: &str =
    "c1057215d437bbdfcf224edbf1fdfb125395c9d5de9355c098bc28eb1da8b07f";
const GOLDEN_E2_BODY_V2_ONE_TX: &str =
    "1e513a3f01e7979788dfa5e21d7727cb61d910fa6a5eca73affbf075c15cde98";
const GOLDEN_E2_GENESIS_V2_EMPTY: &str =
    "ecd8c51071014eabe7715f9591e32f52f71533a3f19ba88325c09894ff182567";
const GOLDEN_E2_GENESIS_V2_ONE_NOTE: &str =
    "7c478b0a8816ea4d03f012d39ec48f97c6c498fc0d5359991159e0e041ad3cb4";

/// Lab #937: the v3 (format-34) domains pinned to hex, by the same method as
/// the v2 ones: an independent Python Keccak-256 rebuild
/// (`logs/937-prB-map-20261008/body_golden.py`, quoted in the PR) that first
/// reproduces the four v2 goldens above byte for byte. The v3 body of the v2
/// fixture differs from the v2 one by the domain alone; the format-34 golden
/// carries a three-output transaction.
#[test]
fn the_v3_commitments_are_pinned() {
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let tx = |commitments: Vec<[u8; 32]>| TxEntry {
        auth: vec![0x5A; 48],
        proof: vec![0xAB; 40],
        public: TxPublic {
            anchor: [0x0F; 32],
            nullifiers: vec![[1; 32], [2; 32]],
            commitments,
            bucket: ArityBucket::TwoByTwo,
            fee: 2,
        },
        discovery: vec![0x00],
        rider: TxEntry::absent_rider(),
        l2: vec![0x01, 0x02],
    };
    let v3 = |b: &BlockBody| hex(&body_commitment_annulet_for(b, L2AuthForm::CandidateAV3));
    assert_eq!(v3(&BlockBody::default()), GOLDEN_937_BODY_V3_EMPTY);
    let two = BlockBody::new(vec![tx(vec![[3; 32], [4; 32]])], Vec::new());
    assert_eq!(v3(&two), GOLDEN_937_BODY_V3_ONE_TX);
    let three = BlockBody::new(vec![tx(vec![[3; 32], [4; 32], [5; 32]])], Vec::new());
    assert_eq!(v3(&three), GOLDEN_937_BODY_V3_THREE_OUTPUT_TX);
    let note = GenesisNote { cm: [9; 32], payload: vec![7; 128] };
    assert_eq!(
        hex(&genesis_body_commitment_annulet_for(&[], L2AuthForm::CandidateAV3)),
        GOLDEN_937_GENESIS_V3_EMPTY
    );
    assert_eq!(
        hex(&genesis_body_commitment_annulet_for(std::slice::from_ref(&note), L2AuthForm::CandidateAV3)),
        GOLDEN_937_GENESIS_V3_ONE_NOTE
    );
    // A format-33 and a format-34 body never commit alike.
    assert_ne!(
        body_commitment_annulet_for(&two, L2AuthForm::CandidateA),
        body_commitment_annulet_for(&two, L2AuthForm::CandidateAV3)
    );
    assert_ne!(
        genesis_body_commitment_annulet_for(std::slice::from_ref(&note), L2AuthForm::CandidateA),
        genesis_body_commitment_annulet_for(&[note], L2AuthForm::CandidateAV3)
    );
}

const GOLDEN_937_BODY_V3_EMPTY: &str =
    "30d2ffea90d95a98777fe6855570054412bfab224452df708d62d1f932e3df9c";
const GOLDEN_937_BODY_V3_ONE_TX: &str =
    "87bc83a5289c7c188eb53ee10d86775d4817d98b440e3d43b839707a028450c5";
const GOLDEN_937_BODY_V3_THREE_OUTPUT_TX: &str =
    "abe222f0cf9ad2011f812e83e27577ed488338287a48bf98e4d999a74076bcf6";
const GOLDEN_937_GENESIS_V3_EMPTY: &str =
    "a1d4472a0407d4a6a81814f28fddc0e446a4dbec5989a9c574936207862f1815";
const GOLDEN_937_GENESIS_V3_ONE_NOTE: &str =
    "310b6b9eef4644f80ad2b9a22cb565015858e164a14c38726d6c581788b7044e";
