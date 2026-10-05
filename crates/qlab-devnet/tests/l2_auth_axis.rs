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
    ANNULET_AUTH_GENESIS_FORMAT_VERSION, ANNULET_GENESIS_FORMAT_VERSION,
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
    for v in [0u32, 8, 9, 10, 31, 34, u32::MAX] {
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
