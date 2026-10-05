//! Lab #896 seam E2: the Annulet genesis's L2 authorization axis — format 33
//! is `(Annulet, CandidateA)`, committed in the bytes the genesis hash covers,
//! and a node opens on the axis its genesis names.

use qlab_devnet::forms::{GenesisForm, L2AuthForm};
use qlab_node::annulet_genesis::{
    registry_leaves, AnnuletGenesisError, AnnuletGenesisFile, AnnuletParams, GenesisNoteRecord,
    RegistryLeafRecord,
};
use qlab_node::MemNode;

fn params() -> AnnuletParams {
    AnnuletParams {
        fee_tier_s: 1,
        fee_tier_p: 2,
        fee_tier_r: 4,
        slot_secs: 10,
        max_empty_slots: 6,
    }
}

fn notes() -> Vec<GenesisNoteRecord> {
    let note = qlab_note::l2note::L2Note {
        value: 1,
        asset: 0,
        rkm: [0xFA0C_E701, 0xFA0C_E702, 0xFA0C_E703, 0xFA0C_E704],
        rho: [0x6E0A_0000, 1, 2, 3],
        rseed: [0x5EED_0000, 4, 5, 6],
    };
    vec![GenesisNoteRecord::of(&note)]
}

fn genesis(auth: L2AuthForm) -> AnnuletGenesisFile {
    AnnuletGenesisFile::assemble_with_auth(
        "annulet-e2-test",
        params(),
        [0x5E; 32],
        vec![RegistryLeafRecord::asset_zero()],
        notes(),
        0,
        auth,
    )
}

#[test]
fn assemble_is_the_v1_genesis_unchanged() {
    let v1 = AnnuletGenesisFile::assemble(
        "annulet-e2-test",
        params(),
        [0x5E; 32],
        vec![RegistryLeafRecord::asset_zero()],
        notes(),
        0,
    );
    assert_eq!(v1, genesis(L2AuthForm::None));
    assert_eq!(v1.format_version, 32);
    assert_eq!(v1.l2_auth(), Ok(L2AuthForm::None));
}

#[test]
fn a_v1_and_a_v2_genesis_with_otherwise_equal_fields_hash_differently() {
    let v1 = genesis(L2AuthForm::None);
    let v2 = genesis(L2AuthForm::CandidateA);
    assert_eq!(v2.format_version, 33);
    assert_eq!(
        (v1.form(), v2.form()),
        (Ok(GenesisForm::Annulet), Ok(GenesisForm::Annulet))
    );
    assert_eq!(v2.l2_auth(), Ok(L2AuthForm::CandidateA));
    assert_ne!(v1.hash(), v2.hash());
    assert_ne!(
        v1.genesis_header.body_commitment,
        v2.genesis_header.body_commitment
    );
    // Same everything else: only the axis-keyed fields differ.
    assert_eq!(
        (v1.network.as_str(), v1.params, &v1.notes()[0].cm),
        (v2.network.as_str(), v2.params, &v2.notes()[0].cm)
    );

    // Both verify, and both survive their bytes.
    v1.verify(None).expect("v1 verifies");
    v2.verify(None).expect("v2 verifies");
    let back = AnnuletGenesisFile::from_bytes(&v2.to_bytes()).expect("format 33 loads");
    assert_eq!(back, v2);
    assert_eq!(
        &v2.to_bytes()[..4],
        &33u32.to_le_bytes(),
        "the axis is the leading u32"
    );
}

#[test]
fn a_genesis_whose_body_commitment_is_under_the_other_axis_is_refused() {
    // A v1 header relabelled format 33 (and the reverse) does not verify: the
    // genesis body commitment is keyed by the axis.
    let mut relabelled = genesis(L2AuthForm::None);
    relabelled.format_version = 33;
    assert!(matches!(
        relabelled.verify(None),
        Err(AnnuletGenesisError::BadAnnulet(_))
    ));
    let mut relabelled = genesis(L2AuthForm::CandidateA);
    relabelled.format_version = 32;
    assert!(matches!(
        relabelled.verify(None),
        Err(AnnuletGenesisError::BadAnnulet(_))
    ));
    let mut other = genesis(L2AuthForm::None);
    other.format_version = 34;
    assert_eq!(
        other.l2_auth(),
        Err(AnnuletGenesisError::NotAnnuletGenesis { got: Some(34) })
    );
}

#[test]
fn a_node_opens_on_its_genesis_axis() {
    let g = genesis(L2AuthForm::CandidateA);
    let notes: Vec<_> = g.notes();
    let fees = g.params.fee_table();
    let leaves = registry_leaves(&g.registry_genesis);
    let node = MemNode::in_memory_annulet_with_auth(
        g.genesis_block_header(),
        &notes,
        fees,
        &leaves,
        qlab_devnet::annulet::AuthContext::candidate_a(g.hash()),
    );
    assert_eq!(node.l2_auth_form(), L2AuthForm::CandidateA);
    let v1 = genesis(L2AuthForm::None);
    let node = MemNode::in_memory_annulet(v1.genesis_block_header(), &v1.notes(), fees, &leaves);
    assert_eq!(node.l2_auth_form(), L2AuthForm::None);
}

#[test]
#[should_panic(expected = "must bind its genesis notes")]
fn a_v2_genesis_header_does_not_open_as_a_v1_node() {
    let g = genesis(L2AuthForm::CandidateA);
    let leaves = registry_leaves(&g.registry_genesis);
    let _ = MemNode::in_memory_annulet(
        g.genesis_block_header(),
        &g.notes(),
        g.params.fee_table(),
        &leaves,
    );
}
