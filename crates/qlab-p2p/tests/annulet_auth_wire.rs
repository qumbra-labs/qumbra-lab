//! Lab #896 seam E2: the Annulet tx wire's presence-conditional **auth
//! section** and the Candidate A served wire form (byte 5).
//!
//! The v1 compat locks are the existing goldens (`served.rs`'s fixture
//! vectors, `annulet_wire.rs`, the codec tests), unchanged: an auth-free
//! transaction encodes byte-identically to v1. These tests add the v2 side and
//! the refusals that keep the two nets apart.

use qlab_devnet::annulet::{L2_AUTH_ABSENT, L2_SURFACE_ABSENT};
use qlab_devnet::body::{BlockBody, TxEntry};
use qlab_devnet::forms::{GenesisForm, L2AuthForm};
use qlab_note::compact::write_varint;
use qlab_p2p::codec::{
    decode_tx_annulet, decode_tx_annulet_with, decode_tx_for, decode_tx_for_auth, encode_tx,
    encode_tx_annulet, encode_tx_for, tx_id, DecodeError,
};
use qlab_p2p::compact::WireForm;
use qlab_p2p::served::{self, fixture, ServedError};

fn signed_tx() -> TxEntry {
    TxEntry {
        auth: vec![0x5A; 2420 + 32],
        ..fixture::tx()
    }
}

/// `TxEntry` has no `PartialEq`: compare by the full Annulet wire (every
/// field, the auth tail included) plus the auth field itself.
fn same(a: &TxEntry, b: &TxEntry) -> bool {
    encode_tx_annulet(a) == encode_tx_annulet(b) && a.auth == b.auth && a.rider == b.rider
}

#[test]
fn an_auth_free_tx_is_byte_identical_to_the_v1_wire() {
    let tx = fixture::tx();
    assert_eq!(tx.auth, L2_AUTH_ABSENT);
    let bytes = encode_tx_annulet(&tx);
    // v1's layout, spelled out: the L1 fields, then `varint len ‖ surface`,
    // and nothing after it.
    let mut want = encode_tx(&TxEntry {
        l2: L2_SURFACE_ABSENT.to_vec(),
        ..tx.clone()
    });
    write_varint(&mut want, tx.l2.len() as u64);
    want.extend_from_slice(&tx.l2);
    assert_eq!(bytes, want);
    // Both nets read it, as the same transaction.
    assert!(same(&decode_tx_annulet(&bytes).unwrap(), &tx));
    assert!(same(
        &decode_tx_annulet_with(&bytes, L2AuthForm::CandidateA).unwrap(),
        &tx
    ));
}

#[test]
fn a_v2_tx_round_trips_with_its_auth_section() {
    let tx = signed_tx();
    let bytes = encode_tx_for(GenesisForm::Annulet, &tx);
    assert_eq!(bytes, encode_tx_annulet(&tx));
    // The tail is exactly `varint len ‖ auth` after the v1 bytes.
    let v1 = encode_tx_annulet(&TxEntry {
        auth: L2_AUTH_ABSENT.to_vec(),
        ..tx.clone()
    });
    let mut want = v1.clone();
    write_varint(&mut want, tx.auth.len() as u64);
    want.extend_from_slice(&tx.auth);
    assert_eq!(bytes, want);
    assert!(same(
        &decode_tx_annulet_with(&bytes, L2AuthForm::CandidateA).unwrap(),
        &tx
    ));
    assert!(same(
        &decode_tx_for_auth(GenesisForm::Annulet, L2AuthForm::CandidateA, &bytes).unwrap(),
        &tx
    ));
}

#[test]
fn a_v1_net_refuses_an_appended_auth_section_as_trailing_bytes() {
    let bytes = encode_tx_annulet(&signed_tx());
    assert!(matches!(
        decode_tx_annulet(&bytes),
        Err(DecodeError::Trailing { .. })
    ));
    assert!(matches!(
        decode_tx_for(GenesisForm::Annulet, &bytes),
        Err(DecodeError::Trailing { .. })
    ));
    assert!(matches!(
        decode_tx_for_auth(GenesisForm::Annulet, L2AuthForm::None, &bytes),
        Err(DecodeError::Trailing { .. })
    ));
}

#[test]
fn candidate_a_refuses_an_explicit_absent_or_empty_auth_section() {
    let v1 = encode_tx_annulet(&fixture::tx());
    for tail in [&[0x01, 0x00][..], &[0x00][..]] {
        let mut bytes = v1.clone();
        bytes.extend_from_slice(tail);
        assert!(
            matches!(
                decode_tx_annulet_with(&bytes, L2AuthForm::CandidateA),
                Err(DecodeError::BadAuthSection)
            ),
            "tail {tail:02x?}: absence is spelled by omission only"
        );
    }
    // A declared length past the buffer is truncation, not a short read.
    let mut short = v1.clone();
    short.extend_from_slice(&[0x10, 0xAA]);
    assert!(decode_tx_annulet_with(&short, L2AuthForm::CandidateA).is_err());
}

#[test]
fn the_p2p_tx_id_covers_the_auth_section() {
    // Compact-relay reconstruction must rebuild the exact body the v2
    // commitment binds, so the relay id of a signed tx is not its unsigned id.
    let tx = signed_tx();
    assert_ne!(
        tx_id(&tx),
        tx_id(&TxEntry {
            auth: L2_AUTH_ABSENT.to_vec(),
            ..tx.clone()
        })
    );
    assert_eq!(
        tx_id(&fixture::tx()),
        qlab_devnet::hash::keccak256(&encode_tx_annulet(&fixture::tx()))
    );
}

#[test]
fn the_candidate_a_served_form_is_byte_5_and_carries_auth() {
    let wf = WireForm::ANNULET_AUTH;
    assert_eq!(
        (wf.form, wf.l2_auth),
        (GenesisForm::Annulet, L2AuthForm::CandidateA)
    );
    assert_eq!(served::wire_form_byte(wf), 5);
    assert_eq!(
        served::wire_form_byte(fixture::AN),
        3,
        "the v1 Annulet byte does not move"
    );

    let (units, _) = fixture::chain();
    let body = BlockBody {
        txs: vec![signed_tx()],
        ..BlockBody::default()
    };
    let ann = qlab_p2p::node::whole_block_announce(units[1].clone(), body.clone());
    let bytes = served::encode_body_answer(wf, 2, &ann).expect("a Candidate A body encodes");
    let back = served::decode_body_answer(wf, 2, &bytes).expect("and decodes under its own form");
    let got = served::body_of(&back).txs;
    assert!(got.len() == 1 && same(&got[0], &body.txs[0]));
    // A v1 reader refuses the v2 frame by its form byte, before the body.
    assert!(matches!(
        served::decode_body_answer(fixture::AN, 2, &bytes),
        Err(ServedError::WrongForm { want: 3, got: 5 })
    ));
    // And a v1-framed answer smuggling an auth tail is refused by the v1
    // tx decoder inside it.
    let smuggled = served::encode_body_answer(fixture::AN, 2, &ann).expect("encodes");
    assert!(matches!(
        served::decode_body_answer(fixture::AN, 2, &smuggled),
        Err(ServedError::Frame(_))
    ));
}

/// Lab #937: the format-34 served form is byte 6 (unused before: 1 V4, 2 V5,
/// 3 Annulet v1, 4 V6, 5 Candidate A). Its tx wire is Candidate A's (the
/// auth tail read by `has_auth`, the commitment count a varint), so a
/// three-output transaction round-trips; a format-33 and a format-34 reader
/// refuse each other's frames by the form byte, both directions.
#[test]
fn the_format_34_served_form_is_byte_6_and_the_formats_refuse_each_other() {
    let wf = WireForm::ANNULET_AUTH_V3;
    assert_eq!((wf.form, wf.l2_auth), (GenesisForm::Annulet, L2AuthForm::CandidateAV3));
    assert_eq!(served::wire_form_byte(wf), 6);
    assert_eq!(served::wire_form_byte(WireForm::ANNULET_AUTH), 5, "format 33's byte does not move");
    let all = [
        WireForm::plain(GenesisForm::V4),
        WireForm::plain(GenesisForm::V5),
        fixture::AN,
        WireForm::V6,
        WireForm::ANNULET_AUTH,
        WireForm::ANNULET_AUTH_V3,
    ];
    let bytes: Vec<u8> = all.iter().map(|w| served::wire_form_byte(*w)).collect();
    assert_eq!(bytes, [1, 2, 3, 4, 5, 6], "one byte per form, none reused");

    // A three-output transaction with its auth tail, through the tx codec.
    let mut tx = signed_tx();
    tx.public.commitments.push([0x77; 32]);
    let enc = encode_tx_annulet(&tx);
    assert!(same(&decode_tx_annulet_with(&enc, L2AuthForm::CandidateAV3).unwrap(), &tx));
    assert!(same(&decode_tx_for_auth(GenesisForm::Annulet, L2AuthForm::CandidateAV3, &enc).unwrap(), &tx));

    // And through the served body frame, under its own form only.
    let (units, _) = fixture::chain();
    let body = BlockBody { txs: vec![tx.clone()], ..BlockBody::default() };
    let ann = qlab_p2p::node::whole_block_announce(units[1].clone(), body.clone());
    let v3 = served::encode_body_answer(wf, 2, &ann).expect("a format-34 body encodes");
    let back = served::decode_body_answer(wf, 2, &v3).expect("and decodes under its own form");
    let got = served::body_of(&back).txs;
    assert!(got.len() == 1 && same(&got[0], &tx));
    assert!(matches!(
        served::decode_body_answer(WireForm::ANNULET_AUTH, 2, &v3),
        Err(ServedError::WrongForm { want: 5, got: 6 })
    ));
    let v2 = served::encode_body_answer(WireForm::ANNULET_AUTH, 2, &ann).expect("encodes");
    assert!(matches!(
        served::decode_body_answer(wf, 2, &v2),
        Err(ServedError::WrongForm { want: 6, got: 5 })
    ));
}
