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
