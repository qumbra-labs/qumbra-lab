//! The proving bundle (lab #924 5A-D1): the split path is the in-process
//! path, the encoding round-trips whole, every refusal fires by name, and the
//! bytes carry no secret.
//!
//! Lane: one S prove (≈ 50 s, the split path's; the in-process proof is the
//! one [`fixture_s`] already pays for in `v2::tests`) and two more
//! `2^D_AUTH` authorization trees.

use std::sync::OnceLock;

use qlab_air::l2::D_AUTH;
use qlab_devnet::annulet::{AuthContext, L2ShapeTag, L2Surface, VPublicTerm, L2_AUTH_ABSENT};
use qlab_devnet::body::TxEntry;
use qlab_l2::Shape;
use qlab_remote_auth::annulet::{auth_master, leaf_key, leaf_seed, DUMMY_DOMAIN};
use qlab_remote_auth::{keccak256, Hash32};

use super::*;
use crate::v2::tests::{fixture_s, prepared_p, prepared_s, sign, GENESIS_HASH};
use crate::v2::{ShapeWitness, SpendWitness};

const CTX: AuthContext = AuthContext::candidate_a(GENESIS_HASH);

/// The secrets the fixtures were built from (`v2::tests`): the S and P
/// keys, and the dummy entropy each passed for slot 2.
const SK_S: Hash32 = [0x51; 32];
const SK_P: Hash32 = [0x52; 32];
const DUMMY_ENTROPY_S: Hash32 = [0xd5; 32];
const DUMMY_ENTROPY_P: Hash32 = [0xd6; 32];

/// A prepared spend, signed as the device signs it, made a bundle.
fn bundle_of(
    prepared: (
        crate::v2::PreparedV2,
        crate::v2::LocalAuth,
        qlab_remote_auth::mldsa::Key,
    ),
    shape: Shape,
) -> ProvingBundle {
    let (p, local, key) = prepared;
    let witness = p.witness;
    assert_eq!(witness.pvs(), p.pvs, "the witness states the prepared PVs");
    let signed = sign(p.tx, p.pvs, p.auth, shape, &local, &[&key]);
    ProvingBundle::new(signed.tx, witness).expect("an honest holder spend is a bundle")
}

fn bundle_s() -> &'static ProvingBundle {
    static B: OnceLock<ProvingBundle> = OnceLock::new();
    B.get_or_init(|| bundle_of(prepared_s(), Shape::S))
}

fn bundle_p() -> &'static ProvingBundle {
    static B: OnceLock<ProvingBundle> = OnceLock::new();
    B.get_or_init(|| bundle_of(prepared_p(), Shape::P))
}

fn wire(tx: &TxEntry) -> Vec<u8> {
    qlab_p2p::codec::encode_tx_annulet(tx)
}

fn without_proof(tx: &TxEntry) -> TxEntry {
    let mut tx = tx.clone();
    tx.proof = Vec::new();
    tx
}

/// The header bytes before the witness: domain, version, shape, the
/// tx length and the tx.
fn witness_offset(b: &ProvingBundle) -> usize {
    BUNDLE_DOMAIN.len() + 2 + 1 + 4 + qlab_p2p::codec::encode_tx_annulet(b.tx()).len()
}

#[test]
fn a_bundle_round_trips_whole() {
    for (b, shape) in [(bundle_s(), L2ShapeTag::S), (bundle_p(), L2ShapeTag::P)] {
        assert_eq!(b.shape(), shape);
        let bytes = b.encode();
        let back = ProvingBundle::decode(&bytes).expect("a bundle decodes");
        assert_eq!(wire(back.tx()), wire(b.tx()), "{shape:?}: the transaction");
        assert_eq!(
            back.witness().statement(),
            b.witness().statement(),
            "{shape:?}: the statement"
        );
        assert_eq!(
            back.encode(),
            bytes,
            "{shape:?}: re-encodes to the same bytes"
        );
        back.check(&CTX)
            .expect("an honest bundle passes the worker's lock");
    }
}

/// F3: the P split at statement level, without proving — prepare, sign,
/// bundle, encode, decode: the lock passes and the PVs are the prepared ones
/// ([`bundle_of`] asserts the witness states them).
#[test]
fn the_p_split_states_the_prepared_pvs() {
    let b = bundle_p();
    let back = ProvingBundle::decode(&b.encode()).expect("a P bundle decodes");
    assert_eq!(back.witness().pvs(), b.witness().pvs());
    assert_eq!(back.witness().pvs().len(), qlab_l2::v2::pv_len(Shape::P));
    back.check(&CTX)
        .expect("an honest P bundle passes the lock");
}

/// B4: the split path — prepare, sign, bundle, encode, decode, prove — is
/// the in-process path ([`fixture_s`]: prepare, prove in process, sign) on
/// every byte but the proof's, and its proof verifies.
#[test]
fn the_split_path_is_the_in_process_path() {
    let f = fixture_s();
    let bundle = ProvingBundle::decode(&bundle_s().encode()).expect("a bundle decodes");
    assert_eq!(bundle.witness().pvs(), f.pvs, "the PVs");
    let tx = bundle.prove(&CTX).expect("an honest bundle proves");
    assert_eq!(
        wire(&without_proof(&tx)),
        wire(&without_proof(&f.tx)),
        "the transaction but its proof, the section included"
    );
    assert_eq!(tx.auth, f.tx.auth, "the section");
    assert!(!tx.proof.is_empty());
    let proof: qlab_l2::Proof<qlab_l2::Config> =
        bincode::deserialize(&tx.proof).expect("the proof decodes");
    assert!(
        qlab_l2::v2::verify_s_u32(&f.pvs, &proof),
        "the split path's proof verifies"
    );
}

// ------------------------------------------------------------- refusals

#[test]
fn a_bundle_is_never_proved_unsigned_or_already_proved() {
    let b = bundle_s();
    let mut proved = b.tx().clone();
    proved.proof = vec![1];
    assert_eq!(
        ProvingBundle::new(proved, b.witness().clone()).err(),
        Some(BundleError::ProofPresent)
    );
    let mut unsigned = b.tx().clone();
    unsigned.auth = L2_AUTH_ABSENT.to_vec();
    assert_eq!(
        ProvingBundle::new(unsigned, b.witness().clone()).err(),
        Some(BundleError::AuthMissing)
    );
}

/// B2/5A-D3: an issuer operation never becomes a bundle — a P row with an
/// issuer secret, a non-zero `vPublic`, shape R on the wire.
#[test]
fn an_issuer_operation_is_refused_by_name() {
    let b = bundle_p();
    let with = |f: &dyn Fn(&mut ShapeWitness)| {
        let mut w = b.witness().clone();
        f(&mut w.shape);
        ProvingBundle::new(b.tx().clone(), w).err()
    };
    let isk = with(&|s| {
        if let ShapeWitness::P { policy, .. } = s {
            policy[1].isk = [7; 4];
        }
    });
    assert!(matches!(isk, Some(BundleError::IssuerShape(_))), "{isk:?}");
    let vp = with(&|s| {
        if let ShapeWitness::P { vp, .. } = s {
            vp[0].amount = 1;
        }
    });
    assert!(matches!(vp, Some(BundleError::IssuerShape(_))), "{vp:?}");
    let mut bytes = b.encode();
    bytes[BUNDLE_DOMAIN.len() + 2] = 2;
    assert!(matches!(
        ProvingBundle::decode(&bytes).err(),
        Some(BundleError::IssuerShape(_))
    ));
}

/// B3: the worker's lock refuses a witness that does not state the
/// transaction, and a section that does not verify, before any proving.
#[test]
fn the_lock_refuses_a_mismatch_before_proving() {
    let b = bundle_s();
    let tamper = |f: &dyn Fn(&mut SpendWitness)| {
        let mut w = b.witness().clone();
        f(&mut w);
        ProvingBundle::new(b.tx().clone(), w)
            .expect("new does not judge the statement")
            .check(&CTX)
            .err()
    };
    assert_eq!(
        tamper(&|w| w.anchor[0] ^= 1),
        Some(BundleError::StatementMismatch("anchor"))
    );
    assert_eq!(
        tamper(&|w| w.inputs[0].rho[0] ^= 1),
        Some(BundleError::StatementMismatch("nullifiers"))
    );
    assert_eq!(
        tamper(&|w| w.outputs[0].value += 1),
        Some(BundleError::StatementMismatch("output commitments"))
    );
    assert_eq!(
        tamper(&|w| w.fee += 1),
        Some(BundleError::StatementMismatch("fee"))
    );
    assert_eq!(
        tamper(&|w| w.registry_root[0] ^= 1),
        Some(BundleError::StatementMismatch("registry root"))
    );

    // F2: openings that do not resolve, though the statement matches.
    assert_eq!(
        tamper(&|w| w.witnesses[0].siblings[3][0] ^= 1),
        Some(BundleError::StatementMismatch("a commitment opening"))
    );
    assert_eq!(
        tamper(
            &|w| if let ShapeWitness::S { reg_witnesses, .. } = &mut w.shape {
                reg_witnesses[0].siblings[0][0] ^= 1
            }
        ),
        Some(BundleError::StatementMismatch("a registry opening"))
    );
    // The dummy fee slot's leaf (off-tree, outside every nullifier) is not
    // the one the section signs for.
    assert_eq!(
        tamper(&|w| if let FeeSlotV2::Dummy { input } = &mut w.fee_slot {
            input.auth.leaf[0] ^= 1
        }),
        Some(BundleError::StatementMismatch("authorization leaves"))
    );

    // Another net's genesis: the intent rebuilds to other bytes.
    let other = b.check(&AuthContext::candidate_a([0x6f; 32])).err();
    assert!(
        matches!(other, Some(BundleError::Unauthorized(_))),
        "{other:?}"
    );
    // A flipped signature byte (the section's last byte).
    let mut tx = b.tx().clone();
    *tx.auth.last_mut().unwrap() ^= 1;
    let sig = ProvingBundle::new(tx, b.witness().clone())
        .unwrap()
        .check(&CTX)
        .err();
    assert!(matches!(sig, Some(BundleError::Unauthorized(_))), "{sig:?}");
    // A modified discovery payload: the intent covers it.
    let mut tx = b.tx().clone();
    *tx.discovery.last_mut().unwrap() ^= 1;
    let disc = ProvingBundle::new(tx, b.witness().clone())
        .unwrap()
        .check(&CTX)
        .err();
    assert!(
        matches!(disc, Some(BundleError::Unauthorized(_))),
        "{disc:?}"
    );
    // `prove` runs the same lock first.
    assert_eq!(
        ProvingBundle::new(b.tx().clone(), {
            let mut w = b.witness().clone();
            w.fee += 1;
            w
        })
        .unwrap()
        .prove(&CTX)
        .err(),
        Some(BundleError::StatementMismatch("fee"))
    );
}

/// F2: the transaction's surface is the one the witness implies — a P
/// surface with a non-zero `vPublic` term is an issuer operation, any other
/// difference a mismatch; and the surface's shape is the witness's.
#[test]
fn the_surface_is_the_witness_s() {
    let b = bundle_p();
    let surface = L2Surface::decode(&b.tx().l2).unwrap().unwrap();
    let with = |s: L2Surface| {
        let mut tx = b.tx().clone();
        tx.l2 = s.encode();
        ProvingBundle::new(tx, b.witness().clone())
            .and_then(|x| x.check(&CTX))
            .err()
    };
    let minted = with(L2Surface {
        vpublic: Some([
            VPublicTerm {
                redeem: false,
                amount: 1,
                asset: 7,
            },
            VPublicTerm::NONE,
        ]),
        ..surface
    });
    assert!(
        matches!(minted, Some(BundleError::IssuerShape(_))),
        "{minted:?}"
    );
    assert_eq!(
        with(L2Surface {
            exit_rkm: [1; 32],
            ..surface
        }),
        Some(BundleError::StatementMismatch("surface"))
    );
    let s_shaped = with(L2Surface {
        shape: L2ShapeTag::S,
        vpublic: None,
        ..surface
    });
    assert!(
        matches!(s_shaped, Some(BundleError::Malformed(_))),
        "{s_shaped:?}"
    );
}

/// F1: a dummy slot carrying a value, an asset or a `d` is refused by name
/// — at `new` and through `decode` — before the instance builder's asserts
/// could panic the worker.
#[test]
fn a_dummy_slot_with_contents_is_refused() {
    let b = bundle_s();
    let refused = |f: &dyn Fn(&mut SpendWitness)| {
        let mut w = b.witness().clone();
        f(&mut w);
        match ProvingBundle::new(b.tx().clone(), w) {
            Err(BundleError::Malformed(why)) => why,
            other => panic!("not refused as malformed: {:?}", other.err()),
        }
    };
    // Slot 2 declared a dummy (`dv`) while it holds the real 50 of asset 7.
    assert!(
        refused(&|w| if let ShapeWitness::S { dv, .. } = &mut w.shape {
            *dv = true
        })
        .contains("dv")
    );
    for f in [
        (&|i: &mut L2AuthInput| i.value = 1) as &dyn Fn(&mut L2AuthInput),
        &|i| i.asset = 7,
        &|i| i.d[1] = 1,
    ] {
        assert!(
            refused(&|w| if let FeeSlotV2::Dummy { input } = &mut w.fee_slot {
                f(input)
            })
            .contains("dummy fee slot")
        );
    }

    // Through the wire: the `dv` bit is an S bundle's last byte.
    let bytes = b.encode();
    let mut dv = bytes.clone();
    *dv.last_mut().unwrap() = 1;
    assert!(
        matches!(ProvingBundle::decode(&dv).err(), Some(BundleError::Malformed(why)) if why.contains("dv"))
    );
    // The dummy fee slot's value: after two inputs, two openings, two
    // outputs, the fee, anchor, registry root and the slot's tag, past nk.
    let input_len = 32 + 8 + 8 + 32 + 32 + 16 + 32 + 4 + 32 * D_AUTH;
    let merkle_len = 32 * qlab_air::narrow::MERKLE_DEPTH + qlab_air::narrow::MERKLE_DEPTH;
    let tag_at = witness_offset(b) + 2 * input_len + 2 * merkle_len + 2 * 112 + 8 + 32 + 32;
    assert_eq!(bytes[tag_at], 1, "the offset is the fee slot's Dummy tag");
    let value_at = tag_at + 1 + 32;
    assert_eq!(
        u64::from_le_bytes(bytes[value_at..value_at + 8].try_into().unwrap()),
        0
    );
    let mut valued = bytes.clone();
    valued[value_at] = 5;
    assert!(
        matches!(ProvingBundle::decode(&valued).err(), Some(BundleError::Malformed(why)) if why.contains("dummy fee slot"))
    );
}

#[test]
fn the_decoder_refuses_by_field() {
    let b = bundle_s();
    let bytes = b.encode();
    let refused = |m: &dyn Fn(&mut Vec<u8>)| {
        let mut x = bytes.clone();
        m(&mut x);
        match ProvingBundle::decode(&x) {
            Err(BundleError::Malformed(why)) => why,
            other => panic!("not refused as malformed: {:?}", other.err()),
        }
    };
    assert!(refused(&|x| x[0] ^= 1).contains("domain"));
    assert!(refused(&|x| x[BUNDLE_DOMAIN.len()] ^= 1).contains("version"));
    assert!(refused(&|x| x[BUNDLE_DOMAIN.len() + 2] = 3).contains("shape code"));
    let len_at = BUNDLE_DOMAIN.len() + 3;
    assert!(refused(
        &|x| x[len_at..len_at + 4].copy_from_slice(&(MAX_BUNDLE_TX_BYTES as u32 + 1).to_le_bytes())
    )
    .contains("over"));
    assert!(refused(&|x| {
        x.pop();
    })
    .contains("truncated"));
    assert!(refused(&|x| x.push(0)).contains("trailing"));
    // An S bundle ends with its `dv` bit.
    assert!(refused(&|x| *x.last_mut().unwrap() = 2).contains("not a bit"));
    // The first input's leaf index: nk, value, asset, rho, rseed, d, leaf.
    let index_at = witness_offset(b) + 32 + 8 + 8 + 32 + 32 + 16 + 32;
    assert_eq!(
        u32::from_le_bytes(bytes[index_at..index_at + 4].try_into().unwrap()),
        b.witness().inputs[0].auth.leaf_index,
        "the offset is the leaf index's"
    );
    assert!(refused(
        &|x| x[index_at..index_at + 4].copy_from_slice(&(1u32 << D_AUTH).to_le_bytes())
    )
    .contains("past depth"));
    // An S bundle's shape byte on a P transaction's bytes.
    let mut p = bundle_p().encode();
    p[BUNDLE_DOMAIN.len() + 2] = 0;
    assert!(matches!(
        ProvingBundle::decode(&p).err(),
        Some(BundleError::Malformed(_))
    ));
}

// ------------------------------------------------------------- no secrets

/// B5, run-time: no 8-byte window of any secret the device holds appears in
/// the bundle's bytes — the key, the generation's authorization master, the
/// leaf seed of every slot's leaf (the dummy's leaf key is its ephemeral key)
/// and the dummy entropy.
#[test]
fn the_bundle_carries_no_secret() {
    for (b, sk, entropy) in [
        (bundle_s(), SK_S, DUMMY_ENTROPY_S),
        (bundle_p(), SK_P, DUMMY_ENTROPY_P),
    ] {
        let bytes = b.encode();
        let master = auth_master(&sk, 0);
        let w = b.witness();
        let mut secrets = vec![
            ("sk", sk),
            ("auth_master", master),
            ("dummy entropy", entropy),
        ];
        for i in &w.inputs {
            // The seed scanned is the one behind the slot's leaf.
            let key = leaf_key(&master, i.auth.leaf_index);
            assert_eq!(
                qlab_note::hash::digest_from_bytes(&key.descriptor(i.auth.leaf_index).leaf()),
                i.auth.leaf,
                "the scan names the real slot's leaf seed"
            );
            secrets.push((
                "a real slot's leaf seed",
                leaf_seed(&master, i.auth.leaf_index),
            ));
        }
        secrets.push((
            "the dummy's key seed",
            keccak256(&[DUMMY_DOMAIN, &entropy, &[2], b"key"]),
        ));
        // The dummy's key is the one its descriptor names.
        let dummy = qlab_remote_auth::mldsa::Key::from_seed(secrets.last().unwrap().1);
        let fee = w.fee_slot.input();
        assert_eq!(
            qlab_note::hash::digest_from_bytes(&dummy.descriptor(fee.auth.leaf_index).leaf()),
            fee.auth.leaf,
            "the scan names the dummy's real key seed"
        );
        for (what, s) in secrets {
            for win in s.windows(8) {
                assert!(
                    !bytes.windows(8).any(|x| x == win),
                    "{:?}: {what} leaks",
                    b.shape()
                );
            }
        }
    }
}

/// B5, by type: a P row's issuer secret has no field on the wire — a decoded
/// row's `isk` is zero whatever the device held — and the encoder takes the
/// bundle (whose constructor refused an `isk`), never a policy input.
#[test]
fn the_issuer_secret_is_unrepresentable() {
    let _encode: fn(&ProvingBundle) -> Vec<u8> = ProvingBundle::encode;
    let _put: fn(&mut Vec<u8>, &SpendWitness) = put_witness;
    let back = ProvingBundle::decode(&bundle_p().encode()).unwrap();
    match &back.witness().shape {
        ShapeWitness::P { policy, vp } => {
            assert!(policy.iter().all(|p| p.isk == [0; 4]));
            assert!(vp.iter().all(|v| v.amount == 0 && !v.redeem));
        }
        ShapeWitness::S { .. } => panic!("a P bundle decodes as P"),
    }
}

/// A bundle's witness is wiped when it drops; [`SpendWitness::wipe`]
/// zeroes every private lane (lab #924, the prover's side).
#[test]
fn a_wiped_witness_holds_no_private_lane() {
    let mut w = bundle_p().witness().clone();
    w.wipe();
    let fee = w.fee_slot.input();
    for i in w.inputs.iter().chain(std::iter::once(fee)) {
        assert_eq!(
            (i.nk, i.value, i.asset, i.rho, i.rseed, i.d),
            ([0; 4], 0, 0, [0; 4], [0; 4], [0; 2])
        );
    }
    for o in &w.outputs {
        assert_eq!(
            (o.value, o.asset, o.rkm, o.rho, o.rseed),
            (0, 0, [0; 4], [0; 4], [0; 4])
        );
    }
    let ShapeWitness::P { policy, .. } = &w.shape else {
        panic!("a P witness")
    };
    assert!(policy.iter().all(|p| p.isk == [0; 4]));
}
