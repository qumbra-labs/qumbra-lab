//! Seam E4's round trips: one honest v2 spend per shape at its real height
//! (S 2^20, P 2^20, R 2^19), built from `L2AuthInput`s and a device-made
//! dummy, signed with [`sign_locally`], attached, and checked the way a node
//! checks it: the STARK against the PVs, the section decoded from `tx.auth`,
//! the intent rebuilt by [`intent_for`] from the transaction and the section's
//! descriptors, then `verify_intent`. Each shape proves once (`OnceLock`);
//! the negatives re-use the proof and cost one ML-DSA verify each.
//!
//! Lane: three proves (≈ 25 s / 50 s / 60 s on r7g for R / S / P) plus three
//! `2^D_AUTH` authorization trees: about +3–4 Graviton min. The fixtures
//! assume the serial runner the suite uses (`--test-threads=1`): run in
//! parallel, the three proves would peak together at about 75 GiB.

use std::sync::OnceLock;

use qlab_air::l2::RegistryLeaf;
use qlab_cbserver::registry::RegistryTree;
use qlab_devnet::annulet::L2SurfaceError;
use qlab_devnet::forms::ANNULET_AUTH_GENESIS_FORMAT_VERSION;
use qlab_remote_auth::annulet;

use super::*;

use crate::fixtures::{opening, real, recipient, rng, tree_of};
pub(crate) use crate::fixtures::{prepared_p, prepared_s, GENESIS_HASH, VALID_UNTIL};

/// An honest v2 spend, signed and attached, with what the builder knew.
pub(crate) struct Signed {
    pub(crate) tx: TxEntry,
    pub(crate) pvs: Vec<u32>,
    pub(crate) auth: Vec<AuthDescriptor>,
    intent: AnnuletIntent,
    shape: qlab_l2::Shape,
}

/// Sign `tx` as the device would and attach the section.
pub(crate) fn sign(
    mut tx: TxEntry,
    pvs: Vec<u32>,
    auth: Vec<AuthDescriptor>,
    shape: qlab_l2::Shape,
    local: &LocalAuth,
    dummies: &[&mldsa::Key],
) -> Signed {
    assert_eq!(
        tx.auth,
        qlab_devnet::annulet::L2_AUTH_ABSENT,
        "a builder leaves auth absent"
    );
    let intent = intent_for(
        &tx,
        ANNULET_AUTH_GENESIS_FORMAT_VERSION,
        &GENESIS_HASH,
        VALID_UNTIL,
        &auth,
    )
    .expect("an honest tx has an intent");
    let section = sign_locally(&intent, local, dummies).expect("every slot is ours or a dummy's");
    attach(&mut tx, &section).expect("a signed section encodes");
    Signed {
        tx,
        pvs,
        auth,
        intent,
        shape,
    }
}

/// [`prepared_s`], proved in process ([`prove_prepared`]) and signed.
pub(crate) fn fixture_s() -> &'static Signed {
    static F: OnceLock<Signed> = OnceLock::new();
    F.get_or_init(|| {
        let (prepared, local, key) = prepared_s();
        let built = prove_prepared(prepared);
        assert_eq!(built.shape, L2ShapeTag::S);
        sign(
            built.tx,
            built.pvs,
            built.auth,
            qlab_l2::Shape::S,
            &local,
            &[&key],
        )
    })
}

/// [`prepared_p`], proved in process and signed.
fn fixture_p() -> &'static Signed {
    static F: OnceLock<Signed> = OnceLock::new();
    F.get_or_init(|| {
        let (prepared, local, key) = prepared_p();
        let built = prove_prepared(prepared);
        assert_eq!(built.shape, L2ShapeTag::P);
        sign(
            built.tx,
            built.pvs,
            built.auth,
            qlab_l2::Shape::P,
            &local,
            &[&key],
        )
    })
}

/// R: a registration of Cloaked asset 9 paid by a 100 (asset 0) note, fee 7.
fn fixture_r() -> &'static Signed {
    static F: OnceLock<Signed> = OnceLock::new();
    F.get_or_init(|| {
        let mut rng = rng(0x5e6);
        let mut local = LocalAuth::new(&[0x53; 32], 0, 0).expect("depth D_AUTH");
        let fee_in = real(&mut local, 0x500, 100, 0);
        let tree = tree_of(&[&fee_in]);
        let reg = RegistryTree::from_leaves(&[RegistryLeaf::cloaked(0)]).unwrap();
        let slot = RegistrySlotOpening {
            height: 0,
            root: reg.root(),
            slot: 9,
            leaf: None,
            witness: reg.opening_at(9),
        };
        let change = recipient(0x51, &mut rng);
        let built = assemble_r_v2(
            &tree,
            &slot,
            &fee_in,
            &change,
            7,
            RegistryLeaf::cloaked(9),
            [0; 4],
            &mut rng,
        )
        .unwrap();
        sign(
            built.tx,
            built.pvs,
            built.auth,
            qlab_l2::Shape::R,
            &local,
            &[],
        )
    })
}

fn intent_shape(f: &Signed) -> annulet::Shape {
    f.intent.shape
}

/// The node's view of `tx`: the section decoded from `tx.auth`, and the
/// intent rebuilt from the transaction and the section's descriptors.
fn node_view(f: &Signed, tx: &TxEntry) -> (AnnuletAuthSection, Result<AnnuletIntent, IntentError>) {
    let section = AnnuletAuthSection::decode(intent_shape(f), &tx.auth)
        .expect("the attached section decodes");
    let descriptors: Vec<AuthDescriptor> = section.slots.iter().map(|s| s.descriptor).collect();
    let intent = intent_for(
        tx,
        ANNULET_AUTH_GENESIS_FORMAT_VERSION,
        &GENESIS_HASH,
        section.valid_until_height,
        &descriptors,
    );
    (section, intent)
}

fn round_trip(f: &Signed) {
    let proof: qlab_l2::Proof<qlab_l2::Config> =
        bincode::deserialize(&f.tx.proof).expect("the proof decodes");
    let ok = match f.shape {
        qlab_l2::Shape::S => qlab_l2::v2::verify_s_u32(&f.pvs, &proof),
        qlab_l2::Shape::P => qlab_l2::v2::verify_p_u32(&f.pvs, &proof),
        qlab_l2::Shape::R => qlab_l2::v2::verify_r_u32(&f.pvs, &proof),
    };
    assert!(ok, "{:?}: the v2 proof verifies", f.shape);
    assert_eq!(f.pvs.len(), qlab_l2::v2::pv_len(f.shape));
    let (section, intent) = node_view(f, &f.tx);
    assert_eq!(section.slots.len(), qlab_l2::v2::auth_slots(f.shape));
    // The leaves the node would put in the PVs are the ones the proof has.
    for (k, s) in section.slots.iter().enumerate() {
        assert_eq!(
            s.descriptor, f.auth[k],
            "slot {k}: the section carries the builder's descriptor"
        );
        let at = qlab_l2::v2::pv_leaf(f.shape, k);
        assert_eq!(
            f.pvs[at..at + 16],
            pv_chunks(&digest_from_bytes(&s.descriptor.leaf())),
            "slot {k}: leaf = PV leaf"
        );
    }
    let intent = intent.expect("the node rebuilds the intent");
    assert_eq!(
        intent, f.intent,
        "the node's intent is the device's (auth is not an input)"
    );
    assert_eq!(section.verify_intent(&intent), Ok(()));
    // Lab #896 F: the consensus check both funnels run accepts the real
    // proof's transaction as built and signed, at its last valid height.
    let ctx = qlab_devnet::annulet::AuthContext::candidate_a(GENESIS_HASH);
    let last = section.valid_until_height;
    assert_eq!(
        qlab_devnet::annulet::check_auth(&f.tx, &ctx, last),
        Ok(Some(last))
    );
}

#[test]
fn v2_s_builds_signs_attaches_and_verifies_at_2_20() {
    round_trip(fixture_s());
}

#[test]
fn v2_p_builds_signs_attaches_and_verifies_at_2_20() {
    round_trip(fixture_p());
}

#[test]
fn v2_r_builds_signs_attaches_and_verifies_at_2_19() {
    round_trip(fixture_r());
}

/// `tx` with `mutate` applied is refused: its intent no longer rebuilds, or
/// the section's signatures do not verify over the rebuilt one.
fn refused(
    f: &Signed,
    what: &str,
    mutate: &dyn Fn(&mut TxEntry),
) -> Result<AuthError, IntentError> {
    let mut tx = f.tx.clone();
    mutate(&mut tx);
    let (section, intent) = node_view(f, &tx);
    match intent {
        Err(e) => Err(e),
        Ok(intent) => {
            assert_ne!(intent, f.intent, "{what}: the intent moved");
            Ok(section.verify_intent(&intent).expect_err(what))
        }
    }
}

fn changed_fields_break_the_signature(f: &Signed) {
    let bad = |what: &str, m: &dyn Fn(&mut TxEntry)| {
        let got = refused(f, what, m);
        assert!(
            matches!(got, Ok(AuthError::BadSignature { slot: 0 })),
            "{what}: {got:?}"
        );
    };
    bad("fee", &|tx| tx.public.fee += 1);
    bad("anchor", &|tx| tx.public.anchor[0] ^= 1);
    bad("last nullifier", &|tx| {
        tx.public.nullifiers.last_mut().unwrap()[31] ^= 1
    });
    bad("commitment 1", &|tx| tx.public.commitments[1][0] ^= 1);
    bad("bucket", &|tx| tx.public.bucket = ArityBucket::FourByFour);
    bad("surface registry root", &|tx| tx.l2[1] ^= 1);
    bad("discovery payload byte", &|tx| {
        *tx.discovery.last_mut().unwrap() ^= 1
    });
    // A surface that does not decode canonically has no intent at all.
    let got = refused(f, "trailing surface byte", &|tx| tx.l2.push(0));
    assert!(
        matches!(
            got,
            Err(IntentError::Surface(L2SurfaceError::WrongLength { .. }))
        ),
        "{got:?}"
    );
    let got = refused(f, "trailing discovery byte", &|tx| tx.discovery.push(0));
    assert!(matches!(got, Err(IntentError::Discovery(_))), "{got:?}");
    let got = refused(f, "absent surface", &|tx| tx.l2 = vec![0]);
    assert!(matches!(got, Err(IntentError::NoSurface)), "{got:?}");
}

/// The intent's own inputs: the genesis, the validity, the descriptors.
fn changed_context_breaks_the_section(f: &Signed) {
    let (section, _) = node_view(f, &f.tx);
    let rebuild = |format: u32, hash: &Hash32, until: u64, auth: &[AuthDescriptor]| {
        section.verify_intent(&intent_for(&f.tx, format, hash, until, auth).unwrap())
    };
    let (fmt, until) = (ANNULET_AUTH_GENESIS_FORMAT_VERSION, VALID_UNTIL);
    assert_eq!(
        rebuild(fmt + 1, &GENESIS_HASH, until, &f.auth),
        Err(AuthError::BadSignature { slot: 0 })
    );
    assert_eq!(
        rebuild(fmt, &[0x6f; 32], until, &f.auth),
        Err(AuthError::BadSignature { slot: 0 })
    );
    assert_eq!(
        rebuild(fmt, &GENESIS_HASH, until + 1, &f.auth),
        Err(AuthError::ValidityMismatch)
    );
    let mut auth = f.auth.clone();
    let AuthDescriptor::MlDsa44 { leaf_index, .. } = &mut auth[0] else {
        unreachable!("ML-DSA-44")
    };
    *leaf_index ^= 1;
    assert_eq!(
        rebuild(fmt, &GENESIS_HASH, until, &auth),
        Err(AuthError::DescriptorMismatch { slot: 0 })
    );
}

#[test]
fn v2_s_intent_binds_every_field() {
    changed_fields_break_the_signature(fixture_s());
    changed_context_breaks_the_section(fixture_s());
}

#[test]
fn v2_p_intent_binds_every_field() {
    let f = fixture_p();
    changed_fields_break_the_signature(f);
    changed_context_breaks_the_section(f);
    // A zero vPublic term re-encoded with its redeem byte set: the same
    // "no issuance", spelled a second way, has no intent (2b §6).
    let got = refused(f, "non-canonical zero term", &|tx| tx.l2[33] = 1);
    assert!(
        matches!(
            got,
            Err(IntentError::Surface(L2SurfaceError::NonCanonicalZeroTerm {
                row: 0
            }))
        ),
        "{got:?}"
    );
    let got = refused(f, "exit recipient", &|tx| *tx.l2.last_mut().unwrap() ^= 1);
    assert!(
        matches!(got, Ok(AuthError::BadSignature { slot: 0 })),
        "{got:?}"
    );
}

#[test]
fn v2_r_intent_binds_every_field() {
    let f = fixture_r();
    changed_fields_break_the_signature(f);
    changed_context_breaks_the_section(f);
    let got = refused(f, "written leaf lane", &|tx| {
        *tx.l2.last_mut().unwrap() ^= 1
    });
    assert!(
        matches!(got, Ok(AuthError::BadSignature { slot: 0 })),
        "{got:?}"
    );
}

/// The single-party signer refuses a slot it holds no key for, by name and
/// before signing anything; and a dummy slot needs its ephemeral key.
#[test]
fn sign_locally_refuses_a_slot_it_cannot_sign() {
    let f = fixture_r();
    let stranger = LocalAuth::new(&[0x54; 32], 0, 0).unwrap();
    assert_eq!(
        sign_locally(&f.intent, &stranger, &[]).unwrap_err(),
        AuthError::LeafMismatch { slot: 0 }
    );
    let s = fixture_s();
    let owner = LocalAuth::new(&[0x51; 32], 0, 0).unwrap();
    assert_eq!(
        sign_locally(&s.intent, &owner, &[]).unwrap_err(),
        AuthError::LeafMismatch { slot: 2 }
    );
}

/// A dummy slot (`dv`) that carries value is refused by name before anything
/// is built — `build_bucket_l2_v2` would otherwise assert on device input.
#[test]
fn a_non_empty_dummy_slot_is_refused_by_name() {
    let mut rng = rng(0xd0d);
    let mut local = LocalAuth::new(&[0x52; 32], 0, 0).expect("depth D_AUTH");
    let a = real(&mut local, 0x300, 100, 0);
    let b = real(&mut local, 0x400, 50, 7);
    let tree = tree_of(&[&a]);
    let reg =
        RegistryTree::from_leaves(&[RegistryLeaf::cloaked(0), RegistryLeaf::cloaked(7)]).unwrap();
    let regs = [opening(&reg, 0), opening(&reg, 7)];
    let (dummy, _) = local
        .dummy(&[0xd6; 32], 2, &[a.auth.leaf_index, b.auth.leaf_index])
        .unwrap();
    let outs = [
        Out {
            to: recipient(0x33, &mut rng),
            value: 90,
            asset: 0,
        },
        Out {
            to: recipient(0x34, &mut rng),
            value: 0,
            asset: 0,
        },
    ];
    let err = assemble_s_v2(
        &tree,
        &regs,
        [&a, &b],
        true,
        FeeIn::Dummy(&dummy),
        &outs,
        10,
        &mut rng,
    )
    .err()
    .expect("refused");
    assert_eq!(
        err,
        SpendError::DummyNotEmpty {
            value: 50,
            asset: 7
        }
    );
}
