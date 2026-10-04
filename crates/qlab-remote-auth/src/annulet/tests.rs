//! Seam A tests (lab #896). Every hex vector here was computed independently
//! with pycryptodome's Keccak-256 (script in the PR body), not by this code.

use super::*;
use crate::{
    codec,
    intent::{fixture_intent, Scheme},
    tree::{air_node, root_with},
};

fn b(x: u8) -> Hash32 {
    [x; 32]
}

fn desc(leaf_index: u32, leaf: u8) -> AuthDescriptor {
    AuthDescriptor::MlDsa44 {
        leaf_index,
        leaf: b(leaf),
    }
}

/// The all-fields fixture: S has three slots, R one.
fn fixture(shape: Shape) -> AnnuletIntent {
    let (nullifiers, auth) = match shape {
        Shape::S | Shape::P => (
            vec![b(0x31), b(0x32), b(0x33)],
            vec![desc(7, 0x81), desc(9, 0x82), desc(11, 0x83)],
        ),
        Shape::R => (vec![b(0x31)], vec![desc(7, 0x81)]),
    };
    AnnuletIntent {
        genesis_format: 6,
        genesis_hash: b(0x11),
        shape,
        anchor: b(0x22),
        nullifiers,
        commitments: [b(0x41), b(0x42)],
        bucket: 0x02,
        valid_until_height: 1_000_256,
        fee: 0x0102_0304_0506_0708,
        registry_root: b(0x71),
        surface_hash: b(0x72),
        discovery_hash: b(0x51),
        auth,
    }
}

/// A fixture whose descriptors come from real keys, signed.
fn signed(shape: Shape) -> (AnnuletIntent, AnnuletAuthSection) {
    let keys: Vec<mldsa::Key> = (0..shape.slots())
        .map(|i| mldsa::Key::from_seed(b(0xa0 + i as u8)))
        .collect();
    let mut intent = fixture(shape);
    intent.auth = keys
        .iter()
        .enumerate()
        .map(|(i, k)| k.descriptor(100 + i as u32))
        .collect();
    let refs: Vec<&mldsa::Key> = keys.iter().collect();
    let section = AnnuletAuthSection::sign(&intent, &refs).unwrap();
    (intent, section)
}

// ------------------------------------------------------------------ intent

#[test]
fn intent_is_fixed_width_and_matches_the_independent_vectors() {
    let s = fixture(Shape::S);
    assert_eq!(s.encode().unwrap().len(), 489);
    assert_eq!(AnnuletIntent::encoded_len_for(Shape::S), 489);
    assert_eq!(AnnuletIntent::encoded_len_for(Shape::P), 489);
    assert_eq!(
        crate::hex(&s.digest().unwrap()),
        "b5409f0a937b3eca80d2a01d553e6e8fcbf30a870ae1a483d95da5d4b17c6397"
    );
    let r = fixture(Shape::R);
    assert_eq!(r.encode().unwrap().len(), 353);
    assert_eq!(
        crate::hex(&r.digest().unwrap()),
        "545e332f5e9da23d10726f32d8b6e759e9ca3aa18384afc8f4f668c26e376121"
    );
    assert!(s.encode().unwrap().starts_with(INTENT_DOMAIN));
}

#[test]
fn every_intent_field_changes_the_digest() {
    let base = fixture(Shape::S);
    let expected = base.digest().unwrap();
    let mut variants: Vec<AnnuletIntent> = Vec::new();
    macro_rules! vary {
        ($f:expr) => {{
            let mut v = base.clone();
            let f = $f;
            f(&mut v);
            variants.push(v);
        }};
    }
    vary!(|v: &mut AnnuletIntent| v.genesis_format ^= 1);
    vary!(|v: &mut AnnuletIntent| v.genesis_hash[0] ^= 1);
    vary!(|v: &mut AnnuletIntent| v.shape = Shape::P);
    vary!(|v: &mut AnnuletIntent| v.anchor[0] ^= 1);
    for i in 0..3 {
        vary!(|v: &mut AnnuletIntent| v.nullifiers[i][0] ^= 1);
    }
    vary!(|v: &mut AnnuletIntent| v.commitments[0][0] ^= 1);
    vary!(|v: &mut AnnuletIntent| v.commitments[1][0] ^= 1);
    vary!(|v: &mut AnnuletIntent| v.bucket ^= 1);
    vary!(|v: &mut AnnuletIntent| v.valid_until_height ^= 1);
    vary!(|v: &mut AnnuletIntent| v.fee ^= 1);
    vary!(|v: &mut AnnuletIntent| v.registry_root[0] ^= 1);
    vary!(|v: &mut AnnuletIntent| v.surface_hash[0] ^= 1);
    vary!(|v: &mut AnnuletIntent| v.discovery_hash[0] ^= 1);
    for i in 0..3 {
        vary!(|v: &mut AnnuletIntent| {
            let AuthDescriptor::MlDsa44 { leaf_index, .. } = &mut v.auth[i] else {
                unreachable!()
            };
            *leaf_index ^= 1;
        });
        vary!(|v: &mut AnnuletIntent| {
            let AuthDescriptor::MlDsa44 { leaf, .. } = &mut v.auth[i] else {
                unreachable!()
            };
            leaf[0] ^= 1;
        });
    }
    // Slot order is bound too: swapping two slots is a different intent.
    vary!(|v: &mut AnnuletIntent| v.auth.swap(0, 1));
    vary!(|v: &mut AnnuletIntent| v.nullifiers.swap(1, 2));
    assert_eq!(variants.len(), 23);
    for (i, v) in variants.iter().enumerate() {
        assert_ne!(
            v.digest().unwrap(),
            expected,
            "intent mutation {i} was not bound"
        );
    }
}

#[test]
fn intent_shape_is_enforced() {
    let mut v = fixture(Shape::S);
    v.nullifiers.pop();
    assert_eq!(
        v.encode(),
        Err(AuthError::SlotCount {
            expected: 3,
            got: 2
        })
    );
    let mut v = fixture(Shape::R);
    v.auth.push(desc(1, 1));
    assert_eq!(
        v.encode(),
        Err(AuthError::SlotCount {
            expected: 1,
            got: 2
        })
    );
    let mut v = fixture(Shape::R);
    v.auth[0] = AuthDescriptor::WotsSha2 {
        public_seed: b(1),
        leaf_index: 7,
        leaf: b(0x81),
    };
    assert!(matches!(v.encode(), Err(AuthError::Malformed(_))));
    assert_eq!(Shape::from_tag(Shape::P.tag()), Some(Shape::P));
    assert_eq!(Shape::from_tag(0), None);
    assert_eq!(Shape::from_tag(4), None);
}

#[test]
fn an_l1_authorization_never_verifies_an_annulet_intent() {
    // The domains differ, so the digests differ...
    let l1_key = mldsa::Key::from_seed(b(0xa0));
    let l1 = fixture_intent(
        Scheme::MlDsa44,
        [l1_key.descriptor(100), l1_key.descriptor(101)],
    );
    let l1_digest = l1.digest();
    // ...and a signature the device made for L1 fails as an Annulet one.
    let (intent, mut section) = signed(Shape::R);
    assert_eq!(section.slots[0].descriptor, l1_key.descriptor(100));
    section.slots[0].signature = l1_key.sign(&l1_digest);
    assert_eq!(
        section.verify_intent(&intent),
        Err(AuthError::BadSignature { slot: 0 })
    );
    // The L1 section (version 1) is not an Annulet section, and vice versa.
    let l1_section = codec::AuthSection::new(
        Scheme::MlDsa44,
        std::array::from_fn(|i| codec::Slot::MlDsa44 {
            descriptor: l1.auth[i],
            verifying_key: l1_key.verifying_key_bytes(),
            signature: l1_key.sign(&l1_digest),
        }),
    )
    .unwrap();
    assert!(matches!(
        AnnuletAuthSection::decode(Shape::S, &l1_section.encode().unwrap()),
        Err(AuthError::Malformed(_))
    ));
    let (_, annulet) = signed(Shape::S);
    assert!(codec::AuthSection::decode(&annulet.encode().unwrap()).is_err());
}

// ----------------------------------------------------------------- section

#[test]
fn section_lengths_round_trip_and_refusals() {
    assert_eq!(AnnuletAuthSection::encoded_len_for(Shape::S), 11_320);
    assert_eq!(AnnuletAuthSection::encoded_len_for(Shape::P), 11_320);
    assert_eq!(AnnuletAuthSection::encoded_len_for(Shape::R), 3_784);

    for shape in [Shape::S, Shape::R] {
        let (intent, section) = signed(shape);
        let bytes = section.encode().unwrap();
        assert_eq!(bytes.len(), AnnuletAuthSection::encoded_len_for(shape));
        assert_eq!(&bytes[8..16], &intent.valid_until_height.to_le_bytes());
        let decoded = AnnuletAuthSection::decode(shape, &bytes).unwrap();
        assert_eq!(decoded, section);
        assert_eq!(decoded.encode().unwrap(), bytes);
        decoded.verify_intent(&intent).unwrap();

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            AnnuletAuthSection::decode(shape, &trailing),
            Err(AuthError::Malformed(_))
        ));
        assert!(matches!(
            AnnuletAuthSection::decode(shape, &bytes[..bytes.len() - 1]),
            Err(AuthError::Malformed(_))
        ));
        assert!(matches!(
            AnnuletAuthSection::decode(shape, &bytes[..10]),
            Err(AuthError::Malformed(_))
        ));
        let mut magic = bytes.clone();
        magic[0] ^= 1;
        assert!(matches!(
            AnnuletAuthSection::decode(shape, &magic),
            Err(AuthError::Malformed(_))
        ));
        let mut version = bytes.clone();
        version[4] = 1;
        assert!(matches!(
            AnnuletAuthSection::decode(shape, &version),
            Err(AuthError::Malformed(_))
        ));
        let mut scheme = bytes.clone();
        scheme[6] = 2;
        assert_eq!(
            AnnuletAuthSection::decode(shape, &scheme),
            Err(AuthError::Scheme(2))
        );
    }
    // A 3-slot section presented for R, and a 1-slot one for S: named.
    let (_, s) = signed(Shape::S);
    assert_eq!(
        AnnuletAuthSection::decode(Shape::R, &s.encode().unwrap()),
        Err(AuthError::SlotCount {
            expected: 1,
            got: 3
        })
    );
    let (_, r) = signed(Shape::R);
    assert_eq!(
        AnnuletAuthSection::decode(Shape::S, &r.encode().unwrap()),
        Err(AuthError::SlotCount {
            expected: 3,
            got: 1
        })
    );
}

#[test]
fn verify_refuses_each_failure_by_name() {
    let (intent, section) = signed(Shape::S);
    section.verify_intent(&intent).unwrap();

    // A worker-changed intent: every signature is now over something else.
    let mut changed = intent.clone();
    changed.commitments[1][0] ^= 1;
    assert_eq!(
        section.verify_intent(&changed),
        Err(AuthError::BadSignature { slot: 0 })
    );

    // The header's validity must equal the intent's.
    let mut v = section.clone();
    v.valid_until_height += 1;
    assert_eq!(v.verify_intent(&intent), Err(AuthError::ValidityMismatch));

    // A descriptor that differs from the intent's.
    let mut d = section.clone();
    let AuthDescriptor::MlDsa44 { leaf_index, .. } = &mut d.slots[2].descriptor else {
        unreachable!()
    };
    *leaf_index ^= 1;
    assert_eq!(
        d.verify_intent(&intent),
        Err(AuthError::DescriptorMismatch { slot: 2 })
    );

    // A leaf that is not mldsa_leaf(index, vk): swap in another slot's key.
    let mut l = section.clone();
    l.slots[1].verifying_key = section.slots[0].verifying_key.clone();
    assert_eq!(
        l.verify_intent(&intent),
        Err(AuthError::LeafMismatch { slot: 1 })
    );

    // A bad signature on one slot only.
    let mut s = section.clone();
    s.slots[2].signature[0] ^= 1;
    assert_eq!(
        s.verify_intent(&intent),
        Err(AuthError::BadSignature { slot: 2 })
    );

    // Wrong slot count against the intent.
    let mut c = section.clone();
    c.slots.pop();
    assert_eq!(
        c.verify_intent(&intent),
        Err(AuthError::SlotCount {
            expected: 3,
            got: 2
        })
    );
}

#[test]
fn expiry_is_inclusive_and_named() {
    assert_eq!(check_expiry(100, 99), Ok(()));
    assert_eq!(check_expiry(100, 100), Ok(()));
    assert_eq!(
        check_expiry(100, 101),
        Err(AuthError::Expired {
            valid_until_height: 100,
            height: 101
        })
    );
}

// -------------------------------------------------------------------- keys

#[test]
fn auth_master_and_leaf_seed_match_the_independent_vectors() {
    let m0 = auth_master(&b(0x07), 0);
    assert_eq!(
        crate::hex(&m0),
        "85408beec62812c0d82c85eb36e5ce4db7424f173ab522eb5905beb0426696f2"
    );
    assert_eq!(
        crate::hex(&auth_master(&b(0x07), 1)),
        "bb46f8f24ac5abbb34c868d82703cdeceaf0833289c21db2c146b619d08075a4"
    );
    assert_eq!(
        crate::hex(&leaf_seed(&m0, 5)),
        "50cd0d59297d043298659fb32af042176dfc15bdbafd21241181f556a68e27d4"
    );
    // The v1 leaf seed is not the spike's.
    assert_ne!(leaf_seed(&m0, 5), mldsa::derive_leaf_seed(&m0, 5));
    assert_eq!(
        leaf_key(&m0, 5).descriptor(5).leaf(),
        mldsa_leaf(5, &leaf_key(&m0, 5).verifying_key_bytes())
    );
}

#[test]
fn auth_tree_paths_fold_to_its_root() {
    let m = auth_master(&b(0x07), 0);
    let tree = AuthTree::build(&m, 3).unwrap();
    let leaves: Vec<Hash32> = (0..8).map(|i| tree.leaf(i)).collect();
    assert_eq!(
        tree.root(),
        root_with(TreeVersion::AirMerkle, leaves.clone()).unwrap()
    );
    for i in 0..8u32 {
        let path = tree.path(i);
        assert_eq!(path.len(), 3);
        assert_eq!(fold_auth_path(tree.leaf(i), i, &path), tree.root());
        assert_ne!(fold_auth_path(tree.leaf(i), i ^ 1, &path), tree.root());
    }
    // The next generation is a different tree.
    let next = AuthTree::build(&auth_master(&b(0x07), 1), 3).unwrap();
    assert_ne!(next.root(), tree.root());
    // from_leaves agrees with the hand-built root of the shared vector.
    let synth = AuthTree::from_leaves(1, vec![b(1), b(2)]).unwrap();
    assert_eq!(synth.root(), air_node(&b(1), &b(2)));
}

// ------------------------------------------------------------------ cursor

#[test]
fn cursor_walks_the_private_permutation_and_matches_the_vector() {
    let m = auth_master(&b(0x07), 0);
    let mut c = Cursor::new(&m, D_AUTH, 0).unwrap();
    assert_eq!(c.remaining(), 4_096);
    let head: Vec<u32> = (0..8).map(|_| c.take().unwrap()).collect();
    assert_eq!(head, [2885, 2468, 2547, 1833, 598, 489, 3350, 2930]);
    assert_eq!(c.next(), 8);
    for &i in &head {
        assert!(c.is_consumed(i));
    }
    // Resuming from a persisted position reproduces the same state.
    let resumed = Cursor::new(&m, D_AUTH, 8).unwrap();
    for i in 0..4_096u32 {
        assert_eq!(resumed.is_consumed(i), c.is_consumed(i));
    }
    assert!(Cursor::new(&m, D_AUTH, 4_097).is_err());
    // Not a counter: the first indices are not 0, 1, 2, ...
    assert_ne!(head[..3], [0, 1, 2]);
}

#[test]
fn cursor_exhausts_without_repeating() {
    let mut c = Cursor::new(&auth_master(&b(0x09), 0), 4, 0).unwrap();
    let mut seen: Vec<u32> = std::iter::from_fn(|| c.take()).collect();
    assert_eq!(seen.len(), 16);
    assert_eq!(c.remaining(), 0);
    assert_eq!(c.take(), None);
    seen.sort_unstable();
    assert_eq!(seen, (0..16).collect::<Vec<_>>());
}

// ------------------------------------------------------------------- dummy

#[test]
fn dummy_index_avoids_consumed_and_taken_positions_and_covers_the_rest() {
    let m = auth_master(&b(0x0b), 0);
    let mut cursor = Cursor::new(&m, 4, 0).unwrap();
    let consumed: Vec<u32> = (0..10).map(|_| cursor.take().unwrap()).collect();
    let real = cursor.take().unwrap(); // this transaction's real slot
    let taken = [real];
    let free: Vec<u32> = (0..16)
        .filter(|i| !consumed.contains(i) && *i != real)
        .collect();
    assert_eq!(free.len(), 5);
    let mut hits = [0u32; 16];
    for e in 0..400u32 {
        let mut entropy = [0u8; 32];
        entropy[..4].copy_from_slice(&e.to_le_bytes());
        let d = draw_dummy(&entropy, 4, &cursor, &taken).unwrap();
        assert!(
            free.contains(&d.leaf_index),
            "dummy drew {} outside the free set",
            d.leaf_index
        );
        hits[d.leaf_index as usize] += 1;
    }
    // Every free position is reachable (uniform: ~80 each of 400).
    for i in &free {
        assert!(
            hits[*i as usize] > 40,
            "free position {i} drawn only {} times",
            hits[*i as usize]
        );
    }
    // Drawing does not consume.
    assert_eq!(cursor.next(), 11);
}

#[test]
fn dummy_is_device_fixed_and_cannot_be_upgraded() {
    let m = auth_master(&b(0x0d), 0);
    let cursor = Cursor::new(&m, 3, 0).unwrap();
    let d = draw_dummy(&b(0x01), 3, &cursor, &[]).unwrap();
    assert_eq!(d.auth_path.len(), 3);
    assert_eq!(
        fold_auth_path(d.descriptor.leaf(), d.leaf_index, &d.auth_path),
        d.auth_root
    );
    assert_eq!(d.descriptor, d.key.descriptor(d.leaf_index));
    // Its root is in no real tree, so no note of this key can carry it.
    assert_ne!(d.auth_root, AuthTree::build(&m, 3).unwrap().root());
    // Deterministic in the device's entropy, distinct across entropy.
    let again = draw_dummy(&b(0x01), 3, &cursor, &[]).unwrap();
    assert_eq!(
        (again.nk, again.rho, again.rseed, again.auth_root),
        (d.nk, d.rho, d.rseed, d.auth_root)
    );
    let other = draw_dummy(&b(0x02), 3, &cursor, &[]).unwrap();
    assert_ne!(other.nk, d.nk);
    assert_ne!(other.rho, d.rho);
    // No free position: refused, never a reused index.
    let mut full = Cursor::new(&m, 2, 0).unwrap();
    while full.take().is_some() {}
    assert!(draw_dummy(&b(0x01), 2, &full, &[]).is_err());
}

#[test]
fn one_real_and_two_dummy_slots_sign_one_intent() {
    let m = auth_master(&b(0x0f), 0);
    let mut cursor = Cursor::new(&m, 3, 0).unwrap();
    let real_index = cursor.take().unwrap();
    let real_key = leaf_key(&m, real_index);
    let d2 = draw_dummy(&b(0x21), 3, &cursor, &[real_index]).unwrap();
    let d3 = draw_dummy(&b(0x22), 3, &cursor, &[real_index, d2.leaf_index]).unwrap();
    let indices = [real_index, d2.leaf_index, d3.leaf_index];
    assert!(indices[0] != indices[1] && indices[1] != indices[2] && indices[0] != indices[2]);

    let mut intent = fixture(Shape::S);
    intent.auth = vec![
        real_key.descriptor(real_index),
        d2.descriptor,
        d3.descriptor,
    ];
    let section = AnnuletAuthSection::sign(&intent, &[&real_key, &d2.key, &d3.key]).unwrap();
    section.verify_intent(&intent).unwrap();
    // A worker that swaps in its own dummy key changes the descriptor the
    // device signed, so the section no longer matches the intent.
    let worker_key = mldsa::Key::from_seed(b(0xee));
    let mut forged = section.clone();
    forged.slots[2] = AuthSlot {
        descriptor: worker_key.descriptor(d3.leaf_index),
        verifying_key: worker_key.verifying_key_bytes(),
        signature: worker_key.sign(&intent.digest().unwrap()),
    };
    assert_eq!(
        forged.verify_intent(&intent),
        Err(AuthError::DescriptorMismatch { slot: 2 })
    );
}
