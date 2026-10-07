//! **Honest Candidate A S and P spends for tests** (lab #924): the v2
//! round trips' fixtures, shared with the bundle tests and — behind the
//! `fixtures` feature, a dev-dependency only — with the prover service's
//! tests. Fixed seeds, fixed keys: nothing here is a secret, and nothing
//! here is compiled into a release binary.

use qlab_air::l2::{L2AuthInput, RegistryLeaf, MODE_HYBRID};
use qlab_air::l2p::{CanonicalFreezeTree, VPublic};
use qlab_cbserver::registry::{RegistryOpening, RegistryTree};
use qlab_cbserver::tree::CommitmentTree;
use qlab_devnet::annulet::L2ShapeTag;
use qlab_devnet::forms::ANNULET_AUTH_GENESIS_FORMAT_VERSION;
use qlab_remote_auth::{mldsa, Hash32};
use rand::SeedableRng;

use crate::bundle::ProvingBundle;
use crate::v2::{
    assemble_s_v2, attach, cm_of_v2, intent_for, policies_then_p_v2, sign_locally, FeeIn,
    LocalAuth, PreparedV2,
};
use crate::{Out, PolicyContext, Recipient};

/// The genesis hash the fixtures sign for (format 33).
pub const GENESIS_HASH: Hash32 = [0x6e; 32];
/// The height the fixtures' sections are valid until.
pub const VALID_UNTIL: u64 = 4_096;

pub fn rng(seed: u64) -> rand::rngs::StdRng {
    rand::rngs::StdRng::seed_from_u64(seed)
}

/// A real slot input: a note of `value`/`asset` under the address
/// `(nk, d, auth_root)`, its authorization path the cursor's next leaf.
pub fn real(auth: &mut LocalAuth, seed: u64, value: u64, asset: u64) -> L2AuthInput {
    L2AuthInput {
        nk: [seed, seed + 1, seed + 2, seed + 3],
        value,
        asset,
        rho: [seed + 4; 4],
        rseed: [seed + 5; 4],
        d: [seed + 6, seed + 7],
        auth: auth.take().expect("a fresh generation has leaves"),
    }
}

pub fn tree_of(inputs: &[&L2AuthInput]) -> CommitmentTree {
    let mut tree = CommitmentTree::new();
    tree.append([0xc0ffee; 4]);
    for i in inputs {
        tree.append(cm_of_v2(i));
    }
    tree
}

pub fn opening(reg: &RegistryTree, asset: u16) -> RegistryOpening {
    RegistryOpening {
        height: 0,
        root: reg.root(),
        leaf: *reg.leaf(asset).expect("a registered asset"),
        witness: reg.witness(asset).expect("a registered asset"),
    }
}

pub fn recipient<R: rand::CryptoRng>(seed: u64, rng: &mut R) -> Recipient {
    Recipient {
        rkm: [seed; 4],
        ek: qlab_note::kem::generate_keypair(rng).ek,
    }
}

/// S: 100 (asset 0) + 50 (Cloaked asset 7) → 90 + 50, fee 10, slot 3 a
/// device-made dummy. Prepared only — no proof — with the signer and the
/// dummy's key: the bundle tests (lab #924) prepare it again and compare.
pub fn prepared_s() -> (PreparedV2, LocalAuth, mldsa::Key) {
    let mut rng = rng(0x5e4);
    let mut local = LocalAuth::new(&[0x51; 32], 0, 0).expect("depth D_AUTH");
    let a = real(&mut local, 0x100, 100, 0);
    let b = real(&mut local, 0x200, 50, 7);
    let tree = tree_of(&[&a, &b]);
    let reg =
        RegistryTree::from_leaves(&[RegistryLeaf::cloaked(0), RegistryLeaf::cloaked(7)]).unwrap();
    let regs = [opening(&reg, 0), opening(&reg, 7)];
    let (dummy, key) = local
        .dummy(&[0xd5; 32], 2, &[a.auth.leaf_index, b.auth.leaf_index])
        .unwrap();
    let outs = [
        Out {
            to: recipient(0x31, &mut rng),
            value: 90,
            asset: 0,
        },
        Out {
            to: recipient(0x32, &mut rng),
            value: 50,
            asset: 7,
        },
    ];
    let prepared = assemble_s_v2(
        &tree,
        &regs,
        [&a, &b],
        false,
        FeeIn::Dummy(&dummy),
        &outs,
        10,
        &mut rng,
    )
    .unwrap();
    (prepared, local, key)
}

/// P: 100 (asset 0) + 50 of Hybrid asset 7 (empty freeze list) → 90 + 50,
/// fee 10, slot 3 a device-made dummy, `vPublic` none. Prepared only.
pub fn prepared_p() -> (PreparedV2, LocalAuth, mldsa::Key) {
    let mut rng = rng(0x5e5);
    let mut local = LocalAuth::new(&[0x52; 32], 0, 0).expect("depth D_AUTH");
    let a = real(&mut local, 0x300, 100, 0);
    let b = real(&mut local, 0x400, 50, 7);
    let tree = tree_of(&[&a, &b]);
    let hybrid = RegistryLeaf {
        asset: 7,
        issuer_key: qlab_air::l2p::issuer_key_of(&[7; 4]),
        mode: MODE_HYBRID,
        freeze_root: CanonicalFreezeTree::from_rkms(&[]).root,
        allow_root: [0; 4],
        flags: 0,
    };
    let reg = RegistryTree::from_leaves(&[RegistryLeaf::cloaked(0), hybrid]).unwrap();
    let regs = [opening(&reg, 0), opening(&reg, 7)];
    let (dummy, key) = local
        .dummy(&[0xd6; 32], 2, &[a.auth.leaf_index, b.auth.leaf_index])
        .unwrap();
    let outs = [
        Out {
            to: recipient(0x41, &mut rng),
            value: 90,
            asset: 0,
        },
        Out {
            to: recipient(0x42, &mut rng),
            value: 50,
            asset: 7,
        },
    ];
    let ctx = PolicyContext::default();
    let prepared = policies_then_p_v2(
        &tree,
        &regs,
        [&a, &b],
        FeeIn::Dummy(&dummy),
        &outs,
        10,
        [&ctx, &ctx],
        [VPublic::NONE; 2],
        &mut rng,
    )
    .unwrap();
    (prepared, local, key)
}

/// [`prepared_s`] or [`prepared_p`], signed as the device signs it, as a
/// [`ProvingBundle`] — what a prover is handed.
pub fn signed_bundle(shape: L2ShapeTag) -> ProvingBundle {
    signed_bundles(shape, &[VALID_UNTIL]).remove(0)
}

/// The same prepared spend signed once per validity height: one bundle per
/// height, each a distinct intent (tests that need several jobs).
pub fn signed_bundles(shape: L2ShapeTag, valid_until: &[u64]) -> Vec<ProvingBundle> {
    let (p, local, key) = match shape {
        L2ShapeTag::S => prepared_s(),
        L2ShapeTag::P => prepared_p(),
        L2ShapeTag::R => panic!("shape R is never a bundle"),
    };
    valid_until
        .iter()
        .map(|until| {
            let mut tx = p.tx.clone();
            let intent = intent_for(
                &tx,
                ANNULET_AUTH_GENESIS_FORMAT_VERSION,
                &GENESIS_HASH,
                *until,
                &p.auth,
            )
            .expect("an honest tx has an intent");
            let section =
                sign_locally(&intent, &local, &[&key]).expect("every slot is ours or a dummy's");
            attach(&mut tx, &section).expect("a signed section encodes");
            ProvingBundle::new(tx, p.witness.clone()).expect("an honest holder spend is a bundle")
        })
        .collect()
}
