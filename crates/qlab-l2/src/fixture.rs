//! The deterministic shape-S, shape-P and shape-R instances — one source.
//!
//! These are the instances W3 measured (`qlab-bench l2shape`, lab #700,
//! `docs/w3-run{1..4}.md`), moved here unchanged so the bench, this crate's
//! goldens and any downstream test all build the *same* witness. The bench's
//! `shape_s_instance` / `shape_p_instance` delegate to these.
//!
//! Nothing here is a consensus object: a fixture is a test witness. What the
//! freeze pins from it is its public-value vector (`GOLDEN_PV_S` / `_P`) —
//! a regression lock on the PV layout and on every host hash that feeds it.

use qlab_air::l2::{build_bucket_l2, L2BucketInstance, L2TxInput, L2TxOutput};
use qlab_air::l2::{
    build_bucket_l2_with_witnesses, derive_input_l2, fabricated_registry_tree, fabricated_tree3,
    FeeSlot,
};
use qlab_air::l2::{RegistryLeaf, MODE_HYBRID};
use qlab_air::l2p::{build_bucket_l2p, issuer_key_of, L2PBucketInstance, PolicyAsset, VPublic};
use qlab_air::l2p::{build_bucket_l2p_with_witnesses, derive_rkm_l2};
use qlab_air::l2r::{build_shape_r, registry_opening, L2ShapeRInstance, RegistryWrite, SeedOutput};

/// The fixtures' xorshift64 stream (the bench's, verbatim).
struct Rnd(u64);

impl Rnd {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn d4(&mut self) -> [u64; 4] {
        [self.next(), self.next(), self.next(), self.next()]
    }
    fn input(&mut self, value: u64, asset: u64) -> L2TxInput {
        let sk = self.d4();
        let rho = self.d4();
        let rseed = self.d4();
        let d = [self.next(), self.next()];
        L2TxInput { sk, value, asset, rho, rseed, d }
    }
    fn output(&mut self, value: u64, asset: u64) -> L2TxOutput {
        let rkm = self.d4();
        let rho = self.d4();
        let rseed = self.d4();
        L2TxOutput { value, asset, rkm, rho, rseed }
    }
}

/// Seed of both fixtures' streams (the bench's).
const SEED: u64 = 0xfeed_face_cafe_beef;

/// Shape S at `log_height`: asset 0 (50,000) + asset 7 (30,000) in, 49,000
/// (asset 0) + 30,000 (asset 7) out, fee 1,000. Both registry leaves Cloaked.
pub fn shape_s_at(log_height: usize) -> L2BucketInstance {
    let mut r = Rnd(SEED);
    let inputs = [r.input(50_000, 0), r.input(30_000, 7)];
    let outputs = [r.output(49_000, 0), r.output(30_000, 7)];
    build_bucket_l2(log_height, &inputs, &outputs, 1_000)
}

/// Shape S at its own height (2^19).
pub fn shape_s() -> L2BucketInstance {
    shape_s_at(crate::LOG_HEIGHT_S)
}

/// The fixture's issuer secret for asset 7.
pub const ISK_7: [u64; 4] = [0x15c7_0001, 0x15c7_0002, 0x15c7_0003, 0x15c7_0004];

/// Shape P at `log_height`: asset 0 (Cloaked, 50,000) + asset 7 (Hybrid:
/// issuer [`ISK_7`], three frozen keys, redeem closed; 30,000) in, 49,000
/// (asset 0) + 30,000 (asset 7) out, fee 1,000, no vPublic. Every gadget is
/// in the trace (fixed shape); the allowlist rides the dummy path.
pub fn shape_p_at(log_height: usize) -> L2PBucketInstance {
    let mut r = Rnd(SEED);
    let inputs = [r.input(50_000, 0), r.input(30_000, 7)];
    let outputs = [r.output(49_000, 0), r.output(30_000, 7)];
    let frozen = [r.d4(), r.d4(), r.d4()];
    let assets = [
        PolicyAsset::cloaked(0),
        PolicyAsset::hybrid(7, ISK_7, false, &frozen),
    ];
    build_bucket_l2p(log_height, &inputs, &outputs, 1_000, &assets, [VPublic::NONE; 2])
}

/// Shape P at its own height (2^20).
pub fn shape_p() -> L2PBucketInstance {
    shape_p_at(crate::LOG_HEIGHT_P)
}

/// Seed of the A4 merge fixtures' stream (distinct from [`SEED`], so the
/// merge notes never collide with the 2×2 fixtures' nullifiers).
const SEED_MERGE: u64 = 0xa4a4_3e3e_f33d_0003;

/// The A4 merge the 3×2 shapes exist for (design #283): two asset-7 notes
/// (30,000 + 20,000) in, 50,000 + a 0-value change (both asset 7) out, the
/// 1,000 fee paid by slot 3's **exact** asset-0 note (`d3 = 0`). All three
/// notes sit in one fabricated commitment tree. Returns the three inputs'
/// notes alongside so a caller can derive commitments.
fn merge_notes() -> ([L2TxInput; 2], [L2TxOutput; 2], L2TxInput) {
    let mut r = Rnd(SEED_MERGE);
    let inputs = [r.input(30_000, 7), r.input(20_000, 7)];
    let outputs = [r.output(50_000, 7), r.output(0, 7)];
    let fee_note = r.input(1_000, 0);
    (inputs, outputs, fee_note)
}

/// Shape S3 at `log_height`: [`merge_notes`] with asset 7 Cloaked.
pub fn shape_s3_merge_at(log_height: usize) -> L2BucketInstance {
    let (inputs, outputs, fee_note) = merge_notes();
    let cms = [&inputs[0], &inputs[1], &fee_note].map(|i| derive_input_l2(i).2);
    let (w, anchor) = fabricated_tree3([&cms[0], &cms[1], &cms[2]]);
    let leaves = [RegistryLeaf::cloaked(7), RegistryLeaf::cloaked(7)];
    let (rw, root) = fabricated_registry_tree(&leaves[0].hash(), &leaves[1].hash());
    build_bucket_l2_with_witnesses(
        log_height,
        &inputs,
        &outputs,
        1_000,
        &[w[0], w[1]],
        anchor,
        &leaves,
        &rw,
        root,
        &FeeSlot::Exact { input: fee_note, witness: w[2] },
    )
}

/// Shape P3 at `log_height`: [`merge_notes`] with asset 7 Hybrid (issuer
/// [`ISK_7`], three frozen keys, redeem closed), no vPublic.
pub fn shape_p3_merge_at(log_height: usize) -> L2PBucketInstance {
    let (inputs, outputs, fee_note) = merge_notes();
    let cms = [&inputs[0], &inputs[1], &fee_note].map(|i| derive_input_l2(i).2);
    let (w, anchor) = fabricated_tree3([&cms[0], &cms[1], &cms[2]]);
    let mut r = Rnd(SEED_MERGE ^ 0xf0f0);
    let frozen = [r.d4(), r.d4(), r.d4()];
    let asset = PolicyAsset::hybrid(7, ISK_7, false, &frozen);
    let leaf = asset.leaf().hash();
    let (rw, root) = fabricated_registry_tree(&leaf, &leaf);
    let policy = [0, 1].map(|i| {
        asset
            .policy_input_for(&derive_rkm_l2(&inputs[i]), rw[i])
            .expect("merge fixture: rkm frozen")
    });
    build_bucket_l2p_with_witnesses(
        log_height,
        &inputs,
        &outputs,
        1_000,
        &[w[0], w[1]],
        anchor,
        &policy,
        root,
        [VPublic::NONE; 2],
        &FeeSlot::Exact { input: fee_note, witness: w[2] },
    )
}

/// The next issuer secret of asset 7 — what the shape-R fixture rotates to.
pub const ISK_7_NEXT: [u64; 4] = [0x15c7_0101, 0x15c7_0102, 0x15c7_0103, 0x15c7_0104];

/// The registry the shape-R fixture writes into: asset 0 (Cloaked) and
/// asset 7 (Hybrid, issuer [`ISK_7`], a published freeze root).
pub fn shape_r_registry() -> Vec<RegistryLeaf> {
    let mut r = Rnd(SEED ^ 0x52);
    vec![
        RegistryLeaf::cloaked(0),
        RegistryLeaf {
            asset: 7,
            issuer_key: issuer_key_of(&ISK_7),
            mode: MODE_HYBRID,
            freeze_root: r.d4(),
            allow_root: [0; 4],
            flags: 0,
        },
    ]
}

/// Shape R at `log_height`: **an update** of asset 7 — the issuer proves
/// [`ISK_7`], rotates the key to [`ISK_7_NEXT`] and publishes a new freeze
/// root — paid by a 50,000 → 50,000 − fee spend in asset 0, fee
/// [`crate::FEE_TIER_R_PLACEHOLDER`] — and seeds a 0-value note of asset 7
/// (A3). The seed is drawn after every earlier draw, so the first 85 public
/// values are A2's, byte for byte.
pub fn shape_r_at(log_height: usize) -> L2ShapeRInstance {
    let mut r = Rnd(SEED ^ 0x52);
    let _ = r.d4(); // the registry's freeze root
    let fee = crate::FEE_TIER_R_PLACEHOLDER;
    let input = r.input(50_000, 0);
    let output = r.output(50_000 - fee, 0);
    let registry = shape_r_registry();
    let old = registry[1];
    let new = RegistryLeaf {
        issuer_key: issuer_key_of(&ISK_7_NEXT),
        freeze_root: r.d4(),
        ..old
    };
    let write = RegistryWrite {
        isk: ISK_7,
        old_leaf: Some(old),
        new_leaf: new,
        opening: registry_opening(&registry, 7).0,
    };
    let seed = SeedOutput { rkm: r.d4(), rseed: r.d4() };
    build_shape_r(log_height, &input, &output, fee, &write, &seed)
}

/// Shape R at its own height (2^18).
pub fn shape_r() -> L2ShapeRInstance {
    shape_r_at(crate::LOG_HEIGHT_R)
}
