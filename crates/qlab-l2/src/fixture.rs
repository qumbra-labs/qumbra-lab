//! The deterministic shape-S and shape-P instances — one source.
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
use qlab_air::l2p::{build_bucket_l2p, L2PBucketInstance, PolicyAsset, VPublic};

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
