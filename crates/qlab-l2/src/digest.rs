//! The shape digest — what "shape S / shape P v1" means, as 32 bytes.
//!
//! The L1 has no AIR digest (its "frozen digest" is `FrozenParams`', a
//! parameter set — lab #704 P7), so this is the first. Ruled on #704 (Q4):
//!
//! ```text
//! shape_digest = Keccak-256( b"qumbra:l2:shape:v1" ‖ tag ‖ constants_digest ‖ constraints_digest )
//! ```
//!
//! - **`constants_digest`** — everything a verifier depends on besides the
//!   constraint polynomials: width, log height, perms, the PV layout, the
//!   canonical program (every 5-bit role code), the tree depths, the asset
//!   width, the mode/flag values, and **known-answer outputs of every host
//!   hash the circuit mirrors** (note commitment, registry leaf, and for P the
//!   issuer key, the credential, the freeze key and the freeze leaf). The
//!   domain separators `D_I`, `D_CRED`, `D_FRZ` are not named constants in
//!   `qlab-air` — they are lane/bit positions inside those blocks — so they
//!   are pinned *through* the known answers, derived rather than re-typed.
//! - **`constraints_digest`** — a structural hash of Plonky3's symbolic
//!   constraint set for the shape (`get_symbolic_constraints`): every node
//!   (`+ − × neg`, column / public / periodic / selector leaf, constant)
//!   hashed by content, in order. Catches a constraint edit that moves none
//!   of the constants. It is a structural walk rather than a `Debug`
//!   rendering: the expressions are an `Arc`-shared DAG and a textual
//!   rendering expands shared subtrees (exponential in the worst case); the
//!   walk hashes content and uses node addresses only as a within-walk cache.
//!
//! **The lane is not in the digest.** `L2_CFG_PROVISIONAL` is not frozen
//! (#704 ruling); the digest pins the shapes, and a lane change must not
//! read as a shape change.
//!
//! **A Plonky3 bump that moves `constraints_digest` is a freeze event**: the
//! symbolic builder is Plonky3's, so a different builder can present the same
//! AIR as a different expression set. Re-pin only with the coordinator.

use std::collections::HashMap;

use p3_air::symbolic::{get_symbolic_constraints, AirLayout, BaseEntry, BaseLeaf, SymbolicExpression};
use p3_air::BaseAir;
use p3_field::PrimeField32;
use tiny_keccak::{Hasher, Keccak};

use qlab_air::l2::{self, RegistryLeaf};
use qlab_air::l2p;
use qlab_air::narrow::MERKLE_DEPTH;

use crate::{Shape, Val};

/// Domain of the outer digest.
pub const SHAPE_DIGEST_DOMAIN: &[u8] = b"qumbra:l2:shape:v1";

/// A little Keccak-256 writer with typed appends.
struct H(Keccak);

impl H {
    fn new(domain: &[u8]) -> Self {
        let mut k = Keccak::v256();
        k.update(&(domain.len() as u64).to_le_bytes());
        k.update(domain);
        H(k)
    }
    fn u64(&mut self, x: u64) -> &mut Self {
        self.0.update(&x.to_le_bytes());
        self
    }
    fn usize(&mut self, x: usize) -> &mut Self {
        self.u64(x as u64)
    }
    fn words(&mut self, w: &[u64]) -> &mut Self {
        self.usize(w.len());
        for x in w {
            self.u64(*x);
        }
        self
    }
    fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.usize(b.len());
        self.0.update(b);
        self
    }
    fn finish(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.0.finalize(&mut out);
        out
    }
}

fn tag(shape: Shape) -> u64 {
    match shape {
        Shape::S => 0x53, // 'S'
        Shape::P => 0x50, // 'P'
    }
}

/// Digest (i): the constants a verifier of `shape` depends on.
pub fn constants_digest(shape: Shape) -> [u8; 32] {
    let mut h = H::new(b"qumbra:l2:shape:v1:constants");
    h.u64(tag(shape))
        .usize(shape.width())
        .usize(shape.log_height())
        .usize(shape.perms())
        .usize(l2::ROWS_PER_PERM);
    // PV layout.
    h.usize(shape.pv_len());
    h.words(&[
        l2::PV_ANCHOR as u64,
        l2::PV_NF1 as u64,
        l2::PV_NF2 as u64,
        l2::PV_CM1 as u64,
        l2::PV_CM2 as u64,
        l2::PV_FEE as u64,
        l2::PV_REGROOT as u64,
    ]);
    if shape == Shape::P {
        h.words(&[l2p::PV_VP1 as u64, l2p::PV_VP2 as u64]);
    }
    // The canonical program, every slot.
    let program: Vec<u64> = crate::canonical_program(shape).iter().map(|r| *r as u64).collect();
    h.words(&program);
    // Depths, asset width, modes, flags.
    h.words(&[
        MERKLE_DEPTH as u64,
        l2::REGISTRY_DEPTH as u64,
        l2::ASSET_BITS as u64,
        l2::MODE_CLOAKED,
        l2::MODE_HYBRID,
        l2::MODE_REGULATED,
    ]);
    // Known answers of the host mirrors (pin the in-block domains).
    let z = [0u64; 4];
    let o = [1u64, 2, 3, 4];
    h.words(&l2::l2_cm(1, 7, &o, &o, &o));
    h.words(&RegistryLeaf::cloaked(7).hash());
    if shape == Shape::P {
        h.words(&[
            l2p::FREEZE_DEPTH as u64,
            l2p::ALLOW_DEPTH as u64,
            l2p::FLAG_REDEEM_OPEN,
        ]);
        h.words(&l2p::issuer_key_of(&o)); // D_I
        h.words(&l2p::cred_of(&o)); // D_CRED
        h.words(&l2p::freeze_leaf_hash(&z, &o));
    }
    h.finish()
}

/// Content hash of one symbolic node; `memo` caches by address within one walk.
fn node_hash(
    e: &SymbolicExpression<Val>,
    memo: &mut HashMap<*const SymbolicExpression<Val>, [u8; 32]>,
) -> [u8; 32] {
    let key = e as *const _;
    if let Some(h) = memo.get(&key) {
        return *h;
    }
    let mut h = H::new(b"n");
    match e {
        SymbolicExpression::Leaf(leaf) => {
            h.u64(0);
            match leaf {
                BaseLeaf::Variable(v) => {
                    h.u64(0);
                    match v.entry {
                        BaseEntry::Preprocessed { offset } => h.u64(0).usize(offset),
                        BaseEntry::Main { offset } => h.u64(1).usize(offset),
                        BaseEntry::Periodic => h.u64(2),
                        BaseEntry::Public => h.u64(3),
                    };
                    h.usize(v.index);
                }
                BaseLeaf::IsFirstRow => {
                    h.u64(1);
                }
                BaseLeaf::IsLastRow => {
                    h.u64(2);
                }
                BaseLeaf::IsTransition => {
                    h.u64(3);
                }
                BaseLeaf::Constant(c) => {
                    h.u64(4).u64(c.as_canonical_u32() as u64);
                }
            }
        }
        SymbolicExpression::Add { x, y, .. } => {
            let (a, b) = (node_hash(x, memo), node_hash(y, memo));
            h.u64(1).bytes(&a).bytes(&b);
        }
        SymbolicExpression::Sub { x, y, .. } => {
            let (a, b) = (node_hash(x, memo), node_hash(y, memo));
            h.u64(2).bytes(&a).bytes(&b);
        }
        SymbolicExpression::Neg { x, .. } => {
            let a = node_hash(x, memo);
            h.u64(3).bytes(&a);
        }
        SymbolicExpression::Mul { x, y, .. } => {
            let (a, b) = (node_hash(x, memo), node_hash(y, memo));
            h.u64(4).bytes(&a).bytes(&b);
        }
    }
    let out = h.finish();
    memo.insert(key, out);
    out
}

fn constraints_digest_of<A>(air: &A) -> ([u8; 32], usize)
where
    A: p3_air::Air<p3_air::symbolic::SymbolicAirBuilder<Val>> + BaseAir<Val>,
{
    let layout = AirLayout::from_air::<Val>(air);
    let constraints = get_symbolic_constraints::<Val, _>(air, layout);
    let mut memo = HashMap::new();
    let mut h = H::new(b"qumbra:l2:shape:v1:constraints");
    h.usize(constraints.len());
    for c in &constraints {
        let n = node_hash(c, &mut memo);
        h.bytes(&n);
    }
    (h.finish(), constraints.len())
}

/// Digest (ii): the symbolic constraint set of `shape`'s canonical AIR, and
/// the number of constraints. Run on a large-stack thread: the walk recurses
/// once per expression depth and a long sum is a deep left spine.
pub fn constraints_digest(shape: Shape) -> ([u8; 32], usize) {
    std::thread::Builder::new()
        .name("l2-constraints-digest".into())
        .stack_size(512 << 20)
        .spawn(move || match shape {
            Shape::S => constraints_digest_of(&crate::verifier_air_s()),
            Shape::P => constraints_digest_of(&crate::verifier_air_p()),
        })
        .expect("spawn the digest thread")
        .join()
        .expect("the digest thread panicked")
}

/// The shape digest: `Keccak-256(domain ‖ tag ‖ constants ‖ constraints)`.
pub fn shape_digest(shape: Shape) -> [u8; 32] {
    let (c, _) = constraints_digest(shape);
    let mut h = H::new(SHAPE_DIGEST_DOMAIN);
    h.u64(tag(shape)).bytes(&constants_digest(shape)).bytes(&c);
    h.finish()
}

/// Lower-case hex of a digest (what the pins are written in).
pub fn hex(d: &[u8; 32]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}
