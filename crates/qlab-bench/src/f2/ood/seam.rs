//! The C1 → C2 seam of the F2b composition (issue #750, "two proofs per
//! leaf"), and the one term order both proofs weight the opened values in.
//!
//! **Term order.** Native `open_input` (p3-fri `verifier.rs:706-753`) runs
//! ONE fri_alpha counter over the randomizer, the trace at ζ, the trace at
//! ζ·g_N and the quotient chunks (uni-stark `verifier.rs:453-510` builds the
//! claims in that order). C1 absorbs the opened values in this order and
//! weights them into Az/Bz by it; C2 weights its Merkle-authenticated row
//! values into Ax/Bx by it. Both read it from [`open_order`], so the two sums
//! cannot be taken in different orders: C1's slot maps and C2's per-block
//! power steps are each checked against this list when their AIR is built.
//!
//! **The seam.** C1 exports, and C2 takes as public inputs, exactly the
//! values of [`Seam`], in one encoding ([`SeamShape`] offsets): every cap
//! (trace, quotient, randomizer, then each commit round, as 16-bit limbs),
//! ζ, fri_alpha, Az, Bz, every β, the final polynomial and the query
//! indices. C1's public values are its inner PVs followed by this slice; C2's
//! public values ARE this slice, with the indices of the query slots it
//! covers. [`check_seams`] is the native field-by-field equality the next
//! recursion level states in-circuit; a mismatch names its group.
//!
//! **R-PV, option (c)** (issue #750, the coordinator's R-PV ruling and its
//! addendum). Every leaf AIR's constraints assume each public value is a
//! 16-bit chunk, with documented 1- and 32-bit exceptions; the native verify
//! paths get that range by construction (they build PVs from u16/u32), an
//! in-circuit verifier does not. C1 **exposes every inner PV unchanged** as
//! its own public values `[0, pv_len)` (all groups exposed, none compressed:
//! no inner PV is hashed, summed or otherwise folded into another value), and
//! C1 checks nothing about their magnitude — the only constraints that read
//! them are `bind_inner_pv` (PV = R⁻¹ · the absorbed word, which `canonical`
//! keeps `< p`) and `in_public` (the machine's input cells); see
//! `c1_accepts_an_out_of_range_leaf_pv`. So option (c) covers
//! every group: [`check_leaf_pvs`] is the native range check the consumer of
//! the aggregation proof applies to C1's public values before accepting.
//! The widths are [`leaf_pv_widths`]: read off the leaf AIRs' own PV
//! builders (`qlab_air::l2::pv_vec_l2`, `l2p::pv_vec_l2p`, `l2r::pv_vec_r`),
//! never restated here.
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField32};
use qlab_consensus::CAP_HEIGHT;
use qlab_l2::Shape;

use super::lane::CAP_WORDS;
use super::{require, Result, Val, E};

/// Extension limbs.
const D: usize = 4;

/// The point a term is opened at.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum Point {
    Zeta,
    Next,
}

/// One opened term: a (matrix column, point) claim of `open_input`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum Open {
    Random(usize),
    Local(usize),
    Next(usize),
    Quotient(usize, usize),
}

impl Open {
    pub(super) fn point(self) -> Point {
        match self {
            Self::Next(_) => Point::Next,
            _ => Point::Zeta,
        }
    }
}

/// Every opened term in native `open_input` order: term k is weighted by
/// fri_alpha^k. Randomizer (4 columns, a hiding child only: `zk` = 1),
/// trace at ζ (w), trace at ζ·g_N (w), quotient chunk c column e (4 per
/// chunk).
pub(super) fn open_order(width: usize, chunks: usize, zk: usize) -> Vec<Open> {
    (0..D * zk)
        .map(Open::Random)
        .chain((0..width).map(Open::Local))
        .chain((0..width).map(Open::Next))
        .chain((0..chunks).flat_map(|c| (0..D).map(move |e| Open::Quotient(c, e))))
        .collect()
}

/// Offsets of every seam group inside a seam slice of public values.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct SeamShape {
    pub(super) rounds: usize,
    pub(super) final_len: usize,
    /// 1: the child is hiding (a randomizer cap block); 0: it is not.
    pub(super) zk: usize,
}

impl SeamShape {
    /// Cap blocks: trace, quotient, the randomizer (hiding only), then each
    /// commit round.
    pub(super) fn cap_blocks(&self) -> usize {
        2 + self.zk + self.rounds
    }
    /// Low limb of cap word `n` (entry n / 8, u64 lane (n % 8) / 2, half n % 2).
    pub(super) fn cap_word(&self, block: usize, n: usize) -> usize {
        2 * (CAP_WORDS * block + n)
    }
    /// 16-bit limb `l` of u64 lane `lane` of cap entry `j`: the order
    /// Keccak's `out[lane][l]` cells use.
    pub(super) fn cap(&self, block: usize, j: usize, lane: usize, l: usize) -> usize {
        2 * CAP_WORDS * block + 16 * j + 4 * lane + l
    }
    pub(super) fn zeta(&self) -> usize {
        2 * CAP_WORDS * self.cap_blocks()
    }
    pub(super) fn fri_alpha(&self) -> usize {
        self.zeta() + D
    }
    pub(super) fn az(&self) -> usize {
        self.fri_alpha() + D
    }
    pub(super) fn bz(&self) -> usize {
        self.az() + D
    }
    pub(super) fn beta(&self, r: usize) -> usize {
        self.bz() + D + D * r
    }
    pub(super) fn final_coeff(&self, c: usize) -> usize {
        self.beta(self.rounds) + D * c
    }
    /// The i-th carried index (C1: query i; C2: its i-th covered slot).
    pub(super) fn index(&self, i: usize) -> usize {
        self.final_coeff(self.final_len) + i
    }
    pub(super) fn len(&self, indices: usize) -> usize {
        self.index(indices)
    }
}

/// The C1 → C2 seam as values.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Seam {
    /// Trace, quotient, randomizer, then every commit round's cap.
    pub(super) caps: Vec<Vec<[u64; 4]>>,
    pub(super) zeta: E,
    pub(super) fri_alpha: E,
    pub(super) az: E,
    pub(super) bz: E,
    pub(super) betas: Vec<E>,
    pub(super) final_poly: Vec<E>,
    /// (query slot, query index), slots ascending.
    pub(super) indices: Vec<(usize, usize)>,
}

/// The seam's groups, in the order `check_seams` compares them.
pub(super) const GROUPS: [&str; 8] = [
    "caps",
    "zeta",
    "fri_alpha",
    "az",
    "bz",
    "betas",
    "final_poly",
    "indices",
];

impl Seam {
    pub(super) fn shape(&self) -> SeamShape {
        SeamShape {
            rounds: self.betas.len(),
            final_len: self.final_poly.len(),
            zk: self.caps.len() - 2 - self.betas.len(),
        }
    }

    /// The seam slice of public values.
    pub(super) fn encode(&self) -> Vec<Val> {
        let s = self.shape();
        let mut pv = Vec::with_capacity(s.len(self.indices.len()));
        for cap in &self.caps {
            for n in 0..CAP_WORDS {
                let word = (cap[n / 8][(n % 8) / 2] >> (32 * (n % 2))) as u32;
                pv.extend([Val::from_u32(word & 0xffff), Val::from_u32(word >> 16)]);
            }
        }
        for v in [self.zeta, self.fri_alpha, self.az, self.bz]
            .iter()
            .chain(&self.betas)
            .chain(&self.final_poly)
        {
            pv.extend_from_slice(v.as_basis_coefficients_slice());
        }
        pv.extend(self.indices.iter().map(|&(_, i)| Val::from_usize(i)));
        pv
    }

    /// Read a seam slice carrying the indices of `slots`.
    pub(super) fn decode(shape: SeamShape, slots: &[usize], pvs: &[Val]) -> Result<Self> {
        require(pvs.len() == shape.len(slots.len()), "seam length")?;
        require(
            slots.windows(2).all(|w| w[0] < w[1]),
            "seam slots must ascend",
        )?;
        let ext = |at: usize| E::from_basis_coefficients_fn(|i| pvs[at + i]);
        let limb = |at: usize| -> Result<u64> {
            let v = pvs[at].as_canonical_u32();
            require(v < 1 << 16, "cap limb wider than 16 bits")?;
            Ok(u64::from(v))
        };
        let mut caps = Vec::with_capacity(shape.cap_blocks());
        for b in 0..shape.cap_blocks() {
            let mut cap = vec![[0u64; 4]; 1 << CAP_HEIGHT];
            for n in 0..CAP_WORDS {
                let at = shape.cap_word(b, n);
                let word = limb(at)? | (limb(at + 1)? << 16);
                cap[n / 8][(n % 8) / 2] |= word << (32 * (n % 2));
            }
            caps.push(cap);
        }
        Ok(Self {
            caps,
            zeta: ext(shape.zeta()),
            fri_alpha: ext(shape.fri_alpha()),
            az: ext(shape.az()),
            bz: ext(shape.bz()),
            betas: (0..shape.rounds).map(|r| ext(shape.beta(r))).collect(),
            final_poly: (0..shape.final_len)
                .map(|c| ext(shape.final_coeff(c)))
                .collect(),
            indices: slots
                .iter()
                .enumerate()
                .map(|(i, &s)| (s, pvs[shape.index(i)].as_canonical_u32() as usize))
                .collect(),
        })
    }
}

/// The seam equality, group by group: every value C2 read as a public input
/// equals the value C1 exported. The error names the first group that
/// differs. C2's index slots are a static property of its layout; each must
/// be one of C1's and carry C1's index. Whether C2 covers EVERY query is
/// [`check_coverage`]'s question, not this one.
pub(super) fn check_seams(c1: &Seam, c2: &Seam) -> Result<()> {
    let slot_ok = c2
        .indices
        .iter()
        .all(|&(s, i)| c1.indices.iter().any(|&(s1, i1)| s1 == s && i1 == i));
    let same = [
        c1.caps == c2.caps,
        c1.zeta == c2.zeta,
        c1.fri_alpha == c2.fri_alpha,
        c1.az == c2.az,
        c1.bz == c2.bz,
        c1.betas == c2.betas,
        c1.final_poly == c2.final_poly,
        slot_ok,
    ];
    for (group, ok) in GROUPS.iter().zip(same) {
        if !ok {
            return Err(format!("seam group `{group}` differs between C1 and C2"));
        }
    }
    Ok(())
}

/// A C2 instance covers every query C1 drew: the production instance does
/// (43 slots, `price::composed_c2`); the tests' two-slot instances do not.
pub(super) fn check_coverage(c1: &Seam, c2: &Seam) -> Result<()> {
    let slots = |s: &Seam| s.indices.iter().map(|&(q, _)| q).collect::<Vec<_>>();
    require(
        slots(c1) == slots(c2),
        "C2 does not cover every query C1 drew",
    )
}

/// One leaf public value's declared range: its group, its index in the
/// group, and its width in bits.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct PvWidth {
    pub(super) group: &'static str,
    pub(super) index: usize,
    pub(super) bits: u32,
}

/// The PV groups of `shape`, as (first index, name): the `PV_*` offsets of
/// the leaf AIR modules. Names only label errors; the widths do not come
/// from here.
fn pv_groups(shape: Shape) -> Vec<(usize, &'static str)> {
    use qlab_air::{l2, l2p, l2r};
    match shape {
        Shape::S => vec![
            (l2::PV_ANCHOR, "anchor"),
            (l2::PV_NF1, "nf1"),
            (l2::PV_NF2, "nf2"),
            (l2::PV_CM1, "cm1"),
            (l2::PV_CM2, "cm2"),
            (l2::PV_FEE, "fee"),
            (l2::PV_REGROOT, "registry_root"),
            (l2::PV_NF3, "nf3"),
        ],
        // vPublic per row k: sign, four amount chunks, asset (l2p.rs
        // `pv_vp_sign` / `pv_vp_chunk` / `pv_vp_asset`).
        Shape::P => vec![
            (l2::PV_ANCHOR, "anchor"),
            (l2::PV_NF1, "nf1"),
            (l2::PV_NF2, "nf2"),
            (l2::PV_CM1, "cm1"),
            (l2::PV_CM2, "cm2"),
            (l2::PV_FEE, "fee"),
            (l2::PV_REGROOT, "registry_root"),
            (l2p::PV_VP1, "vp1_sign"),
            (l2p::PV_VP1 + 1, "vp1_amount"),
            (l2p::PV_VP1 + 5, "vp1_asset"),
            (l2p::PV_VP2, "vp2_sign"),
            (l2p::PV_VP2 + 1, "vp2_amount"),
            (l2p::PV_VP2 + 5, "vp2_asset"),
            (l2p::PV_NF3, "nf3"),
        ],
        Shape::R => vec![
            (l2r::PV_ANCHOR, "anchor"),
            (l2r::PV_NF, "nf"),
            (l2r::PV_CM, "cm"),
            (l2r::PV_FEE, "fee"),
            (l2r::PV_OLD_ROOT, "old_root"),
            (l2r::PV_NEW_ROOT, "new_root"),
            (l2r::PV_ASSET, "asset"),
            (l2r::PV_CM_SEED, "cm_seed"),
        ],
    }
}

/// The leaf PV vector the shape's own builder emits at its widest typed
/// inputs: every digest and amount `u64::MAX`, every sign `true`, every asset
/// id `u64::MAX` (the builders cast it `as u32`).
fn saturated_pvs(shape: Shape) -> Vec<u32> {
    let d = [u64::MAX; 4];
    match shape {
        Shape::S => qlab_l2::pv_vec_s(&d, &d, &d, &d, &d, u64::MAX, &d, &d),
        Shape::P => qlab_l2::pv_vec_p(
            &d,
            &d,
            &d,
            &d,
            &d,
            u64::MAX,
            &d,
            &[qlab_l2::VPublic::redeem(u64::MAX); 2],
            &[u64::MAX; 2],
            &d,
        ),
        Shape::R => qlab_l2::pv_vec_r(&d, &d, &d, u64::MAX, &d, &d, u64::MAX, &d),
    }
}

/// [P] Every leaf PV's width, source-derived: the bit length of the value
/// the shape's PV builder emits at saturated inputs. That gives 16 for every
/// `& 0xffff` chunk (digests, fee, vPublic amounts), 1 for P's vPublic signs
/// (`redeem as u32`) and 32 for the asset ids P's vPublic and R carry
/// (`as u32`). A 32-bit slot is vacuous as a native check (KoalaBear's
/// p < 2^31, and every PV is canonical); those slots are equated in-AIR to
/// an asset accumulator cell (`l2p.rs` `pv_vp_asset`, `l2r.rs` `PV_ASSET`).
pub(super) fn leaf_pv_widths(shape: Shape) -> Vec<PvWidth> {
    let groups = pv_groups(shape);
    saturated_pvs(shape)
        .iter()
        .enumerate()
        .map(|(i, &v)| {
            let g = groups.iter().rposition(|&(at, _)| at <= i).unwrap_or(0);
            PvWidth {
                group: groups[g].1,
                index: i - groups[g].0,
                bits: u32::BITS - v.leading_zeros(),
            }
        })
        .collect()
}

/// The native range check of the leaf PVs at the front of `pvs` against
/// `widths`: a value outside its width is refused by (group, index).
pub(super) fn check_pv_widths(widths: &[PvWidth], pvs: &[Val]) -> Result<()> {
    require(
        pvs.len() >= widths.len(),
        "fewer public values than leaf PVs",
    )?;
    for (i, (w, v)) in widths.iter().zip(pvs).enumerate() {
        let v = u64::from(v.as_canonical_u32());
        if v >> w.bits != 0 {
            return Err(format!(
                "leaf PV {i} (`{}[{}]`) = {v} exceeds its {}-bit width",
                w.group, w.index, w.bits
            ));
        }
    }
    Ok(())
}

/// R-PV option (c): C1's public values start with the inner leaf's PVs,
/// unchanged; the consumer of the aggregation proof range-checks each one
/// by the leaf AIR's width before accepting. C1 itself does not.
pub(super) fn check_leaf_pvs(shape: Shape, c1_pvs: &[Val]) -> Result<()> {
    let widths = leaf_pv_widths(shape);
    require(widths.len() == shape.pv_len(), "PV width table length")?;
    check_pv_widths(&widths, c1_pvs)
}

#[cfg(test)]
mod tests {
    use qlab_air::{l2, l2p, l2r};
    use qlab_l2::fixture;

    use super::*;

    /// C1-shaped public values: the leaf's PVs, then a seam tail that is not
    /// the leaf's (never range-checked by R-PV; here deliberately wide).
    fn c1_pvs(leaf: &[u32]) -> Vec<Val> {
        leaf.iter()
            .map(|&v| Val::from_u32(v))
            .chain([Val::from_u32(1 << 30); 8])
            .collect()
    }

    fn honest(shape: Shape) -> Vec<u32> {
        match shape {
            Shape::S => fixture::shape_s3_merge_at(shape.log_height()).pvs,
            Shape::P => fixture::shape_p3_merge_at(shape.log_height()).pvs,
            Shape::R => fixture::shape_r().pvs,
        }
    }

    #[test]
    fn leaf_pv_widths_are_read_off_the_leaf_builders() {
        // 16-bit chunks everywhere, except P's two vPublic signs (1 bit) and
        // the asset ids P's vPublic and R expose (32 bits).
        for (shape, ones, wide) in [(Shape::S, 0, 0), (Shape::P, 2, 2), (Shape::R, 0, 1)] {
            let w = leaf_pv_widths(shape);
            assert_eq!(w.len(), shape.pv_len(), "{shape:?}");
            let count = |b: u32| w.iter().filter(|x| x.bits == b).count();
            assert_eq!((count(1), count(32)), (ones, wide), "{shape:?}");
            assert_eq!(count(16), shape.pv_len() - ones - wide, "{shape:?}");
        }
        let pw = |group, index, bits| PvWidth { group, index, bits };
        let s = leaf_pv_widths(Shape::S);
        assert_eq!(s[l2::PV_FEE + 3], pw("fee", 3, 16));
        assert_eq!(s[l2::PV_NF3 + 15], pw("nf3", 15, 16));
        let p = leaf_pv_widths(Shape::P);
        assert_eq!(p[l2p::PV_VP1], pw("vp1_sign", 0, 1));
        assert_eq!(p[l2p::PV_VP1 + 4], pw("vp1_amount", 3, 16));
        assert_eq!(p[l2p::PV_VP2 + 5], pw("vp2_asset", 0, 32));
        assert_eq!(p[l2p::PV_NF3], pw("nf3", 0, 16));
        let r = leaf_pv_widths(Shape::R);
        assert_eq!(r[l2r::PV_ASSET], pw("asset", 0, 32));
        assert_eq!(r[l2r::PV_CM_SEED], pw("cm_seed", 0, 16));
    }

    /// R-PV option (c)'s native check: the honest fixtures (the instances
    /// `f2fixture` proves) and the builders' saturated vectors pass; one
    /// 16-bit chunk at 2^16 is refused by name, at 2^16 − 1 accepted; P's
    /// 1-bit sign at 2 is refused by name, at 1 accepted.
    #[test]
    fn check_leaf_pvs_refuses_out_of_range_leaf_pvs_by_name() {
        for shape in [Shape::S, Shape::P, Shape::R] {
            let pvs = honest(shape);
            check_leaf_pvs(shape, &c1_pvs(&pvs)).unwrap();
            check_leaf_pvs(shape, &c1_pvs(&saturated_pvs(shape))).unwrap();
            let (fee, nf) = match shape {
                Shape::R => (l2r::PV_FEE, l2r::PV_NF + 3),
                _ => (l2::PV_FEE, l2::PV_NF1 + 3),
            };
            let nf_name = if shape == Shape::R {
                "`nf[3]`"
            } else {
                "`nf1[3]`"
            };
            for (at, name) in [(fee, "`fee[0]`"), (nf, nf_name)] {
                let mut v = c1_pvs(&pvs);
                v[at] = Val::from_u32((1 << 16) - 1);
                check_leaf_pvs(shape, &v).unwrap();
                for bad in [1 << 16, Val::ORDER_U32 - 1] {
                    v[at] = Val::from_u32(bad);
                    let err = check_leaf_pvs(shape, &v).unwrap_err();
                    assert!(err.contains(name) && err.contains("16-bit"), "{err}");
                }
            }
            assert!(check_leaf_pvs(shape, &c1_pvs(&pvs)[..shape.pv_len() - 1]).is_err());
        }
        let mut v = c1_pvs(&honest(Shape::P));
        v[l2p::PV_VP1] = Val::ONE;
        check_leaf_pvs(Shape::P, &v).unwrap();
        v[l2p::PV_VP1] = Val::from_u32(2);
        let err = check_leaf_pvs(Shape::P, &v).unwrap_err();
        assert!(
            err.contains("`vp1_sign[0]`") && err.contains("1-bit"),
            "{err}"
        );
    }
}
