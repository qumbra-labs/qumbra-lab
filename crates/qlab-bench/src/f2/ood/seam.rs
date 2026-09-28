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
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField32};
use qlab_consensus::CAP_HEIGHT;

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
/// fri_alpha^k. Randomizer (4 columns), trace at ζ (w), trace at ζ·g_N (w),
/// quotient chunk c column e (4 per chunk).
pub(super) fn open_order(width: usize, chunks: usize) -> Vec<Open> {
    (0..D)
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
}

impl SeamShape {
    /// Cap blocks: trace, quotient, randomizer, then each commit round.
    pub(super) fn cap_blocks(&self) -> usize {
        3 + self.rounds
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
