//! Lab #775 F4-3 — the **deposit-sum proof**: the batch's claims' value
//! commitments open to values summing to `D_batch`. It closes the gap
//! F4-2 left (review S3): W's `D_out = D_in + D_batch` takes `D_batch` as a
//! public value, and until this proof binds it, `E_cum ≤ D_cum` (V8) is
//! vacuous.
//!
//! **The statement.** Public: `n`, `D_batch` (four 16-bit limbs) and `dig`
//! (16 chunks). Private: `(v_i, r_v_i)` for `i < n`. The AIR proves
//!
//! 1. each `Cv_i = Keccak256(CV_TAG ‖ 00×3 ‖ v_i ‖ r_v_i)` — exactly the
//!    claim circuit's value commitment (`qlab_air::claim::claim_cv`, frozen
//!    by F1), its tag lanes and padding fixed;
//! 2. `D_batch = Σ_{i<n} v_i` as a u64 (limb sums with 5-bit carries and no
//!    carry out: a sum past 2^64 − 1 has no proof);
//! 3. `dig` is the MD chain `d_0 = 0`, `d_{i+1} = H(d_i ‖ Cv_i)` under the
//!    domain `"qumbra:l2-depsum:v1"` in capacity lanes 21..24, over
//!    `i < n` ([`dep_chain`]).
//!
//! **Capacity** [`DEP_CAP`] entries, `n ≤ DEP_CAP`: entry `i` is active iff
//! `i < n` (the active flags are a prefix — once off, never on again); an
//! idle entry's `v` is 0 and it enters neither the chain nor the count.
//!
//! **The program**: `DEP_CAP` × (the Cv perm, the chain perm) on the wide
//! Keccak lane (`p3-keccak-air`, 24 rows a perm) — 32 perms, 2^10 rows —
//! then padding. It carries values, so it proves under the **hiding** L2
//! config (`qlab_l2::make_config_l2`), as the claim proofs do.
//!
//! **Its verifier half** is `verify_wrapper`'s V9: `n` is the bundle's claim
//! count, `dig` the chain over the claims' `Cv` PVs in bundle order, and
//! `D_batch` W's `PV_DB`.
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_keccak_air::{KeccakAir, NUM_KECCAK_COLS, NUM_ROUNDS};
use qlab_consensus::{Config, Proof, Val};

use crate::cmp::limbs;
use crate::hash::{keccak_idx, out4, KeccakIdx};
use crate::hash::{Digest, EMPTY};
use crate::lane::LaneBuilder;

/// Entries per proof: the widest `k` a wrapper version proves.
pub const DEP_CAP: usize = 16;
const _: () = assert!(DEP_CAP >= crate::wleaf::MAX_K);
/// The 5-bit carries cover `DEP_CAP` chunks plus a carry-in.
const _: () = assert!(DEP_CAP * 0xffff + 31 < 32 << 16);
pub const DEP_PERMS: usize = 2 * DEP_CAP;
pub const DEP_HEIGHT: usize = (DEP_PERMS * NUM_ROUNDS).next_power_of_two();

/// Public values: `n`, `D_batch` (4 limbs), `dig` (16 chunks); all 16-bit.
pub const DPV_N: usize = 0;
pub const DPV_D: usize = 1;
pub const DPV_DIG: usize = 5;
pub const DEP_PV_LEN: usize = 21;

/// One claim's opening: its value and blind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DepEntry {
    pub v: u64,
    pub r_v: Digest,
}

// ---------------------------------------------------------------------------
// Native
// ---------------------------------------------------------------------------

/// `"qumbra:l2-depsum:v1"` in capacity lanes 21..24.
pub fn depsum_domain_lanes() -> [u64; 3] {
    crate::hash::domain3(b"qumbra:l2-depsum:v1")
}

/// `CV_TAG` as its three lanes.
fn cv_tag_lanes() -> [u64; 3] {
    crate::hash::domain3(qlab_air::claim::CV_TAG)
}

/// The Cv block: `CV_TAG ‖ 00×3 ‖ v ‖ r_v`, padded (lanes 8, 16).
pub fn cv_state(v: u64, r_v: &Digest) -> [u64; 25] {
    let mut st = [0u64; 25];
    st[..3].copy_from_slice(&cv_tag_lanes());
    st[3] = v;
    st[4..8].copy_from_slice(r_v);
    st[8] = 1;
    st[16] = 1 << 63;
    st
}

/// One chain step `H(d ‖ Cv)`: lanes 0..4, 4..8; pad lanes 8, 16; the
/// domain in capacity lanes 21..24.
pub fn dep_state(d: &Digest, cv: &Digest) -> [u64; 25] {
    let mut st = [0u64; 25];
    st[..4].copy_from_slice(d);
    st[4..8].copy_from_slice(cv);
    st[8] = 1;
    st[16] = 1 << 63;
    st[21..24].copy_from_slice(&depsum_domain_lanes());
    st
}

/// `dig` over a list of value commitments, in order.
pub fn dep_chain(cvs: &[Digest]) -> Digest {
    cvs.iter().fold(EMPTY, |d, cv| out4(&dep_state(&d, cv)))
}

/// The deposit proof's public values for `entries`, or `None` when they do
/// not fit (more than [`DEP_CAP`], or a sum past 2^64 − 1).
pub fn dep_pvs(entries: &[DepEntry]) -> Option<Vec<u32>> {
    if entries.len() > DEP_CAP {
        return None;
    }
    let d = entries.iter().try_fold(0u64, |a, e| a.checked_add(e.v))?;
    let cvs: Vec<Digest> = entries.iter().map(|e| qlab_air::claim::claim_cv(e.v, &e.r_v)).collect();
    Some(pvs_of(entries.len(), d, &dep_chain(&cvs)))
}

pub fn pvs_of(n: usize, d: u64, dig: &Digest) -> Vec<u32> {
    let mut v = vec![n as u32];
    v.extend((0..4).map(|j| ((d >> (16 * j)) & 0xffff) as u32));
    v.extend(limbs(dig));
    debug_assert_eq!(v.len(), DEP_PV_LEN);
    v
}

// ---------------------------------------------------------------------------
// The AIR
// ---------------------------------------------------------------------------

pub const KCV: usize = NUM_KECCAK_COLS;
pub const KCH: usize = KCV + 1;
pub const KPAD: usize = KCH + 1;
/// The entry index (16 on the padding) and `[EIX = 16]` with its inverse witness.
pub const EIX: usize = KPAD + 1;
pub const Z16: usize = EIX + 1;
pub const ZI: usize = Z16 + 1;
pub const ACT: usize = ZI + 1;
/// `KCV · fin`, `KCH · fin`: materialized (degree 3 throughout).
pub const FCV: usize = ACT + 1;
pub const FCH: usize = FCV + 1;
pub const CV_OFF: usize = FCH + 1;
pub const DIG_OFF: usize = CV_OFF + 16;
/// The value accumulator: four unnormalized 16-bit-chunk sums.
pub const SUM_OFF: usize = DIG_OFF + 16;
pub const NCNT: usize = SUM_OFF + 4;
/// `D_batch`'s three carries, five bits each (used on the last row).
pub const DCB_OFF: usize = NCNT + 1;
pub const DEP_WIDTH: usize = DCB_OFF + 15;

pub const DEP_PHASES: &[&str] = &["keccak", "sched", "cv", "chain", "acc", "first", "last"];

pub struct DepAir {
    kc: KeccakIdx,
}

impl DepAir {
    // Widened from pub(crate) by the move (F5-1); construction stays explicit.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self { kc: keccak_idx() }
    }
}

impl BaseAir<Val> for DepAir {
    fn width(&self) -> usize {
        DEP_WIDTH
    }
    fn num_public_values(&self) -> usize {
        DEP_PV_LEN
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for DepAir {
    fn eval(&self, builder: &mut AB) {
        for p in 0..DEP_PHASES.len() {
            self.eval_phase(p, builder);
        }
    }
}

impl DepAir {
    pub fn eval_phase<AB: AirBuilder<F = Val>>(&self, phase: usize, builder: &mut AB) {
        let main = builder.main();
        let (cur, nxt) = (main.current_slice(), main.next_slice());
        let c = |i: usize| -> AB::Expr { cur[i].into() };
        let n = |i: usize| -> AB::Expr { nxt[i].into() };
        let k = &self.kc;
        let pre = |l: usize, m: usize| c(k.pre[l][m]);
        let out = |l: usize, m: usize| c(k.out[l][m]);
        let fin = c(k.fin);
        let one = AB::Expr::ONE;
        let konst = |v: u64| AB::Expr::from(Val::from_u32(v as u32));
        let limb = |lane: u64, m: usize| (lane >> (16 * m)) & 0xffff;
        let pvs: Vec<AB::Expr> = builder.public_values().iter().map(|v| (*v).into()).collect();
        let radix = Val::from_u32(1 << 16);
        match DEP_PHASES[phase] {
            "keccak" => {
                let mut lane = LaneBuilder { inner: builder, off: 0, width: NUM_KECCAK_COLS };
                KeccakAir {}.eval(&mut lane);
            }
            "sched" => {
                for col in [KCV, KCH, KPAD, Z16, ACT] {
                    builder.assert_bool(cur[col]);
                }
                builder.assert_one(c(KCV) + c(KCH) + c(KPAD));
                builder.assert_zero(c(KPAD) - c(Z16));
                let e16 = c(EIX) - konst(DEP_CAP as u64);
                builder.assert_zero(e16.clone() * c(ZI) - (one.clone() - c(Z16)));
                builder.assert_zero(e16 * c(Z16));
                builder.assert_zero(c(FCV) - c(KCV) * fin.clone());
                builder.assert_zero(c(FCH) - c(KCH) * fin.clone());
                let mut t = builder.when_transition();
                // Cv → chain → Cv … → (after entry DEP_CAP − 1) padding.
                t.assert_zero(n(KCH) - c(KCH) - fin.clone() * (c(KCV) - c(KCH)));
                t.assert_zero(n(KCV) - c(KCV) - fin * (c(KCH) * (one.clone() - n(Z16)) - c(KCV)));
                t.assert_zero(n(EIX) - c(EIX) - c(FCH));
                // ACT is constant over an entry and never turns back on.
                t.assert_zero((one.clone() - c(FCH)) * (n(ACT) - c(ACT)));
                t.assert_zero(c(FCH) * n(ACT) * (one - c(ACT)));
            }
            "cv" => {
                let tag = cv_tag_lanes();
                for l in (0..3).chain(8..25) {
                    for m in 0..4 {
                        let v = match l {
                            0..=2 => limb(tag[l], m),
                            8 => u64::from(m == 0),
                            16 => limb(1 << 63, m),
                            _ => 0,
                        };
                        builder.assert_zero(c(KCV) * (pre(l, m) - konst(v)));
                    }
                }
                for m in 0..4 {
                    builder.assert_zero(c(KCV) * (one.clone() - c(ACT)) * pre(3, m));
                }
                let mut t = builder.when_transition();
                for j in 0..16 {
                    t.assert_zero(n(CV_OFF + j) - c(CV_OFF + j) - c(FCV) * (out(j / 4, j % 4) - c(CV_OFF + j)));
                }
            }
            "chain" => {
                let dom = depsum_domain_lanes();
                for l in 0..25 {
                    for m in 0..4 {
                        let e: AB::Expr = match l {
                            0..=3 => c(DIG_OFF + 4 * l + m),
                            4..=7 => c(CV_OFF + 4 * (l - 4) + m),
                            8 => konst(u64::from(m == 0)),
                            16 => konst(limb(1 << 63, m)),
                            21..=23 => konst(limb(dom[l - 21], m)),
                            _ => AB::Expr::ZERO,
                        };
                        builder.assert_zero(c(KCH) * (pre(l, m) - e));
                    }
                }
                let mut t = builder.when_transition();
                for j in 0..16 {
                    t.assert_zero(n(DIG_OFF + j) - c(DIG_OFF + j) - c(FCH) * c(ACT) * (out(j / 4, j % 4) - c(DIG_OFF + j)));
                }
                t.assert_zero(n(NCNT) - c(NCNT) - c(FCH) * c(ACT));
            }
            "acc" => {
                for b in 0..15 {
                    builder.assert_bool(cur[DCB_OFF + b]);
                }
                let mut t = builder.when_transition();
                for j in 0..4 {
                    t.assert_zero(n(SUM_OFF + j) - c(SUM_OFF + j) - c(FCV) * pre(3, j));
                }
            }
            "first" => {
                let mut f = builder.when_first_row();
                f.assert_one(c(KCV));
                f.assert_zero(c(EIX));
                f.assert_zero(c(NCNT));
                for j in 0..16 {
                    f.assert_zero(c(DIG_OFF + j));
                }
                for j in 0..4 {
                    f.assert_zero(c(SUM_OFF + j));
                }
            }
            "last" => {
                let carry = |j: usize| -> AB::Expr {
                    if j == 0 || j == 4 {
                        AB::Expr::ZERO
                    } else {
                        (0..5).fold(AB::Expr::ZERO, |a, i| a + c(DCB_OFF + 5 * (j - 1) + i) * Val::from_u32(1 << i))
                    }
                };
                let mut l = builder.when_last_row();
                l.assert_one(c(Z16));
                l.assert_zero(c(NCNT) - pvs[DPV_N].clone());
                for j in 0..16 {
                    l.assert_zero(c(DIG_OFF + j) - pvs[DPV_DIG + j].clone());
                }
                for j in 0..4 {
                    // D_batch limb j = SUM_j + c_j − 2^16 c_{j+1}; no carry out.
                    l.assert_zero(pvs[DPV_D + j].clone() - c(SUM_OFF + j) - carry(j) + carry(j + 1) * radix);
                }
            }
            other => unreachable!("phase {other}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Trace generation
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Prove / verify (the hiding L2 config)
// ---------------------------------------------------------------------------

/// The typed entry (condition (p)): `u32` PVs, every one a 16-bit word,
/// checked before the mod-p conversion; then the proof.
pub fn verify_dep_u32(pvs: &[u32], proof: &Proof<Config>) -> bool {
    pvs.len() == DEP_PV_LEN
        && pvs.iter().all(|v| *v < 1 << 16)
        && p3_uni_stark::verify(&qlab_l2::make_config_l2(), &DepAir::new(), proof, &qlab_l2::public_values(pvs)).is_ok()
}

/// The claims' `Cv` PVs of a bundle's members, in order.
pub fn claim_cvs<'a>(pvs: impl Iterator<Item = &'a [u32]>) -> Vec<Digest> {
    pvs.map(|p| crate::hash::pv_digest(p, qlab_air::claim::PV_CV)).collect()
}

// ---------------------------------------------------------------------------
// The constraint scan (tests and `f4dep --check`)
// ---------------------------------------------------------------------------

