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
#![cfg_attr(not(test), allow(dead_code))]
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_keccak_air::{generate_trace_rows, KeccakAir, NUM_KECCAK_COLS, NUM_ROUNDS};
use p3_matrix::dense::RowMajorMatrix;
use qlab_consensus::{Config, Proof, Val};

use crate::f3::cmp::limbs;
use crate::f3::leaf::{inv_or_zero, keccak_idx, out4, KeccakIdx};
use crate::f3::native::{Digest, EMPTY};
use crate::m4skel::LaneBuilder;

/// Entries per proof: the widest `k` a wrapper version proves.
pub(crate) const DEP_CAP: usize = 16;
const _: () = assert!(DEP_CAP >= super::wleaf::MAX_K);
/// The 5-bit carries cover `DEP_CAP` chunks plus a carry-in.
const _: () = assert!(DEP_CAP * 0xffff + 31 < 32 << 16);
pub(crate) const DEP_PERMS: usize = 2 * DEP_CAP;
pub(crate) const DEP_HEIGHT: usize = (DEP_PERMS * NUM_ROUNDS).next_power_of_two();

/// Public values: `n`, `D_batch` (4 limbs), `dig` (16 chunks); all 16-bit.
pub(crate) const DPV_N: usize = 0;
pub(crate) const DPV_D: usize = 1;
pub(crate) const DPV_DIG: usize = 5;
pub(crate) const DEP_PV_LEN: usize = 21;

/// One claim's opening: its value and blind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DepEntry {
    pub v: u64,
    pub r_v: Digest,
}

// ---------------------------------------------------------------------------
// Native
// ---------------------------------------------------------------------------

/// `"qumbra:l2-depsum:v1"` in capacity lanes 21..24.
pub(crate) fn depsum_domain_lanes() -> [u64; 3] {
    super::native::domain3(b"qumbra:l2-depsum:v1")
}

/// `CV_TAG` as its three lanes.
fn cv_tag_lanes() -> [u64; 3] {
    super::native::domain3(qlab_air::claim::CV_TAG)
}

/// The Cv block: `CV_TAG ‖ 00×3 ‖ v ‖ r_v`, padded (lanes 8, 16).
pub(crate) fn cv_state(v: u64, r_v: &Digest) -> [u64; 25] {
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
pub(crate) fn dep_state(d: &Digest, cv: &Digest) -> [u64; 25] {
    let mut st = [0u64; 25];
    st[..4].copy_from_slice(d);
    st[4..8].copy_from_slice(cv);
    st[8] = 1;
    st[16] = 1 << 63;
    st[21..24].copy_from_slice(&depsum_domain_lanes());
    st
}

/// `dig` over a list of value commitments, in order.
pub(crate) fn dep_chain(cvs: &[Digest]) -> Digest {
    cvs.iter().fold(EMPTY, |d, cv| out4(&dep_state(&d, cv)))
}

/// The deposit proof's public values for `entries`, or `None` when they do
/// not fit (more than [`DEP_CAP`], or a sum past 2^64 − 1).
pub(crate) fn dep_pvs(entries: &[DepEntry]) -> Option<Vec<u32>> {
    if entries.len() > DEP_CAP {
        return None;
    }
    let d = entries.iter().try_fold(0u64, |a, e| a.checked_add(e.v))?;
    let cvs: Vec<Digest> = entries.iter().map(|e| qlab_air::claim::claim_cv(e.v, &e.r_v)).collect();
    Some(pvs_of(entries.len(), d, &dep_chain(&cvs)))
}

fn pvs_of(n: usize, d: u64, dig: &Digest) -> Vec<u32> {
    let mut v = vec![n as u32];
    v.extend((0..4).map(|j| ((d >> (16 * j)) & 0xffff) as u32));
    v.extend(limbs(dig));
    debug_assert_eq!(v.len(), DEP_PV_LEN);
    v
}

// ---------------------------------------------------------------------------
// The AIR
// ---------------------------------------------------------------------------

pub(crate) const KCV: usize = NUM_KECCAK_COLS;
pub(crate) const KCH: usize = KCV + 1;
pub(crate) const KPAD: usize = KCH + 1;
/// The entry index (16 on the padding) and `[EIX = 16]` with its inverse witness.
pub(crate) const EIX: usize = KPAD + 1;
pub(crate) const Z16: usize = EIX + 1;
pub(crate) const ZI: usize = Z16 + 1;
pub(crate) const ACT: usize = ZI + 1;
/// `KCV · fin`, `KCH · fin`: materialized (degree 3 throughout).
pub(crate) const FCV: usize = ACT + 1;
pub(crate) const FCH: usize = FCV + 1;
pub(crate) const CV_OFF: usize = FCH + 1;
pub(crate) const DIG_OFF: usize = CV_OFF + 16;
/// The value accumulator: four unnormalized 16-bit-chunk sums.
pub(crate) const SUM_OFF: usize = DIG_OFF + 16;
pub(crate) const NCNT: usize = SUM_OFF + 4;
/// `D_batch`'s three carries, five bits each (used on the last row).
pub(crate) const DCB_OFF: usize = NCNT + 1;
pub(crate) const DEP_WIDTH: usize = DCB_OFF + 15;

pub(crate) const DEP_PHASES: &[&str] = &["keccak", "sched", "cv", "chain", "acc", "first", "last"];

pub(crate) struct DepAir {
    kc: KeccakIdx,
}

impl DepAir {
    pub(crate) fn new() -> Self {
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
    pub(crate) fn eval_phase<AB: AirBuilder<F = Val>>(&self, phase: usize, builder: &mut AB) {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Cv,
    Chain,
    Pad,
}

/// One perm's input and its registers (constant over its 24 rows).
#[derive(Clone, Debug)]
pub(crate) struct DepPerm {
    pub pre: [u64; 25],
    pub kind: Kind,
    pub eix: u32,
    pub act: bool,
    pub cv: Digest,
    pub dig: Digest,
    pub sum: [u64; 4],
    pub ncnt: u32,
}

#[derive(Clone, Debug)]
pub(crate) struct DepPlan {
    pub perms: Vec<DepPerm>,
    pub pad: DepPerm,
    /// `D_batch`'s carries.
    pub dcb: [u32; 3],
}

/// The plan for `entries` (unvalidated: a sum past 2^64 still renders; the
/// AIR refuses it). Entries past `DEP_CAP` are ignored.
pub(crate) fn dep_plan(entries: &[DepEntry]) -> DepPlan {
    let n = entries.len().min(DEP_CAP);
    let (mut cv, mut dig, mut sum, mut ncnt) = (EMPTY, EMPTY, [0u64; 4], 0u32);
    let mut perms = Vec::with_capacity(DEP_PERMS);
    for i in 0..DEP_CAP {
        let act = i < n;
        let e = entries.get(i).filter(|_| act).copied().unwrap_or(DepEntry { v: 0, r_v: EMPTY });
        let pre = cv_state(e.v, &e.r_v);
        perms.push(DepPerm { pre, kind: Kind::Cv, eix: i as u32, act, cv, dig, sum, ncnt });
        cv = out4(&pre);
        for (j, s) in sum.iter_mut().enumerate() {
            *s += (e.v >> (16 * j)) & 0xffff;
        }
        let pre = dep_state(&dig, &cv);
        perms.push(DepPerm { pre, kind: Kind::Chain, eix: i as u32, act, cv, dig, sum, ncnt });
        if act {
            dig = out4(&pre);
            ncnt += 1;
        }
    }
    let pad = DepPerm { pre: [0; 25], kind: Kind::Pad, eix: DEP_CAP as u32, act: false, cv, dig, sum, ncnt };
    let mut dcb = [0u32; 3];
    let mut c = 0u64;
    for (j, b) in dcb.iter_mut().enumerate() {
        c = (sum[j] + c) >> 16;
        *b = c as u32;
    }
    DepPlan { perms, pad, dcb }
}

/// Render the plan.
pub(crate) fn dep_render(plan: &DepPlan) -> RowMajorMatrix<Val> {
    let inputs: Vec<[u64; 25]> = plan.perms.iter().map(|p| p.pre).collect();
    let keccak = generate_trace_rows::<Val>(inputs, 0);
    let height = keccak.values.len() / NUM_KECCAK_COLS;
    assert_eq!(height, DEP_HEIGHT);
    let mut values = Val::zero_vec(height * DEP_WIDTH);
    for (r, row) in values.chunks_exact_mut(DEP_WIDTH).enumerate() {
        row[..NUM_KECCAK_COLS].copy_from_slice(&keccak.values[r * NUM_KECCAK_COLS..(r + 1) * NUM_KECCAK_COLS]);
        let p = plan.perms.get(r / NUM_ROUNDS).unwrap_or(&plan.pad);
        let fin = r % NUM_ROUNDS == NUM_ROUNDS - 1;
        let b = Val::from_bool;
        row[KCV] = b(p.kind == Kind::Cv);
        row[KCH] = b(p.kind == Kind::Chain);
        row[KPAD] = b(p.kind == Kind::Pad);
        let e16 = Val::from_u32(p.eix) - Val::from_u32(DEP_CAP as u32);
        row[EIX] = Val::from_u32(p.eix);
        row[Z16] = b(p.eix as usize == DEP_CAP);
        row[ZI] = inv_or_zero(e16);
        row[ACT] = b(p.act);
        row[FCV] = b(p.kind == Kind::Cv && fin);
        row[FCH] = b(p.kind == Kind::Chain && fin);
        for (j, l) in limbs(&p.cv).iter().enumerate() {
            row[CV_OFF + j] = Val::from_u32(*l);
        }
        for (j, l) in limbs(&p.dig).iter().enumerate() {
            row[DIG_OFF + j] = Val::from_u32(*l);
        }
        for j in 0..4 {
            row[SUM_OFF + j] = Val::from_u32(p.sum[j] as u32);
        }
        row[NCNT] = Val::from_u32(p.ncnt);
        for j in 0..3 {
            for i in 0..5 {
                row[DCB_OFF + 5 * j + i] = Val::from_u32((plan.dcb[j] >> i) & 1);
            }
        }
    }
    RowMajorMatrix::new(values, DEP_WIDTH)
}

// ---------------------------------------------------------------------------
// Prove / verify (the hiding L2 config)
// ---------------------------------------------------------------------------

/// Prove the deposit sum of `entries`; `None` if they do not fit.
pub(crate) fn prove_dep(entries: &[DepEntry]) -> Option<(Vec<u32>, Proof<Config>)> {
    let pvs = dep_pvs(entries)?;
    let trace = dep_render(&dep_plan(entries));
    let proof = p3_uni_stark::prove(&qlab_l2::make_config_l2(), &DepAir::new(), trace, &qlab_l2::public_values(&pvs));
    Some((pvs, proof))
}

/// The typed entry (condition (p)): `u32` PVs, every one a 16-bit word,
/// checked before the mod-p conversion; then the proof.
pub(crate) fn verify_dep_u32(pvs: &[u32], proof: &Proof<Config>) -> bool {
    pvs.len() == DEP_PV_LEN
        && pvs.iter().all(|v| *v < 1 << 16)
        && p3_uni_stark::verify(&qlab_l2::make_config_l2(), &DepAir::new(), proof, &qlab_l2::public_values(pvs)).is_ok()
}

/// The claims' `Cv` PVs of a bundle's members, in order.
pub(crate) fn claim_cvs<'a>(pvs: impl Iterator<Item = &'a [u32]>) -> Vec<Digest> {
    pvs.map(|p| crate::f3::leaf::pv_digest(p, qlab_air::claim::PV_CV)).collect()
}

// ---------------------------------------------------------------------------
// The constraint scan (tests and `f4dep --check`)
// ---------------------------------------------------------------------------

fn dep_phase_ranges(air: &DepAir) -> Vec<std::ops::Range<usize>> {
    use p3_air::symbolic::{AirLayout, SymbolicAirBuilder};
    let layout = AirLayout::from_air::<Val>(air);
    let mut start = 0;
    (0..DEP_PHASES.len())
        .map(|phase| {
            let mut builder = SymbolicAirBuilder::<Val>::new(layout);
            air.eval_phase(phase, &mut builder);
            let end = start + builder.base_constraints().len();
            let r = start..end;
            start = end;
            r
        })
        .collect()
}

/// The lowest failing row and its constraint groups.
pub(crate) fn dep_first_violation(trace: &RowMajorMatrix<Val>, pvs: &[u32]) -> Option<(usize, Vec<&'static str>)> {
    use p3_air::DebugConstraintBuilder;
    use p3_matrix::dense::RowMajorMatrixView;
    use p3_matrix::stack::ViewPair;
    use p3_matrix::Matrix;
    let air = DepAir::new();
    let vals = qlab_l2::public_values(pvs);
    let height = trace.height();
    let ranges = dep_phase_ranges(&air);
    (0..height).find_map(|row| {
        let local = trace.row_slice(row).expect("a row");
        let nxt = trace.row_slice((row + 1) % height).expect("a row");
        let main = ViewPair::new(RowMajorMatrixView::new_row(&*local), RowMajorMatrixView::new_row(&*nxt));
        let prep = ViewPair::new(RowMajorMatrixView::new(&[], 0), RowMajorMatrixView::new(&[], 0));
        let mut b = DebugConstraintBuilder::new(
            row,
            main,
            prep,
            &vals,
            Val::from_bool(row == 0),
            Val::from_bool(row == height - 1),
            Val::from_bool(row != height - 1),
            &[],
        );
        air.eval(&mut b);
        let f: Vec<usize> = b.into_failures().into_iter().map(|f| f.constraint).collect();
        (!f.is_empty()).then(|| {
            let mut ph: Vec<&'static str> =
                f.iter().map(|c| DEP_PHASES[ranges.iter().position(|r| r.contains(c)).expect("a constraint")]).collect();
            ph.dedup();
            (row, ph)
        })
    })
}

/// A fixed fixture: `n` entries of 40-bit values (their limb sums carry).
pub(crate) fn dep_entries(n: usize, seed: u64) -> Vec<DepEntry> {
    let mut rng = crate::f3::native::Rng(seed);
    (0..n).map(|_| DepEntry { v: rng.digest()[0] >> 24, r_v: rng.digest() }).collect()
}

/// `qlab-bench f4dep --check [--n N]`: an honest deposit trace, scanned in full.
pub(crate) fn check(args: &[String]) -> Result<(), String> {
    let n = args.iter().position(|a| a == "--n").and_then(|i| args.get(i + 1)).map_or(Ok(3), |s| s.parse::<usize>()).map_err(|e| e.to_string())?;
    let entries = dep_entries(n, 0x775_de9);
    let pvs = dep_pvs(&entries).ok_or("the entries do not fit")?;
    let t = std::time::Instant::now();
    let trace = dep_render(&dep_plan(&entries));
    let gen = t.elapsed();
    let v = dep_first_violation(&trace, &pvs);
    println!(
        "# f4dep --check n={n}: {} rows x {} cols; gen {gen:.2?}, scan {:.2?}; {}",
        DEP_HEIGHT,
        DEP_WIDTH,
        t.elapsed() - gen,
        match &v {
            None => "every row holds".to_string(),
            Some((r, ph)) => format!("VIOLATED at row {r} (perm {}, round {}): {ph:?}", r / 24, r % 24),
        }
    );
    v.map_or(Ok(()), |_| Err("the honest deposit trace does not hold".into()))
}

#[cfg(test)]
mod tests {
    use p3_air::symbolic::{get_max_constraint_degree, AirLayout};

    use super::*;

    const SEED: u64 = 0x775_de9;

    fn row(perm: usize, r: usize) -> usize {
        NUM_ROUNDS * perm + r
    }

    /// `(name, entries, plan tamper, PV tamper, want row, want group)`.
    fn judge(entries: &[DepEntry], tamper: impl FnOnce(&mut DepPlan, &mut Vec<u32>)) -> Option<(usize, Vec<&'static str>)> {
        let mut plan = dep_plan(entries);
        let mut pvs = dep_pvs(entries).unwrap_or_else(|| {
            // A sum past 2^64: the PVs a cheating prover would claim (wrapped).
            let d = entries.iter().fold(0u64, |a, e| a.wrapping_add(e.v));
            let cvs: Vec<Digest> = entries.iter().map(|e| qlab_air::claim::claim_cv(e.v, &e.r_v)).collect();
            pvs_of(entries.len(), d, &dep_chain(&cvs))
        });
        tamper(&mut plan, &mut pvs);
        dep_first_violation(&dep_render(&plan), &pvs)
    }

    #[test]
    fn f4dep_program_width_degree_and_honest() {
        let air = DepAir::new();
        assert_eq!(get_max_constraint_degree::<Val, _>(&air, AirLayout::from_air::<Val>(&air)), 3);
        assert_eq!((DEP_HEIGHT, DEP_WIDTH), (1 << 10, NUM_KECCAK_COLS + 61));
        for n in [0, 1, 3, DEP_CAP] {
            let e = dep_entries(n, SEED);
            assert_eq!(judge(&e, |_, _| {}), None, "n = {n}");
        }
        // The native chain is what the claims' Cv PVs chain to.
        let e = dep_entries(3, SEED);
        let pvs = dep_pvs(&e).unwrap();
        let cvs: Vec<Digest> = e.iter().map(|x| qlab_air::claim::claim_cv(x.v, &x.r_v)).collect();
        assert_eq!(crate::f3::leaf::pv_digest(&pvs, DPV_DIG), dep_chain(&cvs));
        // The Cv block is the claim circuit's (F1's frozen commitment).
        assert_eq!(out4(&cv_state(e[0].v, &e[0].r_v)), qlab_air::claim::claim_cv(e[0].v, &e[0].r_v));
        // The 40-bit values' limb sums carry.
        assert!(dep_plan(&e).dcb.iter().any(|c| *c > 0));
    }

    type Got = Option<(usize, Vec<&'static str>)>;

    /// Condition (s): each negative's lowest failing row and group.
    #[test]
    fn f4dep_negatives() {
        let e = dep_entries(3, SEED);
        let last = DEP_HEIGHT - 1;
        let cases: Vec<(&str, Got, usize, &str)> = vec![
            (
                "a v not opening its Cv (the register kept)",
                judge(&e, |p, _| p.perms[2].pre[3] += 1),
                row(2, 23),
                "cv",
            ),
            (
                "a wrong carry",
                judge(&e, |p, _| p.dcb[0] ^= 1),
                last,
                "last",
            ),
            (
                "a sum past 2^64 − 1",
                judge(&[DepEntry { v: u64::MAX, r_v: EMPTY }, DepEntry { v: 2, r_v: EMPTY }], |_, _| {}),
                last,
                "last",
            ),
            (
                "an idle entry with v != 0",
                judge(&e, |p, _| p.perms[2 * 3].pre[3] = 5),
                row(2 * 3, 0),
                "cv",
            ),
            (
                "an idle entry chained",
                judge(&e, |p, _| {
                    let d = out4(&p.perms[2 * 3 + 1].pre);
                    for q in p.perms.iter_mut().skip(2 * 3 + 2) {
                        q.dig = d;
                    }
                    p.pad.dig = d;
                }),
                row(2 * 3 + 1, 23),
                "chain",
            ),
            (
                "an entry switched back on",
                judge(&e, |p, _| {
                    p.perms[2 * 4].act = true;
                    p.perms[2 * 4 + 1].act = true;
                }),
                row(2 * 3 + 1, 23),
                "sched",
            ),
            (
                "a forged tag lane",
                judge(&e, |p, _| p.perms[0].pre[0] ^= 1),
                0,
                "cv",
            ),
            (
                "dig over the list with its last entry dropped",
                judge(&e, |_, pvs| {
                    let cvs: Vec<Digest> = e[..2].iter().map(|x| qlab_air::claim::claim_cv(x.v, &x.r_v)).collect();
                    pvs[DPV_DIG..DPV_DIG + 16].copy_from_slice(&limbs(&dep_chain(&cvs)));
                }),
                last,
                "last",
            ),
            (
                "n one more than the entries",
                judge(&e, |_, pvs| pvs[DPV_N] += 1),
                last,
                "last",
            ),
            (
                "D_batch one off",
                judge(&e, |_, pvs| pvs[DPV_D] += 1),
                last,
                "last",
            ),
        ];
        let missed: Vec<String> = cases
            .iter()
            .filter(|(_, got, r, ph)| !matches!(got, Some((gr, gph)) if gr == r && gph.contains(ph)))
            .map(|(name, got, r, ph)| format!("{name}: want row {r} {ph}, got {got:?}"))
            .collect();
        assert!(missed.is_empty(), "{missed:#?}");
    }

    /// The hiding prove round trip, and the u32 gate before it (condition (p)).
    #[test]
    fn f4dep_prove_verify() {
        let e = dep_entries(3, SEED);
        let (pvs, proof) = prove_dep(&e).expect("fits");
        assert!(verify_dep_u32(&pvs, &proof));
        let mut bad = pvs.clone();
        bad[DPV_D] += 1;
        assert!(!verify_dep_u32(&bad, &proof), "D_batch moved");
        let mut wide = pvs.clone();
        wide[DPV_DIG] += 1 << 16;
        assert!(!verify_dep_u32(&wide, &proof), "a 17-bit word, refused before conversion");
        use p3_field::PrimeField32;
        let mut p_plus = pvs.clone();
        p_plus[DPV_N] += Val::ORDER_U32;
        assert!(!verify_dep_u32(&p_plus, &proof), "p + n");
        assert!(prove_dep(&dep_entries(DEP_CAP + 1, SEED)).is_none());
    }
}
