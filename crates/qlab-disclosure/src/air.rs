//! The disclosure AIR: a narrow-Keccak sponge pipeline proving the two hashes
//! of the wallet-interop §3 claim, with the recipient key material `rkm` bound
//! across them.
//!
//! ## Reused core
//!
//! The z-slice Keccak-f[1600] pipeline (128 rows/round, three packed shift
//! registers S/V/U, the in-trace rotating iota-RC ring, and the program /
//! perm-boundary / phase rings) is the qlab-air M1.5c narrow core, adapted
//! here — same constraints, cross-checked against `qlab_air::reference`. What
//! is NEW is the *program*: a fixed 12-permutation schedule for the disclosure
//! statement, a genuine multi-block sponge (capacity-chaining + rate-XOR
//! absorb — the address commitment is 1,233 bytes = 10 rate blocks), and the
//! `rkm` cross-binding.
//!
//! ## Schedule (12 permutations, then DUMMY padding)
//!
//! ```text
//!   perm  0: CM       overwrite-absorb value‖rkm‖rho‖rseed‖pad10*1  -> cm digest
//!   perm  1: ADDR0    overwrite-absorb raw-address bytes[0..136]    (capacity := 0)
//!   perms 2..10: ADDRMID  xor-absorb raw-address bytes[136*i..]     (blocks 1..8)
//!   perm 10: ADDREND  xor-absorb raw-address bytes[1224..1233]‖pad  (block 9)
//!   perm 11: ACLOSE   pure chain — exposes the address digest to be closed
//! ```
//!
//! Because the schedule is short and never wraps (12 real perms ≪ the ~21 that
//! fit in 2^16 rows) and padding is all-DUMMY, no epoch one-shot is needed:
//! a role selector is true at exactly one perm, so each capture/close fires
//! once.
//!
//! ## What is proven
//!
//! - `cm` (public) == the CM permutation's output, closed chunk-for-chunk.
//! - `addr_commitment` (public) == the address sponge's final output, closed.
//! - `value` (public) == the value absorbed into `cm`.
//! - `rkm` inside `cm` (lanes 1..5, aligned) == `rkm` inside the address
//!   preimage (raw bytes 17..49, byte-misaligned in sponge block 0). Bound by a
//!   signed 16×16-bit accumulator: the CM side adds, the ADDR0 side subtracts
//!   through free periodic routing columns; the accumulator must be zero.
//!
//! All constraints are degree ≤ 3.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use qlab_air::reference::{RC, RHO};

// ---------------------------------------------------------------------------
// Column map — core (identical to qlab-air narrow M1.5c, cols 0..402)
// ---------------------------------------------------------------------------

const A_OFF: usize = 0; // 25: round-input bits (chi output) — real on M rows
const C_OFF: usize = 25; // 5: column parities of `eff`
const US_OFF: usize = 30; // 25: unpack of S slot 1 (chi inputs)
const AP_OFF: usize = 55; // 25: theta outputs — real on T rows
const X00_COL: usize = 80; // 1: chi lane (0,0) before iota
const S_OFF: usize = 81; // 126 slots (d = 1..=126)
const S_SLOTS: usize = 126;
const V_OFF: usize = S_OFF + S_SLOTS; // 207: 64 slots
const V_SLOTS: usize = 64;
const UV_OFF: usize = V_OFF + V_SLOTS; // 271: 25: unpack of V slot 1
const U_OFF: usize = UV_OFF + 25; // 296: 65 slots
const U_SLOTS: usize = 65;
const UU_OFF: usize = U_OFF + U_SLOTS; // 361: 10: unpack of U slot 1
const R_OFF: usize = UU_OFF + 10; // 371: 24 rotating iota-RC registers
const B_OFF: usize = R_OFF + 24; // 395: 7: bit-decomposition of R[0]

// --- program machinery (phase-packed ring, copied from narrow) ---
const PB_OFF: usize = B_OFF + 7; // 402: 24: perm-boundary ring [1,0,..]
const PH_OFF: usize = PB_OFF + 24; // 426: 4: perm-phase ring (mod-4 counter)
const PR_OFF: usize = PH_OFF + 4; // 430: 24: program ring, 4 slots x 4 bits/limb
const D_OFF: usize = PR_OFF + 24; // 454: 16: bit-decomposition of PR[0]
const RB_OFF: usize = D_OFF + 16; // 470: 4: current perm's role bits

// --- disclosure program: roles, injection, sponge, binding ---
// Half-selectors materialize the four (r0,r1) and four (r2,r3) products so the
// final role selector is a deg-2 product of two deg-1 columns (deg ≤ 3 house
// rule; a direct 4-bit product would be deg 4).
const HS_OFF: usize = RB_OFF + 4; // 474: 8 [lo_0..3, hi_0..3]
const NSEL: usize = 5; // [cm, addr0, addrmid, addrend, aclose]
const SEL_OFF: usize = HS_OFF + 8; // 482
const INJ_OFF: usize = SEL_OFF + NSEL; // 487: 3: [inj_cm, inj_addr0, inj_xor]
const G4_COL: usize = INJ_OFF + 3; // 490: program-ring rotation gate
const W_OFF: usize = G4_COL + 1; // 491: 17 witness lanes (sponge rate block)
const NW: usize = 17;
const BQCM_OFF: usize = W_OFF + NW; // 508: 16: cm-digest capture bank
const BQAD_OFF: usize = BQCM_OFF + 16; // 524: 16: addr-digest capture bank
const BVAL_OFF: usize = BQAD_OFF + 16; // 540: 4: value capture bank
const RKM_OFF: usize = BVAL_OFF + 4; // 544: 16: rkm signed cross-binding accumulator
const GCAP_OFF: usize = RKM_OFF + 16; // 560: 5: [cmcap, adcap, valcap, rkmcm, rkmad]
const GCLOSE_OFF: usize = GCAP_OFF + 5; // 565: 4: [cmclose, adclose, valclose, rkmclose]
const EFF_OFF: usize = GCLOSE_OFF + 4; // 569: 25: effective round input
pub const DISCLOSURE_WIDTH: usize = EFF_OFF + 25; // 594

/// Perm slots per program period (4-bit roles packed 4 per limb, 24 limbs).
pub const PROGRAM_SLOTS: usize = 96;

// Role codes.
pub const ROLE_DUMMY: u32 = 0;
pub const ROLE_CM: u32 = 1;
pub const ROLE_ADDR0: u32 = 2;
pub const ROLE_ADDRMID: u32 = 3;
pub const ROLE_ADDREND: u32 = 4;
pub const ROLE_ACLOSE: u32 = 5;

/// Rows per 24-round permutation.
pub const ROWS_PER_PERM: usize = 24 * 128;

/// Keccak-256 rate in lanes (17 * 8 = 136 bytes) and the raw address length.
pub const RATE_LANES: usize = 17;
pub const RAW_ADDR_LEN: usize = 1233;

// --- public values ---
pub const PV_CM: usize = 0; // 16 chunks
pub const PV_ADDR: usize = 16; // 16 chunks
pub const PV_VALUE: usize = 32; // 4 chunks
pub const PV_LEN: usize = 36;

/// Pack a 256-bit digest ([u64;4]) into 16 sixteen-bit chunks
/// (index 4*lane + chunk = bits [16*chunk .. 16*chunk+16) of the lane).
pub fn pv_chunks(d: &[u64; 4]) -> [u32; 16] {
    core::array::from_fn(|i| ((d[i / 4] >> (16 * (i % 4))) & 0xffff) as u32)
}

/// Build the public-value vector for a disclosure instance.
pub fn pv_vec(cm: &[u64; 4], addr_commitment: &[u64; 4], value: u64) -> Vec<u32> {
    let mut out = Vec::with_capacity(PV_LEN);
    out.extend_from_slice(&pv_chunks(cm));
    out.extend_from_slice(&pv_chunks(addr_commitment));
    for j in 0..4 {
        out.push(((value >> (16 * j)) & 0xffff) as u32);
    }
    out
}

const fn s_col(d: usize) -> usize {
    S_OFF + d - 1
}
const fn v_col(d: usize) -> usize {
    V_OFF + d - 1
}
const fn u_col(d: usize) -> usize {
    U_OFF + d - 1
}

/// Inverse pi (from narrow): chi's B[bx][by] is the post-rho image of birth
/// lane INV_PI[bx + 5*by].
const fn inv_pi() -> [usize; 25] {
    let mut out = [0usize; 25];
    let mut bx = 0;
    while bx < 5 {
        let mut by = 0;
        while by < 5 {
            let y = bx;
            let x = (3 * (by + 15 - 3 * bx)) % 5;
            out[bx + 5 * by] = x + 5 * y;
            by += 1;
        }
        bx += 1;
    }
    out
}
const INV_PI: [usize; 25] = inv_pi();

// ---------------------------------------------------------------------------
// rkm cross-binding: the ADDR0 routing table
// ---------------------------------------------------------------------------
//
// In `cm`, rkm occupies aligned lanes 1..5. In the raw address, rkm is bytes
// 17..49, i.e. block-0 bits 136..392 — byte-misaligned by 8 bits. Canonical
// rkm bit k (0..256) lives at block bit 136+k, i.e. lane (136+k)/64 bit
// (136+k)%64, which at ADDR0 boundary row z is witness lane L with L*64+z-136 =
// k. Each such (L, canonical-chunk c=k>>4) pair gets a free periodic routing
// column giving weight 2^(k%16) at the rows where it is active.

/// The distinct (witness lane L, canonical chunk c) pairs the ADDR0 side routes
/// rkm bits through, in a fixed order shared by `periodic_columns` and `eval`.
fn addr_rkm_routes() -> Vec<(usize, usize)> {
    let mut v = Vec::new();
    for l in 2..=6usize {
        for z in 0..64usize {
            let pos = l * 64 + z;
            if (136..136 + 256).contains(&pos) {
                let c = (pos - 136) >> 4;
                if !v.contains(&(l, c)) {
                    v.push((l, c));
                }
            }
        }
    }
    v
}

/// The weight (2^(k%16)) contributed by routing lane `l` to chunk `c` at
/// boundary row `z`, or 0 when that (l, c) is not active at `z`.
fn addr_rkm_weight(l: usize, c: usize, z: usize) -> u32 {
    let pos = l * 64 + z;
    if (136..136 + 256).contains(&pos) {
        let k = pos - 136;
        if (k >> 4) == c {
            return 1u32 << (k % 16);
        }
    }
    0
}

// ---------------------------------------------------------------------------
// The AIR
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct DisclosureAir {
    pub log_height: usize,
    /// 4-bit role code per program slot.
    pub program: [u32; PROGRAM_SLOTS],
    /// Witness per program slot (17 sponge rate lanes), cycled through padding.
    pub slot_witness: Vec<[u64; NW]>,
}

impl DisclosureAir {
    /// All-DUMMY instance: pure Keccak chaining (used to validate the core port).
    pub fn chain_only(log_height: usize) -> Self {
        Self {
            log_height,
            program: [ROLE_DUMMY; PROGRAM_SLOTS],
            slot_witness: Vec::new(),
        }
    }

    /// Program-ring limb i: slots 4i..4i+4, 4 bits each.
    fn pr_limb(&self, i: usize) -> u32 {
        (0..4)
            .map(|j| self.program[(4 * i + j) % PROGRAM_SLOTS] << (4 * j))
            .sum()
    }

    /// Round-constant bit consumed at row `t` (narrow's rc_bit).
    fn rc_bit(t: usize) -> bool {
        let z = t % 64;
        let mrow = (t / 64) % 2 == 0;
        if !mrow {
            return false;
        }
        let q = t / 128;
        (RC[(q + 23) % 24] >> z) & 1 == 1
    }

    /// 7-bit pack of RC[j] (narrow's rc_pack).
    fn rc_pack(j: usize) -> u32 {
        (0..7)
            .map(|k| (((RC[j] >> ((1u32 << k) - 1)) & 1) as u32) << k)
            .sum()
    }
}

impl<F: Field> BaseAir<F> for DisclosureAir {
    fn width(&self) -> usize {
        DISCLOSURE_WIDTH
    }

    fn num_public_values(&self) -> usize {
        PV_LEN
    }

    fn num_periodic_columns(&self) -> usize {
        39 + addr_rkm_routes().len()
    }

    /// Periodic columns (period 128):
    /// `[mrow, u63, e1_0..e1_24, blast, iotasel_0..6, pwk_0..3, addr-routes..]`
    /// (the first 39 are narrow's core schedule; the rest are the free ADDR0
    /// rkm routing weights).
    fn periodic_columns(&self) -> Vec<Vec<F>> {
        let routes = addr_rkm_routes();
        let ncols = 39 + routes.len();
        let mut cols = vec![Vec::with_capacity(128); ncols];
        for t in 0..128usize {
            let mrow = t < 64;
            cols[0].push(F::from_bool(mrow));
            cols[1].push(F::from_bool(t == 63));
            for l in 0..25 {
                let wrap = !mrow && (t - 64) + RHO[l] as usize >= 64;
                cols[2 + l].push(F::from_bool(wrap));
            }
            cols[27].push(F::from_bool(t == 127));
            for k in 0..7 {
                cols[28 + k].push(F::from_bool(mrow && t == (1 << k) - 1));
            }
            let z = t % 64;
            for j in 0..4 {
                let v = if mrow && z / 16 == j {
                    F::from_u32(1 << (z % 16))
                } else {
                    F::ZERO
                };
                cols[35 + j].push(v);
            }
            // ADDR0 rkm routing weights (active only on M rows).
            for (i, (l, c)) in routes.iter().enumerate() {
                let w = if mrow { addr_rkm_weight(*l, *c, z) } else { 0 };
                cols[39 + i].push(F::from_u32(w));
            }
        }
        cols
    }
}

/// xor of two bit expressions: a + b - 2ab.
fn xor2<E>(a: E, b: E, two: E) -> E
where
    E: Clone + core::ops::Add<Output = E> + core::ops::Sub<Output = E> + core::ops::Mul<Output = E>,
{
    a.clone() + b.clone() - two * a * b
}

impl<AB: AirBuilder> Air<AB> for DisclosureAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let two = AB::Expr::TWO;

        let main = builder.main();
        let local: Vec<AB::Expr> = main.current_slice().iter().map(|v| (*v).into()).collect();
        let next: Vec<AB::Expr> = main.next_slice().iter().map(|v| (*v).into()).collect();

        let per: Vec<AB::Expr> = builder
            .periodic_values()
            .iter()
            .map(|v| (*v).into())
            .collect();
        let mrow = per[0].clone();
        let u63 = per[1].clone();
        let e1 = |l: usize| per[2 + l].clone();
        let blast = per[27].clone();
        let sel = |k: usize| per[28 + k].clone();
        let pwk = |j: usize| per[35 + j].clone();
        let trow = AB::Expr::ONE - mrow.clone();

        let rc = (0..7)
            .map(|k| sel(k) * local[B_OFF + k].clone())
            .fold(AB::Expr::ZERO, |acc, e| acc + e);

        let a = |l: usize| local[A_OFF + l].clone();
        let eff = |l: usize| local[EFF_OFF + l].clone();
        let c = |x: usize| local[C_OFF + x].clone();
        let us = |l: usize| local[US_OFF + l].clone();
        let ap = |l: usize| local[AP_OFF + l].clone();
        let uv = |l: usize| local[UV_OFF + l].clone();
        let uu = |i: usize| local[UU_OFF + i].clone();
        let x00 = local[X00_COL].clone();
        let w = |i: usize| local[W_OFF + i].clone();

        // ---- Same-row core constraints (identical to narrow) ----
        for l in 0..25 {
            builder.assert_bool(local[US_OFF + l].clone());
            builder.assert_bool(local[UV_OFF + l].clone());
        }
        for i in 0..10 {
            builder.assert_bool(local[UU_OFF + i].clone());
        }
        for x in 0..5 {
            builder.assert_bool(local[C_OFF + x].clone());
        }
        let weighted = |off: usize, n: usize, row: &[AB::Expr]| -> AB::Expr {
            (0..n)
                .map(|i| row[off + i].clone() * AB::Expr::from_u32(1 << i))
                .fold(AB::Expr::ZERO, |acc, e| acc + e)
        };
        builder.assert_eq(weighted(US_OFF, 25, &local), local[s_col(1)].clone());
        builder.assert_eq(weighted(UV_OFF, 25, &local), local[v_col(1)].clone());
        builder.assert_eq(weighted(UU_OFF, 10, &local), local[u_col(1)].clone());

        let b = |bx: usize, by: usize| us(INV_PI[bx + 5 * by]);
        let chi = |x: usize, y: usize| -> AB::Expr {
            let b0 = b(x, y);
            let b1 = b((x + 1) % 5, y);
            let b2 = b((x + 2) % 5, y);
            let and = (AB::Expr::ONE - b1) * b2;
            xor2(b0, and, two.clone())
        };
        for y in 0..5 {
            for x in 0..5 {
                if (x, y) != (0, 0) {
                    builder.assert_eq(a(x + 5 * y), chi(x, y));
                }
            }
        }
        builder.assert_eq(x00.clone(), chi(0, 0));
        builder.assert_eq(a(0), xor2(x00, rc, two.clone()));

        // Column parity of the EFFECTIVE round input.
        for x in 0..5 {
            let s = (0..5)
                .map(|y| eff(x + 5 * y))
                .fold(AB::Expr::ZERO, |acc, e| acc + e);
            let d = s - c(x);
            builder.assert_zero(
                d.clone() * (d.clone() - two.clone()) * (d - two.clone() * two.clone()),
            );
        }

        // Theta.
        for y in 0..5 {
            for x in 0..5 {
                let p = uv(x + 5 * y);
                let q = uu((x + 4) % 5);
                let r = uu(5 + (x + 1) % 5);
                let xor3 = p.clone() + q.clone() + r.clone()
                    - two.clone() * (p.clone() * q.clone() + p.clone() * r.clone() + q.clone() * r.clone())
                    + two.clone() * two.clone() * p * q * r;
                builder.assert_eq(ap(x + 5 * y), xor3);
            }
        }

        // ---- Program rings (identical to narrow) ----
        for i in 0..24 {
            builder.when_first_row().assert_eq(
                local[PB_OFF + i].clone(),
                if i == 0 { AB::Expr::ONE } else { AB::Expr::ZERO },
            );
        }
        for i in 0..4 {
            builder.when_first_row().assert_eq(
                local[PH_OFF + i].clone(),
                if i == 0 { AB::Expr::ONE } else { AB::Expr::ZERO },
            );
        }
        for i in 0..24 {
            builder.when_first_row().assert_eq(
                local[PR_OFF + i].clone(),
                AB::Expr::from_u32(self.pr_limb(i)),
            );
        }
        for k in 0..16 {
            builder.assert_bool(local[D_OFF + k].clone());
        }
        builder.assert_eq(weighted(D_OFF, 16, &local), local[PR_OFF].clone());
        for k in 0..4 {
            let sel_quarter = (0..4)
                .map(|phi| {
                    local[PH_OFF + (4 - phi) % 4].clone() * local[D_OFF + 4 * phi + k].clone()
                })
                .fold(AB::Expr::ZERO, |acc, e| acc + e);
            builder.assert_eq(local[RB_OFF + k].clone(), sel_quarter);
        }

        // Materialize the eight two-bit half-selectors (deg 2), then each role
        // selector is a deg-2 product of two materialized halves (deg ≤ 3).
        let r = |k: usize| local[RB_OFF + k].clone();
        let pair = |b0: AB::Expr, b1: AB::Expr, j: u32| -> AB::Expr {
            let t0 = if j & 1 == 1 { b0 } else { AB::Expr::ONE - b0 };
            let t1 = if j & 2 == 2 { b1 } else { AB::Expr::ONE - b1 };
            t0 * t1
        };
        for j in 0..4u32 {
            builder.assert_eq(local[HS_OFF + j as usize].clone(), pair(r(0), r(1), j));
            builder.assert_eq(local[HS_OFF + 4 + j as usize].clone(), pair(r(2), r(3), j));
        }
        let lo = |j: u32| local[HS_OFF + j as usize].clone();
        let hi = |j: u32| local[HS_OFF + 4 + j as usize].clone();
        let sel_codes: [u32; NSEL] = [ROLE_CM, ROLE_ADDR0, ROLE_ADDRMID, ROLE_ADDREND, ROLE_ACLOSE];
        for (i, code) in sel_codes.iter().enumerate() {
            builder.assert_eq(local[SEL_OFF + i].clone(), lo(code & 3) * hi((code >> 2) & 3));
        }
        let selr = |i: usize| local[SEL_OFF + i].clone();

        // Boundary + perm gates.
        let bnd = mrow.clone() * local[PB_OFF].clone();
        let gperm = blast.clone() * local[PB_OFF + 1].clone();

        // Injection gates: inj_cm, inj_addr0, inj_xor (materialized, deg <= 3).
        builder.assert_eq(local[INJ_OFF].clone(), bnd.clone() * selr(0));
        builder.assert_eq(local[INJ_OFF + 1].clone(), bnd.clone() * selr(1));
        builder.assert_eq(
            local[INJ_OFF + 2].clone(),
            bnd.clone() * (selr(2) + selr(3)),
        );
        let inj_cm = local[INJ_OFF].clone();
        let inj_addr0 = local[INJ_OFF + 1].clone();
        let inj_xor = local[INJ_OFF + 2].clone();

        // Program-ring rotation gate.
        builder.assert_eq(
            local[G4_COL].clone(),
            blast.clone() * local[PB_OFF + 1].clone() * local[PH_OFF + 1].clone(),
        );

        // Witness bits.
        for i in 0..NW {
            builder.assert_bool(local[W_OFF + i].clone());
        }

        // ---- eff: role-multiplexed injection ----
        // CM (overwrite): value|rkm|rho|rseed at lanes 0..13, pad10*1 at
        //   lane 13 z0 and lane 16 z63.
        // ADDR0 (overwrite): the 17 rate lanes = witness, capacity := 0.
        // ADDRMID/ADDREND (xor-absorb): rate lanes = a XOR witness, capacity = a.
        for l in 0..25 {
            let msg_cm: AB::Expr = match l {
                0..=12 => w(l),
                13 => sel(0), // z==0
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            let msg_addr0: AB::Expr = if l < NW { w(l) } else { AB::Expr::ZERO };
            let msg_xor: AB::Expr = if l < NW {
                xor2(a(l), w(l), two.clone())
            } else {
                a(l)
            };
            let expr = a(l)
                + inj_cm.clone() * (msg_cm - a(l))
                + inj_addr0.clone() * (msg_addr0 - a(l))
                + inj_xor.clone() * (msg_xor - a(l));
            builder.assert_eq(eff(l), expr);
        }

        // ---- Capture / close gates (materialized) ----
        // caps: [cmcap, adcap, valcap, rkmcm, rkmad]
        builder.assert_eq(local[GCAP_OFF].clone(), bnd.clone() * selr(1)); // cm digest @ ADDR0
        builder.assert_eq(local[GCAP_OFF + 1].clone(), bnd.clone() * selr(4)); // addr digest @ ACLOSE
        builder.assert_eq(local[GCAP_OFF + 2].clone(), bnd.clone() * selr(0)); // value @ CM
        builder.assert_eq(local[GCAP_OFF + 3].clone(), bnd.clone() * selr(0)); // rkm CM side @ CM
        builder.assert_eq(local[GCAP_OFF + 4].clone(), bnd.clone() * selr(1)); // rkm ADDR side @ ADDR0
        let g_cmcap = local[GCAP_OFF].clone();
        let g_adcap = local[GCAP_OFF + 1].clone();
        let g_valcap = local[GCAP_OFF + 2].clone();
        let g_rkmcm = local[GCAP_OFF + 3].clone();
        let g_rkmad = local[GCAP_OFF + 4].clone();
        // closes: [cmclose, adclose, valclose, rkmclose]
        builder.assert_eq(local[GCLOSE_OFF].clone(), gperm.clone() * selr(1));
        builder.assert_eq(local[GCLOSE_OFF + 1].clone(), gperm.clone() * selr(4));
        builder.assert_eq(local[GCLOSE_OFF + 2].clone(), gperm.clone() * selr(0));
        builder.assert_eq(local[GCLOSE_OFF + 3].clone(), gperm.clone() * selr(1));
        let g_cmclose = local[GCLOSE_OFF].clone();
        let g_adclose = local[GCLOSE_OFF + 1].clone();
        let g_valclose = local[GCLOSE_OFF + 2].clone();
        let g_rkmclose = local[GCLOSE_OFF + 3].clone();

        // ---- Public-value closes ----
        let pvs: Vec<AB::Expr> = builder.public_values().iter().map(|v| (*v).into()).collect();
        let pv = |i: usize| pvs[i].clone();
        for i in 0..16 {
            builder.assert_zero(g_cmclose.clone() * (local[BQCM_OFF + i].clone() - pv(PV_CM + i)));
            builder.assert_zero(g_adclose.clone() * (local[BQAD_OFF + i].clone() - pv(PV_ADDR + i)));
        }
        for j in 0..4 {
            builder.assert_zero(
                g_valclose.clone() * (local[BVAL_OFF + j].clone() - pv(PV_VALUE + j)),
            );
        }
        for c8 in 0..16 {
            builder.assert_zero(g_rkmclose.clone() * local[RKM_OFF + c8].clone());
        }

        // Banks start at zero.
        for i in 0..16 {
            builder.when_first_row().assert_zero(local[BQCM_OFF + i].clone());
            builder.when_first_row().assert_zero(local[BQAD_OFF + i].clone());
            builder.when_first_row().assert_zero(local[RKM_OFF + i].clone());
        }
        for j in 0..4 {
            builder.when_first_row().assert_zero(local[BVAL_OFF + j].clone());
        }

        // ---- RC-ring same-row (identical to narrow) ----
        for k in 0..7 {
            builder.assert_bool(local[B_OFF + k].clone());
        }
        builder.assert_eq(weighted(B_OFF, 7, &local), local[R_OFF].clone());
        for i in 0..24 {
            builder.when_first_row().assert_eq(
                local[R_OFF + i].clone(),
                AB::Expr::from_u32(Self::rc_pack((23 + i) % 24)),
            );
        }

        // ---- Transition constraints ----
        let routes = addr_rkm_routes();
        let mut t = builder.when_transition();

        // RC ring / perm-boundary ring rotation.
        for i in 0..24 {
            t.assert_eq(
                next[R_OFF + i].clone(),
                (AB::Expr::ONE - blast.clone()) * local[R_OFF + i].clone()
                    + blast.clone() * local[R_OFF + (i + 1) % 24].clone(),
            );
            t.assert_eq(
                next[PB_OFF + i].clone(),
                (AB::Expr::ONE - blast.clone()) * local[PB_OFF + i].clone()
                    + blast.clone() * local[PB_OFF + (i + 1) % 24].clone(),
            );
        }
        // Phase ring.
        let g = blast.clone() * local[PB_OFF + 1].clone();
        for i in 0..4 {
            t.assert_eq(
                next[PH_OFF + i].clone(),
                (AB::Expr::ONE - g.clone()) * local[PH_OFF + i].clone()
                    + g.clone() * local[PH_OFF + (i + 1) % 4].clone(),
            );
        }
        // Program ring.
        let g4 = local[G4_COL].clone();
        for i in 0..24 {
            t.assert_eq(
                next[PR_OFF + i].clone(),
                (AB::Expr::ONE - g4.clone()) * local[PR_OFF + i].clone()
                    + g4.clone() * local[PR_OFF + (i + 1) % 24].clone(),
            );
        }

        // S register.
        for d in 1..=S_SLOTS {
            let mut expr = if d < S_SLOTS {
                local[s_col(d + 1)].clone()
            } else {
                AB::Expr::ZERO
            };
            for l in 0..25 {
                let wt = AB::Expr::from_u32(1 << l);
                if RHO[l] as usize == d {
                    expr = expr + e1(l) * wt.clone() * ap(l);
                }
                if 64 + RHO[l] as usize == d {
                    expr = expr + (trow.clone() - e1(l)) * wt * ap(l);
                }
            }
            t.assert_eq(next[s_col(d)].clone(), expr);
        }
        // V register.
        for d in 1..V_SLOTS {
            t.assert_eq(next[v_col(d)].clone(), local[v_col(d + 1)].clone());
        }
        t.assert_eq(
            next[v_col(V_SLOTS)].clone(),
            mrow.clone() * weighted(EFF_OFF, 25, &local),
        );
        // U register.
        let lo_c = (0..5)
            .map(|x| c(x) * AB::Expr::from_u32(1 << x))
            .fold(AB::Expr::ZERO, |acc, e| acc + e);
        let hi_c = (0..5)
            .map(|x| c(x) * AB::Expr::from_u32(1 << (5 + x)))
            .fold(AB::Expr::ZERO, |acc, e| acc + e);
        t.assert_eq(
            next[u_col(1)].clone(),
            local[u_col(2)].clone() + u63.clone() * hi_c.clone(),
        );
        for d in 2..64 {
            t.assert_eq(next[u_col(d)].clone(), local[u_col(d + 1)].clone());
        }
        t.assert_eq(
            next[u_col(64)].clone(),
            local[u_col(65)].clone() + mrow.clone() * lo_c,
        );
        t.assert_eq(next[u_col(65)].clone(), (mrow.clone() - u63.clone()) * hi_c);

        // ---- Bank accumulations (transition) ----
        // Digest capture banks: BQCM/BQAD[4l+j] += gate * pwk(j) * a[l].
        for l in 0..4 {
            for j in 0..4 {
                let idx = 4 * l + j;
                t.assert_eq(
                    next[BQCM_OFF + idx].clone(),
                    local[BQCM_OFF + idx].clone()
                        + g_cmcap.clone() * pwk(j) * local[A_OFF + l].clone(),
                );
                t.assert_eq(
                    next[BQAD_OFF + idx].clone(),
                    local[BQAD_OFF + idx].clone()
                        + g_adcap.clone() * pwk(j) * local[A_OFF + l].clone(),
                );
            }
        }
        // Value bank: BVAL[j] += g_valcap * pwk(j) * w[0].
        for j in 0..4 {
            t.assert_eq(
                next[BVAL_OFF + j].clone(),
                local[BVAL_OFF + j].clone() + g_valcap.clone() * pwk(j) * w(0),
            );
        }
        // rkm accumulator: CM side adds aligned lanes 1..4 (words 0..3);
        // ADDR side subtracts routed block lanes 2..6.
        // CM leg per chunk (4m+j): pwk(j) * w[m+1].
        // ADDR leg per chunk c: sum over routes (l -> c) of routeweight * w[l].
        for cc in 0..16 {
            let m = cc / 4;
            let j = cc % 4;
            let cm_leg = pwk(j) * w(m + 1);
            let mut addr_leg = AB::Expr::ZERO;
            for (i, (l, c)) in routes.iter().enumerate() {
                if *c == cc {
                    addr_leg = addr_leg + per[39 + i].clone() * w(*l);
                }
            }
            t.assert_eq(
                next[RKM_OFF + cc].clone(),
                local[RKM_OFF + cc].clone() + g_rkmcm.clone() * cm_leg
                    - g_rkmad.clone() * addr_leg,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Trace generation
// ---------------------------------------------------------------------------

impl DisclosureAir {
    /// Generate the full-height trace, row by row, from zero-initialized
    /// registers — every cell satisfies the AIR by construction (the chain
    /// semantics are checked against the reference permutation in tests).
    pub fn generate_trace<F: Field>(&self, extra_capacity_bits: usize) -> RowMajorMatrix<F> {
        let height = 1usize << self.log_height;
        let size = height * DISCLOSURE_WIDTH;
        let mut values = Vec::with_capacity(size << extra_capacity_bits);

        let routes = addr_rkm_routes();

        let mut s = [0u32; S_SLOTS + 1];
        let mut v = [0u32; V_SLOTS + 1];
        let mut u = [0u32; U_SLOTS + 1];
        let mut r: [u32; 24] = core::array::from_fn(|i| Self::rc_pack((23 + i) % 24));
        let mut pb: [u32; 24] = core::array::from_fn(|i| (i == 0) as u32);
        let mut ph: [u32; 4] = core::array::from_fn(|i| (i == 0) as u32);
        let mut pr: [u32; 24] = core::array::from_fn(|i| self.pr_limb(i));

        let mut perm_idx = 0usize;
        let role_of = |p: usize| self.program[p % PROGRAM_SLOTS];
        let wit = |p: usize| -> [u64; NW] {
            if self.slot_witness.is_empty() {
                [0u64; NW]
            } else {
                self.slot_witness[p % self.slot_witness.len()]
            }
        };
        let mut cur = wit(0);

        // Signed banks / accumulators.
        let mut bqcm = [0i64; 16];
        let mut bqad = [0i64; 16];
        let mut bval = [0i64; 4];
        let mut rkm = [0i64; 16];

        let bitat = |wrd: u64, i: usize| ((wrd >> i) & 1) as u32;

        for t in 0..height {
            let mrow = (t / 64) % 2 == 0;
            let z = t % 64;

            let us: [u32; 25] = core::array::from_fn(|l| (s[1] >> l) & 1);
            let uv: [u32; 25] = core::array::from_fn(|l| (v[1] >> l) & 1);
            let uu: [u32; 10] = core::array::from_fn(|i| (u[1] >> i) & 1);

            let bb = |bx: usize, by: usize| us[INV_PI[bx + 5 * by]];
            let chi = |x: usize, y: usize| bb(x, y) ^ ((1 - bb((x + 1) % 5, y)) & bb((x + 2) % 5, y));
            let x00 = chi(0, 0);
            let rc = Self::rc_bit(t) as u32;
            let a: [u32; 25] = core::array::from_fn(|l| {
                if l == 0 {
                    x00 ^ rc
                } else {
                    chi(l % 5, l / 5)
                }
            });

            let role_now = role_of(perm_idx);
            let bnd_now = mrow && pb[0] == 1;
            let wbit: [u32; NW] = core::array::from_fn(|i| bitat(cur[i], z));
            let z0 = (z == 0) as u32;
            let z63 = (z == 63) as u32;

            let eff: [u32; 25] = core::array::from_fn(|l| {
                if !bnd_now {
                    return a[l];
                }
                match role_now {
                    ROLE_CM => match l {
                        0..=12 => wbit[l],
                        13 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    ROLE_ADDR0 => {
                        if l < NW {
                            wbit[l]
                        } else {
                            0
                        }
                    }
                    ROLE_ADDRMID | ROLE_ADDREND => {
                        if l < NW {
                            a[l] ^ wbit[l]
                        } else {
                            a[l]
                        }
                    }
                    _ => a[l],
                }
            });

            let sel_cm = (role_now == ROLE_CM) as u32;
            let sel_addr0 = (role_now == ROLE_ADDR0) as u32;
            let sel_addrmid = (role_now == ROLE_ADDRMID) as u32;
            let sel_addrend = (role_now == ROLE_ADDREND) as u32;
            let sel_aclose = (role_now == ROLE_ACLOSE) as u32;
            let bndv = (bnd_now) as u32;
            let gpermv = ((t % 128 == 127) as u32) * pb[1];

            let inj_cm = bndv * sel_cm;
            let inj_addr0 = bndv * sel_addr0;
            let inj_xor = bndv * (sel_addrmid + sel_addrend);

            let g_cmcap = bndv * sel_addr0;
            let g_adcap = bndv * sel_aclose;
            let g_valcap = bndv * sel_cm;
            let g_rkmcm = bndv * sel_cm;
            let g_rkmad = bndv * sel_addr0;

            let c: [u32; 5] = core::array::from_fn(|x| {
                eff[x] ^ eff[x + 5] ^ eff[x + 10] ^ eff[x + 15] ^ eff[x + 20]
            });
            let ap: [u32; 25] = core::array::from_fn(|l| {
                let x = l % 5;
                uv[l] ^ uu[(x + 4) % 5] ^ uu[5 + (x + 1) % 5]
            });

            // Emit the row.
            let base = values.len();
            values.resize(base + DISCLOSURE_WIDTH, F::ZERO);
            let row = &mut values[base..];
            for l in 0..25 {
                row[A_OFF + l] = F::from_u32(a[l]);
                row[US_OFF + l] = F::from_u32(us[l]);
                row[AP_OFF + l] = F::from_u32(ap[l]);
                row[UV_OFF + l] = F::from_u32(uv[l]);
                row[EFF_OFF + l] = F::from_u32(eff[l]);
            }
            for x in 0..5 {
                row[C_OFF + x] = F::from_u32(c[x]);
            }
            for i in 0..10 {
                row[UU_OFF + i] = F::from_u32(uu[i]);
            }
            row[X00_COL] = F::from_u32(x00);
            for (i, ri) in r.iter().enumerate() {
                row[R_OFF + i] = F::from_u32(*ri);
            }
            for k in 0..7 {
                row[B_OFF + k] = F::from_u32((r[0] >> k) & 1);
            }
            for (i, val) in pb.iter().enumerate() {
                row[PB_OFF + i] = F::from_u32(*val);
            }
            for (i, val) in ph.iter().enumerate() {
                row[PH_OFF + i] = F::from_u32(*val);
            }
            for (i, val) in pr.iter().enumerate() {
                row[PR_OFF + i] = F::from_u32(*val);
            }
            for k in 0..16 {
                row[D_OFF + k] = F::from_u32((pr[0] >> k) & 1);
            }
            for k in 0..4 {
                row[RB_OFF + k] = F::from_u32((role_now >> k) & 1);
            }
            // Half-selectors: lo_j = [ (r0,r1) == j ], hi_j = [ (r2,r3) == j ].
            let rb0 = role_now & 1;
            let rb1 = (role_now >> 1) & 1;
            let rb2 = (role_now >> 2) & 1;
            let rb3 = (role_now >> 3) & 1;
            for j in 0..4u32 {
                row[HS_OFF + j as usize] =
                    F::from_u32(((rb0 == (j & 1)) && (rb1 == ((j >> 1) & 1))) as u32);
                row[HS_OFF + 4 + j as usize] =
                    F::from_u32(((rb2 == (j & 1)) && (rb3 == ((j >> 1) & 1))) as u32);
            }
            let selv = [sel_cm, sel_addr0, sel_addrmid, sel_addrend, sel_aclose];
            for (i, val) in selv.iter().enumerate() {
                row[SEL_OFF + i] = F::from_u32(*val);
            }
            row[INJ_OFF] = F::from_u32(inj_cm);
            row[INJ_OFF + 1] = F::from_u32(inj_addr0);
            row[INJ_OFF + 2] = F::from_u32(inj_xor);
            row[G4_COL] = F::from_u32(((t % 128 == 127) as u32) * pb[1] * ph[1]);
            for i in 0..NW {
                row[W_OFF + i] = F::from_u32(wbit[i]);
            }
            row[GCAP_OFF] = F::from_u32(g_cmcap);
            row[GCAP_OFF + 1] = F::from_u32(g_adcap);
            row[GCAP_OFF + 2] = F::from_u32(g_valcap);
            row[GCAP_OFF + 3] = F::from_u32(g_rkmcm);
            row[GCAP_OFF + 4] = F::from_u32(g_rkmad);
            row[GCLOSE_OFF] = F::from_u32(gpermv * sel_addr0);
            row[GCLOSE_OFF + 1] = F::from_u32(gpermv * sel_aclose);
            row[GCLOSE_OFF + 2] = F::from_u32(gpermv * sel_cm);
            row[GCLOSE_OFF + 3] = F::from_u32(gpermv * sel_addr0);
            let sgn = |x: i64| -> F {
                if x >= 0 {
                    F::from_u32(x as u32)
                } else {
                    -F::from_u32((-x) as u32)
                }
            };
            for (i, acc) in bqcm.iter().enumerate() {
                row[BQCM_OFF + i] = sgn(*acc);
            }
            for (i, acc) in bqad.iter().enumerate() {
                row[BQAD_OFF + i] = sgn(*acc);
            }
            for (j, acc) in bval.iter().enumerate() {
                row[BVAL_OFF + j] = sgn(*acc);
            }
            for (i, acc) in rkm.iter().enumerate() {
                row[RKM_OFF + i] = sgn(*acc);
            }
            for d in 1..=S_SLOTS {
                row[s_col(d)] = F::from_u32(s[d]);
            }
            for d in 1..=V_SLOTS {
                row[v_col(d)] = F::from_u32(v[d]);
            }
            for d in 1..=U_SLOTS {
                row[u_col(d)] = F::from_u32(u[d]);
            }

            // ---- Advance banks (mirror the transition constraints) ----
            {
                let jc = z / 16;
                let wgt = 1i64 << (z % 16);
                for l in 0..4 {
                    let idx = 4 * l + jc;
                    bqcm[idx] += (g_cmcap as i64) * wgt * a[l] as i64;
                    bqad[idx] += (g_adcap as i64) * wgt * a[l] as i64;
                }
                bval[jc] += (g_valcap as i64) * wgt * wbit[0] as i64;
                // rkm CM side (aligned words 0..3 = w[1..4]).
                for m in 0..4 {
                    rkm[4 * m + jc] += (g_rkmcm as i64) * wgt * wbit[m + 1] as i64;
                }
                // rkm ADDR side (routed block lanes 2..6).
                for (i, (l, cc)) in routes.iter().enumerate() {
                    let rw = if mrow { addr_rkm_weight(*l, *cc, z) } else { 0 };
                    rkm[*cc] -= (g_rkmad as i64) * (rw as i64) * wbit[*l] as i64;
                    let _ = i;
                }
            }

            // ---- Advance registers to the next row ----
            for d in 1..S_SLOTS {
                s[d] = s[d + 1];
            }
            s[S_SLOTS] = 0;
            if !mrow {
                let j = z;
                for l in 0..25 {
                    let rot = RHO[l] as usize;
                    let d = if j + rot >= 64 { rot } else { 64 + rot };
                    s[d] |= ap[l] << l;
                }
            }
            for d in 1..V_SLOTS {
                v[d] = v[d + 1];
            }
            v[V_SLOTS] = 0;
            for d in 1..U_SLOTS {
                u[d] = u[d + 1];
            }
            u[U_SLOTS] = 0;
            if t % 128 == 127 {
                r.rotate_left(1);
                if pb[1] == 1 {
                    if ph[1] == 1 {
                        pr.rotate_left(1);
                    }
                    ph.rotate_left(1);
                    perm_idx += 1;
                    cur = wit(perm_idx);
                }
                pb.rotate_left(1);
            }
            if mrow {
                let a_limb: u32 = (0..25).map(|l| eff[l] << l).sum();
                let lo: u32 = (0..5).map(|x| c[x] << x).sum();
                let hi: u32 = (0..5).map(|x| c[x] << (5 + x)).sum();
                v[V_SLOTS] = a_limb;
                u[64] |= lo;
                if z == 63 {
                    u[1] |= hi;
                } else {
                    u[65] |= hi;
                }
            }
        }

        RowMajorMatrix::new(values, DISCLOSURE_WIDTH)
    }

    /// Perms used by the disclosure program (excluding trailing DUMMY padding):
    /// CM + ADDR0 + 8×ADDRMID + ADDREND + ACLOSE.
    pub const PROGRAM_PERMS: usize = 12;

    /// The block index at which the CM permutation's output (= `cm`) is
    /// materialized (start of perm 1).
    const CM_OUT_BLOCK: usize = 24;
    /// The block at which the address sponge's final output (= `addr_commitment`)
    /// is materialized (start of perm 11, the ACLOSE perm).
    const ADDR_OUT_BLOCK: usize = 24 * 11;

    /// Extract the state materialized at block `q` (round-q input): bit z of
    /// lane l is the `a` cell at row 128q + z.
    pub fn extract_state<F: Field>(trace: &RowMajorMatrix<F>, q: usize) -> [u64; 25] {
        let mut state = [0u64; 25];
        for z in 0..64 {
            let row = 128 * q + z;
            for (l, lane) in state.iter_mut().enumerate() {
                if trace.values[row * DISCLOSURE_WIDTH + A_OFF + l] == F::ONE {
                    *lane |= 1u64 << z;
                }
            }
        }
        state
    }
}

// ---------------------------------------------------------------------------
// Instance builder
// ---------------------------------------------------------------------------

/// Everything a prover/verifier pair needs for one disclosure instance.
pub struct DisclosureInstance {
    pub air: DisclosureAir,
    /// Public values (see PV_* layout) as u32 chunks.
    pub pvs: Vec<u32>,
    /// The on-chain note commitment (public).
    pub cm: [u64; 4],
    /// Keccak256 of the recipient's full raw address (public).
    pub addr_commitment: [u64; 4],
    /// The disclosed value (public).
    pub value: u64,
}

/// Split a byte slice into `u64` lanes (little-endian, 8 bytes/lane), padding
/// the final lane with zeros.
fn bytes_to_lanes(block: &[u8]) -> [u64; RATE_LANES] {
    let mut out = [0u64; RATE_LANES];
    for (l, lane) in out.iter_mut().enumerate() {
        let mut b = [0u8; 8];
        for (k, bk) in b.iter_mut().enumerate() {
            let idx = l * 8 + k;
            if idx < block.len() {
                *bk = block[idx];
            }
        }
        *lane = u64::from_le_bytes(b);
    }
    out
}

/// Build a disclosure instance for one output note sent to `raw_address`.
///
/// `raw_address` MUST be the recipient's `Address::to_raw_bytes()` (1,233 B).
/// The witness is: the note opening `(value, rkm, rho, rseed)` and the address
/// preimage (the raw bytes, whose bytes 17..49 are `rkm` — bound to the note's
/// `rkm` in-circuit).
pub fn build_disclosure(
    log_height: usize,
    value: u64,
    rkm: &[u64; 4],
    rho: &[u64; 4],
    rseed: &[u64; 4],
    raw_address: &[u8],
) -> DisclosureInstance {
    assert_eq!(raw_address.len(), RAW_ADDR_LEN, "raw address must be 1,233 bytes");
    // Sanity: the address's rkm field (bytes 17..49) must equal the note's rkm,
    // else the in-circuit binding cannot close (caught here with a clear panic
    // rather than a later UNSAT).
    let addr_rkm = qlab_note::hash::digest_from_bytes(
        raw_address[crate::packing::ADDR_RKM_OFFSET
            ..crate::packing::ADDR_RKM_OFFSET + crate::packing::ADDR_RKM_LEN]
            .try_into()
            .unwrap(),
    );
    assert_eq!(&addr_rkm, rkm, "address rkm must match the note rkm (binding)");

    let cm = crate::packing::note_commitment(value, rkm, rho, rseed);
    let addr_commitment = qlab_note::hash::digest_from_bytes(&crate::packing::addr_commitment(raw_address));

    // Padded address message: raw ‖ pad10*1 to a multiple of the rate.
    let n_blocks = raw_address.len().div_ceil(RATE_LANES * 8); // 10
    let mut padded = vec![0u8; n_blocks * RATE_LANES * 8];
    padded[..raw_address.len()].copy_from_slice(raw_address);
    padded[raw_address.len()] ^= 0x01;
    let last = padded.len() - 1;
    padded[last] ^= 0x80;

    // Program + witness.
    let mut program = [ROLE_DUMMY; PROGRAM_SLOTS];
    let mut sw = vec![[0u64; NW]; PROGRAM_SLOTS];

    // perm 0: CM.
    program[0] = ROLE_CM;
    sw[0][0] = value;
    sw[0][1..5].copy_from_slice(rkm);
    sw[0][5..9].copy_from_slice(rho);
    sw[0][9..13].copy_from_slice(rseed);

    // perms 1..1+n_blocks: address sponge (ADDR0, ADDRMID.., ADDREND).
    for i in 0..n_blocks {
        let slot = 1 + i;
        let block = &padded[i * RATE_LANES * 8..(i + 1) * RATE_LANES * 8];
        sw[slot] = bytes_to_lanes(block);
        program[slot] = if i == 0 {
            ROLE_ADDR0
        } else if i == n_blocks - 1 {
            ROLE_ADDREND
        } else {
            ROLE_ADDRMID
        };
    }
    // perm 1+n_blocks: ACLOSE (exposes the address digest).
    program[1 + n_blocks] = ROLE_ACLOSE;

    let pvs = pv_vec(&cm, &addr_commitment, value);
    DisclosureInstance {
        air: DisclosureAir {
            log_height,
            program,
            slot_witness: sw,
        },
        pvs,
        cm,
        addr_commitment,
        value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::check_constraints;
    use p3_koala_bear::KoalaBear;

    type F = KoalaBear;

    fn zero_pvs() -> Vec<F> {
        vec![F::ZERO; PV_LEN]
    }

    /// The deg-3 house rule (task: deg ≤ 3): the whole AIR must stay within it,
    /// so the consensus-lane quotient sizing (log_quotient_degree = 1, blowup ≥
    /// 4) holds.
    #[test]
    fn constraint_degree_within_budget() {
        use p3_air::symbolic::{get_symbolic_constraints, AirLayout};
        let air = build_disclosure(16, 1, &[1, 2, 3, 4], &[5, 6, 7, 8], &[9, 10, 11, 12], &{
            // a throwaway valid 1233-byte address whose rkm field = [1,2,3,4].
            let mut raw = vec![0u8; RAW_ADDR_LEN];
            raw[..1].copy_from_slice(&[1u8]); // version
            raw[crate::packing::ADDR_RKM_OFFSET..crate::packing::ADDR_RKM_OFFSET + 32]
                .copy_from_slice(&qlab_note::hash::digest_bytes(&[1, 2, 3, 4]));
            raw
        })
        .air;
        let layout = AirLayout::from_air::<F>(&air);
        let cs = get_symbolic_constraints::<F, _>(&air, layout);
        let max = cs.iter().map(|c| c.degree_multiple()).max().unwrap_or(0);
        assert!(max <= 3, "disclosure AIR max constraint degree {max} > 3");
    }

    /// The core port: an all-DUMMY instance is pure Keccak chaining and must
    /// satisfy every constraint (validates the z-slice pipeline + rings).
    #[test]
    fn chain_only_satisfies_constraints() {
        let air = DisclosureAir::chain_only(10);
        let trace = air.generate_trace::<F>(0);
        check_constraints(&air, &trace, &zero_pvs());
    }

    /// The chained state at each 24-block group must equal a genuine
    /// keccak-f of the previous group's state (semantic authority).
    #[test]
    fn chain_only_is_real_keccak() {
        use qlab_air::reference::keccak_f;
        // 2^13 = 8192 rows = 64 blocks = 2+ full 24-block perms.
        let air = DisclosureAir::chain_only(13);
        let trace = air.generate_trace::<F>(0);
        // Groups: perm p occupies blocks 24p..24p+24. state(24(p+1)) ==
        // keccak_f(state(24p)) for the first few perms that fit.
        let s0 = DisclosureAir::extract_state(&trace, 0);
        let s1 = DisclosureAir::extract_state(&trace, 24);
        assert_eq!(keccak_f(&s0), s1);
    }

    // A deterministic real address + note for the instance tests.
    fn sample() -> (u64, [u64; 4], [u64; 4], [u64; 4], Vec<u8>) {
        use qlab_note::kem::generate_keypair;
        use qlab_wallet::address::{Address, Diversifier};
        use rand::{rngs::StdRng, SeedableRng};
        let mut rng = StdRng::seed_from_u64(42);
        let kp = generate_keypair(&mut rng);
        // rkm as the wallet would derive it (any 4 lanes — the address carries it).
        let rkm: [u64; 4] = [0x1111, 0x2222, 0x3333, 0x4444];
        let addr = Address::new(Diversifier::from_bytes([7u8; 16]), rkm, &kp.ek);
        let value = 1_234_567u64;
        let rho = [0xaaaa, 0xbbbb, 0xcccc, 0xdddd];
        let rseed = [0x1234, 0x5678, 0x9abc, 0xdef0];
        (value, rkm, rho, rseed, addr.to_raw_bytes())
    }

    #[test]
    fn disclosure_instance_satisfies_constraints() {
        let (value, rkm, rho, rseed, raw) = sample();
        let inst = build_disclosure(16, value, &rkm, &rho, &rseed, &raw);
        let trace = inst.air.generate_trace::<F>(0);
        let pvs: Vec<F> = inst.pvs.iter().map(|v| F::from_u32(*v)).collect();
        check_constraints(&inst.air, &trace, &pvs);
    }

    /// The in-circuit digests match the clear-text packings (semantic check).
    #[test]
    fn disclosure_digests_match_packing() {
        use crate::packing::{addr_commitment, note_commitment};
        let (value, rkm, rho, rseed, raw) = sample();
        let inst = build_disclosure(16, value, &rkm, &rho, &rseed, &raw);
        let trace = inst.air.generate_trace::<F>(0);
        // cm digest = CM perm output (block 24).
        let cm_state = DisclosureAir::extract_state(&trace, DisclosureAir::CM_OUT_BLOCK);
        let cm: [u64; 4] = cm_state[..4].try_into().unwrap();
        assert_eq!(cm, note_commitment(value, &rkm, &rho, &rseed), "in-circuit cm");
        assert_eq!(cm, inst.cm);
        // addr digest = address sponge output (block 264).
        let ad_state = DisclosureAir::extract_state(&trace, DisclosureAir::ADDR_OUT_BLOCK);
        let ad: [u64; 4] = ad_state[..4].try_into().unwrap();
        let expected = qlab_note::hash::digest_from_bytes(&addr_commitment(&raw));
        assert_eq!(ad, expected, "in-circuit addr_commitment");
        assert_eq!(ad, inst.addr_commitment);
    }

    /// Negative: a wrong public `cm` must fail the digest close.
    #[test]
    #[should_panic]
    fn disclosure_wrong_cm_fails() {
        let (value, rkm, rho, rseed, raw) = sample();
        let inst = build_disclosure(16, value, &rkm, &rho, &rseed, &raw);
        let trace = inst.air.generate_trace::<F>(0);
        let mut pvs: Vec<F> = inst.pvs.iter().map(|v| F::from_u32(*v)).collect();
        pvs[PV_CM] += F::ONE; // corrupt one cm chunk
        check_constraints(&inst.air, &trace, &pvs);
    }

    /// Negative: a wrong public `addr_commitment` must fail its close.
    #[test]
    #[should_panic]
    fn disclosure_wrong_addr_fails() {
        let (value, rkm, rho, rseed, raw) = sample();
        let inst = build_disclosure(16, value, &rkm, &rho, &rseed, &raw);
        let trace = inst.air.generate_trace::<F>(0);
        let mut pvs: Vec<F> = inst.pvs.iter().map(|v| F::from_u32(*v)).collect();
        pvs[PV_ADDR] += F::ONE;
        check_constraints(&inst.air, &trace, &pvs);
    }

    /// Negative: a wrong public `value` must fail its close.
    #[test]
    #[should_panic]
    fn disclosure_wrong_value_fails() {
        let (value, rkm, rho, rseed, raw) = sample();
        let inst = build_disclosure(16, value, &rkm, &rho, &rseed, &raw);
        let trace = inst.air.generate_trace::<F>(0);
        let mut pvs: Vec<F> = inst.pvs.iter().map(|v| F::from_u32(*v)).collect();
        pvs[PV_VALUE] += F::ONE;
        check_constraints(&inst.air, &trace, &pvs);
    }

    /// Negative — THE core soundness property: the note's `rkm` and the
    /// address's `rkm` must agree. Here the address carries rkm_B while the
    /// note claims rkm_A ≠ rkm_B; the public `cm` and `addr_commitment` are set
    /// consistent with each hash INDIVIDUALLY, so both digest closes pass — only
    /// the `rkm` cross-binding accumulator can catch the lie. It must.
    #[test]
    #[should_panic]
    fn disclosure_rkm_mismatch_fails() {
        let (value, _rkm, rho, rseed, raw) = sample();
        let rkm_b = qlab_note::hash::digest_from_bytes(raw[17..49].try_into().unwrap());
        let rkm_a = [0x9999u64, 0x8888, 0x7777, 0x6666];
        assert_ne!(rkm_a, rkm_b);
        // Build consistently for rkm_b, then swap only the CM slot to rkm_a.
        let mut inst = build_disclosure(16, value, &rkm_b, &rho, &rseed, &raw);
        inst.air.slot_witness[0][1..5].copy_from_slice(&rkm_a);
        // Public cm made consistent with rkm_a so the cm close still passes.
        let cm_a = crate::packing::note_commitment(value, &rkm_a, &rho, &rseed);
        let new_pvs = pv_vec(&cm_a, &inst.addr_commitment, value);
        let trace = inst.air.generate_trace::<F>(0);
        let pvs: Vec<F> = new_pvs.iter().map(|v| F::from_u32(*v)).collect();
        check_constraints(&inst.air, &trace, &pvs);
    }
}
