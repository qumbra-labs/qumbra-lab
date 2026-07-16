//! M1.5b narrow Keccak-f[1600] AIR: correct semantics at 371 columns.
//!
//! Layout per `docs/m15b-narrow-keccak-layout.md` (v2 timing): a z-slice-
//! serial pipeline at 128 rows per round — window M (rows 0..64 of each
//! 128-row block) materializes the round input and its column parities,
//! window T (rows 64..128) runs theta. Rho's cross-slice taps ride three
//! packed shift registers whose slot index equals the bit's remaining
//! rows-to-consumption:
//!
//!   S (126 slots): post-theta bits A', delayed rot (rho-wrap) or 64+rot
//!   V (64 slots):  round-input bits A, delayed exactly 64 (M -> T)
//!   U (65 slots):  parity bits C, entered twice — delay 64 (as C[x][z])
//!                  and delay 65 (as C[x][z-1]; delay 1 at the z=63 seam)
//!
//! Every register limb packs at most 25 bits (weight 2^lane), and every
//! consumed limb is re-expanded through bool-checked unpack columns, so all
//! constraints stay degree <= 3. The pipeline is UNIFORM: the same
//! constraints hold on every row; schedule variation enters only through
//! 35 periodic columns (period 128 — free for the verifier: the schedule
//! flags, plus a block-boundary flag and 7 iota-position selectors).
//!
//! Iota round constants (M1.5c): RC[r] is nonzero only at the seven
//! z-positions 2^k - 1, so each round's constant is a 7-bit pack. A ring
//! of 24 in-trace registers R[0..24] rotates one step per 128-row block
//! (gated by the periodic block-boundary flag), R[0]'s bits are exposed
//! through 7 bool-checked columns, and the first row pins the ring to the
//! RC table — sound with no preprocessed commitment, replacing M1.5b's
//! 1-column preprocessed trace whose per-query openings cost ~740 B/query.
//!
//! M3 step 1 (program plumbing): a 24-slot perm-boundary ring (pinned
//! [1,0,...,0], rotating per block) exposes where permutations start; a
//! 96-slot program ring rotates once per permutation and exposes the
//! current perm's packed role word through bool-checked bits. The round
//! input consumed downstream (V entries, theta parity) is a materialized
//! `eff` column: eff = a + inj·(msg − a), inj itself materialized so
//! every constraint stays degree ≤ 3. With every program slot set to
//! ROLE_DUMMY the injection is inert and the pipeline is byte-for-byte
//! the M1.5c chain; steps 2-3 wire real roles (Merkle mux, fresh
//! absorbs, public binding) into `msg`.
//!
//! Chaining: permutation p occupies blocks 24p..24p+24; the state
//! materialized at block q is the round-q input, so state(q+1) =
//! Round_{q mod 24}(state(q)) for every q, including padding rows — no
//! gating, no boundary constraints, the first block's state is whatever
//! the zero-initialized registers emit (warmup), and every subsequent
//! 24-block group is a genuine keccak-f of its input.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use crate::reference::{RC, RHO};

// ---------------------------------------------------------------------------
// Column map
// ---------------------------------------------------------------------------

const A_OFF: usize = 0; // 25: round-input bits (chi output) — real on M rows
const C_OFF: usize = 25; // 5: column parities of `a`
const US_OFF: usize = 30; // 25: unpack of S slot 1 (chi inputs)
const AP_OFF: usize = 55; // 25: theta outputs — real on T rows
const X00_COL: usize = 80; // 1: chi lane (0,0) before iota
const S_OFF: usize = 81; // 126 slots (d = 1..=126)
const S_SLOTS: usize = 126;
const V_OFF: usize = S_OFF + S_SLOTS; // 207: 64 slots (d = 1..=64)
const V_SLOTS: usize = 64;
const UV_OFF: usize = V_OFF + V_SLOTS; // 271: 25: unpack of V slot 1
const U_OFF: usize = UV_OFF + 25; // 296: 65 slots (d = 1..=65)
const U_SLOTS: usize = 65;
const UU_OFF: usize = U_OFF + U_SLOTS; // 361: 10: unpack of U slot 1
const R_OFF: usize = UU_OFF + 10; // 371: 24 rotating iota-RC registers
const B_OFF: usize = R_OFF + 24; // 395: 7: bit-decomposition of R[0]
// --- M3 program machinery (phase-packed ring) + step-2 merkle wiring ---
const PB_OFF: usize = B_OFF + 7; // 402: 24: perm-boundary ring [1,0,..,0]
const PH_OFF: usize = PB_OFF + 24; // 426: 4: perm-phase ring (mod-4 counter)
const PR_OFF: usize = PH_OFF + 4; // 430: 24: program ring, 4 slots x 4 bits/limb
const D_OFF: usize = PR_OFF + 24; // 454: 16: bit-decomposition of PR[0]
const RB_OFF: usize = D_OFF + 16; // 470: 4: current perm's role bits
const NSEL: usize = 6; // materialized role selectors, order below
const SEL_OFF: usize = RB_OFF + 4; // 474: 6: [merkle, nf, ank, arkm, acm, acmout]
const INJ_OFF: usize = SEL_OFF + NSEL; // 480: 5: injection flags [mrk+nf, ank, arkm, acm, acmout]
const G4_COL: usize = INJ_OFF + 5; // 485: 1: program-ring rotation gate
const PBIT_COL: usize = G4_COL + 1; // 486: 1: merkle path bit (constant per perm)
const W_OFF: usize = PBIT_COL + 1; // 487: 13: witness lanes (role-multiplexed)
const SIB_OFF: usize = W_OFF; // sibling digest lanes = W0..3 (merkle rows)
const EQ_OFF: usize = W_OFF + 13; // 500: 32: two equality banks, 4 lanes x 4 chunks
const EG_OFF: usize = EQ_OFF + 32; // 532: 6: eq gates [e1pos, e1neg, e1close, e2pos, e2neg, e2close]
const EFF_OFF: usize = EG_OFF + 6; // 538: 25: effective round input
pub const NARROW_WIDTH: usize = EFF_OFF + 25; // 563

/// Program slots (= perm slots per program period).
pub const PROGRAM_SLOTS: usize = 96;
/// 4-bit role codes packed 4-per-limb into the program ring.
pub const ROLE_DUMMY: u32 = 0;
/// Merkle step: msg = mux(path bit; digest a[0..4], sibling W[0..4]) + pad512.
pub const ROLE_MERKLE: u32 = 1;
/// Nullifier: identical wiring to MERKLE with path bit 0 and W[0..4] = rho
/// (nf = H(nk || rho), nk arriving as the chained digest) — but a distinct
/// code so the equality banks can gate on it.
pub const ROLE_NF: u32 = 2;
/// nk = H(sk || D_N): msg lanes 0..4 = W(sk), domain bit at lane 4 z0,
/// pad10*1 at bit 320 (lane 5 z0) and bit 1087.
pub const ROLE_ANK: u32 = 3;
/// rkm = H(nk || D_R): same shape, domain bit at lane 4 z1, nk as witness
/// W[0..4] (bound to the ank digest by equality bank 1).
pub const ROLE_ARKM: u32 = 4;
/// cm = H(value || rkm || rho || rseed): value = W4, rkm = chained digest
/// a[0..4] at lanes 1..5, rho = W5..9 (bound to the NF perm's rho by
/// equality bank 2), rseed = W9..13, pad at bit 832 (lane 13 z0).
pub const ROLE_ACM: u32 = 5;
/// Output cm' = H(value || rkm' || rho' || rseed'): all witness —
/// value = W4, rkm' = W0..4, rho' = W5..9, rseed' = W9..13.
pub const ROLE_ACMOUT: u32 = 6;
// codes 7..16 reserved: bind-anchor / bind-nf / bind-cm / balance (step 3b).

/// Rows per 24-round permutation: 24 rounds x 128 rows.
pub const ROWS_PER_PERM: usize = 24 * 128;

const fn s_col(d: usize) -> usize {
    S_OFF + d - 1
}
const fn v_col(d: usize) -> usize {
    V_OFF + d - 1
}
const fn u_col(d: usize) -> usize {
    U_OFF + d - 1
}

/// Inverse pi: chi's B[bx][by] is the post-rho image of birth lane
/// INV_PI[bx + 5*by] (pi maps (x, y) -> (y, (2x + 3y) mod 5)).
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
// The AIR
// ---------------------------------------------------------------------------

/// Narrow Keccak AIR at a fixed power-of-two height (needed so the
/// preprocessed round-constant column can be built to match the trace).
/// Per-perm-slot witness: 13 generic 64-bit lanes plus the merkle path
/// bit; each role reads the lanes it needs (see the ROLE_* docs).
#[derive(Clone, Copy, Default)]
pub struct SlotWitness {
    pub w: [u64; 13],
    pub pbit: bool,
}

pub struct NarrowKeccakAir {
    pub log_height: usize,
    /// 4-bit role code per program slot (period 96 perms).
    pub program: [u32; PROGRAM_SLOTS],
    /// Witness per program slot, cycled if the padded height replays the
    /// program.
    pub slot_witness: Vec<SlotWitness>,
}

impl NarrowKeccakAir {
    /// M1.5c-equivalent instance: every perm slot dummy, pure chaining.
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
}

impl NarrowKeccakAir {
    /// Round-constant bit consumed at row `t` (block q materializes the
    /// iota output of global round q-1). Trace-generation reference; the
    /// AIR reconstructs the same value from the RC ring + selectors.
    fn rc_bit(t: usize) -> bool {
        let z = t % 64;
        let mrow = (t / 64) % 2 == 0;
        if !mrow {
            return false;
        }
        let q = t / 128;
        (RC[(q + 23) % 24] >> z) & 1 == 1
    }

    /// 7-bit pack of RC[j]: bit k = RC[j] at z-position 2^k - 1. (Those are
    /// the only nonzero positions of every Keccak round constant.)
    fn rc_pack(j: usize) -> u32 {
        (0..7)
            .map(|k| (((RC[j] >> ((1u32 << k) - 1)) & 1) as u32) << k)
            .sum()
    }
}

impl<F: Field> BaseAir<F> for NarrowKeccakAir {
    fn width(&self) -> usize {
        NARROW_WIDTH
    }

    fn num_periodic_columns(&self) -> usize {
        39
    }

    /// 35 period-128 columns: [mrow, u63, e1_0..e1_24, blast, sel_0..sel_6]
    /// where e1_l = trow AND rho-wrap for lane l at this T row's slice,
    /// blast = 1 on the last row of each 128-row block (RC ring rotation),
    /// sel_k = 1 on the M row with z = 2^k - 1 (iota bit positions).
    fn periodic_columns(&self) -> Vec<Vec<F>> {
        let mut cols = vec![Vec::with_capacity(128); 39];
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
            // Chunk-weight columns for the accumulator banks:
            // pwk_j = 2^(z mod 16) when z div 16 == j, else 0 (z = t mod 64).
            let z = t % 64;
            for j in 0..4 {
                let v = if z / 16 == j {
                    F::from_u32(1 << (z % 16))
                } else {
                    F::ZERO
                };
                cols[35 + j].push(v);
            }
        }
        cols
    }
}

/// xor of two bit expressions: a + b - 2ab.
fn xor2<E: Clone + core::ops::Add<Output = E> + core::ops::Sub<Output = E> + core::ops::Mul<Output = E>>(
    a: E,
    b: E,
    two: E,
) -> E {
    a.clone() + b.clone() - two * a * b
}

impl<AB: AirBuilder> Air<AB> for NarrowKeccakAir
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
        let trow = AB::Expr::ONE - mrow.clone();

        // Iota RC from the rotating ring: R[0]'s exposed bits, gated by the
        // position selectors (degree 2; its use inside xor2 stays <= 3).
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

        // --- Same-row constraints (hold on every row) ---

        // Booleans for every unpack column and the parity bits. (`a`, `ap`,
        // `x00` are forced boolean transitively by their defining equations.)
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

        // Unpack recompositions: sum(2^pos * bit) = register slot 1.
        let weighted = |off: usize, n: usize, row: &[AB::Expr]| -> AB::Expr {
            (0..n)
                .map(|i| row[off + i].clone() * AB::Expr::from_u32(1 << i))
                .fold(AB::Expr::ZERO, |acc, e| acc + e)
        };
        builder.assert_eq(weighted(US_OFF, 25, &local), local[s_col(1)].clone());
        builder.assert_eq(weighted(UV_OFF, 25, &local), local[v_col(1)].clone());
        builder.assert_eq(weighted(UU_OFF, 10, &local), local[u_col(1)].clone());

        // Chi + iota: a = chi(B) with B the pi-rearrangement of the S-taps.
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

        // Column parity via the degree-3 trick: sum - c in {0, 2, 4}.
        // Source is the EFFECTIVE round input (eff), not the chi output.
        for x in 0..5 {
            let s = (0..5)
                .map(|y| eff(x + 5 * y))
                .fold(AB::Expr::ZERO, |acc, e| acc + e);
            let d = s - c(x);
            builder.assert_zero(
                d.clone() * (d.clone() - two.clone()) * (d - two.clone() * two.clone()),
            );
        }

        // Theta: ap[x, y] = uv[x, y] XOR C[x-1][z] XOR C[x+1][z-1]
        //                 = uv XOR uu[(x+4)%5] XOR uu[5 + (x+1)%5].
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

        // M3 program machinery: perm-boundary ring pin, phase ring pin,
        // phase-packed program ring pin, slot-0 decomposition, active-role
        // extraction, materialized selectors/gates, and the eff mux.
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
        // PR[0] = 16 bool bits (4 slots x 4 bits).
        for k in 0..16 {
            builder.assert_bool(local[D_OFF + k].clone());
        }
        builder.assert_eq(weighted(D_OFF, 16, &local), local[PR_OFF].clone());
        // Active role bits: phase phi of perm p is p mod 4; the left-rotating
        // phase ring exposes phi via ph[(4 - phi) % 4].
        for k in 0..4 {
            let sel_quarter = (0..4)
                .map(|phi| {
                    local[PH_OFF + (4 - phi) % 4].clone()
                        * local[D_OFF + 4 * phi + k].clone()
                })
                .fold(AB::Expr::ZERO, |acc, e| acc + e);
            builder.assert_eq(local[RB_OFF + k].clone(), sel_quarter);
        }
        // Materialized role selectors, built from two-bit half-selectors so
        // each equality stays deg <= 2 over the (already materialized) bits.
        let r = |k: usize| local[RB_OFF + k].clone();
        let pair = |b0: AB::Expr, b1: AB::Expr, j: u32| -> AB::Expr {
            let t0 = if j & 1 == 1 { b0 } else { AB::Expr::ONE - b0 };
            let t1 = if j & 2 == 2 { b1 } else { AB::Expr::ONE - b1 };
            t0 * t1
        };
        let sel_codes: [u32; NSEL] = [
            ROLE_MERKLE,
            ROLE_NF,
            ROLE_ANK,
            ROLE_ARKM,
            ROLE_ACM,
            ROLE_ACMOUT,
        ];
        for (i, code) in sel_codes.iter().enumerate() {
            let lo = pair(r(0), r(1), code & 3);
            let hi = pair(r(2), r(3), (code >> 2) & 3);
            builder.assert_eq(local[SEL_OFF + i].clone(), lo * hi);
        }
        let sel_role = |i: usize| local[SEL_OFF + i].clone();
        // Injection flags: boundary M rows of each injecting role class.
        // inj[0] covers merkle AND nf (identical wiring).
        let bnd = mrow.clone() * local[PB_OFF].clone();
        builder.assert_eq(
            local[INJ_OFF].clone(),
            bnd.clone() * (sel_role(0) + sel_role(1)),
        );
        for i in 1..5 {
            builder.assert_eq(
                local[INJ_OFF + i].clone(),
                bnd.clone() * sel_role(i + 1),
            );
        }
        // Program-ring rotation gate: perm boundary AND phase wrap.
        builder.assert_eq(
            local[G4_COL].clone(),
            blast.clone() * local[PB_OFF + 1].clone() * local[PH_OFF + 1].clone(),
        );
        // Witness bits.
        builder.assert_bool(local[PBIT_COL].clone());
        for i in 0..13 {
            builder.assert_bool(local[W_OFF + i].clone());
        }
        // eff = a + sum_v inj_v * (msg_v - a): per-variant message states,
        // each deg <= 2, each gated by its materialized injection flag.
        let pbit = local[PBIT_COL].clone();
        let w = |i: usize| local[W_OFF + i].clone();
        let inj = |i: usize| local[INJ_OFF + i].clone();
        for l in 0..25 {
            // merkle / nf: mux(pbit; sibling-or-rho W0..4, digest) + pad512.
            let msg_mrk: AB::Expr = match l {
                0..=3 => pbit.clone() * w(l) + (AB::Expr::ONE - pbit.clone()) * a(l),
                4..=7 => {
                    pbit.clone() * a(l - 4) + (AB::Expr::ONE - pbit.clone()) * w(l - 4)
                }
                8 => sel(0),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            // ank: sk = W0..4, domain-N bit at lane 4 z0, pad10*1 from bit
            // 320 (lane 5 z0) to bit 1087.
            let msg_ank: AB::Expr = match l {
                0..=3 => w(l),
                4 => sel(0),
                5 => sel(0),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            // arkm: nk (witness, bank-1-bound) at lanes 0..4, domain-R bit
            // at lane 4 z1, same padding shape.
            let msg_arkm: AB::Expr = match l {
                0..=3 => w(l),
                4 => sel(1),
                5 => sel(0),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            // acm: value W4 | rkm = chained digest a[0..4] at lanes 1..5 |
            // rho = W5..9 (bank-2-bound) | rseed = W9..13 | pad from bit 832.
            let msg_acm: AB::Expr = match l {
                0 => w(4),
                1..=4 => a(l - 1),
                5..=8 => w(l),
                9..=12 => w(l),
                13 => sel(0),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            // acmout: fully witnessed output note, same lane layout as acm.
            let msg_acmout: AB::Expr = match l {
                0 => w(4),
                1..=4 => w(l - 1),
                5..=8 => w(l),
                9..=12 => w(l),
                13 => sel(0),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            let expr = a(l)
                + inj(0) * (msg_mrk - a(l))
                + inj(1) * (msg_ank - a(l))
                + inj(2) * (msg_arkm - a(l))
                + inj(3) * (msg_acm - a(l))
                + inj(4) * (msg_acmout - a(l));
            builder.assert_eq(eff(l), expr);
        }
        // Equality banks (4 lanes x 4 z-chunks each). Bank 1 binds arkm's
        // witness nk (W0..4 on ARKM boundary rows, negative leg) to the ank
        // digest (a[0..4] on NF boundary rows, positive leg). Bank 2 binds
        // acm's witness rho (W5..9, negative) to the NF perm's rho (W0..4
        // on its boundary rows, positive). Gates are materialized so the
        // accumulator transitions stay deg <= 3; each bank must be zero
        // when its window closes (last row of the consuming perm).
        let gperm = blast.clone() * local[PB_OFF + 1].clone();
        builder.assert_eq(local[EG_OFF].clone(), bnd.clone() * sel_role(1));
        builder.assert_eq(local[EG_OFF + 1].clone(), bnd.clone() * sel_role(3));
        builder.assert_eq(local[EG_OFF + 2].clone(), gperm.clone() * sel_role(3));
        builder.assert_eq(local[EG_OFF + 3].clone(), bnd.clone() * sel_role(1));
        builder.assert_eq(local[EG_OFF + 4].clone(), bnd.clone() * sel_role(4));
        builder.assert_eq(local[EG_OFF + 5].clone(), gperm.clone() * sel_role(4));
        for j in 0..16 {
            builder.assert_zero(local[EG_OFF + 2].clone() * local[EQ_OFF + j].clone());
            builder
                .assert_zero(local[EG_OFF + 5].clone() * local[EQ_OFF + 16 + j].clone());
        }
        for j in 0..32 {
            builder.when_first_row().assert_zero(local[EQ_OFF + j].clone());
        }

        // RC ring: R[0]'s bit decomposition (bool + recompose), first-row
        // pin to the RC table, and one-step rotation per block.
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

        // --- Transition constraints: register shifts + gated entries ---
        let mut t = builder.when_transition();

        // RC ring rotation at block boundaries.
        for i in 0..24 {
            t.assert_eq(
                next[R_OFF + i].clone(),
                (AB::Expr::ONE - blast.clone()) * local[R_OFF + i].clone()
                    + blast.clone() * local[R_OFF + (i + 1) % 24].clone(),
            );
        }
        // Perm-boundary ring: same cadence as the RC ring.
        for i in 0..24 {
            t.assert_eq(
                next[PB_OFF + i].clone(),
                (AB::Expr::ONE - blast.clone()) * local[PB_OFF + i].clone()
                    + blast.clone() * local[PB_OFF + (i + 1) % 24].clone(),
            );
        }
        // Phase ring: rotates once per perm. Gate g = blast*pb[1] is
        // degree 2; the rotation constraint lands at degree 3.
        let g = blast.clone() * local[PB_OFF + 1].clone();
        for i in 0..4 {
            t.assert_eq(
                next[PH_OFF + i].clone(),
                (AB::Expr::ONE - g.clone()) * local[PH_OFF + i].clone()
                    + g.clone() * local[PH_OFF + (i + 1) % 4].clone(),
            );
        }
        // Program ring: rotates one limb every 4 perms, via the
        // materialized gate (blast*pb[1]*ph[1], checked same-row).
        let g4 = local[G4_COL].clone();
        for i in 0..24 {
            t.assert_eq(
                next[PR_OFF + i].clone(),
                (AB::Expr::ONE - g4.clone()) * local[PR_OFF + i].clone()
                    + g4.clone() * local[PR_OFF + (i + 1) % 24].clone(),
            );
        }
        // Path bit: constant within a perm, free at perm boundaries.
        t.assert_zero(
            (AB::Expr::ONE - g.clone())
                * (next[PBIT_COL].clone() - local[PBIT_COL].clone()),
        );

        // S: theta births enter at slot rot (rho wrap, gate e1) or
        // 64 + rot (no wrap, gate trow - e1).
        for d in 1..=S_SLOTS {
            let mut expr = if d < S_SLOTS {
                local[s_col(d + 1)].clone()
            } else {
                AB::Expr::ZERO
            };
            for l in 0..25 {
                let w = AB::Expr::from_u32(1 << l);
                if RHO[l] as usize == d {
                    expr = expr + e1(l) * w.clone() * ap(l);
                }
                if 64 + RHO[l] as usize == d {
                    expr = expr + (trow.clone() - e1(l)) * w * ap(l);
                }
            }
            t.assert_eq(next[s_col(d)].clone(), expr);
        }

        // V: `a` limbs enter at slot 64 on M rows.
        for d in 1..V_SLOTS {
            t.assert_eq(next[v_col(d)].clone(), local[v_col(d + 1)].clone());
        }
        t.assert_eq(
            next[v_col(V_SLOTS)].clone(),
            mrow.clone() * weighted(EFF_OFF, 25, &local),
        );

        // U: parity limbs enter twice — low half (weights 2^0..2^4) at
        // slot 64, high half (weights 2^5..2^9) at slot 65 (or slot 1 on
        // the z = 63 seam row).
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
        t.assert_eq(next[u_col(65)].clone(), (mrow - u63) * hi_c);

        // Equality-bank accumulation (deg 3: gate * chunk-weight * source).
        let pwk = |j: usize| per[35 + j].clone();
        for l in 0..4 {
            for j in 0..4 {
                let idx = 4 * l + j;
                t.assert_eq(
                    next[EQ_OFF + idx].clone(),
                    local[EQ_OFF + idx].clone()
                        + local[EG_OFF].clone() * pwk(j) * local[A_OFF + l].clone()
                        - local[EG_OFF + 1].clone() * pwk(j) * local[W_OFF + l].clone(),
                );
                t.assert_eq(
                    next[EQ_OFF + 16 + idx].clone(),
                    local[EQ_OFF + 16 + idx].clone()
                        + local[EG_OFF + 3].clone() * pwk(j) * local[W_OFF + l].clone()
                        - local[EG_OFF + 4].clone() * pwk(j) * local[W_OFF + 5 + l].clone(),
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Trace generation
// ---------------------------------------------------------------------------

impl NarrowKeccakAir {
    /// Generate the full-height trace by simulating the pipeline row by
    /// row from zero-initialized registers. Every cell satisfies the AIR
    /// by construction; the chain semantics are checked against the
    /// reference permutation in tests.
    pub fn generate_trace<F: Field>(
        &self,
        extra_capacity_bits: usize,
    ) -> RowMajorMatrix<F> {
        let height = 1usize << self.log_height;
        let size = height * NARROW_WIDTH;
        let mut values = Vec::with_capacity(size << extra_capacity_bits);

        // Registers, indexed by slot (index 0 unused).
        let mut s = [0u32; S_SLOTS + 1];
        let mut v = [0u32; V_SLOTS + 1];
        let mut u = [0u32; U_SLOTS + 1];
        // Iota RC ring: R[i] = 7-bit pack of round (q - 1 + i) mod 24.
        let mut r: [u32; 24] = core::array::from_fn(|i| Self::rc_pack((23 + i) % 24));
        // Perm-boundary, phase, and program rings.
        let mut pb: [u32; 24] = core::array::from_fn(|i| (i == 0) as u32);
        let mut ph: [u32; 4] = core::array::from_fn(|i| (i == 0) as u32);
        let mut pr: [u32; 24] = core::array::from_fn(|i| self.pr_limb(i));
        // Per-perm derived state, advanced at perm boundaries.
        let mut perm_idx = 0usize;
        let role_of = |p: usize| self.program[p % PROGRAM_SLOTS];
        let wit = |p: usize| -> SlotWitness {
            if self.slot_witness.is_empty() {
                SlotWitness::default()
            } else {
                self.slot_witness[p % self.slot_witness.len()]
            }
        };
        let mut cur = wit(0);
        // Equality banks: signed accumulators, 2 banks x 4 lanes x 4 chunks.
        let mut eq = [0i64; 32];

        let bit = |w: u32, i: usize| (w >> i) & 1;

        for t in 0..height {
            let mrow = (t / 64) % 2 == 0;
            let z = t % 64;

            // Working cells from the current register state.
            let us: [u32; 25] = core::array::from_fn(|l| bit(s[1], l));
            let uv: [u32; 25] = core::array::from_fn(|l| bit(v[1], l));
            let uu: [u32; 10] = core::array::from_fn(|i| bit(u[1], i));

            let b = |bx: usize, by: usize| us[INV_PI[bx + 5 * by]];
            let chi = |x: usize, y: usize| {
                b(x, y) ^ ((1 - b((x + 1) % 5, y)) & b((x + 2) % 5, y))
            };
            let x00 = chi(0, 0);
            let rc = Self::rc_bit(t) as u32;
            let a: [u32; 25] = core::array::from_fn(|l| {
                if l == 0 {
                    x00 ^ rc
                } else {
                    chi(l % 5, l / 5)
                }
            });
            // Effective round input per the role's message layout.
            let role_now = role_of(perm_idx);
            let bnd_now = ((mrow as u32) * pb[0]) == 1;
            let wbit: [u32; 13] =
                core::array::from_fn(|i| ((cur.w[i] >> z) & 1) as u32);
            let pbv = cur.pbit as u32;
            let z0 = (z == 0) as u32;
            let z1 = (z == 1) as u32;
            let z63 = (z == 63) as u32;
            let eff: [u32; 25] = core::array::from_fn(|l| {
                if !bnd_now {
                    return a[l];
                }
                match role_now {
                    ROLE_MERKLE | ROLE_NF => match l {
                        0..=3 => pbv * wbit[l] + (1 - pbv) * a[l],
                        4..=7 => pbv * a[l - 4] + (1 - pbv) * wbit[l - 4],
                        8 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    ROLE_ANK | ROLE_ARKM => match l {
                        0..=3 => wbit[l],
                        4 => {
                            if role_now == ROLE_ANK {
                                z0
                            } else {
                                z1
                            }
                        }
                        5 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    ROLE_ACM | ROLE_ACMOUT => match l {
                        0 => wbit[4],
                        1..=4 => {
                            if role_now == ROLE_ACM {
                                a[l - 1]
                            } else {
                                wbit[l - 1]
                            }
                        }
                        5..=8 => wbit[l],
                        9..=12 => wbit[l],
                        13 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    _ => a[l],
                }
            });
            // Equality-bank gates (mirror the materialized gate columns).
            let g_e1pos = (bnd_now && role_now == ROLE_NF) as i64;
            let g_e1neg = (bnd_now && role_now == ROLE_ARKM) as i64;
            let g_e2pos = g_e1pos;
            let g_e2neg = (bnd_now && role_now == ROLE_ACM) as i64;
            // Column parity of the EFFECTIVE input (the constraint's source).
            let c: [u32; 5] = core::array::from_fn(|x| {
                eff[x] ^ eff[x + 5] ^ eff[x + 10] ^ eff[x + 15] ^ eff[x + 20]
            });
            let ap: [u32; 25] = core::array::from_fn(|l| {
                let x = l % 5;
                uv[l] ^ uu[(x + 4) % 5] ^ uu[5 + (x + 1) % 5]
            });

            // Emit the row.
            let base = values.len();
            values.resize(base + NARROW_WIDTH, F::ZERO);
            let row = &mut values[base..];
            for l in 0..25 {
                row[A_OFF + l] = F::from_u32(a[l]);
                row[US_OFF + l] = F::from_u32(us[l]);
                row[AP_OFF + l] = F::from_u32(ap[l]);
                row[UV_OFF + l] = F::from_u32(uv[l]);
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
            for (i, v) in pb.iter().enumerate() {
                row[PB_OFF + i] = F::from_u32(*v);
            }
            for (i, v) in ph.iter().enumerate() {
                row[PH_OFF + i] = F::from_u32(*v);
            }
            for (i, v) in pr.iter().enumerate() {
                row[PR_OFF + i] = F::from_u32(*v);
            }
            for k in 0..16 {
                row[D_OFF + k] = F::from_u32((pr[0] >> k) & 1);
            }
            for k in 0..4 {
                row[RB_OFF + k] = F::from_u32((role_now >> k) & 1);
            }
            let sel_codes: [u32; NSEL] = [
                ROLE_MERKLE,
                ROLE_NF,
                ROLE_ANK,
                ROLE_ARKM,
                ROLE_ACM,
                ROLE_ACMOUT,
            ];
            let selv: [u32; NSEL] =
                core::array::from_fn(|i| (role_now == sel_codes[i]) as u32);
            for (i, v) in selv.iter().enumerate() {
                row[SEL_OFF + i] = F::from_u32(*v);
            }
            let bndv = (mrow as u32) * pb[0];
            row[INJ_OFF] = F::from_u32(bndv * (selv[0] + selv[1]));
            for i in 1..5 {
                row[INJ_OFF + i] = F::from_u32(bndv * selv[i + 1]);
            }
            let g4 = ((t % 128 == 127) as u32) * pb[1] * ph[1];
            row[G4_COL] = F::from_u32(g4);
            let gpermv = ((t % 128 == 127) as u32) * pb[1];
            row[EG_OFF] = F::from_u32(bndv * selv[1]);
            row[EG_OFF + 1] = F::from_u32(bndv * selv[3]);
            row[EG_OFF + 2] = F::from_u32(gpermv * selv[3]);
            row[EG_OFF + 3] = F::from_u32(bndv * selv[1]);
            row[EG_OFF + 4] = F::from_u32(bndv * selv[4]);
            row[EG_OFF + 5] = F::from_u32(gpermv * selv[4]);
            row[PBIT_COL] = F::from_u32(pbv);
            for i in 0..13 {
                row[W_OFF + i] = F::from_u32(wbit[i]);
            }
            for (i, acc) in eq.iter().enumerate() {
                row[EQ_OFF + i] = if *acc >= 0 {
                    F::from_u32(*acc as u32)
                } else {
                    -F::from_u32((-*acc) as u32)
                };
            }
            for l in 0..25 {
                row[EFF_OFF + l] = F::from_u32(eff[l]);
            }
            // Advance the equality accumulators (constraint: next = local + legs).
            if z < 64 {
                let jc = z / 16;
                let wgt = 1i64 << (z % 16);
                for l in 0..4 {
                    let idx = 4 * l + jc;
                    eq[idx] += g_e1pos * wgt * a[l] as i64 - g_e1neg * wgt * wbit[l] as i64;
                    eq[16 + idx] +=
                        g_e2pos * wgt * wbit[l] as i64 - g_e2neg * wgt * wbit[5 + l] as i64;
                }
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

            // Advance registers to the next row: shift, then this row's
            // gated entries (mirrors the transition constraints exactly).
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
                    // Perm boundary: advance phase; program limb every 4.
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

        RowMajorMatrix::new(values, NARROW_WIDTH)
    }

    /// Extract the state materialized at block `q` (the round-q input):
    /// bit z of lane l is the `a` cell at row 128q + z.
    pub fn extract_state<F: Field>(
        trace: &RowMajorMatrix<F>,
        q: usize,
    ) -> [u64; 25] {
        let mut state = [0u64; 25];
        for z in 0..64 {
            let row = 128 * q + z;
            for (l, lane) in state.iter_mut().enumerate() {
                if trace.values[row * NARROW_WIDTH + A_OFF + l] == F::ONE {
                    *lane |= 1u64 << z;
                }
            }
        }
        state
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use p3_air::{check_all_constraints, check_constraints};
    use p3_koala_bear::KoalaBear;

    use super::*;
    use crate::reference;

    type F = KoalaBear;

    #[test]
    fn trace_satisfies_constraints() {
        let air = NarrowKeccakAir::chain_only(10);
        let trace = air.generate_trace::<F>(0);
        check_constraints(&air, &trace, &[]);
    }

    #[test]
    fn corrupted_trace_detected() {
        let air = NarrowKeccakAir::chain_only(10);
        let mut trace = air.generate_trace::<F>(0);
        // Flip one A' (theta output) bit on a T row.
        let row = 64 + 7;
        trace.values[row * NARROW_WIDTH + AP_OFF + 3] += F::ONE;
        let report = check_all_constraints(&air, &trace, &[], Some(10));
        assert!(!report.is_ok());
    }

    /// The heart of M1.5b: the pipeline's materialized states advance by
    /// exactly the reference Keccak rounds — every block, including the
    /// warmup and padding blocks.
    #[test]
    fn chain_matches_reference_rounds() {
        let air = NarrowKeccakAir::chain_only(13); // 64 blocks
        let trace = air.generate_trace::<F>(0);
        let blocks = (1usize << air.log_height) / 128;
        for q in 0..blocks - 1 {
            let cur = NarrowKeccakAir::extract_state(&trace, q);
            let nxt = NarrowKeccakAir::extract_state(&trace, q + 1);
            let expect = reference::round(&cur, reference::RC[q % 24]);
            assert_eq!(nxt, expect, "round transition at block {q}");
        }
    }

    /// M3 step 2: a 16-step Merkle chain driven by the program ring and
    /// witness columns must advance exactly like reference Merkle-node
    /// hashing — digest = lanes 0..4 of the previous perm's output,
    /// muxed with the sibling by the path bit.
    #[test]
    fn merkle_chain_matches_reference() {
        let mut program = [ROLE_DUMMY; PROGRAM_SLOTS];
        for slot in program.iter_mut().take(17).skip(1) {
            *slot = ROLE_MERKLE;
        }
        // Deterministic pseudo-random witness.
        let mut x = 0x243f6a8885a308d3u64;
        let mut rnd = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let witness: Vec<([u64; 4], bool)> = (0..16)
            .map(|_| {
                let sib = [rnd(), rnd(), rnd(), rnd()];
                let bit = rnd() & 1 == 1;
                (sib, bit)
            })
            .collect();
        let mut slot_witness = vec![SlotWitness::default(); PROGRAM_SLOTS];
        for (i, (sib, bit)) in witness.iter().enumerate() {
            slot_witness[i + 1].w[..4].copy_from_slice(sib);
            slot_witness[i + 1].pbit = *bit;
        }
        let air = NarrowKeccakAir {
            log_height: 16, // 512 blocks = 21 full perms
            program,
            slot_witness,
        };
        let trace = air.generate_trace::<F>(0);
        check_constraints(&air, &trace, &[]);

        // Reference walk: perm p (1..=16) hashes mux(bit; digest, sib).
        for (i, (sib, bit)) in witness.iter().enumerate() {
            let p = i + 1;
            let prev = NarrowKeccakAir::extract_state(&trace, 24 * p);
            let digest: [u64; 4] = prev[..4].try_into().unwrap();
            let expect = if *bit {
                reference::merkle_node_state(sib, &digest)
            } else {
                reference::merkle_node_state(&digest, sib)
            };
            let got = NarrowKeccakAir::extract_state(&trace, 24 * (p + 1));
            assert_eq!(got, expect, "merkle step {p}");
        }
    }

    /// Corrupting a sibling witness bit or the path bit must be caught.
    #[test]
    fn corrupted_merkle_witness_detected() {
        let mut program = [ROLE_DUMMY; PROGRAM_SLOTS];
        program[1] = ROLE_MERKLE;
        let mut slot_witness = vec![SlotWitness::default(); PROGRAM_SLOTS];
        slot_witness[1].w[..4].copy_from_slice(&[7, 8, 9, 10]);
        slot_witness[1].pbit = true;
        let air = NarrowKeccakAir {
            log_height: 13,
            program,
            slot_witness,
        };
        let mut trace = air.generate_trace::<F>(0);
        // Flip a sibling bit on an injection row (perm 1 boundary block =
        // block 24, row 24*128 + 5).
        let row = 24 * 128 + 5;
        trace.values[row * NARROW_WIDTH + SIB_OFF + 2] += F::ONE;
        let report = check_all_constraints(&air, &trace, &[], Some(10));
        assert!(!report.is_ok(), "sibling corruption not caught");

        // Path bit drift mid-perm must be caught by the constancy rule.
        let mut trace2 = air.generate_trace::<F>(0);
        let row2 = 24 * 128 + 700; // inside perm 1, not a boundary
        trace2.values[row2 * NARROW_WIDTH + PBIT_COL] += F::ONE;
        let report2 = check_all_constraints(&air, &trace2, &[], Some(10));
        assert!(!report2.is_ok(), "path-bit drift not caught");
    }

    /// Helpers for the input-chain tests: expected sponge input states.
    fn st_ank(sk: &[u64; 4], domain_z: u32) -> [u64; 25] {
        let mut st = [0u64; 25];
        st[..4].copy_from_slice(sk);
        st[4] = 1 << domain_z;
        st[5] = 1; // pad10*1 at bit 320
        st[16] = 1 << 63;
        st
    }
    fn st_pair(left: &[u64; 4], right: &[u64; 4]) -> [u64; 25] {
        let mut st = [0u64; 25];
        st[..4].copy_from_slice(left);
        st[4..8].copy_from_slice(right);
        st[8] = 1;
        st[16] = 1 << 63;
        st
    }
    fn st_cm(value: u64, rkm: &[u64; 4], rho: &[u64; 4], rseed: &[u64; 4]) -> [u64; 25] {
        let mut st = [0u64; 25];
        st[0] = value;
        st[1..5].copy_from_slice(rkm);
        st[5..9].copy_from_slice(rho);
        st[9..13].copy_from_slice(rseed);
        st[13] = 1; // pad10*1 at bit 832
        st[16] = 1 << 63;
        st
    }
    fn digest(state: &[u64; 25]) -> [u64; 4] {
        state[..4].try_into().unwrap()
    }

    /// M3 step 3a: the full input chain — ank -> nf -> arkm -> acm ->
    /// merkle x32 — must advance exactly like the reference, with the
    /// equality banks binding arkm's nk witness to the ank digest and
    /// acm's rho witness to the nf perm's rho.
    #[test]
    fn input_chain_matches_reference() {
        let mut x = 0x9e3779b97f4a7c15u64;
        let mut rnd = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let sk: [u64; 4] = core::array::from_fn(|_| rnd());
        let rho: [u64; 4] = core::array::from_fn(|_| rnd());
        let rseed: [u64; 4] = core::array::from_fn(|_| rnd());
        let value = rnd() & 0xffff_ffff;

        // Reference walk.
        let nk_state = reference::keccak_f(&st_ank(&sk, 0));
        let nk = digest(&nk_state);
        let nf_state = reference::keccak_f(&st_pair(&nk, &rho));
        let rkm_state = reference::keccak_f(&st_ank_r(&nk));
        let rkm = digest(&rkm_state);
        let cm_state = reference::keccak_f(&st_cm(value, &rkm, &rho, &rseed));

        let mut program = [ROLE_DUMMY; PROGRAM_SLOTS];
        program[1] = ROLE_ANK;
        program[2] = ROLE_NF;
        program[3] = ROLE_ARKM;
        program[4] = ROLE_ACM;
        let n_merkle = 8usize;
        for slot in 5..5 + n_merkle {
            program[slot] = ROLE_MERKLE;
        }
        let mut sw = vec![SlotWitness::default(); PROGRAM_SLOTS];
        sw[1].w[..4].copy_from_slice(&sk);
        sw[2].w[..4].copy_from_slice(&rho); // nf: rho, pbit = 0
        sw[3].w[..4].copy_from_slice(&nk); // arkm: nk witness (bank 1)
        sw[4].w[4] = value;
        sw[4].w[5..9].copy_from_slice(&rho); // acm: rho witness (bank 2)
        sw[4].w[9..13].copy_from_slice(&rseed);
        let sibs: Vec<([u64; 4], bool)> = (0..n_merkle)
            .map(|_| {
                let sib = [rnd(), rnd(), rnd(), rnd()];
                (sib, rnd() & 1 == 1)
            })
            .collect();
        for (i, (sib, bit)) in sibs.iter().enumerate() {
            sw[5 + i].w[..4].copy_from_slice(sib);
            sw[5 + i].pbit = *bit;
        }
        let air = NarrowKeccakAir {
            log_height: 16, // 21 full perms >= 13 used
            program,
            slot_witness: sw,
        };
        let trace = air.generate_trace::<F>(0);
        check_constraints(&air, &trace, &[]);

        assert_eq!(NarrowKeccakAir::extract_state(&trace, 24 * 2), nk_state);
        assert_eq!(NarrowKeccakAir::extract_state(&trace, 24 * 3), nf_state);
        assert_eq!(NarrowKeccakAir::extract_state(&trace, 24 * 4), rkm_state);
        assert_eq!(NarrowKeccakAir::extract_state(&trace, 24 * 5), cm_state);
        // Merkle walk from cm.
        let mut d = digest(&cm_state);
        for (i, (sib, bit)) in sibs.iter().enumerate() {
            let expect = if *bit {
                reference::merkle_node_state(sib, &d)
            } else {
                reference::merkle_node_state(&d, sib)
            };
            let got = NarrowKeccakAir::extract_state(&trace, 24 * (6 + i));
            assert_eq!(got, expect, "merkle step {i}");
            d = digest(&expect);
        }
    }

    fn st_ank_r(nk: &[u64; 4]) -> [u64; 25] {
        let mut st = [0u64; 25];
        st[..4].copy_from_slice(nk);
        st[4] = 1 << 1; // domain R at z1
        st[5] = 1;
        st[16] = 1 << 63;
        st
    }

    /// The equality banks are the soundness core: an inconsistent rho
    /// (acm vs nf) or nk (arkm vs ank digest) must fail constraints.
    #[test]
    fn inconsistent_witness_detected_by_banks() {
        let mut program = [ROLE_DUMMY; PROGRAM_SLOTS];
        program[1] = ROLE_ANK;
        program[2] = ROLE_NF;
        program[3] = ROLE_ARKM;
        program[4] = ROLE_ACM;
        let sk = [11u64, 22, 33, 44];
        let rho = [55u64, 66, 77, 88];
        let nk = {
            let st = reference::keccak_f(&st_ank(&sk, 0));
            digest(&st)
        };
        let build = |tamper_rho: bool, tamper_nk: bool| {
            let mut sw = vec![SlotWitness::default(); PROGRAM_SLOTS];
            sw[1].w[..4].copy_from_slice(&sk);
            sw[2].w[..4].copy_from_slice(&rho);
            let mut nkw = nk;
            if tamper_nk {
                nkw[2] ^= 1 << 17;
            }
            sw[3].w[..4].copy_from_slice(&nkw);
            let mut rhow = rho;
            if tamper_rho {
                rhow[0] ^= 1 << 5;
            }
            sw[4].w[5..9].copy_from_slice(&rhow);
            NarrowKeccakAir {
                log_height: 13, // 2.67 perms... need 5 perms -> 15360 rows
                program,
                slot_witness: sw,
            }
        };
        // Sanity: untampered witness satisfies constraints at this height.
        let ok_air = NarrowKeccakAir {
            log_height: 14,
            ..build(false, false)
        };
        let trace = ok_air.generate_trace::<F>(0);
        check_constraints(&ok_air, &trace, &[]);
        // Tampered rho: bank 2 close must fire.
        let bad_rho = NarrowKeccakAir {
            log_height: 14,
            ..build(true, false)
        };
        let tr = bad_rho.generate_trace::<F>(0);
        let report = check_all_constraints(&bad_rho, &tr, &[], Some(10));
        assert!(!report.is_ok(), "rho inconsistency not caught");
        // Tampered nk: bank 1 close must fire.
        let bad_nk = NarrowKeccakAir {
            log_height: 14,
            ..build(false, true)
        };
        let tr = bad_nk.generate_trace::<F>(0);
        let report = check_all_constraints(&bad_nk, &tr, &[], Some(10));
        assert!(!report.is_ok(), "nk inconsistency not caught");
    }

    /// Full-permutation check across a 24-block group.
    #[test]
    fn chain_matches_reference_permutation() {
        let air = NarrowKeccakAir::chain_only(13); // 64 blocks >= 2*24
        let trace = air.generate_trace::<F>(0);
        let input = NarrowKeccakAir::extract_state(&trace, 0);
        let output = NarrowKeccakAir::extract_state(&trace, 24);
        assert_eq!(output, reference::keccak_f(&input));
        let output2 = NarrowKeccakAir::extract_state(&trace, 48);
        assert_eq!(output2, reference::keccak_f(&output));
    }
}
