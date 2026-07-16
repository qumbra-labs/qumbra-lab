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
const PR_OFF: usize = PH_OFF + 4; // 430: 24: program ring, 4 slots x 3 bits/limb
const D_OFF: usize = PR_OFF + 24; // 454: 12: bit-decomposition of PR[0]
const RB_OFF: usize = D_OFF + 12; // 466: 3: current perm's role bits
const SELM_COL: usize = RB_OFF + 3; // 469: 1: materialized merkle-role selector
const INJM_COL: usize = SELM_COL + 1; // 470: 1: materialized merkle injection flag
const G4_COL: usize = INJM_COL + 1; // 471: 1: materialized program-ring rotation gate
const PBIT_COL: usize = G4_COL + 1; // 472: 1: merkle path bit (constant per perm)
const SIB_OFF: usize = PBIT_COL + 1; // 473: 4: sibling digest lanes (witness bits)
const EFF_OFF: usize = SIB_OFF + 4; // 477: 25: effective round input
pub const NARROW_WIDTH: usize = EFF_OFF + 25; // 502

/// Program slots (= perm slots per program period).
pub const PROGRAM_SLOTS: usize = 96;
/// 3-bit role codes packed 4-per-limb into the program ring.
pub const ROLE_DUMMY: u32 = 0;
pub const ROLE_MERKLE: u32 = 1;
// codes 2..8 reserved: absorb-fresh, bind-anchor, bind-nf, bind-cm (M3 step 3).

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
pub struct NarrowKeccakAir {
    pub log_height: usize,
    /// 3-bit role code per program slot (period 96 perms).
    pub program: [u32; PROGRAM_SLOTS],
    /// (sibling digest lanes, path bit) consumed in order by merkle-role
    /// perm instances; cycled if the padded height replays the program.
    pub merkle_witness: Vec<([u64; 4], bool)>,
}

impl NarrowKeccakAir {
    /// M1.5c-equivalent instance: every perm slot dummy, pure chaining.
    pub fn chain_only(log_height: usize) -> Self {
        Self {
            log_height,
            program: [ROLE_DUMMY; PROGRAM_SLOTS],
            merkle_witness: Vec::new(),
        }
    }

    /// Program-ring limb i: slots 4i..4i+4, 3 bits each.
    fn pr_limb(&self, i: usize) -> u32 {
        (0..4)
            .map(|j| self.program[(4 * i + j) % PROGRAM_SLOTS] << (3 * j))
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
        35
    }

    /// 35 period-128 columns: [mrow, u63, e1_0..e1_24, blast, sel_0..sel_6]
    /// where e1_l = trow AND rho-wrap for lane l at this T row's slice,
    /// blast = 1 on the last row of each 128-row block (RC ring rotation),
    /// sel_k = 1 on the M row with z = 2^k - 1 (iota bit positions).
    fn periodic_columns(&self) -> Vec<Vec<F>> {
        let mut cols = vec![Vec::with_capacity(128); 35];
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
        // PR[0] = 12 bool bits (4 slots x 3 bits).
        for k in 0..12 {
            builder.assert_bool(local[D_OFF + k].clone());
        }
        builder.assert_eq(weighted(D_OFF, 12, &local), local[PR_OFF].clone());
        // Active role bits: phase phi of perm p is p mod 4; the left-rotating
        // phase ring exposes phi via ph[(4 - phi) % 4], so the selector for
        // quarter phi is ph[(4 - phi) % 4].
        for k in 0..3 {
            let sel_quarter = (0..4)
                .map(|phi| {
                    local[PH_OFF + (4 - phi) % 4].clone()
                        * local[D_OFF + 3 * phi + k].clone()
                })
                .fold(AB::Expr::ZERO, |acc, e| acc + e);
            builder.assert_eq(local[RB_OFF + k].clone(), sel_quarter);
        }
        // Merkle-role selector: role code 1 = 0b001.
        let r0 = local[RB_OFF].clone();
        let r1 = local[RB_OFF + 1].clone();
        let r2 = local[RB_OFF + 2].clone();
        builder.assert_eq(
            local[SELM_COL].clone(),
            r0 * (AB::Expr::ONE - r1) * (AB::Expr::ONE - r2),
        );
        // Merkle injection flag: boundary M rows of a merkle-role perm.
        builder.assert_eq(
            local[INJM_COL].clone(),
            mrow.clone() * local[PB_OFF].clone() * local[SELM_COL].clone(),
        );
        // Program-ring rotation gate: perm boundary AND phase wrap (the
        // phase ring shows ph[1] on perms with p mod 4 == 3).
        builder.assert_eq(
            local[G4_COL].clone(),
            blast.clone() * local[PB_OFF + 1].clone() * local[PH_OFF + 1].clone(),
        );
        // Witness bits.
        builder.assert_bool(local[PBIT_COL].clone());
        for i in 0..4 {
            builder.assert_bool(local[SIB_OFF + i].clone());
        }
        // eff = a + injm*(msg_merkle - a): the merkle message state is
        // mux(path bit; digest = a lanes 0..3, sibling witness) in the
        // first 8 lanes, pad10*1 bits (z=0 lane 8, z=63 lane 16 — original
        // Keccak-256 padding, Ethereum-style, single 512-bit block), and
        // zeros elsewhere including the capacity lanes.
        let pbit = local[PBIT_COL].clone();
        let sib = |i: usize| local[SIB_OFF + i].clone();
        let injm = local[INJM_COL].clone();
        for l in 0..25 {
            let msg: AB::Expr = match l {
                0..=3 => {
                    pbit.clone() * sib(l) + (AB::Expr::ONE - pbit.clone()) * a(l)
                }
                4..=7 => {
                    pbit.clone() * a(l - 4)
                        + (AB::Expr::ONE - pbit.clone()) * sib(l - 4)
                }
                8 => sel(0),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            builder.assert_eq(eff(l), a(l) + injm.clone() * (msg - a(l)));
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
        let mut merkle_count = 0usize;
        let role_of = |p: usize| self.program[p % PROGRAM_SLOTS];
        let wit = |mc: usize| -> ([u64; 4], bool) {
            if self.merkle_witness.is_empty() {
                ([0; 4], false)
            } else {
                self.merkle_witness[mc % self.merkle_witness.len()]
            }
        };
        let (mut cur_sib, mut cur_bit) = if role_of(0) == ROLE_MERKLE {
            merkle_count = 1;
            wit(0)
        } else {
            ([0; 4], false)
        };

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
            // Effective round input: merkle injection replaces the state at
            // boundary M rows of merkle-role perms (mirrors the eff mux).
            let role_now = role_of(perm_idx);
            let injm_now = (mrow as u32) * pb[0] * ((role_now == ROLE_MERKLE) as u32);
            let sibbit: [u32; 4] =
                core::array::from_fn(|i| ((cur_sib[i] >> z) & 1) as u32);
            let pbv = cur_bit as u32;
            let eff: [u32; 25] = core::array::from_fn(|l| {
                if injm_now == 1 {
                    match l {
                        0..=3 => pbv * sibbit[l] + (1 - pbv) * a[l],
                        4..=7 => pbv * a[l - 4] + (1 - pbv) * sibbit[l - 4],
                        8 => (z == 0) as u32,
                        16 => (z == 63) as u32,
                        _ => 0,
                    }
                } else {
                    a[l]
                }
            });
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
            for k in 0..12 {
                row[D_OFF + k] = F::from_u32((pr[0] >> k) & 1);
            }
            let role = role_of(perm_idx);
            for k in 0..3 {
                row[RB_OFF + k] = F::from_u32((role >> k) & 1);
            }
            let selm = (role == ROLE_MERKLE) as u32;
            row[SELM_COL] = F::from_u32(selm);
            let injm = (mrow as u32) * pb[0] * selm;
            row[INJM_COL] = F::from_u32(injm);
            let g4 = ((t % 128 == 127) as u32) * pb[1] * ph[1];
            row[G4_COL] = F::from_u32(g4);
            row[PBIT_COL] = F::from_u32(pbv);
            for i in 0..4 {
                row[SIB_OFF + i] = F::from_u32(sibbit[i]);
            }
            for l in 0..25 {
                row[EFF_OFF + l] = F::from_u32(eff[l]);
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
                    if role_of(perm_idx) == ROLE_MERKLE {
                        merkle_count += 1;
                        let (sb, bt) = wit(merkle_count - 1);
                        cur_sib = sb;
                        cur_bit = bt;
                    } else {
                        cur_sib = [0; 4];
                        cur_bit = false;
                    }
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
        let air = NarrowKeccakAir {
            log_height: 16, // 512 blocks = 21 full perms
            program,
            merkle_witness: witness.clone(),
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
        let air = NarrowKeccakAir {
            log_height: 13,
            program,
            merkle_witness: vec![([7, 8, 9, 10], true)],
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
