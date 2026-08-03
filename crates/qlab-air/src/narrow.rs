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
//! the registers emit at row 0 (warmup).
//!
//! ## What the first permutation's input is bound to, and what makes it safe
//!
//! Nothing binds it (issue #143). Row 0's `S`/`V`/`U` cells appear in `eval`
//! only in read positions — the two same-row recompositions have the register
//! slot on the *source* side of the `assert_eq` (so they range-limit it to
//! 25 / 25 / 10 bits and no more), every other occurrence targets `next[..]`,
//! and no `when_first_row` touches them. So **row 0's `S[1..=64]` carries the
//! first permutation's round-0 input — 64 slots x 25 bits = 1600 bits, one
//! whole Keccak state, entirely prover-chosen.** (The materialized state `a` is
//! their image under chi o pi, plus iota on lane 0; chi is invertible, so every
//! state is reachable.) The remaining 191 free cells (`S[65..=126]`,
//! `V[1..=64]`, `U[1..=65]`) perturb only cells nothing reads.
//!
//! That is safe because the value has **no consumer**, and the three facts
//! carrying that are program-layout facts, not constraints:
//!
//!   1. `program[0] = ROLE_DUMMY`. `ROLE_DUMMY` is absent from `sel_codes`, so
//!      every selector, injection flag and bank gate is 0 on perm 0 — it cannot
//!      reach a public value.
//!   2. `program[1] = ROLE_ANK`, and `msg_ank` is a **full-state override**: it
//!      assigns all 25 lanes from witness + periodic constants with no `a` term.
//!      Since V/U ingest only `eff` and S refills from `ap = theta(eff)`, the
//!      warmup residue is severed exactly one block wide. The first role that
//!      *reads* the chained digest is `program[2] = ROLE_NF`, and what it reads
//!      is the ANK perm's output.
//!   3. Every accumulator reaching a public value is pinned at row 0 (EQ, BQ,
//!      BL, EP), so warmup cannot preload a bank.
//!
//! The program is not prover-chosen either: the PR ring is pinned at row 0 to
//! the verifier's `pr_limb`. So (1) and (2) are verifier-side and the prover
//! cannot deviate from them — but **the AIR does not forbid a program that
//! violates them** (`merkle_chain_matches_reference` builds one, and its first
//! real role does consume the warmup state). Two tests hold this up:
//! `first_perm_input_is_free_and_unconsumed` locks the property, and
//! `bucket_program_does_not_consume_warmup` locks the layout.
//!
//! One consequence of row 0 being free: "every 24-block group is a genuine
//! keccak-f of its input" holds for perms 1.. but **not for perm 0 under an
//! adversarial prover** — row 0's `U[65]` reaches `S` at row 64 through the
//! `u_col(64)` entry, so perm 0's round 0 need not be a Keccak round at all.
//! Under the zero init that `generate_trace` uses, that term is 0 and every
//! block including the warmup is a genuine round (`chain_matches_reference_
//! rounds`). Perm 0's output is read by nothing either way.

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
const NSEL: usize = 13; // materialized role selectors, order = SEL_CODES
const SEL_OFF: usize = RB_OFF + 4; // [mrk, nf, ank, arkm, acm, acmout, banchor, bnf1, bnf2, bcm1, bcm2, bal, end]
const INJ_OFF: usize = SEL_OFF + NSEL; // 5: injection flags [mrk+nf, ank, arkm, acm, acmout]
const G4_COL: usize = INJ_OFF + 5; // 1: program-ring rotation gate
const PBIT_COL: usize = G4_COL + 1; // 1: merkle path bit (constant per perm)
const W_OFF: usize = PBIT_COL + 1; // 13: witness lanes (role-multiplexed)
const SIB_OFF: usize = W_OFF; // sibling digest lanes = W0..3 (merkle rows)
const EQ_OFF: usize = W_OFF + 13; // 32: two equality banks, 4 lanes x 4 chunks
const EG_OFF: usize = EQ_OFF + 32; // 6: eq gates [e1pos, e1neg, e1close, e2pos, e2neg, e2close]
// --- step 3b: one-shot epoch, bind bank, balance ---
const EP_COL: usize = EG_OFF + 6; // 1: epoch flag (1 during program pass 0, then 0)
const GWRAP_COL: usize = EP_COL + 1; // 1: epoch-kill gate (gperm * sel_end)
const SE_OFF: usize = GWRAP_COL + 1; // 6: ep-gated selectors [nf, arkm, acm, acmout, bindsum, bal]
const BQ_OFF: usize = SE_OFF + 6; // 16: bind bank, 4 lanes x 4 chunks
const BGCAP_COL: usize = BQ_OFF + 16; // 1: bind capture gate
const BGRST_COL: usize = BGCAP_COL + 1; // 1: bind reset gate
const BGC_OFF: usize = BGRST_COL + 1; // 5: bind close gates [banchor, bnf1, bnf2, bcm1, bcm2]
const BL_OFF: usize = BGC_OFF + 5; // 4: balance accumulators (16-bit chunks)
const BLC_OFF: usize = BL_OFF + 4; // 9: carry bit encodings (3 bools x 3 carries)
const BLCLOSE_COL: usize = BLC_OFF + 9; // 1: balance close gate
const INJ3E_COL: usize = BLCLOSE_COL + 1; // 1: inj(acm) * ep
const INJ4E_COL: usize = INJ3E_COL + 1; // 1: inj(acmout) * ep
const EFF_OFF: usize = INJ4E_COL + 1; // 25: effective round input
// --- issue #219 / QUM-69: the ROLE_BNF2 liveness latch (feature `q69-latch`) ---
/// `L` — the one-bit span latch. Set at `ROLE_BNF2`'s close row, cleared at the
/// next `ROLE_BANCHOR`'s, pinned to 0 at row 0. Both set and clear events are
/// already materialized as bind-close gates, so this is **program-driven**: the
/// prover chooses nothing about where it is high.
#[cfg(feature = "q69-latch")]
const LATCH_COL: usize = EFF_OFF + 25;
/// `dv` — the prover's liveness bool, persistent for the whole trace.
#[cfg(feature = "q69-latch")]
const DV_COL: usize = LATCH_COL + 1;
/// `L·dv` — materialized so the gated anchor close and the value-zero mint
/// guard both stay at degree 3, matching this file's convention.
#[cfg(feature = "q69-latch")]
const LDV_COL: usize = DV_COL + 1;
#[cfg(feature = "q69-latch")]
pub const NARROW_WIDTH: usize = LDV_COL + 1;
#[cfg(not(feature = "q69-latch"))]
pub const NARROW_WIDTH: usize = EFF_OFF + 25; // 618

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
/// rkm = H(nk || D_R || d): domain bit at lane 4 z1, nk as witness W[0..4]
/// (bound to the ank digest by equality bank 1), the 128-bit diversifier `d`
/// as witness W[5..7] at lanes 5..7, then pad10*1 from bit 448 (lane 7 z0).
/// Absorbing `d` fills previously-zero rate lanes of the SAME single
/// permutation — no extra perm, no height change (issue #32).
pub const ROLE_ARKM: u32 = 4;
/// cm = H(value || rkm || rho || rseed): value = W4, rkm = chained digest
/// a[0..4] at lanes 1..5, rho = W5..9 (bound to the NF perm's rho by
/// equality bank 2), rseed = W9..13, pad at bit 832 (lane 13 z0).
pub const ROLE_ACM: u32 = 5;
/// Output cm' = H(value || rkm' || rho' || rseed'): all witness —
/// value = W4, rkm' = W0..4, rho' = W5..9, rseed' = W9..13.
pub const ROLE_ACMOUT: u32 = 6;
/// Bind perms: no injection (they chain the producer's output state, so
/// their boundary rows carry its digest); the bind bank captures a[0..4]
/// there and closes against the public values at the perm's last row.
pub const ROLE_BANCHOR: u32 = 7;
pub const ROLE_BNF1: u32 = 8;
pub const ROLE_BNF2: u32 = 9;
pub const ROLE_BCM1: u32 = 10;
pub const ROLE_BCM2: u32 = 11;
/// Balance close: the fee comparison fires at this perm's last row.
pub const ROLE_BAL: u32 = 12;
/// Program end: kills the one-shot epoch flag so replayed program passes
/// in the padding region capture and close nothing.
pub const ROLE_END: u32 = 13;

/// Public-value layout: anchor, nf1, nf2, cm1, cm2 as 16 chunks each
/// (4 lanes x 4 sixteen-bit z-chunks, chunk-major within lane), then fee
/// as 4 sixteen-bit chunks. Helpers in `pv_vec`.
pub const PV_ANCHOR: usize = 0;
pub const PV_NF1: usize = 16;
pub const PV_NF2: usize = 32;
pub const PV_CM1: usize = 48;
pub const PV_CM2: usize = 64;
pub const PV_FEE: usize = 80;
pub const PV_LEN: usize = 84;

/// Pack a 256-bit digest into its 16 public-value chunks
/// (index 4*lane + chunk, value = bits [16*chunk .. 16*chunk+16) of lane).
pub fn pv_chunks(d: &[u64; 4]) -> [u32; 16] {
    core::array::from_fn(|i| ((d[i / 4] >> (16 * (i % 4))) & 0xffff) as u32)
}

/// Build the full public-value vector for a bucket instance.
pub fn pv_vec(
    anchor: &[u64; 4],
    nf1: &[u64; 4],
    nf2: &[u64; 4],
    cm1: &[u64; 4],
    cm2: &[u64; 4],
    fee: u64,
) -> Vec<u32> {
    let mut out = Vec::with_capacity(PV_LEN);
    for d in [anchor, nf1, nf2, cm1, cm2] {
        out.extend_from_slice(&pv_chunks(d));
    }
    for j in 0..4 {
        out.push(((fee >> (16 * j)) & 0xffff) as u32);
    }
    out
}

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
    /// Public fee (needed to witness the balance carry encodings).
    pub fee: u64,
    /// Issue #219 / QUM-69: the prover's liveness bool `dv`. `true` declares
    /// **input slot 1 a dummy** — its anchor bind is relaxed and its Merkle fold
    /// is unconstrained, and the AIR forces its value to 0 in exchange.
    ///
    /// It is a *witness*, so it enters only the trace, never a constraint
    /// constant: the AIR is program-independent and so is unchanged by this
    /// flag. Slot 0 can never be the dummy — see the latch section of `eval`.
    /// Honoured only under the `q69-latch` feature; setting it without the
    /// feature panics in `generate_trace_from` rather than silently proving a
    /// real spend the caller believes is a dummy.
    pub dv: bool,
}

impl NarrowKeccakAir {
    /// M1.5c-equivalent instance: every perm slot dummy, pure chaining.
    pub fn chain_only(log_height: usize) -> Self {
        Self {
            log_height,
            program: [ROLE_DUMMY; PROGRAM_SLOTS],
            slot_witness: Vec::new(),
            fee: 0,
            dv: false,
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

    fn num_public_values(&self) -> usize {
        PV_LEN
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
            ROLE_BANCHOR,
            ROLE_BNF1,
            ROLE_BNF2,
            ROLE_BCM1,
            ROLE_BCM2,
            ROLE_BAL,
            ROLE_END,
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
            // at lane 4 z1, diversifier d (witness W5..7) at lanes 5..7, then
            // pad10*1 from lane 7 z0 (bit 448) — one extra absorb-block's worth
            // of rate lanes in the SAME perm (issue #32).
            let msg_arkm: AB::Expr = match l {
                0..=3 => w(l),
                4 => sel(1),
                5 => w(5),
                6 => w(6),
                7 => sel(0),
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
        // ep-gated: replayed program passes in the padding must neither
        // accumulate nor close (SE_OFF holds sel*ep, defined below).
        builder.assert_eq(local[EG_OFF].clone(), bnd.clone() * local[SE_OFF].clone());
        builder.assert_eq(
            local[EG_OFF + 1].clone(),
            bnd.clone() * local[SE_OFF + 1].clone(),
        );
        builder.assert_eq(
            local[EG_OFF + 2].clone(),
            gperm.clone() * local[SE_OFF + 1].clone(),
        );
        builder.assert_eq(local[EG_OFF + 3].clone(), bnd.clone() * local[SE_OFF].clone());
        builder.assert_eq(
            local[EG_OFF + 4].clone(),
            bnd.clone() * local[SE_OFF + 2].clone(),
        );
        builder.assert_eq(
            local[EG_OFF + 5].clone(),
            gperm.clone() * local[SE_OFF + 2].clone(),
        );
        for j in 0..16 {
            builder.assert_zero(local[EG_OFF + 2].clone() * local[EQ_OFF + j].clone());
            builder
                .assert_zero(local[EG_OFF + 5].clone() * local[EQ_OFF + 16 + j].clone());
        }
        for j in 0..32 {
            builder.when_first_row().assert_zero(local[EQ_OFF + j].clone());
        }

        // --- Step 3b: epoch, bind bank, balance (same-row parts) ---
        let ep = local[EP_COL].clone();
        builder.when_first_row().assert_eq(ep.clone(), AB::Expr::ONE);
        // Epoch-kill gate and ep-gated selectors (all materialized so
        // downstream gate definitions stay deg <= 3).
        builder.assert_eq(
            local[GWRAP_COL].clone(),
            gperm.clone() * sel_role(12),
        );
        let se_src: [usize; 4] = [1, 3, 4, 5]; // nf, arkm, acm, acmout
        for (i, si) in se_src.iter().enumerate() {
            builder.assert_eq(local[SE_OFF + i].clone(), sel_role(*si) * ep.clone());
        }
        let bindsum = sel_role(6) + sel_role(7) + sel_role(8) + sel_role(9) + sel_role(10);
        builder.assert_eq(local[SE_OFF + 4].clone(), bindsum * ep.clone());
        builder.assert_eq(local[SE_OFF + 5].clone(), sel_role(11) * ep.clone());
        // Bind capture / reset / close gates.
        builder.assert_eq(
            local[BGCAP_COL].clone(),
            bnd.clone() * local[SE_OFF + 4].clone(),
        );
        builder.assert_eq(
            local[BGRST_COL].clone(),
            gperm.clone() * local[SE_OFF + 4].clone(),
        );
        for (i, si) in [6usize, 7, 8, 9, 10].iter().enumerate() {
            builder.assert_eq(
                local[BGC_OFF + i].clone(),
                gperm.clone() * sel_role(*si),
            );
        }
        // Bind closes: acc must equal the target public chunk, ep-gated on
        // the value side so padding-pass closes degenerate to acc = 0 = 0.
        let pvs: Vec<AB::Expr> = builder
            .public_values()
            .iter()
            .map(|v| (*v).into())
            .collect();
        let pv = |i: usize| -> AB::Expr { pvs[i].clone() };
        let pv_base: [usize; 5] = [PV_ANCHOR, PV_NF1, PV_NF2, PV_CM1, PV_CM2];
        for (x, base) in pv_base.iter().enumerate() {
            for j in 0..16 {
                let close = local[BGC_OFF + x].clone()
                    * (local[BQ_OFF + j].clone() - pv(base + j) * ep.clone());
                // Issue #219: `L·dv` relaxes the ANCHOR close and nothing else.
                // The four other binds (PV_NF1, PV_NF2, PV_CM1, PV_CM2) fire
                // unconditionally, so a dummy slot still publishes a nullifier
                // that the proof commits to — an unbound `PV_NF2` is a
                // censorship vector a relay can rewrite, not merely a
                // uniqueness question. Degree 3 (three materialized factors:
                // the close gate, `1 − L·dv`, and the accumulator; public
                // values are degree 0), so the quotient degree does not move.
                #[cfg(feature = "q69-latch")]
                let close = if x == 0 {
                    (AB::Expr::ONE - local[LDV_COL].clone()) * close
                } else {
                    close
                };
                builder.assert_zero(close);
            }
        }
        for j in 0..16 {
            builder.when_first_row().assert_zero(local[BQ_OFF + j].clone());
        }
        // Balance: ep-gated capture flags; carries as 3-bool encodings; the
        // close row enforces the 16-bit-limb subtraction chain
        // sum_in - sum_out = fee exactly (all magnitudes << p, so the field
        // equations hold as integers).
        builder.assert_eq(local[INJ3E_COL].clone(), inj(3) * ep.clone());
        builder.assert_eq(local[INJ4E_COL].clone(), inj(4) * ep.clone());
        builder.assert_eq(
            local[BLCLOSE_COL].clone(),
            gperm.clone() * local[SE_OFF + 5].clone(),
        );
        for k in 0..9 {
            builder.assert_bool(local[BLC_OFF + k].clone());
        }
        for j in 0..4 {
            builder.when_first_row().assert_zero(local[BL_OFF + j].clone());
        }
        // carry_j = enc_j - 2, enc_j = b0 + 2*b1 + 4*b2 (range [-2, 5]).
        let carry = |j: usize| -> AB::Expr {
            local[BLC_OFF + 3 * j].clone()
                + local[BLC_OFF + 3 * j + 1].clone() * two.clone()
                + local[BLC_OFF + 3 * j + 2].clone() * two.clone() * two.clone()
                - two.clone()
        };
        let close = local[BLCLOSE_COL].clone();
        let w16 = AB::Expr::from_u32(1 << 16);
        builder.assert_zero(
            close.clone()
                * (local[BL_OFF].clone() - pv(PV_FEE) * ep.clone()
                    - w16.clone() * carry(0)),
        );
        for j in 1..3 {
            builder.assert_zero(
                close.clone()
                    * (local[BL_OFF + j].clone() + carry(j - 1)
                        - pv(PV_FEE + j) * ep.clone()
                        - w16.clone() * carry(j)),
            );
        }
        builder.assert_zero(
            close.clone()
                * (local[BL_OFF + 3].clone() + carry(2) - pv(PV_FEE + 3) * ep.clone()),
        );

        // --- Issue #219 / QUM-69: the ROLE_BNF2 liveness latch (same-row) ---
        //
        // The canonical program emits, per input,
        // `ANK → NF → BNF_j → ARKM → ACM → 32 × MERKLE → BANCHOR`, chain 0 with
        // `ROLE_BNF1` and chain 1 with `ROLE_BNF2` (`input_chain` below). So
        // `ROLE_BNF2` marks chain 1 uniquely, and a bit set at its close row and
        // cleared at the next `ROLE_BANCHOR`'s is high across exactly chain 1's
        // `ARKM…BANCHOR` span.
        //
        // Both events are ALREADY materialized as bind-close gates —
        // `BGC_OFF+2 = gperm·sel(BNF2)` and `BGC_OFF+0 = gperm·sel(BANCHOR)`
        // (`:704-709`) — so the latch is **one transition constraint at degree
        // 2**, below. That is why this is cheaper than the equality-bank
        // precedent it was modelled on: the two gates it needs were already paid
        // for by the bind bank.
        //
        // What makes slot 0 unreachable is the row-0 pin plus program order, not
        // an argument: `L` starts at 0 and can only rise at `ROLE_BNF2`'s close,
        // which the verifier's own program places AFTER chain 0's
        // `ROLE_BANCHOR`. The prover picks `dv`; it cannot pick where `L` is
        // high, so `L·dv` can only ever relax chain 1.
        #[cfg(feature = "q69-latch")]
        {
            let latch = local[LATCH_COL].clone();
            let dv = local[DV_COL].clone();
            builder.assert_bool(latch.clone());
            builder.assert_bool(dv.clone());
            builder.when_first_row().assert_zero(latch.clone());
            builder.assert_eq(local[LDV_COL].clone(), latch * dv);
            // 🔴 MANDATORY, and the ruling on `#219` names it explicitly:
            // without the anchor bind, an unconstrained input value is a mint.
            // `INJ3E = inj(acm)·ep` fires on the 64 boundary rows of every
            // `ROLE_ACM` perm and `W4` carries bit z of that slot's value, so
            // this forces the dummy slot's value to 0 one bit at a time. Degree
            // 3 — `L·dv` is materialized precisely so this is not degree 4.
            builder.assert_zero(
                local[INJ3E_COL].clone()
                    * local[LDV_COL].clone()
                    * local[W_OFF + 4].clone(),
            );
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

        // Epoch decay: one-shot, killed at the program-end perm boundary.
        t.assert_eq(
            next[EP_COL].clone(),
            local[EP_COL].clone() * (AB::Expr::ONE - local[GWRAP_COL].clone()),
        );
        // Bind bank: reset after close, capture the chained digest lanes.
        for l in 0..4 {
            for j in 0..4 {
                let idx = 4 * l + j;
                t.assert_eq(
                    next[BQ_OFF + idx].clone(),
                    (AB::Expr::ONE - local[BGRST_COL].clone())
                        * local[BQ_OFF + idx].clone()
                        + local[BGCAP_COL].clone()
                            * per[35 + j].clone()
                            * local[A_OFF + l].clone(),
                );
            }
        }
        // Balance accumulation: +value bits at acm, -value bits at acmout.
        for j in 0..4 {
            t.assert_eq(
                next[BL_OFF + j].clone(),
                local[BL_OFF + j].clone()
                    + local[INJ3E_COL].clone()
                        * per[35 + j].clone()
                        * local[W_OFF + 4].clone()
                    - local[INJ4E_COL].clone()
                        * per[35 + j].clone()
                        * local[W_OFF + 4].clone(),
            );
        }
        // Issue #219 / QUM-69: the latch, as ONE transition constraint at
        // degree 2 — set at BNF2's close, cleared at BANCHOR's, hold otherwise.
        // Both gates are bool and never fire on the same row (one perm, one
        // role), so `L` stays in {0, 1} without needing the bool check to carry
        // the argument. `dv` is persistent: one bool for the whole trace, which
        // is what makes it a per-TRANSACTION declaration rather than something
        // the prover can vary per perm.
        #[cfg(feature = "q69-latch")]
        {
            t.assert_eq(
                next[LATCH_COL].clone(),
                local[LATCH_COL].clone() * (AB::Expr::ONE - local[BGC_OFF].clone())
                    + local[BGC_OFF + 2].clone(),
            );
            t.assert_eq(next[DV_COL].clone(), local[DV_COL].clone());
        }

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
// Bucket instance builder: the full 2x2 transaction statement.
// ---------------------------------------------------------------------------

/// One transaction input: spend key, note fields, and a depth-32 path.
#[derive(Clone)]
pub struct TxInput {
    pub sk: [u64; 4],
    pub value: u64,
    pub rho: [u64; 4],
    pub rseed: [u64; 4],
    /// The address diversifier `d` (128-bit, two little-endian words) bound
    /// into `rkm = H(nk ‖ D_R ‖ d)`. Two addresses of one wallet differ in `d`
    /// and therefore in `rkm`, so their notes are unlinkable (issue #32). `d`
    /// enters the ARKM perm as witness (lanes 5..7); it is pinned to the public
    /// surface through `rkm → cm → membership → anchor`, so the prover cannot
    /// vary it independently of the note it is spending.
    pub d: [u64; 2],
}

/// One transaction output note (recipient key material is witness).
#[derive(Clone, Copy)]
pub struct TxOutput {
    pub value: u64,
    pub rkm: [u64; 4],
    pub rho: [u64; 4],
    pub rseed: [u64; 4],
}

/// Everything a prover/verifier pair needs for one 2x2 bucket instance.
pub struct BucketInstance {
    pub air: NarrowKeccakAir,
    /// Public values (see PV_* layout) as u32 chunks.
    pub pvs: Vec<u32>,
    pub anchor: [u64; 4],
    pub nf: [[u64; 4]; 2],
    pub cm_out: [[u64; 4]; 2],
}

/// Merkle tree depth of the bucket statement.
pub const MERKLE_DEPTH: usize = 32;
/// Perm slots used by the full bucket program, INCLUDING the leading
/// dummy warm-up slot (fits 2^18 rows: 83 x 3072 = 254,976).
pub const BUCKET_PERMS: usize = 1 + 2 * (5 + MERKLE_DEPTH + 1) + 2 * 2 + 2;

/// A caller-supplied depth-32 Merkle authentication path for one spent note
/// (issue #39). `siblings[i]` / `path_bits[i]` describe level `i`, leaf level
/// first. `path_bits[i] == true` means the running digest is the RIGHT child at
/// level `i` (its sibling sits on the LEFT: `H(sibling ‖ digest)`); `false`
/// means the digest is the LEFT child (`H(digest ‖ sibling)`). This is exactly
/// the `pbit` convention the `ROLE_MERKLE` step consumes.
///
/// `build_bucket_with_witnesses` lays these straight into the membership slots;
/// the circuit folds `leaf → … → root` and binds the result to the public
/// anchor, so a witness that does not resolve to the supplied anchor produces an
/// unprovable instance. The prover no longer fabricates the tree — the witness
/// (and the finalized anchor it resolves to) come from the live commitment tree.
#[derive(Clone, Copy)]
pub struct MerkleWitness {
    pub siblings: [[u64; 4]; MERKLE_DEPTH],
    pub path_bits: [bool; MERKLE_DEPTH],
}

impl MerkleWitness {
    /// Fold `leaf` up through the path and return the root this witness resolves
    /// to. Mirrors the `ROLE_MERKLE` fold (`merkle_node_state` digest = lanes
    /// 0..4) so callers can cross-check a witness against a live-tree root before
    /// proving.
    pub fn fold_root(&self, leaf: &[u64; 4]) -> [u64; 4] {
        let mut d = *leaf;
        for (sib, bit) in self.siblings.iter().zip(self.path_bits.iter()) {
            let st = if *bit {
                crate::reference::merkle_node_state(sib, &d)
            } else {
                crate::reference::merkle_node_state(&d, sib)
            };
            d = st[..4].try_into().unwrap();
        }
        d
    }
}

/// Derive `(nk, nf, cm)` for one spend input — the host mirror of the
/// `ROLE_ANK`/`ROLE_NF`/`ROLE_ARKM`/`ROLE_ACM` chain. `cm` is the tree leaf.
pub fn derive_input(inp: &TxInput) -> ([u64; 4], [u64; 4], [u64; 4]) {
    use crate::reference;
    let mut nk_in = [0u64; 25];
    nk_in[..4].copy_from_slice(&inp.sk);
    nk_in[4] = 1; // domain N (z0)
    nk_in[5] = 1;
    nk_in[16] = 1 << 63;
    let nk_st = reference::keccak_f(&nk_in);
    let nk: [u64; 4] = nk_st[..4].try_into().unwrap();
    let mut nf_in = [0u64; 25];
    nf_in[..4].copy_from_slice(&nk);
    nf_in[4..8].copy_from_slice(&inp.rho);
    nf_in[8] = 1;
    nf_in[16] = 1 << 63;
    let nf_st = reference::keccak_f(&nf_in);
    let nf: [u64; 4] = nf_st[..4].try_into().unwrap();
    let mut rkm_in = [0u64; 25];
    rkm_in[..4].copy_from_slice(&nk);
    rkm_in[4] = 1 << 1; // domain R (z1)
    rkm_in[5] = inp.d[0]; // diversifier word 0 (issue #32)
    rkm_in[6] = inp.d[1]; // diversifier word 1
    rkm_in[7] = 1; // pad10*1 start, moved from lane 5 to bit 448
    rkm_in[16] = 1 << 63;
    let rkm_st = reference::keccak_f(&rkm_in);
    let rkm: [u64; 4] = rkm_st[..4].try_into().unwrap();
    let mut cm_in = [0u64; 25];
    cm_in[0] = inp.value;
    cm_in[1..5].copy_from_slice(&rkm);
    cm_in[5..9].copy_from_slice(&inp.rho);
    cm_in[9..13].copy_from_slice(&inp.rseed);
    cm_in[13] = 1;
    cm_in[16] = 1 << 63;
    let cm_st = reference::keccak_f(&cm_in);
    let cm: [u64; 4] = cm_st[..4].try_into().unwrap();
    (nk, nf, cm)
}

/// Fabricate the demo/self-test shared tree: both leaves live at positions 0/1
/// of one depth-32 tree with deterministic pseudo-random upper siblings shared
/// by both paths. Returns `([witness0, witness1], root)`. This is the ONLY place
/// that invents a tree — used by the legacy [`build_bucket`] convenience for
/// benches and self-tests; the live-consensus path supplies real witnesses.
pub fn fabricated_shared_tree(cm1: &[u64; 4], cm2: &[u64; 4]) -> ([MerkleWitness; 2], [u64; 4]) {
    let mut x = 0xa5a5_5a5a_dead_beefu64;
    let mut rnd = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    // MERKLE_DEPTH - 1 shared upper siblings (level 0 sibling = the other leaf).
    let upper: Vec<[u64; 4]> = (1..MERKLE_DEPTH)
        .map(|_| [rnd(), rnd(), rnd(), rnd()])
        .collect();
    let build = |leaf0: bool| {
        let mut siblings = [[0u64; 4]; MERKLE_DEPTH];
        let mut path_bits = [false; MERKLE_DEPTH];
        // Level 0: leaf 0's sibling is leaf 1 (bit 0), leaf 1's is leaf 0 (bit 1).
        siblings[0] = if leaf0 { *cm2 } else { *cm1 };
        path_bits[0] = !leaf0;
        for (i, sib) in upper.iter().enumerate() {
            siblings[i + 1] = *sib;
        }
        MerkleWitness { siblings, path_bits }
    };
    let w0 = build(true);
    let w1 = build(false);
    let root = w0.fold_root(cm1);
    debug_assert_eq!(root, w1.fold_root(cm2), "shared tree must have one root");
    ([w0, w1], root)
}

/// Build the full 2x2 bucket against a **fabricated** shared tree (both inputs
/// at leaves 0/1). Convenience wrapper for benches and self-tests: it invents
/// the membership witnesses via [`fabricated_shared_tree`] and delegates to
/// [`build_bucket_with_witnesses`]. Real consensus proving takes the
/// live-tree path (issue #39). Balance must hold: sum(in) = sum(out) + fee.
pub fn build_bucket(
    log_height: usize,
    inputs: &[TxInput; 2],
    outputs: &[TxOutput; 2],
    fee: u64,
) -> BucketInstance {
    let (_, _, cm1) = derive_input(&inputs[0]);
    let (_, _, cm2) = derive_input(&inputs[1]);
    let (witnesses, anchor) = fabricated_shared_tree(&cm1, &cm2);
    build_bucket_with_witnesses(log_height, inputs, outputs, fee, &witnesses, anchor)
}

/// Build the full 2x2 bucket from **caller-supplied Merkle witnesses** and a
/// caller-supplied `anchor` (issue #39). The builder no longer invents a tree:
/// each input's membership slots are laid straight from `witnesses[i]`, and the
/// public anchor is `anchor` verbatim. Both inputs bind to the SINGLE public
/// anchor (consensus §6: one finalized root per spend), so both witnesses must
/// resolve to `anchor` — the circuit folds `leaf → root` and binds it, so a
/// witness/anchor mismatch yields an unprovable instance (that IS the
/// non-finalized / wrong-root rejection). Callers fetch `witnesses` + `anchor`
/// from the live commitment tree; use [`MerkleWitness::fold_root`] to check
/// consistency before proving.
pub fn build_bucket_with_witnesses(
    log_height: usize,
    inputs: &[TxInput; 2],
    outputs: &[TxOutput; 2],
    fee: u64,
    witnesses: &[MerkleWitness; 2],
    anchor: [u64; 4],
) -> BucketInstance {
    use crate::reference;

    let (nk1, nf1, _cm1) = derive_input(&inputs[0]);
    let (nk2, nf2, _cm2) = derive_input(&inputs[1]);

    let cmo1 = {
        let o = &outputs[0];
        let mut st = [0u64; 25];
        st[0] = o.value;
        st[1..5].copy_from_slice(&o.rkm);
        st[5..9].copy_from_slice(&o.rho);
        st[9..13].copy_from_slice(&o.rseed);
        st[13] = 1;
        st[16] = 1 << 63;
        let d = reference::keccak_f(&st);
        let dd: [u64; 4] = d[..4].try_into().unwrap();
        dd
    };
    let cmo2 = {
        let o = &outputs[1];
        let mut st = [0u64; 25];
        st[0] = o.value;
        st[1..5].copy_from_slice(&o.rkm);
        st[5..9].copy_from_slice(&o.rho);
        st[9..13].copy_from_slice(&o.rseed);
        st[13] = 1;
        st[16] = 1 << 63;
        let d = reference::keccak_f(&st);
        let dd: [u64; 4] = d[..4].try_into().unwrap();
        dd
    };

    // Program + witness.
    let mut program = [ROLE_DUMMY; PROGRAM_SLOTS];
    let mut sw = vec![SlotWitness::default(); PROGRAM_SLOTS];
    let mut slot = 1usize;
    let mut input_chain = |inp: &TxInput,
                           nk: &[u64; 4],
                           witness: &MerkleWitness,
                           bnf_role: u32| {
        program[slot] = ROLE_ANK;
        sw[slot].w[..4].copy_from_slice(&inp.sk);
        slot += 1;
        program[slot] = ROLE_NF;
        sw[slot].w[..4].copy_from_slice(&inp.rho);
        slot += 1;
        program[slot] = bnf_role;
        slot += 1;
        program[slot] = ROLE_ARKM;
        sw[slot].w[..4].copy_from_slice(nk);
        sw[slot].w[5] = inp.d[0]; // diversifier -> rkm = H(nk ‖ D_R ‖ d)
        sw[slot].w[6] = inp.d[1];
        slot += 1;
        program[slot] = ROLE_ACM;
        sw[slot].w[4] = inp.value;
        sw[slot].w[5..9].copy_from_slice(&inp.rho);
        sw[slot].w[9..13].copy_from_slice(&inp.rseed);
        slot += 1;
        for (sib, bit) in witness.siblings.iter().zip(witness.path_bits.iter()) {
            program[slot] = ROLE_MERKLE;
            sw[slot].w[..4].copy_from_slice(sib);
            sw[slot].pbit = *bit;
            slot += 1;
        }
        program[slot] = ROLE_BANCHOR;
        slot += 1;
    };
    input_chain(&inputs[0], &nk1, &witnesses[0], ROLE_BNF1);
    input_chain(&inputs[1], &nk2, &witnesses[1], ROLE_BNF2);
    for (o, bcm) in outputs.iter().zip([ROLE_BCM1, ROLE_BCM2]) {
        program[slot] = ROLE_ACMOUT;
        sw[slot].w[4] = o.value;
        sw[slot].w[..4].copy_from_slice(&o.rkm);
        sw[slot].w[5..9].copy_from_slice(&o.rho);
        sw[slot].w[9..13].copy_from_slice(&o.rseed);
        slot += 1;
        program[slot] = bcm;
        slot += 1;
    }
    program[slot] = ROLE_BAL;
    slot += 1;
    program[slot] = ROLE_END;
    slot += 1;
    assert_eq!(slot, BUCKET_PERMS, "program layout drifted");

    let pvs = pv_vec(&anchor, &nf1, &nf2, &cmo1, &cmo2, fee);
    BucketInstance {
        air: NarrowKeccakAir {
            log_height,
            program,
            slot_witness: sw,
            fee,
            dv: false,
        },
        pvs,
        anchor,
        nf: [nf1, nf2],
        cm_out: [cmo1, cmo2],
    }
}

/// Fabricate a depth-32 path for ONE leaf (issue #219). The dummy-input tests
/// need a tree that holds the real note and does **not** hold the dummy one, so
/// [`fabricated_shared_tree`]'s two-leaves-at-0/1 shape does not fit. Sibling
/// `i` is deterministic pseudo-random, seeded distinctly from that function's,
/// and every path bit is `false` (the leaf is the leftmost of its level).
pub fn fabricated_single_tree(cm: &[u64; 4]) -> (MerkleWitness, [u64; 4]) {
    let mut x = 0x0219_c0de_5eed_1eafu64;
    let mut rnd = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mut siblings = [[0u64; 4]; MERKLE_DEPTH];
    for sib in siblings.iter_mut() {
        *sib = [rnd(), rnd(), rnd(), rnd()];
    }
    let w = MerkleWitness { siblings, path_bits: [false; MERKLE_DEPTH] };
    let root = w.fold_root(cm);
    (w, root)
}

/// A Merkle path for a note that is **in no tree** — the dummy slot's witness
/// (issue #219). Deliberately a distinct deterministic pattern from
/// [`fabricated_single_tree`]'s so a test can assert it does not fold to the
/// real anchor, and thereby that the dummy tests are not vacuous.
#[cfg(feature = "q69-latch")]
pub fn off_tree_witness() -> MerkleWitness {
    let mut x = 0xdead_d0d0_0000_0219u64;
    let mut rnd = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mut siblings = [[0u64; 4]; MERKLE_DEPTH];
    for sib in siblings.iter_mut() {
        *sib = [rnd(), rnd(), rnd(), rnd()];
    }
    MerkleWitness { siblings, path_bits: [true; MERKLE_DEPTH] }
}

/// Build a 2×2 bucket whose **second input slot is a dummy** — issue #219, the
/// `ROLE_BNF2` latch construction the coordinator's ruling selected.
///
/// The program is **byte-identical** to [`build_bucket_with_witnesses`]'s: same
/// 83 perms, same 96-slot role word pinned at row 0, same trace height, same
/// public-value layout. That is the whole point — the padding property
/// `transaction-model` §7/§10 decided requires that a one-input spend be
/// indistinguishable from a two-input one, so nothing about the *shape* may
/// differ. The only differences are in the witness:
///
/// - `dv = true`, which under the latch relaxes chain 1's anchor bind and leaves
///   its Merkle fold unconstrained. That is the entire content of "dummy".
/// - `dummy.value` must be 0. The AIR enforces it
///   (`assert_zero(inj3e · L·dv · w4)`); this asserts it too, so a caller gets a
///   panic at build time rather than an unprovable instance.
/// - `dummy`'s `sk`/`rho`/`rseed` are prover-invented, so `PV_NF2` is a **real
///   nullifier of an invented note** — Orchard's construction, which
///   `transaction-model:61` already adopts as-is. It is still *bound*:
///   `ROLE_BNF2` stays in the dummy chain, so a relay cannot rewrite it.
///
/// `anchor` and `witnesses[0]` come from the live tree exactly as on the real
/// path; `witnesses[1]` may be anything (see [`off_tree_witness`]).
#[cfg(feature = "q69-latch")]
pub fn build_bucket_dummy1(
    log_height: usize,
    real: &TxInput,
    real_witness: &MerkleWitness,
    dummy: &TxInput,
    dummy_witness: &MerkleWitness,
    outputs: &[TxOutput; 2],
    fee: u64,
    anchor: [u64; 4],
) -> BucketInstance {
    assert_eq!(
        dummy.value, 0,
        "a dummy input slot contributes 0 to the balance; the AIR enforces it \
         via assert_zero(inj3e · L·dv · w4) and a nonzero value here is a mint \
         attempt that cannot be proved"
    );
    let inputs = [real.clone(), dummy.clone()];
    let mut inst = build_bucket_with_witnesses(
        log_height,
        &inputs,
        outputs,
        fee,
        &[*real_witness, *dummy_witness],
        anchor,
    );
    inst.air.dv = true;
    inst
}

// ---------------------------------------------------------------------------
// Trace generation
// ---------------------------------------------------------------------------

/// Row-0 contents of the three shift registers, slot-indexed (index 0 unused).
///
/// These are exactly the cells the AIR leaves free (issue #143): no
/// `when_first_row` constraint touches `S`/`V`/`U`, so a prover may put
/// anything here that survives the slot-1 range checks. `S[1..=64]` **carries
/// the first permutation's round-0 input** — 1600 bits, one whole Keccak state.
///
/// Production proving always uses [`RegisterInit::ZERO`] via
/// [`NarrowKeccakAir::generate_trace`]. This type is a parameter, not a knob:
/// it exists so a test can perturb row 0 **and re-run the whole fill**, which is
/// the only honest instrument here — tampering row 0 in a finished trace breaks
/// the row0 -> row1 transition and reads UNSAT, which says nothing about whether
/// row 0 is determined.
#[derive(Clone, Copy)]
struct RegisterInit {
    s: [u32; S_SLOTS + 1],
    v: [u32; V_SLOTS + 1],
    u: [u32; U_SLOTS + 1],
}

impl RegisterInit {
    /// The zero warm-up the honest prover uses.
    const ZERO: Self = Self {
        s: [0; S_SLOTS + 1],
        v: [0; V_SLOTS + 1],
        u: [0; U_SLOTS + 1],
    };
}

impl NarrowKeccakAir {
    /// Generate the full-height trace by simulating the pipeline row by
    /// row from zero-initialized registers. Every cell satisfies the AIR
    /// by construction; the chain semantics are checked against the
    /// reference permutation in tests.
    pub fn generate_trace<F: Field>(
        &self,
        extra_capacity_bits: usize,
    ) -> RowMajorMatrix<F> {
        self.generate_trace_from(extra_capacity_bits, RegisterInit::ZERO)
    }

    /// [`Self::generate_trace`]'s body, with the row-0 register contents as a
    /// parameter. Private: the free cells are a fact about the AIR, not a knob
    /// for a prover, and `generate_trace` is the only production entry point.
    fn generate_trace_from<F: Field>(
        &self,
        extra_capacity_bits: usize,
        init: RegisterInit,
    ) -> RowMajorMatrix<F> {
        let height = 1usize << self.log_height;
        let size = height * NARROW_WIDTH;
        let mut values = Vec::with_capacity(size << extra_capacity_bits);

        // Registers, indexed by slot (index 0 unused).
        let mut s = init.s;
        let mut v = init.v;
        let mut u = init.u;
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
        // Step 3b state: one-shot epoch, bind bank, balance accumulators.
        let mut ep: u32 = 1;
        let mut bq = [0i64; 16];
        let mut bl = [0i64; 4];
        // Issue #219 / QUM-69: the latch starts LOW (the AIR pins row 0) and the
        // liveness bool is constant for the whole trace.
        #[cfg(feature = "q69-latch")]
        let mut latch: u32 = 0;
        #[cfg(feature = "q69-latch")]
        let dvv: u32 = self.dv as u32;
        #[cfg(not(feature = "q69-latch"))]
        assert!(
            !self.dv,
            "dv = true needs the `q69-latch` feature; without it there is no \
             latch and this would prove input slot 1 as a REAL spend"
        );

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
                    ROLE_ANK => match l {
                        0..=3 => wbit[l],
                        4 => z0,
                        5 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    ROLE_ARKM => match l {
                        0..=3 => wbit[l],
                        4 => z1,
                        // diversifier d = W5..7 at lanes 5..6, pad from lane 7.
                        5 => wbit[5],
                        6 => wbit[6],
                        7 => z0,
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
                ROLE_BANCHOR,
                ROLE_BNF1,
                ROLE_BNF2,
                ROLE_BCM1,
                ROLE_BCM2,
                ROLE_BAL,
                ROLE_END,
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
            // ep-gated selector products and all bank gates.
            let bindsum = selv[6] + selv[7] + selv[8] + selv[9] + selv[10];
            let se = [
                selv[1] * ep,
                selv[3] * ep,
                selv[4] * ep,
                selv[5] * ep,
                bindsum * ep,
                selv[11] * ep,
            ];
            for (i, v) in se.iter().enumerate() {
                row[SE_OFF + i] = F::from_u32(*v);
            }
            row[EP_COL] = F::from_u32(ep);
            let gwrap = gpermv * selv[12];
            row[GWRAP_COL] = F::from_u32(gwrap);
            row[EG_OFF] = F::from_u32(bndv * se[0]);
            row[EG_OFF + 1] = F::from_u32(bndv * se[1]);
            row[EG_OFF + 2] = F::from_u32(gpermv * se[1]);
            row[EG_OFF + 3] = F::from_u32(bndv * se[0]);
            row[EG_OFF + 4] = F::from_u32(bndv * se[2]);
            row[EG_OFF + 5] = F::from_u32(gpermv * se[2]);
            let bgcap = bndv * se[4];
            let bgrst = gpermv * se[4];
            row[BGCAP_COL] = F::from_u32(bgcap);
            row[BGRST_COL] = F::from_u32(bgrst);
            for i in 0..5 {
                row[BGC_OFF + i] = F::from_u32(gpermv * selv[6 + i]);
            }
            // Issue #219 / QUM-69: the latch's two events are exactly the
            // BANCHOR and BNF2 bind-close gates just written above.
            #[cfg(feature = "q69-latch")]
            let (bgc_banchor, bgc_bnf2) = (gpermv * selv[6], gpermv * selv[8]);
            #[cfg(feature = "q69-latch")]
            {
                row[LATCH_COL] = F::from_u32(latch);
                row[DV_COL] = F::from_u32(dvv);
                row[LDV_COL] = F::from_u32(latch * dvv);
            }
            let inj3e = bndv * se[2];
            let inj4e = bndv * se[3];
            row[INJ3E_COL] = F::from_u32(inj3e);
            row[INJ4E_COL] = F::from_u32(inj4e);
            row[BLCLOSE_COL] = F::from_u32(gpermv * se[5]);
            let sgn = |v: i64| -> F {
                if v >= 0 {
                    F::from_u32(v as u32)
                } else {
                    -F::from_u32((-v) as u32)
                }
            };
            for (i, acc) in bq.iter().enumerate() {
                row[BQ_OFF + i] = sgn(*acc);
            }
            for (j, acc) in bl.iter().enumerate() {
                row[BL_OFF + j] = sgn(*acc);
            }
            // Balance carry encodings: exact limb-chain carries (meaningful
            // only where the close gate fires; harmless bools elsewhere).
            {
                let fee_j = |j: usize| ((self.fee >> (16 * j)) & 0xffff) as i64;
                let mut c = [0i64; 3];
                let mut prev = 0i64;
                for j in 0..3 {
                    let tj = bl[j] + prev - fee_j(j);
                    c[j] = tj >> 16;
                    prev = c[j];
                }
                for (j, cj) in c.iter().enumerate() {
                    let enc = (cj + 2).clamp(0, 7) as u32;
                    for b in 0..3 {
                        row[BLC_OFF + 3 * j + b] = F::from_u32((enc >> b) & 1);
                    }
                }
            }
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
            // Advance the accumulators (constraint: next = local + legs).
            {
                let jc = z / 16;
                let wgt = 1i64 << (z % 16);
                let epi = ep as i64;
                for l in 0..4 {
                    let idx = 4 * l + jc;
                    eq[idx] += epi
                        * (g_e1pos * wgt * a[l] as i64 - g_e1neg * wgt * wbit[l] as i64);
                    eq[16 + idx] += epi
                        * (g_e2pos * wgt * wbit[l] as i64
                            - g_e2neg * wgt * wbit[5 + l] as i64);
                    bq[idx] += (bgcap as i64) * wgt * a[l] as i64;
                }
                bl[jc] += (inj3e as i64) * wgt * wbit[4] as i64
                    - (inj4e as i64) * wgt * wbit[4] as i64;
                if bgrst == 1 {
                    bq = [0i64; 16];
                }
                ep *= 1 - gwrap;
                // Mirrors the latch transition constraint exactly.
                #[cfg(feature = "q69-latch")]
                {
                    latch = latch * (1 - bgc_banchor) + bgc_bnf2;
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
        check_constraints(&air, &trace, &zero_pvs());
    }

    #[test]
    fn corrupted_trace_detected() {
        let air = NarrowKeccakAir::chain_only(10);
        let mut trace = air.generate_trace::<F>(0);
        // Flip one A' (theta output) bit on a T row.
        let row = 64 + 7;
        trace.values[row * NARROW_WIDTH + AP_OFF + 3] += F::ONE;
        let report = check_all_constraints(&air, &trace, &zero_pvs(), Some(10));
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
            fee: 0,
            dv: false,
        };
        let trace = air.generate_trace::<F>(0);
        check_constraints(&air, &trace, &zero_pvs());

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
            fee: 0,
            dv: false,
        };
        let mut trace = air.generate_trace::<F>(0);
        // Flip a sibling bit on an injection row (perm 1 boundary block =
        // block 24, row 24*128 + 5).
        let row = 24 * 128 + 5;
        trace.values[row * NARROW_WIDTH + SIB_OFF + 2] += F::ONE;
        let report = check_all_constraints(&air, &trace, &zero_pvs(), Some(10));
        assert!(!report.is_ok(), "sibling corruption not caught");

        // Path bit drift mid-perm must be caught by the constancy rule.
        let mut trace2 = air.generate_trace::<F>(0);
        let row2 = 24 * 128 + 700; // inside perm 1, not a boundary
        trace2.values[row2 * NARROW_WIDTH + PBIT_COL] += F::ONE;
        let report2 = check_all_constraints(&air, &trace2, &zero_pvs(), Some(10));
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
    /// Zero public values: valid whenever no bind/balance close fires
    /// during the epoch (programs without bind/bal roles).
    fn zero_pvs() -> Vec<F> {
        vec![F::ZERO; PV_LEN]
    }

    /// Issue #143, and the reason this file's row-0 note says what it says.
    ///
    /// The first permutation's input state is a **free witness** — no
    /// `when_first_row` constraint touches `S`/`V`/`U` — and it is safe only
    /// because nothing consumes it. This test locks **that property**; the
    /// layout that currently delivers it is locked separately by
    /// `bucket_program_does_not_consume_warmup`. This one fails if the severing
    /// ever breaks: if some future role at `program[1]` reads the chained state
    /// instead of overriding it, (b) goes red.
    ///
    /// It is deliberately **perturb-and-repropagate**, not tamper: row 0 is
    /// changed and the whole fill re-runs, so the trace stays self-consistent.
    /// Tampering a finished trace instead would break the row0 -> row1
    /// transition and read UNSAT, which is the false negative that hid this
    /// question in the first place — a prover who picks row 0 and lets every
    /// later row follow has a *valid* trace, not a broken one.
    ///
    /// Only `S[1..=64]` is perturbed, and that is on purpose twice over: those
    /// 64 slots x 25 bits = 1600 bits are exactly the first permutation's
    /// round-0 input, and leaving the other 191 free cells zero keeps the fill
    /// a valid witness (it applies register entries with `|=`, which equals the
    /// constraint's `+` only where the entering bits are disjoint from what the
    /// slot already holds; with `S[65..]`/`V`/`U` zero, every entry ORs into a
    /// zeroed slot). Those 191 cells are free too, but they are not the input
    /// state and they only perturb cells nothing reads.
    #[test]
    fn first_perm_input_is_free_and_unconsumed() {
        let sk = [0xfeed_1111u64, 0xfeed_2222, 0xfeed_3333, 0xfeed_4444];
        let rho = [0xa11c_e001u64, 0xa11c_e002, 0xa11c_e003, 0xa11c_e004];

        // [DUMMY, ANK, NF, DUMMY..]: the consensus prefix. ANK is the first
        // real role (full-state override), NF the first role that READS the
        // chained digest. No bind/bal role, so zero public values are valid.
        let mut program = [ROLE_DUMMY; PROGRAM_SLOTS];
        program[1] = ROLE_ANK;
        program[2] = ROLE_NF;
        let mut slot_witness = vec![SlotWitness::default(); PROGRAM_SLOTS];
        slot_witness[1].w[..4].copy_from_slice(&sk);
        slot_witness[2].w[..4].copy_from_slice(&rho);
        let air = NarrowKeccakAir {
            log_height: 14, // 128 blocks: perm 2's output at block 72 is in range
            program,
            slot_witness,
            fee: 0,
            dv: false,
        };

        // A prover-chosen first-perm input: 64 slots of 25 bits each.
        let mut x = 0x1234_5678_9abc_def0u64;
        let mut rnd = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut chosen = RegisterInit::ZERO;
        for d in 1..=64 {
            chosen.s[d] = (rnd() as u32) & 0x01ff_ffff; // 25 bits
        }

        let honest = air.generate_trace_from::<F>(0, RegisterInit::ZERO);
        let chosen_trace = air.generate_trace_from::<F>(0, chosen);

        // The perturbation really did move the first permutation's input —
        // without this the rest of the test could pass vacuously.
        assert_ne!(
            NarrowKeccakAir::extract_state(&honest, 0),
            NarrowKeccakAir::extract_state(&chosen_trace, 0),
            "the chosen init must change the first perm's round-0 input"
        );

        // (a) The degree of freedom is real: a trace built from a
        // prover-chosen row 0 satisfies EVERY constraint, first-row pins
        // included. Nothing binds the first permutation's input state.
        check_constraints(&air, &chosen_trace, &zero_pvs());

        // (b) And it is severed. The load-bearing half first, as a cross-run
        // equality that does not depend on knowing the right answer: the ANK
        // perm's output (block 24*2, the state perm 2 materializes) is
        // bit-identical no matter what the prover chose for row 0, because
        // `msg_ank` overrides all 25 lanes from witness + periodic constants
        // with no `a` term. Put a role that READS the chained state at
        // `program[1]` and this is the assertion that goes red.
        assert_eq!(
            NarrowKeccakAir::extract_state(&honest, 24 * 2),
            NarrowKeccakAir::extract_state(&chosen_trace, 24 * 2),
            "the first perm's output must not depend on the chosen row 0"
        );
        assert_eq!(
            NarrowKeccakAir::extract_state(&honest, 24 * 3),
            NarrowKeccakAir::extract_state(&chosen_trace, 24 * 3),
            "nor may anything downstream of it"
        );

        // …and the severed value is the RIGHT one — the reference nk, so this
        // cannot be satisfied by a pipeline that severs by producing garbage.
        let nk_state = reference::keccak_f(&st_ank(&sk, 0));
        for (label, trace) in [("honest", &honest), ("chosen", &chosen_trace)] {
            assert_eq!(
                NarrowKeccakAir::extract_state(trace, 24 * 2),
                nk_state,
                "{label}: ANK output must be keccak_f(st_ank(sk))"
            );
        }

        // …and so is everything downstream of it: the NF perm consumes that
        // digest through `msg_mrk`'s lane 0..3, and its output is the nullifier
        // the real bucket binds to PV_NF1.
        let nf_state = reference::keccak_f(&st_pair(&digest(&nk_state), &rho));
        for (label, trace) in [("honest", &honest), ("chosen", &chosen_trace)] {
            assert_eq!(
                NarrowKeccakAir::extract_state(trace, 24 * 3),
                nf_state,
                "{label}: nf must not depend on the warmup state"
            );
        }
    }

    /// Issue #143's tripwire. The severing above holds because of two lines in
    /// `build_bucket_with_witnesses` that read as layout housekeeping —
    /// `let mut slot = 1usize;` leaving `program[0]` dummy, and `input_chain`
    /// writing `ROLE_ANK` first — and **the AIR does not enforce either**:
    /// `merkle_chain_matches_reference` builds a program whose first real role
    /// is `ROLE_MERKLE`, which reads the chained state through `msg_mrk`'s lane
    /// 0..3, i.e. it consumes the warmup. That is fine in a semantics test and
    /// would not be fine here.
    ///
    /// So this asserts the layout directly. If you are here because this test
    /// went red after reordering `input_chain`: the constraint you may not
    /// break is that **neither of the first two perms may read the chained
    /// state**, because for perm 0 and perm 1 that state is prover-chosen
    /// warmup. Re-point the assertion only once that still holds.
    #[test]
    fn bucket_program_does_not_consume_warmup() {
        let inputs = [
            TxInput { sk: [1, 2, 3, 4], value: 7, rho: [5, 6, 7, 8], rseed: [9, 10, 11, 12], d: [0, 0] },
            TxInput { sk: [13, 14, 15, 16], value: 3, rho: [17, 18, 19, 20], rseed: [21, 22, 23, 24], d: [0, 0] },
        ];
        let outputs = [
            TxOutput { value: 6, rkm: [1; 4], rho: [2; 4], rseed: [3; 4] },
            TxOutput { value: 3, rkm: [4; 4], rho: [5; 4], rseed: [6; 4] },
        ];
        let program = build_bucket(18, &inputs, &outputs, 1).air.program;

        assert_eq!(program[0], ROLE_DUMMY, "perm 0 must stay the warm-up slot");
        assert_eq!(
            program[1], ROLE_ANK,
            "perm 1 must be the full-state override that seeds the chain"
        );
        assert_eq!(
            program[2], ROLE_NF,
            "perm 2 is the first role that may read a chained digest"
        );

        // The generalized property the two assertions above stand in for: a
        // role reads the previous perm's output either through its `msg`
        // (MERKLE/NF lane 0..3, ACM lane 1..4) or through the bind bank's
        // capture of `a[0..4]`. None of those may sit at perm 0 or perm 1.
        const READS_CHAINED_STATE: [u32; 8] = [
            ROLE_MERKLE,
            ROLE_NF,
            ROLE_ACM,
            ROLE_BANCHOR,
            ROLE_BNF1,
            ROLE_BNF2,
            ROLE_BCM1,
            ROLE_BCM2,
        ];
        for p in 0..2 {
            assert!(
                !READS_CHAINED_STATE.contains(&program[p]),
                "program[{p}] = {} consumes the prover-chosen warmup state",
                program[p]
            );
        }
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
        let d: [u64; 2] = [rnd(), rnd()]; // nonzero diversifier (issue #32)

        // Reference walk.
        let nk_state = reference::keccak_f(&st_ank(&sk, 0));
        let nk = digest(&nk_state);
        let nf_state = reference::keccak_f(&st_pair(&nk, &rho));
        let rkm_state = reference::keccak_f(&st_ank_r(&nk, &d));
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
        sw[3].w[5] = d[0]; // arkm: diversifier witness (issue #32)
        sw[3].w[6] = d[1];
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
            fee: 0,
            dv: false,
        };
        let trace = air.generate_trace::<F>(0);
        check_constraints(&air, &trace, &zero_pvs());

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

    fn st_ank_r(nk: &[u64; 4], d: &[u64; 2]) -> [u64; 25] {
        let mut st = [0u64; 25];
        st[..4].copy_from_slice(nk);
        st[4] = 1 << 1; // domain R at z1
        st[5] = d[0]; // diversifier word 0 (issue #32)
        st[6] = d[1]; // diversifier word 1
        st[7] = 1; // pad10*1 moved to bit 448
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
                fee: 0,
                dv: false,
            }
        };
        // Sanity: untampered witness satisfies constraints at this height.
        let ok_air = NarrowKeccakAir {
            log_height: 14,
            ..build(false, false)
        };
        let trace = ok_air.generate_trace::<F>(0);
        check_constraints(&ok_air, &trace, &zero_pvs());
        // Tampered rho: bank 2 close must fire.
        let bad_rho = NarrowKeccakAir {
            log_height: 14,
            ..build(true, false)
        };
        let tr = bad_rho.generate_trace::<F>(0);
        let report = check_all_constraints(&bad_rho, &tr, &zero_pvs(), Some(10));
        assert!(!report.is_ok(), "rho inconsistency not caught");
        // Tampered nk: bank 1 close must fire.
        let bad_nk = NarrowKeccakAir {
            log_height: 14,
            ..build(false, true)
        };
        let tr = bad_nk.generate_trace::<F>(0);
        let report = check_all_constraints(&bad_nk, &tr, &zero_pvs(), Some(10));
        assert!(!report.is_ok(), "nk inconsistency not caught");
    }

    /// M3 step 3b: the COMPLETE 2x2 bucket — two inputs (key derivation,
    /// nullifier, commitment opening, depth-32 membership in one shared
    /// tree), two outputs, balance, and every public binding — satisfies
    /// the AIR with the real public values, and fits 2^18 rows.
    #[test]
    fn full_bucket_satisfies_constraints() {
        let (inst, _) = test_bucket(7, 5, 3, 9); // 7+5 = 3+9+0? no: fee below
        let pvs: Vec<F> = inst.pvs.iter().map(|v| F::from_u32(*v)).collect();
        let trace = inst.air.generate_trace::<F>(0);
        check_constraints(&inst.air, &trace, &pvs);
    }

    /// Issue #32: `rkm = H(nk ‖ D_R ‖ d)` genuinely absorbs the diversifier.
    /// Two buckets identical except for input 0's diversifier must (a) both
    /// satisfy constraints, (b) produce DIFFERENT anchors — the commitment tree
    /// depends on `cm → rkm(d)`, so notes at different diversifiers are
    /// unlinkable — while (c) the nullifiers stay identical, since `nf =
    /// H(nk ‖ ρ)` never sees `d`. And the STOP-POINT invariants hold: the perm
    /// count and height are unchanged (`d` fills spare rate lanes of the same
    /// ARKM perm).
    #[test]
    fn rkm_diversifier_dependent() {
        let mk = |d0: [u64; 2]| {
            let inputs = [
                TxInput {
                    sk: [0xa, 0xb, 0xc, 0xd],
                    value: 100,
                    rho: [1, 2, 3, 4],
                    rseed: [5, 6, 7, 8],
                    d: d0,
                },
                TxInput {
                    sk: [1, 1, 1, 1],
                    value: 50,
                    rho: [9, 10, 11, 12],
                    rseed: [13, 14, 15, 16],
                    d: [0, 0],
                },
            ];
            let outputs = [
                TxOutput { value: 90, rkm: [2; 4], rho: [3; 4], rseed: [4; 4] },
                TxOutput { value: 55, rkm: [5; 4], rho: [6; 4], rseed: [7; 4] },
            ];
            build_bucket(18, &inputs, &outputs, 5) // 100+50 = 90+55+5
        };
        let a = mk([0, 0]);
        let b = mk([0xdead_beef, 0xf00d]);

        // (a) both prove.
        for inst in [&a, &b] {
            let pvs: Vec<F> = inst.pvs.iter().map(|v| F::from_u32(*v)).collect();
            let trace = inst.air.generate_trace::<F>(0);
            check_constraints(&inst.air, &trace, &pvs);
        }
        // (b) distinct diversifier => distinct anchor (unlinkability).
        assert_ne!(a.anchor, b.anchor, "diversifier must change the anchor via rkm->cm");
        // (c) but the nullifier is diversifier-independent (nf = H(nk ‖ ρ)).
        assert_eq!(a.nf, b.nf, "nullifiers must not depend on the diversifier");
        // STOP-POINT: perm count + height unchanged by absorbing d.
        assert_eq!(a.air.program.len(), b.air.program.len());
        assert_eq!(BUCKET_PERMS, 83, "perm count unchanged by the d-absorb");
    }

    fn test_bucket(v1: u64, v2: u64, o1: u64, o2: u64) -> (BucketInstance, u64) {
        let fee = (v1 + v2) - (o1 + o2);
        let mut x = 0x1234_5678_9abc_def0u64;
        let mut rnd = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mk_in = |value: u64, rnd: &mut dyn FnMut() -> u64| TxInput {
            sk: [rnd(), rnd(), rnd(), rnd()],
            value,
            rho: [rnd(), rnd(), rnd(), rnd()],
            rseed: [rnd(), rnd(), rnd(), rnd()],
            d: [rnd(), rnd()],
        };
        let mk_out = |value: u64, rnd: &mut dyn FnMut() -> u64| TxOutput {
            value,
            rkm: [rnd(), rnd(), rnd(), rnd()],
            rho: [rnd(), rnd(), rnd(), rnd()],
            rseed: [rnd(), rnd(), rnd(), rnd()],
        };
        let inputs = [mk_in(v1, &mut rnd), mk_in(v2, &mut rnd)];
        let outputs = [mk_out(o1, &mut rnd), mk_out(o2, &mut rnd)];
        (build_bucket(18, &inputs, &outputs, fee), fee)
    }

    /// Wrong public values and unbalanced values must be caught.
    #[test]
    fn bucket_negatives_detected() {
        let (inst, fee) = test_bucket(10, 6, 4, 8);
        assert_eq!(fee, 4);
        let trace = inst.air.generate_trace::<F>(0);
        // Wrong nf1 public value.
        let mut pvs: Vec<F> = inst.pvs.iter().map(|v| F::from_u32(*v)).collect();
        pvs[PV_NF1 + 3] += F::ONE;
        let report = check_all_constraints(&inst.air, &trace, &pvs, Some(10));
        assert!(!report.is_ok(), "wrong nf1 pv not caught");
        // Wrong fee (balance close must fail).
        let mut pvs2: Vec<F> = inst.pvs.iter().map(|v| F::from_u32(*v)).collect();
        pvs2[PV_FEE] += F::ONE;
        let report = check_all_constraints(&inst.air, &trace, &pvs2, Some(10));
        assert!(!report.is_ok(), "wrong fee not caught");
        // Wrong anchor.
        let mut pvs3: Vec<F> = inst.pvs.iter().map(|v| F::from_u32(*v)).collect();
        pvs3[PV_ANCHOR] += F::ONE;
        let report = check_all_constraints(&inst.air, &trace, &pvs3, Some(10));
        assert!(!report.is_ok(), "wrong anchor not caught");
    }

    /// Issue #39: `build_bucket` is now a thin fabricating wrapper over
    /// `build_bucket_with_witnesses`. The fabricated witnesses fold to the shared
    /// anchor, and rebuilding from those explicit witnesses reproduces the
    /// wrapper's program/witness/pvs/anchor exactly — and the witness-path
    /// instance still proves.
    #[test]
    fn fabricated_wrapper_matches_explicit_witnesses() {
        let (inst_wrapper, fee) = test_bucket(10, 6, 4, 8);
        // Reconstruct the same inputs test_bucket used (deterministic rnd).
        let mut x = 0x1234_5678_9abc_def0u64;
        let mut rnd = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mk_in = |value: u64, rnd: &mut dyn FnMut() -> u64| TxInput {
            sk: [rnd(), rnd(), rnd(), rnd()],
            value,
            rho: [rnd(), rnd(), rnd(), rnd()],
            rseed: [rnd(), rnd(), rnd(), rnd()],
            d: [rnd(), rnd()],
        };
        let mk_out = |value: u64, rnd: &mut dyn FnMut() -> u64| TxOutput {
            value,
            rkm: [rnd(), rnd(), rnd(), rnd()],
            rho: [rnd(), rnd(), rnd(), rnd()],
            rseed: [rnd(), rnd(), rnd(), rnd()],
        };
        let inputs = [mk_in(10, &mut rnd), mk_in(6, &mut rnd)];
        let outputs = [mk_out(4, &mut rnd), mk_out(8, &mut rnd)];

        let (_, _, cm1) = derive_input(&inputs[0]);
        let (_, _, cm2) = derive_input(&inputs[1]);
        let (witnesses, anchor) = fabricated_shared_tree(&cm1, &cm2);
        // The fabricated witnesses genuinely resolve to the shared anchor.
        assert_eq!(witnesses[0].fold_root(&cm1), anchor, "leaf 0 folds to anchor");
        assert_eq!(witnesses[1].fold_root(&cm2), anchor, "leaf 1 folds to anchor");
        assert_eq!(anchor, inst_wrapper.anchor, "wrapper anchor == fabricated root");

        let inst_witness =
            build_bucket_with_witnesses(18, &inputs, &outputs, fee, &witnesses, anchor);
        assert_eq!(inst_witness.anchor, inst_wrapper.anchor);
        assert_eq!(inst_witness.pvs, inst_wrapper.pvs);
        assert_eq!(inst_witness.nf, inst_wrapper.nf);
        assert_eq!(inst_witness.cm_out, inst_wrapper.cm_out);
        assert_eq!(inst_witness.air.program, inst_wrapper.air.program);

        // The explicit-witness instance still satisfies every constraint.
        let pvs: Vec<F> = inst_witness.pvs.iter().map(|v| F::from_u32(*v)).collect();
        let trace = inst_witness.air.generate_trace::<F>(0);
        check_constraints(&inst_witness.air, &trace, &pvs);
    }

    /// Issue #39: a caller-supplied witness that does NOT resolve to the supplied
    /// anchor yields an UNPROVABLE instance. Both inputs bind to the single public
    /// anchor; the circuit folds `leaf → root` and binds the fold, so a witness /
    /// anchor mismatch (the shape of a non-finalized or wrong-root anchor) fails
    /// at constraint level. This is what rejects a forged anchor.
    #[test]
    fn witness_anchor_mismatch_rejected() {
        let (inst, fee) = test_bucket(10, 6, 4, 8);
        let mut x = 0x1234_5678_9abc_def0u64;
        let mut rnd = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mk_in = |value: u64, rnd: &mut dyn FnMut() -> u64| TxInput {
            sk: [rnd(), rnd(), rnd(), rnd()],
            value,
            rho: [rnd(), rnd(), rnd(), rnd()],
            rseed: [rnd(), rnd(), rnd(), rnd()],
            d: [rnd(), rnd()],
        };
        let mk_out = |value: u64, rnd: &mut dyn FnMut() -> u64| TxOutput {
            value,
            rkm: [rnd(), rnd(), rnd(), rnd()],
            rho: [rnd(), rnd(), rnd(), rnd()],
            rseed: [rnd(), rnd(), rnd(), rnd()],
        };
        let inputs = [mk_in(10, &mut rnd), mk_in(6, &mut rnd)];
        let outputs = [mk_out(4, &mut rnd), mk_out(8, &mut rnd)];
        let _ = inst;

        let (_, _, cm1) = derive_input(&inputs[0]);
        let (_, _, cm2) = derive_input(&inputs[1]);
        let (witnesses, anchor) = fabricated_shared_tree(&cm1, &cm2);
        // A forged anchor that the witnesses do NOT fold to.
        let mut wrong = anchor;
        wrong[0] ^= 1;
        assert_ne!(witnesses[0].fold_root(&cm1), wrong, "precondition: witness ≠ wrong anchor");
        let bad = build_bucket_with_witnesses(18, &inputs, &outputs, fee, &witnesses, wrong);
        let pvs: Vec<F> = bad.pvs.iter().map(|v| F::from_u32(*v)).collect();
        let trace = bad.air.generate_trace::<F>(0);
        let report = check_all_constraints(&bad.air, &trace, &pvs, Some(10));
        assert!(!report.is_ok(), "witness that does not fold to the anchor must be rejected");
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
