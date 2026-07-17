//! M4 step 0b(ii) increment 1: the composite verifier rectangle, SKELETON.
//!
//! One AIR, one rectangle, three lanes living together — exactly the
//! layout `docs/m4-verifier-circuit-layout.md` fixed:
//!
//!   [ 0 .. 2,633 )               wide Keccak lane (p3-keccak-air, its own
//!                                 constraints evaluated through a column-
//!                                 offset LaneBuilder)
//!   [ 2,633 .. 2,645 )           ext-mul bank (anchor's 12-col row)
//!   [ 2,645 .. 2,657 )           ext-add bank (12-col row, 4 deg-1
//!                                 constraints)
//!
//! at 2^16 rows, with the step-0 workload sizes: 2,233 keccak-f (the 0a
//! census), 28,800 ext-muls and 28,663 ext-adds (the 0b(i) census).
//!
//! What the skeleton proves: the lanes COEXIST at the projected cost —
//! the marginal price of the banks next to the keccak lane is real,
//! measured, and the LaneBuilder composition (a foreign AIR evaluated at
//! a column offset) works inside p3's prover unmodified.
//!
//! What it deliberately does NOT yet do (increment 2+): route data
//! between lanes (the keccak lane hashes its own schedule, the banks
//! multiply their own witnesses — no shared values yet), extract
//! Fiat–Shamir challenges, or bind public values. The skeleton's numbers
//! are the floor the full build must not drift far from.

use std::borrow::Borrow;
use std::time::Instant;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_keccak_air::{KeccakAir, NUM_KECCAK_COLS};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_uni_stark::{prove, verify};
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

use crate::{keccak_inputs, make_config_with, pc_len, FriCfg, Val, RUNS};

// ---------------------------------------------------------------------------
// Lane composition: evaluate a foreign AIR at a column offset
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct LaneWindow<W> {
    inner: W,
    off: usize,
    width: usize,
}

impl<T, W: WindowAccess<T>> WindowAccess<T> for LaneWindow<W> {
    fn current_slice(&self) -> &[T] {
        &self.inner.current_slice()[self.off..self.off + self.width]
    }
    fn next_slice(&self) -> &[T] {
        &self.inner.next_slice()[self.off..self.off + self.width]
    }
}

struct LaneBuilder<'a, AB: AirBuilder> {
    inner: &'a mut AB,
    off: usize,
    width: usize,
}

impl<'a, AB: AirBuilder> AirBuilder for LaneBuilder<'a, AB> {
    type F = AB::F;
    type Expr = AB::Expr;
    type Var = AB::Var;
    type PublicVar = AB::PublicVar;
    type PeriodicVar = AB::PeriodicVar;
    type PreprocessedWindow = AB::PreprocessedWindow;
    type MainWindow = LaneWindow<AB::MainWindow>;

    fn main(&self) -> Self::MainWindow {
        LaneWindow {
            inner: self.inner.main(),
            off: self.off,
            width: self.width,
        }
    }
    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        self.inner.preprocessed()
    }
    fn is_first_row(&self) -> Self::Expr {
        self.inner.is_first_row()
    }
    fn is_last_row(&self) -> Self::Expr {
        self.inner.is_last_row()
    }
    fn is_transition(&self) -> Self::Expr {
        self.inner.is_transition()
    }
    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.inner.assert_zero(x);
    }
}

// ---------------------------------------------------------------------------
// The skeleton AIR
// ---------------------------------------------------------------------------

const MUL_OFF: usize = NUM_KECCAK_COLS;
const ADD_OFF: usize = NUM_KECCAK_COLS + 12;
const SKEL_WIDTH: usize = NUM_KECCAK_COLS + 24;
const W: u32 = 3; // KoalaBear x^4 - 3

struct VerifierSkeletonAir;

impl<F: Field> BaseAir<F> for VerifierSkeletonAir {
    fn width(&self) -> usize {
        SKEL_WIDTH
    }
}

impl<AB: AirBuilder> Air<AB> for VerifierSkeletonAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        // Keccak lane: the stock AIR, evaluated at column offset 0 through
        // the lane adapter (its Borrow-cast sees exactly NUM_KECCAK_COLS).
        {
            let mut lane = LaneBuilder {
                inner: builder,
                off: 0,
                width: NUM_KECCAK_COLS,
            };
            KeccakAir {}.eval(&mut lane);
        }

        // Banks: same rows, dedicated columns. Convert ONLY the 24 bank
        // columns to Exprs — a full-width collect here runs per LDE point
        // in the prover's folder and costs real prove time.
        let main = builder.main();
        let cur = main.current_slice();
        let bank: Vec<AB::Expr> = cur[MUL_OFF..MUL_OFF + 24]
            .iter()
            .map(|v| (*v).into())
            .collect();
        let w = AB::Expr::from(AB::F::from_u32(W));

        // ext-mul bank: c = a * b over F[x]/(x^4 - W); zero rows satisfy.
        let (a, b, c) = (&bank[0..4], &bank[4..8], &bank[8..12]);
        for k in 0..4 {
            let mut acc = AB::Expr::ZERO;
            for i in 0..4 {
                for j in 0..4 {
                    if i + j == k {
                        acc = acc.clone() + a[i].clone() * b[j].clone();
                    } else if i + j == k + 4 {
                        acc = acc.clone() + w.clone() * a[i].clone() * b[j].clone();
                    }
                }
            }
            builder.assert_eq(acc, c[k].clone());
        }

        // ext-add bank: c = a + b, limb-wise; zero rows satisfy.
        let (a, b, c) = (&bank[12..16], &bank[16..20], &bank[20..24]);
        for k in 0..4 {
            builder.assert_eq(a[k].clone() + b[k].clone(), c[k].clone());
        }
    }
}

// ---------------------------------------------------------------------------
// Trace composition
// ---------------------------------------------------------------------------

type Ext = BinomialExtensionField<Val, 4>;

const KECCAK_PERMS: usize = 2_233; // step 0a census
const MUL_ROWS: usize = 28_800; // step 0b(i) census
const ADD_ROWS: usize = 28_663; // step 0b(i) census

fn gen_trace(extra_capacity_bits: usize) -> RowMajorMatrix<Val> {
    // Keccak lane trace from the stock generator (pads itself to 2^16).
    let keccak = p3_keccak_air::generate_trace_rows::<Val>(keccak_inputs(KECCAK_PERMS), 0);
    let rows = keccak.height();
    assert_eq!(rows, 65_536, "expected the 0a rectangle height");

    let mut rng = SmallRng::seed_from_u64(0x5ce1_e701 ^ 0xa9c4_0b11);
    let mut rnd_ext = |rng: &mut SmallRng| -> Ext {
        Ext::from_basis_coefficients_fn(|_| Val::from_u32(rng.next_u32() % 0x7f00_0001))
    };

    // Allocate the full LDE capacity up front (the p3 generators do the
    // same) — a late reserve() reallocs a ~GB buffer and the copy shows
    // up as peak RSS across bench runs.
    let mut values = Vec::with_capacity((rows << extra_capacity_bits) * SKEL_WIDTH);
    values.resize(rows * SKEL_WIDTH, Val::ZERO);
    for r in 0..rows {
        let dst = &mut values[r * SKEL_WIDTH..r * SKEL_WIDTH + NUM_KECCAK_COLS];
        dst.copy_from_slice(&keccak.values[r * NUM_KECCAK_COLS..(r + 1) * NUM_KECCAK_COLS]);
    }
    drop(keccak);
    for r in 0..MUL_ROWS {
        let a = rnd_ext(&mut rng);
        let b = rnd_ext(&mut rng);
        let c = a * b;
        let dst = &mut values[r * SKEL_WIDTH + MUL_OFF..r * SKEL_WIDTH + MUL_OFF + 12];
        dst[0..4].copy_from_slice(a.as_basis_coefficients_slice());
        dst[4..8].copy_from_slice(b.as_basis_coefficients_slice());
        dst[8..12].copy_from_slice(c.as_basis_coefficients_slice());
    }
    for r in 0..ADD_ROWS {
        let a = rnd_ext(&mut rng);
        let b = rnd_ext(&mut rng);
        let c = a + b;
        let dst = &mut values[r * SKEL_WIDTH + ADD_OFF..r * SKEL_WIDTH + ADD_OFF + 12];
        dst[0..4].copy_from_slice(a.as_basis_coefficients_slice());
        dst[4..8].copy_from_slice(b.as_basis_coefficients_slice());
        dst[8..12].copy_from_slice(c.as_basis_coefficients_slice());
    }
    RowMajorMatrix::new(values, SKEL_WIDTH)
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

const LANE_CFGS: [(&str, FriCfg); 2] = [
    (
        "b4/q40/g20/fp16/a16",
        FriCfg {
            log_blowup: 2,
            num_queries: 40,
            grind_bits: 20,
            log_final_poly_len: 4,
            max_log_arity: 4,
        },
    ),
    (
        "b16/q20/g20/fp16/a16",
        FriCfg {
            log_blowup: 4,
            num_queries: 20,
            grind_bits: 20,
            log_final_poly_len: 4,
            max_log_arity: 4,
        },
    ),
];

pub(crate) fn run_m4skel(power: &str, only: Option<&str>) {
    println!("# qumbra-lab M4 step 0b(ii) increment 1: composite rectangle skeleton");
    println!();
    crate::print_env(power);
    println!(
        "- rectangle: {SKEL_WIDTH} cols x 2^16 = keccak lane ({NUM_KECCAK_COLS}, \
         {KECCAK_PERMS} perms) + ext-mul bank (12, {MUL_ROWS} rows) + ext-add \
         bank (12, {ADD_ROWS} rows); foreign-AIR lane composition via a \
         column-offset LaneBuilder; NO cross-lane routing yet (increment 2)"
    );
    println!(
        "- projection to beat (layout note): b4 ~463 ms / ~2.91 GB (the \
         measured 0a baseline + 1.5% columns; this rectangle is 24 cols, \
         projection ~462 ms — routing cols come later)"
    );
    println!();
    println!("| lane config | rows | prove ms | verify ms | postcard KB | fixed KB |");
    println!("|---|---|---|---|---|---|");
    let air = VerifierSkeletonAir;
    for (name, cfg) in &LANE_CFGS {
        if let Some(f) = only {
            if !name.contains(f) {
                continue;
            }
        }
        let config = make_config_with(cfg);
        eprintln!("== skeleton: {name} ==");
        let mut rows = 0;
        let mut best_prove = f64::INFINITY;
        let mut proof_opt = None;
        for _ in 0..RUNS {
            let trace = gen_trace(cfg.log_blowup);
            rows = trace.height();
            let t = Instant::now();
            let proof = prove(&config, &air, trace, &[]);
            best_prove = best_prove.min(t.elapsed().as_secs_f64() * 1e3);
            proof_opt = Some(proof);
        }
        let proof = proof_opt.expect("RUNS > 0");
        let postcard_bytes = pc_len(&proof);
        let fixed_bytes = bincode::serialize(&proof).expect("bincode").len();
        let mut best_verify = f64::INFINITY;
        for _ in 0..RUNS {
            let t = Instant::now();
            verify(&config, &air, &proof, &[]).expect("verify");
            best_verify = best_verify.min(t.elapsed().as_secs_f64() * 1e3);
        }
        println!(
            "| {name} | {rows} | {best_prove:.0} | {best_verify:.1} | {:.1} | {:.1} |",
            postcard_bytes as f64 / 1024.0,
            fixed_bytes as f64 / 1024.0,
        );
    }
    println!();
    println!(
        "Peak RSS: rerun one config under /usr/bin/time -l with --only <cfg>. \
         Semantics note: bank values are self-consistent random instances \
         (a wrong c fails verification — same discipline as the anchor); \
         the keccak lane runs the stock schedule. Cross-lane routing, FS \
         extraction, and public binding are increment 2."
    );
}
