//! M4 step 0b(ii) anchor: a REAL ext-mul arithmetic bank, measured.
//!
//! Step 0b(i) priced the verifier's field-arithmetic glue with a bracketed
//! cells-per-op (mul 24–48). This anchor replaces the bracket with a
//! measurement, the same way M1.5b's step-0 anchor pinned the narrow
//! family before the full build: a 12-column bank AIR proving one
//! degree-4 extension multiplication per row (c = a·b over
//! KoalaBear[x]/(x^4 − 3), 4 constraints of degree 2), proven at the
//! aggregation-lane configs at 2^15 rows — enough for the measured 28.8k
//! muls per verified proof.
//!
//! What it pins: the realized cells/op (12 by construction — the anchor
//! validates no hidden blowup: quotient degree, prover throughput on a
//! tall-skinny rectangle, proof-byte impact), and the composite
//! projection for the full verifier rectangle (keccak lane + banks).

use std::time::Instant;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::extension::BinomialExtensionField;
use p3_field::PrimeCharacteristicRing;
use p3_field::{BasedVectorSpace, Field};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{prove, verify};
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
#[allow(unused_imports)]
use p3_field::PrimeField32;

use crate::{pc_len, FriCfg, Val, RUNS};
// Re-gated by the re-mint: M4 runs on the legacy non-hiding config.
use qlab_consensus::legacy::make_legacy_config_with as make_config_with;

/// One degree-4 binomial-extension multiplication per row.
/// Columns: a[0..4], b[0..4], c[0..4]. W = 3 (KoalaBear x^4 − 3).
struct ExtMulBankAir;

const BANK_WIDTH: usize = 12;
const W: u32 = 3;

impl<F: Field> BaseAir<F> for ExtMulBankAir {
    fn width(&self) -> usize {
        BANK_WIDTH
    }
}

impl<AB: AirBuilder> Air<AB> for ExtMulBankAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: Vec<AB::Expr> = main.current_slice().iter().map(|v| (*v).into()).collect();
        let a: Vec<AB::Expr> = (0..4).map(|i| local[i].clone()).collect();
        let b: Vec<AB::Expr> = (0..4).map(|i| local[4 + i].clone()).collect();
        let c: Vec<AB::Expr> = (0..4).map(|i| local[8 + i].clone()).collect();
        let w = AB::Expr::from(AB::F::from_u32(W));

        // c_k = sum_{i+j=k} a_i b_j + W * sum_{i+j=k+4} a_i b_j
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
    }
}

type Ext = BinomialExtensionField<Val, 4>;

/// Random-instance trace: values computed with the real ext-field type,
/// so the constraints are checked against p3's own arithmetic.
fn gen_trace(log_rows: usize, extra_capacity_bits: usize) -> RowMajorMatrix<Val> {
    let rows = 1usize << log_rows;
    let mut rng = SmallRng::seed_from_u64(0xa9c4_0b11);
    let mut rnd_ext = |rng: &mut SmallRng| -> Ext {
        Ext::from_basis_coefficients_fn(|_| Val::from_u32(rng.next_u32() % 0x7f00_0001))
    };
    let mut values = Vec::with_capacity(rows * BANK_WIDTH);
    for _ in 0..rows {
        let a = rnd_ext(&mut rng);
        let b = rnd_ext(&mut rng);
        let c = a * b;
        values.extend_from_slice(a.as_basis_coefficients_slice());
        values.extend_from_slice(b.as_basis_coefficients_slice());
        values.extend_from_slice(c.as_basis_coefficients_slice());
    }
    let mut m = RowMajorMatrix::new(values, BANK_WIDTH);
    m.values.reserve((rows << extra_capacity_bits) * BANK_WIDTH - m.values.len());
    m
}

/// Lane configs measured (same set as m4census phase B).
const LANE_CFGS: [(&str, FriCfg); 3] = [
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
        "b8/q27/g19/fp16/a16",
        FriCfg {
            log_blowup: 3,
            num_queries: 27,
            grind_bits: 19,
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

const LOG_ROWS: usize = 15; // 32,768 muls >= the measured 28,800/proof

pub(crate) fn run_m4anchor(power: &str) {
    println!("# qumbra-lab M4 step 0b(ii) anchor: ext-mul bank, measured");
    println!();
    crate::print_env(power);
    println!(
        "- bank: {BANK_WIDTH} cols x 2^{LOG_ROWS} rows = one deg-4 ext-mul/row \
         (c = a*b over KoalaBear[x]/(x^4 - {W}), 4 constraints, degree 2); \
         trace values cross-checked against p3's own ext arithmetic"
    );
    println!(
        "- pins step 0b(i)'s bracketed price: 12 cells/mul by construction; \
         the anchor validates prover throughput, quotient shape, and \
         proof-byte impact on a tall-skinny rectangle"
    );
    println!();
    println!("| lane config | prove ms | verify ms | postcard KB | fixed KB |");
    println!("|---|---|---|---|---|");
    let air = ExtMulBankAir;
    for (name, cfg) in &LANE_CFGS {
        let config = make_config_with(cfg);
        eprintln!("== anchor: {name} ==");
        let mut best_prove = f64::INFINITY;
        let mut proof_opt = None;
        for _ in 0..RUNS {
            let trace = gen_trace(LOG_ROWS, cfg.log_blowup);
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
            "| {name} | {best_prove:.1} | {best_verify:.1} | {:.1} | {:.1} |",
            postcard_bytes as f64 / 1024.0,
            fixed_bytes as f64 / 1024.0,
        );
    }
    println!();

    // Composite projection for the full verifier rectangle.
    let hash_rows = 2_233.0 * 24.0; // keccak lane
    let mul_rows = 28_800.0;
    let add_rows = 28_663.0 / 4.0; // batched 4 adds/row in a 12-col bank
    let height: f64 = 65_536.0; // 2^16 covers all lanes
    let keccak_cols = 2_633.0;
    let bank_cols = 12.0 + 12.0; // mul bank + add bank
    let routing_cols = 16.0; // FS/challenge/injection allowance [projected]
    let total_cols = keccak_cols + bank_cols + routing_cols;
    let cells = total_cols * height;
    // Rectangle-to-rectangle comparison: step 0a's phase-B baseline
    // (456 ms / 2.87 GB at b4) was ALREADY a padded 2^16 x 2,633
    // rectangle, so the marginal cost of the verifier build is the added
    // columns only. (Utilized bank cells — 0b(i)'s 0.6–1.1% — and the
    // power-of-two height padding are separate accounting; the padding
    // exists in both baselines and cancels.)
    let hash_rect_cells = keccak_cols * height;
    println!(
        "Composite projection [projected — the full build is 0b(ii)]: one \
         rectangle {total_cols:.0} cols x 2^16 rows = {:.0}M cells = \
         {:+.1}% over the measured hash-only rectangle ({:.0}M, the b4 \
         456 ms / 2.87 GB baseline); row budget: keccak {hash_rows:.0}, \
         mul bank {mul_rows:.0}, add bank {add_rows:.0} — all inside 2^16 \
         with slack. Projected b4 leaf: ~{:.0} ms prove / ~{:.2} GB RSS.",
        cells / 1e6,
        100.0 * (cells - hash_rect_cells) / hash_rect_cells,
        hash_rect_cells / 1e6,
        456.0 * cells / hash_rect_cells,
        2.87 * cells / hash_rect_cells,
    );
}
