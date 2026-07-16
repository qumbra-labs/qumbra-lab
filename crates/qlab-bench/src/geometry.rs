//! M1.5 trace-geometry probe: does a row-heavy NARROW Keccak trace layout
//! reach the <=150 KB proof-size target, and at what narrowing factor?
//!
//! Insight exploited: STARK proof size depends on trace geometry
//! (rows x cols) plus the FRI config — NOT on constraint semantics. So a
//! parametrized mock AIR with realistic geometry and representative
//! constraint density gives exact proof-size answers without implementing
//! correct narrow Keccak semantics. The mock proves AND verifies for real;
//! only the *meaning* of the constraints is fake.
//!
//! Constraint census of the published p3-keccak-air 0.6.1 `eval`
//! (counted by hand from `air.rs` + `round_flags.rs`):
//!
//!   round flags (first-row 24 + rotation 24)            48
//!   preimage == A on first step (5x5x4 limbs)          100
//!   preimage copy across rounds (5x5x4)                100
//!   export bool + export-off-when-not-final              2
//!   theta: C bools (5x64)                              320
//!   theta: C' = xor3 (5x64, degree 3)                  320
//!   A' bools (5x5x64)                                 1600
//!   A limb reconstruction via xor3 bits (5x5x4)        100
//!   theta parity diff*(diff-2)*(diff-4) (5x64, deg 3)  320
//!   chi: A'' limbs from andn/xor bits (5x5x4, deg 3)   100
//!   iota: A''[0,0] bit bools (64) + limb recon (4)      68
//!   iota: A'''[0,0] limbs (4)                            4
//!   round output == next round input (5x5x4)           100
//!   -------------------------------------------------------
//!   total                                             3182 constraints/row
//!
//! Max constraint degree 3 (xor3 / parity / chi), same as the mock's, so
//! the quotient has the same 2-chunk width and calibration is apples to
//! apples. Scaling rule for narrow layouts: hold constraint-evaluation
//! work per permutation constant, i.e.
//!
//!   constraints/row = ceil(3182 * 24 / rows_per_perm).

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_keccak_air::KeccakAir;
use p3_matrix::dense::RowMajorMatrix;

use crate::{keccak_inputs, make_config_with, run_cell, Cell, FriCfg, Val};

/// The best 100-bit-conjectured config from the PR #2 sweep:
/// blowup 16 / 23 queries / 10-bit grind / final-poly 16 (102 bits;
/// `make_config_with` runtime-asserts >= 100).
pub(crate) const GEOMETRY_CFG: FriCfg = FriCfg {
    log_blowup: 4,
    num_queries: 23,
    grind_bits: 10,
    log_final_poly_len: 4,
    max_log_arity: 1,
};

/// Hand-counted census of p3-keccak-air 0.6.1 (see module docs).
pub(crate) const KECCAK_CONSTRAINTS_PER_ROW: usize = 3182;
pub(crate) const KECCAK_ROWS_PER_PERM: usize = 24;
pub(crate) const KECCAK_WIDTH: usize = 2633;
/// Real Keccak AIR max constraint degree (xor3 / parity / chi).
pub(crate) const KECCAK_MAX_DEGREE: usize = 3;

/// Workload: smallest power of two >= 96, approximating the design's
/// ~90-hash 2x2-bucket circuit (same as sweep/breakdown modes).
pub(crate) const GEOMETRY_PERMS: usize = 128;
/// The design's actual ~90-hash bucket, rounded up.
const DESIGN_PERMS: usize = 96;

/// performance-budget SS3 transaction-size target.
pub(crate) const TARGET_KB: f64 = 150.0;

/// Calibration gate: L1 mock must land within this fraction of the real AIR.
const CALIBRATION_TOL: f64 = 0.10;

pub(crate) struct Layout {
    pub name: &'static str,
    pub width: usize,
    pub rows_per_perm: usize,
}

/// The narrowing ladder. L1 reproduces the real Keccak geometry
/// (calibration); each later rung trades ~4x width for ~4x rows at
/// (roughly) constant total trace area.
pub(crate) const LADDER: [Layout; 5] = [
    Layout {
        name: "L1",
        width: KECCAK_WIDTH,
        rows_per_perm: KECCAK_ROWS_PER_PERM,
    },
    Layout {
        name: "L2",
        width: 656,
        rows_per_perm: 96,
    },
    Layout {
        name: "L3",
        width: 330,
        rows_per_perm: 192,
    },
    Layout {
        name: "L4",
        width: 164,
        rows_per_perm: 384,
    },
    Layout {
        name: "L5",
        width: 82,
        rows_per_perm: 768,
    },
];

/// Constraints/row that hold constraint-evaluation work per permutation
/// constant relative to the real Keccak AIR.
pub(crate) fn constraints_per_row(rows_per_perm: usize) -> usize {
    (KECCAK_CONSTRAINTS_PER_ROW * KECCAK_ROWS_PER_PERM).div_ceil(rows_per_perm)
}

// ---------------------------------------------------------------------------
// The mock AIR
// ---------------------------------------------------------------------------

/// Parametrized mock AIR with realistic geometry and representative
/// constraint density.
///
/// Constraints (all satisfied by construction by `generate_trace`):
/// - boundary: column 0 == 2 on the first row;
/// - `n_constraints` transition constraints of degree `max_degree`,
///   `next[col] = local[col]^max_degree`, cycling `col` over all columns
///   (every layout in the ladder has n_constraints >= width, so every
///   column is constrained at least once).
///
/// With `max_degree` = 3 this matches the real Keccak AIR's max degree
/// (`is_transition` counts as degree 0 in Plonky3's quotient accounting),
/// so the quotient width — hence proof size — is geometry-faithful.
pub(crate) struct GeometryAir {
    pub width: usize,
    pub rows_per_perm: usize,
    pub n_constraints: usize,
    pub max_degree: usize,
}

fn pow_deg(v: Val, deg: usize) -> Val {
    (1..deg).fold(v, |acc, _| acc * v)
}

impl GeometryAir {
    /// Trace satisfying the AIR by construction: row 0 seeds column `j`
    /// with `j + 2` (nonzero, non-one), every later row cubes (in general,
    /// `max_degree`-th powers) the row above. x -> x^3 is a bijection on
    /// KoalaBear (3 does not divide p - 1 = 2^24 * 127), so columns never
    /// degenerate to fixed points. Height is padded to the next power of
    /// two, exactly like the real Keccak AIR pads with dummy permutations.
    pub(crate) fn generate_trace(
        &self,
        perms: usize,
        extra_capacity_bits: usize,
    ) -> RowMajorMatrix<Val> {
        let height = (perms * self.rows_per_perm).next_power_of_two();
        let size = height * self.width;
        let mut values = Vec::with_capacity(size << extra_capacity_bits);
        values.extend((0..self.width).map(|j| Val::from_u32(j as u32 + 2)));
        for row in 1..height {
            let prev = (row - 1) * self.width;
            for j in 0..self.width {
                let v = values[prev + j];
                values.push(pow_deg(v, self.max_degree));
            }
        }
        RowMajorMatrix::new(values, self.width)
    }
}

impl<F> BaseAir<F> for GeometryAir {
    fn width(&self) -> usize {
        self.width
    }
}

impl<AB: AirBuilder> Air<AB> for GeometryAir {
    fn eval(&self, builder: &mut AB) {
        let window = builder.main();
        let local = window.current_slice();
        let next = window.next_slice();

        // Boundary constraint on row 0 (mirrors the real AIR's first-row
        // round-flag pinning): column 0 starts at 2.
        builder.when_first_row().assert_eq(local[0], AB::Expr::TWO);

        // n_constraints transition constraints, degree max_degree:
        //   next[col] = local[col]^max_degree, col cycling over all columns.
        let mut transition = builder.when_transition();
        for k in 0..self.n_constraints {
            let col = k % self.width;
            let l: AB::Expr = local[col].into();
            let pow = (1..self.max_degree).fold(l.clone(), |acc, _| acc * l.clone());
            transition.assert_eq(pow, next[col]);
        }
    }
}

// ---------------------------------------------------------------------------
// The probe
// ---------------------------------------------------------------------------

struct GeoRow {
    layout: String,
    width: usize,
    rows_per_perm: usize,
    perms: usize,
    padded_rows: usize,
    constraints_per_row: usize,
    cell: Cell,
    note: &'static str,
}

impl GeoRow {
    fn proof_kb(&self) -> f64 {
        self.cell.proof_bytes as f64 / 1024.0
    }
}

fn measure_mock(name: &'static str, layout: &Layout, perms: usize, note: &'static str) -> GeoRow {
    let air = GeometryAir {
        width: layout.width,
        rows_per_perm: layout.rows_per_perm,
        n_constraints: constraints_per_row(layout.rows_per_perm),
        max_degree: KECCAK_MAX_DEGREE,
    };
    let config = make_config_with(&GEOMETRY_CFG);
    let cell = run_cell(&config, &air, name, perms, "", || {
        air.generate_trace(perms, GEOMETRY_CFG.log_blowup)
    });
    GeoRow {
        layout: name.to_string(),
        width: layout.width,
        rows_per_perm: layout.rows_per_perm,
        perms,
        padded_rows: cell.rows,
        constraints_per_row: air.n_constraints,
        cell,
        note,
    }
}

fn print_geo_table(rows: &[GeoRow]) {
    println!(
        "| layout | width | rows/perm | perms | padded rows | constraints/row \
         | prove ms | verify ms | proof KB | vs {TARGET_KB:.0} KB |"
    );
    println!("|---|---|---|---|---|---|---|---|---|---|");
    for r in rows {
        let verdict = if r.proof_kb() <= TARGET_KB {
            "PASS"
        } else {
            "FAIL"
        };
        println!(
            "| {} | {} | {} | {} | {} | {} | {:.1} | {:.1} | {:.1} | {} |",
            r.layout,
            r.width,
            r.rows_per_perm,
            r.perms,
            r.padded_rows,
            r.constraints_per_row,
            r.cell.prove_ms,
            r.cell.verify_ms,
            r.proof_kb(),
            verdict,
        );
    }
    println!();
    let notes: Vec<&GeoRow> = rows.iter().filter(|r| !r.note.is_empty()).collect();
    if !notes.is_empty() {
        println!("Notes:");
        for r in notes {
            println!("- {} @{} perms: {}", r.layout, r.perms, r.note);
        }
        println!();
    }
}

pub(crate) fn run_geometry(power: &str) {
    println!("# qumbra-lab M1.5 trace-geometry probe");
    println!();
    crate::print_env(power);
    println!(
        "- config: {} = {} bits conjectured (asserted >= 100 at runtime); \
         KoalaBear + degree-4 extension, Keccak-256 FRI Merkle",
        GEOMETRY_CFG.label(),
        GEOMETRY_CFG.num_queries * GEOMETRY_CFG.log_blowup + GEOMETRY_CFG.grind_bits,
    );
    println!(
        "- mock AIR: degree-{KECCAK_MAX_DEGREE} transition constraints \
         next[c] = local[c]^{KECCAK_MAX_DEGREE} cycling over all columns, \
         plus one boundary constraint; trace satisfies them by construction; \
         every cell is proven AND verified (best of 3 runs each)"
    );
    println!(
        "- constraint density: real p3-keccak-air 0.6.1 census = \
         {KECCAK_CONSTRAINTS_PER_ROW} constraints/row x {KECCAK_ROWS_PER_PERM} rows/perm \
         (max degree {KECCAK_MAX_DEGREE}); narrow layouts use \
         ceil({KECCAK_CONSTRAINTS_PER_ROW} * {KECCAK_ROWS_PER_PERM} / rows_per_perm) \
         to hold constraint evaluations per permutation constant"
    );
    println!(
        "- workload: {GEOMETRY_PERMS} permutations-equivalent (plus L4/L5 at \
         {DESIGN_PERMS}, the design's ~90-hash bucket rounded up); heights padded \
         to the next power of two exactly like the real AIR"
    );
    println!();

    let mut rows: Vec<GeoRow> = Vec::new();

    // Calibration reference: the REAL p3-keccak-air at the same config.
    eprintln!("== geometry: real Keccak AIR (calibration reference) ==");
    let config = make_config_with(&GEOMETRY_CFG);
    let keccak_air = KeccakAir {};
    let real_cell = run_cell(
        &config,
        &keccak_air,
        "Keccak-real",
        GEOMETRY_PERMS,
        "",
        || {
            p3_keccak_air::generate_trace_rows::<Val>(
                keccak_inputs(GEOMETRY_PERMS),
                GEOMETRY_CFG.log_blowup,
            )
        },
    );
    let real_kb = real_cell.proof_bytes as f64 / 1024.0;
    rows.push(GeoRow {
        layout: "real".to_string(),
        width: KECCAK_WIDTH,
        rows_per_perm: KECCAK_ROWS_PER_PERM,
        perms: GEOMETRY_PERMS,
        padded_rows: real_cell.rows,
        constraints_per_row: KECCAK_CONSTRAINTS_PER_ROW,
        cell: real_cell,
        note: "published p3-keccak-air, the calibration reference",
    });

    // The ladder at 128 permutations-equivalent.
    eprintln!("== geometry: mock ladder @ {GEOMETRY_PERMS} perms ==");
    for layout in &LADDER {
        rows.push(measure_mock(layout.name, layout, GEOMETRY_PERMS, ""));
    }

    // Calibration check: L1 mock vs the real AIR.
    let l1_kb = rows
        .iter()
        .find(|r| r.layout == "L1")
        .expect("L1 was just measured")
        .proof_kb();
    let delta = (l1_kb - real_kb) / real_kb;
    let calibration_ok = delta.abs() <= CALIBRATION_TOL;

    // L4/L5 additionally at the design's ~90-hash bucket (96 perms). The
    // power-of-two padding note is printed with the table.
    eprintln!("== geometry: L4/L5 @ {DESIGN_PERMS} perms ==");
    for layout in &LADDER {
        if layout.name == "L4" || layout.name == "L5" {
            rows.push(measure_mock(
                layout.name,
                layout,
                DESIGN_PERMS,
                "96 x rows/perm pads to the same power-of-two height as 128 \
                 perms, so the proof is byte-identical to the 128-perm row",
            ));
        }
    }

    print_geo_table(&rows);

    println!(
        "Calibration: L1 mock = {:.1} KB vs real Keccak AIR = {:.1} KB at the \
         same config -> delta {:+.1}% ({})",
        l1_kb,
        real_kb,
        delta * 100.0,
        if calibration_ok {
            format!("within the +/-{:.0}% gate", CALIBRATION_TOL * 100.0)
        } else {
            format!(
                "MISSES the +/-{:.0}% gate — mock numbers below L1 are suspect, investigate",
                CALIBRATION_TOL * 100.0
            )
        },
    );
    println!();

    // Verdict: smallest width that passes the target at 128 perms.
    let passing = rows
        .iter()
        .filter(|r| r.perms == GEOMETRY_PERMS && r.layout != "real" && r.proof_kb() <= TARGET_KB)
        .min_by_key(|r| r.width);
    match passing {
        Some(r) => println!(
            "Verdict: smallest width meeting <= {TARGET_KB:.0} KB at {GEOMETRY_PERMS} perms \
             is {} cols ({}, {:.1} KB) — narrowing factor {:.1}x vs the published \
             {KECCAK_WIDTH}-col Keccak AIR.",
            r.width,
            r.layout,
            r.proof_kb(),
            KECCAK_WIDTH as f64 / r.width as f64,
        ),
        None => println!(
            "Verdict: NO layout in the ladder meets <= {TARGET_KB:.0} KB at \
             {GEOMETRY_PERMS} perms; narrowing alone does not reach the target \
             at this config."
        ),
    }
}

// ---------------------------------------------------------------------------
// Tests: the mock AIR must actually be satisfied by its own trace, and
// corruptions must be caught — no cheating the prover.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use p3_air::{check_all_constraints, check_constraints};

    use super::*;

    fn small_air() -> GeometryAir {
        GeometryAir {
            width: 8,
            rows_per_perm: 4,
            n_constraints: 11,
            max_degree: 3,
        }
    }

    #[test]
    fn mock_trace_satisfies_constraints() {
        let air = small_air();
        let trace = air.generate_trace(4, 0); // 16 rows x 8 cols
        check_constraints(&air, &trace, &[]);
    }

    #[test]
    fn corrupted_mock_trace_detected() {
        let air = small_air();
        let mut trace = air.generate_trace(4, 0);
        // Break next[3] = local[3]^3 at the row 5 -> 6 transition.
        let w = trace.width;
        trace.values[6 * w + 3] += Val::ONE;
        let report = check_all_constraints(&air, &trace, &[], Some(10));
        assert!(!report.is_ok());
    }

    #[test]
    fn ladder_covers_every_column() {
        for layout in &LADDER {
            assert!(
                constraints_per_row(layout.rows_per_perm) >= layout.width,
                "{}: fewer constraints than columns",
                layout.name
            );
        }
    }
}
