//! M1.6 non-geometry levers: can FRI-parameter changes close the 22.5 KB
//! gap between the M1.5 narrow-geometry floor (172.5 KB @ L4, 164 cols)
//! and the <=150 KB target?
//!
//! Two levers, each a rig cell (CLAUDE.md M1.6 (a) and (b)):
//!
//! (a) blowup 32 / 18 queries / 10-bit grind = exactly 100 bits conjectured
//!     (18 x 5 + 10). Fewer queries shrink EVERY per-query term (input rows,
//!     input paths, fold siblings, fold paths) at the cost of a 32x LDE.
//!
//! (b) FRI fold arity > 2 via 0.6.1 `FriParameters::max_log_arity`. Arity
//!     2^k folds k height-halvings into one commit round: the number of
//!     commit-phase rounds (hence fold-path total + commit roots) drops ~k-fold,
//!     while sibling values per round grow to 2^k - 1. This attacks exactly the
//!     fold-rounds/path term that created the M1.5 U-curve, so the two levers
//!     compose with narrowing rather than fighting it.
//!
//! Soundness note: the ethSTARK conjectured-bits arithmetic
//! (`log_blowup x queries + grind`, the same formula the rig asserts >= 100)
//! does not depend on fold arity; arity only reshapes the proof.
//!
//! The probe reuses the M1.5 mock-geometry AIR (calibrated -0.005% vs the
//! real p3-keccak-air at L1) on the narrow rungs L3/L4/L5 plus a new L6
//! rung (41 cols), and runs the REAL p3-keccak-air alongside every config
//! as a full-pipeline sanity check that each configuration proves and
//! verifies a genuine AIR, not just the mock.

use p3_keccak_air::KeccakAir;

use crate::geometry::{
    constraints_per_row, GeometryAir, Layout, GEOMETRY_PERMS, KECCAK_CONSTRAINTS_PER_ROW,
    KECCAK_MAX_DEGREE, KECCAK_ROWS_PER_PERM, KECCAK_WIDTH, LADDER, TARGET_KB,
};
use crate::{keccak_inputs, make_config_with, run_cell, Cell, FriCfg, Val};

/// The M1.5 anchor: blowup 16 / 23 queries / grind 10 / fp16 / arity 2
/// (identical to `geometry::GEOMETRY_CFG`), re-measured here so every
/// lever delta is computed against numbers from the same binary + run.
const G0: FriCfg = FriCfg {
    log_blowup: 4,
    num_queries: 23,
    grind_bits: 10,
    log_final_poly_len: 4,
    max_log_arity: 1,
};

/// The lever matrix. Every config clears >= 100 bits conjectured
/// (runtime-asserted in `make_config_with`).
const LEVER_CFGS: [(&str, FriCfg); 7] = [
    ("G0 (M1.5 anchor)", G0),
    // Lever (a): blowup 32, 18 queries (18 x 5 + 10 = 100 bits).
    (
        "A: blowup 32",
        FriCfg {
            log_blowup: 5,
            num_queries: 18,
            grind_bits: 10,
            log_final_poly_len: 4,
            max_log_arity: 1,
        },
    ),
    // Lever (b) at the anchor blowup: arity 4 / 8 / 16.
    (
        "B: arity 4",
        FriCfg {
            max_log_arity: 2,
            ..G0
        },
    ),
    (
        "B: arity 8",
        FriCfg {
            max_log_arity: 3,
            ..G0
        },
    ),
    (
        "B: arity 16",
        FriCfg {
            max_log_arity: 4,
            ..G0
        },
    ),
    // Both levers combined.
    (
        "A+B: blowup 32, arity 8",
        FriCfg {
            log_blowup: 5,
            num_queries: 18,
            grind_bits: 10,
            log_final_poly_len: 4,
            max_log_arity: 3,
        },
    ),
    (
        "A+B: blowup 32, arity 16",
        FriCfg {
            log_blowup: 5,
            num_queries: 18,
            grind_bits: 10,
            log_final_poly_len: 4,
            max_log_arity: 4,
        },
    ),
];

/// One rung past the M1.5 ladder: if arity flattens the fold-path term that
/// bent the U-curve up below 164 cols, the minimum may move narrower — L6
/// tests that. constraints_per_row(1536) = 50 >= 41, so every column stays
/// constrained (same invariant the ladder test enforces).
const L6: Layout = Layout {
    name: "L6",
    width: 41,
    rows_per_perm: 1536,
};

struct LeverRow {
    cfg_name: &'static str,
    cfg: FriCfg,
    layout: &'static str,
    width: usize,
    cell: Cell,
}

impl LeverRow {
    fn proof_kb(&self) -> f64 {
        self.cell.proof_bytes as f64 / 1024.0
    }
}

fn measure(cfg_name: &'static str, cfg: &FriCfg, layout: &Layout) -> LeverRow {
    let air = GeometryAir {
        width: layout.width,
        rows_per_perm: layout.rows_per_perm,
        n_constraints: constraints_per_row(layout.rows_per_perm),
        max_degree: KECCAK_MAX_DEGREE,
    };
    let config = make_config_with(cfg);
    let cell = run_cell(&config, &air, layout.name, GEOMETRY_PERMS, "", || {
        air.generate_trace(GEOMETRY_PERMS, cfg.log_blowup)
    });
    LeverRow {
        cfg_name,
        cfg: *cfg,
        layout: layout.name,
        width: layout.width,
        cell,
    }
}

pub(crate) fn run_levers(power: &str) {
    println!("# qumbra-lab M1.6 non-geometry levers (blowup 32, FRI arity)");
    println!();
    crate::print_env(power);
    println!(
        "- levers: (a) blowup 32 / 18 queries / 10-bit grind = 100 bits conjectured; \
         (b) `max_log_arity` 2..4 (fold arity 4/8/16) at the M1.5 anchor and \
         combined with (a); every config runtime-asserted >= 100 bits"
    );
    println!(
        "- mock AIR identical to the M1.5 geometry probe (calibrated -0.005% vs \
         the real p3-keccak-air at L1); layouts = narrow rungs L3/L4/L5 plus a \
         new L6 (41 cols x 1536 rows/perm, {} constraints/row) probing whether \
         higher arity moves the U-curve minimum narrower",
        constraints_per_row(L6.rows_per_perm),
    );
    println!(
        "- the REAL p3-keccak-air ({KECCAK_WIDTH} cols, \
         {KECCAK_CONSTRAINTS_PER_ROW} constraints/row x {KECCAK_ROWS_PER_PERM} rows/perm) \
         runs under every config as a full prove+verify sanity check on a genuine AIR"
    );
    println!(
        "- workload: {GEOMETRY_PERMS} permutations-equivalent; per cell prove/verify = \
         best of 3 in-process runs; proof size = postcard bytes"
    );
    println!();

    let narrow: [&Layout; 4] = [&LADDER[2], &LADDER[3], &LADDER[4], &L6];
    let keccak_air = KeccakAir {};

    let mut rows: Vec<LeverRow> = Vec::new();
    for (cfg_name, cfg) in &LEVER_CFGS {
        eprintln!("== levers: {cfg_name} ({}) ==", cfg.label());
        // Real-AIR sanity cell for this config.
        let config = make_config_with(cfg);
        let real_cell = run_cell(&config, &keccak_air, "real", GEOMETRY_PERMS, "", || {
            p3_keccak_air::generate_trace_rows::<Val>(keccak_inputs(GEOMETRY_PERMS), cfg.log_blowup)
        });
        rows.push(LeverRow {
            cfg_name,
            cfg: *cfg,
            layout: "real",
            width: KECCAK_WIDTH,
            cell: real_cell,
        });
        for layout in narrow {
            rows.push(measure(cfg_name, cfg, layout));
        }
    }

    // Baseline (G0) proof size per layout, for the delta column.
    let g0_kb = |layout: &str| -> f64 {
        rows.iter()
            .find(|r| r.cfg_name == LEVER_CFGS[0].0 && r.layout == layout)
            .expect("G0 rows are measured first")
            .proof_kb()
    };

    println!(
        "| config | conj. bits | layout | width | prove ms | verify ms | proof KB \
         | vs G0 same layout | vs {TARGET_KB:.0} KB |"
    );
    println!("|---|---|---|---|---|---|---|---|---|");
    for r in &rows {
        let bits = r.cfg.num_queries * r.cfg.log_blowup + r.cfg.grind_bits;
        let delta = r.proof_kb() - g0_kb(r.layout);
        let verdict = if r.proof_kb() <= TARGET_KB {
            "PASS"
        } else {
            "FAIL"
        };
        println!(
            "| {} ({}) | {} | {} | {} | {:.1} | {:.1} | {:.1} | {:+.1} | {} |",
            r.cfg_name,
            r.cfg.label(),
            bits,
            r.layout,
            r.width,
            r.cell.prove_ms,
            r.cell.verify_ms,
            r.proof_kb(),
            delta,
            verdict,
        );
    }
    println!();

    // Verdict: best mock cell overall (the real 2633-col AIR is a sanity
    // reference, not a candidate layout).
    let best = rows
        .iter()
        .filter(|r| r.layout != "real")
        .min_by(|a, b| a.cell.proof_bytes.cmp(&b.cell.proof_bytes))
        .expect("matrix is non-empty");
    let g0_floor = g0_kb("L4");
    println!(
        "Best cell: {} @ {} ({}) = {:.1} KB — {:+.1} KB vs the M1.5 floor \
         ({:.1} KB @ L4).",
        best.layout,
        best.cfg_name,
        best.cfg.label(),
        best.proof_kb(),
        best.proof_kb() - g0_floor,
        g0_floor,
    );
    if best.proof_kb() <= TARGET_KB {
        println!(
            "Verdict: <= {TARGET_KB:.0} KB REACHED with non-geometry levers -> \
             M1.5b (correct narrow-Keccak AIR at {} cols) is justified.",
            best.width,
        );
    } else {
        println!(
            "Verdict: still {:.1} KB above the {TARGET_KB:.0} KB target -> remaining \
             levers are (c) truncated Merkle digest / (d) WHIR-class PCS, or the \
             target/hash decision goes back to qumbra-design.",
            best.proof_kb() - TARGET_KB,
        );
    }
}

// ---------------------------------------------------------------------------
// Tests: high-arity and blowup-32 configs must prove AND verify end to end
// on a small instance — cheap insurance that the 0.6.1 arity path works
// before burning bench time.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use p3_uni_stark::{prove, verify};

    use super::*;

    fn tiny_air() -> GeometryAir {
        GeometryAir {
            width: 8,
            rows_per_perm: 4,
            n_constraints: 11,
            max_degree: 3,
        }
    }

    fn prove_verify_roundtrip(cfg: &FriCfg) {
        let air = tiny_air();
        let config = make_config_with(cfg);
        let trace = air.generate_trace(16, cfg.log_blowup); // 64 rows x 8 cols
        let proof = prove(&config, &air, trace, &[]);
        verify(&config, &air, &proof, &[]).expect("verify failed");
    }

    #[test]
    fn arity_16_config_roundtrips() {
        prove_verify_roundtrip(&FriCfg {
            log_blowup: 4,
            num_queries: 23,
            grind_bits: 10,
            log_final_poly_len: 0,
            max_log_arity: 4,
        });
    }

    #[test]
    fn blowup_32_arity_8_config_roundtrips() {
        prove_verify_roundtrip(&FriCfg {
            log_blowup: 5,
            num_queries: 18,
            grind_bits: 10,
            log_final_poly_len: 2,
            max_log_arity: 3,
        });
    }

    #[test]
    fn l6_covers_every_column() {
        assert!(constraints_per_row(L6.rows_per_perm) >= L6.width);
    }
}
