//! W3 (lab #700): the L2 circuit family measured — `l2shape` mode.
//!
//! ```text
//! qlab-bench l2shape --shape s|s20|mock118|mock240|p|p19 [--only <lane substring>] [--power <note>]
//! ```
//!
//! Same in-process prove/verify pattern as `bucket`: one shape per process,
//! `--only` narrows to one lane, and the caller wraps the RELEASE BINARY in
//! `/usr/bin/time -l` inside `scripts/rig run -- …` — never `cargo run`
//! inside the window (`docs/mint-combo-build-notes.md` §"Stage 5" records the
//! 25 MB non-number that produces). Peak `phys_footprint` is the RAM figure.
//!
//! Shapes:
//! - `s`       — shape S real (`qlab_air::l2::build_bucket_l2`), 120 perms @ 2^19.
//! - `s20`     — the same instance at 2^20: the shape-S AIR at shape P's height,
//!               the post-stage-1 geometry proxy for P.
//! - `mock118` — **MOCK**: the shape-S AIR carrying the L1-shaped program
//!               (assets all 0, no registry opening) padded with `ROLE_MERKLE`
//!               slots to 118 perms, @ 2^19. Prices geometry only.
//! - `mock240` — **MOCK**: the same 118-perm program @ 2^20. The L2 program
//!               ring holds 128 slots, so "240 perms" is expressed as the
//!               height (341-perm capacity; the pipeline chains through the
//!               padding and every padded block is a genuine Keccak round, so
//!               the prover's work is the height's, not the program's).
//! - `p`       — shape P real (`qlab_air::l2p::build_bucket_l2p`), 214 perms @ 2^20:
//!               a Cloaked asset-0 input + a Hybrid stablecoin input (freeze
//!               tree live, allowlist on the dummy path), no vPublic. Stage 2.
//! - `p19`     — **CANARY** (#700's rule: a 2^19 run of the same shape and lane
//!               before any 2^20): the shape-P AIR at 2^19 in chain-only mode —
//!               same 778 columns, half the rows; the P program does not fit
//!               2^19 (214 perms > 170), so the canary prices width × height only.
//!
//! Lanes (the FRI points), each asserted ≥ 100 bits by `make_config_with`'s
//! capacity proxy and labelled with its 2197-corrected figure:
//! - `b2/q86/g22/fp16/a16`  — the interior lane's ruled point (`m4interior`),
//!   100.2 corrected; shape P's second lane by the stage-1 ruling.
//! - `b4/q43/g22/fp16/a16`  — the L2 lane, read from `qlab_l2::L2_CFG_PROVISIONAL`
//!   (lab #704: one source; equal in value to the M4 leaf point `AGG_CFG`,
//!   not tied to it), 101.6 corrected.
//! - `b8/q29/g22/fp16/a16`  — derived the same way as q43 (see `B8_CFG`).
//! - `b16/q21/g22/fp16/a16` — the L1 consensus point; shape S only, and only
//!   if the b8 run projects it under 32 GB (#700's canary rule; the operator
//!   enforces it by not invoking this lane otherwise).

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Instant;

use p3_air::symbolic::{get_max_constraint_degree, AirLayout};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;
use p3_air::{Air, BaseAir, DebugConstraintBuilder};
use p3_uni_stark::{prove, verify, ProverConstraintFolder, SymbolicAirBuilder, VerifierConstraintFolder};
use qlab_air::l2::{
    L2ShapeSAir, L2TxInput, L2TxOutput, PROGRAM_SLOTS, ROLE_DUMMY, ROLE_END, ROLE_MERKLE,
    ROWS_PER_PERM, SHAPE_S_LOG_HEIGHT, SHAPE_S_PERMS,
};
use qlab_air::l2p::{L2ShapePAir, SHAPE_P_LOG_HEIGHT, SHAPE_P_PERMS};
use qlab_consensus::CONSENSUS_CFG;
use qlab_l2::L2_CFG_PROVISIONAL as L2_CFG;

use crate::{make_config_with, pc_len, Config, FriCfg, Val, RUNS};

/// The b2 lane: the interior lane's ruled point (`m4interior.rs`; B″ q86 —
/// 86 × 0.910 + 22 = 100.2 under the 2197-corrected accounting; capacity
/// proxy 86 × 1 + 22 = 108).
pub(crate) const B2_CFG: FriCfg = FriCfg {
    log_blowup: 1,
    num_queries: 86,
    grind_bits: 22,
    log_final_poly_len: 4,
    max_log_arity: 4,
};

/// The b8 lane. **Derivation (the formula #700 asks for):** under the
/// 2197-corrected accounting (`fri-soundness-accounting-2026-07.md` §6) the
/// conjectured figure is `q · β(ρ) + g`, with `β(ρ) = −log₂(1 − δ*(ρ))` the
/// bits per query at the base-field list-decoding radius `δ*`. The three ruled
/// lanes fix β at three rates: from the §6 table, `(96.9 − 22)/20 = 3.745` at
/// b16, `(96.1 − 22)/40 = 1.853` at b4, `(94.8 − 22)/80 = 0.910` at b2 — and
/// B″'s q21/q43/q86 reproduce 100.6/101.6/100.2 from exactly those rates. Each
/// β gives `1 − δ* = 2^−β`, i.e. δ* = 0.925 (b16), 0.723 (b4), 0.468 (b2), a
/// gap below capacity `1 − ρ` of 0.012, 0.027, 0.032 respectively. For b8
/// (ρ = 1/8, capacity 0.875) the gap brackets between b4's and b16's:
/// δ* ∈ [0.848, 0.863] ⇒ β ∈ [2.72, 2.87] bits/query. At g22 the ≥ 100 floor
/// needs `q ≥ 78/β` ⇒ q ∈ [27.2, 28.7]; **q29** clears it under the
/// conservative end of the bracket (29 × 2.72 + 22 = 100.9) and is what this
/// lane uses. The exact Cor. 4.5 optimisation at ρ = 1/8 was not run here —
/// if it lands above 2.72 bits/query, q29 is ≥ 1 query conservative, never
/// short. Capacity proxy (what `make_config_with` asserts): 29 × 3 + 22 = 109.
pub(crate) const B8_CFG: FriCfg = FriCfg {
    log_blowup: 3,
    num_queries: 29,
    grind_bits: 22,
    log_final_poly_len: 4,
    max_log_arity: 4,
};

const LANES: [(&str, &str, FriCfg); 4] = [
    ("b2/q86/g22/fp16/a16", "100.2 corrected (B″)", B2_CFG),
    ("b4/q43/g22/fp16/a16", "101.6 corrected (B″) — the L2 lane, provisional", L2_CFG),
    ("b8/q29/g22/fp16/a16", "≥100.9 corrected (bracketed, see B8_CFG)", B8_CFG),
    ("b16/q21/g22/fp16/a16", "100.6 corrected (B″)", CONSENSUS_CFG),
];

/// The deterministic shape-S instance every run measures: asset 0 (50,000) +
/// asset 7 (30,000) in, 49,000 (asset 0) + 30,000 (asset 7) out, fee 1,000.
/// Built by `qlab_l2::fixture` — one source for the bench and the goldens.
fn shape_s_instance(log_height: usize) -> (L2ShapeSAir, Vec<Val>) {
    let inst = qlab_l2::fixture::shape_s_at(log_height);
    let pvs = qlab_l2::public_values(&inst.pvs);
    (inst.air, pvs)
}

/// The MOCK program: the shape-S instance with both inputs in asset 0 and
/// the registry chains removed (so it is the L1-shaped 84-perm program on the
/// L2 AIR), then padded with `ROLE_MERKLE` slots after `END` to `perms`.
/// Padding slots inject pseudo-random siblings and chain the digest onward —
/// real Keccak work, bound to nothing (ep is 0 after END).
fn mock_instance(perms: usize, log_height: usize) -> (L2ShapeSAir, Vec<Val>) {
    use qlab_air::l2::{
        build_bucket_l2_with_witnesses, derive_input_l2, fabricated_registry_tree, RegistryLeaf,
        ROLE_AREG, ROLE_BREG,
    };
    use qlab_air::narrow::fabricated_shared_tree;
    let mut x = 0x0118_0240_a11e_0700u64;
    let mut rnd = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let inputs = [
        L2TxInput { sk: [rnd(), rnd(), rnd(), rnd()], value: 60_000, asset: 0, rho: [rnd(), rnd(), rnd(), rnd()], rseed: [rnd(), rnd(), rnd(), rnd()], d: [0, 0] },
        L2TxInput { sk: [rnd(), rnd(), rnd(), rnd()], value: 20_000, asset: 0, rho: [rnd(), rnd(), rnd(), rnd()], rseed: [rnd(), rnd(), rnd(), rnd()], d: [0, 0] },
    ];
    let outputs = [
        L2TxOutput { value: 59_000, asset: 0, rkm: [rnd(); 4], rho: [0; 4], rseed: [rnd(); 4] },
        L2TxOutput { value: 20_000, asset: 0, rkm: [rnd(); 4], rho: [0; 4], rseed: [rnd(); 4] },
    ];
    let (_, _, cm1) = derive_input_l2(&inputs[0]);
    let (_, _, cm2) = derive_input_l2(&inputs[1]);
    let (w, anchor) = fabricated_shared_tree(&cm1, &cm2);
    let leaves = [RegistryLeaf::cloaked(0), RegistryLeaf::cloaked(0)];
    let (rw, root) = fabricated_registry_tree(&leaves[0].hash(), &leaves[1].hash());
    let inst = build_bucket_l2_with_witnesses(
        log_height, &inputs, &outputs, 1_000, &w, anchor, &leaves, &rw, root,
    );
    let mut air = inst.air;
    // Strip the registry chains: AREG + 16 MERKLE + BREG per input → the
    // L1-shaped program. Slots are compacted; witnesses move with them.
    let mut program = [ROLE_DUMMY; PROGRAM_SLOTS];
    let mut sw = Vec::with_capacity(PROGRAM_SLOTS);
    let mut i = 0usize;
    let mut out = 0usize;
    while i < SHAPE_S_PERMS {
        if air.program[i] == ROLE_AREG {
            // skip AREG, its 16 MERKLE steps and BREG
            let mut j = i + 1;
            while air.program[j] != ROLE_BREG {
                j += 1;
            }
            i = j + 1;
            continue;
        }
        program[out] = air.program[i];
        sw.push(air.slot_witness[i]);
        out += 1;
        i += 1;
    }
    assert_eq!(out, 84, "the L1-shaped program is 84 perms");
    assert_eq!(program[out - 1], ROLE_END);
    assert!(perms <= PROGRAM_SLOTS, "the L2 ring holds {PROGRAM_SLOTS} slots");
    while out < perms {
        program[out] = ROLE_MERKLE;
        let mut w = qlab_air::l2::L2SlotWitness::default();
        w.w[..4].copy_from_slice(&[rnd(), rnd(), rnd(), rnd()]);
        w.pbit = rnd() & 1 == 1;
        sw.push(w);
        out += 1;
    }
    while sw.len() < PROGRAM_SLOTS {
        sw.push(qlab_air::l2::L2SlotWitness::default());
    }
    air.program = program;
    air.slot_witness = sw;
    // Row 1 pays the fee from input 1; output 1 balances input 2 in row 2.
    air.sel_o1a = true;
    air.sel_o2a = false;
    air.sel_f1 = true;
    air.sel_q = true; // both inputs asset 0: the rows sum, the fee is paid once
    let pvs = inst.pvs.iter().map(|v| Val::from_u32(*v)).collect();
    (air, pvs)
}

/// The deterministic shape-P instance every run measures: asset 0 (Cloaked,
/// 50,000) + asset 7 (Hybrid: issuer, three frozen keys, redeem closed;
/// 30,000) in, 49,000 (asset 0) + 30,000 (asset 7) out, fee 1,000, no
/// vPublic. Every gadget is in the trace (fixed shape); the allowlist rides
/// the dummy path (asset 7 is not Regulated). Built by `qlab_l2::fixture`.
pub(crate) fn shape_p_instance(log_height: usize) -> (L2ShapePAir, Vec<Val>) {
    let inst = qlab_l2::fixture::shape_p_at(log_height);
    let pvs = qlab_l2::public_values(&inst.pvs);
    (inst.air, pvs)
}

/// One lane through the real prover: best-of-`RUNS` prove and verify, the
/// proof's postcard and bincode-fixed bytes, and the width read off the
/// trace `prove` was handed.
fn bench_lane<A>(
    air: &A,
    pvs: &[Val],
    cfg: &FriCfg,
    gen_trace: impl Fn(usize) -> p3_matrix::dense::RowMajorMatrix<Val>,
) -> (f64, f64, usize, usize, usize)
where
    A: Air<SymbolicAirBuilder<Val>>
        + for<'a> Air<ProverConstraintFolder<'a, Config>>
        + for<'a> Air<VerifierConstraintFolder<'a, Config>>
        + for<'a> Air<DebugConstraintBuilder<'a, Val>>,
{
    let config = make_config_with(cfg);
    let mut best_prove = f64::INFINITY;
    let mut proof_opt = None;
    let mut width = 0;
    for _ in 0..RUNS {
        let trace = gen_trace(cfg.log_blowup);
        width = trace.width();
        let t = Instant::now();
        let proof = prove(&config, air, trace, pvs);
        best_prove = best_prove.min(t.elapsed().as_secs_f64() * 1e3);
        proof_opt = Some(proof);
    }
    let proof = proof_opt.expect("RUNS > 0");
    let proof_bytes = pc_len(&proof);
    let fixed_bytes = bincode::serialize(&proof).expect("bincode").len();
    let mut best_verify = f64::INFINITY;
    for _ in 0..RUNS {
        let t = Instant::now();
        verify(&config, air, &proof, pvs).expect("verification failed");
        best_verify = best_verify.min(t.elapsed().as_secs_f64() * 1e3);
    }
    (best_prove, best_verify, proof_bytes, fixed_bytes, width)
}

/// What one shape hands the lane loop.
struct ShapeUnderTest {
    label: &'static str,
    mock: bool,
    canary: bool,
    program_perms: usize,
    log_height: usize,
    width: usize,
    pv_len: usize,
    max_deg: usize,
    statement: &'static str,
    run: Box<dyn Fn(&FriCfg) -> (f64, f64, usize, usize, usize)>,
}

fn shape_s_under_test(label: &'static str, mock: bool, program_perms: usize, air: L2ShapeSAir, pvs: Vec<Val>) -> ShapeUnderTest {
    let layout = AirLayout::from_air::<Val>(&air);
    let max_deg = get_max_constraint_degree::<Val, _>(&air, layout);
    let log_height = air.log_height;
    let width = <L2ShapeSAir as BaseAir<Val>>::width(&air);
    let pv_len = <L2ShapeSAir as BaseAir<Val>>::num_public_values(&air);
    ShapeUnderTest {
        label,
        mock,
        canary: false,
        program_perms,
        log_height,
        width,
        pv_len,
        max_deg,
        statement: "shape S — 2 inputs (2 assets), per input the L1 chain + a depth-16 \
             registry opening bound to PV_REGROOT, 2 outputs, two-asset balance, mode = Cloaked",
        run: Box::new(move |cfg| bench_lane(&air, &pvs, cfg, |b| air.generate_trace::<Val>(b))),
    }
}

fn shape_p_under_test(label: &'static str, canary: bool, program_perms: usize, air: L2ShapePAir, pvs: Vec<Val>) -> ShapeUnderTest {
    let layout = AirLayout::from_air::<Val>(&air);
    let max_deg = get_max_constraint_degree::<Val, _>(&air, layout);
    let log_height = air.log_height;
    let width = <L2ShapePAir as BaseAir<Val>>::width(&air);
    let pv_len = <L2ShapePAir as BaseAir<Val>>::num_public_values(&air);
    ShapeUnderTest {
        label,
        mock: false,
        canary,
        program_perms,
        log_height,
        width,
        pv_len,
        max_deg,
        statement: "shape P — shape S plus, per input: indexed-Merkle freeze non-membership \
             (depth 20, low leaf + two 256-bit comparisons), allowlist membership (depth 20, \
             dummy path when off), vPublic per row with AISS (issuer key) when required; \
             mode read as flags",
        run: Box::new(move |cfg| bench_lane(&air, &pvs, cfg, |b| air.generate_trace::<Val>(b))),
    }
}

pub(crate) fn run_l2shape(power: &str, shape: &str, only: Option<&str>) {
    let sut: ShapeUnderTest = match shape {
        "s" => {
            let (air, pvs) = shape_s_instance(SHAPE_S_LOG_HEIGHT);
            shape_s_under_test("shape S", false, SHAPE_S_PERMS, air, pvs)
        }
        "s20" => {
            let (air, pvs) = shape_s_instance(SHAPE_S_LOG_HEIGHT + 1);
            shape_s_under_test("shape S @ 2^20 (P-height proxy)", false, SHAPE_S_PERMS, air, pvs)
        }
        "mock118" => {
            let (air, pvs) = mock_instance(118, 19);
            shape_s_under_test("MOCK 118 @ 2^19", true, 118, air, pvs)
        }
        "mock240" => {
            let (air, pvs) = mock_instance(118, 20);
            shape_s_under_test("MOCK 118-prog @ 2^20 (\"240\")", true, 118, air, pvs)
        }
        "p" => {
            let (air, pvs) = shape_p_instance(SHAPE_P_LOG_HEIGHT);
            shape_p_under_test("shape P", false, SHAPE_P_PERMS, air, pvs)
        }
        "p19" => {
            let air = L2ShapePAir::chain_only(SHAPE_P_LOG_HEIGHT - 1);
            let pvs = vec![Val::ZERO; <L2ShapePAir as BaseAir<Val>>::num_public_values(&air)];
            shape_p_under_test("CANARY: shape-P AIR chain-only @ 2^19", true, 0, air, pvs)
        }
        other => {
            eprintln!("l2shape: unknown --shape `{other}`; expected s|s20|mock118|mock240|p|p19");
            std::process::exit(2);
        }
    };

    let height = 1usize << sut.log_height;
    let capacity = height / ROWS_PER_PERM;
    let chunks = (sut.max_deg.max(2) - 1).next_power_of_two();
    let label = sut.label;

    println!(
        "# qumbra-lab W3 l2shape bench — {label}{}",
        if sut.mock {
            " — MOCK: geometry only, gates nothing"
        } else if sut.canary {
            " — CANARY: width × height only, gates nothing but the 2^20 start"
        } else {
            ""
        }
    );
    println!();
    crate::print_env(power);
    println!(
        "- AIR: {} — {} cols x {ROWS_PER_PERM} rows/perm, \
         program {} perms in a {capacity}-perm height (2^{}), \
         max constraint degree {}, {chunks} quotient chunks, {} public values",
        if shape.starts_with('p') { "qlab-air `l2p::L2ShapePAir`" } else { "qlab-air `l2::L2ShapeSAir`" },
        sut.width,
        sut.program_perms,
        sut.log_height,
        sut.max_deg,
        sut.pv_len,
    );
    if sut.mock {
        println!(
            "- MOCK: the L1-shaped 84-perm program on the L2 AIR (assets 0, no registry \
             opening) padded with ROLE_MERKLE slots after END to {}; prices \
             height × width only. House warning (#700): mocks undershot RAM 4× at M4 and \
             width 5–9× at M1.6 — these numbers gate nothing.",
            sut.program_perms
        );
    } else if sut.canary {
        println!(
            "- CANARY: the shape-P AIR with every perm slot dummy at 2^19 (the P program \
             needs 2^20). #700's rule: footprint × 2 < 32 GB or the 2^20 run is not started."
        );
    } else {
        println!("- statement: {}", sut.statement);
    }
    println!("- per cell: prove/verify = best of {RUNS} in-process runs; proof = postcard bytes and bincode-fixed bytes");
    println!("- peak footprint: read `phys_footprint` (peak) from the `/usr/bin/time -l` line wrapping THIS process; one lane per process");
    println!();
    println!("| shape | lane | conj. bits (2197-corrected) | perms (prog/cap) | width | log_height | max deg | prove ms | verify ms | postcard KB | fixed KB |");
    println!("|---|---|---|---|---|---|---|---|---|---|---|");

    for (name, bits, cfg) in LANES.iter() {
        if let Some(f) = only {
            if !name.contains(f) {
                continue;
            }
        }
        eprintln!("== l2shape {label}: {name} ({}) ==", cfg.label());
        let result = catch_unwind(AssertUnwindSafe(|| (sut.run)(cfg)));
        match result {
            Ok((prove_ms, verify_ms, bytes, fixed, width)) => {
                eprintln!(
                    "  [l2shape {label} {name}] prove={prove_ms:.1}ms verify={verify_ms:.1}ms \
                     postcard={bytes}B fixed={fixed}B width={width}"
                );
                println!(
                    "| {} | {} | {} | {}/{} | {} | {} | {} | {:.1} | {:.1} | {:.1} | {:.1} |",
                    label,
                    name,
                    bits,
                    sut.program_perms,
                    capacity,
                    width,
                    sut.log_height,
                    sut.max_deg,
                    prove_ms,
                    verify_ms,
                    bytes as f64 / 1024.0,
                    fixed as f64 / 1024.0,
                );
            }
            Err(_) => {
                eprintln!("  [l2shape {label} {name}] FAILED (panic during prove/verify — see stderr)");
                println!(
                    "| {} | {} | {} | {}/{} | {} | {} | {} | FAILED | FAILED | FAILED | FAILED |",
                    label, name, bits, sut.program_perms, capacity, sut.width, sut.log_height, sut.max_deg,
                );
            }
        }
    }
    println!();
    println!(
        "Envelope (#700): shape P ≤ 16 GB peak footprint and ≤ 20 s prove, judged at the L2 lane \
         (b4/q43 or b2/q86, whichever clears with the larger margin — stage-1 ruling). \
         Proof bytes and verify time are informational."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every lane clears the capacity proxy `make_config_with` asserts, and
    /// the b8 lane's query count is the bracketed derivation in `B8_CFG`.
    #[test]
    fn l2shape_lanes_are_at_the_floor() {
        for (_, _, cfg) in LANES.iter() {
            let _ = make_config_with(cfg); // asserts ≥ 100 (capacity proxy)
        }
        assert_eq!(B8_CFG.label(), "b8/q29/g22/fp16/a16");
        // The bracket: conservative β = 2.72 bits/query at b8.
        let bits_conservative = 29.0 * 2.72 + 22.0;
        assert!(bits_conservative >= 100.0, "{bits_conservative}");
        assert!(28.0 * 2.72 + 22.0 < 100.0, "q28 does not clear the conservative end");
        assert_eq!(L2_CFG.label(), "b4/q43/g22/fp16/a16");
        assert_eq!(CONSENSUS_CFG.label(), "b16/q21/g22/fp16/a16");
        assert_eq!(B2_CFG.label(), "b2/q86/g22/fp16/a16");
        assert!(86.0 * 0.910 + 22.0 >= 100.0, "b2/q86 at the 2197-corrected rate");
    }

    /// Shape P through the real prover at the b4/q43 lane (2^20 × 778 — the
    /// ~15 GB class; the local scoped run skips it by name and it was run
    /// once on its own under the lock, see `docs/w3-run3.md`): the honest
    /// instance proves and verifies, then each of `anchor`, `nf₁`, `fee`,
    /// `registry_root`, and the two vPublic surfaces (`vpa₂`, `m₂`) flipped
    /// in turn must make `verify` Err — the L1's
    /// `rejects_a_tampered_public_surface` pair on shape P. (Not at b2: a
    /// 4-quotient-chunk AIR does not verify at blowup 2 in p3-uni-stark
    /// 0.6.1 — `l2shape_b2_is_not_a_lane_for_a_degree_4_air` pins that.)
    #[test]
    fn l2shape_shape_p_prove_verify_and_tampered_pv_b4() {
        use qlab_air::l2::{PV_ANCHOR, PV_FEE, PV_NF1, PV_REGROOT};
        use qlab_air::l2p::{PV_VP2, PV_LEN};
        let (air, pvs) = shape_p_instance(SHAPE_P_LOG_HEIGHT);
        assert_eq!(pvs.len(), PV_LEN);
        let config = make_config_with(&L2_CFG);
        let trace = air.generate_trace::<Val>(L2_CFG.log_blowup);
        assert_eq!(trace.width(), qlab_l2::Shape::P.width(), "the shape-P width, read off the matrix prove is handed");
        let proof = prove(&config, &air, trace, &pvs);
        verify(&config, &air, &proof, &pvs).expect("shape P must verify at b4/q43");
        for (idx, name) in [
            (PV_ANCHOR + 2, "anchor"),
            (PV_NF1 + 5, "nf1"),
            (PV_FEE, "fee"),
            (PV_REGROOT + 9, "registry_root"),
            (PV_VP2 + 5, "vpa2"),
            (PV_VP2 + 1, "m2 (a mint of 1 claimed after the fact)"),
        ] {
            let mut bad = pvs.clone();
            bad[idx] += Val::ONE;
            assert!(verify(&config, &air, &proof, &bad).is_err(), "a proof verified against a tampered {name}");
        }
    }

    /// 🔴 Finding (stage 2): **b2 is not a lane for a degree-4 AIR** in
    /// p3-uni-stark 0.6.1. With 4 quotient chunks and `log_blowup = 1` the
    /// prover's quotient domain (4N) exceeds the committed LDE (2N); the PCS
    /// falls back to re-extending the trace (`get_evaluations_on_domain`'s
    /// iDFT path — the extra RAM the canary showed) and the verifier rejects
    /// the proof with `OodEvaluationMismatch`. Pinned on a small chain-only
    /// shape-P trace so the fact survives a prover bump: if this test starts
    /// failing, b2 has become available and the stage-1 ruling's second lane
    /// can be measured. The interior lane's b2/q86 works because that AIR has
    /// 2 quotient chunks.
    #[test]
    fn l2shape_b2_is_not_a_lane_for_a_degree_4_air() {
        let air = L2ShapePAir::chain_only(12);
        let pvs = vec![Val::ZERO; <L2ShapePAir as BaseAir<Val>>::num_public_values(&air)];
        let config = make_config_with(&B2_CFG);
        let trace = air.generate_trace::<Val>(B2_CFG.log_blowup);
        let proof = prove(&config, &air, trace, &pvs);
        assert!(
            verify(&config, &air, &proof, &pvs).is_err(),
            "a 4-chunk AIR verified at b2 — the b2 lane has become available; re-measure shape P there"
        );
        // …and the same AIR at b4 verifies (the control).
        let config4 = make_config_with(&L2_CFG);
        let trace4 = air.generate_trace::<Val>(L2_CFG.log_blowup);
        let proof4 = prove(&config4, &air, trace4, &pvs);
        verify(&config4, &air, &proof4, &pvs).expect("the control at b4 must verify");
    }

    /// The MOCK program is the L1-shaped 84 perms plus MERKLE padding and its
    /// instance satisfies the AIR at a small (test-sized) height — so the
    /// measured trace is a valid witness, not garbage the prover would still
    /// commit to.
    #[test]
    fn l2shape_mock_program_is_the_padded_l1_shape() {
        let (air, pvs) = mock_instance(118, 19);
        // 118 program perms INCLUDING the warm-up dummy at slot 0 — so 117
        // non-dummy roles, the same convention as `SHAPE_S_PERMS` (120 = 1 + 119).
        assert_eq!(air.program.iter().filter(|r| **r != ROLE_DUMMY).count(), 117);
        assert_eq!(air.program[0], ROLE_DUMMY);
        let end = air.program.iter().position(|r| *r == ROLE_END).unwrap();
        assert_eq!(end, 83, "END at slot 83 — the L1-shaped program is 84 perms");
        assert!(air.program[84..118].iter().all(|r| *r == ROLE_MERKLE));
        assert!(!air.program[..84].iter().any(|r| *r == qlab_air::l2::ROLE_AREG));
        let trace = air.generate_trace::<Val>(0);
        p3_air::check_constraints(&air, &trace, &pvs);
    }

    /// The real shape-S instance the bench measures proves and verifies
    /// end-to-end at the b4 lane (the prover stack, not only check_constraints).
    #[test]
    fn l2shape_shape_s_prove_verify_roundtrip_b4() {
        let (air, pvs) = shape_s_instance(SHAPE_S_LOG_HEIGHT);
        let config = make_config_with(&L2_CFG);
        let trace = air.generate_trace::<Val>(L2_CFG.log_blowup);
        let proof = prove(&config, &air, trace, &pvs);
        verify(&config, &air, &proof, &pvs).expect("shape S must verify at b4/q43");
    }

    /// 🔴 Stage-2 carry-over (lab #700 stage-1 ruling, cargo item 0 (ii)): the
    /// L1's `rejects_a_tampered_public_surface` pair, on L2. The honest shape-S
    /// instance is proved ONCE at b4/q43 through the real prover; then each of
    /// `anchor`, `nf₁`, `fee`, `registry_root` is flipped in turn in the public
    /// values handed to `p3_uni_stark::verify`, which must Err — a proof for
    /// one surface must not verify against another. (`l2::l2_public_value_negatives`
    /// does the same through `check_all_constraints`; this is the prover-stack
    /// twin, which the L2 lacked.)
    #[test]
    fn l2shape_shape_s_tampered_pv_is_rejected_b4() {
        use qlab_air::l2::{PV_ANCHOR, PV_FEE, PV_NF1, PV_REGROOT};
        let (air, pvs) = shape_s_instance(SHAPE_S_LOG_HEIGHT);
        let config = make_config_with(&L2_CFG);
        let trace = air.generate_trace::<Val>(L2_CFG.log_blowup);
        let proof = prove(&config, &air, trace, &pvs);
        verify(&config, &air, &proof, &pvs).expect("precondition: the honest surface verifies");
        for (idx, name) in [
            (PV_ANCHOR + 2, "anchor"),
            (PV_NF1 + 5, "nf1"),
            (PV_FEE, "fee"),
            (PV_REGROOT + 9, "registry_root"),
        ] {
            let mut bad = pvs.clone();
            bad[idx] += Val::ONE;
            assert!(
                verify(&config, &air, &proof, &bad).is_err(),
                "a proof verified against a tampered {name}"
            );
        }
    }
}
