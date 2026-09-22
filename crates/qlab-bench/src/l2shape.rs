//! W3 (lab #700): the L2 circuit family measured — `l2shape` mode.
//!
//! ```text
//! qlab-bench l2shape --shape s|s20|mock118|mock240|p [--only <lane substring>] [--power <note>]
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
//! - `p`       — shape P: **not built** (stage 2, baton 2). Exits 2.
//!
//! Lanes (the FRI points), each asserted ≥ 100 bits by `make_config_with`'s
//! capacity proxy and labelled with its 2197-corrected figure:
//! - `b4/q43/g22/fp16/a16`  — the shipping leaf point (`m4treerec::AGG_CFG`),
//!   101.6 corrected.
//! - `b8/q29/g22/fp16/a16`  — derived the same way as q43 (see `B8_CFG`).
//! - `b16/q21/g22/fp16/a16` — the L1 consensus point; shape S only, and only
//!   if the b8 run projects it under 32 GB (#700's canary rule; the operator
//!   enforces it by not invoking this lane otherwise).

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Instant;

use p3_air::symbolic::{get_max_constraint_degree, AirLayout};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;
use p3_uni_stark::{prove, verify};
use qlab_air::l2::{
    build_bucket_l2, L2ShapeSAir, L2TxInput, L2TxOutput, L2_WIDTH, PROGRAM_SLOTS, PV_LEN,
    ROLE_DUMMY, ROLE_END, ROLE_MERKLE, ROWS_PER_PERM, SHAPE_S_LOG_HEIGHT, SHAPE_S_PERMS,
};
use qlab_consensus::CONSENSUS_CFG;

use crate::m4treerec::AGG_CFG;
use crate::{make_config_with, pc_len, FriCfg, Val, RUNS};

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

const LANES: [(&str, &str, FriCfg); 3] = [
    ("b4/q43/g22/fp16/a16", "101.6 corrected (B″)", AGG_CFG),
    ("b8/q29/g22/fp16/a16", "≥100.9 corrected (bracketed, see B8_CFG)", B8_CFG),
    ("b16/q21/g22/fp16/a16", "100.6 corrected (B″)", CONSENSUS_CFG),
];

/// The deterministic shape-S instance every run measures: asset 0 (100) +
/// asset 7 (50) in, 90 (asset 0) + 50 (asset 7) out, fee 10.
fn shape_s_instance(log_height: usize) -> (L2ShapeSAir, Vec<Val>) {
    let mut x = 0xfeed_face_cafe_beefu64;
    let mut rnd = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mk_in = |value: u64, asset: u64, rnd: &mut dyn FnMut() -> u64| L2TxInput {
        sk: [rnd(), rnd(), rnd(), rnd()],
        value,
        asset,
        rho: [rnd(), rnd(), rnd(), rnd()],
        rseed: [rnd(), rnd(), rnd(), rnd()],
        d: [rnd(), rnd()],
    };
    let mk_out = |value: u64, asset: u64, rnd: &mut dyn FnMut() -> u64| L2TxOutput {
        value,
        asset,
        rkm: [rnd(), rnd(), rnd(), rnd()],
        rho: [rnd(), rnd(), rnd(), rnd()],
        rseed: [rnd(), rnd(), rnd(), rnd()],
    };
    let inputs = [mk_in(50_000, 0, &mut rnd), mk_in(30_000, 7, &mut rnd)];
    let outputs = [mk_out(49_000, 0, &mut rnd), mk_out(30_000, 7, &mut rnd)];
    let inst = build_bucket_l2(log_height, &inputs, &outputs, 1_000);
    let pvs = inst.pvs.iter().map(|v| Val::from_u32(*v)).collect();
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

pub(crate) fn run_l2shape(power: &str, shape: &str, only: Option<&str>) {
    let (label, mock, program_perms, air, pvs): (&str, bool, usize, L2ShapeSAir, Vec<Val>) =
        match shape {
            "s" => {
                let (air, pvs) = shape_s_instance(SHAPE_S_LOG_HEIGHT);
                ("shape S", false, SHAPE_S_PERMS, air, pvs)
            }
            "s20" => {
                let (air, pvs) = shape_s_instance(SHAPE_S_LOG_HEIGHT + 1);
                ("shape S @ 2^20 (P-height proxy)", false, SHAPE_S_PERMS, air, pvs)
            }
            "mock118" => {
                let (air, pvs) = mock_instance(118, 19);
                ("MOCK 118 @ 2^19", true, 118, air, pvs)
            }
            "mock240" => {
                let (air, pvs) = mock_instance(118, 20);
                ("MOCK 118-prog @ 2^20 (\"240\")", true, 118, air, pvs)
            }
            "p" => {
                eprintln!("l2shape: shape P is stage 2 (baton 2) and is not built on this tree");
                std::process::exit(2);
            }
            other => {
                eprintln!("l2shape: unknown --shape `{other}`; expected s|s20|mock118|mock240|p");
                std::process::exit(2);
            }
        };

    let height = 1usize << air.log_height;
    let capacity = height / ROWS_PER_PERM;
    let layout = AirLayout::from_air::<Val>(&air);
    let max_deg = get_max_constraint_degree::<Val, _>(&air, layout);
    let chunks = (max_deg.max(2) - 1).next_power_of_two();

    println!("# qumbra-lab W3 l2shape bench — {label}{}", if mock { " — MOCK: geometry only, gates nothing" } else { "" });
    println!();
    crate::print_env(power);
    println!(
        "- AIR: qlab-air `l2::L2ShapeSAir` — {L2_WIDTH} cols x {ROWS_PER_PERM} rows/perm, \
         program {program_perms} perms in a {capacity}-perm height (2^{}), \
         max constraint degree {max_deg}, {chunks} quotient chunks, {PV_LEN} public values",
        air.log_height
    );
    if mock {
        println!(
            "- MOCK: the L1-shaped 84-perm program on the L2 AIR (assets 0, no registry \
             opening) padded with ROLE_MERKLE slots after END to {program_perms}; prices \
             height × width only. House warning (#700): mocks undershot RAM 4× at M4 and \
             width 5–9× at M1.6 — these numbers gate nothing."
        );
    } else {
        println!(
            "- statement: shape S — 2 inputs (2 assets), per input the L1 chain + a depth-16 \
             registry opening bound to PV_REGROOT, 2 outputs, two-asset balance, mode = Cloaked"
        );
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
        let config = make_config_with(cfg);
        eprintln!("== l2shape {label}: {name} ({}) ==", cfg.label());
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut best_prove = f64::INFINITY;
            let mut proof_opt = None;
            let mut width = 0;
            for _ in 0..RUNS {
                let trace = air.generate_trace::<Val>(cfg.log_blowup);
                width = trace.width();
                let t = Instant::now();
                let proof = prove(&config, &air, trace, &pvs);
                best_prove = best_prove.min(t.elapsed().as_secs_f64() * 1e3);
                proof_opt = Some(proof);
            }
            let proof = proof_opt.expect("RUNS > 0");
            let proof_bytes = pc_len(&proof);
            let fixed_bytes = bincode::serialize(&proof).expect("bincode").len();
            let mut best_verify = f64::INFINITY;
            for _ in 0..RUNS {
                let t = Instant::now();
                verify(&config, &air, &proof, &pvs).expect("verification failed");
                best_verify = best_verify.min(t.elapsed().as_secs_f64() * 1e3);
            }
            (best_prove, best_verify, proof_bytes, fixed_bytes, width)
        }));
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
                    program_perms,
                    capacity,
                    width,
                    air.log_height,
                    max_deg,
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
                    label, name, bits, program_perms, capacity, L2_WIDTH, air.log_height, max_deg,
                );
            }
        }
    }
    println!();
    println!(
        "Envelope (#700, informational at stage 1 — the gate is shape P at b4): \
         P ≤ 16 GB peak footprint and ≤ 20 s prove. Proof bytes and verify time are informational."
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
        assert_eq!(AGG_CFG.label(), "b4/q43/g22/fp16/a16");
        assert_eq!(CONSENSUS_CFG.label(), "b16/q21/g22/fp16/a16");
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
        let config = make_config_with(&AGG_CFG);
        let trace = air.generate_trace::<Val>(AGG_CFG.log_blowup);
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
        let config = make_config_with(&AGG_CFG);
        let trace = air.generate_trace::<Val>(AGG_CFG.log_blowup);
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
