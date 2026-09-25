//! M4 step 1 stage 2 (棒 2/3): the interior aggregation node — verify TWO child
//! leaf proofs in one rectangle and merge their public digests into the interior
//! root. Circuit analogue of `m4treerec` (which only records one child). The
//! two-child trace assembly lives in `m4gate::build_interior_trace`; this module
//! sources the child schedules and (stage 3) drives the full `prove` for the
//! peak-RSS-vs-32 GB gate.

use p3_field::{PrimeCharacteristicRing, PrimeField32};

use crate::m4gaterec::{keccakf, Schedule};
use crate::Val;

/// Merge-root digest length in field limbs (32-byte keccak digest = 16 u16
/// limbs, matching the cap-limb encoding in `outer_pvs`).
pub(crate) const MERGE_ROOT_LIMBS: usize = 16;

/// Epoch supply-attestation rider width (棒 3-3, M4 step 2): the M3 transaction
/// `fee` is public values `PV_FEE..PV_LEN` = 4 sixteen-bit limbs. The interior
/// exposes their per-child SUM as the root's `Σfee` rider (aggregation-rung1
/// §2's epoch rider, prototype form — Σcoinbase is a block-level M6 concern, not
/// an M3 PV). Fee is the TAIL of each child's opvs: the M3 inner PVs are the
/// opvs tail (after the caps) and `fee` is the M3 PV tail, so the summands are
/// the last `EPOCH_FEE_LIMBS` of each interior pv half.
pub(crate) const EPOCH_FEE_LIMBS: usize = 4;
// Stays glued to the M3 public-value layout (fee = PV_FEE..PV_LEN, the tail).
const _: () = assert!(
    EPOCH_FEE_LIMBS == qlab_air::narrow::PV_LEN - qlab_air::narrow::PV_FEE
        && qlab_air::narrow::PV_LEN == qlab_air::narrow::PV_FEE + EPOCH_FEE_LIMBS,
    "EPOCH_FEE_LIMBS must equal the M3 fee width, and fee must be the PV tail"
);

/// Overwrite-mode keccak sponge over `bytes` (the leaf-sponge convention: the
/// rate lanes are OVERWRITTEN by each block's message, the capacity is carried;
/// pad10*1). Returns each permutation's INPUT state (rate = message block,
/// capacity = previous output's capacity) plus the 32-byte digest. The
/// in-circuit merge lane replays these exact perms; 棒3-2 binds each preimage's
/// rate to the message and its capacity to the previous perm's output.
fn sponge_overwrite(bytes: &[u8]) -> (Vec<[u64; 25]>, [u8; 32]) {
    let mut msg = bytes.to_vec();
    let pad = 136 - (msg.len() % 136); // 1..=136 (never 0 → always a pad block tail)
    let start = msg.len();
    msg.resize(msg.len() + pad, 0);
    msg[start] ^= 0x01;
    *msg.last_mut().unwrap() ^= 0x80;

    let mut state = [0u64; 25];
    let mut inputs = Vec::with_capacity(msg.len() / 136);
    for block in msg.chunks(136) {
        for (l, lane) in block.chunks(8).enumerate() {
            state[l] = u64::from_le_bytes(lane.try_into().unwrap()); // OVERWRITE rate (17 lanes)
        }
        inputs.push(state);
        state = keccakf(&state);
    }
    let mut dig = [0u8; 32];
    for l in 0..4 {
        dig[8 * l..8 * l + 8].copy_from_slice(&state[l].to_le_bytes());
    }
    (inputs, dig)
}

/// Serialize public values as u32-LE bytes (every KoalaBear value is < p < 2^31,
/// so a u32 is lossless): the child's public surface (caps + covered-tx inner
/// PVs) fed to the merge sponge.
fn opvs_bytes(vals: &[Val]) -> Vec<u8> {
    let mut b = Vec::with_capacity(vals.len() * 4);
    for v in vals {
        b.extend_from_slice(&v.as_canonical_u32().to_le_bytes());
    }
    b
}

/// The interior root's 32-byte digest, as `MERGE_ROOT_LIMBS` u16 field limbs
/// (LE), per aggregation-rung1 §2: `root = keccak( keccak(opvsL) ‖ keccak(opvsR) )`.
/// `dL/dR` commit each child's full public surface (⊇ §2's covered-tx digests).
pub(crate) fn merge_root(opvs_l: &[Val], opvs_r: &[Val]) -> Vec<Val> {
    let (_, dl) = sponge_overwrite(&opvs_bytes(opvs_l));
    let (_, dr) = sponge_overwrite(&opvs_bytes(opvs_r));
    let mut m = dl.to_vec();
    m.extend_from_slice(&dr); // 64 bytes → one merge block
    let (_, root) = sponge_overwrite(&m);
    root
        .chunks(2)
        .map(|c| Val::from_u32(u16::from_le_bytes([c[0], c[1]]) as u32))
        .collect()
}

/// The epoch Σfee the interior root exposes, recomputed from the two children's
/// (leaf) opvs — the consumer-side authenticity check for the rider, parallel to
/// `merge_root` for issue #24. `fee` is the TAIL of each child's opvs (M3 fee =
/// PV_FEE..PV_LEN, the inner-PV tail). The interior re-scales inner PVs by
/// `monty_rr` in `outer_pvs`, so the value it binds is `(feeL + feeR)·rr`.
///
/// Honest scope (issue #24 boundary): the interior binds `Σfee` only to the
/// CARRIED pv slots in-circuit — the carried opvs' authenticity is the issue #24
/// consumer invariant (`root == keccak-merge(opvs)`; fee ⊂ opvs). A consumer who
/// runs THIS check against its own verified children's opvs authenticates the
/// exposed Σfee without trusting the prover's carried halves.
pub(crate) fn epoch_fee_sum_expected(opvs_l: &[Val], opvs_r: &[Val]) -> Vec<Val> {
    debug_assert_eq!(opvs_l.len(), opvs_r.len(), "children share the leaf opvs shape");
    let rr = crate::m4gate::monty_rr();
    let base = opvs_l.len() - EPOCH_FEE_LIMBS; // fee is the opvs tail
    (0..EPOCH_FEE_LIMBS).map(|j| (opvs_l[base + j] + opvs_r[base + j]) * rr).collect()
}

/// The child sub-sponge digests `(dL, dR)` as `MERGE_ROOT_LIMBS` u16 limbs each
/// (LE), i.e. `keccak(opvsL)` / `keccak(opvsR)`. The interior circuit captures dL
/// (child-L's last merge perm output) into a carry register and reads dR from
/// child-R's last perm (adjacent to the root perm); both feed the root perm.
pub(crate) fn child_digests(opvs_l: &[Val], opvs_r: &[Val]) -> (Vec<Val>, Vec<Val>) {
    let to_limbs = |d: [u8; 32]| -> Vec<Val> {
        d.chunks(2)
            .map(|c| Val::from_u32(u16::from_le_bytes([c[0], c[1]]) as u32))
            .collect()
    };
    let (_, dl) = sponge_overwrite(&opvs_bytes(opvs_l));
    let (_, dr) = sponge_overwrite(&opvs_bytes(opvs_r));
    (to_limbs(dl), to_limbs(dr))
}

/// The merge lane's permutation INPUT states, in lane order: child-L opvs sponge,
/// child-R opvs sponge, then the root perm (absorbing `dL ‖ dR`). Appended after
/// both children's perms in `build_interior_trace`; the KeccakAir verifies each
/// permutation's keccak-f, and 棒3-2 binds the preimages to the public values.
pub(crate) fn merge_perm_inputs(opvs_l: &[Val], opvs_r: &[Val]) -> Vec<[u64; 25]> {
    let (mut inputs, dl) = sponge_overwrite(&opvs_bytes(opvs_l));
    let (r_inputs, dr) = sponge_overwrite(&opvs_bytes(opvs_r));
    inputs.extend(r_inputs);
    let mut m = dl.to_vec();
    m.extend_from_slice(&dr);
    let (root_inputs, _) = sponge_overwrite(&m);
    inputs.extend(root_inputs);
    inputs
}

/// Two child verification schedules + their outer public values.
///
/// - `distinct == false` (2c): reuse ONE leaf proof for both children. Sufficient
///   for two-child SAT, per-lane tamper binding, and the stage-3 RSS gate, and it
///   halves the ~0.67 s / ~12 GB leaf prove. `opvs_l == opvs_r`, so a single
///   outer-PV set serves both cap comparisons.
/// - `distinct == true` (2d PR-gate): a second, different leaf proof so `L != R`
///   — this catches symmetry / cross-wiring bugs that identical children mask.
pub(crate) fn two_child_schedule(distinct: bool) -> (Schedule, Schedule, Vec<Val>, Vec<Val>) {
    let (leaf_l, opvs_l) = crate::m4treerec::leaf_proof();
    let sched_l = crate::m4treerec::walk_leaf(&leaf_l, &opvs_l);
    if !distinct {
        // Same leaf for both children: re-walk (cheap, ~ms) rather than require
        // Schedule: Clone. The expensive part (the ~12 GB leaf prove) runs once.
        let sched_r = crate::m4treerec::walk_leaf(&leaf_l, &opvs_l);
        return (sched_l, sched_r, opvs_l.clone(), opvs_l);
    }
    // 2d: prove a distinct child (a different M3 witness) so `L != R`.
    let (leaf_r, opvs_r) = crate::m4treerec::leaf_proof_variant();
    let sched_r = crate::m4treerec::walk_leaf(&leaf_r, &opvs_r);
    debug_assert_ne!(opvs_l, opvs_r, "distinct children must have distinct opvs");
    (sched_l, sched_r, opvs_l, opvs_r)
}

/// Interior rectangle shape to prove.
enum Shape {
    /// ONE wide leaf verified at 2^18 — the §7.1 canary. Pins the height-scaling
    /// slope on-axis (same width class + blowup as the 2^16 leaf).
    Single,
    /// TWO distinct wide leaves row-stacked + keccak-merge at 2^19 — the interior
    /// node (the RSS gate's actual subject).
    Two,
}

/// `m4interior` bench mode (M4 step 1 stage 3): the interior peak-RSS gate.
///
/// Proves ONE interior rectangle per invocation (filtered by `--only <name>`),
/// so `/usr/bin/time -l` wrapping the whole process attributes peak RSS to a
/// single config — the measurement protocol of aggregation-rung1 §7.1. The bench
/// prints prove time + fixed proof bytes; **peak RSS is read from the external
/// `/usr/bin/time -l` line**, not measured in-process. This bench does NOT judge
/// against §7.3 — the coordinator does the table lookup on the reported numbers.
///
/// Rows (name = shape/lane-config; b2 is the decided interior lane, listed first).
/// Query counts are B″ (issue #41): interior q80→q86, child leaves q40→q43.
/// (Pre-B″ RSS figures noted below are the q80/q40 measurements; the B″ re-bench
/// refreshes them — see docs/b2prime-run{1,2}.md.)
/// - `single-child/b2/q86/g22/fp16/a16` — the §7.1 canary at the decided lane (measure twice).
/// - `single-child/b4/q43/g22/fp16/a16` — canary at the optional b4 blowup.
/// - `two-child/b2/q86/g22/fp16/a16` — the interior at the DECIDED b2 lane
///   (pre-B″ q80: ~20.5 GB, clean ~4.8 s — the operating point).
/// - `two-child/b4/q43/g22/fp16/a16` — the interior at the optional b4 config
///   (pre-B″ q40: 30.42 GB, compression-noised — run only per §7.1.3; both ~100 bits).
///
/// The child leaves (each ~12 GB peak / ~0.7 s at b4/q43) are proved SERIALLY
/// and ONCE, then dropped — only their recorded `Schedule` + outer PVs survive
/// into the interior prove, so the reported peak RSS is the interior's, never a
/// leaf's (they never coexist in memory with the interior LDE).
pub(crate) fn run_m4interior(power: &str, only: Option<&str>) {
    use std::time::Instant;

    use p3_matrix::Matrix;
    use p3_uni_stark::prove;

    use crate::m4gate::{build_gate_trace, build_interior_trace, GateShape, VerifierGateAir};
    use crate::FriCfg;
    // Re-gated by the re-mint: M4 runs on the legacy non-hiding config.
    use qlab_consensus::legacy::make_legacy_config_with as make_config_with;

    println!("# qumbra-lab M4 step 1 stage 3: interior peak-RSS gate (m4interior)");
    println!();
    crate::print_env(power);
    println!(
        "- shapes: `single-child` = ONE wide leaf verified at 2^18 (the §7.1 canary — \
         pins the height-scaling slope on-axis); `two-child` = TWO DISTINCT wide leaves \
         row-stacked + keccak-merge at 2^19 (the interior node). The lane config is the \
         INTERIOR's own FRI config, independent of the fixed b4/q43 config each child \
         leaf was committed at (child queries q40→q43 per B″, issue #41)."
    );
    println!(
        "- protocol: aggregation-rung1 §7.1. ONE row per process via `--only <name>`; \
         peak RSS from `/usr/bin/time -l` wrapping the whole process (NOT measured \
         in-process), foreground bare run. RSS is the gate; the ≤ 30 s time axis is \
         expected to clear. This bench reports numbers only — the §7.3 verdict is the \
         coordinator's table lookup."
    );
    println!();

    // b2/q86/g22 is the DECIDED interior lane (2026-07-21, Larry — aggregation-rung1
    // §4; query 80→86 per B″ issue #41); b4/q43/g22 stays available as the
    // optional/fallback config (b4 100-bit point matches the leaf lane). Both clear
    // ~100 bits conjectured (make_config_with asserts the capacity proxy: 43·2+22 =
    // 86·1+22 = 108, post-B″/B′) AND the 2197-corrected ceiling (b2/q86 → 100.2,
    // b4/q43 → 101.6). fp16/a16 match the leaf/consensus lane; grind g22 per B′.
    let b4 = FriCfg {
        log_blowup: 2,
        num_queries: 43, // q43 (B″, issue #41 — was q40)
        grind_bits: 22,
        log_final_poly_len: 4,
        max_log_arity: 4,
    };
    let b2 = FriCfg {
        log_blowup: 1,
        num_queries: 86, // q86 (B″, issue #41 — was q80; the decided interior lane)
        grind_bits: 22,
        log_final_poly_len: 4,
        max_log_arity: 4,
    };
    // b2 rows first (the decided primary lane); b4 rows kept as the optional fallback.
    let rows: [(&str, Shape, FriCfg); 4] = [
        ("single-child/b2/q86/g22/fp16/a16", Shape::Single, b2),
        ("single-child/b4/q43/g22/fp16/a16", Shape::Single, b4),
        ("two-child/b2/q86/g22/fp16/a16", Shape::Two, b2),
        ("two-child/b4/q43/g22/fp16/a16", Shape::Two, b4),
    ];

    // Cache the heavy child schedules within a process (each leaf prove has a
    // ~12 GB transient — build once, reuse across any matching lane configs).
    let mut single: Option<(Schedule, Vec<Val>)> = None;
    let mut two: Option<(Schedule, Schedule, Vec<Val>, Vec<Val>)> = None;

    println!("| row | rows | prove s | fixed MB |");
    println!("|---|---|---|---|");
    let mut any = false;
    for (name, shape, cfg) in &rows {
        if let Some(f) = only {
            if !name.contains(f) {
                continue;
            }
        }
        any = true;
        eprintln!("== m4interior: {name} ==");
        let config = make_config_with(cfg);
        // extra_capacity_bits = cfg.log_blowup: reserve LDE capacity up front so
        // the prover's LDE alloc does not realloc mid-prove (m4skel's "late reserve
        // = 3x RSS" lesson) — essential for an accurate peak-RSS reading.
        let (trace, opvs, air) = match shape {
            Shape::Single => {
                if single.is_none() {
                    eprintln!(
                        "   proving ONE child leaf (b4/q43, ~12 GB transient, freed before \
                         the interior prove)..."
                    );
                    let (leaf, opvs) = crate::m4treerec::leaf_proof();
                    let sched = crate::m4treerec::walk_leaf(&leaf, &opvs);
                    drop(leaf); // free the ~780 KB proof; the schedule is what the interior needs
                    single = Some((sched, opvs));
                }
                let (sched, opvs) = single.as_ref().unwrap();
                let (trace, meta) =
                    build_gate_trace(sched, opvs, &GateShape::wide(), cfg.log_blowup);
                (trace, meta.opvs, VerifierGateAir::new_with_shape(GateShape::wide()))
            }
            Shape::Two => {
                if two.is_none() {
                    eprintln!(
                        "   proving TWO DISTINCT child leaves (serial, ~12 GB each, both \
                         freed before the interior prove)..."
                    );
                    let (sl, sr, ol, or) = two_child_schedule(true);
                    two = Some((sl, sr, ol, or));
                }
                let (sl, sr, ol, or) = two.as_ref().unwrap();
                let (trace, meta) =
                    build_interior_trace(sl, sr, ol, or, &GateShape::wide(), cfg.log_blowup);
                (trace, meta.opvs, VerifierGateAir::new_interior())
            }
        };
        let n_rows = trace.height();
        let t = Instant::now();
        let proof = prove(&config, &air, trace, &opvs);
        let prove_s = t.elapsed().as_secs_f64();
        let fixed_mb =
            bincode::serialize(&proof).expect("bincode") .len() as f64 / (1024.0 * 1024.0);
        println!("| {name} | {n_rows} (2^{}) | {prove_s:.2} | {fixed_mb:.2} |", n_rows.trailing_zeros());
    }
    if !any {
        eprintln!("(no row matched --only; nothing proved)");
    }
    println!();
    println!(
        "Peak RSS: read `maximum resident set size` from the `/usr/bin/time -l` line \
         wrapping THIS process (one `--only` row per launch). §7.1: any run with nonzero \
         swap-ins / pageouts is disqualified — close idle memory tasks and rerun. \
         Reproduce each headline row twice. Verdict = coordinator's §7.3 table lookup on \
         the two-child b4 peak RSS (measured, or validated-extrapolated per §7.1.3)."
    );
}
