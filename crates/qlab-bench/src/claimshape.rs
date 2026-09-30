//! F1 (lab #756): the bridge's claim circuit measured — `claimshape` mode.
//!
//! ```text
//! qlab-bench claimshape --layout                            # census, no prove
//! qlab-bench claimshape --lane b4|b16 [--pcs hiding|nonhiding] [--power <note>]
//! ```
//!
//! `--layout` prints the geometry read off the verifier's AIR — width (off a
//! generated trace), perms, height, max constraint degree, constraint count,
//! PV length — and allocates one 2^17 trace. `--lane` runs the fixture claim
//! (`qlab_l2::fixture::claim`) through the real prover `RUNS` times at one
//! lane (b4 = the L2 lane `qlab_l2::L2_CFG_PROVISIONAL`, the ruled one; b16 =
//! the L1 point `CONSENSUS_CFG`, for comparison) and prints best-of prove and
//! verify, and the proof's bytes. One lane per process: wrap the RELEASE
//! binary in `/usr/bin/time -l` (as `l2shape`); peak footprint is that
//! process's. The per-phase heap account is `zkpeak --case claim --phases`.
//!
//! The negatives (N1–N10, the fee) run on the acceptance lane as
//! `qlab-air`'s `claim::tests`; this mode does not repeat them.

use p3_air::symbolic::{get_max_constraint_degree, get_symbolic_constraints, AirLayout};
use p3_air::BaseAir;
use p3_matrix::Matrix;
use qlab_air::claim::{ClaimAir, CLAIM_LOG_HEIGHT, CLAIM_PERMS};
use qlab_air::l2::ROWS_PER_PERM;
use qlab_consensus::CONSENSUS_CFG;
use qlab_l2::L2_CFG_PROVISIONAL as L2_CFG;

use crate::l2shape::{bench_lane, PcsKind};
use crate::{FriCfg, Val, RUNS};

pub(crate) fn run_claimshape(power: &str, layout: bool, lane: Option<&str>, pcs: PcsKind) {
    println!("# qumbra-lab F1 claimshape — the claim circuit (lab #756)");
    println!();
    crate::print_env(power);
    let air = qlab_l2::claim::verifier_air_claim();
    if layout {
        let deg = get_max_constraint_degree::<Val, _>(&air, AirLayout::from_air::<Val>(&air));
        let constraints = get_symbolic_constraints::<Val, _>(&air, AirLayout::from_air::<Val>(&air)).len();
        let width = air.generate_trace::<Val>(0).width();
        let height = 1usize << CLAIM_LOG_HEIGHT;
        println!("| width | perms | rows used | height | max degree | quotient chunks | constraints | PVs |");
        println!("|---|---|---|---|---|---|---|---|");
        println!(
            "| {width} | {CLAIM_PERMS} | {} | 2^{CLAIM_LOG_HEIGHT} = {height} | {deg} | {} | {constraints} | {} |",
            CLAIM_PERMS * ROWS_PER_PERM,
            (deg.max(2) - 1).next_power_of_two(),
            <ClaimAir as BaseAir<Val>>::num_public_values(&air),
        );
        println!();
    }
    let Some(lane) = lane else { return };
    let (name, cfg): (&str, FriCfg) = match lane {
        "b4" => ("b4/q45/g22/fp16/a16 — the L2 lane (frozen, lab #785 F5-2)", L2_CFG),
        "b16" => ("b16/q21/g22/fp16/a16 — the L1 point (comparison)", CONSENSUS_CFG),
        other => {
            eprintln!("claimshape: unknown --lane `{other}`; expected b4|b16");
            std::process::exit(2);
        }
    };
    let inst = qlab_l2::fixture::claim();
    let pvs = qlab_l2::public_values(&inst.pvs);
    let (prove_ms, verify_ms, pc_bytes, fixed_bytes, width) =
        bench_lane(&inst.air, &pvs, &cfg, pcs, |lb| inst.air.generate_trace::<Val>(lb));
    println!("- lane: {name}; PCS: {pcs:?}; best of {RUNS}");
    println!();
    println!("| lane | width | prove ms | verify ms | proof bytes (postcard) | wire bytes (bincode fixint) |");
    println!("|---|---|---|---|---|---|");
    println!("| {lane} | {width} | {prove_ms:.0} | {verify_ms:.1} | {pc_bytes} | {fixed_bytes} |");
    println!();
    println!("Peak footprint: read it from the `/usr/bin/time -l` wrapping THIS process (one lane per process).");
}
