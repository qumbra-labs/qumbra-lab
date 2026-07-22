//! `qlab-demo`: run the end-to-end Qumbra payment loop and print a transcript.
use qlab_demo::run_loop;

fn main() {
    println!("== Qumbra end-to-end wallet demo ==\n");
    let r = run_loop(0xA11CE_B0B);
    for line in &r.transcript {
        println!("  {line}");
    }
    println!("\n-- summary --");
    println!(
        "  sent = {}  detected = {}  (match: {})",
        r.sent_value,
        r.detected_value,
        r.sent_value == r.detected_value
    );
    println!("  cm seam holds: {}", r.cm_seam_holds);
    println!(
        "  proofs generated: {} ({})",
        r.proofs_generated,
        r.prove_secs.iter().map(|s| format!("{s:.2}s")).collect::<Vec<_>>().join(" + ")
    );
    println!(
        "  scan: {} compact bytes, {} matched fetch(es), {} decoy fetch(es), {} note(s) found",
        r.scan_stats.compact_bytes,
        r.scan_stats.matched_fetches,
        r.scan_stats.decoy_fetches,
        r.scan_stats.notes_found
    );
    println!(
        "  double-spend rejected (cross-block / within-block): {} / {}",
        r.double_spend_rejected, r.within_block_double_spend_rejected
    );
    println!("  spend finalized: {}", r.spend_finalized);
    println!("  supply minted: {}  consistent: {}", r.supply_minted, r.supply_consistent);
    println!("  wall-clock: {:.2} s", r.wall_secs);
    assert!(
        r.detected_value == r.sent_value && r.cm_seam_holds && r.spend_finalized && r.supply_consistent,
        "invariants must hold"
    );
}
