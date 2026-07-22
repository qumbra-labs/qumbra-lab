//! End-to-end invariant assertions for the Qumbra payment loop.
use qlab_demo::scenario::run_loop;

#[test]
fn end_to_end_payment_loop_holds_all_invariants() {
    let r = run_loop(0xA11CE_B0B);

    // (1) Bob detects exactly the value Alice sent.
    assert_eq!(r.detected_value, r.sent_value, "detected == sent");
    assert!(r.sent_value > 0);

    // (6) The cm seam: on-chain commitment == compact-entry cm == Note::commitment().
    assert!(r.cm_seam_holds, "cm byte-identical across proof / wire / note");

    // (2) Two real M3 proofs were generated and verified in-block.
    assert_eq!(r.proofs_generated, 2);
    assert_eq!(r.prove_secs.len(), 2);

    // (3) Double-spend: persistent-set rejection + native within-block rejection.
    assert!(r.double_spend_rejected, "cross-block double-spend rejected");
    assert!(r.within_block_double_spend_rejected, "within-block double-spend rejected");

    // (4) Bob's spend block finalizes under the committee quorum.
    assert!(r.spend_finalized, "spend block finalized");

    // (5) Supply invariant.
    assert!(r.supply_consistent, "supply/coinbase counter consistent across the loop");
}
