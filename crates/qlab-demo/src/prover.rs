//! The consensus prover config + wrappers, now sourced from `qlab-consensus`.
//!
//! Issue #38 (F1 from this very demo, PR #37) extracted the consensus
//! `StarkConfig` + `CONSENSUS_CFG` + prove/verify wrappers into the shared
//! `qlab-consensus` crate. This module used to *reconstruct* that config by hand
//! and value-lock the copy; it now simply re-exports the single source, so the
//! demo, `qlab-bench`, and the `qlab-node` stack are guaranteed byte-identical
//! (the 145,609-B wire regression lives in `qlab-consensus`).
//!
//! The one thing that stays here is [`live_witness`]: the wallet/prover step that
//! fetches a spend input's membership witness from a live commitment tree. It
//! depends on `qlab-cbserver`'s `CommitmentTree`, which `qlab-consensus`
//! deliberately does not (that crate is prover-config-only, no chain state).

pub use qlab_consensus::{
    make_config, make_config_with, prove_bucket, public_values, verify_proof, Config, FriCfg,
    Proof, Val, CONSENSUS_CFG, LOG_HEIGHT,
};

use qlab_air::narrow::{derive_input, MerkleWitness, TxInput};
use qlab_cbserver::tree::CommitmentTree;

/// The wallet/prover live-tree fetch step (issue #39): turn a spend input into
/// its membership witness against the live commitment tree. Computes the input
/// note's leaf commitment, locates it in `tree`, fetches the depth-32 auth path,
/// and cross-checks it folds to the finalized `anchor` before proving — so a
/// stale/forged anchor is caught locally instead of only at verify. Panics if
/// the note is not in the tree or the witness does not resolve to `anchor`.
pub fn live_witness(
    tree: &CommitmentTree,
    count: u64,
    anchor: [u64; 4],
    input: &TxInput,
) -> MerkleWitness {
    let (_, _, cm) = derive_input(input);
    let pos = tree
        .position_of(&cm)
        .expect("spend input's note commitment must be a leaf of the live tree");
    let witness = tree.auth_path(pos, count);
    assert_eq!(
        witness.fold_root(&cm),
        anchor,
        "live-tree witness must resolve to the finalized anchor"
    );
    witness
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Issue #39: a REAL proof against a REAL live commitment tree. The two
    /// input notes sit at arbitrary, non-adjacent positions (interleaved with
    /// filler leaves) of one tree; both witnesses fetched from the live tree
    /// resolve to the SAME root, which becomes the anchor. The proof verifies —
    /// build_bucket no longer fabricates the membership tree. (The consensus
    /// config + byte-identical wire are tested in `qlab-consensus`; this test is
    /// the demo-specific live-tree integration the shared crate cannot express.)
    #[test]
    fn real_proof_against_live_tree() {
        use qlab_air::narrow::{build_bucket_with_witnesses, derive_input, TxInput, TxOutput};
        use qlab_cbserver::tree::CommitmentTree;

        let inputs = [
            TxInput { sk: [1, 2, 3, 4], value: 50_000, rho: [5, 6, 7, 8], rseed: [9, 10, 11, 12], d: [7, 0] },
            TxInput { sk: [13, 14, 15, 16], value: 30_000, rho: [17, 18, 19, 20], rseed: [21, 22, 23, 24], d: [0, 9] },
        ];
        let outputs = [
            TxOutput { value: 60_000, rkm: [1; 4], rho: [2; 4], rseed: [3; 4] },
            TxOutput { value: 19_000, rkm: [4; 4], rho: [5; 4], rseed: [6; 4] },
        ];
        let (_, _, cm0) = derive_input(&inputs[0]);
        let (_, _, cm1) = derive_input(&inputs[1]);

        // A live tree: fillers, then the two spent notes at positions 2 and 5.
        let mut tree = CommitmentTree::new();
        let filler = |i: u64| [i.wrapping_mul(0x9e37_79b9), i + 1, i + 2, i + 3];
        tree.append(filler(1));
        tree.append(filler(2));
        let p0 = tree.append(cm0); // position 2
        tree.append(filler(3));
        tree.append(filler(4));
        let p1 = tree.append(cm1); // position 5
        tree.append(filler(5));
        let count = tree.len();
        let anchor = tree.root_at(count);
        assert_eq!((p0, p1), (2, 5));

        // Fetch each witness from the live tree (the wallet/prover step).
        let w0 = live_witness(&tree, count, anchor, &inputs[0]);
        let w1 = live_witness(&tree, count, anchor, &inputs[1]);
        // Both spent notes anchor to the one live root.
        assert_eq!(w0.fold_root(&cm0), anchor);
        assert_eq!(w1.fold_root(&cm1), anchor);

        let inst = build_bucket_with_witnesses(LOG_HEIGHT, &inputs, &outputs, 1_000, &[w0, w1], anchor);
        assert_eq!(inst.anchor, anchor, "proof anchors to the live-tree root");
        let (pvs, proof) = prove_bucket(&inst);
        assert!(verify_proof(&inst, &pvs, &proof), "real proof against live tree must verify");
    }
}
