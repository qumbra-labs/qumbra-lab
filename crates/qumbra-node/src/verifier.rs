//! The node's transaction verifier (M10-T0-4, issue #68 item 1).
//!
//! ## Real verifier is the DEFAULT (the named M11 gate, closed early)
//! [`ConsensusVerifier`] is the real M3 verifier: it decodes a [`TxEntry`]'s
//! serialized proof and runs [`qlab_consensus::verify_proof`] against the frozen
//! `CONSENSUS_CFG` (b16/q21/g22/fp16/a16). It is the **default** the binary
//! injects — PR #65 recorded "the real verifier (`qlab_consensus::verify_proof`)
//! becomes the default before any public net" as a named M11 entry gate; this
//! module closes it. A T0 net mines coinbase-only blocks, so on T0 the verifier
//! is never actually exercised — but the default is now *real*, not a stand-in.
//!
//! [`DevnetRehearsalVerifier`] (accepts everything) is retained as an **explicit
//! opt-in** behind the `--rehearsal-verifier` flag, logged loudly at startup
//! ([`select_verifier`]). [`NodeVerifier`] is the single injected type that
//! dispatches between the two at runtime (so [`crate::run::RunningNode`] stays
//! monomorphic over one `V`).
//!
//! ## How the real verifier bridges `TxEntry` → `verify_proof`
//! The consensus statement is the fixed-shape 2×2 bucket. A `TxEntry` carries
//! opaque `proof` bytes + a declared public surface ([`TxPublic`]: anchor · 2
//! nullifiers · 2 commitments · fee). The verifier:
//!
//! 1. rejects anything that is not a 2×2 bucket with exactly 2 nf + 2 cm (the
//!    only shape the consensus AIR proves);
//! 2. reconstructs the public-value vector **from the declared surface** via
//!    [`qlab_air::narrow::pv_vec`] — so the proof is bound to the *declared*
//!    anchor/nullifiers/commitments/fee. A tx that proves a different surface
//!    than it declares fails to verify (that binding is the point);
//! 3. deserializes the proof with bincode fixint — the consensus wire
//!    (protocol-spec §4; the same encoding `qlab-consensus` pins at 145,609 B);
//! 4. verifies against a **canonical, witness-free AIR**. The AIR's constraints
//!    read only the structural program ring + trace + public values — never
//!    `slot_witness` or `self.fee` — so any 2×2 bucket instance yields the exact
//!    AIR the prover used; we overwrite its `.pvs` with the declared surface.
//!
//! Verification cost is ms-class (M4 census: 2,336 keccak-f/proof native).

use qlab_air::narrow::{build_bucket, pv_vec, BucketInstance, TxInput, TxOutput};
use qlab_consensus::{public_values, verify_proof, Config, Proof, LOG_HEIGHT};
use qlab_devnet::body::{TxEntry, TxPublic, TxVerifier};
use qlab_devnet::fees::ArityBucket;
use qlab_devnet::header::Hash32;

pub use crate::run::DevnetRehearsalVerifier;

/// The real M3 consensus verifier: decodes a tx proof and checks it against the
/// frozen `CONSENSUS_CFG` via [`qlab_consensus::verify_proof`]. This is the
/// default the binary injects (see the module doc). Zero-sized; the canonical
/// verifier AIR is built per call (a handful of keccak-f — negligible next to
/// the STARK verify, and never called at all on a coinbase-only T0).
#[derive(Clone, Copy, Debug, Default)]
pub struct ConsensusVerifier;

impl TxVerifier for ConsensusVerifier {
    fn verify_tx(&self, entry: &TxEntry) -> bool {
        // (1)+(2) Only the fixed-shape 2×2 bucket is a consensus statement;
        // reconstruct its public values from the DECLARED surface (binds the
        // proof to what the tx claims).
        let pvs_u32 = match pvs_u32_from_public(&entry.public) {
            Some(p) => p,
            None => return false,
        };
        // (3) Decode the proof (bincode fixint = the consensus wire).
        let proof: Proof<Config> = match bincode::deserialize(&entry.proof) {
            Ok(p) => p,
            Err(_) => return false,
        };
        // (4) Verify against the canonical witness-free AIR with the declared PVs.
        let mut inst = canonical_bucket_instance();
        inst.pvs = pvs_u32;
        let pvs = public_values(&inst);
        verify_proof(&inst, &pvs, &proof)
    }
}

/// Which transaction verifier the node runs. A single injected type so
/// [`crate::run::RunningNode`] is monomorphic over one `V` while the choice is a
/// runtime flag.
#[derive(Clone, Debug)]
pub enum NodeVerifier {
    /// The real M3 consensus verifier (default).
    Consensus(ConsensusVerifier),
    /// The rehearsal stand-in (accepts everything) — `--rehearsal-verifier`.
    Rehearsal(DevnetRehearsalVerifier),
}

impl TxVerifier for NodeVerifier {
    fn verify_tx(&self, entry: &TxEntry) -> bool {
        match self {
            NodeVerifier::Consensus(v) => v.verify_tx(entry),
            NodeVerifier::Rehearsal(v) => v.verify_tx(entry),
        }
    }
}

/// Choose the injected verifier from the `--rehearsal-verifier` flag and return
/// it alongside the **startup log line** the binary must print. The rehearsal
/// path logs a loud, unmissable warning (issue #68 acceptance: "rehearsal flag
/// logs loudly"); the default path states the real verifier is active.
pub fn select_verifier(rehearsal: bool) -> (NodeVerifier, String) {
    if rehearsal {
        (
            NodeVerifier::Rehearsal(DevnetRehearsalVerifier),
            "⚠️  REHEARSAL VERIFIER ACTIVE (--rehearsal-verifier): transaction proofs are \
             NOT cryptographically verified — every tx proof is accepted. Rehearsal/devnet \
             ONLY; NEVER run this on a public network."
                .to_string(),
        )
    } else {
        (
            NodeVerifier::Consensus(ConsensusVerifier),
            "verifier: real M3 consensus verifier active \
             (qlab_consensus::verify_proof, frozen CONSENSUS_CFG b16/q21/g22/fp16/a16)."
                .to_string(),
        )
    }
}

/// Reconstruct the bucket public-value vector (u32 chunks, PV_* layout) from a
/// tx's declared public surface. `None` for anything that is not a 2×2 bucket
/// with exactly 2 nullifiers + 2 commitments — the only shape the consensus AIR
/// proves.
fn pvs_u32_from_public(p: &TxPublic) -> Option<Vec<u32>> {
    if p.bucket != ArityBucket::TwoByTwo || p.nullifiers.len() != 2 || p.commitments.len() != 2 {
        return None;
    }
    Some(pv_vec(
        &digest_words(&p.anchor),
        &digest_words(&p.nullifiers[0]),
        &digest_words(&p.nullifiers[1]),
        &digest_words(&p.commitments[0]),
        &digest_words(&p.commitments[1]),
        p.fee,
    ))
}

/// A 32-byte digest → `[u64; 4]` lane-major little-endian — the inverse of the
/// `h32` convention the node uses to expose circuit digests as `Hash32`.
fn digest_words(h: &Hash32) -> [u64; 4] {
    core::array::from_fn(|i| u64::from_le_bytes(h[i * 8..i * 8 + 8].try_into().expect("8 bytes")))
}

/// A canonical 2×2-bucket instance whose `.air` is exactly the AIR the prover
/// used. The AIR's constraints read only the structural program ring, trace, and
/// public values — never `slot_witness` or `self.fee` — so the specific witness
/// values (and the balance) are irrelevant to verification; the caller overwrites
/// `.pvs` with the tx's declared surface.
fn canonical_bucket_instance() -> BucketInstance {
    let inputs = [
        TxInput { sk: [1, 2, 3, 4], value: 3, rho: [5, 6, 7, 8], rseed: [9, 10, 11, 12], d: [0, 0] },
        TxInput { sk: [13, 14, 15, 16], value: 2, rho: [17, 18, 19, 20], rseed: [21, 22, 23, 24], d: [0, 0] },
    ];
    let outputs = [
        TxOutput { value: 3, rkm: [1; 4], rho: [2; 4], rseed: [3; 4] },
        TxOutput { value: 1, rkm: [4; 4], rho: [5; 4], rseed: [6; 4] },
    ];
    // 3 + 2 = 3 + 1 + fee(1) — balanced (immaterial to the AIR shape, kept tidy).
    build_bucket(LOG_HEIGHT, &inputs, &outputs, 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_consensus::prove_bucket;

    /// `[u64;4]` digest → 32 bytes (lane-major LE) — the node's `h32` convention,
    /// the exact inverse of [`digest_words`].
    fn h32(x: &[u64; 4]) -> Hash32 {
        let mut o = [0u8; 32];
        for i in 0..4 {
            o[i * 8..i * 8 + 8].copy_from_slice(&x[i].to_le_bytes());
        }
        o
    }

    /// A balanced 2-in/2-out bucket (50k+30k = 60k+19k + 1k fee) — the
    /// qlab-consensus reference instance.
    fn balanced_bucket() -> BucketInstance {
        let inputs = [
            TxInput { sk: [1, 2, 3, 4], value: 50_000, rho: [5, 6, 7, 8], rseed: [9, 10, 11, 12], d: [0, 0] },
            TxInput { sk: [13, 14, 15, 16], value: 30_000, rho: [17, 18, 19, 20], rseed: [21, 22, 23, 24], d: [0, 0] },
        ];
        let outputs = [
            TxOutput { value: 60_000, rkm: [1; 4], rho: [2; 4], rseed: [3; 4] },
            TxOutput { value: 19_000, rkm: [4; 4], rho: [5; 4], rseed: [6; 4] },
        ];
        build_bucket(LOG_HEIGHT, &inputs, &outputs, 1_000)
    }

    /// Build the `TxEntry` a real 2×2 tx would carry: the bincode-encoded proof
    /// (the consensus wire) + the public surface derived from the instance.
    fn real_tx_entry(inst: &BucketInstance, proof: &Proof<Config>) -> TxEntry {
        TxEntry {
            proof: bincode::serialize(proof).expect("serialize proof"),
            public: TxPublic {
                anchor: h32(&inst.anchor),
                nullifiers: vec![h32(&inst.nf[0]), h32(&inst.nf[1])],
                commitments: vec![h32(&inst.cm_out[0]), h32(&inst.cm_out[1])],
                bucket: ArityBucket::TwoByTwo,
                fee: 1_000,
            },
        }
    }

    #[test]
    fn real_verifier_accepts_a_real_m3_proof() {
        // The round-trip that pins the PV-reconstruction limb convention: a real
        // proof, wired exactly as a tx would carry it, verifies through the
        // decode → reconstruct-pvs → canonical-AIR path.
        let inst = balanced_bucket();
        let (_pvs, proof) = prove_bucket(&inst);
        let entry = real_tx_entry(&inst, &proof);
        assert!(ConsensusVerifier.verify_tx(&entry), "real proof must verify via ConsensusVerifier");
        // And via the dispatched default.
        let (v, log) = select_verifier(false);
        assert!(matches!(v, NodeVerifier::Consensus(_)));
        assert!(log.contains("real M3 consensus verifier"));
        assert!(v.verify_tx(&entry));
    }

    #[test]
    fn real_verifier_rejects_a_tampered_public_surface() {
        // Same proof, but the declared surface lies: flip a byte of a declared
        // nullifier. The reconstructed PVs no longer match what the proof binds,
        // so verification fails (the declared-surface binding).
        let inst = balanced_bucket();
        let (_pvs, proof) = prove_bucket(&inst);
        let mut entry = real_tx_entry(&inst, &proof);
        entry.public.nullifiers[0][0] ^= 0x01;
        assert!(!ConsensusVerifier.verify_tx(&entry), "tampered nullifier must fail");

        // Tampered fee likewise (fee is a public value).
        let mut entry2 = real_tx_entry(&inst, &proof);
        entry2.public.fee += 1;
        assert!(!ConsensusVerifier.verify_tx(&entry2), "tampered fee must fail");
    }

    #[test]
    fn real_verifier_rejects_garbage_and_wrong_shape() {
        let inst = balanced_bucket();
        let (_pvs, proof) = prove_bucket(&inst);

        // Undecodable proof bytes → reject (no panic).
        let mut entry = real_tx_entry(&inst, &proof);
        entry.proof = vec![0xAB; 16];
        assert!(!ConsensusVerifier.verify_tx(&entry), "garbage proof bytes must fail");

        // Non-2×2 shape (wrong nullifier count) → reject before any decode.
        let mut entry2 = real_tx_entry(&inst, &proof);
        entry2.public.nullifiers.truncate(1);
        assert!(!ConsensusVerifier.verify_tx(&entry2), "non-2×2 shape must fail");

        // A non-TwoByTwo bucket → reject (AIR only proves 2×2).
        let mut entry3 = real_tx_entry(&inst, &proof);
        entry3.public.bucket = ArityBucket::FourByFour;
        assert!(!ConsensusVerifier.verify_tx(&entry3), "non-2×2 bucket must fail");
    }

    #[test]
    fn rehearsal_flag_is_opt_in_and_logs_loudly() {
        // Default = real verifier; log states so and carries NO rehearsal warning.
        let (def, deflog) = select_verifier(false);
        assert!(matches!(def, NodeVerifier::Consensus(_)));
        assert!(deflog.contains("real M3 consensus verifier"));
        assert!(!deflog.to_uppercase().contains("REHEARSAL"));

        // Opt-in = rehearsal; log is a loud, unmissable warning.
        let (reh, rehlog) = select_verifier(true);
        assert!(matches!(reh, NodeVerifier::Rehearsal(_)));
        assert!(rehlog.contains("REHEARSAL VERIFIER ACTIVE"));
        assert!(rehlog.contains("NOT cryptographically verified"));
        assert!(rehlog.contains("NEVER"));

        // The rehearsal verifier accepts anything (it is the labelled stand-in).
        let entry = TxEntry {
            proof: vec![],
            public: TxPublic {
                anchor: [0; 32],
                nullifiers: vec![[0; 32], [1; 32]],
                commitments: vec![[2; 32], [3; 32]],
                bucket: ArityBucket::TwoByTwo,
                fee: 1_000,
            },
        };
        assert!(reh.verify_tx(&entry), "rehearsal stand-in accepts everything");
        // …while the real default rejects the same bytes (no real proof).
        assert!(!def.verify_tx(&entry), "real verifier rejects a bogus proof");
    }
}
