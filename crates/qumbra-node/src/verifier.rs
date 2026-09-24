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
//!    (protocol-spec §4; the same encoding `qlab-consensus` pins at 148,625 B);
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
        // Lab #712: an L2 transaction is never an L1 one — refused before its
        // proof is read (the L1 wire cannot even carry the surface).
        if entry.l2 != qlab_devnet::annulet::L2_SURFACE_ABSENT {
            return false;
        }
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

/// **The L2 transaction verifier** (lab #712, B4): every Annulet
/// transaction's proof is verified against its **declared** public surface,
/// as [`ConsensusVerifier`] does for the L1 — under `qlab_l2`'s canonical
/// witness-free AIRs and its one config site, `make_config_l2()`.
///
/// **No wire-byte literal.** The lane is provisional (lab #704), so the proof
/// is judged by what the config implies: a strict decode (fixint,
/// reject-trailing, bounded by the input), then its structure — trace height
/// `LOG_HEIGHT_{S,P}`, `num_queries` query proofs, a `2^log_final_poly_len`
/// final polynomial — each read from `qlab_l2`. That structure is also what
/// separates an L1 proof (the L1 lane, 2^LOG_HEIGHT) from an L2 one: both
/// decode as `Proof<Config>`.
#[derive(Clone, Copy, Debug, Default)]
pub struct L2Verifier;

/// Why [`L2Verifier`] refused a transaction — by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum L2VerifyError {
    /// No L2 surface: an L1 transaction.
    NoSurface,
    /// The surface bytes are not canonical.
    SurfaceMalformed,
    /// Not the 2×2 bucket (2 nullifiers, 2 commitments) — shapes S and P.
    NotTwoByTwo,
    /// A registry write (shape R) that is not 1 nullifier / 1 commitment
    /// under the 2×2 bucket declaration (lab #728 Q2).
    RegistryWriteArity,
    /// The proof bytes do not decode strictly.
    ProofDecode,
    /// The decoded proof's structure is not the one the L2 config implies
    /// for this shape.
    ProofShape { what: &'static str, got: usize, want: usize },
    /// The proof does not verify against the declared surface.
    ProofInvalid,
}

impl L2Verifier {
    /// Judge one transaction, naming the refusal.
    pub fn check(&self, entry: &TxEntry) -> Result<(), L2VerifyError> {
        use qlab_devnet::annulet::{L2ShapeTag, L2Surface};
        let surface = match L2Surface::decode(&entry.l2) {
            Ok(Some(s)) => s,
            Ok(None) => return Err(L2VerifyError::NoSurface),
            Err(_) => return Err(L2VerifyError::SurfaceMalformed),
        };
        let p = &entry.public;
        // Lab #728 Q2: every Annulet surface declares the 2×2 bucket; the
        // shape gates the counts.
        let arity_ok = p.bucket == ArityBucket::TwoByTwo
            && match surface.shape {
                L2ShapeTag::S | L2ShapeTag::P => p.nullifiers.len() == 2 && p.commitments.len() == 2,
                L2ShapeTag::R => p.nullifiers.len() == 1 && p.commitments.len() == 1,
            };
        if !arity_ok {
            return Err(match surface.shape {
                L2ShapeTag::S | L2ShapeTag::P => L2VerifyError::NotTwoByTwo,
                L2ShapeTag::R => L2VerifyError::RegistryWriteArity,
            });
        }
        let proof = decode_proof_strict(&entry.proof)?;
        let (anchor, root) = (digest_words(&p.anchor), digest_words(&surface.registry_root));
        if surface.shape == L2ShapeTag::R {
            // Shape R (lab #728): one input, one output, the write's roots and
            // the written slot (the new leaf's asset lane). The leaf itself is
            // not a public value — the node binds it by applying it to its own
            // tree and requiring `new_root`.
            let Some(w) = surface.write else { return Err(L2VerifyError::SurfaceMalformed) };
            check_proof_shape(&proof, qlab_l2::LOG_HEIGHT_R)?;
            let pvs = qlab_l2::pv_vec_r(
                &anchor,
                &digest_words(&p.nullifiers[0]),
                &digest_words(&p.commitments[0]),
                p.fee,
                &root,
                &digest_words(&w.new_root),
                w.asset(),
            );
            let verified = qlab_l2::verify_r(&qlab_l2::public_values(&pvs), &proof);
            return verified.then_some(()).ok_or(L2VerifyError::ProofInvalid);
        }
        let (nf1, nf2, cm1, cm2) = (
            digest_words(&p.nullifiers[0]),
            digest_words(&p.nullifiers[1]),
            digest_words(&p.commitments[0]),
            digest_words(&p.commitments[1]),
        );
        let verified = match (surface.shape, surface.vpublic) {
            (L2ShapeTag::S, None) => {
                check_proof_shape(&proof, qlab_l2::LOG_HEIGHT_S)?;
                let pvs = qlab_l2::pv_vec_s(&anchor, &nf1, &nf2, &cm1, &cm2, p.fee, &root);
                qlab_l2::verify_s(&qlab_l2::public_values(&pvs), &proof)
            }
            (L2ShapeTag::P, Some(terms)) => {
                check_proof_shape(&proof, qlab_l2::LOG_HEIGHT_P)?;
                let pvs = qlab_l2::pv_vec_p(&anchor, &nf1, &nf2, &cm1, &cm2, p.fee, &root, &vpublic(&terms), &vpublic_assets(&terms));
                qlab_l2::verify_p(&qlab_l2::public_values(&pvs), &proof)
            }
            // A canonical surface pairs S with no vPublic and P with some; R
            // returned above.
            (L2ShapeTag::S, Some(_)) | (L2ShapeTag::P, None) | (L2ShapeTag::R, _) => {
                return Err(L2VerifyError::SurfaceMalformed)
            }
        };
        verified.then_some(()).ok_or(L2VerifyError::ProofInvalid)
    }
}

impl TxVerifier for L2Verifier {
    fn verify_tx(&self, entry: &TxEntry) -> bool {
        self.check(entry).is_ok()
    }
}

/// A surface's vPublic terms as the P AIR's public values read them.
fn vpublic(terms: &[qlab_devnet::annulet::VPublicTerm; 2]) -> [qlab_l2::VPublic; 2] {
    terms.map(|t| qlab_l2::VPublic { redeem: t.redeem, amount: t.amount })
}

/// The asset each vPublic row reveals.
fn vpublic_assets(terms: &[qlab_devnet::annulet::VPublicTerm; 2]) -> [u64; 2] {
    terms.map(|t| t.asset as u64)
}

/// Decode a proof strictly: fixint (the encoding `bincode::serialize`
/// writes), reject-trailing, and never more than the input could hold.
fn decode_proof_strict(bytes: &[u8]) -> Result<Proof<Config>, L2VerifyError> {
    use bincode::Options;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(bytes.len() as u64)
        .deserialize(bytes)
        .map_err(|_| L2VerifyError::ProofDecode)
}

/// The structure the L2 config implies for a proof at `log_height`, each
/// quantity read from `qlab_l2` (no literal here).
fn check_proof_shape(proof: &Proof<Config>, log_height: usize) -> Result<(), L2VerifyError> {
    let cfg = qlab_l2::L2_CFG_PROVISIONAL;
    let checks = [
        ("degree_bits", proof.degree_bits, log_height),
        ("query_proofs", proof.opening_proof.query_proofs.len(), cfg.num_queries),
        ("final_poly", proof.opening_proof.final_poly.len(), 1usize << cfg.log_final_poly_len),
    ];
    for (what, got, want) in checks {
        if got != want {
            return Err(L2VerifyError::ProofShape { what, got, want });
        }
    }
    Ok(())
}

/// Which transaction verifier the node runs. A single injected type so
/// [`crate::run::RunningNode`] is monomorphic over one `V` while the choice is a
/// runtime flag.
#[derive(Clone, Debug)]
pub enum NodeVerifier {
    /// The real M3 consensus verifier (the L1 default).
    Consensus(ConsensusVerifier),
    /// The real L2 verifier (the Annulet default, lab #712).
    L2(L2Verifier),
    /// The rehearsal stand-in (accepts everything) — `--rehearsal-verifier`.
    Rehearsal(DevnetRehearsalVerifier),
}

impl TxVerifier for NodeVerifier {
    fn verify_tx(&self, entry: &TxEntry) -> bool {
        match self {
            NodeVerifier::Consensus(v) => v.verify_tx(entry),
            NodeVerifier::L2(v) => v.verify_tx(entry),
            NodeVerifier::Rehearsal(v) => v.verify_tx(entry),
        }
    }
}

/// Choose the injected verifier from the `--rehearsal-verifier` flag and return
/// it alongside the **startup log line** the binary must print. The rehearsal
/// path logs a loud, unmissable warning (issue #68 acceptance: "rehearsal flag
/// logs loudly"); the default path states the real verifier is active.
///
/// Lab #712: the real verifier is the default on **both** forms — the L2
/// verifier on an Annulet genesis — and rehearsal is never implied.
pub fn select_verifier(rehearsal: bool, form: qlab_devnet::forms::GenesisForm) -> (NodeVerifier, String) {
    use qlab_devnet::forms::GenesisForm;
    if rehearsal {
        (
            NodeVerifier::Rehearsal(DevnetRehearsalVerifier),
            "⚠️  REHEARSAL VERIFIER ACTIVE (--rehearsal-verifier): transaction proofs are \
             NOT cryptographically verified — every tx proof is accepted. Rehearsal/devnet \
             ONLY; NEVER run this on a public network."
                .to_string(),
        )
    } else {
        match form {
            GenesisForm::V4 | GenesisForm::V5 => {}
            GenesisForm::Annulet => {
                return (
                    NodeVerifier::L2(L2Verifier),
                    "verifier: real L2 verifier active (qlab_l2::verify_s / verify_p under make_config_l2, \
                     the provisional L2 lane)."
                        .to_string(),
                );
            }
        }
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
    /// The one real L1 (M3) proof this module's tests share (lab #712: one
    /// prove instead of one per test, which also funds the L2 proves below).
    fn l1_proof() -> &'static (BucketInstance, Proof<Config>) {
        static P: std::sync::OnceLock<(BucketInstance, Proof<Config>)> = std::sync::OnceLock::new();
        P.get_or_init(|| {
            let inst = balanced_bucket();
            let (_pvs, proof) = prove_bucket(&inst);
            (inst, proof)
        })
    }

    fn real_tx_entry(inst: &BucketInstance, proof: &Proof<Config>) -> TxEntry {
        TxEntry::with_placeholder_discovery(bincode::serialize(proof).expect("serialize proof"), TxPublic {
            anchor: h32(&inst.anchor),
            nullifiers: vec![h32(&inst.nf[0]), h32(&inst.nf[1])],
            commitments: vec![h32(&inst.cm_out[0]), h32(&inst.cm_out[1])],
            bucket: ArityBucket::TwoByTwo,
            fee: 1_000,
            })
    }

    #[test]
    fn real_verifier_accepts_a_real_m3_proof() {
        // The round-trip that pins the PV-reconstruction limb convention: a real
        // proof, wired exactly as a tx would carry it, verifies through the
        // decode → reconstruct-pvs → canonical-AIR path.
        let (inst, proof) = l1_proof();
        let entry = real_tx_entry(inst, proof);
        assert!(ConsensusVerifier.verify_tx(&entry), "real proof must verify via ConsensusVerifier");
        // And via the dispatched default.
        let (v, log) = select_verifier(false, qlab_devnet::forms::GenesisForm::V4);
        assert!(matches!(v, NodeVerifier::Consensus(_)));
        assert!(log.contains("real M3 consensus verifier"));
        assert!(v.verify_tx(&entry));
    }

    #[test]
    fn real_verifier_rejects_a_tampered_public_surface() {
        // Same proof, but the declared surface lies: flip a byte of a declared
        // nullifier. The reconstructed PVs no longer match what the proof binds,
        // so verification fails (the declared-surface binding).
        let (inst, proof) = l1_proof();
        let mut entry = real_tx_entry(inst, proof);
        entry.public.nullifiers[0][0] ^= 0x01;
        assert!(!ConsensusVerifier.verify_tx(&entry), "tampered nullifier must fail");

        // Tampered fee likewise (fee is a public value).
        let mut entry2 = real_tx_entry(inst, proof);
        entry2.public.fee += 1;
        assert!(!ConsensusVerifier.verify_tx(&entry2), "tampered fee must fail");
    }

    #[test]
    fn real_verifier_rejects_garbage_and_wrong_shape() {
        let (inst, proof) = l1_proof();

        // Undecodable proof bytes → reject (no panic).
        let mut entry = real_tx_entry(inst, proof);
        entry.proof = vec![0xAB; 16];
        assert!(!ConsensusVerifier.verify_tx(&entry), "garbage proof bytes must fail");

        // Non-2×2 shape (wrong nullifier count) → reject before any decode.
        let mut entry2 = real_tx_entry(inst, proof);
        entry2.public.nullifiers.truncate(1);
        assert!(!ConsensusVerifier.verify_tx(&entry2), "non-2×2 shape must fail");

        // A non-TwoByTwo bucket → reject (AIR only proves 2×2).
        let mut entry3 = real_tx_entry(inst, proof);
        entry3.public.bucket = ArityBucket::FourByFour;
        assert!(!ConsensusVerifier.verify_tx(&entry3), "non-2×2 bucket must fail");
    }

    #[test]
    fn rehearsal_flag_is_opt_in_and_logs_loudly() {
        // Default = real verifier; log states so and carries NO rehearsal warning.
        let (def, deflog) = select_verifier(false, qlab_devnet::forms::GenesisForm::V4);
        assert!(matches!(def, NodeVerifier::Consensus(_)));
        assert!(deflog.contains("real M3 consensus verifier"));
        assert!(!deflog.to_uppercase().contains("REHEARSAL"));

        // Opt-in = rehearsal; log is a loud, unmissable warning.
        let (reh, rehlog) = select_verifier(true, qlab_devnet::forms::GenesisForm::V4);
        assert!(matches!(reh, NodeVerifier::Rehearsal(_)));
        assert!(rehlog.contains("REHEARSAL VERIFIER ACTIVE"));
        assert!(rehlog.contains("NOT cryptographically verified"));
        assert!(rehlog.contains("NEVER"));

        // The rehearsal verifier accepts anything (it is the labelled stand-in).
        let entry = TxEntry::with_placeholder_discovery(vec![], TxPublic {
            anchor: [0; 32],
            nullifiers: vec![[0; 32], [1; 32]],
            commitments: vec![[2; 32], [3; 32]],
            bucket: ArityBucket::TwoByTwo,
            fee: 1_000,
            });
        assert!(reh.verify_tx(&entry), "rehearsal stand-in accepts everything");
        // …while the real default rejects the same bytes (no real proof).
        assert!(!def.verify_tx(&entry), "real verifier rejects a bogus proof");
    }

    // ── Lab #712: the L2 verifier ────────────────────────────────────────────

    /// The shared real shape-S and shape-P proofs (one prove each, ≈ 10 s on
    /// the Graviton lane), over `qlab_l2`'s deterministic fixtures.
    fn s_proof() -> &'static (qlab_l2::L2BucketInstance, Proof<Config>) {
        static P: std::sync::OnceLock<(qlab_l2::L2BucketInstance, Proof<Config>)> = std::sync::OnceLock::new();
        P.get_or_init(|| {
            let inst = qlab_l2::fixture::shape_s();
            let (_pvs, proof) = qlab_l2::prove_s(&inst);
            (inst, proof)
        })
    }

    fn p_proof() -> &'static (qlab_l2::L2PBucketInstance, Proof<Config>) {
        static P: std::sync::OnceLock<(qlab_l2::L2PBucketInstance, Proof<Config>)> = std::sync::OnceLock::new();
        P.get_or_init(|| {
            let inst = qlab_l2::fixture::shape_p();
            let (_pvs, proof) = qlab_l2::prove_p(&inst);
            (inst, proof)
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn l2_entry(
        anchor: &[u64; 4],
        nf: &[[u64; 4]; 2],
        cm: &[[u64; 4]; 2],
        root: &[u64; 4],
        fee: u64,
        surface_shape: qlab_devnet::annulet::L2ShapeTag,
        vpublic: Option<[qlab_devnet::annulet::VPublicTerm; 2]>,
        proof: &Proof<Config>,
    ) -> TxEntry {
        TxEntry {
            proof: bincode::serialize(proof).expect("serialize proof"),
            public: TxPublic {
                anchor: h32(anchor),
                nullifiers: vec![h32(&nf[0]), h32(&nf[1])],
                commitments: vec![h32(&cm[0]), h32(&cm[1])],
                bucket: ArityBucket::TwoByTwo,
                fee,
            },
            discovery: vec![0x00],
            rider: qlab_devnet::names::RIDER_ABSENT.to_vec(),
            l2: qlab_devnet::annulet::L2Surface { shape: surface_shape, registry_root: h32(root), vpublic, write: None }.encode(),
        }
    }

    fn s_entry() -> TxEntry {
        let (i, proof) = s_proof();
        l2_entry(&i.anchor, &i.nf, &i.cm_out, &i.registry_root, 1_000, qlab_devnet::annulet::L2ShapeTag::S, None, proof)
    }

    fn p_entry() -> TxEntry {
        let (i, proof) = p_proof();
        let none = [qlab_devnet::annulet::VPublicTerm::NONE; 2];
        l2_entry(&i.anchor, &i.nf, &i.cm_out, &i.registry_root, 1_000, qlab_devnet::annulet::L2ShapeTag::P, Some(none), proof)
    }

    #[test]
    fn the_l2_verifier_accepts_real_s_and_p_proofs_and_is_the_annulet_default() {
        assert_eq!(L2Verifier.check(&s_entry()), Ok(()));
        assert_eq!(L2Verifier.check(&p_entry()), Ok(()));
        let (v, log) = select_verifier(false, qlab_devnet::forms::GenesisForm::Annulet);
        assert!(matches!(v, NodeVerifier::L2(_)));
        assert!(log.contains("real L2 verifier"), "{log}");
        assert!(!log.to_uppercase().contains("REHEARSAL"));
        assert!(v.verify_tx(&s_entry()));
        // Rehearsal stays a loud opt-in on the Annulet form too.
        let (r, rlog) = select_verifier(true, qlab_devnet::forms::GenesisForm::Annulet);
        assert!(matches!(r, NodeVerifier::Rehearsal(_)));
        assert!(rlog.contains("REHEARSAL VERIFIER ACTIVE"));
    }

    /// The declared-surface binding: every surface field the proof binds,
    /// tampered, fails verification; a shape tag that lies fails on the
    /// proof's structure, by name.
    #[test]
    fn the_l2_verifier_refuses_a_tampered_surface_by_name() {
        let mut e = s_entry();
        e.public.fee += 1;
        assert_eq!(L2Verifier.check(&e), Err(L2VerifyError::ProofInvalid), "fee");
        let mut e = s_entry();
        e.public.nullifiers[1][0] ^= 1;
        assert_eq!(L2Verifier.check(&e), Err(L2VerifyError::ProofInvalid), "nullifier");
        let (i, proof) = s_proof();
        let mut other_root = i.registry_root;
        other_root[0] ^= 1;
        let e = l2_entry(&i.anchor, &i.nf, &i.cm_out, &other_root, 1_000, qlab_devnet::annulet::L2ShapeTag::S, None, proof);
        assert_eq!(L2Verifier.check(&e), Err(L2VerifyError::ProofInvalid), "registry root");
        // An S proof declared as P: refused on its structure, before verify.
        let none = [qlab_devnet::annulet::VPublicTerm::NONE; 2];
        let e = l2_entry(&i.anchor, &i.nf, &i.cm_out, &i.registry_root, 1_000, qlab_devnet::annulet::L2ShapeTag::P, Some(none), proof);
        assert_eq!(
            L2Verifier.check(&e),
            Err(L2VerifyError::ProofShape { what: "degree_bits", got: qlab_l2::LOG_HEIGHT_S, want: qlab_l2::LOG_HEIGHT_P })
        );
        // A P proof with a vPublic term it did not prove.
        let (pi, pproof) = p_proof();
        let lie = [qlab_devnet::annulet::VPublicTerm::NONE, qlab_devnet::annulet::VPublicTerm { redeem: false, amount: 5, asset: 7 }];
        let e = l2_entry(&pi.anchor, &pi.nf, &pi.cm_out, &pi.registry_root, 1_000, qlab_devnet::annulet::L2ShapeTag::P, Some(lie), pproof);
        assert_eq!(L2Verifier.check(&e), Err(L2VerifyError::ProofInvalid), "vPublic");
    }

    /// The strict decode: garbage, a trailing byte and a truncation are
    /// refused by name, never verified.
    #[test]
    fn the_l2_verifier_decodes_strictly() {
        let mut e = s_entry();
        e.proof = vec![0xAB; 16];
        assert_eq!(L2Verifier.check(&e), Err(L2VerifyError::ProofDecode));
        let mut e = s_entry();
        e.proof.push(0);
        assert_eq!(L2Verifier.check(&e), Err(L2VerifyError::ProofDecode), "trailing byte");
        let mut e = s_entry();
        e.proof.truncate(e.proof.len() - 1);
        assert_eq!(L2Verifier.check(&e), Err(L2VerifyError::ProofDecode), "truncation");
        let mut e = s_entry();
        e.public.nullifiers.truncate(1);
        assert_eq!(L2Verifier.check(&e), Err(L2VerifyError::NotTwoByTwo));
    }

    /// 🔴 The L1/L2 separation, both ways (the lab #712 ruling on Q1/Q4):
    /// an L1 proof under an L2 surface is refused by its **structure**; an L1
    /// transaction is refused by the L2 verifier for lacking a surface; an L2
    /// transaction is refused by the L1 verifier.
    #[test]
    fn l1_and_l2_proofs_are_separated_both_ways() {
        // L1 → L2: a real M3 proof dressed with an L2 surface.
        let (l1, l1proof) = l1_proof();
        let e = l2_entry(&l1.anchor, &l1.nf, &l1.cm_out, &[0; 4], 1_000, qlab_devnet::annulet::L2ShapeTag::S, None, l1proof);
        match L2Verifier.check(&e) {
            Err(L2VerifyError::ProofShape { .. }) => {}
            other => panic!("an L1 proof must be refused by structure, got {other:?}"),
        }
        // An L1 transaction as it travels: no surface.
        let bare = real_tx_entry(l1, l1proof);
        assert_eq!(L2Verifier.check(&bare), Err(L2VerifyError::NoSurface));
        assert!(ConsensusVerifier.verify_tx(&bare), "and it is the L1 verifier's");
        // L2 → L1: the L1 verifier refuses a transaction carrying a surface,
        // and an L2 proof stripped of its surface still fails the L1 lane.
        assert!(!ConsensusVerifier.verify_tx(&s_entry()));
        let mut stripped = s_entry();
        stripped.l2 = qlab_devnet::annulet::L2_SURFACE_ABSENT.to_vec();
        assert!(!ConsensusVerifier.verify_tx(&stripped));
    }

    /// Q5: the non-zero vPublic → public-value mapping, without a prove: the
    /// verifier's surface-to-PV conversion is `pv_vec_p`'s layout.
    #[test]
    fn vpublic_terms_map_onto_the_p_public_values() {
        let t = [
            qlab_devnet::annulet::VPublicTerm { redeem: true, amount: 0x0001_0002_0003_0004, asset: 9 },
            qlab_devnet::annulet::VPublicTerm { redeem: false, amount: 77, asset: 3 },
        ];
        let pvs = qlab_l2::pv_vec_p(&[0; 4], &[0; 4], &[0; 4], &[0; 4], &[0; 4], 0, &[0; 4], &vpublic(&t), &vpublic_assets(&t));
        let v1 = qlab_l2::PV_VP1;
        assert_eq!(&pvs[v1..v1 + 6], &[1, 4, 3, 2, 1, 9]);
        let v2 = qlab_l2::PV_VP2;
        assert_eq!(&pvs[v2..v2 + 6], &[0, 77, 0, 0, 0, 3]);
    }
}
