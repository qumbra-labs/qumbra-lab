//! qlab-consensus — the single source of truth for the Qumbra consensus STARK
//! configuration and its prove/verify wrappers.
//!
//! Before this crate the consensus `StarkConfig` (field / hash / FRI plumbing)
//! and the frozen [`CONSENSUS_CFG`] lived `pub(crate)` inside the `qlab-bench`
//! *binary* (main.rs type aliases + `make_config_with`, m4gaterec.rs
//! `CONSENSUS_CFG`), so every other consumer — `qlab-demo`, and now the
//! `qlab-node` stack — had to reconstruct it and value-lock the copy by hand
//! (issue #38, follow-up F1 from the wallet demo, PR #37). This crate is that
//! single source: import it and you get the exact same config, byte-for-byte.
//!
//! Nothing here is a fork of prover logic — it is the standard Plonky3
//! `StarkConfig` any integrator constructs, pinned to Qumbra's frozen choices:
//!
//! - **Field** KoalaBear (p = 2³¹ − 2²⁴ + 1); challenge = degree-4 extension.
//! - **Hash** Keccak-256 everywhere in the commitment layer (the conservative
//!   consensus hash — protocol-spec §1).
//! - **FRI** the FROZEN v1.0 consensus point b16/q21/g22/fp16/a16
//!   ([`CONSENSUS_CFG`]; consensus-parameters FROZEN §1, issue #41 "B″").
//!
//! The byte-identical wire is regression-pinned at **145,609 B** by
//! `consensus_wire_is_145609_bytes` below — the same number the bench suite
//! measures (CLAUDE.md "B″ batch", coordinator-accepted PR #47).

use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_field::PrimeCharacteristicRing;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_koala_bear::KoalaBear;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark::{prove, verify, StarkConfig};

use qlab_air::narrow::BucketInstance;

// Re-export the proof type + prove/verify so consumers need not depend on
// p3-uni-stark directly just to name a `Proof<Config>`.
pub use p3_uni_stark::Proof;

// ---------------------------------------------------------------------------
// Field + hash + FRI plumbing — identical for the whole consensus stack.
//
// Field:      KoalaBear (31-bit prime 2^31 - 2^24 + 1), the Plonky3-preferred
//             Monty-31 field. Challenge = degree-4 binomial extension (~124-bit).
// FRI Merkle: Keccak-256 (vectorized Keccak-f sponge) — conservative hash for
//             the commitment layer, matching Qumbra's consensus hash stance.
// DFT:        Radix2DitParallel.
// ---------------------------------------------------------------------------

/// The base field: KoalaBear.
pub type Val = KoalaBear;
/// The challenge field: degree-4 binomial extension of [`Val`] (~124-bit).
pub type Challenge = BinomialExtensionField<Val, 4>;

type ByteHash = Keccak256Hash;
type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
type FieldHash = SerializingHasher<U64Hash>;
type MyCompress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
type ValMmcs = MerkleTreeMmcs<
    [Val; p3_keccak::VECTOR_LEN],
    [u64; p3_keccak::VECTOR_LEN],
    FieldHash,
    MyCompress,
    2,
    4,
>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
/// The parallel radix-2 DIT DFT used by the FRI PCS.
pub type Dft = p3_dft::Radix2DitParallel<Val>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
/// The complete consensus `StarkConfig` (field, hash, FRI PCS, challenger).
pub type Config = StarkConfig<Pcs, Challenge, Challenger>;

/// The Merkle cap height baked into the consensus `ValMmcs`
/// (`ValMmcs::new(.., CAP_HEIGHT)`). Part of the wire: changing it changes the
/// commit-layer opening shape and therefore the byte count.
pub const CAP_HEIGHT: usize = 3;

/// One point in the FRI parameter space. Everything else (field, extension,
/// DFT, Merkle hash) is held fixed — only FRI parameters vary. Fields are `pub`
/// so bench sweeps and other consumers can build their own points; the frozen
/// consensus point is [`CONSENSUS_CFG`].
#[derive(Clone, Copy)]
pub struct FriCfg {
    pub log_blowup: usize,
    pub num_queries: usize,
    pub grind_bits: usize,
    /// log2 of the final polynomial length — stops FRI folding early,
    /// trading commit-phase Merkle paths for plaintext final-poly coeffs.
    pub log_final_poly_len: usize,
    /// log2 of the maximum FRI fold arity (0.6.1 `FriParameters::max_log_arity`).
    /// 1 = classic arity-2 folding; k folds up to 2^k per round, trading fewer
    /// fold rounds (fewer commit roots + shorter path total) for 2^k - 1 sibling
    /// values per round per query.
    pub max_log_arity: usize,
}

impl FriCfg {
    /// The `b{blowup}/q{queries}/g{grind}[/fp{final}][/a{arity}]` label used in
    /// bench tables and doc references.
    pub fn label(&self) -> String {
        let mut s = format!(
            "b{}/q{}/g{}",
            1 << self.log_blowup,
            self.num_queries,
            self.grind_bits
        );
        if self.log_final_poly_len > 0 {
            s.push_str(&format!("/fp{}", 1 << self.log_final_poly_len));
        }
        if self.max_log_arity > 1 {
            s.push_str(&format!("/a{}", 1 << self.max_log_arity));
        }
        s
    }
}

/// The FROZEN consensus config: **b16/q21/g22/fp16/a16**.
///
/// B′ (issue #22, 2026-07-19) took grind 20 → 22 to restore the "~100-bit
/// conjectured" headline under the DG25 list-decoding-capacity repricing (proof
/// sizes are byte-identical — grind is a PoW nonce, not openings). B″ (issue
/// #41, DECIDED 2026-07-22, `fri-soundness-accounting-2026-07.md` §6) then took
/// query 20 → 21: the 2025/2197 close-read reprices the conjectured ceiling to
/// base-field list-decoding entropy, and +1 query (unlike grind, this DOES pay
/// bytes) restores the standing ~100-bit invariant (b16/q21/g22 → 100.6
/// corrected). GENESIS FREEZE v1.0 (2026-07-23) makes this the binding genesis
/// value (consensus-parameters FROZEN §1); it changes henceforth only via a
/// halt-height upgrade carrying its own revision doc.
///
/// This is THE single source; `qlab-bench` and `qlab-demo` re-export it, and
/// `m4gate::NQ` derives its query count from it.
pub const CONSENSUS_CFG: FriCfg = FriCfg {
    log_blowup: 4,
    num_queries: 21,
    grind_bits: 22,
    log_final_poly_len: 4,
    max_log_arity: 4,
};

/// log2 of the 2×2 bucket trace height (83 perms → 2^18 rows; protocol-spec §4).
pub const LOG_HEIGHT: usize = 18;

/// Build a `StarkConfig` at an arbitrary FRI point. Field, hash, DFT, and the
/// Merkle cap height are held at the frozen consensus values; only the FRI
/// parameters come from `cfg`. Every point must clear the ~100-bit security bar.
pub fn make_config_with(cfg: &FriCfg) -> Config {
    let byte_hash = ByteHash {};
    let u64_hash = U64Hash::new(KeccakF {});
    let field_hash = FieldHash::new(u64_hash);
    let compress = MyCompress::new(u64_hash);
    let val_mmcs = ValMmcs::new(field_hash, compress, CAP_HEIGHT);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let challenger = Challenger::from_hasher(vec![], byte_hash);

    let fri_params = FriParameters {
        log_blowup: cfg.log_blowup,
        log_final_poly_len: cfg.log_final_poly_len,
        max_log_arity: cfg.max_log_arity,
        num_queries: cfg.num_queries,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: cfg.grind_bits,
        mmcs: challenge_mmcs,
    };
    // Every config in the stack must clear the security bar. Label 口径 (design
    // repo `fri-soundness-accounting-2026-07.md`): "~100-bit conjectured
    // (list-decoding-capacity accounting, 2025-repriced); proven-Johnson ≈ 59/58
    // query-phase, field-capped ~80". The pinned Plonky3 0.6.x
    // `conjectured_soundness_bits()` still computes the OLD capacity arithmetic
    // (num_queries·log2(blowup) + grind) — the up-to-capacity conjecture behind
    // it was disproved in late 2025 (DG25/CS25). We do NOT change the method
    // (the DG25 re-anchor is a docs-layer relabel, not a code formula change);
    // post-B′ (g22) it returns 102 for all three lanes (20·4+22 = 40·2+22 =
    // 80·1+22), a conservative proxy for the honest DG25 conjectured ~100.4–100.8.
    // So `>= 100` on the capacity value still gates correctly with ~2 bits to spare.
    assert!(
        fri_params.conjectured_soundness_bits() >= 100,
        "config {} is only {} bits conjectured (capacity proxy)",
        cfg.label(),
        fri_params.conjectured_soundness_bits(),
    );

    let pcs = Pcs::new(Dft::default(), val_mmcs, fri_params);
    Config::new(pcs, challenger)
}

/// The consensus config — `make_config_with(&CONSENSUS_CFG)`. This is the config
/// a node uses to verify transaction proofs and a wallet uses to prove them.
pub fn make_config() -> Config {
    make_config_with(&CONSENSUS_CFG)
}

/// A bucket instance's public values as challenge-base field elements.
pub fn public_values(inst: &BucketInstance) -> Vec<Val> {
    inst.pvs.iter().map(|v| Val::from_u32(*v)).collect()
}

/// Generate the trace and prove the 2×2 bucket at the consensus config (~1.6 s
/// on an Apple M-class laptop). Returns the public values alongside the proof.
pub fn prove_bucket(inst: &BucketInstance) -> (Vec<Val>, Proof<Config>) {
    let config = make_config();
    let pvs = public_values(inst);
    let trace = inst.air.generate_trace::<Val>(CONSENSUS_CFG.log_blowup);
    let proof = prove(&config, &inst.air, trace, &pvs);
    (pvs, proof)
}

/// Node-side verification: `true` iff `proof` is a valid consensus proof for
/// `inst` under `pvs`.
pub fn verify_proof(inst: &BucketInstance, pvs: &[Val], proof: &Proof<Config>) -> bool {
    let config = make_config();
    verify(&config, &inst.air, proof, pvs).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_air::narrow::{build_bucket, TxInput, TxOutput};

    #[test]
    fn consensus_cfg_is_value_locked() {
        // The FROZEN v1.0 consensus point (issue #41 B″): b16/q21/g22/fp16/a16.
        assert_eq!(CONSENSUS_CFG.log_blowup, 4);
        assert_eq!(CONSENSUS_CFG.num_queries, 21);
        assert_eq!(CONSENSUS_CFG.grind_bits, 22);
        assert_eq!(CONSENSUS_CFG.log_final_poly_len, 4);
        assert_eq!(CONSENSUS_CFG.max_log_arity, 4);
        assert_eq!(LOG_HEIGHT, 18);
        assert_eq!(CAP_HEIGHT, 3);
        assert_eq!(CONSENSUS_CFG.label(), "b16/q21/g22/fp16/a16");
    }

    /// A balanced 2-in/2-out bucket (50k+30k = 60k+19k+1k fee).
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

    #[test]
    fn real_m3_proof_roundtrips() {
        let inst = balanced_bucket();
        let (pvs, proof) = prove_bucket(&inst);
        assert!(verify_proof(&inst, &pvs, &proof), "real M3 proof must verify");
    }

    /// The consensus wire is byte-identical at **145,609 B** — the number the
    /// bench suite measured and the coordinator reproduced for B″ (PR #47),
    /// promoted here to a permanent single-source regression pin. bincode fixint
    /// is the consensus wire (protocol-spec §4). Proof byte length is a function
    /// of the AIR shape + config only, so it is instance-independent (the grind
    /// nonce is a fixed-width field).
    #[test]
    fn consensus_wire_is_145609_bytes() {
        let inst = balanced_bucket();
        let (pvs, proof) = prove_bucket(&inst);
        assert!(verify_proof(&inst, &pvs, &proof));
        let bytes = bincode::serialize(&proof)
            .expect("bincode serialization failed")
            .len();
        #[cfg(not(feature = "q69-latch"))]
        assert_eq!(
            bytes, 145_609,
            "consensus wire byte-identical regression (issue #38 extraction / #41 B″)"
        );
        // Issue #219 / QUM-69: the `q69-latch` feature adds three trace columns
        // (`NARROW_WIDTH` 617 → 620). 145,957 = 145,609 + 3 × 116, i.e. the
        // latch's real columns cost exactly what QUM-67's three INERT probe
        // columns cost — the 116.0 B/column slope, which holds only because the
        // quotient degree does not move (`q69_quotient_degree_does_not_move`).
        //
        // 🔴 This is why the feature is default-off: 145,957 ≠
        // `qumbra_node::genesis::CONSENSUS_WIRE_BYTES`, a FROZEN v1.0 constant
        // baked into the genesis hash. Enabling it by default is a genesis
        // change, not a builder's call.
        #[cfg(feature = "q69-latch")]
        assert_eq!(
            bytes, 145_957,
            "latched consensus wire (issue #219): 145,609 + 3 columns × 116 B"
        );
    }

    // -----------------------------------------------------------------------
    // Issue #219 / QUM-69: the dummy-input arm, through the REAL verifier.
    //
    // `check_constraints` passing is not the same claim as `p3_uni_stark::verify`
    // accepting at the frozen config, so both are exercised: the AIR-level
    // soundness set lives in `qlab-air`, and this is the end-to-end one.
    // -----------------------------------------------------------------------

    /// A one-real-input spend: 1,000 in, 600 + 399 out, fee 1, slot 1 dummy.
    #[cfg(feature = "q69-latch")]
    fn dummy1_bucket() -> qlab_air::narrow::BucketInstance {
        use qlab_air::narrow::{
            build_bucket_dummy1, derive_input, fabricated_single_tree, off_tree_witness,
        };
        let real = TxInput {
            sk: [0x11, 0x22, 0x33, 0x44],
            value: 1_000,
            rho: [0x55, 0x66, 0x77, 0x88],
            rseed: [0x99, 0xaa, 0xbb, 0xcc],
            d: [0xd1, 0xd2],
        };
        let dummy = TxInput {
            sk: [0xf00d, 0xf00e, 0xf00f, 0xf010],
            value: 0,
            rho: [0xbeef01, 0xbeef02, 0xbeef03, 0xbeef04],
            rseed: [0xcafe01, 0xcafe02, 0xcafe03, 0xcafe04],
            d: [0, 0],
        };
        let outputs = [
            TxOutput { value: 600, rkm: [2; 4], rho: [3; 4], rseed: [4; 4] },
            TxOutput { value: 399, rkm: [5; 4], rho: [6; 4], rseed: [7; 4] },
        ];
        let (_, _, cm_real) = derive_input(&real);
        let (w_real, anchor) = fabricated_single_tree(&cm_real);
        build_bucket_dummy1(
            LOG_HEIGHT,
            &real,
            &w_real,
            &dummy,
            &off_tree_witness(),
            &outputs,
            1,
            anchor,
        )
    }

    /// 🔴 The padding property, measured end to end: a **dummy** transaction's
    /// proof is accepted by the real verifier at the frozen config AND is
    /// **byte-identical in size** to a real two-input one. Same program, same
    /// height, same width, same quotient degree — so proof size discloses
    /// nothing about the sender's true input arity, which is the whole reason
    /// `transaction-model` §7/§10 lists arity buckets as Decided.
    #[cfg(feature = "q69-latch")]
    #[test]
    fn q69_dummy_proof_verifies_and_is_size_indistinguishable() {
        let real = balanced_bucket();
        let (real_pvs, real_proof) = prove_bucket(&real);
        assert!(verify_proof(&real, &real_pvs, &real_proof), "real 2×2 must verify");

        let dummy = dummy1_bucket();
        assert!(dummy.air.dv, "precondition: slot 1 is declared dummy");
        let (d_pvs, d_proof) = prove_bucket(&dummy);
        assert!(
            verify_proof(&dummy, &d_pvs, &d_proof),
            "the dummy-slot proof must be accepted by p3_uni_stark::verify at \
             the frozen config, not merely by check_constraints"
        );

        let real_bytes = bincode::serialize(&real_proof).unwrap().len();
        let d_bytes = bincode::serialize(&d_proof).unwrap().len();
        assert_eq!(
            d_bytes, real_bytes,
            "a dummy proof must not be distinguishable by size"
        );
        assert_eq!(d_bytes, 145_957, "latched wire");
    }

    /// The verifier binds the dummy instance to its declared surface exactly as
    /// it binds a real one: tamper `PV_NF2` — the dummy slot's own nullifier —
    /// and the real verifier refuses. The relaxed anchor bind does not relax
    /// this, which is what keeps a relay from rewriting a dummy nullifier.
    #[cfg(feature = "q69-latch")]
    #[test]
    fn q69_dummy_proof_is_bound_to_its_declared_nullifier() {
        use qlab_air::narrow::PV_NF2;
        let dummy = dummy1_bucket();
        let (pvs, proof) = prove_bucket(&dummy);
        assert!(verify_proof(&dummy, &pvs, &proof));
        let mut tampered = pvs.clone();
        tampered[PV_NF2 + 5] += Val::ONE;
        assert!(
            !verify_proof(&dummy, &tampered, &proof),
            "a rewritten dummy nullifier must be refused by the real verifier"
        );
    }
}
