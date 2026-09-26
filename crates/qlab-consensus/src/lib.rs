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
//! The byte-identical wire is regression-pinned at **148,625 B** by
//! `consensus_wire_is_148625_bytes` below — issue #215 (i) + #219, measured on
//! one tree. It was 145,609 B (CLAUDE.md "B″ batch", coordinator-accepted
//! PR #47) before those two landed.

use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_field::PrimeCharacteristicRing;
use p3_fri::{FriParameters, HidingFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_koala_bear::KoalaBear;
use p3_merkle_tree::MerkleTreeHidingMmcs;
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
/// Field elements of salt per hiding-Merkle leaf: 4 × 31 bits = 124 bits of
/// salt entropy per leaf (Plonky3's example value; re-derived in the re-mint's
/// security accounting).
pub const SALT_ELEMS: usize = 4;
/// Random codewords `HidingFriPcs` appends to every committed matrix, to each
/// quotient chunk and to the randomizer commitment.
///
/// **0 since re-genesis batch 2** (lab #747; Larry's ruling on lab #742,
/// 2026-09-26: rc = 0 on the T-net, mainnet after the audit). It was 4 at the
/// security re-mint — Plonky3's example value. On the eprint 2024/1037 reading
/// the re-mint accounting used, none of the paper's zero-knowledge conditions
/// (`h`, `h_p`, the FRI batch mask `R`) depends on this count; the analysis is
/// qumbra-design `hiding-random-codewords-2026-09` and the dated amendment to
/// `docs/remint-zk-security-accounting.md` §3. At 4 it cost 1.25 GiB of the P3
/// and L1 peaks and 4,064 B of the L1 wire. `rc_is_zero_and_no_random_openings_travel`
/// pins it.
pub const NUM_RANDOM_CODEWORDS: usize = 0;

type ValMmcs = MerkleTreeHidingMmcs<
    [Val; p3_keccak::VECTOR_LEN],
    [u64; p3_keccak::VECTOR_LEN],
    FieldHash,
    MyCompress,
    ProverRng,
    2,
    4,
    SALT_ELEMS,
>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
/// The parallel radix-2 DIT DFT used by the FRI PCS.
pub type Dft = p3_dft::Radix2DitParallel<Val>;
/// The hiding FRI PCS: the transaction proofs are zero-knowledge.
type Pcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, ProverRng>;
/// The complete consensus `StarkConfig` (field, hash, hiding FRI PCS,
/// challenger).
pub type Config = StarkConfig<Pcs, Challenge, Challenger>;

/// `1`: the PCS is hiding. A proof's `degree_bits` is the trace's log height
/// **plus this** (the committed trace is randomized to twice its height), and
/// the quotient is split into twice the chunks. Locked against the config's
/// own `is_zk()` by `the_consensus_pcs_is_hiding`.
pub const IS_ZK: usize = 1;

// ---------------------------------------------------------------------------
// The prover's randomness
// ---------------------------------------------------------------------------

/// The one RNG type the proof stack draws its masks, random codewords and
/// Merkle salts from: ChaCha20, seeded from the operating system.
///
/// **Clone reseeds from the OS — it never copies state.** Plonky3's hiding
/// PCS and MMCS hold their RNG inside the config, and their `Clone` clones
/// it; with a state-copying RNG, a cloned config would hand two proofs the
/// same masks and silently void zero knowledge. Making the *type* fork fresh
/// entropy on every clone turns that hazard from a convention into a
/// property: a config may be cloned, cached or shared freely.
#[derive(Debug)]
pub struct ProverRng(rand::rngs::ChaCha20Rng);

impl ProverRng {
    /// A fresh generator seeded with 32 bytes from the operating system.
    pub fn from_os() -> Self {
        use rand::{SeedableRng, TryRng};
        let mut seed = [0u8; 32];
        rand::rngs::SysRng
            .try_fill_bytes(&mut seed)
            .expect("the operating system's RNG is available");
        Self(rand::rngs::ChaCha20Rng::from_seed(seed))
    }

    /// A deterministically seeded generator — **tests only**. A clone of it
    /// still reseeds from the OS (see the type doc), so determinism holds only
    /// for the draws the seeded instance itself makes.
    pub fn seeded(seed: u64) -> Self {
        use rand::SeedableRng;
        Self(rand::rngs::ChaCha20Rng::seed_from_u64(seed))
    }
}

impl Clone for ProverRng {
    fn clone(&self) -> Self {
        Self::from_os()
    }
}

impl rand::TryRng for ProverRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(rand::Rng::next_u32(&mut self.0))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(rand::Rng::next_u64(&mut self.0))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        rand::Rng::fill_bytes(&mut self.0, dst);
        Ok(())
    }
}

impl rand::TryCryptoRng for ProverRng {}

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

/// log2 of the 2×2 bucket trace height (84 perms → 2^18 rows; protocol-spec §4).
pub const LOG_HEIGHT: usize = 18;

/// Build a `StarkConfig` at an arbitrary FRI point. Field, hash, DFT, and the
/// Merkle cap height are held at the frozen consensus values; only the FRI
/// parameters come from `cfg`. Every point must clear the ~100-bit security bar.
pub fn make_config_with(cfg: &FriCfg) -> Config {
    make_config_from(cfg, ProverRng::from_os)
}

/// [`make_config_with`] with deterministically seeded generators — **tests
/// only** (production configs are always OS-seeded). The three consumers —
/// the trace MMCS, the FRI MMCS and the PCS — get three distinct seeds.
pub fn make_config_seeded(cfg: &FriCfg, seed: u64) -> Config {
    let mut n = 0u64;
    make_config_from(cfg, || {
        n += 1;
        ProverRng::seeded(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(n))
    })
}

/// The one construction site. Each randomness consumer gets its **own**
/// generator from `rng` — never a clone of another's.
fn make_config_from(cfg: &FriCfg, mut rng: impl FnMut() -> ProverRng) -> Config {
    let byte_hash = ByteHash {};
    let u64_hash = U64Hash::new(KeccakF {});
    let field_hash = FieldHash::new(u64_hash);
    let compress = MyCompress::new(u64_hash);
    let val_mmcs = ValMmcs::new(field_hash, compress.clone(), CAP_HEIGHT, rng());
    let challenge_mmcs = ChallengeMmcs::new(ValMmcs::new(field_hash, compress, CAP_HEIGHT, rng()));
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

    let pcs = Pcs::new(Dft::default(), val_mmcs, fri_params, NUM_RANDOM_CODEWORDS, rng());
    Config::new(pcs, challenger)
}

/// **Legacy, non-hiding** — the pre-re-mint `TwoAdicFriPcs` stack, kept for
/// exactly one consumer: the M4 aggregation bench (`qlab-bench` `m4*`), whose
/// in-circuit recorder and gate AIR verify the non-hiding FRI proof shape.
/// Rung-1 aggregation is **re-gated** by the re-mint: it measures aggregating
/// proofs the network no longer produces, until it is extended to the hiding
/// shape (a named post-re-mint milestone). Nothing that proves or verifies a
/// transaction may use this module.
pub mod legacy {
    use super::*;
    use p3_fri::TwoAdicFriPcs;
    use p3_merkle_tree::MerkleTreeMmcs;

    type LegacyValMmcs = MerkleTreeMmcs<
        [Val; p3_keccak::VECTOR_LEN],
        [u64; p3_keccak::VECTOR_LEN],
        FieldHash,
        MyCompress,
        2,
        4,
    >;
    type LegacyChallengeMmcs = ExtensionMmcs<Val, Challenge, LegacyValMmcs>;
    type LegacyPcs = TwoAdicFriPcs<Val, Dft, LegacyValMmcs, LegacyChallengeMmcs>;
    /// The pre-re-mint config (non-hiding).
    pub type LegacyNonHidingConfig = StarkConfig<LegacyPcs, Challenge, Challenger>;

    /// The pre-re-mint `make_config_with`, byte-for-byte.
    pub fn make_legacy_config_with(cfg: &FriCfg) -> LegacyNonHidingConfig {
        let u64_hash = U64Hash::new(KeccakF {});
        let val_mmcs = LegacyValMmcs::new(FieldHash::new(u64_hash), MyCompress::new(u64_hash), CAP_HEIGHT);
        let challenge_mmcs = LegacyChallengeMmcs::new(val_mmcs.clone());
        let fri_params = FriParameters {
            log_blowup: cfg.log_blowup,
            log_final_poly_len: cfg.log_final_poly_len,
            max_log_arity: cfg.max_log_arity,
            num_queries: cfg.num_queries,
            commit_proof_of_work_bits: 0,
            query_proof_of_work_bits: cfg.grind_bits,
            mmcs: challenge_mmcs,
        };
        assert!(fri_params.conjectured_soundness_bits() >= 100, "config {} below the floor", cfg.label());
        let pcs = LegacyPcs::new(Dft::default(), val_mmcs, fri_params);
        LegacyNonHidingConfig::new(pcs, Challenger::from_hasher(vec![], ByteHash {}))
    }
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

    /// The minted consensus proof size. **One source of truth**: both the wire
    /// pin and the dummy-proof size-indistinguishability test read it, so a wire
    /// change cannot be half applied — which is exactly what a stale literal in
    /// the second test caused while the two changes were still feature-gated.
    ///
    /// **148,625 B** — a MEASUREMENT on one tree, 5/5 byte-exact. Not 148,161,
    /// which was a sum of measurements on *different* trees and mints nothing.
    ///
    /// | tree | width | perms | bytes |
    /// |---|---|---|---|
    /// | pre-mint `main` | 617 | 83 | 145,609 |
    /// | + issue #219 latch (3 cols) | 620 | 83 | 145,957 |
    /// | + issue #215 (i) option 4 (23 cols, 1 perm) | 643 | 84 | **148,625** |
    ///
    /// 26 × 116.0 B/column. The added *permutation* costs zero bytes: proof size
    /// is a function of `log_height`, width, quotient degree and the FRI config,
    /// and a permutation moves none of the four (#219's six-arm measurement).
    /// The 116 B line holds only because the quotient degree does not move,
    /// which `q69_quotient_degree_does_not_move` asserts off Plonky3's own
    /// symbolic evaluation.
    ///
    /// **The re-mint (hiding PCS) moves it**: the committed trace doubles in
    /// height, the quotient splits into twice the chunks, every matrix gains
    /// random codewords and every Merkle leaf a salt. **182,745 B**, measured
    /// on the Graviton acceptance lane: both readers
    /// (`consensus_wire_is_pinned`, `q69_…`) measured it identically, and proof
    /// bytes are deterministic across machines. Over the design's ≤ 150 KB
    /// target — a design question, not this pin's.
    ///
    /// **Re-genesis batch 2 (lab #747): 182,745 → 178,681 B** with
    /// `NUM_RANDOM_CODEWORDS` 4 → 0. Each random codeword was 10 opened base
    /// values per query (trace 1, quotient chunks 8, randomizer 1) plus 11
    /// extension values of `opened_values_rand` (trace at ζ and ζ·g, 8 chunks,
    /// randomizer): 4 × (21 × 40 + 176) = 4,064 B; every length prefix stays.
    /// Equal to the genesis-side `CONSENSUS_WIRE_BYTES`.
    const WIRE_BYTES: Option<usize> = Some(178_681);

    fn assert_wire(bytes: usize, what: &str) {
        match WIRE_BYTES {
            Some(pin) => assert_eq!(bytes, pin, "{what}"),
            None => panic!("{what}: WIRE_BYTES is PENDING the re-mint's rig measurement — measured {bytes} B"),
        }
    }

    /// The consensus wire is byte-identical at **148,625 B**, a permanent
    /// single-source regression pin. bincode fixint
    /// is the consensus wire (protocol-spec §4). Proof byte length is a function
    /// of the AIR shape + config only, so it is instance-independent (the grind
    /// nonce is a fixed-width field).
    #[test]
    fn consensus_wire_is_pinned() {
        let inst = balanced_bucket();
        let (pvs, proof) = prove_bucket(&inst);
        assert!(verify_proof(&inst, &pvs, &proof));
        let bytes = bincode::serialize(&proof)
            .expect("bincode serialization failed")
            .len();
        assert_wire(bytes, "consensus wire, measured on one tree");
    }

    // -----------------------------------------------------------------------
    // Issue #219 / QUM-69: the dummy-input arm, through the REAL verifier.
    //
    // `check_constraints` passing is not the same claim as `p3_uni_stark::verify`
    // accepting at the frozen config, so both are exercised: the AIR-level
    // soundness set lives in `qlab-air`, and this is the end-to-end one.
    // -----------------------------------------------------------------------

    /// A one-real-input spend: 1,000 in, 600 + 399 out, fee 1, slot 1 dummy.
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
        // The absolute lives in `WIRE_BYTES`, not here — see its note.
        assert_wire(d_bytes, "the minted wire");
    }

    /// The verifier binds the dummy instance to its declared surface exactly as
    /// it binds a real one: tamper `PV_NF2` — the dummy slot's own nullifier —
    /// and the real verifier refuses. The relaxed anchor bind does not relax
    /// this, which is what keeps a relay from rewriting a dummy nullifier.
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

    // -----------------------------------------------------------------------
    // The re-mint: the PCS is hiding, and its randomness is never shared.
    // -----------------------------------------------------------------------

    /// The config's own `is_zk()` is [`IS_ZK`] = 1.
    #[test]
    fn the_consensus_pcs_is_hiding() {
        use p3_uni_stark::StarkGenericConfig;
        assert_eq!(make_config().is_zk(), IS_ZK);
        assert_eq!(IS_ZK, 1);
        assert!(make_config_seeded(&CONSENSUS_CFG, 1).is_zk() == 1);
    }

    /// `ProverRng`: a seed reproduces its own stream; a CLONE does not
    /// continue it — it reseeds from the OS, so two clones never share masks.
    #[test]
    fn prover_rng_clones_reseed_rather_than_copy() {
        use rand::Rng;
        let draw = |r: &mut ProverRng| (0..4).map(|_| r.next_u64()).collect::<Vec<_>>();
        let (mut a, mut b) = (ProverRng::seeded(7), ProverRng::seeded(7));
        assert_eq!(draw(&mut a), draw(&mut b), "a seed reproduces its stream");
        let mut a2 = a.clone();
        assert_ne!(draw(&mut a), draw(&mut a2), "a clone must not continue the parent's stream");
        let (mut o1, mut o2) = (ProverRng::from_os(), ProverRng::from_os());
        assert_ne!(draw(&mut o1), draw(&mut o2), "two OS-seeded generators differ");
    }

    /// Zero knowledge is live: two proofs of the SAME witness — from one
    /// config, from a clone of it, and from a second config — are pairwise
    /// different and all verify. A chain-only trace at 2^13 under the
    /// consensus FRI point keeps this cheap while exercising the real PCS.
    #[test]
    fn two_proofs_of_one_witness_differ_and_both_verify() {
        use qlab_air::narrow::NarrowKeccakAir;
        let air = NarrowKeccakAir::chain_only(13);
        let pvs = vec![Val::ZERO; <NarrowKeccakAir as p3_air::BaseAir<Val>>::num_public_values(&air)];
        let prove_with = |config: &Config| {
            let trace = air.generate_trace::<Val>(CONSENSUS_CFG.log_blowup);
            let proof = prove(config, &air, trace, &pvs);
            assert!(verify(&make_config(), &air, &proof, &pvs).is_ok(), "a hiding proof verifies");
            bincode::serialize(&proof).expect("bincode")
        };
        let config = make_config();
        let p1 = prove_with(&config);
        let p2 = prove_with(&config);
        let p3 = prove_with(&config.clone());
        let p4 = prove_with(&make_config());
        assert_eq!(p1.len(), p2.len(), "same shape, same size");
        for (i, (x, y)) in [(&p1, &p2), (&p1, &p3), (&p2, &p3), (&p1, &p4)].iter().enumerate() {
            assert_ne!(x, y, "pair {i}: two proofs of one witness must differ");
        }
    }

    /// Re-genesis batch 2 (lab #747): rc = 0 is a checked property, not a
    /// comment — the constant is 0, and a real proof carries no random-codeword
    /// openings (every per-matrix, per-point vector of `opened_values_rand` is
    /// empty). Chain-only 2^13, as above.
    #[test]
    fn rc_is_zero_and_no_random_openings_travel() {
        use qlab_air::narrow::NarrowKeccakAir;
        assert_eq!(NUM_RANDOM_CODEWORDS, 0, "rc = 0 on the T-net (lab #742 ruling)");
        let air = NarrowKeccakAir::chain_only(13);
        let pvs = vec![Val::ZERO; <NarrowKeccakAir as p3_air::BaseAir<Val>>::num_public_values(&air)];
        let trace = air.generate_trace::<Val>(CONSENSUS_CFG.log_blowup);
        let proof = prove(&make_config(), &air, trace, &pvs);
        let rand = &proof.opening_proof.0;
        assert!(!rand.is_empty(), "the hiding PCS still reports its rounds");
        for (r, round) in rand.iter().enumerate() {
            for (m, mat) in round.iter().enumerate() {
                for (z, point) in mat.iter().enumerate() {
                    assert!(point.is_empty(), "round {r} matrix {m} point {z}: a random-codeword opening travelled");
                }
            }
        }
        assert!(verify(&make_config(), &air, &proof, &pvs).is_ok());
    }
}
