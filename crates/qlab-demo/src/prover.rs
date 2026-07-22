//! F1: the Plonky3 consensus prover configuration, reconstructed as library API.
//!
//! The identical plumbing lives `pub(crate)` inside the `qlab-bench` *binary*
//! (main.rs type aliases + `make_config_with`; m4gaterec.rs `CONSENSUS_CFG`),
//! so it cannot be imported. This is the standard StarkConfig any integrator
//! constructs; it is NOT a fork of crate logic. Value-locked to the documented
//! decision (issue #22 B′) and guarded by `real_m3_proof_roundtrips`.
//! Follow-up: extract a shared `qlab-consensus` crate so bench + demo agree.

use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_field::PrimeCharacteristicRing;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_koala_bear::KoalaBear;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark::{prove, verify, Proof, StarkConfig};

use qlab_air::narrow::BucketInstance;

pub type Val = KoalaBear;
type Challenge = BinomialExtensionField<Val, 4>;

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
type Dft = p3_dft::Radix2DitParallel<Val>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
pub type Config = StarkConfig<Pcs, Challenge, Challenger>;

/// One FRI parameter point (only FRI params vary; field/hash held fixed).
#[derive(Clone, Copy)]
pub struct FriCfg {
    pub log_blowup: usize,
    pub num_queries: usize,
    pub grind_bits: usize,
    pub log_final_poly_len: usize,
    pub max_log_arity: usize,
}

/// The decided consensus config (issue #41 B″): b16/q21/g22/fp16/a16 — query
/// 20 → 21 restores ~100-bit conjectured under the 2197-corrected accounting
/// (`fri-soundness-accounting-2026-07.md` §6). Must stay equal to the lab's
/// canonical `m4gaterec::CONSENSUS_CFG` (cross-crate copy — qlab-demo can't
/// import from the qlab-bench bin crate; the value-lock test below pins it).
pub const CONSENSUS_CFG: FriCfg = FriCfg {
    log_blowup: 4,
    num_queries: 21,
    grind_bits: 22,
    log_final_poly_len: 4,
    max_log_arity: 4,
};
pub const LOG_HEIGHT: usize = 18;

pub fn make_config() -> Config {
    let byte_hash = ByteHash {};
    let u64_hash = U64Hash::new(KeccakF {});
    let field_hash = FieldHash::new(u64_hash);
    let compress = MyCompress::new(u64_hash);
    let val_mmcs = ValMmcs::new(field_hash, compress, 3);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let challenger = Challenger::from_hasher(vec![], byte_hash);
    let fri_params = FriParameters {
        log_blowup: CONSENSUS_CFG.log_blowup,
        log_final_poly_len: CONSENSUS_CFG.log_final_poly_len,
        max_log_arity: CONSENSUS_CFG.max_log_arity,
        num_queries: CONSENSUS_CFG.num_queries,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: CONSENSUS_CFG.grind_bits,
        mmcs: challenge_mmcs,
    };
    assert!(
        fri_params.conjectured_soundness_bits() >= 100,
        "consensus config must clear the ~100-bit capacity bar"
    );
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri_params);
    Config::new(pcs, challenger)
}

/// Public values as field elements, from a bucket instance.
pub fn public_values(inst: &BucketInstance) -> Vec<Val> {
    inst.pvs.iter().map(|v| Val::from_u32(*v)).collect()
}

/// Generate the trace and prove the bucket at the consensus config (~1.6 s).
pub fn prove_bucket(inst: &BucketInstance) -> (Vec<Val>, Proof<Config>) {
    let config = make_config();
    let pvs = public_values(inst);
    let trace = inst.air.generate_trace::<Val>(CONSENSUS_CFG.log_blowup);
    let proof = prove(&config, &inst.air, trace, &pvs);
    (pvs, proof)
}

/// Node-side verification of a proof against its instance + public values.
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
        // Locked to the documented decision (issue #41 B″): b16/q21/g22/fp16/a16.
        assert_eq!(CONSENSUS_CFG.log_blowup, 4);
        assert_eq!(CONSENSUS_CFG.num_queries, 21);
        assert_eq!(CONSENSUS_CFG.grind_bits, 22);
        assert_eq!(CONSENSUS_CFG.log_final_poly_len, 4);
        assert_eq!(CONSENSUS_CFG.max_log_arity, 4);
        assert_eq!(LOG_HEIGHT, 18);
    }

    #[test]
    fn real_m3_proof_roundtrips() {
        // A balanced 2-in/2-out bucket (50k+30k = 60k+19k+1k fee).
        let inputs = [
            TxInput { sk: [1, 2, 3, 4], value: 50_000, rho: [5, 6, 7, 8], rseed: [9, 10, 11, 12], d: [0, 0] },
            TxInput { sk: [13, 14, 15, 16], value: 30_000, rho: [17, 18, 19, 20], rseed: [21, 22, 23, 24], d: [0, 0] },
        ];
        let outputs = [
            TxOutput { value: 60_000, rkm: [1; 4], rho: [2; 4], rseed: [3; 4] },
            TxOutput { value: 19_000, rkm: [4; 4], rho: [5; 4], rseed: [6; 4] },
        ];
        let inst = build_bucket(LOG_HEIGHT, &inputs, &outputs, 1_000);
        let (pvs, proof) = prove_bucket(&inst);
        assert!(verify_proof(&inst, &pvs, &proof), "real M3 proof must verify");
    }
}
