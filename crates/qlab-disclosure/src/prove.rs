//! The prover stack for the disclosure AIR — the SAME field / extension / FRI
//! Merkle-hash / DFT choices and the SAME `>= 100 bit conjectured` discipline
//! as `qlab-bench` (Plonky3 0.6.1, KoalaBear + degree-4 extension, Keccak-256
//! FRI Merkle). Replicated here because `qlab-bench` is a binary crate — its
//! config helpers are not importable — not because anything differs.

use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_field::PrimeCharacteristicRing;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_koala_bear::KoalaBear;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark::{prove as p3_prove, verify as p3_verify, Proof, StarkConfig};

use crate::air::{DisclosureAir, DisclosureInstance};

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
pub type DisclosureProof = Proof<Config>;

/// One FRI parameter point (mirrors qlab-bench's `FriCfg`).
#[derive(Clone, Copy, Debug)]
pub struct FriCfg {
    pub log_blowup: usize,
    pub num_queries: usize,
    pub grind_bits: usize,
    pub log_final_poly_len: usize,
    pub max_log_arity: usize,
}

impl FriCfg {
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

    /// Conjectured-security capacity proxy (queries·log2(blowup) + grind),
    /// the same value qlab-bench asserts `>= 100`.
    pub fn conjectured_bits(&self) -> usize {
        self.num_queries * self.log_blowup + self.grind_bits
    }
}

/// The consensus lane, post-B′ grind (g22): b16/q20/g22, 100-bit conjectured
/// — the disclosure floor is reported against this and its low-blowup siblings.
pub const CONSENSUS_CFG: FriCfg = FriCfg {
    log_blowup: 4,
    num_queries: 20,
    grind_bits: 22,
    log_final_poly_len: 0,
    max_log_arity: 4,
};

pub fn make_config(cfg: &FriCfg) -> Config {
    let byte_hash = ByteHash {};
    let u64_hash = U64Hash::new(KeccakF {});
    let field_hash = FieldHash::new(u64_hash);
    let compress = MyCompress::new(u64_hash);
    let val_mmcs = ValMmcs::new(field_hash, compress, 3);
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
    assert!(
        fri_params.conjectured_soundness_bits() >= 100,
        "config {} is only {} bits conjectured",
        cfg.label(),
        fri_params.conjectured_soundness_bits(),
    );
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri_params);
    Config::new(pcs, challenger)
}

/// Prove a disclosure instance under `cfg`.
pub fn prove(inst: &DisclosureInstance, cfg: &FriCfg) -> DisclosureProof {
    let config = make_config(cfg);
    let pvs: Vec<Val> = inst.pvs.iter().map(|v| Val::from_u32(*v)).collect();
    let trace = inst.air.generate_trace::<Val>(cfg.log_blowup);
    p3_prove(&config, &inst.air, trace, &pvs)
}

/// Verify a disclosure proof against `air` (which fixes the height/schedule)
/// and the public values. Returns `Err(reason)` on any failure (bad opening,
/// out-of-domain mismatch, unsatisfied constraint).
pub fn verify(
    air: &DisclosureAir,
    proof: &DisclosureProof,
    pvs: &[u32],
    cfg: &FriCfg,
) -> Result<(), String> {
    let config = make_config(cfg);
    let pvs: Vec<Val> = pvs.iter().map(|v| Val::from_u32(*v)).collect();
    p3_verify(&config, air, proof, &pvs).map_err(|e| format!("{e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::air::build_disclosure;
    use qlab_note::kem::generate_keypair;
    use qlab_wallet::address::{Address, Diversifier};
    use rand::{rngs::StdRng, SeedableRng};

    fn small_cfg() -> FriCfg {
        FriCfg {
            log_blowup: 2,
            num_queries: 45,
            grind_bits: 10,
            log_final_poly_len: 2,
            max_log_arity: 3,
        }
    }

    fn sample_instance() -> DisclosureInstance {
        let mut rng = StdRng::seed_from_u64(9);
        let kp = generate_keypair(&mut rng);
        let rkm = [0xabcdu64, 0x1234, 0x5678, 0x9abc];
        let addr = Address::new(Diversifier::from_bytes([2u8; 16]), rkm, &kp.ek);
        build_disclosure(
            16,
            9_999u64,
            &rkm,
            &[1, 2, 3, 4],
            &[5, 6, 7, 8],
            &addr.to_raw_bytes(),
        )
    }

    /// End-to-end: a real disclosure instance proves and verifies through the
    /// full FRI stack (debug builds also run check_constraints inside prove).
    #[test]
    fn prove_verify_roundtrip() {
        let inst = sample_instance();
        let cfg = small_cfg();
        let proof = prove(&inst, &cfg);
        verify(&inst.air, &proof, &inst.pvs, &cfg).expect("verify");
    }

    /// A tampered public value must be rejected by the verifier.
    #[test]
    fn wrong_pv_rejected() {
        let inst = sample_instance();
        let cfg = small_cfg();
        let proof = prove(&inst, &cfg);
        let mut bad = inst.pvs.clone();
        bad[crate::air::PV_ADDR] ^= 1;
        assert!(verify(&inst.air, &proof, &bad, &cfg).is_err());
    }
}
