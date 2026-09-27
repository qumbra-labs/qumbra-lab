//! Counting mirror of the live hiding L2 verifier config. Never used to prove.
//! Same primitives as consensus; counters belong to one verification only.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_fri::{FriParameters, HidingFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{
    CompressionFunctionFromHasher, CryptographicHasher, CryptographicPermutation,
    PaddingFreeSponge, Permutation, SerializingHasher,
};
use p3_uni_stark::StarkConfig;
use qlab_consensus::{
    Challenge, Dft, ProverRng, Val, CAP_HEIGHT, NUM_RANDOM_CODEWORDS, SALT_ELEMS,
};
use qlab_l2::L2_CFG_PROVISIONAL;
use serde_json::{json, Value};

#[derive(Clone, Default)]
pub(super) struct Counters {
    leaf: Arc<AtomicUsize>,
    compression: Arc<AtomicUsize>,
    flush_bytes: Arc<Mutex<Vec<usize>>>,
}

#[derive(Clone)]
pub(super) struct CountPermutation(Arc<AtomicUsize>);

impl<T: Clone> Permutation<T> for CountPermutation
where
    KeccakF: Permutation<T>,
{
    fn permute_mut(&self, input: &mut T) {
        self.0.fetch_add(1, Ordering::Relaxed);
        KeccakF {}.permute_mut(input);
    }
}

impl<T: Clone> CryptographicPermutation<T> for CountPermutation where
    KeccakF: CryptographicPermutation<T>
{
}

#[derive(Clone)]
pub(super) struct CountHash(Arc<Mutex<Vec<usize>>>);

impl CryptographicHasher<u8, [u8; 32]> for CountHash {
    fn hash_iter<I: IntoIterator<Item = u8>>(&self, input: I) -> [u8; 32] {
        let bytes: Vec<_> = input.into_iter().collect();
        self.0.lock().unwrap().push(bytes.len());
        Keccak256Hash.hash_iter(bytes)
    }
}

type Sponge = PaddingFreeSponge<CountPermutation, 25, 17, 4>;
type Mmcs = MerkleTreeHidingMmcs<
    [Val; p3_keccak::VECTOR_LEN],
    [u64; p3_keccak::VECTOR_LEN],
    SerializingHasher<Sponge>,
    CompressionFunctionFromHasher<Sponge, 2, 4>,
    ProverRng,
    2,
    4,
    SALT_ELEMS,
>;
type ExtMmcs = ExtensionMmcs<Val, Challenge, Mmcs>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, CountHash, 32>>;
type Pcs = HidingFriPcs<Val, Dft, Mmcs, ExtMmcs, ProverRng>;
pub(super) type Config = StarkConfig<Pcs, Challenge, Challenger>;

impl Counters {
    pub(super) fn config(&self) -> Config {
        let leaf = SerializingHasher::new(Sponge::new(CountPermutation(self.leaf.clone())));
        let compression = CompressionFunctionFromHasher::new(Sponge::new(CountPermutation(
            self.compression.clone(),
        )));
        // Verification draws no randomness. Separate RNGs mirror consensus's
        // ownership and avoid introducing a reusable proving configuration.
        let input = Mmcs::new(
            leaf.clone(),
            compression.clone(),
            CAP_HEIGHT,
            ProverRng::from_os(),
        );
        let fri = ExtMmcs::new(Mmcs::new(
            leaf,
            compression,
            CAP_HEIGHT,
            ProverRng::from_os(),
        ));
        let cfg = L2_CFG_PROVISIONAL;
        let params = FriParameters {
            log_blowup: cfg.log_blowup,
            log_final_poly_len: cfg.log_final_poly_len,
            max_log_arity: cfg.max_log_arity,
            num_queries: cfg.num_queries,
            commit_proof_of_work_bits: 0,
            query_proof_of_work_bits: cfg.grind_bits,
            mmcs: fri,
        };
        Config::new(
            Pcs::new(
                Dft::default(),
                input,
                params,
                NUM_RANDOM_CODEWORDS,
                ProverRng::from_os(),
            ),
            Challenger::from_hasher(vec![], CountHash(self.flush_bytes.clone())),
        )
    }

    pub(super) fn report(&self) -> Value {
        let leaf = self.leaf.load(Ordering::Relaxed);
        let compression = self.compression.load(Ordering::Relaxed);
        let flushes = self.flush_bytes.lock().unwrap();
        let fs: usize = flushes.iter().map(|n| n / 136 + 1).sum();
        json!({"evidence": "M", "source": "successful counting native verification",
            "leaf_absorb_permutations": leaf, "path_compression_permutations": compression,
            "challenger_permutations": fs, "total_permutations": leaf + compression + fs,
            "challenger_flush_bytes": *flushes})
    }
}
