//! Share-PoW execution.
//!
//! **Where hashing lives (the stage-2 decision):** the RandomX primitive
//! stays in [`qlab_pow::RandomXHasher`] — this crate does not fork the
//! engine. Composition is a [`ShareHasher`] trait:
//!
//! - Production (`feature = "randomx"`, default ON): [`RandomXShareHasher`]
//!   wraps `RandomXHasher::hash(seed, blob)`.
//! - Tests / `Pool::new`: [`FixedHasher`] returns a predetermined digest
//!   so unit tests never build a 256 MiB RandomX cache.
//!
//! `qlab-stratum` stays off this graph. `qlab-devnet` stays
//! `default-features = false`. Only `qlab-pow/randomx` is flipped on.

use qlab_devnet::header::Hash32;

/// Hash a reconstructed job blob under the job's RandomX seed.
pub trait ShareHasher: Send {
    fn hash(&self, seed: &[u8], blob: &[u8]) -> Hash32;
}

/// Test / structural hasher: every `(seed, blob)` returns `digest`.
/// Existing stage-1 tests submit an all-zero `result` and keep working
/// when the pool is built with [`FixedHasher::zeros`].
pub struct FixedHasher {
    pub digest: Hash32,
}

impl FixedHasher {
    pub fn zeros() -> Self {
        Self { digest: [0u8; 32] }
    }
}

impl ShareHasher for FixedHasher {
    fn hash(&self, _seed: &[u8], _blob: &[u8]) -> Hash32 {
        self.digest
    }
}

/// Keccak-256 of the blob, seed ignored — matches [`qlab_devnet::pow::KeccakPow`].
/// Live-leg tests drive an in-process node on KeccakPow so share-PoW and
/// consensus-PoW are the same function.
pub struct KeccakShareHasher;

impl ShareHasher for KeccakShareHasher {
    fn hash(&self, _seed: &[u8], blob: &[u8]) -> Hash32 {
        qlab_devnet::hash::keccak256(blob)
    }
}

/// Production hasher. `RandomXHasher` is `!Send` (raw VM pointers), so
/// the VM lives on a dedicated thread and this handle is a channel.
#[cfg(feature = "randomx")]
pub struct RandomXShareHasher {
    tx: std::sync::Mutex<std::sync::mpsc::Sender<HashJob>>,
}

#[cfg(feature = "randomx")]
struct HashJob {
    seed: Vec<u8>,
    blob: Vec<u8>,
    reply: std::sync::mpsc::Sender<Hash32>,
}

#[cfg(feature = "randomx")]
impl RandomXShareHasher {
    pub fn new() -> Self {
        let (tx, rx) = std::sync::mpsc::channel::<HashJob>();
        std::thread::Builder::new()
            .name("qumbra-pool-randomx".into())
            .spawn(move || {
                let hasher = qlab_pow::RandomXHasher::new();
                while let Ok(job) = rx.recv() {
                    let digest = hasher.hash(&job.seed, &job.blob);
                    let _ = job.reply.send(digest);
                }
            })
            .expect("spawn RandomX hash thread");
        Self {
            tx: std::sync::Mutex::new(tx),
        }
    }
}

#[cfg(feature = "randomx")]
impl Default for RandomXShareHasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "randomx")]
impl ShareHasher for RandomXShareHasher {
    fn hash(&self, seed: &[u8], blob: &[u8]) -> Hash32 {
        let (rtx, rrx) = std::sync::mpsc::channel();
        self.tx
            .lock()
            .expect("hash channel")
            .send(HashJob {
                seed: seed.to_vec(),
                blob: blob.to_vec(),
                reply: rtx,
            })
            .expect("RandomX thread alive");
        rrx.recv().expect("RandomX hash reply")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_hasher_returns_the_injected_digest() {
        let h = FixedHasher { digest: [0xAB; 32] };
        assert_eq!(h.hash(b"seed", b"blob"), [0xAB; 32]);
        assert_eq!(FixedHasher::zeros().hash(&[], &[]), [0u8; 32]);
    }

    /// Composition proof: the wrapper's digest IS qlab-pow's official
    /// first vector. Runs only when the feature is on (CI default).
    #[cfg(feature = "randomx")]
    #[test]
    fn randomx_wrapper_matches_qlab_pow_official_vector() {
        let h = RandomXShareHasher::new();
        let got = h.hash(b"test key 000", b"This is a test");
        let want_v = hex_decode("639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f");
        let mut want = [0u8; 32];
        want.copy_from_slice(&want_v);
        assert_eq!(got, want, "wrapper must not fork the engine");
    }

    #[cfg(feature = "randomx")]
    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
