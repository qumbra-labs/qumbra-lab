//! Proof-of-work behind a trait: the real **RandomX** engine ([`RandomXPow`]) and
//! the Keccak **placeholder** ([`KeccakPow`]) that predated it.
//!
//! ## From placeholder to RandomX (M9-N3)
//!
//! The M6 devnet shipped only [`KeccakPow`] while the algorithm stayed an open
//! question (consensus-and-network §10: "CPU-friendly RandomX-class"). M9-N3
//! answers it: [`RandomXPow`] binds the reference RandomX (via `qlab-pow`) as the
//! block hash. Both live behind [`PowEngine`], so mining, validation and fork
//! choice are engine-agnostic — a node picks its engine at construction.
//!
//! ## The keyed hash
//!
//! RandomX is **keyed**: the VM is seeded from a rotating *key block* (see
//! `qlab_pow::keyblock`). [`PowEngine::pow_hash`] therefore takes the `seed` (the
//! key-block hash) alongside the header; the devnet computes it from the chain
//! ([`crate::validation::pow_seed`]). The Keccak placeholder **ignores** the seed
//! — it has no key concept — so its output is unchanged from M6, keeping every M6
//! test a byte-for-byte regression guard.
//!
//! ## Sim difficulty model
//!
//! A real target is a 256-bit threshold. The devnet keeps its scalar
//! simplification: interpret the PoW hash's leading 8 bytes as a big-endian `u64`,
//! and require it `≤ u64::MAX / difficulty`. Higher difficulty ⇒ smaller threshold
//! ⇒ more work; a block's `difficulty` doubles as its heaviest-chain weight. This
//! is a sim convenience, not a consensus rule proposal, and it is what LWMA-120
//! (`qlab_pow::lwma`, wired in [`crate::validation`]) retargets.

#[cfg(feature = "randomx")]
use qlab_pow::RandomXHasher;

use crate::forms::GenesisForm;
use crate::header::{BlockHeader, Hash32};

/// The PoW algorithm, abstracted so mining/validation/fork-choice never name a
/// concrete engine.
pub trait PowEngine {
    /// Human-readable algorithm name (surfaced in logs / reports).
    fn name(&self) -> &'static str;

    /// The PoW hash of `header` under RandomX key `seed` (the key-block hash;
    /// ignored by engines without a key, like [`KeccakPow`]). Mining varies
    /// `header.nonce` and re-hashes until [`satisfies_target`] holds.
    ///
    /// `form` selects the preimage layout (lab #470 stage 1): the PoW message
    /// is the canonical header preimage **under the net's genesis form**, so
    /// the engine cannot be fed one layout by the miner and another by the
    /// validator — both receive the form from the one installed [`ChainRules`]
    /// (`crate::forms::ChainRules`).
    fn pow_hash(&self, form: GenesisForm, header: &BlockHeader, seed: &[u8]) -> Hash32;
}

/// DEVNET PLACEHOLDER PoW: Keccak-256 of the header preimage.
///
/// Predates RandomX integration; retained as a fast, allocation-free engine for
/// the consensus/finality/network sims that don't need a real PoW primitive. It
/// has no key concept, so it **ignores** the `seed` — its output is identical to
/// the M6 placeholder.
#[derive(Clone, Copy, Debug, Default)]
pub struct KeccakPow;

impl PowEngine for KeccakPow {
    fn name(&self) -> &'static str {
        "keccak-devnet-placeholder"
    }

    fn pow_hash(&self, form: GenesisForm, header: &BlockHeader, _seed: &[u8]) -> Hash32 {
        // No key: the seed does not participate (documented placeholder behavior).
        header.header_hash_for(form)
    }
}

/// The real CPU-friendly PoW: **RandomX** over the header preimage, keyed by the
/// rotating key-block seed.
///
/// Wraps a memoizing [`RandomXHasher`] (light mode). Not `Clone`/`Sync` (it owns a
/// RandomX VM behind a `RefCell`); the multi-node [`crate::net::Network`] sims,
/// which need `Clone`, stay on [`KeccakPow`]. A single [`crate::node::Node`] drives
/// RandomX fine.
#[cfg(feature = "randomx")]
pub struct RandomXPow {
    hasher: RandomXHasher,
}

#[cfg(feature = "randomx")]
impl RandomXPow {
    /// A RandomX engine using the platform's recommended flags.
    pub fn new() -> Self {
        Self {
            hasher: RandomXHasher::new(),
        }
    }
}

#[cfg(feature = "randomx")]
impl Default for RandomXPow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "randomx")]
impl PowEngine for RandomXPow {
    fn name(&self) -> &'static str {
        "randomx"
    }

    fn pow_hash(&self, form: GenesisForm, header: &BlockHeader, seed: &[u8]) -> Hash32 {
        // RandomX key = the key-block seed; message = the canonical header
        // preimage under the net's form.
        self.hasher.hash(seed, &header.preimage_for(form))
    }
}

/// Interpret a PoW hash's leading 8 bytes as a big-endian `u64` work value.
pub fn hash_to_work_value(hash: &Hash32) -> u64 {
    u64::from_be_bytes(hash[..8].try_into().expect("Hash32 has ≥ 8 bytes"))
}

/// The sim target threshold at `difficulty`: `u64::MAX / max(difficulty, 1)`.
/// Monotonically non-increasing in difficulty — more difficulty, harder target.
pub fn target_threshold(difficulty: u64) -> u64 {
    u64::MAX / difficulty.max(1)
}

/// Whether a PoW hash satisfies the target at `difficulty`.
pub fn satisfies_target(hash: &Hash32, difficulty: u64) -> bool {
    hash_to_work_value(hash) <= target_threshold(difficulty)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_is_monotone_in_difficulty() {
        // Higher difficulty ⇒ strictly-not-larger threshold.
        assert!(target_threshold(1) >= target_threshold(10));
        assert!(target_threshold(10) >= target_threshold(1_000));
        assert!(target_threshold(1_000) >= target_threshold(1_000_000));
        // Difficulty 0 is treated as 1 (no divide-by-zero).
        assert_eq!(target_threshold(0), target_threshold(1));
    }

    #[test]
    fn a_mined_nonce_actually_satisfies_the_target() {
        // At a low difficulty a valid nonce is found in a handful of tries; the
        // found header must satisfy the target under the same engine.
        let pow = KeccakPow;
        let mut h = BlockHeader::genesis(4, 0); // easy target
        let mut found = None;
        for nonce in 0..100_000u64 {
            h.nonce = nonce;
            let hash = pow.pow_hash(GenesisForm::V4, &h, &[]);
            if satisfies_target(&hash, h.difficulty) {
                found = Some(nonce);
                break;
            }
        }
        let nonce = found.expect("must find a valid nonce at difficulty 4");
        h.nonce = nonce;
        assert!(satisfies_target(&pow.pow_hash(GenesisForm::V4, &h, &[]), h.difficulty));
    }

    #[test]
    fn keccak_placeholder_ignores_the_seed() {
        // The placeholder's output must not depend on the key-block seed — that is
        // what keeps every M6 test a valid regression guard.
        let h = BlockHeader::genesis(1_000, 0);
        let pow = KeccakPow;
        assert_eq!(
            pow.pow_hash(GenesisForm::V4, &h, &[]),
            pow.pow_hash(GenesisForm::V4, &h, b"any seed at all")
        );
        assert!(pow.name().contains("placeholder"));
    }
}
