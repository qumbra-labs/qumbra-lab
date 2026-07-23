//! Deterministic RandomX hashing over `randomx-rs` (reference tevador/RandomX).
//!
//! ## Light mode, by design
//!
//! We build a **cache** (≈256 MiB) and run the VM against it — we do NOT build
//! the ≈2 GiB dataset ("fast mode"). Verification and light mining only need the
//! cache; the dataset is a mining throughput optimization the devnet does not
//! need, and its footprint would dominate the workspace test suite's RAM. The
//! RandomX output is **identical** in light and fast mode, so reference vectors
//! computed either way match.
//!
//! ## Determinism
//!
//! A RandomX hash is a pure function of `(key, input)` — independent of the flag
//! set (JIT vs interpreter, hard vs soft AES). We use `get_recommended_flags()`
//! (auto-detected AES + JIT, plus `FLAG_SECURE` for W^X on hardened runtimes),
//! which is the fast *and* correct choice; the vectors below prove the output is
//! the canonical one.
//!
//! ## Key memoization
//!
//! Building the cache is expensive (~100s of ms). RandomX rotates its key only on
//! a key-block boundary (see `keyblock`), so within a key epoch every hash shares
//! one key. [`RandomXHasher`] therefore memoizes the `(key, VM)` pair and rebuilds
//! only when the key changes — turning per-hash cache builds into per-epoch ones.

use std::cell::RefCell;

use randomx_rs::{RandomXCache, RandomXFlag, RandomXVM};

/// A 256-bit RandomX digest.
pub type Hash32 = [u8; 32];

/// A deterministic, key-memoizing RandomX hasher (light mode).
///
/// `&self` hashing with interior mutability: the cache/VM are rebuilt lazily when
/// the key changes, so a caller can hash a whole key-epoch's worth of headers
/// through one `RandomXHasher` and pay the cache-build cost once.
pub struct RandomXHasher {
    flags: RandomXFlag,
    keyed: RefCell<Option<Keyed>>,
}

/// The cache/VM currently loaded, tagged by the key that built it.
struct Keyed {
    key: Vec<u8>,
    vm: RandomXVM,
}

impl RandomXHasher {
    /// A hasher using the platform's recommended flags (auto AES + JIT + secure).
    pub fn new() -> Self {
        Self::with_flags(RandomXFlag::get_recommended_flags())
    }

    /// A hasher with explicit flags (tests pin `FLAG_DEFAULT` to prove the output
    /// is flag-independent).
    pub fn with_flags(flags: RandomXFlag) -> Self {
        Self {
            flags,
            keyed: RefCell::new(None),
        }
    }

    /// The RandomX flags this hasher builds VMs with.
    pub fn flags(&self) -> RandomXFlag {
        self.flags
    }

    /// The RandomX hash of `input` under RandomX key `key`. Rebuilds the cache/VM
    /// iff `key` differs from the currently-loaded one.
    ///
    /// Panics only on a RandomX allocation/init failure (out of memory building
    /// the cache), which is not a recoverable condition for a miner/validator.
    pub fn hash(&self, key: &[u8], input: &[u8]) -> Hash32 {
        let mut slot = self.keyed.borrow_mut();
        let need_rebuild = match slot.as_ref() {
            Some(k) => k.key != key,
            None => true,
        };
        if need_rebuild {
            let cache = RandomXCache::new(self.flags, key)
                .expect("RandomX cache allocation failed");
            let vm = RandomXVM::new(self.flags, Some(cache), None)
                .expect("RandomX VM creation failed");
            *slot = Some(Keyed { key: key.to_vec(), vm });
        }
        let digest = slot
            .as_ref()
            .expect("keyed VM present after rebuild")
            .vm
            .calculate_hash(input)
            .expect("RandomX hash computation failed");
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }
}

impl Default for RandomXHasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four official RandomX test vectors (tevador/RandomX
    /// `src/tests/tests.cpp`, the `calculate_hash` cases), verified against the
    /// reference build. These pin our binding to the canonical RandomX output.
    const KEY_000: &[u8] = b"test key 000";
    const KEY_001: &[u8] = b"test key 001";
    const SED: &[u8] =
        b"sed do eiusmod tempor incididunt ut labore et dolore magna aliqua";

    /// (key, input, expected-hex).
    const VECTORS: &[(&[u8], &[u8], &str)] = &[
        (
            KEY_000,
            b"This is a test",
            "639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f",
        ),
        (
            KEY_000,
            b"Lorem ipsum dolor sit amet",
            "300a0adb47603dedb42228ccb2b211104f4da45af709cd7547cd049e9489c969",
        ),
        (
            KEY_000,
            SED,
            "c36d4ed4191e617309867ed66a443be4075014e2b061bcdaf9ce7b721d2b77a8",
        ),
        (
            KEY_001,
            SED,
            "e9ff4503201c0c2cca26d285c93ae883f9b1d30c9eb240b820756f2d5a7905fc",
        ),
    ];

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn matches_official_reference_vectors() {
        let h = RandomXHasher::new();
        for (key, input, want) in VECTORS {
            assert_eq!(&hex(&h.hash(key, input)), want, "vector for key {key:?}");
        }
    }

    /// A RandomX hash is a pure function of (key, input): the platform-recommended
    /// flags (JIT/AES/secure) and the portable `FLAG_DEFAULT` must agree.
    #[test]
    fn output_is_flag_independent() {
        let recommended = RandomXHasher::new();
        let portable = RandomXHasher::with_flags(RandomXFlag::FLAG_DEFAULT);
        for (key, input, _) in VECTORS {
            assert_eq!(
                recommended.hash(key, input),
                portable.hash(key, input),
                "flags must not change the RandomX output",
            );
        }
    }

    /// Same (key, input) ⇒ same hash; changing the key OR the input changes it.
    #[test]
    fn deterministic_and_key_and_input_sensitive() {
        let h = RandomXHasher::new();
        let base = h.hash(KEY_000, b"This is a test");
        assert_eq!(base, h.hash(KEY_000, b"This is a test"), "must be deterministic");
        assert_ne!(base, h.hash(KEY_001, b"This is a test"), "key must matter");
        assert_ne!(base, h.hash(KEY_000, b"This is a NOT test"), "input must matter");
    }

    /// Memoization: re-hashing under the SAME key (many inputs) stays correct even
    /// though the cache is only built once; switching keys rebuilds transparently.
    #[test]
    fn memoized_key_switch_stays_correct() {
        let h = RandomXHasher::new();
        // Interleave keys to force rebuilds, asserting every result stays canonical.
        for (key, input, want) in VECTORS.iter().rev().chain(VECTORS.iter()) {
            assert_eq!(&hex(&h.hash(key, input)), want);
        }
    }
}
