//! Domain-separated key/tag derivation from the ML-KEM shared secret.
//!
//! The doc (§2, "Detection-tag derivation domain separation") left the exact
//! derivation open for this prototype. All outputs are Keccak-256 of a
//! DISTINCT domain constant followed by the shared secret and a per-item
//! binder — so the public detection tag reveals nothing about the AEAD key or
//! nonce (independent random-oracle outputs).
//!
//! - `detection_tag` binds `(K, cm)` → wrong-key/wrong-cm scans miss (no false
//!   detection), and `K` being secret means no attacker can forge a tag.
//! - `aead_key` / `aead_nonce` bind `(K, index)`, NOT `cm`: `K` is shared
//!   across a recipient's outputs in one tx (amortization), so indexing by the
//!   note's output slot gives a DISTINCT key+nonce per note (no nonce reuse
//!   under the shared key), while leaving the note commitment free to be the
//!   sole, independently-checked authenticity anchor on scan path (b).

use crate::hash::{digest_bytes, keccak256};

/// Detection-tag length in bytes → 2^-64 false-positive rate.
pub const TAG_LEN: usize = 8;

/// Domain-separation constants (distinct byte prefixes, versioned).
pub const DS_TAG: &[u8] = b"qumbra:note-detect:v1";
pub const DS_AEAD: &[u8] = b"qumbra:note-aead-key:v1";
pub const DS_NONCE: &[u8] = b"qumbra:note-aead-nonce:v1";

fn kdf(domain: &[u8], k: &[u8; 32], binder: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(domain.len() + 32 + binder.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(k);
    input.extend_from_slice(binder);
    keccak256(&input)
}

/// `tag = Keccak256(DS_TAG ‖ K ‖ cm)[0..8]`. `cm` is qlab-air's `[u64;4]`
/// commitment. 8 bytes → 2^-64 false-positive against a wrong `(K, cm)`.
pub fn detection_tag(k: &[u8; 32], cm: &[u64; 4]) -> [u8; TAG_LEN] {
    let d = kdf(DS_TAG, k, &digest_bytes(cm));
    d[..TAG_LEN].try_into().expect("TAG_LEN <= 32")
}

/// `k_aead = Keccak256(DS_AEAD ‖ K ‖ u32le(index))` — 32-byte ChaCha20 key,
/// distinct per output `index` under a shared `K`.
pub fn aead_key(k: &[u8; 32], index: u32) -> [u8; 32] {
    kdf(DS_AEAD, k, &index.to_le_bytes())
}

/// `nonce = Keccak256(DS_NONCE ‖ K ‖ u32le(index))[0..12]` — 96-bit nonce,
/// distinct per output `index`.
pub fn aead_nonce(k: &[u8; 32], index: u32) -> [u8; 12] {
    let d = kdf(DS_NONCE, k, &index.to_le_bytes());
    d[..12].try_into().expect("12 <= 32")
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: [u8; 32] = [0x11; 32];
    const K2: [u8; 32] = [0x22; 32];

    #[test]
    fn tag_determinism_and_sensitivity() {
        let cm_a = [1u64, 2, 3, 4];
        let cm_b = [1u64, 2, 3, 5];
        assert_eq!(detection_tag(&K, &cm_a), detection_tag(&K, &cm_a), "deterministic");
        assert_ne!(detection_tag(&K, &cm_a), detection_tag(&K, &cm_b), "cm-sensitive");
        assert_ne!(detection_tag(&K, &cm_a), detection_tag(&K2, &cm_a), "K-sensitive");
        assert_eq!(detection_tag(&K, &cm_a).len(), 8);
    }

    #[test]
    fn per_index_key_nonce_distinct() {
        assert_ne!(aead_key(&K, 0), aead_key(&K, 1), "keys distinct per index");
        assert_ne!(aead_nonce(&K, 0), aead_nonce(&K, 1), "nonces distinct per index");
        assert_eq!(aead_key(&K, 5), aead_key(&K, 5), "deterministic");
        assert_eq!(aead_key(&K, 0).len(), 32);
        assert_eq!(aead_nonce(&K, 0).len(), 12);
    }

    /// Domain separation: changing ONLY the domain constant (same K, same
    /// binder bytes) yields an independent output — the tag can't leak the key.
    #[test]
    fn domain_separation() {
        let binder = 7u32.to_le_bytes();
        let via_tag = kdf(DS_TAG, &K, &binder);
        let via_aead = kdf(DS_AEAD, &K, &binder);
        let via_nonce = kdf(DS_NONCE, &K, &binder);
        assert_ne!(via_tag, via_aead);
        assert_ne!(via_tag, via_nonce);
        assert_ne!(via_aead, via_nonce);
    }
}
