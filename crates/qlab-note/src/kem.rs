//! ML-KEM-768 wrapper: key generation, encapsulation, and full-FO
//! decapsulation (the standard IND-CCA usage — scan path (a)).
//!
//! Backed by `ml-kem` 0.3.2 (RustCrypto, FIPS 203 final; tested upstream vs
//! NIST ACVP + Wycheproof). We deliberately treat the KEM as a black box and
//! do NOT reimplement any of its internals.
//!
//! ## FO-skip / path (b) — an honest note
//!
//! The ratified design's scan path (b) skips the Fujisaki–Okamoto
//! re-encryption check at scan time (authenticity recovered by recomputing the
//! note commitment, `note::note_commitment`). A *true* CPA-only decapsulation
//! needs the inner K-PKE.Decrypt, but in `ml-kem` 0.3.2 that
//! (`pke::DecryptionKey::decrypt`) is `pub(crate)` — NOT public. Reimplementing
//! it would be hand-rolling KEM internals, which this prototype refuses.
//!
//! Consequences, stated plainly:
//! - For a well-formed ciphertext, CPA-decap and full-FO decap return the SAME
//!   shared secret, so path (b)'s *scan logic and authenticity model* (tag →
//!   AEAD → recompute-cm) are fully implementable and testable using `K` from
//!   `decapsulate` (see `scan`).
//! - The compute *speedup* of skipping FO cannot be obtained by timing a
//!   CPA-decap here. It is instead measured by DECOMPOSITION: the skipped work
//!   is one K-PKE.Encrypt (the re-encryption), whose cost ≈ `encapsulate`. The
//!   bench reports `speedup ≈ decap / (decap − encap)` (see `m5note` bench).
//! - A production FO-skip path needs a KEM crate exposing CPA-decap — a named
//!   remainder in the PR (`libcrux-ml-kem` exposes lower-level APIs; unverified).

use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{DecapsulationKey, EncapsulationKey, Kem, KeyExport, MlKem768};
use rand::CryptoRng;

/// ML-KEM-768 ciphertext length (FIPS 203): 960-B u + 128-B v.
pub const CT_LEN: usize = 1088;
/// Shared-secret length.
pub const SHARED_LEN: usize = 32;
/// ML-KEM-768 encapsulation-key (public) length.
pub const EK_LEN: usize = 1184;

/// Recipient encapsulation (public) key.
pub type Ek = EncapsulationKey<MlKem768>;
/// Recipient decapsulation (secret) key.
pub type Dk = DecapsulationKey<MlKem768>;

/// A recipient's ML-KEM-768 keypair.
pub struct Keypair {
    pub dk: Dk,
    pub ek: Ek,
}

/// Generate a recipient keypair from a caller-supplied CSPRNG.
pub fn generate_keypair<R: CryptoRng>(rng: &mut R) -> Keypair {
    let (dk, ek) = MlKem768::generate_keypair_from_rng(rng);
    Keypair { dk, ek }
}

/// Encapsulate to `ek`: returns the 1,088-B ciphertext (shared per `(tx,
/// recipient)`) and the 32-B shared secret `K`.
pub fn encapsulate<R: CryptoRng + ?Sized>(ek: &Ek, rng: &mut R) -> ([u8; CT_LEN], [u8; SHARED_LEN]) {
    let (ct, k) = ek.encapsulate_with_rng(rng);
    let mut ct_bytes = [0u8; CT_LEN];
    ct_bytes.copy_from_slice(ct.as_slice());
    let mut k_bytes = [0u8; SHARED_LEN];
    k_bytes.copy_from_slice(k.as_slice());
    (ct_bytes, k_bytes)
}

/// Full-FO decapsulation (scan path (a); standard IND-CCA). Infallible per
/// FIPS 203: a malformed/wrong-key ciphertext yields an implicit-rejection
/// pseudo-random secret rather than an error.
pub fn decapsulate(dk: &Dk, ct: &[u8; CT_LEN]) -> [u8; SHARED_LEN] {
    let k = dk
        .decapsulate_slice(ct)
        .expect("ciphertext is exactly CT_LEN bytes");
    let mut out = [0u8; SHARED_LEN];
    out.copy_from_slice(k.as_slice());
    out
}

/// Serialize the recipient encapsulation key (the address's ML-KEM part).
pub fn ek_to_bytes(ek: &Ek) -> [u8; EK_LEN] {
    let enc = ek.to_bytes();
    let mut out = [0u8; EK_LEN];
    out.copy_from_slice(enc.as_slice());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn encap_decap_roundtrip_and_sizes() {
        let mut rng = StdRng::seed_from_u64(1);
        let kp = generate_keypair(&mut rng);
        let (ct, k_enc) = encapsulate(&kp.ek, &mut rng);
        assert_eq!(ct.len(), 1088, "ML-KEM-768 ct must be 1088 B");
        assert_eq!(k_enc.len(), 32);
        assert_eq!(ek_to_bytes(&kp.ek).len(), 1184, "ML-KEM-768 ek must be 1184 B");
        let k_dec = decapsulate(&kp.dk, &ct);
        assert_eq!(k_enc, k_dec, "encap/decap shared secrets must agree");
    }

    #[test]
    fn wrong_key_decap_differs() {
        let mut rng = StdRng::seed_from_u64(2);
        let kp_a = generate_keypair(&mut rng);
        let kp_b = generate_keypair(&mut rng);
        let (ct, k_enc) = encapsulate(&kp_a.ek, &mut rng);
        // Decapsulating A's ciphertext with B's key gives the implicit-rejection
        // secret — different from the true K with overwhelming probability.
        let k_wrong = decapsulate(&kp_b.dk, &ct);
        assert_ne!(k_enc, k_wrong, "wrong-key decap must not recover K");
    }

    #[test]
    fn distinct_encapsulations_differ() {
        let mut rng = StdRng::seed_from_u64(3);
        let kp = generate_keypair(&mut rng);
        let (ct1, k1) = encapsulate(&kp.ek, &mut rng);
        let (ct2, k2) = encapsulate(&kp.ek, &mut rng);
        assert_ne!(ct1, ct2, "fresh encapsulations differ");
        assert_ne!(k1, k2);
    }
}
