//! Diversified addresses and the short-address indirection.
//!
//! A raw address is `version ‖ diversifier ‖ rkm ‖ ML-KEM-768 ek`:
//!
//! | field | bytes | role |
//! |---|---|---|
//! | version | 1 | format version (evolves when diversified-rkm lands) |
//! | diversifier `d` | 16 | selects the per-address ML-KEM keypair |
//! | `rkm` | 32 | recipient key material bound into the note commitment |
//! | ML-KEM-768 ek | 1184 | note-encryption public key |
//!
//! Raw size = **1233 B ≈ 1.2 KB** (see [`Address::RAW_LEN`]) — dominated by the
//! 1,184-B ek, matching `transaction-model-and-anonymity-set.md` §4's ~1.3 KB.
//! Encoded with **bech32m** (see [`crate::bech32m`]): versioned HRP + BCH
//! checksum. The encoded string is ~2 KB — hence the short-address layer.
//!
//! ## Diversification caveat
//!
//! Per the coordinator-confirmed Option 1, the diversifier `d` varies ONLY the
//! ML-KEM keypair; `rkm` is the shared circuit-bound `H(nk ‖ D_R)`. A wallet's
//! addresses therefore share `rkm` and are linkable via it — full unlinkability
//! needs a circuit change (`rkm = H(nk ‖ D_R ‖ d)`; see the plan doc / PR).

use std::collections::HashMap;

use qlab_note::hash::{digest_bytes, digest_from_bytes, keccak256};
use qlab_note::kem::{ek_from_bytes, ek_to_bytes, Ek, EK_LEN};

use crate::keys::Lanes;

/// Current raw-address format version.
pub const ADDRESS_VERSION: u8 = 1;
/// Diversifier width in bytes (128-bit; ample headroom over Sapling's 88-bit).
pub const DIV_LEN: usize = 16;
/// `rkm` width on the wire (little-endian lanes of the `[u64; 4]`).
pub const RKM_LEN: usize = 32;
/// Human-readable part for full addresses.
pub const ADDR_HRP: &str = "qaddr";
/// Human-readable part for short addresses.
pub const SHORT_HRP: &str = "qs";
/// Short-address hash length (128-bit; 2^-64 collision resistance under a
/// birthday bound is ample for a resolution key).
pub const SHORT_HASH_LEN: usize = 16;
/// Domain string for the short-address hash commitment (wallet-only KDF).
pub const DS_SHORTADDR: &[u8] = b"qumbra:wallet:short-addr:v1";

/// A per-address diversifier. The default (all-zero) is the wallet's canonical
/// address; other values select independent ML-KEM keypairs.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Diversifier(pub [u8; DIV_LEN]);

impl Diversifier {
    pub fn from_bytes(b: [u8; DIV_LEN]) -> Self {
        Self(b)
    }
    pub fn as_bytes(&self) -> &[u8; DIV_LEN] {
        &self.0
    }
}

/// A diversified Qumbra address.
#[derive(Clone)]
pub struct Address {
    pub version: u8,
    pub diversifier: Diversifier,
    /// Recipient key material `rkm` (as little-endian bytes of the `[u64; 4]`).
    pub rkm: [u8; RKM_LEN],
    /// ML-KEM-768 encapsulation key bytes.
    pub ek: [u8; EK_LEN],
}

impl Address {
    /// Raw serialized length: 1 + 16 + 32 + 1184 = 1233 bytes.
    pub const RAW_LEN: usize = 1 + DIV_LEN + RKM_LEN + EK_LEN;

    /// Assemble an address from its parts (used by the wallet's key layer).
    pub fn new(diversifier: Diversifier, rkm: Lanes, ek: &Ek) -> Self {
        Self {
            version: ADDRESS_VERSION,
            diversifier,
            rkm: digest_bytes(&rkm),
            ek: ek_to_bytes(ek),
        }
    }

    /// The `rkm` as `[u64; 4]` lanes (the form the note commitment consumes).
    pub fn rkm_lanes(&self) -> Lanes {
        digest_from_bytes(&self.rkm)
    }

    /// The ML-KEM encapsulation key, reconstructed for the sender to encrypt to.
    /// `None` if the ek bytes are not a valid ML-KEM-768 key.
    pub fn encapsulation_key(&self) -> Option<Ek> {
        ek_from_bytes(&self.ek)
    }

    /// Serialize to raw bytes (`version ‖ d ‖ rkm ‖ ek`).
    pub fn to_raw_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::RAW_LEN);
        out.push(self.version);
        out.extend_from_slice(self.diversifier.as_bytes());
        out.extend_from_slice(&self.rkm);
        out.extend_from_slice(&self.ek);
        out
    }

    /// Parse raw bytes. `None` on a length or version mismatch.
    pub fn from_raw_bytes(b: &[u8]) -> Option<Address> {
        if b.len() != Self::RAW_LEN {
            return None;
        }
        let version = b[0];
        if version != ADDRESS_VERSION {
            return None; // unknown format version
        }
        let mut off = 1;
        let mut diversifier = [0u8; DIV_LEN];
        diversifier.copy_from_slice(&b[off..off + DIV_LEN]);
        off += DIV_LEN;
        let mut rkm = [0u8; RKM_LEN];
        rkm.copy_from_slice(&b[off..off + RKM_LEN]);
        off += RKM_LEN;
        let mut ek = [0u8; EK_LEN];
        ek.copy_from_slice(&b[off..off + EK_LEN]);
        Some(Address {
            version,
            diversifier: Diversifier(diversifier),
            rkm,
            ek,
        })
    }

    /// Encode as a bech32m string under [`ADDR_HRP`].
    pub fn encode(&self) -> String {
        crate::bech32m::encode(ADDR_HRP, &self.to_raw_bytes())
    }

    /// Decode a bech32m address string. `None` on a wrong HRP, bad checksum, or
    /// malformed payload.
    pub fn decode(s: &str) -> Option<Address> {
        let (hrp, payload) = crate::bech32m::decode(s)?;
        if hrp != ADDR_HRP {
            return None;
        }
        Address::from_raw_bytes(&payload)
    }

    /// The short-address hash commitment of this address:
    /// `Keccak256(DS_SHORTADDR ‖ raw_bytes)[..SHORT_HASH_LEN]`.
    pub fn short(&self) -> ShortAddress {
        let mut input = Vec::with_capacity(DS_SHORTADDR.len() + Self::RAW_LEN);
        input.extend_from_slice(DS_SHORTADDR);
        input.extend_from_slice(&self.to_raw_bytes());
        let h = keccak256(&input);
        let mut hash = [0u8; SHORT_HASH_LEN];
        hash.copy_from_slice(&h[..SHORT_HASH_LEN]);
        ShortAddress { hash }
    }
}

/// The compact user-facing handle: a hash commitment of the full address.
/// Resolving it back to the full address requires a resolution layer (network
/// transport OUT OF SCOPE — [`AddressBook`] is a local format+interface stub).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ShortAddress {
    pub hash: [u8; SHORT_HASH_LEN],
}

impl ShortAddress {
    /// Encode as a bech32m string under [`SHORT_HRP`] (~40 chars user-facing).
    pub fn encode(&self) -> String {
        crate::bech32m::encode(SHORT_HRP, &self.hash)
    }

    /// Decode a short-address string. `None` on wrong HRP / bad checksum / length.
    pub fn decode(s: &str) -> Option<ShortAddress> {
        let (hrp, payload) = crate::bech32m::decode(s)?;
        if hrp != SHORT_HRP || payload.len() != SHORT_HASH_LEN {
            return None;
        }
        let mut hash = [0u8; SHORT_HASH_LEN];
        hash.copy_from_slice(&payload);
        Some(ShortAddress { hash })
    }
}

/// A resolution stub: maps short addresses -> full addresses in memory. This is
/// the FORMAT and INTERFACE of short-address resolution only — the real
/// resolver (a network service / on-chain registry) is out of M7 scope. On
/// registration the commitment is verified (the map cannot be poisoned with a
/// full address whose hash does not match the short address).
#[derive(Default)]
pub struct AddressBook {
    map: HashMap<[u8; SHORT_HASH_LEN], Vec<u8>>,
}

impl AddressBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a full address under its (recomputed, verified) short address.
    /// Returns the `ShortAddress` it is keyed by.
    pub fn register(&mut self, addr: &Address) -> ShortAddress {
        let short = addr.short();
        self.map.insert(short.hash, addr.to_raw_bytes());
        short
    }

    /// Resolve a short address to the full address, verifying the commitment
    /// (defensive: a stored entry must still hash to the queried short address).
    pub fn resolve(&self, short: &ShortAddress) -> Option<Address> {
        let raw = self.map.get(&short.hash)?;
        let addr = Address::from_raw_bytes(raw)?;
        if addr.short() != *short {
            return None; // commitment mismatch — refuse
        }
        Some(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_note::kem::generate_keypair;
    use rand::{rngs::StdRng, SeedableRng};

    fn sample_address(seed: u64, d: [u8; DIV_LEN]) -> Address {
        let mut rng = StdRng::seed_from_u64(seed);
        let kp = generate_keypair(&mut rng);
        let rkm: Lanes = [seed, seed ^ 0xff, seed.wrapping_mul(3), 42];
        Address::new(Diversifier::from_bytes(d), rkm, &kp.ek)
    }

    #[test]
    fn raw_len_is_1233() {
        assert_eq!(Address::RAW_LEN, 1233);
        let a = sample_address(1, [0u8; DIV_LEN]);
        assert_eq!(a.to_raw_bytes().len(), 1233);
    }

    #[test]
    fn raw_roundtrip() {
        let a = sample_address(2, [9u8; DIV_LEN]);
        let raw = a.to_raw_bytes();
        let b = Address::from_raw_bytes(&raw).expect("round-trip");
        assert_eq!(b.version, a.version);
        assert_eq!(b.diversifier, a.diversifier);
        assert_eq!(b.rkm, a.rkm);
        assert_eq!(b.ek, a.ek);
        // Wrong length / version rejected.
        assert!(Address::from_raw_bytes(&raw[..1232]).is_none());
        let mut bad = raw.clone();
        bad[0] = 2;
        assert!(Address::from_raw_bytes(&bad).is_none(), "unknown version rejected");
    }

    #[test]
    fn bech32m_roundtrip_and_hrp() {
        let a = sample_address(3, [1u8; DIV_LEN]);
        let s = a.encode();
        assert!(s.starts_with("qaddr1"), "HRP prefix: {}", &s[..8]);
        let b = Address::decode(&s).expect("decode own encoding");
        assert_eq!(b.rkm, a.rkm);
        assert_eq!(b.ek, a.ek);
        assert_eq!(b.diversifier, a.diversifier);
        // A wrong-HRP string is rejected.
        let short_s = a.short().encode();
        assert!(Address::decode(&short_s).is_none(), "short-addr HRP is not an address");
    }

    #[test]
    fn rkm_lanes_roundtrips() {
        let rkm: Lanes = [0x1122, 0x3344, 0x5566, 0x7788];
        let mut rng = StdRng::seed_from_u64(7);
        let kp = generate_keypair(&mut rng);
        let a = Address::new(Diversifier::default(), rkm, &kp.ek);
        assert_eq!(a.rkm_lanes(), rkm, "rkm survives bytes<->lanes");
    }

    #[test]
    fn encapsulation_key_is_functional() {
        let mut rng = StdRng::seed_from_u64(8);
        let kp = generate_keypair(&mut rng);
        let a = Address::new(Diversifier::default(), [1, 2, 3, 4], &kp.ek);
        let ek = a.encapsulation_key().expect("valid ek in address");
        let (ct, k) = qlab_note::kem::encapsulate(&ek, &mut rng);
        assert_eq!(qlab_note::kem::decapsulate(&kp.dk, &ct), k, "address ek encrypts to the keypair");
    }

    #[test]
    fn short_address_roundtrip_and_resolution() {
        let a = sample_address(4, [3u8; DIV_LEN]);
        let short = a.short();
        // Short-address string round-trips.
        let s = short.encode();
        assert!(s.starts_with("qs1"));
        assert_eq!(ShortAddress::decode(&s), Some(short));
        // Resolution stub returns the full address.
        let mut book = AddressBook::new();
        let key = book.register(&a);
        assert_eq!(key, short);
        let resolved = book.resolve(&short).expect("registered address resolves");
        assert_eq!(resolved.to_raw_bytes(), a.to_raw_bytes());
        // An unknown short address does not resolve.
        let other = sample_address(5, [0u8; DIV_LEN]).short();
        assert!(book.resolve(&other).is_none());
    }

    #[test]
    fn different_diversifiers_distinct_short_addresses() {
        // Same wallet keypair-seed but different diversifier -> different raw
        // bytes -> different short address (diversifier IS part of the commitment).
        let a0 = sample_address(6, [0u8; DIV_LEN]);
        let mut d1 = [0u8; DIV_LEN];
        d1[0] = 1;
        let a1 = Address { diversifier: Diversifier(d1), ..a0.clone() };
        assert_ne!(a0.short(), a1.short(), "diversifier changes the short address");
    }
}
