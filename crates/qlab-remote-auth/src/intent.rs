//! The spike's exact complete-intent preimage.
//!
//! This is a candidate codec, not the production transaction codec. It is
//! fixed-width on purpose: one semantic value has one byte representation,
//! and adding a consensus-semantic field requires a version change rather
//! than an optional tail an older signer would ignore.

use crate::{keccak256, Hash32};

pub const INTENT_DOMAIN: &[u8] = b"qumbra:remote-auth:intent:v1";
pub const INTENT_VERSION: u16 = 1;
pub const INPUT_SLOTS: usize = 2;

/// Domain-separated candidate rows. Stateful and random-index WOTS+ use the
/// same primitive but different safety contracts, so algorithm substitution
/// between them must change the signed digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Scheme {
    MlDsa44 = 1,
    WotsSha2Stateful = 2,
    WotsSha2RandomIndex = 3,
}

impl Scheme {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::MlDsa44),
            2 => Some(Self::WotsSha2Stateful),
            3 => Some(Self::WotsSha2RandomIndex),
            _ => None,
        }
    }
}

/// Public authorization values that a future AIR would bind to the hidden
/// note. `tree_context` is the RFC 8391 public seed for WOTS+ and an
/// address-tree domain salt for ML-DSA. `leaf_index` fixes Merkle directions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthDescriptor {
    pub tree_context: Hash32,
    pub leaf_index: u32,
    pub leaf: Hash32,
}

impl AuthDescriptor {
    pub const ENCODED_BYTES: usize = 32 + 4 + 32;

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.tree_context);
        out.extend_from_slice(&self.leaf_index.to_le_bytes());
        out.extend_from_slice(&self.leaf);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intent {
    /// Genesis format selects the consensus form; the file hash below is the
    /// actual Qumbra network identity.
    pub genesis_format: u32,
    pub genesis_hash: Hash32,
    pub anchor: Hash32,
    pub nullifiers: [Hash32; INPUT_SLOTS],
    pub commitments: [Hash32; 2],
    pub bucket: u8,
    pub fee: u64,
    pub discovery_hash: Hash32,
    pub rider_hash: Hash32,
    pub scheme: Scheme,
    pub auth: [AuthDescriptor; INPUT_SLOTS],
}

impl Intent {
    pub const ENCODED_BYTES: usize = INTENT_DOMAIN.len()
        + 2
        + 4
        + 32
        + 32
        + (32 * INPUT_SLOTS)
        + (32 * 2)
        + 1
        + 8
        + 32
        + 32
        + 1
        + (AuthDescriptor::ENCODED_BYTES * INPUT_SLOTS);

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::ENCODED_BYTES);
        out.extend_from_slice(INTENT_DOMAIN);
        out.extend_from_slice(&INTENT_VERSION.to_le_bytes());
        out.extend_from_slice(&self.genesis_format.to_le_bytes());
        out.extend_from_slice(&self.genesis_hash);
        out.extend_from_slice(&self.anchor);
        for nf in self.nullifiers {
            out.extend_from_slice(&nf);
        }
        for cm in self.commitments {
            out.extend_from_slice(&cm);
        }
        out.push(self.bucket);
        out.extend_from_slice(&self.fee.to_le_bytes());
        out.extend_from_slice(&self.discovery_hash);
        out.extend_from_slice(&self.rider_hash);
        out.push(self.scheme as u8);
        for descriptor in &self.auth {
            descriptor.encode_into(&mut out);
        }
        assert_eq!(out.len(), Self::ENCODED_BYTES);
        out
    }

    pub fn digest(&self) -> Hash32 {
        keccak256(&[&self.encode()])
    }
}

/// The stable all-fields fixture used by vectors and mutation tests.
pub fn fixture_intent(scheme: Scheme, auth: [AuthDescriptor; 2]) -> Intent {
    Intent {
        genesis_format: 5,
        genesis_hash: [0x11; 32],
        anchor: [0x22; 32],
        nullifiers: [[0x31; 32], [0x32; 32]],
        commitments: [[0x41; 32], [0x42; 32]],
        bucket: 0x02,
        fee: 0x0102_0304_0506_0708,
        discovery_hash: [0x51; 32],
        rider_hash: [0x61; 32],
        scheme,
        auth,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(byte: u8, index: u32) -> AuthDescriptor {
        AuthDescriptor {
            tree_context: [byte; 32],
            leaf_index: index,
            leaf: [byte + 1; 32],
        }
    }

    #[test]
    fn intent_is_fixed_width_and_stable() {
        let intent = fixture_intent(
            Scheme::MlDsa44,
            [descriptor(0x71, 0x1122_3344), descriptor(0x81, 0x5566_7788)],
        );
        assert_eq!(intent.encode().len(), Intent::ENCODED_BYTES);
        assert_eq!(Intent::ENCODED_BYTES, 436);
        assert_eq!(
            crate::hex(&intent.digest()),
            "0ae629a6f6f13bd24a44806ec9607a3e1ae849c7ae5c862449c674780a58d30c"
        );
    }

    #[test]
    fn every_semantic_field_changes_the_digest() {
        let base = fixture_intent(Scheme::MlDsa44, [descriptor(0x71, 7), descriptor(0x81, 9)]);
        let expected = base.digest();
        let mut variants = Vec::new();

        let mut v = base.clone();
        v.genesis_format ^= 1;
        variants.push(v);
        let mut v = base.clone();
        v.genesis_hash[0] ^= 1;
        variants.push(v);
        let mut v = base.clone();
        v.anchor[0] ^= 1;
        variants.push(v);
        let mut v = base.clone();
        v.nullifiers[0][0] ^= 1;
        variants.push(v);
        let mut v = base.clone();
        v.nullifiers[1][0] ^= 1;
        variants.push(v);
        let mut v = base.clone();
        v.commitments[0][0] ^= 1;
        variants.push(v);
        let mut v = base.clone();
        v.commitments[1][0] ^= 1;
        variants.push(v);
        let mut v = base.clone();
        v.bucket ^= 1;
        variants.push(v);
        let mut v = base.clone();
        v.fee ^= 1;
        variants.push(v);
        let mut v = base.clone();
        v.discovery_hash[0] ^= 1;
        variants.push(v);
        let mut v = base.clone();
        v.rider_hash[0] ^= 1;
        variants.push(v);
        let mut v = base.clone();
        v.scheme = Scheme::WotsSha2Stateful;
        variants.push(v);
        let mut v = base.clone();
        v.auth[0].tree_context[0] ^= 1;
        variants.push(v);
        let mut v = base.clone();
        v.auth[0].leaf_index ^= 1;
        variants.push(v);
        let mut v = base.clone();
        v.auth[0].leaf[0] ^= 1;
        variants.push(v);
        let mut v = base.clone();
        v.auth[1].tree_context[0] ^= 1;
        variants.push(v);
        let mut v = base.clone();
        v.auth[1].leaf_index ^= 1;
        variants.push(v);
        let mut v = base.clone();
        v.auth[1].leaf[0] ^= 1;
        variants.push(v);

        for (i, variant) in variants.iter().enumerate() {
            assert_ne!(
                variant.digest(),
                expected,
                "semantic mutation {i} was not bound"
            );
        }
    }
}
