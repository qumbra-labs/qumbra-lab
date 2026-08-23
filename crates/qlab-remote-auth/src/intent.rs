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
/// note. ML-DSA deliberately has no public per-address tree context: publishing
/// one would turn every spend from an address into a linkable cluster. WOTS+
/// retains its RFC 8391 public seed because native verification requires it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthDescriptor {
    MlDsa44 {
        leaf_index: u32,
        leaf: Hash32,
    },
    WotsSha2 {
        public_seed: Hash32,
        leaf_index: u32,
        leaf: Hash32,
    },
}

impl AuthDescriptor {
    pub const MLDSA_ENCODED_BYTES: usize = 4 + 32;
    pub const WOTS_ENCODED_BYTES: usize = 32 + 4 + 32;

    pub const fn encoded_len_for(scheme: Scheme) -> usize {
        match scheme {
            Scheme::MlDsa44 => Self::MLDSA_ENCODED_BYTES,
            Scheme::WotsSha2Stateful | Scheme::WotsSha2RandomIndex => Self::WOTS_ENCODED_BYTES,
        }
    }

    pub const fn matches_scheme(self, scheme: Scheme) -> bool {
        matches!(
            (scheme, self),
            (Scheme::MlDsa44, Self::MlDsa44 { .. })
                | (
                    Scheme::WotsSha2Stateful | Scheme::WotsSha2RandomIndex,
                    Self::WotsSha2 { .. }
                )
        )
    }

    pub const fn leaf_index(self) -> u32 {
        match self {
            Self::MlDsa44 { leaf_index, .. } | Self::WotsSha2 { leaf_index, .. } => leaf_index,
        }
    }

    pub const fn leaf(self) -> Hash32 {
        match self {
            Self::MlDsa44 { leaf, .. } | Self::WotsSha2 { leaf, .. } => leaf,
        }
    }

    pub const fn public_seed(self) -> Option<Hash32> {
        match self {
            Self::MlDsa44 { .. } => None,
            Self::WotsSha2 { public_seed, .. } => Some(public_seed),
        }
    }

    fn encode_into(&self, scheme: Scheme, out: &mut Vec<u8>) {
        match (scheme, self) {
            (Scheme::MlDsa44, Self::MlDsa44 { leaf_index, leaf }) => {
                out.extend_from_slice(&leaf_index.to_le_bytes());
                out.extend_from_slice(leaf);
            }
            (
                Scheme::WotsSha2Stateful | Scheme::WotsSha2RandomIndex,
                Self::WotsSha2 {
                    public_seed,
                    leaf_index,
                    leaf,
                },
            ) => {
                out.extend_from_slice(public_seed);
                out.extend_from_slice(&leaf_index.to_le_bytes());
                out.extend_from_slice(leaf);
            }
            _ => panic!("authorization descriptor does not match intent scheme"),
        }
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
    const BASE_ENCODED_BYTES: usize =
        INTENT_DOMAIN.len() + 2 + 4 + 32 + 32 + (32 * INPUT_SLOTS) + (32 * 2) + 1 + 8 + 32 + 32 + 1;

    pub const fn encoded_len_for(scheme: Scheme) -> usize {
        Self::BASE_ENCODED_BYTES + (AuthDescriptor::encoded_len_for(scheme) * INPUT_SLOTS)
    }

    pub fn validate_shape(&self) -> Result<(), String> {
        for (index, descriptor) in self.auth.iter().enumerate() {
            if !descriptor.matches_scheme(self.scheme) {
                return Err(format!(
                    "authorization descriptor {index} does not match the intent scheme"
                ));
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        self.validate_shape()
            .expect("fixture intent descriptors match their scheme");
        let encoded_len = Self::encoded_len_for(self.scheme);
        let mut out = Vec::with_capacity(encoded_len);
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
            descriptor.encode_into(self.scheme, &mut out);
        }
        assert_eq!(out.len(), encoded_len);
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

    fn mldsa_descriptor(byte: u8, index: u32) -> AuthDescriptor {
        AuthDescriptor::MlDsa44 {
            leaf_index: index,
            leaf: [byte; 32],
        }
    }

    fn wots_descriptor(byte: u8, index: u32) -> AuthDescriptor {
        AuthDescriptor::WotsSha2 {
            public_seed: [byte; 32],
            leaf_index: index,
            leaf: [byte + 1; 32],
        }
    }

    #[test]
    fn intent_is_fixed_width_and_stable() {
        let intent = fixture_intent(
            Scheme::MlDsa44,
            [
                mldsa_descriptor(0x72, 0x1122_3344),
                mldsa_descriptor(0x82, 0x5566_7788),
            ],
        );
        assert_eq!(intent.encode().len(), 372);
        assert_eq!(Intent::encoded_len_for(Scheme::MlDsa44), 372);
        assert_eq!(Intent::encoded_len_for(Scheme::WotsSha2Stateful), 436);
        assert_eq!(intent.auth[0].public_seed(), None);
        assert_eq!(
            crate::hex(&intent.digest()),
            "6faad91acc3904617f82f1c6ae219d8221914eaaf64c8da6be57907fec49f186"
        );

        let invalid = fixture_intent(
            Scheme::MlDsa44,
            [wots_descriptor(0x71, 7), wots_descriptor(0x81, 9)],
        );
        assert!(invalid.validate_shape().is_err());
    }

    #[test]
    fn every_semantic_field_changes_the_digest() {
        let base = fixture_intent(
            Scheme::MlDsa44,
            [mldsa_descriptor(0x72, 7), mldsa_descriptor(0x82, 9)],
        );
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
        v.auth = [wots_descriptor(0x71, 7), wots_descriptor(0x81, 9)];
        variants.push(v);
        let mut v = base.clone();
        let AuthDescriptor::MlDsa44 { leaf_index, .. } = &mut v.auth[0] else {
            unreachable!()
        };
        *leaf_index ^= 1;
        variants.push(v);
        let mut v = base.clone();
        let AuthDescriptor::MlDsa44 { leaf, .. } = &mut v.auth[0] else {
            unreachable!()
        };
        leaf[0] ^= 1;
        variants.push(v);
        let mut v = base.clone();
        let AuthDescriptor::MlDsa44 { leaf_index, .. } = &mut v.auth[1] else {
            unreachable!()
        };
        *leaf_index ^= 1;
        variants.push(v);
        let mut v = base.clone();
        let AuthDescriptor::MlDsa44 { leaf, .. } = &mut v.auth[1] else {
            unreachable!()
        };
        leaf[0] ^= 1;
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
