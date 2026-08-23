//! FIPS 204 ML-DSA-44 stateless-leaf comparator.

use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa44, Signature, SigningKey, VerifyingKey,
    B32,
};

use crate::{intent::AuthDescriptor, tree::mldsa_leaf, Hash32};

pub const VERIFYING_KEY_BYTES: usize = 1_312;
pub const SIGNATURE_BYTES: usize = 2_420;
pub const SIGNING_CONTEXT: &[u8] = b"qumbra:remote-auth:mldsa44:v1";

/// A deterministic key wrapper for vectors and measurements. Production key
/// lifecycle is explicitly out of scope for this spike.
pub struct Key {
    signing: SigningKey<MlDsa44>,
}

impl Key {
    pub fn from_seed(seed: Hash32) -> Self {
        let seed: B32 = seed.into();
        Self {
            signing: SigningKey::<MlDsa44>::from_seed(&seed),
        }
    }

    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        self.signing.verifying_key().encode().to_vec()
    }

    pub fn descriptor(&self, tree_context: Hash32, leaf_index: u32) -> AuthDescriptor {
        let verifying_key = self.verifying_key_bytes();
        AuthDescriptor {
            tree_context,
            leaf_index,
            leaf: mldsa_leaf(&tree_context, leaf_index, &verifying_key),
        }
    }

    /// FIPS 204's optional deterministic signing variant with a fixed context.
    /// Determinism is useful for exact vectors; a production wallet may prefer
    /// hedged signing without changing the public codec.
    pub fn sign(&self, digest: &Hash32) -> Vec<u8> {
        self.signing
            .expanded_key()
            .sign_deterministic(digest, SIGNING_CONTEXT)
            .expect("the fixed context is below FIPS 204's 255-byte bound")
            .encode()
            .to_vec()
    }
}

pub fn verify(
    descriptor: &AuthDescriptor,
    verifying_key: &[u8],
    signature: &[u8],
    digest: &Hash32,
) -> bool {
    if verifying_key.len() != VERIFYING_KEY_BYTES || signature.len() != SIGNATURE_BYTES {
        return false;
    }
    if mldsa_leaf(
        &descriptor.tree_context,
        descriptor.leaf_index,
        verifying_key,
    ) != descriptor.leaf
    {
        return false;
    }

    let Ok(encoded_key) = EncodedVerifyingKey::<MlDsa44>::try_from(verifying_key) else {
        return false;
    };
    let key = VerifyingKey::<MlDsa44>::decode(&encoded_key);
    let Ok(encoded_signature) = EncodedSignature::<MlDsa44>::try_from(signature) else {
        return false;
    };
    let Some(signature) = Signature::<MlDsa44>::decode(&encoded_signature) else {
        return false;
    };
    key.verify_with_context(digest, SIGNING_CONTEXT, &signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stateless_leaf_signs_and_binds_key_context_and_index() {
        let key = Key::from_seed([7u8; 32]);
        let descriptor = key.descriptor([8u8; 32], 9);
        let digest = [10u8; 32];
        let public = key.verifying_key_bytes();
        let signature = key.sign(&digest);
        assert_eq!(public.len(), VERIFYING_KEY_BYTES);
        assert_eq!(signature.len(), SIGNATURE_BYTES);
        assert!(verify(&descriptor, &public, &signature, &digest));

        let mut changed = digest;
        changed[0] ^= 1;
        assert!(!verify(&descriptor, &public, &signature, &changed));
        let mut changed_descriptor = descriptor;
        changed_descriptor.leaf_index ^= 1;
        assert!(!verify(&changed_descriptor, &public, &signature, &digest));
    }
}
