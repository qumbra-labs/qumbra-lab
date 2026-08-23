//! RFC 8391 `WOTSP-SHA2_256` comparator.
//!
//! F, H, PRF, addresses, base-w conversion, checksum, chain traversal and
//! L-tree compression follow RFC 8391. Private elements use the HRS16-style
//! deterministic expansion in the RFC authors' reference implementation
//! (padding identifier 4, public seed and OTS address included). This is a
//! research implementation, not production cryptography.

use sha2::{Digest, Sha256};

use crate::{intent::AuthDescriptor, Hash32};

pub const N: usize = 32;
pub const W: usize = 16;
pub const LEN_1: usize = 64;
pub const LEN_2: usize = 3;
pub const LEN: usize = LEN_1 + LEN_2;
pub const SIGNATURE_BYTES: usize = LEN * N;

const ADDRESS_WORDS: usize = 8;
const TYPE_OTS: u32 = 0;
const TYPE_LTREE: u32 = 1;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Address([u32; ADDRESS_WORDS]);

impl Address {
    fn set_type(&mut self, kind: u32) {
        self.0[3] = kind;
        self.0[4..].fill(0);
    }

    fn set_ots(&mut self, index: u32) {
        self.0[4] = index;
    }

    fn set_chain(&mut self, chain: u32) {
        self.0[5] = chain;
    }

    fn set_hash(&mut self, hash: u32) {
        self.0[6] = hash;
    }

    fn set_ltree(&mut self, index: u32) {
        self.0[4] = index;
    }

    fn set_tree_height(&mut self, height: u32) {
        self.0[5] = height;
    }

    fn set_tree_index(&mut self, index: u32) {
        self.0[6] = index;
    }

    fn set_key_and_mask(&mut self, value: u32) {
        self.0[7] = value;
    }

    fn bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (word, bytes) in self.0.iter().zip(out.chunks_exact_mut(4)) {
            bytes.copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature(pub [Hash32; LEN]);

impl Signature {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SIGNATURE_BYTES);
        for element in self.0 {
            out.extend_from_slice(&element);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != SIGNATURE_BYTES {
            return None;
        }
        let elements = std::array::from_fn(|i| {
            bytes[i * N..(i + 1) * N]
                .try_into()
                .expect("the exact length was checked")
        });
        Some(Self(elements))
    }
}

fn sha256(parts: &[&[u8]]) -> Hash32 {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}

fn padding(identifier: u64) -> [u8; N] {
    let mut out = [0u8; N];
    out[N - 8..].copy_from_slice(&identifier.to_be_bytes());
    out
}

fn prf(key: &Hash32, input: &[u8; 32]) -> Hash32 {
    sha256(&[&padding(3), key, input])
}

/// HRS16-style key expansion used by the RFC authors' reference code.
fn prf_keygen(secret_seed: &Hash32, public_seed: &Hash32, address: &Address) -> Hash32 {
    sha256(&[&padding(4), secret_seed, public_seed, &address.bytes()])
}

fn f(key: &Hash32, input: &Hash32) -> Hash32 {
    sha256(&[&padding(0), key, input])
}

fn h(key: &Hash32, left: &Hash32, right: &Hash32) -> Hash32 {
    sha256(&[&padding(1), key, left, right])
}

fn thash_f(input: &Hash32, public_seed: &Hash32, address: &mut Address) -> Hash32 {
    address.set_key_and_mask(0);
    let key = prf(public_seed, &address.bytes());
    address.set_key_and_mask(1);
    let mask = prf(public_seed, &address.bytes());
    let mut masked = [0u8; N];
    for i in 0..N {
        masked[i] = input[i] ^ mask[i];
    }
    f(&key, &masked)
}

fn thash_h(left: &Hash32, right: &Hash32, public_seed: &Hash32, address: &mut Address) -> Hash32 {
    address.set_key_and_mask(0);
    let key = prf(public_seed, &address.bytes());
    address.set_key_and_mask(1);
    let left_mask = prf(public_seed, &address.bytes());
    address.set_key_and_mask(2);
    let right_mask = prf(public_seed, &address.bytes());
    let mut masked_left = [0u8; N];
    let mut masked_right = [0u8; N];
    for i in 0..N {
        masked_left[i] = left[i] ^ left_mask[i];
        masked_right[i] = right[i] ^ right_mask[i];
    }
    h(&key, &masked_left, &masked_right)
}

fn chain(
    input: Hash32,
    start: usize,
    steps: usize,
    public_seed: &Hash32,
    address: &mut Address,
) -> Option<Hash32> {
    if start + steps > W - 1 {
        return None;
    }
    let mut out = input;
    for step in start..start + steps {
        address.set_hash(step as u32);
        out = thash_f(&out, public_seed, address);
    }
    Some(out)
}

/// RFC 8391 Algorithm 1 specialized to w=16: high nibble, then low nibble.
fn base_w(input: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len);
    for &byte in input {
        if out.len() < out_len {
            out.push(byte >> 4);
        }
        if out.len() < out_len {
            out.push(byte & 0x0f);
        }
    }
    assert_eq!(out.len(), out_len);
    out
}

pub fn chain_lengths(message: &Hash32) -> [u8; LEN] {
    let message_digits = base_w(message, LEN_1);
    let checksum: u32 = message_digits
        .iter()
        .map(|&digit| (W - 1) as u32 - digit as u32)
        .sum();
    // RFC 8391 Algorithm 5: len_2*lg(w)=12 bits, left-aligned in two bytes.
    let shifted = checksum << 4;
    let checksum_bytes = (shifted as u16).to_be_bytes();
    let checksum_digits = base_w(&checksum_bytes, LEN_2);

    std::array::from_fn(|i| {
        if i < LEN_1 {
            message_digits[i]
        } else {
            checksum_digits[i - LEN_1]
        }
    })
}

fn secret_elements(secret_seed: &Hash32, public_seed: &Hash32, leaf_index: u32) -> [Hash32; LEN] {
    let mut address = Address::default();
    address.set_type(TYPE_OTS);
    address.set_ots(leaf_index);
    address.set_hash(0);
    address.set_key_and_mask(0);
    std::array::from_fn(|i| {
        address.set_chain(i as u32);
        prf_keygen(secret_seed, public_seed, &address)
    })
}

fn public_key_elements(
    secret_seed: &Hash32,
    public_seed: &Hash32,
    leaf_index: u32,
) -> [Hash32; LEN] {
    let secret = secret_elements(secret_seed, public_seed, leaf_index);
    let mut address = Address::default();
    address.set_type(TYPE_OTS);
    address.set_ots(leaf_index);
    std::array::from_fn(|i| {
        address.set_chain(i as u32);
        chain(secret[i], 0, W - 1, public_seed, &mut address)
            .expect("the full RFC chain is in range")
    })
}

fn public_key_from_signature(
    message: &Hash32,
    signature: &Signature,
    public_seed: &Hash32,
    leaf_index: u32,
) -> [Hash32; LEN] {
    let lengths = chain_lengths(message);
    let mut address = Address::default();
    address.set_type(TYPE_OTS);
    address.set_ots(leaf_index);
    std::array::from_fn(|i| {
        address.set_chain(i as u32);
        let start = lengths[i] as usize;
        chain(
            signature.0[i],
            start,
            W - 1 - start,
            public_seed,
            &mut address,
        )
        .expect("the complementary RFC chain is in range")
    })
}

fn ltree(mut public_key: [Hash32; LEN], public_seed: &Hash32, leaf_index: u32) -> Hash32 {
    let mut address = Address::default();
    address.set_type(TYPE_LTREE);
    address.set_ltree(leaf_index);
    address.set_tree_height(0);

    let mut len = LEN;
    let mut height = 0u32;
    while len > 1 {
        let parents = len / 2;
        for i in 0..parents {
            address.set_tree_index(i as u32);
            public_key[i] = thash_h(
                &public_key[2 * i],
                &public_key[2 * i + 1],
                public_seed,
                &mut address,
            );
        }
        if len % 2 == 1 {
            public_key[parents] = public_key[len - 1];
            len = parents + 1;
        } else {
            len = parents;
        }
        height += 1;
        address.set_tree_height(height);
    }
    public_key[0]
}

pub fn leaf(secret_seed: &Hash32, public_seed: &Hash32, leaf_index: u32) -> Hash32 {
    ltree(
        public_key_elements(secret_seed, public_seed, leaf_index),
        public_seed,
        leaf_index,
    )
}

pub fn descriptor(secret_seed: &Hash32, public_seed: Hash32, leaf_index: u32) -> AuthDescriptor {
    AuthDescriptor::WotsSha2 {
        public_seed,
        leaf_index,
        leaf: leaf(secret_seed, &public_seed, leaf_index),
    }
}

pub fn sign(
    message: &Hash32,
    secret_seed: &Hash32,
    public_seed: &Hash32,
    leaf_index: u32,
) -> Signature {
    let lengths = chain_lengths(message);
    let secret = secret_elements(secret_seed, public_seed, leaf_index);
    let mut address = Address::default();
    address.set_type(TYPE_OTS);
    address.set_ots(leaf_index);
    Signature(std::array::from_fn(|i| {
        address.set_chain(i as u32);
        chain(secret[i], 0, lengths[i] as usize, public_seed, &mut address)
            .expect("a message digit is below w")
    }))
}

pub fn leaf_from_signature(
    message: &Hash32,
    signature: &Signature,
    public_seed: &Hash32,
    leaf_index: u32,
) -> Hash32 {
    ltree(
        public_key_from_signature(message, signature, public_seed, leaf_index),
        public_seed,
        leaf_index,
    )
}

pub fn verify(descriptor: &AuthDescriptor, signature: &[u8], message: &Hash32) -> bool {
    let AuthDescriptor::WotsSha2 {
        public_seed,
        leaf_index,
        leaf,
    } = descriptor
    else {
        return false;
    };
    let Some(signature) = Signature::decode(signature) else {
        return false;
    };
    leaf_from_signature(message, &signature, public_seed, *leaf_index) == *leaf
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sha256Cost {
    pub expand: usize,
    pub chain_steps: usize,
    pub ltree_nodes: usize,
    pub total_sha256: usize,
}

fn cost(expand: usize, chain_steps: usize, ltree_nodes: usize) -> Sha256Cost {
    // One chain step = two PRFs + F = 3 SHA-256 calls.
    // One L-tree node = key PRF + two masks + H = 4 SHA-256 calls.
    Sha256Cost {
        expand,
        chain_steps,
        ltree_nodes,
        total_sha256: expand + 3 * chain_steps + 4 * ltree_nodes,
    }
}

pub fn leaf_cost() -> Sha256Cost {
    cost(LEN, LEN * (W - 1), LEN - 1)
}

pub fn sign_cost(message: &Hash32) -> Sha256Cost {
    let steps = chain_lengths(message).iter().map(|&v| v as usize).sum();
    cost(LEN, steps, 0)
}

pub fn verify_cost(message: &Hash32) -> Sha256Cost {
    let signed_steps: usize = chain_lengths(message).iter().map(|&v| v as usize).sum();
    cost(0, LEN * (W - 1) - signed_steps, LEN - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_shape_and_costs_are_exact() {
        assert_eq!((LEN_1, LEN_2, LEN, SIGNATURE_BYTES), (64, 3, 67, 2_144));
        assert_eq!(leaf_cost().total_sha256, 3_346);
        let msg = [0x5au8; 32];
        assert_eq!(
            sign_cost(&msg).chain_steps + verify_cost(&msg).chain_steps,
            LEN * (W - 1)
        );
    }

    #[test]
    fn signature_recovers_the_same_ltree_leaf() {
        let secret_seed = [0x11u8; 32];
        let public_seed = [0x22u8; 32];
        let message = [0x33u8; 32];
        let index = 0x1020_3040;
        let descriptor = descriptor(&secret_seed, public_seed, index);
        let signature = sign(&message, &secret_seed, &public_seed, index).encode();
        assert_eq!(signature.len(), SIGNATURE_BYTES);
        assert!(verify(&descriptor, &signature, &message));

        let mut changed = message;
        changed[0] ^= 1;
        assert!(!verify(&descriptor, &signature, &changed));
        let mut changed_descriptor = descriptor;
        let AuthDescriptor::WotsSha2 { leaf_index, .. } = &mut changed_descriptor else {
            unreachable!()
        };
        *leaf_index ^= 1;
        assert!(!verify(&changed_descriptor, &signature, &message));
    }
}
