//! Annulet authorization: Candidate A, Phase 3 seam A (lab #896).
//!
//! The shape is design `remote-proving-authorization-shape-annulet`, ratified
//! for the testnet by Larry 2026-10-04 18:02 (lab #894 Q3, design PR #363 at
//! review head `582bbf5c`). Section numbers below (§N) refer to it.
//!
//! What lives here, and nothing else (no AIR, wire, node or wallet code):
//! - [`AnnuletIntent`]: the complete intent the device signs (§4);
//! - [`AnnuletAuthSection`]: the 1- or 3-slot ML-DSA-44 section with the
//!   mandatory `valid_until_height` in its header (§6, §7, §10 decided 4);
//! - key derivation per key and tree generation (§2, §9), the per-`(sk, g)`
//!   [`Cursor`] (§5), the AIR-form [`AuthTree`] (§10 decided 2);
//! - the device-side dummy generator [`draw_dummy`] (§5).
//!
//! The L1 spike types in [`crate::intent`] / [`crate::codec`] are untouched;
//! their vectors still hold.

use crate::{
    intent::AuthDescriptor,
    keccak256, mldsa,
    rotation::{draw_below, selection_order_with},
    tree::{fold_path_with, mldsa_leaf, RootAccumulator, TreeVersion},
    Hash32,
};

pub const INTENT_DOMAIN: &[u8] = b"qumbra:remote-auth:intent:annulet:v1";
pub const INTENT_VERSION: u16 = 1;

/// Testnet `D_AUTH` (§9; #894 Q1, Larry 2026-10-04 "D=12 可以"). The AIR's
/// compile-time constant (seam B) must equal this. Mainnet D is PENDING.
pub const D_AUTH: u8 = 12;

/// `auth_master_g = H(D_AUTH_MASTER ‖ sk ‖ g)` (§2).
pub const AUTH_MASTER_DOMAIN: &[u8] = b"qumbra:remote-auth:annulet-auth-master:v1";
/// The frozen `v1` leaf-seed domain (§2; the spike's is `…-seed:spike-v1`).
pub const LEAF_SEED_DOMAIN: &[u8] = b"qumbra:remote-auth:mldsa44-seed:v1";
/// The cursor's private permutation stream (§5).
pub const ORDER_DOMAIN: &[u8] = b"qumbra:remote-auth:mldsa44-order:v1";
/// The dummy generator's stream (§5).
pub const DUMMY_DOMAIN: &[u8] = b"qumbra:remote-auth:annulet-dummy:v1";

/// Section header: `QRA1` ‖ version 2 ‖ scheme ‖ slot count ‖ `valid_until_height`.
pub const SECTION_MAGIC: &[u8; 4] = b"QRA1";
pub const SECTION_VERSION: u16 = 2;
pub const SECTION_HEADER_BYTES: usize = 4 + 2 + 1 + 1 + 8;
const SCHEME_MLDSA44: u8 = 1;
const SLOT_BYTES: usize =
    AuthDescriptor::MLDSA_ENCODED_BYTES + mldsa::VERIFYING_KEY_BYTES + mldsa::SIGNATURE_BYTES;

/// The Annulet transaction shape the intent binds (§3). The tag bytes equal
/// `qlab-devnet` `L2ShapeTag::byte()`; seam E keeps them in step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    S,
    P,
    R,
}

impl Shape {
    pub const fn tag(self) -> u8 {
        match self {
            Shape::S => 0x01,
            Shape::P => 0x02,
            Shape::R => 0x03,
        }
    }

    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0x01 => Some(Shape::S),
            0x02 => Some(Shape::P),
            0x03 => Some(Shape::R),
            _ => None,
        }
    }

    /// Authorization slots = nullifiers: S/P 3 (two payment inputs and the
    /// fee slot), R 1 (`check_l2_arity`).
    pub const fn slots(self) -> usize {
        match self {
            Shape::S | Shape::P => 3,
            Shape::R => 1,
        }
    }
}

/// Genesis format **34** (lab #937): the Annulet net whose S/P spends carry
/// **three** output commitments. Mirrors `qlab_devnet::forms::
/// ANNULET_AUTH_V3_GENESIS_FORMAT_VERSION` (this crate does not depend on
/// `qlab-devnet`; a test there cross-locks the two).
pub const ANNULET_V3_GENESIS_FORMAT: u32 = 34;

/// The output commitments an intent for `shape` binds on the net
/// `genesis_format` names: S/P **3** on format 34, **2** on every other
/// format (formats 33 and earlier — so every pre-#937 intent encodes byte for
/// byte as before); R 2 everywhere. Defaulting every other format to 2 is
/// add-don't-edit by design: format 34 is the one value that changes the
/// count, and no existing intent's bytes or goldens move.
pub const fn intent_outputs(genesis_format: u32, shape: Shape) -> usize {
    match shape {
        Shape::S | Shape::P if genesis_format == ANNULET_V3_GENESIS_FORMAT => 3,
        _ => 2,
    }
}

/// A named refusal. Seam F maps these onto node errors one to one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthError {
    /// Wrong magic, version, truncation, trailing bytes, or a bad length.
    Malformed(String),
    /// A scheme other than ML-DSA-44.
    Scheme(u8),
    /// The slot count does not match the shape.
    SlotCount { expected: usize, got: usize },
    /// Lab #937: the commitment count does not match the shape on the
    /// intent's net ([`intent_outputs`]).
    OutputCount { expected: usize, got: usize },
    /// The header's `valid_until_height` differs from the intent's.
    ValidityMismatch,
    /// A slot's descriptor differs from the intent's.
    DescriptorMismatch { slot: usize },
    /// A slot's leaf is not `mldsa_leaf(leaf_index, verifying_key)`.
    LeafMismatch { slot: usize },
    /// A slot's ML-DSA signature does not verify over the intent digest.
    BadSignature { slot: usize },
    /// The block height is above `valid_until_height`.
    Expired {
        valid_until_height: u64,
        height: u64,
    },
}

/// `Expired` check (§6): a transaction may land at any height up to and
/// including `valid_until_height`. The node runs this before the signatures.
pub fn check_expiry(valid_until_height: u64, height: u64) -> Result<(), AuthError> {
    if height > valid_until_height {
        return Err(AuthError::Expired {
            valid_until_height,
            height,
        });
    }
    Ok(())
}

/// The complete Annulet intent (§4). Field order is fixed; a new field is a
/// version change. Every descriptor is ML-DSA-44.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnnuletIntent {
    pub genesis_format: u32,
    pub genesis_hash: Hash32,
    pub shape: Shape,
    pub anchor: Hash32,
    /// One per slot, in slot order (the fee slot last on S/P).
    pub nullifiers: Vec<Hash32>,
    /// The output commitments: [`intent_outputs`]`(genesis_format, shape)`
    /// of them — two, or three on format 34 (lab #937).
    pub commitments: Vec<Hash32>,
    pub bucket: u8,
    pub valid_until_height: u64,
    pub fee: u64,
    pub registry_root: Hash32,
    /// Keccak-256 of the node's canonical `L2Surface::encode()` bytes.
    pub surface_hash: Hash32,
    /// Keccak-256 of the canonical discovery group.
    pub discovery_hash: Hash32,
    /// One per slot, in slot order.
    pub auth: Vec<AuthDescriptor>,
}

impl AnnuletIntent {
    /// The encoded length with two output commitments (every format but 34).
    pub const fn encoded_len_for(shape: Shape) -> usize {
        Self::encoded_len_with(shape, 2)
    }

    /// The encoded length with `outputs` output commitments.
    pub const fn encoded_len_with(shape: Shape, outputs: usize) -> usize {
        let n = shape.slots();
        INTENT_DOMAIN.len()
            + 2
            + 4
            + 32
            + 1
            + 32
            + 32 * n
            + 32 * outputs
            + 1
            + 8
            + 8
            + 32
            + 32
            + 32
            + 1
            + AuthDescriptor::MLDSA_ENCODED_BYTES * n
    }

    pub fn validate_shape(&self) -> Result<(), AuthError> {
        let expected = self.shape.slots();
        for got in [self.nullifiers.len(), self.auth.len()] {
            if got != expected {
                return Err(AuthError::SlotCount { expected, got });
            }
        }
        let outputs = intent_outputs(self.genesis_format, self.shape);
        if self.commitments.len() != outputs {
            return Err(AuthError::OutputCount { expected: outputs, got: self.commitments.len() });
        }
        if let Some(slot) = self
            .auth
            .iter()
            .position(|d| !matches!(d, AuthDescriptor::MlDsa44 { .. }))
        {
            return Err(AuthError::Malformed(format!(
                "descriptor {slot} is not ML-DSA-44"
            )));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, AuthError> {
        self.validate_shape()?;
        let len = Self::encoded_len_with(self.shape, self.commitments.len());
        let mut out = Vec::with_capacity(len);
        out.extend_from_slice(INTENT_DOMAIN);
        out.extend_from_slice(&INTENT_VERSION.to_le_bytes());
        out.extend_from_slice(&self.genesis_format.to_le_bytes());
        out.extend_from_slice(&self.genesis_hash);
        out.push(self.shape.tag());
        out.extend_from_slice(&self.anchor);
        for nf in &self.nullifiers {
            out.extend_from_slice(nf);
        }
        for cm in &self.commitments {
            out.extend_from_slice(cm);
        }
        out.push(self.bucket);
        out.extend_from_slice(&self.valid_until_height.to_le_bytes());
        out.extend_from_slice(&self.fee.to_le_bytes());
        out.extend_from_slice(&self.registry_root);
        out.extend_from_slice(&self.surface_hash);
        out.extend_from_slice(&self.discovery_hash);
        out.push(SCHEME_MLDSA44);
        for d in &self.auth {
            out.extend_from_slice(&d.leaf_index().to_le_bytes());
            out.extend_from_slice(&d.leaf());
        }
        assert_eq!(out.len(), len);
        Ok(out)
    }

    pub fn digest(&self) -> Result<Hash32, AuthError> {
        Ok(keccak256(&[&self.encode()?]))
    }
}

/// One slot: descriptor, ML-DSA-44 verifying key, signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthSlot {
    pub descriptor: AuthDescriptor,
    pub verifying_key: Vec<u8>,
    pub signature: Vec<u8>,
}

/// The Annulet authorization section (§7): fixed width for its slot count,
/// decoded whole-input at exact length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnnuletAuthSection {
    pub valid_until_height: u64,
    pub slots: Vec<AuthSlot>,
}

impl AnnuletAuthSection {
    /// 16 + slots × 3,768: S/P 11,320 B, R 3,784 B (§7).
    pub const fn encoded_len_for(shape: Shape) -> usize {
        SECTION_HEADER_BYTES + shape.slots() * SLOT_BYTES
    }

    /// Sign `intent` with one key per slot, in slot order. The caller (the
    /// device) supplies real leaf keys and ephemeral dummy keys alike.
    pub fn sign(intent: &AnnuletIntent, keys: &[&mldsa::Key]) -> Result<Self, AuthError> {
        intent.validate_shape()?;
        if keys.len() != intent.auth.len() {
            return Err(AuthError::SlotCount {
                expected: intent.auth.len(),
                got: keys.len(),
            });
        }
        let digest = intent.digest()?;
        let slots = keys
            .iter()
            .zip(&intent.auth)
            .map(|(key, descriptor)| AuthSlot {
                descriptor: *descriptor,
                verifying_key: key.verifying_key_bytes(),
                signature: key.sign(&digest),
            })
            .collect();
        Ok(Self {
            valid_until_height: intent.valid_until_height,
            slots,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, AuthError> {
        let n = self.slots.len();
        if !matches!(n, 1 | 3) {
            return Err(AuthError::Malformed(format!(
                "{n} slots is not an Annulet shape"
            )));
        }
        let mut out = Vec::with_capacity(SECTION_HEADER_BYTES + n * SLOT_BYTES);
        out.extend_from_slice(SECTION_MAGIC);
        out.extend_from_slice(&SECTION_VERSION.to_le_bytes());
        out.push(SCHEME_MLDSA44);
        out.push(n as u8);
        out.extend_from_slice(&self.valid_until_height.to_le_bytes());
        for (i, slot) in self.slots.iter().enumerate() {
            let AuthDescriptor::MlDsa44 { leaf_index, leaf } = slot.descriptor else {
                return Err(AuthError::Malformed(format!(
                    "slot {i} descriptor is not ML-DSA-44"
                )));
            };
            if slot.verifying_key.len() != mldsa::VERIFYING_KEY_BYTES
                || slot.signature.len() != mldsa::SIGNATURE_BYTES
            {
                return Err(AuthError::Malformed(format!(
                    "slot {i} key/signature width"
                )));
            }
            out.extend_from_slice(&leaf_index.to_le_bytes());
            out.extend_from_slice(&leaf);
            out.extend_from_slice(&slot.verifying_key);
            out.extend_from_slice(&slot.signature);
        }
        Ok(out)
    }

    /// Decode for a known shape (the node takes the shape from the decoded
    /// surface). Refuses any other length, magic, version, scheme or count.
    pub fn decode(shape: Shape, bytes: &[u8]) -> Result<Self, AuthError> {
        if bytes.len() < SECTION_HEADER_BYTES {
            return Err(AuthError::Malformed(format!(
                "{} bytes is shorter than the header",
                bytes.len()
            )));
        }
        if &bytes[..4] != SECTION_MAGIC {
            return Err(AuthError::Malformed("wrong magic".into()));
        }
        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if version != SECTION_VERSION {
            return Err(AuthError::Malformed(format!("section version {version}")));
        }
        if bytes[6] != SCHEME_MLDSA44 {
            return Err(AuthError::Scheme(bytes[6]));
        }
        let got = bytes[7] as usize;
        if got != shape.slots() {
            return Err(AuthError::SlotCount {
                expected: shape.slots(),
                got,
            });
        }
        let expected_len = Self::encoded_len_for(shape);
        if bytes.len() != expected_len {
            return Err(AuthError::Malformed(format!(
                "{} bytes; shape {shape:?} requires exactly {expected_len}",
                bytes.len()
            )));
        }
        let valid_until_height = u64::from_le_bytes(bytes[8..16].try_into().expect("8 bytes"));
        let slots = bytes[SECTION_HEADER_BYTES..]
            .chunks_exact(SLOT_BYTES)
            .map(|c| {
                let (desc, rest) = c.split_at(AuthDescriptor::MLDSA_ENCODED_BYTES);
                let (vk, sig) = rest.split_at(mldsa::VERIFYING_KEY_BYTES);
                AuthSlot {
                    descriptor: AuthDescriptor::MlDsa44 {
                        leaf_index: u32::from_le_bytes(desc[..4].try_into().expect("4 bytes")),
                        leaf: desc[4..].try_into().expect("32 bytes"),
                    },
                    verifying_key: vk.to_vec(),
                    signature: sig.to_vec(),
                }
            })
            .collect();
        Ok(Self {
            valid_until_height,
            slots,
        })
    }

    /// The node-side check over an intent the node rebuilt from its own
    /// canonical re-encoding (§6). Order: shape/count, validity, descriptors,
    /// leaves, then the ML-DSA signatures (the expensive step, last).
    /// `Expired` is the caller's, against the block height, before this.
    pub fn verify_intent(&self, intent: &AnnuletIntent) -> Result<(), AuthError> {
        intent.validate_shape()?;
        let expected = intent.shape.slots();
        if self.slots.len() != expected {
            return Err(AuthError::SlotCount {
                expected,
                got: self.slots.len(),
            });
        }
        if self.valid_until_height != intent.valid_until_height {
            return Err(AuthError::ValidityMismatch);
        }
        for (slot, (s, d)) in self.slots.iter().zip(&intent.auth).enumerate() {
            if s.descriptor != *d {
                return Err(AuthError::DescriptorMismatch { slot });
            }
        }
        for (slot, s) in self.slots.iter().enumerate() {
            if mldsa_leaf(s.descriptor.leaf_index(), &s.verifying_key) != s.descriptor.leaf() {
                return Err(AuthError::LeafMismatch { slot });
            }
        }
        let digest = intent.digest()?;
        for (slot, s) in self.slots.iter().enumerate() {
            if !mldsa::verify(&s.descriptor, &s.verifying_key, &s.signature, &digest) {
                return Err(AuthError::BadSignature { slot });
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------- keys (§2)

/// `auth_master_g = Keccak(D_AUTH_MASTER ‖ sk ‖ g)`, `g` u32 LE. `sk` is the
/// note key's 32 bytes (lanes LE). Independent of `nk = H(sk ‖ D_N)`.
pub fn auth_master(sk: &Hash32, generation: u32) -> Hash32 {
    keccak256(&[AUTH_MASTER_DOMAIN, sk, &generation.to_le_bytes()])
}

pub fn leaf_seed(auth_master: &Hash32, leaf_index: u32) -> Hash32 {
    keccak256(&[LEAF_SEED_DOMAIN, auth_master, &leaf_index.to_le_bytes()])
}

pub fn leaf_key(auth_master: &Hash32, leaf_index: u32) -> mldsa::Key {
    mldsa::Key::from_seed(leaf_seed(auth_master, leaf_index))
}

/// One generation's AIR-form authorization tree: all `2^depth` public leaves
/// and the root that goes into `rkm`. The leaves are public-derivable only
/// from `auth_master`, which never leaves the device.
pub struct AuthTree {
    depth: u8,
    leaves: Vec<Hash32>,
    root: Hash32,
}

impl AuthTree {
    /// `2^depth` ML-DSA-44 key generations (D12: 0.320 s native on the
    /// 2026-08-24 evidence set).
    pub fn build(auth_master: &Hash32, depth: u8) -> Result<Self, String> {
        check_depth(depth)?;
        let leaves: Vec<Hash32> = (0..1u32 << depth)
            .map(|i| leaf_key(auth_master, i).descriptor(i).leaf())
            .collect();
        Self::from_leaves(depth, leaves)
    }

    pub fn from_leaves(depth: u8, leaves: Vec<Hash32>) -> Result<Self, String> {
        let mut acc = RootAccumulator::new_with(TreeVersion::AirMerkle, depth)?;
        for leaf in &leaves {
            acc.push(*leaf)?;
        }
        let root = acc.finish()?;
        Ok(Self {
            depth,
            leaves,
            root,
        })
    }

    pub fn root(&self) -> Hash32 {
        self.root
    }

    pub fn leaf(&self, index: u32) -> Hash32 {
        self.leaves[index as usize]
    }

    /// The sibling path, leaf level first (the AIR's `MERKLE` order).
    pub fn path(&self, index: u32) -> Vec<Hash32> {
        let mut level = self.leaves.clone();
        let mut i = index as usize;
        let mut path = Vec::with_capacity(self.depth as usize);
        while level.len() > 1 {
            path.push(level[i ^ 1]);
            level = level
                .chunks_exact(2)
                .map(|p| crate::tree::air_node(&p[0], &p[1]))
                .collect();
            i >>= 1;
        }
        path
    }
}

/// Depths outside `1..=24` are refused by name rather than truncated or
/// overflowed (24 is the selection order's measurable bound).
fn check_depth(depth: u8) -> Result<(), String> {
    if depth == 0 || depth > crate::rotation::MAX_MEASURABLE_DEPTH {
        return Err(format!(
            "authorization-tree depth {depth} is outside 1..={}",
            crate::rotation::MAX_MEASURABLE_DEPTH
        ));
    }
    Ok(())
}

pub fn fold_auth_path(leaf: Hash32, index: u32, path: &[Hash32]) -> Hash32 {
    fold_path_with(TreeVersion::AirMerkle, leaf, index, path)
}

// -------------------------------------------------------------- cursor (§5)

/// One private permutation per `(sk, g)`, shared by every diversified address
/// of the key and consumed in order. A counter is forbidden (§5). Persist
/// [`Cursor::next`]; everything else re-derives from `auth_master_g`.
pub struct Cursor {
    depth: u8,
    order: Vec<u32>,
    /// `position[index]` = where `index` sits in `order`.
    position: Vec<u32>,
    next: u32,
}

impl Cursor {
    pub fn new(auth_master: &Hash32, depth: u8, next: u32) -> Result<Self, String> {
        check_depth(depth)?;
        let order = selection_order_with(ORDER_DOMAIN, auth_master, depth)?;
        if next as usize > order.len() {
            return Err(format!(
                "cursor position {next} is beyond {} leaves",
                order.len()
            ));
        }
        let mut position = vec![0u32; order.len()];
        for (p, &index) in order.iter().enumerate() {
            position[index as usize] = p as u32;
        }
        Ok(Self {
            depth,
            order,
            position,
            next,
        })
    }

    /// The tree depth this cursor walks; a dummy drawn against it uses the same.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// The position to persist (fail-closed: persist the advance before the
    /// authorization is exported).
    pub fn next(&self) -> u32 {
        self.next
    }

    pub fn remaining(&self) -> u32 {
        self.order.len() as u32 - self.next
    }

    pub fn is_consumed(&self, index: u32) -> bool {
        self.position
            .get(index as usize)
            .is_none_or(|&p| p < self.next)
    }

    /// Consume the next real leaf index, or `None` when the generation is
    /// exhausted (§9: migrate before this happens).
    pub fn take(&mut self) -> Option<u32> {
        let index = *self.order.get(self.next as usize)?;
        self.next += 1;
        Some(index)
    }
}

// --------------------------------------------------------------- dummy (§5)

/// Everything the device makes for one dummy slot. `nk`, `rho`, `rseed` and
/// the auth material go to the worker; `key` signs once and is dropped.
pub struct DummySlot {
    pub nk: Hash32,
    pub rho: Hash32,
    pub rseed: Hash32,
    pub leaf_index: u32,
    pub key: mldsa::Key,
    pub descriptor: AuthDescriptor,
    pub auth_path: Vec<Hash32>,
    pub auth_root: Hash32,
}

/// Make one dummy slot from 32 bytes of device entropy.
///
/// The caller draws **fresh** entropy from the OS CSPRNG **for each dummy
/// slot**, never from anything the worker supplies. `slot` (the slot's index
/// in the transaction) enters every derived stream as well, so even a caller
/// that reuses one entropy value across slots gets different nullifiers, keys
/// and paths per slot: two dummies of one transaction can never collide.
///
/// `leaf_index` is uniform over the positions of `(sk, g)` that are neither
/// consumed nor `taken` by this transaction's other slots, so real and dummy
/// indices share one joint law (§5). It does not consume the position. The
/// ephemeral key sits in a throwaway tree whose other nodes are random, so
/// its `auth_root` is in no address's `rkm` and the dummy cannot be upgraded.
pub fn draw_dummy(
    entropy: &Hash32,
    slot: u8,
    cursor: &Cursor,
    taken: &[u32],
) -> Result<DummySlot, String> {
    let depth = cursor.depth();
    let size = 1u64 << depth;
    let free = (0..size as u32)
        .filter(|i| !cursor.is_consumed(*i) && !taken.contains(i))
        .count();
    if free == 0 {
        return Err("no unconsumed leaf position is left for a dummy".into());
    }
    let stream = |label: &[u8]| keccak256(&[DUMMY_DOMAIN, entropy, &[slot], label]);
    let index_seed = stream(b"index");
    let mut counter = 0u64;
    let leaf_index = loop {
        let i = draw_below(DUMMY_DOMAIN, &index_seed, &mut counter, size) as u32;
        if !cursor.is_consumed(i) && !taken.contains(&i) {
            break i;
        }
    };
    let key = mldsa::Key::from_seed(stream(b"key"));
    let descriptor = key.descriptor(leaf_index);
    let auth_path: Vec<Hash32> = (0..depth as u32)
        .map(|level| {
            keccak256(&[
                DUMMY_DOMAIN,
                entropy,
                &[slot],
                b"path",
                &level.to_le_bytes(),
            ])
        })
        .collect();
    let auth_root = fold_auth_path(descriptor.leaf(), leaf_index, &auth_path);
    Ok(DummySlot {
        nk: stream(b"nk"),
        rho: stream(b"rho"),
        rseed: stream(b"rseed"),
        leaf_index,
        key,
        descriptor,
        auth_path,
        auth_root,
    })
}

/// Lab #896 seams G/H: the authorization journal (`auth.v1`) — a key's
/// per-generation cursor positions, persisted fail-closed under one writer.
pub mod journal;

#[cfg(test)]
mod tests;
