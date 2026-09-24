//! The **asset registry tree** and its served wire (lab #710, L2-B3).
//!
//! A depth-16 sparse Merkle tree: leaf `i` is `RegistryLeaf::hash()` of asset
//! `i` (`qlab_air::l2`), an empty slot is the zero digest, and a node is the
//! consensus node hash — the same hash and empty leaf as the commitment tree,
//! whose ladder ([`crate::tree::zeros`]) the registry reuses for its first 17
//! rungs. It is a **sibling** of [`crate::tree::CommitmentTree`], not a
//! generalization of it: the commitment tree is an append-only frontier over
//! sequential positions, the registry is sparse, keyed by asset id, and (from
//! A2) replaced in place. The witness is the circuit's own
//! [`RegistryWitness`], so a served opening goes into a shape-S instance
//! unchanged.
//!
//! **Immutable after genesis until A2** (shape R): nothing here mutates a
//! built tree.
//!
//! # The served wire (`GET /v1/registry/root`, `GET /v1/registry/{asset}`)
//!
//! Every response leads with [`REGISTRY_WIRE_VERSION`] (the #212 discipline)
//! and carries the height and **the root it was computed against** — a wallet
//! binds its transaction to a header's registry root, so it must know which
//! root an opening matches. Digests are 32 bytes, lane-major little-endian.
//!
//! ```text
//! root:    ver(u8) ‖ height(u64 LE) ‖ root(32)
//! opening: ver(u8) ‖ height(u64 LE) ‖ root(32) ‖ leaf(15 × u64 LE) ‖ 16 × sibling(32)
//! ```
//!
//! The leaf's 15 lanes are `RegistryLeaf::state()[0..15]`: `asset ‖
//! issuer_key(4) ‖ mode ‖ freeze_root(4) ‖ allow_root(4) ‖ flags`. **No path
//! bits travel**: an opening is for position `asset`, so the decoder derives
//! them from the leaf's asset id rather than trusting a second copy.

use std::collections::BTreeMap;

pub use qlab_air::l2::{RegistryLeaf, RegistryWitness, REGISTRY_DEPTH};
use qlab_note::hash::{digest_bytes, digest_from_bytes};

use crate::tree::{hash_node, zeros};

/// The registry wire's version byte.
pub const REGISTRY_WIRE_VERSION: u8 = 1;
/// `GET /v1/registry/root` body length.
pub const REGISTRY_ROOT_LEN: usize = 1 + 8 + 32;
/// `GET /v1/registry/{asset}` body length.
pub const REGISTRY_OPENING_LEN: usize = REGISTRY_ROOT_LEN + 15 * 8 + REGISTRY_DEPTH * 32;

/// A built registry tree: every non-empty node, per level.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryTree {
    leaves: BTreeMap<u16, RegistryLeaf>,
    /// `levels[l][i]` = node `i` at height `l` (`l = 0` the leaf hashes,
    /// `l = 16` the root), present only where some leaf lies beneath.
    levels: Vec<BTreeMap<u64, [u64; 4]>>,
}

/// Why a registry could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryError {
    /// An asset id at or above `2^REGISTRY_DEPTH`.
    AssetOutOfRange { asset: u64 },
    /// Two leaves for one asset.
    DuplicateAsset { asset: u16 },
    /// A registry update before A2 lands shape R: the registry is immutable
    /// after genesis until then.
    UpdatesArriveWithA2,
}

impl RegistryTree {
    /// Build from the genesis leaves (any order; each asset at most once).
    pub fn from_leaves(leaves: &[RegistryLeaf]) -> Result<Self, RegistryError> {
        let mut by_asset = BTreeMap::new();
        for l in leaves {
            if l.asset >= 1u64 << REGISTRY_DEPTH {
                return Err(RegistryError::AssetOutOfRange { asset: l.asset });
            }
            let a = l.asset as u16;
            if by_asset.insert(a, *l).is_some() {
                return Err(RegistryError::DuplicateAsset { asset: a });
            }
        }
        let z = zeros();
        let mut levels: Vec<BTreeMap<u64, [u64; 4]>> = Vec::with_capacity(REGISTRY_DEPTH + 1);
        levels.push(by_asset.iter().map(|(&a, l)| (a as u64, l.hash())).collect());
        for lvl in 0..REGISTRY_DEPTH {
            let below = &levels[lvl];
            let mut up = BTreeMap::new();
            for &i in below.keys() {
                let parent = i >> 1;
                if up.contains_key(&parent) {
                    continue;
                }
                let left = *below.get(&(i & !1)).unwrap_or(&z[lvl]);
                let right = *below.get(&(i | 1)).unwrap_or(&z[lvl]);
                up.insert(parent, hash_node(&left, &right));
            }
            levels.push(up);
        }
        Ok(Self { leaves: by_asset, levels })
    }

    /// The registry root (the empty tree's root when no asset is registered).
    pub fn root(&self) -> [u64; 4] {
        *self.levels[REGISTRY_DEPTH].get(&0).unwrap_or(&zeros()[REGISTRY_DEPTH])
    }

    /// The registered leaf of `asset`, if any.
    pub fn leaf(&self, asset: u16) -> Option<&RegistryLeaf> {
        self.leaves.get(&asset)
    }

    /// Every registered leaf, ascending by asset.
    pub fn leaves(&self) -> impl Iterator<Item = &RegistryLeaf> {
        self.leaves.values()
    }

    /// The authentication path of a **registered** asset (`None` for an empty
    /// slot — the circuit opens leaves, not absences).
    pub fn witness(&self, asset: u16) -> Option<RegistryWitness> {
        self.leaves.get(&asset)?;
        Some(witness_at(&self.levels, asset))
    }

    /// The single update seam — refused until A2 lands shape R.
    pub fn apply_update(&mut self, _leaf: RegistryLeaf) -> Result<(), RegistryError> {
        Err(RegistryError::UpdatesArriveWithA2)
    }
}

fn witness_at(levels: &[BTreeMap<u64, [u64; 4]>], asset: u16) -> RegistryWitness {
    let z = zeros();
    let mut siblings = [[0u64; 4]; REGISTRY_DEPTH];
    let mut path_bits = [false; REGISTRY_DEPTH];
    for lvl in 0..REGISTRY_DEPTH {
        let i = (asset as u64) >> lvl;
        siblings[lvl] = *levels[lvl].get(&(i ^ 1)).unwrap_or(&z[lvl]);
        path_bits[lvl] = i & 1 == 1;
    }
    RegistryWitness { siblings, path_bits }
}

/// The path bits of an opening for `asset` (its position's bits, low first).
pub fn path_bits_of(asset: u16) -> [bool; REGISTRY_DEPTH] {
    core::array::from_fn(|lvl| (asset >> lvl) & 1 == 1)
}

// ---------------------------------------------------------------------------
// The served wire
// ---------------------------------------------------------------------------

/// A decoded `GET /v1/registry/{asset}` answer.
#[derive(Clone, Copy)]
pub struct RegistryOpening {
    pub height: u64,
    /// The root the opening was computed against.
    pub root: [u64; 4],
    pub leaf: RegistryLeaf,
    /// Siblings from the wire; path bits derived from `leaf.asset`.
    pub witness: RegistryWitness,
}

/// Why a registry body did not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryWireError {
    WrongLength { got: usize, want: usize },
    BadVersion { got: u8 },
    AssetOutOfRange { asset: u64 },
}

/// Encode a `GET /v1/registry/root` body.
pub fn encode_registry_root(height: u64, root: &[u64; 4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(REGISTRY_ROOT_LEN);
    out.push(REGISTRY_WIRE_VERSION);
    out.extend_from_slice(&height.to_le_bytes());
    out.extend_from_slice(&digest_bytes(root));
    out
}

/// Decode a `GET /v1/registry/root` body: `(height, root)`.
pub fn decode_registry_root(b: &[u8]) -> Result<(u64, [u64; 4]), RegistryWireError> {
    if b.len() != REGISTRY_ROOT_LEN {
        return Err(RegistryWireError::WrongLength { got: b.len(), want: REGISTRY_ROOT_LEN });
    }
    head(b)
}

fn head(b: &[u8]) -> Result<(u64, [u64; 4]), RegistryWireError> {
    if b[0] != REGISTRY_WIRE_VERSION {
        return Err(RegistryWireError::BadVersion { got: b[0] });
    }
    let height = u64::from_le_bytes(b[1..9].try_into().expect("8 bytes"));
    let root = digest_from_bytes(b[9..41].try_into().expect("32 bytes"));
    Ok((height, root))
}

/// Encode a `GET /v1/registry/{asset}` body from a tree (`None` when the
/// asset is not registered).
pub fn encode_registry_opening(tree: &RegistryTree, height: u64, asset: u16) -> Option<Vec<u8>> {
    let leaf = tree.leaf(asset)?;
    let w = tree.witness(asset)?;
    Some(encode_opening_parts(height, &tree.root(), leaf, &w.siblings))
}

/// The opening body from its parts (the one layout).
pub fn encode_opening_parts(
    height: u64,
    root: &[u64; 4],
    leaf: &RegistryLeaf,
    siblings: &[[u64; 4]; REGISTRY_DEPTH],
) -> Vec<u8> {
    let mut out = encode_registry_root(height, root);
    for lane in &leaf.state()[..15] {
        out.extend_from_slice(&lane.to_le_bytes());
    }
    for s in siblings {
        out.extend_from_slice(&digest_bytes(s));
    }
    debug_assert_eq!(out.len(), REGISTRY_OPENING_LEN);
    out
}

/// Decode a `GET /v1/registry/{asset}` body.
pub fn decode_registry_opening(b: &[u8]) -> Result<RegistryOpening, RegistryWireError> {
    if b.len() != REGISTRY_OPENING_LEN {
        return Err(RegistryWireError::WrongLength { got: b.len(), want: REGISTRY_OPENING_LEN });
    }
    let (height, root) = head(b)?;
    let lane = |i: usize| {
        let at = REGISTRY_ROOT_LEN + i * 8;
        u64::from_le_bytes(b[at..at + 8].try_into().expect("8 bytes"))
    };
    let d4 = |i: usize| [lane(i), lane(i + 1), lane(i + 2), lane(i + 3)];
    let leaf = RegistryLeaf {
        asset: lane(0),
        issuer_key: d4(1),
        mode: lane(5),
        freeze_root: d4(6),
        allow_root: d4(10),
        flags: lane(14),
    };
    if leaf.asset >= 1u64 << REGISTRY_DEPTH {
        return Err(RegistryWireError::AssetOutOfRange { asset: leaf.asset });
    }
    let sib0 = REGISTRY_ROOT_LEN + 15 * 8;
    let siblings = core::array::from_fn(|i| {
        let at = sib0 + i * 32;
        digest_from_bytes(b[at..at + 32].try_into().expect("32 bytes"))
    });
    let witness = RegistryWitness { siblings, path_bits: path_bits_of(leaf.asset as u16) };
    Ok(RegistryOpening { height, root, leaf, witness })
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_air::l2::MODE_HYBRID;

    fn hybrid(asset: u64) -> RegistryLeaf {
        RegistryLeaf { mode: MODE_HYBRID, issuer_key: [asset; 4], ..RegistryLeaf::cloaked(asset) }
    }

    /// Every served witness folds to the root under the **circuit's own**
    /// fold (`RegistryWitness::fold_root`) — the independent check of the
    /// tree, since the tree and the fold are separate code.
    #[test]
    fn every_opening_folds_to_the_root_under_the_circuits_fold() {
        let leaves = [RegistryLeaf::cloaked(0), RegistryLeaf::cloaked(5), hybrid(7), RegistryLeaf::cloaked(65_535)];
        let t = RegistryTree::from_leaves(&leaves).unwrap();
        for l in &leaves {
            let w = t.witness(l.asset as u16).unwrap();
            assert_eq!(w.fold_root(&l.hash()), t.root(), "asset {}", l.asset);
            assert_eq!(w.path_bits, path_bits_of(l.asset as u16));
        }
        assert!(t.witness(6).is_none(), "an empty slot has no opening");
        // A tampered sibling no longer folds to the root.
        let mut w = t.witness(5).unwrap();
        w.siblings[3][0] ^= 1;
        assert_ne!(w.fold_root(&RegistryLeaf::cloaked(5).hash()), t.root());
    }

    #[test]
    fn the_empty_registry_root_is_the_zero_ladder_and_updates_wait_for_a2() {
        let mut t = RegistryTree::from_leaves(&[]).unwrap();
        assert_eq!(t.root(), zeros()[REGISTRY_DEPTH]);
        assert_eq!(t.apply_update(RegistryLeaf::cloaked(1)), Err(RegistryError::UpdatesArriveWithA2));
        assert_eq!(
            RegistryTree::from_leaves(&[RegistryLeaf::cloaked(3), RegistryLeaf::cloaked(3)]),
            Err(RegistryError::DuplicateAsset { asset: 3 })
        );
        assert_eq!(
            RegistryTree::from_leaves(&[RegistryLeaf::cloaked(1 << 16)]),
            Err(RegistryError::AssetOutOfRange { asset: 1 << 16 })
        );
    }

    #[test]
    fn an_opening_round_trips_with_path_bits_derived_from_the_asset() {
        let t = RegistryTree::from_leaves(&[RegistryLeaf::cloaked(0), hybrid(7)]).unwrap();
        let b = encode_registry_opening(&t, 42, 7).unwrap();
        assert_eq!(b.len(), REGISTRY_OPENING_LEN);
        let o = decode_registry_opening(&b).unwrap();
        assert_eq!((o.height, o.root, o.leaf), (42, t.root(), hybrid(7)));
        assert_eq!(o.witness.siblings, t.witness(7).unwrap().siblings);
        assert_eq!(o.witness.path_bits, t.witness(7).unwrap().path_bits);
        assert!(encode_registry_opening(&t, 42, 6).is_none());
        let mut bad = b.clone();
        bad[0] = 2;
        assert_eq!(decode_registry_opening(&bad).err(), Some(RegistryWireError::BadVersion { got: 2 }));
        assert!(matches!(decode_registry_opening(&b[..b.len() - 1]), Err(RegistryWireError::WrongLength { .. })));
    }

    /// The wire, byte for byte. The expected bytes come from an independent
    /// Python encoder over synthetic digests (the codec does not hash).
    #[test]
    fn the_registry_wire_is_byte_for_byte() {
        let root = [0x1111_1111_1111_1111, 0x2222_2222_2222_2222, 0x3333_3333_3333_3333, 0x4444_4444_4444_4444];
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(hex(&encode_registry_root(0x0102_0304_0506_0708, &root)), GOLDEN_ROOT_HEX);
        assert_eq!(decode_registry_root(&encode_registry_root(9, &root)), Ok((9, root)));
        let leaf = RegistryLeaf {
            asset: 7,
            issuer_key: [0xa1, 0xa2, 0xa3, 0xa4],
            mode: 2,
            freeze_root: [0xf1, 0xf2, 0xf3, 0xf4],
            allow_root: [0xb1, 0xb2, 0xb3, 0xb4],
            flags: 0x0f,
        };
        let siblings: [[u64; 4]; REGISTRY_DEPTH] = core::array::from_fn(|i| [(i as u64 + 1) * 0x0101_0101_0101_0101; 4]);
        let bytes = encode_opening_parts(9, &root, &leaf, &siblings);
        assert_eq!(bytes.len(), 673);
        assert_eq!(hex(&bytes), GOLDEN_OPENING_HEX);
        let back = decode_registry_opening(&bytes).unwrap();
        assert_eq!((back.height, back.root, back.leaf, back.witness.siblings), (9, root, leaf, siblings));
    }

    const GOLDEN_ROOT_HEX: &str =
        "0108070605040302011111111111111111222222222222222233333333333333334444444444444444";
    const GOLDEN_OPENING_HEX: &str = "01090000000000000011111111111111112222222222222222333333333333333344444444444444440700000000000000a100000000000000a200000000000000a300000000000000a4000000000000000200000000000000f100000000000000f200000000000000f300000000000000f400000000000000b100000000000000b200000000000000b300000000000000b4000000000000000f000000000000000101010101010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020203030303030303030303030303030303030303030303030303030303030303030404040404040404040404040404040404040404040404040404040404040404050505050505050505050505050505050505050505050505050505050505050506060606060606060606060606060606060606060606060606060606060606060707070707070707070707070707070707070707070707070707070707070707080808080808080808080808080808080808080808080808080808080808080809090909090909090909090909090909090909090909090909090909090909090a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f1010101010101010101010101010101010101010101010101010101010101010";
}

// ---------------------------------------------------------------------------
// GET /v1/genesis/notes (lab #714, B5)
// ---------------------------------------------------------------------------

/// The genesis-notes wire's version byte.
pub const GENESIS_NOTES_WIRE_VERSION: u8 = 1;

/// One genesis note as served: its commitment and its 128-B
/// `GenesisPlaintext` payload (plaintext ‖ zero tag, by construction).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServedGenesisNote {
    pub cm: [u8; 32],
    pub payload: qlab_note::l2note::GenesisPlaintext,
}

/// Why a genesis-notes body did not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenesisNotesWireError {
    Truncated,
    BadVersion { got: u8 },
    /// Bytes after the declared notes.
    Trailing,
    /// A payload that is not a genesis plaintext (a nonzero tag).
    NotGenesisPlaintext { index: usize },
}

/// Encode `GET /v1/genesis/notes` — a projection of the genesis file:
/// `ver(u8) ‖ genesis_hash(32) ‖ n(u32 LE) ‖ [cm(32) ‖ payload(128)]×n`. The
/// hash names the genesis file the notes were projected from.
pub fn encode_genesis_notes(genesis_hash: &[u8; 32], notes: &[ServedGenesisNote]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 + 4 + notes.len() * (32 + qlab_note::l2note::L2_PAYLOAD_LEN));
    out.push(GENESIS_NOTES_WIRE_VERSION);
    out.extend_from_slice(genesis_hash);
    out.extend_from_slice(&(notes.len() as u32).to_le_bytes());
    for n in notes {
        out.extend_from_slice(&n.cm);
        out.extend_from_slice(&n.payload.0);
    }
    out
}

/// Decode `GET /v1/genesis/notes`: `(genesis_hash, notes)`. Every payload
/// must be a genesis plaintext — a nonzero tag is refused by name.
pub fn decode_genesis_notes(b: &[u8]) -> Result<([u8; 32], Vec<ServedGenesisNote>), GenesisNotesWireError> {
    let w = qlab_note::l2note::L2_PAYLOAD_LEN;
    if b.len() < 37 {
        return Err(GenesisNotesWireError::Truncated);
    }
    if b[0] != GENESIS_NOTES_WIRE_VERSION {
        return Err(GenesisNotesWireError::BadVersion { got: b[0] });
    }
    let hash: [u8; 32] = b[1..33].try_into().expect("32 bytes");
    let n = u32::from_le_bytes(b[33..37].try_into().expect("4 bytes")) as usize;
    let want = n.checked_mul(32 + w).and_then(|x| x.checked_add(37)).ok_or(GenesisNotesWireError::Truncated)?;
    match b.len().cmp(&want) {
        std::cmp::Ordering::Less => return Err(GenesisNotesWireError::Truncated),
        std::cmp::Ordering::Greater => return Err(GenesisNotesWireError::Trailing),
        std::cmp::Ordering::Equal => {}
    }
    let mut notes = Vec::with_capacity(n);
    for i in 0..n {
        let at = 37 + i * (32 + w);
        let cm: [u8; 32] = b[at..at + 32].try_into().expect("32 bytes");
        let p: [u8; qlab_note::l2note::L2_PAYLOAD_LEN] = b[at + 32..at + 32 + w].try_into().expect("128 bytes");
        if !qlab_note::compact::payload_tag_is_zero(&p) {
            return Err(GenesisNotesWireError::NotGenesisPlaintext { index: i });
        }
        notes.push(ServedGenesisNote { cm, payload: qlab_note::l2note::GenesisPlaintext(p) });
    }
    Ok((hash, notes))
}

/// The route an Annulet node serves its fee tiers on (lab #720).
pub const ANNULET_PARAMS_PATH: &str = "/v1/annulet/params";
pub const ANNULET_PARAMS_WIRE_VERSION: u8 = 1;
/// `version ‖ genesis_hash(32) ‖ fee_tier_s u64 LE ‖ fee_tier_p u64 LE`.
pub const ANNULET_PARAMS_LEN: usize = 1 + 32 + 8 + 8;

/// `GET /v1/annulet/params` (lab #720): the posted fee tiers of the genesis
/// the node runs, under that genesis's hash — the tariff a wallet must pay
/// exactly (fee notes are exact-tariff). `[devnet-placeholder]` values until
/// the pilot prices them; the route carries whatever the genesis says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnnuletParams {
    pub genesis_hash: [u8; 32],
    pub fee_tier_s: u64,
    pub fee_tier_p: u64,
}

/// Why an Annulet params body did not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnnuletParamsWireError {
    /// Not exactly [`ANNULET_PARAMS_LEN`] bytes.
    Length { got: usize },
    BadVersion { got: u8 },
}

pub fn encode_annulet_params(p: &AnnuletParams) -> Vec<u8> {
    let mut out = Vec::with_capacity(ANNULET_PARAMS_LEN);
    out.push(ANNULET_PARAMS_WIRE_VERSION);
    out.extend_from_slice(&p.genesis_hash);
    out.extend_from_slice(&p.fee_tier_s.to_le_bytes());
    out.extend_from_slice(&p.fee_tier_p.to_le_bytes());
    out
}

pub fn decode_annulet_params(b: &[u8]) -> Result<AnnuletParams, AnnuletParamsWireError> {
    if b.len() != ANNULET_PARAMS_LEN {
        return Err(AnnuletParamsWireError::Length { got: b.len() });
    }
    if b[0] != ANNULET_PARAMS_WIRE_VERSION {
        return Err(AnnuletParamsWireError::BadVersion { got: b[0] });
    }
    Ok(AnnuletParams {
        genesis_hash: b[1..33].try_into().expect("32 bytes"),
        fee_tier_s: u64::from_le_bytes(b[33..41].try_into().expect("8 bytes")),
        fee_tier_p: u64::from_le_bytes(b[41..49].try_into().expect("8 bytes")),
    })
}

#[cfg(test)]
mod annulet_params_tests {
    use super::*;

    #[test]
    fn annulet_params_round_trip_and_refuse_by_name() {
        let p = AnnuletParams { genesis_hash: [0x6f; 32], fee_tier_s: 1, fee_tier_p: 2 };
        let b = encode_annulet_params(&p);
        assert_eq!(b.len(), ANNULET_PARAMS_LEN);
        assert_eq!(decode_annulet_params(&b), Ok(p));
        assert_eq!(decode_annulet_params(&b[..48]), Err(AnnuletParamsWireError::Length { got: 48 }));
        let mut v2 = b.clone();
        v2[0] = 2;
        assert_eq!(decode_annulet_params(&v2), Err(AnnuletParamsWireError::BadVersion { got: 2 }));
    }
}

#[cfg(test)]
mod genesis_notes_tests {
    use super::*;

    #[test]
    fn genesis_notes_round_trip_and_refuse_what_is_not_a_genesis_plaintext() {
        let note = qlab_note::l2note::L2Note { value: 1, asset: 0, rkm: [1, 2, 3, 4], rho: [5; 4], rseed: [6; 4] };
        let g = ServedGenesisNote { cm: [0x11; 32], payload: qlab_note::l2note::GenesisPlaintext::of(&note) };
        let bytes = encode_genesis_notes(&[0x22; 32], std::slice::from_ref(&g));
        assert_eq!(bytes.len(), 1 + 32 + 4 + 32 + 128);
        let (h, back) = decode_genesis_notes(&bytes).unwrap();
        assert_eq!((h, back), ([0x22; 32], vec![g.clone()]));
        assert_eq!(qlab_note::l2note::GenesisPlaintext::open(&back_payload(&bytes)), Some(note));
        let mut tagged = bytes.clone();
        let last = tagged.len() - 1;
        tagged[last] = 1;
        assert_eq!(decode_genesis_notes(&tagged).err(), Some(GenesisNotesWireError::NotGenesisPlaintext { index: 0 }));
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(decode_genesis_notes(&trailing).err(), Some(GenesisNotesWireError::Trailing));
        assert_eq!(decode_genesis_notes(&bytes[..bytes.len() - 1]).err(), Some(GenesisNotesWireError::Truncated));
    }

    fn back_payload(bytes: &[u8]) -> Vec<u8> {
        bytes[37 + 32..].to_vec()
    }
}
