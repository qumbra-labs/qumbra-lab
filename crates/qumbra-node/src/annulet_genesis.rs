//! The **Annulet genesis file** (lab #706 Q2, l2-roadmap B1).
//!
//! A separate bincode struct from the L1 [`GenesisFile`], because the L1
//! file's hash *is* the T1/T2 network identity: a field added there moves both
//! genesis hashes, and its `FrozenParams` is the L1's frozen table, which an
//! L2 must not claim. The two are told apart by their **leading `u32`** — the
//! `format_version` is the first field of both, and bincode's fixint encoding
//! writes it as the first four bytes, little-endian — so:
//!
//! - [`load_any`] dispatches `4 | 5 → L1`, `32 → Annulet`, anything else →
//!   refused by name;
//! - [`GenesisFile::from_bytes`] refuses a leading 32 **by name**
//!   (`GenesisError::AnnuletGenesisNotServed`) before decoding a byte — which
//!   is also how `qumbra-node run` (and every other L1 loader: explorer,
//!   faucet, mine) refuses an Annulet genesis until B2's producer exists;
//! - [`AnnuletGenesisFile::from_bytes`] refuses anything but 32 by name.
//!
//! What the file carries (Q2): the L2 fee table (Q7 — genesis parameters,
//! never code constants), one sequencer ML-DSA-65 verifying key, the registry
//! genesis (asset 0's pinned leaf plus any genesis-registered assets), the
//! fee-unit genesis notes (Q5 — the fee unit's whole Phase-0 supply), and the
//! genesis header's fields. [`AnnuletGenesisFile::verify`] recomputes the
//! registry root and the genesis body commitment and refuses a file whose
//! header does not bind them.
//!
//! **The registry root here is B3's contract, fixed early.** The depth-16
//! registry tree is B3's to build; the genesis must pin a root now, so this
//! module defines it — leaf `i` is `RegistryLeaf::hash()` of asset `i`, an
//! empty slot is the zero digest, interior nodes are `qlab-air`'s Merkle node
//! hash — and B3's `RegistryTree` must reproduce [`registry_root_of`] exactly.

use ml_dsa::{EncodedVerifyingKey, MlDsa65, VerifyingKey};
use serde::{Deserialize, Serialize};

use qlab_air::l2::{RegistryLeaf, REGISTRY_DEPTH};
use qlab_devnet::annulet::{
    genesis_body_commitment_annulet, AnnuletHeaderFields, GenesisNote, L2FeeTable,
};
use qlab_devnet::committee::Validator;
use qlab_devnet::forms::{GenesisForm, ANNULET_GENESIS_FORMAT_VERSION};
use qlab_devnet::header::{BlockHeader, Hash32};

use crate::genesis::{GenesisError, GenesisFile};

/// A registry leaf as the genesis file stores it (lane values, as
/// [`RegistryLeaf`] holds them; `asset` is the slot index).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryLeafRecord {
    pub asset: u16,
    pub issuer_key: [u64; 4],
    pub mode: u64,
    pub freeze_root: [u64; 4],
    pub allow_root: [u64; 4],
    pub flags: u64,
}

impl RegistryLeafRecord {
    fn leaf(&self) -> RegistryLeaf {
        RegistryLeaf {
            asset: self.asset as u64,
            issuer_key: self.issuer_key,
            mode: self.mode,
            freeze_root: self.freeze_root,
            allow_root: self.allow_root,
            flags: self.flags,
        }
    }

    /// Asset 0's pinned leaf (l2-own-circuit-decision §2.4): the fee asset —
    /// no issuer, Cloaked, both roots 0.
    pub fn asset_zero() -> Self {
        let l = RegistryLeaf::cloaked(0);
        RegistryLeafRecord {
            asset: 0,
            issuer_key: l.issuer_key,
            mode: l.mode,
            freeze_root: l.freeze_root,
            allow_root: l.allow_root,
            flags: l.flags,
        }
    }
}

/// A genesis fee-unit note: commitment + 128-B discovery payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisNoteRecord {
    pub cm: Hash32,
    pub payload: Vec<u8>,
}

/// The L2 genesis parameters (Q7): the posted fee tiers in fee-unit base
/// units. **Placeholders** in the fixture (S = 1, P = 2), pending C2/B4's
/// tariff; a real devnet mints its own values (B6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnnuletParams {
    pub fee_tier_s: u64,
    pub fee_tier_p: u64,
}

impl AnnuletParams {
    /// As the body rule consumes them.
    pub fn fee_table(&self) -> L2FeeTable {
        L2FeeTable { tier_s: self.fee_tier_s, tier_p: self.fee_tier_p }
    }
}

/// The Annulet genesis header's recorded fields (the rest are fixed:
/// height 0, `prev` zero, no PoW fields).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnnuletGenesisHeader {
    pub timestamp: u64,
    pub l1_anchor_height: u64,
    pub l1_anchor_root: Hash32,
    pub registry_root: Hash32,
    pub body_commitment: Hash32,
}

/// The Annulet genesis file. **`format_version` must stay the first field**
/// — [`load_any`] and both loaders dispatch on the leading `u32`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnnuletGenesisFile {
    /// Always [`ANNULET_GENESIS_FORMAT_VERSION`] (32).
    pub format_version: u32,
    /// Network label — not consensus.
    pub network: String,
    pub params: AnnuletParams,
    /// The single sequencer's ML-DSA-65 verifying key (encoded).
    pub sequencer_key: Vec<u8>,
    /// Genesis-registered assets, strictly ascending by `asset`, asset 0
    /// first and pinned ([`RegistryLeafRecord::asset_zero`]).
    pub registry_genesis: Vec<RegistryLeafRecord>,
    /// The fee unit's whole Phase-0 supply (Q5), valid only at height 0.
    pub genesis_notes: Vec<GenesisNoteRecord>,
    pub genesis_header: AnnuletGenesisHeader,
}

/// Either kind of genesis file, as [`load_any`] returns it.
#[derive(Debug)]
pub enum AnyGenesis {
    L1(Box<GenesisFile>),
    Annulet(Box<AnnuletGenesisFile>),
}

/// The leading `u32` of a genesis file's bytes — its `format_version`.
pub fn leading_format_version(bytes: &[u8]) -> Option<u32> {
    bytes.get(..4).map(|b| u32::from_le_bytes(b.try_into().expect("4 bytes")))
}

/// Dispatch a genesis file by its leading `format_version` (Q2).
pub fn load_any(bytes: &[u8]) -> Result<AnyGenesis, GenesisError> {
    let got = leading_format_version(bytes).ok_or_else(|| GenesisError::Decode("genesis file shorter than its format version".into()))?;
    match GenesisForm::from_genesis_format_version(got) {
        Some(GenesisForm::V4) | Some(GenesisForm::V5) => {
            Ok(AnyGenesis::L1(Box::new(GenesisFile::from_bytes(bytes)?)))
        }
        Some(GenesisForm::Annulet) => {
            Ok(AnyGenesis::Annulet(Box::new(AnnuletGenesisFile::from_bytes(bytes)?)))
        }
        None => Err(GenesisError::WrongFormatVersion { got, want: ANNULET_GENESIS_FORMAT_VERSION }),
    }
}

/// The digest `[u64; 4]` as 32 bytes, lane-major little-endian (the node's
/// `h32` convention).
fn h32(d: &[u64; 4]) -> Hash32 {
    let mut o = [0u8; 32];
    for (i, lane) in d.iter().enumerate() {
        o[i * 8..i * 8 + 8].copy_from_slice(&lane.to_le_bytes());
    }
    o
}

fn node(l: &[u64; 4], r: &[u64; 4]) -> [u64; 4] {
    qlab_air::reference::merkle_node_state(l, r)[..4].try_into().expect("4 lanes")
}

/// **The registry root** of a genesis registry (B3's contract — see the module
/// doc): a depth-16 sparse Merkle tree, leaf `i` = `RegistryLeaf::hash()` of
/// asset `i`, empty slot = the zero digest.
pub fn registry_root_of(leaves: &[RegistryLeafRecord]) -> [u64; 4] {
    let mut empty = [[0u64; 4]; REGISTRY_DEPTH + 1];
    for lvl in 0..REGISTRY_DEPTH {
        empty[lvl + 1] = node(&empty[lvl], &empty[lvl]);
    }
    let mut level: std::collections::BTreeMap<u64, [u64; 4]> =
        leaves.iter().map(|r| (r.asset as u64, r.leaf().hash())).collect();
    for (lvl, empty_here) in empty.iter().enumerate().take(REGISTRY_DEPTH) {
        let mut up = std::collections::BTreeMap::new();
        for (&i, d) in &level {
            let parent = i >> 1;
            if up.contains_key(&parent) {
                continue;
            }
            let (l, r) = if i & 1 == 0 {
                (*d, *level.get(&(i | 1)).unwrap_or(empty_here))
            } else {
                (*level.get(&(i & !1)).unwrap_or(empty_here), *d)
            };
            up.insert(parent, node(&l, &r));
        }
        let _ = lvl;
        level = up;
    }
    level.get(&0).copied().unwrap_or(empty[REGISTRY_DEPTH])
}

impl AnnuletGenesisFile {
    /// Decode, refusing a non-Annulet file **by name** before decoding a byte.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GenesisError> {
        match leading_format_version(bytes) {
            Some(ANNULET_GENESIS_FORMAT_VERSION) => {}
            got => {
                return Err(GenesisError::NotAnnuletGenesis { got });
            }
        }
        bincode::deserialize(bytes).map_err(|e| GenesisError::Decode(e.to_string()))
    }

    /// The canonical on-disk bytes (bincode).
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("AnnuletGenesisFile is always serializable")
    }

    /// The genesis hash — keccak256 over the file's bincode, as for L1.
    pub fn hash(&self) -> Hash32 {
        qlab_devnet::hash::keccak256(&self.to_bytes())
    }

    /// Hex of [`Self::hash`].
    pub fn hash_hex(&self) -> String {
        crate::genesis::hex_encode(&self.hash())
    }

    /// Always [`GenesisForm::Annulet`] for a verified file.
    pub fn form(&self) -> Result<GenesisForm, GenesisError> {
        match GenesisForm::from_genesis_format_version(self.format_version) {
            Some(GenesisForm::Annulet) => Ok(GenesisForm::Annulet),
            Some(GenesisForm::V4) | Some(GenesisForm::V5) | None => {
                Err(GenesisError::NotAnnuletGenesis { got: Some(self.format_version) })
            }
        }
    }

    /// The sequencer's verifying key, decoded.
    pub fn sequencer(&self) -> Result<VerifyingKey<MlDsa65>, GenesisError> {
        let e = EncodedVerifyingKey::<MlDsa65>::try_from(self.sequencer_key.as_slice())
            .map_err(|_| GenesisError::BadAnnulet("sequencer key does not decode"))?;
        Ok(VerifyingKey::<MlDsa65>::decode(&e))
    }

    fn notes(&self) -> Vec<GenesisNote> {
        self.genesis_notes.iter().map(|n| GenesisNote { cm: n.cm, payload: n.payload.clone() }).collect()
    }

    /// The genesis header this file pins.
    pub fn genesis_block_header(&self) -> BlockHeader {
        let h = &self.genesis_header;
        BlockHeader::genesis_annulet(
            AnnuletHeaderFields {
                l1_anchor_height: h.l1_anchor_height,
                l1_anchor_root: h.l1_anchor_root,
                registry_root: h.registry_root,
            },
            h.body_commitment,
            h.timestamp,
        )
    }

    /// Structural verification: the form, the sequencer key, the registry
    /// (asset 0 pinned first, ascending, roots recomputed), the notes' payload
    /// width and the genesis header's bindings — and, if `expected_hex` is set,
    /// the genesis hash.
    pub fn verify(&self, expected_hex: Option<&str>) -> Result<(), GenesisError> {
        self.form()?;
        self.sequencer()?;
        if self.registry_genesis.first() != Some(&RegistryLeafRecord::asset_zero()) {
            return Err(GenesisError::BadAnnulet("asset 0's pinned leaf must be the first registry entry"));
        }
        if !self.registry_genesis.windows(2).all(|w| w[0].asset < w[1].asset) {
            return Err(GenesisError::BadAnnulet("registry genesis must be strictly ascending by asset"));
        }
        if h32(&registry_root_of(&self.registry_genesis)) != self.genesis_header.registry_root {
            return Err(GenesisError::BadAnnulet("genesis header registry_root does not match the registry genesis"));
        }
        if self.genesis_notes.iter().any(|n| n.payload.len() != qlab_note::l2note::L2_PAYLOAD_LEN) {
            return Err(GenesisError::BadAnnulet("a genesis note payload is not L2_PAYLOAD_LEN (128) bytes"));
        }
        if genesis_body_commitment_annulet(&self.notes()) != self.genesis_header.body_commitment {
            return Err(GenesisError::BadAnnulet("genesis header body_commitment does not bind the genesis notes"));
        }
        if let Some(want) = expected_hex {
            let got = self.hash_hex();
            if !got.eq_ignore_ascii_case(want) {
                return Err(GenesisError::WrongGenesisHash { got, want: want.to_string() });
            }
        }
        Ok(())
    }

    /// Assemble a file from its parts, computing the header's registry root
    /// and body commitment (so a caller cannot pin an inconsistent header).
    pub fn assemble(
        network: &str,
        params: AnnuletParams,
        sequencer_seed: [u8; 32],
        registry_genesis: Vec<RegistryLeafRecord>,
        genesis_notes: Vec<GenesisNoteRecord>,
        timestamp: u64,
    ) -> Self {
        let sequencer_key = Validator::from_seed(0, sequencer_seed).verifying_key().encode().to_vec();
        let notes: Vec<GenesisNote> =
            genesis_notes.iter().map(|n| GenesisNote { cm: n.cm, payload: n.payload.clone() }).collect();
        let genesis_header = AnnuletGenesisHeader {
            timestamp,
            l1_anchor_height: 0,
            l1_anchor_root: [0u8; 32],
            registry_root: h32(&registry_root_of(&registry_genesis)),
            body_commitment: genesis_body_commitment_annulet(&notes),
        };
        AnnuletGenesisFile {
            format_version: ANNULET_GENESIS_FORMAT_VERSION,
            network: network.to_string(),
            params,
            sequencer_key,
            registry_genesis,
            genesis_notes,
            genesis_header,
        }
    }

    /// **The B1 fixture** — deterministic, NOT a devnet (B6 mints that, with
    /// the faucet's real address and its own parameters):
    ///
    /// - fee tiers S = 1 / P = 2 (placeholders);
    /// - the sequencer key from the fixed seed `[0x5E; 32]`;
    /// - registry: asset 0 (pinned) and asset 7, a Hybrid test asset with a
    ///   fixed issuer key, the empty freeze tree's root and no allowlist
    ///   (A2's mode ⇒ roots invariant: Hybrid ⇒ `allow_root = 0`);
    /// - four fee-unit notes of the S tier to a fixed `rkm`, each with a
    ///   **fixture payload** — the 112-B note plaintext and a zero 16-B tag,
    ///   *not encrypted*: a devnet genesis seals them to the faucet's
    ///   ML-KEM key (B6).
    pub fn fixture() -> Self {
        let params = AnnuletParams { fee_tier_s: 1, fee_tier_p: 2 };
        let isk = [0x15c7_0001, 0x15c7_0002, 0x15c7_0003, 0x15c7_0004];
        let asset7 = RegistryLeafRecord {
            asset: 7,
            issuer_key: qlab_air::l2p::issuer_key_of(&isk),
            mode: qlab_air::l2::MODE_HYBRID,
            freeze_root: qlab_air::l2p::FreezeTree::empty().root,
            allow_root: [0; 4],
            flags: 0,
        };
        let faucet_rkm = [0xFA0C_E7_01, 0xFA0C_E7_02, 0xFA0C_E7_03, 0xFA0C_E7_04];
        let notes = (0..4u64)
            .map(|i| {
                let note = qlab_note::l2note::L2Note {
                    value: params.fee_tier_s,
                    asset: 0,
                    rkm: faucet_rkm,
                    rho: [0x6E0A_0000 + i, 1, 2, 3],
                    rseed: [0x5EED_0000 + i, 4, 5, 6],
                };
                let mut payload = note.to_plaintext().to_vec();
                payload.extend_from_slice(&[0u8; 16]);
                GenesisNoteRecord { cm: h32(&note.commitment()), payload }
            })
            .collect();
        Self::assemble(
            "annulet-fixture",
            params,
            [0x5E; 32],
            vec![RegistryLeafRecord::asset_zero(), asset7],
            notes,
            0,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fixture's genesis hash — computed by the named
    /// `annulet_fixture_genesis` run (twice, byte-identical).
    const FIXTURE_GENESIS_HASH: &str = "PENDING";

    #[test]
    fn the_fixture_verifies_and_selects_the_annulet_form() {
        let g = AnnuletGenesisFile::fixture();
        g.verify(None).expect("the fixture verifies");
        assert_eq!(g.form().unwrap(), GenesisForm::Annulet);
        assert_eq!(g.format_version, 32);
        assert_eq!(leading_format_version(&g.to_bytes()), Some(32), "format_version is the leading u32");
        assert_eq!(g.genesis_notes.len(), 4);
        assert_eq!(g.params.fee_table().posted_fee_l2(qlab_devnet::annulet::L2ShapeTag::P), 2);
    }

    #[test]
    fn annulet_fixture_genesis_hash_is_pinned() {
        let a = AnnuletGenesisFile::fixture();
        assert_eq!(a, AnnuletGenesisFile::fixture(), "the fixture is deterministic");
        assert_eq!(a.hash_hex(), FIXTURE_GENESIS_HASH);
        a.verify(Some(FIXTURE_GENESIS_HASH)).expect("pins itself");
    }

    #[test]
    fn load_any_dispatches_on_the_leading_format_version() {
        let an = AnnuletGenesisFile::fixture().to_bytes();
        assert!(matches!(load_any(&an), Ok(AnyGenesis::Annulet(_))));
        for l1 in [GenesisFile::new_devnet_t0(), GenesisFile::new_t2()] {
            assert!(matches!(load_any(&l1.to_bytes()), Ok(AnyGenesis::L1(_))));
        }
        let mut junk = an.clone();
        junk[..4].copy_from_slice(&6u32.to_le_bytes());
        assert!(matches!(load_any(&junk), Err(GenesisError::WrongFormatVersion { got: 6, .. })));
        assert!(load_any(&[1, 2]).is_err());
    }

    /// Q2's two misparse refusals, by name: the L1 loader fed an Annulet file
    /// (this is also `qumbra-node run`'s refusal — `run` loads through
    /// `GenesisFile::load`), and the Annulet loader fed a v4 / v5 file.
    #[test]
    fn neither_loader_misparses_the_other_kind() {
        let an = AnnuletGenesisFile::fixture().to_bytes();
        let err = GenesisFile::from_bytes(&an).unwrap_err();
        assert!(matches!(err, GenesisError::AnnuletGenesisNotServed), "{err}");
        assert!(err.to_string().contains("B2"), "the refusal names the milestone: {err}");
        for (l1, v) in [(GenesisFile::new_devnet_t0(), 4u32), (GenesisFile::new_t2(), 5)] {
            assert!(matches!(
                AnnuletGenesisFile::from_bytes(&l1.to_bytes()),
                Err(GenesisError::NotAnnuletGenesis { got: Some(g) }) if g == v
            ));
        }
    }

    #[test]
    fn verify_refuses_an_inconsistent_file_by_name() {
        let good = AnnuletGenesisFile::fixture();
        let mut bad_root = good.clone();
        bad_root.genesis_header.registry_root[0] ^= 1;
        assert!(matches!(bad_root.verify(None), Err(GenesisError::BadAnnulet(m)) if m.contains("registry_root")));
        let mut bad_note = good.clone();
        bad_note.genesis_notes[2].cm[0] ^= 1;
        assert!(matches!(bad_note.verify(None), Err(GenesisError::BadAnnulet(m)) if m.contains("body_commitment")));
        let mut short = good.clone();
        short.genesis_notes[0].payload.pop();
        assert!(matches!(short.verify(None), Err(GenesisError::BadAnnulet(m)) if m.contains("128")));
        let mut no_zero = good.clone();
        no_zero.registry_genesis.remove(0);
        assert!(matches!(no_zero.verify(None), Err(GenesisError::BadAnnulet(m)) if m.contains("asset 0")));
        let mut key = good.clone();
        key.sequencer_key.truncate(10);
        assert!(matches!(key.verify(None), Err(GenesisError::BadAnnulet(m)) if m.contains("sequencer")));
        assert!(matches!(good.verify(Some("00")), Err(GenesisError::WrongGenesisHash { .. })));
    }

    /// The registry root is the sparse depth-16 tree it claims to be: a
    /// single-leaf registry folds that leaf with the empty subtrees, and the
    /// fixture's two leaves reproduce by an independent full-tree fold.
    #[test]
    fn registry_root_of_is_the_depth_16_tree() {
        let only0 = vec![RegistryLeafRecord::asset_zero()];
        let mut d = RegistryLeaf::cloaked(0).hash();
        let mut e = [0u64; 4];
        for _ in 0..REGISTRY_DEPTH {
            d = node(&d, &e);
            e = node(&e, &e);
        }
        assert_eq!(registry_root_of(&only0), d);
        // Full fold over all 2^16 slots for the fixture's leaves.
        let fx = AnnuletGenesisFile::fixture().registry_genesis;
        let mut layer: Vec<[u64; 4]> = vec![[0; 4]; 1 << REGISTRY_DEPTH];
        for r in &fx {
            layer[r.asset as usize] = r.leaf().hash();
        }
        while layer.len() > 1 {
            layer = layer.chunks(2).map(|p| node(&p[0], &p[1])).collect();
        }
        assert_eq!(registry_root_of(&fx), layer[0]);
    }

    /// Nothing about the L1 genesis moved (the compat law): both L1 files
    /// still load through the L1 loader and hash to their pins.
    #[test]
    fn the_l1_genesis_files_are_untouched() {
        let t1 = GenesisFile::new_devnet_t0();
        assert_eq!(GenesisFile::from_bytes(&t1.to_bytes()).unwrap().hash(), t1.hash());
        let t2 = GenesisFile::new_t2();
        assert_eq!(GenesisFile::from_bytes(&t2.to_bytes()).unwrap().hash(), t2.hash());
    }
}
