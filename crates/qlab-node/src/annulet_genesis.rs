//! The **Annulet genesis file** (lab #706 Q2, l2-roadmap B1): the file type
//! and the reads a verifier needs — decode, hash, the sequencer key, the
//! genesis notes and header, structural verification, and assembly.
//!
//! **Moved here from `qumbra-node::annulet_genesis` by lab #850 (AD1)**,
//! verbatim apart from the path, the error type and one visibility edit
//! (`h32` is now `pub`, for the constructors that stayed behind), so a wallet
//! can verify an Annulet chain **from the genesis bytes** without the node
//! binary's crate: it hashes the file it fetched, decodes it here, and takes
//! the sequencer key and the genesis header from what it hashed.
//! `qumbra-node::annulet_genesis` re-exports every item, so no node call site
//! moved; the loader dispatch (`load_any`), the sequencer key file and the
//! fixture/devnet constructors stay there. The fixture and devnet genesis hash
//! pins did not move — they are the byte-identity proof of this move.
//!
//! **The registry root here is B3's contract, fixed early.** The depth-16
//! registry tree is B3's to build; the genesis must pin a root now, so this
//! module defines it — leaf `i` is `RegistryLeaf::hash()` of asset `i`, an
//! empty slot is the zero digest, interior nodes are `qlab-air`'s Merkle node
//! hash — and B3's `RegistryTree` must reproduce [`registry_root_of`] exactly.

use ml_dsa::{EncodedVerifyingKey, MlDsa65, VerifyingKey};
use serde::{Deserialize, Serialize};

use qlab_air::l2::RegistryLeaf;
use qlab_devnet::annulet::{
    genesis_body_commitment_annulet, AnnuletHeaderFields, GenesisNote, L2FeeTable,
};
use qlab_devnet::committee::Validator;
use qlab_devnet::forms::{GenesisForm, ANNULET_GENESIS_FORMAT_VERSION};
use qlab_devnet::header::{BlockHeader, Hash32};

/// Why an Annulet genesis file was refused. Each variant is the one
/// `qumbra-node`'s `GenesisError` carried for the same refusal before the
/// move, and converts back to it there with the message unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnnuletGenesisError {
    /// The leading `format_version` is not 32 (`None`: shorter than four bytes).
    NotAnnuletGenesis { got: Option<u32> },
    /// The bytes do not decode as the file.
    Decode(String),
    /// The file is internally inconsistent.
    BadAnnulet(&'static str),
    /// The genesis hash does not match the expected pin.
    WrongGenesisHash { got: String, want: String },
}

impl std::fmt::Display for AnnuletGenesisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnnuletGenesisError::NotAnnuletGenesis { got } => {
                write!(f, "not an Annulet genesis file: leading format_version {got:?}, want 32")
            }
            AnnuletGenesisError::Decode(e) => write!(f, "genesis decode: {e}"),
            AnnuletGenesisError::BadAnnulet(why) => write!(f, "Annulet genesis: {why}"),
            AnnuletGenesisError::WrongGenesisHash { got, want } => {
                write!(f, "genesis hash {got} != expected {want} — refusing to start")
            }
        }
    }
}

impl std::error::Error for AnnuletGenesisError {}

/// Lowercase hex, as `qumbra-node`'s `genesis::hex_encode` writes it.
fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

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
    /// The record of a circuit leaf (lab #722: test genesis assembly).
    pub fn of(l: &RegistryLeaf) -> Self {
        RegistryLeafRecord {
            asset: u16::try_from(l.asset).expect("a registry index is 16-bit"),
            issuer_key: l.issuer_key,
            mode: l.mode,
            freeze_root: l.freeze_root,
            allow_root: l.allow_root,
            flags: l.flags,
        }
    }

    /// The circuit's leaf for this record.
    pub fn leaf(&self) -> RegistryLeaf {
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

impl GenesisNoteRecord {
    /// A genesis note record: the committed cm and the note's
    /// `GenesisPlaintext` (lab #722: test genesis assembly).
    pub fn of(n: &qlab_note::l2note::L2Note) -> Self {
        GenesisNoteRecord { cm: h32(&n.commitment()), payload: qlab_note::l2note::GenesisPlaintext::of(n).0.to_vec() }
    }
}

/// The L2 genesis parameters: the posted fee tiers in fee-unit base units
/// (lab #706 Q7 — **placeholders** in the fixture, S = 1 / P = 2, pending
/// C2/B4's tariff) and the sequencer's slot cadence (lab #708 Q5 — genesis
/// parameters, not code constants: `slot_secs` = 10, an empty block at most
/// every `max_empty_slots` = 6 slots, the §5 defaults). A real devnet mints
/// its own values (B6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnnuletParams {
    pub fee_tier_s: u64,
    pub fee_tier_p: u64,
    /// **`fee_tier_r` — a labelled PLACEHOLDER** (lab #728, from A2's
    /// `qlab_l2::FEE_TIER_R_PLACEHOLDER`): the fee a registry write (shape R)
    /// pays. Registration is permissionless into 65,536 slots (asset ids are
    /// 16-bit registry indices; asset 0 is never writable), so **this tier is
    /// the only price on exhausting the registry** — the pilot's tariff must
    /// set it; the fixture and devnet values are not that price.
    pub fee_tier_r: u64,
    /// The slot length in seconds (lab #708 Q5).
    pub slot_secs: u64,
    /// The producer seals an empty block at the latest every this many slots
    /// with an empty pool (lab #708 Q5).
    pub max_empty_slots: u64,
}

impl AnnuletParams {
    /// As the body rule consumes them.
    pub fn fee_table(&self) -> L2FeeTable {
        L2FeeTable { tier_s: self.fee_tier_s, tier_p: self.fee_tier_p, tier_r: self.fee_tier_r }
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

/// The leading `u32` of a genesis file's bytes — its `format_version`.
pub fn leading_format_version(bytes: &[u8]) -> Option<u32> {
    bytes.get(..4).map(|b| u32::from_le_bytes(b.try_into().expect("4 bytes")))
}

/// The digest `[u64; 4]` as 32 bytes, lane-major little-endian (the node's
/// `h32` convention).
pub fn h32(d: &[u64; 4]) -> Hash32 {
    let mut o = [0u8; 32];
    for (i, lane) in d.iter().enumerate() {
        o[i * 8..i * 8 + 8].copy_from_slice(&lane.to_le_bytes());
    }
    o
}


/// **The registry root** of a genesis registry (B3's contract — see the module
/// doc): a depth-16 sparse Merkle tree, leaf `i` = `RegistryLeaf::hash()` of
/// asset `i`, empty slot = the zero digest.
pub fn registry_root_of(leaves: &[RegistryLeafRecord]) -> [u64; 4] {
    // Lab #710: one tree — the registry state's own. The fixture genesis
    // hash pin (unchanged by this delegation) is the byte-identity proof.
    qlab_cbserver::registry::RegistryTree::from_leaves(&registry_leaves(leaves))
        .expect("a verified registry genesis has unique assets below 2^16")
        .root()
}

/// The genesis registry as the circuit's leaves (lab #710).
pub fn registry_leaves(leaves: &[RegistryLeafRecord]) -> Vec<RegistryLeaf> {
    leaves.iter().map(RegistryLeafRecord::leaf).collect()
}

impl AnnuletGenesisFile {
    /// Decode, refusing a non-Annulet file **by name** before decoding a byte.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AnnuletGenesisError> {
        match leading_format_version(bytes) {
            Some(ANNULET_GENESIS_FORMAT_VERSION) => {}
            got => {
                return Err(AnnuletGenesisError::NotAnnuletGenesis { got });
            }
        }
        bincode::deserialize(bytes).map_err(|e| AnnuletGenesisError::Decode(e.to_string()))
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
        hex_encode(&self.hash())
    }

    /// Always [`GenesisForm::Annulet`] for a verified file.
    pub fn form(&self) -> Result<GenesisForm, AnnuletGenesisError> {
        match GenesisForm::from_genesis_format_version(self.format_version) {
            Some(GenesisForm::Annulet) => Ok(GenesisForm::Annulet),
            Some(GenesisForm::V4) | Some(GenesisForm::V5) | None => {
                Err(AnnuletGenesisError::NotAnnuletGenesis { got: Some(self.format_version) })
            }
        }
    }

    /// The sequencer's verifying key, decoded.
    pub fn sequencer(&self) -> Result<VerifyingKey<MlDsa65>, AnnuletGenesisError> {
        let e = EncodedVerifyingKey::<MlDsa65>::try_from(self.sequencer_key.as_slice())
            .map_err(|_| AnnuletGenesisError::BadAnnulet("sequencer key does not decode"))?;
        Ok(VerifyingKey::<MlDsa65>::decode(&e))
    }

    /// The genesis notes in the form the genesis-body commitment binds.
    pub fn notes(&self) -> Vec<GenesisNote> {
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
    pub fn verify(&self, expected_hex: Option<&str>) -> Result<(), AnnuletGenesisError> {
        self.form()?;
        self.sequencer()?;
        if self.registry_genesis.first() != Some(&RegistryLeafRecord::asset_zero()) {
            return Err(AnnuletGenesisError::BadAnnulet("asset 0's pinned leaf must be the first registry entry"));
        }
        if !self.registry_genesis.windows(2).all(|w| w[0].asset < w[1].asset) {
            return Err(AnnuletGenesisError::BadAnnulet("registry genesis must be strictly ascending by asset"));
        }
        if h32(&registry_root_of(&self.registry_genesis)) != self.genesis_header.registry_root {
            return Err(AnnuletGenesisError::BadAnnulet("genesis header registry_root does not match the registry genesis"));
        }
        if self.genesis_notes.iter().any(|n| n.payload.len() != qlab_note::l2note::L2_PAYLOAD_LEN) {
            return Err(AnnuletGenesisError::BadAnnulet("a genesis note payload is not L2_PAYLOAD_LEN (128) bytes"));
        }
        // Lab #714 rule (i): every genesis payload is a GenesisPlaintext that
        // opens to the note its commitment names.
        if self.genesis_notes.iter().any(|n| {
            qlab_note::l2note::GenesisPlaintext::open(&n.payload).is_none_or(|note| h32(&note.commitment()) != n.cm)
        }) {
            return Err(AnnuletGenesisError::BadAnnulet(
                "a genesis note payload is not a GenesisPlaintext opening to its commitment",
            ));
        }
        if genesis_body_commitment_annulet(&self.notes()) != self.genesis_header.body_commitment {
            return Err(AnnuletGenesisError::BadAnnulet("genesis header body_commitment does not bind the genesis notes"));
        }
        if let Some(want) = expected_hex {
            let got = self.hash_hex();
            if !got.eq_ignore_ascii_case(want) {
                return Err(AnnuletGenesisError::WrongGenesisHash { got, want: want.to_string() });
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
}
