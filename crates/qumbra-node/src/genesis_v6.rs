//! **The V6 genesis** (lab #785 F5-3c): genesis format 10, the wrapper-bundle
//! net — `(GenesisForm::V5, BodySections::V6)` (ruling B).
//!
//! ## Why its own file type
//!
//! [`GenesisFile`] is positional bincode, and its hash is T1's network
//! identity (`740ba41c…`). A field added to it — even an `Option` — moves
//! every existing genesis hash. So V6 is a **separate** struct that *contains*
//! a [`GenesisFile`] (`base`, carrying format 10 in its leading `u32`) followed
//! by the [`WrapperParams`] section; the loader dispatches on that leading
//! version exactly as it does for the Annulet (32). T1's and V5's files, their
//! types and their hashes are untouched.
//!
//! ## committee₀
//!
//! committee₀ is `base.committee_keys` — covered by the V6 genesis hash, which
//! every node pins. It is the roster finality records are judged against
//! (ruling Q1), and the node's committee₀ is taken from this file and nowhere
//! else ([`GenesisFileV6::committee`]); no second digest of it is carried.
//!
//! ## The wrapper parameters and the revision
//!
//! [`WrapperParams`] freezes the L2's consensus constants for this net. Their
//! keccak is folded into the V6 revision digest
//! ([`crate::revision::revision_digest_v6`]) beside `frozen_digest`. In F5-3c
//! that digest is **computed, pinned and printed** (`genesis init --t2`) — it
//! is **not yet** a V6 net's rule domain or halt-marker identity: `prepare_v6`
//! runs the release's ordinary `Revision::digest()`, exactly as T1 and V5 do.
//! Wiring it in (with T1's and V5's domains byte-identical and a CI pin) is
//! F5-4 condition C1 (review of PR #794).

use serde::{Deserialize, Serialize};

use qlab_devnet::committee::{Committee, Validator};
use qlab_devnet::forms::{BodySections, GenesisForm, V6_GENESIS_FORMAT_VERSION};
use qlab_devnet::header::Hash32;
use qlab_devnet::params_devnet as pd;

use crate::genesis::{committee_seed, hex_encode, FrozenParams, GenesisError, GenesisFile, T0_GENESIS_DIFFICULTY};

/// The L2 lane, frozen at q45 (lab #785 F5-2, Q-L2) — `qlab_l2::L2_CFG`'s
/// label, cross-locked by test.
pub const L2_LANE_V1: &str = "b4/q45/g22/fp16/a16";
/// Wrapper version 1's lane, b2/q91 (F5-2) — `qlab_wrapper::config::W_V1_CFG`'s
/// label, cross-locked by test.
pub const WRAPPER_LANE_V1: &str = "b2/q91/g22/fp16/a16";
/// Exits per bundle, `K_exit` (stage-0 §C).
pub const K_EXIT_V1: u32 = 8;
/// The minimum spacing between one `l2_id`'s bundles, in blocks (Q-L3).
pub const WRAPPER_SPACING_BLOCKS_V1: u64 = 48;
/// The finality-record format this net runs (`qlab_devnet::finality_record`).
pub const FINALITY_RECORD_VERSION_V1: u32 = 1;
/// The rehearsal net's one `l2_id` (Q-L3). A `u64`: `qlab_wrapper`'s `Surface`
/// carries `l2_id` as a `u64`, and the genesis must name the same value the
/// verifier threads (the plan's `[u8; 32]` would have needed a mapping that
/// nothing else defines).
pub const REHEARSAL_L2_ID: u64 = 1;

/// **The V6 genesis registry** (lab #785 F5-4a, finding F-A): asset 0's
/// pinned Cloaked leaf and nothing else — the Annulet genesis's asset-0
/// record, and the registry every F3/F4 fixture starts from. It cannot be
/// empty: shapes S and P open each input's asset leaf under R (dummy input
/// slots carry asset 0), a leaf digest is a Keccak output and never the zero
/// digest, and asset 0's slot is never writable afterwards (lab #724) — so
/// over an empty registry no L2 transaction would ever be provable.
pub fn v6_genesis_registry() -> Vec<qlab_air::l2::RegistryLeaf> {
    vec![qlab_air::l2::RegistryLeaf::cloaked(0)]
}

/// The root of [`v6_genesis_registry`] — the node's registry tree over it.
pub fn v6_genesis_registry_root() -> [u64; 4] {
    qlab_cbserver::registry::RegistryTree::from_leaves(&v6_genesis_registry())
        .expect("asset 0's leaf is a valid registry")
        .root()
}

/// The W genesis surface commitment for the rehearsal `l2_id` over
/// [`v6_genesis_registry`] — `Surface::genesis(1, REHEARSAL_L2_ID,
/// WState::genesis(&[cloaked(0)]).roots()).commitment`, **copied from the
/// named `qlab-bench wgenesis` run's output** (Q-S = (b) on issue #785; the
/// registry per F-A). F5-4a's port recomputes it, and
/// `the_rehearsal_genesis_surface_is_the_ported_one` holds this pin to it.
pub const REHEARSAL_GENESIS_SURFACE: [u64; 4] =
    [3351788334638659005, 15912216378482193296, 6060495819875004553, 538790937245016534];

/// The domain the rehearsal sequencer key's seed is derived under.
pub const REHEARSAL_SEQUENCER_DOMAIN: &[u8] = b"qumbra:rehearsal-sequencer:v1";

/// The L2 consensus constants a V6 genesis freezes (lab #785 F5-3, plan §D).
/// Field order is the bincode order and part of the genesis hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrapperParams {
    pub l2_lane: String,
    pub wrapper_lane: String,
    pub k_exit: u32,
    pub wrapper_spacing_blocks: u64,
    pub finality_record_version: u32,
    pub l2_id: u64,
    /// The sequencer's ML-DSA-65 verifying key (1,952 B): a bundle's
    /// permission (stage-0 §C).
    pub sequencer_key: Vec<u8>,
    /// The W genesis surface commitment.
    pub genesis_surface: [u64; 4],
}

/// The rehearsal sequencer's seed: `keccak("qumbra:rehearsal-sequencer:v1")`.
/// In code, and so never secret — refused in any launch genesis.
pub fn rehearsal_sequencer_seed() -> [u8; 32] {
    qlab_devnet::hash::keccak256(REHEARSAL_SEQUENCER_DOMAIN)
}

/// The rehearsal sequencer's verifying key.
pub fn rehearsal_sequencer_key() -> Vec<u8> {
    Validator::from_seed(0, rehearsal_sequencer_seed()).verifying_key().encode().to_vec()
}

impl WrapperParams {
    /// Version-1 parameters for a given `l2_id`, sequencer key and genesis
    /// surface — the only three a V6 genesis chooses.
    pub fn v1(l2_id: u64, sequencer_key: Vec<u8>, genesis_surface: [u64; 4]) -> Self {
        WrapperParams {
            l2_lane: L2_LANE_V1.to_string(),
            wrapper_lane: WRAPPER_LANE_V1.to_string(),
            k_exit: K_EXIT_V1,
            wrapper_spacing_blocks: WRAPPER_SPACING_BLOCKS_V1,
            finality_record_version: FINALITY_RECORD_VERSION_V1,
            l2_id,
            sequencer_key,
            genesis_surface,
        }
    }

    /// The rehearsal parameters: `l2_id` 1, the rehearsal sequencer key, the
    /// pinned rehearsal genesis surface.
    pub fn rehearsal() -> Self {
        Self::v1(REHEARSAL_L2_ID, rehearsal_sequencer_key(), REHEARSAL_GENESIS_SURFACE)
    }

    /// `keccak(bincode(self))` — the value folded into the V6 revision digest.
    pub fn digest(&self) -> Hash32 {
        qlab_devnet::hash::keccak256(&bincode::serialize(self).expect("WrapperParams serializes"))
    }

    /// Hex form of [`Self::digest`].
    pub fn digest_hex(&self) -> String {
        hex_encode(&self.digest())
    }

    /// These parameters describe **this binary's** version-1 constants, and
    /// the sequencer key decodes. A genesis naming another lane, `K_exit`,
    /// spacing or record version is a net this binary does not run.
    pub fn check_v1(&self) -> Result<(), GenesisError> {
        let want = Self::v1(self.l2_id, self.sequencer_key.clone(), self.genesis_surface);
        if *self != want {
            return Err(GenesisError::V6Refused(format!(
                "WrapperParams {self:?} are not this binary's v1 constants \
                 (lanes {L2_LANE_V1} / {WRAPPER_LANE_V1}, K_exit {K_EXIT_V1}, spacing \
                 {WRAPPER_SPACING_BLOCKS_V1}, finality record v{FINALITY_RECORD_VERSION_V1})"
            )));
        }
        let enc = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa65>::try_from(self.sequencer_key.as_slice())
            .map_err(|_| GenesisError::V6Refused(format!("sequencer key is {} bytes, not an ML-DSA-65 key", self.sequencer_key.len())))?;
        let _ = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(&enc);
        Ok(())
    }

    /// Whether the sequencer key is the in-code rehearsal key.
    pub fn has_rehearsal_sequencer_key(&self) -> bool {
        self.sequencer_key == rehearsal_sequencer_key()
    }
}

/// The rehearsal committee's 21 verifying keys (`committee_seed`), encoded.
fn rehearsal_committee_keys() -> Vec<Vec<u8>> {
    (0..pd::FROZEN_COMMITTEE_SIZE)
        .map(|i| Validator::from_seed(i, committee_seed(i)).verifying_key().encode().to_vec())
        .collect()
}

/// A **V6** genesis file: the L1 genesis shape at format 10, then the
/// wrapper section. See the module doc for why it is its own type.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GenesisFileV6 {
    pub base: GenesisFile,
    pub wrapper: WrapperParams,
}

impl GenesisFileV6 {
    /// The **rehearsal** V6 genesis — what `genesis init --t2` mints since
    /// lab #785 F5-3c: network `qumbra-t2`, FrozenParams v1.0, the rehearsal
    /// committee, the V6 genesis block (empty body under `commitment_v6`), and
    /// the rehearsal wrapper parameters.
    pub fn new_rehearsal() -> Self {
        Self::from_parts(rehearsal_committee_keys(), T0_GENESIS_DIFFICULTY, "qumbra-t2".into(), WrapperParams::rehearsal())
    }

    fn from_parts(committee_keys: Vec<Vec<u8>>, difficulty: u64, network: String, wrapper: WrapperParams) -> Self {
        GenesisFileV6 {
            base: GenesisFile {
                format_version: V6_GENESIS_FORMAT_VERSION,
                network,
                frozen: FrozenParams::v1_0(),
                committee_keys,
                genesis_difficulty: difficulty,
                genesis_block: qlab_node::genesis_block_v6(difficulty, 0),
            },
            wrapper,
        }
    }

    /// **The V6 re-mint** of a V5 T2 genesis (format 9 — the launch file):
    /// the relaunch ceremony's constructor. Carried unchanged: network,
    /// committee₀, difficulty. New: format 10, the V6 genesis block, and the
    /// wrapper section with the ceremony's sequencer key — **never** the
    /// rehearsal one — and the given `l2_id` / genesis surface.
    pub fn remint_from_v5(
        old: &GenesisFile,
        expect_hex: &str,
        sequencer_key: Vec<u8>,
        l2_id: u64,
        genesis_surface: [u64; 4],
    ) -> Result<Self, GenesisError> {
        let got = old.hash_hex();
        if !got.eq_ignore_ascii_case(expect_hex) {
            return Err(GenesisError::RemintInput(format!(
                "the input's genesis hash is {got}, not the expected {expect_hex}"
            )));
        }
        if old.format_version != crate::genesis::GENESIS_FORMAT_VERSION_T2 {
            return Err(GenesisError::RemintInput(format!(
                "a V6 re-mint starts from the V5 T2 format {}, not {}",
                crate::genesis::GENESIS_FORMAT_VERSION_T2,
                old.format_version
            )));
        }
        let new = Self::from_parts(
            old.committee_keys.clone(),
            old.genesis_difficulty,
            old.network.clone(),
            WrapperParams::v1(l2_id, sequencer_key, genesis_surface),
        );
        new.verify_startup(None)?;
        Ok(new)
    }

    /// The forms this file selects: `(V5, V6)`.
    pub fn forms(&self) -> (GenesisForm, BodySections) {
        (GenesisForm::V5, BodySections::V6)
    }

    /// committee₀ — the one source of the V6 node's record roster.
    pub fn committee(&self) -> Result<Committee, GenesisError> {
        self.base.committee()
    }

    /// Whether this is a rehearsal genesis: its committee₀ is the in-code
    /// rehearsal committee.
    pub fn is_rehearsal(&self) -> bool {
        self.base.committee_keys == rehearsal_committee_keys()
    }

    /// The V6 genesis hash: keccak over the file's canonical bincode.
    pub fn hash(&self) -> Hash32 {
        qlab_devnet::hash::keccak256(&self.to_bytes())
    }

    /// Hex form of [`Self::hash`].
    pub fn hash_hex(&self) -> String {
        hex_encode(&self.hash())
    }

    /// Canonical on-disk bytes (bincode).
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("GenesisFileV6 is always serializable")
    }

    /// Decode, refusing anything but a leading format 10 **by name**.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GenesisError> {
        match crate::annulet_genesis::leading_format_version(bytes) {
            Some(V6_GENESIS_FORMAT_VERSION) => {}
            got => return Err(GenesisError::NotV6Genesis { got }),
        }
        let file: Self = bincode::deserialize(bytes).map_err(|e| GenesisError::Decode(e.to_string()))?;
        // Canonical only (review R3 on PR #794): bincode 1.3's `deserialize`
        // accepts trailing bytes, so the decode is re-encoded and compared —
        // one file has one byte string, and its hash names exactly it.
        if file.to_bytes() != bytes {
            return Err(GenesisError::Decode("a V6 genesis file must be exactly its canonical bytes (trailing or non-canonical bytes)".into()));
        }
        Ok(file)
    }

    /// The V6 startup gate: format 10, the base's committee size / quorum /
    /// key decoding, the V6 genesis block, this binary's v1 wrapper constants,
    /// no rehearsal sequencer key outside a rehearsal genesis, and — if set —
    /// the V6 genesis hash pin.
    pub fn verify_startup(&self, expected_hex: Option<&str>) -> Result<(), GenesisError> {
        if self.base.format_version != V6_GENESIS_FORMAT_VERSION {
            return Err(GenesisError::NotV6Genesis { got: Some(self.base.format_version) });
        }
        self.base.verify_structure(None)?;
        if self.base.genesis_block != qlab_node::genesis_block_v6(self.base.genesis_difficulty, 0) {
            return Err(GenesisError::V6Refused("the genesis block is not the V6 genesis block at this difficulty".into()));
        }
        self.wrapper.check_v1()?;
        // C2 (lab #785 F5-4b): the pinned genesis surface is the one this
        // binary computes for the genesis's l2_id over the empty registry —
        // the surface every node's first bundle threads from.
        let computed = qlab_wrapper::genesis::genesis_surface(self.wrapper.l2_id, &qlab_wrapper::genesis::empty_registry_root());
        if self.wrapper.genesis_surface != computed.commitment {
            return Err(GenesisError::V6Refused(format!(
                "WrapperParams.genesis_surface {:?} is not the empty L2 state's surface for l2_id {} ({:?})",
                self.wrapper.genesis_surface, self.wrapper.l2_id, computed.commitment
            )));
        }
        if self.wrapper.has_rehearsal_sequencer_key() && !self.is_rehearsal() {
            return Err(GenesisError::V6Refused(
                "a launch genesis (non-rehearsal committee₀) carries the in-code rehearsal sequencer key".into(),
            ));
        }
        if let Some(want) = expected_hex {
            let got = self.hash_hex();
            if !got.eq_ignore_ascii_case(want) {
                return Err(GenesisError::WrongGenesisHash { got, want: want.to_string() });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🔒 The V6 rehearsal genesis, from the named `genesis init --t2` runs ×2
    /// (byte-identical files; lab #785 F5-3c, re-pinned in F5-4a over the
    /// asset-0 genesis registry, finding F-A). The V5 rehearsal genesis
    /// (`83776614…`) and T1 (`740ba41c…`) keep their own pins in `genesis.rs`.
    #[test]
    fn the_v6_rehearsal_genesis_is_pinned() {
        let a = GenesisFileV6::new_rehearsal();
        assert_eq!(a, GenesisFileV6::new_rehearsal(), "deterministic");
        assert_eq!(a.hash_hex(), "68594df44b53151dd5bccfc23832c5a527831f717784d16124640b29f84d0093");
        assert_eq!(
            a.wrapper.digest_hex(),
            "7567956821dce68d5f1b4021fb18290c57edae0732bb0ee2c5df7445c3e31224"
        );
        assert_eq!(
            hex_encode(&crate::revision::revision_digest_v6(
                crate::release::REVISION_V1_0.id,
                crate::release::REVISION_V1_0.frozen_digest_hex,
                &a.wrapper,
            )),
            "89e36dac55fcae4d1e4f3975e74df689ae4984b997272f3f65b44c4d77e2ffe4"
        );
        assert_eq!(a.base.format_version, 10);
        assert_eq!(a.forms(), (GenesisForm::V5, BodySections::V6));
        a.verify_startup(Some(&a.hash_hex())).expect("the rehearsal genesis verifies");
        let back = GenesisFileV6::from_bytes(&a.to_bytes()).unwrap();
        assert_eq!(back, a);
        assert_eq!(back.hash(), a.hash());
    }

    /// F-A (lab #785 F5-4a): the V6 genesis registry is exactly the Annulet
    /// genesis's pinned asset-0 record — Cloaked, no issuer, both roots 0 —
    /// and its root is the node registry tree's over it.
    #[test]
    fn the_v6_genesis_registry_is_asset_zeros_pinned_leaf() {
        let reg = v6_genesis_registry();
        assert_eq!(reg, vec![crate::annulet_genesis::RegistryLeafRecord::asset_zero().leaf()]);
        assert_eq!(reg[0].mode, qlab_air::l2::MODE_CLOAKED, "shape S admits only a Cloaked leaf");
        let root = v6_genesis_registry_root();
        assert_ne!(root, [0; 4]);
        assert_ne!(root, qlab_cbserver::registry::RegistryTree::from_leaves(&[]).unwrap().root(), "not the empty registry");
    }

    /// Lab #785 F5-4a (ruling condition (a)): the pinned surface, copied
    /// from qlab-bench's native model, is the value `qlab_wrapper`'s port
    /// computes for the rehearsal `l2_id` over the V6 genesis registry.
    #[test]
    fn the_rehearsal_genesis_surface_is_the_ported_one() {
        use qlab_wrapper::genesis::genesis_surface;
        assert_eq!(genesis_surface(REHEARSAL_L2_ID, &v6_genesis_registry_root()).commitment, REHEARSAL_GENESIS_SURFACE);
    }

    /// The lanes are the wrapper and L2 crates' own configs, not copies.
    #[test]
    fn the_wrapper_lanes_are_the_crates_configs() {
        assert_eq!(L2_LANE_V1, qlab_l2::L2_CFG.label());
        assert_eq!(WRAPPER_LANE_V1, qlab_wrapper::config::W_V1_CFG.label());
    }

    /// V6 bytes dispatch to V6, and the L1 loader refuses them by name rather
    /// than decoding the base and ignoring the wrapper section.
    #[test]
    fn a_v6_file_is_never_read_as_its_l1_base() {
        let bytes = GenesisFileV6::new_rehearsal().to_bytes();
        assert!(matches!(
            crate::annulet_genesis::load_any(&bytes).unwrap(),
            crate::annulet_genesis::AnyGenesis::V6(_)
        ));
        assert!(matches!(GenesisFile::from_bytes(&bytes), Err(GenesisError::V6Refused(_))));
        let t1 = GenesisFile::new_devnet_t0().to_bytes();
        assert!(matches!(GenesisFileV6::from_bytes(&t1), Err(GenesisError::NotV6Genesis { got: Some(8) })));
    }

    /// Review R3 on PR #794: a V6 file is exactly its canonical bytes — a
    /// trailing byte and a truncation are both refused.
    #[test]
    fn a_v6_file_with_trailing_or_missing_bytes_is_refused() {
        let bytes = GenesisFileV6::new_rehearsal().to_bytes();
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(GenesisFileV6::from_bytes(&trailing), Err(GenesisError::Decode(_))));
        assert!(matches!(GenesisFileV6::from_bytes(&bytes[..bytes.len() - 1]), Err(GenesisError::Decode(_))));
        assert!(GenesisFileV6::from_bytes(&bytes).is_ok());
    }

    /// Every v1 constant is checked: a genesis naming another lane, K_exit,
    /// spacing or record version is not a net this binary runs.
    #[test]
    fn a_genesis_off_the_v1_constants_is_refused() {
        let base = GenesisFileV6::new_rehearsal();
        let edits: [fn(&mut WrapperParams); 5] = [
            |w| w.l2_lane = "b4/q43/g22/fp16/a16".into(),
            |w| w.wrapper_lane = "b2/q86/g22/fp16/a16".into(),
            |w| w.k_exit = 9,
            |w| w.wrapper_spacing_blocks = 47,
            |w| w.finality_record_version = 2,
        ];
        for edit in edits {
            let mut g = base.clone();
            edit(&mut g.wrapper);
            assert!(matches!(g.verify_startup(None), Err(GenesisError::V6Refused(_))));
        }
        let mut bad_key = base.clone();
        bad_key.wrapper.sequencer_key.pop();
        assert!(matches!(bad_key.verify_startup(None), Err(GenesisError::V6Refused(_))));
    }

    /// C2 (lab #785 F5-4b): a V6 genesis whose pinned surface is not the
    /// empty L2 state's for its `l2_id` is refused at startup — a flipped
    /// lane, and an `l2_id` changed without its surface.
    #[test]
    fn a_v6_genesis_with_the_wrong_genesis_surface_is_refused() {
        let base = GenesisFileV6::new_rehearsal();
        assert!(base.verify_startup(None).is_ok());
        let mut flipped = base.clone();
        flipped.wrapper.genesis_surface[0] ^= 1;
        assert!(matches!(flipped.verify_startup(None), Err(GenesisError::V6Refused(m)) if m.contains("genesis_surface")));
        let mut other_id = base.clone();
        other_id.wrapper.l2_id = 2;
        assert!(matches!(other_id.verify_startup(None), Err(GenesisError::V6Refused(m)) if m.contains("genesis_surface")));
        let mut both = base;
        both.wrapper.l2_id = 2;
        both.wrapper.genesis_surface = qlab_wrapper::genesis::genesis_surface(2, &qlab_wrapper::genesis::empty_registry_root()).commitment;
        assert!(both.verify_startup(None).is_ok(), "a consistent pair passes");
    }

    /// The rehearsal sequencer key is refused in any genesis whose committee₀
    /// is not the rehearsal committee — and a launch key passes.
    #[test]
    fn the_rehearsal_sequencer_key_is_refused_in_a_launch_genesis() {
        let seeds: Vec<[u8; 32]> = (0..pd::FROZEN_COMMITTEE_SIZE).map(|i| [i as u8 + 0x40; 32]).collect();
        let v5 = GenesisFile::new_t2_with_committee_seeds(4096, &seeds);
        let launch_key = Validator::from_seed(0, [0x77; 32]).verifying_key().encode().to_vec();
        let ok = GenesisFileV6::remint_from_v5(&v5, &v5.hash_hex(), launch_key.clone(), REHEARSAL_L2_ID, REHEARSAL_GENESIS_SURFACE)
            .expect("a V5 launch genesis re-mints into V6 with a ceremony key");
        assert!(!ok.is_rehearsal());
        assert_eq!(ok.base.committee_keys, v5.committee_keys, "committee₀ carried");
        assert_eq!(ok.base.genesis_difficulty, 4096, "difficulty carried");
        assert_eq!(ok.base.network, v5.network);
        assert_eq!(ok.base.format_version, 10);
        let refused = GenesisFileV6::remint_from_v5(
            &v5,
            &v5.hash_hex(),
            rehearsal_sequencer_key(),
            REHEARSAL_L2_ID,
            REHEARSAL_GENESIS_SURFACE,
        );
        assert!(matches!(refused, Err(GenesisError::V6Refused(_))));
        // The input is identified by hash and must be the V5 T2 format.
        assert!(GenesisFileV6::remint_from_v5(&v5, &"00".repeat(32), launch_key.clone(), 1, REHEARSAL_GENESIS_SURFACE).is_err());
        let t1 = GenesisFile::new_devnet_t0();
        assert!(GenesisFileV6::remint_from_v5(&t1, &t1.hash_hex(), launch_key, 1, REHEARSAL_GENESIS_SURFACE).is_err());
    }

    /// committee₀ is bound to the genesis by its hash (review M5 on PR #791):
    /// a V6 genesis carrying any other committee is a different genesis, and
    /// a node pinned to the original refuses it.
    #[test]
    fn a_v6_genesis_with_a_different_committee_is_refused_under_the_pin() {
        let g = GenesisFileV6::new_rehearsal();
        let pin = g.hash_hex();
        let mut swapped = g.clone();
        swapped.base.committee_keys[3] = Validator::from_seed(3, [0x33; 32]).verifying_key().encode().to_vec();
        // A swapped committee is no longer the rehearsal committee, so the
        // rehearsal sequencer key refuses it first, by name…
        assert!(
            matches!(swapped.verify_startup(Some(&pin)), Err(GenesisError::V6Refused(ref m)) if m.contains("rehearsal sequencer key")),
            "{:?}",
            swapped.verify_startup(Some(&pin))
        );
        // …and with a launch sequencer key the pin is what refuses it.
        swapped.wrapper.sequencer_key = Validator::from_seed(0, [0x44; 32]).verifying_key().encode().to_vec();
        assert!(matches!(swapped.verify_startup(Some(&pin)), Err(GenesisError::WrongGenesisHash { .. })));
        assert!(swapped.verify_startup(None).is_ok(), "only the pin refuses it");
        // And the committee a node takes is the file's, key for key.
        let c = g.committee().unwrap();
        for (i, enc) in g.base.committee_keys.iter().enumerate() {
            assert_eq!(c.member(i).map(|k| k.encode().to_vec()).as_ref(), Some(enc), "member {i}");
        }
    }

    /// The V6 revision digest is new: it differs from the ordinary revision
    /// digest (so T1's and V5's rule domains cannot collide with a V6 one) and
    /// it moves with every wrapper parameter.
    #[test]
    fn the_v6_revision_digest_folds_the_wrapper_parameters() {
        let r = crate::release::REVISION_V1_0;
        let w = WrapperParams::rehearsal();
        let v6 = crate::revision::revision_digest_v6(r.id, r.frozen_digest_hex, &w);
        assert_ne!(v6, crate::revision::revision_digest(r.id, r.frozen_digest_hex));
        let mut other = w.clone();
        other.l2_id = 2;
        assert_ne!(v6, crate::revision::revision_digest_v6(r.id, r.frozen_digest_hex, &other));
    }
}
