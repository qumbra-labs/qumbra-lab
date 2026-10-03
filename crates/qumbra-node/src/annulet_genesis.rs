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
//!   is how every L1-only loader (explorer, faucet, mine) refuses an Annulet
//!   genesis. `qumbra-node run` loads through [`load_any`] since B2b (lab
//!   #708) and runs the sequencer net;
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
//!
//! **Lab #850 (AD1) moved the file type and its reads to
//! `qlab_node::annulet_genesis`** (re-exported below, so every path still
//! resolves), so a wallet can decode the genesis bytes it verifies. What stays
//! here is the node's: [`load_any`], the sequencer key file, and the fixture
//! and devnet constructors behind [`AnnuletGenesisBuild`].

use serde::{Deserialize, Serialize};

use qlab_devnet::forms::{GenesisForm, ANNULET_GENESIS_FORMAT_VERSION};

use crate::genesis::{GenesisError, GenesisFile};

/// The file type and its reads live in `qlab-node` since lab #850 (AD1), so a
/// wallet can decode the genesis bytes it verifies; every item is re-exported
/// here, so no caller's path changed.
pub use qlab_node::annulet_genesis::{
    h32, leading_format_version, registry_leaves, registry_root_of, AnnuletGenesisError, AnnuletGenesisFile,
    AnnuletGenesisHeader, AnnuletParams, GenesisNoteRecord, RegistryLeafRecord,
};

impl From<AnnuletGenesisError> for GenesisError {
    fn from(e: AnnuletGenesisError) -> Self {
        match e {
            AnnuletGenesisError::NotAnnuletGenesis { got } => GenesisError::NotAnnuletGenesis { got },
            AnnuletGenesisError::Decode(s) => GenesisError::Decode(s),
            AnnuletGenesisError::BadAnnulet(why) => GenesisError::BadAnnulet(why),
            AnnuletGenesisError::WrongGenesisHash { got, want } => GenesisError::WrongGenesisHash { got, want },
        }
    }
}

/// The sequencer key file's name in a node's data dir (lab #708 Q6): its
/// presence makes the node the **producer**; without it the node follows.
/// Never config or env inline — the committee-key convention.
pub const SEQUENCER_KEY_FILE: &str = "sequencer.key";

/// The sequencer signing-key file (TOML, like the committee `KeyFile`): the
/// 32-byte ML-DSA seed, hex-encoded. Read only by the node binary at start;
/// `run` checks the derived key against the genesis `sequencer_key` and
/// refuses a mismatch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencerKeyFile {
    pub seed_hex: String,
    #[serde(default)]
    pub note: String,
}

impl SequencerKeyFile {
    /// The seed bytes.
    pub fn seed(&self) -> Result<[u8; 32], GenesisError> {
        let bytes = crate::genesis::hex_decode(&self.seed_hex).ok_or(GenesisError::BadHex)?;
        bytes.try_into().map_err(|_| GenesisError::BadSeedLen)
    }

    /// Parse from TOML.
    pub fn from_toml(text: &str) -> Result<Self, GenesisError> {
        toml::from_str(text).map_err(|e| GenesisError::Parse(e.to_string()))
    }

    /// Serialize to TOML.
    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).expect("SequencerKeyFile is always TOML-serializable")
    }
}

/// Either kind of genesis file, as [`load_any`] returns it.
#[derive(Debug)]
pub enum AnyGenesis {
    L1(Box<GenesisFile>),
    /// Lab #785 F5-3c: genesis format 10.
    V6(Box<crate::genesis_v6::GenesisFileV6>),
    Annulet(Box<AnnuletGenesisFile>),
}

/// Dispatch a genesis file by its leading `format_version` (Q2).
pub fn load_any(bytes: &[u8]) -> Result<AnyGenesis, GenesisError> {
    let got = leading_format_version(bytes).ok_or_else(|| GenesisError::Decode("genesis file shorter than its format version".into()))?;
    if crate::genesis::PRE_REMINT_FORMAT_VERSIONS.contains(&got) {
        return Err(GenesisError::PreRemintGenesis { got });
    }
    if got == qlab_devnet::forms::V6_GENESIS_FORMAT_VERSION {
        return Ok(AnyGenesis::V6(Box::new(crate::genesis_v6::GenesisFileV6::from_bytes(bytes)?)));
    }
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

/// The fixture and devnet genesis constructors (lab #850: the file type moved
/// to `qlab-node`; these stay with the node because the fixture's `fee_tier_r`
/// is `qlab-l2`'s placeholder, which `qlab-node` does not depend on). Bring the
/// trait into scope to call `AnnuletGenesisFile::fixture()` / `::devnet()`.
pub trait AnnuletGenesisBuild: Sized {
    /// **The B1 fixture** (see the impl).
    fn fixture() -> Self;
    /// **The Annulet devnet genesis** (see the impl).
    fn devnet() -> Self;
}

impl AnnuletGenesisBuild for AnnuletGenesisFile {
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
    fn fixture() -> Self {
        let params = AnnuletParams {
            fee_tier_s: 1,
            fee_tier_p: 2,
            fee_tier_r: qlab_l2::FEE_TIER_R_PLACEHOLDER,
            slot_secs: 10,
            max_empty_slots: 6,
        };
        let isk = [0x15c7_0001, 0x15c7_0002, 0x15c7_0003, 0x15c7_0004];
        let asset7 = RegistryLeafRecord {
            asset: 7,
            issuer_key: qlab_air::l2p::issuer_key_of(&isk),
            mode: qlab_air::l2::MODE_HYBRID,
            // The fixture genesis keeps the seeded fixture tree: its hash and
            // the B-track goldens are pinned to it (lab #722: fixture only).
            freeze_root: qlab_air::l2p::FreezeTree::fixture_empty_for_tests().root,
            allow_root: [0; 4],
            flags: 0,
        };
        let faucet_rkm = [0xFA0C_E701, 0xFA0C_E702, 0xFA0C_E703, 0xFA0C_E704];
        let notes = (0..4u64)
            .map(|i| {
                let note = qlab_note::l2note::L2Note {
                    value: params.fee_tier_s,
                    asset: 0,
                    rkm: faucet_rkm,
                    rho: [0x6E0A_0000 + i, 1, 2, 3],
                    rseed: [0x5EED_0000 + i, 4, 5, 6],
                };
                // Lab #714 rule (i): a genesis payload is a GenesisPlaintext
                // (the note plaintext ‖ a zero tag) by construction.
                let payload = qlab_note::l2note::GenesisPlaintext::of(&note).0.to_vec();
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
    /// **The Annulet devnet genesis** (lab #716): asset 0 and `USDT-test`
    /// (Hybrid, dev issuer) registered; [`devnet::STOCK_NOTES`] fee-unit stock
    /// notes to the faucet and one `USDT-test` note to the dev holder, all as
    /// `GenesisPlaintext`s. Pinned by `annulet_devnet_genesis_hash_is_pinned`;
    /// the fixture stays as it is.
    fn devnet() -> Self {
        let params = AnnuletParams {
            fee_tier_s: devnet::FEE_TIER_S,
            fee_tier_p: devnet::FEE_TIER_P,
            fee_tier_r: devnet::FEE_TIER_R,
            slot_secs: 10,
            max_empty_slots: 6,
        };
        let usdt = devnet::usdt_test_leaf();
        let usdt = RegistryLeafRecord {
            asset: usdt.asset as u16,
            issuer_key: usdt.issuer_key,
            mode: usdt.mode,
            freeze_root: usdt.freeze_root,
            allow_root: usdt.allow_root,
            flags: usdt.flags,
        };
        let record = |n: &qlab_note::l2note::L2Note| GenesisNoteRecord {
            cm: h32(&n.commitment()),
            payload: qlab_note::l2note::GenesisPlaintext::of(n).0.to_vec(),
        };
        let mut notes: Vec<GenesisNoteRecord> =
            (0..devnet::STOCK_NOTES).map(|i| record(&devnet::stock_note(i))).collect();
        notes.push(record(&devnet::holder_usdt_note()));
        Self::assemble(
            "annulet-devnet",
            params,
            devnet::SEQUENCER_SEED,
            vec![RegistryLeafRecord::asset_zero(), usdt],
            notes,
            0,
        )
    }
}

/// **The Annulet devnet's dev keys and stock** (lab #716, B6) — **devnet
/// only**, labelled so exactly as the committee rehearsal keys are: every
/// secret here is public by construction, so a devnet built from them holds
/// nothing of value. The devnet genesis ([`AnnuletGenesisFile::devnet`])
/// mints from these, and the journey harness spends with them.
pub mod devnet {
    use qlab_air::l2::L2TxInput;
    use qlab_note::l2note::L2Note;

    /// The faucet's dev spend key and diversifier: its `rkm` receives the
    /// fee-unit stock.
    pub const FAUCET_SK: [u64; 4] = [0xFA0C_E7DE_0001, 0xFA0C_E7DE_0002, 0xFA0C_E7DE_0003, 0xFA0C_E7DE_0004];
    pub const FAUCET_D: [u64; 2] = [0xFA0C, 1];
    /// The dev holder of the genesis-minted `USDT-test` note.
    pub const HOLDER_SK: [u64; 4] = [0x401D_E7DE_0001, 0x401D_E7DE_0002, 0x401D_E7DE_0003, 0x401D_E7DE_0004];
    pub const HOLDER_D: [u64; 2] = [0x401D, 1];
    /// `USDT-test`'s dev issuer secret.
    pub const USDT_ISSUER_ISK: [u64; 4] = [0x1557_7E57_0001, 0x1557_7E57_0002, 0x1557_7E57_0003, 0x1557_7E57_0004];
    /// `USDT-test`'s registry index.
    pub const USDT_TEST_ASSET: u64 = 1;
    /// The sequencer's dev seed.
    pub const SEQUENCER_SEED: [u8; 32] = [0xDE; 32];
    /// Fee-unit stock notes minted to the faucet, one grant each.
    pub const STOCK_NOTES: u64 = 16;
    /// The genesis-minted `USDT-test` balance of the dev holder.
    pub const HOLDER_USDT_VALUE: u64 = 1_000_000;
    /// The devnet fee tiers (fee-unit base units): S = 1, P = 2.
    pub const FEE_TIER_S: u64 = 1;
    pub const FEE_TIER_P: u64 = 2;
    /// Shape R's devnet tier (lab #728) — a labelled placeholder, set to one
    /// faucet grant ([`GRANT_VALUE`]) because R spends exactly **one** fee
    /// note: a registrant pays a registration with one grant. (The fixture
    /// genesis uses `qlab_l2::FEE_TIER_R_PLACEHOLDER` = 4; neither is the
    /// pilot's price.)
    pub const FEE_TIER_R: u64 = GRANT_VALUE;
    /// One grant pays exactly one shape-P fee; a stock note carries the grant
    /// plus the shape-S fee of the grant transaction that spends it whole —
    /// so the faucet needs no change tracking.
    pub const GRANT_VALUE: u64 = FEE_TIER_P;
    pub const STOCK_NOTE_VALUE: u64 = GRANT_VALUE + FEE_TIER_S;

    /// A key's receiving `rkm` (`H(nk ‖ D ‖ d)`, the circuit's derivation).
    pub fn rkm(sk: [u64; 4], d: [u64; 2]) -> [u64; 4] {
        qlab_air::l2p::derive_rkm_l2(&L2TxInput { sk, value: 0, asset: 0, rho: [0; 4], rseed: [0; 4], d })
    }

    /// `USDT-test`'s registry leaf: Hybrid, the dev issuer, redeem closed,
    /// and the **canonical** empty freeze tree (lab #722 — the seeded fixture
    /// tree it used before could not be rebuilt from a published list).
    pub fn usdt_test_leaf() -> qlab_air::l2::RegistryLeaf {
        qlab_air::l2::RegistryLeaf {
            asset: USDT_TEST_ASSET,
            issuer_key: qlab_air::l2p::issuer_key_of(&USDT_ISSUER_ISK),
            mode: qlab_air::l2::MODE_HYBRID,
            freeze_root: qlab_air::l2p::CanonicalFreezeTree::empty().root,
            allow_root: [0; 4],
            flags: 0,
        }
    }

    /// Stock note `i` (asset 0, [`STOCK_NOTE_VALUE`]) to the faucet.
    pub fn stock_note(i: u64) -> L2Note {
        L2Note {
            value: STOCK_NOTE_VALUE,
            asset: 0,
            rkm: rkm(FAUCET_SK, FAUCET_D),
            rho: [0x5700_C000 + i, 1, 2, 3],
            rseed: [0x5EED_5700 + i, 4, 5, 6],
        }
    }

    /// The dev holder's genesis-minted `USDT-test` note.
    pub fn holder_usdt_note() -> L2Note {
        L2Note {
            value: HOLDER_USDT_VALUE,
            asset: USDT_TEST_ASSET,
            rkm: rkm(HOLDER_SK, HOLDER_D),
            rho: [0x401D_0000, 1, 2, 3],
            rseed: [0x401D_5EED, 4, 5, 6],
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use qlab_air::l2::RegistryLeaf;
    use qlab_air::l2::REGISTRY_DEPTH;

    /// The consensus node hash, spelled independently of the registry tree
    /// for the dense reference fold below.
    fn node(l: &[u64; 4], r: &[u64; 4]) -> [u64; 4] {
        qlab_air::reference::merkle_node_state(l, r)[..4].try_into().expect("4 lanes")
    }

    /// The fixture's genesis hash — computed by the named
    /// `annulet_fixture_genesis` run, twice, byte-identical. **Re-pinned by
    /// lab #708 (Q5)**: the slot parameters joined `AnnuletParams`; the B1
    /// value was `c0257d67…b19a` (3,031 B file), then 3,047 B `a73f547d…ead2`.
    /// **Re-pinned by lab #728 (Q8)**: `fee_tier_r` joined `AnnuletParams`;
    /// now 3,055 B.
    const FIXTURE_GENESIS_HASH: &str = "85dd805d1ecd720de91b9af4a9ef394ae40e24afe80f102956f4201abc2b6cce";

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

    /// The devnet genesis is deterministic, verifies, pins its hash, and
    /// registers the harness's own `USDT-test` policy leaf (lab #716).
    #[test]
    fn annulet_devnet_genesis_hash_is_pinned() {
        let a = AnnuletGenesisFile::devnet();
        let b = AnnuletGenesisFile::devnet();
        assert_eq!(a.to_bytes(), b.to_bytes(), "deterministic");
        a.verify(Some(DEVNET_GENESIS_HASH)).expect("the devnet genesis verifies and pins itself");
        assert_eq!(a.hash_hex(), DEVNET_GENESIS_HASH);
        // Its registry leaf for USDT-test is the canonical one (lab #722).
        assert_eq!(a.registry_genesis[1].leaf(), devnet::usdt_test_leaf());
        assert_eq!(a.genesis_notes.len() as u64, devnet::STOCK_NOTES + 1);
    }

    /// The devnet genesis hash — from the named `annulet_devnet_genesis` run,
    /// twice, byte-identical (lab #716; re-pinned in lab #722 when USDT-test
    /// moved to the canonical freeze tree — it was `6f0978eb…f374`; re-pinned
    /// in lab #728 when `fee_tier_r` joined `AnnuletParams` — it was
    /// `831de12f…e9ef`, 5,230 B; now 5,238 B).
    const DEVNET_GENESIS_HASH: &str = "00c70e55c95e8f6519e956884bf6ffc56476fe1b3cd196983a46e1f4221d7e03";

    #[test]
    /// Also the byte-identity proof of lab #710's delegation: `registry_root_of`
    /// now runs `RegistryTree`, and the genesis header binds its root, so an
    /// unchanged pin is an unchanged root.
    fn annulet_fixture_genesis_hash_is_pinned_and_so_the_registry_tree_delegation_is_byte_identical() {
        let a = AnnuletGenesisFile::fixture();
        assert_eq!(a, AnnuletGenesisFile::fixture(), "the fixture is deterministic");
        assert_eq!(a.hash_hex(), FIXTURE_GENESIS_HASH);
        a.verify(Some(FIXTURE_GENESIS_HASH)).expect("pins itself");
    }

    #[test]
    fn load_any_dispatches_on_the_leading_format_version() {
        let an = AnnuletGenesisFile::fixture().to_bytes();
        assert!(matches!(load_any(&an), Ok(AnyGenesis::Annulet(_))));
        for l1 in [GenesisFile::new_devnet_t0(), GenesisFile::new_t2_v5()] {
            assert!(matches!(load_any(&l1.to_bytes()), Ok(AnyGenesis::L1(_))));
        }
        let mut junk = an.clone();
        // An unserved version no format bump will ever take (lab #747: the literal
        // 8 used here collided with batch 2's T1 format).
        const NEVER_A_FORMAT: u32 = u32::MAX;
        junk[..4].copy_from_slice(&NEVER_A_FORMAT.to_le_bytes());
        assert!(matches!(load_any(&junk), Err(GenesisError::WrongFormatVersion { got: NEVER_A_FORMAT, .. })));
        // The pre-re-mint (4 / 5) and batch-1 (6 / 7) T1 / T2 formats are refused by name.
        for v in crate::genesis::PRE_REMINT_FORMAT_VERSIONS {
            junk[..4].copy_from_slice(&v.to_le_bytes());
            assert!(matches!(load_any(&junk), Err(GenesisError::PreRemintGenesis { got }) if got == v), "v{v}");
        }
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
        // The batch-2 L1 files (T1 = 8, T2 = 9, lab #747) and the refused
        // earlier ones (4–7) are all named as not-Annulet by their own version;
        // the refusal by name itself lives in the L1 loader.
        // Read from the constructors' own fields, never literals (lab #747's
        // lesson: a literal version in a test goes stale at every format bump).
        for l1 in [GenesisFile::new_devnet_t0(), GenesisFile::new_t2_v5()] {
            let v = l1.format_version;
            assert!(matches!(
                AnnuletGenesisFile::from_bytes(&l1.to_bytes()),
                Err(AnnuletGenesisError::NotAnnuletGenesis { got: Some(g) }) if g == v
            ));
        }
        for v in crate::genesis::PRE_REMINT_FORMAT_VERSIONS {
            let mut old = GenesisFile::new_t2_v5();
            old.format_version = v;
            assert!(matches!(
                AnnuletGenesisFile::from_bytes(&old.to_bytes()),
                Err(AnnuletGenesisError::NotAnnuletGenesis { got: Some(g) }) if g == v
            ));
        }
    }

    #[test]
    fn verify_refuses_an_inconsistent_file_by_name() {
        let good = AnnuletGenesisFile::fixture();
        let mut bad_root = good.clone();
        bad_root.genesis_header.registry_root[0] ^= 1;
        assert!(matches!(bad_root.verify(None), Err(AnnuletGenesisError::BadAnnulet(m)) if m.contains("registry_root")));
        let mut bad_note = good.clone();
        bad_note.genesis_notes[2].cm[0] ^= 1;
        // Lab #714 rule (i) catches a note whose payload does not open to its cm.
        assert!(matches!(bad_note.verify(None), Err(AnnuletGenesisError::BadAnnulet(m)) if m.contains("GenesisPlaintext")));
        let mut tagged = good.clone();
        let last = tagged.genesis_notes[1].payload.len() - 1;
        tagged.genesis_notes[1].payload[last] = 1;
        assert!(matches!(tagged.verify(None), Err(AnnuletGenesisError::BadAnnulet(m)) if m.contains("GenesisPlaintext")));
        let mut bad_body = good.clone();
        bad_body.genesis_header.body_commitment[0] ^= 1;
        assert!(matches!(bad_body.verify(None), Err(AnnuletGenesisError::BadAnnulet(m)) if m.contains("body_commitment")));
        let mut short = good.clone();
        short.genesis_notes[0].payload.pop();
        assert!(matches!(short.verify(None), Err(AnnuletGenesisError::BadAnnulet(m)) if m.contains("128")));
        let mut no_zero = good.clone();
        no_zero.registry_genesis.remove(0);
        assert!(matches!(no_zero.verify(None), Err(AnnuletGenesisError::BadAnnulet(m)) if m.contains("asset 0")));
        let mut key = good.clone();
        key.sequencer_key.truncate(10);
        assert!(matches!(key.verify(None), Err(AnnuletGenesisError::BadAnnulet(m)) if m.contains("sequencer")));
        assert!(matches!(good.verify(Some("00")), Err(AnnuletGenesisError::WrongGenesisHash { .. })));
    }

    /// Lab #728 Q6 — **a demonstration, not a refusal test, because the file
    /// the question imagines cannot be written.** A genesis registry record
    /// has no slot field: it carries its asset lane, and the tree places it at
    /// that slot (`RegistryTree::from_leaves`). So "asset 9's leaf at slot 10"
    /// is not expressible in the format; the nearest attempts are a record
    /// repeated or out of order, which `verify` refuses by name. Asserted:
    /// every record of the fixture plus an added asset 9 sits at its own slot,
    /// slot 10 stays empty, the tree's invariant holds, and a duplicate asset
    /// is refused.
    #[test]
    fn a_genesis_registry_record_can_only_sit_at_its_own_slot() {
        let mut records = AnnuletGenesisFile::fixture().registry_genesis;
        let mut nine = RegistryLeaf::cloaked(9);
        nine.mode = 1;
        nine.issuer_key = [9, 9, 9, 9];
        records.push(RegistryLeafRecord::of(&nine));
        records.sort_by_key(|r| r.asset);
        let tree = qlab_cbserver::registry::RegistryTree::from_leaves(&registry_leaves(&records)).unwrap();
        for r in &records {
            assert_eq!(tree.leaf(r.asset), Some(&r.leaf()), "asset {} sits at slot {}", r.asset, r.asset);
        }
        assert_eq!(tree.leaf(10), None, "slot 10 is empty: nothing can name it for asset 9");
        assert_eq!(tree.leaves().count(), records.len());
        assert_eq!(tree.check_invariant(), Ok(()));
        // The nearest expressible attempt: asset 9 twice.
        let mut file = AnnuletGenesisFile::fixture();
        file.registry_genesis = records.clone();
        file.registry_genesis.push(RegistryLeafRecord::of(&nine));
        assert!(matches!(file.verify(None), Err(AnnuletGenesisError::BadAnnulet(m)) if m.contains("strictly ascending")));
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
        let t2 = GenesisFile::new_t2_v5();
        assert_eq!(GenesisFile::from_bytes(&t2.to_bytes()).unwrap().hash(), t2.hash());
    }
}
