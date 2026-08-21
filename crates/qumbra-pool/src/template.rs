//! Form-keyed template source.
//!
//! The selection point is [`qlab_devnet::forms::ChainRules::form`] — the
//! genesis identity — never a free-floating config switch (H1). A v5
//! template produces the 97-byte stratum blob; a v4 template produces
//! the 98-byte preimage and the pool refuses stock-xmrig login (#356
//! UNCLEAN stands). Stage 2's N=1 fallback is accounting testability
//! on v4, not "stock xmrig earns shares on T1".

use qlab_devnet::body::CoinbasePayee;
use qlab_devnet::forms::GenesisForm;
use qlab_devnet::header::{
    AggregateProofSlot, BlockHeader, EpochSupplyAttestation, HEADER_PREIMAGE_LEN_V4,
    HEADER_PREIMAGE_LEN_V5,
};
use qlab_pow::KeyBlockSchedule;
use qlab_stratum::blob::{set_extranonce, BlobError};

use crate::hexutil::{self, HexError};

/// A tip-derived job template. The header's `nonce` is ignored — the
/// pool writes the per-connection extra-nonce into the blob after
/// serializing a zero-nonce preimage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Template {
    /// The form this template was built under. Arrives with the
    /// template (the node's genesis identity), not as an operator pick.
    pub form: GenesisForm,
    pub header: BlockHeader,
    /// RandomX key-block hash at `KeyBlockSchedule::seed_height(height)`.
    pub seed_hash: [u8; 32],
    /// Next key-block hash, when the source has one. The pool decides
    /// whether to put it on the job (preload window).
    pub next_seed_hash: Option<[u8; 32]>,
    /// Assembled body from the node (lab #511). Static `[template]` files
    /// leave this `None` and a block-class share is logged, not POSTed.
    pub body: Option<TemplateBody>,
}

/// The body a completed header must carry. Opaque tx wires so this crate
/// does not take `qlab-p2p`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateBody {
    pub coinbase_payees: Vec<CoinbasePayee>,
    pub txs: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateError {
    Blob(String),
    Hex(HexError),
    UnknownForm(String),
}

impl std::fmt::Display for TemplateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TemplateError::Blob(s) => write!(f, "template blob: {s}"),
            TemplateError::Hex(e) => write!(f, "template hex: {e}"),
            TemplateError::UnknownForm(s) => {
                write!(f, "unknown genesis form `{s}` (want v4 or v5)")
            }
        }
    }
}

impl std::error::Error for TemplateError {}

impl From<BlobError> for TemplateError {
    fn from(e: BlobError) -> Self {
        TemplateError::Blob(e.to_string())
    }
}

impl From<HexError> for TemplateError {
    fn from(e: HexError) -> Self {
        TemplateError::Hex(e)
    }
}

impl Template {
    /// Stock-xmrig is a v5-only product claim (#356 UNCLEAN on v4).
    pub fn serves_stock_xmrig(&self) -> bool {
        self.form == GenesisForm::V5
    }

    /// Serialize the hashing blob with `extra` written into the v5
    /// extra-nonce window. On v4 there is no such window — the preimage
    /// is returned as-is (and the endpoint must have already refused
    /// stratum login).
    pub fn blob_with_extranonce(&self, extra: [u8; 4]) -> Result<Vec<u8>, TemplateError> {
        let mut header = self.header;
        header.nonce = 0;
        match self.form {
            GenesisForm::V5 => {
                let mut blob = header.preimage_for(GenesisForm::V5);
                debug_assert_eq!(blob.len(), HEADER_PREIMAGE_LEN_V5);
                set_extranonce(&mut blob, &extra)?;
                Ok(blob)
            }
            GenesisForm::V4 => {
                let blob = header.preimage_for(GenesisForm::V4);
                debug_assert_eq!(blob.len(), HEADER_PREIMAGE_LEN_V4);
                Ok(blob)
            }
        }
    }
}

/// Where jobs come from. The pool reads [`Self::current`] on login and
/// on tip-driven re-issue. Implementors key off `ChainRules.form` at
/// construction; they do not grow a form switch later.
pub trait TemplateSource: Send {
    fn current(&self) -> Template;
}

/// In-memory source. Tests inject it; the binary loads one from the
/// config's `[template]` table. A later node-RPC source implements the
/// same trait and does not change the endpoint.
pub struct HeldTemplateSource {
    current: Template,
}

impl HeldTemplateSource {
    pub fn new(template: Template) -> Self {
        Self { current: template }
    }

    pub fn replace(&mut self, template: Template) {
        self.current = template;
    }
}

impl TemplateSource for HeldTemplateSource {
    fn current(&self) -> Template {
        self.current.clone()
    }
}

/// In-process template built from `qlab_devnet` headers — genesis + one
/// child. No node, no RPC, no mining. Stage 3's "devnet template source".
pub struct DevnetTemplateSource {
    current: Template,
}

impl DevnetTemplateSource {
    /// A height-1 child of a v5 genesis. Seed is the genesis header hash
    /// (key-block at height 0).
    pub fn v5_tip(difficulty: u64) -> Self {
        Self::from_form(GenesisForm::V5, difficulty)
    }

    /// Same shape on v4 — used to prove login is refused by name.
    pub fn v4_tip(difficulty: u64) -> Self {
        Self::from_form(GenesisForm::V4, difficulty)
    }

    fn from_form(form: GenesisForm, difficulty: u64) -> Self {
        let genesis = BlockHeader::genesis_for(form, difficulty, 0);
        let tip =
            BlockHeader::child_of_for(form, &genesis, 75, difficulty, genesis.tx_body_commitment);
        Self {
            current: Template {
                form,
                header: tip,
                seed_hash: genesis.header_hash_for(form),
                next_seed_hash: None,
                body: None,
            },
        }
    }
}

impl TemplateSource for DevnetTemplateSource {
    fn current(&self) -> Template {
        self.current.clone()
    }
}

/// Preload window for `next_seed_hash`, in blocks. Equals Monero's lag
/// so a miner can start the dataset reload one lag before the rotation
/// (mapping doc §2.3 / §8). Pool policy, not a consensus field.
pub const NEXT_SEED_PRELOAD_BLOCKS: u64 = KeyBlockSchedule::MONERO_EPOCH_LAG;

/// Height of the next key-block rotation strictly after `height`, if
/// the schedule ever rotates.
pub fn next_rotation_height(height: u64, schedule: KeyBlockSchedule) -> Option<u64> {
    if schedule.epoch == 0 {
        return None;
    }
    let first = schedule.epoch + schedule.lag + 1;
    if height < first {
        return Some(first);
    }
    let current_seed = schedule.seed_height(height);
    Some(current_seed + schedule.epoch + schedule.lag + 1)
}

/// Whether a job at `height` should carry `next_seed_hash`.
pub fn next_seed_in_preload_window(height: u64, schedule: KeyBlockSchedule) -> bool {
    match next_rotation_height(height, schedule) {
        Some(rot) => rot.saturating_sub(height) <= NEXT_SEED_PRELOAD_BLOCKS,
        None => false,
    }
}

/// Parse a form token from a template file. This is a *fact about the
/// template* (which net built it), not an operator preference.
pub fn parse_form(s: &str) -> Result<GenesisForm, TemplateError> {
    match s.trim().to_ascii_lowercase().as_str() {
        "v4" | "4" => Ok(GenesisForm::V4),
        "v5" | "5" => Ok(GenesisForm::V5),
        other => Err(TemplateError::UnknownForm(other.to_string())),
    }
}

/// Build a [`BlockHeader`] from the hex fields a template file carries.
pub fn header_from_parts(
    prev: &str,
    height: u64,
    timestamp: u64,
    difficulty: u64,
    tx_body_commitment: &str,
) -> Result<BlockHeader, TemplateError> {
    Ok(BlockHeader {
        prev: hexutil::decode_exact(prev)?,
        height,
        timestamp,
        difficulty,
        nonce: 0,
        tx_body_commitment: hexutil::decode_exact(tx_body_commitment)?,
        aggregate_proof: AggregateProofSlot,
        epoch_supply_attestation: EpochSupplyAttestation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_stratum::blob::{extranonce_of, miner_nonce_of, V5_BLOB_LEN};

    fn sample_header(height: u64) -> BlockHeader {
        BlockHeader {
            prev: [0x11; 32],
            height,
            timestamp: 1_785_000_000,
            difficulty: 256,
            nonce: 0xDEAD_BEEF_CAFE_BABE, // must be ignored
            tx_body_commitment: [0x22; 32],
            aggregate_proof: AggregateProofSlot,
            epoch_supply_attestation: EpochSupplyAttestation,
        }
    }

    fn sample_template(form: GenesisForm, height: u64) -> Template {
        Template {
            form,
            header: sample_header(height),
            seed_hash: [0x33; 32],
            next_seed_hash: Some([0x44; 32]),
            body: None,
        }
    }

    #[test]
    fn v5_blob_is_preimage_for_v5_with_extranonce_written() {
        let t = sample_template(GenesisForm::V5, 100);
        let extra = [0x04, 0x03, 0x02, 0x01];
        let blob = t.blob_with_extranonce(extra).unwrap();
        assert_eq!(blob.len(), V5_BLOB_LEN);
        assert_eq!(blob.len(), HEADER_PREIMAGE_LEN_V5);
        assert_eq!(miner_nonce_of(&blob).unwrap(), [0, 0, 0, 0]);
        assert_eq!(extranonce_of(&blob).unwrap(), extra);
        // Template header nonce must not leak into the blob — the pool
        // owns the extra-nonce and the miner owns the grind window.
        let mut expected = sample_header(100);
        expected.nonce = u64::from_le_bytes([0, 0, 0, 0, 0x04, 0x03, 0x02, 0x01]);
        assert_eq!(blob, expected.preimage_for(GenesisForm::V5));
    }

    #[test]
    fn v4_blob_is_preimage_for_v4_and_does_not_claim_xmrig() {
        let t = sample_template(GenesisForm::V4, 100);
        assert!(!t.serves_stock_xmrig());
        let blob = t.blob_with_extranonce([1, 2, 3, 4]).unwrap();
        assert_eq!(blob.len(), HEADER_PREIMAGE_LEN_V4);
        let mut expected = sample_header(100);
        expected.nonce = 0;
        assert_eq!(blob, expected.preimage_for(GenesisForm::V4));
    }

    #[test]
    fn form_is_the_selector_same_header_two_blobs() {
        let v4 = sample_template(GenesisForm::V4, 7);
        let v5 = sample_template(GenesisForm::V5, 7);
        let b4 = v4.blob_with_extranonce([0; 4]).unwrap();
        let b5 = v5.blob_with_extranonce([0; 4]).unwrap();
        assert_ne!(b4.len(), b5.len());
        assert_ne!(b4, b5);
        assert!(v5.serves_stock_xmrig());
        assert!(!v4.serves_stock_xmrig());
    }

    #[test]
    fn next_rotation_and_preload_window() {
        let s = KeyBlockSchedule::default();
        let first = s.epoch + s.lag + 1; // 2113
        assert_eq!(next_rotation_height(0, s), Some(first));
        assert_eq!(next_rotation_height(first - 1, s), Some(first));
        assert_eq!(
            next_rotation_height(first, s),
            Some(2 * s.epoch + s.lag + 1)
        );
        assert!(!next_seed_in_preload_window(0, s));
        assert!(next_seed_in_preload_window(
            first - NEXT_SEED_PRELOAD_BLOCKS,
            s
        ));
        assert!(next_seed_in_preload_window(first - 1, s));
        assert!(!next_seed_in_preload_window(
            first - NEXT_SEED_PRELOAD_BLOCKS - 1,
            s
        ));
    }
}
