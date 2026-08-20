//! Mine-template / block-submit RPC (lab #511, launch gate G4).
//!
//! Two additive routes on the discovery listener (pure route addition — no
//! `RPC_VERSION` bump, house rule at PR #315):
//!
//! - `GET /v1/mine/template` — the unground candidate [`NodeAdapter::assemble_block`]
//!   produces (the `mine_on_parent` assembly path without `mine_under`).
//! - `POST /v1/mine/block` — a completed header+body through
//!   [`P2pNode::announce_block_named`] (the own-mined ingest path, refusals named).
//!
//! Both are refused with the UNAVAILABLE token unless `template_serving = true`.
//! JSON, not a versioned binary wire: the pool already speaks hex + JSON, and
//! this surface is host-local (the pool talks to its own node).

use std::sync::mpsc;

use qlab_devnet::body::BlockBody;
use qlab_devnet::forms::GenesisForm;
use qlab_devnet::header::BlockHeader;
use qlab_p2p::adapter::AssembledCandidate;
use qlab_p2p::codec::{decode_header, decode_tx, encode_header, encode_tx};
use qlab_p2p::n1::IngestOutcome;
use serde::{Deserialize, Serialize};

use crate::genesis::{hex_decode, hex_encode};

/// `GET /v1/mine/template`.
pub const MINE_TEMPLATE_PATH: &str = "/v1/mine/template";
/// `POST /v1/mine/block`.
pub const MINE_BLOCK_PATH: &str = "/v1/mine/block";

/// Named refusal when the config gate is off.
pub const TEMPLATE_SERVING_DISABLED: &str = "unavailable: template-serving-disabled";

/// How long a mine-RPC handler waits for the run loop.
pub const MINE_VERDICT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// One `GET /v1/mine/template` handed to the run loop.
pub struct TemplateRequest {
    pub reply: mpsc::SyncSender<Result<MineTemplateWire, String>>,
}

/// One `POST /v1/mine/block` handed to the run loop (already decoded).
pub struct BlockSubmitRequest {
    pub header: BlockHeader,
    pub body: BlockBody,
    pub reply: mpsc::SyncSender<BlockSubmitOutcome>,
}

/// The run loop's verdict on a submitted block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockSubmitOutcome {
    Accepted { hash: [u8; 32] },
    Duplicate { hash: [u8; 32] },
    Orphan { hash: [u8; 32] },
    Refused { name: String },
    Unavailable { name: String },
}

/// JSON body of `GET /v1/mine/template`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MineTemplateWire {
    pub form: String,
    pub prev: String,
    pub height: u64,
    pub timestamp: u64,
    pub difficulty: u64,
    pub nonce: u64,
    pub tx_body_commitment: String,
    pub seed_hash: String,
    pub next_seed_hash: Option<String>,
    pub coinbase: u64,
    pub coinbase_rkm: String,
    pub txs: Vec<String>,
}

/// JSON body of `POST /v1/mine/block`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MineBlockWire {
    pub form: String,
    pub header: String,
    pub coinbase: u64,
    pub coinbase_rkm: String,
    pub txs: Vec<String>,
}

/// Channels the discovery server uses to reach the run loop.
#[derive(Clone)]
pub struct MineServing {
    pub enabled: bool,
    pub templates: mpsc::SyncSender<TemplateRequest>,
    pub blocks: mpsc::SyncSender<BlockSubmitRequest>,
}

impl MineTemplateWire {
    pub fn from_candidate(c: &AssembledCandidate) -> Self {
        Self {
            form: form_token(c.form),
            prev: hex_encode(&c.header.prev),
            height: c.header.height,
            timestamp: c.header.timestamp,
            difficulty: c.header.difficulty,
            nonce: c.header.nonce,
            tx_body_commitment: hex_encode(&c.header.tx_body_commitment),
            seed_hash: hex_encode(&c.seed_hash),
            next_seed_hash: c.next_seed_hash.map(|h| hex_encode(&h)),
            coinbase: c.body.coinbase,
            coinbase_rkm: rkm_hex(&c.body.coinbase_rkm),
            txs: c.body.txs.iter().map(|tx| hex_encode(&encode_tx(tx))).collect(),
        }
    }
}

impl MineBlockWire {
    pub fn decode(&self) -> Result<(GenesisForm, BlockHeader, BlockBody), String> {
        let form = parse_form(&self.form)?;
        let header_bytes = hex_decode(&self.header).ok_or_else(|| "header: bad hex".to_string())?;
        let header = decode_header(form, &header_bytes).map_err(|e| format!("header: {e:?}"))?;
        let coinbase_rkm = rkm_from_hex(&self.coinbase_rkm)?;
        let mut txs = Vec::with_capacity(self.txs.len());
        for (i, t) in self.txs.iter().enumerate() {
            let bytes = hex_decode(t).ok_or_else(|| format!("tx[{i}]: bad hex"))?;
            let tx = decode_tx(&bytes).map_err(|e| format!("tx[{i}]: {e:?}"))?;
            txs.push(tx);
        }
        Ok((
            form,
            header,
            BlockBody {
                txs,
                coinbase: self.coinbase,
                coinbase_rkm,
            },
        ))
    }
}

/// Map the own-mined ingest outcome onto the HTTP vocabulary.
pub fn outcome_from_ingest(form: GenesisForm, header: &BlockHeader, outcome: IngestOutcome) -> BlockSubmitOutcome {
    let hash = header.header_hash_for(form);
    match outcome {
        IngestOutcome::Accepted => BlockSubmitOutcome::Accepted { hash },
        IngestOutcome::Duplicate => BlockSubmitOutcome::Duplicate { hash },
        IngestOutcome::Orphan => BlockSubmitOutcome::Orphan { hash },
        IngestOutcome::Rejected(reason) => BlockSubmitOutcome::Refused {
            name: reason.to_string(),
        },
        IngestOutcome::Ignored(reason) => BlockSubmitOutcome::Unavailable {
            name: reason.to_string(),
        },
    }
}

pub fn render_block_outcome(o: &BlockSubmitOutcome) -> (u16, String) {
    match o {
        BlockSubmitOutcome::Accepted { hash } => (202, format!("accepted {}", hex_encode(hash))),
        BlockSubmitOutcome::Duplicate { hash } => (200, format!("duplicate {}", hex_encode(hash))),
        BlockSubmitOutcome::Orphan { hash } => {
            (400, format!("refused: orphan {}", hex_encode(hash)))
        }
        BlockSubmitOutcome::Refused { name } => (400, format!("refused: {name}")),
        BlockSubmitOutcome::Unavailable { name } => (503, format!("unavailable: {name}")),
    }
}

pub fn form_token(form: GenesisForm) -> String {
    match form {
        GenesisForm::V4 => "v4".into(),
        GenesisForm::V5 => "v5".into(),
    }
}

pub fn parse_form(s: &str) -> Result<GenesisForm, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "v4" | "4" => Ok(GenesisForm::V4),
        "v5" | "5" => Ok(GenesisForm::V5),
        other => Err(format!("unknown genesis form `{other}` (want v4 or v5)")),
    }
}

pub fn rkm_hex(rkm: &[u64; 4]) -> String {
    let mut bytes = [0u8; 32];
    for (i, lane) in rkm.iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&lane.to_le_bytes());
    }
    hex_encode(&bytes)
}

pub fn rkm_from_hex(s: &str) -> Result<[u64; 4], String> {
    let bytes = hex_decode(s).ok_or_else(|| "coinbase_rkm: bad hex".to_string())?;
    if bytes.len() != 32 {
        return Err(format!(
            "coinbase_rkm: decoded {} bytes, want 32",
            bytes.len()
        ));
    }
    let mut lanes = [0u64; 4];
    for (i, lane) in lanes.iter_mut().enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        *lane = u64::from_le_bytes(buf);
    }
    Ok(lanes)
}

/// Header preimage hex — what POST carries as `header`.
pub fn header_hex(form: GenesisForm, header: &BlockHeader) -> String {
    hex_encode(&encode_header(form, header))
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_devnet::header::{AggregateProofSlot, EpochSupplyAttestation};

    fn sample_header() -> BlockHeader {
        BlockHeader {
            prev: [0x11; 32],
            height: 1,
            timestamp: 75,
            difficulty: 256,
            nonce: 0,
            tx_body_commitment: [0x22; 32],
            aggregate_proof: AggregateProofSlot,
            epoch_supply_attestation: EpochSupplyAttestation,
        }
    }

    #[test]
    fn block_wire_round_trips_a_coinbase_only_v5_body() {
        let header = sample_header();
        let body = BlockBody {
            txs: Vec::new(),
            coinbase: 5_000_000_000,
            coinbase_rkm: [1, 2, 3, 4],
        };
        let wire = MineBlockWire {
            form: "v5".into(),
            header: header_hex(GenesisForm::V5, &header),
            coinbase: body.coinbase,
            coinbase_rkm: rkm_hex(&body.coinbase_rkm),
            txs: vec![],
        };
        let json = serde_json::to_string(&wire).unwrap();
        let back: MineBlockWire = serde_json::from_str(&json).unwrap();
        let (form, h, b) = back.decode().unwrap();
        assert_eq!(form, GenesisForm::V5);
        assert_eq!(h, header);
        assert_eq!(b.coinbase, body.coinbase);
        assert_eq!(b.coinbase_rkm, body.coinbase_rkm);
        assert!(b.txs.is_empty());
    }

    #[test]
    fn rkm_hex_is_lane_major_le() {
        let hex = rkm_hex(&[1, 2, 3, 4]);
        assert_eq!(hex, "0100000000000000020000000000000003000000000000000400000000000000");
        assert_eq!(rkm_from_hex(&hex).unwrap(), [1, 2, 3, 4]);
    }
}
