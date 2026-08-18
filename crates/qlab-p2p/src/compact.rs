//! Compact-block relay — the two distinct "compact block" objects, separated.
//!
//! **(1) protocol-spec §5 compact blocks** (note-discovery serving wire). Relayed
//! **verbatim** through the golden-locked `qlab_cbserver::codec` — same
//! `version(0x01)` lead byte, same LEB128 varints, same reject-trailing /
//! unknown-version / non-zero-clue. This is the literal "§5 framing" the issue
//! cites; [`encode_cmpct_relay`] / [`decode_cmpct_relay`] are thin pass-throughs
//! so there is exactly one implementation of that wire in the tree.
//!
//! **(2) consensus-and-network §7 block relay** (BIP-152-shape inter-node block
//! propagation: announce header + short transaction ids, peer reconstructs the
//! body from its mempool, requests only what it is missing). This wire is part of
//! §10's deferred "P2P message formats", so it is a `[devnet-placeholder]` shape
//! here — framed with the **same** §5-conformant LEB128 varints for consistency,
//! with §0 versioning carried by the outer [`crate::wire`] envelope.

use qlab_cbserver::codec::{decode_compact_response, encode_compact_response, CodecError};
use qlab_devnet::body::TxEntry;
use qlab_devnet::hash::keccak256;
use qlab_devnet::header::{BlockHeader, Hash32};

use crate::codec::{decode_header, encode_header, encode_tx, header_wire_len, tx_id, DecodeError, Reader};
use qlab_devnet::forms::GenesisForm;
use crate::varint::write_varint;

pub use qlab_cbserver::codec::{CompactBlock, CompactGroup};

// ==========================================================================
// (1) §5 compact-block relay — verbatim reuse of the ratified codec
// ==========================================================================

/// Encode one or more §5 compact blocks for relay — **exactly** the note-
/// discovery serving wire (`qlab_cbserver::codec::encode_compact_response`).
pub fn encode_cmpct_relay(blocks: &[CompactBlock]) -> Vec<u8> {
    encode_compact_response(blocks)
}

/// Decode a §5 compact-block relay payload — inherits the ratified codec's
/// reject-unknown-version / reject-non-zero-clue / reject-trailing guarantees.
pub fn decode_cmpct_relay(buf: &[u8]) -> Result<Vec<CompactBlock>, CodecError> {
    decode_compact_response(buf)
}

// ==========================================================================
// (2) §7 BIP-152-shape block relay — [devnet-placeholder]
// ==========================================================================

/// Short-transaction-id length (bytes). BIP-152 uses 6; we match it.
pub const SHORTID_LEN: usize = 6;

/// A short transaction id: `keccak256(nonce_le ‖ tx_id)[..6]`. The per-announce
/// `nonce` randomizes the mapping so an attacker cannot precompute collisions
/// across blocks (BIP-152's siphash-key role, with the consensus hash instead).
pub fn short_id(nonce: u64, txid: &Hash32) -> [u8; SHORTID_LEN] {
    let mut pre = Vec::with_capacity(8 + 32);
    pre.extend_from_slice(&nonce.to_le_bytes());
    pre.extend_from_slice(txid);
    let d = keccak256(&pre);
    let mut s = [0u8; SHORTID_LEN];
    s.copy_from_slice(&d[..SHORTID_LEN]);
    s
}

/// A transaction the announcer includes in full (e.g. the coinbase, or txs it
/// predicts the peer lacks).
#[derive(Clone)]
pub struct PrefilledTx {
    pub index: u32,
    pub tx: TxEntry,
}

/// A block announcement: the header, the salt nonce, the ordered short ids, and
/// any prefilled transactions.
#[derive(Clone)]
pub struct BlockAnnounce {
    pub header: BlockHeader,
    pub nonce: u64,
    /// The block body's coinbase emission counter (`BlockBody::coinbase`). Carried
    /// so a receiver can reconstruct the exact body (the coinbase is not a tx slot)
    /// and validate/fold it. §7 relay is `[devnet-placeholder]`, not a frozen wire.
    pub coinbase: u64,
    /// The block body's coinbase payout key (`BlockBody::coinbase_rkm`, issue
    /// #101) — 32 bytes, four little-endian lanes, immediately after `coinbase`.
    ///
    /// Carried for the same reason `coinbase` is: it is part of the body, it is
    /// not a tx slot, and without it the receiver reconstructs a *different* body
    /// whose commitment does not match the header — so every announced block
    /// would be rejected as a binding mismatch (#79) and, worse, its announcer
    /// penalised for a fault that is ours. **This is a wire break**: a pre-#101
    /// peer's announce is 32 bytes short and fails to decode.
    pub coinbase_rkm: [u64; 4],
    pub short_ids: Vec<[u8; SHORTID_LEN]>,
    pub prefilled: Vec<PrefilledTx>,
}

/// A request for the transactions a peer could not reconstruct, by index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetBlockTxn {
    pub block_hash: Hash32,
    pub indexes: Vec<u32>,
}

/// The requested transactions, in the requested order.
#[derive(Clone)]
pub struct BlockTxn {
    pub block_hash: Hash32,
    pub txs: Vec<TxEntry>,
}

// --- BlockAnnounce ---

/// Encode a `BlockAnnounce`.
pub fn encode_announce(form: GenesisForm, a: &BlockAnnounce) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&encode_header(form, &a.header));
    out.extend_from_slice(&a.nonce.to_le_bytes());
    out.extend_from_slice(&a.coinbase.to_le_bytes());
    for lane in &a.coinbase_rkm {
        out.extend_from_slice(&lane.to_le_bytes());
    }
    write_varint(&mut out, a.short_ids.len() as u64);
    for s in &a.short_ids {
        out.extend_from_slice(s);
    }
    write_varint(&mut out, a.prefilled.len() as u64);
    for pf in &a.prefilled {
        write_varint(&mut out, pf.index as u64);
        let tx_bytes = encode_tx(&pf.tx);
        write_varint(&mut out, tx_bytes.len() as u64);
        out.extend_from_slice(&tx_bytes);
    }
    out
}

/// Decode a `BlockAnnounce`.
pub fn decode_announce(form: GenesisForm, buf: &[u8]) -> Result<BlockAnnounce, DecodeError> {
    let mut r = Reader::new(buf);
    let hdr_bytes = r.rest(header_wire_len(form), "announce.header")?;
    let header = decode_header(form, &hdr_bytes)?;
    let nonce = r.u64_le("announce.nonce")?;
    let coinbase = r.u64_le("announce.coinbase")?;
    let mut coinbase_rkm = [0u64; 4];
    for lane in coinbase_rkm.iter_mut() {
        *lane = r.u64_le("announce.coinbase_rkm")?;
    }
    let n_short = r.varint()? as usize;
    let mut short_ids = Vec::with_capacity(n_short);
    for _ in 0..n_short {
        let s = r.rest(SHORTID_LEN, "announce.shortid")?;
        short_ids.push(s.try_into().unwrap());
    }
    let n_pf = r.varint()? as usize;
    let mut prefilled = Vec::with_capacity(n_pf);
    for _ in 0..n_pf {
        let index = r.varint()? as u32;
        let tx_len = r.varint()? as usize;
        let tx_bytes = r.rest(tx_len, "announce.prefilled.tx")?;
        prefilled.push(PrefilledTx { index, tx: crate::codec::decode_tx(&tx_bytes)? });
    }
    r.finish()?;
    Ok(BlockAnnounce { header, nonce, coinbase, coinbase_rkm, short_ids, prefilled })
}

// --- GetBlockTxn ---

/// Encode a `GetBlockTxn`.
pub fn encode_get_block_txn(g: &GetBlockTxn) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&g.block_hash);
    write_varint(&mut out, g.indexes.len() as u64);
    for i in &g.indexes {
        write_varint(&mut out, *i as u64);
    }
    out
}

/// Decode a `GetBlockTxn`.
pub fn decode_get_block_txn(buf: &[u8]) -> Result<GetBlockTxn, DecodeError> {
    let mut r = Reader::new(buf);
    let block_hash = r.hash32("gbt.block_hash")?;
    let n = r.varint()? as usize;
    let mut indexes = Vec::with_capacity(n);
    for _ in 0..n {
        indexes.push(r.varint()? as u32);
    }
    r.finish()?;
    Ok(GetBlockTxn { block_hash, indexes })
}

// --- BlockTxn ---

/// Encode a `BlockTxn`.
pub fn encode_block_txn(b: &BlockTxn) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&b.block_hash);
    write_varint(&mut out, b.txs.len() as u64);
    for tx in &b.txs {
        let tx_bytes = encode_tx(tx);
        write_varint(&mut out, tx_bytes.len() as u64);
        out.extend_from_slice(&tx_bytes);
    }
    out
}

/// Decode a `BlockTxn`.
pub fn decode_block_txn(buf: &[u8]) -> Result<BlockTxn, DecodeError> {
    let mut r = Reader::new(buf);
    let block_hash = r.hash32("bt.block_hash")?;
    let n = r.varint()? as usize;
    let mut txs = Vec::with_capacity(n);
    for _ in 0..n {
        let tx_len = r.varint()? as usize;
        let tx_bytes = r.rest(tx_len, "bt.tx")?;
        txs.push(crate::codec::decode_tx(&tx_bytes)?);
    }
    r.finish()?;
    Ok(BlockTxn { block_hash, txs })
}

// --- reconstruction ---

/// Outcome of trying to reconstruct a block body from a `BlockAnnounce` + a
/// candidate transaction set (the receiver's mempool).
#[derive(Clone)]
pub enum Reconstruct {
    /// Fully reconstructed: the ordered transactions.
    Complete(Vec<TxEntry>),
    /// Missing some slots — request them by index via [`GetBlockTxn`].
    Missing(Vec<u32>),
}

/// Attempt to reconstruct the ordered transaction list from an announcement and
/// the receiver's `candidates` (its mempool). Prefilled slots are used directly;
/// remaining slots are matched by short id. Returns [`Reconstruct::Missing`] with
/// the still-unknown indexes if any short id has no candidate.
pub fn reconstruct(a: &BlockAnnounce, candidates: &[TxEntry]) -> Reconstruct {
    let total = a.short_ids.len() + a.prefilled.len();
    let mut slots: Vec<Option<TxEntry>> = vec![None; total];

    // Place prefilled transactions.
    for pf in &a.prefilled {
        if let Some(slot) = slots.get_mut(pf.index as usize) {
            *slot = Some(pf.tx.clone());
        }
    }

    // Build a short-id → candidate map under this announce's nonce.
    let mut by_short: std::collections::HashMap<[u8; SHORTID_LEN], TxEntry> =
        std::collections::HashMap::new();
    for tx in candidates {
        by_short.insert(short_id(a.nonce, &tx_id(tx)), tx.clone());
    }

    // Fill the non-prefilled slots (in order) from short ids.
    let mut short_iter = a.short_ids.iter();
    for slot in slots.iter_mut() {
        if slot.is_some() {
            continue; // prefilled
        }
        match short_iter.next() {
            Some(sid) => *slot = by_short.get(sid).cloned(),
            None => break,
        }
    }

    let missing: Vec<u32> =
        slots.iter().enumerate().filter(|(_, s)| s.is_none()).map(|(i, _)| i as u32).collect();
    if missing.is_empty() {
        Reconstruct::Complete(slots.into_iter().map(|s| s.unwrap()).collect())
    } else {
        Reconstruct::Missing(missing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_devnet::body::TxPublic;
    use qlab_devnet::fees::ArityBucket;

    fn tx(seed: u8) -> TxEntry {
        TxEntry::with_placeholder_discovery(vec![seed; 16], TxPublic {
            anchor: [seed; 32],
            nullifiers: vec![[seed; 32]],
            commitments: vec![[seed.wrapping_add(1); 32]],
            bucket: ArityBucket::TwoByTwo,
            fee: 1_000_000,
            })
    }

    fn header() -> BlockHeader {
        let g = BlockHeader::genesis(1000, 0);
        BlockHeader::child_of(&g, 75, 1000, [1; 32])
    }

    #[test]
    fn s5_relay_is_byte_identical_to_cbserver() {
        // A minimal but real §5 compact block; the relay wire MUST equal the
        // note-discovery serving wire byte-for-byte (single source).
        let block = CompactBlock { height: 7, groups: vec![] };
        let relay = encode_cmpct_relay(std::slice::from_ref(&block));
        let native = encode_compact_response(std::slice::from_ref(&block));
        assert_eq!(relay, native);
        let back = decode_cmpct_relay(&relay).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].height, 7);
        // Leading byte is the §5 WIRE_VERSION (0x01).
        assert_eq!(relay[0], qlab_cbserver::WIRE_VERSION);
    }

    #[test]
    fn s5_relay_inherits_reject_unknown_version() {
        let block = CompactBlock { height: 1, groups: vec![] };
        let mut bytes = encode_cmpct_relay(std::slice::from_ref(&block));
        bytes[0] = 0x02; // bad version
        assert!(matches!(decode_cmpct_relay(&bytes), Err(CodecError::BadVersion { got: 2 })));
    }

    #[test]
    fn announce_round_trips() {
        let a = BlockAnnounce {
            header: header(),
            nonce: 0xDEADBEEF,
            coinbase: 0,
            coinbase_rkm: [0; 4],
            short_ids: vec![short_id(0xDEADBEEF, &tx_id(&tx(2))), short_id(0xDEADBEEF, &tx_id(&tx(3)))],
            prefilled: vec![PrefilledTx { index: 0, tx: tx(1) }],
        };
        let bytes = encode_announce(GenesisForm::V4, &a);
        let back = decode_announce(GenesisForm::V4, &bytes).unwrap();
        assert_eq!(back.header, a.header);
        assert_eq!(back.nonce, a.nonce);
        assert_eq!(back.short_ids, a.short_ids);
        assert_eq!(back.prefilled.len(), 1);
        assert_eq!(tx_id(&back.prefilled[0].tx), tx_id(&tx(1)));
    }

    #[test]
    fn get_and_block_txn_round_trip() {
        let g = GetBlockTxn { block_hash: [5; 32], indexes: vec![1, 3, 7] };
        assert_eq!(decode_get_block_txn(&encode_get_block_txn(&g)).unwrap(), g);

        let b = BlockTxn { block_hash: [5; 32], txs: vec![tx(1), tx(2)] };
        let back = decode_block_txn(&encode_block_txn(&b)).unwrap();
        assert_eq!(back.block_hash, b.block_hash);
        assert_eq!(back.txs.len(), 2);
        assert_eq!(tx_id(&back.txs[0]), tx_id(&tx(1)));
    }

    #[test]
    fn reconstruct_complete_when_mempool_has_all() {
        let nonce = 42;
        let coinbase = tx(0);
        let t1 = tx(1);
        let t2 = tx(2);
        let a = BlockAnnounce {
            header: header(),
            nonce,
            coinbase: 0,
            coinbase_rkm: [0; 4],
            // slots 1,2 are short ids; slot 0 is prefilled coinbase.
            short_ids: vec![short_id(nonce, &tx_id(&t1)), short_id(nonce, &tx_id(&t2))],
            prefilled: vec![PrefilledTx { index: 0, tx: coinbase.clone() }],
        };
        match reconstruct(&a, &[t2.clone(), t1.clone()]) {
            Reconstruct::Complete(txs) => {
                assert_eq!(txs.len(), 3);
                assert_eq!(tx_id(&txs[0]), tx_id(&coinbase));
                assert_eq!(tx_id(&txs[1]), tx_id(&t1));
                assert_eq!(tx_id(&txs[2]), tx_id(&t2));
            }
            Reconstruct::Missing(m) => panic!("expected complete, missing {m:?}"),
        }
    }

    #[test]
    fn reconstruct_reports_missing_slots() {
        let nonce = 7;
        let t1 = tx(1);
        let t2 = tx(2);
        let a = BlockAnnounce {
            header: header(),
            nonce,
            coinbase: 0,
            coinbase_rkm: [0; 4],
            short_ids: vec![short_id(nonce, &tx_id(&t1)), short_id(nonce, &tx_id(&t2))],
            prefilled: vec![],
        };
        // Mempool only has t1 → slot 1 (t2) is missing.
        match reconstruct(&a, &[t1]) {
            Reconstruct::Missing(m) => assert_eq!(m, vec![1]),
            Reconstruct::Complete(_) => panic!("expected missing"),
        }
    }
}
