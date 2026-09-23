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
use qlab_devnet::body::{
    coinbase_payee_cap_v5_above, CoinbasePayee, TxEntry,
    COINBASE_PAYEE_CAP_V5_BOUNDARY_HEIGHT,
};
use qlab_devnet::hash::keccak256;
use qlab_devnet::header::{BlockHeader, Hash32};

use crate::codec::{decode_header, encode_header, encode_tx, header_wire_len, tx_id, DecodeError, Reader};
use qlab_devnet::forms::GenesisForm;

/// Project a list into the byte-frozen v4 announce pair.
fn single_payee_parts(payees: &[CoinbasePayee]) -> Option<(u64, [u64; 4])> {
    match payees {
        [] => Some((0, [0; 4])),
        [payee] => Some((payee.amount, payee.rkm)),
        _ => None,
    }
}
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
    /// The block body's coinbase payee list. V4 projects this to its frozen
    /// `(amount, rkm)` pair; V5 writes the already-shipped
    /// `count ‖ [rkm ‖ amount]×N` bytes.
    pub coinbase_payees: Vec<CoinbasePayee>,
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
    encode_announce_above(COINBASE_PAYEE_CAP_V5_BOUNDARY_HEIGHT, form, a)
}

/// [`encode_announce`] with the V5 payee-cap boundary injected for drills.
pub fn encode_announce_above(
    payee_boundary: Option<u64>,
    form: GenesisForm,
    a: &BlockAnnounce,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&encode_header(form, &a.header));
    out.extend_from_slice(&a.nonce.to_le_bytes());
    match form {
        // Locally-built input only (the decoder refuses peers by error).
        GenesisForm::Annulet => panic!(
            "no compact block announce on an Annulet net yet: lands with B5 (lab #706)"
        ),
        GenesisForm::V4 => {
            // The v4 wire, byte-frozen: coinbase total ‖ rkm lanes.
            let (coinbase, coinbase_rkm) = single_payee_parts(&a.coinbase_payees)
                .expect("v4 announce requires zero or one coinbase payee");
            out.extend_from_slice(&coinbase.to_le_bytes());
            for lane in &coinbase_rkm {
                out.extend_from_slice(&lane.to_le_bytes());
            }
        }
        GenesisForm::V5 => {
            // The v5 payee-list form (lab #470 stage 2): count ‖ [rkm ‖
            // amount]×N, mirroring the v5 body-preimage tail — the total is
            // Σ amounts and travels nowhere else on this wire either.
            let cap = coinbase_payee_cap_v5_above(payee_boundary, a.header.height);
            assert!(a.coinbase_payees.len() <= cap);
            out.push(a.coinbase_payees.len() as u8);
            for payee in &a.coinbase_payees {
                for lane in &payee.rkm {
                    out.extend_from_slice(&lane.to_le_bytes());
                }
                out.extend_from_slice(&payee.amount.to_le_bytes());
            }
        }
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
    decode_announce_above(COINBASE_PAYEE_CAP_V5_BOUNDARY_HEIGHT, form, buf)
}

/// [`decode_announce`] with the V5 payee-cap boundary injected for drills.
pub fn decode_announce_above(
    payee_boundary: Option<u64>,
    form: GenesisForm,
    buf: &[u8],
) -> Result<BlockAnnounce, DecodeError> {
    // Refused before reading a byte, so the refusal names the form rather
    // than whichever field the Annulet bytes happen to truncate first.
    match form {
        GenesisForm::V4 | GenesisForm::V5 => {}
        GenesisForm::Annulet => return Err(DecodeError::FormNotServed { form, owner: "B5" }),
    }
    let mut r = Reader::new(buf);
    let hdr_bytes = r.rest(header_wire_len(form), "announce.header")?;
    let header = decode_header(form, &hdr_bytes)?;
    let nonce = r.u64_le("announce.nonce")?;
    let coinbase_payees = match form {
        GenesisForm::Annulet => return Err(DecodeError::FormNotServed { form, owner: "B5" }),
        GenesisForm::V4 => {
            let coinbase = r.u64_le("announce.coinbase")?;
            let mut coinbase_rkm = [0u64; 4];
            for lane in coinbase_rkm.iter_mut() {
                *lane = r.u64_le("announce.coinbase_rkm")?;
            }
            match (coinbase, coinbase_rkm) {
                (0, rkm) if rkm == [0; 4] => Vec::new(),
                (amount, rkm) => vec![CoinbasePayee { rkm, amount }],
            }
        }
        GenesisForm::V5 => {
            let count = r.u8("announce.payee_count")? as usize;
            let cap = coinbase_payee_cap_v5_above(payee_boundary, header.height);
            if count > cap {
                return Err(DecodeError::TooManyCoinbasePayees {
                    got: count,
                    cap,
                });
            }
            let mut payees = Vec::with_capacity(count);
            for _ in 0..count {
                let mut rkm = [0u64; 4];
                for lane in rkm.iter_mut() {
                    *lane = r.u64_le("announce.payee_rkm")?;
                }
                let amount = r.u64_le("announce.payee_amount")?;
                payees.push(CoinbasePayee { rkm, amount });
            }
            payees
        }
    };
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
    Ok(BlockAnnounce { header, nonce, coinbase_payees, short_ids, prefilled })
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
            coinbase_payees: Vec::new(),
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
            coinbase_payees: Vec::new(),
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
            coinbase_payees: Vec::new(),
            short_ids: vec![short_id(nonce, &tx_id(&t1)), short_id(nonce, &tx_id(&t2))],
            prefilled: vec![],
        };
        // Mempool only has t1 → slot 1 (t2) is missing.
        match reconstruct(&a, &[t1]) {
            Reconstruct::Missing(m) => assert_eq!(m, vec![1]),
            Reconstruct::Complete(_) => panic!("expected missing"),
        }
    }
    // ── v5 payee-list announce (lab #470 stage 2) ───────────────────────────

    fn sample_announce() -> BlockAnnounce {
        BlockAnnounce {
            header: header(),
            nonce: 0xDEADBEEF,
            coinbase_payees: vec![CoinbasePayee {
                rkm: [11, 22, 33, 44],
                amount: 5_000_000_000,
            }],
            short_ids: vec![short_id(0xDEADBEEF, &tx_id(&tx(2)))],
            prefilled: vec![PrefilledTx { index: 0, tx: tx(1) }],
        }
    }

    #[test]
    fn v5_announce_round_trips_the_payee_list() {
        let mut a = sample_announce();
        let bytes = encode_announce(GenesisForm::V5, &a);
        let back = decode_announce(GenesisForm::V5, &bytes).unwrap();
        assert_eq!(back.coinbase_payees, a.coinbase_payees);
        assert_eq!(back.header, a.header);
        // The mint-nothing shape carries a 0 count and round-trips too.
        a.coinbase_payees.clear();
        let bytes = encode_announce(GenesisForm::V5, &a);
        let back = decode_announce(GenesisForm::V5, &bytes).unwrap();
        assert!(back.coinbase_payees.is_empty());
    }

    /// N > the height-keyed cap is refused BY NAME at decode.
    #[test]
    fn v5_announce_refuses_more_payees_than_the_cap_by_name() {
        let a = sample_announce();
        let good = encode_announce(GenesisForm::V5, &a);
        // Hand-forge a 2-payee announce: bump the count byte and splice in a
        // second (rkm ‖ amount) entry after the first.
        let count_pos = 97 + 8; // header ‖ nonce ‖ count
        assert_eq!(good[count_pos], 1, "fixture announce carries one payee");
        let entry_start = count_pos + 1;
        let entry_len = 32 + 8;
        let mut forged = Vec::new();
        forged.extend_from_slice(&good[..count_pos]);
        forged.push(2);
        forged.extend_from_slice(&good[entry_start..entry_start + entry_len]);
        forged.extend_from_slice(&good[entry_start..entry_start + entry_len]);
        forged.extend_from_slice(&good[entry_start + entry_len..]);
        assert!(matches!(
            decode_announce(GenesisForm::V5, &forged),
            Err(DecodeError::TooManyCoinbasePayees { got: 2, cap: 1 })
        ));
    }

    #[test]
    fn v5_announce_refuses_more_than_eight_above_the_boundary_by_name() {
        let a = sample_announce();
        let good = encode_announce_above(Some(0), GenesisForm::V5, &a);
        let count_pos = 97 + 8;
        let entry_start = count_pos + 1;
        let entry_len = 32 + 8;
        let mut forged = Vec::new();
        forged.extend_from_slice(&good[..count_pos]);
        forged.push(9);
        for _ in 0..9 {
            forged.extend_from_slice(&good[entry_start..entry_start + entry_len]);
        }
        forged.extend_from_slice(&good[entry_start + entry_len..]);
        assert!(matches!(
            decode_announce_above(Some(0), GenesisForm::V5, &forged),
            Err(DecodeError::TooManyCoinbasePayees { got: 9, cap: 8 })
        ));
    }

    #[test]
    fn v5_multi_payee_announce_round_trips_only_above_the_boundary() {
        let boundary = 7;
        let height = boundary + 1;
        let txs = vec![tx(1), tx(2)];
        let payees = vec![
            CoinbasePayee {
                rkm: [11, 22, 33, 44],
                amount: 456,
            },
            CoinbasePayee {
                rkm: [55, 66, 77, 88],
                amount: 123,
            },
        ];
        let body = qlab_devnet::body::BlockBody::new(txs.clone(), payees.clone());
        let header = BlockHeader {
            height,
            ..BlockHeader::child_of_for(
                GenesisForm::V5,
                &BlockHeader::genesis_for(GenesisForm::V5, 1000, 0),
                75,
                1000,
                body.commitment_v5_above(Some(boundary), height),
            )
        };
        let a = BlockAnnounce {
            header,
            nonce: 0,
            coinbase_payees: payees,
            short_ids: Vec::new(),
            prefilled: txs
                .into_iter()
                .enumerate()
                .map(|(index, tx)| PrefilledTx {
                    index: index as u32,
                    tx,
                })
                .collect(),
        };
        let bytes = encode_announce_above(Some(boundary), GenesisForm::V5, &a);
        let back = decode_announce_above(Some(boundary), GenesisForm::V5, &bytes)
            .expect("N=2 is valid above the boundary");
        assert_eq!(back.coinbase_payees, a.coinbase_payees);
        let Reconstruct::Complete(txs) = reconstruct(&back, &[]) else {
            panic!("all transactions were prefilled");
        };
        let rebuilt = qlab_devnet::body::BlockBody::new(txs, back.coinbase_payees);
        assert_eq!(
            rebuilt.commitment_v5_above(Some(boundary), height),
            back.header.tx_body_commitment,
            "decoded N-payee announce reconstructs exactly the announced body"
        );

        let mut pre_boundary = bytes;
        // V5 height occupies bytes 33..39 as u48 LE.
        pre_boundary[33..39].copy_from_slice(&boundary.to_le_bytes()[..6]);
        assert!(matches!(
            decode_announce_above(Some(boundary), GenesisForm::V5, &pre_boundary),
            Err(DecodeError::TooManyCoinbasePayees { got: 2, cap: 1 })
        ));
    }

}
