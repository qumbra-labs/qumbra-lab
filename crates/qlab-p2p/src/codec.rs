//! Hand-rolled little-endian (de)serialization of the devnet consensus objects
//! that travel on the P2P wire. The devnet types carry **no serde** (the whole
//! consensus stack is hand-rolled LE), so this module owns their wire form.
//!
//! Framing discipline matches §5: unsigned LEB128 varints for all counts/lengths
//! (via [`crate::varint`], the single reused source), fixed-width fields
//! otherwise, and **reject-unknown / reject-trailing** on decode. These message
//! *bodies* are `[devnet-placeholder]` shape (§10); the *discipline* is binding.

use ml_dsa::{EncodedSignature, MlDsa65, Signature};
use qlab_devnet::body::{TxEntry, TxPublic};
use qlab_devnet::committee::{Checkpoint, MemberSig, Vote};
use qlab_devnet::fees::ArityBucket;
use qlab_devnet::hash::keccak256;
use qlab_devnet::header::{
    AggregateProofSlot, BlockHeader, EpochSupplyAttestation, Hash32,
};

use crate::varint::{read_varint, write_varint, CodecError};

/// The fixed on-wire length of a block header = its 98-byte hash preimage
/// (`prev(32) ‖ height(8) ‖ timestamp(8) ‖ difficulty(8) ‖ nonce(8) ‖
/// tx_body_commitment(32) ‖ 0xA6 ‖ 0x59`).
pub const HEADER_WIRE_LEN: usize = 98;

/// ML-DSA-65 signature length (frozen; [`MemberSig`] encodes to exactly this).
pub const SIG_LEN: usize = 3309;

/// Errors decoding a consensus object off the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Not enough bytes for the field being read.
    Truncated { what: &'static str },
    /// A count/length varint was malformed (overlong / truncated).
    Varint,
    /// Bytes remained after a complete object (reject-trailing).
    Trailing { remaining: usize },
    /// A block-header reserved-slot tag byte was not its frozen value.
    BadHeaderTag { pos: usize, got: u8 },
    /// An arity-bucket discriminant was not 0/1/2 (reject-unknown).
    BadBucket { got: u8 },
    /// An inventory-kind discriminant was not 1/2/3 (reject-unknown).
    BadInvKind { got: u8 },
    /// The ML-DSA signature bytes did not decode to a valid signature.
    BadSignature,
}

impl From<CodecError> for DecodeError {
    fn from(e: CodecError) -> Self {
        match e {
            CodecError::VarintOverflow => DecodeError::Varint,
            CodecError::Truncated { what } => DecodeError::Truncated { what },
            _ => DecodeError::Varint,
        }
    }
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for DecodeError {}

/// A single-pass byte-cursor reader with reject-trailing at the end.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], DecodeError> {
        if self.pos + n > self.buf.len() {
            return Err(DecodeError::Truncated { what });
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn u8(&mut self, what: &'static str) -> Result<u8, DecodeError> {
        Ok(self.take(1, what)?[0])
    }

    pub fn u64_le(&mut self, what: &'static str) -> Result<u64, DecodeError> {
        let b = self.take(8, what)?;
        Ok(u64::from_le_bytes(b.try_into().unwrap()))
    }

    pub fn hash32(&mut self, what: &'static str) -> Result<Hash32, DecodeError> {
        let b = self.take(32, what)?;
        Ok(b.try_into().unwrap())
    }

    pub fn varint(&mut self) -> Result<u64, DecodeError> {
        Ok(read_varint(self.buf, &mut self.pos)?)
    }

    pub fn rest(&mut self, n: usize, what: &'static str) -> Result<Vec<u8>, DecodeError> {
        Ok(self.take(n, what)?.to_vec())
    }

    /// Assert the whole buffer was consumed (reject-trailing).
    pub fn finish(self) -> Result<(), DecodeError> {
        if self.pos != self.buf.len() {
            return Err(DecodeError::Trailing { remaining: self.buf.len() - self.pos });
        }
        Ok(())
    }
}

// --------------------------------------------------------------------------
// Block header
// --------------------------------------------------------------------------

/// Encode a block header as its canonical 98-byte hash preimage.
pub fn encode_header(h: &BlockHeader) -> Vec<u8> {
    // `preimage()` IS the canonical fixed-width wire form; reusing it keeps the
    // wire byte-identical to the PoW / block-id input, so a header can never be
    // relayed under a different identity than it hashes to.
    h.preimage()
}

/// Decode a block header from its 98-byte preimage, checking the two frozen
/// reserved-slot tag bytes (reject-unknown on the tags).
pub fn decode_header(buf: &[u8]) -> Result<BlockHeader, DecodeError> {
    let mut r = Reader::new(buf);
    let prev = r.hash32("prev")?;
    let height = r.u64_le("height")?;
    let timestamp = r.u64_le("timestamp")?;
    let difficulty = r.u64_le("difficulty")?;
    let nonce = r.u64_le("nonce")?;
    let tx_body_commitment = r.hash32("tx_body_commitment")?;
    let tag_a = r.u8("aggregate_proof_tag")?;
    if tag_a != AggregateProofSlot::PREIMAGE_TAG {
        return Err(DecodeError::BadHeaderTag { pos: 96, got: tag_a });
    }
    let tag_b = r.u8("epoch_supply_tag")?;
    if tag_b != EpochSupplyAttestation::PREIMAGE_TAG {
        return Err(DecodeError::BadHeaderTag { pos: 97, got: tag_b });
    }
    r.finish()?;
    Ok(BlockHeader {
        prev,
        height,
        timestamp,
        difficulty,
        nonce,
        tx_body_commitment,
        aggregate_proof: AggregateProofSlot,
        epoch_supply_attestation: EpochSupplyAttestation,
    })
}

// --------------------------------------------------------------------------
// Checkpoint + votes
// --------------------------------------------------------------------------

fn write_checkpoint(out: &mut Vec<u8>, cp: &Checkpoint) {
    out.extend_from_slice(&cp.height.to_le_bytes());
    out.extend_from_slice(&cp.block_hash);
    out.extend_from_slice(&cp.root);
}

fn read_checkpoint(r: &mut Reader) -> Result<Checkpoint, DecodeError> {
    let height = r.u64_le("cp.height")?;
    let block_hash = r.hash32("cp.block_hash")?;
    let root = r.hash32("cp.root")?;
    Ok(Checkpoint::new(height, block_hash, root))
}

fn write_vote(out: &mut Vec<u8>, v: &Vote) {
    write_varint(out, v.signer as u64);
    // ML-DSA-65 signatures are fixed-length (SIG_LEN); a varint length prefix
    // keeps the format self-describing and list-safe.
    let sig = v.signature.encode();
    write_varint(out, sig.len() as u64);
    out.extend_from_slice(&sig);
}

fn read_vote(r: &mut Reader) -> Result<Vote, DecodeError> {
    let signer = r.varint()? as usize;
    let sig_len = r.varint()? as usize;
    let sig_bytes = r.rest(sig_len, "vote.signature")?;
    let enc = EncodedSignature::<MlDsa65>::try_from(sig_bytes.as_slice())
        .map_err(|_| DecodeError::BadSignature)?;
    let signature: MemberSig =
        Signature::<MlDsa65>::decode(&enc).ok_or(DecodeError::BadSignature)?;
    Ok(Vote { signer, signature })
}

/// Encode a checkpoint together with its votes (the `Checkpoint` gossip body).
pub fn encode_checkpoint_msg(cp: &Checkpoint, votes: &[Vote]) -> Vec<u8> {
    let mut out = Vec::new();
    write_checkpoint(&mut out, cp);
    write_varint(&mut out, votes.len() as u64);
    for v in votes {
        write_vote(&mut out, v);
    }
    out
}

/// Decode a checkpoint + votes body.
pub fn decode_checkpoint_msg(buf: &[u8]) -> Result<(Checkpoint, Vec<Vote>), DecodeError> {
    let mut r = Reader::new(buf);
    let cp = read_checkpoint(&mut r)?;
    let n = r.varint()? as usize;
    let mut votes = Vec::with_capacity(n);
    for _ in 0..n {
        votes.push(read_vote(&mut r)?);
    }
    r.finish()?;
    Ok((cp, votes))
}

/// A checkpoint's inventory id — binds (height, block_hash, root) + domain.
pub fn checkpoint_id(cp: &Checkpoint) -> Hash32 {
    keccak256(&cp.signing_message())
}

// --------------------------------------------------------------------------
// Transaction
// --------------------------------------------------------------------------

fn bucket_to_u8(b: ArityBucket) -> u8 {
    match b {
        ArityBucket::TwoByTwo => 0,
        ArityBucket::FourByFour => 1,
        ArityBucket::EightByEight => 2,
    }
}

fn bucket_from_u8(v: u8) -> Result<ArityBucket, DecodeError> {
    match v {
        0 => Ok(ArityBucket::TwoByTwo),
        1 => Ok(ArityBucket::FourByFour),
        2 => Ok(ArityBucket::EightByEight),
        got => Err(DecodeError::BadBucket { got }),
    }
}

/// Encode a transaction (public values + opaque proof).
pub fn encode_tx(tx: &TxEntry) -> Vec<u8> {
    let mut out = Vec::new();
    let p = &tx.public;
    out.extend_from_slice(&p.anchor);
    write_varint(&mut out, p.nullifiers.len() as u64);
    for nf in &p.nullifiers {
        out.extend_from_slice(nf);
    }
    write_varint(&mut out, p.commitments.len() as u64);
    for cm in &p.commitments {
        out.extend_from_slice(cm);
    }
    out.push(bucket_to_u8(p.bucket));
    out.extend_from_slice(&p.fee.to_le_bytes());
    write_varint(&mut out, tx.proof.len() as u64);
    out.extend_from_slice(&tx.proof);
    out
}

/// Decode a transaction body.
pub fn decode_tx(buf: &[u8]) -> Result<TxEntry, DecodeError> {
    let mut r = Reader::new(buf);
    let anchor = r.hash32("tx.anchor")?;
    let n_nf = r.varint()? as usize;
    let mut nullifiers = Vec::with_capacity(n_nf);
    for _ in 0..n_nf {
        nullifiers.push(r.hash32("tx.nf")?);
    }
    let n_cm = r.varint()? as usize;
    let mut commitments = Vec::with_capacity(n_cm);
    for _ in 0..n_cm {
        commitments.push(r.hash32("tx.cm")?);
    }
    let bucket = bucket_from_u8(r.u8("tx.bucket")?)?;
    let fee = r.u64_le("tx.fee")?;
    let proof_len = r.varint()? as usize;
    let proof = r.rest(proof_len, "tx.proof")?;
    r.finish()?;
    Ok(TxEntry { proof, public: TxPublic { anchor, nullifiers, commitments, bucket, fee } })
}

/// A transaction's inventory id (there is no consensus tx-id in the devnet; the
/// body commitment is the block-level digest — for per-tx gossip dedup we hash
/// the canonical tx wire).
pub fn tx_id(tx: &TxEntry) -> Hash32 {
    keccak256(&encode_tx(tx))
}

// --------------------------------------------------------------------------
// Inventory (inv / getdata / notfound)
// --------------------------------------------------------------------------

/// The kind of an inventory item. Reject-unknown on decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InvKind {
    Tx = 1,
    Block = 2,
    Checkpoint = 3,
}

impl InvKind {
    fn from_u8(v: u8) -> Result<Self, DecodeError> {
        match v {
            1 => Ok(InvKind::Tx),
            2 => Ok(InvKind::Block),
            3 => Ok(InvKind::Checkpoint),
            got => Err(DecodeError::BadInvKind { got }),
        }
    }
}

/// A `(kind, id)` inventory item — the unit of inv / getdata / notfound.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InvItem {
    pub kind: InvKind,
    pub id: Hash32,
}

/// Encode an inventory vector (used for inv / getdata / notfound bodies).
pub fn encode_inv(items: &[InvItem]) -> Vec<u8> {
    let mut out = Vec::new();
    write_varint(&mut out, items.len() as u64);
    for it in items {
        out.push(it.kind as u8);
        out.extend_from_slice(&it.id);
    }
    out
}

/// Decode an inventory vector.
pub fn decode_inv(buf: &[u8]) -> Result<Vec<InvItem>, DecodeError> {
    let mut r = Reader::new(buf);
    let n = r.varint()? as usize;
    let mut items = Vec::with_capacity(n);
    for _ in 0..n {
        let kind = InvKind::from_u8(r.u8("inv.kind")?)?;
        let id = r.hash32("inv.id")?;
        items.push(InvItem { kind, id });
    }
    r.finish()?;
    Ok(items)
}

// --------------------------------------------------------------------------
// Header-first sync: locator + header batch
// --------------------------------------------------------------------------

/// A block-locator for `GetHeaders`: a set of known hashes (dense near the tip,
/// sparse toward genesis) + a stop hash (`ZERO_HASH` = "as far as you can").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Locator {
    pub have: Vec<Hash32>,
    pub stop: Hash32,
}

/// Encode a `GetHeaders` locator body.
pub fn encode_locator(loc: &Locator) -> Vec<u8> {
    let mut out = Vec::new();
    write_varint(&mut out, loc.have.len() as u64);
    for h in &loc.have {
        out.extend_from_slice(h);
    }
    out.extend_from_slice(&loc.stop);
    out
}

/// Decode a `GetHeaders` locator body.
pub fn decode_locator(buf: &[u8]) -> Result<Locator, DecodeError> {
    let mut r = Reader::new(buf);
    let n = r.varint()? as usize;
    let mut have = Vec::with_capacity(n);
    for _ in 0..n {
        have.push(r.hash32("loc.have")?);
    }
    let stop = r.hash32("loc.stop")?;
    r.finish()?;
    Ok(Locator { have, stop })
}

/// Encode a `Headers` batch body (ancestor-first).
pub fn encode_headers(headers: &[BlockHeader]) -> Vec<u8> {
    let mut out = Vec::new();
    write_varint(&mut out, headers.len() as u64);
    for h in headers {
        out.extend_from_slice(&encode_header(h));
    }
    out
}

/// Decode a `Headers` batch body.
pub fn decode_headers(buf: &[u8]) -> Result<Vec<BlockHeader>, DecodeError> {
    let mut r = Reader::new(buf);
    let n = r.varint()? as usize;
    let mut headers = Vec::with_capacity(n);
    for _ in 0..n {
        let raw = r.rest(HEADER_WIRE_LEN, "headers.item")?;
        headers.push(decode_header(&raw)?);
    }
    r.finish()?;
    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_devnet::committee::devnet_committee;
    use qlab_devnet::header::ZERO_HASH;

    fn sample_header() -> BlockHeader {
        let g = BlockHeader::genesis(1000, 42);
        BlockHeader::child_of(&g, 117, 1000, [7u8; 32])
    }

    #[test]
    fn header_round_trips_and_preserves_hash() {
        let h = sample_header();
        let bytes = encode_header(&h);
        assert_eq!(bytes.len(), HEADER_WIRE_LEN);
        let back = decode_header(&bytes).unwrap();
        assert_eq!(back, h);
        // The wire form IS the hash preimage → identity is preserved.
        assert_eq!(back.header_hash(), h.header_hash());
    }

    #[test]
    fn header_rejects_tampered_reserved_tag() {
        let mut bytes = encode_header(&sample_header());
        bytes[96] = 0x00; // clobber the aggregate-proof tag (0xA6)
        assert!(matches!(decode_header(&bytes), Err(DecodeError::BadHeaderTag { pos: 96, .. })));
    }

    #[test]
    fn header_rejects_trailing() {
        let mut bytes = encode_header(&sample_header());
        bytes.push(0x00);
        assert!(matches!(decode_header(&bytes), Err(DecodeError::Trailing { .. })));
    }

    #[test]
    fn checkpoint_and_votes_round_trip() {
        let (committee, validators) = devnet_committee(7);
        let cp = Checkpoint::new(2, [0xAB; 32], [0xCD; 32]);
        let votes: Vec<Vote> = validators[..5].iter().map(|v| v.sign_checkpoint(&cp)).collect();
        let bytes = encode_checkpoint_msg(&cp, &votes);
        let (cp2, votes2) = decode_checkpoint_msg(&bytes).unwrap();
        assert_eq!(cp2, cp);
        assert_eq!(votes2.len(), 5);
        // Decoded signatures still verify against the committee.
        for v in &votes2 {
            assert!(committee.verify_vote(&cp2, v));
        }
    }

    #[test]
    fn vote_signature_is_frozen_length() {
        let (_c, validators) = devnet_committee(1);
        let cp = Checkpoint::new(1, [1; 32], [2; 32]);
        let v = validators[0].sign_checkpoint(&cp);
        assert_eq!(v.signature.encode().len(), SIG_LEN);
    }

    #[test]
    fn tx_round_trips() {
        let tx = TxEntry {
            proof: vec![9u8; 200],
            public: TxPublic {
                anchor: [1; 32],
                nullifiers: vec![[2; 32], [3; 32]],
                commitments: vec![[4; 32], [5; 32]],
                bucket: ArityBucket::TwoByTwo,
                fee: 1_000_000,
            },
        };
        let bytes = encode_tx(&tx);
        let back = decode_tx(&bytes).unwrap();
        assert_eq!(back.public, tx.public);
        assert_eq!(back.proof, tx.proof);
        assert_eq!(tx_id(&back), tx_id(&tx));
    }

    #[test]
    fn tx_rejects_unknown_bucket() {
        let tx = TxEntry {
            proof: vec![],
            public: TxPublic {
                anchor: [0; 32],
                nullifiers: vec![],
                commitments: vec![],
                bucket: ArityBucket::EightByEight,
                fee: 0,
            },
        };
        let mut bytes = encode_tx(&tx);
        // bucket byte sits after anchor(32) + n_nf(1 varint=0) + n_cm(1 varint=0).
        let bucket_pos = 32 + 1 + 1;
        bytes[bucket_pos] = 9;
        assert!(matches!(decode_tx(&bytes), Err(DecodeError::BadBucket { got: 9 })));
    }

    #[test]
    fn inv_round_trips_and_rejects_unknown_kind() {
        let items = vec![
            InvItem { kind: InvKind::Tx, id: [1; 32] },
            InvItem { kind: InvKind::Block, id: [2; 32] },
            InvItem { kind: InvKind::Checkpoint, id: [3; 32] },
        ];
        let bytes = encode_inv(&items);
        assert_eq!(decode_inv(&bytes).unwrap(), items);

        let mut bad = encode_inv(&items);
        bad[1] = 0xFF; // first item's kind byte
        assert_eq!(decode_inv(&bad), Err(DecodeError::BadInvKind { got: 0xFF }));
    }

    #[test]
    fn locator_round_trips() {
        let loc = Locator { have: vec![[1; 32], [2; 32]], stop: ZERO_HASH };
        let bytes = encode_locator(&loc);
        assert_eq!(decode_locator(&bytes).unwrap(), loc);
    }

    #[test]
    fn headers_batch_round_trips() {
        let g = BlockHeader::genesis(1000, 0);
        let h1 = BlockHeader::child_of(&g, 75, 1000, [1; 32]);
        let h2 = BlockHeader::child_of(&h1, 150, 1000, [2; 32]);
        let batch = vec![g, h1, h2];
        let bytes = encode_headers(&batch);
        assert_eq!(decode_headers(&bytes).unwrap(), batch);
    }
}
