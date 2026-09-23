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
use qlab_devnet::ebbflow::EquivocationEvidence;
use qlab_devnet::fees::ArityBucket;
use qlab_devnet::forms::GenesisForm;
use qlab_devnet::hash::keccak256;
use qlab_devnet::header::{
    AggregateProofSlot, BlockHeader, EpochSupplyAttestation, Hash32, HEADER_PREIMAGE_LEN_V4,
    HEADER_PREIMAGE_LEN_V5, HEADER_VERSION_BYTE_V5,
};

use crate::varint::{read_varint, write_varint, CodecError};

/// The fixed on-wire length of a **v4** block header = its 98-byte hash
/// preimage (`prev(32) ‖ height(8) ‖ timestamp(8) ‖ difficulty(8) ‖ nonce(8) ‖
/// tx_body_commitment(32) ‖ 0xA6 ‖ 0x59`). Since lab #470 the wire length is
/// form-keyed — see [`header_wire_len`]; this constant is the v4 value and the
/// live T1 net's compat lock.
pub const HEADER_WIRE_LEN: usize = HEADER_PREIMAGE_LEN_V4;

/// The on-wire length of a block header under `form` (lab #470 stage 1). The
/// two forms deliberately differ in length (98 vs 97), so a header of the
/// other net's form is refused by [`DecodeError::WrongHeaderLen`] — by name,
/// never misparsed.
pub fn header_wire_len(form: GenesisForm) -> usize {
    match form {
        GenesisForm::V4 => HEADER_PREIMAGE_LEN_V4,
        GenesisForm::V5 => HEADER_PREIMAGE_LEN_V5,
    }
}

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
    ///
    /// **Deliberately still an error**, and NOT the [`InvKind`] case issue #181
    /// changed: an `ArityBucket` is a *consensus* value (it selects the proof
    /// shape and the fee schedule), so a transaction naming one this build does
    /// not implement is a transaction this build cannot validate. Skipping it
    /// would mean relaying an object we never judged. An inventory kind is only
    /// an offer of something to fetch, and declining the offer costs nothing.
    BadBucket { got: u8 },
    /// The ML-DSA signature bytes did not decode to a valid signature.
    BadSignature,
    /// A block header's byte length is not this net's form length — the named
    /// refusal a v4 header meets on a v5 net and vice versa (lab #470: the two
    /// forms differ in length by construction, so cross-net headers are refused
    /// here, never misparsed).
    WrongHeaderLen { got: usize, want: usize },
    /// A v5 block header's format-version byte (offset 32) was not 0x05.
    BadHeaderVersion { got: u8 },
    /// A v5 announce names more coinbase payees than the height-keyed cap —
    /// refused by name before constructing a body this build cannot validate
    /// (the same grounds as `BadBucket`).
    TooManyCoinbasePayees { got: usize, cap: usize },
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

    /// Whether any bytes remain — the probe behind presence-conditional
    /// sections (the tx rider, lab #367). Deliberately not a general peek:
    /// the only honest question a conditional section can ask is "is there
    /// more", never "what is next".
    pub fn has_more(&self) -> bool {
        self.pos < self.buf.len()
    }
}

// --------------------------------------------------------------------------
// Block header
// --------------------------------------------------------------------------

/// Encode a block header as its canonical hash preimage under `form`.
pub fn encode_header(form: GenesisForm, h: &BlockHeader) -> Vec<u8> {
    // `preimage_for()` IS the canonical fixed-width wire form; reusing it keeps
    // the wire byte-identical to the PoW / block-id input, so a header can
    // never be relayed under a different identity than it hashes to.
    h.preimage_for(form)
}

/// Decode a block header from its preimage bytes under this net's `form`,
/// checking the exact form length first (a wrong-form header is refused by
/// [`DecodeError::WrongHeaderLen`], by name), then — for v5 — the format
/// version byte, then the two frozen reserved-slot tag bytes (reject-unknown).
pub fn decode_header(form: GenesisForm, buf: &[u8]) -> Result<BlockHeader, DecodeError> {
    let want = header_wire_len(form);
    if buf.len() != want {
        return Err(DecodeError::WrongHeaderLen { got: buf.len(), want });
    }
    let mut r = Reader::new(buf);
    let prev = r.hash32("prev")?;
    let (height, nonce, timestamp, difficulty, tag_pos) = match form {
        GenesisForm::V4 => {
            let height = r.u64_le("height")?;
            let timestamp = r.u64_le("timestamp")?;
            let difficulty = r.u64_le("difficulty")?;
            let nonce = r.u64_le("nonce")?;
            (height, nonce, timestamp, difficulty, 96usize)
        }
        GenesisForm::V5 => {
            let version = r.u8("header_format_version")?;
            if version != HEADER_VERSION_BYTE_V5 {
                return Err(DecodeError::BadHeaderVersion { got: version });
            }
            let mut h6 = [0u8; 8];
            h6[..6].copy_from_slice(&r.rest(6, "height_u48")?);
            let height = u64::from_le_bytes(h6);
            let nonce = r.u64_le("nonce")?;
            let timestamp = r.u64_le("timestamp")?;
            let difficulty = r.u64_le("difficulty")?;
            (height, nonce, timestamp, difficulty, 95usize)
        }
    };
    let tx_body_commitment = r.hash32("tx_body_commitment")?;
    let tag_a = r.u8("aggregate_proof_tag")?;
    if tag_a != AggregateProofSlot::PREIMAGE_TAG {
        return Err(DecodeError::BadHeaderTag { pos: tag_pos, got: tag_a });
    }
    let tag_b = r.u8("epoch_supply_tag")?;
    if tag_b != EpochSupplyAttestation::PREIMAGE_TAG {
        return Err(DecodeError::BadHeaderTag { pos: tag_pos + 1, got: tag_b });
    }
    r.finish()?;
    Ok(BlockHeader { ext: qlab_devnet::annulet::HeaderExt::NONE,
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
    // The count is attacker-controlled (peer wire): cap the pre-allocation by
    // what the remaining bytes could actually hold (a vote carries a SIG_LEN
    // signature), so a tiny payload claiming 2^60 votes is a truncation refusal
    // on its first read and never a giant allocation. Same shape as decode_tx
    // (issue #275 / PR #277); remaining sites closed by issue #279.
    let n = r.varint()? as usize;
    let mut votes = Vec::with_capacity(n.min(buf.len() / SIG_LEN));
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

/// The 24-byte tag that marks an [`InvKind::Checkpoint`] id as a **query** rather
/// than a checkpoint id (issue #204).
///
/// A checkpoint id is `keccak256(signing_message)`; this tag fixes 192 bits of the
/// 256-bit id space to a constant, so a real checkpoint id colliding with the query
/// namespace is a 2⁻¹⁹² event. The remaining 8 bytes carry the queried height,
/// big-endian, so the id stays byte-ordered by height and is trivially readable in
/// a hexdump.
pub const CHECKPOINT_QUERY_TAG: [u8; 24] = *b"qumbra:cp-at-or-below:v1";

/// Build the `GetData(InvKind::Checkpoint, …)` id that means **"the highest
/// finalized checkpoint you hold at height ≤ `height`"** (issue #204).
///
/// The gap #204 names is that `GetData(Checkpoint, id)` requires the requester to
/// already know the checkpoint's id, and a node that never accumulated the quorum
/// does not. This is the same door #130 (c) opened for block bodies: the *request*
/// is unchanged and already understood by every deployed node, and only what it
/// answers with changes. A node running the current image answers `NotFound` (it
/// holds no checkpoint under this id), which the requester deliberately does not
/// score — see [`crate::node::P2pNode::on_not_found`].
pub fn checkpoint_query_id(height: u64) -> Hash32 {
    let mut id = [0u8; 32];
    id[..24].copy_from_slice(&CHECKPOINT_QUERY_TAG);
    id[24..].copy_from_slice(&height.to_be_bytes());
    id
}

/// The height an id built by [`checkpoint_query_id`] asks about, or `None` if the
/// id is an ordinary checkpoint id.
pub fn checkpoint_query_height(id: &Hash32) -> Option<u64> {
    if id[..24] != CHECKPOINT_QUERY_TAG {
        return None;
    }
    let mut h = [0u8; 8];
    h.copy_from_slice(&id[24..]);
    Some(u64::from_be_bytes(h))
}

/// Encode a `CheckpointVotes` (0x0024) body — a checkpoint plus a **partial** vote
/// set that nodes accumulate to a quorum (M10-T0-5). The body is byte-identical to
/// the [`MsgType::Checkpoint`] body ([`encode_checkpoint_msg`]); only the envelope
/// type differs. Reuses `write_checkpoint`/`write_vote`/varint — the codec is NOT
/// forked (task-book S2).
pub fn encode_checkpoint_votes(cp: &Checkpoint, votes: &[Vote]) -> Vec<u8> {
    encode_checkpoint_msg(cp, votes)
}

/// Decode a `CheckpointVotes` body (reject-trailing/truncated as the shared codec).
pub fn decode_checkpoint_votes(buf: &[u8]) -> Result<(Checkpoint, Vec<Vote>), DecodeError> {
    decode_checkpoint_msg(buf)
}

// --------------------------------------------------------------------------
// Equivocation evidence (committee-gov §3 — gossiped so the whole network
// applies the automated tombstone; M9-N5)
// --------------------------------------------------------------------------

/// Encode equivocation evidence: two (checkpoint, vote) pairs for the same slot.
pub fn encode_evidence_msg(ev: &EquivocationEvidence) -> Vec<u8> {
    let mut out = Vec::new();
    write_checkpoint(&mut out, &ev.cp_a);
    write_vote(&mut out, &ev.vote_a);
    write_checkpoint(&mut out, &ev.cp_b);
    write_vote(&mut out, &ev.vote_b);
    out
}

/// Decode an equivocation-evidence body (reject-trailing).
pub fn decode_evidence_msg(buf: &[u8]) -> Result<EquivocationEvidence, DecodeError> {
    let mut r = Reader::new(buf);
    let cp_a = read_checkpoint(&mut r)?;
    let vote_a = read_vote(&mut r)?;
    let cp_b = read_checkpoint(&mut r)?;
    let vote_b = read_vote(&mut r)?;
    r.finish()?;
    Ok(EquivocationEvidence { cp_a, vote_a, cp_b, vote_b })
}

/// An evidence object's inventory/dedup id — binds both signing messages and the
/// offending signer, so re-gossip of the same evidence dedups to one relay.
pub fn evidence_id(ev: &EquivocationEvidence) -> Hash32 {
    let mut m = Vec::new();
    m.extend_from_slice(&ev.cp_a.signing_message());
    m.extend_from_slice(&ev.cp_b.signing_message());
    m.extend_from_slice(&(ev.vote_a.signer as u64).to_le_bytes());
    keccak256(&m)
}

// --------------------------------------------------------------------------
// Transaction
// --------------------------------------------------------------------------

fn bucket_to_u8(b: ArityBucket) -> u8 {
    // Since lab #470 stage 3 this IS the shared encoding (#233): the same
    // `wire_discriminant` the v5 body preimage commits, so the codec byte and
    // the committed byte are one function rather than two that agree.
    b.wire_discriminant()
}

fn bucket_from_u8(v: u8) -> Result<ArityBucket, DecodeError> {
    ArityBucket::from_wire_discriminant(v).ok_or(DecodeError::BadBucket { got: v })
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
    // Issue #188: the discovery group travels with the transaction, because the
    // block body commits to it. A transaction relayed without it could not be
    // included in any valid block, so this is not an optional extension of the
    // tx payload — it is what makes the body change coherent on the wire.
    write_varint(&mut out, tx.discovery.len() as u64);
    out.extend_from_slice(&tx.discovery);
    // Lab #367: the name rider travels the same way — but the section is
    // PRESENCE-CONDITIONAL, unlike discovery's, and unlike the body preimage's
    // unconditional v3 tail. The reason is the #181 lesson run forward: an
    // unconditional tail here would make every tx from a #367 build unreadable
    // to every pre-#367 peer — a relay partition on a wire that has no
    // boundary to hide behind (riders only become *valid* above the name
    // boundary, but transactions relay before and after it). A rider-absent tx
    // therefore encodes byte-identically to a pre-#367 tx, and only a
    // rider-carrying tx (which no pre-#367 build could include in a block
    // anyway) grows the section. Canonicity: absence is spelled by OMISSION on
    // this wire — an explicit `[0x00]` tail is refused at decode, so one tx
    // has one encoding and `tx_id` stays collision-free.
    if tx.rider != qlab_devnet::names::RIDER_ABSENT {
        write_varint(&mut out, tx.rider.len() as u64);
        out.extend_from_slice(&tx.rider);
    }
    out
}

/// Decode a transaction body.
pub fn decode_tx(buf: &[u8]) -> Result<TxEntry, DecodeError> {
    let mut r = Reader::new(buf);
    let anchor = r.hash32("tx.anchor")?;
    // The counts are attacker-controlled (this decodes the peer wire, and since
    // issue #275 an HTTP body too): cap each pre-allocation by what the remaining
    // bytes could actually hold, so a tiny payload claiming 2^60 entries is a
    // truncation refusal on its first read and never a giant allocation.
    let n_nf = r.varint()? as usize;
    let mut nullifiers = Vec::with_capacity(n_nf.min(buf.len() / 32));
    for _ in 0..n_nf {
        nullifiers.push(r.hash32("tx.nf")?);
    }
    let n_cm = r.varint()? as usize;
    let mut commitments = Vec::with_capacity(n_cm.min(buf.len() / 32));
    for _ in 0..n_cm {
        commitments.push(r.hash32("tx.cm")?);
    }
    let bucket = bucket_from_u8(r.u8("tx.bucket")?)?;
    let fee = r.u64_le("tx.fee")?;
    let proof_len = r.varint()? as usize;
    let proof = r.rest(proof_len, "tx.proof")?;
    let discovery_len = r.varint()? as usize;
    let discovery = r.rest(discovery_len, "tx.discovery")?;
    // Lab #367: presence-conditional rider section — see encode_tx's note.
    let rider = if r.has_more() {
        let rider_len = r.varint()? as usize;
        let rider = r.rest(rider_len, "tx.rider")?;
        if rider == qlab_devnet::names::RIDER_ABSENT {
            // Absence is spelled by omission on this wire; an explicit absent
            // tail is a second encoding of the same tx and is refused so
            // `tx_id` stays one-to-one.
            return Err(DecodeError::Trailing { remaining: rider.len() });
        }
        rider
    } else {
        TxEntry::absent_rider()
    };
    r.finish()?;
    Ok(TxEntry { l2: qlab_devnet::annulet::L2_SURFACE_ABSENT.to_vec(),
        proof,
        discovery,
        public: TxPublic { anchor, nullifiers, commitments, bucket, fee },
        rider,
    })
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

/// The kind of an inventory item.
///
/// **An unrecognised kind is skipped, not rejected** (issue #181) — see
/// [`InvVec`]. It is [`crate::wire::Frame::UnknownType`]'s problem one layer in:
/// a kind code this build does not implement means the *sender* implements one
/// this build does not, which is version skew and not misbehaviour. Before #181
/// it was `DecodeError::BadInvKind`, every `decode_inv` caller charged
/// `PENALTY_MALFORMED` for a decode failure, and a single `inv` naming a newer
/// kind therefore banned its sender — which is what stopped `issue #133` D2 from
/// allocating `InvKind::Evidence`.
///
/// `CheckpointVotes = 4` is reserved by the coordinator (task-book S3) for an
/// inv/getdata vote-set path; M10-T0-5 relays partial vote sets by **direct push**
/// ([`crate::wire::MsgType::CheckpointVotes`]) rather than inv/getdata, so code 4 is
/// intentionally left unallocated here — reserved, not used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InvKind {
    Tx = 1,
    Block = 2,
    Checkpoint = 3,
    // 4 = CheckpointVotes — reserved (direct-push relay; see the type doc).
}

impl InvKind {
    /// Decode a raw kind code, or `None` for one this build does not implement.
    /// Mirrors [`crate::wire::MsgType::from_u16`] deliberately: same question,
    /// same answer shape, so the two cannot drift into different policies.
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => InvKind::Tx,
            2 => InvKind::Block,
            3 => InvKind::Checkpoint,
            _ => return None,
        })
    }
}

/// A decoded inventory vector: the items this build can act on, plus **how many
/// it skipped because their kind code is newer than this build** (issue #181).
///
/// The skipped count is carried out of the codec rather than swallowed here for
/// the same reason [`crate::wire::Frame::UnknownType`] carries its type code: a
/// silent ignore is how the next version-skew incident becomes invisible. It is a
/// count and never a verdict — no caller may score it.
///
/// Skipping is safe *because the item is fixed-width*: `kind(1) ‖ id(32)`. The
/// reader steps past an unknown kind exactly as far as it steps past a known one,
/// so the rest of the vector still parses and reject-trailing still binds. That
/// is not true of a variable-length unknown, which is why this treatment does not
/// generalise to, say, an unknown [`ArityBucket`] inside a transaction body.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InvVec {
    /// Items whose kind this build implements, in wire order.
    pub items: Vec<InvItem>,
    /// Well-formed items whose kind code this build does not implement.
    pub unknown_kinds: usize,
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

/// Decode an inventory vector, skipping items whose kind this build does not
/// implement (issue #181 — see [`InvVec`]).
///
/// Truncation, a malformed varint and trailing bytes are still `Err`, and still
/// the sender's fault. The **only** thing that moved is the kind code.
pub fn decode_inv(buf: &[u8]) -> Result<InvVec, DecodeError> {
    let mut r = Reader::new(buf);
    let n = r.varint()? as usize;
    let mut out = InvVec::default();
    for _ in 0..n {
        // The id is read either way: the item is fixed-width, so an unknown kind
        // is stepped over rather than desyncing the rest of the vector.
        let kind = InvKind::from_u8(r.u8("inv.kind")?);
        let id = r.hash32("inv.id")?;
        match kind {
            Some(kind) => out.items.push(InvItem { kind, id }),
            None => out.unknown_kinds += 1,
        }
    }
    r.finish()?;
    Ok(out)
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
    // The count is attacker-controlled (peer wire): cap the pre-allocation by
    // what the remaining bytes could actually hold (each hash is 32 B), so a
    // tiny payload claiming 2^60 hashes is a truncation refusal on its first
    // read and never a giant allocation. Same shape as decode_tx (issue #275 /
    // PR #277); remaining sites closed by issue #279.
    let n = r.varint()? as usize;
    let mut have = Vec::with_capacity(n.min(buf.len() / 32));
    for _ in 0..n {
        have.push(r.hash32("loc.have")?);
    }
    let stop = r.hash32("loc.stop")?;
    r.finish()?;
    Ok(Locator { have, stop })
}

/// Encode a `Headers` batch body (ancestor-first).
pub fn encode_headers(form: GenesisForm, headers: &[BlockHeader]) -> Vec<u8> {
    let mut out = Vec::new();
    write_varint(&mut out, headers.len() as u64);
    for h in headers {
        out.extend_from_slice(&encode_header(form, h));
    }
    out
}

/// Decode a `Headers` batch body.
pub fn decode_headers(form: GenesisForm, buf: &[u8]) -> Result<Vec<BlockHeader>, DecodeError> {
    let mut r = Reader::new(buf);
    // The count is attacker-controlled (peer wire): cap the pre-allocation by
    // what the remaining bytes could actually hold (each header is
    // HEADER_WIRE_LEN), so a tiny payload claiming 2^60 headers is a truncation
    // refusal on its first read and never a giant allocation. Same shape as
    // decode_tx (issue #275 / PR #277); remaining sites closed by issue #279.
    let wire_len = header_wire_len(form);
    let n = r.varint()? as usize;
    let mut headers = Vec::with_capacity(n.min(buf.len() / wire_len));
    for _ in 0..n {
        let raw = r.rest(wire_len, "headers.item")?;
        headers.push(decode_header(form, &raw)?);
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
        let bytes = encode_header(GenesisForm::V4, &h);
        assert_eq!(bytes.len(), HEADER_WIRE_LEN);
        let back = decode_header(GenesisForm::V4, &bytes).unwrap();
        assert_eq!(back, h);
        // The wire form IS the hash preimage → identity is preserved.
        assert_eq!(back.header_hash(), h.header_hash());
    }

    #[test]
    fn header_rejects_tampered_reserved_tag() {
        let mut bytes = encode_header(GenesisForm::V4, &sample_header());
        bytes[96] = 0x00; // clobber the aggregate-proof tag (0xA6)
        assert!(matches!(
            decode_header(GenesisForm::V4, &bytes),
            Err(DecodeError::BadHeaderTag { pos: 96, .. })
        ));
    }

    #[test]
    fn header_rejects_trailing() {
        let mut bytes = encode_header(GenesisForm::V4, &sample_header());
        bytes.push(0x00);
        // Since lab #470 the exact-length gate fires before the positional
        // reader, so trailing bytes are refused as WrongHeaderLen — one named
        // refusal earlier than the old Trailing, never weaker.
        assert!(matches!(
            decode_header(GenesisForm::V4, &bytes),
            Err(DecodeError::WrongHeaderLen { got: 99, want: 98 })
        ));
    }

    // ── v5 header form (lab #470 stage 1) ───────────────────────────────────

    #[test]
    fn v5_header_round_trips_and_is_97_bytes() {
        let h = sample_header();
        let bytes = encode_header(GenesisForm::V5, &h);
        assert_eq!(bytes.len(), header_wire_len(GenesisForm::V5));
        assert_eq!(bytes.len(), 97);
        let back = decode_header(GenesisForm::V5, &bytes).unwrap();
        assert_eq!(back, h);
        assert_eq!(back.header_hash_for(GenesisForm::V5), h.header_hash_for(GenesisForm::V5));
    }

    /// The adversarial contract of the C2 ruling: a v4 header presented to a
    /// v5 net (and vice versa) is refused BY NAME, never misparsed. The two
    /// forms differ in length by construction, so the refusal is structural.
    #[test]
    fn cross_form_headers_are_refused_by_name() {
        let h = sample_header();
        let v4_bytes = encode_header(GenesisForm::V4, &h);
        let v5_bytes = encode_header(GenesisForm::V5, &h);
        assert!(matches!(
            decode_header(GenesisForm::V5, &v4_bytes),
            Err(DecodeError::WrongHeaderLen { got: 98, want: 97 })
        ));
        assert!(matches!(
            decode_header(GenesisForm::V4, &v5_bytes),
            Err(DecodeError::WrongHeaderLen { got: 97, want: 98 })
        ));
    }

    #[test]
    fn v5_header_rejects_a_wrong_version_byte() {
        let h = sample_header();
        let mut bytes = encode_header(GenesisForm::V5, &h);
        bytes[32] = 0x04; // not the v5 version byte
        assert!(matches!(
            decode_header(GenesisForm::V5, &bytes),
            Err(DecodeError::BadHeaderVersion { got: 0x04 })
        ));
    }

    #[test]
    fn v5_header_rejects_tampered_reserved_tags_at_their_v5_offsets() {
        let h = sample_header();
        let mut bytes = encode_header(GenesisForm::V5, &h);
        bytes[95] = 0x00;
        assert!(matches!(
            decode_header(GenesisForm::V5, &bytes),
            Err(DecodeError::BadHeaderTag { pos: 95, .. })
        ));
        let mut bytes = encode_header(GenesisForm::V5, &h);
        bytes[96] = 0x00;
        assert!(matches!(
            decode_header(GenesisForm::V5, &bytes),
            Err(DecodeError::BadHeaderTag { pos: 96, .. })
        ));
    }

    #[test]
    fn v5_headers_batch_round_trips_on_the_v5_stride() {
        let g = BlockHeader::genesis(1_000, 0);
        let a = BlockHeader::child_of_for(GenesisForm::V5, &g, 1, 1_000, [1u8; 32]);
        let b = BlockHeader::child_of_for(GenesisForm::V5, &a, 2, 1_000, [2u8; 32]);
        let batch = vec![g, a, b];
        let bytes = encode_headers(GenesisForm::V5, &batch);
        assert_eq!(decode_headers(GenesisForm::V5, &bytes).unwrap(), batch);
        // A v4 reader on the same bytes strides wrong and refuses; it can
        // never silently yield headers.
        assert!(decode_headers(GenesisForm::V4, &bytes).is_err());
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

    /// Golden byte-vector for the `CheckpointVotes` (0x0024) body (task-book §4 #9).
    /// The deterministic prefix — `write_checkpoint(72) ‖ varint(n_votes)` — is locked
    /// exactly; the vote bodies (3,309-B ML-DSA sigs) are exercised by round-trip.
    #[test]
    fn checkpoint_votes_body_golden_and_roundtrip() {
        let (committee, validators) = devnet_committee(7);
        let cp = Checkpoint::new(2, [0xAB; 32], [0xCD; 32]);

        // Empty-set body is fully golden-able: height(8 LE)=02.. ‖ block_hash(32)=AB.. ‖
        // root(32)=CD.. ‖ varint(0)=00. Exactly 73 bytes.
        let empty = encode_checkpoint_votes(&cp, &[]);
        let mut want = Vec::new();
        want.extend_from_slice(&2u64.to_le_bytes());
        want.extend_from_slice(&[0xAB; 32]);
        want.extend_from_slice(&[0xCD; 32]);
        want.push(0x00); // varint(0) votes
        assert_eq!(empty, want, "CheckpointVotes body field order is locked");
        assert_eq!(empty.len(), 73);
        assert_eq!(decode_checkpoint_votes(&empty).unwrap().1.len(), 0);

        // With real votes, the alias is byte-identical to the Checkpoint body and
        // round-trips with verifying signatures.
        let votes: Vec<Vote> = validators[..3].iter().map(|v| v.sign_checkpoint(&cp)).collect();
        let bytes = encode_checkpoint_votes(&cp, &votes);
        assert_eq!(bytes, encode_checkpoint_msg(&cp, &votes), "same body as Checkpoint 0x0022");
        let (cp2, votes2) = decode_checkpoint_votes(&bytes).unwrap();
        assert_eq!(cp2, cp);
        assert_eq!(votes2.len(), 3);
        for v in &votes2 {
            assert!(committee.verify_vote(&cp2, v));
        }
    }

    #[test]
    fn checkpoint_votes_reject_trailing_and_truncated() {
        let (_c, validators) = devnet_committee(7);
        let cp = Checkpoint::new(2, [0xAB; 32], [0xCD; 32]);
        let votes: Vec<Vote> = validators[..2].iter().map(|v| v.sign_checkpoint(&cp)).collect();
        let bytes = encode_checkpoint_votes(&cp, &votes);

        let mut trailing = bytes.clone();
        trailing.push(0x00);
        assert!(matches!(decode_checkpoint_votes(&trailing), Err(DecodeError::Trailing { .. })));

        assert!(decode_checkpoint_votes(&bytes[..bytes.len() - 1]).is_err(), "truncated rejected");
        assert!(decode_checkpoint_votes(&[]).is_err(), "empty rejected");
    }

    /// A tiny payload claiming 2^60 votes is a truncation refusal, never a
    /// giant pre-allocation (issue #279 — the count is attacker-controlled on
    /// the peer wire). Before the cap, `Vec::with_capacity(n)` ran on the
    /// claimed count *before* the first vote read could refuse it. Shared body
    /// with `decode_checkpoint_msg`, so one test covers both aliases.
    #[test]
    fn checkpoint_votes_decode_refuses_a_count_the_bytes_cannot_hold_without_allocating() {
        let mut bytes = Vec::new();
        // checkpoint: height(8) ‖ block_hash(32) ‖ root(32)
        bytes.extend_from_slice(&2u64.to_le_bytes());
        bytes.extend_from_slice(&[0xAB; 32]);
        bytes.extend_from_slice(&[0xCD; 32]);
        write_varint(&mut bytes, 1u64 << 60); // n_votes, a lie
        assert!(matches!(
            decode_checkpoint_votes(&bytes),
            Err(DecodeError::Truncated { .. })
        ));
        // Same body path as CheckpointVotes — the alias must refuse identically.
        assert!(matches!(
            decode_checkpoint_msg(&bytes),
            Err(DecodeError::Truncated { .. })
        ));
    }

    #[test]
    fn evidence_round_trips_and_id_is_stable() {
        use qlab_devnet::ebbflow::EquivocationEvidence;
        let (committee, validators) = devnet_committee(7);
        // Signer 3 signs two conflicting checkpoints at the same height.
        let a = Checkpoint::new(8, [0xAA; 32], [0xAA; 32]);
        let b = Checkpoint::new(8, [0xBB; 32], [0xBB; 32]);
        let ev = EquivocationEvidence {
            vote_a: validators[3].sign_checkpoint(&a),
            cp_a: a,
            vote_b: validators[3].sign_checkpoint(&b),
            cp_b: b,
        };
        let bytes = encode_evidence_msg(&ev);
        let back = decode_evidence_msg(&bytes).unwrap();
        // Both decoded votes still verify against the committee.
        assert!(committee.verify_vote(&back.cp_a, &back.vote_a));
        assert!(committee.verify_vote(&back.cp_b, &back.vote_b));
        assert_eq!(back.vote_a.signer, 3);
        assert_eq!(evidence_id(&back), evidence_id(&ev));
        // Trailing byte is rejected.
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(matches!(decode_evidence_msg(&extra), Err(DecodeError::Trailing { .. })));
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
        let tx = TxEntry::with_placeholder_discovery(vec![9u8; 200], TxPublic {
            anchor: [1; 32],
            nullifiers: vec![[2; 32], [3; 32]],
            commitments: vec![[4; 32], [5; 32]],
            bucket: ArityBucket::TwoByTwo,
            fee: 1_000_000,
            });
        let bytes = encode_tx(&tx);
        let back = decode_tx(&bytes).unwrap();
        assert_eq!(back.public, tx.public);
        assert_eq!(back.proof, tx.proof);
        assert_eq!(tx_id(&back), tx_id(&tx));
    }

    /// 🔴 Issue #188: the discovery group survives the tx wire, and the body a
    /// peer rebuilds from decoded transactions commits to the same value.
    ///
    /// Without this the change is incoherent rather than merely incomplete: a
    /// transaction whose discovery is dropped in transit can be included in no
    /// valid block, and the failure would surface as a `CommitmentMismatch` at
    /// the far end of the sync path rather than here.
    #[test]
    fn the_discovery_group_survives_the_tx_wire() {
        use qlab_devnet::body::BlockBody;
        use qlab_note::wire::{ClueSlot, CompactEntry, RecipientBundle};

        let cms = vec![[4u8; 32], [5u8; 32]];
        let bundles = vec![RecipientBundle {
            ct: core::array::from_fn(|i| (i % 251) as u8),
            entries: cms
                .iter()
                .map(|cm| CompactEntry { cm: *cm, tag: [0xA5; 8], clue: ClueSlot::Empty })
                .collect(),
        }];
        let n_payloads = qlab_note::compact::contents_entry_count(&bundles);
        let tx = TxEntry::new(
            vec![9u8; 200],
            TxPublic {
                anchor: [1; 32],
                nullifiers: vec![[2; 32], [3; 32]],
                commitments: cms,
                bucket: ArityBucket::TwoByTwo,
                fee: 1_000_000,
            },
            &bundles,
            // Issue #188 (a): payloads are committed alongside the bundles.
            &vec![vec![0u8; qlab_note::compact::PAYLOAD_LEN]; n_payloads],
        );
        assert!(tx.discovery.len() > 1, "a real group is not the empty encoding");

        let back = decode_tx(&encode_tx(&tx)).unwrap();
        assert_eq!(back.discovery, tx.discovery, "discovery bytes are carried verbatim");

        let here = BlockBody::from_single_payee(vec![tx.clone()], 7, [1, 2, 3, 4]);
        let there = BlockBody::from_single_payee(vec![back], 7, [1, 2, 3, 4]);
        assert_eq!(here.commitment(), there.commitment());

        // And a peer that strips the group produces a different body — the
        // mutation this test exists to catch.
        let mut stripped = decode_tx(&encode_tx(&tx)).unwrap();
        stripped.discovery = TxEntry::empty_discovery();
        let mutated = BlockBody::from_single_payee(vec![stripped], 7, [1, 2, 3, 4]);
        assert_ne!(here.commitment(), mutated.commitment());
    }

    /// Lab #367: the tx wire's rider section, all four properties in one place:
    ///   1. a rider-free tx encodes **byte-identically** to the pre-#367 wire —
    ///      the no-relay-partition property (the #181 lesson);
    ///   2. a rider-carrying tx round-trips verbatim;
    ///   3. an explicit `[0x00]` tail is refused — absence is spelled by
    ///      omission here, so one tx has one encoding and `tx_id` stays 1:1;
    ///   4. a stripped rider changes `tx_id` — the pool cannot dedup a
    ///      registration against its stripped twin.
    #[test]
    fn the_rider_wire_is_conditional_canonical_and_identity_bearing() {
        let base = TxEntry::with_placeholder_discovery(vec![9u8; 40], TxPublic {
            anchor: [1; 32],
            nullifiers: vec![[2; 32]],
            commitments: vec![],
            bucket: ArityBucket::TwoByTwo,
            fee: 1_000_000,
        });

        // (1) rider-free = the pre-#367 bytes: the encoding ends at discovery.
        let wire = encode_tx(&base);
        let mut pre367 = Vec::new();
        pre367.extend_from_slice(&base.public.anchor);
        write_varint(&mut pre367, 1);
        pre367.extend_from_slice(&base.public.nullifiers[0]);
        write_varint(&mut pre367, 0);
        pre367.push(bucket_to_u8(base.public.bucket));
        pre367.extend_from_slice(&base.public.fee.to_le_bytes());
        write_varint(&mut pre367, base.proof.len() as u64);
        pre367.extend_from_slice(&base.proof);
        write_varint(&mut pre367, base.discovery.len() as u64);
        pre367.extend_from_slice(&base.discovery);
        assert_eq!(wire, pre367, "a rider-free tx must be byte-identical to the old wire");
        assert_eq!(decode_tx(&wire).unwrap().rider, TxEntry::absent_rider());

        // (2) a rider-carrying tx round-trips verbatim.
        let registering = base.clone().with_name_op(&qlab_devnet::names::NameOp::Commit {
            commit: [0x5A; 32],
        });
        let back = decode_tx(&encode_tx(&registering)).unwrap();
        assert_eq!(back.rider, registering.rider, "rider bytes are carried verbatim");
        assert_eq!(back.public, registering.public);
        assert_eq!(back.proof, registering.proof);
        assert_eq!(back.discovery, registering.discovery);

        // (3) an explicit absent tail is a second spelling — refused.
        let mut respelled = wire.clone();
        write_varint(&mut respelled, 1);
        respelled.push(0x00);
        assert!(
            matches!(decode_tx(&respelled), Err(DecodeError::Trailing { .. })),
            "explicit [0x00] rider tail must be refused"
        );

        // (4) the rider is identity-bearing on this wire.
        assert_ne!(tx_id(&base), tx_id(&registering));
    }

    #[test]
    fn tx_rejects_unknown_bucket() {
        let tx = TxEntry::with_placeholder_discovery(vec![], TxPublic {
            anchor: [0; 32],
            nullifiers: vec![],
            commitments: vec![],
            bucket: ArityBucket::EightByEight,
            fee: 0,
            });
        let mut bytes = encode_tx(&tx);
        // bucket byte sits after anchor(32) + n_nf(1 varint=0) + n_cm(1 varint=0).
        let bucket_pos = 32 + 1 + 1;
        bytes[bucket_pos] = 9;
        assert!(matches!(decode_tx(&bytes), Err(DecodeError::BadBucket { got: 9 })));
    }

    /// A tiny payload claiming 2^60 nullifiers is a truncation refusal, never a
    /// 2^65-byte pre-allocation (issue #275 — the counts are attacker-controlled
    /// on the peer wire, and on an HTTP body once `POST /v1/tx` serves this
    /// decoder). Before the cap, `Vec::with_capacity(n_nf)` ran on the claimed
    /// count *before* the first element read could refuse it.
    #[test]
    fn tx_decode_refuses_a_count_the_bytes_cannot_hold_without_allocating() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0u8; 32]); // anchor
        write_varint(&mut bytes, 1u64 << 60); // n_nf, a lie
        assert!(matches!(decode_tx(&bytes), Err(DecodeError::Truncated { .. })));

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0u8; 32]); // anchor
        write_varint(&mut bytes, 0); // n_nf
        write_varint(&mut bytes, 1u64 << 60); // n_cm, the same lie one field later
        assert!(matches!(decode_tx(&bytes), Err(DecodeError::Truncated { .. })));
    }

    #[test]
    fn inv_round_trips() {
        let items = vec![
            InvItem { kind: InvKind::Tx, id: [1; 32] },
            InvItem { kind: InvKind::Block, id: [2; 32] },
            InvItem { kind: InvKind::Checkpoint, id: [3; 32] },
        ];
        let bytes = encode_inv(&items);
        let got = decode_inv(&bytes).unwrap();
        assert_eq!(got.items, items);
        assert_eq!(got.unknown_kinds, 0);
    }

    /// 🔴 **Issue #181, the [`InvKind`] half.** An unknown kind is skipped and
    /// counted; the known items around it still decode. This used to be
    /// `Err(BadInvKind)`, which every caller charged `PENALTY_MALFORMED` for.
    ///
    /// The middle item is the one clobbered on purpose: skipping it must not
    /// desync the reader, or the third item would decode as garbage.
    #[test]
    fn inv_skips_an_unknown_kind_and_keeps_the_rest() {
        let items = vec![
            InvItem { kind: InvKind::Tx, id: [1; 32] },
            InvItem { kind: InvKind::Block, id: [2; 32] },
            InvItem { kind: InvKind::Checkpoint, id: [3; 32] },
        ];
        let mut bad = encode_inv(&items);
        // varint(3) is one byte, then item i starts at 1 + i*33.
        bad[1 + 33] = 0x04; // the reserved-but-unallocated CheckpointVotes code
        assert!(InvKind::from_u8(0x04).is_none(), "code 4 really is unallocated");
        let got = decode_inv(&bad).unwrap();
        assert_eq!(got.unknown_kinds, 1);
        assert_eq!(
            got.items,
            vec![items[0], items[2]],
            "the reader stepped over the unknown item without losing its place"
        );

        // A vector of nothing but unknown kinds decodes to nothing, and is still
        // not an error — the whole message is one newer peer's offer we decline.
        let mut all_unknown = encode_inv(&items);
        for i in 0..3 {
            all_unknown[1 + i * 33] = 0xFF;
        }
        let got = decode_inv(&all_unknown).unwrap();
        assert!(got.items.is_empty());
        assert_eq!(got.unknown_kinds, 3);
    }

    /// The complement, and the reason the fix is a distinction rather than a
    /// widening: an inv that is genuinely **malformed** is still `Err`.
    #[test]
    fn inv_still_rejects_malformed_bytes() {
        let items = vec![InvItem { kind: InvKind::Tx, id: [1; 32] }];
        let bytes = encode_inv(&items);

        let mut trailing = bytes.clone();
        trailing.push(0x00);
        assert!(matches!(decode_inv(&trailing), Err(DecodeError::Trailing { .. })));

        assert!(
            matches!(decode_inv(&bytes[..bytes.len() - 1]), Err(DecodeError::Truncated { .. })),
            "a truncated id is garbage, not version skew"
        );

        // A count that outruns the body: the same, even though every kind byte
        // present is fine.
        let mut over = bytes.clone();
        over[0] = 0x02;
        assert!(matches!(decode_inv(&over), Err(DecodeError::Truncated { .. })));
    }

    #[test]
    fn locator_round_trips() {
        let loc = Locator { have: vec![[1; 32], [2; 32]], stop: ZERO_HASH };
        let bytes = encode_locator(&loc);
        assert_eq!(decode_locator(&bytes).unwrap(), loc);
    }

    /// A tiny payload claiming 2^60 locator hashes is a truncation refusal,
    /// never a giant pre-allocation (issue #279 — the count is attacker-controlled
    /// on the peer wire). Before the cap, `Vec::with_capacity(n)` ran on the
    /// claimed count *before* the first hash read could refuse it.
    ///
    /// Premise note: issue #279 named this site `decode_inv` at ~line 531; on
    /// `main` that line is `decode_locator`. `decode_inv` has never used
    /// `with_capacity` (it pushes into `InvVec::default()` and fails on the
    /// first truncated element read without a giant allocation).
    #[test]
    fn locator_decode_refuses_a_count_the_bytes_cannot_hold_without_allocating() {
        let mut bytes = Vec::new();
        write_varint(&mut bytes, 1u64 << 60); // n_have, a lie
        assert!(matches!(decode_locator(&bytes), Err(DecodeError::Truncated { .. })));
    }

    #[test]
    fn headers_batch_round_trips() {
        let g = BlockHeader::genesis(1000, 0);
        let h1 = BlockHeader::child_of(&g, 75, 1000, [1; 32]);
        let h2 = BlockHeader::child_of(&h1, 150, 1000, [2; 32]);
        let batch = vec![g, h1, h2];
        let bytes = encode_headers(GenesisForm::V4, &batch);
        assert_eq!(decode_headers(GenesisForm::V4, &bytes).unwrap(), batch);
    }

    /// A tiny payload claiming 2^60 headers is a truncation refusal, never a
    /// giant pre-allocation (issue #279 — the count is attacker-controlled on
    /// the peer wire). Before the cap, `Vec::with_capacity(n)` ran on the
    /// claimed count *before* the first header read could refuse it.
    #[test]
    fn headers_decode_refuses_a_count_the_bytes_cannot_hold_without_allocating() {
        let mut bytes = Vec::new();
        write_varint(&mut bytes, 1u64 << 60); // n_headers, a lie
        assert!(matches!(decode_headers(GenesisForm::V4, &bytes), Err(DecodeError::Truncated { .. })));
    }
}
