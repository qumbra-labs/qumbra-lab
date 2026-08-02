//! Versioned message envelope — protocol-spec §0 (reject-unknown) discipline.
//!
//! Layout (`[devnet-placeholder]` shape — §10 defers P2P formats; the *discipline*
//! is what binds):
//!
//! ```text
//! MAGIC (4)        b"QMBP"  — cheap misconnection / junk-stream guard
//! version (u16 LE)          — PROTOCOL_VERSION; reject-unknown per §0
//! msg_type (u16 LE)         — MsgType; reject-unknown per §0
//! payload_len (u32 LE)      — length of the body; bounded by MAX_PAYLOAD
//! payload (payload_len)     — msg-type-specific body (see `codec` / `compact`)
//! ```
//!
//! The header is fixed 12 bytes, so a stream transport reads the header, learns
//! the exact body length, and frames one message deterministically. Everything
//! after the length prefix is authoritative: decoders reject trailing bytes,
//! truncation, unknown version, and oversize frames.
//!
//! ## An unknown *type* is not an error (issue #181)
//!
//! Framing has **three** outcomes, not two — see [`Frame`]. A type code this
//! build does not implement is not a [`WireError`]; it cannot be, because
//! [`WireError`] is the vocabulary of "the sender is at fault" and *"you are
//! running a newer build than me"* is not a fault. The two used to share
//! `WireError::UnknownMsgType`, one caller matched `Err(_)`, and an additive
//! `MsgType` therefore banned its sender on the first frame. **The variant is
//! gone so that branch cannot be written again.**

/// Envelope magic — `b"QMBP"` (Qumbra P2P). Not a protocol version; purely a
/// stream-desync / wrong-protocol guard so junk bytes fail fast rather than
/// being misparsed as a length.
pub const MAGIC: [u8; 4] = *b"QMBP";

/// The P2P protocol version (§0: NU-style versioned from v1). Peers advertising a
/// different version are rejected at handshake, and any framed message carrying a
/// different version is rejected at decode.
pub const PROTOCOL_VERSION: u16 = 1;

/// Fixed envelope-header length: MAGIC(4) + version(2) + msg_type(2) + len(4).
pub const HEADER_LEN: usize = 12;

/// Hard cap on a single message body. A DoS guard, not a spec constant — the
/// prototype never frames a full block (≈90–115 MB/block at 10 TPS, §7) in one
/// envelope; bodies move as compact blocks + per-tx fetches. Generous enough for
/// a batch of headers or a bundle of ML-DSA votes, bounded enough to reject a
/// hostile length prefix before allocating.
pub const MAX_PAYLOAD: u32 = 8 * 1024 * 1024;

/// Message types. `[devnet-placeholder]` — the *set* and *codes* are a lab
/// proposal (§10). A code this build does not implement makes
/// [`MsgType::from_u16`] return `None`, which [`Frame::from_parts`] turns into
/// [`Frame::UnknownType`] — **ignored, never scored** (issue #181).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MsgType {
    // --- connection / peer management ---
    /// Handshake offer: advertise version + services + tip height.
    Version = 0x0001,
    /// Handshake accept.
    VerAck = 0x0002,
    /// Liveness probe (carries a nonce).
    Ping = 0x0003,
    /// Liveness reply (echoes the nonce).
    Pong = 0x0004,
    /// Request the peer's address book.
    GetAddr = 0x0005,
    /// Address book response.
    Addr = 0x0006,

    // --- inventory gossip ---
    /// Announce inventory (ids the sender has).
    Inv = 0x0010,
    /// Request full objects for announced inventory ids.
    GetData = 0x0011,
    /// Report requested ids that the sender does not have.
    NotFound = 0x0012,

    // --- gossip payloads ---
    /// A single transaction (proof + public values).
    Tx = 0x0020,
    /// A single block header.
    Header = 0x0021,
    /// A finalized checkpoint together with its committee votes.
    Checkpoint = 0x0022,
    /// Equivocation evidence: two conflicting signed votes by one committee member
    /// for the same slot (committee-gov §3). Gossiped so the whole network applies
    /// the automated tombstone + slash.
    Evidence = 0x0023,
    /// A **partial** committee vote set for a checkpoint (M10-T0-5): `(Checkpoint,
    /// Vec<Vote>)`, same body as [`MsgType::Checkpoint`] but push-gossiped so nodes
    /// accumulate votes across messages to a quorum (the committee is split across
    /// nodes, so no one message carries a quorum). Body reuses the checkpoint codec.
    CheckpointVotes = 0x0024,

    // --- header-first sync ---
    /// Locator → request a batch of headers building on it.
    GetHeaders = 0x0030,
    /// A batch of headers (ancestor-first).
    Headers = 0x0031,

    // --- compact-block relay ---
    /// Relay of a protocol-spec §5 compact block (note-discovery wire), verbatim.
    CmpctBlock = 0x0040,
    /// §7 BIP-152-shape block announcement: header + short transaction ids.
    BlockAnnounce = 0x0041,
    /// Request the transactions a peer was missing from a `BlockAnnounce`.
    GetBlockTxn = 0x0042,
    /// The requested transactions.
    BlockTxn = 0x0043,
}

impl MsgType {
    /// Decode a raw code, or `None` for an unknown type (→ reject-unknown, §0).
    pub fn from_u16(v: u16) -> Option<Self> {
        use MsgType::*;
        Some(match v {
            0x0001 => Version,
            0x0002 => VerAck,
            0x0003 => Ping,
            0x0004 => Pong,
            0x0005 => GetAddr,
            0x0006 => Addr,
            0x0010 => Inv,
            0x0011 => GetData,
            0x0012 => NotFound,
            0x0020 => Tx,
            0x0021 => Header,
            0x0022 => Checkpoint,
            0x0023 => Evidence,
            0x0024 => CheckpointVotes,
            0x0030 => GetHeaders,
            0x0031 => Headers,
            0x0040 => CmpctBlock,
            0x0041 => BlockAnnounce,
            0x0042 => GetBlockTxn,
            0x0043 => BlockTxn,
            _ => return None,
        })
    }

    /// The raw wire code.
    pub fn as_u16(self) -> u16 {
        self as u16
    }
}

/// Errors from envelope framing. Reject-unknown / reject-trailing surface here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WireError {
    /// Buffer too short to hold even the fixed header, or shorter than the
    /// declared body.
    Truncated { need: usize, got: usize },
    /// Leading magic did not match — wrong protocol or a desynced stream.
    BadMagic { got: [u8; 4] },
    /// Version-tagged format carried a version we do not implement (§0).
    ///
    /// **Deliberately still an error, and issue #181 did not change it** — see
    /// [`Frame`] for the grounds and for the finding this leaves open.
    UnsupportedVersion { got: u16 },
    /// Declared body length exceeds [`MAX_PAYLOAD`].
    Oversize { got: u32, max: u32 },
    /// Bytes remained after a complete, well-formed envelope (reject-trailing).
    TrailingBytes { remaining: usize },
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WireError::Truncated { need, got } => {
                write!(f, "truncated frame: need {need} bytes, got {got}")
            }
            WireError::BadMagic { got } => write!(f, "bad magic: {got:02x?}"),
            WireError::UnsupportedVersion { got } => {
                write!(f, "unsupported protocol version {got} (want {PROTOCOL_VERSION})")
            }
            WireError::Oversize { got, max } => write!(f, "oversize frame: {got} > {max}"),
            WireError::TrailingBytes { remaining } => {
                write!(f, "trailing bytes after envelope: {remaining}")
            }
        }
    }
}

impl std::error::Error for WireError {}

/// The parsed fixed header of a frame — enough to know the body length before
/// allocating for it (used by the streaming TCP transport).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    pub version: u16,
    pub msg_type_raw: u16,
    pub payload_len: u32,
}

impl FrameHeader {
    /// Parse and validate the 12-byte header: checks magic and the length bound.
    /// Version / type validity is deferred to [`Envelope::from_parts`] so a stream
    /// reader can bound its allocation first, then reject-unknown after the body
    /// is in hand.
    pub fn parse(hdr: &[u8]) -> Result<FrameHeader, WireError> {
        if hdr.len() < HEADER_LEN {
            return Err(WireError::Truncated { need: HEADER_LEN, got: hdr.len() });
        }
        let magic: [u8; 4] = hdr[0..4].try_into().unwrap();
        if magic != MAGIC {
            return Err(WireError::BadMagic { got: magic });
        }
        let version = u16::from_le_bytes([hdr[4], hdr[5]]);
        let msg_type_raw = u16::from_le_bytes([hdr[6], hdr[7]]);
        let payload_len = u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
        if payload_len > MAX_PAYLOAD {
            return Err(WireError::Oversize { got: payload_len, max: MAX_PAYLOAD });
        }
        Ok(FrameHeader { version, msg_type_raw, payload_len })
    }
}

/// A framed protocol message: a validated type and its opaque body. The body is
/// (de)serialized by the `codec` / `compact` layers per `msg_type`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub version: u16,
    pub msg_type: MsgType,
    pub payload: Vec<u8>,
}

impl Envelope {
    /// Build an envelope at the current protocol version.
    pub fn new(msg_type: MsgType, payload: Vec<u8>) -> Envelope {
        Envelope { version: PROTOCOL_VERSION, msg_type, payload }
    }

    /// Serialize to wire bytes (a whole frame).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.msg_type.as_u16().to_le_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

}

/// **One framed inbound message, classified — and the whole point is that there
/// are three outcomes and not two** (issue #181).
///
/// | outcome | means | the sender's fault |
/// |---|---|---|
/// | `Ok(Frame::Known)` | a type this build implements | — |
/// | `Ok(Frame::UnknownType)` | **you are running a newer build than me** | **no** |
/// | `Err(WireError)` | you sent bytes I cannot parse | **yes** |
///
/// Before #181 the middle row did not exist: `MsgType::from_u16` returning `None`
/// became `WireError::UnknownMsgType`, [`crate::node::P2pNode::tick`] matched
/// `Err(_)` and charged `PENALTY_MALFORMED` (100) against a `BAN_THRESHOLD` of
/// −100 — **an instant, one-frame ban for the crime of being newer.** On a net
/// that rolls one host at a time, that made any additive `MsgType` a partition:
/// the upgraded host would be banned by every host it still needed. `issue #130`
/// (c) was authorised to add a type and declined for exactly this reason.
///
/// The separation is structural rather than behavioural on purpose. The bug
/// existed because both cases were reachable through one `Err(_)`, so the
/// unknown-type case was **removed from [`WireError`] entirely**: a future caller
/// cannot re-conflate them, because the error type can no longer say it.
///
/// ## What this does NOT cover, and it is the thing most likely to bite next
///
/// [`WireError::UnsupportedVersion`] is still an error and still scores. That is
/// deliberate and it is a narrower claim than it looks:
///
/// - an additive **type code** inside one protocol version is designed to be
///   forward-compatible — the framing is unchanged, the body is skippable
///   because its length is declared, and the receiver loses nothing by ignoring
///   it;
/// - a **version** bump is by definition a wire break, and nothing guarantees a
///   v2 frame is even framed the way this parser assumes. "Ignore it and keep
///   reading the stream" is not obviously safe there, and choosing between
///   ignore / disconnect / score is a handshake-policy decision this baton was
///   not given.
///
/// 🔴 **So the consequence stands and is reported rather than fixed: if a future
/// change bumps `PROTOCOL_VERSION` instead of adding a type code, it partitions a
/// rolling upgrade exactly the way #181 describes, and this fix does not help.**
/// There is also no separate handshake version check to fall back on — `peer.rs`
/// says the guarantee "is enforced one layer down, at `crate::wire` decode", and
/// that decode is this one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    /// A type this build implements. Dispatch it.
    Known(Envelope),
    /// A well-formed frame at **our** protocol version whose type code this build
    /// does not implement. Ignore it; count it; never score it.
    ///
    /// The body is dropped rather than carried: we cannot parse it (that is what
    /// unknown means) and holding it would only invite someone to try.
    UnknownType {
        /// The raw code, so the counter can say *what* the newer peer is speaking.
        msg_type_raw: u16,
        /// The body length we skipped — an unknown type is still framed, because
        /// the length prefix is type-independent.
        payload_len: usize,
    },
}

impl Frame {
    /// Classify a validated header + already-read body. Version is reject-unknown
    /// (§0); type is reject-unknown *without* being an error (issue #181).
    pub fn from_parts(header: FrameHeader, payload: Vec<u8>) -> Result<Frame, WireError> {
        if header.version != PROTOCOL_VERSION {
            return Err(WireError::UnsupportedVersion { got: header.version });
        }
        match MsgType::from_u16(header.msg_type_raw) {
            Some(msg_type) => {
                Ok(Frame::Known(Envelope { version: header.version, msg_type, payload }))
            }
            None => Ok(Frame::UnknownType {
                msg_type_raw: header.msg_type_raw,
                payload_len: payload.len(),
            }),
        }
    }

    /// Decode exactly one frame from a whole-frame buffer. Rejects truncation and
    /// trailing bytes (the transport delivers one frame per buffer).
    pub fn decode(buf: &[u8]) -> Result<Frame, WireError> {
        let header = FrameHeader::parse(buf)?;
        let total = HEADER_LEN + header.payload_len as usize;
        if buf.len() < total {
            return Err(WireError::Truncated { need: total, got: buf.len() });
        }
        if buf.len() > total {
            return Err(WireError::TrailingBytes { remaining: buf.len() - total });
        }
        Frame::from_parts(header, buf[HEADER_LEN..total].to_vec())
    }

    /// The envelope, if this build implements the type. Convenience for tests and
    /// for readers that only care about known traffic.
    pub fn known(&self) -> Option<&Envelope> {
        match self {
            Frame::Known(e) => Some(e),
            Frame::UnknownType { .. } => None,
        }
    }

    /// The message type, if this build implements it.
    pub fn msg_type(&self) -> Option<MsgType> {
        self.known().map(|e| e.msg_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_all_msg_types() {
        for raw in [
            0x0001u16, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0010, 0x0011, 0x0012, 0x0020,
            0x0021, 0x0022, 0x0023, 0x0024, 0x0030, 0x0031, 0x0040, 0x0041, 0x0042, 0x0043,
        ] {
            let mt = MsgType::from_u16(raw).expect("known type");
            assert_eq!(mt.as_u16(), raw);
            let env = Envelope::new(mt, vec![1, 2, 3, 4, 5]);
            let bytes = env.encode();
            assert_eq!(Frame::decode(&bytes).unwrap(), Frame::Known(env));
        }
    }

    #[test]
    fn golden_header_bytes() {
        // Lock the exact 12-byte header for a Version(0x0001) frame with a 5-byte
        // body: MAGIC "QMBP" ‖ ver=1 LE ‖ type=1 LE ‖ len=5 LE. Any drift here is a
        // wire break and MUST be an explicit, versioned change.
        let env = Envelope::new(MsgType::Version, vec![0xAA; 5]);
        let bytes = env.encode();
        assert_eq!(
            &bytes[..HEADER_LEN],
            &[0x51, 0x4D, 0x42, 0x50, 0x01, 0x00, 0x01, 0x00, 0x05, 0x00, 0x00, 0x00]
        );
        assert_eq!(bytes.len(), HEADER_LEN + 5);
    }

    #[test]
    fn golden_checkpoint_votes_header_bytes() {
        // Lock the exact 12-byte header for a CheckpointVotes(0x0024) frame with a
        // 5-byte body: MAGIC "QMBP" ‖ ver=1 LE ‖ type=0x0024 LE ‖ len=5 LE. The wire
        // code is coordinator-allocated (task-book S2); drift here is a wire break.
        let env = Envelope::new(MsgType::CheckpointVotes, vec![0xAA; 5]);
        let bytes = env.encode();
        assert_eq!(
            &bytes[..HEADER_LEN],
            &[0x51, 0x4D, 0x42, 0x50, 0x01, 0x00, 0x24, 0x00, 0x05, 0x00, 0x00, 0x00]
        );
        assert_eq!(MsgType::from_u16(0x0024), Some(MsgType::CheckpointVotes));
        assert_eq!(MsgType::CheckpointVotes.as_u16(), 0x0024);
    }

    #[test]
    fn empty_payload_round_trips() {
        let env = Envelope::new(MsgType::VerAck, vec![]);
        let bytes = env.encode();
        assert_eq!(bytes.len(), HEADER_LEN);
        assert_eq!(Frame::decode(&bytes).unwrap(), Frame::Known(env));
    }

    #[test]
    fn reject_unknown_version() {
        let mut bytes = Envelope::new(MsgType::Version, vec![]).encode();
        bytes[4] = 0x02; // version 2
        assert_eq!(Frame::decode(&bytes), Err(WireError::UnsupportedVersion { got: 2 }));
    }

    /// **Issue #181 at the framing layer: an unknown type is `Ok`, not `Err`.**
    ///
    /// The assertion that carries the fix is not the returned variant, it is that
    /// no [`WireError`] is produced at all — the caller that used to ban on
    /// `Err(_)` now has nothing to ban on. The body is skipped by its declared
    /// length, which is what makes ignoring safe: the frame is still framed.
    #[test]
    fn an_unknown_msg_type_is_a_frame_outcome_and_not_an_error() {
        let mut bytes = Envelope::new(MsgType::Version, vec![7; 5]).encode();
        bytes[6] = 0xFF; // type 0x00FF, unassigned
        bytes[7] = 0x00;
        assert!(MsgType::from_u16(0x00FF).is_none(), "0x00FF really is unallocated");
        assert_eq!(
            Frame::decode(&bytes),
            Ok(Frame::UnknownType { msg_type_raw: 0x00FF, payload_len: 5 }),
            "a newer peer's type code is an outcome, never a WireError"
        );
        let f = Frame::decode(&bytes).unwrap();
        assert!(f.known().is_none());
        assert_eq!(f.msg_type(), None);
    }

    /// The complement: **the frames that ARE the sender's fault still are.** These
    /// four are the whole of `WireError` besides `UnsupportedVersion`, and every
    /// one of them is bytes this node cannot parse under any type it knows.
    #[test]
    fn malformed_framing_is_still_an_error_for_every_case() {
        let mut bad_magic = Envelope::new(MsgType::Ping, vec![]).encode();
        bad_magic[0] = b'X';
        assert!(matches!(Frame::decode(&bad_magic), Err(WireError::BadMagic { .. })));

        let mut trailing = Envelope::new(MsgType::Pong, vec![9, 9]).encode();
        trailing.push(0x00);
        assert_eq!(Frame::decode(&trailing), Err(WireError::TrailingBytes { remaining: 1 }));

        let full = Envelope::new(MsgType::Tx, vec![1, 2, 3, 4]).encode();
        assert!(matches!(
            Frame::decode(&full[..full.len() - 1]),
            Err(WireError::Truncated { .. })
        ));

        let mut oversize = Vec::new();
        oversize.extend_from_slice(&MAGIC);
        oversize.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        oversize.extend_from_slice(&MsgType::Tx.as_u16().to_le_bytes());
        oversize.extend_from_slice(&(MAX_PAYLOAD + 1).to_le_bytes());
        assert!(matches!(Frame::decode(&oversize), Err(WireError::Oversize { .. })));

        // And the distinction holds when both are wrong at once: garbage framing
        // wins, because we never got far enough to read a type code.
        let mut both = Envelope::new(MsgType::Ping, vec![]).encode();
        both[0] = b'X';
        both[6] = 0xFF;
        assert!(matches!(Frame::decode(&both), Err(WireError::BadMagic { .. })));
    }

    #[test]
    fn reject_oversize_length_prefix() {
        // Hand-craft a header whose declared length exceeds MAX_PAYLOAD, so the
        // guard fires before any allocation of the body.
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&MAGIC);
        hdr.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        hdr.extend_from_slice(&MsgType::Tx.as_u16().to_le_bytes());
        hdr.extend_from_slice(&(MAX_PAYLOAD + 1).to_le_bytes());
        assert_eq!(
            FrameHeader::parse(&hdr),
            Err(WireError::Oversize { got: MAX_PAYLOAD + 1, max: MAX_PAYLOAD })
        );
    }
}
