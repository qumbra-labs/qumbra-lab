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
//! truncation, unknown version, unknown type, and oversize frames.

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
/// proposal (§10). Unknown codes are reject-unknown (§0): [`MsgType::from_u16`]
/// returns `None`, and [`Envelope::from_parts`] turns that into
/// [`WireError::UnknownMsgType`].
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
    UnsupportedVersion { got: u16 },
    /// Message-type code is not one we implement (§0 reject-unknown).
    UnknownMsgType { got: u16 },
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
            WireError::UnknownMsgType { got } => write!(f, "unknown message type 0x{got:04x}"),
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

    /// Reassemble a validated header + already-read body into an envelope,
    /// applying reject-unknown on version and type (§0).
    pub fn from_parts(header: FrameHeader, payload: Vec<u8>) -> Result<Envelope, WireError> {
        if header.version != PROTOCOL_VERSION {
            return Err(WireError::UnsupportedVersion { got: header.version });
        }
        let msg_type = MsgType::from_u16(header.msg_type_raw)
            .ok_or(WireError::UnknownMsgType { got: header.msg_type_raw })?;
        Ok(Envelope { version: header.version, msg_type, payload })
    }

    /// Decode exactly one envelope from a whole-frame buffer. Rejects truncation
    /// and trailing bytes (the transport delivers one frame per buffer).
    pub fn decode(buf: &[u8]) -> Result<Envelope, WireError> {
        let header = FrameHeader::parse(buf)?;
        let total = HEADER_LEN + header.payload_len as usize;
        if buf.len() < total {
            return Err(WireError::Truncated { need: total, got: buf.len() });
        }
        if buf.len() > total {
            return Err(WireError::TrailingBytes { remaining: buf.len() - total });
        }
        let payload = buf[HEADER_LEN..total].to_vec();
        Envelope::from_parts(header, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_all_msg_types() {
        for raw in [
            0x0001u16, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0010, 0x0011, 0x0012, 0x0020,
            0x0021, 0x0022, 0x0030, 0x0031, 0x0040, 0x0041, 0x0042, 0x0043,
        ] {
            let mt = MsgType::from_u16(raw).expect("known type");
            assert_eq!(mt.as_u16(), raw);
            let env = Envelope::new(mt, vec![1, 2, 3, 4, 5]);
            let bytes = env.encode();
            assert_eq!(Envelope::decode(&bytes).unwrap(), env);
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
    fn empty_payload_round_trips() {
        let env = Envelope::new(MsgType::VerAck, vec![]);
        let bytes = env.encode();
        assert_eq!(bytes.len(), HEADER_LEN);
        assert_eq!(Envelope::decode(&bytes).unwrap(), env);
    }

    #[test]
    fn reject_unknown_version() {
        let mut bytes = Envelope::new(MsgType::Version, vec![]).encode();
        bytes[4] = 0x02; // version 2
        assert_eq!(Envelope::decode(&bytes), Err(WireError::UnsupportedVersion { got: 2 }));
    }

    #[test]
    fn reject_unknown_msg_type() {
        let mut bytes = Envelope::new(MsgType::Version, vec![]).encode();
        bytes[6] = 0xFF; // type 0x00FF, unassigned
        bytes[7] = 0x00;
        assert_eq!(Envelope::decode(&bytes), Err(WireError::UnknownMsgType { got: 0x00FF }));
        assert!(MsgType::from_u16(0x00FF).is_none());
    }

    #[test]
    fn reject_bad_magic() {
        let mut bytes = Envelope::new(MsgType::Ping, vec![]).encode();
        bytes[0] = b'X';
        match Envelope::decode(&bytes) {
            Err(WireError::BadMagic { .. }) => {}
            other => panic!("expected BadMagic, got {other:?}"),
        }
    }

    #[test]
    fn reject_trailing_bytes() {
        let mut bytes = Envelope::new(MsgType::Pong, vec![9, 9]).encode();
        bytes.push(0x00); // one byte too many
        assert_eq!(Envelope::decode(&bytes), Err(WireError::TrailingBytes { remaining: 1 }));
    }

    #[test]
    fn reject_truncated_body() {
        let bytes = Envelope::new(MsgType::Tx, vec![1, 2, 3, 4]).encode();
        let short = &bytes[..bytes.len() - 1];
        match Envelope::decode(short) {
            Err(WireError::Truncated { .. }) => {}
            other => panic!("expected Truncated, got {other:?}"),
        }
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
