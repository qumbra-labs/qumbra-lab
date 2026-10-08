//! **The served chain** (lab #850, AD1): the two discovery-listener routes a
//! light client verifies a chain with — `GET /v1/headers?from=&to=` and
//! `GET /v1/block/{h}/body` — as one encoder and one strict reader each.
//!
//! **No new block or header encoding.** Each answer is a short versioned
//! prefix over a frame this crate already speaks to peers:
//!
//! ```text
//! /v1/headers        ver(u8 = 1) ‖ wire_form(u8) ‖ from(u64 LE) ‖ encode_wire_headers(form, units)
//! /v1/block/{h}/body ver(u8 = 1) ‖ wire_form(u8) ‖ height(u64 LE) ‖ encode_announce_for(wf, whole_block_announce(..))
//! ```
//!
//! - A **header unit** is the net's header message unit
//!   ([`crate::codec::header_msg_len`]): the bare L1 header, or the Annulet
//!   **sealed** header (3,462 B: the header and the sequencer's ML-DSA-65
//!   seal). An L1 unit carries no seal — there is none to carry — so a reader
//!   that wants one on L1 gets [`ServedError::NoSealOnThisForm`], by name.
//! - A **body answer** is the historical-body frame a node already serves a
//!   peer ([`crate::node::whole_block_announce`]): every transaction
//!   prefilled, no short ids, the V6 sections inline. The reader refuses short
//!   ids and gapped or reordered prefilled indices, so the body it rebuilds
//!   ([`crate::node::announced_body`]) is the block's, or nothing.
//!
//! **Why the prefix.** The frames do not name their own form, and both forms'
//! header units differ in length, so a reader told the wrong form would fail
//! deep inside a decoder with a message about lengths. The `wire_form` byte
//! makes that a named refusal ([`ServedError::WrongForm`]) before a frame byte
//! is read; `from` / `height` let the reader check the answer is the one it
//! asked for. The version byte is this pair of routes' own (a pure route
//! addition, PR #315's rule: `RPC_VERSION` does not move).
//!
//! **Bounds.** A headers page holds at most [`MAX_HEADERS_PAGE`] units (an
//! Annulet page at the bound is 256 × 3,462 B ≈ 0.85 MiB). A body answer is
//! bounded by [`crate::node::MAX_SERVED_BODY_BYTES`], the bound the node
//! already applies to a body it serves a peer; the reader refuses a longer
//! one before decoding.

use qlab_devnet::forms::{BodySections, GenesisForm, L2AuthForm};

use crate::codec::{decode_wire_headers, encode_wire_headers, DecodeError, WireHeader};
use crate::compact::{decode_announce_for, encode_announce_for, AnnounceEncodeError, BlockAnnounce, WireForm};

/// The only version of either answer this build writes and reads.
pub const SERVED_CHAIN_VERSION: u8 = 1;

/// `GET /v1/headers?from=&to=` — a contiguous page of header units.
pub const HEADERS_PATH: &str = "/v1/headers";

/// `GET /v1/block/{h}/body` — one whole block in the historical-body frame.
pub const BODY_PATH_SHAPE: &str = "/v1/block/{h}/body";

/// The most header units one page carries.
pub const MAX_HEADERS_PAGE: usize = 256;

/// The wire-form byte: which header units and which body frame follow.
pub fn wire_form_byte(wf: WireForm) -> u8 {
    match (wf.form, wf.sections, wf.l2_auth) {
        (GenesisForm::V4, BodySections::None, L2AuthForm::None) => 1,
        (GenesisForm::V5, BodySections::None, L2AuthForm::None) => 2,
        (GenesisForm::Annulet, BodySections::None, L2AuthForm::None) => 3,
        (GenesisForm::V5, BodySections::V6, L2AuthForm::None) => 4,
        // Lab #896 E2: the Candidate A Annulet — node-to-node bodies carry
        // each transaction's auth section, so its frame is its own form.
        (GenesisForm::Annulet, BodySections::None, L2AuthForm::CandidateA) => 5,
        // Lab #937: the format-34 Annulet (three-output S/P) — the Candidate A
        // frame, under its own byte so a format-33 reader refuses it by name.
        (GenesisForm::Annulet, BodySections::None, L2AuthForm::CandidateAV3) => 6,
        (form, sections, auth) => panic!("no served wire form for {form:?} with {sections:?} / {auth:?} (lab #850)"),
    }
}

fn wire_form_of(b: u8) -> Option<WireForm> {
    match b {
        1 => Some(WireForm::plain(GenesisForm::V4)),
        2 => Some(WireForm::plain(GenesisForm::V5)),
        3 => Some(WireForm::plain(GenesisForm::Annulet)),
        4 => Some(WireForm::V6),
        5 => Some(WireForm::ANNULET_AUTH),
        6 => Some(WireForm::ANNULET_AUTH_V3),
        _ => None,
    }
}

/// Why a served-chain answer was refused — each by name, never a panic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServedError {
    /// Shorter than its fixed prefix.
    Truncated,
    /// A version this build does not read.
    UnknownVersion { got: u8 },
    /// A wire-form byte that names no form.
    UnknownForm { got: u8 },
    /// The answer is for another net's form than the reader's.
    WrongForm { want: u8, got: u8 },
    /// A seal was asked of a form that has none (every L1 form).
    NoSealOnThisForm,
    /// The headers page starts elsewhere than asked.
    WrongFrom { want: u64, got: u64 },
    /// The body answer is for another height than asked.
    WrongHeight { want: u64, got: u64 },
    /// More header units than [`MAX_HEADERS_PAGE`].
    PageTooLong { got: usize },
    /// A body answer longer than [`crate::node::MAX_SERVED_BODY_BYTES`].
    BodyTooLong { got: usize },
    /// The body frame uses short ids: it is a relay announce, not a whole block.
    ShortIdsInBody { got: usize },
    /// The prefilled indices are not exactly `0, 1, …, n−1` in order.
    PrefilledNotWhole { at: usize, index: u32 },
    /// The frame after the prefix did not decode.
    Frame(DecodeError),
}

impl std::fmt::Display for ServedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServedError::Truncated => write!(f, "served-chain answer shorter than its prefix"),
            ServedError::UnknownVersion { got } => {
                write!(f, "served-chain answer version {got}; this build reads only {SERVED_CHAIN_VERSION}")
            }
            ServedError::UnknownForm { got } => write!(f, "served-chain answer names no form ({got})"),
            ServedError::WrongForm { want, got } => {
                write!(f, "served-chain answer is for wire form {got}, this reader's net is {want}")
            }
            ServedError::NoSealOnThisForm => write!(f, "an L1 header carries no seal: there is none to verify"),
            ServedError::WrongFrom { want, got } => write!(f, "headers page starts at {got}, asked from {want}"),
            ServedError::WrongHeight { want, got } => write!(f, "body answer is for height {got}, asked {want}"),
            ServedError::PageTooLong { got } => write!(f, "headers page of {got} units exceeds {MAX_HEADERS_PAGE}"),
            ServedError::BodyTooLong { got } => {
                write!(f, "body answer of {got} B exceeds {} B", crate::node::MAX_SERVED_BODY_BYTES)
            }
            ServedError::ShortIdsInBody { got } => {
                write!(f, "body answer carries {got} short id(s): a relay announce, not a whole block")
            }
            ServedError::PrefilledNotWhole { at, index } => {
                write!(f, "body answer's prefilled entry {at} is index {index}: not every transaction, in order")
            }
            ServedError::Frame(e) => write!(f, "served-chain frame does not decode: {e:?}"),
        }
    }
}

impl std::error::Error for ServedError {}

fn prefix(wf: WireForm, at: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    out.push(SERVED_CHAIN_VERSION);
    out.push(wire_form_byte(wf));
    out.extend_from_slice(&at.to_le_bytes());
    out
}

/// Read the prefix: version, form (must be `want`), and the `u64` after it.
fn read_prefix(want: WireForm, buf: &[u8]) -> Result<(u64, &[u8]), ServedError> {
    if buf.len() < 10 {
        return Err(ServedError::Truncated);
    }
    if buf[0] != SERVED_CHAIN_VERSION {
        return Err(ServedError::UnknownVersion { got: buf[0] });
    }
    if wire_form_of(buf[1]).is_none() {
        return Err(ServedError::UnknownForm { got: buf[1] });
    }
    let want_b = wire_form_byte(want);
    if buf[1] != want_b {
        return Err(ServedError::WrongForm { want: want_b, got: buf[1] });
    }
    let at = u64::from_le_bytes(buf[2..10].try_into().expect("8 bytes"));
    Ok((at, &buf[10..]))
}

/// Encode a headers page starting at `from`. Units must be of `wf`'s kind (a
/// locally-built mismatch panics, as [`encode_wire_headers`] does).
pub fn encode_headers_page(wf: WireForm, from: u64, units: &[WireHeader]) -> Vec<u8> {
    assert!(units.len() <= MAX_HEADERS_PAGE, "a headers page holds at most {MAX_HEADERS_PAGE} units");
    let mut out = prefix(wf, from);
    out.extend_from_slice(&encode_wire_headers(wf.form, units));
    out
}

/// Decode a headers page asked for `from` on a net of form `wf`. An empty page
/// is "this node holds no main-chain height from `from` on" — a fact, not an
/// error. Contiguity and seals are the verifier's: this reads bytes.
pub fn decode_headers_page(wf: WireForm, from: u64, buf: &[u8]) -> Result<Vec<WireHeader>, ServedError> {
    let (got, rest) = read_prefix(wf, buf)?;
    if got != from {
        return Err(ServedError::WrongFrom { want: from, got });
    }
    let units = decode_wire_headers(wf.form, rest).map_err(ServedError::Frame)?;
    if units.len() > MAX_HEADERS_PAGE {
        return Err(ServedError::PageTooLong { got: units.len() });
    }
    Ok(units)
}

/// The sealed header of a unit, or why there is none.
pub fn sealed(unit: &WireHeader) -> Result<&qlab_devnet::annulet::SealedHeader, ServedError> {
    match unit {
        WireHeader::Sealed(s) => Ok(s),
        WireHeader::L1(_) => Err(ServedError::NoSealOnThisForm),
    }
}

/// Encode one whole block's body answer at `height`.
pub fn encode_body_answer(wf: WireForm, height: u64, ann: &BlockAnnounce) -> Result<Vec<u8>, AnnounceEncodeError> {
    let mut out = prefix(wf, height);
    out.extend_from_slice(&encode_announce_for(wf, ann)?);
    Ok(out)
}

/// Decode a body answer asked for `height` on a net of form `wf`: the
/// announce, refused unless it is a whole block (no short ids, every
/// transaction prefilled in index order).
pub fn decode_body_answer(wf: WireForm, height: u64, buf: &[u8]) -> Result<BlockAnnounce, ServedError> {
    if buf.len() > crate::node::MAX_SERVED_BODY_BYTES + 10 {
        return Err(ServedError::BodyTooLong { got: buf.len() });
    }
    let (got, rest) = read_prefix(wf, buf)?;
    if got != height {
        return Err(ServedError::WrongHeight { want: height, got });
    }
    let ann = decode_announce_for(wf, rest).map_err(ServedError::Frame)?;
    if !ann.short_ids.is_empty() {
        return Err(ServedError::ShortIdsInBody { got: ann.short_ids.len() });
    }
    if let Some((at, p)) = ann.prefilled.iter().enumerate().find(|(i, p)| p.index as usize != *i) {
        return Err(ServedError::PrefilledNotWhole { at, index: p.index });
    }
    Ok(ann)
}

/// The body a whole-block answer carries (its prefilled transactions in
/// order, its coinbase and sections) — what the reader recomputes the
/// header's `tx_body_commitment` over.
pub fn body_of(ann: &BlockAnnounce) -> qlab_devnet::body::BlockBody {
    crate::node::announced_body(ann, ann.prefilled.iter().map(|p| p.tx.clone()).collect())
}

/// **The golden fixture** (lab #850 AD1): one deterministic sealed header
/// page and one whole-block body answer, built from fixed seeds, for the
/// golden-vector tests here and the `ad_goldens` example that computes the
/// literals. The lane recomputes them; it never trusts the example.
#[doc(hidden)]
pub mod fixture {
    use super::*;
    use qlab_devnet::annulet::{AnnuletHeaderFields, L2ShapeTag, L2Surface, SequencerKey};
    use qlab_devnet::body::{BlockBody, TxEntry, TxPublic};
    use qlab_devnet::fees::ArityBucket;
    use qlab_devnet::header::BlockHeader;

    /// The Annulet wire form.
    pub const AN: WireForm = WireForm::plain(GenesisForm::Annulet);

    fn ext() -> AnnuletHeaderFields {
        AnnuletHeaderFields { l1_anchor_height: 0, l1_anchor_root: [0; 32], registry_root: [7; 32] }
    }

    /// One Annulet transaction with an S surface and a placeholder group.
    pub fn tx() -> TxEntry {
        let public = TxPublic {
            anchor: [0x0A; 32],
            nullifiers: vec![[0x11; 32], [0x12; 32], [0x13; 32]],
            commitments: vec![[0x21; 32], [0x22; 32]],
            bucket: ArityBucket::TwoByTwo,
            fee: 1,
        };
        let discovery = qlab_devnet::annulet::placeholder_discovery_annulet(&public.commitments);
        let surface = L2Surface { shape: L2ShapeTag::S, registry_root: [7; 32], vpublic: None, write: None, exit_rkm: [0; 32] };
        TxEntry { auth: qlab_devnet::annulet::L2_AUTH_ABSENT.to_vec(), proof: vec![0xAB; 64], public, discovery, rider: TxEntry::absent_rider(), l2: surface.encode() }
    }

    /// Heights 1 and 2 over a fixed genesis, sealed under seed `[0x5E; 32]`;
    /// height 2 carries [`tx`].
    pub fn chain() -> (Vec<WireHeader>, BlockBody) {
        let key = SequencerKey::from_seed([0x5E; 32]);
        let g = BlockHeader::genesis_annulet(ext(), [1; 32], 0);
        let empty = BlockBody::default();
        let h1 = BlockHeader::child_of_annulet(&g, 10, ext(), qlab_devnet::annulet::body_commitment_annulet(&empty));
        let body = BlockBody { txs: vec![tx()], ..BlockBody::default() };
        let h2 = BlockHeader::child_of_annulet(&h1, 20, ext(), qlab_devnet::annulet::body_commitment_annulet(&body));
        (vec![WireHeader::Sealed(key.seal(h1)), WireHeader::Sealed(key.seal(h2))], body)
    }

    /// The `/v1/headers?from=1&to=2` answer over [`chain`].
    pub fn headers_page() -> Vec<u8> {
        encode_headers_page(AN, 1, &chain().0)
    }

    /// The `/v1/block/2/body` answer over [`chain`].
    pub fn body_answer() -> Vec<u8> {
        let (units, body) = chain();
        let ann = crate::node::whole_block_announce(units[1].clone(), body);
        encode_body_answer(AN, 2, &ann).expect("an Annulet body encodes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_devnet::annulet::{AnnuletHeaderFields, SequencerKey};
    use qlab_devnet::body::BlockBody;
    use qlab_devnet::header::BlockHeader;

    fn sealed_unit(height: u64) -> WireHeader {
        let key = SequencerKey::from_seed([0x5E; 32]);
        let g = BlockHeader::genesis_annulet(
            AnnuletHeaderFields { l1_anchor_height: 0, l1_anchor_root: [0; 32], registry_root: [7; 32] },
            [1; 32],
            0,
        );
        let ext = AnnuletHeaderFields { l1_anchor_height: 0, l1_anchor_root: [0; 32], registry_root: [7; 32] };
        let mut h = BlockHeader::child_of_annulet(&g, 10 * height, ext, [2; 32]);
        h.height = height;
        WireHeader::Sealed(key.seal(h))
    }

    const AN: WireForm = WireForm::plain(GenesisForm::Annulet);

    #[test]
    fn a_headers_page_round_trips_and_names_its_start() {
        let units = vec![sealed_unit(1), sealed_unit(2)];
        let bytes = encode_headers_page(AN, 1, &units);
        assert_eq!(bytes[0], SERVED_CHAIN_VERSION);
        assert_eq!(decode_headers_page(AN, 1, &bytes).unwrap(), units);
        assert_eq!(decode_headers_page(AN, 2, &bytes), Err(ServedError::WrongFrom { want: 2, got: 1 }));
        let empty = encode_headers_page(AN, 9, &[]);
        assert_eq!(decode_headers_page(AN, 9, &empty).unwrap(), Vec::new());
    }

    #[test]
    fn every_prefix_and_any_trailing_byte_is_refused_never_a_panic() {
        let bytes = encode_headers_page(AN, 1, &[sealed_unit(1)]);
        for n in 0..bytes.len() {
            assert!(decode_headers_page(AN, 1, &bytes[..n]).is_err(), "prefix {n}");
        }
        let mut long = bytes.clone();
        long.push(0);
        assert!(decode_headers_page(AN, 1, &long).is_err());
    }

    #[test]
    fn the_wrong_version_or_form_is_refused_by_name() {
        let mut bytes = encode_headers_page(AN, 1, &[sealed_unit(1)]);
        let v5 = WireForm::plain(GenesisForm::V5);
        assert_eq!(decode_headers_page(v5, 1, &bytes), Err(ServedError::WrongForm { want: 2, got: 3 }));
        bytes[1] = 9;
        assert_eq!(decode_headers_page(AN, 1, &bytes), Err(ServedError::UnknownForm { got: 9 }));
        bytes[0] = 2;
        assert_eq!(decode_headers_page(AN, 1, &bytes), Err(ServedError::UnknownVersion { got: 2 }));
    }

    /// **Golden vectors, one per route** (lab #850 condition (f)): the keccak
    /// of each answer over [`fixture::chain`], and its length. Literals from
    /// the named `ad_goldens` run; this test recomputes them, and if the two
    /// ever disagree the test is right and the literal changes in a commit
    /// that says why.
    #[test]
    fn golden_headers_page_and_body_answer() {
        let page = fixture::headers_page();
        let body = fixture::body_answer();
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!((page.len(), hex(&qlab_devnet::hash::keccak256(&page))), (GOLDEN_HEADERS_LEN, GOLDEN_HEADERS_KECCAK.to_string()));
        assert_eq!((body.len(), hex(&qlab_devnet::hash::keccak256(&body))), (GOLDEN_BODY_LEN, GOLDEN_BODY_KECCAK.to_string()));
        // And each decodes to the chain it was built from.
        let (units, b) = fixture::chain();
        assert_eq!(decode_headers_page(fixture::AN, 1, &page).unwrap(), units);
        let Ok(ann) = decode_body_answer(fixture::AN, 2, &body) else { panic!("the golden body decodes") };
        assert_eq!(qlab_devnet::annulet::body_commitment_annulet(&body_of(&ann)), qlab_devnet::annulet::body_commitment_annulet(&b));
        assert_eq!(ann.header, units[1].header());
    }

    const GOLDEN_HEADERS_LEN: usize = 6935;
    const GOLDEN_HEADERS_KECCAK: &str = "32d382f3bc30faa5a0bd1bf6f9df2b251efcc0a3f9d7e0aec18ab36ea29351dd";
    const GOLDEN_BODY_LEN: usize = 5217;
    const GOLDEN_BODY_KECCAK: &str = "4475ff1961823112712cfc0df44a25e2b507f817731de9e57f85aa379f11d586";

    #[test]
    fn an_l1_unit_has_no_seal_by_name() {
        let h = BlockHeader::genesis(1, 0);
        assert_eq!(sealed(&WireHeader::L1(h)).unwrap_err(), ServedError::NoSealOnThisForm);
        assert!(sealed(&sealed_unit(1)).is_ok());
    }

    #[test]
    fn a_body_answer_round_trips_and_refuses_a_relay_announce() {
        let unit = sealed_unit(3);
        let ann = crate::node::whole_block_announce(unit.clone(), BlockBody::default());
        let bytes = encode_body_answer(AN, 3, &ann).unwrap();
        let Ok(back) = decode_body_answer(AN, 3, &bytes) else { panic!("a whole block decodes") };
        assert_eq!(back.header, unit.header());
        assert_eq!(decode_body_answer(AN, 4, &bytes).err(), Some(ServedError::WrongHeight { want: 4, got: 3 }));
        let mut relay = ann.clone();
        relay.short_ids.push([0; crate::compact::SHORTID_LEN]);
        let bytes = encode_body_answer(AN, 3, &relay).unwrap();
        assert_eq!(decode_body_answer(AN, 3, &bytes).err(), Some(ServedError::ShortIdsInBody { got: 1 }));
    }
}
