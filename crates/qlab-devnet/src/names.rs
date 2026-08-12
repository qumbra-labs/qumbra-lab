//! The name-service rider: parameters, grammar, codec, and fees (lab #367).
//!
//! Design walls, all STAMPED and none of them this module's to move:
//! `name-service-decision.md` D1–D4 (on-chain only · bulk-sync/local-resolve ·
//! dedicated diversified address · T2 placement) and `name-service-t2-brief.md`
//! N1–N7. Task book: `docs/prompts/name-service-taskbook-DRAFT.md`.
//!
//! # INERT AT MERGE
//!
//! [`NAME_RULE_BOUNDARY_HEIGHT`] is `None` — the emission gate's pins-unset
//! precedent. With no boundary, riders are invalid at every height, the body
//! commitment is the v2 encoding everywhere, and this module changes nothing
//! about the running chain. The boundary height is Larry's stamp at T2 arming
//! time and arrives through the #74/#81 halt-marker machinery, exactly like
//! `RULE_BOUNDARY_HEIGHT` did (D4's activation ordering, kept).
//!
//! # What a rider is
//!
//! One optional name operation per transaction, carried as **committed bytes**
//! on [`crate::body::TxEntry`] under `discovery`'s exact discipline: held as
//! bytes so the canonicity rule ("decode canonically and re-encode to
//! yourself") is checkable against the wire, canonical absence is `[0x00]`
//! (one well-formed way to say nothing — a zero-length field would be a second
//! spelling; see `TxEntry::discovery`'s note). The circuit never sees any of
//! this: every rule here is plain consensus code over public bytes (N5).
//!
//! # Grammar (N3, narrow on purpose)
//!
//! `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$` with `--` refused at positions 3–4
//! (0-indexed 2–3 — the punycode/`xn--` shape, the ENSIP-15 move). Bytes, not
//! chars: nothing above 0x7f is reachable. Widening is a **versioned door at a
//! later boundary** — a builder widening this grammar is a stop point, not a
//! judgment call. `0/o 1/l` confusables pass **by design**: that residue is
//! D3's fingerprint's to carry, and the test saying so is named for it.

use crate::hash::keccak256;
use crate::header::Hash32;

// ---------------------------------------------------------------------------
// Parameters (task book §2 — PROPOSED values, ratified at merge per lab #367;
// absolute numbers revisable only at halt-height boundaries thereafter)
// ---------------------------------------------------------------------------

/// The halt-height boundary above which riders become valid and the body
/// commitment switches to its v3 encoding. **`None` = never** — merged inert.
///
/// Mirrors `emission_exact::RULE_BOUNDARY_HEIGHT`'s role exactly; the
/// `*_above` function variants are the drill seam, this constant is the
/// shipped rule.
pub const NAME_RULE_BOUNDARY_HEIGHT: Option<u64> = None;

/// One bessel-denominated QMB (fees.rs precedent: 0.01 QMB = 10⁶ bessel).
/// Cross-locked against `posted_fee` below rather than imported from a wallet
/// crate — the dependency arrow points the other way.
const BESSEL_PER_QMB: u64 = 100_000_000;

/// Registration/renewal term: 365 epochs ≈ one year at the frozen 24 h epoch.
pub const NAME_TERM_EPOCHS: u64 = 365;
/// Grace window after expiry: the name still resolves (flagged), cannot be
/// re-registered.
pub const NAME_GRACE_EPOCHS: u64 = 90;

/// Term and grace in blocks, derived from the frozen epoch length.
pub const NAME_TERM_BLOCKS: u64 = NAME_TERM_EPOCHS * crate::params_devnet::EPOCH_LENGTH_BLOCKS;
/// See [`NAME_TERM_BLOCKS`].
pub const NAME_GRACE_BLOCKS: u64 = NAME_GRACE_EPOCHS * crate::params_devnet::EPOCH_LENGTH_BLOCKS;

/// A reveal is valid only for a commit mined in
/// `[reveal_height − COMMIT_MAX_AGE, reveal_height − COMMIT_MIN_AGE]`.
/// ~10 min / ~2 days at the 75 s target (brief §1). Outside the window the
/// commit is dead and its salt must never be reused — stated, not protected.
pub const COMMIT_MIN_AGE: u64 = 8;
/// See [`COMMIT_MIN_AGE`].
pub const COMMIT_MAX_AGE: u64 = 2_304;

/// Record kind: an L1 payment address (wallet-interop §1, 1,233 B).
pub const RECORD_KIND_L1_ADDRESS: u8 = 0x01;
/// The L2 addendum **reserves** 0x02 (`annulet-address`) and forbids this
/// baton from defining it. The constant exists so the refusal is greppable.
pub const RECORD_KIND_RESERVED_ANNULET: u8 = 0x02;

/// Raw serialized length of an L1 address (`qlab_wallet::Address::RAW_LEN`;
/// the cross-lock test lives wallet-side because the dependency arrow points
/// this way).
pub const L1_ADDRESS_LEN: usize = 1_233;

/// Grammar bound: 1–63 bytes (hsd `MAX_NAME_SIZE` precedent, DNS label limit).
pub const MAX_NAME_LEN: usize = 63;

/// The name fee (burned, N2) for a name of `len` bytes, per 365-epoch term,
/// in bessel. Length-tiered: the 4/3-char multipliers are ENS's measured tier
/// structure (32×/128× base), extended 4× per step where ENS held an auction
/// instead (N1 refuses auctions, so scarcity is priced by rent alone).
pub fn name_fee_bessel(len: usize) -> u64 {
    let qmb = |n: u64| n * BESSEL_PER_QMB;
    match len {
        0 => 0, // unreachable behind the grammar; 0 so a caller cannot mint meaning from it
        1 => qmb(2_048),
        2 => qmb(512),
        3 => qmb(128),
        4 => qmb(32),
        _ => qmb(1),
    }
}

// ---------------------------------------------------------------------------
// Grammar (N3)
// ---------------------------------------------------------------------------

/// The v1 grammar, as a hand-rolled byte check — no regex dependency reaches
/// consensus. See the module docs for the rule and its walls.
pub fn valid_name(name: &[u8]) -> bool {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return false;
    }
    let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !alnum(name[0]) || !alnum(name[name.len() - 1]) {
        return false;
    }
    if !name.iter().all(|&b| alnum(b) || b == b'-') {
        return false;
    }
    // No `--` at positions 3–4 (0-indexed 2–3): blocks punycode-shaped labels
    // (`xn--…`), the ENSIP-15 move.
    if name.len() >= 4 && name[2] == b'-' && name[3] == b'-' {
        return false;
    }
    true
}

// ---------------------------------------------------------------------------
// The rider: types
// ---------------------------------------------------------------------------

/// A name record: what a reveal binds, forever (N4 — write-once).
///
/// `kind` sits **inside** the commit preimage (see [`commit_hash`]): the L2
/// addendum requires the record-kind byte from v1, and a commit that did not
/// bind it would let the reveal swap kinds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameRecord {
    /// [`RECORD_KIND_L1_ADDRESS`] is the only kind this version defines.
    pub kind: u8,
    /// The bare name — `.qmb` is a display convention, never on chain.
    pub name: Vec<u8>,
    /// The bound payment address (raw bytes; length is kind-checked).
    pub address: Vec<u8>,
}

/// One name operation. **One op per transaction at v1** — batching is a door
/// (a rider version 2 can carry a vector without a wire redesign).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameOp {
    /// Step one of registration: publish `H(record ‖ salt)` and nothing else.
    /// Pays relay tier only — no name fee, nothing revealed.
    Commit { commit: Hash32 },
    /// Step two: reveal the record and the salt. Consensus checks the commit
    /// exists in-window, the grammar, uniqueness, and the fee split.
    Reveal { record: NameRecord, salt: [u8; 32] },
    /// Extend an existing registration by one term from `max(now, expiry)`.
    /// **No authorization** (N4): extending an immutable binding harms nobody.
    Renew { name: Vec<u8> },
}

// ---------------------------------------------------------------------------
// The rider: codec
// ---------------------------------------------------------------------------

/// The canonical absence: "this transaction carries no name op", as one
/// well-formed byte. Mirrors `TxEntry::empty_discovery`'s rule and reasoning.
pub const RIDER_ABSENT: &[u8] = &[0x00];

/// Rider format version byte. Additive-only: a later version widens, never
/// reinterprets.
pub const RIDER_V1: u8 = 0x01;

const OP_COMMIT: u8 = 0x01;
const OP_REVEAL: u8 = 0x02;
const OP_RENEW: u8 = 0x03;

/// Why rider bytes were refused. *Cannot parse* and *parses but violates a
/// name rule* are different answers on different layers — this enum is only
/// the first; the rule verdicts live with `validate_body`'s `BodyError`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RiderError {
    /// Empty input — even absence must be spelled (`[0x00]`).
    Empty,
    /// Unknown rider version byte.
    UnknownVersion(u8),
    /// Unknown op byte under a known version.
    UnknownOp(u8),
    /// Truncated: the layout wanted more bytes than were present.
    Truncated,
    /// Trailing bytes after a complete op — a second spelling, refused.
    TrailingBytes,
    /// A declared length field exceeds its hard bound (name > 63, address
    /// beyond kind size); refused at decode so no rule layer sees it.
    LengthOutOfBounds,
}

fn encode_record_into(buf: &mut Vec<u8>, r: &NameRecord) {
    buf.push(r.kind);
    buf.push(r.name.len() as u8);
    buf.extend_from_slice(&r.name);
    buf.extend_from_slice(&(r.address.len() as u16).to_le_bytes());
    buf.extend_from_slice(&r.address);
}

fn decode_record(b: &[u8]) -> Result<(NameRecord, usize), RiderError> {
    if b.len() < 2 {
        return Err(RiderError::Truncated);
    }
    let kind = b[0];
    let name_len = b[1] as usize;
    if name_len == 0 || name_len > MAX_NAME_LEN {
        return Err(RiderError::LengthOutOfBounds);
    }
    let mut at = 2;
    if b.len() < at + name_len + 2 {
        return Err(RiderError::Truncated);
    }
    let name = b[at..at + name_len].to_vec();
    at += name_len;
    let addr_len = u16::from_le_bytes([b[at], b[at + 1]]) as usize;
    at += 2;
    // Hard bound: no kind this version defines exceeds L1_ADDRESS_LEN, and an
    // unknown kind is a *rule* question — but an absurd length is a codec one.
    if addr_len > L1_ADDRESS_LEN {
        return Err(RiderError::LengthOutOfBounds);
    }
    if b.len() < at + addr_len {
        return Err(RiderError::Truncated);
    }
    let address = b[at..at + addr_len].to_vec();
    at += addr_len;
    Ok((NameRecord { kind, name, address }, at))
}

/// Encode a rider. `None` yields the canonical absence.
pub fn encode_rider(op: Option<&NameOp>) -> Vec<u8> {
    let Some(op) = op else {
        return RIDER_ABSENT.to_vec();
    };
    let mut buf = vec![RIDER_V1];
    match op {
        NameOp::Commit { commit } => {
            buf.push(OP_COMMIT);
            buf.extend_from_slice(commit);
        }
        NameOp::Reveal { record, salt } => {
            buf.push(OP_REVEAL);
            encode_record_into(&mut buf, record);
            buf.extend_from_slice(salt);
        }
        NameOp::Renew { name } => {
            buf.push(OP_RENEW);
            buf.push(name.len() as u8);
            buf.extend_from_slice(name);
        }
    }
    buf
}

/// Decode a rider. The layout is length-prefixed and fixed-order throughout
/// and trailing bytes are refused, so decode is injective — canonicity holds
/// by construction, and [`rider_is_canonical`] states it as a check anyway
/// (the discovery lane's §4 rule 3, applied to the field that copied its
/// discipline).
pub fn decode_rider(b: &[u8]) -> Result<Option<NameOp>, RiderError> {
    match b {
        [] => Err(RiderError::Empty),
        [0x00] => Ok(None),
        [0x00, ..] => Err(RiderError::TrailingBytes),
        [version, rest @ ..] => {
            if *version != RIDER_V1 {
                return Err(RiderError::UnknownVersion(*version));
            }
            let [op, rest @ ..] = rest else {
                return Err(RiderError::Truncated);
            };
            match *op {
                OP_COMMIT => {
                    if rest.len() < 32 {
                        return Err(RiderError::Truncated);
                    }
                    if rest.len() > 32 {
                        return Err(RiderError::TrailingBytes);
                    }
                    let mut commit = [0u8; 32];
                    commit.copy_from_slice(rest);
                    Ok(Some(NameOp::Commit { commit }))
                }
                OP_REVEAL => {
                    let (record, used) = decode_record(rest)?;
                    let tail = &rest[used..];
                    if tail.len() < 32 {
                        return Err(RiderError::Truncated);
                    }
                    if tail.len() > 32 {
                        return Err(RiderError::TrailingBytes);
                    }
                    let mut salt = [0u8; 32];
                    salt.copy_from_slice(tail);
                    Ok(Some(NameOp::Reveal { record, salt }))
                }
                OP_RENEW => {
                    let [len, rest @ ..] = rest else {
                        return Err(RiderError::Truncated);
                    };
                    let len = *len as usize;
                    if len == 0 || len > MAX_NAME_LEN {
                        return Err(RiderError::LengthOutOfBounds);
                    }
                    if rest.len() < len {
                        return Err(RiderError::Truncated);
                    }
                    if rest.len() > len {
                        return Err(RiderError::TrailingBytes);
                    }
                    Ok(Some(NameOp::Renew { name: rest.to_vec() }))
                }
                other => Err(RiderError::UnknownOp(other)),
            }
        }
    }
}

/// §4-rule-3 shape: decode canonically and re-encode to yourself.
pub fn rider_is_canonical(b: &[u8]) -> bool {
    match decode_rider(b) {
        Ok(op) => encode_rider(op.as_ref()) == b,
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// The commit hash
// ---------------------------------------------------------------------------

/// Domain tag for the commit preimage — the `b"qumbra:checkpoint:v1"`
/// precedent. Versioned with the rider format.
pub const NAME_COMMIT_DOMAIN: &[u8] = b"qumbra:name:commit:v1";

/// `H(domain ‖ record ‖ salt)`. The record encoding is the codec's own —
/// one encoder, so the hash and the wire cannot drift apart. `kind` is inside
/// the preimage (module docs say why).
pub fn commit_hash(record: &NameRecord, salt: &[u8; 32]) -> Hash32 {
    let mut buf = Vec::with_capacity(NAME_COMMIT_DOMAIN.len() + 4 + record.name.len() + record.address.len() + 32);
    buf.extend_from_slice(NAME_COMMIT_DOMAIN);
    encode_record_into(&mut buf, record);
    buf.extend_from_slice(salt);
    keccak256(&buf)
}

/// The burned name-fee portion (bessel) a transaction carrying `op` owes on
/// top of its relay tier. Commits owe nothing (brief §1).
pub fn name_fee_for(op: &NameOp) -> u64 {
    match op {
        NameOp::Commit { .. } => 0,
        NameOp::Reveal { record, .. } => name_fee_bessel(record.name.len()),
        NameOp::Renew { name } => name_fee_bessel(name.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fees::{posted_fee, ArityBucket};

    // -- parameters ---------------------------------------------------------

    #[test]
    fn inert_at_merge_boundary_is_none() {
        // The load-bearing merge property (lab #367): no boundary, no rule.
        assert_eq!(NAME_RULE_BOUNDARY_HEIGHT, None);
    }

    #[test]
    fn bessel_per_qmb_cross_locked_against_the_fee_table() {
        // fees.rs: 0.01 QMB posted for 2×2 ⇒ 1 QMB = 100 × posted_fee(2×2).
        assert_eq!(BESSEL_PER_QMB, 100 * posted_fee(ArityBucket::TwoByTwo));
    }

    #[test]
    fn fee_table_is_the_task_book_table() {
        let qmb = |n: u64| n * BESSEL_PER_QMB;
        assert_eq!(name_fee_bessel(1), qmb(2_048));
        assert_eq!(name_fee_bessel(2), qmb(512));
        assert_eq!(name_fee_bessel(3), qmb(128));
        assert_eq!(name_fee_bessel(4), qmb(32));
        assert_eq!(name_fee_bessel(5), qmb(1));
        assert_eq!(name_fee_bessel(63), qmb(1));
    }

    #[test]
    fn term_and_grace_derive_from_the_frozen_epoch() {
        assert_eq!(NAME_TERM_BLOCKS, 365 * 1_152);
        assert_eq!(NAME_GRACE_BLOCKS, 90 * 1_152);
    }

    // -- grammar ------------------------------------------------------------

    #[test]
    fn grammar_accepts_the_plain_shapes() {
        for ok in ["a", "z9", "alice", "a-b", "abc-def-9", "a0", "0a", "9", &"a".repeat(63)] {
            assert!(valid_name(ok.as_bytes()), "{ok:?} should pass");
        }
    }

    #[test]
    fn grammar_refuses_case_length_and_edges() {
        let too_long = "a".repeat(64);
        for bad in ["", "Alice", "-a", "a-", "a_b", "a.b", "a b", "café", too_long.as_str()] {
            assert!(!valid_name(bad.as_bytes()), "{bad:?} should fail");
        }
    }

    #[test]
    fn grammar_refuses_the_punycode_shape() {
        // `--` at positions 3–4 — the ENSIP-15 move.
        assert!(!valid_name(b"xn--fake"));
        assert!(!valid_name(b"ab--cd"));
        // …but interior double-hyphen elsewhere is legal:
        assert!(valid_name(b"abc--d"));
        assert!(valid_name(b"a-b-c"));
    }

    #[test]
    fn confusables_pass_by_design_the_fingerprint_carries_the_residue() {
        // N3 states it: `0/o 1/l` survives this grammar. The residue is D3's
        // fingerprint's to carry — this test exists so nobody "fixes" it.
        assert!(valid_name(b"a11ce"));
        assert!(valid_name(b"al1ce"));
        assert!(valid_name(b"0liver"));
        assert!(valid_name(b"oliver"));
    }

    // -- codec --------------------------------------------------------------

    fn sample_record() -> NameRecord {
        NameRecord {
            kind: RECORD_KIND_L1_ADDRESS,
            name: b"alice".to_vec(),
            address: vec![0xAB; L1_ADDRESS_LEN],
        }
    }

    #[test]
    fn absence_is_one_byte_and_round_trips() {
        assert_eq!(encode_rider(None), RIDER_ABSENT);
        assert_eq!(decode_rider(RIDER_ABSENT), Ok(None));
        assert!(rider_is_canonical(RIDER_ABSENT));
        // …and an empty Vec is NOT a second spelling of it:
        assert_eq!(decode_rider(&[]), Err(RiderError::Empty));
        assert_eq!(decode_rider(&[0x00, 0x00]), Err(RiderError::TrailingBytes));
    }

    #[test]
    fn all_three_ops_round_trip_canonically() {
        let ops = [
            NameOp::Commit { commit: [7u8; 32] },
            NameOp::Reveal { record: sample_record(), salt: [9u8; 32] },
            NameOp::Renew { name: b"alice".to_vec() },
        ];
        for op in &ops {
            let bytes = encode_rider(Some(op));
            assert_eq!(decode_rider(&bytes), Ok(Some(op.clone())), "{op:?}");
            assert!(rider_is_canonical(&bytes), "{op:?}");
        }
    }

    #[test]
    fn truncation_and_trailing_are_two_different_refusals() {
        let full = encode_rider(Some(&NameOp::Commit { commit: [7u8; 32] }));
        assert_eq!(decode_rider(&full[..full.len() - 1]), Err(RiderError::Truncated));
        let mut long = full.clone();
        long.push(0xFF);
        assert_eq!(decode_rider(&long), Err(RiderError::TrailingBytes));
    }

    #[test]
    fn unknown_version_and_op_are_named_refusals() {
        assert_eq!(decode_rider(&[0x02, 0x01]), Err(RiderError::UnknownVersion(0x02)));
        assert_eq!(decode_rider(&[RIDER_V1, 0x04]), Err(RiderError::UnknownOp(0x04)));
    }

    #[test]
    fn oversize_lengths_are_refused_at_decode() {
        // Name length 64 in a reveal record.
        let mut buf = vec![RIDER_V1, OP_REVEAL, RECORD_KIND_L1_ADDRESS, 64];
        buf.extend_from_slice(&[b'a'; 64]);
        buf.extend_from_slice(&(0u16).to_le_bytes());
        buf.extend_from_slice(&[0u8; 32]);
        assert_eq!(decode_rider(&buf), Err(RiderError::LengthOutOfBounds));
        // Address length beyond the L1 bound.
        let mut buf = vec![RIDER_V1, OP_REVEAL, RECORD_KIND_L1_ADDRESS, 1, b'a'];
        buf.extend_from_slice(&((L1_ADDRESS_LEN as u16 + 1).to_le_bytes()));
        assert_eq!(decode_rider(&buf), Err(RiderError::LengthOutOfBounds));
    }

    // -- commit hash ---------------------------------------------------------

    #[test]
    fn commit_hash_binds_every_field_including_kind() {
        let r = sample_record();
        let salt = [3u8; 32];
        let base = commit_hash(&r, &salt);

        let mut kind = r.clone();
        kind.kind = 0x7F; // not RESERVED_ANNULET: binding is generic, not enum-shaped
        assert_ne!(base, commit_hash(&kind, &salt), "kind must be inside the preimage");

        let mut name = r.clone();
        name.name = b"al1ce".to_vec();
        assert_ne!(base, commit_hash(&name, &salt));

        let mut addr = r.clone();
        addr.address[0] ^= 1;
        assert_ne!(base, commit_hash(&addr, &salt));

        assert_ne!(base, commit_hash(&r, &[4u8; 32]), "salt must be inside the preimage");
        assert_eq!(base, commit_hash(&r.clone(), &salt), "and the hash is deterministic");
    }

    #[test]
    fn name_fee_for_charges_reveal_and_renew_never_commit() {
        assert_eq!(name_fee_for(&NameOp::Commit { commit: [0u8; 32] }), 0);
        assert_eq!(
            name_fee_for(&NameOp::Reveal { record: sample_record(), salt: [0u8; 32] }),
            name_fee_bessel(5)
        );
        assert_eq!(name_fee_for(&NameOp::Renew { name: b"abc".to_vec() }), name_fee_bessel(3));
    }
}
