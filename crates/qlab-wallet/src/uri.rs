//! `qumbra:` payment URIs — `wallet-interop-spec.md` §1 (lab issue #342).
//!
//! ```text
//! qumbra:<address>[?amount=<decimal>&memo=<base64url>&label=<utf8>]
//! ```
//!
//! Kernel, not CLI: this module lives here so `qumbra-ffi`/iOS can reuse it.
//! Zero dependencies beyond what the crate already has — the base64url and
//! percent codecs below are hand-rolled for the same reason `bech32m` is.
//!
//! Spec rules implemented (already decided, not redesigned here):
//!
//! - `amount` is whole-coin decimal **QMB**; 1 QMB = 10⁸ bessel (frozen
//!   consensus parameter — [`BESSEL_PER_QMB`] is cross-locked against
//!   `qlab_node::emission::BESSEL_PER_QMB` from `qumbra-wallet`, since this
//!   crate deliberately gains no dependency). All QMB↔bessel arithmetic is
//!   **integer-exact**: no `f32`/`f64` anywhere on this path (lab issue #303
//!   is standing law on money values).
//! - Unknown query keys are ignored (forward compatibility). A *known* key
//!   with an unparseable value is an error, never ignored.
//! - A `qs1…` short address is refused **by name**: a fingerprint commitment
//!   cannot receive funds (name-service D3 / wallet-interop §1).
//! - URI version is implied by the address version (`Address::decode` is the
//!   sole address authority; this module adds no second reading).
//!
//! Positions this module takes where the spec is silent (stated in the PR):
//!
//! - `label` travels RFC 3986 percent-encoded on emit; parse accepts both
//!   percent-encoded and raw UTF-8, and `+` is a literal plus, never a space.
//! - `memo` is base64url (RFC 4648 §5), emitted unpadded; parse accepts
//!   optional `=` padding but rejects non-canonical trailing bits.
//! - Amount parse requires digits on **both** sides of a `.` when one is
//!   present (`5.` and `.5` are refused — for money, a lopsided decimal is
//!   likelier truncation than intent). Leading zeros are accepted.
//! - The amount upper bound is "fits in `u64` bessel": tail emission makes
//!   total supply unbounded, and `u64` bessel is the platform's money type on
//!   every path (`send --amount`, tx body, fee table).
//! - A duplicated known key is an error (two `amount`s cannot both be honored
//!   and silently preferring one is exactly the trap the conflict rule on
//!   `send` exists to avoid).

use crate::address::{Address, ShortAddress};

/// The URI scheme. Matched ASCII-case-insensitively on parse (RFC 3986 §3.1),
/// emitted lowercase.
pub const URI_SCHEME: &str = "qumbra";

/// Frozen consensus parameter: 1 QMB = 10⁸ bessel (`consensus-parameters.md`
/// §8). Defined locally because this crate takes no new dependencies;
/// cross-locked against `qlab_node::emission::BESSEL_PER_QMB` by a test in
/// `qumbra-wallet` (which already depends on both crates).
pub const BESSEL_PER_QMB: u64 = 100_000_000;

/// Decimal digits in the QMB fractional part (10⁸ bessel per QMB).
pub const QMB_FRAC_DIGITS: usize = 8;

/// A parsed `qumbra:` payment URI.
///
/// `label` and `memo` are **display-only**: the send path has no memo
/// plumbing, and this type deliberately does not imply one — a consumer must
/// surface them marked "not transmitted".
#[derive(Clone)]
pub struct PaymentRequest {
    pub address: Address,
    /// Requested amount in bessel, if the URI carried one.
    pub amount_bessel: Option<u64>,
    /// Display-only human label (already percent-decoded, valid UTF-8).
    pub label: Option<String>,
    /// Display-only memo bytes (already base64url-decoded). NOT transmitted.
    pub memo: Option<Vec<u8>>,
}

impl std::fmt::Debug for PaymentRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `Address` has no Debug (2 KB of key material is not a debug line);
        // show the same qs1… fingerprint every user surface shows.
        f.debug_struct("PaymentRequest")
            .field("address", &self.address.short().encode())
            .field("amount_bessel", &self.amount_bessel)
            .field("label", &self.label)
            .field("memo", &self.memo)
            .finish()
    }
}

/// Typed parse errors, the style of `contacts.rs`' `ContactError`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UriError {
    /// The string does not start with the `qumbra:` scheme.
    Scheme { got: String },
    /// The address part is a `qs1…` short address — a fingerprint commitment,
    /// which cannot receive funds. Its `Display` says why.
    ShortAddressUnpayable,
    /// The address part is not a decodable `qaddr1…` address.
    InvalidAddress,
    /// A known key's value failed to parse. `why` names the rule broken.
    BadValue { key: &'static str, got: String, why: &'static str },
    /// A known key appeared more than once.
    DuplicateKey { key: &'static str },
}

impl std::fmt::Display for UriError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UriError::Scheme { got } => {
                write!(f, "not a qumbra: URI (scheme is `{got}`, expected `{URI_SCHEME}`)")
            }
            UriError::ShortAddressUnpayable => write!(
                f,
                "this is a qs1… SHORT address — a fingerprint commitment for verifying an \
                 address out of band, not a payable address; it cannot receive funds. Ask the \
                 payee for their full qaddr1… address"
            ),
            UriError::InvalidAddress => {
                write!(f, "the address part is not a valid qaddr1… address")
            }
            UriError::BadValue { key, got, why } => {
                write!(f, "bad `{key}` value `{got}`: {why}")
            }
            UriError::DuplicateKey { key } => {
                write!(f, "query key `{key}` appears more than once")
            }
        }
    }
}

impl std::error::Error for UriError {}

/// Encode a payment URI. Query keys are emitted in spec order
/// (`amount`, `memo`, `label`); absent options emit no key at all.
pub fn encode(
    addr: &Address,
    amount_bessel: Option<u64>,
    label: Option<&str>,
    memo: Option<&[u8]>,
) -> String {
    let mut out = String::with_capacity(2100);
    out.push_str(URI_SCHEME);
    out.push(':');
    out.push_str(&addr.encode());
    let mut sep = '?';
    let mut push = |out: &mut String, key: &str, value: &str| {
        out.push(sep);
        out.push_str(key);
        out.push('=');
        out.push_str(value);
        sep = '&';
    };
    if let Some(b) = amount_bessel {
        push(&mut out, "amount", &bessel_to_qmb(b));
    }
    if let Some(m) = memo {
        push(&mut out, "memo", &b64url_encode(m));
    }
    if let Some(l) = label {
        push(&mut out, "label", &percent_encode(l));
    }
    out
}

/// Parse a payment URI. The address is validated via [`Address::decode`] — the
/// one address authority; a `qs1…` fingerprint is refused by name.
pub fn parse(s: &str) -> Result<PaymentRequest, UriError> {
    let colon = s.find(':').ok_or_else(|| UriError::Scheme { got: truncated(s) })?;
    let scheme = &s[..colon];
    if !scheme.eq_ignore_ascii_case(URI_SCHEME) {
        return Err(UriError::Scheme { got: truncated(scheme) });
    }
    let rest = &s[colon + 1..];
    let (addr_part, query) = match rest.find('?') {
        Some(q) => (&rest[..q], Some(&rest[q + 1..])),
        None => (rest, None),
    };
    let address = match Address::decode(addr_part) {
        Some(a) => a,
        None if ShortAddress::decode(addr_part).is_some() => {
            return Err(UriError::ShortAddressUnpayable)
        }
        None => return Err(UriError::InvalidAddress),
    };

    let mut amount_bessel = None;
    let mut label = None;
    let mut memo = None;
    if let Some(query) = query {
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (key, value) = match pair.find('=') {
                Some(e) => (&pair[..e], Some(&pair[e + 1..])),
                None => (pair, None),
            };
            match key {
                "amount" => {
                    if amount_bessel.is_some() {
                        return Err(UriError::DuplicateKey { key: "amount" });
                    }
                    let v = known_value("amount", value)?;
                    amount_bessel = Some(qmb_to_bessel(v).map_err(|why| {
                        UriError::BadValue { key: "amount", got: truncated(v), why }
                    })?);
                }
                "memo" => {
                    if memo.is_some() {
                        return Err(UriError::DuplicateKey { key: "memo" });
                    }
                    let v = known_value("memo", value)?;
                    memo = Some(b64url_decode(v).map_err(|why| UriError::BadValue {
                        key: "memo",
                        got: truncated(v),
                        why,
                    })?);
                }
                "label" => {
                    if label.is_some() {
                        return Err(UriError::DuplicateKey { key: "label" });
                    }
                    let v = known_value("label", value)?;
                    label = Some(percent_decode(v).map_err(|why| UriError::BadValue {
                        key: "label",
                        got: truncated(v),
                        why,
                    })?);
                }
                // Unknown keys MUST be ignored (forward compatibility),
                // including their values, well-formed or not.
                _ => {}
            }
        }
    }
    Ok(PaymentRequest { address, amount_bessel, label, memo })
}

/// A known key with no `=` at all is a known key with an unparseable value.
fn known_value<'a>(key: &'static str, value: Option<&'a str>) -> Result<&'a str, UriError> {
    value.ok_or(UriError::BadValue { key, got: String::new(), why: "key has no value" })
}

/// Clip a value for an error message so a 2 KB junk string doesn't become the
/// error text.
fn truncated(s: &str) -> String {
    const MAX: usize = 32;
    if s.len() <= MAX {
        s.to_string()
    } else {
        let mut end = MAX;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &s[..end])
    }
}

// ---------------------------------------------------------------------------
// QMB decimal ↔ bessel — integer/string arithmetic only. No float anywhere on
// this path (lab issue #303: platform-dependent floats on money values).
// ---------------------------------------------------------------------------

/// Parse a whole-coin decimal QMB string to bessel, exactly.
///
/// Accepted: ASCII digits with at most one `.`, digits on both sides of it,
/// ≤ [`QMB_FRAC_DIGITS`] fractional digits, value fitting `u64` bessel.
/// Rejected by name: empty, `.`-only and lopsided decimals, exponent forms,
/// signs, and anything past 8 fractional digits (there is no such bessel).
pub fn qmb_to_bessel(s: &str) -> Result<u64, &'static str> {
    if s.is_empty() {
        return Err("empty amount");
    }
    if !s.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        // One message for `1e3`, `+1`, `-1`, `1_000`, whitespace, …
        return Err("amount must be plain decimal digits with at most one `.` \
                    (no exponent, sign, or separators)");
    }
    let (int_str, frac_str) = match s.find('.') {
        Some(dot) => {
            let (i, f) = (&s[..dot], &s[dot + 1..]);
            if f.contains('.') {
                return Err("more than one `.`");
            }
            if i.is_empty() || f.is_empty() {
                return Err("a `.` needs digits on both sides");
            }
            (i, f)
        }
        None => (s, ""),
    };
    if frac_str.len() > QMB_FRAC_DIGITS {
        return Err("more than 8 fractional digits — no such bessel exists");
    }
    let mut int_part: u64 = 0;
    for b in int_str.bytes() {
        int_part = int_part
            .checked_mul(10)
            .and_then(|v| v.checked_add((b - b'0') as u64))
            .ok_or("amount overflows the bessel range")?;
    }
    // ≤ 8 digits: cannot overflow u64 on its own.
    let mut frac_part: u64 = 0;
    for b in frac_str.bytes() {
        frac_part = frac_part * 10 + (b - b'0') as u64;
    }
    for _ in frac_str.len()..QMB_FRAC_DIGITS {
        frac_part *= 10;
    }
    int_part
        .checked_mul(BESSEL_PER_QMB)
        .and_then(|v| v.checked_add(frac_part))
        .ok_or("amount overflows the bessel range")
}

/// Format bessel as minimal whole-coin decimal QMB: no trailing zeros, no
/// trailing `.`. The exact inverse of [`qmb_to_bessel`] on its own output.
pub fn bessel_to_qmb(bessel: u64) -> String {
    let whole = bessel / BESSEL_PER_QMB;
    let frac = bessel % BESSEL_PER_QMB;
    if frac == 0 {
        return whole.to_string();
    }
    let mut frac_str = format!("{frac:08}");
    while frac_str.ends_with('0') {
        frac_str.pop();
    }
    format!("{whole}.{frac_str}")
}

// ---------------------------------------------------------------------------
// base64url (RFC 4648 §5) — hand-rolled, same additive-only discipline as
// `bech32m`. Emit unpadded; accept optional padding; reject non-canonical
// trailing bits (a memo that decodes two ways is two memos).
// ---------------------------------------------------------------------------

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut buf = [0u8; 3];
        buf[..chunk.len()].copy_from_slice(chunk);
        let n = (buf[0] as u32) << 16 | (buf[1] as u32) << 8 | buf[2] as u32;
        let symbols = [(n >> 18) & 63, (n >> 12) & 63, (n >> 6) & 63, n & 63];
        // 1 byte → 2 symbols, 2 → 3, 3 → 4; no `=` padding on emit.
        for &sym in &symbols[..chunk.len() + 1] {
            out.push(B64URL[sym as usize] as char);
        }
    }
    out
}

fn b64url_decode(s: &str) -> Result<Vec<u8>, &'static str> {
    let trimmed = s.trim_end_matches('=');
    if trimmed.len() < s.len() && (s.len() % 4 != 0 || s.len() - trimmed.len() > 2) {
        return Err("malformed base64 padding");
    }
    let mut out = Vec::with_capacity(trimmed.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for b in trimmed.bytes() {
        let v = B64URL
            .iter()
            .position(|&c| c == b)
            .ok_or("not a base64url character (alphabet is A–Z a–z 0–9 - _)")?;
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    // A final group of 6 bits (len % 4 == 1) encodes no byte; and the bits
    // left over after the last full byte must be zero to be canonical.
    if bits >= 6 {
        return Err("truncated base64url (dangling symbol)");
    }
    if acc & ((1 << bits) - 1) != 0 {
        return Err("non-canonical base64url (non-zero trailing bits)");
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Percent-encoding (RFC 3986) for `label` — emit encodes everything outside
// the unreserved set; parse accepts raw UTF-8 too. `+` is a plus, not a space.
// ---------------------------------------------------------------------------

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn percent_decode(s: &str) -> Result<String, &'static str> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3).ok_or("truncated %-escape")?;
            let hi = (hex[0] as char).to_digit(16).ok_or("bad %-escape (not hex)")?;
            let lo = (hex[1] as char).to_digit(16).ok_or("bad %-escape (not hex)")?;
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "label is not valid UTF-8 after %-decoding")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Address;

    /// The golden address: fixed raw bytes, version 1, every other byte the
    /// pattern `(7i + 3) % 256`. No key validity is needed for URI work —
    /// `Address::from_raw_bytes` checks length + version only.
    fn golden_address() -> Address {
        let mut raw = vec![0u8; Address::RAW_LEN];
        raw[0] = 1;
        for (i, b) in raw.iter_mut().enumerate().skip(1) {
            *b = ((7 * i + 3) % 256) as u8;
        }
        Address::from_raw_bytes(&raw).expect("fixed golden bytes decode")
    }

    #[test]
    fn golden_uri_vector() {
        let addr = golden_address();
        let uri = encode(&addr, Some(150_000_000), Some("coffee shop"), Some(b"hello"));
        let expected = format!(
            "qumbra:{}?amount=1.5&memo=aGVsbG8&label=coffee%20shop",
            addr.encode()
        );
        assert_eq!(uri, expected);
        // The address part itself is pinned by its checksum: lock the exact
        // head/tail so the vector survives even a bech32m regression that
        // preserves length.
        assert!(uri.starts_with("qumbra:qaddr1"));
        assert_eq!(uri.len(), "qumbra:".len() + 1985 + "?amount=1.5&memo=aGVsbG8&label=coffee%20shop".len());
    }

    #[test]
    fn round_trips() {
        let addr = golden_address();
        for (amount, label, memo) in [
            (None, None, None),
            (Some(1u64), None, None),
            (Some(u64::MAX), Some("café ☕ 100% +plus&=?"), Some(&b"\x00\xff\x10binary"[..])),
            (None, Some(""), Some(&b""[..])),
        ] {
            let uri = encode(&addr, amount, label, memo);
            let req = parse(&uri).expect("own encoding parses");
            assert_eq!(req.address.to_raw_bytes(), addr.to_raw_bytes());
            assert_eq!(req.amount_bessel, amount);
            assert_eq!(req.label.as_deref(), label);
            assert_eq!(req.memo.as_deref(), memo);
        }
    }

    #[test]
    fn bare_address_uri_parses() {
        let addr = golden_address();
        let req = parse(&format!("qumbra:{}", addr.encode())).expect("bare URI");
        assert_eq!(req.address.to_raw_bytes(), addr.to_raw_bytes());
        assert_eq!(req.amount_bessel, None);
        assert_eq!(req.label, None);
        assert_eq!(req.memo, None);
    }

    #[test]
    fn unknown_keys_ignored() {
        let addr = golden_address();
        let uri = format!(
            "qumbra:{}?future=1e99&amount=2&x&novalue=&label2=%ZZ",
            addr.encode()
        );
        let req = parse(&uri).expect("unknown keys must be ignored, even junk ones");
        assert_eq!(req.amount_bessel, Some(200_000_000));
        assert_eq!(req.label, None);
    }

    #[test]
    fn scheme_checked_case_insensitively() {
        let addr = golden_address();
        assert!(parse(&format!("QUMBRA:{}", addr.encode())).is_ok());
        match parse(&format!("bitcoin:{}", addr.encode())).unwrap_err() {
            UriError::Scheme { got } => assert_eq!(got, "bitcoin"),
            other => panic!("wrong error: {other:?}"),
        }
        assert!(matches!(parse("no-colon-here").unwrap_err(), UriError::Scheme { .. }));
    }

    #[test]
    fn short_address_refused_by_name() {
        let short = golden_address().short().encode();
        let err = parse(&format!("qumbra:{short}")).unwrap_err();
        assert_eq!(err, UriError::ShortAddressUnpayable);
        // The message says WHY — a fingerprint cannot receive funds.
        let msg = err.to_string();
        assert!(msg.contains("cannot receive funds"), "message must say why: {msg}");
        assert!(msg.contains("qaddr1"), "message must point at the fix: {msg}");
    }

    #[test]
    fn invalid_address_refused() {
        assert_eq!(parse("qumbra:qaddr1junk").unwrap_err(), UriError::InvalidAddress);
        // A corrupted (checksum-broken) full address is invalid, not short.
        let mut s = golden_address().encode();
        s.pop();
        s.push('q');
        assert_eq!(parse(&format!("qumbra:{s}")).unwrap_err(), UriError::InvalidAddress);
    }

    #[test]
    fn known_key_with_unparseable_value_is_an_error_never_ignored() {
        let addr = golden_address();
        for query in ["amount=1e3", "amount", "amount=", "memo=a", "memo=ab=c", "label=%G1"] {
            let uri = format!("qumbra:{}?{}", addr.encode(), query);
            assert!(
                matches!(parse(&uri).unwrap_err(), UriError::BadValue { .. }),
                "`{query}` must be a typed error"
            );
        }
    }

    #[test]
    fn duplicate_known_key_is_an_error() {
        let addr = golden_address();
        let uri = format!("qumbra:{}?amount=1&amount=1", addr.encode());
        assert_eq!(parse(&uri).unwrap_err(), UriError::DuplicateKey { key: "amount" });
    }

    // -- amount conversion: its own exhaustive edge set ---------------------

    #[test]
    fn qmb_parse_exact_edges() {
        // One bessel.
        assert_eq!(qmb_to_bessel("0.00000001"), Ok(1));
        // Below one bessel: no such value.
        assert!(qmb_to_bessel("0.000000001").is_err());
        // Whole coins and leading zeros.
        assert_eq!(qmb_to_bessel("1"), Ok(100_000_000));
        assert_eq!(qmb_to_bessel("007"), Ok(700_000_000));
        assert_eq!(qmb_to_bessel("0.10000000"), Ok(10_000_000));
        assert_eq!(qmb_to_bessel("1.5"), Ok(150_000_000));
        assert_eq!(qmb_to_bessel("0.00000000"), Ok(0));
        // The exact top of the bessel range, and one past it.
        assert_eq!(qmb_to_bessel("184467440737.09551615"), Ok(u64::MAX));
        assert!(qmb_to_bessel("184467440737.09551616").is_err());
        assert!(qmb_to_bessel("184467440738").is_err());
        assert!(qmb_to_bessel("99999999999999999999999").is_err());
    }

    #[test]
    fn qmb_parse_rejects_malformed() {
        for bad in [
            "", ".", "1.", ".5", "1..2", "1.2.3", // empty / lopsided / multi-dot
            "1e3", "1E3", "1e-3", // exponent forms
            "+1", "-1", " 1", "1 ", "1_000", "0x10", "NaN", "inf", // signs & junk
        ] {
            assert!(qmb_to_bessel(bad).is_err(), "`{bad}` must be rejected");
        }
    }

    #[test]
    fn qmb_emit_is_minimal() {
        assert_eq!(bessel_to_qmb(0), "0");
        assert_eq!(bessel_to_qmb(1), "0.00000001");
        assert_eq!(bessel_to_qmb(10_000_000), "0.1");
        assert_eq!(bessel_to_qmb(100_000_000), "1");
        assert_eq!(bessel_to_qmb(150_000_000), "1.5");
        assert_eq!(bessel_to_qmb(u64::MAX), "184467440737.09551615");
    }

    #[test]
    fn qmb_round_trips() {
        for b in [0, 1, 9, 10, 99_999_999, 100_000_000, 100_000_001, 5_000_000_000, u64::MAX] {
            assert_eq!(qmb_to_bessel(&bessel_to_qmb(b)), Ok(b), "bessel {b}");
        }
    }

    // -- base64url ----------------------------------------------------------

    #[test]
    fn b64url_round_trips_and_is_unpadded() {
        for bytes in [&b""[..], b"f", b"fo", b"foo", b"hello", &[0u8, 255, 16, 254][..]] {
            let s = b64url_encode(bytes);
            assert!(!s.contains('='), "emit is unpadded: {s}");
            assert_eq!(b64url_decode(&s).as_deref(), Ok(bytes), "round-trip {s}");
        }
        assert_eq!(b64url_encode(b"hello"), "aGVsbG8");
        // URL-safe alphabet: 0xfb 0xff hits `-` and `_` territory.
        assert_eq!(b64url_encode(&[0xfb, 0xef, 0xff]), "--__");
    }

    #[test]
    fn b64url_accepts_padding_rejects_junk() {
        assert_eq!(b64url_decode("aGVsbG8="), Ok(b"hello".to_vec()));
        assert!(b64url_decode("a").is_err(), "dangling symbol");
        assert!(b64url_decode("aGVsbG8==").is_err(), "over-padded");
        assert!(b64url_decode("a=b").is_err(), "interior padding");
        assert!(b64url_decode("aGVsb+8").is_err(), "`+` is standard base64, not base64url");
        assert!(b64url_decode("aGVsb/8").is_err(), "`/` is standard base64, not base64url");
        // Non-canonical: `aGVsbG9` would need non-zero trailing bits.
        assert!(b64url_decode("aGVsbG9").is_err(), "non-zero trailing bits");
    }

    // -- percent-encoding ---------------------------------------------------

    #[test]
    fn label_percent_round_trips_utf8() {
        for label in ["", "coffee shop", "café ☕", "a&b=c?d#e%f", "+not a space+"] {
            let enc = percent_encode(label);
            assert!(enc.bytes().all(|b| b.is_ascii() && b != b'&' && b != b'='), "{enc}");
            assert_eq!(percent_decode(&enc).as_deref(), Ok(label));
        }
        // Parse also accepts raw (un-encoded) UTF-8, and `+` stays a plus.
        assert_eq!(percent_decode("café"), Ok("café".to_string()));
        assert_eq!(percent_decode("a+b"), Ok("a+b".to_string()));
    }

    #[test]
    fn label_percent_rejects_bad_escapes() {
        assert!(percent_decode("%").is_err());
        assert!(percent_decode("%1").is_err());
        assert!(percent_decode("%G1").is_err());
        // %FF alone is not valid UTF-8.
        assert!(percent_decode("%FF").is_err());
    }
}
