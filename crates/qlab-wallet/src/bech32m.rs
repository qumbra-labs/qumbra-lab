//! A minimal, self-contained bech32m codec (BIP-350).
//!
//! Hand-rolled rather than pulling a new external dependency (additive-only
//! discipline), and cross-checked against BIP-350's published test vectors so a
//! transcription bug cannot self-validate. bech32m is the `M = 0x2bc830a3`
//! variant Bitcoin adopted for segwit v1+ (Taproot) after bech32's insertion
//! weakness; we use it for versioned, checksummed address strings.
//!
//! NOTE: we deliberately do NOT enforce BIP-173's advisory 90-char cap — a
//! Qumbra raw address is ~1.2 KB (encoded ~2 KB), far over it. That length is
//! exactly why the short-address indirection exists; the BCH checksum is valid
//! at any length.

/// bech32 character set (index = 5-bit value).
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
/// bech32m checksum constant (BIP-350).
const BECH32M_CONST: u32 = 0x2bc8_30a3;

fn charset_rev(c: u8) -> Option<u8> {
    CHARSET.iter().position(|&x| x == c).map(|p| p as u8)
}

fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let mut chk: u32 = 1;
    for &v in values {
        let b = (chk >> 25) as u8;
        chk = ((chk & 0x1ff_ffff) << 5) ^ (v as u32);
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let b = hrp.as_bytes();
    let mut v = Vec::with_capacity(b.len() * 2 + 1);
    for &c in b {
        v.push(c >> 5);
    }
    v.push(0);
    for &c in b {
        v.push(c & 0x1f);
    }
    v
}

/// Convert between bit groups (e.g. 8-bit bytes <-> 5-bit symbols).
fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    let maxv: u32 = (1 << to) - 1;
    for &value in data {
        let v = value as u32;
        if (v >> from) != 0 {
            return None; // value out of range for `from` bits
        }
        acc = (acc << from) | v;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return None; // non-zero padding on decode
    }
    Some(out)
}

fn create_checksum(hrp: &str, data: &[u8]) -> [u8; 6] {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0; 6]);
    let m = polymod(&values) ^ BECH32M_CONST;
    core::array::from_fn(|i| ((m >> (5 * (5 - i))) & 0x1f) as u8)
}

fn verify_checksum(hrp: &str, data: &[u8]) -> bool {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    polymod(&values) == BECH32M_CONST
}

/// Encode `payload` bytes as a bech32m string under human-readable part `hrp`.
pub fn encode(hrp: &str, payload: &[u8]) -> String {
    let mut data = convert_bits(payload, 8, 5, true).expect("8->5 with pad is infallible");
    let checksum = create_checksum(hrp, &data);
    data.extend_from_slice(&checksum);
    let mut s = String::with_capacity(hrp.len() + 1 + data.len());
    s.push_str(hrp);
    s.push('1');
    for d in data {
        s.push(CHARSET[d as usize] as char);
    }
    s
}

/// Decode a bech32m string, returning `(hrp, payload_bytes)`. Rejects mixed
/// case, a bad separator, out-of-charset symbols, a failed checksum, or
/// non-zero padding.
pub fn decode(s: &str) -> Option<(String, Vec<u8>)> {
    // Reject mixed case (BIP-173).
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        return None;
    }
    let lower = s.to_ascii_lowercase();
    let pos = lower.rfind('1')?;
    if pos == 0 || pos + 7 > lower.len() {
        return None; // empty hrp or too-short data part
    }
    let hrp = &lower[..pos];
    if !hrp.bytes().all(|c| (33..=126).contains(&c)) {
        return None;
    }
    let mut data = Vec::with_capacity(lower.len() - pos - 1);
    for c in lower[pos + 1..].bytes() {
        data.push(charset_rev(c)?);
    }
    if !verify_checksum(hrp, &data) {
        return None;
    }
    let payload = convert_bits(&data[..data.len() - 6], 5, 8, false)?;
    Some((hrp.to_string(), payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BIP-350 valid bech32m strings must verify (checksum-only round via decode
    /// with an empty payload tolerance — we check they decode without error).
    #[test]
    fn bip350_valid_vectors_verify() {
        // (string) — all VALID bech32m per BIP-350's test list.
        let valids = [
            "A1LQFN3A",
            "a1lqfn3a",
            "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
            "?1v759aa",
        ];
        for v in valids {
            let lower = v.to_ascii_lowercase();
            let pos = lower.rfind('1').unwrap();
            let hrp = &lower[..pos];
            let data: Vec<u8> = lower[pos + 1..].bytes().map(|c| charset_rev(c).unwrap()).collect();
            assert!(verify_checksum(hrp, &data), "BIP-350 vector must verify: {v}");
        }
    }

    /// BIP-350 invalid strings must fail to decode.
    #[test]
    fn bip350_invalid_vectors_reject() {
        let invalids = [
            "in1muywd",           // invalid checksum (bech32 not bech32m)
            "A1G7SGD8",           // invalid checksum (was valid bech32)
            "1qzzfhee",           // empty hrp
            "10a06t8",            // empty hrp
        ];
        for v in invalids {
            assert!(decode(v).is_none(), "must reject invalid bech32m: {v}");
        }
    }

    /// Round-trip arbitrary payloads, including a large (address-sized) one.
    #[test]
    fn roundtrip_payloads() {
        for len in [0usize, 1, 20, 32, 100, 1233] {
            let payload: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(37).wrapping_add(3)).collect();
            let enc = encode("qtest", &payload);
            let (hrp, dec) = decode(&enc).expect("decode own encoding");
            assert_eq!(hrp, "qtest");
            assert_eq!(dec, payload, "round-trip mismatch at len {len}");
        }
    }

    /// A single flipped character must fail the checksum (BCH detection).
    #[test]
    fn corruption_detected() {
        let payload = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let enc = encode("qtest", &payload);
        let mut bytes: Vec<u8> = enc.into_bytes();
        // Flip a data char (after the '1' separator) to a different charset char.
        let sep = bytes.iter().rposition(|&b| b == b'1').unwrap();
        let idx = sep + 1;
        bytes[idx] = if bytes[idx] == b'q' { b'p' } else { b'q' };
        let corrupted = String::from_utf8(bytes).unwrap();
        assert!(decode(&corrupted).is_none(), "corruption must be detected");
    }
}
