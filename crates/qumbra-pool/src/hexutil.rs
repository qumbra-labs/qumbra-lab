//! Tiny hex helpers. The pool crate does not take a hex crate — same
//! posture as `qlab-stratum::target` (hand-rolled, lowercase, no `0x`).

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexError {
    OddLength {
        got: usize,
    },
    BadDigit,
    BadLength {
        got: usize,
        want: usize,
    },
    /// 64-hex rkm decoded to the all-zero key no body may carry.
    ZeroRkm,
}

impl std::fmt::Display for HexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HexError::OddLength { got } => write!(f, "hex length {got} is odd"),
            HexError::BadDigit => write!(f, "hex contains a non-hex digit"),
            HexError::BadLength { got, want } => {
                write!(f, "hex decoded to {got} bytes; want {want}")
            }
            HexError::ZeroRkm => write!(f, "rkm is all-zero (MissingCoinbasePayee)"),
        }
    }
}

impl std::error::Error for HexError {}

pub fn encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

pub fn decode(s: &str) -> Result<Vec<u8>, HexError> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err(HexError::OddLength { got: s.len() });
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = from_hex(bytes[i]).ok_or(HexError::BadDigit)?;
        let lo = from_hex(bytes[i + 1]).ok_or(HexError::BadDigit)?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

pub fn decode_exact<const N: usize>(s: &str) -> Result<[u8; N], HexError> {
    let v = decode(s)?;
    if v.len() != N {
        return Err(HexError::BadLength {
            got: v.len(),
            want: N,
        });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&v);
    Ok(out)
}

/// 64-hex → `[u64; 4]` lane-major LE, the node/faucet `miner_rkm` wire.
pub fn rkm_lanes_from_hex(s: &str) -> Result<[u64; 4], HexError> {
    let bytes = decode_exact::<32>(s)?;
    let mut lanes = [0u64; 4];
    for (i, lane) in lanes.iter_mut().enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        *lane = u64::from_le_bytes(buf);
    }
    if lanes == [0u64; 4] {
        return Err(HexError::ZeroRkm);
    }
    Ok(lanes)
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_refuses_odd() {
        assert_eq!(encode(&[0xde, 0xad]), "dead");
        assert_eq!(decode("DeAd").unwrap(), vec![0xde, 0xad]);
        assert!(matches!(decode("abc"), Err(HexError::OddLength { got: 3 })));
        assert_eq!(
            decode_exact::<4>("d0030040").unwrap(),
            [0xd0, 0x03, 0x00, 0x40]
        );
    }
}
