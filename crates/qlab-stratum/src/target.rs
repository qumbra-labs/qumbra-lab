//! Difficulty / target encoding for stratum jobs.
//!
//! Qumbra's PoW check (lab #356, `qlab_devnet::pow`): a hash satisfies
//! difficulty `d` iff the leading 8 bytes of the hash, read big-endian as a
//! `u64`, are `<= u64::MAX / max(d, 1)`. That is the same shape as xmrig's
//! internal 64-bit `toDiff` model, and xmrig accepts **8-byte raw** targets
//! on the wire.
//!
//! We therefore encode the stratum `target` field as the **8-byte little-endian
//! hex** of that threshold. Monero pools often emit a 4-byte compact target;
//! that compact form is a FINDING for our u64 model (lossy / differently
//! scaled) — see the mapping doc. Stage 0 commits to the 8-byte raw form.

/// Error from target parse/encode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetError {
    /// Hex string was not valid hex or not 4 or 8 bytes.
    BadHex,
    /// Hex decoded to a length other than 4 or 8.
    BadLength { got: usize },
    /// Difficulty was zero (treated as 1 by the consensus helper; refused here
    /// so a pool cannot silently widen the target).
    ZeroDifficulty,
}

impl std::fmt::Display for TargetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetError::BadHex => write!(f, "target is not valid hex"),
            TargetError::BadLength { got } => {
                write!(f, "target length {got} bytes; want 4 or 8")
            }
            TargetError::ZeroDifficulty => write!(f, "difficulty must be ≥ 1"),
        }
    }
}

impl std::error::Error for TargetError {}

/// The consensus threshold at `difficulty`: `u64::MAX / max(difficulty, 1)`.
///
/// Mirrors `qlab_devnet::pow::target_threshold` without taking that dependency.
pub fn target_from_difficulty(difficulty: u64) -> Result<u64, TargetError> {
    if difficulty == 0 {
        return Err(TargetError::ZeroDifficulty);
    }
    Ok(u64::MAX / difficulty)
}

/// Invert an 8-byte raw target to a difficulty floor: `u64::MAX / max(target, 1)`.
///
/// Round-trip is exact only when `difficulty` divides `u64::MAX` evenly; for
/// share accounting the pool should keep the difficulty it assigned, not
/// re-derive it from the target bytes.
pub fn difficulty_from_target(target: u64) -> u64 {
    u64::MAX / target.max(1)
}

/// Encode a threshold as 8-byte little-endian hex (xmrig raw-target form).
pub fn encode_target_le_hex(target: u64) -> String {
    hex_encode(&target.to_le_bytes())
}

/// Parse a stratum `target` hex string.
///
/// - **8 bytes**: raw LE u64 threshold (preferred; our native form).
/// - **4 bytes**: Monero compact LE — accepted for decode so a fixture captured
///   from a Monero pool can be inspected; **not** produced by our encoder.
///   The compact→threshold expansion used here is the xmrig-compatible
///   zero-extend (`u32 as u64`), which is NOT Monero's full compact semantics
///   and is named as a FINDING in the mapping doc. Do not use 4-byte targets
///   on a Qumbra job.
pub fn parse_target_hex(hex: &str) -> Result<u64, TargetError> {
    let bytes = hex_decode(hex).ok_or(TargetError::BadHex)?;
    match bytes.len() {
        8 => {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes);
            Ok(u64::from_le_bytes(buf))
        }
        4 => {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&bytes);
            Ok(u32::from_le_bytes(buf) as u64)
        }
        n => Err(TargetError::BadLength { got: n }),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = from_hex(bytes[i])?;
        let lo = from_hex(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
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
    fn difficulty_1024_round_trips_as_8byte_raw() {
        let t = target_from_difficulty(1024).unwrap();
        assert_eq!(t, u64::MAX / 1024);
        let hex = encode_target_le_hex(t);
        assert_eq!(hex, "ffffffffffff3f00");
        assert_eq!(parse_target_hex(&hex).unwrap(), t);
    }

    #[test]
    fn four_byte_compact_is_accepted_as_zero_extend_only() {
        // xmrig-proxy STRATUM.md example target "b88d0600" — 4-byte LE.
        let t = parse_target_hex("b88d0600").unwrap();
        assert_eq!(t, 0x0006_8db8);
    }

    #[test]
    fn zero_difficulty_refused() {
        assert_eq!(
            target_from_difficulty(0),
            Err(TargetError::ZeroDifficulty)
        );
    }
}
