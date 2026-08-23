//! Research-only Candidate A authorization spike (lab issue #630).
//!
//! This crate compares a FIPS 204 ML-DSA-44 stateless leaf with the RFC 8391
//! `WOTSP-SHA2_256` leaf under one exact intent, two-slot shape, and canonical
//! codec. It is deliberately unreachable from every shipping `qumbra-*`
//! crate. Nothing here is a selected protocol, consensus rule, wallet format,
//! or authorization implementation.
//!
//! The security boundary under study is narrow: a phone keeps the signing
//! secret while a remote worker receives proving material. Every node must be
//! able to reject a worker-modified intent before doing STARK verification.

pub mod codec;
pub mod intent;
pub mod mldsa;
pub mod rotation;
pub mod shape;
pub mod state;
pub mod tree;
pub mod wots;

use tiny_keccak::{Hasher, Keccak};

pub type Hash32 = [u8; 32];

/// Qumbra's existing Keccak-256 spelling, kept local so this research crate
/// does not pull the node or consensus graph into a leaf-comparison tool.
pub fn keccak256(parts: &[&[u8]]) -> Hash32 {
    let mut h = Keccak::v256();
    for part in parts {
        h.update(part);
    }
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("hex has an odd number of digits".into());
    }
    fn nibble(b: u8) -> Result<u8, String> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err(format!("non-hex byte 0x{b:02x}")),
        }
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}
