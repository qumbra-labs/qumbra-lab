//! BIP-39-*style* mnemonic encode/decode for the 256-bit master seed (issue #43,
//! part 1, optional). A backup-phrase nicety — never consensus-visible.
//!
//! ## What is and is NOT BIP-39
//!
//! This deliberately reuses BIP-39's **human-facing structure** (the standard
//! 2048-word English wordlist, 11-bit indices, a trailing checksum), so the UX
//! and the unique-4-letter-prefix property carry over, while making TWO explicit
//! deviations that keep Qumbra self-consistent:
//!
//! 1. **Checksum hash = Keccak-256, not SHA-256.** Qumbra is conservative-hash-
//!    *everywhere* on one permutation ([`qlab_note::hash::keccak256`]); pulling in
//!    SHA-256 only for a mnemonic checksum would add a second hash for no reason.
//!    Consequence: a Qumbra 24-word phrase is **NOT interchangeable with a
//!    BIP-39 wallet** — same words, different checksum bits. This is intended and
//!    is why the phrase is a Qumbra artifact, not a portable BIP-39 seed.
//! 2. **No PBKDF2 seed-stretching / passphrase.** BIP-39 turns (mnemonic ‖
//!    passphrase) into a 512-bit seed via PBKDF2-HMAC-SHA512. Here the mnemonic
//!    is a **reversible encoding of the 256-bit entropy itself** — that entropy
//!    IS [`crate::seed::MasterSeed`]'s entropy, fed straight into the Keccak HD
//!    chain. A passphrase-hardened variant is a future option (design-repo note).
//!
//! Only the 24-word / 256-bit size is supported — it is the wallet's fixed seed
//! width. (BIP-39 also defines 12/15/18/21-word sizes; unneeded here.)

use qlab_note::hash::keccak256;

use crate::seed::{MasterSeed, ENTROPY_LEN};

/// The 2048-word English wordlist (canonical BIP-39 list, embedded verbatim).
const WORDLIST_RAW: &str = include_str!("english_wordlist.txt");

/// Number of words in a Qumbra mnemonic (256-bit entropy + 8-bit checksum =
/// 264 bits = 24 × 11).
pub const WORD_COUNT: usize = 24;

/// Bits per wordlist index.
const BITS_PER_WORD: usize = 11;

/// Checksum length in bits for 256-bit entropy (`ENT / 32`).
const CHECKSUM_BITS: usize = (ENTROPY_LEN * 8) / 32; // = 8

/// The wordlist as a `Vec<&str>` (2048 entries). Built once per call site; cheap
/// (a split over an embedded `&'static str`). Kept private — callers use the
/// encode/decode API.
fn wordlist() -> Vec<&'static str> {
    let w: Vec<&'static str> = WORDLIST_RAW.lines().collect();
    debug_assert_eq!(w.len(), 1 << BITS_PER_WORD, "wordlist must be exactly 2048");
    w
}

/// A mnemonic encode/decode failure.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum MnemonicError {
    /// The phrase did not have exactly [`WORD_COUNT`] words.
    WrongWordCount(usize),
    /// A word is not in the wordlist (carries the offending word).
    UnknownWord(String),
    /// The trailing checksum bits did not match the entropy.
    BadChecksum,
}

impl core::fmt::Display for MnemonicError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MnemonicError::WrongWordCount(n) => {
                write!(f, "expected {WORD_COUNT} words, got {n}")
            }
            MnemonicError::UnknownWord(w) => write!(f, "word not in wordlist: {w:?}"),
            MnemonicError::BadChecksum => write!(f, "mnemonic checksum mismatch"),
        }
    }
}

impl std::error::Error for MnemonicError {}

/// The 8-bit checksum for 256-bit entropy: the top [`CHECKSUM_BITS`] bits of
/// `Keccak256(entropy)` (here exactly its first byte).
fn checksum_byte(entropy: &[u8; ENTROPY_LEN]) -> u8 {
    // CHECKSUM_BITS == 8 for our fixed width, so the whole first hash byte is the
    // checksum. The `>>`/mask keeps this correct if the width ever generalises.
    let h0 = keccak256(entropy)[0];
    h0 >> (8 - CHECKSUM_BITS)
}

/// Encode a [`MasterSeed`]'s entropy as a 24-word mnemonic phrase (space-joined).
///
/// The seed's version byte is NOT encoded in the phrase — the phrase carries the
/// 256-bit entropy only; the version is a decode-time parameter (default
/// [`crate::seed::SEED_VERSION`], see [`mnemonic_to_seed`]).
pub fn seed_to_mnemonic(seed: &MasterSeed) -> String {
    let entropy = seed.entropy();
    // 264-bit big-endian stream: 256 entropy bits, then 8 checksum bits.
    let mut bits: Vec<bool> = Vec::with_capacity(ENTROPY_LEN * 8 + CHECKSUM_BITS);
    for &byte in entropy.iter() {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1 == 1);
        }
    }
    let cs = checksum_byte(entropy);
    for i in (0..CHECKSUM_BITS).rev() {
        bits.push((cs >> i) & 1 == 1);
    }

    let words = wordlist();
    let mut out: Vec<&str> = Vec::with_capacity(WORD_COUNT);
    for chunk in bits.chunks(BITS_PER_WORD) {
        let mut idx = 0usize;
        for &b in chunk {
            idx = (idx << 1) | (b as usize);
        }
        out.push(words[idx]);
    }
    out.join(" ")
}

/// Decode a mnemonic phrase back to a [`MasterSeed`] at the given version,
/// verifying the checksum. Whitespace-tolerant (any run of ASCII whitespace
/// separates words); case-sensitive on the wordlist (BIP-39 words are lowercase).
pub fn mnemonic_to_seed(phrase: &str, version: u8) -> Result<MasterSeed, MnemonicError> {
    let tokens: Vec<&str> = phrase.split_whitespace().collect();
    if tokens.len() != WORD_COUNT {
        return Err(MnemonicError::WrongWordCount(tokens.len()));
    }

    let words = wordlist();
    // Reconstruct the 264-bit stream from the 11-bit indices.
    let mut bits: Vec<bool> = Vec::with_capacity(WORD_COUNT * BITS_PER_WORD);
    for tok in &tokens {
        let idx = words
            .iter()
            .position(|w| *w == *tok)
            .ok_or_else(|| MnemonicError::UnknownWord((*tok).to_string()))?;
        for i in (0..BITS_PER_WORD).rev() {
            bits.push((idx >> i) & 1 == 1);
        }
    }

    // Split: first 256 bits = entropy, last 8 = checksum.
    let mut entropy = [0u8; ENTROPY_LEN];
    for (byte_i, byte) in entropy.iter_mut().enumerate() {
        let mut v = 0u8;
        for bit_i in 0..8 {
            v = (v << 1) | (bits[byte_i * 8 + bit_i] as u8);
        }
        *byte = v;
    }
    let mut got_cs = 0u8;
    for bit_i in 0..CHECKSUM_BITS {
        got_cs = (got_cs << 1) | (bits[ENTROPY_LEN * 8 + bit_i] as u8);
    }

    if got_cs != checksum_byte(&entropy) {
        return Err(MnemonicError::BadChecksum);
    }
    Ok(MasterSeed::with_version(version, entropy))
}

impl MasterSeed {
    /// This seed's 24-word backup phrase (see [`seed_to_mnemonic`]).
    pub fn to_mnemonic(&self) -> String {
        seed_to_mnemonic(self)
    }

    /// Recover a seed from a backup phrase at [`crate::seed::SEED_VERSION`],
    /// verifying the checksum (see [`mnemonic_to_seed`]).
    pub fn from_mnemonic(phrase: &str) -> Result<MasterSeed, MnemonicError> {
        mnemonic_to_seed(phrase, crate::seed::SEED_VERSION)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entropy(fill: u8) -> [u8; ENTROPY_LEN] {
        [fill; ENTROPY_LEN]
    }

    #[test]
    fn wordlist_is_2048_unique() {
        let w = wordlist();
        assert_eq!(w.len(), 2048);
        let mut sorted = w.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 2048, "wordlist has duplicates");
    }

    #[test]
    fn roundtrip_all_seed_recovers() {
        for fill in [0u8, 1, 0x55, 0xaa, 0xff] {
            let seed = MasterSeed::from_entropy(entropy(fill));
            let phrase = seed.to_mnemonic();
            assert_eq!(phrase.split_whitespace().count(), WORD_COUNT);
            let back = MasterSeed::from_mnemonic(&phrase).expect("valid phrase");
            assert_eq!(back.entropy(), seed.entropy(), "entropy survives roundtrip");
            assert_eq!(back.version(), seed.version());
        }
    }

    /// GOLDEN LOCK: all-zero entropy encodes to a frozen phrase. Like BIP-39's
    /// famous all-zero vector (`abandon × 23 + art`) but with Qumbra's Keccak
    /// checksum, so the LAST word differs from BIP-39 — the visible marker that
    /// this is a Qumbra phrase, not a portable BIP-39 one.
    #[test]
    fn zero_entropy_is_byte_frozen() {
        let seed = MasterSeed::from_entropy([0u8; ENTROPY_LEN]);
        let phrase = seed.to_mnemonic();
        // First 23 words are all "abandon" (all-zero 11-bit indices); the 24th
        // carries the 3 low entropy bits (0) ‖ 8 checksum bits.
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert!(words[..23].iter().all(|w| *w == "abandon"), "first 23 = abandon");
        assert_eq!(phrase, ZERO_PHRASE, "zero-entropy phrase drifted");
        // And it round-trips.
        assert_eq!(MasterSeed::from_mnemonic(&phrase).unwrap().entropy(), &[0u8; 32]);
    }

    // Pinned zero-entropy phrase (recomputed + locked; regenerate ONLY on a
    // deliberate, version-bumped format change).
    const ZERO_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon abandon abandon ahead";

    #[test]
    fn bad_checksum_rejected() {
        let seed = MasterSeed::from_entropy(entropy(0x33));
        let phrase = seed.to_mnemonic();
        let mut words: Vec<String> = phrase.split_whitespace().map(String::from).collect();
        // Flip the LAST word (carries the checksum) to a different valid word.
        let wl = wordlist();
        let last_idx = wl.iter().position(|w| *w == words[WORD_COUNT - 1]).unwrap();
        words[WORD_COUNT - 1] = wl[(last_idx + 1) % 2048].to_string();
        let tampered = words.join(" ");
        assert_eq!(
            MasterSeed::from_mnemonic(&tampered).unwrap_err(),
            MnemonicError::BadChecksum,
            "a flipped checksum word must be rejected"
        );
    }

    #[test]
    fn wrong_word_count_rejected() {
        assert_eq!(
            MasterSeed::from_mnemonic("abandon abandon abandon").unwrap_err(),
            MnemonicError::WrongWordCount(3)
        );
    }

    #[test]
    fn unknown_word_rejected() {
        let seed = MasterSeed::from_entropy(entropy(1));
        let phrase = seed.to_mnemonic();
        let mut words: Vec<String> = phrase.split_whitespace().map(String::from).collect();
        words[0] = "notaword".to_string();
        match MasterSeed::from_mnemonic(&words.join(" ")).unwrap_err() {
            MnemonicError::UnknownWord(w) => assert_eq!(w, "notaword"),
            e => panic!("expected UnknownWord, got {e:?}"),
        }
    }

    #[test]
    fn whitespace_tolerant() {
        let seed = MasterSeed::from_entropy(entropy(0x77));
        let phrase = seed.to_mnemonic();
        let messy = format!("  {}  ", phrase.replace(' ', "\n  "));
        assert_eq!(
            MasterSeed::from_mnemonic(&messy).unwrap().entropy(),
            seed.entropy(),
            "extra/newline whitespace between words is tolerated"
        );
    }
}
