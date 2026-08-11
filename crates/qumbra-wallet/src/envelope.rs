//! The seed-file format **envelope** — a reserved discriminator, and nothing
//! else (lab issue #348).
//!
//! ```text
//!   bytes 0..8   MAGIC = b"QMBSEED\0"    fixed, forever
//!   byte  8      format id               versioned, reject-unknown
//!   byte  9      protection id           versioned, reject-unknown
//!   bytes 10..   the format's own payload — DELIBERATELY uninterpreted here
//! ```
//!
//! # Why this exists before anything writes it
//!
//! The wallet dir's only seed format is `1 + ENTROPY_LEN` plain bytes, and the
//! open path used to conclude that *any* other length was a damaged file. The
//! moment a second format exists — the desktop shell's per-OS key-store wrap
//! (`desktop-wallet-brief` §5), or a passphrase fallback, or anything else —
//! every other reader of that directory would call an **intact** wallet
//! unreadable. That is the "vanished funds" reading this crate spends real
//! effort avoiding elsewhere (see `store.rs`'s version gate).
//!
//! So the discriminator is reserved now, while the plain format is still the
//! only one in existence. **This module reads a header and names what it
//! found. It cannot open an envelope, and nothing in this repo writes one** —
//! the first writer is the desktop shell, in its own repo, against the registry
//! below.
//!
//! # The version byte is not available for this, and that is the whole problem
//!
//! `store.rs`'s seed version byte is a **derivation-domain separator** (the
//! #246 finding: a wrong byte silently derives a *different* wallet). It must
//! never become a format field, which is why the discriminator has to be a
//! self-describing header instead.
//!
//! # Collision-freedom is by construction, not by luck
//!
//! [`inspect`] is called from exactly one place: the arm of `WalletDir::open`
//! that has already established `bytes.len() != 1 + ENTROPY_LEN`. A valid plain
//! file therefore never enters this code. On top of that, a *truncated* plain
//! file is a prefix of `[SEED_VERSION, entropy…]`, and `MAGIC[0] != SEED_VERSION`
//! is asserted at compile time below — so a truncation cannot match the magic
//! even in principle, and a randomly clobbered file matches at 2⁻⁶⁴.
//!
//! One consequence is worth stating out loud rather than discovering later: a
//! hypothetical envelope that were *exactly* `1 + ENTROPY_LEN` bytes long would
//! be read as a plain file (and refused by the version gate as version 81,
//! `MAGIC[0]`), because this module is never consulted on that length. No
//! defined format can produce one — 33 bytes leaves a 23-byte payload, and a
//! wrapped record is ciphertext + nonce + tag — and changing what a 33-byte
//! file does is a stop-point for this baton, so the gap is documented instead
//! of closed.

use qlab_wallet::seed::SEED_VERSION;

/// The fixed envelope magic. Eight bytes, trailing NUL so it is not plausible
/// text either. **Never change this** — it is the one thing every future reader
/// keys on.
pub const MAGIC: [u8; 8] = *b"QMBSEED\0";

/// Magic + format id + protection id. A file shorter than this cannot name
/// itself, however good its magic.
pub const HEADER_LEN: usize = MAGIC.len() + 2;

// A truncated plain seed file starts with SEED_VERSION, so if these two were
// ever equal the "collision-free by construction" claim above would weaken to a
// probabilistic one. Compile-time, not a debug_assert: the acceptance bar runs
// --release, where a debug_assert is a comment.
const _: () = assert!(
    MAGIC[0] != SEED_VERSION,
    "the envelope magic must not begin with the plain seed file's version byte"
);

/// Reserved **format** ids: what the payload after the header is.
///
/// The payload layout itself is deliberately NOT specified here — issue #348
/// reserves the slot; the desktop task book defines the bytes.
const FORMATS: &[(u8, &str)] = &[
    // 0x00 is permanently reserved-invalid, so an all-zero region after a
    // magic can never read as a known format.
    (0x01, "wrapped-seed-v1"),
];

/// Reserved **protection** ids: which key store holds the unwrapping key.
///
/// The granularity is set by `qumbra-wallet-desktop`'s `docs/key-storage-posture.md`
/// platform table, which requires that the protection level travel *with the
/// record* and that Windows DPAPI vs TPM-backed CNG — and macOS's Enclave key vs
/// its software P-256 fallback — be told apart, because "only one of them may be
/// printed". The id **is** the printed claim, so one id per OS could not satisfy
/// that.
///
/// Two ids are deliberately absent: there is no `none` (an unwrapped record on a
/// server) and no passphrase id. Both are records whose remedy is *not* "open it
/// on the other machine", and [`Verdict::Wrapped`] is the only vocabulary a
/// reserved id can reach — so reserving them would buy a confidently wrong
/// message, where leaving them unreserved routes them to [`Verdict::Unknown`]
/// ("a newer tool"), which is true. Adding ids later is free by construction:
/// reject-unknown means an older binary says "newer tool" and is right.
const PROTECTIONS: &[(u8, &str)] = &[
    (0x01, "macOS Keychain (Secure-Enclave-held key)"),
    (0x02, "macOS Keychain (software key, P-256 fallback)"),
    (0x03, "Windows DPAPI (per-user software protection)"),
    (0x04, "Windows CNG (TPM-backed)"),
    (0x05, "Linux Secret Service"),
];

/// What a non-plain-length seed file turned out to be.
///
/// The three refusal vocabularies of issue #348 are [`NotAnEnvelope`] (damaged,
/// today's message), [`Wrapped`] (intact, elsewhere) and [`Unknown`] (intact,
/// newer tool) — plus [`TruncatedHeader`], which is damaged like the first but
/// says so in envelope terms.
///
/// [`NotAnEnvelope`]: Verdict::NotAnEnvelope
/// [`Wrapped`]: Verdict::Wrapped
/// [`Unknown`]: Verdict::Unknown
/// [`TruncatedHeader`]: Verdict::TruncatedHeader
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// No magic. Not an envelope at all — the caller keeps its existing
    /// corrupt/truncated message, unchanged.
    NotAnEnvelope,
    /// The magic, but too few bytes to carry the header. A damaged envelope:
    /// nothing can be named, and the record is not recoverable from itself.
    TruncatedHeader { len: usize },
    /// A well-formed envelope this binary has no reader for, with both ids
    /// known. Intact and locatable — the wallet is elsewhere, not lost.
    Wrapped { format: &'static str, protection: &'static str },
    /// A well-formed envelope carrying a format or protection id this binary
    /// does not know. Written by a newer tool; never "corrupt".
    Unknown { format: u8, protection: u8 },
}

/// Classify a seed file that is **not** of the plain length.
///
/// Call this only from that arm (see the module docs on collision-freedom).
pub fn inspect(bytes: &[u8]) -> Verdict {
    if !bytes.starts_with(&MAGIC) {
        return Verdict::NotAnEnvelope;
    }
    if bytes.len() < HEADER_LEN {
        return Verdict::TruncatedHeader { len: bytes.len() };
    }
    let format = bytes[MAGIC.len()];
    let protection = bytes[MAGIC.len() + 1];
    match (name_of(FORMATS, format), name_of(PROTECTIONS, protection)) {
        (Some(format), Some(protection)) => Verdict::Wrapped { format, protection },
        // Either id unknown is the same situation: a record written against a
        // registry this binary does not have. Both raw ids are reported so the
        // refusal is actionable without a debugger.
        _ => Verdict::Unknown { format, protection },
    }
}

fn name_of(table: &[(u8, &'static str)], id: u8) -> Option<&'static str> {
    table.iter().find(|(k, _)| *k == id).map(|(_, name)| *name)
}

/// The format ids this binary knows, for a refusal that tells the user what it
/// was expecting. Rendered from the registry so the two cannot drift.
pub fn known_format_ids() -> String {
    id_list(FORMATS)
}

/// The protection ids this binary knows. See [`known_format_ids`].
pub fn known_protection_ids() -> String {
    id_list(PROTECTIONS)
}

fn id_list(table: &[(u8, &str)]) -> String {
    let ids: Vec<String> = table.iter().map(|(k, _)| format!("{k}")).collect();
    ids.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_wallet::seed::ENTROPY_LEN;

    fn envelope(format: u8, protection: u8, payload_len: usize) -> Vec<u8> {
        let mut v = MAGIC.to_vec();
        v.push(format);
        v.push(protection);
        v.extend(std::iter::repeat_n(0xAB, payload_len));
        v
    }

    /// The magic is a wire constant that other repos will key on: a golden
    /// vector, not a re-spelling of the definition.
    #[test]
    fn the_magic_and_header_length_are_golden() {
        assert_eq!(MAGIC, [0x51, 0x4D, 0x42, 0x53, 0x45, 0x45, 0x44, 0x00]);
        assert_eq!(&MAGIC, b"QMBSEED\0");
        assert_eq!(HEADER_LEN, 10);
        assert!(MAGIC.len() >= 8, "issue #348 S3 requires at least 8 magic bytes");
    }

    /// The reserved registry is a published contract — the desktop task book
    /// cites these numbers, so a silent renumbering must fail here.
    #[test]
    fn the_reserved_registry_is_golden() {
        assert_eq!(FORMATS, &[(0x01u8, "wrapped-seed-v1")]);
        assert_eq!(
            PROTECTIONS,
            &[
                (0x01u8, "macOS Keychain (Secure-Enclave-held key)"),
                (0x02u8, "macOS Keychain (software key, P-256 fallback)"),
                (0x03u8, "Windows DPAPI (per-user software protection)"),
                (0x04u8, "Windows CNG (TPM-backed)"),
                (0x05u8, "Linux Secret Service"),
            ]
        );
        assert_eq!(known_format_ids(), "1");
        assert_eq!(known_protection_ids(), "1, 2, 3, 4, 5");
        // 0x00 is reserved-invalid in both tables, permanently.
        assert!(name_of(FORMATS, 0x00).is_none());
        assert!(name_of(PROTECTIONS, 0x00).is_none());
    }

    #[test]
    fn a_known_record_is_named_by_format_and_platform() {
        let v = inspect(&envelope(0x01, 0x01, 64));
        assert_eq!(
            v,
            Verdict::Wrapped {
                format: "wrapped-seed-v1",
                protection: "macOS Keychain (Secure-Enclave-held key)"
            }
        );
        // Every reserved protection id resolves to a name — an id that parses
        // but cannot be printed would be worse than an unreserved one.
        for (id, name) in PROTECTIONS {
            assert_eq!(
                inspect(&envelope(0x01, *id, 8)),
                Verdict::Wrapped { format: "wrapped-seed-v1", protection: name }
            );
        }
    }

    #[test]
    fn an_unknown_id_on_either_axis_is_a_newer_tool_not_a_wrapped_record() {
        assert_eq!(
            inspect(&envelope(0x7F, 0x01, 16)),
            Verdict::Unknown { format: 0x7F, protection: 0x01 },
            "unknown format, known protection"
        );
        assert_eq!(
            inspect(&envelope(0x01, 0x7F, 16)),
            Verdict::Unknown { format: 0x01, protection: 0x7F },
            "known format, unknown protection"
        );
        assert_eq!(
            inspect(&envelope(0x00, 0x00, 16)),
            Verdict::Unknown { format: 0, protection: 0 },
            "the reserved-invalid ids are unknown, never a match"
        );
    }

    #[test]
    fn magic_without_a_whole_header_is_a_damaged_envelope() {
        for len in 0..2 {
            let mut v = MAGIC.to_vec();
            v.extend(std::iter::repeat_n(0x01, len));
            assert_eq!(
                inspect(&v),
                Verdict::TruncatedHeader { len: MAGIC.len() + len },
                "magic + {len} byte(s) cannot name itself"
            );
        }
        // Exactly the header, no payload: nameable, so NOT truncated. What the
        // payload has to be is the writer's problem, not the discriminator's.
        assert!(matches!(inspect(&envelope(0x01, 0x05, 0)), Verdict::Wrapped { .. }));
    }

    #[test]
    fn anything_without_the_magic_is_not_an_envelope() {
        assert_eq!(inspect(&[]), Verdict::NotAnEnvelope);
        assert_eq!(inspect(&[0xFF; 41]), Verdict::NotAnEnvelope);
        // A truncated plain file — the case the magic was chosen against. Its
        // first byte is SEED_VERSION, which MAGIC[0] provably is not.
        let mut plain = vec![SEED_VERSION];
        plain.extend(std::iter::repeat_n(0x5A, ENTROPY_LEN));
        for cut in 1..plain.len() {
            assert_eq!(
                inspect(&plain[..cut]),
                Verdict::NotAnEnvelope,
                "a plain file truncated to {cut} bytes must never look like an envelope"
            );
        }
        // A near-miss magic is not the magic.
        let mut near = MAGIC.to_vec();
        near[7] = 0x01;
        near.extend([0x01, 0x01]);
        assert_eq!(inspect(&near), Verdict::NotAnEnvelope);
    }
}
