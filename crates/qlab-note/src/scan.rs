//! Sender encryption and the client scan flow — BOTH variants behind a flag.
//!
//! Per note-discovery.md §2 client flow:
//!   decap once per (tx, recipient) → derive note keys → check tag → on match,
//!   decrypt the payload and (path b) recompute cm and compare → accept.
//!
//! Two scan modes:
//! - [`ScanMode::FullFo`] — the DEFAULT. Standard IND-CCA usage: the KEM's
//!   Fujisaki–Okamoto check runs inside `decapsulate`; authenticity of a
//!   detected note rests on that + the AEAD tag.
//! - [`ScanMode::FoSkip`] — EXPERIMENTAL. Models the ratified FO-skip path:
//!   authenticity rests on recomputing the note commitment and comparing it to
//!   the on-chain `cm` (the object the circuit binds). The ANON-CCA security
//!   argument that justifies skipping FO is an OPEN design-repo obligation
//!   (doc §2) — NOT decided here. (Note: `ml-kem` 0.3.2 does not expose
//!   CPA-decap, so both modes call the same `decapsulate`; FoSkip changes the
//!   AUTHENTICITY MODEL, and the compute saving is measured by decomposition
//!   in the bench — see `kem`.)

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use rand::CryptoRng;

use crate::derive::{aead_key, aead_nonce, detection_tag};
use crate::hash::{digest_bytes, digest_from_bytes};
use crate::kem::{decapsulate, encapsulate, Dk, Ek};
use crate::note::Note;
use crate::wire::{ClueSlot, CompactEntry, RecipientBundle};

/// Scan-time authenticity model (the flag of item 4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ScanMode {
    /// Standard full-FO decapsulation (default; IND-CCA).
    FullFo,
    /// EXPERIMENTAL FO-skip: authenticity via note-commitment recompute.
    FoSkip,
}

/// Everything produced for one `(tx, recipient)`: the compact bundle (shared
/// ct + per-note entries) plus the AEAD payloads that a wallet full-fetches
/// only for matched notes.
pub struct EncryptedOutputs {
    pub bundle: RecipientBundle,
    /// AEAD ciphertext per output (index-aligned with `bundle.entries`).
    pub payloads: Vec<Vec<u8>>,
}

/// A detected + decrypted note and its output index.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DetectedNote {
    pub index: usize,
    pub note: Note,
}

/// Encrypt `notes` to a single recipient `ek`, sharing ONE ML-KEM ciphertext
/// across all of them (the amortization structure). Output index `i` binds the
/// per-note AEAD key/nonce.
pub fn encrypt_to_recipient<R: CryptoRng>(
    ek: &Ek,
    notes: &[Note],
    rng: &mut R,
) -> EncryptedOutputs {
    let (ct, k) = encapsulate(ek, rng);
    let mut entries = Vec::with_capacity(notes.len());
    let mut payloads = Vec::with_capacity(notes.len());
    for (i, note) in notes.iter().enumerate() {
        let cm = note.commitment();
        let tag = detection_tag(&k, &cm);
        let cipher = ChaCha20Poly1305::new_from_slice(&aead_key(&k, i as u32))
            .expect("32-byte key");
        let nonce = Nonce::try_from(aead_nonce(&k, i as u32).as_slice()).expect("12-byte nonce");
        let payload = cipher
            .encrypt(&nonce, note.to_plaintext().as_slice())
            .expect("AEAD encryption is infallible for a valid key/nonce");
        entries.push(CompactEntry {
            cm: digest_bytes(&cm),
            tag,
            clue: ClueSlot::Empty,
        });
        payloads.push(payload);
    }
    EncryptedOutputs {
        bundle: RecipientBundle { ct, entries },
        payloads,
    }
}

/// FoSkip authenticity gate: does the note recovered from the payload recompute
/// to the `cm` stored on the wire? This is the "recompute the note commitment"
/// check that replaces the FO re-encryption at scan time.
pub fn recompute_matches(note: &Note, stored_cm_bytes: &[u8; 32]) -> bool {
    digest_bytes(&note.commitment()) == *stored_cm_bytes
}

/// Scan a recipient's outputs with the recipient's decapsulation key. Returns
/// the notes that are detected AND pass the mode's authenticity check.
pub fn scan(dk: &Dk, out: &EncryptedOutputs, mode: ScanMode) -> Vec<DetectedNote> {
    // decap once per (tx, recipient).
    let k = decapsulate(dk, &out.bundle.ct);
    let mut found = Vec::new();
    for (i, entry) in out.bundle.entries.iter().enumerate() {
        // Cheap pre-filter: does the tag match? (2^-64 FP; wrong key misses.)
        let cm_lanes = digest_from_bytes(&entry.cm);
        if detection_tag(&k, &cm_lanes) != entry.tag {
            continue;
        }
        // On match, full-fetch + AEAD-decrypt the payload.
        let Some(payload) = out.payloads.get(i) else {
            continue;
        };
        let cipher = ChaCha20Poly1305::new_from_slice(&aead_key(&k, i as u32))
            .expect("32-byte key");
        let nonce = Nonce::try_from(aead_nonce(&k, i as u32).as_slice()).expect("12-byte nonce");
        let Ok(pt) = cipher.decrypt(&nonce, payload.as_slice()) else {
            continue; // tampered payload / wrong key
        };
        let Some(note) = Note::from_plaintext(&pt) else {
            continue;
        };
        // Authenticity.
        match mode {
            ScanMode::FullFo => {
                // FO ran inside decapsulate; AEAD tag verified above. Accept.
            }
            ScanMode::FoSkip => {
                // Authenticity via commitment recompute (FO skipped).
                if !recompute_matches(&note, &entry.cm) {
                    continue;
                }
            }
        }
        found.push(DetectedNote { index: i, note });
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::generate_keypair;
    use rand::{rngs::StdRng, SeedableRng};

    fn note(seed: u64) -> Note {
        let lane = |k: u64| core::array::from_fn::<u64, 4, _>(|i| seed ^ (k << 8) ^ (i as u64 + 1));
        Note {
            value: 500 + seed,
            rkm: lane(1),
            rho: lane(2),
            rseed: lane(3),
        }
    }

    #[test]
    fn roundtrip_both_paths() {
        let mut rng = StdRng::seed_from_u64(10);
        let kp = generate_keypair(&mut rng);
        let n = note(1);
        let out = encrypt_to_recipient(&kp.ek, &[n], &mut rng);
        for mode in [ScanMode::FullFo, ScanMode::FoSkip] {
            let found = scan(&kp.dk, &out, mode);
            assert_eq!(found.len(), 1, "{mode:?}: one note detected");
            assert_eq!(found[0].note, n, "{mode:?}: decrypted note matches");
            assert_eq!(found[0].index, 0);
        }
    }

    #[test]
    fn recompute_gate_rejects_tampered_cm() {
        // The FoSkip authenticity gate in isolation (item 5).
        let n = note(2);
        let good = digest_bytes(&n.commitment());
        assert!(recompute_matches(&n, &good));
        let mut bad = good;
        bad[0] ^= 0x01;
        assert!(!recompute_matches(&n, &bad), "tampered cm must fail recompute");
    }
}
