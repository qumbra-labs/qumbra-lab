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
#[derive(Clone)]
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

/// **Detection alone** — which of `bundle`'s outputs are addressed to `dk`, by
/// output index. One decapsulation, then the tag comparison, and nothing else.
///
/// ## Why this is a public primitive since issue #188 baton 2
///
/// Under `discovery-on-the-consensus-wire.md` the compact bundle — the shared
/// ML-KEM ct and the per-output `cm ‖ tag` — is **committed to the block body**,
/// while the AEAD payload [`scan`] needs is not. So *detecting* a payment is
/// answerable from chain data alone, and *opening* it is not, and the two stopped
/// being one operation on the day the first half moved onto the consensus wire.
///
/// This is what a wallet runs against a node's `/v1/compact`: it locates the
/// outputs paid to it without asking anybody for a payload, and therefore without
/// a server being in a position to hide one. Before this it existed only as a
/// private helper inside `qlab-cbserver`'s reference *client*, which is the wrong
/// home for the one operation the chain now guarantees.
///
/// **A match is a detection, not an authentication.** The tag's false-positive
/// rate is 2^-64 and a tag is not a signature; the authenticity check is
/// [`scan`]'s (FO inside `decapsulate`, plus the AEAD tag, plus — under
/// [`ScanMode::FoSkip`] — the commitment recompute). A caller that treats a
/// detection as a received note has skipped that.
pub fn detect_matches(dk: &Dk, bundle: &RecipientBundle) -> Vec<usize> {
    let k = decapsulate(dk, &bundle.ct);
    bundle
        .entries
        .iter()
        .enumerate()
        .filter(|(_, e)| detection_tag(&k, &digest_from_bytes(&e.cm)) == e.tag)
        .map(|(i, _)| i)
        .collect()
}

/// A sender sealed a note seed that contradicts the one the chain derives.
///
/// 🔴 **Diagnostics, not coverage — and the distinction is the whole point of
/// this type existing.**
///
/// **Coverage belongs entirely to the `cm` recompute in [`scan`]**, which is
/// unconditional in both scan modes: a wrong ρ produces a note whose recomputed
/// commitment does not match the entry's, so it is refused by every scanner class
/// before this type is ever consulted. Deleting the seed comparison removes **no**
/// refusal — `deleting_the_seed_check_does_not_weaken_the_refusal` pins exactly
/// that, and it is the test that keeps this label honest.
///
/// **What it buys is attribution, which is load-bearing one layer up.** An `ivk`
/// auditor who can say *"the sender sealed a ρ that contradicts the chain"* is
/// making a checkable accusation; one who can only say *"this does not open"* is
/// shrugging. That difference is the disclosure stack's operational value, and it
/// is why this is built rather than skipped as redundant.
///
/// **It is not a consensus rule and cannot become one.**
/// `discovery-on-the-consensus-wire.md` §4 rule 4 forbids consensus judging
/// payload validity, and here the prohibition is also a physical fact: the
/// payload is AEAD-sealed to a key no validator holds, so a node cannot run this
/// check even if the rule allowed it. (The #188 amendment's "a full-body observer
/// cross-checks payload-ρ" sentence was retracted by name on that ground.)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SealedSeedMismatch {
    /// Position within the transaction's outputs — the index ρ is derived at.
    pub output_index: usize,
    /// The seed the sender put in the AEAD payload.
    pub sealed: [u64; 4],
    /// The seed the chain derives from `nf_0` at this position (issue #215 (i)).
    pub derived: [u64; 4],
}

/// Cross-check the seed a sender **sealed** against the one the chain
/// **derives** at `output_index`, given the transaction's public `nf0`.
///
/// See [`SealedSeedMismatch`]: this attributes, it does not refuse. Callers that
/// want a refusal already have one in [`scan`]'s commitment recompute.
pub fn check_sealed_seed(
    note: &Note,
    nf0: &[u64; 4],
    output_index: usize,
) -> Result<(), SealedSeedMismatch> {
    let derived = qlab_air::narrow::derive_output_rho(nf0, output_index);
    if note.rho == derived {
        return Ok(());
    }
    Err(SealedSeedMismatch { output_index, sealed: note.rho, derived })
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
        // 🔴 **The commitment recompute is a post-match OBLIGATION, in both
        // modes.** It used to run only under `FoSkip`, on the reading that FO
        // inside `decapsulate` plus the AEAD tag already established
        // authenticity. They do — of the *ciphertext*. They say nothing about
        // whether the note inside it is the note the **chain committed**, which
        // is a different claim and the only one a wallet can spend on.
        //
        // A sender who encrypts note A while the entry carries `cm(B)` produces
        // a payload that decapsulates cleanly and whose AEAD tag verifies, so the
        // old `FullFo` arm accepted it and reported a note at a commitment the
        // tree does not hold — unspendable, and detected as a balance only much
        // later. Since issue #188 (a) the payload is **committed**, so that
        // mismatch is a fact about the block rather than a serving accident, and
        // a scanner must refuse it.
        //
        // This does not weaken `FullFo` or relax `anon-cca-fo-skip`'s boundary:
        // the FO check still runs inside `decapsulate` on the standard path, and
        // the recompute is added *after* the match rather than substituted for
        // anything. `FoSkip` is unchanged — it was already carrying this check as
        // its whole authenticity argument.
        if !recompute_matches(&note, &entry.cm) {
            continue;
        }
        match mode {
            ScanMode::FullFo => {
                // FO ran inside `decapsulate`; AEAD tag verified above; the
                // recompute above binds the note to the committed `cm`.
            }
            ScanMode::FoSkip => {
                // Authenticity rests on the recompute above, FO skipped.
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

    #[test]
    fn wrong_key_no_detection() {
        let mut rng = StdRng::seed_from_u64(11);
        let kp = generate_keypair(&mut rng);
        let attacker = generate_keypair(&mut rng);
        let out = encrypt_to_recipient(&kp.ek, &[note(3), note(4)], &mut rng);
        for mode in [ScanMode::FullFo, ScanMode::FoSkip] {
            assert!(
                scan(&attacker.dk, &out, mode).is_empty(),
                "{mode:?}: wrong key must detect nothing"
            );
        }
    }

    #[test]
    fn tampered_mlkem_ct_no_detection() {
        // Flipping the shared ML-KEM ct changes the decapsulated K → tag miss.
        let mut rng = StdRng::seed_from_u64(12);
        let kp = generate_keypair(&mut rng);
        let mut out = encrypt_to_recipient(&kp.ek, &[note(5)], &mut rng);
        out.bundle.ct[100] ^= 0x01;
        for mode in [ScanMode::FullFo, ScanMode::FoSkip] {
            assert!(scan(&kp.dk, &out, mode).is_empty(), "{mode:?}: tampered ct");
        }
    }

    #[test]
    fn tampered_aead_payload_fails() {
        // Tag/cm untouched → detection proceeds, but the AEAD Poly1305 tag
        // rejects the tampered payload → the note is dropped on BOTH paths.
        let mut rng = StdRng::seed_from_u64(13);
        let kp = generate_keypair(&mut rng);
        let mut out = encrypt_to_recipient(&kp.ek, &[note(6)], &mut rng);
        let last = out.payloads[0].len() - 1;
        out.payloads[0][last] ^= 0x01;
        for mode in [ScanMode::FullFo, ScanMode::FoSkip] {
            assert!(scan(&kp.dk, &out, mode).is_empty(), "{mode:?}: tampered payload");
        }
    }

    #[test]
    fn tampered_cm_no_detection() {
        // The tag binds cm, so a tampered on-wire cm misses at the pre-filter
        // (the recompute gate itself is covered by recompute_gate_rejects_tampered_cm).
        let mut rng = StdRng::seed_from_u64(14);
        let kp = generate_keypair(&mut rng);
        let mut out = encrypt_to_recipient(&kp.ek, &[note(7)], &mut rng);
        out.bundle.entries[0].cm[0] ^= 0x01;
        assert!(
            scan(&kp.dk, &out, ScanMode::FoSkip).is_empty(),
            "tampered cm must not yield an accepted note"
        );
    }

    /// 🔴 The check that was **present but asleep** under `FullFo`, made to fail.
    ///
    /// Both entries keep a self-consistent `(cm, tag)` pair — the pairs are
    /// swapped between positions, so every tag still matches the `cm` beside it
    /// and the detection filter passes. The payloads are untouched, so the AEAD
    /// decrypt at each index also passes. The **only** thing wrong is that the
    /// note a position opens is not the note that position's `cm` commits to.
    ///
    /// Before the recompute became unconditional, `FullFo` accepted both and
    /// reported each note against the other's commitment — a note no tree holds.
    #[test]
    fn a_payload_that_does_not_open_the_committed_cm_is_refused_in_both_modes() {
        let mut rng = StdRng::seed_from_u64(31);
        let kp = generate_keypair(&mut rng);
        let ns = [note(30), note(31)];
        let honest = encrypt_to_recipient(&kp.ek, &ns, &mut rng);
        // Control: honest outputs are found in both modes.
        for mode in [ScanMode::FullFo, ScanMode::FoSkip] {
            assert_eq!(scan(&kp.dk, &honest, mode).len(), 2, "{mode:?}: control");
        }
        let mut swapped = honest.clone();
        swapped.bundle.entries.swap(0, 1);
        for mode in [ScanMode::FullFo, ScanMode::FoSkip] {
            let found = scan(&kp.dk, &swapped, mode);
            assert!(
                found.is_empty(),
                "{mode:?}: a note that does not open its own committed cm was ACCEPTED \
                 ({} found) — the recompute is not running",
                found.len()
            );
        }
    }

    /// 🔴 **The test that keeps `SealedSeedMismatch`'s label honest.**
    ///
    /// A forged payload — a note sealed at a seed the chain does not derive — must
    /// be refused **by the commitment recompute alone**, with the seed comparison
    /// taking no part in it. That is what makes the diagnostic a diagnostic.
    ///
    /// The test does not simulate deleting the check; it demonstrates the check is
    /// not in the refusal path at all, by showing the refusal happening in `scan`
    /// (which never calls `check_sealed_seed`) and the attribution happening
    /// separately, on the same forgery, in a caller that does.
    #[test]
    fn deleting_the_seed_check_does_not_weaken_the_refusal() {
        let mut rng = StdRng::seed_from_u64(41);
        let kp = generate_keypair(&mut rng);
        let nf0 = [0xfeedu64, 2, 3, 4];

        // Honest: the sender seals the seed the chain derives at output 0.
        let honest = Note {
            value: 4_242,
            rkm: [7u64, 7, 7, 7],
            rho: qlab_air::narrow::derive_output_rho(&nf0, 0),
            rseed: [9u64, 9, 9, 9],
        };
        let good = encrypt_to_recipient(&kp.ek, &[honest], &mut rng);
        for mode in [ScanMode::FullFo, ScanMode::FoSkip] {
            assert_eq!(scan(&kp.dk, &good, mode).len(), 1, "{mode:?}: control");
        }
        assert_eq!(check_sealed_seed(&honest, &nf0, 0), Ok(()), "honest seed attributes clean");

        // Forged: the sender seals a seed of its own choosing. Its `cm` is
        // self-consistent — `encrypt_to_recipient` derives the entry from the note
        // it is given — so the AEAD opens and the tag matches. The ONLY thing
        // wrong is that the chain derives a different seed at this position.
        let forged = Note { rho: [0xdead_beefu64, 1, 2, 3], ..honest };
        assert_ne!(forged.rho, honest.rho);
        let bad = encrypt_to_recipient(&kp.ek, &[forged], &mut rng);

        // (1) `scan` FINDS it — and that is correct and not a hole. Nothing here
        //     knows `nf0`, so at this layer the forgery is a well-formed note
        //     whose commitment is self-consistent. The refusal that matters
        //     happens where the CHAIN's `cm` is the comparand, which is the entry
        //     the block committed — see (3).
        for mode in [ScanMode::FullFo, ScanMode::FoSkip] {
            let found = scan(&kp.dk, &bad, mode);
            assert_eq!(found.len(), 1, "{mode:?}: self-consistent forgery opens");
            assert_eq!(found[0].note.rho, forged.rho);
        }

        // (2) The diagnostic attributes it, which is its entire job.
        let attributed = check_sealed_seed(&forged, &nf0, 0).expect_err("must attribute");
        assert_eq!(attributed.output_index, 0);
        assert_eq!(attributed.sealed, forged.rho);
        assert_eq!(attributed.derived, honest.rho);

        // (3) 🔴 And the REFUSAL is the recompute's, with the seed check absent.
        //     Against the commitment the chain actually holds — the honest note's
        //     — the forged note does not recompute. `scan` never calls
        //     `check_sealed_seed`, so this refusal is coverage the diagnostic
        //     contributes nothing to. Delete `check_sealed_seed` entirely and this
        //     assertion still holds; that is the label, pinned.
        let committed_cm = digest_bytes(&honest.commitment());
        assert!(
            !recompute_matches(&forged, &committed_cm),
            "the forgery must be refused by the cm recompute ALONE"
        );
        assert!(recompute_matches(&honest, &committed_cm), "control: honest recomputes");
    }

    #[test]
    fn amortization_two_outputs_one_ct() {
        // A 2-output tx to one recipient shares ONE ML-KEM ct; both detect.
        let mut rng = StdRng::seed_from_u64(15);
        let kp = generate_keypair(&mut rng);
        let n0 = note(20);
        let n1 = note(21);
        let out = encrypt_to_recipient(&kp.ek, &[n0, n1], &mut rng);
        // One shared ciphertext, two entries.
        assert_eq!(out.bundle.entries.len(), 2);
        assert_eq!(out.bundle.ct.len(), 1088);
        assert_eq!(
            out.bundle.compact_stream_len(),
            1088 + 2 * CompactEntry::LEN_EMPTY_CLUE
        );
        for mode in [ScanMode::FullFo, ScanMode::FoSkip] {
            let found = scan(&kp.dk, &out, mode);
            assert_eq!(found.len(), 2, "{mode:?}: both amortized notes detected");
            assert_eq!(found[0].note, n0);
            assert_eq!(found[1].note, n1);
        }
    }
}
