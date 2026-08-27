//! The scan-resume artifact (lab #568 step 2) — a **sealed** state a shell can
//! store and hand back, and cannot read.
//!
//! # Why sealed, when the ledger blob beside it is plaintext
//!
//! [`crate::ledger_blob`] carries heights, values and prose to a layer whose job
//! is to *display* them, and its doc states the rule that follows from that:
//! **no key material — never `rho`/`rseed`/seed/spending material.**
//!
//! A resume state cannot obey that rule and still be a resume state. It must
//! carry the located notes, because a state carrying only figures can neither
//! shadow a later nullifier collision nor feed selection — and a `LocatedNote`
//! holds a [`qlab_note::note::Note`], i.e. `{ value, rkm, rho, rseed }`. That is
//! not seed-grade and it is not nothing: ρ determines the nullifier
//! (`nf = H(nk ‖ ρ)`), and `value` is the balance.
//!
//! In a browser shell a plaintext artifact would sit in `chrome.storage.local`,
//! where today only the seed sits — sealed, and only when its owner opted in.
//! Putting note plaintext there by default, as a *performance* feature, is not a
//! trade to make quietly. So the kernel seals it and the shell stores bytes it
//! cannot interpret. Inside the seal the plaintext is still the tagged
//! length-prefixed blob of [`crate::ledger_blob`]'s shape, which earns its keep
//! for forward compatibility of record kinds — the reason it was chosen.
//!
//! # The wallet binding comes free, and structurally
//!
//! `ClaimSet`'s own doc says *"one wallet per set, and the type cannot enforce
//! it"*: `nf = keccak(nk ‖ ρ)` collides on equal ρ only when `nk` is equal too,
//! so a set built from another wallet's scans yields **false positives** and
//! writes off a live note. Resume is the first thing that makes that reachable
//! across sessions.
//!
//! Because the seal key derives from the wallet's own `nk`, a resume against a
//! different wallet **cannot decrypt**. A refusal by failed AEAD is not a check
//! somebody can forget to call.
//!
//! # Layout
//!
//! ```text
//! artifact := header || sealed_body
//! header   := u8 version
//!          || [32] genesis
//!          || u8 coverage_tag (0 = Empty, 1 = Range)
//!          || u64le from || u64le to        (zeroed when Empty)
//!          || u8 finalized                 (1 = the watermark is a FINALIZED height)
//!          || [12] nonce
//! ```
//!
//! The header is **cleartext and authenticated**: it is passed verbatim as the
//! AEAD's associated data, so editing it breaks the seal rather than shifting
//! what opens.
//!
//! It is cleartext on purpose. Without it a shell cannot tell *"this artifact is
//! for another network"* from *"this artifact is for another wallet"*, and those
//! are two different sentences a person needs. The cost is that the artifact
//! reveals that this wallet scanned this network up to height H — already
//! inferable from the storage key existing at all, where the alternative is a
//! wallet that can only say "refused" and never explain itself.
//!
//! 🔴 `finalized` is in the header because it decides whether a watermark
//! **exists**, not how good it is: a scan whose upper bound fell back to the tip
//! (nothing finalized yet) has no finality behind it and produces no resumable
//! watermark. `Some` vs `None` is not a detail to flatten.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use qlab_ledger::coverage::Coverage;
use qlab_note::hash::{digest_bytes, keccak256};
use qlab_wallet::viewing::Wallet;

/// Domain string: `resume_key = Keccak256(DS_RESUME_SEAL ‖ digest_bytes(nk))`.
///
/// House style (`qlab_wallet::viewing::DS_DIV_SEED` and friends). Versioned in
/// the string: a change to what the sealed body means gets `:v2` and old
/// artifacts then fail to open, which is the honest outcome — an artifact whose
/// meaning moved must not be read under the new meaning.
pub const DS_RESUME_SEAL: &[u8] = b"qumbra:wallet:resume-seal:v1";

/// The artifact's own version byte, for the header's layout.
pub const RESUME_VERSION: u8 = 1;

const GENESIS_LEN: usize = 32;
const NONCE_LEN: usize = 12;
/// version + genesis + coverage tag + from + to + finalized + nonce
const HEADER_LEN: usize = 1 + GENESIS_LEN + 1 + 8 + 8 + 1 + NONCE_LEN;

/// What the header says, without opening anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResumeHeader {
    pub genesis: [u8; GENESIS_LEN],
    pub coverage: Coverage,
    /// The watermark is a height the endpoint reported FINALIZED at scan time.
    /// A `false` here means there is no resumable watermark (see the module doc).
    pub finalized: bool,
}

/// Why an artifact could not be used. Every variant is a sentence a shell can
/// show, because "resume failed" tells a person nothing about what to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResumeRefusal {
    /// Too short, or a version this build does not know.
    Malformed { why: String },
    /// The artifact is for a different chain than the endpoint being resumed
    /// against. Names both, because the user's next move depends on which is
    /// wrong.
    WrongNetwork { artifact: String, endpoint: String },
    /// The seal did not open: a different wallet, or tampered bytes. Those two
    /// are indistinguishable by design — the AEAD does not say which.
    Sealed,
    /// The artifact carries no finalized watermark, so there is nothing to
    /// resume FROM even though it decrypted.
    NoWatermark,
}

impl std::fmt::Display for ResumeRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResumeRefusal::Malformed { why } => write!(f, "resume state is malformed: {why}"),
            ResumeRefusal::WrongNetwork { artifact, endpoint } => write!(
                f,
                "this resume state is for network {artifact} and this endpoint serves {endpoint} \
                 — scan from the start against this endpoint instead of resuming"
            ),
            ResumeRefusal::Sealed => write!(
                f,
                "this resume state does not open with this wallet's key — it belongs to another \
                 wallet, or it has been altered. Scan from the start."
            ),
            ResumeRefusal::NoWatermark => write!(
                f,
                "this resume state was taken from a scan with nothing finalized, so it carries no \
                 height to resume from. Scan from the start."
            ),
        }
    }
}

impl std::error::Error for ResumeRefusal {}

/// `resume_key = Keccak256(DS_RESUME_SEAL ‖ digest_bytes(nk))`.
fn resume_key(wallet: &Wallet) -> [u8; 32] {
    let mut input = Vec::with_capacity(DS_RESUME_SEAL.len() + 32);
    input.extend_from_slice(DS_RESUME_SEAL);
    input.extend_from_slice(&digest_bytes(&wallet.nk()));
    keccak256(&input)
}

/// The 12-byte nonce as the AEAD's type. `from_slice` is deprecated in
/// chacha20poly1305 0.11; `try_from` is the replacement and the length is a
/// compile-time constant here, so the expect is unreachable.
fn nonce_of(n: &[u8; NONCE_LEN]) -> Nonce {
    Nonce::try_from(n.as_slice()).expect("12-byte nonce")
}

fn write_header(h: &ResumeHeader, nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN);
    out.push(RESUME_VERSION);
    out.extend_from_slice(&h.genesis);
    match h.coverage {
        Coverage::Empty => {
            out.push(0);
            out.extend_from_slice(&0u64.to_le_bytes());
            out.extend_from_slice(&0u64.to_le_bytes());
        }
        Coverage::Range { from, to } => {
            out.push(1);
            out.extend_from_slice(&from.to_le_bytes());
            out.extend_from_slice(&to.to_le_bytes());
        }
    }
    out.push(u8::from(h.finalized));
    out.extend_from_slice(nonce);
    out
}

/// Read the header without opening the seal — the only thing a shell may learn
/// from an artifact it cannot decrypt.
pub fn read_header(artifact: &[u8]) -> Result<ResumeHeader, ResumeRefusal> {
    if artifact.len() < HEADER_LEN {
        return Err(ResumeRefusal::Malformed {
            why: format!("{} bytes, header alone needs {HEADER_LEN}", artifact.len()),
        });
    }
    if artifact[0] != RESUME_VERSION {
        return Err(ResumeRefusal::Malformed {
            why: format!(
                "version {} — this build reads {RESUME_VERSION}. A state whose meaning moved must \
                 not be read under the new meaning",
                artifact[0]
            ),
        });
    }
    let mut genesis = [0u8; GENESIS_LEN];
    genesis.copy_from_slice(&artifact[1..1 + GENESIS_LEN]);
    let p = 1 + GENESIS_LEN;
    let tag = artifact[p];
    let from = u64::from_le_bytes(artifact[p + 1..p + 9].try_into().unwrap());
    let to = u64::from_le_bytes(artifact[p + 9..p + 17].try_into().unwrap());
    let coverage = match tag {
        0 => Coverage::Empty,
        1 => Coverage::range(from, to),
        other => {
            return Err(ResumeRefusal::Malformed {
                why: format!("coverage tag {other} is not 0 or 1"),
            })
        }
    };
    let finalized = match artifact[p + 17] {
        0 => false,
        1 => true,
        // Any nonzero could have been read as true. It is refused instead: a
        // byte we did not write means bytes we do not understand, and guessing
        // "finalized" is guessing that a watermark is safe to resume from.
        other => {
            return Err(ResumeRefusal::Malformed {
                why: format!("finalized flag is {other}, not 0 or 1"),
            })
        }
    };
    Ok(ResumeHeader { genesis, coverage, finalized })
}

/// Seal `body` for `wallet` under `header`. `nonce` is supplied rather than
/// generated here so the caller owns entropy (the platform does, in this ABI)
/// and so tests are deterministic.
pub fn seal(
    wallet: &Wallet,
    header: &ResumeHeader,
    nonce: &[u8; NONCE_LEN],
    body: &[u8],
) -> Vec<u8> {
    let key = resume_key(wallet);
    let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("32-byte key");
    let head = write_header(header, nonce);
    let ct = cipher
        .encrypt(&nonce_of(nonce), Payload { msg: body, aad: &head })
        .expect("ChaCha20-Poly1305 encryption of an in-memory buffer cannot fail");
    let mut out = head;
    out.extend_from_slice(&ct);
    out
}

/// Open an artifact for `wallet`, checking it is for `endpoint_genesis` first.
///
/// Order matters and is part of the contract: the **network** is checked before
/// the seal, so an artifact from another chain says so by name instead of
/// reporting the generic "does not open with this wallet's key". A user pointed
/// at the wrong endpoint and a user with the wrong wallet need different
/// sentences.
pub fn open(
    wallet: &Wallet,
    endpoint_genesis: &[u8; GENESIS_LEN],
    artifact: &[u8],
) -> Result<(ResumeHeader, Vec<u8>), ResumeRefusal> {
    let header = read_header(artifact)?;
    if &header.genesis != endpoint_genesis {
        return Err(ResumeRefusal::WrongNetwork {
            artifact: hex32(&header.genesis),
            endpoint: hex32(endpoint_genesis),
        });
    }
    let head = &artifact[..HEADER_LEN];
    let nonce: [u8; NONCE_LEN] = artifact[HEADER_LEN - NONCE_LEN..HEADER_LEN].try_into().unwrap();
    let key = resume_key(wallet);
    let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("32-byte key");
    let body = cipher
        .decrypt(
            &nonce_of(&nonce),
            Payload { msg: &artifact[HEADER_LEN..], aad: head },
        )
        .map_err(|_| ResumeRefusal::Sealed)?;
    // 🔴 Enforced here rather than left to a caller. The ruling on #568: a
    // watermark may only be a height the endpoint reported FINALIZED, because
    // below a finalized checkpoint a change is a finality REVERSION and not a
    // reorg to reconcile. A scan whose upper bound fell back to the tip has no
    // finality behind it, so it carries no height to resume from — and an
    // artifact that decrypts is exactly when a caller is most likely to trust
    // it, which is why the gate is on this side of the seal.
    if !header.finalized || header.coverage.watermark().is_none() {
        return Err(ResumeRefusal::NoWatermark);
    }
    Ok((header, body))
}

fn hex32(b: &[u8; GENESIS_LEN]) -> String {
    let mut s = String::with_capacity(16);
    for x in &b[..8] {
        s.push_str(&format!("{x:02x}"));
    }
    s.push('…');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wallet(seed: u8) -> Wallet {
        Wallet::from_seed_lanes([seed as u64, 2, 3, 4])
    }
    const G: [u8; 32] = [7u8; 32];
    const N: [u8; 12] = [9u8; 12];

    fn header() -> ResumeHeader {
        ResumeHeader { genesis: G, coverage: Coverage::range(0, 1000), finalized: true }
    }

    #[test]
    fn a_sealed_state_round_trips_for_the_wallet_that_sealed_it() {
        let w = wallet(1);
        let body = b"the tagged blob would go here".to_vec();
        let art = seal(&w, &header(), &N, &body);
        let (h, out) = open(&w, &G, &art).expect("its own wallet must open it");
        assert_eq!(out, body);
        assert_eq!(h, header());
        assert_eq!(h.coverage.watermark(), Some(1000));
    }

    /// 🔴 The property the wallet binding exists for. `ClaimSet` is one-wallet-only
    /// and the type cannot enforce it; resuming another wallet's state writes off
    /// live notes as spent. Here it cannot even decrypt.
    #[test]
    fn another_wallets_state_does_not_open() {
        let mine = wallet(1);
        let theirs = wallet(2);
        let art = seal(&theirs, &header(), &N, b"their notes");
        assert_eq!(open(&mine, &G, &art).unwrap_err(), ResumeRefusal::Sealed);
        // And the sentence tells the user what to do rather than naming a cipher.
        let said = ResumeRefusal::Sealed.to_string();
        assert!(said.contains("another wallet"), "{said}");
        assert!(said.contains("Scan from the start"), "{said}");
    }

    /// The network is checked BEFORE the seal, so a cross-chain artifact gets its
    /// own sentence instead of the generic wrong-wallet one. Same wallet, so the
    /// only way this can report WrongNetwork is by checking in that order.
    #[test]
    fn a_state_from_another_chain_says_so_by_name_not_as_a_seal_failure() {
        let w = wallet(1);
        let art = seal(&w, &header(), &N, b"notes from T1");
        let other_chain = [8u8; 32];
        match open(&w, &other_chain, &art) {
            Err(ResumeRefusal::WrongNetwork { artifact, endpoint }) => {
                assert!(artifact.starts_with("0707"), "{artifact}");
                assert!(endpoint.starts_with("0808"), "{endpoint}");
            }
            other => panic!("expected WrongNetwork, got {other:?}"),
        }
        let said = ResumeRefusal::WrongNetwork {
            artifact: "aa…".into(),
            endpoint: "bb…".into(),
        }
        .to_string();
        assert!(said.contains("scan from the start"), "{said}");
    }

    /// 🔴 The header is cleartext, so it is the obvious thing to edit. Every
    /// field of it is authenticated: flipping one must break the seal, not
    /// change what opens. Without the AAD binding, an attacker could relabel a
    /// state's coverage — claiming a scan reached further than it did, which is
    /// a balance that looks complete and is not.
    #[test]
    fn every_header_field_is_authenticated() {
        let w = wallet(1);
        let art = seal(&w, &header(), &N, b"body");
        // Each of these offsets is a header field: genesis, coverage tag, from,
        // to, finalized, nonce. Genesis is skipped here because editing it
        // produces WrongNetwork (its own test above), which is also a refusal.
        for off in [1 + GENESIS_LEN, 1 + GENESIS_LEN + 1, 1 + GENESIS_LEN + 9, 1 + GENESIS_LEN + 17, HEADER_LEN - 1] {
            let mut bad = art.clone();
            bad[off] ^= 0x01;
            let got = open(&w, &G, &bad);
            assert!(
                got.is_err(),
                "editing header byte {off} did not refuse — got {got:?}"
            );
        }
        // And the body itself.
        let mut bad = art.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        assert_eq!(open(&w, &G, &bad).unwrap_err(), ResumeRefusal::Sealed);
    }

    /// Coverage must survive the header verbatim — including Empty, which is a
    /// covered state and NOT a range of zero.
    ///
    /// Read through `read_header`, not `open`, and the difference is the point:
    /// the header's job is to SAY what the artifact covers, and `open`'s job is
    /// to refuse a state with no resumable watermark. `Coverage::Empty` is a
    /// legitimate thing for a header to carry and an illegitimate thing to
    /// resume from, so testing the round trip through `open` conflated the two.
    /// It did, in the first version of this file: the NoWatermark gate landed in
    /// the same commit and this assertion was left calling `open().unwrap()` on
    /// Empty. CI caught it — see the note on the PR.
    #[test]
    fn coverage_survives_the_header_including_empty() {
        let w = wallet(1);
        for cov in [Coverage::Empty, Coverage::range(0, 0), Coverage::range(5, 9)] {
            let h = ResumeHeader { genesis: G, coverage: cov, finalized: true };
            let art = seal(&w, &h, &N, b"x");
            assert_eq!(
                read_header(&art).unwrap().coverage,
                cov,
                "coverage {cov:?} did not survive the header"
            );
        }
        // And the ones that CAN be resumed from still open, so this test is not
        // quietly asserting only the weaker half.
        for cov in [Coverage::range(0, 0), Coverage::range(5, 9)] {
            let h = ResumeHeader { genesis: G, coverage: cov, finalized: true };
            let art = seal(&w, &h, &N, b"x");
            let (back, body) = open(&w, &G, &art).expect("a finalized non-empty state opens");
            assert_eq!(back.coverage, cov);
            assert_eq!(body, b"x");
        }
        // Empty and 0..=0 must not encode to the same thing: one says nothing
        // was served, the other says height 0 was.
        let empty = seal(&w, &ResumeHeader { genesis: G, coverage: Coverage::Empty, finalized: true }, &N, b"x");
        let zero = seal(&w, &ResumeHeader { genesis: G, coverage: Coverage::range(0, 0), finalized: true }, &N, b"x");
        assert_ne!(empty, zero, "Empty was flattened into 0..=0");
        assert_eq!(read_header(&empty).unwrap().coverage.watermark(), None);
        assert_eq!(read_header(&zero).unwrap().coverage.watermark(), Some(0));
    }

    /// 🔴 finalized decides whether a watermark EXISTS. It must round-trip, and
    /// a byte we did not write must not be read as `true`.
    #[test]
    fn the_finalized_flag_round_trips_and_refuses_a_byte_we_did_not_write() {
        let w = wallet(1);
        for fin in [true, false] {
            let h = ResumeHeader { genesis: G, coverage: Coverage::range(0, 10), finalized: fin };
            let art = seal(&w, &h, &N, b"x");
            assert_eq!(read_header(&art).unwrap().finalized, fin);
        }
        let mut art = seal(&w, &header(), &N, b"x");
        art[1 + GENESIS_LEN + 17] = 2;
        match read_header(&art) {
            Err(ResumeRefusal::Malformed { why }) => assert!(why.contains("finalized"), "{why}"),
            other => panic!("a finalized byte of 2 was accepted: {other:?}"),
        }
    }

    /// 🔴 The ruling's Q3, enforced: a state from a scan with nothing finalized
    /// decrypts fine and is still refused, because there is no height behind it
    /// that a reorg could not move. Same for a decrypting state whose coverage
    /// is Empty — `finalized: true` over nothing is not a watermark either.
    #[test]
    fn a_state_without_a_finalized_watermark_is_refused_even_though_it_opens() {
        let w = wallet(1);
        for h in [
            ResumeHeader { genesis: G, coverage: Coverage::range(0, 1000), finalized: false },
            ResumeHeader { genesis: G, coverage: Coverage::Empty, finalized: true },
        ] {
            let art = seal(&w, &h, &N, b"body");
            // It reads: a shell may say WHY without opening anything.
            assert_eq!(read_header(&art).unwrap(), h);
            // It does not open for resume.
            assert_eq!(open(&w, &G, &art).unwrap_err(), ResumeRefusal::NoWatermark);
        }
        let said = ResumeRefusal::NoWatermark.to_string();
        assert!(said.contains("nothing finalized"), "{said}");
        assert!(said.contains("Scan from the start"), "{said}");
    }

    #[test]
    fn a_short_or_unknown_version_artifact_is_malformed_not_a_panic() {
        let w = wallet(1);
        for len in [0usize, 1, HEADER_LEN - 1] {
            let short = vec![RESUME_VERSION; len];
            assert!(matches!(read_header(&short), Err(ResumeRefusal::Malformed { .. })));
            assert!(matches!(open(&w, &G, &short), Err(ResumeRefusal::Malformed { .. })));
        }
        let mut art = seal(&w, &header(), &N, b"x");
        art[0] = RESUME_VERSION + 1;
        match read_header(&art) {
            Err(ResumeRefusal::Malformed { why }) => {
                assert!(why.contains("meaning"), "the reason must say why, not just refuse: {why}")
            }
            other => panic!("a future version was accepted: {other:?}"),
        }
    }

    #[test]
    fn a_coverage_tag_we_did_not_write_is_refused() {
        let w = wallet(1);
        let mut art = seal(&w, &header(), &N, b"x");
        art[1 + GENESIS_LEN] = 7;
        assert!(matches!(read_header(&art), Err(ResumeRefusal::Malformed { .. })));
    }

    /// Two seals of the same state under different nonces differ, and each opens.
    /// A fixed nonce would make two artifacts of one wallet byte-identical and
    /// leak equality of state across sessions.
    #[test]
    fn the_nonce_is_carried_and_used() {
        let w = wallet(1);
        let a = seal(&w, &header(), &[1u8; 12], b"same body");
        let b = seal(&w, &header(), &[2u8; 12], b"same body");
        assert_ne!(a, b, "the nonce did not reach the ciphertext");
        assert_eq!(open(&w, &G, &a).unwrap().1, b"same body");
        assert_eq!(open(&w, &G, &b).unwrap().1, b"same body");
    }

    /// The key is domain-separated from every other use of nk. Pinned as a
    /// property rather than a golden vector: a golden would also pass if the
    /// domain string were dropped from a DIFFERENT derivation that happened to
    /// collide, and what matters is that this key is not reachable another way.
    #[test]
    fn the_seal_key_is_domain_separated_from_nk_itself() {
        let w = wallet(1);
        let k = resume_key(&w);
        assert_ne!(k, digest_bytes(&w.nk()), "the key is the raw nk digest");
        assert_ne!(k, keccak256(&digest_bytes(&w.nk())), "the domain string is not mixed in");
        assert_ne!(resume_key(&wallet(2)), k, "two wallets share a key");
    }
}
