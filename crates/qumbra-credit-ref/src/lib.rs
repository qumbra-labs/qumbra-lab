//! Exchange crediting-flow reference — **stage 2** (lab #483): the credit
//! engine, transport-agnostic.
//!
//! The flow an exchange copies (`docs/kit-stage0-survey.md` §4, ratified with
//! out-of-band delivery as the design of record):
//!
//! ```text
//! envelope (however it arrived)             this engine
//!   ──────────────────────────►  1. peek: claim fields (no STARK yet)
//!                                2. is the claim about OUR deposit address?
//!                                3. read /v1/anchors: tip + finalized head
//!                                4. scan 0..=tip with our dk (the reference
//!                                   light client, verbatim — #297 seam)
//!                                5. candidates = our opened deposits whose
//!                                   value matches the claim
//!                                6. qlab_vask::verify against each candidate's
//!                                   COMMITTED cm — verification is what
//!                                   identifies the deposit (see below)
//!                                7. finalized? not already credited? → credit
//! ```
//!
//! ## Why matching is by `cm`, not by `tx_ref` — a finding, stated
//!
//! The envelope's `tx_ref` is a statement txid, but **the deployed serving
//! wire has no txid lookup**: `/v1/compact` names outputs by
//! `(height, tx_index, output_index)` and nothing serves txid → coordinates
//! (`qlab_node::rpc::tx_id` exists node-side only). It also does not need
//! one: `tx_ref`/`output_index` are envelope FRAMING, not public inputs — the
//! proof binds `(cm, addr_commitment, value)` (`qlab_disclosure::air::pv_vec`)
//! and `cm` is the chain's own unique, committed name for the output. So the
//! engine treats the locator fields as an advisory echo and keys everything
//! load-bearing on `cm`: the deposit credited is the one whose committed
//! commitment the proof actually verifies against, which is strictly stronger
//! than trusting a claimed txid. A production exchange with node access can
//! resolve `tx_ref` for bookkeeping; nothing in crediting requires it.
//!
//! ## What "credit" means here
//!
//! This is a reference, not a ledger: a credit is the verdict plus the
//! chain coordinates, and an in-memory credited-`cm` set enforces the one
//! crediting-semantics rule that must live server-side — **the same deposit
//! credits once** (`already-credited` on a replay). Everything else an
//! exchange adds (accounts, balances, persistence) hangs off [`Credited`].
//!
//! Boundaries, stated: one deposit address (a real exchange rotates many —
//! the addr-check generalizes to a set lookup); matches spendable notes only
//! (a shadowed deposit — one whose nullifier another of our notes already
//! claims — does not credit; pathological for a depositor to construct, and
//! crediting unspendable money would be worse); no rate limiter (#308's
//! lesson is cited in the shell docs, out of reference scope); the scan is
//! per-request over `0..=tip` (a real service caches by height).

use std::collections::BTreeSet;

use qlab_cbserver::client::{light_client_scan_with, Completeness, DecoyPolicy, ScanConfig};
use qlab_disclosure::packing::addr_commitment;
use qlab_node::AnchorSet;
use qlab_note::kem::Dk;
use qlab_vask::{Claim, VaskError};
use qlab_wallet::address::Diversifier;
use qlab_wallet::Wallet;
use rand::rngs::StdRng;
use rand::SeedableRng;

/// `/v1/anchors` — served by the same discovery endpoint the scan reads
/// (`qumbra-node/src/discovery_server.rs` `ANCHORS_PATH`; not imported, that
/// crate is the node binary's).
pub const ANCHORS_PATH: &str = "/v1/anchors";

/// The exchange's deposit identity: the viewing-side scan key and the address
/// commitment envelopes must name. Derived, never assembled by hand, so the
/// dk and the commitment cannot disagree about which address they are.
///
/// Devnet-grade custody, stated: derivation starts from the wallet seed. The
/// production shape is standing viewing-key custody (fvk/ivk — the
/// USDCx-on-Aleo precedent), which is #483 stage 3's documentation surface.
pub struct ExchangeKeys {
    dk: Dk,
    addr_commitment: [u8; 32],
}

impl ExchangeKeys {
    pub fn from_seed_lanes(seed: [u64; 4], d: Diversifier) -> ExchangeKeys {
        let wallet = Wallet::from_seed_lanes(seed);
        let addr = wallet.address(d);
        ExchangeKeys {
            dk: wallet.diversified_keypair(&d).dk,
            addr_commitment: addr_commitment(&addr.to_raw_bytes()),
        }
    }

    /// The Keccak-256 address commitment a valid deposit envelope must carry.
    pub fn addr_commitment(&self) -> [u8; 32] {
        self.addr_commitment
    }
}

/// A credit verdict: the proven claim and where on the chain it is true.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credited {
    pub claim: Claim,
    /// Committed coordinates of the credited deposit (the chain's own name
    /// for the output — `NoteRef` semantics, not the claim's advisory locator).
    pub height: u64,
    pub tx_index: u64,
    pub output_index: usize,
    pub cm: [u8; 32],
    /// The finalized head the credit was decided against.
    pub finalized_height: u64,
}

/// Named refusals — the house pattern. Every variant carries a stable token
/// (one grep covers the service) and maps to an HTTP status in the shell;
/// [`Refusal::http_status`] is the one mapping, test-locked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The envelope itself refused at the kit boundary (§3 rules 2–3 framing;
    /// carries qlab-vask's own named refusal).
    Envelope(VaskError),
    /// The claim names an address commitment that is not this exchange's
    /// deposit address — refused before any chain contact.
    NotOurAddress,
    /// The chain has no finalized head yet; nothing is creditable.
    NothingFinalized,
    /// The deposit exists and verifies but sits above the finalized head —
    /// retry after finality reaches it. Crediting on tip would credit
    /// reorg-able money (auditable-privacy §4: finalized = creditable).
    NotFinalized { deposit_height: u64, finalized: u64 },
    /// No deposit of ours matches the claimed value in `0..=tip`.
    DepositNotFound,
    /// Value-matching deposits exist, but the proof verifies against none of
    /// their committed commitments.
    ProofRefused { candidates: usize, reason: String },
    /// This deposit (by committed `cm`) has already been credited.
    AlreadyCredited { height: u64, tx_index: u64 },
    /// The scan could not read everything it detected — refusing rather than
    /// crediting on a partial view (the UNAVAILABLE discipline; #312's
    /// truncation-reads-as-complete lesson).
    ScanIncomplete { detail: String },
    /// The upstream node could not be read at all.
    Upstream { detail: String },
}

impl Refusal {
    /// The stable refusal token (kebab, machine-matchable).
    pub fn token(&self) -> &'static str {
        match self {
            Refusal::Envelope(VaskError::Malformed(_)) => "envelope-malformed",
            Refusal::Envelope(VaskError::UnknownVersion(_)) => "envelope-unknown-version",
            Refusal::Envelope(VaskError::UnknownClaimType(_)) => "envelope-unknown-claim-type",
            Refusal::Envelope(VaskError::ProofDecode) => "envelope-proof-decode",
            Refusal::Envelope(VaskError::ProofInvalid(_)) => "envelope-proof-invalid",
            Refusal::NotOurAddress => "not-our-address",
            Refusal::NothingFinalized => "nothing-finalized",
            Refusal::NotFinalized { .. } => "not-finalized",
            Refusal::DepositNotFound => "deposit-not-found",
            Refusal::ProofRefused { .. } => "proof-refused",
            Refusal::AlreadyCredited { .. } => "already-credited",
            Refusal::ScanIncomplete { .. } => "scan-incomplete",
            Refusal::Upstream { .. } => "upstream-unavailable",
        }
    }

    /// The HTTP status the shell answers with. Decisions are 4xx, never 5xx
    /// (the faucet's posture: a 500 says "the service broke" when in fact it
    /// decided). The two 503s are NOT decisions — the upstream could not be
    /// read, or read incompletely, and blaming the client with a 4xx would be
    /// the dishonest direction.
    pub fn http_status(&self) -> u16 {
        match self {
            Refusal::Envelope(VaskError::ProofInvalid(_)) => 422,
            Refusal::Envelope(_) => 400,
            Refusal::NotOurAddress => 422,
            Refusal::NothingFinalized => 409,
            Refusal::NotFinalized { .. } => 409,
            Refusal::DepositNotFound => 404,
            Refusal::ProofRefused { .. } => 422,
            Refusal::AlreadyCredited { .. } => 409,
            Refusal::ScanIncomplete { .. } => 503,
            Refusal::Upstream { .. } => 503,
        }
    }

    /// The human detail line beside the token.
    pub fn detail(&self) -> String {
        match self {
            Refusal::Envelope(e) => e.reason(),
            Refusal::NotOurAddress => {
                "the claimed address commitment is not this exchange's deposit address".into()
            }
            Refusal::NothingFinalized => {
                "the chain has no finalized head yet; nothing is creditable".into()
            }
            Refusal::NotFinalized { deposit_height, finalized } => format!(
                "deposit at height {deposit_height} is above the finalized head {finalized}; retry after finality"
            ),
            Refusal::DepositNotFound => {
                "no deposit to this exchange matches the claimed value up to the chain tip".into()
            }
            Refusal::ProofRefused { candidates, reason } => format!(
                "proof verifies against none of {candidates} value-matching deposit(s); last verifier reason: {reason}"
            ),
            Refusal::AlreadyCredited { height, tx_index } => format!(
                "this deposit (height {height}, tx {tx_index}) has already been credited"
            ),
            Refusal::ScanIncomplete { detail } => format!(
                "the deposit scan could not read everything it detected — refusing to decide on a partial view: {detail}"
            ),
            Refusal::Upstream { detail } => format!("the upstream node could not be read: {detail}"),
        }
    }
}

/// The credit engine. One instance per service; `try_credit` is the whole
/// decision path over a caller-supplied fetch (the #297 transport seam), so
/// the same engine runs over plaintext HTTP, TLS, or an in-memory fake.
pub struct CreditEngine {
    keys: ExchangeKeys,
    /// Committed `cm`s already credited — the once-only rule. In-memory by
    /// reference-service design; a real exchange persists this with its
    /// deposit records.
    credited: BTreeSet<[u8; 32]>,
    /// Decoy rng the scan signature requires; decoys are OFF (the service
    /// scans its own upstream — no fetch pattern to hide from yourself), so
    /// the seed is inert.
    rng: StdRng,
}

impl CreditEngine {
    pub fn new(keys: ExchangeKeys) -> CreditEngine {
        CreditEngine { keys, credited: BTreeSet::new(), rng: StdRng::seed_from_u64(0) }
    }

    /// How many deposits this engine has credited.
    pub fn credited_count(&self) -> usize {
        self.credited.len()
    }

    /// The address commitment valid deposit envelopes must name (for the
    /// status surface and startup log — an integrator's first cross-check).
    pub fn keys_addr_commitment(&self) -> [u8; 32] {
        self.keys.addr_commitment
    }

    /// Decide one envelope. `fetch` is the upstream read (`path → bytes`),
    /// exactly [`light_client_scan_with`]'s contract.
    pub fn try_credit<F>(&mut self, envelope: &[u8], fetch: &mut F) -> Result<Credited, Refusal>
    where
        F: FnMut(&str) -> Result<Vec<u8>, String>,
    {
        // 1–2. The claim, and is it about us — before any chain contact.
        let claim = qlab_vask::peek(envelope).map_err(Refusal::Envelope)?;
        if claim.addr_commitment != self.keys.addr_commitment {
            return Err(Refusal::NotOurAddress);
        }

        // 3. Tip + finalized head, from the same upstream the scan reads.
        let anchors = fetch(ANCHORS_PATH)
            .map_err(|detail| Refusal::Upstream { detail })
            .and_then(|bytes| {
                AnchorSet::from_bytes(&bytes).map_err(|e| Refusal::Upstream {
                    detail: format!("{ANCHORS_PATH} did not decode: {e:?}"),
                })
            })?;
        let finalized = anchors.finalized_height.ok_or(Refusal::NothingFinalized)?;

        // 4. The reference light client, verbatim. Scan to TIP, not to the
        // finalized head, so "your deposit is here but not finalized yet" and
        // "no such deposit" stay distinguishable refusals.
        let out = light_client_scan_with(
            fetch,
            &self.keys.dk,
            0,
            anchors.tip_height,
            ScanConfig { mode: qlab_note::scan::ScanMode::FullFo, decoy: DecoyPolicy::Off },
            &mut self.rng,
        )
        .map_err(|e| Refusal::Upstream { detail: e.to_string() })?;
        match out.completeness() {
            Completeness::Complete | Completeness::Shadowed { .. } => {}
            other => return Err(Refusal::ScanIncomplete { detail: format!("{other:?}") }),
        }

        // 5–6. Verification identifies the deposit: the claim carries no cm,
        // so the engine tries the proof against each value-matching committed
        // commitment (26 ms each, measured — docs/disclosure-run2.md; an
        // exchange's same-value candidate set is small).
        let candidates: Vec<_> =
            out.notes.iter().filter(|n| n.detected.note.value == claim.value).collect();
        if candidates.is_empty() {
            return Err(Refusal::DepositNotFound);
        }
        let mut last_reason = String::new();
        for cand in &candidates {
            match qlab_vask::verify(envelope, &cand.cm) {
                Ok(proven) => {
                    // 7. Policy, on the PROVEN deposit only.
                    if self.credited.contains(&cand.cm) {
                        return Err(Refusal::AlreadyCredited {
                            height: cand.height,
                            tx_index: cand.tx_index,
                        });
                    }
                    if cand.height > finalized {
                        return Err(Refusal::NotFinalized {
                            deposit_height: cand.height,
                            finalized,
                        });
                    }
                    self.credited.insert(cand.cm);
                    return Ok(Credited {
                        claim: proven,
                        height: cand.height,
                        tx_index: cand.tx_index,
                        output_index: cand.detected.index,
                        cm: cand.cm,
                        finalized_height: finalized,
                    });
                }
                Err(e) => last_reason = e.reason(),
            }
        }
        Err(Refusal::ProofRefused { candidates: candidates.len(), reason: last_reason })
    }
}

pub mod http;

#[cfg(test)]
mod citation_tests {
    //! Stage-0 citations (survey §1.3), kept live: the seams the crediting
    //! flow consumes exist with the inventoried signatures. Nothing here
    //! proves, opens a socket, or touches a chain.

    use qlab_cbserver::client::{light_client_scan_with, ScanConfig, ScanOutcome};
    use qlab_cbserver::codec::decode_full_response;
    use qlab_note::compact::PAYLOAD_LEN;
    use qlab_note::kem::Dk;
    use rand::rngs::StdRng;

    /// Survey §1.3: the transport-agnostic scan seam this engine is built on
    /// (stage 2 moved the citation from the socket wrapper to the seam the
    /// engine actually calls).
    #[test]
    fn the_scan_seam_exists() {
        fn _uses<F: FnMut(&str) -> Result<Vec<u8>, String>>(
            f: &mut F,
            dk: &Dk,
            rng: &mut StdRng,
        ) -> std::io::Result<ScanOutcome> {
            light_client_scan_with(f, dk, 0, 0, ScanConfig::default(), rng)
        }
    }

    /// Survey §1.3: the full-fetch decode the scan uses to open a matched
    /// deposit's payloads exists.
    #[test]
    #[allow(clippy::type_complexity)] // the citation IS the signature, verbatim
    fn the_full_fetch_decode_seam_exists() {
        let _decode: fn(&[u8]) -> Result<Vec<Vec<Vec<u8>>>, qlab_cbserver::codec::CodecError> =
            decode_full_response;
    }

    /// Survey §1.2 (the memo-gap finding's constant): the per-output AEAD
    /// payload on the deployed wire is fixed 120 B — no memo channel; the
    /// out-of-band delivery this service implements is the design of record
    /// (#483 stage-0 ruling).
    #[test]
    fn the_payload_is_fixed_120_bytes_no_memo_channel() {
        assert_eq!(PAYLOAD_LEN, 120);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A §3-framed envelope with chosen claim fields and garbage proof bytes —
    /// parses, peeks, and can never verify. The unit tests' whole vocabulary.
    fn framed_envelope(addr_commitment: [u8; 32], value: u64) -> Vec<u8> {
        let mut out = vec![0x01, 0x01];
        out.extend_from_slice(&[0x11u8; 32]); // tx_ref (advisory)
        out.extend_from_slice(&value.to_le_bytes());
        out.extend_from_slice(&addr_commitment);
        out.push(0); // output_index
        out.push(64); // proof_len varint
        out.extend_from_slice(&[0xEEu8; 64]);
        out
    }

    fn engine() -> CreditEngine {
        CreditEngine::new(ExchangeKeys::from_seed_lanes(
            [21, 22, 23, 24],
            Diversifier::from_bytes([0x2c; 16]),
        ))
    }

    /// The refusal table is total and stable: every refusal has a kebab token
    /// and a status; decisions are 4xx, and exactly the two cannot-answer
    /// refusals are 503 — a deliberate split from the faucet's 4xx-only
    /// posture, because "your upstream is down" blamed on the client would be
    /// the dishonest direction.
    #[test]
    fn every_refusal_has_a_token_and_no_decision_is_a_server_error() {
        let decisions = [
            Refusal::Envelope(VaskError::Malformed("x")),
            Refusal::Envelope(VaskError::UnknownVersion(2)),
            Refusal::Envelope(VaskError::UnknownClaimType(3)),
            Refusal::Envelope(VaskError::ProofDecode),
            Refusal::Envelope(VaskError::ProofInvalid("why".into())),
            Refusal::NotOurAddress,
            Refusal::NothingFinalized,
            Refusal::NotFinalized { deposit_height: 5, finalized: 3 },
            Refusal::DepositNotFound,
            Refusal::ProofRefused { candidates: 2, reason: "r".into() },
            Refusal::AlreadyCredited { height: 1, tx_index: 0 },
        ];
        for r in &decisions {
            assert!((400..500).contains(&r.http_status()), "{} is a decision", r.token());
            assert!(!r.token().is_empty() && !r.token().contains(' '));
        }
        let cannot_answer = [
            Refusal::ScanIncomplete { detail: "d".into() },
            Refusal::Upstream { detail: "d".into() },
        ];
        for r in &cannot_answer {
            assert_eq!(r.http_status(), 503, "{} is not a decision", r.token());
        }
        // The shipped tokens, by literal — a rename is a broken integration.
        assert_eq!(Refusal::DepositNotFound.token(), "deposit-not-found");
        assert_eq!(Refusal::NotOurAddress.token(), "not-our-address");
        assert_eq!(
            Refusal::AlreadyCredited { height: 0, tx_index: 0 }.token(),
            "already-credited"
        );
        assert_eq!(Refusal::Upstream { detail: String::new() }.token(), "upstream-unavailable");
    }

    /// Wrong-address claims refuse BEFORE any chain contact — the fetch here
    /// panics if touched, which is the assertion.
    #[test]
    fn a_claim_about_someone_elses_address_never_touches_the_chain() {
        let mut e = engine();
        let env = framed_envelope([0xab; 32], 1_000);
        let mut fetch = |_: &str| -> Result<Vec<u8>, String> {
            panic!("refusal must precede chain contact")
        };
        assert_eq!(e.try_credit(&env, &mut fetch), Err(Refusal::NotOurAddress));
    }

    /// An envelope the kit refuses at the boundary carries qlab-vask's own
    /// named refusal out, still with no chain contact.
    #[test]
    fn a_refused_envelope_carries_the_kits_named_refusal() {
        let mut e = engine();
        let mut fetch = |_: &str| -> Result<Vec<u8>, String> {
            panic!("refusal must precede chain contact")
        };
        let r = e.try_credit(&[0x02], &mut fetch).unwrap_err();
        assert_eq!(r.token(), "envelope-unknown-version");
        assert_eq!(r.http_status(), 400);
    }

    /// Upstream unreadable → 503 by name, not a guess and not a 4xx.
    #[test]
    fn an_unreadable_upstream_refuses_upstream_unavailable() {
        let mut e = engine();
        let ours = e.keys.addr_commitment;
        let env = framed_envelope(ours, 1_000);
        let mut fetch =
            |_: &str| -> Result<Vec<u8>, String> { Err("connection refused".into()) };
        let r = e.try_credit(&env, &mut fetch).unwrap_err();
        assert_eq!(r.token(), "upstream-unavailable");
        assert_eq!(r.http_status(), 503);
    }

    /// A chain with no finalized head credits nothing (finalized =
    /// creditable is the confirmation policy, not an option).
    #[test]
    fn a_chain_with_nothing_finalized_credits_nothing() {
        let mut e = engine();
        let ours = e.keys.addr_commitment;
        let env = framed_envelope(ours, 1_000);
        let anchors =
            AnchorSet { tip_height: 3, finalized_height: None, max_age_blocks: 64, roots: vec![] };
        let mut fetch = |path: &str| -> Result<Vec<u8>, String> {
            assert_eq!(path, ANCHORS_PATH, "nothing past anchors may be fetched");
            Ok(anchors.to_bytes())
        };
        assert_eq!(e.try_credit(&env, &mut fetch), Err(Refusal::NothingFinalized));
    }
}
