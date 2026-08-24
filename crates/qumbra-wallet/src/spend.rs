//! The spend flow, split at the one safe handoff: select → prove → submit.
//!
//! [`select`] owns the wallet/network work through finalized-anchor selection
//! and produces a versioned [`crate::bundle::WitnessBundle`]. [`prove`] consumes
//! that bundle plus freshly decoded public chain facts; it has no wallet dir,
//! network, caller-provided wallet RNG or second key source. (The prover itself
//! remains randomized.) [`submit`] accepts canonical wire bytes and returns the
//! node's typed answer. [`execute`] remains the CLI/desktop surface and is
//! exactly their composition, with the local send record kept before the socket
//! as required below.
//!
//! # Why this is separate from [`crate::send`]
//!
//! [`crate::send`] is the **builder/prover core**: selected notes and a tree in,
//! then a proved artifact out, no sockets. This module is the **flow** around it, and it is the
//! part that touches the network, the local send log, and the clock. Keeping them
//! apart keeps `send.rs` free of transport, which is the same boundary
//! `qlab-cbserver` keeps for a harder reason.
//!
//! # Why it is here at all, rather than in the CLI
//!
//! It was ~180 lines in `qumbra-wallet`'s `main.rs`, and the desktop shell needed
//! every one of them. This repo has met that fork three times:
//!
//! | | |
//! |---|---|
//! | the scan loop | copied into the shell, then diverged **three times** — transport, spent-note subtraction, and finally the shared types, which broke the build |
//! | the history flow | hoisted to [`crate::history::report`] *before* anyone copied it |
//! | **the spend** | here |
//!
//! **This one had the most to lose.** A diverged balance is a wrong number on a
//! screen; a diverged spend is a proof built against the wrong tree, an input
//! selected that the chain already consumed, or a recipient recorded for a
//! transaction that was never sent.
//!
//! # Progress is part of the contract, not a nicety
//!
//! The proof takes seconds and gigabytes. A caller that cannot say so while it
//! happens looks hung at the worst moment, so [`execute`] takes a sink and emits
//! [`SendStep`]s as it goes. The CLI's sink writes them to stderr; a GUI's raises
//! them as events. **The steps are data for the same reason
//! [`crate::history::HistoryReport::notes`] are:** one flow cannot know where two
//! surfaces put their words, and should not try.
//!
//! # 🔴 The one ordering rule that is not style
//!
//! **The local send record is written BEFORE the socket.** The chain carries every
//! other fact about a transaction — nullifiers, outputs, fee, the height it lands
//! at — and it can never carry the recipient, because the outputs are addressed to
//! keys this wallet does not hold. So the recipient is recorded here or it is lost,
//! and "here" has to be before the POST: **a submission whose answer never arrives
//! is exactly the case where a user needs to know what they sent.**

use std::path::Path;

use qlab_cbserver::client::{light_client_scan_with, Completeness, ScanConfig, ScanOutcome};
use qlab_wallet::address::Address;

use crate::bundle::WitnessBundle;
#[cfg(feature = "net")]
use crate::net::{
    self, HttpAnchorSource, HttpNullifierSource, SubmitAnswer, SubmitClass,
};
use crate::send::os_rng;
#[cfg(feature = "prove")]
use crate::send::{prove_bundle, SendArtifact};
use crate::spent::{fetch_spent, SpentSet};
use crate::store::WalletDir;
use crate::sync::{AnchorSource, Anchors};
// See the note in `send.rs`: used only from the `prove` half.
#[cfg(feature = "prove")]
use crate::sync::hex32;

/// What the caller asked for. Separate from the flow so a surface can validate
/// and present a request before anything touches the network.
pub struct SendRequest<'a> {
    /// The wallet dir — also where the local send record lands.
    pub dir: &'a Path,
    /// The compact/scan endpoint.
    pub url: &'a str,
    /// The node's discovery server (`/v1/tree/leaves`, `/v1/anchors`, `POST /v1/tx`).
    /// One host normally serves both; keeping them separable buys scanning one
    /// node and submitting to another.
    pub node_url: &'a str,
    pub recipient: &'a Address,
    /// Shown beside the resolved address when the recipient came from a contact —
    /// **paying the wrong person is the one mistake with no undo**, so the surface
    /// must be able to echo both.
    pub contact_name: Option<&'a str>,
    pub amount: u64,
    pub scan_to: u64,
    /// Skip the POST. The artifact is still returned, so a caller can keep the
    /// bytes; **discarding them is the failure this option exists to avoid.**
    pub no_submit: bool,
    /// A name-service rider to carry (lab #367): `Some` on the two
    /// registration steps and on renewals, `None` on every ordinary send. The
    /// declared fee grows by the op's burned name fee; the proof is untouched.
    pub name_op: Option<&'a qlab_devnet::names::NameOp>,
    /// 🔴 The genesis form of the net being spent on (lab #566). The coinbase
    /// phase derives this wallet's mined notes under it, and a wrong value makes
    /// every mined input a commitment in no tree — which `select` then refuses
    /// at the witness lookup rather than proving against the wrong anchor. It is
    /// a request field and not a constant because one binary serves both nets.
    pub form: qlab_devnet::forms::GenesisForm,
}

/// One thing that happened, as it happened.
///
/// Deliberately not `Display`: the two surfaces word these differently (stderr
/// lines vs. panel state), and a single rendering here would be one of them
/// wearing the other's clothes.
#[derive(Debug, Clone)]
pub enum SendStep {
    /// The recipient, resolved. Carries the contact name when there was one.
    Resolved {
        recipient_short: String,
        contact: Option<String>,
    },
    /// 🔴 **The coinbase stream could not be read (lab #424), so selection ran
    /// on TRANSACTION notes only.** Not a refusal — the 2026-08-16 ruling — but
    /// it must be SEEN: a user must never think they spent from a complete view
    /// when their mined coins were invisible. Carries
    /// [`crate::coinbase::TRANSACTIONS_ONLY`], the token the scan's balance line
    /// prints, so one grep covers both surfaces.
    CoinbaseUnavailable { why: String },
    /// Input selection finished. `skipped_spent` is notes this wallet owns whose
    /// nullifiers are already on the chain — reported, not silently dropped.
    /// `mined` is how many of `spendable` are MATURE coinbase notes (lab #424);
    /// it is 0 both when this wallet mined nothing and when the stream could not
    /// be read, which is why the event above is separate from this count.
    Selected {
        spendable: usize,
        skipped_spent: usize,
        mined: usize,
    },
    /// The local tree caught up and an anchor was chosen.
    Tree {
        held: u64,
        fetched: u64,
        anchor_count: u64,
        anchor_root: String,
        node_tip: u64,
        finalized: Option<u64>,
        /// The anchor trails what the node served. **Normal, not lag** — a witness
        /// must be built against a FINALIZED root.
        anchor_behind: u64,
    },
    /// About to prove. **Seconds and gigabytes**; say so.
    Proving,
    Built {
        amount: u64,
        fee: u64,
        change: u64,
        prove_secs: f64,
        used_dummy: bool,
    },
    /// The local record went in — before the socket, per the module docs.
    Recorded,
    /// Something that must be SEEN but must not stop the spend. The money matters
    /// more than the memo; losing the memo silently is how a ledger starts lying.
    Warning(String),
    Submitting,
    /// The node's answer, verbatim. The refusal vocabulary is the node's to own.
    Answered {
        status: u16,
        body: String,
    },
}

/// A spend that got far enough to have bytes.
#[derive(Debug)]
#[cfg(feature = "net")]
pub struct SendOutcome {
    /// The canonical wire bytes. **Keep them.** A proof that cost gigabytes should
    /// survive a failed socket, and resubmitting the same bytes answers
    /// `duplicate`, which is safe.
    pub wire_bytes: Vec<u8>,
    /// `None` when `no_submit` was set.
    pub answer: Option<SubmitAnswer>,
    pub fee: u64,
    pub change_value: u64,
    pub prove_secs: f64,
    pub used_dummy: bool,
}

/// Why a spend stopped.
///
/// 🔴 **`Incomplete` is not a refusal and must never be shown as one.** The POST
/// did not complete, so the transaction *may have landed*; the bytes are attached
/// precisely so the caller can offer a retry, and a retry of the same bytes is
/// safe. Presenting this as "failed" is how a user is invited to double-send.
#[derive(Debug)]
pub enum SendError {
    /// Refused with no ambiguous network submission. Normally cheap and
    /// pre-proof; the pre-submit preservation hook can also refuse after proof
    /// when it cannot make exact retry bytes durable.
    Refused(String),
    /// The proof was made and the POST did not complete.
    Incomplete { why: String, wire_bytes: Vec<u8> },
    /// The node answered, and the answer was not an acceptance.
    #[cfg(feature = "net")]
    Answered {
        class: SubmitClass,
        status: u16,
        body: String,
        wire_bytes: Vec<u8>,
    },
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendError::Refused(why) => write!(f, "{why}"),
            SendError::Incomplete { why, .. } => write!(f, "{why}"),
            #[cfg(feature = "net")]
            SendError::Answered { body, .. } => write!(f, "{body}"),
        }
    }
}

impl std::error::Error for SendError {}

/// Phase 1: scan, subtract spent notes, select inputs, sync the tree and choose
/// a finalized anchor. The returned artifact is the complete prover handoff.
#[cfg(feature = "net")]
pub fn select(
    req: &SendRequest<'_>,
    on: &mut dyn FnMut(SendStep),
) -> Result<WitnessBundle, SendError> {
    let w = WalletDir::open(req.dir).map_err(|e| SendError::Refused(e.to_string()))?;
    select_opened(req, on, &w)
}

/// Phase 1 using a wallet already authenticated by a platform seed provider.
///
/// The request directory still owns public caches and the local send log. Only
/// seed loading is injected; scanning, spent-note subtraction, input selection,
/// witness construction, and proving remain the core's decisions.
#[cfg(feature = "net")]
pub fn select_opened(
    req: &SendRequest<'_>,
    on: &mut dyn FnMut(SendStep),
    w: &WalletDir,
) -> Result<WitnessBundle, SendError> {
    let wallet = w.wallet();
    let mut rng = os_rng();

    select_with_rng(req, on, w, &wallet, &mut rng)
}

#[cfg(feature = "net")]
fn select_with_rng(
    req: &SendRequest<'_>,
    on: &mut dyn FnMut(SendStep),
    w: &WalletDir,
    wallet: &qlab_wallet::Wallet,
    rng: &mut rand::rngs::StdRng,
) -> Result<WitnessBundle, SendError> {
    let recipient_short = req.recipient.short().encode();
    on(SendStep::Resolved {
        recipient_short: recipient_short.clone(),
        contact: req.contact_name.map(str::to_string),
    });

    // ---- Gather spendables, and REFUSE on any non-Complete verdict: a spend
    // built on partial knowledge can double-claim a nullifier. -----------------
    let mut scanned: Vec<(u64, ScanOutcome)> = Vec::new();
    for &idx in &w.allocated {
        let d = wallet.diversifier_at_index(idx);
        let kp = wallet.diversified_keypair(&d);
        let mut fetch = net::scan_fetch(req.url);
        let outcome = light_client_scan_with(
            &mut fetch,
            &kp.dk,
            0,
            req.scan_to,
            ScanConfig::default(),
            rng,
        )
        .map_err(|e| SendError::Refused(format!("scan never started for index {idx}: {e}")))?;
        match outcome.completeness() {
            Completeness::Complete | Completeness::Shadowed { .. } => {}
            other => {
                return Err(SendError::Refused(format!(
                    "index {idx} scanned {other:?} — refusing to build a spend on partial \
                     knowledge (a double-claimed nullifier could be among the unread outputs)"
                )))
            }
        }
        scanned.push((idx, outcome));
    }

    // ---- Everything after the scan is the ONE phase-1 orchestration — the
    // caller-pumped driver (lab #399). This synchronous flow is its pump: the
    // spent-subtraction (lab #314), the witness source's twin refusals (see
    // `sync`'s module docs), the selection and the witness build all live in
    // [`crate::driver::SelectDriver`], and there is no second copy to drift.
    let leaves_path = req.dir.join(crate::sync::LEAVES_FILE);
    let held =
        crate::sync::load_cache(&leaves_path).map_err(|e| SendError::Refused(e.to_string()))?;
    let mut driver = crate::driver::SelectDriver::new(
        wallet.clone(),
        req.recipient.clone(),
        req.amount,
        req.name_op.cloned(),
        scanned,
        held,
        req.scan_to,
        req.form,
    );
    let mut persisted = false;
    loop {
        let step = driver.step(rng);
        for ev in driver.take_events() {
            on(ev);
        }
        // Persist the caught-up tree at the same point `sync_tree` used to —
        // after the leaf stream completes, before the anchor fetch.
        if !persisted {
            if let Some(tree) = driver.tree() {
                crate::sync::persist_cache(&leaves_path, tree)
                    .map_err(|e| SendError::Refused(e.to_string()))?;
                persisted = true;
            }
        }
        match step {
            crate::driver::SelectStep::Need { endpoint, path } => {
                let base = match endpoint {
                    crate::driver::SelectEndpoint::Scan => req.url,
                    crate::driver::SelectEndpoint::Node => req.node_url,
                };
                driver.supply(net::http_get(base, &path).map_err(|e| e.to_string()));
            }
            crate::driver::SelectStep::Done(bundle) => return Ok(*bundle),
            crate::driver::SelectStep::Failed(why) => return Err(SendError::Refused(why)),
        }
    }
}

/// Fresh public chain facts supplied to the pure prover phase. Fetching them is
/// outside [`prove`]: the host receives values, never a URL or a socket.
pub struct ProveContext {
    pub anchors: Anchors,
    pub spent: SpentSet,
}

/// Fetch the phase-2 preflight facts used by [`execute`]. A browser extension
/// may obtain and decode the same two public surfaces itself, then pass the
/// resulting values across its native boundary with the bundle.
#[cfg(feature = "net")]
pub fn preflight(req: &SendRequest<'_>) -> Result<ProveContext, SendError> {
    preflight_urls(req.url, req.node_url)
}

/// Fetch phase-2 facts without constructing a wallet send request. Native
/// prover hosts use this entry point because their serialized witness bundle
/// already fixes the recipient, amount, fee, and outputs; only the two public
/// endpoints remain outside that artifact.
#[cfg(feature = "net")]
pub fn preflight_urls(scan_url: &str, node_url: &str) -> Result<ProveContext, SendError> {
    let anchors = HttpAnchorSource::new(node_url)
        .anchors()
        .map_err(|e| SendError::Refused(format!("anchor-preflight-unavailable: {e}")))?;
    let spent = fetch_spent(&HttpNullifierSource::new(scan_url), 0, anchors.tip_height).map_err(
        |e| {
            SendError::Refused(format!(
                "nullifier-preflight-unavailable: {e} — refusing to prove inputs the chain may already have consumed"
            ))
        },
    )?;
    Ok(ProveContext { anchors, spent })
}

/// Phase 2: current-state preflight followed by the real STARK. No wallet dir,
/// network handle, caller-provided wallet RNG, or second key source is reachable
/// here; all witness/key bytes come from `bundle`, and current chain state
/// arrives as decoded public data. The prover's own randomness remains internal.
#[cfg(feature = "prove")]
pub fn prove(
    bundle: &WitnessBundle,
    current: &ProveContext,
    on: &mut dyn FnMut(SendStep),
) -> Result<SendArtifact, SendError> {
    bundle
        .validate()
        .map_err(|e| SendError::Refused(e.to_string()))?;
    if !current.anchors.roots.contains(&bundle.anchor()) {
        return Err(SendError::Refused(format!(
            "anchor-no-longer-accepted: bundle anchor {} selected at tip {} is absent from the node's current valid-anchor set at tip {}",
            hex32(&bundle.anchor()),
            bundle.selected_at_tip(),
            current.anchors.tip_height,
        )));
    }
    let outputs = bundle.output_range().ok_or_else(|| {
        SendError::Refused(
            "witness-bundle-nullifier-coverage-missing: no scan output range was recorded".into(),
        )
    })?;
    let current_range = Some((outputs.0, current.anchors.tip_height.max(outputs.1)));
    current.spent.covers_outputs(current_range).map_err(|e| {
        SendError::Refused(format!(
            "nullifier-preflight-not-covered: {e} — refusing to prove inputs the chain may already have consumed"
        ))
    })?;
    for nf in bundle.real_nullifiers() {
        if current.spent.contains(&nf) {
            return Err(SendError::Refused(format!(
                "bundle-input-already-spent: selected nullifier {} is now on chain; refusing before proof",
                hex32(&nf),
            )));
        }
    }

    on(SendStep::Proving);
    let art = prove_bundle(bundle).map_err(SendError::Refused)?;
    on(SendStep::Built {
        amount: bundle.amount(),
        fee: art.fee,
        change: art.change_value,
        prove_secs: art.prove_secs,
        used_dummy: art.used_dummy,
    });
    Ok(art)
}

/// Phase 3: canonical transaction bytes in, the node's typed answer out. A
/// `duplicate` remains [`SubmitClass::Duplicate`] rather than being collapsed
/// into a generic success or error.
#[cfg(feature = "net")]
pub fn submit(
    node_url: &str,
    wire_bytes: &[u8],
    on: &mut dyn FnMut(SendStep),
) -> Result<SubmitAnswer, SendError> {
    on(SendStep::Submitting);
    let answer = net::submit_tx(node_url, wire_bytes).map_err(|e| SendError::Incomplete {
        why: format!(
            "POST /v1/tx never completed ({e}). This is NOT a refusal — the transaction may \
             have landed. Resubmit the SAME bytes: an already-pending transaction answers \
             `duplicate`, which is safe."
        ),
        wire_bytes: wire_bytes.to_vec(),
    })?;
    on(SendStep::Answered {
        status: answer.status,
        body: answer.body.clone(),
    });
    Ok(answer)
}

/// The original CLI/desktop surface, now exactly the composition of the three
/// callable phases above. Every early return before [`SendStep::Proving`] is a
/// cheap named refusal.
#[cfg(all(feature = "net", feature = "prove"))]
pub fn execute(
    req: &SendRequest<'_>,
    on: &mut dyn FnMut(SendStep),
) -> Result<SendOutcome, SendError> {
    execute_with_phases(req, on, select, preflight, prove, submit, |_| Ok(()))
}

/// Execute after handing the canonical transaction bytes to `before_submit`.
/// The hook runs after proving but before both the local send record and the
/// network socket, including under `no_submit`. Name registration uses this to
/// make the exact randomized reveal retryable before its first POST can answer.
#[cfg(all(feature = "net", feature = "prove"))]
pub fn execute_with_pre_submit(
    req: &SendRequest<'_>,
    on: &mut dyn FnMut(SendStep),
    before_submit: &mut dyn FnMut(&[u8]) -> Result<(), String>,
) -> Result<SendOutcome, SendError> {
    execute_with_phases(req, on, select, preflight, prove, submit, before_submit)
}

/// Execute a send using a wallet already opened by a platform seed provider.
/// This is otherwise byte-for-byte the same three-phase flow as [`execute`].
#[cfg(all(feature = "net", feature = "prove"))]
pub fn execute_opened(
    req: &SendRequest<'_>,
    wallet: &WalletDir,
    on: &mut dyn FnMut(SendStep),
) -> Result<SendOutcome, SendError> {
    execute_with_phases(
        req,
        on,
        |req, on| select_opened(req, on, wallet),
        preflight,
        prove,
        submit,
        |_| Ok(()),
    )
}

#[cfg(all(feature = "net", feature = "prove"))]
fn execute_with_phases<Select, Preflight, Prove, Submit, BeforeSubmit>(
    req: &SendRequest<'_>,
    on: &mut dyn FnMut(SendStep),
    select_phase: Select,
    preflight_phase: Preflight,
    prove_phase: Prove,
    submit_phase: Submit,
    mut before_submit: BeforeSubmit,
) -> Result<SendOutcome, SendError>
where
    Select: FnOnce(&SendRequest<'_>, &mut dyn FnMut(SendStep)) -> Result<WitnessBundle, SendError>,
    Preflight: FnOnce(&SendRequest<'_>) -> Result<ProveContext, SendError>,
    Prove: FnOnce(
        &WitnessBundle,
        &ProveContext,
        &mut dyn FnMut(SendStep),
    ) -> Result<SendArtifact, SendError>,
    Submit: FnOnce(&str, &[u8], &mut dyn FnMut(SendStep)) -> Result<SubmitAnswer, SendError>,
    BeforeSubmit: FnMut(&[u8]) -> Result<(), String>,
{
    let bundle = select_phase(req, on)?;
    let current = preflight_phase(req)?;
    let art = prove_phase(&bundle, &current, on)?;
    before_submit(&art.wire_bytes).map_err(|why| {
        SendError::Refused(format!(
            "transaction was built but NOT submitted because its exact retry bytes could not be saved: {why}"
        ))
    })?;

    let outcome = |answer| SendOutcome {
        wire_bytes: art.wire_bytes.clone(),
        answer,
        fee: art.fee,
        change_value: art.change_value,
        prove_secs: art.prove_secs,
        used_dummy: art.used_dummy,
    };

    if req.no_submit {
        return Ok(outcome(None));
    }

    // ---- 🔴 The local record, written BEFORE the socket. See the module docs.
    let record = crate::sends_build::declared_record(
        &art.entry.public,
        bundle.selected_at_tip(),
        bundle.amount(),
        bundle.recipient_short().to_string(),
    );
    match crate::sends::SendLog::append(req.dir, &record) {
        Ok(()) => on(SendStep::Recorded),
        Err(e) => on(SendStep::Warning(format!(
            "could not write the local send record ({e}). The transaction is unaffected, but \
             `history` will show this send with `recipient: not recorded`."
        ))),
    }

    let answer = submit_phase(req.node_url, &art.wire_bytes, on)?;

    // The cross-check the local derivation earns: a node naming a different
    // statement id means the record just written points at a transaction nobody
    // else agrees exists. `history` joins on the declared nullifiers rather than
    // the id, so the ledger is unaffected — but two derivations disagreeing is
    // worth reporting rather than swallowing.
    if let Some(theirs) = answer.txid_hex() {
        let ours = crate::sends::hex32(&record.txid);
        if theirs != ours {
            on(SendStep::Warning(format!(
                "this wallet derived statement id {ours} and the node answered {theirs}. The \
                 ledger is unaffected (it joins on nullifiers), but the disagreement is real."
            )));
        }
    }

    match answer.class() {
        SubmitClass::Accepted | SubmitClass::Duplicate => Ok(outcome(Some(answer))),
        class => Err(SendError::Answered {
            class,
            status: answer.status,
            body: answer.body,
            wire_bytes: art.wire_bytes,
        }),
    }
}

#[cfg(all(test, feature = "net", feature = "prove"))]
mod tests {
    use super::*;
    use crate::send::Spendable;
    use std::cell::RefCell;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::rc::Rc;

    use qlab_air::narrow::derive_input;
    use qlab_cbserver::tree::CommitmentTree;
    use qlab_devnet::body::{TxEntry, TxPublic};
    use qlab_devnet::fees::ArityBucket;
    use qlab_wallet::seed::MasterSeed;
    use qlab_wallet::Wallet;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn bundle() -> WitnessBundle {
        let wallet = Wallet::from_master_seed(&MasterSeed::from_entropy([0x41; 32]), 0);
        let recipient =
            Wallet::from_master_seed(&MasterSeed::from_entropy([0x42; 32]), 0).address_at_index(0);
        let note = Spendable {
            div_index: 0,
            value: 10_000_000,
            rho: [7; 4],
            rseed: [9; 4],
        };
        let input = wallet.spend_input(
            note.value,
            note.rho,
            note.rseed,
            wallet.diversifier_at_index(0),
        );
        let mut tree = CommitmentTree::new();
        tree.append(derive_input(&input).2);
        crate::send::build_bundle(
            &wallet,
            &[note],
            &recipient,
            4_000_000,
            &tree,
            tree.len(),
            9,
            recipient.short().encode(),
            Some((2, 9)),
            Some((0, 9)),
            None,
            &mut StdRng::seed_from_u64(0x351),
        )
        .expect("valid bundle")
    }

    fn context(bundle: &WitnessBundle, accepted: bool, spent_nfs: Vec<[u8; 32]>) -> ProveContext {
        ProveContext {
            anchors: Anchors {
                tip_height: 9,
                finalized_height: Some(8),
                max_age_blocks: 64,
                roots: vec![if accepted {
                    bundle.anchor()
                } else {
                    [0xA5; 32]
                }],
            },
            spent: SpentSet::from_parts(Some((0, 9)), spent_nfs.into_iter().map(|nf| (9, nf))),
        }
    }

    /// Hazard (a): the freshness data is an argument, not a network call in
    /// phase 2, and the named refusal happens before the Proving event.
    #[test]
    fn stale_anchor_is_refused_by_name_before_proving() {
        let bundle = bundle();
        let mut steps = Vec::new();
        let err = prove(&bundle, &context(&bundle, false, Vec::new()), &mut |s| {
            steps.push(s)
        })
        .err()
        .expect("stale anchor refuses");
        assert!(
            err.to_string().contains("anchor-no-longer-accepted"),
            "{err}"
        );
        assert!(!steps.iter().any(|s| matches!(s, SendStep::Proving)));
    }

    /// The delayed-bundle form of hazard (c): even a once-valid selection is
    /// cheap-refused when a selected real nullifier appears before proving.
    #[test]
    fn bundle_whose_selected_note_was_consumed_since_selection_refuses_before_proving() {
        let bundle = bundle();
        let nfs = bundle.real_nullifiers();
        let mut steps = Vec::new();
        let err = prove(&bundle, &context(&bundle, true, nfs), &mut |s| {
            steps.push(s)
        })
        .err()
        .expect("consumed input refuses");
        assert!(
            err.to_string().contains("bundle-input-already-spent"),
            "{err}"
        );
        assert!(!steps.iter().any(|s| matches!(s, SendStep::Proving)));
    }

    /// Hazard (b): retrying the SAME bytes carries the node's `duplicate`
    /// vocabulary through the public phase-3 seam without flattening it.
    #[test]
    fn replaying_same_bundle_preserves_duplicate_vocabulary_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            for (status, body) in [(202, "accepted 010203"), (200, "duplicate 010203")] {
                let (mut stream, _) = listener.accept().unwrap();
                read_http_request(&mut stream);
                write!(
                    stream,
                    "HTTP/1.1 {status} test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });

        let wire = [0x51, 0x35, 0x31];
        let first = submit(&base, &wire, &mut |_| {}).expect("first answer arrives");
        let replay = submit(&base, &wire, &mut |_| {}).expect("replay answer arrives");
        server.join().unwrap();
        assert_eq!(first.class(), SubmitClass::Accepted);
        assert_eq!(replay.class(), SubmitClass::Duplicate);
        assert_eq!(replay.status, 200);
        assert_eq!(
            replay.body, "duplicate 010203",
            "the node's vocabulary is verbatim"
        );
    }

    /// Hazard (d): the public compatibility surface runs the three callable
    /// phases in order and hands submit the exact bytes prove returned. The
    /// real deterministic wire shell is golden-locked in
    /// `send::tests::one_real_spend_builds_proves_and_binds_its_seams`.
    #[test]
    fn execute_is_exactly_select_prove_submit_and_preserves_the_wire_bytes() {
        let bundle = bundle();
        let recipient =
            Wallet::from_master_seed(&MasterSeed::from_entropy([0x43; 32]), 0).address_at_index(0);
        let req = SendRequest {
            dir: std::path::Path::new("target/i351-composition-parent-does-not-exist/wallet"),
            url: "unused-scan-url",
            node_url: "phase-three-url",
            recipient: &recipient,
            contact_name: None,
            amount: bundle.amount(),
            scan_to: bundle.selected_at_tip(),
            no_submit: false,
            name_op: None,
            form: qlab_devnet::forms::GenesisForm::V4,
        };
        let calls = Rc::new(RefCell::new(Vec::new()));
        let select_calls = Rc::clone(&calls);
        let preflight_calls = Rc::clone(&calls);
        let prove_calls = Rc::clone(&calls);
        let submit_calls = Rc::clone(&calls);
        let preserve_calls = Rc::clone(&calls);
        let selected = bundle.clone();
        let proved_wire = vec![0x51, 0x35, 0x31];
        let expected_wire = proved_wire.clone();

        let outcome = execute_with_phases(
            &req,
            &mut |_| {},
            move |_, _| {
                select_calls.borrow_mut().push("select");
                Ok(selected)
            },
            move |_| {
                preflight_calls.borrow_mut().push("preflight");
                Ok(context(&bundle, true, Vec::new()))
            },
            move |selected, _, _| {
                prove_calls.borrow_mut().push("prove");
                Ok(SendArtifact {
                    entry: TxEntry {
                        proof: Vec::new(),
                        public: TxPublic {
                            anchor: selected.anchor(),
                            nullifiers: vec![[0x11; 32], [0x12; 32]],
                            commitments: vec![[0x21; 32], [0x22; 32]],
                            bucket: ArityBucket::TwoByTwo,
                            fee: selected.fee(),
                        },
                        discovery: vec![0],
                        rider: TxEntry::absent_rider(),
                    },
                    wire_bytes: proved_wire,
                    fee: selected.fee(),
                    used_dummy: selected.used_dummy(),
                    prove_secs: 1.25,
                    change_value: selected.change_value(),
                    pvs: Vec::new(),
                    declared_anchor: [0; 4],
                    declared_nf: [[0; 4]; 2],
                    declared_cm: [[0; 4]; 2],
                })
            },
            move |url, wire, _| {
                submit_calls.borrow_mut().push("submit");
                assert_eq!(url, "phase-three-url");
                assert_eq!(wire, expected_wire);
                Ok(SubmitAnswer {
                    status: 200,
                    body: "duplicate".into(),
                })
            },
            move |wire| {
                preserve_calls.borrow_mut().push("preserve");
                assert_eq!(wire, [0x51, 0x35, 0x31]);
                Ok(())
            },
        )
        .expect("duplicate is the safe retry outcome");

        assert_eq!(
            calls.borrow().as_slice(),
            ["select", "preflight", "prove", "preserve", "submit"]
        );
        assert_eq!(outcome.wire_bytes, [0x51, 0x35, 0x31]);
        assert_eq!(outcome.answer.unwrap().class(), SubmitClass::Duplicate);
    }

    fn read_http_request(stream: &mut std::net::TcpStream) {
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = stream.read(&mut chunk).unwrap();
            assert!(n > 0, "client closed before its request completed");
            bytes.extend_from_slice(&chunk[..n]);
            let Some(header_end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") else {
                continue;
            };
            let headers = String::from_utf8_lossy(&bytes[..header_end]);
            let content_len = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            if bytes.len() >= header_end + 4 + content_len {
                return;
            }
        }
    }
}
