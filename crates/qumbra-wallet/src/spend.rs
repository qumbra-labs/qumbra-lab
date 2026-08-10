//! The whole spend, as one flow — scan, select, sync, prove, record, submit.
//!
//! # Why this is separate from [`crate::send`]
//!
//! [`crate::send::build_send`] is the **builder**: notes and a tree in, a proved
//! artifact out, no sockets. This module is the **flow** around it, and it is the
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

use crate::net::{
    self, HttpAnchorSource, HttpLeafSource, HttpNullifierSource, SubmitAnswer, SubmitClass,
};
use crate::send::{build_send, os_rng, Spendable};
use crate::spent::{fetch_spent, subtract_spent};
use crate::store::WalletDir;
use crate::sync::{hex32, sync_and_select};

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
}

/// One thing that happened, as it happened.
///
/// Deliberately not `Display`: the two surfaces word these differently (stderr
/// lines vs. panel state), and a single rendering here would be one of them
/// wearing the other's clothes.
#[derive(Debug, Clone)]
pub enum SendStep {
    /// The recipient, resolved. Carries the contact name when there was one.
    Resolved { recipient_short: String, contact: Option<String> },
    /// Input selection finished. `skipped_spent` is notes this wallet owns whose
    /// nullifiers are already on the chain — reported, not silently dropped.
    Selected { spendable: usize, skipped_spent: usize },
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
    Built { amount: u64, fee: u64, change: u64, prove_secs: f64, used_dummy: bool },
    /// The local record went in — before the socket, per the module docs.
    Recorded,
    /// Something that must be SEEN but must not stop the spend. The money matters
    /// more than the memo; losing the memo silently is how a ledger starts lying.
    Warning(String),
    Submitting,
    /// The node's answer, verbatim. The refusal vocabulary is the node's to own.
    Answered { status: u16, body: String },
}

/// A spend that got far enough to have bytes.
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
    /// Refused before anything was proved — cheap, and named.
    Refused(String),
    /// The proof was made and the POST did not complete.
    Incomplete { why: String, wire_bytes: Vec<u8> },
    /// The node answered, and the answer was not an acceptance.
    Answered { class: SubmitClass, status: u16, body: String, wire_bytes: Vec<u8> },
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendError::Refused(why) => write!(f, "{why}"),
            SendError::Incomplete { why, .. } => write!(f, "{why}"),
            SendError::Answered { body, .. } => write!(f, "{body}"),
        }
    }
}

impl std::error::Error for SendError {}

/// Build and (unless refused, and unless `no_submit`) submit a spend, reporting
/// progress through `on`.
///
/// Every early return before [`SendStep::Proving`] is a **cheap** refusal, and
/// that is the design: the expensive thing happens only once the wallet knows it
/// is spending notes the chain still has.
pub fn execute(
    req: &SendRequest<'_>,
    on: &mut dyn FnMut(SendStep),
) -> Result<SendOutcome, SendError> {
    let w = WalletDir::open(req.dir).map_err(|e| SendError::Refused(e.to_string()))?;
    let wallet = w.wallet();
    let mut rng = os_rng();

    on(SendStep::Resolved {
        recipient_short: req.recipient.short().encode(),
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
            &mut rng,
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

    // ---- Selection skips what the chain already spent (lab #314). ------------
    //
    // Without this the wallet would pick a note it spent an hour ago, pay ~3 s
    // and ~12 GB to prove a statement about it, and be refused `nullifier-spent`
    // at the node. An UNAVAILABLE stream refuses the whole send rather than
    // guessing: a spend built on "I could not check" is exactly that wasted proof.
    let outputs =
        crate::scan::widest_range(scanned.iter().map(|(_, o)| o.stats.compact_range_served));
    let spent_set = fetch_spent(&HttpNullifierSource::new(req.url), 0, req.scan_to).map_err(|e| {
        SendError::Refused(format!(
            "{e} — refusing to select inputs this wallet may already have spent"
        ))
    })?;
    spent_set.covers_outputs(outputs).map_err(|e| {
        SendError::Refused(format!(
            "{e} — refusing to select inputs this wallet may already have spent"
        ))
    })?;

    let mut spendables: Vec<Spendable> = Vec::new();
    let mut skipped = 0usize;
    for (idx, outcome) in &scanned {
        let report = subtract_spent(&wallet, *idx, &outcome.notes, &spent_set);
        skipped += report.spent.len();
        for ln in &report.spendable {
            spendables.push(Spendable {
                div_index: *idx,
                value: ln.detected.note.value,
                rho: ln.detected.note.rho,
                rseed: ln.detected.note.rseed,
            });
        }
    }
    on(SendStep::Selected { spendable: spendables.len(), skipped_spent: skipped });

    if spendables.is_empty() {
        return Err(SendError::Refused(format!(
            "no spendable notes: the scan of 0..={} found nothing this wallet can spend \
             ({skipped} note(s) it found are already spent). If you expect a coinbase, it is not \
             spendable until it matures (frozen §2, COINBASE_MATURITY_BLOCKS in qlab-node); if \
             you expect a received note, check that its address index is allocated here.",
            req.scan_to
        )));
    }

    // ---- The witness source. Both halves refuse by name and neither is
    // skippable (see `sync`'s module docs). -----------------------------------
    let (synced, anchor) = sync_and_select(
        req.dir,
        &HttpLeafSource::new(req.node_url),
        &HttpAnchorSource::new(req.node_url),
    )
    .map_err(|e| SendError::Refused(e.to_string()))?;
    on(SendStep::Tree {
        held: synced.count,
        fetched: synced.fetched,
        anchor_count: anchor.count,
        anchor_root: hex32(&anchor.root),
        node_tip: anchor.tip_height,
        finalized: anchor.finalized_height,
        anchor_behind: anchor.leaves_behind_local,
    });

    on(SendStep::Proving);
    let art = build_send(
        &wallet,
        &spendables,
        req.recipient,
        req.amount,
        &synced.tree,
        anchor.count,
        &mut rng,
    )
    .map_err(|e| SendError::Refused(e.to_string()))?;
    on(SendStep::Built {
        amount: req.amount,
        fee: art.fee,
        change: art.change_value,
        prove_secs: art.prove_secs,
        used_dummy: art.used_dummy,
    });

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
    let record = crate::sends::SendRecord::declared(
        &art.entry.public,
        anchor.tip_height,
        req.amount,
        req.recipient.short().encode(),
    );
    match crate::sends::SendLog::append(req.dir, &record) {
        Ok(()) => on(SendStep::Recorded),
        Err(e) => on(SendStep::Warning(format!(
            "could not write the local send record ({e}). The transaction is unaffected, but \
             `history` will show this send with `recipient: not recorded`."
        ))),
    }

    on(SendStep::Submitting);
    let answer = net::submit_tx(req.node_url, &art.wire_bytes).map_err(|e| {
        SendError::Incomplete {
            why: format!(
                "POST /v1/tx never completed ({e}). This is NOT a refusal — the transaction may \
                 have landed. Resubmit the SAME bytes: an already-pending transaction answers \
                 `duplicate`, which is safe."
            ),
            wire_bytes: art.wire_bytes.clone(),
        }
    })?;
    on(SendStep::Answered { status: answer.status, body: answer.body.clone() });

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
