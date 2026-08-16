//! The caller-pumped phase-1 driver (lab #399) — selection for a host with no
//! synchronous network.
//!
//! [`crate::spend::select`] runs phase 1 as one synchronous flow: scan, spent
//! subtraction, input selection, tree catch-up, anchor choice, witness build.
//! A wasm/extension host can do none of the I/O in that sentence — the same
//! wall lab #350 hit one phase earlier, and the same inversion answers it:
//! **the driver owns every decision and does no I/O.** Callers alternate
//! [`SelectDriver::step`] (`Need` a path / `Done` with the bundle / `Failed`
//! by name) with [`SelectDriver::supply`], from any transport, suspending as
//! long as they like.
//!
//! # The coinbase phase (lab #424) and the one ruling it is built on
//!
//! [`ScanOutcome::notes`] are **transaction outputs**, and a coinbase note is
//! not in that set by construction — it has no discovery group at all, which is
//! the whole of lab #415. So until #424 this driver's input set could not hold
//! a mined note, `scan` reported a matured coinbase as spendable, and a `send`
//! on the same wallet refused with "no spendable notes" one line below it.
//!
//! The fix is a fourth phase, `Spent → Coinbase → Tree → Anchors`: the same
//! `GET /v1/coinbase` stream `scan` pages, through the same accumulator
//! ([`CoinbaseCatchUp`]) and the same reconstruction ([`match_mined`] →
//! `qlab_node::coinbase_note_parts`), so there is no second derivation of a
//! mined note anywhere. **Only [`MinedReport::spendable`] enters selection** —
//! a maturing note is real money this wallet owns and cannot spend, and it must
//! never be selectable.
//!
//! 🔴 **What a send does when that route 404s — RULED (Larry, 2026-08-16, lab
//! #424): proceed on transaction notes only, LOUDLY.** The grounds are the
//! safety shape: a missing coinbase source only ever *shrinks* the input set, so
//! the worst it can produce is an insufficient-funds refusal that is loud and
//! wrong-in-the-safe-direction. That is categorically unlike a missing
//! **nullifier** feed, where an incomplete view lets a spend reuse a note the
//! chain already consumed — which is why [`Phase::Spent`] below is untouched by
//! this change and stays fail-closed. Three guardrails ride the ruling and all
//! three are pinned by tests:
//!
//! 1. the degradation is **visible on the send path** —
//!    [`SendStep::CoinbaseUnavailable`], carrying
//!    [`crate::coinbase::TRANSACTIONS_ONLY`], the same token the scan's balance
//!    line prints;
//! 2. an insufficient-funds refusal out of the shrunk set **names that coinbase
//!    was not visible**, so a user can tell it from a true low balance;
//! 3. nothing here widens or weakens the spent-note path.
//!
//! What deliberately does NOT move here:
//!
//! - **Scanning.** The caller supplies completed [`ScanOutcome`]s — the
//!   extension already holds them (it scans in-extension via #350's driver),
//!   and the CLI's pump feeds the ones its scan loop just produced. The
//!   Complete/Shadowed verdict gate is enforced HERE too, so handing outcomes
//!   in does not make the partial-knowledge refusal skippable.
//! - **The wallet dir.** The caller supplies held leaves in and may persist
//!   the caught-up tree after; the driver never touches a filesystem.
//! - **The accumulation protocols.** [`SpentCatchUp`] and [`TreeCatchUp`] are
//!   the one copy of the paging checks, shared with the synchronous pumps —
//!   the #312/#313/#314 divergence lesson, pointed at selection.
//!
//! Two endpoints, because [`crate::spend::SendRequest`] deliberately keeps
//! them separable: [`SelectEndpoint::Scan`] paths go to the compact/nullifier
//! host, [`SelectEndpoint::Node`] paths to the discovery server. One host
//! normally serves both.

use qlab_cbserver::client::{Completeness, ScanOutcome};
use qlab_cbserver::codec::{CoinbasePage, NullifierPage};
use qlab_cbserver::tree::CommitmentTree;
use qlab_node::AnchorSet;
use qlab_wallet::address::Address;
use qlab_wallet::Wallet;
use rand::rngs::StdRng;

use crate::bundle::WitnessBundle;
use crate::coinbase::{
    match_mined, CoinbaseCatchUp, CoinbaseChunk, MinedChain, MinedReport, TRANSACTIONS_ONLY,
};
use crate::scan::widest_range;
use crate::send::{build_bundle, BuildRefusal, Spendable};
use crate::spend::SendStep;
use crate::spent::{subtract_spent, NullifierChunk, SpentCatchUp, SpentRefusal, SpentSet};
use crate::sync::{hex32, select_anchor, Anchors, LeafChunk, SyncRefusal, TreeCatchUp};

/// Which of the request's two endpoints a [`SelectStep::Need`] path belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectEndpoint {
    /// The compact/scan host — `/v1/nullifiers`.
    Scan,
    /// The node's discovery server — `/v1/tree/leaves`, `/v1/anchors`.
    Node,
}

/// One observation from a caller-pumped [`SelectDriver`]. `Done` and `Failed`
/// are terminal.
pub enum SelectStep {
    Need { endpoint: SelectEndpoint, path: String },
    Done(Box<WitnessBundle>),
    Failed(String),
}

enum Phase {
    Spent(SpentCatchUp),
    /// Lab #424. Runs AFTER `Spent` because a mined note can be spent like any
    /// other and [`match_mined`] needs the nullifier set to say so.
    Coinbase(CoinbaseCatchUp),
    Tree(TreeCatchUp),
    Anchors { got: Option<Anchors> },
    Finished,
}

#[derive(Clone, Copy)]
enum Pending {
    Nullifiers { from: u64, to: u64 },
    Coinbase { from: u64, to: u64 },
    Leaves { from: u64 },
    Anchors,
}

/// The sans-I/O phase 1. Owns a cloned [`Wallet`] (the #358 S6 shape: an
/// owning FFI wrapper must not be self-referential) and never a URL, socket,
/// or path.
pub struct SelectDriver {
    wallet: Wallet,
    recipient: Address,
    recipient_short: String,
    amount: u64,
    name_op: Option<qlab_devnet::names::NameOp>,
    to: u64,
    outcomes: Vec<(u64, ScanOutcome)>,
    outputs: Option<(u64, u64)>,
    held: Option<CommitmentTree>,
    phase: Phase,
    pending: Option<Pending>,
    fatal: Option<String>,
    events: Vec<SendStep>,
    spendables: Vec<Spendable>,
    spent_covered: Option<(u64, u64)>,
    synced: Option<crate::sync::SyncedTree>,
    /// Carried from the spent phase into the coinbase phase, then consumed by
    /// selection. `None` once selection has run.
    spent: Option<SpentSet>,
    /// This wallet's mined notes over the served range, `None` when the stream
    /// could not be read at all. `Some` with an empty `spendable` is a real
    /// answer — "you mined nothing spendable here" — and is what `None` must
    /// never be confused with.
    mined: Option<MinedReport>,
    /// 🔴 Set when this send could NOT see all of coinbase — carries the reason
    /// verbatim. Never fatal (the 2026-08-16 ruling); it becomes the visible
    /// degradation and the caveat on an insufficient-funds refusal.
    coinbase_gap: Option<String>,
    /// Notes this wallet owns whose nullifiers are already on the chain, both
    /// categories — kept for the refusal text.
    skipped_spent: usize,
}

impl SelectDriver {
    /// `outcomes` are completed scans per allocated index (the caller's own —
    /// the driver re-checks their verdicts); `held` is whatever commitment
    /// tree the caller already has, empty on first use; `to` is the height the
    /// scans ran to.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wallet: Wallet,
        recipient: Address,
        amount: u64,
        name_op: Option<qlab_devnet::names::NameOp>,
        outcomes: Vec<(u64, ScanOutcome)>,
        held: CommitmentTree,
        to: u64,
    ) -> SelectDriver {
        // The `Resolved` narration stays with the CALLER (it precedes the scan,
        // which precedes this driver's birth) — the driver's events begin at
        // `Selected`.
        let recipient_short = recipient.short().encode();
        let mut fatal = None;
        // The verdict gate, again: a spend built on partial knowledge can
        // double-claim a nullifier, and supplying outcomes must not make this
        // refusal skippable (#399's hazard list).
        for (idx, outcome) in &outcomes {
            match outcome.completeness() {
                Completeness::Complete | Completeness::Shadowed { .. } => {}
                other => {
                    fatal = Some(format!(
                        "index {idx} scanned {other:?} — refusing to build a spend on partial \
                         knowledge (a double-claimed nullifier could be among the unread outputs)"
                    ));
                    break;
                }
            }
        }
        let outputs = widest_range(outcomes.iter().map(|(_, o)| o.stats.compact_range_served));
        SelectDriver {
            wallet,
            recipient,
            recipient_short: recipient_short.clone(),
            amount,
            name_op,
            to,
            outcomes,
            outputs,
            held: Some(held),
            phase: Phase::Spent(SpentCatchUp::new(0, to)),
            pending: None,
            fatal,
            events: Vec::new(),
            spendables: Vec::new(),
            spent_covered: None,
            synced: None,
            spent: None,
            mined: None,
            coinbase_gap: None,
            skipped_spent: 0,
        }
    }

    /// Progress narration accumulated since the last drain — the same
    /// [`SendStep`]s the synchronous flow hands its `on` callback, in order.
    pub fn take_events(&mut self) -> Vec<SendStep> {
        std::mem::take(&mut self.events)
    }

    /// The caught-up tree, once the leaf phase has finished — the CLI pump
    /// persists this to the wallet dir at the same point `sync_tree` used to.
    pub fn tree(&self) -> Option<&CommitmentTree> {
        self.synced.as_ref().map(|s| &s.tree)
    }

    /// Advance until the selection needs one path, completes, or fails.
    pub fn step(&mut self, rng: &mut StdRng) -> SelectStep {
        if let Some(err) = &self.fatal {
            return SelectStep::Failed(err.clone());
        }
        if let Some(pending) = self.pending {
            return self.need_for(pending);
        }
        loop {
            match &mut self.phase {
                Phase::Spent(catch) => match catch.want() {
                    Some((from, to)) => {
                        self.pending = Some(Pending::Nullifiers { from, to });
                        return self.need_for(Pending::Nullifiers { from, to });
                    }
                    None => {
                        let Phase::Spent(catch) =
                            std::mem::replace(&mut self.phase, Phase::Finished)
                        else {
                            unreachable!()
                        };
                        let spent_set = catch.finish();
                        // 🔴 UNTOUCHED by lab #424, deliberately: this is the
                        // fail-closed half, and the coinbase ruling's whole
                        // argument is that it is NOT like the coinbase stream.
                        if let Err(e) = spent_set.covers_outputs(self.outputs) {
                            return self.fail(format!(
                                "{e} — refusing to select inputs this wallet may already have spent"
                            ));
                        }
                        self.spent_covered = spent_set.covered;
                        self.spent = Some(spent_set);
                        self.phase = Phase::Coinbase(CoinbaseCatchUp::new(0, self.to));
                    }
                },
                Phase::Coinbase(catch) => {
                    // A gap that has already been named abandons the stream
                    // rather than paging it again — proceeding is the ruling.
                    let want = if self.coinbase_gap.is_some() { None } else { catch.want() };
                    match want {
                        Some((from, to)) => {
                            self.pending = Some(Pending::Coinbase { from, to });
                            return self.need_for(Pending::Coinbase { from, to });
                        }
                        None => {
                            let Phase::Coinbase(catch) =
                                std::mem::replace(&mut self.phase, Phase::Finished)
                            else {
                                unreachable!()
                            };
                            // A stream that FAILED is dropped whole; a stream
                            // that merely stopped short keeps what it served and
                            // names the rest. Both directions only shrink the
                            // input set, which is the ruling's safety shape.
                            let chain = if self.coinbase_gap.is_some() {
                                MinedChain::default()
                            } else {
                                let chain = catch.finish();
                                if let Err(e) = chain.covers(Some((0, self.to))) {
                                    self.coinbase_gap = Some(e.to_string());
                                }
                                chain
                            };
                            self.select_inputs(&chain);
                            if self.spendables.is_empty() {
                                return self.fail(format!(
                                    "no spendable notes: the scan of 0..={} found nothing this wallet can \
                                     spend ({} note(s) it found are already spent). If you expect a received \
                                     note, check that its address index is allocated here.{}",
                                    self.to,
                                    self.skipped_spent,
                                    self.shortfall_context()
                                ));
                            }
                            let held = self.held.take().expect("held leaves are taken once");
                            self.phase = Phase::Tree(TreeCatchUp::new(held));
                        }
                    }
                }
                Phase::Tree(catch) => match catch.want_from() {
                    Some(from) => {
                        self.pending = Some(Pending::Leaves { from });
                        return self.need_for(Pending::Leaves { from });
                    }
                    None => {
                        let Phase::Tree(catch) =
                            std::mem::replace(&mut self.phase, Phase::Anchors { got: None })
                        else {
                            unreachable!()
                        };
                        self.synced = Some(catch.finish());
                    }
                },
                Phase::Anchors { got: None } => {
                    self.pending = Some(Pending::Anchors);
                    return self.need_for(Pending::Anchors);
                }
                Phase::Anchors { got: Some(_) } => {
                    let Phase::Anchors { got: Some(anchors) } =
                        std::mem::replace(&mut self.phase, Phase::Finished)
                    else {
                        unreachable!()
                    };
                    let synced = self.synced.as_ref().expect("tree phase preceded anchors");
                    let anchor = match select_anchor(synced, &anchors) {
                        Ok(a) => a,
                        Err(e) => return self.fail(e.to_string()),
                    };
                    self.events.push(SendStep::Tree {
                        held: synced.count,
                        fetched: synced.fetched,
                        anchor_count: anchor.count,
                        anchor_root: hex32(&anchor.root),
                        node_tip: anchor.tip_height,
                        finalized: anchor.finalized_height,
                        anchor_behind: anchor.leaves_behind_local,
                    });
                    let bundle = match build_bundle(
                        &self.wallet,
                        &self.spendables,
                        &self.recipient,
                        self.amount,
                        &synced.tree,
                        anchor.count,
                        anchor.tip_height,
                        self.recipient_short.clone(),
                        self.outputs,
                        self.spent_covered,
                        self.name_op.as_ref(),
                        rng,
                    ) {
                        Ok(b) => b,
                        // Only a VALUE shortfall carries the coinbase caveat.
                        // "not in the supplied tree" and "outside the anchor"
                        // are not statements about how much money this wallet
                        // has, and decorating them would make the caveat noise.
                        Err(e @ BuildRefusal::CannotCover { .. }) => {
                            let ctx = self.shortfall_context();
                            return self.fail(format!("{e}{ctx}"));
                        }
                        Err(e) => return self.fail(e.to_string()),
                    };
                    return SelectStep::Done(Box::new(bundle));
                }
                Phase::Finished => {
                    return SelectStep::Failed("select driver already completed".to_string());
                }
            }
        }
    }

    /// Build the input set: the scans' transaction outputs, then this wallet's
    /// own MATURE mined notes (lab #424), both with the chain's nullifiers
    /// already subtracted.
    fn select_inputs(&mut self, chain: &MinedChain) {
        let spent = self.spent.take().expect("the spent phase precedes selection");
        for (idx, outcome) in &self.outcomes {
            let report = subtract_spent(&self.wallet, *idx, &outcome.notes, &spent);
            self.skipped_spent += report.spent.len();
            for ln in &report.spendable {
                self.spendables.push(Spendable {
                    div_index: *idx,
                    value: ln.detected.note.value,
                    rho: ln.detected.note.rho,
                    rseed: ln.detected.note.rseed,
                });
            }
        }

        let mut mined = 0usize;
        if chain.covered.is_some() {
            // The scanned indices ARE the allocated ones — an address that can
            // receive is an address that can mine (`coinbase`'s own rule).
            let indices: Vec<u64> = self.outcomes.iter().map(|(idx, _)| *idx).collect();
            let report = match_mined(&self.wallet, &indices, chain, &spent);
            self.skipped_spent += report.spent.len();
            let mut unchecked = 0usize;
            for n in &report.spendable {
                // 🔴 A mined note can be spent like any other, so one at heights
                // the NULLIFIER stream did not reach cannot be shown to be
                // unspent. Dropped, and named — not folded into
                // `covers_outputs` above, which would turn a coinbase-serving,
                // nullifier-short node into a NEW hard refusal for wallets that
                // never mined. Dropping only shrinks; widening the fail-closed
                // check would not.
                if !spent
                    .covered
                    .is_some_and(|(from, to)| from <= n.minted_height && to >= self.to)
                {
                    unchecked += 1;
                    continue;
                }
                self.spendables.push(Spendable {
                    div_index: n.div_index,
                    value: n.note.value,
                    rho: n.note.rho,
                    rseed: n.note.rseed,
                });
                mined += 1;
            }
            if unchecked > 0 {
                self.coinbase_gap = Some(format!(
                    "{unchecked} matured mined note(s) lie at heights the nullifier stream did \
                     not cover, so this send could not tell whether they are already spent and \
                     left them out"
                ));
            }
            self.mined = Some(report);
        }

        // The degradation goes out BEFORE the selection line it explains.
        if let Some(line) = self.coinbase_degradation() {
            self.events.push(SendStep::CoinbaseUnavailable { why: line });
        }
        self.events.push(SendStep::Selected {
            spendable: self.spendables.len(),
            skipped_spent: self.skipped_spent,
            mined,
        });
    }

    /// The one wording for "this send could not see coinbase", shared by the
    /// visible degradation and by the refusal a shrunk set produces — so a user
    /// meets the same sentence in both places.
    fn coinbase_degradation(&self) -> Option<String> {
        self.coinbase_gap.as_ref().map(|why| {
            format!(
                "coinbase was NOT visible to this send — its inputs are {TRANSACTIONS_ONLY} \
                 ({why}). If this wallet's rkm mines, what it earned was not among the inputs \
                 considered."
            )
        })
    }

    /// What a **value shortfall** — and only a value shortfall — must carry, so
    /// "you do not have it" is never confused with "this send could not see it"
    /// or with "you have it and it is not mature yet".
    fn shortfall_context(&self) -> String {
        if let Some(line) = self.coinbase_degradation() {
            return format!(
                " 🔴 {line} So this refusal is NOT evidence that the balance is too low: a node \
                 that serves GET /v1/coinbase may answer it differently."
            );
        }
        match &self.mined {
            Some(m) if !m.maturing.is_empty() => format!(
                " Coinbase WAS visible, and this wallet holds {} bessel of mined coins that are \
                 not spendable yet — the earliest matures at height {}, stated as of tip {}. You \
                 have it; it is not available at this height.",
                m.maturing_value(),
                m.next_maturity().map_or_else(|| "unknown".to_string(), |h| h.to_string()),
                m.as_of,
            ),
            _ => String::new(),
        }
    }

    /// Supply the result for the currently outstanding `Need`. A transport
    /// `Err` becomes the same named refusal the synchronous flow produces; the
    /// bytes are decoded by the SAME decoders `crate::net`'s sources use.
    pub fn supply(&mut self, response: Result<Vec<u8>, String>) {
        let Some(pending) = self.pending.take() else {
            self.fatal =
                Some("select driver received a response without requesting a path".to_string());
            return;
        };
        let path = self.path_of(pending);
        let bytes = match response {
            Ok(bytes) => bytes,
            Err(why) => {
                self.supply_failed(pending, format!("GET {path}: {why}"));
                return;
            }
        };
        match pending {
            Pending::Nullifiers { .. } => {
                let page = match NullifierPage::from_bytes(&bytes) {
                    Ok(p) => p,
                    Err(e) => {
                        return self.supply_failed(
                            pending,
                            format!("GET {path} did not decode: {e:?}"),
                        )
                    }
                };
                let chunk = NullifierChunk {
                    from: page.from,
                    to: page.to,
                    blocks: page.blocks.into_iter().map(|b| (b.height, b.nullifiers)).collect(),
                };
                let Phase::Spent(catch) = &mut self.phase else {
                    self.fatal = Some("a nullifier page arrived outside the spent phase".into());
                    return;
                };
                if let Err(e) = catch.supply(chunk) {
                    self.fatal = Some(format!(
                        "{e} — refusing to select inputs this wallet may already have spent"
                    ));
                }
            }
            Pending::Coinbase { .. } => {
                let page = match CoinbasePage::from_bytes(&bytes) {
                    Ok(p) => p,
                    Err(e) => {
                        return self.supply_failed(
                            pending,
                            format!("GET {path} did not decode: {e:?}"),
                        )
                    }
                };
                let chunk =
                    CoinbaseChunk { from: page.from, to: page.to, blocks: page.blocks };
                let Phase::Coinbase(catch) = &mut self.phase else {
                    self.fatal = Some("a coinbase page arrived outside the coinbase phase".into());
                    return;
                };
                // 🔴 A stream that answers but LIES about its own range —
                // `Gap`/`NotAscending`/`RangeMismatch`/`OutOfRange` — is the same
                // named degradation as an absent one, not a refusal. Every mined
                // note is re-verified downstream regardless of what the stream
                // said: a wrong value derives a `cm` that is in no tree
                // (`not in the supplied tree`) and a note faked into looking
                // mature has no leaf inside the anchor (`outside the anchor`).
                // So a hostile coinbase server can shrink the input set or waste
                // a lookup; it cannot get an unsafe input selected. Refusing
                // would instead hand any node that serves a bad page a switch to
                // stop this wallet's sends.
                if let Err(e) = catch.supply(chunk) {
                    self.coinbase_gap = Some(e.to_string());
                }
            }
            Pending::Leaves { .. } => {
                let page = match qlab_node::TreeLeaves::from_bytes(&bytes) {
                    Ok(p) => p,
                    Err(e) => {
                        return self.supply_failed(
                            pending,
                            format!("GET {path} did not decode: {e:?}"),
                        )
                    }
                };
                let chunk = LeafChunk { from: page.from, total: page.total, leaves: page.leaves };
                let Phase::Tree(catch) = &mut self.phase else {
                    self.fatal = Some("a leaf chunk arrived outside the tree phase".into());
                    return;
                };
                if let Err(e) = catch.supply(chunk) {
                    self.fatal = Some(e.to_string());
                }
            }
            Pending::Anchors => {
                let set = match AnchorSet::from_bytes(&bytes) {
                    Ok(s) => s,
                    Err(e) => {
                        return self.supply_failed(
                            pending,
                            format!("GET {path} did not decode: {e:?}"),
                        )
                    }
                };
                let Phase::Anchors { got } = &mut self.phase else {
                    self.fatal = Some("an anchor set arrived outside the anchor phase".into());
                    return;
                };
                *got = Some(Anchors {
                    tip_height: set.tip_height,
                    finalized_height: set.finalized_height,
                    max_age_blocks: set.max_age_blocks,
                    roots: set.roots,
                });
            }
        }
    }

    fn supply_failed(&mut self, pending: Pending, why: String) {
        match pending {
            Pending::Nullifiers { .. } => {
                self.fatal = Some(format!(
                    "{} — refusing to select inputs this wallet may already have spent",
                    SpentRefusal::Endpoint { why }
                ))
            }
            // 🔴 The 404 posture, and the ONE place it differs from every other
            // endpoint here: not fatal. See this module's header.
            Pending::Coinbase { .. } => {
                self.coinbase_gap =
                    Some(crate::coinbase::CoinbaseRefusal::Endpoint { why }.to_string())
            }
            Pending::Leaves { .. } | Pending::Anchors => {
                self.fatal = Some(SyncRefusal::Endpoint { why }.to_string())
            }
        }
    }

    fn fail(&mut self, why: String) -> SelectStep {
        self.fatal = Some(why.clone());
        SelectStep::Failed(why)
    }

    fn path_of(&self, pending: Pending) -> String {
        match pending {
            Pending::Nullifiers { from, to } => format!("/v1/nullifiers?from={from}&to={to}"),
            Pending::Coinbase { from, to } => format!("/v1/coinbase?from={from}&to={to}"),
            Pending::Leaves { from } => format!("/v1/tree/leaves?from={from}"),
            Pending::Anchors => "/v1/anchors".to_string(),
        }
    }

    fn need_for(&self, pending: Pending) -> SelectStep {
        let endpoint = match pending {
            // The coinbase stream is the compact host's, as it is for `scan`
            // (`crate::scan::gather` fetches it from the same `url`).
            Pending::Nullifiers { .. } | Pending::Coinbase { .. } => SelectEndpoint::Scan,
            Pending::Leaves { .. } | Pending::Anchors => SelectEndpoint::Node,
        };
        SelectStep::Need { endpoint, path: self.path_of(pending) }
    }
}
