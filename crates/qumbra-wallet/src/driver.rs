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
//! 🔴 **What this driver still cannot select: a MINED note (lab #424).** Its
//! input set comes from [`ScanOutcome::notes`], i.e. transaction outputs, and a
//! coinbase note is not in that set by construction — it has no discovery group
//! at all, which is the whole of lab #415. Since #415 landed, `scan` reports a
//! matured coinbase as spendable and a `send` on the same wallet still refuses
//! with "no spendable notes", so the gap is now a visible contradiction rather
//! than a quiet absence. The witness path is already proved to work for such a
//! note (`coinbase::tests::a_mined_note_is_locatable_in_the_tree_and_the_spend_path_accepts_it`);
//! what it needs is a fourth phase here and a ruling on what a send does when
//! `/v1/coinbase` 404s. Both are on lab #424.
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
use qlab_cbserver::codec::NullifierPage;
use qlab_cbserver::tree::CommitmentTree;
use qlab_node::AnchorSet;
use qlab_wallet::address::Address;
use qlab_wallet::Wallet;
use rand::rngs::StdRng;

use crate::bundle::WitnessBundle;
use crate::scan::widest_range;
use crate::send::{build_bundle, Spendable};
use crate::spend::SendStep;
use crate::spent::{subtract_spent, NullifierChunk, SpentCatchUp, SpentRefusal};
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
    Tree(TreeCatchUp),
    Anchors { got: Option<Anchors> },
    Finished,
}

#[derive(Clone, Copy)]
enum Pending {
    Nullifiers { from: u64, to: u64 },
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
                        if let Err(e) = spent_set.covers_outputs(self.outputs) {
                            return self.fail(format!(
                                "{e} — refusing to select inputs this wallet may already have spent"
                            ));
                        }
                        let mut skipped = 0usize;
                        for (idx, outcome) in &self.outcomes {
                            let report =
                                subtract_spent(&self.wallet, *idx, &outcome.notes, &spent_set);
                            skipped += report.spent.len();
                            for ln in &report.spendable {
                                self.spendables.push(Spendable {
                                    div_index: *idx,
                                    value: ln.detected.note.value,
                                    rho: ln.detected.note.rho,
                                    rseed: ln.detected.note.rseed,
                                });
                            }
                        }
                        self.events.push(SendStep::Selected {
                            spendable: self.spendables.len(),
                            skipped_spent: skipped,
                        });
                        if self.spendables.is_empty() {
                            return self.fail(format!(
                                "no spendable notes: the scan of 0..={} found nothing this wallet can spend \
                                 ({skipped} note(s) it found are already spent). If you expect a coinbase, it is not \
                                 spendable until it matures (frozen §2, COINBASE_MATURITY_BLOCKS in qlab-node); if \
                                 you expect a received note, check that its address index is allocated here.",
                                self.to
                            ));
                        }
                        self.spent_covered = spent_set.covered;
                        let held = self.held.take().expect("held leaves are taken once");
                        self.phase = Phase::Tree(TreeCatchUp::new(held));
                    }
                },
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
                        Err(e) => return self.fail(e),
                    };
                    return SelectStep::Done(Box::new(bundle));
                }
                Phase::Finished => {
                    return SelectStep::Failed("select driver already completed".to_string());
                }
            }
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
                let why = format!("GET {path}: {why}");
                self.fatal = Some(match pending {
                    Pending::Nullifiers { .. } => format!(
                        "{} — refusing to select inputs this wallet may already have spent",
                        SpentRefusal::Endpoint { why }
                    ),
                    Pending::Leaves { .. } | Pending::Anchors => {
                        SyncRefusal::Endpoint { why }.to_string()
                    }
                });
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
        self.fatal = Some(match pending {
            Pending::Nullifiers { .. } => format!(
                "{} — refusing to select inputs this wallet may already have spent",
                SpentRefusal::Endpoint { why }
            ),
            Pending::Leaves { .. } | Pending::Anchors => SyncRefusal::Endpoint { why }.to_string(),
        });
    }

    fn fail(&mut self, why: String) -> SelectStep {
        self.fatal = Some(why.clone());
        SelectStep::Failed(why)
    }

    fn path_of(&self, pending: Pending) -> String {
        match pending {
            Pending::Nullifiers { from, to } => format!("/v1/nullifiers?from={from}&to={to}"),
            Pending::Leaves { from } => format!("/v1/tree/leaves?from={from}"),
            Pending::Anchors => "/v1/anchors".to_string(),
        }
    }

    fn need_for(&self, pending: Pending) -> SelectStep {
        let endpoint = match pending {
            Pending::Nullifiers { .. } => SelectEndpoint::Scan,
            Pending::Leaves { .. } | Pending::Anchors => SelectEndpoint::Node,
        };
        SelectStep::Need { endpoint, path: self.path_of(pending) }
    }
}
