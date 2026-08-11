//! The service loop: harvest → dispense → submit → confirm, on the node's own tick.
//!
//! ## Why one mutex and no threads of its own
//!
//! [`FaucetGate`] holds the [`Faucet`] and the receipt ledger behind **one** lock.
//! The HTTP thread takes it to call [`qlab_faucet::Faucet::accept`] (a MAC check, a
//! token bucket and a queue push — microseconds). The node loop takes it to call
//! [`qlab_faucet::Faucet::dispense`], which **proves inside the lock**: a measured
//! ~2.3 s 2×2 STARK. So an arriving request can wait up to one proof time.
//!
//! That is a real cost and it is stated rather than hidden. It is not fixable from
//! out here: `dispense` takes `&mut self` and plans, selects, proves and books the
//! result in one call, so there is no seam at which a listener could hold the lock
//! for the bookkeeping and release it for the proving. Splitting plan-from-prove is a
//! change to the core, and this baton reports it instead of forking the core to get
//! it. Against a 75 s block time and a funding budget of a few grants per won block
//! (`qlab_faucet::inventory`), 2.3 s of admission latency is not the constraint on
//! anything.
//!
//! ## Receipts, and why they are the listener's and not the core's
//!
//! A browser needs a handle to come back to. `Faucet::accept` returns a queue
//! *position*, which changes as the queue drains, so it cannot be one. The listener
//! therefore assigns a receipt and keeps a ledger of what happened to it.
//!
//! Pairing a receipt to an outcome is exact rather than heuristic: `RequestQueue` is
//! FIFO, `pop` takes the front, and `retry` returns a failed request **to the front**
//! (deliberately — the requester already waited). So the head of the faucet's queue
//! is always the head of the receipt queue, and [`FaucetGate`] pushes and pops both
//! under the same lock. They cannot drift, because nothing can observe one without
//! the other.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

use qlab_faucet::{
    AcceptError, DispenseOutcome, Faucet, GrantPlan, PendingRequest, StallReason, Ticket,
};
use qlab_faucet::ChainView;
use qlab_node::{MemNode, NodeState};
use qlab_wallet::address::{Address, Diversifier};
use qlab_wallet::Wallet;
// `NodeState::is_spent` is how a refused grant's inputs are diagnosed as stale.

use crate::harvest::{harvest_matured, HarvestReport};
use crate::state::{classify, Availability, ServiceStatus};
use crate::view::NodeView;

/// Why a local grant submission was refused — named for the operator log
/// (lab issue #310 / #241's typed-reason discipline, one layer up).
///
/// One token per attempt. The strings match the deployed `POST /v1/tx` surface
/// where the verdict is the same (`nullifier-spent`, `anchor-not-valid`, …) so an
/// operator reading either log sees one vocabulary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubmitRefusal {
    /// The faucet's own pre-submit check failed (anchor lease aged out under the
    /// proof). Never reached the mempool.
    AnchorExpired,
    /// The node refused. `reason` is a stable token, not a `Debug` dump.
    Node { reason: String },
}

impl std::fmt::Display for SubmitRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubmitRefusal::AnchorExpired => write!(f, "anchor-expired"),
            SubmitRefusal::Node { reason } => write!(f, "{reason}"),
        }
    }
}

/// Result of submitting a proved grant to the co-resident node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalSubmit {
    Accepted,
    Refused(SubmitRefusal),
}

/// What the faucet service needs from the node it shares a process with.
///
/// Three methods, all of which already existed on the node in some form: two reads
/// and **one** write, and the write is the node's own local-origination path. There
/// is deliberately no `&mut MemNode` here — a co-resident wallet must not be able to
/// fold state directly.
pub trait FaucetNode {
    /// Live consensus state: the commitment tree, the anchor set, the chain.
    fn chain_state(&self) -> &MemNode;

    /// Submit a proved grant. Carries the **named** refusal when the node did not
    /// take it (lab issue #310) — a boolean was how the operator log only ever
    /// saw `gave-up` with no per-attempt reason.
    ///
    /// It takes the whole [`GrantPlan`] rather than just `plan.entry` for
    /// history's sake: when this trait was written (issue #123), discovery
    /// artifacts existed only in an in-memory side table, `plan.entry` could not
    /// carry them, and the wide signature kept that loss visible at the call
    /// site. Since issue #188 the committed discovery group — bundle **and**
    /// payloads — rides *inside* `plan.entry.discovery`, covered by
    /// `tx_body_commitment`, so `plan.entry` alone now carries everything the
    /// chain commits to; `plan.discovery` is the same artifacts in their
    /// pre-encoding shape. See the `RunningNode` impl below.
    fn submit_local(&mut self, plan: &GrantPlan) -> LocalSubmit;

    /// Connected peers — service state, not chain state (a faucet with no peers is a
    /// faucet on its own fork).
    fn peers(&self) -> u64;

    /// **The node's two chain views** — the height it has applied, and the height
    /// its fork choice holds a header for (lab issue #296).
    ///
    /// Returned as one [`qlab_node::StateLag`] rather than as a second bare `u64`
    /// so the gap between the two is computed by the tree's single definition
    /// (`StateLag::blocks`), the same one the node's duty gate and its `slag=`
    /// telemetry field use. A page that differenced two numbers itself would be a
    /// fourth restatement of a rule that already exists, and the page is where a
    /// visitor would be least able to tell it had drifted.
    ///
    /// A node with no separate fork-choice view answers with its applied tip in
    /// both positions, which is honest — it is not behind, it simply has one view.
    /// There is deliberately no default implementation: a new `FaucetNode` must
    /// state which it has rather than inherit a `slag=0` it never checked.
    fn chain_views(&self) -> qlab_node::StateLag;
}

impl<P: qlab_devnet::pow::PowEngine, V: qlab_devnet::body::TxVerifier + Clone> FaucetNode
    for qumbra_node::run::RunningNode<P, V>
{
    fn chain_state(&self) -> &MemNode {
        self.state()
    }
    /// `plan.entry` carries the grant whole — nothing is dropped here any more.
    ///
    /// This comment block used to say the opposite, and was true when written
    /// (issue #123): back then `TxEntry` had no discovery field, `StoredTx` had
    /// none either, and the ML-KEM artifacts a recipient needs lived only in
    /// `qlab_node::rpc::NodeRpc`'s in-memory side table — which `qumbra-node`
    /// composes nowhere — so a grant's recipient could not detect the note
    /// (reported on #123 as the headline finding). **Stale since issue #188**:
    /// the discovery group (bundle and, since #188 (a), the AEAD payloads too)
    /// is part of `TxEntry::discovery`, committed under `tx_body_commitment`,
    /// carried on the P2P tx wire, persisted in `StoredTx`, and its compact
    /// bundle served by the deployed node's own `/v1/compact` — so
    /// `announce_tx_typed(plan.entry)` submits the consensus transaction *and*
    /// the recipient's discovery in one object, and a recipient **detects** the
    /// grant from what a deployed node serves
    /// (`qumbra-node/tests/recipient_scan.rs` is the locating property, over a
    /// real socket, for a transaction submitted through this very path).
    ///
    /// Lab #310: uses the **typed** admission path so a refusal reaches the
    /// operator log as a named token rather than a bare `false`. Same gates as
    /// `submit_local_tx` / peer `ingest_tx` — only the return shape differs.
    fn submit_local(&mut self, plan: &GrantPlan) -> LocalSubmit {
        match self.submit_local_tx_named(plan.entry.clone()) {
            Ok(()) => LocalSubmit::Accepted,
            Err(reason) => LocalSubmit::Refused(SubmitRefusal::Node { reason }),
        }
    }
    fn peers(&self) -> u64 {
        self.p2p().peers().len() as u64
    }
    /// The adapter's own `state_lag()`, unmodified — the identical call
    /// `qumbra-node`'s `TELEMETRY` line and `/metrics` scrape make (`run.rs`, issue
    /// #130 (a)). So the faucet page, the node's log line and the node's scrape
    /// cannot disagree about how far behind this node is.
    fn chain_views(&self) -> qlab_node::StateLag {
        self.p2p().node().state_lag()
    }
}

/// Where one request got to. This is the whole state machine a browser sees.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestState {
    /// Admitted and waiting. `position` is a snapshot, not a promise.
    Queued { position: usize },
    /// A grant was proved, submitted and accepted by the node. `height` is the tip
    /// the submission was accepted at — the block it lands in is at or above it.
    Granted { txid_hex: String, value_bessel: u64, submitted_at_tip: u64 },
    /// The faucet tried and failed, and the requester's attempt budget is spent.
    /// `reason` is the faucet's own words, never a stack trace.
    GaveUp { reason: String },
}

/// The [`Faucet`] plus the receipt ledger, behind one lock (see the module docs).
pub struct FaucetGate {
    faucet: Faucet,
    /// Receipts in the same order as the faucet's queue. Pushed and popped with it.
    order: VecDeque<u64>,
    receipts: HashMap<u64, RequestState>,
    next_receipt: u64,
}

impl FaucetGate {
    /// Wrap a funded (or not yet funded) faucet.
    pub fn new(faucet: Faucet) -> FaucetGate {
        FaucetGate {
            faucet,
            order: VecDeque::new(),
            receipts: HashMap::new(),
            next_receipt: 1,
        }
    }

    /// Read-only faucet (status rendering, tests).
    pub fn faucet(&self) -> &Faucet {
        &self.faucet
    }

    /// Issue an operator ticket.
    pub fn issue_ticket(&self, id: u64) -> Ticket {
        self.faucet.issue_ticket(id)
    }

    /// Take a request through the core's gate, assigning a receipt if it is
    /// admitted. The receipt and the queue entry are created together, under this
    /// lock, so the two orders cannot diverge.
    pub fn accept(
        &mut self,
        client: &str,
        recipient: Address,
        ticket: Option<Ticket>,
        now_ms: u64,
    ) -> Result<(u64, usize), AcceptError> {
        let position = self.faucet.accept(client, recipient, ticket, now_ms)?;
        let receipt = self.next_receipt;
        self.next_receipt += 1;
        self.order.push_back(receipt);
        self.receipts.insert(receipt, RequestState::Queued { position });
        Ok((receipt, position))
    }

    /// A receipt's current state. `None` = never issued by this process.
    pub fn state_of(&self, receipt: u64) -> Option<RequestState> {
        self.receipts.get(&receipt).cloned()
    }

    /// The receipt at the head of the queue — the one `dispense` is about to serve.
    fn head(&self) -> Option<u64> {
        self.order.front().copied()
    }

    /// Refresh every queued receipt's position after the queue moved, so a browser
    /// polling `/r/<receipt>` is told where it actually is.
    fn renumber(&mut self) {
        for (i, r) in self.order.iter().enumerate() {
            if let Some(RequestState::Queued { position }) = self.receipts.get_mut(r) {
                *position = i + 1;
            }
        }
    }
}

/// One tick's worth of what the service did — returned so a caller (and the tests)
/// can assert on it instead of parsing logs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServeReport {
    /// Notes funded in this tick, and what is still maturing.
    pub harvest: HarvestReport,
    /// A grant was proved, submitted and confirmed. Carries the receipt.
    pub granted: Option<u64>,
    /// The faucet could not serve the head of the queue, and why. A stall consumes
    /// nothing — not the request, not its attempt budget.
    pub stalled: Option<String>,
    /// A built grant the node refused; the requester keeps their place.
    pub rejected: Option<u64>,
    /// Named reason for a refused attempt this tick (lab issue #310) — one token
    /// for the operator log, never a stack trace. Set whenever `rejected` or
    /// `gave_up` is set from a submit refusal, and also when stale inputs were
    /// dropped without burning the attempt budget.
    pub refusal_reason: Option<String>,
    /// A request abandoned after exhausting its attempts.
    pub gave_up: Option<u64>,
    /// Stale inventory entries dropped this tick (notes whose nullifiers were
    /// already on-chain). Non-zero means the restart-inventory bug path fired
    /// and the service recovered by forgetting rather than re-proving.
    pub dropped_spent: usize,
}

/// The faucet service: the gate, the wallet that owns the notes, and the harvest
/// cursor.
pub struct FaucetService {
    gate: Arc<Mutex<FaucetGate>>,
    /// The spending wallet. Held here and nowhere else; no `Debug` on this struct
    /// reaches it (the type has none at all, deliberately — see PR #103).
    wallet: Wallet,
    d: Diversifier,
    /// Coinbase-note commitments already funded, so a re-walk never funds twice.
    harvested: HashSet<[u8; 32]>,
    /// The height the earliest outstanding immature note matures at, from the last
    /// harvest pass. Carried because it is what the status page answers with.
    next_maturity: Option<u64>,
    /// Immature coinbase notes outstanding, from the last harvest pass.
    maturing: usize,
    /// Rendered status, shared with the HTTP thread. Same snapshot discipline as the
    /// node's `/metrics`: the loop renders on its own cadence, a request clones.
    status: Arc<Mutex<ServiceStatus>>,
}

impl FaucetService {
    /// Build a service over `faucet`, whose notes are owned by `wallet` at `d`.
    ///
    /// `d` must be the diversifier the faucet was constructed with (its change
    /// address), because that is the `rkm` the node was told to pay.
    pub fn new(faucet: Faucet, wallet: Wallet, d: Diversifier) -> FaucetService {
        let status = ServiceStatus {
            // Nothing sampled yet: both views at genesis, so the page shows a zero
            // gap rather than a fabricated one before the first `refresh_status`.
            chain: qlab_node::StateLag::default(),
            finalized_height: None,
            peers: 0,
            availability: Availability::ColdChain,
            queued: 0,
            queue_capacity: faucet.queue().capacity(),
            wait_blocks: 1,
            grant_value: faucet.config().grant_value,
            tickets_required: matches!(
                faucet.config().limits.ticket_policy,
                qlab_faucet::TicketPolicy::Required
            ),
            confirmed: 0,
            refused: 0,
            notes_held: faucet.inventory().len(),
            notes_maturing: 0,
        };
        FaucetService {
            gate: Arc::new(Mutex::new(FaucetGate::new(faucet))),
            wallet,
            d,
            harvested: HashSet::new(),
            next_maturity: None,
            maturing: 0,
            status: Arc::new(Mutex::new(status)),
        }
    }

    /// The shared gate — this is what the HTTP listener is handed.
    pub fn gate(&self) -> Arc<Mutex<FaucetGate>> {
        Arc::clone(&self.gate)
    }

    /// The shared status snapshot — what the listener renders.
    pub fn status(&self) -> Arc<Mutex<ServiceStatus>> {
        Arc::clone(&self.status)
    }

    /// The faucet's own receive address — where the node must be told to pay.
    pub fn address(&self) -> Address {
        self.wallet.address(self.d)
    }

    /// Lock the gate, ignoring poisoning: a panicking HTTP handler must not wedge
    /// the faucet.
    fn lock_gate(&self) -> MutexGuard<'_, FaucetGate> {
        self.gate.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// One service tick: harvest matured coinbase, then serve at most one request.
    ///
    /// **At most one grant per tick, on purpose.** A grant is a ~2.3 s proof on the
    /// node's own loop thread; serving the whole queue in one tick would stall the
    /// transport pump and mining for `queue_depth × 2.3 s` (up to 73 s at the 32-deep
    /// cap — one whole block interval). One per tick bounds the loop's worst
    /// iteration at one proof, and the gate's refill window admits one grant per
    /// block interval anyway (`qlab_faucet::FaucetLimits`), so nothing is lost.
    pub fn tick<N: FaucetNode, R: rand::CryptoRng>(
        &mut self,
        node: &mut N,
        rng: &mut R,
    ) -> ServeReport {
        let mut report = ServeReport::default();

        // (1) Funding. The frozen §2 maturity gate is applied here — see `harvest`.
        {
            // `self.gate` and `self.harvested` are disjoint fields, so the lock is
            // taken inline rather than through `lock_gate(&self)` — which would
            // borrow all of `self`.
            let mut gate = self.gate.lock().unwrap_or_else(|e| e.into_inner());
            let state = node.chain_state();
            report.harvest =
                harvest_matured(&mut gate.faucet, state, &self.wallet, self.d, &mut self.harvested);
        }
        self.next_maturity = report.harvest.next_maturity;
        self.maturing = report.harvest.maturing;

        // (2) Serve at most one request.
        let outcome = {
            let mut gate = self.lock_gate();
            let receipt = gate.head();
            let view = NodeView(node.chain_state());
            let outcome = gate.faucet.dispense(&view, rng);
            (receipt, outcome)
        };
        match outcome {
            (_, DispenseOutcome::Idle) => {}
            (_, DispenseOutcome::Stalled(reason)) => {
                report.stalled = Some(stall_text(&reason));
            }
            (receipt, DispenseOutcome::Ready { plan, request }) => {
                self.submit(node, *plan, request, receipt, &mut report);
            }
            (_, DispenseOutcome::Retrying { reason }) => {
                report.stalled = Some(format!("build failed, requeued: {reason}"));
            }
            (receipt, DispenseOutcome::Abandoned { request, reason }) => {
                let _ = request; // never logged: it carries the recipient address
                let mut gate = self.lock_gate();
                gate.order.pop_front();
                if let Some(r) = receipt {
                    gate.receipts.insert(r, RequestState::GaveUp { reason: reason.to_string() });
                }
                gate.renumber();
                report.gave_up = receipt;
            }
        }

        // (3) Re-render the snapshot the page serves.
        self.refresh_status(node);
        report
    }

    /// Submit a proved grant and book the result. The two-phase seam is the core's
    /// and it is respected: the inventory moves only when the chain says it moved.
    fn submit<N: FaucetNode>(
        &mut self,
        node: &mut N,
        plan: GrantPlan,
        request: PendingRequest,
        receipt: Option<u64>,
        report: &mut ServeReport,
    ) {
        // The faucet's own pre-submit re-check: the anchor lease may have run out
        // while the proof was being built. Declining here costs a proof; submitting
        // an expired one costs a proof AND a rejected transaction.
        let submittable = {
            let view = NodeView(node.chain_state());
            plan.is_submittable(&view)
        };
        let outcome = if !submittable {
            LocalSubmit::Refused(SubmitRefusal::AnchorExpired)
        } else {
            node.submit_local(&plan)
        };
        let tip = node.chain_state().tip_height();

        match outcome {
            LocalSubmit::Accepted => {
                let mut gate = self.lock_gate();
                let txid = qlab_node::txid(&plan.entry);
                let value = plan.grant_value;
                gate.faucet.confirm(plan);
                gate.order.pop_front();
                if let Some(r) = receipt {
                    gate.receipts.insert(
                        r,
                        RequestState::Granted {
                            txid_hex: hex32(&txid),
                            value_bessel: value,
                            submitted_at_tip: tip,
                        },
                    );
                }
                gate.renumber();
                report.granted = receipt;
            }
            LocalSubmit::Refused(refusal) => {
                let reason = refusal.to_string();
                report.refusal_reason = Some(reason.clone());

                // Lab #310: if any input's nullifier is already on-chain, drop
                // those notes and requeue without burning the attempt budget.
                // Restoring them would make the next attempt re-pick the same
                // pair (select_pair is deterministic) and burn the budget.
                let spent_cms: Vec<[u64; 4]> = plan
                    .spent
                    .iter()
                    .filter(|n| {
                        let nf = qlab_note::hash::digest_bytes(&self.wallet.nullifier(&n.rho));
                        node.chain_state().is_spent(&nf)
                    })
                    .map(|n| n.cm)
                    .collect();

                // Remember the leaves so harvest does not re-fund them (before
                // taking the gate lock — `self.harvested` and the gate are
                // disjoint fields, but the lock is on `self.gate`).
                if !spent_cms.is_empty() {
                    report.dropped_spent = spent_cms.len();
                    for cm in &spent_cms {
                        self.harvested.insert(qlab_note::hash::digest_bytes(cm));
                    }
                }

                let mut gate = self.lock_gate();
                if !spent_cms.is_empty() {
                    gate.faucet.reject_stale_inputs(plan, request, &spent_cms);
                    report.rejected = receipt;
                    // Receipt stays Queued — the attempt was not consumed.
                } else {
                    // Ordinary refusal: restore inputs, burn one attempt.
                    let still_queued = gate.faucet.reject(plan, request);
                    if still_queued {
                        report.rejected = receipt;
                    } else {
                        gate.order.pop_front();
                        if let Some(r) = receipt {
                            gate.receipts.insert(
                                r,
                                RequestState::GaveUp {
                                    reason: format!(
                                        "the node did not admit this grant ({reason}), and the \
                                         retry budget is spent"
                                    ),
                                },
                            );
                        }
                        report.gave_up = receipt;
                    }
                }
                gate.renumber();
            }
        }
    }

    /// Re-render the status snapshot the HTTP surface serves.
    pub fn refresh_status<N: FaucetNode>(&self, node: &N) {
        let gate = self.lock_gate();
        let view = NodeView(node.chain_state());
        let availability = classify(gate.faucet(), &view, self.next_maturity, self.maturing);
        let stats = gate.faucet().stats();
        let next = ServiceStatus {
            // `chain.state_tip` is the same `MemNode::tip_height()` this `view`
            // reads — `RunningNode::state()` and `state_lag()`'s left operand are
            // one object — so the two are not two samples that could disagree.
            chain: node.chain_views(),
            finalized_height: view.finalized_height(),
            peers: node.peers(),
            availability,
            queued: gate.faucet().queue().len(),
            queue_capacity: gate.faucet().queue().capacity(),
            wait_blocks: gate.faucet().queue().estimated_wait_blocks(),
            grant_value: gate.faucet().config().grant_value,
            tickets_required: matches!(
                gate.faucet().config().limits.ticket_policy,
                qlab_faucet::TicketPolicy::Required
            ),
            confirmed: stats.confirmed,
            refused: stats.refused,
            notes_held: gate.faucet().inventory().len(),
            notes_maturing: self.maturing,
        };
        drop(gate);
        if let Ok(mut slot) = self.status.lock() {
            *slot = next;
        }
    }
}

/// A stall in the requester's terms. `StallReason` already words itself for a
/// human; this only prefixes the fact that nothing was consumed, because a requester
/// reading "out of spendable notes" needs to know they are still in the queue.
fn stall_text(reason: &StallReason) -> String {
    format!("{reason} (your place in the queue is unchanged)")
}

/// Lower-case hex of a 32-byte id.
fn hex32(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_faucet::{FaucetConfig, FaucetLimits, Refusal, TicketPolicy, TicketSecret};

    fn gate() -> FaucetGate {
        FaucetGate::new(Faucet::new(
            Wallet::from_seed_lanes([0x4321; 4]),
            Diversifier::default(),
            TicketSecret::from_bytes([7; 32]),
            FaucetConfig {
                limits: FaucetLimits {
                    ticket_policy: TicketPolicy::Disabled,
                    ..FaucetLimits::unlimited()
                },
                ..FaucetConfig::default()
            },
        ))
    }

    fn addr(i: u64) -> Address {
        Wallet::from_seed_lanes([0xA000 + i; 4]).address(Diversifier::default())
    }

    /// Receipts are handed out in order, and each one's position is its place in the
    /// queue — the thing a browser polls for.
    #[test]
    fn receipts_are_issued_in_queue_order_and_carry_a_position() {
        let mut g = gate();
        let (r1, p1) = g.accept("203.0.113.1", addr(1), None, 0).expect("admitted");
        let (r2, p2) = g.accept("203.0.113.2", addr(2), None, 1_000).expect("admitted");
        assert_eq!((p1, p2), (1, 2));
        assert_ne!(r1, r2);
        assert_eq!(g.state_of(r1), Some(RequestState::Queued { position: 1 }));
        assert_eq!(g.state_of(r2), Some(RequestState::Queued { position: 2 }));
        assert_eq!(g.head(), Some(r1), "the head of the receipt queue is the head of the faucet's");
        assert_eq!(g.state_of(999), None, "an unissued receipt is not a state");
    }

    /// A refused request gets **no** receipt: there is nothing to come back for, and
    /// handing out a handle to a request that does not exist is how a status page
    /// starts lying.
    #[test]
    fn a_refusal_issues_no_receipt() {
        let mut g = FaucetGate::new(Faucet::new(
            Wallet::from_seed_lanes([0x4322; 4]),
            Diversifier::default(),
            TicketSecret::from_bytes([8; 32]),
            FaucetConfig::default(), // tickets Required
        ));
        let err = g.accept("203.0.113.9", addr(3), None, 0).unwrap_err();
        assert_eq!(err, AcceptError::Refused(Refusal::TicketMissing));
        assert!(g.order.is_empty());
        assert!(g.receipts.is_empty());
    }

    /// The receipt queue and the faucet queue move together: after the head is
    /// served, everyone behind moves up by exactly one.
    #[test]
    fn serving_the_head_renumbers_everyone_behind_it() {
        let mut g = gate();
        let (_r1, _) = g.accept("203.0.113.1", addr(1), None, 0).unwrap();
        let (r2, _) = g.accept("203.0.113.2", addr(2), None, 1_000).unwrap();
        let (r3, _) = g.accept("203.0.113.3", addr(3), None, 2_000).unwrap();
        // Simulate the head being served (what `submit` does on acceptance).
        let _ = g.faucet.queue();
        g.order.pop_front();
        g.renumber();
        assert_eq!(g.state_of(r2), Some(RequestState::Queued { position: 1 }));
        assert_eq!(g.state_of(r3), Some(RequestState::Queued { position: 2 }));
    }
}
