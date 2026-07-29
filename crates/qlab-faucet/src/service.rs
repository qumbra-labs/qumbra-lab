//! The faucet itself: gate → queue → plan → prove → hand back for submission.
//!
//! ## Why this is two-phase rather than "submit it for me"
//!
//! [`Faucet::dispense`] returns a proved [`GrantPlan`]; the caller submits it and
//! reports back with [`Faucet::confirm`] or [`Faucet::reject`]. The seam is there
//! because the faucet's inventory must only move when the *chain* says it moved.
//! A faucet that optimistically credits its own change note is a faucet that
//! quietly stops being able to pay after the first rejected submission, and it is
//! the exact failure the "N consecutive grants" acceptance item is looking for.
//!
//! The rollback is safe against the one race it has: if a submission actually
//! landed while the faucet believed it had not, the restored input notes are
//! already spent and the node refuses the retry from its permanent nullifier set.
//! The faucet loses a proof, never consensus safety.
//!
//! ## Key custody, and the loss bound when it fails
//!
//! The faucet holds a live [`Wallet`], i.e. a spending key on a public service.
//! Spend authorisation on this chain is *inside the proof* — there is no per-spend
//! signature — so **knowledge of `sk` is sufficient to spend**, and the loss upper
//! bound on compromise is unavoidably "every note that key owns, plus every grant
//! until the key is rotated".
//!
//! What this crate does about that, and what it deliberately does not:
//!
//! - **Scope the key.** [`FaucetConfig::hd_account`] documents that the faucet is a
//!   distinct HD account ([`qlab_wallet::Wallet::from_master_seed`]), so compromise
//!   reaches the faucet's notes and nothing else derived from the same seed. This is
//!   the mitigation that actually bounds the loss.
//! - **Never render the key.** No `Debug` on this struct reaches the wallet, and the
//!   ticket secret redacts itself ([`crate::policy::TicketSecret`]).
//! - **No listener here** (see the crate docs): a hot key and a public socket in one
//!   crate is a decision `testnet-plan.md` §6 assigns to its own row.
//!
//! And the honest negative result, because it changes the recommendation: **a small
//! hot balance is not achievable here.** Topping a hot key up from a cold one is
//! itself a 2×2 transaction, and by the conservation law each such transaction moves
//! exactly **one** note across (2 cold in → 1 to hot + 1 cold change). Maintaining a
//! hot inventory of *n* notes therefore costs *n* proofs from the cold key, which
//! must be online to make them — so "cold" is a fiction the arithmetic does not
//! support. The defensible posture is the opposite one: accept a large hot balance,
//! keep it valueless (testnet), scope the account, and make rotation cheap by
//! funding the faucet from a mining payout address that can be repointed. Stated as
//! a bound: **loss ≤ (blocks mined since rotation) × coinbase(h) + the accrued
//! change**, so a 1,152-block (24 h, one committee epoch) rotation cadence bounds it
//! at one day of emission and one day of service.

use qlab_devnet::fees::{posted_fee, ArityBucket};
use qlab_wallet::address::{Address, Diversifier};
use qlab_wallet::Wallet;
use rand::CryptoRng;

use crate::grant::{build_grant, AnchorLease, GrantError, GrantPlan, PROOF_LEASE_BLOCKS};
use crate::inventory::{Inventory, InventoryError, OwnedNote};
use crate::policy::{AbuseGate, FaucetLimits, GateStats, Refusal, Ticket, TicketSecret};
use crate::queue::{PendingRequest, QueueError, RequestQueue, MAX_QUEUE_DEPTH};
use crate::view::ChainView;

/// Default grant value in bessel: **10 QMB** (1 QMB = 10⁸ bessel, frozen §8).
/// `[devnet-placeholder]` testnet-tunable, NOT frozen — no design doc pins a faucet
/// grant.
///
/// Grounds: the 2×2 posted fee is 0.01 QMB (frozen §5), so a grant is **1,000
/// transactions** of runway — enough for a joiner to actually exercise the chain
/// rather than to look at it. It is also 1/5 of one coinbase note at `coinbase(0)`
/// = 50 QMB, which matters only for value: the binding constraint is the note count
/// (one grant per note, regardless of value), so making the grant smaller buys no
/// extra grants at all.
pub const DEFAULT_GRANT_BESSEL: u64 = 10 * 100_000_000;

/// Faucet configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaucetConfig {
    /// Grant value in bessel.
    pub grant_value: u64,
    /// Self-imposed anchor lease in blocks ([`PROOF_LEASE_BLOCKS`]).
    pub lease_blocks: u64,
    /// Queue depth ([`MAX_QUEUE_DEPTH`]).
    pub queue_depth: usize,
    /// Off-chain gate limits.
    pub limits: FaucetLimits,
    /// The HD account the faucet's spending key is derived at
    /// (`Wallet::from_master_seed(seed, hd_account)`).
    ///
    /// Recorded in the config rather than left implicit because it **is** the loss
    /// bound (module docs): a faucet sharing an account with the treasury turns a
    /// service compromise into a treasury compromise. Account 0 is conventionally
    /// the primary wallet, so the default here is deliberately not 0.
    pub hd_account: u32,
}

impl Default for FaucetConfig {
    fn default() -> Self {
        FaucetConfig {
            grant_value: DEFAULT_GRANT_BESSEL,
            lease_blocks: PROOF_LEASE_BLOCKS,
            queue_depth: MAX_QUEUE_DEPTH,
            limits: FaucetLimits::default(),
            hd_account: 1,
        }
    }
}

/// Counters an operator reads. Process-lifetime totals; every rate quoted from
/// these must carry the window it was taken over.
///
/// No `Eq`: `prove_secs` is an accumulated `f64`, and pretending a wall-clock sum
/// has exact equality is the kind of small lie that makes a test pass for the wrong
/// reason.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct FaucetStats {
    /// Requests that passed the gate and were queued.
    pub queued: u64,
    /// Requests refused by the gate.
    pub refused: u64,
    /// Requests refused because the queue was full (the gate was never consulted,
    /// so no ticket was burned).
    pub queue_full: u64,
    /// Grants built and proved.
    pub built: u64,
    /// Grants the chain accepted.
    pub confirmed: u64,
    /// Built grants the chain (or the faucet's own pre-submit check) refused.
    pub rejected: u64,
    /// Dispense attempts that could not plan at all (no anchor, or no spendable
    /// pair). The request keeps its place in the queue and burns no attempt.
    pub stalled: u64,
    /// Requests abandoned after exhausting their attempt budget.
    pub abandoned: u64,
    /// Total seconds inside the prover. Divide by [`Self::built`] for the mean —
    /// and quote the count with it.
    pub prove_secs: f64,
    /// Total bessel granted (confirmed only).
    pub granted_bessel: u64,
    /// Total bessel paid in posted fees (confirmed only).
    pub fees_bessel: u64,
}

/// Why a request could not be accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptError {
    /// The off-chain gate refused it.
    Refused(Refusal),
    /// The queue is full. Checked **before** the gate, so the requester's ticket is
    /// not burned by a capacity problem that is not their fault.
    Queue(QueueError),
}

impl std::fmt::Display for AcceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcceptError::Refused(r) => write!(f, "{r}"),
            AcceptError::Queue(q) => write!(f, "{q}"),
        }
    }
}

impl std::error::Error for AcceptError {}

/// Why a dispense attempt could not produce a plan, without consuming anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StallReason {
    /// Nothing is finalized, so there is no valid anchor to bind a proof to. On a
    /// fresh net this is the cold start.
    NoValidAnchor,
    /// The inventory cannot fund a transaction right now. `OutOfNotes` with
    /// `held ≥ 2` means *wait for finality*; with `held < 2` the note budget is
    /// spent and only coinbase refills it.
    Inventory(InventoryError),
}

impl std::fmt::Display for StallReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StallReason::NoValidAnchor => f.write_str(
                "no valid anchor yet (nothing finalized) — the faucet is funded but unspendable",
            ),
            StallReason::Inventory(e) => write!(f, "{e}"),
        }
    }
}

/// The outcome of one [`Faucet::dispense`] call.
#[derive(Debug)]
pub enum DispenseOutcome {
    /// Nothing is queued.
    Idle,
    /// Something is queued but cannot be served right now. The head keeps its
    /// place and burns no attempt.
    Stalled(StallReason),
    /// A proved grant, ready to submit. The caller must report back via
    /// [`Faucet::confirm`] or [`Faucet::reject`].
    Ready { plan: Box<GrantPlan>, request: PendingRequest },
    /// Building failed and the request was requeued for another attempt.
    Retrying { reason: GrantError },
    /// Building failed and the attempt budget is spent.
    Abandoned { request: PendingRequest, reason: GrantError },
}

/// A funded, rate-limited, proof-generating faucet.
pub struct Faucet {
    wallet: Wallet,
    change_d: Diversifier,
    config: FaucetConfig,
    inventory: Inventory,
    gate: AbuseGate,
    queue: RequestQueue,
    stats: FaucetStats,
}

impl std::fmt::Debug for Faucet {
    /// Deliberately hand-written: a derived `Debug` would reach the [`Wallet`], and
    /// a struct printed wholesale into a log line is the likeliest way a spending
    /// key escapes a Rust service.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Faucet")
            .field("grant_value", &self.config.grant_value)
            .field("hd_account", &self.config.hd_account)
            .field("notes_held", &self.inventory.len())
            .field("grants_available", &self.inventory.grants_available())
            .field("queued", &self.queue.len())
            .field("wallet", &"<spending key withheld>")
            .finish()
    }
}

impl Faucet {
    /// Build a faucet over `wallet`, issuing tickets under `secret`.
    ///
    /// `change_d` is the diversifier the faucet's change notes are paid to. It is
    /// fixed rather than rotated per grant: the change note is the faucet's own, and
    /// rotating it would cost a diversifier ledger for zero privacy gain (the faucet
    /// is a publicly-known payer either way — every grant it makes announces it).
    pub fn new(
        wallet: Wallet,
        change_d: Diversifier,
        secret: TicketSecret,
        config: FaucetConfig,
    ) -> Faucet {
        Faucet {
            wallet,
            change_d,
            gate: AbuseGate::new(secret, config.limits),
            queue: RequestQueue::new(config.queue_depth),
            inventory: Inventory::new(),
            stats: FaucetStats::default(),
            config,
        }
    }

    /// The faucet's own receive address — where funding is paid.
    pub fn address(&self) -> Address {
        self.wallet.address(self.change_d)
    }

    /// Issue a ticket (operator-side).
    pub fn issue_ticket(&self, id: u64) -> Ticket {
        self.gate.issue(id)
    }

    /// Record a note the faucet owns.
    pub fn fund(&mut self, note: OwnedNote) {
        self.inventory.insert(note);
    }

    /// Read-only inventory (the note-count budget lives here).
    pub fn inventory(&self) -> &Inventory {
        &self.inventory
    }

    /// Read-only queue.
    pub fn queue(&self) -> &RequestQueue {
        &self.queue
    }

    /// Counters.
    pub fn stats(&self) -> FaucetStats {
        self.stats
    }

    /// Gate counters.
    pub fn gate_stats(&self) -> GateStats {
        self.gate.stats()
    }

    /// Configuration.
    pub fn config(&self) -> &FaucetConfig {
        &self.config
    }

    /// Take a request: capacity check, then the off-chain gate, then queue it.
    ///
    /// **Capacity is checked first on purpose.** The gate burns a single-use ticket
    /// when it admits, and a full queue is the faucet's problem rather than the
    /// requester's — consulting the gate first would spend their ticket on a
    /// capacity refusal.
    pub fn accept(
        &mut self,
        client: &str,
        recipient: Address,
        ticket: Option<Ticket>,
        now_ms: u64,
    ) -> Result<usize, AcceptError> {
        if self.queue.len() >= self.queue.capacity() {
            self.stats.queue_full += 1;
            return Err(AcceptError::Queue(QueueError::Full { depth: self.queue.len() }));
        }
        let ticket_id = match self.gate.admit(client, ticket, now_ms) {
            Ok(id) => id,
            Err(r) => {
                self.stats.refused += 1;
                return Err(AcceptError::Refused(r));
            }
        };
        let pos = self
            .queue
            .push(PendingRequest {
                client: client.to_string(),
                recipient,
                ticket_id,
                admitted_ms: now_ms,
                attempts: 0,
            })
            .map_err(AcceptError::Queue)?;
        self.stats.queued += 1;
        Ok(pos)
    }

    /// Plan and prove the next queued grant.
    ///
    /// Nothing is consumed until a plan is certain: the anchor lease and the input
    /// pair are both resolved *before* the request leaves the queue, so a stalled
    /// faucet does not spend its requesters' attempt budgets on its own shortage.
    pub fn dispense<V: ChainView, R: CryptoRng>(
        &mut self,
        view: &V,
        rng: &mut R,
    ) -> DispenseOutcome {
        if self.queue.is_empty() {
            return DispenseOutcome::Idle;
        }
        let Some(lease) = AnchorLease::acquire(view, self.config.lease_blocks) else {
            self.stats.stalled += 1;
            return DispenseOutcome::Stalled(StallReason::NoValidAnchor);
        };
        let need = self.config.grant_value + posted_fee(ArityBucket::TwoByTwo);
        let pair = match self.inventory.select_pair(need, view.tree(), lease.leaf_count) {
            Ok(p) => p,
            Err(e) => {
                self.stats.stalled += 1;
                return DispenseOutcome::Stalled(StallReason::Inventory(e));
            }
        };

        let request = self.queue.pop().expect("queue is non-empty");
        let inputs = self.inventory.take_pair(pair);
        // `build_grant` takes the notes by value; keep a copy so a build failure —
        // which touches nothing on the chain — can restore the inventory exactly.
        let backup = inputs.clone();
        match build_grant(
            &self.wallet,
            self.change_d,
            &request.recipient,
            self.config.grant_value,
            inputs,
            lease,
            view.tree(),
            rng,
        ) {
            Ok((plan, _inst, _pvs, _proof)) => {
                self.stats.built += 1;
                self.stats.prove_secs += plan.prove_secs;
                DispenseOutcome::Ready { plan: Box::new(plan), request }
            }
            Err(reason) => {
                self.inventory.restore_pair(backup);
                self.stats.rejected += 1;
                match self.queue.retry(request) {
                    None => DispenseOutcome::Retrying { reason },
                    Some(request) => {
                        self.stats.abandoned += 1;
                        DispenseOutcome::Abandoned { request, reason }
                    }
                }
            }
        }
    }

    /// The chain accepted a grant: bank the change note and the counters.
    pub fn confirm(&mut self, plan: GrantPlan) {
        self.stats.confirmed += 1;
        self.stats.granted_bessel += plan.grant_value;
        self.stats.fees_bessel += plan.fee;
        // Held, not yet anchored: it becomes spendable only once a valid anchor's
        // prefix contains its leaf (see `Inventory::anchored`).
        self.inventory.insert(plan.change);
    }

    /// The chain (or the faucet's own pre-submit check) refused a grant: restore the
    /// inputs and give the requester another attempt.
    ///
    /// Returns `false` if the attempt budget is now spent, in which case the request
    /// is abandoned and counted — a rising `abandoned` means the **faucet** is
    /// broken, not the requesters.
    pub fn reject(&mut self, plan: GrantPlan, request: PendingRequest) -> bool {
        self.stats.rejected += 1;
        self.inventory.restore_pair(plan.spent);
        match self.queue.retry(request) {
            None => true,
            Some(_abandoned) => {
                self.stats.abandoned += 1;
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::TicketPolicy;
    use qlab_devnet::header::Hash32;
    use qlab_wallet::Wallet;
    use rand::SeedableRng;

    fn faucet(limits: FaucetLimits) -> Faucet {
        Faucet::new(
            Wallet::from_seed_lanes([0xF00D_F00D_F00D_F00D; 4]),
            Diversifier::default(),
            TicketSecret::from_bytes([0x11; 32]),
            FaucetConfig { limits, ..FaucetConfig::default() },
        )
    }

    fn user_address(i: u64) -> Address {
        Wallet::from_seed_lanes([0xAB00 + i; 4]).address(Diversifier::default())
    }

    #[test]
    fn the_default_grant_is_a_thousand_fees() {
        // The stated ground for the [devnet-placeholder] grant value.
        let fee = qlab_devnet::fees::posted_fee(qlab_devnet::fees::ArityBucket::TwoByTwo);
        assert_eq!(fee, 1_000_000, "frozen §5 2×2 posted price");
        assert_eq!(DEFAULT_GRANT_BESSEL, 1_000_000_000);
        assert_eq!(DEFAULT_GRANT_BESSEL / fee, 1_000, "a grant is 1,000 transactions of runway");
    }

    #[test]
    fn the_faucet_key_is_not_account_zero() {
        // The loss-bound decision, test-locked: sharing an account with the primary
        // wallet would turn a service compromise into a wallet compromise.
        assert_ne!(FaucetConfig::default().hd_account, 0);
    }

    #[test]
    fn a_full_queue_does_not_burn_a_ticket() {
        // Capacity is checked before the gate, so a capacity refusal costs the
        // requester nothing.
        let mut f = Faucet::new(
            Wallet::from_seed_lanes([1; 4]),
            Diversifier::default(),
            TicketSecret::from_bytes([2; 32]),
            FaucetConfig {
                queue_depth: 1,
                limits: FaucetLimits { subnet_burst: 100, ..FaucetLimits::default() },
                ..FaucetConfig::default()
            },
        );
        let t1 = f.issue_ticket(1);
        let t2 = f.issue_ticket(2);
        assert_eq!(f.accept("203.0.113.1", user_address(1), Some(t1), 0), Ok(1));
        let err = f.accept("203.0.113.1", user_address(2), Some(t2), 0).unwrap_err();
        assert_eq!(err, AcceptError::Queue(QueueError::Full { depth: 1 }));
        assert_eq!(f.gate_stats().tickets_spent, 1, "t2 was never presented to the gate");
        assert_eq!(f.stats().queue_full, 1);
    }

    #[test]
    fn a_gate_refusal_never_reaches_the_queue() {
        let mut f = faucet(FaucetLimits::default());
        let err = f.accept("203.0.113.1", user_address(1), None, 0).unwrap_err();
        assert_eq!(err, AcceptError::Refused(Refusal::TicketMissing));
        assert!(f.queue().is_empty());
        assert_eq!(f.stats().refused, 1);
        assert_eq!(f.stats().queued, 0);
    }

    #[test]
    fn dispense_is_idle_with_nothing_queued_and_stalls_without_an_anchor() {
        // A chain view with nothing finalized: no valid anchor, so a funded faucet
        // is still unspendable. That is the cold start, named rather than hidden.
        struct ColdChain(qlab_cbserver::tree::CommitmentTree);
        impl ChainView for ColdChain {
            fn tip_height(&self) -> u64 {
                0
            }
            fn finalized_height(&self) -> Option<u64> {
                None
            }
            fn is_valid_anchor(&self, _: &Hash32) -> bool {
                false
            }
            fn newest_anchor(&self) -> Option<Hash32> {
                None
            }
            fn tree(&self) -> &qlab_cbserver::tree::CommitmentTree {
                &self.0
            }
        }
        let view = ColdChain(qlab_cbserver::tree::CommitmentTree::new());
        let mut rng = rand::rngs::StdRng::from_seed([9u8; 32]);
        let mut f = faucet(FaucetLimits { ticket_policy: TicketPolicy::Disabled, ..FaucetLimits::default() });

        assert!(matches!(f.dispense(&view, &mut rng), DispenseOutcome::Idle));
        f.accept("203.0.113.1", user_address(1), None, 0).expect("accepted");
        assert!(matches!(
            f.dispense(&view, &mut rng),
            DispenseOutcome::Stalled(StallReason::NoValidAnchor)
        ));
        // The stall did not consume the request or an attempt.
        assert_eq!(f.queue().len(), 1);
        assert_eq!(f.queue().front().unwrap().attempts, 0);
        assert_eq!(f.stats().stalled, 1);
    }
}
