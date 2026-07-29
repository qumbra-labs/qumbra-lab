//! The admitted-request queue — bounded, FIFO, and honest about the wait.
//!
//! A faucet on this chain serves at most **one grant per 75 s block** (the
//! note-inflow law in [`crate::inventory`]) and each grant costs a measured 2.28 s
//! of proving. Those two rates are ~33× apart, which makes the queue depth a
//! statement about which of them the operator is promising:
//!
//! | regime | per-grant cost | 32-deep tail wait |
//! |---|---|---|
//! | note-rich (a funded buffer) | 2.28 s of proving | 73 s ≈ one block interval |
//! | note-starved (steady state) | one coinbase note | 32 blocks ≈ 40 min |
//!
//! [`MAX_QUEUE_DEPTH`] is set from the note-rich figure, and
//! [`RequestQueue::estimated_wait_blocks`] reports the *starved* figure, so the
//! number the requester sees is the one that is true when the faucet is poor rather
//! than the one that flatters it when it is rich.
//!
//! **Full means refuse, not evict.** Dropping the oldest entry would punish the
//! requester who waited longest and let a burst evict the honest arrivals in front
//! of it — turning a queue into a lottery whose odds improve with request volume,
//! which is exactly the property an abuse gate exists to remove.

use std::collections::VecDeque;

use qlab_wallet::address::Address;

/// Requests held at once. `[devnet-placeholder]` testnet-tunable, NOT frozen.
///
/// **Derived from the measurement**: 75 s (the frozen block interval) ÷ 2.28 s (the
/// measured grant-proof mean) = 32.9 grants, rounded down to 32 — one block interval
/// of proof-bound backlog, which is the point past which a queue advertises a wait
/// it will not honour. See the module docs for the note-starved reading of the same
/// number, which is 40 minutes and is the one a requester is quoted.
pub const MAX_QUEUE_DEPTH: usize = 32;

/// Attempts one admitted request gets before the faucet gives up on it.
/// `[devnet-placeholder]`.
///
/// A retry exists because a *faucet-side* failure (an anchor that aged out under a
/// slow block, a rejected submission) must not cost the requester their ticket —
/// they did nothing wrong. Three is enough to cross one anchor-refresh boundary
/// without turning a systematically broken faucet into an infinite prover loop.
pub const MAX_ATTEMPTS: u32 = 3;

/// One admitted request awaiting service. Admission has already happened — a
/// `PendingRequest` exists only because [`crate::AbuseGate`] said yes.
#[derive(Clone)]
pub struct PendingRequest {
    /// The requester's address as the transport saw it. Kept for ops/logging only;
    /// the gate has already made its decision.
    pub client: String,
    /// Where the grant goes.
    pub recipient: Address,
    /// The ticket serial that bought this slot, if tickets are enabled. Carried so
    /// a give-up can be reported against the serial the operator issued.
    pub ticket_id: Option<u64>,
    /// Wall-clock milliseconds at admission (the queue's own ordering is FIFO; this
    /// is for reporting the realised wait).
    pub admitted_ms: u64,
    /// How many times the faucet has tried to serve this request.
    pub attempts: u32,
}

impl std::fmt::Debug for PendingRequest {
    /// Hand-written so the recipient address is **truncated**. A full address in a
    /// log is a standing record of who asked for funds, which is not something a
    /// privacy chain's own faucet should leave in an operator's log rotation.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let a = self.recipient.encode();
        let shown: String = a.chars().take(16).collect();
        f.debug_struct("PendingRequest")
            .field("client", &self.client)
            .field("recipient", &format!("{shown}…"))
            .field("ticket_id", &self.ticket_id)
            .field("admitted_ms", &self.admitted_ms)
            .field("attempts", &self.attempts)
            .finish()
    }
}

/// Why a request could not be queued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueError {
    /// The queue is at [`MAX_QUEUE_DEPTH`]. Refuse; do not evict (module docs).
    Full { depth: usize },
}

impl std::fmt::Display for QueueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueueError::Full { depth } => {
                write!(f, "faucet queue full ({depth} waiting); try later")
            }
        }
    }
}

impl std::error::Error for QueueError {}

/// A bounded FIFO of admitted requests.
#[derive(Clone, Debug)]
pub struct RequestQueue {
    q: VecDeque<PendingRequest>,
    cap: usize,
    /// Requests abandoned after [`MAX_ATTEMPTS`] — a counter an operator must be
    /// able to see, because a rising one means the *faucet* is broken, not the
    /// requesters.
    given_up: u64,
}

impl Default for RequestQueue {
    fn default() -> Self {
        RequestQueue::new(MAX_QUEUE_DEPTH)
    }
}

impl RequestQueue {
    /// A queue holding at most `cap` requests.
    pub fn new(cap: usize) -> RequestQueue {
        RequestQueue { q: VecDeque::new(), cap: cap.max(1), given_up: 0 }
    }

    /// Requests waiting.
    pub fn len(&self) -> usize {
        self.q.len()
    }

    /// Whether nothing is waiting.
    pub fn is_empty(&self) -> bool {
        self.q.is_empty()
    }

    /// The configured depth cap.
    pub fn capacity(&self) -> usize {
        self.cap
    }

    /// Requests abandoned after exhausting [`MAX_ATTEMPTS`].
    pub fn given_up(&self) -> u64 {
        self.given_up
    }

    /// Enqueue an admitted request, or refuse because the queue is full.
    pub fn push(&mut self, req: PendingRequest) -> Result<usize, QueueError> {
        if self.q.len() >= self.cap {
            return Err(QueueError::Full { depth: self.q.len() });
        }
        self.q.push_back(req);
        Ok(self.q.len())
    }

    /// Take the next request to serve (FIFO).
    pub fn pop(&mut self) -> Option<PendingRequest> {
        self.q.pop_front()
    }

    /// Return a request to the **front** after a faucet-side failure, incrementing
    /// its attempt count. `None` means requeued; `Some(req)` hands the request back
    /// because its attempt budget is spent (and counts it in [`Self::given_up`]).
    ///
    /// Front, not back: the requester has already waited, and a faucet-side failure
    /// is not their fault. Sending them to the back would let a broken faucet
    /// starve its earliest arrivals indefinitely.
    pub fn retry(&mut self, mut req: PendingRequest) -> Option<PendingRequest> {
        req.attempts += 1;
        if req.attempts >= MAX_ATTEMPTS {
            self.given_up += 1;
            return Some(req);
        }
        self.q.push_front(req);
        None
    }

    /// Peek at the head without removing it.
    pub fn front(&self) -> Option<&PendingRequest> {
        self.q.front()
    }

    /// Blocks a request queued *now* would wait for in the **note-starved** regime
    /// — one grant per block, the sustainable rate. This is the pessimistic figure
    /// and it is the one to show a requester: the optimistic one (proof-bound, a
    /// measured 2.28 s each) is only true while a funded note buffer lasts.
    pub fn estimated_wait_blocks(&self) -> usize {
        self.q.len() + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_wallet::address::Diversifier;
    use qlab_wallet::Wallet;

    fn addr(i: u64) -> Address {
        Wallet::from_seed_lanes([i; 4]).address(Diversifier::default())
    }

    fn req(i: u64) -> PendingRequest {
        PendingRequest {
            client: format!("203.0.113.{i}"),
            recipient: addr(i + 1),
            ticket_id: Some(i),
            admitted_ms: i * 1_000,
            attempts: 0,
        }
    }

    #[test]
    fn the_queue_is_fifo() {
        let mut q = RequestQueue::new(8);
        for i in 0..3 {
            q.push(req(i)).expect("room");
        }
        assert_eq!(q.len(), 3);
        assert_eq!(q.pop().unwrap().ticket_id, Some(0));
        assert_eq!(q.pop().unwrap().ticket_id, Some(1));
        assert_eq!(q.pop().unwrap().ticket_id, Some(2));
        assert!(q.pop().is_none());
    }

    #[test]
    fn a_full_queue_refuses_rather_than_evicting() {
        // The property: the requester who waited longest keeps their place.
        let mut q = RequestQueue::new(2);
        q.push(req(0)).unwrap();
        q.push(req(1)).unwrap();
        assert_eq!(q.push(req(2)), Err(QueueError::Full { depth: 2 }));
        assert_eq!(q.front().unwrap().ticket_id, Some(0), "the earliest arrival is still first");
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn a_retry_goes_to_the_front_and_gives_up_after_the_budget() {
        let mut q = RequestQueue::new(8);
        q.push(req(0)).unwrap();
        q.push(req(1)).unwrap();
        let first = q.pop().unwrap();
        assert!(q.retry(first).is_none(), "attempt 1 -> requeued");
        assert_eq!(q.front().unwrap().ticket_id, Some(0), "requeued at the front, not the back");

        let again = q.pop().unwrap();
        assert_eq!(again.attempts, 1);
        assert!(q.retry(again).is_none(), "attempt 2 -> requeued");
        let last = q.pop().unwrap();
        assert_eq!(last.attempts, 2);
        let handed_back = q.retry(last).expect("attempt 3 exhausts the budget");
        assert_eq!(handed_back.attempts, MAX_ATTEMPTS, "the abandoned request carries its count");
        assert_eq!(q.given_up(), 1);
        // The other request is untouched by the give-up.
        assert_eq!(q.len(), 1);
        assert_eq!(q.pop().unwrap().ticket_id, Some(1));
    }

    #[test]
    fn the_estimated_wait_is_the_pessimistic_one() {
        // A requester is quoted the note-starved rate (one grant per block), not
        // the proof-bound rate that only holds while a buffer lasts.
        let mut q = RequestQueue::new(MAX_QUEUE_DEPTH);
        assert_eq!(q.estimated_wait_blocks(), 1, "an empty queue still costs a block");
        for i in 0..9 {
            q.push(req(i)).unwrap();
        }
        assert_eq!(q.estimated_wait_blocks(), 10);
    }

    #[test]
    fn the_default_depth_is_the_documented_one() {
        let q = RequestQueue::default();
        assert_eq!(q.capacity(), MAX_QUEUE_DEPTH);
        // 75 s block interval / 2.28 s measured grant proof = 32.9, floored.
        assert_eq!(MAX_QUEUE_DEPTH, 32);
        assert_eq!(MAX_ATTEMPTS, 3);
    }
}
