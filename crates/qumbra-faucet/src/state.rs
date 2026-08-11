//! **Position 2: what a user sees when the faucet is empty.**
//!
//! "Empty" is not one state, it is five, and they call for different answers:
//!
//! | state | why | answer |
//! |---|---|---|
//! | [`Availability::Ready`] | an anchored note (or pair) covers the outlay | queue it |
//! | [`Availability::AwaitingFinality`] | notes held, none witnessable by the current anchor | queue it — it clears on the checkpoint cadence |
//! | [`Availability::Maturing`] | coinbase notes held, still inside the frozen §2 144-block gate | queue it **only** if it matures inside the wait the queue would quote; otherwise refuse, naming the height |
//! | [`Availability::ColdChain`] | nothing finalized, so no valid anchor exists | refuse |
//! | [`Availability::Empty`] | nothing held that covers the outlay, and none coming | refuse |
//!
//! The first two rows read `<2` / `≥2` anchored notes until 2026-08-11: a grant
//! took two real notes, so one anchored note was an unservable faucet. Issue #292's
//! fallback makes a single anchored note spendable (`qlab_faucet::Inventory::
//! select_inputs`), which moves the boundary and turns the tail of the inventory
//! from a count question into a value one.
//!
//! **The rule, stated once: queue only what can be served inside the wait the queue
//! quotes.** `RequestQueue::estimated_wait_blocks` quotes the note-starved rate —
//! one grant per block — and the queue's own depth cap of 32 is derived from one
//! block interval of proof-bound backlog. So 32 blocks (40 min at the frozen 75 s)
//! is the longest wait this faucet is willing to *advertise*, and anything longer
//! than that is not a queue slot, it is a promise it has no basis for. A request
//! that cannot be served inside it is refused with the height at which the answer
//! changes, which is the one thing a requester can act on.
//!
//! **A refusal here burns no ticket.** These checks run *before*
//! `Faucet::accept`, and `accept` is where the gate spends the single-use ticket.
//! That ordering is deliberate and it is the same reasoning the core already uses to
//! check queue capacity before the gate: the faucet's own shortage is not the
//! requester's fault, so it must not cost them their one admission.

use qlab_faucet::{Faucet, InventoryError, MAX_QUEUE_DEPTH};

/// The longest wait this faucet will advertise, in blocks — the queue's own depth
/// cap, for the reason in the module docs. At the FROZEN 75 s block time that is
/// 40 minutes.
pub const MAX_ADVERTISED_WAIT_BLOCKS: u64 = MAX_QUEUE_DEPTH as u64;

/// Whether the faucet can serve a request, and if not, why and when that changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Availability {
    /// Servable now. `grants` is the value budget, `⌊total value / (grant + fee)⌋`
    /// — an upper bound, see `Inventory::grants_available`. It was the note-count
    /// budget (`held − 1`) until the #292 fallback made that number wrong.
    Ready { grants: usize },
    /// Notes are held but the current anchor's prefix cannot witness any of them —
    /// the change note of a recent grant is in a block that is mined but not yet
    /// finalized. Self-clearing on the checkpoint cadence.
    AwaitingFinality { held: usize, anchored: usize },
    /// Coinbase notes are held but still inside the frozen §2 maturity delay — they
    /// have no commitment-tree leaf yet, so no witness and no provable spend
    /// (issue #102). `matures_at` is the height the earliest one's leaf lands at.
    Maturing { held: usize, matures_at: u64, tip: u64 },
    /// Nothing is finalized, so there is no valid anchor and no proof can be bound.
    /// On a fresh net this is the cold start; the faucet may be fully funded.
    ColdChain,
    /// No note the anchor can witness covers the outlay, and nothing is maturing —
    /// either nothing is held at all, or what is held is too small. Only coinbase
    /// refills it.
    Empty { held: usize },
}

impl Availability {
    /// Whether a request should be **queued**. See the module docs for the rule.
    pub fn admits_requests(&self) -> bool {
        match self {
            Availability::Ready { .. } | Availability::AwaitingFinality { .. } => true,
            Availability::Maturing { matures_at, tip, .. } => {
                matures_at.saturating_sub(*tip) <= MAX_ADVERTISED_WAIT_BLOCKS
            }
            Availability::ColdChain | Availability::Empty { .. } => false,
        }
    }

    /// The blocks a requester must wait before the faucet's state changes, when
    /// that is knowable. `None` for the states where nothing is pending at all.
    pub fn blocks_until_servable(&self) -> Option<u64> {
        match self {
            Availability::Ready { .. } => Some(0),
            // A checkpoint closes on the cadence grid; the honest statement is
            // "within one cadence", not a specific block.
            Availability::AwaitingFinality { .. } => {
                Some(qlab_devnet::params_devnet::CHECKPOINT_CADENCE_BLOCKS)
            }
            Availability::Maturing { matures_at, tip, .. } => Some(matures_at.saturating_sub(*tip)),
            Availability::ColdChain | Availability::Empty { .. } => None,
        }
    }

    /// One sentence for a requester — the state, and the height or interval at which
    /// it changes. This is what the page and the refusal body both say, so a
    /// requester and an operator never read two different explanations.
    pub fn explain(&self) -> String {
        match self {
            Availability::Ready { grants } => format!(
                "ready — {grants} grant{} of value available",
                if *grants == 1 { "" } else { "s" }
            ),
            Availability::AwaitingFinality { held, anchored } => format!(
                "waiting for finality — {held} notes held, {anchored} witnessable by the current \
                 anchor. A transaction needs 1, and a note becomes witnessable when the block \
                 holding it finalizes (every {} blocks).",
                qlab_devnet::params_devnet::CHECKPOINT_CADENCE_BLOCKS
            ),
            Availability::Maturing { held, matures_at, tip } => {
                let blocks = matures_at.saturating_sub(*tip);
                format!(
                    "funded but not yet spendable — {held} coinbase note(s) held, spendable once \
                     the chain reaches height {matures_at}; it is at {tip}, so {blocks} more \
                     block(s) (~{} min at the 75 s block time). New coin cannot be spent for \
                     {} blocks (FROZEN §2 COINBASE_MATURITY_BLOCKS).",
                    blocks * 75 / 60,
                    qlab_node::COINBASE_MATURITY_BLOCKS,
                )
            }
            Availability::ColdChain => "the chain has finalized nothing yet, so no transaction \
                 anchor exists. The faucet may be funded and still unable to pay — a grant proof \
                 must be bound to a finalized commitment root."
                .to_string(),
            Availability::Empty { held } => format!(
                "out of funds — {held} note(s) held, none of them able to cover a grant plus its \
                 fee. A grant may be built from a single note, so this is a value shortage and \
                 not a count one, and the only refill is a coinbase note from a block this \
                 faucet's node wins."
            ),
        }
    }
}

/// Everything the page and the JSON view render, sampled from the faucet and its
/// node on the run loop's own cadence — the same snapshot discipline
/// `qumbra-node`'s `/metrics` and `/v1/telemetry` use, and for the same reason: the
/// service decides how often it pays, and a request costs a clone rather than a lock
/// on live state.
#[derive(Clone, Debug)]
pub struct ServiceStatus {
    /// **This node's two chain views, from the tree's one definition of the pair**
    /// (`qlab_node::StateLag`) rather than two fields the page could difference
    /// itself: `state_tip` is the height whose body this faucet has *applied*, and
    /// `fork_choice_tip` is the height whose header the chain it follows has
    /// reached.
    ///
    /// Both, and not just the first, because of lab issue #296. The page used to
    /// carry `state_tip` alone under the label `chain tip`, and on 2026-08-08
    /// `faucet.qumbra.org` published `chain tip 1930` while `explorer.qumbra.org`
    /// published 4116 for the same chain — two Qumbra surfaces disagreeing by two
    /// thousand blocks with nothing on either page explaining why. The explorer
    /// renders `Telemetry::tip_height`, which `qlab_node::telemetry` documents as
    /// fork choice; this faucet reads its own applied state, because that is the
    /// state a grant proof binds to. Neither was wrong. Only one of them was shown.
    ///
    /// `state_tip` stays the number every serving decision is made on — see
    /// [`classify`], which asks the [`qlab_faucet::ChainView`] directly and never
    /// reads this field.
    pub chain: qlab_node::StateLag,
    /// The finalized height of the **applied** view. `None` = nothing finalized.
    ///
    /// Left exactly as it was, deliberately: on a faucet whose applied state has
    /// not yet reached a finalized checkpoint, `nothing finalized yet` is true and
    /// the 503 it produces is OPERATOR §9.1's design working (issue #296's own
    /// 'Not a defect' section).
    pub finalized_height: Option<u64>,
    /// Peers the in-process node is connected to. Not chain state — service state:
    /// a faucet with zero peers is a faucet on its own fork, and that is the one
    /// fact that makes an otherwise-inexplicable stall legible.
    pub peers: u64,
    /// Whether the faucet can serve, and if not, why.
    pub availability: Availability,
    /// Requests waiting.
    pub queued: usize,
    /// The queue's depth cap.
    pub queue_capacity: usize,
    /// Blocks a request queued now would wait, at the note-starved rate the core
    /// quotes (`RequestQueue::estimated_wait_blocks`).
    pub wait_blocks: usize,
    /// Grant value in bessel.
    pub grant_value: u64,
    /// Whether an operator-issued ticket is required.
    pub tickets_required: bool,
    /// Confirmed grants this process has made.
    pub confirmed: u64,
    /// Requests refused by the gate.
    pub refused: u64,
    /// Notes held (anchored or not).
    pub notes_held: usize,
    /// Coinbase notes this node mined that are not yet mature, so not yet funded in.
    pub notes_maturing: usize,
}

/// Classify what the faucet can do right now.
///
/// `next_maturity` is the height at which the earliest **immature** coinbase note
/// this node mined becomes spendable, if any is outstanding — i.e. the height its
/// leaf is appended at (`minted + 144`, issue #102). It is passed in rather than
/// derived here because only a caller walking its own node's main chain knows which
/// blocks this faucet mined and at what heights.
pub fn classify<V: qlab_faucet::ChainView>(
    faucet: &Faucet,
    view: &V,
    next_maturity: Option<u64>,
    maturing_count: usize,
) -> Availability {
    let tip = view.tip_height();
    let held = faucet.inventory().len();

    // A pending maturity is reported even when the inventory could serve — no:
    // being servable wins, because it is what the requester asked about. Maturity
    // only becomes the answer when the faucet cannot pay.
    let Some(anchor) = view.newest_anchor() else {
        return Availability::ColdChain;
    };
    let Some(leaf_count) = view.anchor_leaf_count(&anchor) else {
        // The anchor is valid but its prefix is not resolvable against the live
        // tree — treat it as the cold start rather than inventing a leaf count,
        // which would cut witnesses that fold to the wrong root.
        return Availability::ColdChain;
    };

    // One definition of the outlay, on the faucet itself — selection, the budget
    // figure and this classification all have to be asking the same question.
    let need = faucet.need();
    match faucet.inventory().select_inputs(need, view.tree(), leaf_count) {
        Ok(_) => Availability::Ready { grants: faucet.inventory().grants_available(need) },
        Err(InventoryError::OutOfNotes { held, anchored }) => {
            if anchored >= 1 {
                // Unreachable in practice (`select_inputs` only returns OutOfNotes
                // with anchored == 0 since the #292 fallback), but classifying it
                // as a value shortage rather than a witness shortage would be a lie
                // if it ever were reachable.
                Availability::AwaitingFinality { held, anchored }
            } else if let Some(matures_at) = next_maturity.filter(|m| *m > tip) {
                Availability::Maturing { held: held + maturing_count, matures_at, tip }
            } else if held >= 1 {
                Availability::AwaitingFinality { held, anchored }
            } else {
                Availability::Empty { held }
            }
        }
        // Anchored notes exist, but no legal input set covers the outlay. On this
        // chain that is a *value* shortage, and the only refill is coinbase — the
        // same remedy as an empty inventory, so it is reported as one rather than as
        // a fifth state a requester cannot act on differently.
        Err(InventoryError::InsufficientValue { .. }) => match next_maturity.filter(|m| *m > tip) {
            Some(matures_at) => {
                Availability::Maturing { held: held + maturing_count, matures_at, tip }
            }
            None => Availability::Empty { held },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The queue-only-what-you-can-serve rule, at the boundary. 32 blocks is
    /// advertised; 33 is refused.
    #[test]
    fn maturity_inside_the_advertised_wait_is_queued_and_beyond_it_is_refused() {
        let inside = Availability::Maturing { held: 2, matures_at: 132, tip: 100 };
        assert_eq!(inside.blocks_until_servable(), Some(32));
        assert!(inside.admits_requests(), "32 blocks is exactly the wait the queue quotes");

        let beyond = Availability::Maturing { held: 2, matures_at: 133, tip: 100 };
        assert_eq!(beyond.blocks_until_servable(), Some(33));
        assert!(!beyond.admits_requests(), "33 blocks is longer than the faucet will promise");
        // …and the refusal is actionable: it names the height and the interval.
        let text = beyond.explain();
        assert!(text.contains("reaches height 133"), "{text}");
        assert!(text.contains("41 min"), "{text}");
        assert!(text.contains("144"), "the frozen constant is named: {text}");
    }

    /// The two states that refuse outright, and the two that queue.
    #[test]
    fn only_the_self_clearing_states_accept_requests() {
        assert!(Availability::Ready { grants: 1 }.admits_requests());
        assert!(Availability::AwaitingFinality { held: 3, anchored: 1 }.admits_requests());
        assert!(!Availability::ColdChain.admits_requests());
        assert!(!Availability::Empty { held: 1 }.admits_requests());
    }

    /// Every state explains itself in terms a requester can act on. A state whose
    /// explanation is empty is a state that renders as a blank page.
    #[test]
    fn every_state_explains_itself() {
        for a in [
            Availability::Ready { grants: 0 },
            Availability::AwaitingFinality { held: 2, anchored: 1 },
            Availability::Maturing { held: 1, matures_at: 145, tip: 1 },
            Availability::ColdChain,
            Availability::Empty { held: 0 },
        ] {
            let text = a.explain();
            assert!(text.len() > 30, "{a:?} explains itself thinly: {text}");
        }
        // The law is stated where it matters, because a requester looking at a
        // faucet holding notes that will not pay assumes the opposite. Since lab
        // #292 that law is about value: one note can fund a grant, so a held note
        // that cannot pay is too small, not too lonely.
        let empty = Availability::Empty { held: 1 }.explain();
        assert!(empty.contains("value shortage and not a count one"), "{empty}");
    }

    /// The advertised wait is the queue's own cap, not a second number that could
    /// drift from it.
    #[test]
    fn the_advertised_wait_is_the_queue_depth() {
        assert_eq!(MAX_ADVERTISED_WAIT_BLOCKS, MAX_QUEUE_DEPTH as u64);
        assert_eq!(MAX_ADVERTISED_WAIT_BLOCKS, 32);
        assert_eq!(MAX_ADVERTISED_WAIT_BLOCKS * 75 / 60, 40, "40 minutes at the frozen 75 s");
    }
}
