//! **Position 2: what a user sees when the faucet is empty.**
//!
//! "Empty" is not one state, it is five, and they call for different answers:
//!
//! | state | why | answer |
//! |---|---|---|
//! | [`Availability::Ready`] | an anchored note (or pair) covers the outlay | queue it |
//! | [`Availability::AwaitingFinality`] | notes held, none witnessable by the current anchor | queue it — it clears on the checkpoint cadence |
//! | [`Availability::Maturing`] | coinbase is inside the frozen §2 144-block gate, and nothing already funded in can pay yet | queue it **only** if it matures inside the wait the queue would quote; otherwise refuse, naming the height |
//! | [`Availability::Unharvested`] | no harvest pass has run, so this faucet has not looked at its own inventory | refuse — and say so; do NOT answer for the inventory |
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

/// Why the notes **already funded in** cannot pay, while coinbase is maturing.
///
/// Lab issue #539: [`Availability::Maturing`] is reached from two different
/// `select_inputs` failures, and until this type existed both rendered as one
/// sentence — "funded but not yet spendable … spendable once the chain reaches
/// height H". On the value branch that sentence named a height at which the held
/// notes still would not pay, and cited the maturity constant for a shortage that
/// was not about maturity. The reason is carried so the message can be true for
/// the branch it was actually reached from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shortage {
    /// Nothing the current anchor can witness — the notes exist but no finalized
    /// root contains them. Maturity is not what they are waiting on.
    NoWitness,
    /// Anchored notes exist and no legal input set reaches the outlay, so the
    /// shortage is value. The figures are `InventoryError::InsufficientValue`'s,
    /// in bessel, and the shortfall is `need - best_inputs`.
    Value { need: u64, best_inputs: u64 },
}

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
    /// Coinbase notes are outstanding but still inside the frozen §2 maturity delay
    /// — they have no commitment-tree leaf yet, so no witness and no provable spend
    /// (issue #102). `matures_at` is the height the earliest one's leaf lands at.
    ///
    /// The two counts are **not** summed (lab #539). `maturing` is the immature
    /// coinbase this node mined — the population `matures_at` is about. `held` is
    /// what is already funded in and still cannot pay, for the reason in
    /// `shortage`. Their sum was published as one `held` figure until 2026-08-20,
    /// which is how `faucet.qumbra.org` came to say "139 coinbase note(s) held"
    /// over a table reading "113 / 26": one number that was neither of them.
    Maturing { held: usize, maturing: usize, matures_at: u64, tip: u64, shortage: Shortage },
    /// The process is up and the listener is bound, but the node is still
    /// rebuilding its state from `blocks.log` — it has no chain view yet, so
    /// nothing here can be answered from it (lab #365).
    ///
    /// `replayed`/`total` are the live walk position from
    /// `qlab_node::replay_progress`; `total == 0` means a replay is known to be
    /// running but its size is not published yet.
    ///
    /// This is deliberately **not** [`Availability::ColdChain`]. "The chain has
    /// finalized nothing" is a claim about the chain; before the node opens, this
    /// faucet has not looked at the chain at all, and saying otherwise is the #296
    /// failure in a new place.
    Starting { replayed: u64, total: u64 },
    /// **No harvest pass has run since this process started**, so the faucet has
    /// not walked its own chain and cannot say what it holds or what is maturing
    /// (lab #543).
    ///
    /// Distinct from every state below it, and the distinction is the whole point:
    /// `Empty` means *looked, and there is nothing coming*. Before a pass there is
    /// no basis for the second half. `main.rs` used to render the first status
    /// snapshot between opening the node and the first tick, when `next_maturity`
    /// was still `None` and `maturing` still `0` — the values a pass reports for a
    /// faucet with no immature coinbase — so a faucet whose entire stock was inside
    /// the §2 maturity gate published *"out of funds … the only refill is a coinbase
    /// note"* to a live listener, and refused requests it would have queued one tick
    /// later.
    ///
    /// The first sample is a whole tick now, so this state is not reached in the
    /// binary as it stands. It is kept, named and refusing, because the way that
    /// defect happened was a caller rendering before harvesting — and the type is
    /// what stops the next one from spelling it as a zero.
    Unharvested,
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
            // Starting refuses for the same reason ColdChain does, and one more:
            // a grant needs a finalized anchor, and this faucet cannot even name
            // the chain yet. Queueing here would burn a ticket on a request it
            // has no basis to promise — the #310 shape.
            Availability::Starting { .. }
            | Availability::Unharvested
            | Availability::ColdChain
            | Availability::Empty { .. } => false,
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
            // A replay's remaining time is not a block count and not predictable
            // from here — it has been minutes and it has been five hours (#359).
            // `None` makes the caller quote its one-block-interval default rather
            // than this state inventing a completion time it cannot keep.
            Availability::Starting { .. }
            // One loop iteration, not a block count — and a state that publishes no
            // number is exactly the point of it.
            | Availability::Unharvested
            | Availability::ColdChain
            | Availability::Empty { .. } => None,
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
            Availability::Maturing { held, maturing, matures_at, tip, shortage } => {
                let blocks = matures_at.saturating_sub(*tip);
                // The `when`, which is the one thing a requester can act on, and it
                // is about the maturing coinbase only — never about `held`.
                let coming = format!(
                    "{maturing} coinbase note(s) mature at height {matures_at}; the chain is at \
                     {tip}, so {blocks} more block(s) (~{} min at the 75 s block time). New coin \
                     cannot be spent for {} blocks (FROZEN §2 COINBASE_MATURITY_BLOCKS).",
                    blocks * 75 / 60,
                    qlab_node::COINBASE_MATURITY_BLOCKS,
                );
                // Lab #539: what `held` is waiting on decides the first clause. The
                // value branch must not promise that these notes become spendable at
                // `matures_at` — they are not immature, they are too small.
                match shortage {
                    Shortage::Value { need, best_inputs } => format!(
                        "funded but short of a grant — the {held} note(s) already funded in reach \
                         only {best_inputs} bessel of the {need} bessel one grant costs, so what \
                         the wait buys is value, not those notes becoming spendable. {coming}"
                    ),
                    Shortage::NoWitness if *held == 0 => format!(
                        "not yet spendable — nothing is funded in yet, so a grant waits on that \
                         coinbase. {coming}"
                    ),
                    Shortage::NoWitness => format!(
                        "funded but not yet spendable — the {held} note(s) already funded in are \
                         not witnessable by the current anchor, so none of them can pay now; a \
                         note becomes witnessable when the block holding it finalizes (every {} \
                         blocks). {coming}",
                        qlab_devnet::params_devnet::CHECKPOINT_CADENCE_BLOCKS
                    ),
                }
            }
            Availability::Starting { replayed, total } => {
                let progress = if *total == 0 {
                    "reading its log".to_string()
                } else {
                    format!(
                        "{replayed} of {total} records ({}%)",
                        replayed.saturating_mul(100) / total
                    )
                };
                format!(
                    "starting — this faucet's node is rebuilding its state from disk, {progress}. \
                     It replays every record it has after a restart, which takes minutes to hours \
                     depending on how recent its last snapshot is. Nothing is wrong and nothing is \
                     lost; requests are refused rather than queued until it can bind a grant to a \
                     finalized anchor."
                )
            }
            Availability::Unharvested => "not answering yet — this faucet has not walked \
                 its own chain since it started, so it cannot say what it holds or what is \
                 maturing. It refuses rather than reporting an inventory it has not read; the \
                 next loop pass settles it."
                .to_string(),
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
    ///
    /// `None` until the node has been opened and sampled once (lab #365). It was
    /// `StateLag::default()` — two zeroes — which renders as `applied height 0 /
    /// chain tip 0 / behind by 0`, i.e. a **funded-and-current-looking** page for a
    /// faucet that has not yet read a single block. #296 is the standing rule that
    /// this page does not publish numbers it has not got; an `Option` is how that
    /// rule is made unrepresentable to break.
    pub chain: Option<qlab_node::StateLag>,
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
    ///
    /// `None` until a harvest pass has produced the number (lab #543) — the #365
    /// rule applied to the one figure that still published an unmeasured zero. It
    /// renders as `UNAVAILABLE`, because `0` here reads as *nothing is coming* and
    /// that is a claim no pass has made yet.
    pub notes_maturing: Option<usize>,
}

/// Classify what the faucet can do right now.
///
/// `harvest` is what the last pass over this node's own main chain found about
/// coinbase that has not landed yet — the maturing count and the height the
/// earliest of them becomes spendable at (`minted + 144`, issue #102). It is passed
/// in rather than derived here because only a caller walking its own node's chain
/// knows which blocks this faucet mined and at what heights.
///
/// 🔴 **`None` means no pass has run, and it is not the same as a pass that found
/// nothing** (lab #543). Answering the inventory question without having looked is
/// how the page came to publish `Empty` — *"none coming"* — for a faucet whose whole
/// stock was maturing.
pub fn classify<V: qlab_faucet::ChainView>(
    faucet: &Faucet,
    view: &V,
    harvest: Option<crate::harvest::HarvestFacts>,
) -> Availability {
    let Some(harvest) = harvest else {
        return Availability::Unharvested;
    };
    let (next_maturity, maturing_count) = (harvest.next_maturity, harvest.maturing);
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
                Availability::Maturing {
                    held,
                    maturing: maturing_count,
                    matures_at,
                    tip,
                    shortage: Shortage::NoWitness,
                }
            } else if held >= 1 {
                Availability::AwaitingFinality { held, anchored }
            } else {
                Availability::Empty { held }
            }
        }
        // Anchored notes exist, but no legal input set covers the outlay. On this
        // chain that is a *value* shortage, and the only refill is coinbase — the
        // same remedy as an empty inventory, so it is not a fifth state a requester
        // could act on differently. It is carried into `Maturing` as its own
        // `Shortage` (lab #539) because the *sentence* differs even where the
        // remedy does not: maturing coinbase is when more value arrives, not when
        // these notes become spendable.
        Err(InventoryError::InsufficientValue { need, best_inputs }) => {
            match next_maturity.filter(|m| *m > tip) {
                Some(matures_at) => Availability::Maturing {
                    held,
                    maturing: maturing_count,
                    matures_at,
                    tip,
                    shortage: Shortage::Value { need, best_inputs },
                },
                None => Availability::Empty { held },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A witness-shortage `Maturing`, the state the tests below are about.
    fn maturing(held: usize, matures_at: u64, tip: u64) -> Availability {
        Availability::Maturing {
            held,
            maturing: 1,
            matures_at,
            tip,
            shortage: Shortage::NoWitness,
        }
    }

    /// 🔴 **Lab #539: the two populations are counted separately, and only the
    /// maturing one is promised at `matures_at`.** The live page said "139 coinbase
    /// note(s) held, spendable once the chain reaches height 472" over a table
    /// reading 113 held / 26 maturing — the banner's figure was their sum, so it
    /// matched neither surface and promised a height for notes that were not
    /// waiting on one.
    #[test]
    fn the_banner_counts_the_maturing_coinbase_and_the_held_notes_apart() {
        let live = Availability::Maturing {
            held: 113,
            maturing: 26,
            matures_at: 472,
            tip: 470,
            shortage: Shortage::NoWitness,
        };
        let text = live.explain();
        assert!(text.contains("26 coinbase note(s) mature at height 472"), "{text}");
        assert!(text.contains("113 note(s) already funded in"), "{text}");
        assert!(!text.contains("139"), "the sum of two populations is not a count: {text}");
    }

    /// 🔴 **A value shortage never promises that the held notes become spendable.**
    /// It is reached from `InsufficientValue`, where the held notes are anchored and
    /// mature and simply too small — so the maturity height is when *more value*
    /// arrives, and the sentence has to say that and not the other thing.
    #[test]
    fn a_value_shortage_names_the_shortfall_rather_than_promising_maturity() {
        let short = Availability::Maturing {
            held: 4,
            maturing: 1,
            matures_at: 200,
            tip: 190,
            shortage: Shortage::Value { need: 100_000_000, best_inputs: 250 },
        };
        let text = short.explain();
        assert!(text.contains("250 bessel of the 100000000 bessel"), "{text}");
        assert!(text.contains("not those notes becoming spendable"), "{text}");
        // The `when` survives — it is still the one actionable thing on the page.
        assert!(text.contains("mature at height 200"), "{text}");
        // …and the state is still self-clearing inside the advertised wait, because
        // the remedy is the same one: coinbase.
        assert!(short.admits_requests(), "10 blocks is inside the advertised wait");
    }

    /// The queue-only-what-you-can-serve rule, at the boundary. 32 blocks is
    /// advertised; 33 is refused.
    #[test]
    fn maturity_inside_the_advertised_wait_is_queued_and_beyond_it_is_refused() {
        let inside = maturing(2, 132, 100);
        assert_eq!(inside.blocks_until_servable(), Some(32));
        assert!(inside.admits_requests(), "32 blocks is exactly the wait the queue quotes");

        let beyond = maturing(2, 133, 100);
        assert_eq!(beyond.blocks_until_servable(), Some(33));
        assert!(!beyond.admits_requests(), "33 blocks is longer than the faucet will promise");
        // …and the refusal is actionable: it names the height and the interval.
        let text = beyond.explain();
        assert!(text.contains("mature at height 133"), "{text}");
        assert!(text.contains("41 min"), "{text}");
        assert!(text.contains("144"), "the frozen constant is named: {text}");
    }

    /// Lab #365: the state a request meets while the node is replaying. It refuses,
    /// it says the percentage, and it never promises a completion time it cannot
    /// keep — a replay has been 2.5 hours and it has been five (#359).
    #[test]
    fn starting_refuses_and_reports_the_walk_rather_than_a_deadline() {
        let mid = Availability::Starting { replayed: 1_644, total: 3_287 };
        assert!(!mid.admits_requests(), "a replaying faucet must not queue a request");
        assert_eq!(
            mid.blocks_until_servable(),
            None,
            "a replay's remaining time is not a block count and must not be guessed"
        );
        let text = mid.explain();
        assert!(text.contains("1644 of 3287 records (50%)"), "{text}");
        assert!(text.contains("rebuilding its state from disk"), "{text}");
        // …and the honest degradation when the walk's size is not published yet.
        let early = Availability::Starting { replayed: 0, total: 0 };
        assert!(early.explain().contains("reading its log"), "{}", early.explain());
        assert!(!early.explain().contains("(0%)"), "no fabricated percentage: {}", early.explain());

        // It is NOT ColdChain, and the difference is the point: ColdChain is a
        // claim about the chain, which a faucet that has not opened its node
        // cannot make (#296).
        assert_ne!(mid.explain(), Availability::ColdChain.explain());
        assert!(!mid.explain().contains("finalized nothing"), "{text}");
    }

    /// The two states that refuse outright, and the two that queue.
    #[test]
    fn only_the_self_clearing_states_accept_requests() {
        assert!(Availability::Ready { grants: 1 }.admits_requests());
        assert!(Availability::AwaitingFinality { held: 3, anchored: 1 }.admits_requests());
        assert!(!Availability::ColdChain.admits_requests());
        // Lab #543: a faucet that has not read its own inventory promises nothing.
        assert!(!Availability::Unharvested.admits_requests());
        assert_eq!(Availability::Unharvested.blocks_until_servable(), None);
        assert!(!Availability::Empty { held: 1 }.admits_requests());
    }

    /// Every state explains itself in terms a requester can act on. A state whose
    /// explanation is empty is a state that renders as a blank page.
    #[test]
    fn every_state_explains_itself() {
        for a in [
            Availability::Ready { grants: 0 },
            Availability::AwaitingFinality { held: 2, anchored: 1 },
            maturing(1, 145, 1),
            maturing(0, 145, 1),
            Availability::Maturing {
                held: 3,
                maturing: 1,
                matures_at: 145,
                tip: 1,
                shortage: Shortage::Value { need: 1_000_000_000, best_inputs: 4_200 },
            },
            Availability::Starting { replayed: 1, total: 2 },
            Availability::Starting { replayed: 0, total: 0 },
            Availability::Unharvested,
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
