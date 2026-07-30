//! **Round-level committee diagnostics** (issue #87).
//!
//! The 42 h T0 WAN soak measured 14.5–15.9 % of samples in `Degraded` and a stall
//! peak of 42 blocks against a threshold of 16 — and the four nodes produced *ten*
//! non-telemetry log lines in 42 hours, all at startup. Every one of those stalls is
//! a checkpoint round that did not reach quorum, and the node said nothing about any
//! of them: no round number, no vote count, no timeout, no absentee list. The stall
//! gauge climbed from 8 to 40 and came back down, and the middle was a black box.
//!
//! This module is that black box opened. It keeps one [`RoundRecord`] per checkpoint
//! slot — **whether or not the round succeeds** — and closes it with the facts an
//! operator needs to answer *why this round did not finalize*:
//!
//! | field | answers |
//! |---|---|
//! | `have` / `need` / `active` / `roster` | was the quorum reachable at all? |
//! | `voted` / `absent` / `excluded` | who was missing, and who was excluded by rule |
//! | `first_ms` / `last_ms` / `closed_ms` | were votes still arriving when it ended? |
//! | `quorum_ms` | how long the round took when it *did* work |
//! | `rej` | were votes arriving and being thrown away (forged/unknown/dup)? |
//! | `variants` | is the committee split across conflicting checkpoints? |
//!
//! [`RoundRecord::diagnose`] turns those into a single named verdict, and the
//! discriminant that matters — **timeout vs. votes-short** — is decided by
//! `closed_ms − last_ms` against [`STILL_ARRIVING_MS`]: a round whose last *new*
//! vote landed just before it was cut off was still accumulating (timeout); a round
//! whose votes stopped minutes earlier had all the votes it was ever going to get
//! (votes short). See [`RoundDiagnosis`] for the full ladder.
//!
//! ## Caliper (口径), stated with the numbers rather than after them
//! * Timings are **wall-clock milliseconds at the observing node**, measured from
//!   the moment *this node* opened the round. They are **not** synchronized across
//!   nodes and must not be differenced between hosts. Chain-time (block timestamps)
//!   cannot express "votes were still arriving", which is why this one quantity is
//!   not deterministic — see [`ObsClock`].
//! * `have` is **distinct active signers accumulated at this node**, across every
//!   message it received — the same set the authoritative
//!   `FinalityTracker::try_finalize` gate is handed. A different node may legitimately
//!   record a different `have` for the same round; that difference is itself a
//!   finding (gossip reach), not an inconsistency.
//! * `absent` is "in the roster, not tombstoned/jailed, and no vote of theirs reached
//!   *this* node before the round closed". It is not proof the member was down.
//! * Counters and timings are **since process start**; a restart resets them, which
//!   is deliberate (this project counts restarts).
//! * [`RoundLedger::closed_total`] / [`RoundLedger::failed_total`] — the `rounds=` /
//!   `rfail=` pair on the `TELEMETRY` line — count **live rounds only** (issue #105).
//!   A slot this node reached long after the chain had passed it is a
//!   [`RoundDiagnosis::Backfill`] round: journalled like any other, counted in
//!   [`RoundLedger::backfill_total`], and **absent from both alarm counters**. See
//!   [`RoundLedger::is_live_slot`] for the exact predicate.
//!
//! ## Live vs. backfill (issue #105), and why the test is the slot's distance to our tip
//!
//! A healthy node reported `rounds=1316 rfail=1315` while its finalized checkpoint
//! matched its three peers. Nothing was lying: during a 3,597-block resync the slot
//! cursor opened a round for every cadence slot it crossed, including thousands the
//! network had settled hours earlier, and each closed with no votes. **An alarm that
//! reads 99.9 % on a healthy node has been switched off by its own value.**
//!
//! The fix has to name what those rounds were not, and it must do so from a fact the
//! node cannot be wrong about:
//!
//! * *Not* "the node was syncing" — the sync phase is entered because **a peer claims
//!   to be taller**, so a peer advertising an absurd height would hold `rfail` off
//!   forever. An alarm with a remote off-switch is worse than the defect.
//! * *Not* "the slot is at or below the finalized head" — [`FinalityTracker`] is
//!   rebuilt empty at every process start (it is process state, not chain state) and
//!   the vote tally refuses every ahead-of-tip vote set until the tip arrives, so the
//!   finalized head is `None` for the **whole** of a catch-up. The floor is not there
//!   to gate on.
//!
//! What is always there is this node's own tip. A slot the node crossed while its own
//! chain had already run a full cadence past it was history when it got there: the
//! next round had opened before this one could be voted in, at this node, on this
//! node's own evidence. That is the test, and it is symmetric — a slot more than one
//! cadence *above* our tip is a slot we are too far behind to participate in, and it
//! is the same bound the tally already applies (`TALLY_TIP_SLACK`) one layer down.
//!
//! [`FinalityTracker`]: qlab_devnet::finality::FinalityTracker
//!
//! Nothing here touches consensus: the ledger observes, it never gates. The quorum
//! rule, the roster, the tombstone filter and `try_finalize` are all unchanged and
//! upstream of every call into this module.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use qlab_devnet::committee::checkpoint_id_hex;

/// How many closed rounds are retained for in-process inspection (`/metrics` reads
/// aggregates, the journal line is emitted at close, so this ring only backs
/// operator/test queries). **Devnet-grade, tunable, NOT frozen.**
pub const RETAINED_ROUNDS: usize = 64;

/// Cap on simultaneously-open rounds. The vote tally already bounds itself to
/// `MAX_TALLIED_SLOTS`; this is the same defence one layer up, so a peer spraying
/// vote sets for junk heights cannot grow the ledger without bound. The oldest open
/// round is closed as [`RoundClose::Evicted`] when the cap is hit — an evicted round
/// is *reported*, not silently dropped. **Devnet-grade, tunable, NOT frozen.**
pub const MAX_OPEN_ROUNDS: usize = 16;

/// How long a round may stay open before it is **reported while still open**.
///
/// A stall used to produce no journal output at all until it *ended* — the detail
/// landed only once a later slot finalized past it, which is precisely the moment an
/// operator no longer urgently needs it. One round period (cadence 8 × 75 s) is the
/// natural threshold: a round still open after a full period has already missed its
/// slot. **Devnet-grade, tunable, NOT frozen.**
pub const OVERDUE_AFTER_MS: u64 = 600_000;

/// Minimum spacing between repeat reports of the *same* still-open round when
/// nothing about it has changed. A round stuck at `have=11/15` should say so, and
/// then stop repeating itself: a new line is emitted when the vote count moves, or
/// once per this interval, whichever comes first. **Devnet-grade, tunable, NOT
/// frozen.**
pub const OVERDUE_REPEAT_MS: u64 = 600_000;

/// The timeout/votes-short discriminant: a round whose most recent **new** vote
/// arrived within this many milliseconds of its close was still accumulating when it
/// was cut off.
///
/// Basis: the T0 net's measured inter-node RTT is 68–223 ms (baseline taken
/// 2026-07-26 before the run), so a healthy round's votes all land within a second
/// or so of the proposal. 60 s is ~270× the worst measured RTT and ~1/10 of the
/// 600 s round period (cadence 8 × 75 s), which puts it comfortably clear of both
/// "still in flight" and "stopped long ago". **Devnet-grade, tunable, NOT frozen.**
pub const STILL_ARRIVING_MS: u64 = 60_000;

/// How far a checkpoint slot may sit from **this node's own tip**, in either
/// direction, and still be a round this node was a participant in (issue #105).
///
/// One checkpoint cadence, and the value is not a free parameter in either
/// direction:
/// * **below** the tip — a slot the chain has already run a full cadence past is a
///   slot whose *successor* round had opened before this node arrived; there was
///   never a moment at which this node could have voted in it;
/// * **above** the tip — this is exactly [`qlab_devnet::tally::TALLY_TIP_SLACK`],
///   the window the vote tally itself admits. A vote set the tally refuses can
///   never grow a round, so opening one for it and then reporting that it failed
///   counts our own distance from the chain as a committee fault.
///
/// **Devnet-grade, tunable, NOT frozen** — it is derived from the cadence, so it
/// moves with it.
pub const LIVE_SLOT_SLACK: u64 = qlab_devnet::params_devnet::CHECKPOINT_CADENCE_BLOCKS;

/// The clock backing round timings.
///
/// Mirrors [`qlab_devnet`]'s established `MiningClock` seam (M10-T0-3 Phase A): the
/// **deterministic default keeps every in-process simulation and the N7 soak
/// byte-identical**, and the binary opts into the wall clock. `Deterministic` yields
/// `None` rather than a fabricated zero — a round record from a deterministic run
/// says "no timing basis" and [`RoundRecord::diagnose`] degrades honestly to
/// [`RoundDiagnosis::Unclassified`] instead of inventing a verdict.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ObsClock {
    /// No timing. Deterministic runs record counts and rosters only.
    #[default]
    Deterministic,
    /// Wall-clock milliseconds since the Unix epoch (the binary's choice).
    WallClock,
}

impl ObsClock {
    /// The current instant in milliseconds, or `None` under [`Self::Deterministic`].
    pub fn now_ms(&self) -> Option<u64> {
        match self {
            ObsClock::Deterministic => None,
            ObsClock::WallClock => Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0),
            ),
        }
    }
}

/// Votes that reached the node but could not count, by reason. These are the
/// *rejected* half of "was anyone even talking to us" — a round with `have=0` and
/// `rej=f9/…` failed very differently from one with `have=0` and no traffic at all.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VoteRejects {
    /// Signature did not verify against this checkpoint.
    pub forged: u32,
    /// Signer index is not in this height's roster.
    pub unknown_signer: u32,
    /// The same signer appeared twice in one message (padding).
    pub duplicate: u32,
    /// Valid signature by an in-roster member that is tombstoned/jailed — excluded
    /// by the frozen §4 rule before the count, and **not** a misbehaviour.
    pub inactive: u32,
}

impl VoteRejects {
    /// Total rejected votes across all reasons.
    pub fn total(&self) -> u32 {
        self.forged + self.unknown_signer + self.duplicate + self.inactive
    }
    fn add(&mut self, other: VoteRejects) {
        self.forged += other.forged;
        self.unknown_signer += other.unknown_signer;
        self.duplicate += other.duplicate;
        self.inactive += other.inactive;
    }
}

/// Why a round stopped being open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoundClose {
    /// Quorum was reached and the checkpoint finalized.
    Finalized,
    /// A **later** slot finalized first, so this one can never finalize
    /// (`try_finalize` is strictly advancing). This is the shape a catch-up takes:
    /// the 61-of-165 advances that jumped 16/24/32/40 blocks each superseded the
    /// slots they skipped, and *those* are the rounds worth reading.
    Superseded {
        /// The finalized height that overtook this round.
        by_height: u64,
    },
    /// Closed by the open-round cap rather than by an outcome (spray defence).
    Evicted,
}

impl RoundClose {
    /// Short token for the journal line.
    pub fn as_str(&self) -> &'static str {
        match self {
            RoundClose::Finalized => "finalized",
            RoundClose::Superseded { .. } => "superseded",
            RoundClose::Evicted => "evicted",
        }
    }
}

/// The verdict for one round — **the thing the 42 h soak could not produce**.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoundDiagnosis {
    /// Reached quorum and finalized.
    Finalized,
    /// **This node reached the slot as history, not as a round** (issue #105): its
    /// own tip was already more than one cadence away when it first learned of the
    /// slot, so there was no moment at which it could have participated. Recorded
    /// and journalled like any other round; **never counted as a failure**, because
    /// nothing failed — the node simply was not there.
    ///
    /// This is also the answer to "is `silent` the right word during catch-up?".
    /// It is not: `have == 0` on a slot the network settled hours ago is the
    /// *expected* reading, and calling it silence puts a diagnosis on a
    /// non-event.
    Backfill,
    /// Fewer active members than the quorum needs: the round **could not** have
    /// finalized however well the network behaved. Points at the roster
    /// (tombstones/jails/epoch), not at latency.
    QuorumImpossible,
    /// No vote of any kind reached this node for this slot. Points upstream — at
    /// the proposer or the network — not at participation.
    Silent,
    /// Votes arrived, then stopped well before the round closed. The committee gave
    /// all it had and it was short of quorum: the `absent` list is the finding.
    VotesShort,
    /// Votes were **still arriving** when the round was cut off (a later slot
    /// finalized, or the ledger evicted it). More time, or an earlier proposal,
    /// would plausibly have closed it.
    Timeout,
    /// No timing basis (deterministic clock) and the count-only tests did not
    /// settle it. Never asserted as a cause.
    Unclassified,
    /// **Still open.** Not a verdict — a round that has not ended has no cause yet.
    /// Reported so a stall is visible *while it is happening*; the counts on the line
    /// are real, only the outcome is undecided. Never counted as a closed verdict.
    Open,
}

impl RoundDiagnosis {
    /// Short token for the journal line and the metric label.
    pub fn as_str(&self) -> &'static str {
        match self {
            RoundDiagnosis::Finalized => "finalized",
            RoundDiagnosis::Backfill => "backfill",
            RoundDiagnosis::QuorumImpossible => "quorum_impossible",
            RoundDiagnosis::Silent => "silent",
            RoundDiagnosis::VotesShort => "votes_short",
            RoundDiagnosis::Timeout => "timeout",
            RoundDiagnosis::Unclassified => "unclassified",
            RoundDiagnosis::Open => "open",
        }
    }

    /// Every **closed-round** verdict, so a metrics family can pre-declare its series
    /// (a counter that only appears after the first failure is a counter an alert
    /// cannot be written against). [`RoundDiagnosis::Open`] is deliberately absent:
    /// it is not an outcome and must never be counted as one.
    pub const ALL: [RoundDiagnosis; 7] = [
        RoundDiagnosis::Finalized,
        RoundDiagnosis::Backfill,
        RoundDiagnosis::QuorumImpossible,
        RoundDiagnosis::Silent,
        RoundDiagnosis::VotesShort,
        RoundDiagnosis::Timeout,
        RoundDiagnosis::Unclassified,
    ];

    /// Whether this verdict counts toward the `rounds=` / `rfail=` alarm pair
    /// (issue #105). [`RoundDiagnosis::Backfill`] is the one closed verdict that
    /// does not: it is history this node walked through, not a round it lost.
    pub fn counts_as_a_round(&self) -> bool {
        !matches!(self, RoundDiagnosis::Backfill | RoundDiagnosis::Open)
    }
}

/// One checkpoint round, from the first thing this node learned about the slot to
/// the reason it closed. See the module docs for the caliper on every field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoundRecord {
    /// The checkpoint slot = the round number (cadence grid; slot N is height N).
    pub height: u64,
    /// Committee epoch this slot is judged against.
    pub epoch: u64,
    /// Roster size at this height.
    pub roster: usize,
    /// Members active at this height (roster minus tombstoned/jailed).
    pub active: usize,
    /// Quorum threshold at this height (⅔ rule, read — never re-derived here).
    pub need: usize,
    /// Distinct **counting** signers accumulated at this node, ascending.
    pub voted: Vec<usize>,
    /// In-roster signers whose valid votes were excluded as inactive, ascending.
    pub excluded: Vec<usize>,
    /// Distinct checkpoint variants seen at this height (>1 ⇒ the committee is
    /// split, which is a different failure from being short of votes).
    pub variants: usize,
    /// Vote-set messages ingested for this round.
    pub msgs: u32,
    /// Votes this node itself contributed (its own held committee keys).
    pub local_votes: usize,
    /// **What this node's own keys committed to for this slot** (issue #84):
    /// [`qlab_devnet::committee::Checkpoint::identity`] of the checkpoint held in
    /// this node's never-double-sign ledger, or `None` when it holds no committee
    /// keys, or holds keys but has committed to nothing for this slot.
    ///
    /// This is the field that makes a *split* legible. A minority that signed a
    /// different variant still **finalizes the majority's** once the quorum
    /// reaches it, so every node's finalized identity agrees and the disagreement
    /// leaves no trace on the winning side of the record. What each node's keys
    /// were asked to sign does not agree, and that is here.
    ///
    /// It is the same fact as the last record in that node's `finalizer-*.state`
    /// file — the file an operator otherwise has to copy off the host and hash by
    /// hand — recorded per slot, in the journal, at the moment it happens.
    pub local_cpid: Option<u64>,
    /// Whether this node proposed this slot.
    pub proposed_locally: bool,
    /// **Whether this node was a participant in this round** (issue #105), decided
    /// once, when the round was opened, by [`RoundLedger::is_live_slot`] against the
    /// node's own tip at that instant. `false` = the slot was already history to us.
    ///
    /// Fixed at open on purpose. Re-deciding it at close would silence the exact
    /// alarm this counter exists for: during a committee outage the node keeps
    /// mining, so its tip runs a long way past a round it genuinely lost, and a
    /// close-time test would call that backfill too.
    pub live: bool,
    /// Votes that reached the node and could not count.
    pub rejects: VoteRejects,
    /// Absolute wall-clock ms when this node opened the round (`None` under
    /// [`ObsClock::Deterministic`]).
    pub opened_at_ms: Option<u64>,
    /// Offset (ms from open) of the first counting vote.
    pub first_ms: Option<u64>,
    /// Offset (ms from open) of the most recent **new** counting vote.
    pub last_ms: Option<u64>,
    /// Offset (ms from open) at which `have` first reached `need`.
    pub quorum_ms: Option<u64>,
    /// Offset (ms from open) at which the round closed.
    pub closed_ms: Option<u64>,
    /// How it closed; `None` while still open.
    pub close: Option<RoundClose>,
}

impl RoundRecord {
    fn new(
        height: u64,
        epoch: u64,
        roster: usize,
        active: usize,
        need: usize,
        live: bool,
        now: Option<u64>,
    ) -> Self {
        Self {
            height,
            epoch,
            roster,
            active,
            need,
            voted: Vec::new(),
            excluded: Vec::new(),
            variants: 0,
            msgs: 0,
            local_votes: 0,
            local_cpid: None,
            proposed_locally: false,
            live,
            rejects: VoteRejects::default(),
            opened_at_ms: now,
            first_ms: None,
            last_ms: None,
            quorum_ms: None,
            closed_ms: None,
            close: None,
        }
    }

    /// Distinct counting signers accumulated (`have`).
    pub fn have(&self) -> usize {
        self.voted.len()
    }

    /// Roster members with no counting vote at this node and no exclusion —
    /// **the absentee list**. Ascending. See the module caliper: this is "no vote
    /// reached us", not "the member was down".
    pub fn absent(&self) -> Vec<usize> {
        let voted: BTreeSet<usize> = self.voted.iter().copied().collect();
        let excluded: BTreeSet<usize> = self.excluded.iter().copied().collect();
        (0..self.roster).filter(|i| !voted.contains(i) && !excluded.contains(i)).collect()
    }

    /// **The verdict.** The ladder, in order:
    ///
    /// 1. closed as finalized ⇒ [`RoundDiagnosis::Finalized`];
    /// 2. opened as history (`live == false`) ⇒ [`RoundDiagnosis::Backfill`] — the
    ///    node was not a participant, so no cause below applies to it (issue #105);
    /// 3. `active < need` ⇒ [`RoundDiagnosis::QuorumImpossible`] (the roster could
    ///    not have produced a quorum, so latency is not the story);
    /// 4. `have == 0` ⇒ [`RoundDiagnosis::Silent`] (nothing reached us at all);
    /// 5. with timing: last new vote within [`STILL_ARRIVING_MS`] of the close ⇒
    ///    [`RoundDiagnosis::Timeout`], else [`RoundDiagnosis::VotesShort`];
    /// 6. without timing ⇒ [`RoundDiagnosis::Unclassified`].
    ///
    /// Step 5 is the discriminant issue #87 asks for, and it is decidable **from the
    /// recorded fields alone** — `closed_ms`, `last_ms`, `have`, `need`, `active` —
    /// which is the property the round journal exists to have.
    ///
    /// Step 2 sits *below* `Finalized` and not above it: a backfilled slot that
    /// nevertheless reached quorum here did happen as a round, and saying otherwise
    /// would hide a success rather than a failure.
    pub fn diagnose(&self) -> RoundDiagnosis {
        if self.close.is_none() {
            // Still open: the counts are real, the outcome is not yet decided, and
            // guessing one would be the fabrication this module exists to avoid.
            return RoundDiagnosis::Open;
        }
        if self.close == Some(RoundClose::Finalized) {
            return RoundDiagnosis::Finalized;
        }
        if !self.live {
            return RoundDiagnosis::Backfill;
        }
        if self.active < self.need {
            return RoundDiagnosis::QuorumImpossible;
        }
        if self.have() == 0 {
            return RoundDiagnosis::Silent;
        }
        match (self.last_ms, self.closed_ms) {
            (Some(last), Some(closed)) => {
                if closed.saturating_sub(last) <= STILL_ARRIVING_MS {
                    RoundDiagnosis::Timeout
                } else {
                    RoundDiagnosis::VotesShort
                }
            }
            _ => RoundDiagnosis::Unclassified,
        }
    }

    /// The journal line. One line per closed round, `key=value` like the existing
    /// `TELEMETRY` line so the same grep/awk habits work. Absent/voted lists are
    /// comma-separated committee **indices** (see the naming decision in the PR:
    /// indices are already public in the genesis file, and the frozen §4 downtime
    /// jail already acts on exactly this per-member participation data).
    pub fn to_line(&self) -> String {
        fn idx_list(v: &[usize]) -> String {
            if v.is_empty() {
                "-".to_string()
            } else {
                v.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",")
            }
        }
        fn ms(v: Option<u64>) -> String {
            v.map(|x| x.to_string()).unwrap_or_else(|| "-".to_string())
        }
        let close = self.close.map(|c| c.as_str()).unwrap_or("open");
        let by = match self.close {
            Some(RoundClose::Superseded { by_height }) => by_height.to_string(),
            _ => "-".to_string(),
        };
        format!(
            "ROUND slot={} epoch={} why={} close={} by={} have={} need={} active={} roster={} \
             voted={} absent={} excluded={} variants={} msgs={} local={} \
             rej=f{}/u{}/d{}/i{} open_ms={} first_ms={} last_ms={} quorum_ms={} closed_ms={} \
             cpid={}",
            self.height,
            self.epoch,
            self.diagnose().as_str(),
            close,
            by,
            self.have(),
            self.need,
            self.active,
            self.roster,
            idx_list(&self.voted),
            idx_list(&self.absent()),
            idx_list(&self.excluded),
            self.variants,
            self.msgs,
            self.local_votes,
            self.rejects.forged,
            self.rejects.unknown_signer,
            self.rejects.duplicate,
            self.rejects.inactive,
            ms(self.opened_at_ms),
            ms(self.first_ms),
            ms(self.last_ms),
            ms(self.quorum_ms),
            ms(self.closed_ms),
            // Issue #84 — **appended at the end**, same discipline as the
            // `TELEMETRY` line: existing fields keep their name and position.
            // Absent is printed (`-`), never omitted, so a fixed reader never has
            // to special-case the "this node holds no keys" node.
            checkpoint_id_hex(self.local_cpid),
        )
    }
}

/// What a caller observed about one slot: the roster context plus the accumulated
/// state after a message was processed. Roster/quorum values are **read** from the
/// committee state by the caller — this module never derives them.
#[derive(Clone, Debug)]
pub struct SlotContext {
    /// Checkpoint slot.
    pub height: u64,
    /// Committee epoch for that height.
    pub epoch: u64,
    /// Roster size at that height.
    pub roster: usize,
    /// Active members at that height.
    pub active: usize,
    /// Quorum threshold at that height.
    pub need: usize,
    /// **This node's own tip height when the observation was made** (issue #105).
    /// Read from the local chain by the caller, like every other field here — it is
    /// what decides whether a slot is a live round or history walked through, and it
    /// is deliberately our own number rather than a peer's claim about theirs.
    pub tip: u64,
}

/// What one ingested vote-set message added to a round.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NewVotes {
    /// Signers that were not already counted for this round. Exact under either
    /// clock.
    pub newly: usize,
    /// Arrival offsets (ms from round open) for those signers — one entry each.
    /// Empty under [`ObsClock::Deterministic`], which records counts but never
    /// invents timings.
    pub arrivals: Vec<u64>,
}

/// The per-slot ledger. Opens a record on the first thing learned about a slot,
/// accumulates, and emits the record when the slot closes.
///
/// **Observation only** — no method here can change what finalizes.
#[derive(Clone, Debug)]
pub struct RoundLedger {
    clock: ObsClock,
    open: BTreeMap<u64, RoundRecord>,
    /// Closed records awaiting emission to the journal (drained by the run loop).
    emit: VecDeque<RoundRecord>,
    /// Bounded ring of the most recent closed records (operator/test queries).
    recent: VecDeque<RoundRecord>,
    /// height → (vote count, instant) at that round's last still-open report, so a
    /// stuck round says so once and then stops repeating itself.
    reported: BTreeMap<u64, (usize, Option<u64>)>,
    /// The highest slot this node has finalized, once it has finalized anything.
    /// A slot at or below it is settled and can never open another round — without
    /// this, a re-gossiped vote set for a finalized slot re-opens the record that
    /// already closed, and the open-round cap then closes it a second time as a
    /// failure. Nothing else in the ledger remembers what has already closed.
    finalized_floor: Option<u64>,
    closed_total: u64,
    failed_total: u64,
    backfill_total: u64,
}

impl Default for RoundLedger {
    fn default() -> Self {
        Self::new(ObsClock::default())
    }
}

impl RoundLedger {
    /// A ledger on the given clock basis.
    pub fn new(clock: ObsClock) -> Self {
        Self {
            clock,
            open: BTreeMap::new(),
            emit: VecDeque::new(),
            recent: VecDeque::new(),
            reported: BTreeMap::new(),
            finalized_floor: None,
            closed_total: 0,
            failed_total: 0,
            backfill_total: 0,
        }
    }

    /// The clock basis in force (reported in the run doc so numbers carry it).
    pub fn clock(&self) -> ObsClock {
        self.clock
    }

    fn now(&self) -> Option<u64> {
        self.clock.now_ms()
    }

    /// Offset of `now` from a round's open instant, when both are known.
    fn offset(rec: &RoundRecord, now: Option<u64>) -> Option<u64> {
        match (rec.opened_at_ms, now) {
            (Some(open), Some(n)) => Some(n.saturating_sub(open)),
            _ => None,
        }
    }

    /// Whether `height` is a slot this ledger keeps a round for.
    ///
    /// **Genesis is never a slot.** `finality::is_checkpoint_height` says so for the
    /// cadence grid, and the same must hold here: the binary finalizes height 0 at
    /// startup as a bootstrap act, with no proposal, no round and nobody to be
    /// absent from it. Journalling it would put a fictional row at the top of every
    /// node's record and inflate the finalized-round count by one on every restart —
    /// which is exactly the kind of quietly-wrong denominator this issue exists to
    /// stop producing.
    fn tracked(height: u64) -> bool {
        height != 0
    }

    /// **Was this node a participant in `height`'s round, or did it arrive as a
    /// tourist?** (issue #105) — decided from the slot's distance to this node's own
    /// tip, in either direction, against [`LIVE_SLOT_SLACK`].
    ///
    /// This is the whole classification, and it is deliberately a fact about the
    /// chain rather than a mode the node believes itself to be in. See the module
    /// docs for why neither the sync phase nor the finalized head can carry it.
    pub fn is_live_slot(height: u64, tip: u64) -> bool {
        height.saturating_add(LIVE_SLOT_SLACK) > tip
            && height <= tip.saturating_add(LIVE_SLOT_SLACK)
    }

    /// Whether `height` is settled — at or below this node's finalized head, so no
    /// round for it can still be running.
    fn settled(&self, height: u64) -> bool {
        self.finalized_floor.is_some_and(|f| height <= f)
    }

    /// Open the record for `ctx.height` if this node has not seen the slot yet.
    /// Returns nothing — it is the entry point every other method funnels through.
    fn ensure_open(&mut self, ctx: &SlotContext) {
        if !Self::tracked(ctx.height) || self.settled(ctx.height) {
            return;
        }
        if self.open.contains_key(&ctx.height) {
            // Refresh the roster context: tombstones/jails can change mid-round, and
            // the *closing* roster is what the verdict must be judged against.
            let now = self.now();
            let rec = self.open.get_mut(&ctx.height).expect("present");
            rec.roster = ctx.roster;
            rec.active = ctx.active;
            rec.need = ctx.need;
            rec.epoch = ctx.epoch;
            let _ = now;
            return;
        }
        let now = self.now();
        // Issue #105: the live/backfill verdict is taken HERE, from the tip this
        // node held at the moment it first learned of the slot, and never revisited.
        // A later refresh knows a different tip and would answer a different
        // question ("is it still live?"), which is not the one that decides whether
        // this node was ever a participant.
        let live = Self::is_live_slot(ctx.height, ctx.tip);
        self.open.insert(
            ctx.height,
            RoundRecord::new(ctx.height, ctx.epoch, ctx.roster, ctx.active, ctx.need, live, now),
        );
        self.enforce_open_cap(ctx.height);
    }

    /// Keep at most [`MAX_OPEN_ROUNDS`] open, closing the oldest as `Evicted`.
    /// `keep` is the slot just admitted, which is never the one evicted unless it is
    /// itself the oldest.
    fn enforce_open_cap(&mut self, keep: u64) {
        while self.open.len() > MAX_OPEN_ROUNDS {
            let oldest = *self.open.keys().next().expect("non-empty");
            if oldest == keep && self.open.len() == 1 {
                break;
            }
            self.close(oldest, RoundClose::Evicted);
        }
    }

    /// **The slot cursor.** Record that the chain reached a checkpoint slot, even if
    /// no vote for it ever arrives. Without this a slot nobody proposed leaves no
    /// trace at all — which is precisely the 42 h silence. Idempotent.
    pub fn note_slot_reached(&mut self, ctx: &SlotContext) {
        self.ensure_open(ctx);
    }

    /// Record that this node proposed the slot and contributed `local_votes` of its
    /// own held keys (the proposer path; `local_votes` may be 0 when every held key
    /// was refused by the never-double-sign guard — itself a finding).
    ///
    /// `local_cpid` (issue #84) is the identity of the checkpoint this node's keys
    /// are *committed to* for the slot, read from the never-double-sign ledger
    /// rather than from the vote just produced. The distinction is the whole value
    /// of the field: when `local_votes == 0` because the guard refused, the node
    /// still holds a prior commitment for that slot, and **that** commitment — not
    /// the absence of a fresh vote — is what a split forensic needs.
    pub fn note_local_proposal(
        &mut self,
        ctx: &SlotContext,
        local_votes: usize,
        local_cpid: Option<u64>,
    ) {
        self.ensure_open(ctx);
        let Some(rec) = self.open.get_mut(&ctx.height) else { return };
        rec.proposed_locally = true;
        rec.local_votes = local_votes;
        // Never un-set a known commitment: the ledger is append-only per slot and a
        // later observation that reads `None` (e.g. a key file removed at restart)
        // must not erase what this node is on record as having signed.
        if local_cpid.is_some() {
            rec.local_cpid = local_cpid;
        }
    }

    /// Record a vote-set message that could not count at all (forged / unknown
    /// signer / duplicate padding). Opens the slot if needed: a round that only ever
    /// received junk is a round with a story.
    pub fn note_rejected_message(&mut self, ctx: &SlotContext, rejects: VoteRejects) {
        self.ensure_open(ctx);
        let Some(rec) = self.open.get_mut(&ctx.height) else { return };
        rec.msgs += 1;
        rec.rejects.add(rejects);
    }

    /// Record a processed vote-set message.
    ///
    /// * `counted` — the **full accumulated** distinct counting signers after this
    ///   message (the same set handed to `try_finalize`), not just this message's.
    ///   Merged into the round, never replacing it, so a message that added nothing
    ///   (a duplicate, or one the tally window refused) can be recorded truthfully
    ///   with an empty `counted` without erasing what is already known.
    /// * `excluded` — in-roster signers in this message excluded as inactive.
    /// * `variants` — distinct checkpoint variants now tracked at this height.
    ///
    /// Returns how many signers were **new** and their arrival offsets (ms from
    /// round open), so a caller can feed a real histogram at the source rather than
    /// sampling a gauge later. `arrivals` is empty when the clock is deterministic;
    /// `newly` is exact either way.
    pub fn note_votes(
        &mut self,
        ctx: &SlotContext,
        counted: &[usize],
        excluded: &[usize],
        rejects: VoteRejects,
        variants: usize,
    ) -> NewVotes {
        self.ensure_open(ctx);
        let now = self.now();
        let Some(rec) = self.open.get_mut(&ctx.height) else {
            return NewVotes::default(); // genesis is never a round — see `tracked`
        };
        rec.msgs += 1;
        rec.rejects.add(rejects);
        rec.variants = rec.variants.max(variants);

        let mut merged: BTreeSet<usize> = rec.voted.iter().copied().collect();
        let before = merged.len();
        merged.extend(counted.iter().copied());
        let newly = merged.len() - before;
        rec.voted = merged.into_iter().collect();

        let mut ex: BTreeSet<usize> = rec.excluded.iter().copied().collect();
        ex.extend(excluded.iter().copied());
        rec.excluded = ex.into_iter().collect();

        let offset = Self::offset(rec, now);
        if newly > 0 {
            if rec.first_ms.is_none() {
                rec.first_ms = offset;
            }
            rec.last_ms = offset;
        }
        if rec.quorum_ms.is_none() && rec.voted.len() >= rec.need {
            rec.quorum_ms = offset;
        }
        let arrivals = match offset {
            Some(o) if newly > 0 => vec![o; newly],
            _ => Vec::new(),
        };
        NewVotes { newly, arrivals }
    }

    /// Close `height` as finalized, and close every **lower** open round as
    /// [`RoundClose::Superseded`] — a strictly-advancing finalize is exactly what
    /// makes those rounds unfinalizable, so this is where a catch-up jump turns into
    /// one journal line per skipped slot.
    pub fn note_finalized(&mut self, height: u64) {
        let lower: Vec<u64> = self.open.keys().copied().filter(|&h| h < height).collect();
        for h in lower {
            self.close(h, RoundClose::Superseded { by_height: height });
        }
        if self.open.contains_key(&height) {
            self.close(height, RoundClose::Finalized);
        }
        // Everything at or below the new head is settled: no later observation may
        // re-open a round for it (issue #105 — this is candidate B, kept for the one
        // thing it does buy, which is not the resync case).
        self.finalized_floor = Some(self.finalized_floor.map_or(height, |f| f.max(height)));
    }

    fn close(&mut self, height: u64, how: RoundClose) {
        let now = self.now();
        let Some(mut rec) = self.open.remove(&height) else {
            return;
        };
        rec.closed_ms = Self::offset(&rec, now);
        rec.close = Some(how);
        // Issue #105: only a round this node was a participant in reaches the alarm
        // pair. A round that FINALIZED counts however it was classified at open —
        // it demonstrably happened here, and hiding a success is the one direction
        // this filter must never move in.
        if rec.diagnose().counts_as_a_round() {
            self.closed_total += 1;
            if how != RoundClose::Finalized {
                self.failed_total += 1;
            }
        } else {
            self.backfill_total += 1;
        }
        self.reported.remove(&height);
        self.emit.push_back(rec.clone());
        self.recent.push_back(rec);
        while self.recent.len() > RETAINED_ROUNDS {
            self.recent.pop_front();
        }
        // The emit queue is drained every run-loop pass; bound it anyway so a caller
        // that never drains cannot grow it (the ledger must not be a leak).
        while self.emit.len() > RETAINED_ROUNDS {
            self.emit.pop_front();
        }
    }

    /// Rounds that are **still open** and overdue enough to be worth saying out loud
    /// again, returned as journal lines.
    ///
    /// A stall used to be silent until it ended. This is the fix: a round open longer
    /// than [`OVERDUE_AFTER_MS`] is reported, and reported again whenever its vote
    /// count moves or [`OVERDUE_REPEAT_MS`] passes — so "stuck at 11 of 15, and these
    /// ten have not been heard from" reaches the log *during* the incident, while
    /// staying quiet about a round that is merely repeating itself.
    ///
    /// Requires a timing basis: under [`ObsClock::Deterministic`] there is no age to
    /// compare, so nothing is reported and nothing is invented.
    pub fn overdue_reports(&mut self) -> Vec<String> {
        let now = self.now();
        let Some(now) = now else { return Vec::new() };
        let mut out = Vec::new();
        for (height, rec) in &self.open {
            let Some(opened) = rec.opened_at_ms else { continue };
            let age = now.saturating_sub(opened);
            if age < OVERDUE_AFTER_MS {
                continue;
            }
            let have = rec.have();
            let due = match self.reported.get(height) {
                None => true,
                Some((last_have, last_at)) => {
                    *last_have != have
                        || last_at.is_none_or(|t| now.saturating_sub(t) >= OVERDUE_REPEAT_MS)
                }
            };
            if due {
                out.push(rec.to_line());
                self.reported.insert(*height, (have, Some(now)));
            }
        }
        // A round that closed is no longer worth remembering a report for.
        self.reported.retain(|h, _| self.open.contains_key(h));
        out
    }

    /// Take the closed records awaiting journal emission.
    pub fn take_emitted(&mut self) -> Vec<RoundRecord> {
        self.emit.drain(..).collect()
    }

    /// The most recent closed records, oldest first (bounded by [`RETAINED_ROUNDS`]).
    pub fn recent(&self) -> impl Iterator<Item = &RoundRecord> {
        self.recent.iter()
    }

    /// The still-open record for `height`, if any.
    pub fn open_round(&self, height: u64) -> Option<&RoundRecord> {
        self.open.get(&height)
    }

    /// Number of currently-open rounds.
    pub fn open_len(&self) -> usize {
        self.open.len()
    }

    /// **Live** rounds closed since process start (`rounds=`).
    ///
    /// Caliper (issue #105): rounds this node was a participant in — slot within
    /// [`LIVE_SLOT_SLACK`] of its own tip when it first learned of the slot — plus
    /// any round that finalized here regardless. Slots crossed as history are in
    /// [`Self::backfill_total`] instead, so this is a denominator an operator can
    /// divide by.
    pub fn closed_total(&self) -> u64 {
        self.closed_total
    }

    /// **Live** rounds closed **without** finalizing since process start (`rfail=`)
    /// — the number that makes a stall visible to a consumer that only reads the
    /// `TELEMETRY` line, and the one issue #105 exists to make readable again.
    ///
    /// Caliper: the same population as [`Self::closed_total`]. A resync, a restart,
    /// or any other path that walks the node through slots the chain had already
    /// passed adds **nothing** here; a live round that timed out, fell short of
    /// quorum, or heard nothing at all still adds one.
    pub fn failed_total(&self) -> u64 {
        self.failed_total
    }

    /// Slots closed that this node reached as **history** (issue #105) — journalled,
    /// never counted as rounds and never as failures. A large value beside a small
    /// `rfail` is the signature of a node that restarted and caught up, which is a
    /// fact worth having and not an alarm.
    pub fn backfill_total(&self) -> u64 {
        self.backfill_total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A slot this node reached **as the chain's frontier** — `tip == height`, which
    /// is what ordinary operation looks like (the tip advances one block at a time,
    /// so it is exactly on the slot when the cursor crosses it). Every pre-#105 test
    /// means this, so it stays the default.
    fn ctx(height: u64, roster: usize, active: usize, need: usize) -> SlotContext {
        ctx_at_tip(height, height, roster, active, need)
    }

    /// A slot observed while this node's own tip was at `tip` — the shape a resync
    /// makes, where the tip has already jumped far past the slot being opened.
    fn ctx_at_tip(
        height: u64,
        tip: u64,
        roster: usize,
        active: usize,
        need: usize,
    ) -> SlotContext {
        SlotContext { height, epoch: 1, roster, active, need, tip }
    }

    /// A record built by hand at a chosen instant — the classifier tests need
    /// synthetic times, which is exactly why the ledger takes its clock as a seam.
    fn rec_at(have: usize, need: usize, active: usize, last: u64, closed: u64) -> RoundRecord {
        let mut r = RoundRecord::new(8, 1, 21, active, need, true, Some(0));
        r.voted = (0..have).collect();
        r.first_ms = Some(0);
        r.last_ms = Some(last);
        r.closed_ms = Some(closed);
        r.close = Some(RoundClose::Superseded { by_height: 16 });
        r
    }

    /// **The acceptance judgement of issue #87 question 3**: from the recorded
    /// fields alone, can "timeout" be told from "not enough votes"? Both directions,
    /// plus the two cases that are neither.
    #[test]
    fn diagnosis_separates_timeout_from_votes_short() {
        // Still arriving when cut off: last new vote 2 s before close ⇒ timeout.
        let t = rec_at(11, 15, 21, 598_000, 600_000);
        assert_eq!(t.diagnose(), RoundDiagnosis::Timeout);

        // Votes stopped 9 minutes before the close ⇒ the committee gave all it had.
        let s = rec_at(11, 15, 21, 60_000, 600_000);
        assert_eq!(s.diagnose(), RoundDiagnosis::VotesShort);

        // Exactly at the boundary counts as still-arriving (inclusive, documented).
        let b = rec_at(11, 15, 21, 600_000 - STILL_ARRIVING_MS, 600_000);
        assert_eq!(b.diagnose(), RoundDiagnosis::Timeout);
        let b2 = rec_at(11, 15, 21, 600_000 - STILL_ARRIVING_MS - 1, 600_000);
        assert_eq!(b2.diagnose(), RoundDiagnosis::VotesShort);

        // Not enough ACTIVE members to ever reach quorum: neither of the above.
        let imp = rec_at(11, 15, 14, 598_000, 600_000);
        assert_eq!(imp.diagnose(), RoundDiagnosis::QuorumImpossible);

        // Nothing arrived at all: upstream, not participation.
        let sil = rec_at(0, 15, 21, 0, 600_000);
        assert_eq!(sil.diagnose(), RoundDiagnosis::Silent);

        // Finalized wins over everything.
        let mut fin = rec_at(15, 15, 21, 900, 1_000);
        fin.close = Some(RoundClose::Finalized);
        assert_eq!(fin.diagnose(), RoundDiagnosis::Finalized);
    }

    /// Without a timing basis the verdict degrades to `Unclassified` rather than
    /// inventing one — the deterministic clock must not fabricate a cause.
    #[test]
    fn deterministic_clock_records_counts_but_never_invents_a_cause() {
        let mut l = RoundLedger::new(ObsClock::Deterministic);
        let c = ctx(8, 21, 21, 15);
        l.note_slot_reached(&c);
        let added = l.note_votes(&c, &[0, 1, 2, 3, 4, 5], &[], VoteRejects::default(), 1);
        assert_eq!(added.newly, 6, "the count is exact under either clock");
        assert!(added.arrivals.is_empty(), "no clock ⇒ no arrival offsets");
        l.note_finalized(16);
        let r = &l.take_emitted()[0];
        assert_eq!(r.have(), 6);
        assert_eq!(r.opened_at_ms, None);
        assert_eq!(r.diagnose(), RoundDiagnosis::Unclassified);
    }

    /// Accumulation across messages, the absentee list, and the catch-up shape: a
    /// later finalize supersedes the slots it skipped and each leaves a record.
    #[test]
    fn accumulates_names_absentees_and_supersedes_skipped_slots() {
        let mut l = RoundLedger::new(ObsClock::Deterministic);
        let c8 = ctx(8, 21, 21, 15);
        let c16 = ctx(16, 21, 21, 15);

        l.note_local_proposal(&c8, 6, Some(0xabc));
        l.note_votes(&c8, &[0, 1, 2, 3, 4, 5], &[], VoteRejects::default(), 1);
        l.note_votes(&c8, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10], &[], VoteRejects::default(), 1);
        assert_eq!(l.open_round(8).unwrap().have(), 11);
        assert_eq!(l.open_round(8).unwrap().msgs, 2);

        // Slot 16 reaches quorum; slot 8 is superseded by it.
        l.note_slot_reached(&c16);
        l.note_votes(&c16, &(0..15).collect::<Vec<_>>(), &[], VoteRejects::default(), 1);
        l.note_finalized(16);

        let out = l.take_emitted();
        assert_eq!(out.len(), 2, "the skipped slot and the finalized one both close");
        let r8 = out.iter().find(|r| r.height == 8).expect("slot 8 closed");
        assert_eq!(r8.close, Some(RoundClose::Superseded { by_height: 16 }));
        assert_eq!(r8.absent(), (11..21).collect::<Vec<_>>(), "the ten who did not vote here");
        assert!(r8.proposed_locally && r8.local_votes == 6);
        let r16 = out.iter().find(|r| r.height == 16).expect("slot 16 closed");
        assert_eq!(r16.close, Some(RoundClose::Finalized));
        assert_eq!(r16.diagnose(), RoundDiagnosis::Finalized);
        assert!(r16.absent().is_empty() || r16.absent() == (15..21).collect::<Vec<_>>());
        assert_eq!(l.closed_total(), 2);
        assert_eq!(l.failed_total(), 1, "one round closed without finalizing");
    }

    /// Inactive (tombstoned/jailed) members are `excluded`, not `absent` — the
    /// operator must not go looking for a host that the rule itself removed.
    #[test]
    fn excluded_members_are_not_reported_absent() {
        let mut l = RoundLedger::new(ObsClock::Deterministic);
        let c = ctx(8, 7, 5, 5);
        l.note_votes(&c, &[0, 1, 2], &[3, 4], VoteRejects { inactive: 2, ..Default::default() }, 1);
        let r = l.open_round(8).unwrap();
        assert_eq!(r.excluded, vec![3, 4]);
        assert_eq!(r.absent(), vec![5, 6], "only the silent members are absent");
        assert_eq!(r.rejects.inactive, 2);
    }

    /// Genesis is never a round: the binary finalizes height 0 at startup with no
    /// proposal and nobody to be absent from it, and journalling that would inflate
    /// every node's finalized-round count by one on every restart.
    #[test]
    fn genesis_is_never_journalled_as_a_round() {
        let mut l = RoundLedger::new(ObsClock::Deterministic);
        let g = ctx(0, 21, 21, 15);
        l.note_slot_reached(&g);
        l.note_local_proposal(&g, 21, Some(0xabc));
        assert_eq!(l.note_votes(&g, &(0..21).collect::<Vec<_>>(), &[], VoteRejects::default(), 1), NewVotes::default());
        l.note_rejected_message(&g, VoteRejects { forged: 1, ..Default::default() });
        l.note_finalized(0);
        assert_eq!(l.open_len(), 0);
        assert_eq!(l.closed_total(), 0, "height 0 leaves no record at all");
        assert!(l.take_emitted().is_empty());

        // …and a real slot right after it is unaffected.
        let c8 = ctx(8, 21, 21, 15);
        l.note_votes(&c8, &(0..15).collect::<Vec<_>>(), &[], VoteRejects::default(), 1);
        l.note_finalized(8);
        assert_eq!(l.closed_total(), 1);
    }

    /// A round that received only junk is still a round with a story: `have=0` plus
    /// a non-zero reject count reads very differently from silence.
    #[test]
    fn rejected_only_round_is_recorded_not_dropped() {
        let mut l = RoundLedger::new(ObsClock::Deterministic);
        let c = ctx(8, 21, 21, 15);
        l.note_rejected_message(&c, VoteRejects { forged: 3, ..Default::default() });
        l.note_rejected_message(&c, VoteRejects { unknown_signer: 1, ..Default::default() });
        let r = l.open_round(8).unwrap();
        assert_eq!(r.have(), 0);
        assert_eq!(r.rejects.forged, 3);
        assert_eq!(r.rejects.unknown_signer, 1);
        assert_eq!(r.rejects.total(), 4);
        assert_eq!(r.msgs, 2);
        // While open it has no verdict; once it closes, "nothing counted ever reached
        // us" is the finding — and the reject counts say the traffic was not absent,
        // only unusable.
        assert_eq!(r.diagnose(), RoundDiagnosis::Open);
        l.note_finalized(16);
        let closed = l.take_emitted();
        assert_eq!(closed[0].diagnose(), RoundDiagnosis::Silent);
        assert_eq!(closed[0].rejects.total(), 4);
    }

    /// A height spray cannot grow the ledger without bound, and an evicted round is
    /// *reported* rather than silently dropped.
    #[test]
    fn open_rounds_are_capped_and_evictions_are_reported() {
        let mut l = RoundLedger::new(ObsClock::Deterministic);
        for k in 1..=(MAX_OPEN_ROUNDS as u64 + 5) {
            l.note_slot_reached(&ctx(k * 8, 21, 21, 15));
        }
        assert_eq!(l.open_len(), MAX_OPEN_ROUNDS, "open-round cap holds under a spray");
        let emitted = l.take_emitted();
        assert_eq!(emitted.len(), 5, "every evicted round is emitted");
        assert!(emitted.iter().all(|r| r.close == Some(RoundClose::Evicted)));
        assert!(l.open_round(8).is_none(), "oldest evicted");
    }

    /// **A stall must be visible WHILE IT IS HAPPENING.** Before this, a round that
    /// never finalized produced no journal output until a later slot superseded it —
    /// which on a long stall is exactly when the operator no longer urgently needs
    /// it. An overdue open round reports itself, repeats when its vote count moves,
    /// and otherwise stays quiet.
    #[test]
    fn a_stuck_round_reports_itself_while_still_open_and_then_stops_repeating() {
        // A ledger on a controllable clock: the wall-clock variant cannot be stepped,
        // so this drives the ledger's own fields directly, the way the classifier
        // tests do.
        let mut l = RoundLedger::new(ObsClock::Deterministic);
        let c = ctx(8, 21, 21, 15);
        l.note_votes(&c, &(0..11).collect::<Vec<_>>(), &[], VoteRejects::default(), 1);
        // No timing basis ⇒ nothing reported, nothing invented.
        assert!(l.overdue_reports().is_empty(), "a deterministic run has no age to judge");

        // Now with timings, driven through the record the ledger holds.
        let mut l = RoundLedger::new(ObsClock::WallClock);
        l.note_votes(&c, &(0..11).collect::<Vec<_>>(), &[], VoteRejects::default(), 1);
        // Fresh round: not overdue yet.
        assert!(l.overdue_reports().is_empty(), "a round that just opened is not overdue");

        // Backdate the open instant past the threshold — the same thing the passage
        // of a round period does.
        let now = ObsClock::WallClock.now_ms().expect("wall clock");
        l.open.get_mut(&8).unwrap().opened_at_ms = Some(now - OVERDUE_AFTER_MS - 1);
        let first = l.overdue_reports();
        assert_eq!(first.len(), 1, "an overdue open round says so");
        assert!(first[0].contains("why=open"), "an open round has no verdict yet: {}", first[0]);
        assert!(first[0].contains("close=open"), "{}", first[0]);
        assert!(first[0].contains("have=11 need=15 active=21"), "{}", first[0]);
        assert!(first[0].contains("absent=11,12,13,14,15,16,17,18,19,20"), "{}", first[0]);

        // Nothing changed ⇒ it does not repeat itself.
        assert!(l.overdue_reports().is_empty(), "a stuck round must not spam the log");

        // The vote count moves ⇒ worth saying again.
        l.note_votes(&c, &(0..13).collect::<Vec<_>>(), &[], VoteRejects::default(), 1);
        let second = l.overdue_reports();
        assert_eq!(second.len(), 1);
        assert!(second[0].contains("have=13"), "{}", second[0]);
        assert!(l.overdue_reports().is_empty());

        // Once it closes it is journalled normally and never reported open again.
        l.note_finalized(16);
        assert!(l.overdue_reports().is_empty());
        let closed = l.take_emitted();
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].close, Some(RoundClose::Superseded { by_height: 16 }));
        assert_ne!(closed[0].diagnose(), RoundDiagnosis::Open, "a closed round has a verdict");
    }

    /// `Open` is not an outcome and must never be pre-declared or counted as one.
    #[test]
    fn open_is_not_a_closed_verdict() {
        assert!(!RoundDiagnosis::ALL.contains(&RoundDiagnosis::Open));
        assert_eq!(RoundDiagnosis::ALL.len(), 7);
        assert!(!RoundDiagnosis::Open.counts_as_a_round());
    }

    /// **The write-volume caliper, machine-checked.** The always-on decision rests on
    /// one journal line per round at 144 rounds/day; the estimate is only honest if
    /// the line length is bounded. A full 21-member round with every list populated
    /// stays under the budget the PR quotes.
    #[test]
    fn journal_line_stays_within_the_quoted_budget() {
        const BUDGET_BYTES: usize = 400;
        let mut r = RoundRecord::new(1_384, 12, 21, 21, 15, true, Some(1_769_000_000_000));
        r.voted = (0..11).collect();
        r.excluded = vec![19, 20];
        r.variants = 2;
        r.msgs = 9;
        r.local_votes = 6;
        r.proposed_locally = true;
        r.rejects = VoteRejects { forged: 2, unknown_signer: 1, duplicate: 1, inactive: 2 };
        r.first_ms = Some(211);
        r.last_ms = Some(598_402);
        r.closed_ms = Some(600_113);
        r.close = Some(RoundClose::Superseded { by_height: 1_392 });
        r.local_cpid = Some(0x4cc8_904e_1f2a); // issue #84 — the widest this field gets
        let line = r.to_line();
        assert!(
            line.len() <= BUDGET_BYTES,
            "round journal line is {} B, budget {BUDGET_BYTES} B: {line}",
            line.len()
        );
        // The line must actually carry the discriminant fields, not just be short.
        for key in ["why=timeout", "have=11", "need=15", "active=21", "absent=", "last_ms=", "closed_ms="] {
            assert!(line.contains(key), "journal line is missing {key}: {line}");
        }
    }

    // ---- issue #84: the identity in the per-slot journal ----------------------

    /// `cpid` is **appended at the end** and every pre-#84 key keeps its name and
    /// its position. Same contract the `TELEMETRY` line holds itself to, for the
    /// same reason: `qumbra-ops/` parses these lines out of archived container
    /// logs, and a reader that counts fields must not be shifted under.
    #[test]
    fn round_line_gains_cpid_at_the_end_and_nowhere_else() {
        let mut r = RoundRecord::new(3_776, 12, 21, 21, 15, true, None);
        r.voted = (0..16).collect();
        r.close = Some(RoundClose::Finalized);
        let line = r.to_line();
        let keys: Vec<&str> = line
            .split_whitespace()
            .skip(1) // the "ROUND" tag
            .map(|kv| kv.split('=').next().unwrap())
            .collect();
        assert_eq!(
            keys,
            vec![
                // ── the pre-#84 fields, in their original order ──
                "slot", "epoch", "why", "close", "by", "have", "need", "active", "roster",
                "voted", "absent", "excluded", "variants", "msgs", "local", "rej", "open_ms",
                "first_ms", "last_ms", "quorum_ms", "closed_ms",
                // ── appended by #84, at the end ──
                "cpid",
            ],
            "existing ROUND fields must not move or be renamed"
        );
    }

    /// **Slot 3776, reconstructed.** Three nodes' keys signed one variant and one
    /// node's signed another; all four then finalize the majority variant, so the
    /// round closes `finalized` on every host and nothing but `cpid` distinguishes
    /// them. One `grep 'ROUND slot=3776'` across four hosts is the whole forensic.
    #[test]
    fn a_split_round_is_one_grep_across_the_hosts() {
        let majority = 0x4cc8_904e_1f2a;
        let minority = 0xee8e_07e9_5b31;
        let host = |cpid: u64| {
            let mut l = RoundLedger::new(ObsClock::Deterministic);
            let c = ctx(3_776, 21, 21, 15);
            l.note_local_proposal(&c, 5, Some(cpid));
            // Every host accumulates the same 16 counting signers and finalizes the
            // same majority checkpoint — the split leaves no mark on `have`.
            l.note_votes(&c, &(0..16).collect::<Vec<_>>(), &[], VoteRejects::default(), 2);
            l.note_finalized(3_776);
            l.take_emitted().remove(0).to_line()
        };
        let lines: Vec<String> =
            [majority, majority, majority, minority].iter().map(|c| host(*c)).collect();

        // Every host reports the same round, the same counts, the same outcome…
        for l in &lines {
            assert!(l.contains("have=16 need=15"), "{l}");
            assert!(l.contains("close=finalized"), "{l}");
            assert!(l.contains("variants=2"), "{l}");
        }
        // …and `variants=2` says only that *a* split existed locally, which is what
        // the T0 net could already see and could not act on.
        assert_eq!(lines[0], lines[1], "the three agreeing hosts are byte-identical");
        assert_eq!(lines[0], lines[2]);
        // `cpid` is the one field that names which side each host was on.
        assert_ne!(lines[0], lines[3], "the minority host's line differs");
        assert!(lines[0].contains("cpid=4cc8904e1f2a"), "{}", lines[0]);
        assert!(lines[3].contains("cpid=ee8e07e95b31"), "{}", lines[3]);
    }

    /// A node holding **no committee keys** still emits the field, as `-`. The
    /// alternative — omitting the key — makes every parser special-case the
    /// verify-only nodes, and that special case is the one that gets skipped.
    #[test]
    fn a_node_with_no_keys_prints_the_absent_sentinel() {
        let mut l = RoundLedger::new(ObsClock::Deterministic);
        let c = ctx(8, 21, 21, 15);
        l.note_slot_reached(&c);
        l.note_votes(&c, &(0..15).collect::<Vec<_>>(), &[], VoteRejects::default(), 1);
        l.note_finalized(8);
        let line = l.take_emitted().remove(0).to_line();
        assert!(line.contains(" cpid=-"), "absence is printed, not omitted: {line}");
    }

    /// The guard-refused case, which is why `cpid` is read from the ledger and not
    /// from the vote just produced: `local=0` (every held key refused to re-sign)
    /// and yet the node **is** on record as committed to a variant for this slot.
    /// Reading the fresh vote would print `-` here and lose exactly the commitment
    /// a restart-equivocation forensic is looking for.
    #[test]
    fn a_guard_refused_slot_still_names_what_this_node_is_committed_to() {
        let mut l = RoundLedger::new(ObsClock::Deterministic);
        let c = ctx(8, 21, 21, 15);
        l.note_local_proposal(&c, 0, Some(0x0000_0000_00ff));
        l.note_finalized(16); // superseded, never finalized here
        let line = l.take_emitted().remove(0).to_line();
        assert!(line.contains(" local=0 "), "{line}");
        assert!(line.contains(" cpid=0000000000ff"), "the commitment survives: {line}");
    }

    /// A later observation that reads `None` must not erase a recorded commitment.
    #[test]
    fn a_recorded_commitment_is_never_un_set() {
        let mut l = RoundLedger::new(ObsClock::Deterministic);
        let c = ctx(8, 21, 21, 15);
        l.note_local_proposal(&c, 5, Some(0xabc));
        l.note_local_proposal(&c, 0, None);
        assert_eq!(l.open_round(8).unwrap().local_cpid, Some(0xabc));
    }
}
