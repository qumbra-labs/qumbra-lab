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
//!
//! Nothing here touches consensus: the ledger observes, it never gates. The quorum
//! rule, the roster, the tombstone filter and `try_finalize` are all unchanged and
//! upstream of every call into this module.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

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
}

impl RoundDiagnosis {
    /// Short token for the journal line and the metric label.
    pub fn as_str(&self) -> &'static str {
        match self {
            RoundDiagnosis::Finalized => "finalized",
            RoundDiagnosis::QuorumImpossible => "quorum_impossible",
            RoundDiagnosis::Silent => "silent",
            RoundDiagnosis::VotesShort => "votes_short",
            RoundDiagnosis::Timeout => "timeout",
            RoundDiagnosis::Unclassified => "unclassified",
        }
    }

    /// Every diagnosis label, so a metrics family can pre-declare its series (a
    /// counter that only appears after the first failure is a counter an alert
    /// cannot be written against).
    pub const ALL: [RoundDiagnosis; 6] = [
        RoundDiagnosis::Finalized,
        RoundDiagnosis::QuorumImpossible,
        RoundDiagnosis::Silent,
        RoundDiagnosis::VotesShort,
        RoundDiagnosis::Timeout,
        RoundDiagnosis::Unclassified,
    ];
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
    /// Whether this node proposed this slot.
    pub proposed_locally: bool,
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
    fn new(height: u64, epoch: u64, roster: usize, active: usize, need: usize, now: Option<u64>) -> Self {
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
            proposed_locally: false,
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
    /// 2. `active < need` ⇒ [`RoundDiagnosis::QuorumImpossible`] (the roster could
    ///    not have produced a quorum, so latency is not the story);
    /// 3. `have == 0` ⇒ [`RoundDiagnosis::Silent`] (nothing reached us at all);
    /// 4. with timing: last new vote within [`STILL_ARRIVING_MS`] of the close ⇒
    ///    [`RoundDiagnosis::Timeout`], else [`RoundDiagnosis::VotesShort`];
    /// 5. without timing ⇒ [`RoundDiagnosis::Unclassified`].
    ///
    /// Step 4 is the discriminant issue #87 asks for, and it is decidable **from the
    /// recorded fields alone** — `closed_ms`, `last_ms`, `have`, `need`, `active` —
    /// which is the property the round journal exists to have.
    pub fn diagnose(&self) -> RoundDiagnosis {
        if self.close == Some(RoundClose::Finalized) {
            return RoundDiagnosis::Finalized;
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
             rej=f{}/u{}/d{}/i{} open_ms={} first_ms={} last_ms={} quorum_ms={} closed_ms={}",
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
    closed_total: u64,
    failed_total: u64,
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
            closed_total: 0,
            failed_total: 0,
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

    /// Open the record for `ctx.height` if this node has not seen the slot yet.
    /// Returns nothing — it is the entry point every other method funnels through.
    fn ensure_open(&mut self, ctx: &SlotContext) {
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
        self.open.insert(
            ctx.height,
            RoundRecord::new(ctx.height, ctx.epoch, ctx.roster, ctx.active, ctx.need, now),
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
    pub fn note_local_proposal(&mut self, ctx: &SlotContext, local_votes: usize) {
        self.ensure_open(ctx);
        let rec = self.open.get_mut(&ctx.height).expect("just opened");
        rec.proposed_locally = true;
        rec.local_votes = local_votes;
    }

    /// Record a vote-set message that could not count at all (forged / unknown
    /// signer / duplicate padding). Opens the slot if needed: a round that only ever
    /// received junk is a round with a story.
    pub fn note_rejected_message(&mut self, ctx: &SlotContext, rejects: VoteRejects) {
        self.ensure_open(ctx);
        let rec = self.open.get_mut(&ctx.height).expect("just opened");
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
        let rec = self.open.get_mut(&ctx.height).expect("just opened");
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
    }

    fn close(&mut self, height: u64, how: RoundClose) {
        let now = self.now();
        let Some(mut rec) = self.open.remove(&height) else {
            return;
        };
        rec.closed_ms = Self::offset(&rec, now);
        rec.close = Some(how);
        self.closed_total += 1;
        if how != RoundClose::Finalized {
            self.failed_total += 1;
        }
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

    /// Rounds closed since process start.
    pub fn closed_total(&self) -> u64 {
        self.closed_total
    }

    /// Rounds closed **without** finalizing since process start — the number that
    /// makes a stall visible to a consumer that only reads the `TELEMETRY` line.
    pub fn failed_total(&self) -> u64 {
        self.failed_total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(height: u64, roster: usize, active: usize, need: usize) -> SlotContext {
        SlotContext { height, epoch: 1, roster, active, need }
    }

    /// A record built by hand at a chosen instant — the classifier tests need
    /// synthetic times, which is exactly why the ledger takes its clock as a seam.
    fn rec_at(have: usize, need: usize, active: usize, last: u64, closed: u64) -> RoundRecord {
        let mut r = RoundRecord::new(8, 1, 21, active, need, Some(0));
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

        l.note_local_proposal(&c8, 6);
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
        assert_eq!(r.diagnose(), RoundDiagnosis::Silent);
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

    /// **The write-volume caliper, machine-checked.** The always-on decision rests on
    /// one journal line per round at 144 rounds/day; the estimate is only honest if
    /// the line length is bounded. A full 21-member round with every list populated
    /// stays under the budget the PR quotes.
    #[test]
    fn journal_line_stays_within_the_quoted_budget() {
        const BUDGET_BYTES: usize = 400;
        let mut r = RoundRecord::new(1_384, 12, 21, 21, 15, Some(1_769_000_000_000));
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
}
