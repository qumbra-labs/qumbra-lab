//! **Issue #229 — make the ask set observable.** Instrumentation only; nothing
//! here changes what the node asks for, what it applies, or when it rewinds.
//!
//! ## What was unobservable, and why it mattered
//!
//! On 2026-08-03 three T0 hosts sat stranded off the main chain for over an hour
//! with `stip` frozen at 2693, a header chain at 2714, `slag=21` — and `breq=1`
//! or `2`. A node stranded at 2693 against a fork point near 2680 should have been
//! asking for roughly ten to fifteen main-chain bodies
//! ([`crate::node::MAX_BODIES_IN_FLIGHT`] is 16, so an ask set that size becomes
//! that many in flight on the next tick). It was asking for one or two.
//!
//! **Three layers can produce that number and they have different fixes:**
//!
//! - **(a)** the ask set itself is wrong or empty —
//!   [`crate::adapter::NodeAdapter::state_fork_point`] returns `None` or a wrong
//!   base, so `missing_body_hashes` walks from the wrong place;
//! - **(b)** the asks are right and nobody serves them — the only holders of a
//!   historical body are nodes that applied it, `P2pNode::blocks` is never
//!   persisted (#135), and possession-based serving (#199) honestly answers
//!   "don't have";
//! - **(c)** bodies arrive but the rejoin gate never passes —
//!   [`crate::adapter::NodeAdapter::rejoin_main_chain`] requires the main-chain
//!   body at `fork + 1` in the pending-body window, and ordering or retention
//!   drops it.
//!
//! **On the record before this module the ask set's contents were inferred, never
//! observed** — by everyone, including two coordinator rulings that were
//! withdrawn. This is the surface that decides between the three from one
//! stranding, and its whole design is answering that question:
//!
//! | reading | layer |
//! |---|---|
//! | `ask=` far below `slag=`, or `sfork=none` | **(a)** |
//! | `ask=` ≈ the gap, answers are `dont-have` / `header-only` / `noreply` | **(b)** |
//! | answers are `served`, `pend=` climbing, `gate=missing` | **(c)** |
//!
//! ## Why a journal line and not a metric
//!
//! `metrics_addr` is `Option<String>` with `#[serde(default)]`, documented as
//! *"Unset = no listener at all, the default and the right one for any node"* —
//! and every T0 host runs that default. `refuse_for_lag` is already
//! `self.metrics.observe_lag_refusal(duty)` and nothing else, which is exactly why
//! three hosts stopped mining for forty minutes with no reachable surface saying
//! so. A new counter there would reproduce the defect it exists to close.
//!
//! A journal line is what an operator reads under `docker logs`, it needs no
//! inbound rule, and — the part a telemetry field cannot do — it carries
//! **per-entry, per-peer** detail.

use std::collections::{BTreeMap, BTreeSet};

use qlab_devnet::header::Hash32;

use crate::peer::PeerId;

/// How many distinct peers' answers are kept per outstanding request.
///
/// The outbound cap is 8 and the inbound cap 32 (#83), so a hash re-asked long
/// enough could accumulate 40 entries; the rotation
/// ([`crate::node::P2pNode::body_rr`]) spreads re-asks across ready peers, so the
/// first few carry the verdict and the rest repeat it. 8 is the outbound cap,
/// which is the set this node actually chose to talk to. Truncation is **printed**
/// (`+N`), never silent.
pub const MAX_ANSWERS_PER_ASK: usize = 8;

/// How many ask records are tracked at once, before the oldest by first-ask is
/// dropped.
///
/// `2 × MAX_BODIES_IN_FLIGHT_CATCHUP` — twice the WIDEST in-flight window a node
/// can open ([`crate::node::body_window_for`]), which is the catch-up one since
/// QUM-115. This ledger is pruned against the in-flight map every pass, so the
/// cap is a backstop rather than a working bound — it exists so that a bug in the
/// pruning cannot turn an observation ledger into a memory leak on a node that is
/// already unwell. Sized against the steady 16 it would instead have evicted live
/// records of a catch-up in progress, i.e. gone blind at exactly the moment #229
/// was built to see.
pub const MAX_TRACKED_ASKS: usize = 2 * crate::node::MAX_BODIES_IN_FLIGHT_CATCHUP;

/// **What a peer answered when we asked it for a block body.**
///
/// The three are not degrees of the same thing — they are three different peers'
/// three different honest positions, and telling them apart is the whole of layer
/// (b):
///
/// - [`Self::Served`] — a `BlockAnnounce` carrying the whole body came back. The
///   peer had it. If the ask is *still outstanding* after a `served` answer, the
///   body arrived and this node did not apply it, which is layer (c).
/// - [`Self::HeaderOnly`] — the peer answered `GetData(Block)` with a bare
///   `Header`. It holds the header and **does not possess the body** (#199's
///   honest answer, and the shape a node that restarted always gives: `blocks` is
///   never persisted, #135). This is layer (b)'s signature and it is the answer
///   easiest to leave out of an instrument, because on the wire it looks like
///   ordinary header traffic.
/// - [`Self::DontHave`] — `NotFound`: the peer does not hold the block at all,
///   not even its header.
///
/// A peer that was asked and said nothing at all has no entry here; it renders as
/// `noreply`, which is a fourth reading and is deliberately the absence of a
/// value rather than a variant, because "no answer" is not something a peer sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BodyAnswer {
    Served,
    HeaderOnly,
    DontHave,
}

impl BodyAnswer {
    pub fn as_str(self) -> &'static str {
        match self {
            BodyAnswer::Served => "served",
            BodyAnswer::HeaderOnly => "header-only",
            BodyAnswer::DontHave => "dont-have",
        }
    }
}

/// One outstanding body request, with what came back — the per-entry half of the
/// #229 line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BodyAskEntry {
    /// The block whose body is wanted.
    pub hash: Hash32,
    /// Its height, from this node's own header chain. `None` only if the header
    /// went away between the ask and the read, which cannot happen while the hash
    /// is in the ask set (`missing_body_hashes` walks the header chain).
    pub height: Option<u64>,
    /// How long this hash has been wanted, in ms — **across re-asks**.
    ///
    /// This is the number `breq=` cannot carry and the reason this ledger is
    /// separate from the in-flight map: the in-flight entry's lifetime is the 15 s
    /// re-ask ladder ([`crate::node::BODY_REQUEST_TIMEOUT_MS`]), so its timestamp
    /// answers "how long since the last ask", and the question the incident asks is
    /// "how long has this node been unable to get this block".
    pub outstanding_ms: u64,
    /// How many times it has been asked, over that window.
    pub asks: u32,
    /// Peers this hash has been asked of, in ask order.
    pub asked: Vec<PeerId>,
    /// The most recent answer from each peer that gave one.
    pub answers: BTreeMap<PeerId, BodyAnswer>,
    /// Peers whose answers were not kept because [`MAX_ANSWERS_PER_ASK`] bit.
    pub answers_dropped: usize,
    /// Whether the request is **still outstanding** right now (`breq=` counts
    /// exactly these), as opposed to answered-and-no-longer-wanted.
    ///
    /// Both are reported, and the flag is why. An ask that was answered with a
    /// body and left the ask set is the node **being served**; an ask that was
    /// answered with a body and is *still* outstanding is a body that arrived and
    /// was not applied. Dropping the answered ones would erase the (c) reading
    /// entirely on the common path, because a buffered body leaves the ask set the
    /// moment it lands — `missing_body_hashes` excludes anything in the
    /// pending-body window — so the only trace that it ever arrived is here.
    pub in_flight: bool,
}

impl BodyAskEntry {
    /// `ans=` — every peer this hash was asked of, with its answer or `noreply`.
    ///
    /// **Asked peers with no answer are listed, not omitted.** "Three peers, none
    /// of which replied" and "one peer, which said don't-have" are different
    /// facts and an instrument that prints only the answers collapses them.
    fn answer_field(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        let mut seen: BTreeSet<PeerId> = BTreeSet::new();
        for pid in &self.asked {
            if !seen.insert(*pid) {
                continue;
            }
            match self.answers.get(pid) {
                Some(a) => parts.push(format!("p{}:{}", pid.0, a.as_str())),
                None => parts.push(format!("p{}:noreply", pid.0)),
            }
        }
        // An answer from a peer we never asked is still an answer about this hash
        // (a relayed header, a gossiped announce). It is reported rather than
        // dropped, because on the (b)/(c) question what came back matters more
        // than who was asked for it.
        for (pid, a) in &self.answers {
            if seen.insert(*pid) {
                parts.push(format!("p{}:{}", pid.0, a.as_str()));
            }
        }
        if self.answers_dropped > 0 {
            parts.push(format!("+{}", self.answers_dropped));
        }
        if parts.is_empty() {
            return "none".to_string();
        }
        parts.join(",")
    }

    /// The per-entry journal line.
    pub fn to_line(&self) -> String {
        format!(
            "BODYWAIT ask h={} id={} age_s={} asks={} flight={} ans={}",
            self.height.map_or_else(|| "?".to_string(), |h| h.to_string()),
            hex12(&self.hash),
            self.outstanding_ms / 1_000,
            self.asks,
            if self.in_flight { "y" } else { "n" },
            self.answer_field(),
        )
    }
}

/// **Whether the rewind that would rejoin the main chain can be followed by an
/// application** — [`crate::adapter::NodeAdapter::rejoin_main_chain`]'s gate,
/// evaluated read-only.
///
/// The gate is *"this node holds the main-chain body at `fork + 1` in
/// `pending_bodies`"*, and it is the input layer (c) is about: bodies that arrive
/// and never satisfy it leave the node exactly as stranded as bodies that never
/// arrive, and the two look identical from outside.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejoinGate {
    /// The applied tip is already the fork point — there is nothing to rejoin.
    OnMain,
    /// `state_fork_point()` answered `None`. **Layer (a) in one word.**
    NoForkPoint,
    /// Fork choice holds no main-chain block at `fork + 1`.
    NoMainBlock,
    /// The body at `fork + 1` is held: the next `drain_pending_bodies` rewinds.
    Held(u64),
    /// The body at `fork + 1` is **not** held: the rewind will not be taken.
    Missing(u64),
}

impl RejoinGate {
    fn field(self) -> String {
        match self {
            RejoinGate::OnMain => "on-main".to_string(),
            RejoinGate::NoForkPoint => "no-fork".to_string(),
            RejoinGate::NoMainBlock => "no-main-block".to_string(),
            RejoinGate::Held(h) => format!("held@{h}"),
            RejoinGate::Missing(h) => format!("missing@{h}"),
        }
    }
}

/// **What this node's mining duty is doing right now**, from the same two facts
/// the gate at `adapter.rs:1540` reads.
///
/// It is on this line because the three stranded hosts **stopped mining** —
/// correctly, `lagging && !exempt ⇒ refuse` — and nothing said so. It was
/// deducible only by differencing `tip` across hosts, and it is the operational
/// consequence an operator actually cares about: a stranding does not merely stop
/// a node participating in finality, it removes its hashrate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MineDuty {
    /// This node does not mine at all (config).
    Off,
    /// Lagging and not exempt: **refusing to mine.**
    RefusedLag,
    /// Lagging but under #200's unobtainable-body exemption: mining on the state tip.
    Exempt,
    /// Not lagging: the duty gate is not engaged.
    Ok,
}

impl MineDuty {
    fn as_str(self) -> &'static str {
        match self {
            MineDuty::Off => "off",
            MineDuty::RefusedLag => "refused-lag",
            MineDuty::Exempt => "exempt",
            MineDuty::Ok => "ok",
        }
    }
}

/// **The derived quantities layer (a) is invisible without**, read off the
/// adapter in one pass so the line and the requester cannot disagree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AskSetObservation {
    /// Whether the stall latch is armed — see
    /// [`crate::adapter::NodeAdapter::ask_set_observation`] for the predicate.
    pub armed: bool,
    /// How long `stip` has not moved, in ms.
    pub stuck_ms: u64,
    /// The applied tip's height (`stip=`).
    pub state_tip: u64,
    /// The applied tip's identity, as `stipid=` spells it.
    pub state_tip_id: String,
    /// `tip − stip` (`slag=`).
    pub lag: u64,
    /// Whether the applied tip is off the fork-choice main chain (`schain=fork`).
    pub off_main: bool,
    /// **`state_fork_point()`'s answer**: the height of the highest applied block
    /// that is also on the main chain, or `None`.
    ///
    /// This is one of the two quantities #229 asks for by name, and it is the one
    /// no existing surface carries. `schain=fork` says the applied tip is on a
    /// losing branch; only this says **how deep the divergence is**, and therefore
    /// where the requester is walking from.
    pub fork_point: Option<u64>,
    /// **The size of the ask set `missing_body_hashes` produced**, as distinct
    /// from how many are in flight.
    ///
    /// *"An ask set of 15 with 2 in flight and an ask set of 2 are the same `breq`
    /// and different bugs."* Capped at [`crate::node::MAX_BODIES_IN_FLIGHT`],
    /// because that is the `max` the requester itself passes — this reports what
    /// the requester would produce, not a hypothetical unbounded set.
    pub ask_set: usize,
    /// In-flight body requests — the same number `breq=` prints.
    pub in_flight: usize,
    /// Entries held in the pending-body window.
    pub pending: usize,
    /// The rejoin gate, evaluated without taking it.
    pub gate: RejoinGate,
    /// What the mining duty is doing.
    pub mine: MineDuty,
    /// How many times a duty has been refused for lag since process start — the
    /// evidence that the predicate above is not merely true but has fired.
    pub mine_refusals: u64,
}

impl AskSetObservation {
    /// The summary line.
    pub fn to_line(&self) -> String {
        format!(
            "BODYWAIT stip={} stipid={} schain={} slag={} sfork={} ask={} breq={} pend={} gate={} mine={} mrefuse={} stuck_s={}",
            self.state_tip,
            self.state_tip_id,
            if self.off_main { "fork" } else { "main" },
            self.lag,
            self.fork_point.map_or_else(|| "none".to_string(), |h| h.to_string()),
            self.ask_set,
            self.in_flight,
            self.pending,
            self.gate.field(),
            self.mine.as_str(),
            self.mine_refusals,
            self.stuck_ms / 1_000,
        )
    }

    /// The `bask=` telemetry field: **the ask set's size and the fork point**, the
    /// two derived quantities, in one field.
    ///
    /// Two numbers in one field has this line's own precedent (`dialable=`,
    /// `unk=`): they answer one question — *"is the requester asking for the right
    /// blocks?"* — and splitting them would put two fields on the line for one
    /// fact.
    ///
    /// Always printed, `0@-` included (the #130 (a) rule): a node always knows both.
    pub fn telemetry_field(&self) -> String {
        format!(
            "{}@{}",
            self.ask_set,
            self.fork_point.map_or_else(|| "-".to_string(), |h| h.to_string())
        )
    }

    /// What must change before the full report is re-emitted. See
    /// [`BodyWaitJournal`].
    fn signature(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}|{}",
            self.state_tip,
            self.fork_point.map_or(-1i128, |h| h as i128),
            self.ask_set,
            self.in_flight,
            self.gate.field(),
            self.mine.as_str(),
            self.off_main,
        )
    }
}

/// **The rate limit, and it is the part of this that is a position rather than a
/// mechanism.**
///
/// The failure this closes is *a stranding that produced no output for an hour*.
/// The failure it must not become is *a line every 30 s*, which teaches an
/// operator to ignore the surface — the same objection that shaped `ROUND`'s
/// overdue reports (*"reports repeat when the vote count moves and otherwise stay
/// quiet"*). Three rules, in the shape those lines already take:
///
/// 1. **Nothing at all unless the latch is armed.** Six legitimate rewinds in
///    fifteen minutes is normal and must produce no line; so must a node merely
///    behind with `stip` advancing. The arming predicate is the adapter's, not
///    this type's — see [`crate::adapter::NodeAdapter::ask_set_observation`].
/// 2. **A full report — summary plus one line per outstanding entry — when the
///    picture changes**: the fork point, the ask-set size, the in-flight set, the
///    gate, the mining duty, or any peer's answer. Those are the transitions an
///    operator would act on, and in a steady stranding they stop happening after
///    the first few re-ask rotations.
/// 3. **A summary line on a heartbeat while the latch stays armed**, so a
///    stranding that changes nothing still proves the node is in it — bounded
///    below by [`crate::node::BODY_REQUEST_TIMEOUT_MS`], the ladder's own period,
///    so no amount of flapping can exceed one report per re-ask cycle.
///
/// **The heartbeat reuses `UNOBTAINABLE_BODY_CADENCES`'s clock** (20 min at the
/// live 75 s target, 32 s in the in-process sim) rather than adding a second
/// constant, for #201's reason and one more: a stranding of the observed length
/// (2 h 13 m – 2 h 23 m) then yields about seven heartbeat lines, which is a
/// record and not a stream.
#[derive(Clone, Debug, Default)]
pub struct BodyWaitJournal {
    last_signature: Option<String>,
    last_emit_ms: Option<u64>,
}

impl BodyWaitJournal {
    pub fn new() -> Self {
        Self::default()
    }

    /// Lines to journal this pass — empty on every healthy node, always.
    ///
    /// `heartbeat_ms` is the adapter's `unobtainable_threshold_ms()`, `floor_ms`
    /// is [`crate::node::BODY_REQUEST_TIMEOUT_MS`]. Both are passed in rather than
    /// read here so this type has no opinion about the network's parameters.
    pub fn report(
        &mut self,
        obs: &AskSetObservation,
        entries: &[BodyAskEntry],
        now_ms: u64,
        heartbeat_ms: u64,
        floor_ms: u64,
    ) -> Vec<String> {
        if !obs.armed {
            // Disarmed: forget everything, so a node that strands, recovers and
            // strands again reports the second one in full rather than matching it
            // against the first one's signature.
            self.last_signature = None;
            self.last_emit_ms = None;
            return Vec::new();
        }
        let sig = full_signature(obs, entries);
        let changed = self.last_signature.as_deref() != Some(sig.as_str());
        let since = self.last_emit_ms.map(|t| now_ms.saturating_sub(t));
        let floored = since.is_some_and(|d| d < floor_ms);
        let heartbeat = since.is_none_or(|d| d >= heartbeat_ms);

        if floored || !(changed || heartbeat) {
            return Vec::new();
        }
        self.last_emit_ms = Some(now_ms);
        self.last_signature = Some(sig);

        let mut lines = vec![obs.to_line()];
        if changed {
            lines.extend(entries.iter().map(BodyAskEntry::to_line));
        }
        lines
    }
}

fn full_signature(obs: &AskSetObservation, entries: &[BodyAskEntry]) -> String {
    let mut sig = obs.signature();
    for e in entries {
        sig.push('|');
        sig.push_str(&hex12(&e.hash));
        sig.push(':');
        sig.push_str(if e.in_flight { "y:" } else { "n:" });
        sig.push_str(&e.answer_field());
    }
    sig
}

/// The 12-char lowercase hex prefix every identity on these surfaces uses —
/// `stipid=`, `fid=`, `sid=` are the same six bytes in the same spelling, so a
/// hash on this line can be grepped against them directly.
fn hex12(h: &Hash32) -> String {
    h[..6].iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs() -> AskSetObservation {
        AskSetObservation {
            armed: true,
            stuck_ms: 2_400_000,
            state_tip: 2693,
            state_tip_id: "c0b41b81c154".to_string(),
            lag: 21,
            off_main: true,
            fork_point: Some(2680),
            ask_set: 15,
            in_flight: 2,
            pending: 0,
            gate: RejoinGate::Missing(2681),
            mine: MineDuty::RefusedLag,
            mine_refusals: 41,
        }
    }

    fn entry(h: u64, answers: &[(u64, BodyAnswer)], asked: &[u64]) -> BodyAskEntry {
        let mut hash = [0u8; 32];
        hash[0] = h as u8;
        BodyAskEntry {
            hash,
            height: Some(h),
            outstanding_ms: 1_800_000,
            asks: 120,
            asked: asked.iter().map(|p| PeerId(*p)).collect(),
            answers: answers.iter().map(|(p, a)| (PeerId(*p), *a)).collect(),
            answers_dropped: 0,
            in_flight: true,
        }
    }

    /// A peer that was asked and said nothing is **listed**, because "three peers,
    /// none replied" and "one peer, don't-have" are different facts.
    #[test]
    fn an_asked_peer_that_never_answered_is_named_as_noreply() {
        let e = entry(2681, &[(1, BodyAnswer::HeaderOnly)], &[1, 2, 3]);
        assert_eq!(e.answer_field(), "p1:header-only,p2:noreply,p3:noreply");
    }

    #[test]
    fn an_ask_nobody_was_asked_for_and_nobody_answered_says_none() {
        let e = entry(2681, &[], &[]);
        assert_eq!(e.answer_field(), "none");
        assert!(e.to_line().ends_with(" ans=none"), "{}", e.to_line());
    }

    /// The summary line carries both derived quantities and the mining refusal,
    /// which are the three things no existing surface says.
    #[test]
    fn the_summary_carries_the_fork_point_the_ask_set_and_the_mining_refusal() {
        let line = obs().to_line();
        assert!(line.contains(" sfork=2680 "), "{line}");
        assert!(line.contains(" ask=15 breq=2 "), "the ask set is NOT breq: {line}");
        assert!(line.contains(" mine=refused-lag mrefuse=41 "), "{line}");
        assert!(line.contains(" gate=missing@2681 "), "{line}");
    }

    /// `sfork=none` is layer (a) in one field, and it must not print as a height.
    #[test]
    fn a_missing_fork_point_prints_none_and_not_a_number() {
        let mut o = obs();
        o.fork_point = None;
        o.gate = RejoinGate::NoForkPoint;
        assert!(o.to_line().contains(" sfork=none "), "{}", o.to_line());
        assert_eq!(o.telemetry_field(), "15@-");
    }

    /// **The rate limit, both halves.** A changed picture reports in full; an
    /// unchanged one is silent until the heartbeat.
    #[test]
    fn a_steady_stranding_reports_once_and_then_only_on_the_heartbeat() {
        let mut j = BodyWaitJournal::new();
        let o = obs();
        let e = vec![entry(2681, &[(1, BodyAnswer::HeaderOnly)], &[1])];
        let first = j.report(&o, &e, 0, 32_000, 15_000);
        assert_eq!(first.len(), 2, "summary + one entry: {first:?}");

        // Nothing changed and the heartbeat has not elapsed.
        assert!(j.report(&o, &e, 16_000, 32_000, 15_000).is_empty());
        // The heartbeat: the summary alone, not the entries.
        let beat = j.report(&o, &e, 40_000, 32_000, 15_000);
        assert_eq!(beat.len(), 1, "heartbeat is the summary only: {beat:?}");
    }

    /// A peer moving from silence to an answer is a transition worth a line.
    #[test]
    fn a_new_peer_answer_re_reports_in_full() {
        let mut j = BodyWaitJournal::new();
        let o = obs();
        let e1 = vec![entry(2681, &[], &[1])];
        assert_eq!(j.report(&o, &e1, 0, 32_000, 15_000).len(), 2);
        let e2 = vec![entry(2681, &[(1, BodyAnswer::DontHave)], &[1])];
        let second = j.report(&o, &e2, 16_000, 32_000, 15_000);
        assert_eq!(second.len(), 2, "the answer changed: {second:?}");
    }

    /// The floor: no amount of flapping exceeds one report per re-ask cycle.
    #[test]
    fn the_floor_bounds_a_flapping_picture_to_one_report_per_re_ask_cycle() {
        let mut j = BodyWaitJournal::new();
        let o = obs();
        let e1 = vec![entry(2681, &[], &[1])];
        let e2 = vec![entry(2681, &[(1, BodyAnswer::DontHave)], &[1])];
        assert_eq!(j.report(&o, &e1, 0, 32_000, 15_000).len(), 2);
        assert!(j.report(&o, &e2, 1_000, 32_000, 15_000).is_empty(), "inside the floor");
        assert!(j.report(&o, &e1, 2_000, 32_000, 15_000).is_empty(), "still inside it");
        assert!(!j.report(&o, &e2, 15_000, 32_000, 15_000).is_empty(), "and it opens again");
    }

    /// **The negative, at this layer.** A disarmed observation emits nothing, and
    /// re-arming reports in full rather than being deduplicated against the last
    /// stranding.
    #[test]
    fn a_disarmed_latch_is_silent_and_re_arming_reports_in_full() {
        let mut j = BodyWaitJournal::new();
        let o = obs();
        let e = vec![entry(2681, &[(1, BodyAnswer::HeaderOnly)], &[1])];
        assert_eq!(j.report(&o, &e, 0, 32_000, 15_000).len(), 2);
        let mut disarmed = o.clone();
        disarmed.armed = false;
        assert!(j.report(&disarmed, &e, 1_000, 32_000, 15_000).is_empty());
        let again = j.report(&o, &e, 2_000, 32_000, 15_000);
        assert_eq!(again.len(), 2, "the second stranding is reported in full: {again:?}");
    }
}
