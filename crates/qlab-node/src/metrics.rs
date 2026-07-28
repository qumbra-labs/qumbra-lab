//! **Structured metrics** — counters and histograms that are counters and histograms
//! *at the source* (issue #87).
//!
//! The 42 h T0 soak's headline numbers — block interval `mean 86 s / median 60 / p99
//! 312`, finality advance `median 673 / p90 1802 / max 3161`, `Degraded` 14.5–15.9 %,
//! `stall` peak 42 — were all reconstructed **after the fact by counting sampled
//! gauge prints**. That reconstruction is lossy in a way no amount of care at the
//! parsing end can undo: a printed gauge has already thrown away every value it held
//! between two prints. A p99 recovered from 30 s samples is a p99 of the samples, not
//! of the events.
//!
//! So every distribution here is a real [`Histogram`] fed **at the event**, and every
//! rate is a monotonic [`Counter`] incremented at the event:
//!
//! * `Degraded` share is [`Metrics::observe_regime`] — *seconds accumulated per
//!   regime*, not a fraction of samples that happened to be printed while degraded;
//! * block interval and finality advance are observed when a block connects and when
//!   finality moves, at full event resolution;
//! * time-to-quorum and per-vote arrival latency did not exist at all before this
//!   module — they are the round's own clock, and they are the quantities that say
//!   whether a stall is latency or participation.
//!
//! Gauges (tip, peers, mempool, …) stay gauges: they are levels, and a level's
//! current value is the whole of its meaning.
//!
//! ## Caliper (口径)
//! Every family below carries its window and basis in its `HELP` text, so a number
//! read off `/metrics` cannot be separated from how it was taken. Counters and
//! histograms are **since process start** (a restart resets them — deliberate, this
//! project counts restarts). Bucket bounds are chosen against the measured T0 numbers
//! and are named in the constants; they are **devnet-grade, tunable, NOT frozen**.
//!
//! ## Exposition
//! [`render`] emits Prometheus text exposition format v0.0.4. No floats are held in
//! the source of truth: durations are accumulated as integer milliseconds (or whole
//! seconds where the input is a block timestamp) and scaled only at render.

use std::collections::BTreeMap;

use crate::round::{RoundDiagnosis, RoundRecord, VoteRejects};

/// Time-to-quorum / vote-arrival buckets, in **milliseconds**.
/// Basis: measured T0 inter-node RTT 68–223 ms (baseline 2026-07-26), so a healthy
/// round completes in well under a second; the long tail out to 600 s covers a whole
/// round period (cadence 8 × 75 s).
pub const LATENCY_MS_BUCKETS: &[u64] =
    &[250, 500, 1_000, 2_000, 5_000, 10_000, 30_000, 60_000, 300_000, 600_000];

/// Distinct-vote-count buckets for a closed round, **unitless**.
/// Basis: frozen roster 21, quorum 15 — the bucket at 14 vs 15 is the one that
/// separates "one vote short" from "reached it".
pub const VOTE_COUNT_BUCKETS: &[u64] = &[0, 3, 6, 9, 12, 14, 15, 18, 21];

/// Block-interval buckets, in **whole seconds** of chain time.
/// Basis: 75 s target (FROZEN, read only); observed mean 86 / median 60 / p99 312.
pub const BLOCK_INTERVAL_SECS_BUCKETS: &[u64] =
    &[30, 45, 60, 75, 90, 120, 180, 300, 600, 1_200];

/// Finality-advance buckets, in **whole seconds** of chain time between successive
/// finalized checkpoints. Basis: nominal 690 s (8 × 86 s observed); observed median
/// 673, p90 1802, max 3161.
pub const FINALITY_ADVANCE_SECS_BUCKETS: &[u64] =
    &[600, 690, 900, 1_200, 1_800, 2_400, 3_600, 7_200];

/// Finality-advance buckets in **blocks**. Basis: cadence 8; the soak's 61-of-165
/// catch-up advances jumped 16/24/32/40 in one step, and that shape is invisible in a
/// seconds histogram alone.
pub const FINALITY_ADVANCE_BLOCKS_BUCKETS: &[u64] = &[8, 16, 24, 32, 40, 48, 64, 96];

/// Stall-depth-at-advance buckets, in **blocks**: how deep `tip − finalized` had
/// fallen at the moment finality moved again. Basis: `DEGRADED_MODE_LAG_BLOCKS = 16`
/// (FROZEN — read here, never written); observed peak 42.
pub const STALL_DEPTH_BUCKETS: &[u64] = &[4, 8, 12, 16, 24, 32, 40, 48, 64, 96];

/// A monotonic count since process start.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counter(u64);

impl Counter {
    /// Add one.
    pub fn inc(&mut self) {
        self.0 += 1;
    }
    /// Add `n`.
    pub fn add(&mut self, n: u64) {
        self.0 += n;
    }
    /// The current value.
    pub fn get(&self) -> u64 {
        self.0
    }
}

/// A cumulative-bucket histogram fed at the event.
///
/// `bounds` are inclusive upper bounds in the metric's storage unit; `divisor` scales
/// storage units to the exported unit at render time (1 for unitless/seconds, 1000
/// for milliseconds-stored-seconds-exported). Storing integers keeps floats out of
/// the source of truth entirely.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Histogram {
    bounds: &'static [u64],
    /// `bounds.len() + 1` per-bucket (not cumulative) counts; the last is `+Inf`.
    counts: Vec<u64>,
    sum: u64,
    count: u64,
    divisor: u64,
}

impl Histogram {
    /// A histogram over `bounds`, exported in units of `1/divisor` of the storage
    /// unit (`divisor = 1000` stores ms and exports seconds).
    pub fn new(bounds: &'static [u64], divisor: u64) -> Self {
        Self {
            bounds,
            counts: vec![0; bounds.len() + 1],
            sum: 0,
            count: 0,
            divisor: divisor.max(1),
        }
    }

    /// Record one observation.
    pub fn observe(&mut self, v: u64) {
        let idx = self.bounds.iter().position(|&b| v <= b).unwrap_or(self.bounds.len());
        self.counts[idx] += 1;
        self.sum = self.sum.saturating_add(v);
        self.count += 1;
    }

    /// Number of observations.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Sum of observations, in the storage unit.
    pub fn sum_raw(&self) -> u64 {
        self.sum
    }

    /// Cumulative count at or below `bound` (test/inspection hook).
    pub fn cumulative_at(&self, bound: u64) -> u64 {
        let mut acc = 0;
        for (i, &b) in self.bounds.iter().enumerate() {
            acc += self.counts[i];
            if b == bound {
                return acc;
            }
        }
        self.count
    }

    fn render_into(&self, out: &mut String, name: &str, help: &str) {
        out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} histogram\n"));
        let mut acc = 0u64;
        for (i, &b) in self.bounds.iter().enumerate() {
            acc += self.counts[i];
            out.push_str(&format!(
                "{name}_bucket{{le=\"{}\"}} {acc}\n",
                scaled(b, self.divisor)
            ));
        }
        acc += self.counts[self.bounds.len()];
        out.push_str(&format!("{name}_bucket{{le=\"+Inf\"}} {acc}\n"));
        out.push_str(&format!("{name}_sum {}\n", scaled(self.sum, self.divisor)));
        out.push_str(&format!("{name}_count {}\n", self.count));
    }
}

/// Render an integer storage value in its exported unit. Integer-only arithmetic —
/// no float ever holds a metric value on the way out.
fn scaled(v: u64, divisor: u64) -> String {
    if divisor <= 1 {
        v.to_string()
    } else {
        format!("{}.{:03}", v / divisor, v % divisor)
    }
}

/// Node-level gauges read live at render time. These are levels: a level's current
/// value is the whole of its meaning, so they are not accumulated here.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LiveGauges {
    /// Fork-choice tip height.
    pub tip_height: u64,
    /// Finalized head height, if any.
    pub finalized_height: Option<u64>,
    /// `tip − finalized` (or `tip` when nothing is finalized) — the same rule the
    /// telemetry wire uses, read from it rather than re-derived.
    pub stall_depth: u64,
    /// Ebb-and-Flow / halt regime token (`final|degraded|halting|halted`).
    pub regime: &'static str,
    /// Difficulty of the tip block (the LWMA retarget trace).
    pub difficulty: u64,
    /// Connected peers.
    pub peers: u64,
    /// Dialable / known addresses (the NAT re-open trigger, issue #83).
    pub dialable: u64,
    /// Known addresses.
    pub known: u64,
    /// Mempool size.
    pub mempool: u64,
    /// Current committee epoch.
    pub epoch: u64,
    /// Roster size of the current committee.
    pub committee_size: u64,
    /// Active members of the current committee (roster minus tombstoned/jailed).
    pub committee_active: u64,
    /// Quorum threshold now in force.
    pub quorum: u64,
    /// Currently-open checkpoint rounds in the ledger.
    pub open_rounds: u64,
    /// The scheduled halt height, if this release carries one (issue #74).
    pub halt_at: Option<u64>,
    /// Unix seconds when the process started.
    pub process_start_secs: u64,
    /// Unix seconds this snapshot was rendered — a scraper reads staleness from it
    /// without having to trust the scrape's own clock.
    pub rendered_at_secs: u64,
}

/// All regime tokens, pre-declared so every series exists from the first scrape (an
/// alert cannot be written against a counter that only appears after the first
/// failure).
pub const REGIMES: [&str; 4] = ["final", "degraded", "halting", "halted"];

/// Vote-outcome tokens for `qumbra_checkpoint_votes_total`.
pub const VOTE_RESULTS: [&str; 5] = ["counted", "inactive", "forged", "unknown_signer", "duplicate"];

/// The node's accumulated metric state. Owned by the node adapter (which is where
/// the events happen) and rendered on demand.
#[derive(Clone, Debug)]
pub struct Metrics {
    // ---- checkpoint rounds ------------------------------------------------
    rounds_total: BTreeMap<&'static str, Counter>,
    votes_total: BTreeMap<&'static str, Counter>,
    signer_signed: BTreeMap<usize, Counter>,
    signer_absent: BTreeMap<usize, Counter>,
    time_to_quorum: Histogram,
    vote_arrival: Histogram,
    round_votes: Histogram,
    round_variants_total: Counter,
    // ---- chain ------------------------------------------------------------
    blocks_connected: Counter,
    block_interval: Histogram,
    finality_advances: Counter,
    finality_advance_secs: Histogram,
    finality_advance_blocks: Histogram,
    stall_depth_at_advance: Histogram,
    // ---- regime residency --------------------------------------------------
    regime_ms: BTreeMap<&'static str, u64>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    /// A fresh registry with every labelled series pre-declared at zero.
    pub fn new() -> Self {
        let mut rounds_total = BTreeMap::new();
        for d in RoundDiagnosis::ALL {
            rounds_total.insert(d.as_str(), Counter::default());
        }
        let mut votes_total = BTreeMap::new();
        for r in VOTE_RESULTS {
            votes_total.insert(r, Counter::default());
        }
        let mut regime_ms = BTreeMap::new();
        for r in REGIMES {
            regime_ms.insert(r, 0u64);
        }
        Self {
            rounds_total,
            votes_total,
            signer_signed: BTreeMap::new(),
            signer_absent: BTreeMap::new(),
            time_to_quorum: Histogram::new(LATENCY_MS_BUCKETS, 1_000),
            vote_arrival: Histogram::new(LATENCY_MS_BUCKETS, 1_000),
            round_votes: Histogram::new(VOTE_COUNT_BUCKETS, 1),
            round_variants_total: Counter::default(),
            blocks_connected: Counter::default(),
            block_interval: Histogram::new(BLOCK_INTERVAL_SECS_BUCKETS, 1),
            finality_advances: Counter::default(),
            finality_advance_secs: Histogram::new(FINALITY_ADVANCE_SECS_BUCKETS, 1),
            finality_advance_blocks: Histogram::new(FINALITY_ADVANCE_BLOCKS_BUCKETS, 1),
            stall_depth_at_advance: Histogram::new(STALL_DEPTH_BUCKETS, 1),
            regime_ms,
        }
    }

    /// Pre-declare the per-signer series for a roster of `n`, so `signer="7"` exists
    /// from the first scrape rather than appearing the first time member 7 misses a
    /// round. Idempotent.
    pub fn declare_roster(&mut self, n: usize) {
        for i in 0..n {
            self.signer_signed.entry(i).or_default();
            self.signer_absent.entry(i).or_default();
        }
    }

    /// Accumulate residency in `regime` for `ms` of wall time. This is how the
    /// `Degraded` share becomes a measured quantity instead of a count of samples.
    pub fn observe_regime(&mut self, regime: &'static str, ms: u64) {
        if let Some(slot) = self.regime_ms.get_mut(regime) {
            *slot += ms;
        }
    }

    /// Record the votes in one ingested message: `counted_new` newly-counting signers
    /// plus whatever was rejected, by reason.
    pub fn observe_votes(&mut self, counted_new: u64, rejects: VoteRejects) {
        if let Some(c) = self.votes_total.get_mut("counted") {
            c.add(counted_new);
        }
        for (key, n) in [
            ("inactive", rejects.inactive),
            ("forged", rejects.forged),
            ("unknown_signer", rejects.unknown_signer),
            ("duplicate", rejects.duplicate),
        ] {
            if n > 0 {
                if let Some(c) = self.votes_total.get_mut(key) {
                    c.add(n as u64);
                }
            }
        }
    }

    /// Record the arrival offset (ms from round open) of one newly-counting vote.
    pub fn observe_vote_arrival(&mut self, offset_ms: u64) {
        self.vote_arrival.observe(offset_ms);
    }

    /// Fold one **closed** round into the aggregates: its verdict, its vote count,
    /// its time-to-quorum, and per-member signed/absent participation.
    pub fn observe_round(&mut self, r: &RoundRecord) {
        if let Some(c) = self.rounds_total.get_mut(r.diagnose().as_str()) {
            c.inc();
        }
        self.round_votes.observe(r.have() as u64);
        if let Some(q) = r.quorum_ms {
            self.time_to_quorum.observe(q);
        }
        if r.variants > 1 {
            self.round_variants_total.inc();
        }
        self.declare_roster(r.roster);
        for i in &r.voted {
            self.signer_signed.entry(*i).or_default().inc();
        }
        for i in r.absent() {
            self.signer_absent.entry(i).or_default().inc();
        }
    }

    /// Record a connected block and the chain-time gap to its parent.
    pub fn observe_block(&mut self, interval_secs: u64) {
        self.blocks_connected.inc();
        self.block_interval.observe(interval_secs);
    }

    /// Record a finality advance: `blocks` of height, `secs` of chain time (when the
    /// two checkpoint blocks' timestamps are both known locally), and the stall depth
    /// it was carrying at that moment.
    pub fn observe_finality_advance(&mut self, blocks: u64, secs: Option<u64>, stall_depth: u64) {
        self.finality_advances.inc();
        self.finality_advance_blocks.observe(blocks);
        if let Some(s) = secs {
            self.finality_advance_secs.observe(s);
        }
        self.stall_depth_at_advance.observe(stall_depth);
    }

    /// Rounds closed by verdict (test/inspection hook).
    pub fn rounds_by_verdict(&self, verdict: RoundDiagnosis) -> u64 {
        self.rounds_total.get(verdict.as_str()).map_or(0, |c| c.get())
    }

    /// Votes counted/rejected by result (test/inspection hook).
    pub fn votes_by_result(&self, result: &str) -> u64 {
        self.votes_total.get(result).map_or(0, |c| c.get())
    }

    /// Accumulated milliseconds in `regime` (test/inspection hook).
    pub fn regime_ms(&self, regime: &str) -> u64 {
        self.regime_ms.get(regime).copied().unwrap_or(0)
    }

    /// The time-to-quorum histogram (test/inspection hook).
    pub fn time_to_quorum(&self) -> &Histogram {
        &self.time_to_quorum
    }

    /// The block-interval histogram (test/inspection hook).
    pub fn block_interval(&self) -> &Histogram {
        &self.block_interval
    }
}

/// Render the full exposition text for a scrape.
///
/// Label values here are static tokens and decimal integers only — no operator- or
/// peer-supplied string ever becomes a label, so no escaping is needed and label
/// cardinality is bounded by the committee roster (a consensus quantity), never by
/// anything an attacker can send.
pub fn render(m: &Metrics, g: &LiveGauges) -> String {
    let mut o = String::with_capacity(8 * 1024);

    // ---- rounds -----------------------------------------------------------
    o.push_str(
        "# HELP qumbra_checkpoint_rounds_total Checkpoint rounds CLOSED since process start, by verdict. \
A round is one cadence slot; it closes when it finalizes, when a later slot finalizes past it (superseded), \
or when the open-round cap evicts it.\n\
# TYPE qumbra_checkpoint_rounds_total counter\n",
    );
    for (label, c) in &m.rounds_total {
        o.push_str(&format!(
            "qumbra_checkpoint_rounds_total{{verdict=\"{label}\"}} {}\n",
            c.get()
        ));
    }

    o.push_str(
        "# HELP qumbra_checkpoint_votes_total Checkpoint votes SEEN since process start, by how they were \
judged. counted = distinct in-roster active signers newly accumulated; inactive = valid but \
tombstoned/jailed (excluded by frozen rule, not misbehaviour); forged/unknown_signer/duplicate = rejected.\n\
# TYPE qumbra_checkpoint_votes_total counter\n",
    );
    for (label, c) in &m.votes_total {
        o.push_str(&format!(
            "qumbra_checkpoint_votes_total{{result=\"{label}\"}} {}\n",
            c.get()
        ));
    }

    o.push_str(
        "# HELP qumbra_committee_signed_rounds_total Rounds CLOSED at this node in which committee member \
`signer` had a counting vote. Denominator is qumbra_checkpoint_rounds_total (all verdicts summed).\n\
# TYPE qumbra_committee_signed_rounds_total counter\n",
    );
    for (i, c) in &m.signer_signed {
        o.push_str(&format!(
            "qumbra_committee_signed_rounds_total{{signer=\"{i}\"}} {}\n",
            c.get()
        ));
    }
    o.push_str(
        "# HELP qumbra_committee_absent_rounds_total Rounds CLOSED at this node in which member `signer` was \
in the roster, not tombstoned/jailed, and no vote of theirs had reached THIS node. Reach, not proof of \
downtime: a different node may record a different absentee set for the same round.\n\
# TYPE qumbra_committee_absent_rounds_total counter\n",
    );
    for (i, c) in &m.signer_absent {
        o.push_str(&format!(
            "qumbra_committee_absent_rounds_total{{signer=\"{i}\"}} {}\n",
            c.get()
        ));
    }

    o.push_str(&format!(
        "# HELP qumbra_checkpoint_split_rounds_total Rounds in which more than one checkpoint VARIANT was \
seen at the same height (a split committee — a different failure from being short of votes).\n\
# TYPE qumbra_checkpoint_split_rounds_total counter\nqumbra_checkpoint_split_rounds_total {}\n",
        m.round_variants_total.get()
    ));

    m.time_to_quorum.render_into(
        &mut o,
        "qumbra_checkpoint_time_to_quorum_seconds",
        "Wall-clock seconds from THIS node opening a round to the accumulated distinct active vote count \
first reaching quorum. Observed only on rounds that reached quorum. Node-local clock; not comparable \
across hosts.",
    );
    m.vote_arrival.render_into(
        &mut o,
        "qumbra_checkpoint_vote_arrival_seconds",
        "Wall-clock seconds from THIS node opening a round to each newly-counting vote arriving. One \
observation per distinct signer per round. Node-local clock.",
    );
    m.round_votes.render_into(
        &mut o,
        "qumbra_checkpoint_round_votes",
        "Distinct counting signers accumulated at THIS node when a round closed, all verdicts. Compare \
against the quorum gauge qumbra_committee_quorum.",
    );

    // ---- chain ------------------------------------------------------------
    o.push_str(&format!(
        "# HELP qumbra_blocks_connected_total Blocks connected to this node's tip since process start.\n\
# TYPE qumbra_blocks_connected_total counter\nqumbra_blocks_connected_total {}\n",
        m.blocks_connected.get()
    ));
    m.block_interval.render_into(
        &mut o,
        "qumbra_block_interval_seconds",
        "CHAIN-time seconds between a connected block and its parent (header timestamps, not wall clock). \
Target is 75 s (FROZEN, read only).",
    );
    o.push_str(&format!(
        "# HELP qumbra_finality_advances_total Times the finalized head moved since process start.\n\
# TYPE qumbra_finality_advances_total counter\nqumbra_finality_advances_total {}\n",
        m.finality_advances.get()
    ));
    m.finality_advance_secs.render_into(
        &mut o,
        "qumbra_finality_advance_seconds",
        "CHAIN-time seconds between successive finalized checkpoints (their blocks' header timestamps). \
Observed only when both blocks are known locally.",
    );
    m.finality_advance_blocks.render_into(
        &mut o,
        "qumbra_finality_advance_blocks",
        "Height jumped by one finality advance. Cadence is 8, so anything above 8 is a catch-up over slots \
that never finalized — read those slots' ROUND journal lines for why.",
    );
    m.stall_depth_at_advance.render_into(
        &mut o,
        "qumbra_finality_stall_depth_blocks",
        "tip − finalized at the instant finality advanced: how deep the stall had gone before it cleared. \
Sampled at the EVENT, so it is not a re-derivation of the stall gauge.",
    );

    // ---- regime residency --------------------------------------------------
    o.push_str(
        "# HELP qumbra_finality_regime_seconds_total Wall-clock seconds accumulated in each finality regime \
since process start. This is the measured Degraded share; it is NOT a fraction of printed samples.\n\
# TYPE qumbra_finality_regime_seconds_total counter\n",
    );
    for r in REGIMES {
        o.push_str(&format!(
            "qumbra_finality_regime_seconds_total{{regime=\"{r}\"}} {}\n",
            scaled(m.regime_ms.get(r).copied().unwrap_or(0), 1_000)
        ));
    }

    // ---- live gauges ------------------------------------------------------
    let gauges: [(&str, &str, u64); 12] = [
        ("qumbra_tip_height", "Fork-choice tip height.", g.tip_height),
        (
            "qumbra_finalized_height",
            "Finalized head height. Absent (no series) when nothing is finalized — never 0-as-unknown.",
            g.finalized_height.unwrap_or(0),
        ),
        (
            "qumbra_stall_depth_blocks",
            "tip − finalized right now (or tip when nothing is finalized). Degraded fires above \
DEGRADED_MODE_LAG_BLOCKS = 16 (FROZEN, read only).",
            g.stall_depth,
        ),
        ("qumbra_tip_difficulty", "PoW difficulty of the tip block (the LWMA retarget trace).", g.difficulty),
        ("qumbra_peers", "Connected peers.", g.peers),
        ("qumbra_addrs_dialable", "Addresses in the book believed dialable (issue #83 NAT trigger).", g.dialable),
        ("qumbra_addrs_known", "Addresses in the book.", g.known),
        ("qumbra_mempool_size", "Transactions in the mempool.", g.mempool),
        ("qumbra_committee_epoch", "Current committee epoch.", g.epoch),
        ("qumbra_committee_size", "Roster size of the current committee.", g.committee_size),
        ("qumbra_committee_active", "Roster minus tombstoned/jailed, right now.", g.committee_active),
        ("qumbra_committee_quorum", "Quorum threshold in force (⅔ rule; read, never re-derived).", g.quorum),
    ];
    for (name, help, v) in gauges {
        if name == "qumbra_finalized_height" && g.finalized_height.is_none() {
            // Deliberately emit no series rather than a zero that reads as height 0.
            o.push_str(&format!("# HELP {name} {help}\n# TYPE {name} gauge\n"));
            continue;
        }
        o.push_str(&format!("# HELP {name} {help}\n# TYPE {name} gauge\n{name} {v}\n"));
    }

    o.push_str(&format!(
        "# HELP qumbra_open_rounds Checkpoint rounds currently open in the diagnostics ledger.\n\
# TYPE qumbra_open_rounds gauge\nqumbra_open_rounds {}\n",
        g.open_rounds
    ));
    o.push_str("# HELP qumbra_halt_height Scheduled halt height of this release (issue #74). No series when \
this release carries no halt.\n# TYPE qumbra_halt_height gauge\n");
    if let Some(h) = g.halt_at {
        o.push_str(&format!("qumbra_halt_height {h}\n"));
    }
    o.push_str(
        "# HELP qumbra_finality_regime Current regime, one-hot: the series with value 1 is the live one.\n\
# TYPE qumbra_finality_regime gauge\n",
    );
    for r in REGIMES {
        o.push_str(&format!(
            "qumbra_finality_regime{{regime=\"{r}\"}} {}\n",
            u8::from(r == g.regime)
        ));
    }
    o.push_str(&format!(
        "# HELP qumbra_process_start_time_seconds Unix time this process started. A change in this value \
IS a restart — the property the T0 evidence pack counts.\n\
# TYPE qumbra_process_start_time_seconds gauge\nqumbra_process_start_time_seconds {}\n",
        g.process_start_secs
    ));
    o.push_str(&format!(
        "# HELP qumbra_metrics_rendered_timestamp_seconds Unix time this snapshot was rendered. The node \
renders on its own cadence and serves the last snapshot, so a scraper reads staleness from here rather \
than assuming scrape time.\n\
# TYPE qumbra_metrics_rendered_timestamp_seconds gauge\nqumbra_metrics_rendered_timestamp_seconds {}\n",
        g.rendered_at_secs
    ));
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::round::{ObsClock, RoundLedger, SlotContext, VoteRejects};

    fn gauges() -> LiveGauges {
        LiveGauges {
            tip_height: 1_392,
            finalized_height: Some(1_352),
            stall_depth: 40,
            regime: "degraded",
            difficulty: 1_234,
            peers: 3,
            dialable: 3,
            known: 4,
            mempool: 0,
            epoch: 1,
            committee_size: 21,
            committee_active: 21,
            quorum: 15,
            open_rounds: 2,
            halt_at: None,
            process_start_secs: 1_769_000_000,
            rendered_at_secs: 1_769_150_000,
        }
    }

    /// Buckets are cumulative and monotone, the `+Inf` bucket equals `_count`, and
    /// the exported unit is scaled from integer storage — the properties a Prometheus
    /// consumer relies on.
    #[test]
    fn histogram_renders_cumulative_monotone_buckets() {
        let mut h = Histogram::new(LATENCY_MS_BUCKETS, 1_000);
        for v in [100, 300, 300, 1_500, 90_000, 10_000_000] {
            h.observe(v);
        }
        assert_eq!(h.count(), 6);
        assert_eq!(h.cumulative_at(250), 1);
        assert_eq!(h.cumulative_at(500), 3);
        assert_eq!(h.cumulative_at(2_000), 4);

        let mut out = String::new();
        h.render_into(&mut out, "test_seconds", "help");
        let mut last = 0u64;
        for line in out.lines().filter(|l| l.contains("_bucket{")) {
            let n: u64 = line.rsplit(' ').next().unwrap().parse().unwrap();
            assert!(n >= last, "buckets must be cumulative: {out}");
            last = n;
        }
        assert!(out.contains("test_seconds_bucket{le=\"0.250\"} 1"));
        assert!(out.contains("test_seconds_bucket{le=\"+Inf\"} 6"));
        assert!(out.contains("test_seconds_count 6"));
        // sum = 10,092,200 ms → 10092.200 s, from integer arithmetic only.
        assert!(out.contains("test_seconds_sum 10092.200"), "{out}");
    }

    /// The Degraded share is a measured residency, not a fraction of samples: two
    /// ticks of 30 s in Degraded and one in Final give exactly 60/30 s.
    #[test]
    fn regime_residency_is_accumulated_not_sampled() {
        let mut m = Metrics::new();
        m.observe_regime("degraded", 30_000);
        m.observe_regime("degraded", 30_000);
        m.observe_regime("final", 30_000);
        assert_eq!(m.regime_ms("degraded"), 60_000);
        assert_eq!(m.regime_ms("final"), 30_000);
        let text = render(&m, &gauges());
        assert!(text.contains("qumbra_finality_regime_seconds_total{regime=\"degraded\"} 60.000"));
        assert!(text.contains("qumbra_finality_regime_seconds_total{regime=\"halted\"} 0.000"), "pre-declared");
    }

    /// Every labelled series exists at zero from the first scrape — an alert must be
    /// writable before the first failure, not after it.
    #[test]
    fn every_series_is_predeclared_and_shaped_for_prometheus() {
        let mut m = Metrics::new();
        m.declare_roster(21);
        let text = render(&m, &gauges());
        for verdict in RoundDiagnosis::ALL {
            assert!(
                text.contains(&format!("qumbra_checkpoint_rounds_total{{verdict=\"{}\"}} 0", verdict.as_str())),
                "missing verdict series {}",
                verdict.as_str()
            );
        }
        for r in VOTE_RESULTS {
            assert!(text.contains(&format!("qumbra_checkpoint_votes_total{{result=\"{r}\"}} 0")));
        }
        assert!(text.contains("qumbra_committee_absent_rounds_total{signer=\"20\"} 0"));
        assert!(text.contains("qumbra_finality_regime{regime=\"degraded\"} 1"));
        assert!(text.contains("qumbra_finality_regime{regime=\"final\"} 0"));
        // Every family declares HELP and TYPE, and no metric line is emitted without
        // a preceding TYPE for its family.
        let types: Vec<&str> = text
            .lines()
            .filter(|l| l.starts_with("# TYPE "))
            .map(|l| l.split(' ').nth(2).unwrap())
            .collect();
        assert!(types.contains(&"qumbra_checkpoint_time_to_quorum_seconds"));
        for line in text.lines().filter(|l| l.starts_with("qumbra_")) {
            let name = line.split(['{', ' ']).next().unwrap();
            let family = name
                .trim_end_matches("_bucket")
                .trim_end_matches("_sum")
                .trim_end_matches("_count");
            assert!(
                types.contains(&family) || types.contains(&name),
                "series {name} has no TYPE declaration"
            );
        }
    }

    /// `finalized_height` at cold start emits **no series** rather than 0 — the
    /// PR #72 S8 lesson (`age_s=-`, never `age_s=0`) applied to the metrics surface.
    #[test]
    fn nothing_finalized_emits_no_finalized_height_series() {
        let m = Metrics::new();
        let mut g = gauges();
        g.finalized_height = None;
        let text = render(&m, &g);
        assert!(text.contains("# TYPE qumbra_finalized_height gauge"));
        assert!(
            !text.lines().any(|l| l.starts_with("qumbra_finalized_height ")),
            "a never-finalized node must not report height 0 as finalized"
        );
    }

    /// A closed round folds into the aggregates exactly once, and per-member
    /// participation splits into signed vs absent.
    #[test]
    fn closed_round_folds_into_verdict_and_member_counters() {
        let mut l = RoundLedger::new(ObsClock::Deterministic);
        let c = SlotContext { height: 8, epoch: 1, roster: 21, active: 21, need: 15 };
        l.note_votes(&c, &(0..11).collect::<Vec<_>>(), &[], VoteRejects::default(), 1);
        l.note_finalized(16); // slot 8 superseded, unfinalized

        let mut m = Metrics::new();
        for r in l.take_emitted() {
            m.observe_round(&r);
        }
        assert_eq!(m.rounds_by_verdict(RoundDiagnosis::Unclassified), 1, "no clock ⇒ no cause invented");
        let text = render(&m, &gauges());
        assert!(text.contains("qumbra_committee_signed_rounds_total{signer=\"0\"} 1"));
        assert!(text.contains("qumbra_committee_absent_rounds_total{signer=\"11\"} 1"));
        assert!(text.contains("qumbra_committee_absent_rounds_total{signer=\"0\"} 0"));
    }

    /// The soak's headline distributions are recoverable at full event resolution —
    /// which is what "a histogram at the source" buys over sampled gauges.
    #[test]
    fn event_fed_histograms_carry_the_soak_quantities() {
        let mut m = Metrics::new();
        for secs in [60, 60, 75, 86, 312, 60, 90] {
            m.observe_block(secs);
        }
        assert_eq!(m.block_interval().count(), 7);
        assert_eq!(m.block_interval().cumulative_at(60), 3, "the three at-median blocks");
        assert_eq!(m.block_interval().cumulative_at(75), 4, "the 75 s target bucket");
        assert_eq!(m.block_interval().cumulative_at(300), 6, "the p99 tail is its own bucket");

        m.observe_finality_advance(8, Some(673), 8);
        m.observe_finality_advance(40, Some(3_161), 40);
        let text = render(&m, &gauges());
        assert!(text.contains("qumbra_finality_advance_blocks_bucket{le=\"8\"} 1"));
        assert!(text.contains("qumbra_finality_advance_blocks_bucket{le=\"40\"} 2"), "the catch-up jump");
        assert!(text.contains("qumbra_finality_stall_depth_blocks_bucket{le=\"40\"} 2"));
    }
}
