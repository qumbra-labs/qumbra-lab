//! **The `LOOP` journal — where the main loop's period actually goes** (issue
//! #107 S1).
//!
//! `sample_interval` is 30 s and the telemetry emit is a check at the *bottom*
//! of the main loop, so 30 s is a floor on the gap between two `TELEMETRY`
//! lines and never a cadence: the line appears the next time the loop gets
//! there. `t0-wan-1` reached that floor constantly; every image since has never
//! come in below ~131 s across 53 samples on four hosts, and three separate
//! hypotheses about why were argued from the outside — two of them refuted by
//! measurement, one still unproven — because the gap is the only number anyone
//! had.
//!
//! This is the instrument that makes the gap decomposable. One iteration is
//! timed phase by phase; the pump's own share arrives already split by
//! [`qlab_p2p::ticktime::TickTimings`]. **One degraded sample now attributes
//! itself.**
//!
//! ## Emission policy, and why it is not one line per iteration
//!
//! A quiescent iteration ends in a 20 ms sleep, so the loop turns ~50×/s and a
//! line per iteration would be ~4 M lines/day/host. Two lines instead, both to
//! stdout beside `TELEMETRY` and `ROUND` (the #87 discipline: the container log
//! is what is archived and cited, and unlike a scrape target it needs no
//! inbound rule to reach):
//!
//! - **`LOOP kind=slow`** — one iteration exceeded [`SLOW_ITERATION_MS`],
//!   carrying that iteration's whole breakdown. This is the line that would
//!   have ended this issue in July: a 131 s iteration prints a 131 s phase
//!   beside its name. Capped at [`MAX_SLOW_LINES_PER_WINDOW`] per telemetry
//!   window, with the suppressed count carried on the window line, so a
//!   pathologically slow node degrades the journal by a bounded amount instead
//!   of drowning it.
//! - **`LOOP kind=window`** — one aggregate per telemetry sample, always. The
//!   degraded population was *steadily* slow rather than spiking (min 131 s,
//!   median 158–185 s — there is no quiet baseline in it to spike away from),
//!   and a threshold-only instrument would have printed the same thing on a
//!   healthy node and a 3–6× degraded one if the threshold sat above both.
//!
//! **Not `/metrics`.** `metrics_addr` is `Option<String>`, unset by default and
//! unset on every T0 host, so a counter there would reproduce exactly the
//! defect #229 recorded: a condition reported only to a surface nobody has
//! bound. The journal is the load-bearing surface; a scrape gauge can follow if
//! a collector ever exists.
//!
//! ## Units
//!
//! Every duration on both lines is **milliseconds to one decimal**, declared by
//! `unit=ms` on the line itself. Fields are fixed and always present, including
//! zeros — `TELEMETRY`'s own rule, so an `awk` over an archive does not have to
//! discover the schema per line.

use std::time::{Duration, Instant};

use qlab_p2p::ticktime::TickTimings;

/// An iteration at or above this is journalled on its own. One second is far
/// above anything a healthy iteration does (the loop's own floor is a 20 ms
/// idle sleep) and far below the ~131 s this issue is about, so the line is
/// silent on a healthy node without being blind to a mild regression.
///
/// A **mining** iteration legitimately reaches it — `try_mine` runs RandomX
/// synchronously on this thread — and that is deliberate: mining cost per
/// attempt was on July's instrumentation list and has never been measured on a
/// host. It is bounded by `mine_interval`, so it costs ~1 line per 75 s.
pub const SLOW_ITERATION_MS: u64 = 1_000;

/// Cap on `LOOP kind=slow` lines per telemetry window. Beyond this the count is
/// carried on the window line as `slowsup=`, so the fact is kept and the volume
/// is not.
///
/// **Eight, and the number comes from the live sampler rather than from taste.**
/// `qumbra-ops/t0-sampler.sh` reads each host with
/// `docker logs --tail 60 | grep TELEMETRY | tail -1`, and an empty result is
/// logged as `UNREACHABLE-OR-SILENT` — so any line this node adds competes with
/// `TELEMETRY` for that 60-line window, and a node that talked too much would
/// be reported as *down*. At eight, one window costs at most ~10 lines
/// (8 slow + 1 window + 1 `TELEMETRY`), so `TELEMETRY` stays five windows deep
/// in the tail even while a node is degraded, with room left for `ROUND` and
/// `BODYWAIT`. Eight consecutive slow iterations characterise a degraded node;
/// the ninth is volume, and it is counted rather than printed.
pub const MAX_SLOW_LINES_PER_WINDOW: u64 = 8;

/// Per-phase durations for one iteration of the node's main loop.
///
/// The phases are the loop's own statements, in order. `pump` is
/// [`qlab_p2p::P2pNode::tick`] and carries its own six-way split in `tick`;
/// `sleep` is the idle back-off and is the one phase that is *not* work.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LoopPhases {
    /// `step_once` — the transport pump. Split further by `tick`.
    pub pump: Duration,
    /// The #87/#162/#204/#229 journal emitters plus regime accounting.
    pub journal: Duration,
    /// `try_mine` + `try_checkpoint` — synchronous RandomX when it runs.
    pub mine: Duration,
    /// `maintain_boundary_checkpoint` (#360).
    pub boundary: Duration,
    /// `/metrics` snapshot render, when a listener is bound.
    pub metrics: Duration,
    /// Discovery/leaf/anchor refresh, when a discovery server is bound.
    pub discovery: Duration,
    /// `drain_remote_submits` — the submitter queue.
    pub submit: Duration,
    /// `/v1/telemetry` snapshot render, when a listener is bound.
    ///
    /// The field is `telsrv=` on the wire, not `telemetry=`: every archived
    /// reader of these logs greps for the string `TELEMETRY`, and one of them
    /// (`qumbra-ops/t0-sampler.sh`) treats a miss as a node being down. A
    /// case-insensitive grep anywhere in that chain would have matched this
    /// field and returned a `LOOP` line where a `TELEMETRY` line was expected.
    pub telsrv: Duration,
    /// The `TELEMETRY` line itself + overdue rounds + the halt marker.
    pub sample: Duration,
    /// `maintain_peers` — the dial pass (#83).
    pub maintain: Duration,
    /// `maintain_snapshot` — the #359 snapshot cadence, an fsync when it fires.
    pub snapshot: Duration,
    /// The co-resident `on_tick` hook (#123, the in-process faucet).
    pub hook: Duration,
    /// The idle back-off. Not work — excluded from [`Self::busy`].
    pub sleep: Duration,
    /// The pump's own split.
    pub tick: TickTimings,
}

impl LoopPhases {
    /// The twelve work phases in run order. `sleep` is deliberately absent.
    fn work(&self) -> [(&'static str, Duration); 12] {
        [
            ("pump", self.pump),
            ("journal", self.journal),
            ("mine", self.mine),
            ("boundary", self.boundary),
            ("metrics", self.metrics),
            ("discovery", self.discovery),
            ("submit", self.submit),
            ("telsrv", self.telsrv),
            ("sample", self.sample),
            ("maintain", self.maintain),
            ("snapshot", self.snapshot),
            ("hook", self.hook),
        ]
    }

    /// Time this iteration spent doing something.
    pub fn busy(&self) -> Duration {
        self.work().iter().map(|(_, d)| *d).sum()
    }

    /// Wall time for the whole iteration, idle back-off included.
    pub fn total(&self) -> Duration {
        self.busy() + self.sleep
    }

    /// **The attribution**: the phase that dominated this iteration. When that
    /// phase is the pump, the answer descends into the tick's own split, so the
    /// name is `pump.dispatch` rather than `pump` — which is the difference
    /// between "it was in the network layer" and an answer.
    ///
    /// Ties go to the earlier phase in run order.
    pub fn worst(&self) -> (String, Duration) {
        let mut worst = ("idle", Duration::ZERO);
        for (name, d) in self.work() {
            if d > worst.1 {
                worst = (name, d);
            }
        }
        if worst.0 == "pump" {
            let (sub, d) = self.tick.worst();
            return (format!("pump.{sub}"), d);
        }
        (worst.0.to_string(), worst.1)
    }

    /// Fold another iteration in (window accumulation).
    pub fn add(&mut self, o: &LoopPhases) {
        self.pump += o.pump;
        self.journal += o.journal;
        self.mine += o.mine;
        self.boundary += o.boundary;
        self.metrics += o.metrics;
        self.discovery += o.discovery;
        self.submit += o.submit;
        self.telsrv += o.telsrv;
        self.sample += o.sample;
        self.maintain += o.maintain;
        self.snapshot += o.snapshot;
        self.hook += o.hook;
        self.sleep += o.sleep;
        self.tick.add(&o.tick);
    }

    /// The shared field tail both lines carry, so one `awk` reads either.
    fn fields(&self) -> String {
        let mut s = String::new();
        for (name, d) in self.work() {
            s.push_str(&format!("{name}={} ", ms(d)));
        }
        s.push_str(&format!("sleep={}", ms(self.sleep)));
        for (name, d) in self.tick.phases() {
            s.push_str(&format!(" {name}={}", ms(d)));
        }
        // The overlay, named so nobody adds it into the total: it is time
        // already inside `dispatch` and `sync`.
        s.push_str(&format!(" send*={}", ms(self.tick.send)));
        s
    }
}

/// Milliseconds to one decimal — the unit both `LOOP` lines declare.
fn ms(d: Duration) -> String {
    format!("{:.1}", d.as_secs_f64() * 1000.0)
}

/// Accumulates iterations into the two `LOOP` lines.
///
/// Owned by the run loop; holds no clock of its own beyond the window start, so
/// a test can drive it with synthetic [`LoopPhases`] and get byte-identical
/// lines to a live node's.
pub struct LoopJournal {
    window: LoopPhases,
    iterations: u64,
    /// The worst single iteration in this window, by busy time.
    worst: LoopPhases,
    slow_emitted: u64,
    slow_suppressed: u64,
    threshold: Duration,
    window_started: Instant,
}

impl Default for LoopJournal {
    fn default() -> Self {
        Self::new()
    }
}

impl LoopJournal {
    pub fn new() -> Self {
        LoopJournal {
            window: LoopPhases::default(),
            iterations: 0,
            worst: LoopPhases::default(),
            slow_emitted: 0,
            slow_suppressed: 0,
            threshold: Duration::from_millis(SLOW_ITERATION_MS),
            window_started: Instant::now(),
        }
    }

    /// Re-tune the slow threshold (tests / testnet). Programmatic rather than a
    /// config key, following [`qlab_p2p::P2pNode::set_rate_limits`]: this
    /// number should move because a measurement said so.
    pub fn set_threshold(&mut self, d: Duration) {
        self.threshold = d;
    }

    /// Fold one iteration in. Returns the `LOOP kind=slow` line when this
    /// iteration tripped the threshold and the window's cap has room.
    ///
    /// The iteration is accumulated either way — suppression drops the *line*,
    /// never the measurement.
    pub fn note(&mut self, p: &LoopPhases) -> Option<String> {
        self.iterations += 1;
        self.window.add(p);
        if p.busy() > self.worst.busy() {
            self.worst = *p;
        }
        if p.busy() < self.threshold {
            return None;
        }
        if self.slow_emitted >= MAX_SLOW_LINES_PER_WINDOW {
            self.slow_suppressed += 1;
            return None;
        }
        self.slow_emitted += 1;
        let (phase, d) = p.worst();
        Some(format!(
            "LOOP kind=slow unit=ms ms={} phase={phase} phase_ms={} frames={} {}",
            ms(p.busy()),
            ms(d),
            p.tick.frames,
            p.fields()
        ))
    }

    /// The window aggregate, emitted on the telemetry cadence. Resets the
    /// accumulator, so consecutive lines partition the run with no overlap and
    /// no gap.
    ///
    /// `win=` is measured wall time and `acct=` is the sum of the iterations,
    /// so **`unacct=` is the instrument's own blind spot, reported rather than
    /// asserted to be small**. Three things live in it, and the third is why it
    /// is a field and not a footnote:
    ///
    /// 1. the loop condition and the clock reads themselves — nanoseconds;
    /// 2. the `println!` of these very lines, which is deliberately outside
    ///    every phase (a phase cannot time its own report);
    /// 3. **anything that blocks stdout.** `println!` takes the stdout lock and
    ///    writes to a pipe: under `docker logs` or a rate-limiting journald, a
    ///    full pipe blocks the consensus loop for as long as the reader takes.
    ///    Nothing in this issue's history has ever measured that, and a large
    ///    `unacct` with small phases is exactly what it would look like.
    pub fn window_line(&mut self) -> String {
        let win = self.window_started.elapsed();
        let (phase, d) = self.worst.worst();
        let line = format!(
            "LOOP kind=window unit=ms win={} iters={} busy={} acct={} unacct={} maxiter={} maxphase={phase} maxphase_ms={} frames={} slow={} slowsup={} {}",
            ms(win),
            self.iterations,
            ms(self.window.busy()),
            ms(self.window.total()),
            ms(win.saturating_sub(self.window.total())),
            ms(self.worst.busy()),
            ms(d),
            self.window.tick.frames,
            self.slow_emitted,
            self.slow_suppressed,
            self.window.fields()
        );
        self.window = LoopPhases::default();
        self.worst = LoopPhases::default();
        self.iterations = 0;
        self.slow_emitted = 0;
        self.slow_suppressed = 0;
        self.window_started = Instant::now();
        line
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msd(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// The degraded sample this issue has never had: one 131 s iteration, and
    /// the line names the phase.
    #[test]
    fn a_131_second_iteration_attributes_itself_to_a_tick_phase() {
        let mut j = LoopJournal::new();
        let degraded = LoopPhases {
            pump: msd(131_174),
            journal: msd(1),
            maintain: msd(20),
            tick: TickTimings {
                frames: 6,
                poll: msd(2),
                dispatch: msd(131_170),
                send: msd(131_165),
                ..Default::default()
            },
            ..Default::default()
        };
        let line = j.note(&degraded).expect("131 s is above any threshold");
        assert!(line.starts_with("LOOP kind=slow unit=ms "), "{line}");
        assert!(line.contains(" phase=pump.dispatch "), "the attribution: {line}");
        assert!(line.contains(" phase_ms=131170.0 "), "with its number: {line}");
        assert!(line.contains(" ms=131195.0 "), "the iteration's own busy time: {line}");
        // The overlay is present and marked, so a reader cannot add it into the
        // total by accident.
        assert!(line.contains(" send*=131165.0"), "{line}");
        assert!(line.contains(" frames=6 "), "{line}");
    }

    #[test]
    fn a_healthy_iteration_prints_nothing() {
        let mut j = LoopJournal::new();
        let healthy = LoopPhases {
            pump: Duration::from_micros(120),
            journal: Duration::from_micros(8),
            sleep: msd(20),
            tick: TickTimings { frames: 0, poll: Duration::from_micros(90), ..Default::default() },
            ..Default::default()
        };
        for _ in 0..500 {
            assert_eq!(j.note(&healthy), None, "silent on a healthy node");
        }
        // ...and the window line still reports it, which is the half a
        // threshold-only instrument would have missed.
        let w = j.window_line();
        assert!(w.contains(" iters=500 "), "{w}");
        assert!(w.contains(" busy=64.0 "), "500 × 128 us: {w}");
        assert!(w.contains(" sleep=10000.0"), "the idle back-off is reported, not hidden: {w}");
    }

    /// The sleep is not work: a loop that spends its whole window idle must not
    /// read as a busy loop.
    #[test]
    fn sleep_is_excluded_from_busy_and_included_in_the_accounted_total() {
        let p = LoopPhases { pump: msd(1), sleep: msd(20), ..Default::default() };
        assert_eq!(p.busy(), msd(1));
        assert_eq!(p.total(), msd(21));
    }

    #[test]
    fn the_slow_line_is_capped_per_window_and_the_suppressed_count_survives() {
        let mut j = LoopJournal::new();
        let slow = LoopPhases { mine: msd(1_500), ..Default::default() };
        let emitted = (0..50).filter(|_| j.note(&slow).is_some()).count() as u64;
        assert_eq!(emitted, MAX_SLOW_LINES_PER_WINDOW, "the cap holds");
        let w = j.window_line();
        assert!(w.contains(&format!(" slow={MAX_SLOW_LINES_PER_WINDOW} ")), "{w}");
        assert!(w.contains(" slowsup=42 "), "the suppressed lines are counted, not lost: {w}");
        // Suppression drops the line, never the measurement: all 50 are in the
        // window's own totals.
        assert!(w.contains(" mine=75000.0 "), "50 × 1500 ms: {w}");
        assert!(w.contains(" iters=50 "), "{w}");
    }

    /// The residual is reported, and it is the field that would catch a
    /// blocking `println!` — the one thing on this loop that no phase covers.
    #[test]
    fn the_unaccounted_residual_is_a_field_and_not_a_footnote() {
        let mut j = LoopJournal::new();
        // An iteration that claims 1 ms of work inside a window that really
        // lasted longer: whatever the difference is, it is on the line.
        j.note(&LoopPhases { pump: msd(1), ..Default::default() });
        std::thread::sleep(msd(30));
        let w = j.window_line();
        let unacct: f64 = w
            .split(" unacct=")
            .nth(1)
            .and_then(|s| s.split(' ').next())
            .and_then(|s| s.parse().ok())
            .expect("unacct is on the line: {w}");
        assert!(unacct >= 25.0, "the 30 ms nobody claimed is visible: {w}");
    }

    #[test]
    fn the_window_resets_so_consecutive_lines_do_not_overlap() {
        let mut j = LoopJournal::new();
        j.note(&LoopPhases { pump: msd(10), ..Default::default() });
        let first = j.window_line();
        assert!(first.contains(" pump=10.0 "), "{first}");
        let second = j.window_line();
        assert!(second.contains(" iters=0 "), "{second}");
        assert!(second.contains(" pump=0.0 "), "no carry-over: {second}");
    }

    #[test]
    fn the_threshold_is_tunable_so_a_test_need_not_burn_a_second() {
        let mut j = LoopJournal::new();
        let modest = LoopPhases { snapshot: msd(5), ..Default::default() };
        assert_eq!(j.note(&modest), None);
        j.set_threshold(msd(1));
        let line = j.note(&modest).expect("above the lowered threshold");
        assert!(line.contains(" phase=snapshot "), "{line}");
    }

    /// Attribution must survive the phase moving: whichever statement in the
    /// loop is slow is the one named, and a pump-dominated iteration descends
    /// into the tick while a non-pump one does not.
    #[test]
    fn every_phase_can_win_the_attribution() {
        let cases: Vec<(LoopPhases, &str)> = vec![
            (LoopPhases { mine: msd(80_000), ..Default::default() }, "mine"),
            (LoopPhases { snapshot: msd(9_000), ..Default::default() }, "snapshot"),
            (LoopPhases { maintain: msd(4_000), ..Default::default() }, "maintain"),
            (LoopPhases { sample: msd(2_000), ..Default::default() }, "sample"),
            (LoopPhases { hook: msd(2_300), ..Default::default() }, "hook"),
            (
                LoopPhases {
                    pump: msd(7_000),
                    tick: TickTimings { ratelimit: msd(6_900), ..Default::default() },
                    ..Default::default()
                },
                "pump.ratelimit",
            ),
            (
                LoopPhases {
                    pump: msd(7_000),
                    tick: TickTimings { poll: msd(6_900), ..Default::default() },
                    ..Default::default()
                },
                "pump.poll",
            ),
        ];
        for (p, expect) in cases {
            let mut j = LoopJournal::new();
            let line = j.note(&p).expect("all of these are above the threshold");
            assert!(
                line.contains(&format!(" phase={expect} ")),
                "expected {expect} in: {line}"
            );
        }
    }

    /// An idle iteration has no dominant phase, and must say so rather than
    /// naming whichever field happens to be first.
    #[test]
    fn an_iteration_that_did_nothing_is_attributed_to_idle() {
        let (name, d) = LoopPhases::default().worst();
        assert_eq!(name, "idle");
        assert_eq!(d, Duration::ZERO);
    }

    /// Both lines carry the same field tail, so one parser reads either.
    #[test]
    fn both_lines_share_one_schema() {
        let mut j = LoopJournal::new();
        let p = LoopPhases { mine: msd(2_000), ..Default::default() };
        let slow = j.note(&p).unwrap();
        let window = j.window_line();
        for key in [
            "pump=", "journal=", "mine=", "boundary=", "metrics=", "discovery=", "submit=",
            "telsrv=", "sample=", "maintain=", "snapshot=", "hook=", "sleep=", "dials=",
            "poll=", "ratelimit=", "decode=", "dispatch=", "sync=", "send*=", "unit=ms",
        ] {
            assert!(slow.contains(key), "slow line is missing {key}: {slow}");
            assert!(window.contains(key), "window line is missing {key}: {window}");
        }
    }
}
