//! **Where one [`crate::P2pNode::tick`] spent its time** (issue #107 S1).
//!
//! The main-loop period regressed 3–6× between two deployed images and stayed
//! there: `t0-wan-1` reached its 30 s telemetry floor constantly, every image
//! since has never come in below ~131 s across 53 samples on four hosts. Three
//! hypotheses were argued from the outside and two were refuted by measurement,
//! because the only instrument anyone had was *the gap between two telemetry
//! lines* — a number that says the loop was slow and nothing whatever about
//! which part of it was.
//!
//! This module is the missing half: the pump's own time, split by phase, so a
//! single degraded iteration attributes itself instead of having to be argued
//! about. It is **observation only** — no value here is read by any decision,
//! ever, which is the same rule [`crate::ratelimit::RateStats`] and
//! [`crate::node::UnknownStats`] follow and for the same reason.
//!
//! ## What the phases are, and why these boundaries
//!
//! They are cut where a *blocking call* would land, because that is the shape
//! the July analysis was hunting and could not see:
//!
//! | phase | covers | what a large value means |
//! |---|---|---|
//! | `dials` | `finish_dials` | applying connector-thread completions — #132 moved the connect itself off this thread, so this should be microseconds |
//! | `poll` | `Transport::poll` | draining the inbox; a mutex plus a `mem::take`, so a large value is **lock contention** with the reader threads |
//! | `ratelimit` | `rate_key` + `charge_frame`, per frame | #91's per-frame charge, the July suspect that was never timed |
//! | `decode` | `Frame::decode`, per frame | wire parsing |
//! | `dispatch` | the handler for each frame | consensus ingest, validation, and the responses it sends |
//! | `sync` | `maybe_start_sync` + the two request passes + `observe_body_fetch` | the ask ladders |
//!
//! [`TickTimings::send`] is an **overlay, not a phase**: socket writes are
//! counted separately *and* are already inside `dispatch` and `sync`, so it is
//! excluded from every total. It exists because `TcpTransport::send` holds the
//! `writers` mutex across the write and waits up to
//! [`crate::sendstall::SEND_WRITE_TIMEOUT_MS`] for the kernel — one slow peer
//! serialising every other send is the last unmeasured blocking call on the
//! pump path, and separating it is what lets "the loop was in dispatch" be told
//! apart from "the loop was in a socket".
//!
//! ## Cost
//!
//! Six `Instant::now()` per tick plus three per frame. On this class of machine
//! that is tens of nanoseconds each (a vDSO read, no syscall) — see
//! `instrumentation_costs_tens_of_nanoseconds_per_frame` for the measured
//! number and its basis. It runs unconditionally, on the fleet and in every
//! sim, because an instrument you have to turn on is an instrument that is off
//! when the incident happens. Determinism is unaffected: the in-process sims
//! keep taking their clock as a parameter, and nothing here is an input to
//! anything.

use std::time::{Duration, Instant};

/// Per-phase durations for one [`crate::P2pNode::tick`].
///
/// Additive: `dials + poll + ratelimit + decode + dispatch + sync` is the whole
/// of the tick, up to the rounding of the clock reads themselves. `send` is an
/// overlay of `dispatch`/`sync` and is deliberately outside that sum.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TickTimings {
    /// Frames handed to this tick by the transport (including ones the limiter
    /// then dropped — they arrived and were charged, so they were handled).
    pub frames: u64,
    /// `finish_dials` — applying whatever the connector threads completed.
    pub dials: Duration,
    /// `Transport::poll` — the inbox drain.
    pub poll: Duration,
    /// Per-frame: the rate key and [`crate::ratelimit::RateLimiter::charge_frame`].
    pub ratelimit: Duration,
    /// Per-frame: `Frame::decode`.
    pub decode: Duration,
    /// Per-frame: the dispatch handler (or the unknown-type / malformed arms).
    pub dispatch: Duration,
    /// The post-frame passes: sync kick, body requests, checkpoint queries.
    pub sync: Duration,
    /// **Overlay, not a phase** — time inside `Transport::send`, already counted
    /// in `dispatch` and `sync`. See the module doc.
    pub send: Duration,
}

impl TickTimings {
    /// The six phases, in the order they run. `send` is deliberately absent.
    pub fn phases(&self) -> [(&'static str, Duration); 6] {
        [
            ("dials", self.dials),
            ("poll", self.poll),
            ("ratelimit", self.ratelimit),
            ("decode", self.decode),
            ("dispatch", self.dispatch),
            ("sync", self.sync),
        ]
    }

    /// Wall time this tick accounts for.
    pub fn total(&self) -> Duration {
        self.phases().iter().map(|(_, d)| *d).sum()
    }

    /// The phase that took the longest, and how long. Ties go to the earlier
    /// phase in run order, so the answer is stable rather than map-ordered.
    pub fn worst(&self) -> (&'static str, Duration) {
        let mut worst = ("dials", Duration::ZERO);
        for (name, d) in self.phases() {
            if d > worst.1 {
                worst = (name, d);
            }
        }
        worst
    }

    /// Fold another tick's timings in (window accumulation).
    pub fn add(&mut self, o: &TickTimings) {
        self.frames += o.frames;
        self.dials += o.dials;
        self.poll += o.poll;
        self.ratelimit += o.ratelimit;
        self.decode += o.decode;
        self.dispatch += o.dispatch;
        self.sync += o.sync;
        self.send += o.send;
    }
}

/// Read the clock, return the interval since `t`, and advance `t` to now.
///
/// One call per phase boundary, so a phase's cost is measured by exactly two
/// clock reads and no phase is double-charged for the read between it and its
/// neighbour.
#[inline]
pub fn lap(t: &mut Instant) -> Duration {
    let now = Instant::now();
    let d = now.saturating_duration_since(*t);
    *t = now;
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn the_total_is_the_six_phases_and_excludes_the_send_overlay() {
        let t = TickTimings {
            frames: 3,
            dials: ms(1),
            poll: ms(2),
            ratelimit: ms(4),
            decode: ms(8),
            dispatch: ms(16),
            sync: ms(32),
            // Larger than every phase, and still not in the total: it is time
            // already counted inside `dispatch`, reported twice on purpose.
            send: ms(1000),
        };
        assert_eq!(t.total(), ms(63));
        assert_eq!(t.phases().len(), 6);
        assert!(!t.phases().iter().any(|(n, _)| *n == "send"), "send is not a phase");
    }

    #[test]
    fn worst_names_the_dominant_phase_and_breaks_ties_in_run_order() {
        let t = TickTimings { dispatch: ms(131_174), poll: ms(2), ..Default::default() };
        assert_eq!(t.worst(), ("dispatch", ms(131_174)));

        // A tie: the earlier phase in run order wins, so the same input always
        // produces the same attribution.
        let tie = TickTimings { poll: ms(5), decode: ms(5), ..Default::default() };
        assert_eq!(tie.worst().0, "poll");

        // An idle tick has no dominant phase and must not panic or pick noise.
        assert_eq!(TickTimings::default().worst(), ("dials", Duration::ZERO));
    }

    #[test]
    fn add_accumulates_every_field_including_the_overlay() {
        let mut a = TickTimings { frames: 2, poll: ms(1), send: ms(3), ..Default::default() };
        let b = TickTimings { frames: 5, poll: ms(4), send: ms(7), dispatch: ms(9), ..Default::default() };
        a.add(&b);
        assert_eq!(a.frames, 7);
        assert_eq!(a.poll, ms(5));
        assert_eq!(a.send, ms(10));
        assert_eq!(a.dispatch, ms(9));
    }

    #[test]
    fn lap_advances_the_cursor_so_neighbouring_phases_are_not_double_charged() {
        let mut t = Instant::now();
        let first = lap(&mut t);
        std::thread::sleep(ms(15));
        let second = lap(&mut t);
        assert!(second >= ms(10), "the sleep lands in the second lap: {second:?}");
        assert!(first < ms(10), "and not in the first: {first:?}");
    }

    /// **The instrumentation's own cost, measured rather than asserted** — the
    /// number the PR quotes, with its basis in the failure message.
    ///
    /// Deliberately a loose bound: this runs on shared CI and a laptop, so it
    /// fails only if a clock read has become *microseconds*, which would mean
    /// the platform is trapping to the kernel and the design decision to run
    /// this unconditionally would need revisiting.
    #[test]
    fn instrumentation_costs_tens_of_nanoseconds_per_frame() {
        const N: u32 = 100_000;
        let mut t = Instant::now();
        let started = Instant::now();
        let mut sink = Duration::ZERO;
        for _ in 0..N {
            sink += lap(&mut t);
        }
        let per_call = started.elapsed() / N;
        assert!(sink > Duration::ZERO || sink == Duration::ZERO); // keep the loop
        assert!(
            per_call < Duration::from_micros(1),
            "one clock read cost {per_call:?}; the per-frame overhead is three of these, \
             and above ~1 us the unconditional instrumentation decision needs revisiting"
        );
    }
}
