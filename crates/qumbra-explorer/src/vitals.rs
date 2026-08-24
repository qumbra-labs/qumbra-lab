//! Net vitals over time: `GET /v1/vitals` (lab #486 scope item 4).
//!
//! ```text
//!   Telemetry ──sample_of──▶ VitalsRing ──document──▶ GET /v1/vitals
//! ```
//!
//! The one genuinely new projection in the front-of-house set: nothing anywhere
//! retains peer count / mempool over time (`Telemetry` is instantaneous, the
//! metrics `Histogram`s aggregate without retaining samples), so the explorer
//! process samples its own telemetry on a fixed cadence into a bounded ring.
//!
//! # The bound is the point (#135)
//!
//! [`VITALS_SAMPLES`]` = 1440` × [`SAMPLE_SECS`]` = 60` ⇒ 24 h of samples,
//! ≈ 1440 × 40 B ≈ 58 KB resident, **fixed** — the ring never grows past the
//! bound, eviction is oldest-first, and the worst-case document (~120 KB JSON)
//! is served whole (no paging needed at this size; parameterless like
//! `health.json`).
//!
//! # `since` — the honesty field
//!
//! The ring is process-lifetime and bounded, so the served history begins at
//! the **oldest retained sample** — at first that is process start, and once
//! the ring evicts it is the 24 h window's edge. `since` states it either way
//! (`null` while no sample exists); the page renders "sampled every 60 s since
//! …", never implied chain-lifetime history. Same rule as
//! [`crate::checkpoints`]' `history_from_height`. Not persisted, same grounds
//! as the checkpoint ring: a restart gap in a vitals chart is honest and
//! cheap, a second persistence format is neither.

use std::collections::VecDeque;

use qlab_node::telemetry::Telemetry;

use crate::json::num;

/// The document's own version — its own integer, the standing json.rs argument.
pub const VITALS_VERSION: u32 = 1;

/// The ring bound: 24 h at the sampling cadence. `[devnet-placeholder]`,
/// testnet-tunable, NOT frozen.
pub const VITALS_SAMPLES: usize = 1440;

/// Sampling cadence in seconds. Served on the document so the page never
/// hardcodes it.
pub const SAMPLE_SECS: u64 = 60;

/// One sample of the observer's own instantaneous telemetry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sample {
    /// Unix seconds at the sampling tick (the process wall clock — this is an
    /// observation timestamp, not chain data).
    pub t: u64,
    pub peers: u64,
    pub mempool: u64,
    pub tip_height: u64,
    pub stall_depth: u64,
}

/// Project one [`Telemetry`] snapshot into a sample at time `t`. The field
/// selection is the stage-0 R3 shape: everything here is already public on
/// `health.json` instantaneously; this route only adds the time axis.
pub fn sample_of(t: u64, tele: &Telemetry) -> Sample {
    Sample {
        t,
        peers: tele.peer_count,
        mempool: tele.mempool_size,
        tip_height: tele.tip_height,
        stall_depth: tele.stall_depth,
    }
}

/// The bounded sampling ring. Owned by the run loop (single writer); readers
/// see only the pre-serialized document, so the ring itself needs no lock.
#[derive(Debug, Default)]
pub struct VitalsRing {
    samples: VecDeque<Sample>,
}

impl VitalsRing {
    pub fn new() -> Self {
        Self::default()
    }

    /// The cadence rule, pure so it is testable: append when the ring is empty
    /// or `s.t` is at least [`SAMPLE_SECS`] past the last sample, evicting the
    /// oldest at the bound. Returns whether it appended (the caller
    /// re-serializes only then).
    ///
    /// A timestamp at or before the last sample appends nothing: a wall clock
    /// stepped backwards must not produce a non-monotone series — the ring
    /// simply waits until real time passes the cadence again.
    pub fn maybe_push(&mut self, s: Sample) -> bool {
        if let Some(last) = self.samples.back() {
            if s.t < last.t.saturating_add(SAMPLE_SECS) {
                return false;
            }
        }
        if self.samples.len() == VITALS_SAMPLES {
            self.samples.pop_front();
        }
        self.samples.push_back(s);
        true
    }

    /// Where the served history begins: the oldest retained sample's `t`.
    pub fn since(&self) -> Option<u64> {
        self.samples.front().map(|s| s.t)
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Serialize the ring — hand-rolled, zero new runtime dependencies, the
    /// `crate::json` posture.
    pub fn document(&self) -> String {
        let rows: Vec<String> = self
            .samples
            .iter()
            .map(|s| {
                format!(
                    "{{\"t\":{t},\"peers\":{p},\"mempool\":{m},\"tip_height\":{h},\
                     \"stall_depth\":{d}}}",
                    t = s.t,
                    p = s.peers,
                    m = s.mempool,
                    h = s.tip_height,
                    d = s.stall_depth,
                )
            })
            .collect();
        format!(
            "{{\"v\":{VITALS_VERSION},\
             \"sample_secs\":{SAMPLE_SECS},\
             \"since\":{since},\
             \"samples\":[{rows}]}}",
            since = num(self.since()),
            rows = rows.join(","),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(t: u64) -> Sample {
        Sample { t, peers: 5, mempool: 0, tip_height: 15_761, stall_depth: 0 }
    }

    fn parse(s: &str) -> serde_json::Value {
        serde_json::from_str(s).expect("the hand-rolled encoder emits real JSON")
    }

    /// The cadence rule: first sample always, then one per SAMPLE_SECS — a tick
    /// one second early appends nothing, the cadence boundary itself appends.
    #[test]
    fn one_sample_per_cadence_interval() {
        let mut ring = VitalsRing::new();
        assert!(ring.maybe_push(s(1_787_000_000)), "an empty ring samples immediately");
        assert!(!ring.maybe_push(s(1_787_000_000 + SAMPLE_SECS - 1)), "one second early");
        assert!(ring.maybe_push(s(1_787_000_000 + SAMPLE_SECS)), "the boundary itself");
        assert_eq!(ring.len(), 2);
    }

    /// A wall clock stepped backwards appends nothing — the series stays
    /// monotone, and sampling resumes once real time passes the cadence again.
    #[test]
    fn a_backwards_clock_cannot_produce_a_non_monotone_series() {
        let mut ring = VitalsRing::new();
        assert!(ring.maybe_push(s(1_787_000_000)));
        assert!(!ring.maybe_push(s(1_786_999_000)), "clock stepped back");
        assert!(!ring.maybe_push(s(1_787_000_000)), "same instant again");
        assert!(ring.maybe_push(s(1_787_000_000 + SAMPLE_SECS)));
        let times: Vec<u64> =
            parse(&ring.document())["samples"].as_array().unwrap().iter()
                .map(|v| v["t"].as_u64().unwrap())
                .collect();
        assert!(times.windows(2).all(|w| w[0] < w[1]), "monotone: {times:?}");
    }

    /// 🔴 The #135 bound: the ring never grows past VITALS_SAMPLES, eviction is
    /// oldest-first, and `since` moves to the new oldest — the honesty field
    /// tracks what is actually served, not what was once sampled.
    #[test]
    fn the_ring_is_bounded_and_since_tracks_the_oldest_retained() {
        let mut ring = VitalsRing::new();
        let t0 = 1_787_000_000u64;
        for i in 0..(VITALS_SAMPLES as u64 + 3) {
            assert!(ring.maybe_push(s(t0 + i * SAMPLE_SECS)));
        }
        assert_eq!(ring.len(), VITALS_SAMPLES, "never past the bound");
        assert_eq!(
            ring.since(),
            Some(t0 + 3 * SAMPLE_SECS),
            "the three oldest fell off and since says so"
        );
    }

    /// Nothing sampled yet: an empty document with a null start — the same
    /// honest empty state every surface here serves, never an error.
    #[test]
    fn an_empty_ring_serves_an_honest_empty_document() {
        let v = parse(&VitalsRing::new().document());
        assert_eq!(v["v"], VITALS_VERSION);
        assert_eq!(v["sample_secs"], SAMPLE_SECS);
        assert!(v["since"].is_null());
        assert_eq!(v["samples"].as_array().unwrap().len(), 0);
    }

    /// The Telemetry projection takes exactly the four instantaneous fields the
    /// stage-0 R3 shape names — all already public on health.json; this route
    /// adds only the time axis.
    #[test]
    fn sample_of_projects_the_r3_fields() {
        // Assembled the way the node does it: tip 16_051 over finalized 16_048
        // derives stall_depth 3 — the sample carries the derived field, not a
        // re-derivation of its own.
        let tele = Telemetry::assemble(16_051, Some(16_048), Some(42), 2, 7, 0, 64);
        let got = sample_of(1_787_000_060, &tele);
        assert_eq!(
            got,
            Sample { t: 1_787_000_060, peers: 7, mempool: 2, tip_height: 16_051, stall_depth: 3 }
        );
    }

    // ---- goldens -----------------------------------------------------------------

    const GOLDEN_DIGEST: &str =
        "65a4ce4e9c58d45a1a2039a21b8629da103608c46249a3eb5a71a82095ec171b";

    /// Two states the page renders: a live series and the fresh-observer empty
    /// state. Samples are **literal** — the golden locks the encoder's bytes,
    /// and every byte of the checked-in files is derivable by eye.
    fn golden_cases() -> Vec<(&'static str, String)> {
        let mut live = VitalsRing::new();
        assert!(live.maybe_push(Sample {
            t: 1_787_000_000,
            peers: 5,
            mempool: 0,
            tip_height: 15_761,
            stall_depth: 0,
        }));
        assert!(live.maybe_push(Sample {
            t: 1_787_000_060,
            peers: 4,
            mempool: 1,
            tip_height: 15_762,
            stall_depth: 7,
        }));
        vec![
            ("vitals-live", live.document()),
            ("vitals-empty", VitalsRing::new().document()),
        ]
    }

    /// 🔴 GOLDEN — the checked-in files ARE the vectors (txlist's golden docs;
    /// same discipline, same regeneration asymmetry).
    #[test]
    fn golden_files_match_the_encoder_byte_for_byte() {
        for (name, produced) in golden_cases() {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("goldens").join(name);
            let on_disk = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("golden {name} missing at {}: {e}", path.display()));
            assert_eq!(
                on_disk.trim_end_matches('\n'),
                produced,
                "golden {name} drifted — see this test's docs before updating the file"
            );
        }
    }

    #[test]
    fn the_goldens_decode_and_state_their_start() {
        for (name, produced) in golden_cases() {
            let v = parse(&produced);
            assert_eq!(v["v"], VITALS_VERSION, "{name} is versioned");
            assert!(v.get("since").is_some(), "{name} states its start");
            assert!(v.get("sample_secs").is_some(), "{name} states its cadence");
        }
    }

    #[test]
    #[ignore = "writes files; run explicitly when a shape change is intended"]
    fn regenerate_goldens() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("goldens");
        std::fs::create_dir_all(&dir).expect("goldens dir");
        for (name, produced) in golden_cases() {
            std::fs::write(dir.join(name), format!("{produced}\n")).expect("write golden");
            println!("wrote {name}");
        }
        let all: String = golden_cases().into_iter().map(|(_, s)| s).collect();
        let hex: String =
            qlab_note::hash::keccak256(all.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
        println!("GOLDEN_DIGEST = \"{hex}\"");
    }

    #[test]
    fn golden_digest_locks_the_regenerated_files() {
        let all: String = golden_cases().into_iter().map(|(_, s)| s).collect();
        let digest = qlab_note::hash::keccak256(all.as_bytes());
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex, GOLDEN_DIGEST,
            "GOLDEN digest — update ONLY with an intentional, documented shape change"
        );
    }
}
