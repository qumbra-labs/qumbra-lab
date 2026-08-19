//! The finality ticker's data: `GET /v1/checkpoints` (lab #486 scope item 2).
//!
//! ```text
//!   FinalityTracker ──finalized_tail──▶ CheckpointsView ──▶ json ──▶ GET /v1/checkpoints
//! ```
//!
//! Checkpoints as they finalized — the Ebb-and-Flow story made visible: each row
//! is (height, block-hash identity, `fid`, span), where **span** is the height
//! delta from the previous finalized checkpoint, so a span above the 8-block
//! cadence *is* a degraded window crossed, readable off the wire.
//!
//! # Identity rendering — one scheme, deliberately
//!
//! `fid` is [`Checkpoint::identity`] through [`checkpoint_id_hex`] — the exact
//! rendering `health.json`'s `head1.checkpoint_id` uses, so the ticker's newest
//! row and the health document's head agree byte-for-byte. `block_hash` is
//! [`BlockIdentity::of`] through the same helper: 12-hex identity **display**
//! fields, the #84/#212 discipline (unlike `/v1/blocks`' full hashes, which are
//! primary keys — the same block appears there in full).
//!
//! # `history_from_height` — the honesty field
//!
//! The tracker rehydrates from **one** checkpoint at restart, so its depth is
//! process-lifetime; the document says where its history actually begins and the
//! page renders "since the observer last restarted", never implied chain-lifetime
//! history. Historical `slot` is not retained node-side and the ticker ships
//! **without it** — coordinator-ratified divergence from the tracker's
//! "(fid, slot, span)" wording (stage-0 review ruling 5): honesty over a
//! fabricated display field.
//!
//! Served bound: the last [`MAX_CHECKPOINTS`] (~2.8 days at the 8-block cadence)
//! — a serving bound regardless of the tracker's own growth (which is
//! pre-existing and #135-adjacent, named in `finality.rs`, not fixed here). The
//! ring is deliberately not persisted: bounded memory is law, a restart gap in a
//! ticker is honest and cheap, a second persistence format is neither.

use qlab_devnet::committee::{checkpoint_id_hex, Checkpoint};
use qlab_devnet::finality::FinalityTracker;
use qlab_node::telemetry::BlockIdentity;

use crate::json::num;

/// The document's own version — its own integer, the standing json.rs argument.
pub const CHECKPOINTS_VERSION: u32 = 1;

/// The most rows one document carries — the newest [`MAX_CHECKPOINTS`], ~2.8
/// days at the 8-block / 75 s cadence. `[devnet-placeholder]`, testnet-tunable,
/// NOT frozen. No paging: the document is parameterless and bounded, like
/// `health.json`.
pub const MAX_CHECKPOINTS: usize = 512;

/// One finalized checkpoint, as the page renders it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointRow {
    pub height: u64,
    /// The finalized block's 12-hex identity (display field, #212 discipline).
    pub block_id: BlockIdentity,
    /// The checkpoint identity (#84) — the same value `health.json` serves as
    /// `head1.checkpoint_id` when this row is the head.
    pub fid: u64,
    /// Height delta from the previous finalized checkpoint; `None` on the first
    /// checkpoint this process knows of (its predecessor is genuinely unknown —
    /// a restored tracker starts from one checkpoint).
    pub span: Option<u64>,
}

/// What `/v1/checkpoints` serves — projected whole, then pre-serialized by the
/// run loop like `health.json` (parameterless routes never encode per request).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CheckpointsView {
    /// The height the tracker's record actually begins at — process-lifetime
    /// honesty; `None` when nothing is finalized yet.
    pub history_from_height: Option<u64>,
    /// Ascending, the newest [`MAX_CHECKPOINTS`] at most.
    pub rows: Vec<CheckpointRow>,
}

/// Build rows from a served tail. `prev_height` is the height of the checkpoint
/// immediately BEFORE the tail (`None` = the tail starts at the record's true
/// first entry), which is what makes every served span real rather than an
/// artifact of the serving bound.
pub fn view_of_tail(
    history_from_height: Option<u64>,
    prev_height: Option<u64>,
    tail: &[Checkpoint],
) -> CheckpointsView {
    let mut rows = Vec::with_capacity(tail.len());
    let mut prev = prev_height;
    for cp in tail {
        rows.push(CheckpointRow {
            height: cp.height,
            block_id: BlockIdentity::of(&cp.block_hash),
            fid: cp.identity(),
            span: prev.map(|p| cp.height.saturating_sub(p)),
        });
        prev = Some(cp.height);
    }
    CheckpointsView { history_from_height, rows }
}

/// Project the tracker's bounded tail. Fetches one extra checkpoint so the
/// oldest SERVED row still gets its real span when the record is longer than
/// the bound.
pub fn project(tracker: &FinalityTracker) -> CheckpointsView {
    let history_from_height = tracker.finalized_tail(usize::MAX).first().map(|c| c.height);
    let tail_plus = tracker.finalized_tail(MAX_CHECKPOINTS + 1);
    let (prev_height, tail) = if tail_plus.len() > MAX_CHECKPOINTS {
        (Some(tail_plus[0].height), &tail_plus[1..])
    } else {
        (None, tail_plus)
    };
    view_of_tail(history_from_height, prev_height, tail)
}

/// The cheap "did the record move" fingerprint the run loop re-serializes on:
/// count catches growth, the latest identity catches a same-height variant
/// difference after a restart-rehydrate.
pub type Fingerprint = (usize, Option<u64>);

/// See [`Fingerprint`].
pub fn fingerprint(tracker: &FinalityTracker) -> Fingerprint {
    (tracker.count(), tracker.latest().map(|c| c.identity()))
}

/// Re-project and re-serialize when the record moved. Pure decision, publish is
/// the caller's (`main.rs` swaps the pre-serialized slot exactly as it does for
/// `health.json`) — the rule lives here so it is testable.
pub fn refreshed_document(last: &mut Option<Fingerprint>, tracker: &FinalityTracker) -> Option<String> {
    let fp = fingerprint(tracker);
    if *last == Some(fp) {
        return None;
    }
    *last = Some(fp);
    Some(document(&project(tracker)))
}

/// Serialize the view — hand-rolled, zero new runtime dependencies, the
/// `crate::json` posture.
pub fn document(v: &CheckpointsView) -> String {
    let rows: Vec<String> = v
        .rows
        .iter()
        .map(|r| {
            format!(
                "{{\"height\":{h},\"block_hash\":\"{bh}\",\"fid\":\"{fid}\",\"span\":{span}}}",
                h = r.height,
                bh = r.block_id.field(),
                fid = checkpoint_id_hex(Some(r.fid)),
                span = num(r.span),
            )
        })
        .collect();
    format!(
        "{{\"v\":{CHECKPOINTS_VERSION},\
         \"history_from_height\":{from},\
         \"checkpoints\":[{rows}]}}",
        from = num(v.history_from_height),
        rows = rows.join(","),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_devnet::committee::devnet_committee;

    fn h32(first: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = first;
        h
    }

    fn cp(height: u64) -> Checkpoint {
        Checkpoint::new(height, h32(height as u8), h32(height.wrapping_add(1) as u8))
    }

    /// A tracker with checkpoints at the given heights, finalized through the
    /// real quorum path — the accessor serves what real finalization recorded.
    fn tracker_at(heights: &[u64]) -> FinalityTracker {
        let (committee, validators) = devnet_committee(7); // quorum = 5
        let mut fin = FinalityTracker::new();
        for &h in heights {
            let c = cp(h);
            let votes: Vec<_> = validators[..5].iter().map(|v| v.sign_checkpoint(&c)).collect();
            fin.try_finalize(&c, &votes, &committee).unwrap();
        }
        fin
    }

    fn parse(s: &str) -> serde_json::Value {
        serde_json::from_str(s).expect("the hand-rolled encoder emits real JSON")
    }

    /// Spans are real deltas; the first known checkpoint has no predecessor and
    /// says so with null, never a fabricated zero.
    #[test]
    fn spans_are_height_deltas_and_the_first_is_null() {
        let view = project(&tracker_at(&[8, 16, 40]));
        assert_eq!(view.history_from_height, Some(8));
        let spans: Vec<Option<u64>> = view.rows.iter().map(|r| r.span).collect();
        assert_eq!(spans, vec![None, Some(8), Some(24)], "24 = a degraded window crossed");
    }

    /// 🔴 The identity renderings are the shared helpers' — the ticker's newest
    /// row must agree byte-for-byte with health.json's head fields, which is what
    /// one scheme buys.
    #[test]
    fn identities_render_through_the_shared_helpers() {
        let c = cp(16);
        let view = view_of_tail(Some(16), None, &[c]);
        let v = parse(&document(&view));
        assert_eq!(v["checkpoints"][0]["fid"], checkpoint_id_hex(Some(c.identity())));
        assert_eq!(
            v["checkpoints"][0]["block_hash"],
            BlockIdentity::of(&c.block_hash).field(),
            "12-hex display identity, the #212 discipline"
        );
        assert_eq!(v["checkpoints"][0]["fid"].as_str().unwrap().len(), 12);
    }

    /// The serving bound: the newest MAX_CHECKPOINTS rows — and the oldest
    /// served row still carries its REAL span, computed against the checkpoint
    /// the bound just cut off.
    #[test]
    fn the_bound_serves_the_newest_rows_with_real_spans_at_the_edge() {
        let heights: Vec<u64> = (1..=(MAX_CHECKPOINTS as u64 + 3)).map(|i| i * 8).collect();
        let view = project(&tracker_at(&heights));
        assert_eq!(view.rows.len(), MAX_CHECKPOINTS);
        assert_eq!(view.rows[0].height, 4 * 8, "the three oldest fell off");
        assert_eq!(
            view.rows[0].span,
            Some(8),
            "the edge row's span is real — computed against the cut-off predecessor"
        );
        assert_eq!(
            view.history_from_height,
            Some(8),
            "…while history_from_height still names the record's true start"
        );
    }

    /// Nothing finalized: an empty document with a null start, never an error
    /// and never a fabricated row.
    #[test]
    fn an_empty_tracker_serves_an_honest_empty_document() {
        let view = project(&FinalityTracker::new());
        let v = parse(&document(&view));
        assert!(v["history_from_height"].is_null());
        assert_eq!(v["checkpoints"].as_array().unwrap().len(), 0);
    }

    /// A restored tracker (one checkpoint, restart rehydrate) reports history
    /// from that checkpoint — process-lifetime honesty on the wire.
    #[test]
    fn a_restored_tracker_reports_history_from_its_one_checkpoint() {
        let fin = FinalityTracker::from_restored_checkpoint(cp(15_320));
        let view = project(&fin);
        assert_eq!(view.history_from_height, Some(15_320));
        assert_eq!(view.rows.len(), 1);
        assert_eq!(view.rows[0].span, None, "its predecessor is genuinely unknown");
    }

    /// The re-serialize rule: once per record movement, silent otherwise.
    #[test]
    fn refreshed_document_fires_once_per_record_movement() {
        let mut last = None;
        let fin = tracker_at(&[8]);
        assert!(refreshed_document(&mut last, &fin).is_some(), "first render");
        assert!(refreshed_document(&mut last, &fin).is_none(), "unchanged record");
        let fin2 = tracker_at(&[8, 16]);
        assert!(refreshed_document(&mut last, &fin2).is_some(), "the record grew");
    }

    /// 🔴 No `slot` key anywhere (ruling 5): the ticker ships without historical
    /// slot rather than growing node state to backfill a display field.
    #[test]
    fn no_slot_key_is_served() {
        let s = document(&project(&tracker_at(&[8, 16])));
        assert!(!s.contains("slot"), "ruling 5 — no fabricated history: {s}");
    }

    // ---- goldens -----------------------------------------------------------------

    const GOLDEN_DIGEST: &str =
        "42c0fb69fc2bf056c6d2b9f0ca8fe5b2057ac71a8c54d0a105501fbdf27ff621";

    /// Two states the page renders: a live ticker (with a degraded-window span
    /// visible), and the fresh-observer empty state.
    ///
    /// The rows are **literal** — a golden locks the ENCODER's bytes, and literal
    /// rows keep every byte of the checked-in files derivable by eye (a `fid` is
    /// `checkpoint_id_hex` of the literal, zero-padded to 12; a `block_hash`
    /// display field is the hash's first six bytes in hex). The identity
    /// *derivation* is locked separately, by
    /// `identities_render_through_the_shared_helpers` above and the helpers' own
    /// tests. The second row's leading-zero `fid` is deliberate: it locks the
    /// zero-padding.
    fn golden_cases() -> Vec<(&'static str, String)> {
        let live = CheckpointsView {
            history_from_height: Some(15_320),
            rows: vec![
                CheckpointRow {
                    height: 15_320,
                    block_id: BlockIdentity::of(&h32(0xe0)),
                    fid: 0x3ba0_8370_682f,
                    span: None,
                },
                CheckpointRow {
                    height: 15_328,
                    block_id: BlockIdentity::of(&h32(0xe1)),
                    fid: 0x0c11_5e2a_9b40,
                    span: Some(8),
                },
                CheckpointRow {
                    height: 15_352,
                    block_id: BlockIdentity::of(&h32(0xe2)),
                    fid: 0xf00d_0000_cafe,
                    span: Some(24),
                },
            ],
        };
        vec![
            ("checkpoints-live", document(&live)),
            ("checkpoints-empty", document(&CheckpointsView::default())),
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
    fn the_goldens_decode_and_state_their_history_start() {
        for (name, produced) in golden_cases() {
            let v = parse(&produced);
            assert_eq!(v["v"], CHECKPOINTS_VERSION, "{name} is versioned");
            assert!(v.get("history_from_height").is_some(), "{name} states its start");
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
