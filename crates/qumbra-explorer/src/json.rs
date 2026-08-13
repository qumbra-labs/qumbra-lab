//! The chain-health **projection**: one [`Telemetry`] snapshot as versioned JSON.
//!
//! Replaces this crate's rendered page (issue #281, design brief
//! `t1-explorer-split-decision.md`). Pure: `Telemetry` in, bytes out.
//!
//! Hand-rolled encoder, **zero new runtime dependencies**: every value here is a
//! number, a fixed enum name, or one of `Telemetry`'s own field renderings, and
//! this surface consumes no input. That makes [`esc`] unreachable from the only
//! caller that exists — and it is here anyway, with a test, because a hand-rolled
//! encoder that its own input can break is a defect independent of who calls it.
//!
//! `serde_json` and `qlab-note` are **dev-dependencies**: a real parser is what
//! proves these bytes are JSON rather than something that resembles it, and the
//! golden digest is test machinery. Neither reaches the binary.

use qlab_devnet::ebbflow::FinalityStatus;
use qlab_node::telemetry::SupplyCoverage;
use qlab_node::Telemetry;

/// The stable refused-figures token, same spelling as `qumbra-opview`'s and the
/// wallet CLI's (#136) — one grep covers all three surfaces.
pub const UNAVAILABLE: &str = "UNAVAILABLE";

/// The stable non-zero-divergence token, carried on a supply row whose measured and
/// expected coinbase disagree.
///
/// Kept across the split deliberately: the rendered page pinned this as *"a stable
/// token alerting may depend on"* (PR #236), and replacing it with a bare number
/// would have quietly downgraded this surface's alerting vocabulary to something a
/// grep cannot find. The exact signed delta is carried too — the token says *that*
/// it disagrees, the delta says *by how much*.
pub const DIVERGENT: &str = "DIVERGENT";

/// The verdict token for a **grandfathered** non-zero row — a scar the chain is known
/// to carry (`qlab_node::supply::KNOWN_SUPPLY_SCARS`, lab #299 ruling item 2).
///
/// A third token rather than reusing either of the other two, because both
/// alternatives lie: `agreed` hides a real number the page is supposed to publish,
/// and `DIVERGENT` on a row that will read the same forever is how a stable alerting
/// token becomes noise. Alerting keys on `DIVERGENT` and this one is deliberately not
/// a substring of it, so an existing grep neither matches it nor has to be rewritten.
pub const KNOWN_SCAR: &str = "KNOWN_SCAR";

/// The projection's own version, bumped when this object's **shape** changes.
///
/// 🔴 Deliberately **not** `qlab_node::rpc::RPC_VERSION` (`0x05` at issue #275).
/// The explorer's projection can change while the node's wire does not, and the
/// reverse, so one integer cannot carry both. This is the reasoning that gave
/// `dfinbh` its own name instead of becoming a fourth `…id` field: two meanings
/// in one slot is how a comparison that cannot mean anything gets written.
///
/// A reader that does not know this value must say so and render nothing else —
/// reject-unknown, the posture `peers.dat` and the finalizer state already take.
pub const HEALTH_VERSION: u32 = 1;

/// The whole projection. `genesis_file_hash` is [`GenesisFile::hash_hex`]'s value
/// — the hash a node refuses to boot against a mismatch of (issue #206's
/// which-hash-is-which discipline).
///
/// `refresh_secs` is the operator's configured cadence, carried so it still
/// reaches the reader after the page left this binary; without it the config knob
/// would silently become dead.
///
/// [`GenesisFile::hash_hex`]: qumbra_node::genesis::GenesisFile::hash_hex
pub fn health(t: &Telemetry, genesis_file_hash: &str, refresh_secs: u64) -> String {
    format!(
        "{{\"v\":{HEALTH_VERSION},\
         \"genesis_file_hash\":\"{genesis}\",\
         \"refresh_secs\":{refresh_secs},\
         \"chain\":{{\
         \"tip_height\":{tip},\"tip_difficulty\":{diff},\"regime\":\"{regime}\",\
         \"peers\":{peers},\"mempool\":{mempool}\
         }},\
         \"finality\":{{\
         \"head1\":{{\"height\":{h1},\"checkpoint_id\":\"{fid}\",\
         \"age_s\":\"{age}\",\"stall_depth\":{stall}}},\
         \"head3\":{{\"state\":\"{state}\",\"height\":{h3},\"block_hash\":\"{bh}\"}},\
         \"agreement\":{agreement}\
         }},\
         \"committee\":{{\
         \"epoch\":{epoch},\"roster\":{roster},\"active\":{active},\"quorum\":{quorum}\
         }},\
         \"supply\":{supply}\
         }}",
        genesis = esc(genesis_file_hash),
        tip = t.tip_height,
        diff = num(t.tip_difficulty),
        regime = regime(t.finality_status),
        peers = t.peer_count,
        mempool = t.mempool_size,
        h1 = num(t.finalized_height),
        fid = t.fid_field(),
        age = esc(&t.age_field()),
        stall = t.stall_depth,
        state = durable_state(t),
        h3 = num(t.durable.head().map(|h| h.height)),
        bh = t.durable.id_field(),
        agreement = agreement(t),
        epoch = t.epoch,
        roster = t.committee_size,
        active = t.committee_active,
        quorum = t.committee_quorum,
        supply = supply(t),
    )
}

/// The cheap "has anything a reader would notice moved" summary the run loop
/// re-serializes on.
///
/// 🔴 **`durable` is in here, and before issue #281 it was not** — the loop compared
/// `(tip, final, fid, peers, epoch)`, so head #3 advancing, or a head #1/head #3
/// divergence appearing, waited up to one `refresh_secs` to reach a reader. It also
/// lived in `main.rs`, where a rule cannot be tested; `main.rs` says of itself that
/// it is CLI glue only, and this is the rule it was hiding.
///
/// [`DurableView`] goes in whole rather than as a height, which buys three
/// distinctions for one field: an advance, **the same height holding a different
/// block**, and `Unavailable`-vs-`Nothing`.
///
/// `mempool_size` stays out, as it did before: it churns on a busy net and would
/// re-serialize the document continuously to report a number nothing alarms on. The
/// bound on its staleness is `refresh_secs`, which is stated rather than implied.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fingerprint {
    tip: u64,
    finalized: Option<u64>,
    fid: Option<u64>,
    peers: u64,
    epoch: u64,
    durable: qlab_node::DurableView,
}

/// See [`Fingerprint`].
pub fn fingerprint(t: &Telemetry) -> Fingerprint {
    Fingerprint {
        tip: t.tip_height,
        finalized: t.finalized_height,
        fid: t.finalized_id,
        peers: t.peer_count,
        epoch: t.epoch,
        durable: t.durable,
    }
}

/// The Ebb-and-Flow regime as a **machine name**, not the page's prose.
///
/// The rendered page said *"degraded (PoW-only until finality resumes)"*; the words
/// belong to the reader now, and the discriminant belongs here. Frozen §4 semantics
/// are read, never re-derived.
fn regime(s: FinalityStatus) -> &'static str {
    match s {
        FinalityStatus::Final => "final",
        FinalityStatus::Degraded => "degraded",
        FinalityStatus::Halting => "halting",
        FinalityStatus::Halted => "halted",
    }
}

/// The supply attestation, with the availability verdict delegated to
/// [`Telemetry::supply_coverage`].
///
/// 🔴 **Under anything but `Complete` the `epochs` key does not exist.** Not an
/// empty array, not zeros, not `null`: issues #130/#136 hold that a partial ledger
/// is *neither supply agreement nor a supply violation*, and on the rendered page
/// that held because we chose not to write the figures. A consumer of this document
/// cannot make that choice wrongly, because the figures are not in it. The token
/// keeps `qumbra-opview`'s spelling so one grep covers both surfaces.
fn supply(t: &Telemetry) -> String {
    match t.supply_coverage() {
        SupplyCoverage::Unavailable {
            state_tip,
            fork_choice_tip,
        } => format!(
            "{{\"coverage\":\"{UNAVAILABLE}\",\"state_tip\":{},\"fork_choice_tip\":{}}}",
            num(state_tip),
            fork_choice_tip,
        ),
        SupplyCoverage::Complete => {
            let rows: Vec<String> = t
                .supply
                .iter()
                .map(|e| {
                    let delta = e.measured_coinbase as i128 - e.expected_coinbase as i128;
                    format!(
                        "{{\"epoch\":{},\"start_height\":{},\"end_height\":{},\
                         \"expected_coinbase\":{},\"measured_coinbase\":{},\"fees\":{},\
                         \"burned\":{},\
                         \"delta\":{delta},\"verdict\":\"{verdict}\"}}",
                        e.epoch,
                        e.start_height,
                        e.end_height,
                        e.expected_coinbase,
                        e.measured_coinbase,
                        e.fees,
                        // Lab #367 arming prep: name-fee supply destruction,
                        // per epoch. Honest here and only here for now: this
                        // page reads its OWN in-process node (always the
                        // current wire), never a remote vintage.
                        e.burned,
                        delta = delta,
                        // #299 ruling item 2: the grandfathered epoch-1 scar keeps its
                        // row and its delta, but it is NOT reported as a violation —
                        // a page that shows a permanent DIVERGENT teaches its readers
                        // that DIVERGENT means nothing. `KNOWN_SCAR` is a third,
                        // greppable token, matched on epoch, endpoints and the exact
                        // delta, so one bessel either side of it is still DIVERGENT.
                        verdict = if delta == 0 {
                            "agreed"
                        } else if e.known_scar().is_some() {
                            KNOWN_SCAR
                        } else {
                            DIVERGENT
                        },
                    )
                })
                .collect();
            format!(
                "{{\"coverage\":\"COMPLETE\",\"epochs\":[{}]}}",
                rows.join(",")
            )
        }
    }
}

/// Minimal JSON string escaping.
///
/// Every string this module writes today is hex, a fixed enum name, or one of
/// `Telemetry`'s own field renderings, so **this is unreachable from the one caller
/// that exists**. It is here rather than in a comment because a hand-rolled encoder
/// that its own input can break is a defect independent of who calls it, and
/// `a_hostile_genesis_hash_cannot_break_the_document` is cheaper than the argument
/// that no caller will ever change.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// The head #1 vs head #3 verdict, **carried whole from
/// [`Telemetry::durable_agreement`]** — this module computes no comparison of its
/// own, because a second place for the rule is a second place for it to be wrong.
///
/// `token` keeps the upper-case spelling `qumbra-opview` and `qumbra-wallet` use,
/// so one grep still covers all three surfaces; a serialization format is not a
/// licence to re-spell a token alerting depends on. `divergent` is
/// [`DurableAgreement::is_divergent`], which is already `false` for
/// `Unavailable` — **an alarm must not fire on the absence of evidence**, and
/// delegating is how that stays true here without restating it.
fn agreement(t: &Telemetry) -> String {
    use qlab_node::DurableAgreement as A;
    let a = t.durable_agreement();
    let (tracker, durable) = match a {
        A::Unavailable | A::Agreed => (None, None),
        A::TrackerAhead { tracker, durable } => (Some(tracker), Some(durable)),
        A::DurableAhead { tracker, durable } => (tracker, Some(durable)),
        A::NothingDurable { tracker } => (Some(tracker), None),
    };
    format!(
        "{{\"divergent\":{},\"token\":{},\"tracker\":{},\"durable\":{}}}",
        a.is_divergent(),
        a.token()
            .map(|t| format!("\"{t}\""))
            .unwrap_or_else(|| "null".into()),
        num(tracker),
        num(durable),
    )
}

/// A `u64` or JSON `null`. `null` is right for a height that **does not exist**;
/// it is deliberately not used for a value the snapshot *refuses to state* — those
/// keep their named string rendering (`age_s`, the identity fields), because a
/// consumer's `|| 0` turns a null into a zero and a refusal into a lie.
fn num(v: Option<u64>) -> String {
    v.map(|x| x.to_string()).unwrap_or_else(|| "null".into())
}

/// [`qlab_node::DurableView`]'s three states, which are three different facts:
/// this composition cannot read head #3 · it read it and nothing is finalized ·
/// it read it and this is the head. The distinction survives to the reader.
fn durable_state(t: &Telemetry) -> &'static str {
    use qlab_node::DurableView;
    match t.durable {
        DurableView::Unavailable => "unavailable",
        DurableView::Nothing => "nothing",
        DurableView::Head(_) => "head",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_node::supply::SupplyEpoch;

    fn epoch_row(end: u64, expected: u64, measured: u64) -> SupplyEpoch {
        SupplyEpoch {
            epoch: 0,
            start_height: 1,
            end_height: end,
            measured_coinbase: measured,
            expected_coinbase: expected,
            fees: 0,
            burned: 0,
        }
    }

    /// The epoch-1 row this chain actually carries (#299 §5): the full epoch, 4,114
    /// bessel under the closed form.
    fn epoch_one_scar_row(delta: i128) -> SupplyEpoch {
        let expected = 1_000_000_000u64;
        SupplyEpoch {
            epoch: 1,
            start_height: 1_152,
            end_height: 2_303,
            measured_coinbase: (expected as i128 + delta) as u64,
            expected_coinbase: expected,
            fees: 0,
            burned: 0,
        }
    }

    const MAX_LAG: u64 = 16;

    /// Keccak-256 over the four golden serializations concatenated, in source so a
    /// blind file regeneration cannot make the goldens pass by itself.
    const GOLDEN_DIGEST: &str = "60782c21627e326fa4ad60e8a65f4690ad2223598aa9beebebeeb9b9ec6f7acb";

    fn hash32(first: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = first;
        h
    }

    fn parse(s: &str) -> serde_json::Value {
        serde_json::from_str(s).expect("the hand-rolled encoder emits real JSON")
    }

    /// The debt this baton pays: head #1 and head #3 are both on the surface, and
    /// head #3's block hash with them. Before #281 the page rendered head #1 only.
    #[test]
    fn both_heads_reach_the_surface_with_the_durable_block_hash() {
        let t = Telemetry::assemble(1052, Some(1048), 42, 0, 7, 0, MAX_LAG)
            .with_checkpoint(Some(0xb682_3616), None)
            .with_durable_head(Some((1040, hash32(0x3f))));
        let v = parse(&health(&t, "138e1524aabb", 30));

        assert_eq!(v["v"], HEALTH_VERSION, "the projection is versioned");
        assert_eq!(v["genesis_file_hash"], "138e1524aabb");
        assert_eq!(
            v["refresh_secs"], 30,
            "the operator's cadence survives the split"
        );

        assert_eq!(v["finality"]["head1"]["height"], 1048);
        assert_eq!(v["finality"]["head1"]["checkpoint_id"], t.fid_field());

        assert_eq!(v["finality"]["head3"]["state"], "head");
        assert_eq!(v["finality"]["head3"]["height"], 1040);
        assert_eq!(
            v["finality"]["head3"]["block_hash"],
            t.durable.id_field(),
            "the durable BLOCK hash, from the snapshot's own field renderer"
        );
    }

    /// The verdict is `Telemetry`'s, carried whole — token spelling included, so
    /// one grep still covers opview, the wallet CLI and this surface.
    #[test]
    fn a_tracker_ahead_of_the_durable_head_carries_the_lag_token_and_both_heights() {
        let t = Telemetry::assemble(1052, Some(1048), 42, 0, 7, 0, MAX_LAG)
            .with_durable_head(Some((1040, hash32(0x3f))));
        let v = parse(&health(&t, "aa", 30));
        let a = &v["finality"]["agreement"];

        assert_eq!(a["divergent"], true);
        assert_eq!(a["token"], "DURABLE_LAG");
        assert_eq!(a["tracker"], 1048);
        assert_eq!(
            a["durable"], 1040,
            "the height this node would come back at"
        );
    }

    /// A different magnitude of the same failure, and its own token: head #1 states
    /// a finalized height and head #3 holds nothing, so a restart returns to genesis.
    #[test]
    fn a_finalized_tracker_over_no_durable_head_carries_the_absent_token() {
        let t = Telemetry::assemble(2900, Some(2864), 42, 0, 7, 0, MAX_LAG).with_durable_head(None);
        let v = parse(&health(&t, "aa", 30));

        assert_eq!(
            v["finality"]["head3"]["state"], "nothing",
            "read, and it holds nothing"
        );
        assert_eq!(v["finality"]["agreement"]["token"], "DURABLE_ABSENT");
    }

    /// Agreement is silence: none of the three spellings may appear anywhere in the
    /// bytes. A negative pin, because a token that leaks on a healthy node is how
    /// operators learn to ignore the one that means something.
    #[test]
    fn agreement_carries_no_token_at_all() {
        let t = Telemetry::assemble(1052, Some(1048), 42, 0, 7, 0, MAX_LAG)
            .with_durable_head(Some((1048, hash32(0x3f))));
        let s = health(&t, "aa", 30);
        let v = parse(&s);

        assert_eq!(v["finality"]["agreement"]["divergent"], false);
        assert!(
            v["finality"]["agreement"]["token"].is_null(),
            "no token key value"
        );
        for spelling in ["DURABLE_LAG", "DURABLE_AHEAD", "DURABLE_ABSENT"] {
            assert!(!s.contains(spelling), "{spelling} must not appear: {s}");
        }
    }

    /// 🔴 A composition that cannot read head #3 is **not** a divergence: an alarm
    /// must not fire on the absence of evidence. This comes free by delegating —
    /// `DurableAgreement::is_divergent()` is already `false` there — and the test
    /// exists so nobody re-derives it into something that alarms.
    #[test]
    fn an_unreadable_durable_head_is_a_named_state_and_never_an_alarm() {
        // `with_durable_head` never called: this composition does not read head #3.
        let t = Telemetry::assemble(1052, Some(1048), 42, 0, 7, 0, MAX_LAG);
        let s = health(&t, "aa", 30);
        let v = parse(&s);

        assert_eq!(v["finality"]["head3"]["state"], "unavailable");
        assert_eq!(v["finality"]["head3"]["height"], serde_json::Value::Null);
        assert_eq!(
            v["finality"]["agreement"]["divergent"], false,
            "absence of evidence"
        );
        assert!(v["finality"]["agreement"]["token"].is_null());
    }

    #[test]
    fn the_chain_block_carries_the_five_facts_and_the_regime_as_a_machine_name() {
        let t = Telemetry::assemble(1052, Some(1048), 42, 3, 7, 0, MAX_LAG)
            .with_tip_difficulty(Some(1_048_576));
        let v = parse(&health(&t, "aa", 30));

        assert_eq!(v["chain"]["tip_height"], 1052);
        assert_eq!(v["chain"]["tip_difficulty"], 1_048_576);
        assert_eq!(v["chain"]["peers"], 7);
        assert_eq!(v["chain"]["mempool"], 3);
        assert_eq!(
            v["chain"]["regime"], "final",
            "a machine name, not the page's prose — the reader supplies the words"
        );
    }

    #[test]
    fn a_missing_tip_difficulty_is_null_and_never_a_zero() {
        let t = Telemetry::assemble(1052, Some(1048), 42, 0, 7, 0, MAX_LAG);
        let v = parse(&health(&t, "aa", 30));
        assert!(v["chain"]["tip_difficulty"].is_null(), "absent, not 0");
    }

    #[test]
    fn the_committee_block_carries_the_three_aggregates_and_the_epoch() {
        let t =
            Telemetry::assemble(1052, Some(1048), 42, 0, 7, 4, MAX_LAG).with_committee(21, 20, 15);
        let v = parse(&health(&t, "aa", 30));

        assert_eq!(v["committee"]["epoch"], 4);
        assert_eq!(v["committee"]["roster"], 21);
        assert_eq!(v["committee"]["active"], 20);
        assert_eq!(v["committee"]["quorum"], 15);
    }

    /// 🔴 `age_s` is a **string**, because `age_field()`'s `-` (issue #73) is a legal
    /// value: the node is refusing to state an age, not reporting a small one. As a
    /// number-or-null a consumer's `|| 0` prints a zero, which is a different claim.
    #[test]
    fn age_s_is_a_string_and_the_refusal_survives_as_such() {
        let stated = Telemetry::assemble(1052, Some(1048), 42, 0, 7, 0, MAX_LAG);
        let v = parse(&health(&stated, "aa", 30));
        assert_eq!(
            v["finality"]["head1"]["age_s"], "42",
            "a string, not the number 42"
        );

        // Nothing finalized: `age_field` refuses, and the refusal reaches the reader
        // in the vocabulary every other Qumbra surface uses for it.
        let refused = Telemetry::assemble(0, None, 0, 0, 0, 0, MAX_LAG);
        let v = parse(&health(&refused, "aa", 30));
        assert_eq!(
            v["finality"]["head1"]["age_s"], "-",
            "the #73 refusal, verbatim"
        );
        assert_eq!(v["finality"]["head1"]["age_s"], refused.age_field());
    }

    #[test]
    fn stall_depth_is_carried() {
        let t = Telemetry::assemble(1052, Some(1048), 42, 0, 7, 0, MAX_LAG);
        let v = parse(&health(&t, "aa", 30));
        assert_eq!(v["finality"]["head1"]["stall_depth"], 4);
    }

    #[test]
    fn complete_coverage_carries_the_epoch_rows_and_the_shared_token_spelling() {
        let t = Telemetry::assemble(14, Some(8), 75, 0, 3, 1, MAX_LAG)
            .with_supply(vec![epoch_row(14, 700, 700)]);
        assert!(matches!(t.supply_coverage(), SupplyCoverage::Complete));
        let v = parse(&health(&t, "aa", 30));

        assert_eq!(v["supply"]["coverage"], "COMPLETE");
        let rows = v["supply"]["epochs"]
            .as_array()
            .expect("rows under complete coverage");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["expected_coinbase"], 700);
        assert_eq!(rows[0]["measured_coinbase"], 700);
        assert_eq!(rows[0]["start_height"], 1);
        assert_eq!(rows[0]["end_height"], 14);
        // Lab #367 arming prep: the burn column rides every row. Zero is
        // honest HERE (this page reads its own in-process node, current wire,
        // and no name boundary is armed) — the remote-vintage honesty problem
        // that kept this off the page lives in opview, not here.
        assert_eq!(rows[0]["burned"], 0);
    }

    /// **#299 ruling item 2 on the public page.** The grandfathered epoch-1 scar keeps
    /// its row and its exact delta but carries `KNOWN_SCAR`, not `DIVERGENT` — a page
    /// that shows a permanent `DIVERGENT` teaches its readers that the token means
    /// nothing, which is the one thing this surface must not do. And the annotation has
    /// teeth: one bessel either side of the recorded total is `DIVERGENT` again.
    #[test]
    fn the_grandfathered_scar_is_named_and_a_neighbouring_total_is_not() {
        let t = Telemetry::assemble(2_303, Some(2_303), 75, 0, 3, 1, MAX_LAG)
            .with_supply(vec![epoch_one_scar_row(-4_114)]);
        let s = health(&t, "aa", 30);
        let row = &parse(&s)["supply"]["epochs"][0];
        assert_eq!(row["verdict"], KNOWN_SCAR);
        assert_eq!(row["delta"], -4_114, "the number is published, not hidden");
        assert!(
            !s.contains(DIVERGENT),
            "a standing scar must not spend the DIVERGENT token: {s}"
        );
        // KNOWN_SCAR is deliberately not a substring of DIVERGENT, so an existing
        // alerting grep neither matches it nor needs rewriting.
        assert!(!KNOWN_SCAR.contains(DIVERGENT) && !DIVERGENT.contains(KNOWN_SCAR));

        for other in [-4_113i128, -4_115] {
            let t = Telemetry::assemble(2_303, Some(2_303), 75, 0, 3, 1, MAX_LAG)
                .with_supply(vec![epoch_one_scar_row(other)]);
            let s = health(&t, "aa", 30);
            assert_eq!(parse(&s)["supply"]["epochs"][0]["verdict"], DIVERGENT, "{other}");
        }
    }

    /// The rendered page carried a `DIVERGENT` token on a non-zero supply row and
    /// pinned it as *"a stable token alerting may depend on"* (PR #236). A number in
    /// its place would have been a silent downgrade of this surface's own alerting
    /// vocabulary, so the token survives the split beside the exact signed delta.
    #[test]
    fn a_divergent_supply_row_carries_the_stable_token_and_the_exact_delta() {
        let t = Telemetry::assemble(14, Some(8), 75, 0, 3, 1, MAX_LAG)
            .with_supply(vec![epoch_row(14, 700, 705)]);
        let s = health(&t, "aa", 30);
        let v = parse(&s);
        let row = &v["supply"]["epochs"][0];

        assert_eq!(row["verdict"], DIVERGENT, "the stable token, not just a number");
        assert_eq!(row["delta"], 5, "the exact signed delta, in bessel");
        assert!(s.contains(DIVERGENT), "and it is greppable in the raw bytes");
    }

    #[test]
    fn an_agreed_supply_row_carries_no_divergence_token() {
        let t = Telemetry::assemble(14, Some(8), 75, 0, 3, 1, MAX_LAG)
            .with_supply(vec![epoch_row(14, 700, 700)]);
        let s = health(&t, "aa", 30);
        assert_eq!(parse(&s)["supply"]["epochs"][0]["verdict"], "agreed");
        assert!(!s.contains(DIVERGENT), "no token on a healthy row: {s}");
    }

    /// 🔴 The #130/#136 rule, made **structural**: on the rendered page it held
    /// because we chose not to write the figures. Here the key is absent, so a
    /// consumer cannot obtain a figure it must not display — and the distinctive
    /// value makes its absence checkable as absence.
    #[test]
    fn partial_coverage_omits_the_epochs_key_entirely_and_leaks_no_figure() {
        let t = Telemetry::assemble(14, Some(8), 75, 0, 3, 1, MAX_LAG)
            .with_supply(vec![epoch_row(4, 123_456_789, 123_456_789)]);
        assert!(matches!(
            t.supply_coverage(),
            SupplyCoverage::Unavailable { .. }
        ));
        let s = health(&t, "aa", 30);
        let v = parse(&s);

        assert_eq!(
            v["supply"]["coverage"], "UNAVAILABLE",
            "the spelling opview greps for"
        );
        assert!(
            v["supply"].get("epochs").is_none(),
            "the KEY is absent, not empty: {s}"
        );
        assert!(
            !s.contains("123456789"),
            "no figure escapes partial coverage: {s}"
        );
        assert_eq!(
            v["supply"]["state_tip"], 4,
            "the two heights the refusal is about"
        );
        assert_eq!(v["supply"]["fork_choice_tip"], 14);
    }

    /// 🔴 The fingerprint the run loop re-serializes on. Before #281 it was
    /// `(tip, final, fid, peers, epoch)` **inside `main.rs`** — so a durable head that
    /// moved, or a divergence that appeared, waited up to one `refresh_secs` to reach
    /// a reader, and no test could say so because the rule lived in CLI glue.
    #[test]
    fn the_fingerprint_moves_when_the_durable_head_does() {
        let base = Telemetry::assemble(1052, Some(1048), 42, 0, 7, 0, MAX_LAG)
            .with_durable_head(Some((1048, hash32(0x3f))));
        let advanced = Telemetry::assemble(1052, Some(1048), 42, 0, 7, 0, MAX_LAG)
            .with_durable_head(Some((1052, hash32(0x3f))));
        assert_ne!(
            fingerprint(&base),
            fingerprint(&advanced),
            "head #3 advanced"
        );

        // Same height, different block: the divergence head #3 exists to expose.
        let forked = Telemetry::assemble(1052, Some(1048), 42, 0, 7, 0, MAX_LAG)
            .with_durable_head(Some((1048, hash32(0xaa))));
        assert_ne!(
            fingerprint(&base),
            fingerprint(&forked),
            "same height, other block"
        );

        // And the availability distinction is not flattened away.
        let unreadable = Telemetry::assemble(1052, Some(1048), 42, 0, 7, 0, MAX_LAG);
        let nothing =
            Telemetry::assemble(1052, Some(1048), 42, 0, 7, 0, MAX_LAG).with_durable_head(None);
        assert_ne!(
            fingerprint(&unreadable),
            fingerprint(&nothing),
            "Unavailable vs Nothing"
        );
    }

    #[test]
    fn an_unchanged_snapshot_has_an_unchanged_fingerprint() {
        let t = || {
            Telemetry::assemble(1052, Some(1048), 42, 0, 7, 0, MAX_LAG)
                .with_durable_head(Some((1048, hash32(0x3f))))
        };
        assert_eq!(
            fingerprint(&t()),
            fingerprint(&t()),
            "no spurious re-serialization"
        );
    }

    // ---- goldens (stamp rider (1), #277's discipline) ------------------------

    /// The four states the front end in `qumbra-explorer-web` renders, and the
    /// **same bytes** it asserts against. One artifact, two directions: a field
    /// renamed on either side of the repo boundary turns one of the two red.
    fn golden_cases() -> Vec<(&'static str, String)> {
        let agreed = Telemetry::assemble(1052, Some(1048), 42, 0, 7, 3, MAX_LAG)
            .with_checkpoint(Some(0xb682_3616), None)
            .with_tip_difficulty(Some(1_048_576))
            .with_committee(21, 21, 15)
            .with_supply(vec![epoch_row(1052, 500, 500)])
            .with_durable_head(Some((1048, hash32(0x3f))));
        let lag = Telemetry::assemble(1052, Some(1048), 42, 0, 7, 3, MAX_LAG)
            .with_checkpoint(Some(0xb682_3616), None)
            .with_tip_difficulty(Some(1_048_576))
            .with_committee(21, 21, 15)
            .with_supply(vec![epoch_row(1052, 500, 500)])
            .with_durable_head(Some((1040, hash32(0x3f))));
        let absent = Telemetry::assemble(2900, Some(2864), 77, 1, 4, 2, MAX_LAG)
            .with_checkpoint(Some(0x17dd_2cbd), None)
            .with_tip_difficulty(Some(2_097_152))
            .with_committee(21, 20, 15)
            .with_supply(vec![epoch_row(2900, 900, 900)])
            .with_durable_head(None);
        let uncovered = Telemetry::assemble(14, Some(8), 75, 0, 3, 1, MAX_LAG)
            .with_supply(vec![epoch_row(4, 123_456_789, 123_456_789)])
            .with_durable_head(Some((8, hash32(0x11))));
        vec![
            ("agreed", health(&agreed, "138e1524addb", 30)),
            ("durable-lag", health(&lag, "138e1524addb", 30)),
            ("durable-absent", health(&absent, "138e1524addb", 30)),
            (
                "coverage-unavailable",
                health(&uncovered, "138e1524addb", 30),
            ),
        ]
    }

    /// 🔴 GOLDEN — the checked-in files ARE the vectors.
    ///
    /// For a **text** wire a reviewable file beats a digest: the diff shows what
    /// changed, which is what `#277`'s binary vectors could not do. Update these
    /// files ONLY with an intentional, documented shape change — and note that
    /// regenerating them is not enough on its own, because
    /// [`golden_digest_locks_the_regenerated_files`] pins a digest in *source* that
    /// a blind regeneration leaves red.
    #[test]
    fn golden_files_match_the_encoder_byte_for_byte() {
        for (name, produced) in golden_cases() {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("goldens")
                .join(name);
            let on_disk = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("golden {name} missing at {}: {e}", path.display()));
            assert_eq!(
                on_disk.trim_end_matches('\n'),
                produced,
                "golden {name} drifted — see this test's docs before updating the file"
            );
        }
    }

    /// The second place that must be updated deliberately: a digest over all four
    /// serializations, in **source**. Regenerating the files without touching this
    /// leaves the suite red, which is the point — it is the same "freeze on purpose,
    /// not by accident" the wallet-send stamp's rider (1) asks of a served wire.
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

    /// The documented regeneration path, deliberately `#[ignore]`d so no ordinary run
    /// can rewrite a golden:
    ///
    /// ```text
    /// cargo test -p qumbra-explorer regenerate_goldens -- --ignored --nocapture
    /// ```
    ///
    /// It writes the files and **does not** touch [`GOLDEN_DIGEST`]. That asymmetry is
    /// the safeguard: a regeneration nobody intended still fails
    /// `golden_digest_locks_the_regenerated_files`, and the person updating the digest
    /// has to look at the diff to do it.
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
        let hex: String = qlab_note::hash::keccak256(all.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        println!("GOLDEN_DIGEST = \"{hex}\"");
    }

    /// A hand-rolled encoder that its own input can break is a defect regardless of
    /// who calls it. Today's only caller passes `GenesisFile::hash_hex`, so this is
    /// unreachable — which is exactly why it is worth a test rather than a comment.
    #[test]
    fn a_hostile_genesis_hash_cannot_break_the_document() {
        let t = Telemetry::assemble(1, None, 0, 0, 0, 0, MAX_LAG);
        let s = health(&t, "a\"b\\c\nd", 30);
        let v = parse(&s); // would panic on malformed JSON
        assert_eq!(
            v["genesis_file_hash"], "a\"b\\c\nd",
            "and it round-trips verbatim"
        );
    }
}
