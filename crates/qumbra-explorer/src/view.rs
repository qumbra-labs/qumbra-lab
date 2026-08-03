//! Render one [`Telemetry`] snapshot as the chain-health page.
//!
//! Pure: `Telemetry` in, HTML out. Every availability decision is delegated to
//! the snapshot's own rules (`age_field`, `supply_coverage`) — this module
//! formats verdicts, it does not make them. The two tokens alerting or a reader
//! may grep for are stable and pinned by tests on both sides: `UNAVAILABLE`
//! (supply figures refused, issues #130/#136) and `DIVERGENT` (a supply row
//! whose exact divergence is non-zero).

use qlab_devnet::ebbflow::FinalityStatus;
use qlab_node::telemetry::SupplyCoverage;
use qlab_node::Telemetry;

/// The label rendered beside `fid` until issue #212 lands: the value is the
/// committee tracker's in-memory view, not the durable finalized head, and a
/// public page must not launder that distinction.
pub const FID_CAVEAT: &str = "committee-tracker view, not the durable head — lab #212";

/// The stable refused-figures token, same spelling as `qumbra-opview`'s (#136),
/// so one grep covers both surfaces.
pub const UNAVAILABLE: &str = "UNAVAILABLE";

/// The stable non-zero-divergence token.
pub const DIVERGENT: &str = "DIVERGENT";

fn regime(s: FinalityStatus) -> &'static str {
    match s {
        FinalityStatus::Final => "final",
        FinalityStatus::Degraded => "degraded (PoW-only until finality resumes)",
        FinalityStatus::Halting => "halting (paused at the upgrade boundary)",
        FinalityStatus::Halted => "halted (upgrade boundary finalized)",
    }
}

fn row(label: &str, value: &str) -> String {
    format!("<tr><th>{label}</th><td>{value}</td></tr>\n")
}

fn opt(v: Option<u64>) -> String {
    v.map(|x| x.to_string()).unwrap_or_else(|| "-".into())
}

/// The whole page. `genesis_file_hash` is [`GenesisFile::hash_hex`]'s value — the
/// hash a node refuses to boot against a mismatch of (named per issue #206's
/// which-hash-is-which discipline).
pub fn render(t: &Telemetry, genesis_file_hash: &str, refresh_secs: u64) -> String {
    let mut chain = String::new();
    chain.push_str(&row("tip height", &t.tip_height.to_string()));
    chain.push_str(&row("tip difficulty", &opt(t.tip_difficulty)));
    chain.push_str(&row("regime", regime(t.finality_status)));
    chain.push_str(&row("peers", &t.peer_count.to_string()));
    chain.push_str(&row("mempool", &t.mempool_size.to_string()));

    let mut finality = String::new();
    finality.push_str(&row(
        "finalized height",
        &t.finalized_height.map(|h| h.to_string()).unwrap_or_else(|| "none yet".into()),
    ));
    finality.push_str(&row("age (chain-time s)", &t.age_field()));
    finality.push_str(&row("stall depth", &t.stall_depth.to_string()));
    finality.push_str(&row(
        "checkpoint identity",
        &format!("{} <small>({FID_CAVEAT})</small>", opt(t.finalized_id)),
    ));

    let mut committee = String::new();
    committee.push_str(&row("epoch", &t.epoch.to_string()));
    committee.push_str(&row("roster", &t.committee_size.to_string()));
    committee.push_str(&row("active", &t.committee_active.to_string()));
    committee.push_str(&row("quorum", &t.committee_quorum.to_string()));

    let supply = match t.supply_coverage() {
        SupplyCoverage::Unavailable { state_tip, fork_choice_tip } => format!(
            "<p><strong>{UNAVAILABLE}</strong> — the supply ledger covers height {} while \
             fork choice is at {}. The only conclusion available is that this node's ledger \
             is behind: <em>neither supply agreement nor a supply violation</em> (issues \
             #130/#136). No figures are rendered from partial coverage.</p>",
            state_tip.map(|h| h.to_string()).unwrap_or_else(|| "-".into()),
            fork_choice_tip,
        ),
        SupplyCoverage::Complete => {
            let mut rows = String::from(
                "<table><tr><th>epoch</th><th>heights</th><th>expected (bessel)</th>\
                 <th>measured (bessel)</th><th>fees</th><th>verdict</th></tr>\n",
            );
            for e in &t.supply {
                let delta = e.measured_coinbase as i128 - e.expected_coinbase as i128;
                let verdict = if delta == 0 {
                    "agreed".to_string()
                } else {
                    format!("🔴 {DIVERGENT} ({delta:+} bessel)")
                };
                rows.push_str(&format!(
                    "<tr><td>{}</td><td>{}–{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                    e.epoch, e.start_height, e.end_height, e.expected_coinbase,
                    e.measured_coinbase, e.fees, verdict,
                ));
            }
            rows.push_str("</table>\n");
            rows
        }
    };

    format!(
        "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n\
         <meta http-equiv=\"refresh\" content=\"{refresh_secs}\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>Qumbra chain health</title>\n\
         <style>body{{font-family:monospace;max-width:52rem;margin:2rem auto;padding:0 1rem}}\
         table{{border-collapse:collapse;margin:0 0 1.5rem}}th,td{{border:1px solid #8884;\
         padding:.25rem .6rem;text-align:left}}h2{{margin:1.2rem 0 .4rem}}small{{opacity:.75}}\
         footer{{margin-top:2rem;opacity:.75}}</style></head><body>\n\
         <h1>Qumbra chain health</h1>\n\
         <p>genesis file hash <code>{genesis_file_hash}</code> — this page is rendered from \
         its own observer node's view of the network, refreshed every {refresh_secs}\u{2009}s.</p>\n\
         <h2>Chain</h2>\n<table>\n{chain}</table>\n\
         <h2>Finality</h2>\n<table>\n{finality}</table>\n\
         <h2>Committee</h2>\n<table>\n{committee}</table>\n\
         <h2>Supply attestation</h2>\n{supply}\
         <footer><p>Read-only. This is deliberately <strong>not</strong> a transaction \
         explorer: no transaction, address or note lookup exists here or anywhere — Qumbra \
         is a single shielded pool (testnet-plan §6). The fleet's telemetry endpoints are \
         private; this page's node learns over P2P like any peer.</p></footer>\n\
         </body></html>\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_node::supply::SupplyEpoch;

    const MAX_LAG: u64 = 16;

    fn epoch_row(end: u64, expected: u64, measured: u64) -> SupplyEpoch {
        SupplyEpoch {
            epoch: 0,
            start_height: 1,
            end_height: end,
            measured_coinbase: measured,
            expected_coinbase: expected,
            fees: 0,
        }
    }

    #[test]
    fn renders_chain_finality_committee_and_the_fid_caveat() {
        let t = Telemetry::assemble(34, Some(24), 75, 2, 3, 1, MAX_LAG)
            .with_checkpoint(Some(0xb682_3616), None)
            .with_tip_difficulty(Some(1_048_576))
            .with_committee(21, 21, 15)
            .with_supply(vec![epoch_row(34, 500, 500)]);
        let html = render(&t, "8811d4e0aabb", 30);
        assert!(html.contains("<td>34</td>") || html.contains("<td>34<"), "tip");
        assert!(html.contains("1048576"), "difficulty");
        assert!(html.contains("8811d4e0aabb"), "genesis file hash");
        assert!(html.contains(&0xb682_3616u64.to_string()), "fid value");
        assert!(html.contains(FID_CAVEAT), "the #212 caveat must sit beside fid");
        assert!(html.contains("<th>quorum</th><td>15</td>"), "quorum");
    }

    #[test]
    fn partial_supply_coverage_renders_unavailable_and_never_a_number() {
        // Distinctive figures so absence is checkable as absence.
        let t = Telemetry::assemble(14, Some(8), 75, 0, 3, 1, MAX_LAG)
            .with_supply(vec![epoch_row(4, 123_456_789, 123_456_789)]);
        assert!(matches!(t.supply_coverage(), SupplyCoverage::Unavailable { .. }));
        let html = render(&t, "aa", 30);
        assert!(html.contains(UNAVAILABLE), "the stable token");
        assert!(html.contains("height 4"), "state tip named");
        assert!(!html.contains("123456789"), "no figure escapes partial coverage");
        assert!(html.contains("neither supply agreement nor a supply violation"));
    }

    #[test]
    fn complete_coverage_renders_figures_and_no_unavailable_token() {
        let t = Telemetry::assemble(14, Some(8), 75, 0, 3, 1, MAX_LAG)
            .with_supply(vec![epoch_row(14, 700, 700)]);
        assert!(matches!(t.supply_coverage(), SupplyCoverage::Complete));
        let html = render(&t, "aa", 30);
        assert!(html.contains("<td>700</td>"), "figures render under complete coverage");
        assert!(!html.contains(UNAVAILABLE), "token absent under complete coverage");
        assert!(html.contains("agreed"));
        assert!(!html.contains(DIVERGENT));
    }

    #[test]
    fn a_divergent_supply_row_is_flagged_with_the_stable_token() {
        let t = Telemetry::assemble(14, Some(8), 75, 0, 3, 1, MAX_LAG)
            .with_supply(vec![epoch_row(14, 700, 705)]);
        let html = render(&t, "aa", 30);
        assert!(html.contains(DIVERGENT), "non-zero divergence is named");
        assert!(html.contains("+5"), "the exact signed delta is shown");
    }

    #[test]
    fn nothing_finalized_renders_named_states_not_zeros() {
        let t = Telemetry::assemble(0, None, 0, 0, 0, 0, MAX_LAG);
        let html = render(&t, "aa", 30);
        assert!(html.contains("none yet"), "finalized height is a named state");
        assert!(
            html.contains("<th>age (chain-time s)</th><td>-</td>"),
            "age_field's refusal (issue #73) reaches the page verbatim"
        );
    }
}
