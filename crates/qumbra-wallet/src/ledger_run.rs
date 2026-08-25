//! Running the ledger against a real wallet directory over the network.
//!
//! The ledger itself lives in `qlab-ledger` so every shell shares one
//! implementation (lab #407). This half stays here because it is CLI-shaped:
//! it opens a `WalletDir`, it is `net`-gated, and it is the caller that can
//! reach the posted-fee table — `qlab-devnet` carries that table and does not
//! cross-compile to iOS, which is why the ledger takes it as an argument
//! instead of importing it.

use qlab_ledger::history::{build, render, AddressScan, Ledger};
use qlab_ledger::sends::SendLog;

/// The fee this platform can attribute. The circuit is a frozen fixed-shape
/// 2x2, so there is exactly one arity and therefore one posted fee.
pub fn posted_fee_2x2() -> u64 {
    qlab_devnet::fees::posted_fee(qlab_devnet::fees::ArityBucket::TwoByTwo)
}


/// A rendered ledger plus the caveats a caller must show beside it.
///
/// The notes are **data, not output**, because the two callers place them
/// differently — the CLI writes them to stderr, a GUI has no stderr and must put
/// them in the panel. Returning them as strings is what lets one flow serve
/// both without either re-deriving the ledger.
pub struct HistoryReport {
    /// The ledger, already rendered.
    pub text: String,
    /// 🔴 **Show these.** Each one names a reason a `recipient:` line below reads
    /// `not recorded`. Dropping them turns "this wallet has no local record of
    /// who it paid" into an unexplained blank, which is the same class of lie as
    /// a balance quoted without its coverage.
    pub notes: Vec<String>,
}

/// The structured result of the history flow, before any terminal-oriented
/// rendering. Native clients consume this so they can build accessible views
/// without parsing [`HistoryReport::text`]. All accounting and `UNAVAILABLE`
/// decisions remain in this crate.
pub struct HistoryData {
    pub ledger: Ledger,
    pub notes: Vec<String>,
}

/// The whole `history` flow: the local send log if there is one, the two chain
/// streams via [`crate::scan::gather`], and the rendered ledger.
///
/// 🔴 **One flow, every caller — the same rule [`crate::scan`] exists for.** This
/// was ~20 lines in the CLI, and a shell that wanted the ledger would have had
/// to copy them. That copy has been made before, three times, and each time it
/// diverged on the axis nobody was watching (transport, then spent-note
/// subtraction, then the shared types). The ledger is a worse thing to diverge
/// than the balance: it is the wallet's account of its own past, and two of them
/// disagreeing is not a stale number but a contradiction.
///
/// The local record is **optional enrichment and must never stop a chain-derived
/// ledger from rendering** — an unreadable file becomes a note and the ledger
/// continues, chain-only.
#[cfg(feature = "net")]
pub fn report(
    dir: &std::path::Path,
    w: &crate::store::WalletDir,
    url: &str,
    from: u64,
    to: u64,
    form: qlab_devnet::forms::GenesisForm,
) -> HistoryReport {
    let data = report_data(dir, w, url, from, to, form);
    HistoryReport { text: render(&data.ledger, url), notes: data.notes }
}

/// Run the same history flow as [`report`], returning its typed ledger.
#[cfg(feature = "net")]
pub fn report_data(
    dir: &std::path::Path,
    w: &crate::store::WalletDir,
    url: &str,
    from: u64,
    to: u64,
    form: qlab_devnet::forms::GenesisForm,
) -> HistoryData {
    use crate::sends::{SendLog, SENDS_FILE};

    let wallet = w.wallet();
    let mut notes: Vec<String> = Vec::new();

    let log = match SendLog::load(dir) {
        Ok(log) => log,
        Err(e) => {
            notes.push(format!(
                "{e} — the ledger below is chain-only, so every `recipient:` line reads \
                 `not recorded`."
            ));
            None
        }
    };
    if log.is_none() {
        notes.push(format!(
            "no {SENDS_FILE} in this wallet dir, so recipients are not shown. That file is \
             written by `send` on this machine and is NEVER recoverable from a mnemonic; \
             everything else below comes from the chain."
        ));
    }

    // 🔴 `mined` and `coinbase_coverage` are deliberately dropped here (lab
    // #415): this ledger's events are derived from transaction outputs and the
    // nullifier stream, and a coinbase receipt is a different event shape (no
    // tx, no recipient, a maturity date). Folding it in unexamined would put an
    // event in this ledger that `history`'s own grouping rules were never
    // written for. **The consequence is stated rather than hidden: a
    // mining-only wallet's `history` is empty while its `scan` now reads
    // non-zero**, which is reported as a known gap on the PR rather than
    // discovered by a miner.
    // `form` is threaded rather than hardcoded even though the coinbase half is
    // dropped two lines up: it is fetched here, and a literal form in a flow
    // that later starts *using* `mined` is precisely how lab #566 happened.
    let crate::scan::Gathered { outcomes, coverage, set, mined, .. } =
        crate::scan::gather(w, url, from, to, form);
    // 🔴 **`mined` is no longer dropped whole** (lab #658). Its *notes* still are,
    // for the reason stated above — a coinbase receipt is a different event
    // shape. What is kept is one fact off the same already-fetched pages:
    // `BlockCoinbase::name_burn`, i.e. which heights burned a name fee. A send
    // event at such a height cannot quote `inputs − change − posted_fee` as the
    // amount sent, because the burn is value that left and entered no note, so
    // that subtraction hands it to the recipient. `None` here means the route
    // was not read and the answer is unknown — which is NOT the same as no burn,
    // and is the distinction this argument exists to preserve.
    let name_burns: Option<std::collections::BTreeMap<u64, u64>> = mined.as_ref().map(|m| {
        m.blocks
            .iter()
            .filter(|b| b.name_burn > 0)
            .map(|b| (b.height, b.name_burn))
            .collect()
    });
    let scans: Vec<AddressScan> = outcomes
        .into_iter()
        .map(|(div_index, address_short, outcome)| AddressScan { div_index, address_short, outcome })
        .collect();
    let ledger = build(
        &wallet,
        &scans,
        set.as_ref(),
        &coverage,
        log.as_ref(),
        (from, to),
        // This platform HAS the posted-fee table, so send events get exact fees.
        Some(posted_fee_2x2()),
        name_burns.as_ref(),
    );
    HistoryData { ledger, notes }
}

#[cfg(all(test, feature = "net"))]
mod tests {
    // Relocated from qlab-ledger with `report` itself (lab #407): it exercises a
    // WalletDir and the net-gated flow, both of which are CLI-shaped.
    /// The local send log is optional enrichment; its absence is a NOTE, never a
    /// missing ledger and never a silent blank.
    ///
    /// A restored wallet never has a `sends.v1` — it is written by `send` on one
    /// machine and is not recoverable from a mnemonic — so this is the ordinary
    /// state for anyone who moved wallets, not an edge case. The endpoint here is
    /// dead as well, which is the harsher combination: no local record AND no
    /// chain. Both facts must reach the caller.
    #[test]
    fn a_wallet_with_no_send_log_gets_a_note_and_still_gets_a_ledger() {
        use crate::store::WalletDir;
        use qlab_wallet::seed::{MasterSeed, ENTROPY_LEN};
        use rand::Rng;

        let dir = std::env::temp_dir().join("qmb_history_report_no_log");
        let _ = std::fs::remove_dir_all(&dir);
        let mut entropy = [0u8; ENTROPY_LEN];
        rand::rng().fill_bytes(&mut entropy);
        let w = WalletDir::create(&dir, MasterSeed::from_entropy(entropy)).expect("create wallet");

        let out = super::report(&dir, &w, "http://127.0.0.1:1", 0, 8, qlab_devnet::forms::GenesisForm::V4);

        assert!(
            out.notes.iter().any(|n| n.contains(crate::sends::SENDS_FILE)),
            "the absent local record must be NAMED: {:?}",
            out.notes
        );
        assert!(!out.text.is_empty(), "a chain-only ledger still renders");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
