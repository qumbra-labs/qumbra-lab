//! **The wallet on an Annulet net** (lab #718, L2 C1): the asset-aware scan and
//! the per-asset balance.
//!
//! What differs from the L1 scan is decided here, by name:
//!
//! - **The form is verified, not assumed.** An Annulet node answers
//!   `/v1/genesis/notes` with its genesis hash, and an L1 node refuses that
//!   route by name. So `--net annulet` against an L1 endpoint fails loudly,
//!   and an optional `--genesis-hash` pin refuses any other Annulet genesis.
//!   The L1 cannot do this: nothing it serves carries its genesis (lab #566).
//! - **The notes are `L2Note`s** at the 128-B payload width, scanned by the one
//!   light-client driver instantiated at `L2Note`.
//! - **Genesis notes count.** They are not on `/v1/compact` (height 0 is
//!   groupless); they are served as plaintext on `/v1/genesis/notes`, and a
//!   wallet owns the ones whose `rkm` is one of its addresses'.
//! - **There is no coinbase** on a sequencer net: nothing is fetched and no
//!   mined figure is reported, never a zero.
//! - **Balances are per asset**, in each asset's own units. Asset 0 is the fee
//!   unit, never QMB.
//!
//! The rule is still lab #314's: a figure exists only where both the outputs
//! and the nullifier stream are known.
//!
//! Every function takes a **fetch closure** (`path → bytes`), the shape the L1
//! scan lends to `qumbra-wallet`'s TLS transport, so the flow is the same over
//! a socket, over https, and over an in-process fixture.

use std::cell::RefCell;

use qlab_cbserver::client::{light_client_scan_l2_with, ScanConfig, ScanOutcome};
use qlab_ledger::assets::{AssetIndex, OwnedL2Note};
use qlab_ledger::spent::{coverage_for, widest_range, NullifierChunk, NullifierSource, SpentSet};
use qlab_ledger::vocab::SpentCoverage;
use qlab_note::l2note::{GenesisPlaintext, L2Note};
use rand::rngs::StdRng;

use crate::store::WalletDir;

/// Why an Annulet scan did not start — by name. Each is a refusal of the
/// whole scan, not a row: without a verified form there is nothing to report.
#[derive(Debug, PartialEq, Eq)]
pub enum AnnuletRefusal {
    /// `/v1/genesis/notes` did not answer as an Annulet node answers it. An L1
    /// node refuses that route; so does anything that is not a node.
    NotAnnulet { why: String },
    /// The endpoint's genesis is not the pinned one.
    GenesisMismatch { pinned: [u8; 32], served: [u8; 32] },
}

impl std::fmt::Display for AnnuletRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnnuletRefusal::NotAnnulet { why } => write!(
                f,
                "--net annulet, but this endpoint does not serve an Annulet chain: /v1/genesis/notes \
                 answered {why}. An L1 node refuses that route; point --url at an Annulet node or \
                 drop --net annulet"
            ),
            AnnuletRefusal::GenesisMismatch { pinned, served } => write!(
                f,
                "the endpoint serves genesis {} but --genesis-hash pins {} — refusing to report \
                 balances of a different chain",
                hex(served),
                hex(pinned)
            ),
        }
    }
}

impl std::error::Error for AnnuletRefusal {}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Parse a `--genesis-hash` value (64 hex characters).
pub fn parse_genesis_hash(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    if s.len() != 64 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("--genesis-hash must be 64 hex characters, got {:?}", s));
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("checked hex");
    }
    Ok(out)
}

/// A served genesis: its hash, and each genesis note with its committed cm.
pub type ServedGenesis = ([u8; 32], Vec<([u8; 32], L2Note)>);

/// Verify the form against the endpoint: read `/v1/genesis/notes`, check the
/// pin, and return the served genesis hash with its notes.
pub fn verify_annulet<F>(fetch: &mut F, pin: Option<[u8; 32]>) -> Result<ServedGenesis, AnnuletRefusal>
where
    F: FnMut(&str) -> Result<Vec<u8>, String>,
{
    let body = fetch("/v1/genesis/notes").map_err(|why| AnnuletRefusal::NotAnnulet { why })?;
    let (served, notes) = qlab_cbserver::registry::decode_genesis_notes(&body)
        .map_err(|e| AnnuletRefusal::NotAnnulet { why: format!("an undecodable body ({e:?})") })?;
    if let Some(pinned) = pin {
        if pinned != served {
            return Err(AnnuletRefusal::GenesisMismatch { pinned, served });
        }
    }
    let mut opened = Vec::with_capacity(notes.len());
    for n in &notes {
        let note = GenesisPlaintext::open(&n.payload.0).ok_or_else(|| AnnuletRefusal::NotAnnulet {
            why: "a genesis note that does not open as a genesis plaintext".into(),
        })?;
        opened.push((n.cm, note));
    }
    Ok((served, opened))
}

/// A [`NullifierSource`] over a fetch closure.
struct FetchNullifiers<'a, F>(RefCell<&'a mut F>);

impl<F> NullifierSource for FetchNullifiers<'_, F>
where
    F: FnMut(&str) -> Result<Vec<u8>, String>,
{
    fn fetch_range(&self, from: u64, to: u64) -> Result<NullifierChunk, String> {
        let path = format!("/v1/nullifiers?from={from}&to={to}");
        let bytes = (self.0.borrow_mut())(&path).map_err(|e| format!("GET {path}: {e}"))?;
        let page = qlab_cbserver::codec::NullifierPage::from_bytes(&bytes)
            .map_err(|e| format!("GET {path} did not decode: {e:?}"))?;
        Ok(NullifierChunk {
            from: page.from,
            to: page.to,
            blocks: page.blocks.into_iter().map(|b| (b.height, b.nullifiers)).collect(),
        })
    }
}

/// One address's row: its scan, or why the scan never started.
pub struct AnnuletRow {
    pub index: u64,
    pub short: String,
    pub scan: Result<ScanOutcome<L2Note>, String>,
}

/// Everything an Annulet scan read, and the per-asset index when both halves
/// are known.
pub struct AnnuletReport {
    /// The served (and, when pinned, verified) genesis hash.
    pub genesis_hash: [u8; 32],
    pub rows: Vec<AnnuletRow>,
    /// Genesis notes whose `rkm` is one of this wallet's addresses'.
    pub genesis_owned: usize,
    pub spent: SpentCoverage,
    /// `Some` only when every scan started and the nullifier stream covers
    /// what they found (lab #314): the per-asset figures.
    pub index: Option<AssetIndex>,
    /// Notes a scan opened that did not become owned records (an asset lane
    /// out of range, or an `rkm` that is not the address's), by reason.
    pub refused: Vec<String>,
}

/// **The Annulet scan**: verify the form, scan every allocated address at
/// the L2 width, match genesis notes, fetch the nullifier stream over what
/// the outputs reached, and index per asset.
pub fn scan_annulet<F>(
    w: &WalletDir,
    fetch: &mut F,
    from: u64,
    to: u64,
    pin: Option<[u8; 32]>,
    rng: &mut StdRng,
) -> Result<AnnuletReport, AnnuletRefusal>
where
    F: FnMut(&str) -> Result<Vec<u8>, String>,
{
    let wallet = w.wallet();
    let (genesis_hash, genesis) = verify_annulet(fetch, pin)?;

    let mut rows = Vec::new();
    for &idx in &w.allocated {
        let kp = wallet.diversified_keypair(&wallet.diversifier_at_index(idx));
        let scan = light_client_scan_l2_with(fetch, &kp.dk, from, to, ScanConfig::default(), rng)
            .map_err(|e| e.to_string());
        rows.push(AnnuletRow { index: idx, short: wallet.address_at_index(idx).short().encode(), scan });
    }

    let mut owned = Vec::new();
    let mut refused = Vec::new();
    for (cm, note) in &genesis {
        for &idx in &w.allocated {
            if wallet.rkm(wallet.diversifier_at_index(idx)) == note.rkm {
                match OwnedL2Note::from_genesis(&wallet, idx, *cm, *note) {
                    Ok(n) => owned.push(n),
                    Err(e) => refused.push(format!("genesis note: {e}")),
                }
            }
        }
    }
    let genesis_owned = owned.len();
    for row in &rows {
        if let Ok(outcome) = &row.scan {
            for located in &outcome.notes {
                match OwnedL2Note::from_located(&wallet, row.index, located) {
                    Ok(n) => owned.push(n),
                    Err(e) => refused.push(format!("height {} tx {}: {e}", located.height, located.tx_index)),
                }
            }
        }
    }

    // The nullifier stream must cover everything the owned notes could have
    // been spent in: a genesis note from height 1 on.
    let outputs = widest_range(
        rows.iter()
            .filter_map(|r| r.scan.as_ref().ok())
            .map(|o| o.stats.compact_range_served)
            .chain(std::iter::once((genesis_owned > 0).then_some((1, 1)))),
    );
    let nf_from = if genesis_owned > 0 { from.min(1) } else { from };
    let source = FetchNullifiers(RefCell::new(fetch));
    let (spent, set): (SpentCoverage, Option<SpentSet>) = coverage_for(&source, nf_from, to, outputs);

    let every_scan_started = rows.iter().all(|r| r.scan.is_ok());
    let index = match (&set, every_scan_started) {
        (Some(set), true) => Some(AssetIndex::build(&wallet, owned, set)),
        _ => None,
    };
    Ok(AnnuletReport { genesis_hash, rows, genesis_owned, spent, index, refused })
}

/// The report as text: the verified genesis, one line per asset, the
/// coverage, and every row that could not be read — never a figure without
/// both halves.
pub fn render(report: &AnnuletReport, url: &str, range: (u64, u64)) -> String {
    let mut out = String::new();
    out.push_str(&format!("net:      annulet — genesis {} (verified against {url})\n", hex(&report.genesis_hash)));
    out.push_str(&format!("range:    {}..={}\n", range.0, range.1));
    out.push_str("coinbase: none on a sequencer net (not fetched)\n");
    match &report.spent {
        SpentCoverage::Covered { range: Some((a, b)) } => out.push_str(&format!("spends:   subtracted over {a}..={b}\n")),
        SpentCoverage::Covered { range: None } => out.push_str("spends:   the endpoint held no block in range\n"),
        SpentCoverage::Unavailable { why } => out.push_str(&format!("spends:   UNAVAILABLE ({why})\n")),
    }
    for row in &report.rows {
        if let Err(why) = &row.scan {
            out.push_str(&format!("address {} ({}): UNAVAILABLE — the scan never started: {why}\n", row.index, row.short));
        }
    }
    match &report.index {
        None => out.push_str("balance:  UNAVAILABLE — no figure without both the outputs and the spends\n"),
        Some(index) if index.by_asset.is_empty() => out.push_str("balance:  no notes in range\n"),
        Some(index) => {
            for (asset, notes) in &index.by_asset {
                let unit = if *asset == 0 { " (fee units)" } else { "" };
                out.push_str(&format!(
                    "asset {asset}{unit}: {} spendable in {} note(s); {} spent\n",
                    notes.spendable_value(),
                    notes.spendable.len(),
                    notes.spent.len()
                ));
            }
        }
    }
    for why in &report.refused {
        out.push_str(&format!("refused:  {why}\n"));
    }
    out
}

/// [`render`] with a fixed URL and range — the tests' view of the text.
#[doc(hidden)]
pub fn render_for_test(report: &AnnuletReport) -> String {
    render(report, "fixture", (0, 10))
}
