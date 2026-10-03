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

use qlab_cbserver::client::{
    light_client_scan_l2_multi_with, light_client_scan_l2_with, MultiScan, MultiScanDriver, MultiScanRefusal, MultiScanStep,
    ScanConfig, ScanOutcome,
};
use qlab_ledger::assets::{AssetIndex, OwnedL2Note};
use qlab_ledger::spent::{coverage_of, widest_range, NullifierChunk, SpentCatchUp, SpentRefusal, SpentSet};
use qlab_ledger::vocab::SpentCoverage;
use qlab_note::l2note::{GenesisPlaintext, L2Note};
use qlab_note::kem::Dk;
use qlab_wallet::Wallet;
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

/// Where the nullifier stream must start for owned genesis notes: height 1
/// is the first a genesis note can be spent in, and height 0 when the scan
/// starts there — so a chain still at its genesis (tip 0) is covered by the
/// genesis block itself rather than asked for a height 1 that does not
/// exist yet (lab #722: C3's first lane run, a mint at tip 0 read `NoBalance`).
fn genesis_from(from: u64) -> u64 {
    from.min(1)
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
    /// Every note this scan made the wallet's, genesis notes first — what the
    /// ledger (`history --net annulet`, lab #831 W1) is built from, kept
    /// whether or not an index could be.
    pub owned: Vec<OwnedL2Note>,
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
    let (genesis_hash, genesis) = verify_annulet(fetch, pin)?;
    Ok(scan_annulet_from(w, fetch, from, to, genesis_hash, &genesis, rng))
}

/// [`scan_annulet`] after its genesis is known: scan every allocated address
/// over `from ..= to`, match `genesis`'s notes, read the spends, and index.
/// Lab #850 (AD1) split it out so the verified scan
/// ([`crate::annulet_verify`]) runs the same body over genesis notes read from
/// the genesis **file** it hashed, not from `/v1/genesis/notes`. Since lab
/// #858 WA1 it is the pump of [`AnnuletScanCore`], the one orchestration.
pub fn scan_annulet_from<F>(
    w: &WalletDir,
    fetch: &mut F,
    from: u64,
    to: u64,
    genesis_hash: [u8; 32],
    genesis: &[([u8; 32], L2Note)],
    rng: &mut StdRng,
) -> AnnuletReport
where
    F: FnMut(&str) -> Result<Vec<u8>, String>,
{
    let mut core = AnnuletScanCore::new(w.wallet(), w.allocated.clone(), from, to, genesis_hash, genesis.to_vec());
    loop {
        match core.step(rng) {
            CoreStep::Need(path) => core.supply(fetch(&path)),
            CoreStep::Done(report) => return report,
            CoreStep::Failed(why) => unreachable!("the pump never misuses the scan core: {why}"),
        }
    }
}

/// One observation from a caller-pumped [`AnnuletScanCore`]. `Done` and
/// `Failed` are terminal. The scan itself never fails — what it cannot read
/// becomes a row's or the spends' named gap, as it always has; `Failed` is
/// only a host's misuse (a step after `Done`, an answer with no `Need`
/// outstanding), by name.
pub enum CoreStep {
    Need(String),
    Done(AnnuletReport),
    Failed(String),
}

/// **The scan body, caller-pumped** (lab #858 WA1): every allocated address
/// over one shared fetch ([`MultiScanDriver`]), the genesis notes matched, the
/// nullifier stream paged through [`SpentCatchUp`] — the one copy of the
/// paging checks — and judged by [`coverage_of`], the one copy of the
/// Covered/Unavailable rule. No I/O: [`scan_annulet_from`] and the verified
/// driver ([`crate::annulet_driver`]) are its pumps.
pub struct AnnuletScanCore {
    wallet: Wallet,
    allocated: Vec<u64>,
    from: u64,
    to: u64,
    genesis_hash: [u8; 32],
    genesis: Vec<([u8; 32], L2Note)>,
    phase: CorePhase,
    pending: Option<String>,
    failed: Option<String>,
}

enum CorePhase {
    Rows(Option<Box<MultiScanDriver>>),
    Spent { tally: Box<Tally>, catch: SpentCatchUp },
    Finished,
}

/// What the rows made the wallet's, before the spends are read.
struct Tally {
    rows: Vec<AnnuletRow>,
    owned: Vec<OwnedL2Note>,
    refused: Vec<String>,
    genesis_owned: usize,
    outputs: Option<(u64, u64)>,
    /// The paging's verdict, once a page or the transport ended it.
    stream: Option<Result<SpentSet, SpentRefusal>>,
}

impl AnnuletScanCore {
    pub fn new(
        wallet: Wallet,
        allocated: Vec<u64>,
        from: u64,
        to: u64,
        genesis_hash: [u8; 32],
        genesis: Vec<([u8; 32], L2Note)>,
    ) -> Self {
        let rows = (!allocated.is_empty())
            .then(|| Box::new(MultiScanDriver::new(scan_keys(&wallet, &allocated), from, to, ScanConfig::default())));
        AnnuletScanCore { wallet, allocated, from, to, genesis_hash, genesis, phase: CorePhase::Rows(rows), pending: None, failed: None }
    }

    /// Advance until the scan needs one path or completes.
    pub fn step(&mut self, rng: &mut StdRng) -> CoreStep {
        if let Some(why) = &self.failed {
            return CoreStep::Failed(why.clone());
        }
        if let Some(path) = &self.pending {
            return CoreStep::Need(path.clone());
        }
        loop {
            match std::mem::replace(&mut self.phase, CorePhase::Finished) {
                CorePhase::Rows(None) => self.spent_phase(Vec::new()),
                CorePhase::Rows(Some(mut multi)) => match multi.step(rng) {
                    MultiScanStep::Need(path) => {
                        self.phase = CorePhase::Rows(Some(multi));
                        self.pending = Some(path.clone());
                        return CoreStep::Need(path);
                    }
                    MultiScanStep::Done(m) => {
                        let rows = rows_of(&self.wallet, &self.allocated, Ok(m));
                        self.spent_phase(rows);
                    }
                    MultiScanStep::Failed(refusal) => {
                        let rows = rows_of(&self.wallet, &self.allocated, Err(refusal));
                        self.spent_phase(rows);
                    }
                },
                CorePhase::Spent { mut tally, catch } => {
                    if tally.stream.is_none() {
                        if let Some((from, to)) = catch.want() {
                            let path = nullifiers_path(from, to);
                            self.phase = CorePhase::Spent { tally, catch };
                            self.pending = Some(path.clone());
                            return CoreStep::Need(path);
                        }
                        tally.stream = Some(Ok(catch.finish()));
                    }
                    let stream = tally.stream.take().expect("set above or by a page");
                    return CoreStep::Done(self.report(*tally, stream));
                }
                CorePhase::Finished => {
                    let why = "scan core already completed".to_string();
                    self.failed = Some(why.clone());
                    return CoreStep::Failed(why);
                }
            }
        }
    }

    /// Answer the outstanding `Need`. An answer with none outstanding fails
    /// the core by name.
    pub fn supply(&mut self, answer: Result<Vec<u8>, String>) {
        if self.failed.is_some() {
            return;
        }
        let Some(path) = self.pending.take() else {
            self.failed = Some("scan core received a response without requesting a path".into());
            return;
        };
        match &mut self.phase {
            CorePhase::Rows(Some(multi)) => multi.supply(answer),
            CorePhase::Spent { tally, catch } => {
                let fed = nullifier_chunk(&path, answer)
                    .map_err(|why| SpentRefusal::Endpoint { why })
                    .and_then(|page| catch.supply(page));
                if let Err(e) = fed {
                    tally.stream = Some(Err(e));
                }
            }
            CorePhase::Rows(None) | CorePhase::Finished => {}
        }
    }

    fn spent_phase(&mut self, rows: Vec<AnnuletRow>) {
        let wallet = &self.wallet;
        let mut owned = Vec::new();
        let mut refused = Vec::new();
        for (cm, note) in &self.genesis {
            for &idx in &self.allocated {
                if wallet.rkm(wallet.diversifier_at_index(idx)) == note.rkm {
                    match OwnedL2Note::from_genesis(wallet, idx, *cm, *note) {
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
                    match OwnedL2Note::from_located(wallet, row.index, located) {
                        Ok(n) => owned.push(n),
                        Err(e) => refused.push(format!("height {} tx {}: {e}", located.height, located.tx_index)),
                    }
                }
            }
        }

        // The nullifier stream must cover everything the owned notes could have
        // been spent in: a genesis note from height 1 on (from 0 when the scan
        // starts at 0, which also covers a chain still at its genesis).
        let from = self.from;
        let outputs = widest_range(
            rows.iter()
                .filter_map(|r| r.scan.as_ref().ok())
                .map(|o| o.stats.compact_range_served)
                .chain(std::iter::once((genesis_owned > 0).then_some((genesis_from(from), genesis_from(from))))),
        );
        let nf_from = if genesis_owned > 0 { genesis_from(from) } else { from };
        let tally = Box::new(Tally { rows, owned, refused, genesis_owned, outputs, stream: None });
        self.phase = CorePhase::Spent { tally, catch: SpentCatchUp::new(nf_from, self.to) };
    }

    fn report(&self, tally: Tally, stream: Result<SpentSet, SpentRefusal>) -> AnnuletReport {
        let Tally { rows, owned, refused, genesis_owned, outputs, .. } = tally;
        let (spent, set): (SpentCoverage, Option<SpentSet>) = coverage_of(stream, outputs);
        let every_scan_started = rows.iter().all(|r| r.scan.is_ok());
        let index = match (&set, every_scan_started) {
            (Some(set), true) => Some(AssetIndex::build(&self.wallet, owned.clone(), set)),
            _ => None,
        };
        AnnuletReport { genesis_hash: self.genesis_hash, rows, genesis_owned, owned, spent, index, refused }
    }
}

/// `/v1/nullifiers` over `from ..= to`.
fn nullifiers_path(from: u64, to: u64) -> String {
    format!("/v1/nullifiers?from={from}&to={to}")
}

/// One `/v1/nullifiers` answer as a page, or why not — the one reading of
/// the route, for the synchronous source and the pumped core alike.
fn nullifier_chunk(path: &str, answer: Result<Vec<u8>, String>) -> Result<NullifierChunk, String> {
    let bytes = answer.map_err(|e| format!("GET {path}: {e}"))?;
    let page = qlab_cbserver::codec::NullifierPage::from_bytes(&bytes)
        .map_err(|e| format!("GET {path} did not decode: {e:?}"))?;
    Ok(NullifierChunk {
        from: page.from,
        to: page.to,
        blocks: page.blocks.into_iter().map(|b| (b.height, b.nullifiers)).collect(),
    })
}

/// Each allocated index's scan key.
fn scan_keys(wallet: &Wallet, allocated: &[u64]) -> Vec<(u64, Dk)> {
    allocated.iter().map(|&idx| (idx, wallet.diversified_keypair(&wallet.diversifier_at_index(idx)).dk)).collect()
}

/// The rows out of a multi-key scan: one per index, or every index failed
/// with the driver's message.
fn rows_of(wallet: &Wallet, allocated: &[u64], scan: Result<MultiScan, MultiScanRefusal>) -> Vec<AnnuletRow> {
    let short = |idx: u64| wallet.address_at_index(idx).short().encode();
    match scan {
        Ok(multi) => multi.outcomes.into_iter().map(|(idx, outcome)| AnnuletRow { index: idx, short: short(idx), scan: Ok(outcome) }).collect(),
        Err(refusal) => {
            let why = match refusal {
                MultiScanRefusal::Range(why) => why,
                other => format!("{other:?}"),
            };
            allocated.iter().map(|&idx| AnnuletRow { index: idx, short: short(idx), scan: Err(why.clone()) }).collect()
        }
    }
}

/// One row per allocated index, scanned over **one** fetch of the range (lab
/// #819): `light_client_scan_l2_multi_with` runs each index's key through the
/// unchanged scan driver over a shared fetch, so the range and every `/full`
/// are requested once — not once per index, which cost N× the pages and
/// told the server how many addresses this wallet holds.
///
/// Each row is what [`annulet_rows_per_index`] (the pre-#819 path) gives on
/// the same responses. A range that cannot be read fails every row with the
/// driver's message, exactly as each per-index scan of it failed.
pub fn annulet_rows<F>(w: &WalletDir, fetch: &mut F, from: u64, to: u64, rng: &mut StdRng) -> Vec<AnnuletRow>
where
    F: FnMut(&str) -> Result<Vec<u8>, String>,
{
    let wallet = w.wallet();
    if w.allocated.is_empty() {
        return Vec::new();
    }
    let keys = scan_keys(&wallet, &w.allocated);
    rows_of(&wallet, &w.allocated, light_client_scan_l2_multi_with(fetch, &keys, from, to, ScanConfig::default(), rng))
}

/// The pre-#819 rows: one full scan of the range per allocated index. **Kept
/// only as the equality reference for `tests/annulet_scan.rs`; not a scan
/// path** — the wallet scans through [`annulet_rows`].
#[doc(hidden)]
pub fn annulet_rows_per_index<F>(w: &WalletDir, fetch: &mut F, from: u64, to: u64, rng: &mut StdRng) -> Vec<AnnuletRow>
where
    F: FnMut(&str) -> Result<Vec<u8>, String>,
{
    let wallet = w.wallet();
    w.allocated
        .iter()
        .map(|&idx| {
            let kp = wallet.diversified_keypair(&wallet.diversifier_at_index(idx));
            let scan = light_client_scan_l2_with(fetch, &kp.dk, from, to, ScanConfig::default(), rng).map_err(|e| e.to_string());
            AnnuletRow { index: idx, short: wallet.address_at_index(idx).short().encode(), scan }
        })
        .collect()
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

/// **The Annulet ledger** (lab #831 W1): the scan's report, read as this
/// wallet's history. Every verdict and every gap is the scan's own — an
/// address whose scan never started, outputs detected and not read, a note
/// refused — handed to [`qlab_ledger::l2history::build`] verbatim, so the
/// ledger and `scan --net annulet` can never disagree about what was read.
pub fn history(report: &AnnuletReport, range: (u64, u64)) -> qlab_ledger::l2history::L2Ledger {
    use qlab_cbserver::client::Completeness;
    use qlab_ledger::l2history::{build, L2Verdict};
    use qlab_ledger::vocab::UNAVAILABLE;

    let mut verdicts = Vec::new();
    let mut gaps = Vec::new();
    for row in &report.rows {
        let verdict = match &row.scan {
            Err(why) => {
                gaps.push(format!(
                    "outputs for address [{}] over heights {}..={}: the scan never started ({why})",
                    row.index, range.0, range.1
                ));
                format!("{UNAVAILABLE} — the scan never started: {why}")
            }
            Ok(outcome) => match outcome.completeness() {
                Completeness::Complete => "complete".to_string(),
                Completeness::Shadowed { opened, spendable } => format!(
                    "complete; {} of {opened} opened note(s) are already dead (another note claims \
                     their nullifier) and are in no figure",
                    opened - spendable
                ),
                Completeness::Incomplete { detected, opened }
                | Completeness::IncompleteAndShadowed { detected, opened, .. } => {
                    gaps.push(format!(
                        "outputs for address [{}]: {detected} output(s) are this key's by the \
                         committed discovery and only {opened} could be read",
                        row.index
                    ));
                    format!("{UNAVAILABLE} — {detected} detected, {opened} read")
                }
            },
        };
        verdicts.push(L2Verdict { div_index: row.index, address_short: row.short.clone(), verdict });
    }
    for why in &report.refused {
        gaps.push(format!("a note the scan opened was not made this wallet's: {why}"));
    }
    build(range, report.genesis_hash, verdicts, &report.owned, report.index.as_ref(), &report.spent, gaps)
}

/// [`render`] with a fixed URL and range — the tests' view of the text.
#[doc(hidden)]
pub fn render_for_test(report: &AnnuletReport) -> String {
    render(report, "fixture", (0, 10))
}
