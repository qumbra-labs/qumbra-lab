//! **Imported openings** (lab #937, after PR E): the payee wallet's side of
//! a remote prover's **paid ledger**.
//!
//! On a format-34 net the prover is paid in each transaction's third output.
//! An honest kernel encrypts that output's discovery payload to the payee, so
//! the payee's ordinary scan finds it. A wallet that did not (malicious or
//! buggy) leaves a note the payee owns but cannot detect. The prover service
//! therefore appends every accepted submission's output-3 opening to a paid
//! ledger (`docs/prover-service-annulet.md`); the operator copies that file to
//! the payee wallet's machine, by hand, and imports it here. The payee's seed
//! never goes to the prover's box.
//!
//! **What the import checks** ([`import_openings`], offline — no network):
//! the ledger's version header (else the whole file is refused); then, per
//! line, the line's length, its entry version, its fields, asset 0, that the
//! opening opens its own `cm`, and that its `rkm` is one of this wallet's
//! (an allocated address × a generation of its authorization journal).
//! Accepted openings are kept in [`OPENINGS_FILE`], 0600, deduplicated by `cm`.
//!
//! **What it does not check: membership.** Whether `cm` is on chain is the
//! scan's question, decided where every other note's is
//! ([`crate::annulet::AnnuletScanCore::with_imported`]): a scan that sees an
//! imported `cm` in the served compact stream owns that note at the chain's
//! height and transaction (verified against the block body in a verified
//! scan). An opening the scan does not see is only counted, never a figure.
//!
//! The file opens notes: `rho` and `rseed` are never printed, only a `cm`
//! and a verdict ([`LineVerdict`]'s `Display`).

use std::collections::HashSet;
use std::io::Write;
use std::path::Path;

use qlab_ledger::assets::{AssetError, GenerationRoots, OwnedL2Note};
use qlab_note::hash::{digest_bytes, digest_from_bytes};
use qlab_note::l2note::L2Note;
use qlab_wallet::Wallet;

use crate::auth_journal::AuthJournal;
use crate::store::WalletDir;

/// The wallet file holding the imported openings.
pub const OPENINGS_FILE: &str = "openings.v1";
const OPENINGS_HEADER: &str = "qumbra-wallet-openings 1";
/// The prover service's paid-ledger header (format version 1).
pub const PAID_LEDGER_HEADER: &str = "qumbra-prover-paid-ledger 1";
/// The one paid-ledger entry version this wallet reads.
pub const PAID_ENTRY_VERSION: &str = "1";
/// A ledger line longer than this is refused before it is parsed.
pub const MAX_LINE_BYTES: usize = 1024;

/// One imported opening: the note, its `cm`, and where in the wallet it is
/// owned (address index and authorization generation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedOpening {
    pub cm: [u8; 32],
    pub note: L2Note,
    pub div_index: u64,
    pub generation: u32,
}

/// Why a ledger line was not imported — by name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LineRefusal {
    /// The named field (or `length`, `empty`, `fields`) is not as the format states.
    Malformed(&'static str),
    /// The line's entry version is not one this wallet reads.
    EntryVersionUnknown(String),
    /// The opening is not asset 0 (a prover is paid in asset 0).
    NotAsset0,
    /// The opening does not open the line's `cm`.
    CmMismatch,
    /// The `rkm` is no allocated address of this wallet's, under any of its
    /// generations.
    NotThisWallet,
}

/// What the import did with one line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Imported,
    AlreadyImported,
    Refused(LineRefusal),
    /// The file's last line has no newline: a write torn by a crash.
    SkippedTornLastLine,
}

/// One line's verdict: the line number (1 is the header), its `cm` when the
/// line got far enough to name one, and the verdict. Its `Display` names
/// nothing else — never `rho` or `rseed`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineVerdict {
    pub line: usize,
    pub cm: Option<[u8; 32]>,
    pub verdict: Verdict,
}

impl std::fmt::Display for LineRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LineRefusal::Malformed(what) => write!(f, "malformed({what})"),
            LineRefusal::EntryVersionUnknown(v) => write!(f, "entry-version-unknown({v})"),
            LineRefusal::NotAsset0 => f.write_str("not-asset-0"),
            LineRefusal::CmMismatch => f.write_str("cm-mismatch"),
            LineRefusal::NotThisWallet => f.write_str("not-this-wallet"),
        }
    }
}

impl std::fmt::Display for LineVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cm = self.cm.map_or_else(|| "-".to_string(), |cm| format!("{}…", hex(&cm[..8])));
        let verdict = match &self.verdict {
            Verdict::Imported => "imported".to_string(),
            Verdict::AlreadyImported => "already-imported".to_string(),
            Verdict::Refused(why) => format!("refused:{why}"),
            Verdict::SkippedTornLastLine => "skipped:torn-last-line".to_string(),
        };
        write!(f, "line {}: cm {cm} {verdict}", self.line)
    }
}

/// Why the import, or the openings file, was refused as a whole — by name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpeningsError {
    /// The file is not a version-1 paid ledger (its first line).
    NotAPaidLedger,
    /// The wallet has no Candidate A authorization journal (`auth.v1`): it
    /// has no version-2 address a prover could have been paid to, and a v1
    /// net has no prover fee.
    NotCandidateA,
    /// The journal could not be read.
    AuthJournal(String),
    /// [`OPENINGS_FILE`] does not parse, or names an opening this wallet does
    /// not own (a file edited by hand).
    OpeningsFile(String),
    /// A file could not be read or written.
    Io(String),
}

impl std::fmt::Display for OpeningsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpeningsError::NotAPaidLedger => {
                write!(f, "not a version-1 paid ledger: its first line is not `{PAID_LEDGER_HEADER}`")
            }
            OpeningsError::NotCandidateA => f.write_str(
                "this wallet has no Candidate A authorization journal (auth.v1): imported openings are for a \
                 Candidate A (format-34) net, and a v1 net has no prover fee",
            ),
            OpeningsError::AuthJournal(why) => write!(f, "the authorization journal could not be read: {why}"),
            OpeningsError::OpeningsFile(why) => write!(f, "{OPENINGS_FILE}: {why}"),
            OpeningsError::Io(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for OpeningsError {}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn decimal(s: &str) -> Option<u64> {
    (!s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.parse().ok()).flatten()
}

/// The wallet's generations, from its journal — none is [`OpeningsError::NotCandidateA`].
fn generations(dir: &Path) -> Result<Vec<(u32, [u64; 4])>, OpeningsError> {
    let journal = AuthJournal::load(dir)
        .map_err(|e| OpeningsError::AuthJournal(e.to_string()))?
        .ok_or(OpeningsError::NotCandidateA)?;
    Ok(journal.generations().iter().map(|g| (g.g, g.auth_root)).collect())
}

/// The allocated index and generation `note` is owned under, if any.
fn owner(wallet: &Wallet, allocated: &[u64], generations: &GenerationRoots, cm: [u8; 32], note: L2Note) -> Option<(u64, u32)> {
    allocated.iter().find_map(|&idx| match OwnedL2Note::from_genesis_v2(wallet, idx, cm, note, generations) {
        Ok(owned) => owned.generation.map(|g| (idx, g)),
        Err(AssetError::NotThisAddress { .. } | AssetError::AssetOutOfRange { .. }) => None,
    })
}

/// One paid-ledger entry line, checked in the ruled order: length, entry
/// version, fields, asset 0, `cm`, ownership. The `cm` is named once the
/// fields parsed.
fn check_line(
    line: &str,
    wallet: &Wallet,
    allocated: &[u64],
    generations: &GenerationRoots,
) -> (Option<[u8; 32]>, Result<ImportedOpening, LineRefusal>) {
    use LineRefusal::*;
    if line.len() > MAX_LINE_BYTES {
        return (None, Err(Malformed("length")));
    }
    let tokens: Vec<&str> = line.split(' ').collect();
    match tokens.first() {
        None | Some(&"") => return (None, Err(Malformed("empty"))),
        Some(&PAID_ENTRY_VERSION) => {}
        Some(v) => {
            // Echoed, so bounded and printable: a version is a short token.
            let shown: String = v.chars().take(8).filter(|c| c.is_ascii_alphanumeric() || *c == '.').collect();
            return (None, Err(EntryVersionUnknown(shown)));
        }
    }
    const KEYS: [&str; 8] = ["cm", "value", "asset", "rkm", "rho", "rseed", "shape", "at"];
    if tokens.len() != 1 + KEYS.len() {
        return (None, Err(Malformed("fields")));
    }
    let mut v = [""; 8];
    for (i, key) in KEYS.iter().enumerate() {
        match tokens[1 + i].split_once('=') {
            Some((k, value)) if k == *key => v[i] = value,
            _ => return (None, Err(Malformed(key))),
        }
    }
    let Some(cm) = hex32(v[0]) else { return (None, Err(Malformed("cm"))) };
    let Some(value) = decimal(v[1]) else { return (Some(cm), Err(Malformed("value"))) };
    let Some(asset) = decimal(v[2]) else { return (Some(cm), Err(Malformed("asset"))) };
    let lanes = |s: &str| hex32(s).map(|b| digest_from_bytes(&b));
    let Some(rkm) = lanes(v[3]) else { return (Some(cm), Err(Malformed("rkm"))) };
    let Some(rho) = lanes(v[4]) else { return (Some(cm), Err(Malformed("rho"))) };
    let Some(rseed) = lanes(v[5]) else { return (Some(cm), Err(Malformed("rseed"))) };
    // Format checks only: neither is stored, nor affects the verdict.
    if !matches!(v[6], "S" | "P") {
        return (Some(cm), Err(Malformed("shape")));
    }
    if decimal(v[7]).is_none() {
        return (Some(cm), Err(Malformed("at")));
    }
    if asset != 0 {
        return (Some(cm), Err(NotAsset0));
    }
    let note = L2Note { value, asset: 0, rkm, rho, rseed };
    if digest_bytes(&note.commitment()) != cm {
        return (Some(cm), Err(CmMismatch));
    }
    match owner(wallet, allocated, generations, cm, note) {
        Some((div_index, generation)) => (Some(cm), Ok(ImportedOpening { cm, note, div_index, generation })),
        None => (Some(cm), Err(NotThisWallet)),
    }
}

/// **The import**, pure: check `ledger` (the paid ledger's text) against the
/// wallet, given the openings already `known` (by `cm`). Returns each entry
/// line's verdict and the openings to add, in file order.
pub fn check_ledger(
    ledger: &str,
    wallet: &Wallet,
    allocated: &[u64],
    generations: &GenerationRoots,
    known: &HashSet<[u8; 32]>,
) -> Result<(Vec<LineVerdict>, Vec<ImportedOpening>), OpeningsError> {
    let mut lines = ledger.split('\n');
    if lines.next() != Some(PAID_LEDGER_HEADER) || !ledger.contains('\n') {
        return Err(OpeningsError::NotAPaidLedger);
    }
    let torn = !ledger.ends_with('\n');
    let entries: Vec<&str> = lines.collect();
    // The text after the last newline: empty for a whole file, the torn
    // line otherwise.
    let last = entries.len().saturating_sub(1);
    let mut verdicts = Vec::new();
    let mut added: Vec<ImportedOpening> = Vec::new();
    let mut seen = known.clone();
    for (i, line) in entries.iter().enumerate() {
        let number = i + 2;
        if i == last {
            if torn {
                verdicts.push(LineVerdict { line: number, cm: None, verdict: Verdict::SkippedTornLastLine });
            }
            break;
        }
        let (cm, checked) = check_line(line, wallet, allocated, generations);
        let verdict = match checked {
            Err(why) => Verdict::Refused(why),
            Ok(opening) if !seen.insert(opening.cm) => Verdict::AlreadyImported,
            Ok(opening) => {
                added.push(opening);
                Verdict::Imported
            }
        };
        verdicts.push(LineVerdict { line: number, cm, verdict });
    }
    Ok((verdicts, added))
}

/// **`annulet import-openings`**: check the paid ledger `ledger` against the
/// wallet in `w` and append what it owns to [`OPENINGS_FILE`]. Offline.
/// Refused as a whole when the file is not a version-1 paid ledger, or the
/// wallet has no Candidate A journal.
pub fn import_openings(w: &WalletDir, ledger: &str) -> Result<Vec<LineVerdict>, OpeningsError> {
    let generations = generations(&w.dir)?;
    let mut openings = load_openings_with(w, &generations)?;
    let known: HashSet<[u8; 32]> = openings.iter().map(|o| o.cm).collect();
    let (verdicts, added) = check_ledger(ledger, &w.wallet(), &w.allocated, &generations, &known)?;
    if !added.is_empty() {
        openings.extend(added);
        save(&w.dir, &openings)?;
    }
    Ok(verdicts)
}

/// What `import-openings` prints: one line per verdict, then the summary.
/// Only line numbers, `cm` prefixes, verdicts and counts — never `rho` or
/// `rseed`.
pub fn render(verdicts: &[LineVerdict]) -> String {
    let mut out: String = verdicts.iter().map(|v| format!("{v}\n")).collect();
    out.push_str(&summary(verdicts));
    out.push('\n');
    out
}

/// The summary line after the verdicts: counts only.
pub fn summary(verdicts: &[LineVerdict]) -> String {
    let count = |f: fn(&Verdict) -> bool| verdicts.iter().filter(|v| f(&v.verdict)).count();
    format!(
        "imported {}, already imported {}, refused {}, skipped {} — membership is checked by `scan --net annulet`, \
         never here",
        count(|v| matches!(v, Verdict::Imported)),
        count(|v| matches!(v, Verdict::AlreadyImported)),
        count(|v| matches!(v, Verdict::Refused(_))),
        count(|v| matches!(v, Verdict::SkippedTornLastLine)),
    )
}

/// The wallet's imported openings, each re-checked on load against the
/// journal's generations and the allocated addresses (a file edited by hand
/// cannot assign a note to an address the wallet never allocated). An
/// absent file is none.
pub fn load_openings(w: &WalletDir) -> Result<Vec<ImportedOpening>, OpeningsError> {
    match std::fs::metadata(w.dir.join(OPENINGS_FILE)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        _ => {}
    }
    load_openings_with(w, &generations(&w.dir)?)
}

/// [`load_openings`] under `generations` (a scan given its own).
pub fn load_openings_with(w: &WalletDir, generations: &GenerationRoots) -> Result<Vec<ImportedOpening>, OpeningsError> {
    let path = w.dir.join(OPENINGS_FILE);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(OpeningsError::Io(format!("{OPENINGS_FILE} could not be read: {e}"))),
    };
    let bad = |n: usize, why: &str| OpeningsError::OpeningsFile(format!("line {n}: {why}"));
    let mut lines = text.lines();
    if lines.next() != Some(OPENINGS_HEADER) {
        return Err(OpeningsError::OpeningsFile(format!("its first line is not `{OPENINGS_HEADER}`")));
    }
    let wallet = w.wallet();
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for (i, line) in lines.enumerate() {
        let n = i + 2;
        let f: Vec<&str> = line.split(' ').collect();
        let field = |k: usize, key: &str| {
            f.get(k).and_then(|t| t.strip_prefix(key)).and_then(|t| t.strip_prefix('=')).ok_or_else(|| bad(n, key))
        };
        if f.len() != 6 {
            return Err(bad(n, "not six fields"));
        }
        let cm = hex32(field(0, "cm")?).ok_or_else(|| bad(n, "cm"))?;
        let value = decimal(field(1, "value")?).ok_or_else(|| bad(n, "value"))?;
        let rho = hex32(field(2, "rho")?).map(|b| digest_from_bytes(&b)).ok_or_else(|| bad(n, "rho"))?;
        let rseed = hex32(field(3, "rseed")?).map(|b| digest_from_bytes(&b)).ok_or_else(|| bad(n, "rseed"))?;
        let div_index = decimal(field(4, "index")?).ok_or_else(|| bad(n, "index"))?;
        let generation: u32 =
            decimal(field(5, "generation")?).and_then(|g| g.try_into().ok()).ok_or_else(|| bad(n, "generation"))?;
        if !w.allocated.contains(&div_index) {
            return Err(bad(n, "names an address index this wallet never allocated"));
        }
        let root = generations
            .iter()
            .find(|(g, _)| *g == generation)
            .map(|(_, r)| *r)
            .ok_or_else(|| bad(n, "names a generation this wallet's journal does not hold"))?;
        let d = wallet.diversifier_at_index(div_index).lanes();
        let rkm = qlab_wallet::keys::derive_rkm_v2(&wallet.nk(), &d, &root);
        let note = L2Note { value, asset: 0, rkm, rho, rseed };
        if digest_bytes(&note.commitment()) != cm {
            return Err(bad(n, "the opening does not open its cm at that address and generation"));
        }
        if !seen.insert(cm) {
            return Err(bad(n, "a cm listed twice"));
        }
        out.push(ImportedOpening { cm, note, div_index, generation });
    }
    Ok(out)
}

/// Write `openings` whole: a temporary file created 0600, synced, then
/// renamed over [`OPENINGS_FILE`] (the rkm is not stored — it is derived on
/// load from the index and generation).
fn save(dir: &Path, openings: &[ImportedOpening]) -> Result<(), OpeningsError> {
    let mut text = format!("{OPENINGS_HEADER}\n");
    for o in openings {
        text.push_str(&format!(
            "cm={} value={} rho={} rseed={} index={} generation={}\n",
            hex(&o.cm),
            o.note.value,
            hex(&digest_bytes(&o.note.rho)),
            hex(&digest_bytes(&o.note.rseed)),
            o.div_index,
            o.generation
        ));
    }
    let io = |e: std::io::Error| OpeningsError::Io(format!("{OPENINGS_FILE} could not be written: {e}"));
    let tmp = dir.join(format!("{OPENINGS_FILE}.tmp"));
    let _ = std::fs::remove_file(&tmp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp).map_err(io)?;
    file.write_all(text.as_bytes()).and_then(|()| file.sync_all()).map_err(io)?;
    std::fs::rename(&tmp, dir.join(OPENINGS_FILE)).map_err(io)?;
    std::fs::File::open(dir).and_then(|d| d.sync_all()).map_err(io)
}
