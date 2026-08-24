//! The wallet's name layer (lab #367): local registry, pins, resolution.
//!
//! Design walls, applied wallet-side:
//!
//! - **D2** — the registry is bulk-synced (`GET /v1/names?from=&to=`) and every
//!   resolution is **local**. No code path here can ask a server about one
//!   name; the sync closure fetches height ranges and nothing else.
//! - **D3/N6** — a name saves typing, not verification: every resolution
//!   surfaces the `qs1…` fingerprint, first use requires out-of-band
//!   confirmation, and a changed binding is an **alarm** ([`PinVerdict::Rebind`],
//!   the known_hosts model) that refuses until re-confirmed.
//! - **N6** — a name in its grace window still resolves, flagged
//!   ([`Resolution::Expiring`]), so a lapsed renewal is an outage warning
//!   before it becomes a loss.
//!
//! Files (`contacts.v1` discipline: 0600, versioned header, reject-unknown):
//!
//! ```text
//!   <wallet dir>/names-registry.v1   the synced registry cache (rebuildable)
//!   <wallet dir>/names-pins.v1       name → pinned fingerprint (NOT rebuildable)
//! ```
//!
//! The cache is disposable — a re-sync rebuilds it from the chain. The pins
//! are not: they are the wallet's memory of what the user confirmed out of
//! band, which no server can restore.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::Path;

use qlab_cbserver::codec::NamesPage;
use qlab_devnet::names::{decode_rider, extended_expiry, reopens_at, NameOp};
use qlab_wallet::address::Address;

use crate::store::WalletDir;

pub const REGISTRY_FILE: &str = "names-registry.v1";
pub const REGISTRY_HEADER: &str = "qumbra-wallet names-registry v1";
pub const PINS_FILE: &str = "names-pins.v1";
pub const PINS_HEADER: &str = "qumbra-wallet names-pins v1";

/// One synced registration, as the chain published it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameEntry {
    pub kind: u8,
    /// Raw record address bytes (kind 0x01: the 1,233-B L1 address).
    pub address: Vec<u8>,
    pub registered: u64,
    pub expiry: u64,
}

/// The wallet's replayed registry + its sync cursor.
///
/// Replay trusts consensus (the node validated windows, uniqueness and fees;
/// a light client re-checking them would need the chain it deliberately does
/// not hold) — what it does NOT trust is the server's completeness, which the
/// paging guard in [`sync_names`] owns.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WalletRegistry {
    names: BTreeMap<String, NameEntry>,
    /// Highest height folded in; sync resumes at `+ 1`.
    pub synced_to: u64,
}

/// A local resolution verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// Registered and inside its term.
    Active(NameEntry),
    /// Past expiry but inside grace (N6): still resolves, flagged — renew or
    /// expect the alarm when someone re-registers it.
    Expiring { entry: NameEntry, reopens_at: u64 },
    /// Unknown, or past grace (a lapsed binding is NOT resolved — paying a
    /// name whose registration ended is paying a claim nobody holds).
    Unknown,
}

impl WalletRegistry {
    /// Fold one served page in. Heights must arrive ascending across calls —
    /// the sync loop's job; replay itself just applies reveals and renewals.
    pub fn apply_page(&mut self, page: &NamesPage) {
        for block in &page.blocks {
            for rider in &block.riders {
                // A rider the codec refuses cannot have been committed by a
                // conforming chain; skipping it here mirrors consensus (which
                // refused the block) rather than inventing a wallet-side
                // verdict about server bytes.
                let Ok(Some(op)) = decode_rider(rider) else { continue };
                match op {
                    NameOp::Commit { .. } => {}
                    NameOp::Reveal { record, .. } => {
                        let Ok(name) = String::from_utf8(record.name.clone()) else { continue };
                        self.names.insert(
                            name,
                            NameEntry {
                                kind: record.kind,
                                address: record.address,
                                registered: block.height,
                                expiry: extended_expiry(None, block.height),
                            },
                        );
                    }
                    NameOp::Renew { name } => {
                        let Ok(name) = String::from_utf8(name) else { continue };
                        if let Some(e) = self.names.get_mut(&name) {
                            e.expiry = extended_expiry(Some(e.expiry), block.height);
                        }
                    }
                }
            }
            self.synced_to = self.synced_to.max(block.height);
        }
    }

    /// Resolve `name` locally at chain height `tip`. `.qmb` is a display
    /// convention and is stripped here, never stored.
    pub fn resolve(&self, name: &str, tip: u64) -> Resolution {
        let bare = name.strip_suffix(".qmb").unwrap_or(name);
        match self.names.get(bare) {
            None => Resolution::Unknown,
            Some(e) if tip < e.expiry => Resolution::Active(e.clone()),
            Some(e) if tip < reopens_at(e.expiry) => {
                Resolution::Expiring { entry: e.clone(), reopens_at: reopens_at(e.expiry) }
            }
            Some(_) => Resolution::Unknown,
        }
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Height at which this exact in-flight record was revealed, when the
    /// synced chain view contains it inside this commit's reveal window.
    /// Matching the dedicated address as well as the name prevents an old or
    /// competing binding from being mistaken for confirmation of our reveal.
    pub fn observed_reveal_height(&self, state: &RegisterState) -> Option<u64> {
        use qlab_devnet::names::{COMMIT_MAX_AGE, COMMIT_MIN_AGE};
        let committed = state.committed_at?;
        let entry = self.names.get(&state.name)?;
        let opens = committed.checked_add(COMMIT_MIN_AGE)?;
        let closes = committed.checked_add(COMMIT_MAX_AGE)?;
        (entry.kind == state.record.kind
            && entry.address == state.record.address
            && (opens..=closes).contains(&entry.registered))
        .then_some(entry.registered)
    }

    // ---- the cache file (rebuildable; contacts.v1 discipline) --------------

    pub fn save(&self, dir: &Path) -> io::Result<()> {
        let mut out = String::new();
        out.push_str(REGISTRY_HEADER);
        out.push('\n');
        out.push_str(&format!("synced_to {}\n", self.synced_to));
        for (name, e) in &self.names {
            out.push_str(&format!(
                "{name} {} {} {} {}\n",
                e.kind,
                e.registered,
                e.expiry,
                hex(&e.address)
            ));
        }
        write_owner_only(&dir.join(REGISTRY_FILE), out.as_bytes())
    }

    pub fn load(dir: &Path) -> io::Result<Option<WalletRegistry>> {
        let path = dir.join(REGISTRY_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(&path)?;
        let mut lines = text.lines();
        let bad = |why: String| io::Error::new(io::ErrorKind::InvalidData, format!("{REGISTRY_FILE}: {why}"));
        if lines.next() != Some(REGISTRY_HEADER) {
            return Err(bad("unknown header — written by an incompatible build; delete and re-sync".into()));
        }
        let synced_to = lines
            .next()
            .and_then(|l| l.strip_prefix("synced_to "))
            .and_then(|v| v.parse::<u64>().ok())
            .ok_or_else(|| bad("missing synced_to".into()))?;
        let mut names = BTreeMap::new();
        for (i, line) in lines.enumerate() {
            let mut f = line.split(' ');
            let (Some(name), Some(kind), Some(reg), Some(exp), Some(addr)) =
                (f.next(), f.next(), f.next(), f.next(), f.next())
            else {
                return Err(bad(format!("record {i}: wrong field count")));
            };
            let parse = |v: &str| v.parse::<u64>().map_err(|_| bad(format!("record {i}: bad number")));
            names.insert(
                name.to_string(),
                NameEntry {
                    kind: kind.parse::<u8>().map_err(|_| bad(format!("record {i}: bad kind")))?,
                    registered: parse(reg)?,
                    expiry: parse(exp)?,
                    address: unhex(addr).ok_or_else(|| bad(format!("record {i}: bad address hex")))?,
                },
            );
        }
        Ok(Some(WalletRegistry { names, synced_to }))
    }
}

/// Sync the registry forward over `fetch` (a `GET path → body bytes` closure —
/// the #297 injection pattern, so TLS stays in the caller). Pages
/// `[synced_to+1 ..= tip]` with the #312 progress guard: **a page that does
/// not advance is a refusal, never `complete`** — the
/// truncation-reads-as-complete pattern has cost this project nine defects
/// and this loop does not add a tenth.
pub fn sync_names<F>(
    registry: &mut WalletRegistry,
    tip: u64,
    mut fetch: F,
) -> Result<(), String>
where
    F: FnMut(&str) -> Result<Vec<u8>, String>,
{
    while registry.synced_to < tip {
        let from = registry.synced_to + 1;
        let path = format!("/v1/names?from={from}&to={tip}");
        let bytes = fetch(&path)?;
        let page = NamesPage::from_bytes(&bytes).map_err(|e| format!("{path}: {e:?}"))?;
        if page.from != from || page.to != tip {
            return Err(format!("{path}: page echoes [{}, {}] — misattributed", page.from, page.to));
        }
        match page.last_height() {
            Some(last) if last >= from => {
                registry.apply_page(&page);
                registry.synced_to = last;
            }
            // An empty page for a non-empty remaining range: the server holds
            // none of those heights. Honest only if it can hold none — treat
            // as caught-up to tip (the server's view of it) rather than loop.
            None => {
                registry.synced_to = tip;
            }
            Some(last) => {
                return Err(format!(
                    "{path}: page ends at {last} < from {from} — no progress; refusing to read \
                     a stuck server as complete"
                ));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Pins (N6, the known_hosts model)
// ---------------------------------------------------------------------------

/// The pinned fingerprints: name → the `qs1…` the user confirmed out of band.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pins {
    pins: BTreeMap<String, String>,
}

/// What the pin layer says about a resolution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PinVerdict {
    /// No pin yet: first payment to this name — confirm the fingerprint out
    /// of band (D3), then pin it.
    FirstUse { fingerprint: String },
    /// The resolved address matches the pin.
    Match,
    /// 🔴 THE ALARM (N6): the name now resolves to a DIFFERENT address than
    /// the one confirmed. Never silent, never auto-accepted — the caller must
    /// refuse the payment until the new fingerprint is re-confirmed out of
    /// band and the pin explicitly replaced.
    Rebind { pinned: String, resolved: String },
}

impl Pins {
    /// Judge `resolved` (the record's raw address bytes) against the pin for
    /// `name`. An undecodable address (unreachable on a conforming chain)
    /// degrades to a **bytes-derived** marker rather than a constant one — a
    /// constant marker would silently `Match` across two DIFFERENT undecodable
    /// addresses, which is a rebind reading as safety (found by this module's
    /// own drill test before it could ship).
    pub fn check(&self, name: &str, resolved_address: &[u8]) -> PinVerdict {
        let bare = name.strip_suffix(".qmb").unwrap_or(name);
        let fingerprint = Address::from_raw_bytes(resolved_address)
            .map(|a| a.short().encode())
            .unwrap_or_else(|| {
                let prefix: String =
                    resolved_address.iter().take(16).map(|b| format!("{b:02x}")).collect();
                format!("<undecodable:{}B:{prefix}>", resolved_address.len())
            });
        match self.pins.get(bare) {
            None => PinVerdict::FirstUse { fingerprint },
            Some(pinned) if *pinned == fingerprint => PinVerdict::Match,
            Some(pinned) => {
                PinVerdict::Rebind { pinned: pinned.clone(), resolved: fingerprint }
            }
        }
    }

    /// Pin (or explicitly re-pin) a confirmed fingerprint.
    pub fn pin(&mut self, name: &str, fingerprint: &str) {
        let bare = name.strip_suffix(".qmb").unwrap_or(name);
        self.pins.insert(bare.to_string(), fingerprint.to_string());
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        let bare = name.strip_suffix(".qmb").unwrap_or(name);
        self.pins.get(bare).map(String::as_str)
    }

    pub fn save(&self, dir: &Path) -> io::Result<()> {
        let mut out = String::new();
        out.push_str(PINS_HEADER);
        out.push('\n');
        for (name, fp) in &self.pins {
            out.push_str(&format!("{name} {fp}\n"));
        }
        write_owner_only(&dir.join(PINS_FILE), out.as_bytes())
    }

    pub fn load(dir: &Path) -> io::Result<Pins> {
        let path = dir.join(PINS_FILE);
        if !path.exists() {
            return Ok(Pins::default());
        }
        let text = std::fs::read_to_string(&path)?;
        let mut lines = text.lines();
        if lines.next() != Some(PINS_HEADER) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{PINS_FILE}: unknown header — refusing to guess (pins are the user's out-of-band confirmations)"),
            ));
        }
        let mut pins = BTreeMap::new();
        for line in lines {
            let mut f = line.split(' ');
            let (Some(name), Some(fp)) = (f.next(), f.next()) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{PINS_FILE}: malformed record"),
                ));
            };
            pins.insert(name.to_string(), fp.to_string());
        }
        Ok(Pins { pins })
    }
}

// ---------------------------------------------------------------------------
// Registration (commit → wait → reveal), resumable
// ---------------------------------------------------------------------------

pub const REG_FILE: &str = "names-reg.v1";
pub const REG_HEADER_V1: &str = "qumbra-wallet names-reg v1";
pub const REG_HEADER_V2: &str = "qumbra-wallet names-reg v2";
pub const REG_HEADER: &str = "qumbra-wallet names-reg v3";

/// One in-flight registration. **Persisted BEFORE the commit tx posts** (the
/// #324 lesson: write the local record before the network can answer) — the
/// salt exists nowhere else, and a commit whose salt is lost is a dead window
/// plus a burned relay fee.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisterState {
    pub name: String,
    /// The record being bound — the wallet allocates a FRESH dedicated
    /// diversified address (D3) before this state exists.
    pub record: qlab_devnet::names::NameRecord,
    pub salt: [u8; 32],
    /// Height the commit tx was observed mined at; `None` until confirmed.
    pub committed_at: Option<u64>,
    /// Set and persisted before the first commit transaction is built. Once
    /// true, discarding this state could lose the only salt for an on-chain
    /// commitment, so presentation layers must not offer an ordinary cancel.
    pub commit_attempted: bool,
    /// Exact canonical reveal transaction bytes, persisted after proving and
    /// BEFORE the first POST. A proof is randomized, so only these bytes can
    /// make a retry byte-identical rather than merely rider-identical.
    pub reveal_tx: Option<Vec<u8>>,
    /// Height at which the exact record was observed in the synced chain view.
    /// Persisted before clearing so a failed clear cannot cause a re-post.
    pub revealed_at: Option<u64>,
}

/// Where a registration stands at chain height `tip`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegisterStep {
    /// No confirmed commit yet: post (or re-post) the commit tx.
    NeedsCommit,
    /// Commit confirmed; the reveal window opens at `at` (~10 min after the
    /// commit at the 75 s target).
    WaitForWindow { at: u64 },
    /// Inside `[opens, closes]`: post the reveal now.
    RevealNow { closes: u64 },
    /// The reveal was observed on chain. The presentation layer may now clear
    /// the salt and the retained retry transaction.
    RevealConfirmed { at: u64 },
    /// 🔴 The window closed unrevealed. The commit is dead and the salt MUST
    /// NOT be reused (brief §1) — start over with a fresh salt.
    WindowClosed,
}

impl RegisterState {
    pub fn new(name: &str, record: qlab_devnet::names::NameRecord, salt: [u8; 32]) -> Self {
        Self {
            name: name.to_string(),
            record,
            salt,
            committed_at: None,
            commit_attempted: false,
            reveal_tx: None,
            revealed_at: None,
        }
    }

    /// The op for step one. Pays relay tier only.
    pub fn commit_op(&self) -> NameOp {
        NameOp::Commit { commit: qlab_devnet::names::commit_hash(&self.record, &self.salt) }
    }

    /// The op for step two. Pays relay + the burned name fee.
    pub fn reveal_op(&self) -> NameOp {
        NameOp::Reveal { record: self.record.clone(), salt: self.salt }
    }

    /// Where this registration stands at `tip`.
    pub fn step(&self, tip: u64) -> RegisterStep {
        use qlab_devnet::names::{COMMIT_MAX_AGE, COMMIT_MIN_AGE};
        if let Some(at) = self.revealed_at {
            return RegisterStep::RevealConfirmed { at };
        }
        match self.committed_at {
            None => RegisterStep::NeedsCommit,
            Some(h) => {
                let opens = h + COMMIT_MIN_AGE;
                let closes = h + COMMIT_MAX_AGE;
                if tip < opens {
                    RegisterStep::WaitForWindow { at: opens }
                } else if tip <= closes {
                    RegisterStep::RevealNow { closes }
                } else {
                    RegisterStep::WindowClosed
                }
            }
        }
    }

    pub fn save(&self, dir: &Path) -> io::Result<()> {
        let mut out = String::new();
        out.push_str(REG_HEADER);
        out.push('\n');
        out.push_str(&format!(
            "{} {} {} {} {} {} {} {}\n",
            self.name,
            self.record.kind,
            hex(&self.salt),
            self.committed_at.map_or("none".to_string(), |h| h.to_string()),
            if self.commit_attempted { "attempted" } else { "prepared" },
            self.revealed_at.map_or("none".to_string(), |h| h.to_string()),
            hex(&self.record.address),
            self.reveal_tx.as_deref().map_or("none".to_string(), hex),
        ));
        write_owner_only(&dir.join(REG_FILE), out.as_bytes())
    }

    pub fn load(dir: &Path) -> io::Result<Option<RegisterState>> {
        let path = dir.join(REG_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(&path)?;
        let bad = |why: &str| io::Error::new(io::ErrorKind::InvalidData, format!("{REG_FILE}: {why}"));
        let mut lines = text.lines();
        let header = lines.next();
        if !matches!(header, Some(REG_HEADER | REG_HEADER_V2 | REG_HEADER_V1)) {
            return Err(bad("unknown header — an in-flight registration must never be guessed at"));
        }
        let Some(line) = lines.next() else { return Ok(None) };
        let mut f = line.split(' ');
        let (Some(name), Some(kind), Some(salt), Some(committed)) =
            (f.next(), f.next(), f.next(), f.next())
        else {
            return Err(bad("malformed record"));
        };
        let parse_attempted = |value| match value {
            Some("attempted") => Ok(true),
            Some("prepared") => Ok(false),
            _ => Err(bad("bad commit-attempt state")),
        };
        let (commit_attempted, revealed, addr, reveal_tx) = if header == Some(REG_HEADER) {
            let attempted = parse_attempted(f.next())?;
            (
                attempted,
                Some(f.next().ok_or_else(|| bad("missing reveal height"))?),
                f.next().ok_or_else(|| bad("missing address"))?,
                Some(f.next().ok_or_else(|| bad("missing reveal transaction"))?),
            )
        } else if header == Some(REG_HEADER_V2) {
            let attempted = parse_attempted(f.next())?;
            (attempted, None, f.next().ok_or_else(|| bad("missing address"))?, None)
        } else {
            // A v1 record has no evidence that its commit was never posted.
            // Fail closed: preserve its salt and require explicit recovery.
            (true, None, f.next().ok_or_else(|| bad("missing address"))?, None)
        };
        if f.next().is_some() {
            return Err(bad("unexpected trailing fields"));
        }
        let committed_at = match committed {
            "none" => None,
            v => Some(v.parse::<u64>().map_err(|_| bad("bad commit height"))?),
        };
        let revealed_at = match revealed {
            None | Some("none") => None,
            Some(v) => Some(v.parse::<u64>().map_err(|_| bad("bad reveal height"))?),
        };
        let reveal_tx = match reveal_tx {
            None | Some("none") => None,
            Some(v) => Some(
                unhex(v)
                    .filter(|bytes| !bytes.is_empty())
                    .ok_or_else(|| bad("bad reveal transaction"))?,
            ),
        };
        if revealed_at.is_some() && committed_at.is_none() {
            return Err(bad("a confirmed reveal is missing its commit height"));
        }
        if reveal_tx.is_some() && (committed_at.is_none() || !commit_attempted) {
            return Err(bad("a retained reveal transaction is missing its attempted commit"));
        }
        if revealed_at.is_some() && reveal_tx.is_none() {
            return Err(bad("a confirmed reveal is missing its retained transaction"));
        }
        if let (Some(committed), Some(revealed)) = (committed_at, revealed_at) {
            use qlab_devnet::names::{COMMIT_MAX_AGE, COMMIT_MIN_AGE};
            let opens = committed.checked_add(COMMIT_MIN_AGE)
                .ok_or_else(|| bad("commit height overflows its reveal window"))?;
            let closes = committed.checked_add(COMMIT_MAX_AGE)
                .ok_or_else(|| bad("commit height overflows its reveal window"))?;
            if !(opens..=closes).contains(&revealed) {
                return Err(bad("reveal height is outside its commit window"));
            }
        }
        let salt_v = unhex(salt).filter(|v| v.len() == 32).ok_or_else(|| bad("bad salt"))?;
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&salt_v);
        Ok(Some(RegisterState {
            name: name.to_string(),
            record: qlab_devnet::names::NameRecord {
                kind: kind.parse::<u8>().map_err(|_| bad("bad kind"))?,
                name: name.as_bytes().to_vec(),
                address: unhex(addr).ok_or_else(|| bad("bad address"))?,
            },
            salt,
            committed_at,
            commit_attempted,
            reveal_tx,
            revealed_at,
        }))
    }

    /// Discard the state file (registration completed, or window dead).
    pub fn clear(dir: &Path) -> io::Result<()> {
        let path = dir.join(REG_FILE);
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }
}

/// Prepare a resumable registration around a fresh dedicated address. This is
/// the shared API used by native shells: validation, cursor allocation, salt
/// generation, and the pre-network durable write all remain wallet rules.
pub fn prepare_registration(wallet: &mut WalletDir, name: &str) -> Result<RegisterState, String> {
    let bare = name.strip_suffix(".qmb").unwrap_or(name);
    if !qlab_devnet::names::valid_name(bare.as_bytes()) {
        return Err(format!(
            "{bare:?} fails the v1 name grammar (a-z 0-9, interior hyphens, 1-63 bytes)"
        ));
    }
    match RegisterState::load(&wallet.dir).map_err(|error| error.to_string())? {
        Some(state) if state.name == bare => return Ok(state),
        Some(state) => {
            return Err(format!(
                "a registration for {} is already in flight",
                state.name
            ))
        }
        None => {}
    }
    let index = wallet.allocate_next().map_err(|error| error.to_string())?;
    let address = wallet.wallet().address_at_index(index).to_raw_bytes();
    let mut salt = [0u8; 32];
    use rand::Rng as _;
    crate::send::os_rng().fill_bytes(&mut salt);
    let record = qlab_devnet::names::NameRecord {
        kind: qlab_devnet::names::RECORD_KIND_L1_ADDRESS,
        name: bare.as_bytes().to_vec(),
        address,
    };
    let state = RegisterState::new(bare, record, salt);
    state.save(&wallet.dir).map_err(|error| error.to_string())?;
    Ok(state)
}

/// Construct a renewal operation after applying the consensus name grammar.
pub fn renewal_op(name: &str) -> Result<NameOp, String> {
    let bare = name.strip_suffix(".qmb").unwrap_or(name);
    if !qlab_devnet::names::valid_name(bare.as_bytes()) {
        return Err(format!(
            "{bare:?} fails the v1 name grammar (a-z 0-9, interior hyphens, 1-63 bytes)"
        ));
    }
    Ok(NameOp::Renew { name: bare.as_bytes().to_vec() })
}

fn write_owner_only(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut f = std::fs::File::create(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(bytes)?;
    f.sync_all()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_cbserver::codec::BlockNames;
    use qlab_devnet::names::{
        encode_rider, NameRecord, L1_ADDRESS_LEN, NAME_GRACE_BLOCKS, NAME_TERM_BLOCKS,
        RECORD_KIND_L1_ADDRESS,
    };

    fn page(blocks: Vec<BlockNames>, from: u64, to: u64) -> NamesPage {
        NamesPage { from, to, blocks }
    }

    fn reveal(name: &[u8]) -> Vec<u8> {
        encode_rider(Some(&NameOp::Reveal {
            record: NameRecord {
                kind: RECORD_KIND_L1_ADDRESS,
                name: name.to_vec(),
                address: vec![0xAB; L1_ADDRESS_LEN],
            },
            salt: [7; 32],
        }))
    }

    #[test]
    fn replay_resolve_and_the_grace_flag() {
        let mut reg = WalletRegistry::default();
        reg.apply_page(&page(
            vec![BlockNames { height: 9_100, riders: vec![vec![0x00], reveal(b"alice")] }],
            0,
            10_000,
        ));
        let expiry = 9_100 + NAME_TERM_BLOCKS;

        // Active, `.qmb` display convention stripped.
        assert!(matches!(reg.resolve("alice.qmb", 10_000), Resolution::Active(e) if e.expiry == expiry));
        // In grace: resolves, flagged with the reopening height.
        assert!(matches!(
            reg.resolve("alice", expiry + 1),
            Resolution::Expiring { reopens_at, .. } if reopens_at == expiry + NAME_GRACE_BLOCKS
        ));
        // Past grace: a lapsed binding is NOT resolved.
        assert_eq!(reg.resolve("alice", expiry + NAME_GRACE_BLOCKS), Resolution::Unknown);
        assert_eq!(reg.resolve("bob", 10_000), Resolution::Unknown);

        // Renewal extends from expiry.
        reg.apply_page(&page(
            vec![BlockNames {
                height: 9_200,
                riders: vec![encode_rider(Some(&NameOp::Renew { name: b"alice".to_vec() }))],
            }],
            0,
            10_000,
        ));
        assert!(matches!(
            reg.resolve("alice", expiry + 10),
            Resolution::Active(e) if e.expiry == expiry + NAME_TERM_BLOCKS
        ));
    }

    #[test]
    fn sync_pages_with_the_progress_guard() {
        let mut reg = WalletRegistry::default();
        // A server that serves [1..=2] then [3..=3]; tip 3.
        let mut calls = 0;
        let result = sync_names(&mut reg, 3, |path| {
            calls += 1;
            match calls {
                1 => {
                    assert_eq!(path, "/v1/names?from=1&to=3");
                    Ok(page(
                        vec![
                            BlockNames { height: 1, riders: vec![] },
                            BlockNames { height: 2, riders: vec![reveal(b"alice")] },
                        ],
                        1,
                        3,
                    )
                    .to_bytes())
                }
                2 => {
                    assert_eq!(path, "/v1/names?from=3&to=3");
                    Ok(page(vec![BlockNames { height: 3, riders: vec![] }], 3, 3).to_bytes())
                }
                _ => panic!("sync must stop at tip"),
            }
        });
        result.unwrap();
        assert_eq!(reg.synced_to, 3);
        assert_eq!(reg.len(), 1);

        // The #312 guard: a page that repeats old heights is a refusal, not
        // an infinite loop and not `complete`.
        let mut stuck = WalletRegistry { synced_to: 5, ..Default::default() };
        let err = sync_names(&mut stuck, 10, |_| {
            Ok(page(vec![BlockNames { height: 2, riders: vec![] }], 6, 10).to_bytes())
        })
        .unwrap_err();
        assert!(err.contains("no progress"), "{err}");

        // A misattributed echo is refused by name.
        let mut wrong = WalletRegistry { synced_to: 5, ..Default::default() };
        let err = sync_names(&mut wrong, 10, |_| {
            Ok(page(vec![], 0, 3).to_bytes())
        })
        .unwrap_err();
        assert!(err.contains("misattributed"), "{err}");
    }

    #[test]
    fn registry_cache_round_trips_and_rejects_unknown_headers() {
        let dir = std::env::temp_dir().join(format!("qw-names-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        assert_eq!(WalletRegistry::load(&dir).unwrap(), None);
        let mut reg = WalletRegistry::default();
        reg.apply_page(&page(
            vec![BlockNames { height: 9_100, riders: vec![reveal(b"alice")] }],
            0,
            9_100,
        ));
        reg.save(&dir).unwrap();
        assert_eq!(WalletRegistry::load(&dir).unwrap(), Some(reg));

        std::fs::write(dir.join(REGISTRY_FILE), "something else\n").unwrap();
        assert!(WalletRegistry::load(&dir).is_err(), "unknown header refuses");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn register_state_machine_and_the_dead_window() {
        use qlab_devnet::names::{COMMIT_MAX_AGE, COMMIT_MIN_AGE};
        let dir = std::env::temp_dir().join(format!("qw-reg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let record = NameRecord {
            kind: RECORD_KIND_L1_ADDRESS,
            name: b"alice".to_vec(),
            address: vec![0xAB; L1_ADDRESS_LEN],
        };
        let mut st = RegisterState::new("alice", record, [7u8; 32]);
        assert!(!st.commit_attempted);
        // Persisted BEFORE any tx posts — the salt exists nowhere else.
        st.save(&dir).unwrap();
        assert_eq!(RegisterState::load(&dir).unwrap(), Some(st.clone()));

        assert_eq!(st.step(9_000), RegisterStep::NeedsCommit);
        st.commit_attempted = true;
        st.committed_at = Some(9_000);
        st.save(&dir).unwrap();
        assert_eq!(
            st.step(9_000 + COMMIT_MIN_AGE - 1),
            RegisterStep::WaitForWindow { at: 9_000 + COMMIT_MIN_AGE }
        );
        assert_eq!(
            st.step(9_000 + COMMIT_MIN_AGE),
            RegisterStep::RevealNow { closes: 9_000 + COMMIT_MAX_AGE }
        );
        assert_eq!(st.step(9_000 + COMMIT_MAX_AGE), RegisterStep::RevealNow { closes: 9_000 + COMMIT_MAX_AGE });
        assert_eq!(st.step(9_000 + COMMIT_MAX_AGE + 1), RegisterStep::WindowClosed);

        // The ops line up with the consensus hash.
        let NameOp::Commit { commit } = st.commit_op() else { panic!() };
        assert_eq!(commit, qlab_devnet::names::commit_hash(&st.record, &st.salt));
        assert!(matches!(st.reveal_op(), NameOp::Reveal { .. }));

        // The v3 additions round-trip: exact retry bytes first, then the chain
        // observation that makes clearing safe even if the window has passed.
        st.reveal_tx = Some(vec![0x51, 0x36, 0x32]);
        st.save(&dir).unwrap();
        assert_eq!(RegisterState::load(&dir).unwrap(), Some(st.clone()));
        let revealed_at = 9_000 + COMMIT_MIN_AGE;
        let mut registry = WalletRegistry::default();
        registry.apply_page(&page(
            vec![BlockNames { height: revealed_at, riders: vec![reveal(b"alice")] }],
            revealed_at,
            revealed_at,
        ));
        assert_eq!(registry.observed_reveal_height(&st), Some(revealed_at));
        st.revealed_at = Some(revealed_at);
        st.save(&dir).unwrap();
        assert_eq!(RegisterState::load(&dir).unwrap(), Some(st.clone()));
        assert_eq!(
            st.step(9_000 + COMMIT_MAX_AGE + 1),
            RegisterStep::RevealConfirmed { at: revealed_at },
        );
        RegisterState::clear(&dir).unwrap();
        assert_eq!(RegisterState::load(&dir).unwrap(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn native_registration_api_allocates_once_and_legacy_state_fails_closed() {
        use qlab_wallet::seed::MasterSeed;

        let dir = std::env::temp_dir().join(format!("qw-reg-api-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut wallet = WalletDir::create(&dir, MasterSeed::from_entropy([0x51; 32])).unwrap();

        let first = prepare_registration(&mut wallet, "alice.qmb").unwrap();
        let second = prepare_registration(&mut wallet, "alice").unwrap();
        assert_eq!(first, second, "reopening the same flow must not allocate again");
        assert_eq!(wallet.allocated, vec![0, 1]);
        assert_eq!(first.record.address, wallet.wallet().address_at_index(1).to_raw_bytes());
        assert!(prepare_registration(&mut wallet, "UPPER").is_err());
        assert!(prepare_registration(&mut wallet, "bob").is_err());

        let v2 = format!(
            "{REG_HEADER_V2}\nalice {} {} 9000 attempted {}\n",
            RECORD_KIND_L1_ADDRESS,
            hex(&first.salt),
            hex(&first.record.address),
        );
        std::fs::write(dir.join(REG_FILE), v2).unwrap();
        let recovered = RegisterState::load(&dir).unwrap().unwrap();
        assert!(recovered.commit_attempted);
        assert_eq!(recovered.committed_at, Some(9_000));
        assert_eq!(recovered.reveal_tx, None);
        assert_eq!(recovered.revealed_at, None);

        let legacy = format!(
            "{REG_HEADER_V1}\nalice {} {} none {}\n",
            RECORD_KIND_L1_ADDRESS,
            hex(&first.salt),
            hex(&first.record.address),
        );
        std::fs::write(dir.join(REG_FILE), legacy).unwrap();
        let recovered = RegisterState::load(&dir).unwrap().unwrap();
        assert!(
            recovered.commit_attempted,
            "v1 cannot prove its commit was never posted, so cancel must fail closed"
        );
        std::fs::write(dir.join(REG_FILE), "qumbra-wallet names-reg v99\n").unwrap();
        let err = RegisterState::load(&dir).unwrap_err().to_string();
        assert!(err.contains("unknown header"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pins_first_use_match_and_the_rebind_alarm() {
        let dir = std::env::temp_dir().join(format!("qw-pins-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut pins = Pins::load(&dir).unwrap();
        let addr_a = vec![0xAB; L1_ADDRESS_LEN];
        let addr_b = vec![0xCD; L1_ADDRESS_LEN];

        // First use: no pin — the caller confirms out of band, then pins.
        let PinVerdict::FirstUse { fingerprint } = pins.check("alice", &addr_a) else {
            panic!("expected first use");
        };
        pins.pin("alice", &fingerprint);
        assert_eq!(pins.check("alice", &addr_a), PinVerdict::Match);

        // THE ALARM: same name, different address.
        match pins.check("alice.qmb", &addr_b) {
            PinVerdict::Rebind { pinned, resolved } => {
                assert_eq!(pinned, fingerprint);
                assert_ne!(pinned, resolved);
            }
            other => panic!("a rebind must alarm, got {other:?}"),
        }

        // Pins survive disk.
        pins.save(&dir).unwrap();
        let back = Pins::load(&dir).unwrap();
        assert_eq!(back, pins);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
