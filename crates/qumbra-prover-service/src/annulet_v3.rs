//! **Format 34: the prover is paid inside the transaction** (lab #937 PR E;
//! rulings D4/D5, and the PR E ruling on issue #937, comment 6163115955).
//!
//! On a format-34 net a bundle's third output pays this service: `rkm` the
//! configured payee's, asset 0, value at least the advertised price of the
//! bundle's shape. There is no token and no identity: admission keys on the
//! client's IP, as Caddy states it (one live job per IP, IPv6 by /64), and
//! the only cost a bad request can impose is bounded by that. What this
//! module holds:
//!
//! - [`V3Config`]: the payee, the price, the paid ledger and the chain
//!   follow, refused by name at startup when any is missing or malformed;
//! - [`client_key`]: `X-Qumbra-Client-IP` to a salted 16-byte key, never a
//!   logged IP;
//! - [`prover_fee`]: the fee read from the witness's output 3, which
//!   `ProvingBundle::check` has already bound to the transaction's commitment;
//! - [`NullifierFollow`]: the landed nullifiers, followed from height 1 on
//!   the pinned node's `/v1/nullifiers` — loudly: until it has caught up, or
//!   once it is more than one slot behind, admission answers 503 and
//!   `/healthz` is not ready;
//! - [`PaidLedger`]: one line per accepted submission, the opening of
//!   output 3, fsynced before the job reads `submitted` (D5).

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use qlab_air::l2::L2TxOutput;
use qlab_devnet::annulet::L2ShapeTag;
use qlab_remote_auth::keccak256;
use qlab_wallet::address::{Address, ADDRESS_VERSION_CANDIDATE_A};
use qumbra_wallet::spent::{NullifierChunk, NullifierSource};
use serde::Serialize;
use zeroize::Zeroize;

use crate::token::hex;
use crate::{lock, ApiError};

/// The payee: a **full** version-2 address (a `qs1…` short address is a
/// hash and cannot be checked). Compared by its decoded `rkm`.
pub const PAYEE_VAR: &str = "QUMBRA_PROVER_ANNULET_PAYEE";
/// The price of shape S, in asset-0 fee units.
pub const PRICE_S_VAR: &str = "QUMBRA_PROVER_ANNULET_PRICE_S";
/// The price of shape P, in asset-0 fee units.
pub const PRICE_P_VAR: &str = "QUMBRA_PROVER_ANNULET_PRICE_P";
/// The paid ledger's path (D5): created 0600, or an existing 0600 ledger.
pub const PAID_LEDGER_VAR: &str = "QUMBRA_PROVER_ANNULET_PAID_LEDGER";
/// The header Caddy sets from the connection it trusts (Cloudflare's ranges,
/// else the socket's own address), overwriting any copy a client sends.
pub const CLIENT_IP_HEADER: &str = "X-Qumbra-Client-IP";
/// The paid ledger's first line: the file format's version.
pub const PAID_LEDGER_HEADER: &str = "qumbra-prover-paid-ledger 1";
/// Each entry's first field: the entry format's version.
pub const PAID_ENTRY_VERSION: &str = "1";

/// The advertised price per shape, in asset-0 fee units — `/info`'s
/// `price: {"S", "P"}`, the fields the kernel's `prover_pins::admit` reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ProverPrice {
    #[serde(rename = "S")]
    pub s: u64,
    #[serde(rename = "P")]
    pub p: u64,
}

impl ProverPrice {
    /// The price of `shape`. Shape R is never a bundle: nothing pays it.
    pub fn of(&self, shape: L2ShapeTag) -> u64 {
        match shape {
            L2ShapeTag::S => self.s,
            L2ShapeTag::P => self.p,
            L2ShapeTag::R => u64::MAX,
        }
    }
}

/// The format-34 configuration: who is paid, how much, where the paid
/// openings go, and how the landed nullifiers are followed.
pub struct V3Config {
    /// The payee address as configured, for `/info`.
    pub payee: String,
    /// Its decoded `rkm`: what output 3 must carry.
    pub payee_rkm: [u64; 4],
    pub price: ProverPrice,
    pub ledger: Arc<PaidLedger>,
    pub follow: Arc<dyn ChainFollow>,
}

/// The payee's `rkm`, or the startup refusal by name: not an address, or
/// not version 2.
pub fn payee_rkm(raw: &str) -> Result<[u64; 4], String> {
    let address = Address::decode_any(raw.trim()).ok_or_else(|| format!("{PAYEE_VAR} is not an address"))?;
    address
        .require_version(ADDRESS_VERSION_CANDIDATE_A)
        .map_err(|e| format!("{PAYEE_VAR} must be a full version-2 address: {e}"))?;
    Ok(address.rkm_lanes())
}

impl V3Config {
    /// The configuration from its variables' values (each `None` when
    /// unset), refusing by name. The ledger is opened (or created) here, so
    /// a ledger the service could not write stops it at startup.
    pub fn from_values(
        payee: Option<String>,
        price_s: Option<String>,
        price_p: Option<String>,
        ledger: Option<String>,
        follow: Arc<dyn ChainFollow>,
    ) -> Result<Self, String> {
        let payee = payee.ok_or_else(|| format!("{PAYEE_VAR} is required on format 34"))?;
        let payee_rkm = payee_rkm(&payee)?;
        let price = |name: &str, raw: Option<String>| -> Result<u64, String> {
            raw.ok_or_else(|| format!("{name} is required on format 34"))?
                .parse()
                .map_err(|_| format!("{name} must be a whole number of fee units"))
        };
        let price = ProverPrice { s: price(PRICE_S_VAR, price_s)?, p: price(PRICE_P_VAR, price_p)? };
        let ledger = ledger.ok_or_else(|| format!("{PAID_LEDGER_VAR} is required on format 34"))?;
        let ledger = Arc::new(PaidLedger::open(Path::new(&ledger))?);
        Ok(Self { payee: payee.trim().to_string(), payee_rkm, price, ledger, follow })
    }
}

// ------------------------------------------------------------- the client

/// The client's admission key: `X-Qumbra-Client-IP` parsed as an IP — an
/// IPv4-mapped IPv6 address as its IPv4, an IPv6 address by its /64 — hashed
/// under this process's random `salt`. Absent or not an IP is `400
/// client-ip-unknown`: lumping such requests under one key would let one
/// client's job block everyone's.
pub fn client_key(header: Option<&str>, salt: &[u8; 32]) -> Result<[u8; 16], ApiError> {
    let ip: IpAddr = header
        .map(str::trim)
        .and_then(|h| h.parse().ok())
        .ok_or(ApiError { status: 400, code: "client-ip-unknown" })?;
    let (family, bytes): (u8, Vec<u8>) = match ip.to_canonical() {
        IpAddr::V4(v4) => (4, v4.octets().to_vec()),
        IpAddr::V6(v6) => (6, v6.octets()[..8].to_vec()),
    };
    let h = keccak256(&[b"qumbra:prover-client-ip:v1", &salt[..], &[family], &bytes]);
    Ok(h[..16].try_into().expect("16 bytes"))
}

// ------------------------------------------------------------- the fee

/// The fee, read from the witness's output 3 (`check()` has bound it to the
/// transaction's third commitment, so it is the opening on chain): `rkm` the
/// payee's and asset 0, else `402 prover-fee-missing`; value at least
/// `price`, else `402 prover-fee-short`. More than the price is accepted.
pub fn prover_fee(out3: Option<&L2TxOutput>, payee_rkm: &[u64; 4], price: u64) -> Result<(), ApiError> {
    let missing = ApiError { status: 402, code: "prover-fee-missing" };
    let out3 = out3.ok_or(missing.clone())?;
    if out3.rkm != *payee_rkm || out3.asset != 0 {
        return Err(missing);
    }
    if out3.value < price {
        return Err(ApiError { status: 402, code: "prover-fee-short" });
    }
    Ok(())
}

// ------------------------------------------------------------- the ledger

/// One paid opening: output 3 of an accepted submission. The payee's wallet
/// needs `value`, `rho`, `rseed` (and checks `rkm`) to rebuild the note and
/// find `cm` in the tree.
pub struct PaidEntry {
    /// The transaction's third commitment, as on chain.
    pub cm: [u8; 32],
    pub value: u64,
    pub rkm: [u64; 4],
    pub rho: [u64; 4],
    pub rseed: [u64; 4],
    pub shape: L2ShapeTag,
}

impl PaidEntry {
    /// `out3` (the witness's) and `cm` (the transaction's third commitment).
    pub fn of(out3: &L2TxOutput, cm: [u8; 32], shape: L2ShapeTag) -> Self {
        Self { cm, value: out3.value, rkm: out3.rkm, rho: out3.rho, rseed: out3.rseed, shape }
    }

    /// The entry's line: the entry version, then `key=value` fields — the
    /// lane fields are the four `u64` lanes, each little-endian, as 64 hex.
    pub fn line(&self, at_unix: u64) -> String {
        let lanes = |l: &[u64; 4]| l.iter().map(|x| hex(&x.to_le_bytes())).collect::<String>();
        let shape = match self.shape {
            L2ShapeTag::S => "S",
            L2ShapeTag::P => "P",
            L2ShapeTag::R => "R",
        };
        format!(
            "{PAID_ENTRY_VERSION} cm={} value={} asset=0 rkm={} rho={} rseed={} shape={shape} at={at_unix}\n",
            hex(&self.cm),
            self.value,
            lanes(&self.rkm),
            lanes(&self.rho),
            lanes(&self.rseed),
        )
    }
}

impl Drop for PaidEntry {
    fn drop(&mut self) {
        self.rho.zeroize();
        self.rseed.zeroize();
    }
}

/// The paid ledger (D5): an append-only file of [`PaidEntry`] lines under a
/// version header. Created 0600 by this process; an existing one must be
/// 0600 and start with [`PAID_LEDGER_HEADER`]. Each append is fsynced before
/// the job reports `submitted`. A torn line never swallows the next entry: an
/// append that fails is cut back to the length before it, and a crash's
/// newline-less tail is closed with a newline when the ledger is next
/// opened — so a reader skips one malformed line and loses no good one.
pub struct PaidLedger {
    file: Mutex<File>,
}

impl PaidLedger {
    pub fn open(path: &Path) -> Result<Self, String> {
        match std::fs::symlink_metadata(path) {
            Ok(meta) => {
                if !meta.is_file() {
                    return Err(format!("{PAID_LEDGER_VAR} is not a regular file"));
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if meta.permissions().mode() & 0o077 != 0 {
                        return Err(format!("{PAID_LEDGER_VAR} must be readable and writable by its owner only (0600)"));
                    }
                }
                let mut first = String::new();
                File::open(path)
                    .and_then(|f| BufReader::new(f).read_line(&mut first))
                    .map_err(|_| format!("{PAID_LEDGER_VAR} could not be read"))?;
                if first.strip_suffix('\n') != Some(PAID_LEDGER_HEADER) {
                    return Err(format!(
                        "{PAID_LEDGER_VAR} is not a version-1 paid ledger (its first line is not `{PAID_LEDGER_HEADER}`)"
                    ));
                }
                let mut file = OpenOptions::new()
                    .read(true)
                    .append(true)
                    .open(path)
                    .map_err(|_| format!("{PAID_LEDGER_VAR} could not be opened for appending"))?;
                close_torn_tail(&mut file).map_err(|_| format!("{PAID_LEDGER_VAR}'s torn last line could not be closed"))?;
                Ok(Self { file: Mutex::new(file) })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut options = OpenOptions::new();
                options.append(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                let mut file = options.open(path).map_err(|_| format!("{PAID_LEDGER_VAR} could not be created"))?;
                file.write_all(format!("{PAID_LEDGER_HEADER}\n").as_bytes())
                    .and_then(|()| file.sync_all())
                    .map_err(|_| format!("{PAID_LEDGER_VAR}'s header could not be written"))?;
                // The new name itself, durably.
                let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
                File::open(dir)
                    .and_then(|d| d.sync_all())
                    .map_err(|_| format!("{PAID_LEDGER_VAR}'s directory could not be synced"))?;
                Ok(Self { file: Mutex::new(file) })
            }
            Err(_) => Err(format!("{PAID_LEDGER_VAR} could not be read")),
        }
    }

    /// Append `entry`'s line and fsync it. On failure the file is cut back
    /// to its length before the write (best effort), so a partial line does
    /// not prefix the next entry.
    pub fn append(&self, entry: &PaidEntry, at_unix: u64) -> std::io::Result<()> {
        let mut file = lock(&self.file);
        let before = file.metadata()?.len();
        let written = file.write_all(entry.line(at_unix).as_bytes()).and_then(|()| file.sync_data());
        if written.is_err() {
            let _ = file.set_len(before).and_then(|()| file.sync_data());
        }
        written
    }
}

/// A ledger whose last byte is not a newline ends in a torn line (a crash
/// mid-write): close it with a newline, fsynced, so the next entry starts on
/// its own line.
fn close_torn_tail(file: &mut File) -> std::io::Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(());
    }
    let mut last = [0u8; 1];
    file.seek(SeekFrom::Start(len - 1))?;
    file.read_exact(&mut last)?;
    if last[0] != b'\n' {
        file.write_all(b"\n")?;
        file.sync_data()?;
    }
    Ok(())
}

// ------------------------------------------------------------- the follow

/// The pinned node, as the follow reads it.
pub trait ChainFollow: Send + Sync + 'static {
    /// The node's tip height.
    fn tip(&self) -> Result<u64, String>;
    /// One page of `GET /v1/nullifiers?from=&to=`.
    fn nullifiers(&self, from: u64, to: u64) -> Result<NullifierChunk, String>;
}

/// [`ChainFollow`] over HTTP(S): the tip is `/v1/registry/root`'s height (the
/// Annulet node's own word on its tip, as the wallet reads it), the
/// nullifiers `/v1/nullifiers` through the wallet's own source.
pub struct HttpFollow {
    node_url: String,
    source: qumbra_wallet::net::HttpNullifierSource,
}

impl HttpFollow {
    pub fn new(node_url: &str) -> Self {
        Self { node_url: node_url.to_string(), source: qumbra_wallet::net::HttpNullifierSource::new(node_url) }
    }
}

impl ChainFollow for HttpFollow {
    fn tip(&self) -> Result<u64, String> {
        let body = qumbra_wallet::net::http_get_limited(&self.node_url, "/v1/registry/root", Some(4096))
            .map_err(|e| format!("GET /v1/registry/root: {e}"))?;
        qlab_cbserver::registry::decode_registry_root(&body)
            .map(|(height, _)| height)
            .map_err(|e| format!("GET /v1/registry/root did not decode: {e:?}"))
    }
    fn nullifiers(&self, from: u64, to: u64) -> Result<NullifierChunk, String> {
        self.source.fetch_range(from, to)
    }
}

#[derive(Default)]
struct Followed {
    landed: HashSet<[u8; 32]>,
    /// The highest height followed; 0 before the first block (genesis spends
    /// nothing).
    height: u64,
    /// When the tip this set reaches was read: `None` until the first
    /// catch-up.
    caught_up_at: Option<Instant>,
}

/// The landed nullifiers, in memory, rebuilt from height 1 at each start
/// (the PR E ruling: a rebuild over 60 s opens a persistence issue; the
/// first catch-up logs how long it took).
pub struct NullifierFollow {
    state: Mutex<Followed>,
    /// Behind by more than this is stale: one slot.
    slot: Duration,
}

impl NullifierFollow {
    pub fn new(slot: Duration) -> Self {
        Self { state: Mutex::new(Followed::default()), slot }
    }

    /// Ready when the set reached the node's tip within the last slot. Not
    /// ready is `503 nullifiers-catching-up` (never caught up since start)
    /// or `503 nullifiers-stale` (the node unreachable, or the follow more
    /// than one slot behind).
    pub fn readiness(&self) -> Result<(), ApiError> {
        match lock(&self.state).caught_up_at {
            None => Err(ApiError { status: 503, code: "nullifiers-catching-up" }),
            Some(at) if at.elapsed() > self.slot => Err(ApiError { status: 503, code: "nullifiers-stale" }),
            Some(_) => Ok(()),
        }
    }

    /// Admission's dedupe against the chain: ready, and none of `nullifiers`
    /// landed — else `409 nullifier-landed`.
    pub fn check(&self, nullifiers: &[[u8; 32]]) -> Result<(), ApiError> {
        self.readiness()?;
        let state = lock(&self.state);
        if nullifiers.iter().any(|nf| state.landed.contains(nf)) {
            return Err(ApiError { status: 409, code: "nullifier-landed" });
        }
        Ok(())
    }

    /// `(nullifiers held, height followed)`.
    pub fn size(&self) -> (usize, u64) {
        let s = lock(&self.state);
        (s.landed.len(), s.height)
    }

    /// One follow step: read the tip, then page the nullifiers from the
    /// followed height + 1 to it. Every height must be served, in order; a
    /// page that skips one is an error (the set does not advance past what it
    /// saw). A tip below the followed height — a reorganisation deeper than
    /// the set, or a node rolled back — empties the set: it is rebuilt from
    /// height 1, catching up again, rather than holding admission at 503
    /// until the chain regrows past the old height.
    pub fn poll(&self, node: &dyn ChainFollow) -> Result<(), String> {
        let asked = Instant::now();
        let tip = node.tip()?;
        let followed = lock(&self.state).height;
        if tip < followed {
            *lock(&self.state) = Followed::default();
            return Err(format!(
                "the node's tip {tip} is below the followed height {followed}: rebuilding the set from height 1"
            ));
        }
        let mut next = followed + 1;
        while next <= tip {
            let chunk = node.nullifiers(next, tip)?;
            if (chunk.from, chunk.to) != (next, tip) {
                return Err(format!("the node's nullifier page answers {}..={}, not {next}..={tip}", chunk.from, chunk.to));
            }
            if chunk.blocks.is_empty() {
                return Err(format!("the node served no block at height {next}"));
            }
            let mut state = lock(&self.state);
            for (height, nullifiers) in chunk.blocks {
                if height != next {
                    return Err(format!("the node's nullifier page skips height {next} (it serves {height})"));
                }
                state.landed.extend(nullifiers);
                state.height = height;
                next = height + 1;
            }
        }
        lock(&self.state).caught_up_at = Some(asked);
        Ok(())
    }
}

/// The follow's thread: poll every quarter slot (no more often than every
/// 200 ms) until the service is dropped — so a poll that takes a while still
/// lands well inside the one slot after which the set is stale. The first
/// catch-up logs the rebuild's size and time; a failure logs once, and its
/// recovery once, with the set's size.
pub fn follow(follow: Weak<NullifierFollow>, node: Arc<dyn ChainFollow>, slot: Duration) {
    let every = (slot / 4).max(Duration::from_millis(200));
    let started = Instant::now();
    let mut rebuilt = false;
    let mut failing: Option<String> = None;
    loop {
        let Some(f) = follow.upgrade() else { return };
        match f.poll(&*node) {
            Ok(()) => {
                if !rebuilt {
                    rebuilt = true;
                    let (n, height) = f.size();
                    eprintln!(
                        "qumbra-prover-service: annulet nullifier set rebuilt: {n} nullifiers through height {height} in {} ms",
                        started.elapsed().as_millis()
                    );
                } else if failing.is_some() {
                    let (n, height) = f.size();
                    eprintln!(
                        "qumbra-prover-service: annulet nullifier follow recovered: {n} nullifiers through height {height}"
                    );
                }
                failing = None;
            }
            Err(e) => {
                if failing.as_deref() != Some(e.as_str()) {
                    eprintln!("qumbra-prover-service: error: annulet nullifier follow failed (admission answers 503): {e}");
                }
                failing = Some(e);
            }
        }
        drop(f);
        std::thread::sleep(every);
    }
}
