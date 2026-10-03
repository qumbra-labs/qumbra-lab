//! **The verified Annulet scan** (lab #850, AD1): a balance this wallet can
//! stand behind on a chain it does not run.
//!
//! [`crate::annulet::scan_annulet`] trusts the endpoint: its genesis pin
//! compares the hash `/v1/genesis/notes` *states*, and nothing it reads is
//! checked against a sealed header. A lying node can therefore encrypt a note
//! to any public address and the wallet would show it as money. This module
//! closes that, in four steps, each refusing by name:
//!
//! 1. **Genesis by bytes.** Fetch [`GENESIS_FILE_PATH`], keccak it against the
//!    pin (required — there is no verified scan of an unnamed chain), decode it
//!    with the node's own type ([`qlab_node::annulet_genesis`]) and run its
//!    structural check, which binds the genesis notes and registry to the
//!    genesis header. The sequencer key and the genesis notes come from these
//!    bytes, never from a route.
//! 2. **The seal chain.** Page `/v1/headers` from height 1, and admit each
//!    header through the consensus header rule itself
//!    ([`qlab_devnet::validation::validate_sealed_header_annulet`]: parent,
//!    height, timestamps, no PoW fields, anchor monotone, the seal under the
//!    genesis key), refusing a gap or a fork. **The scanned tip is the highest
//!    header verified here**, never the node's stated tip.
//! 3. **Notes by the body.** Scan as before over `from ..= verified tip`. For
//!    every owned note found in a block, fetch that block's whole body
//!    (`/v1/block/{h}/body`), require its header to be the verified one,
//!    recompute `tx_body_commitment` with
//!    [`qlab_devnet::annulet::body_commitment_annulet`] — the function the
//!    node's body rule uses — and require the note to open to a commitment that
//!    transaction carries. One body per block with a hit; none for a block
//!    without one.
//! 4. **Registry openings by the header.** [`verify_registry_leaf`] binds an
//!    opening to the verified header at the height it names and folds its path.
//!
//! **What it does not verify — the spends** (lab #853; stated, so nobody reads
//! more into "verified"). The nullifiers subtracted are `/v1/nullifiers`' list,
//! and nothing proves it complete. A node that **withholds the nullifier of a
//! spent note leaves that note in the figure: the balance is OVERSTATED** —
//! money the wallet shows and no longer has. Catching it needs every body from
//! the oldest owned note to the tip, or a committed nullifier set; one body per
//! hit cannot. [`VerifiedAnnulet::spends_verified`] says so in the type, and is
//! `false` today. (The output side is the safe direction: a withheld output
//! only makes a figure smaller.)
//!
//! **The verified-header cache** (lab #852, WA0 of #858). Re-verifying every
//! seal from genesis on every scan costs ~3.4 KB and one ML-DSA-65 verify per
//! header. So a scan that verified the chain records the verified header
//! *preimages* (153 B each, seals dropped after admission) in
//! `<wallet dir>/annulet-chain.<genesis hex>` — keyed by genesis, because the
//! verified chain is a chain fact, not an endpoint fact — and the next scan
//! resumes from its tip. The record is **the wallet's own prior
//! verification**, trusted at the wallet dir's trust level (the seed's class):
//! on load it is relinked from the genesis header built from the pinned bytes
//! (prev-hash chain, consecutive heights) with no seal re-verify, and **the
//! served header at the cached tip is re-checked on every resume**, so a
//! fabricated-but-linking record, or an endpoint telling another story, meets
//! a fork at the tip. Either case — [`VerifyRefusal::ChainCacheInvalid`] or
//! [`VerifyRefusal::CachedTipForked`] — discards the record and re-verifies
//! from genesis, named in [`VerifiedAnnulet::cache`]; never a silent fallback.
//! A refused scan never writes the record.
//!
//! The result is [`VerifiedAnnulet`], whose only constructor is
//! [`scan_annulet_verified`]: a balance cannot reach a view model through any
//! other path.

use qlab_devnet::annulet::{body_commitment_annulet, HeaderExt};
use qlab_devnet::chain::ChainState;
use qlab_devnet::forms::GenesisForm;
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_node::annulet_genesis::{h32, AnnuletGenesisFile};
use qlab_note::l2note::{GenesisPlaintext, L2Note};
use qlab_p2p::compact::WireForm;
use qlab_p2p::served::{decode_body_answer, decode_headers_page, sealed, MAX_HEADERS_PAGE};
use rand::rngs::StdRng;

use crate::annulet::{scan_annulet_from, AnnuletReport};
use crate::store::WalletDir;

/// Where the genesis file is read from: the scan endpoint, same origin — an
/// Annulet node answers it itself, and the path is the one an L1 wallet reads
/// from the L1 edge (`wallet-network-identity-decision`).
pub const GENESIS_FILE_PATH: &str = "/genesis.qmb";

const ANNULET: WireForm = WireForm::plain(GenesisForm::Annulet);

/// The largest genesis file a verified scan will read (lab #850 AD1b). The
/// gateway testnet's is 11,295 B (53 genesis notes); 1 MiB leaves room for
/// thousands of genesis notes and registered assets, and is checked by name
/// here as well as at the transport, so no fetch can hand the verifier more.
pub const MAX_GENESIS_FILE_BYTES: usize = 1 << 20;

/// Room for an HTTP status line and headers on top of a route's body bound —
/// the transport's ceiling covers the whole response.
pub const RESPONSE_HEAD_SLACK: usize = 16 * 1024;

/// A `/v1/headers` answer's largest body: the 10-B prefix, a ≤ 9-B count
/// varint, and [`MAX_HEADERS_PAGE`] sealed units.
pub const MAX_HEADERS_ANSWER_BYTES: usize =
    10 + 9 + MAX_HEADERS_PAGE * qlab_devnet::annulet::SEALED_HEADER_LEN_ANNULET;

/// A `/v1/block/{h}/body` answer's largest body: the 10-B prefix over the
/// node's own served-body bound.
pub const MAX_BODY_ANSWER_BYTES: usize = 10 + qlab_p2p::node::MAX_SERVED_BODY_BYTES;

/// A `/v1/registry/{asset}` answer's largest body: the slot route's 676 B is
/// the widest registry answer; 4 KiB is stated headroom.
pub const MAX_REGISTRY_ANSWER_BYTES: usize = 4 * 1024;

/// **The whole-response ceiling for each route the verified scan reads**
/// (lab #850 AD1b): a hostile endpoint cannot stream more than the route can
/// legitimately carry into the wallet before anything is verified. `None` is
/// a route whose bound is the transport's general GET cap (the paged scan
/// routes: `/v1/compact`, `/v1/nullifiers`, `/full`, `/v1/registry/root`).
pub fn response_ceiling(path: &str) -> Option<usize> {
    let route = path.split_once('?').map_or(path, |(r, _)| r);
    let body = if route == GENESIS_FILE_PATH {
        MAX_GENESIS_FILE_BYTES
    } else if route == qlab_p2p::served::HEADERS_PATH {
        MAX_HEADERS_ANSWER_BYTES
    } else if route.starts_with("/v1/block/") && route.ends_with("/body") {
        MAX_BODY_ANSWER_BYTES
    } else if route.starts_with("/v1/registry/") && route != "/v1/registry/root" {
        MAX_REGISTRY_ANSWER_BYTES
    } else if route.starts_with(crate::v6_bundle::BUNDLE_PATH_PREFIX) {
        // Lab #860 R2: one raw V6 bundle, bounded by the V6 body bound.
        qlab_devnet::body::MAX_V6_BODY_BYTES
    } else {
        return None;
    };
    Some(body + RESPONSE_HEAD_SLACK)
}

/// Why a verified scan was refused — each a reason the endpoint cannot be
/// believed, never a figure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyRefusal {
    /// No genesis pin: there is no verified scan of an unnamed chain.
    NoPin,
    /// `/genesis.qmb` could not be read.
    GenesisUnavailable { why: String },
    /// `/genesis.qmb` is longer than [`MAX_GENESIS_FILE_BYTES`].
    GenesisTooLarge { got: usize },
    /// The bytes served are not the pinned genesis.
    GenesisMismatch { pinned: [u8; 32], fetched: [u8; 32] },
    /// The pinned bytes do not decode, or fail the file's own structure check.
    GenesisInvalid { why: String },
    /// A headers page could not be read.
    HeadersUnavailable { from: u64, why: String },
    /// A headers page did not decode.
    HeadersMalformed { from: u64, why: String },
    /// The page skipped or repeated a height.
    HeaderGap { want: u64, got: u64 },
    /// A header whose parent is not the header verified below it.
    HeaderFork { height: u64 },
    /// A header the consensus rule refuses (the seal included).
    HeaderInvalid { height: u64, why: String },
    /// A body answer could not be read.
    BodyUnavailable { height: u64, why: String },
    /// A body answer did not decode.
    BodyMalformed { height: u64, why: String },
    /// The body answer's header is not the verified header at its height.
    BodyHeaderMismatch { height: u64 },
    /// The body does not hash to the verified header's `tx_body_commitment`.
    BodyCommitmentMismatch { height: u64 },
    /// A note the endpoint served that the verified block does not carry.
    ForgedNote { height: u64, tx_index: u64, why: String },
    /// A genesis note the scan matched that the verified genesis does not carry.
    ForgedGenesisNote { cm: [u8; 32] },
    /// A registry opening could not be read or decoded.
    RegistryUnavailable { asset: u16, why: String },
    /// A registry opening for another asset than asked.
    RegistryWrongAsset { want: u16, got: u64 },
    /// A registry opening at a height above the verified tip.
    RegistryHeightUnverified { height: u64, tip: u64 },
    /// A registry opening whose root is not the verified header's.
    RegistryRootMismatch { height: u64 },
    /// A registry opening whose path does not fold to its root.
    RegistryPathMismatch { asset: u16 },
    /// The verified-header record does not load: the wrong version or
    /// genesis, a bad length, a header that does not decode, or a broken link.
    ChainCacheInvalid { why: String },
    /// The endpoint's header at the recorded tip is not the recorded one.
    CachedTipForked { height: u64 },
}

impl std::fmt::Display for VerifyRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use VerifyRefusal::*;
        match self {
            NoPin => write!(f, "no genesis pin: a verified Annulet scan needs the chain named by its genesis hash"),
            GenesisUnavailable { why } => write!(f, "GET {GENESIS_FILE_PATH}: {why}"),
            GenesisTooLarge { got } => {
                write!(f, "{GENESIS_FILE_PATH} is {got} B, over the {MAX_GENESIS_FILE_BYTES} B bound")
            }
            GenesisMismatch { pinned, fetched } => write!(
                f,
                "the endpoint's genesis file hashes to {} but the pin is {} — a different chain",
                hex(fetched),
                hex(pinned)
            ),
            GenesisInvalid { why } => write!(f, "the pinned genesis file is invalid: {why}"),
            HeadersUnavailable { from, why } => write!(f, "GET /v1/headers from {from}: {why}"),
            HeadersMalformed { from, why } => write!(f, "/v1/headers from {from} did not decode: {why}"),
            HeaderGap { want, got } => write!(f, "headers skip: expected height {want}, served {got}"),
            HeaderFork { height } => write!(f, "header {height} does not extend the verified chain (a fork)"),
            HeaderInvalid { height, why } => write!(f, "header {height} fails the sealed-header rule: {why}"),
            BodyUnavailable { height, why } => write!(f, "GET /v1/block/{height}/body: {why}"),
            BodyMalformed { height, why } => write!(f, "/v1/block/{height}/body did not decode: {why}"),
            BodyHeaderMismatch { height } => {
                write!(f, "the body served for height {height} carries another header than the verified one")
            }
            BodyCommitmentMismatch { height } => {
                write!(f, "the body served for height {height} does not hash to its sealed header's commitment")
            }
            ForgedNote { height, tx_index, why } => {
                write!(f, "a note served at height {height} tx {tx_index} is not in the verified block: {why}")
            }
            ForgedGenesisNote { cm } => write!(f, "genesis note {} is not in the verified genesis", hex(cm)),
            RegistryUnavailable { asset, why } => write!(f, "registry opening for asset {asset}: {why}"),
            RegistryWrongAsset { want, got } => write!(f, "registry opening for asset {got}, asked {want}"),
            RegistryHeightUnverified { height, tip } => {
                write!(f, "registry opening at height {height}, above the verified tip {tip}")
            }
            RegistryRootMismatch { height } => {
                write!(f, "registry opening's root is not the verified header's at height {height}")
            }
            RegistryPathMismatch { asset } => write!(f, "registry opening for asset {asset} does not fold to its root"),
            ChainCacheInvalid { why } => write!(f, "the verified-header record is invalid ({why}); discarded"),
            CachedTipForked { height } => write!(
                f,
                "the endpoint's header at the recorded tip {height} is not the one this wallet verified (a fork); \
                 the record is discarded"
            ),
        }
    }
}

impl std::error::Error for VerifyRefusal {}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A genesis verified by its bytes.
#[derive(Clone, Debug)]
pub struct VerifiedGenesis {
    /// keccak of the file — equal to the pin.
    pub hash: [u8; 32],
    pub file: AnnuletGenesisFile,
    /// The genesis header's hash: height 1's `prev`.
    pub header_hash: Hash32,
}

/// Step 1: fetch the genesis file, hash it against `pin`, decode and check it.
pub fn verify_genesis<F>(fetch: &mut F, pin: [u8; 32]) -> Result<VerifiedGenesis, VerifyRefusal>
where
    F: FnMut(&str) -> Result<Vec<u8>, String>,
{
    let bytes = fetch(GENESIS_FILE_PATH).map_err(|why| VerifyRefusal::GenesisUnavailable { why })?;
    if bytes.len() > MAX_GENESIS_FILE_BYTES {
        return Err(VerifyRefusal::GenesisTooLarge { got: bytes.len() });
    }
    let fetched = qlab_devnet::hash::keccak256(&bytes);
    if fetched != pin {
        return Err(VerifyRefusal::GenesisMismatch { pinned: pin, fetched });
    }
    let file = AnnuletGenesisFile::from_bytes(&bytes).map_err(|e| VerifyRefusal::GenesisInvalid { why: e.to_string() })?;
    file.verify(None).map_err(|e| VerifyRefusal::GenesisInvalid { why: e.to_string() })?;
    let header_hash = file.genesis_block_header().header_hash_for(GenesisForm::Annulet);
    Ok(VerifiedGenesis { hash: fetched, file, header_hash })
}

/// A header chain verified from the genesis file to its tip.
#[derive(Clone, Debug)]
pub struct VerifiedChain {
    pub genesis: VerifiedGenesis,
    /// `headers[i]` is height `i + 1`.
    headers: Vec<BlockHeader>,
}

impl VerifiedChain {
    /// The highest verified height (0 when the chain is its genesis).
    pub fn tip(&self) -> u64 {
        self.headers.len() as u64
    }

    /// The verified header at `height` (the genesis header at 0).
    pub fn header(&self, height: u64) -> Option<BlockHeader> {
        match height {
            0 => Some(self.genesis.file.genesis_block_header()),
            h => self.headers.get(h as usize - 1).copied(),
        }
    }
}

/// Step 2: verify every sealed header from height 1 up to `up_to` (or the
/// endpoint's last), through the consensus header rule.
pub fn verify_chain<F>(fetch: &mut F, genesis: VerifiedGenesis, up_to: u64) -> Result<VerifiedChain, VerifyRefusal>
where
    F: FnMut(&str) -> Result<Vec<u8>, String>,
{
    let mut state = ChainState::new_for(GenesisForm::Annulet, genesis.file.genesis_block_header());
    let mut headers = Vec::new();
    extend_chain(fetch, &genesis, &mut state, &mut headers, up_to)?;
    Ok(VerifiedChain { genesis, headers })
}

/// Admit sealed headers past `headers` (heights `headers.len() + 1 ..`) up to
/// `up_to` or the endpoint's last — the one admission path, from genesis or
/// from a resumed record.
fn extend_chain<F>(
    fetch: &mut F,
    genesis: &VerifiedGenesis,
    state: &mut ChainState,
    headers: &mut Vec<BlockHeader>,
    up_to: u64,
) -> Result<(), VerifyRefusal>
where
    F: FnMut(&str) -> Result<Vec<u8>, String>,
{
    let key = genesis.file.sequencer().map_err(|e| VerifyRefusal::GenesisInvalid { why: e.to_string() })?;
    let mut parent = headers.last().map_or(genesis.header_hash, |h| h.header_hash_for(GenesisForm::Annulet));
    loop {
        let from = headers.len() as u64 + 1;
        if from > up_to {
            break;
        }
        let to = up_to.min(from + MAX_HEADERS_PAGE as u64 - 1);
        let path = format!("/v1/headers?from={from}&to={to}");
        let bytes = fetch(&path).map_err(|why| VerifyRefusal::HeadersUnavailable { from, why })?;
        let units = decode_headers_page(ANNULET, from, &bytes)
            .map_err(|e| VerifyRefusal::HeadersMalformed { from, why: e.to_string() })?;
        let asked = to - from + 1;
        let got = units.len() as u64;
        for unit in &units {
            let s = sealed(unit).map_err(|e| VerifyRefusal::HeadersMalformed { from, why: e.to_string() })?;
            let want = headers.len() as u64 + 1;
            if s.header.height != want {
                return Err(VerifyRefusal::HeaderGap { want, got: s.header.height });
            }
            if s.header.prev != parent {
                return Err(VerifyRefusal::HeaderFork { height: want });
            }
            qlab_devnet::validation::validate_sealed_header_annulet(state, s, &key)
                .map_err(|e| VerifyRefusal::HeaderInvalid { height: want, why: format!("{e:?}") })?;
            parent = state
                .insert_header(s.header)
                .map_err(|e| VerifyRefusal::HeaderInvalid { height: want, why: format!("{e:?}") })?;
            headers.push(s.header);
        }
        if got < asked {
            break;
        }
    }
    Ok(())
}

/// The most headers the record holds: 2^18 × 153 B ≈ 38 MiB. Past it the
/// record is refused by name on load and not written (a scan then verifies
/// from genesis, as before the record existed).
pub const MAX_CACHED_HEADERS: u64 = 1 << 18;

/// The only record version this build reads and writes.
pub const CHAIN_CACHE_VERSION: u8 = 1;

/// The record's path: one per genesis, in the wallet dir.
pub fn chain_cache_path(w: &WalletDir, genesis_hash: &[u8; 32]) -> std::path::PathBuf {
    w.dir.join(format!("annulet-chain.{}", hex(genesis_hash)))
}

const PREIMAGE_LEN_ANNULET: usize = qlab_devnet::header::HEADER_PREIMAGE_LEN_ANNULET;

/// `ver(1) ‖ genesis(32) ‖ n(u64 LE) ‖ n × 153-B header preimage`.
fn encode_chain_cache(genesis_hash: &[u8; 32], headers: &[BlockHeader]) -> Vec<u8> {
    let mut out = Vec::with_capacity(41 + headers.len() * PREIMAGE_LEN_ANNULET);
    out.push(CHAIN_CACHE_VERSION);
    out.extend_from_slice(genesis_hash);
    out.extend_from_slice(&(headers.len() as u64).to_le_bytes());
    for h in headers {
        out.extend_from_slice(&qlab_p2p::codec::encode_header(GenesisForm::Annulet, h));
    }
    out
}

/// Read the record and relink it from the genesis header (no seal
/// re-verify: it is this wallet's own prior verification). `Ok(None)` when
/// there is none; `Err(why)` when there is one and it does not load.
pub fn load_chain_cache(w: &WalletDir, genesis: &VerifiedGenesis) -> Result<Option<Vec<BlockHeader>>, String> {
    let path = chain_cache_path(w, &genesis.hash);
    let b = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    if b.len() < 41 {
        return Err("shorter than its prefix".into());
    }
    if b[0] != CHAIN_CACHE_VERSION {
        return Err(format!("version {}; this build reads only {CHAIN_CACHE_VERSION}", b[0]));
    }
    if b[1..33] != genesis.hash {
        return Err("recorded for another genesis".into());
    }
    let n = u64::from_le_bytes(b[33..41].try_into().expect("8 bytes"));
    if n > MAX_CACHED_HEADERS {
        return Err(format!("{n} headers, over the {MAX_CACHED_HEADERS} bound"));
    }
    if (b.len() - 41) as u64 != n * PREIMAGE_LEN_ANNULET as u64 {
        return Err(format!("{} B of headers for {n} headers", b.len() - 41));
    }
    let mut parent = genesis.header_hash;
    let mut headers = Vec::with_capacity(n as usize);
    for (i, chunk) in b[41..].chunks_exact(PREIMAGE_LEN_ANNULET).enumerate() {
        let h = qlab_p2p::codec::decode_header(GenesisForm::Annulet, chunk)
            .map_err(|e| format!("header {} does not decode: {e:?}", i + 1))?;
        if h.height != i as u64 + 1 || h.prev != parent {
            return Err(format!("header {} does not link", i + 1));
        }
        parent = h.header_hash_for(GenesisForm::Annulet);
        headers.push(h);
    }
    Ok(Some(headers))
}

/// Write the record atomically (`<path>.tmp`, fsync, rename).
fn save_chain_cache(w: &WalletDir, genesis_hash: &[u8; 32], headers: &[BlockHeader]) -> Result<(), String> {
    use std::io::Write;
    if headers.len() as u64 > MAX_CACHED_HEADERS {
        return Err(format!("{} headers, over the {MAX_CACHED_HEADERS} bound: not recorded", headers.len()));
    }
    let path = chain_cache_path(w, genesis_hash);
    let tmp = path.with_extension("tmp");
    let write = || -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&encode_chain_cache(genesis_hash, headers))?;
        f.sync_all()?;
        std::fs::rename(&tmp, &path)
    };
    write().map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("{}: {e}", path.display())
    })
}

/// Resume from a loaded record: re-check the endpoint's header at the
/// anchor (the recorded tip, or `up_to` below it) against the record, then
/// admit what is past it. An endpoint that serves nothing at the anchor is
/// behind the record: the chain is clamped to the endpoint's stated tip,
/// re-checked there the same way — never claimed above what this endpoint
/// serves.
fn resume_chain<F>(
    fetch: &mut F,
    genesis: VerifiedGenesis,
    cached: Vec<BlockHeader>,
    up_to: u64,
) -> Result<VerifiedChain, VerifyRefusal>
where
    F: FnMut(&str) -> Result<Vec<u8>, String>,
{
    let mut anchor = (cached.len() as u64).min(up_to);
    if anchor == 0 {
        return verify_chain(fetch, genesis, up_to);
    }
    let served_at = |fetch: &mut F, h: u64| -> Result<Option<BlockHeader>, VerifyRefusal> {
        let bytes = fetch(&format!("/v1/headers?from={h}&to={h}"))
            .map_err(|why| VerifyRefusal::HeadersUnavailable { from: h, why })?;
        let units = decode_headers_page(ANNULET, h, &bytes)
            .map_err(|e| VerifyRefusal::HeadersMalformed { from: h, why: e.to_string() })?;
        match units.first() {
            None => Ok(None),
            Some(u) => Ok(Some(sealed(u).map_err(|e| VerifyRefusal::HeadersMalformed { from: h, why: e.to_string() })?.header)),
        }
    };
    let served = match served_at(fetch, anchor)? {
        Some(h) => h,
        None => {
            // Behind the record: clamp to the endpoint's own stated tip.
            let stated = fetch("/v1/registry/root")
                .ok()
                .and_then(|b| qlab_cbserver::registry::decode_registry_root(&b).ok())
                .map(|(height, _)| height)
                .unwrap_or(0);
            anchor = stated.min(anchor);
            if anchor == 0 {
                return Ok(VerifiedChain { genesis, headers: Vec::new() });
            }
            served_at(fetch, anchor)?.ok_or(VerifyRefusal::CachedTipForked { height: anchor })?
        }
    };
    if served != cached[anchor as usize - 1] {
        return Err(VerifyRefusal::CachedTipForked { height: anchor });
    }
    let mut headers: Vec<BlockHeader> = cached;
    headers.truncate(anchor as usize);
    let mut state = ChainState::new_for(GenesisForm::Annulet, genesis.file.genesis_block_header());
    for h in &headers {
        state.insert_header(*h).map_err(|e| VerifyRefusal::ChainCacheInvalid { why: format!("{e:?}") })?;
    }
    if anchor as usize == headers.len() && anchor < up_to {
        extend_chain(fetch, &genesis, &mut state, &mut headers, up_to)?;
    }
    Ok(VerifiedChain { genesis, headers })
}

/// What the verified-header record did for a scan — for the trust line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainCache {
    /// None was recorded: verified from genesis.
    Unused,
    /// Resumed: the record (`recorded` headers) was re-checked at `anchor`
    /// and the chain admitted past it. `anchor < recorded` with no headers
    /// past it is an endpoint behind the record: the verified tip is clamped
    /// to what this endpoint serves.
    Resumed { anchor: u64, recorded: u64 },
    /// The record was refused ([`VerifyRefusal::ChainCacheInvalid`] or
    /// [`VerifyRefusal::CachedTipForked`]), discarded, and the chain
    /// re-verified from genesis.
    Discarded(VerifyRefusal),
}

/// A scan whose every figure is bound to the verified chain. Constructed only
/// by [`scan_annulet_verified`].
pub struct VerifiedAnnulet {
    report: AnnuletReport,
    chain: VerifiedChain,
    range: (u64, u64),
    bodies_fetched: u64,
    body_bytes: u64,
    stated_tip: Option<u64>,
    cache: ChainCache,
    /// Why the record could not be written, if it could not (the scan
    /// stands; the next one verifies more).
    cache_write: Option<String>,
}

impl VerifiedAnnulet {
    /// The scan's report (its `genesis_hash` is the pinned one).
    pub fn report(&self) -> &AnnuletReport {
        &self.report
    }

    /// The verified chain the figures are bound to.
    pub fn chain(&self) -> &VerifiedChain {
        &self.chain
    }

    /// The heights scanned: `from ..= the verified tip` (or the asked `to`).
    pub fn range(&self) -> (u64, u64) {
        self.range
    }

    /// Whether the spend side is bound to the chain — **`false`**: the
    /// nullifier list is the endpoint's, so a withheld spend overstates the
    /// balance (lab #853). A view model renders this; a shell cannot hide it.
    pub fn spends_verified(&self) -> bool {
        false
    }

    /// The tip the endpoint states (`/v1/registry/root`'s height), beside
    /// [`VerifiedChain::tip`]: a node serving fewer headers than it claims
    /// leaves the wallet behind, which is freshness, not a lie. `None` when
    /// the endpoint did not say.
    pub fn stated_tip(&self) -> Option<u64> {
        self.stated_tip
    }

    /// What the verified-header record did for this scan.
    pub fn cache(&self) -> &ChainCache {
        &self.cache
    }

    /// Why the record could not be written after this scan, if so.
    pub fn cache_write(&self) -> Option<&str> {
        self.cache_write.as_deref()
    }

    /// Bodies fetched to bind notes, and their bytes: the per-hit cost.
    pub fn body_cost(&self) -> (u64, u64) {
        (self.bodies_fetched, self.body_bytes)
    }
}

/// **The verified Annulet scan**: steps 1–3 of the module doc, then the
/// unchanged scan body over the verified range and genesis.
pub fn scan_annulet_verified<F>(
    w: &WalletDir,
    fetch: &mut F,
    from: u64,
    to: u64,
    pin: Option<[u8; 32]>,
    rng: &mut StdRng,
) -> Result<VerifiedAnnulet, VerifyRefusal>
where
    F: FnMut(&str) -> Result<Vec<u8>, String>,
{
    let pin = pin.ok_or(VerifyRefusal::NoPin)?;
    let genesis = verify_genesis(fetch, pin)?;
    let recorded = load_chain_cache(w, &genesis);
    let recorded_len = recorded.as_ref().ok().and_then(|r| r.as_ref().map(Vec::len)).unwrap_or(0);
    let (chain, cache) = match recorded {
        Ok(None) => (verify_chain(fetch, genesis, to)?, ChainCache::Unused),
        Err(why) => (verify_chain(fetch, genesis, to)?, ChainCache::Discarded(VerifyRefusal::ChainCacheInvalid { why })),
        Ok(Some(cached)) => match resume_chain(fetch, genesis.clone(), cached, to) {
            Ok(chain) => {
                let anchor = (recorded_len as u64).min(to).min(chain.tip());
                (chain, ChainCache::Resumed { anchor, recorded: recorded_len as u64 })
            }
            Err(e @ VerifyRefusal::CachedTipForked { .. }) | Err(e @ VerifyRefusal::ChainCacheInvalid { .. }) => {
                (verify_chain(fetch, genesis, to)?, ChainCache::Discarded(e))
            }
            Err(e) => return Err(e),
        },
    };
    let to = to.min(chain.tip());

    let genesis_notes: Vec<([u8; 32], L2Note)> = chain
        .genesis
        .file
        .genesis_notes
        .iter()
        .map(|n| {
            let note = GenesisPlaintext::open(&n.payload).expect("the file's structural check opened every payload");
            (n.cm, note)
        })
        .collect();
    let report = scan_annulet_from(w, fetch, from, to, chain.genesis.hash, &genesis_notes, rng);

    // Each block with a hit is fetched and bound once, whichever address's
    // row found it; what is kept is each transaction's commitments.
    let (mut bodies_fetched, mut body_bytes) = (0u64, 0u64);
    let mut bound: std::collections::BTreeMap<u64, Vec<Vec<[u8; 32]>>> = std::collections::BTreeMap::new();
    for owned in &report.owned {
        let Some(tx_index) = owned.tx_index else {
            if !genesis_notes.iter().any(|(cm, _)| *cm == owned.cm) {
                return Err(VerifyRefusal::ForgedGenesisNote { cm: owned.cm });
            }
            continue;
        };
        let height = owned.height;
        let forged = |why: &str| VerifyRefusal::ForgedNote { height, tx_index, why: why.to_string() };
        if h32(&owned.note.commitment()) != owned.cm {
            return Err(forged("the note does not open to the commitment it was served under"));
        }
        if let std::collections::btree_map::Entry::Vacant(slot) = bound.entry(height) {
            let header = chain.header(height).ok_or_else(|| forged("above the verified tip"))?;
            let bytes = fetch(&format!("/v1/block/{height}/body"))
                .map_err(|why| VerifyRefusal::BodyUnavailable { height, why })?;
            bodies_fetched += 1;
            body_bytes += bytes.len() as u64;
            let ann = decode_body_answer(ANNULET, height, &bytes)
                .map_err(|e| VerifyRefusal::BodyMalformed { height, why: e.to_string() })?;
            if ann.header != header {
                return Err(VerifyRefusal::BodyHeaderMismatch { height });
            }
            let body = qlab_p2p::served::body_of(&ann);
            if body_commitment_annulet(&body) != header.tx_body_commitment {
                return Err(VerifyRefusal::BodyCommitmentMismatch { height });
            }
            slot.insert(body.txs.iter().map(|tx| tx.public.commitments.clone()).collect());
        }
        let txs = &bound[&height];
        let cms = txs.get(tx_index as usize).ok_or_else(|| forged("the block has no such transaction"))?;
        if !cms.contains(&owned.cm) {
            return Err(forged("the transaction carries no such commitment"));
        }
    }
    // Freshness, not trust: the node's own word on its tip, for the line that
    // says how far behind the verified chain is.
    let stated_tip = fetch("/v1/registry/root")
        .ok()
        .and_then(|b| qlab_cbserver::registry::decode_registry_root(&b).ok())
        .map(|(height, _)| height);
    // The record is written only now, after every check passed — a refused
    // scan never writes it — and only when it would grow or was discarded.
    let grows = chain.headers.len() > recorded_len;
    let cache_write = match (&cache, grows) {
        (ChainCache::Discarded(_), _) | (_, true) => save_chain_cache(w, &chain.genesis.hash, &chain.headers).err(),
        _ => None,
    };
    Ok(VerifiedAnnulet { report, chain, range: (from, to), bodies_fetched, body_bytes, stated_tip, cache, cache_write })
}

/// Step 4: the registry leaf of `asset`, bound to the verified chain — the
/// opening's root must be the verified header's at the height it names, and
/// its path must fold to that root.
pub fn verify_registry_leaf<F>(
    fetch: &mut F,
    chain: &VerifiedChain,
    asset: u16,
) -> Result<qlab_air::l2::RegistryLeaf, VerifyRefusal>
where
    F: FnMut(&str) -> Result<Vec<u8>, String>,
{
    let path = format!("/v1/registry/{asset}");
    let bytes = fetch(&path).map_err(|why| VerifyRefusal::RegistryUnavailable { asset, why })?;
    let opening = qlab_cbserver::registry::decode_registry_opening(&bytes)
        .map_err(|e| VerifyRefusal::RegistryUnavailable { asset, why: format!("{e:?}") })?;
    if opening.leaf.asset != asset as u64 {
        return Err(VerifyRefusal::RegistryWrongAsset { want: asset, got: opening.leaf.asset });
    }
    let header = chain
        .header(opening.height)
        .ok_or(VerifyRefusal::RegistryHeightUnverified { height: opening.height, tip: chain.tip() })?;
    let HeaderExt::Annulet(ext) = header.ext else {
        return Err(VerifyRefusal::RegistryRootMismatch { height: opening.height });
    };
    if h32(&opening.root) != ext.registry_root {
        return Err(VerifyRefusal::RegistryRootMismatch { height: opening.height });
    }
    if opening.witness.fold_root(&opening.leaf.hash()) != opening.root {
        return Err(VerifyRefusal::RegistryPathMismatch { asset });
    }
    Ok(opening.leaf)
}

/// The report out of a verified scan — for a surface that prints it beside
/// the trust line the verification earned (the CLI). A view model takes
/// [`VerifiedAnnulet`] itself, never this.
pub fn into_report(v: VerifiedAnnulet) -> AnnuletReport {
    v.report
}
