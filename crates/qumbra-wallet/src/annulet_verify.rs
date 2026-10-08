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
//! The result is [`VerifiedAnnulet`], whose only constructor is the
//! caller-pumped [`crate::annulet_driver::AnnuletVerifyDriver`] (lab #858
//! WA1), and [`scan_annulet_verified`] is its pump: a balance cannot reach a
//! view model through any other path.

use qlab_devnet::annulet::HeaderExt;
use qlab_devnet::chain::ChainState;
use qlab_devnet::forms::{GenesisForm, L2AuthForm};
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_node::annulet_genesis::{h32, AnnuletGenesisFile};
use qlab_p2p::compact::WireForm;
use qlab_p2p::served::{decode_headers_page, sealed, MAX_HEADERS_PAGE};
use rand::rngs::StdRng;

use crate::annulet::AnnuletReport;
use crate::store::WalletDir;

/// Where the genesis file is read from: the scan endpoint, same origin — an
/// Annulet node answers it itself, and the path is the one an L1 wallet reads
/// from the L1 edge (`wallet-network-identity-decision`).
pub const GENESIS_FILE_PATH: &str = "/genesis.qmb";

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

/// `/v1/l2/index` (lab #860 R1): `{"v":1,"height":…,"bundle_id":"<64 hex>",
/// "refused":…}` — a reason of a few hundred bytes at most.
pub const MAX_L2_INDEX_ANSWER_BYTES: usize = 1024;

/// The nullifiers one V6 height can carry, as this wallet bounds them: one
/// bundle of K = 16 members, a transaction member publishing three (two
/// inputs and the fee slot) — 48 — rounded up to 64. **An assumption, named**:
/// a page past it fails on the wire as a transport error, and the V6 exit
/// plan says so beside that error.
pub const MAX_L2_NULLIFIERS_PER_HEIGHT: usize = 64;

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
    } else if route == "/v1/l2/index" {
        // Lab #860 R1: the index's one JSON line (two numbers, a hex id, a reason).
        MAX_L2_INDEX_ANSWER_BYTES
    } else if route == "/v1/l2/tree/leaves" {
        // One page of at most MAX_TREE_LEAVES 32-byte leaves, plus its header.
        qlab_node::rpc::MAX_TREE_LEAVES * 32 + 64
    } else if route == "/v1/l2/nullifiers" {
        // At most MAX_NULLIFIER_BLOCKS heights, each one bundle's nullifiers.
        qlab_cbserver::codec::MAX_NULLIFIER_BLOCKS * (32 + MAX_L2_NULLIFIERS_PER_HEIGHT * 32) + 64
    } else if route.starts_with("/v1/l2/registry/") {
        MAX_REGISTRY_ANSWER_BYTES
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
    /// Lab #896 G: the wallet's authorization journal (`auth.v1`) could not
    /// be read — the scan will not guess which generations are the wallet's.
    AuthJournal { why: String },
    /// `/genesis.qmb` could not be read.
    GenesisUnavailable { why: String },
    /// `/genesis.qmb` is longer than [`MAX_GENESIS_FILE_BYTES`].
    GenesisTooLarge { got: usize },
    /// The bytes served are not the pinned genesis.
    GenesisMismatch { pinned: [u8; 32], fetched: [u8; 32] },
    /// The pinned bytes do not decode, or fail the file's own structure check.
    GenesisInvalid { why: String },
    /// Lab #937: a net this **caller** does not serve yet. The wallet CLI
    /// scans and builds format 34 since lab #937 PR C; the kernel
    /// (`qumbra-ffi`) refuses a format-34 net by name until PR D, raising
    /// this after its verified scan. Never raised by the verifier itself.
    FormatNotSupported { format_version: u32 },
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
    /// A host misused the caller-pumped driver (lab #858 WA1): a step after
    /// a terminal step, or an answer with no `Need` outstanding. Never an
    /// endpoint's fault, and never reached by the synchronous pump.
    DriverMisuse { why: String },
}

impl std::fmt::Display for VerifyRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use VerifyRefusal::*;
        match self {
            NoPin => write!(f, "no genesis pin: a verified Annulet scan needs the chain named by its genesis hash"),
            AuthJournal { why } => write!(f, "the authorization journal could not be read: {why}"),
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
            FormatNotSupported { format_version } => write!(
                f,
                "genesis format {format_version} (three-output S/P spends) is not supported by this kernel yet (lab #937 PR D)"
            ),
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
            DriverMisuse { why } => write!(f, "the verified-scan driver was misused: {why}"),
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
    /// The net's L2 authorization axis, read from the file's
    /// `format_version` (lab #896 G, QG3): the pin covers the format, so it
    /// fixes the axis.
    pub l2_auth: L2AuthForm,
}

impl VerifiedGenesis {
    /// The served wire form of this net's headers and bodies (byte 3 on a
    /// v1 Annulet, 5 on a Candidate A one).
    pub fn wire(&self) -> WireForm {
        WireForm { form: GenesisForm::Annulet, sections: qlab_devnet::forms::BodySections::None, l2_auth: self.l2_auth }
    }
}

/// Step 1: fetch the genesis file, hash it against `pin`, decode and check it.
pub fn verify_genesis<F>(fetch: &mut F, pin: [u8; 32]) -> Result<VerifiedGenesis, VerifyRefusal>
where
    F: FnMut(&str) -> Result<Vec<u8>, String>,
{
    let bytes = fetch(GENESIS_FILE_PATH).map_err(|why| VerifyRefusal::GenesisUnavailable { why })?;
    genesis_from_bytes(pin, &bytes)
}

/// Step 1 without the fetch (lab #858 WA1): the genesis file's bytes against
/// `pin` — bounded, hashed, decoded and checked.
pub fn genesis_from_bytes(pin: [u8; 32], bytes: &[u8]) -> Result<VerifiedGenesis, VerifyRefusal> {
    if bytes.len() > MAX_GENESIS_FILE_BYTES {
        return Err(VerifyRefusal::GenesisTooLarge { got: bytes.len() });
    }
    let fetched = qlab_devnet::hash::keccak256(bytes);
    if fetched != pin {
        return Err(VerifyRefusal::GenesisMismatch { pinned: pin, fetched });
    }
    let file = AnnuletGenesisFile::from_bytes(bytes).map_err(|e| VerifyRefusal::GenesisInvalid { why: e.to_string() })?;
    file.verify(None).map_err(|e| VerifyRefusal::GenesisInvalid { why: e.to_string() })?;
    let header_hash = file.genesis_block_header().header_hash_for(GenesisForm::Annulet);
    let l2_auth = file.l2_auth().map_err(|e| VerifyRefusal::GenesisInvalid { why: e.to_string() })?;
    Ok(VerifiedGenesis { hash: fetched, file, header_hash, l2_auth })
}

/// Lab #896 G: refuse, by name, an endpoint body whose transaction lists
/// more than 255 nullifiers or commitments — the body commitment encodes
/// each count in one byte and asserts it, so such a body must never reach
/// it from a served answer.
pub(crate) fn check_body_counts(height: u64, body: &qlab_devnet::body::BlockBody) -> Result<(), VerifyRefusal> {
    let over = body
        .txs
        .iter()
        .any(|tx| tx.public.nullifiers.len() > u8::MAX as usize || tx.public.commitments.len() > u8::MAX as usize);
    if over {
        return Err(VerifyRefusal::BodyMalformed {
            height,
            why: "a transaction lists more than 255 nullifiers or commitments".into(),
        });
    }
    Ok(())
}

/// A header chain verified from the genesis file to its tip.
#[derive(Clone, Debug)]
pub struct VerifiedChain {
    pub genesis: VerifiedGenesis,
    /// `headers[i]` is height `i + 1`.
    pub(crate) headers: Vec<BlockHeader>,
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
    let mut walk = ChainWalk::from_genesis(genesis, up_to)?;
    while let Some((from, path)) = walk.want() {
        walk.admit(from, fetch(&path))?;
    }
    Ok(walk.finish())
}

/// **The one admission path for sealed headers**, caller-pumped (lab #858
/// WA1): heights past `headers` (`headers.len() + 1 ..`) up to `up_to` or the
/// endpoint's last, from genesis or from a resumed record. [`verify_chain`]
/// and the verified driver are its pumps.
pub(crate) struct ChainWalk {
    genesis: VerifiedGenesis,
    state: ChainState,
    headers: Vec<BlockHeader>,
    parent: Hash32,
    key: ml_dsa::VerifyingKey<ml_dsa::MlDsa65>,
    up_to: u64,
    done: bool,
}

impl ChainWalk {
    /// A walk from the genesis header.
    pub(crate) fn from_genesis(genesis: VerifiedGenesis, up_to: u64) -> Result<Self, VerifyRefusal> {
        let state = ChainState::new_for(GenesisForm::Annulet, genesis.file.genesis_block_header());
        Self::start(genesis, state, Vec::new(), up_to)
    }

    /// A walk past `headers`, whose admission `state` already holds.
    pub(crate) fn start(
        genesis: VerifiedGenesis,
        state: ChainState,
        headers: Vec<BlockHeader>,
        up_to: u64,
    ) -> Result<Self, VerifyRefusal> {
        let key = genesis.file.sequencer().map_err(|e| VerifyRefusal::GenesisInvalid { why: e.to_string() })?;
        let parent = headers.last().map_or(genesis.header_hash, |h| h.header_hash_for(GenesisForm::Annulet));
        Ok(ChainWalk { genesis, state, headers, parent, key, up_to, done: false })
    }

    /// The next page to read — its first height and path — or `None` once
    /// the walk is complete.
    pub(crate) fn want(&self) -> Option<(u64, String)> {
        let from = self.headers.len() as u64 + 1;
        if self.done || from > self.up_to {
            return None;
        }
        let to = self.page_end(from);
        Some((from, format!("/v1/headers?from={from}&to={to}")))
    }

    fn page_end(&self, from: u64) -> u64 {
        self.up_to.min(from + MAX_HEADERS_PAGE as u64 - 1)
    }

    /// Admit the answer to the page [`Self::want`] named at `from`.
    pub(crate) fn admit(&mut self, from: u64, answer: Result<Vec<u8>, String>) -> Result<(), VerifyRefusal> {
        let to = self.page_end(from);
        let bytes = answer.map_err(|why| VerifyRefusal::HeadersUnavailable { from, why })?;
        let units = decode_headers_page(self.genesis.wire(), from, &bytes)
            .map_err(|e| VerifyRefusal::HeadersMalformed { from, why: e.to_string() })?;
        let asked = to - from + 1;
        let got = units.len() as u64;
        for unit in &units {
            let s = sealed(unit).map_err(|e| VerifyRefusal::HeadersMalformed { from, why: e.to_string() })?;
            let want = self.headers.len() as u64 + 1;
            if s.header.height != want {
                return Err(VerifyRefusal::HeaderGap { want, got: s.header.height });
            }
            if s.header.prev != self.parent {
                return Err(VerifyRefusal::HeaderFork { height: want });
            }
            qlab_devnet::validation::validate_sealed_header_annulet(&self.state, s, &self.key)
                .map_err(|e| VerifyRefusal::HeaderInvalid { height: want, why: format!("{e:?}") })?;
            self.parent = self
                .state
                .insert_header(s.header)
                .map_err(|e| VerifyRefusal::HeaderInvalid { height: want, why: format!("{e:?}") })?;
            self.headers.push(s.header);
        }
        if got < asked {
            self.done = true;
        }
        Ok(())
    }

    pub(crate) fn finish(self) -> VerifiedChain {
        VerifiedChain { genesis: self.genesis, headers: self.headers }
    }
}

/// The served header at `height` out of a one-header `/v1/headers` answer:
/// `None` when the endpoint serves nothing there (it is behind).
pub(crate) fn served_header_at(
    wire: WireForm,
    height: u64,
    answer: Result<Vec<u8>, String>,
) -> Result<Option<BlockHeader>, VerifyRefusal> {
    let bytes = answer.map_err(|why| VerifyRefusal::HeadersUnavailable { from: height, why })?;
    let units = decode_headers_page(wire, height, &bytes)
        .map_err(|e| VerifyRefusal::HeadersMalformed { from: height, why: e.to_string() })?;
    match units.first() {
        None => Ok(None),
        Some(u) => Ok(Some(sealed(u).map_err(|e| VerifyRefusal::HeadersMalformed { from: height, why: e.to_string() })?.header)),
    }
}

/// The one-header `/v1/headers` path at `height`.
pub(crate) fn header_path(height: u64) -> String {
    format!("/v1/headers?from={height}&to={height}")
}

/// The height out of a `/v1/registry/root` answer — the endpoint's own word
/// on its tip; `None` when it did not say.
pub(crate) fn stated_height(answer: Result<Vec<u8>, String>) -> Option<u64> {
    answer.ok().and_then(|b| qlab_cbserver::registry::decode_registry_root(&b).ok()).map(|(height, _)| height)
}

/// The route [`stated_height`] reads.
pub const REGISTRY_ROOT_PATH: &str = "/v1/registry/root";

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

/// The largest record this build writes or reads: the 41-B prefix and
/// [`MAX_CACHED_HEADERS`] preimages — the bound a host-supplied record is
/// checked against before it is copied (lab #858 WA2).
pub const MAX_CHAIN_RECORD_BYTES: usize = 41 + MAX_CACHED_HEADERS as usize * PREIMAGE_LEN_ANNULET;

/// `ver(1) ‖ genesis(32) ‖ n(u64 LE) ‖ n × 153-B header preimage` — what a
/// driver host writes from [`VerifiedAnnulet::record_to_write`].
pub fn encode_chain_cache(genesis_hash: &[u8; 32], headers: &[BlockHeader]) -> Vec<u8> {
    let mut out = Vec::with_capacity(41 + headers.len() * PREIMAGE_LEN_ANNULET);
    out.push(CHAIN_CACHE_VERSION);
    out.extend_from_slice(genesis_hash);
    out.extend_from_slice(&(headers.len() as u64).to_le_bytes());
    for h in headers {
        out.extend_from_slice(&qlab_p2p::codec::encode_header(GenesisForm::Annulet, h));
    }
    out
}

/// Read the record's bytes for the chain `genesis_hash` names: `Ok(None)`
/// when there is none, `Err(why)` when it cannot be read. What a driver host
/// hands [`crate::annulet_driver::AnnuletVerifyDriver::new`].
pub fn read_chain_record(w: &WalletDir, genesis_hash: &[u8; 32]) -> Result<Option<Vec<u8>>, String> {
    let path = chain_cache_path(w, genesis_hash);
    match std::fs::read(&path) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Read the record and relink it from the genesis header (no seal
/// re-verify: it is this wallet's own prior verification). `Ok(None)` when
/// there is none; `Err(why)` when there is one and it does not load.
pub fn load_chain_cache(w: &WalletDir, genesis: &VerifiedGenesis) -> Result<Option<Vec<BlockHeader>>, String> {
    match read_chain_record(w, &genesis.hash)? {
        None => Ok(None),
        Some(b) => decode_chain_cache(&b, genesis).map(Some),
    }
}

/// The record's bytes, relinked from the genesis header — the load without
/// the file read.
pub fn decode_chain_cache(b: &[u8], genesis: &VerifiedGenesis) -> Result<Vec<BlockHeader>, String> {
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
    Ok(headers)
}

/// Write the record atomically (`<path>.tmp`, fsync, rename).
pub(crate) fn save_chain_cache(w: &WalletDir, genesis_hash: &[u8; 32], headers: &[BlockHeader]) -> Result<(), String> {
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
    pub(crate) report: AnnuletReport,
    pub(crate) chain: VerifiedChain,
    pub(crate) range: (u64, u64),
    pub(crate) bodies_fetched: u64,
    pub(crate) body_bytes: u64,
    pub(crate) stated_tip: Option<u64>,
    pub(crate) cache: ChainCache,
    /// Whether the record should be (re)written: it grows, or was discarded.
    pub(crate) write_record: bool,
    /// Why the record could not be written, if it could not (the scan
    /// stands; the next one verifies more).
    pub(crate) cache_write: Option<String>,
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

    /// The verified net's L2 authorization axis — [`L2AuthForm::CandidateA`]
    /// on a format-33 genesis, [`L2AuthForm::None`] on format 32 — read from
    /// the genesis file the scan verified against the pin (lab #896; macOS
    /// #60 D2: a shell asks this before deriving an address or planning a
    /// send, never infers it from its own net table). The same value is
    /// `chain().genesis.l2_auth`; a pre-scan check on raw genesis bytes is
    /// `AnnuletGenesisFile::from_bytes(b)?.l2_auth()`.
    pub fn l2_auth(&self) -> L2AuthForm {
        self.chain.genesis.l2_auth
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

    /// The verified headers to record after this scan — `Some` exactly when
    /// the record would grow or was discarded (lab #858 WA1: the driver never
    /// touches a filesystem; its host writes this and says how it went with
    /// [`Self::set_cache_write`]).
    pub fn record_to_write(&self) -> Option<&[BlockHeader]> {
        self.write_record.then_some(self.chain.headers.as_slice())
    }

    /// The host's report of the record write: `None` when it was written.
    pub fn set_cache_write(&mut self, outcome: Option<String>) {
        self.cache_write = outcome;
    }

    /// Bodies fetched to bind notes, and their bytes: the per-hit cost.
    pub fn body_cost(&self) -> (u64, u64) {
        (self.bodies_fetched, self.body_bytes)
    }
}

/// **The verified Annulet scan**: steps 1–3 of the module doc, then the
/// unchanged scan body over the verified range and genesis. Since lab #858
/// WA1 the pump of [`crate::annulet_driver::AnnuletVerifyDriver`] — the one
/// orchestration — reading and writing the wallet dir's record around it.
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
    scan_annulet_verified_with_generations(w, fetch, from, to, pin, &[], rng)
}

/// [`scan_annulet_verified`] with the **authorization generations** a
/// Candidate A (format-33) scan owns notes under, as `(g, auth_root(g))`
/// (`crate::auth_journal::generation_root`) — lab #896, the Rust-API twin of
/// `qmb_annulet_new_v2` (macOS #60 D2). A non-empty list is used as given
/// (a receive-only wallet passes generation 0 alone); an empty list is
/// [`scan_annulet_verified`]'s own rule — the wallet's journal when it has
/// one, else the driver's probe. A v1 net does not read them. The record is
/// read and written exactly as [`scan_annulet_verified`] does.
pub fn scan_annulet_verified_with_generations<F>(
    w: &WalletDir,
    fetch: &mut F,
    from: u64,
    to: u64,
    pin: Option<[u8; 32]>,
    generations: &[(u32, [u64; 4])],
    rng: &mut StdRng,
) -> Result<VerifiedAnnulet, VerifyRefusal>
where
    F: FnMut(&str) -> Result<Vec<u8>, String>,
{
    use crate::annulet_driver::{AnnuletStep, AnnuletVerifyDriver};
    let pin = pin.ok_or(VerifyRefusal::NoPin)?;
    let record = read_chain_record(w, &pin);
    let mut driver = AnnuletVerifyDriver::new(w.wallet(), w.allocated.clone(), pin, from, to, record);
    if !generations.is_empty() {
        driver = driver.with_generations(generations.to_vec());
    } else {
        // Lab #896 G: the journal's generations, when the wallet has one (a
        // Candidate A net only reads them; a v1 net ignores them).
        match crate::auth_journal::AuthJournal::load(&w.dir) {
            Ok(Some(j)) => {
                driver = driver.with_generations(j.generations().iter().map(|r| (r.g, r.auth_root)).collect())
            }
            Ok(None) => {}
            Err(e) => return Err(VerifyRefusal::AuthJournal { why: e.to_string() }),
        }
    }
    let mut v = loop {
        match driver.step(rng) {
            AnnuletStep::Need(path) => driver.supply(fetch(&path)),
            AnnuletStep::Done(v) => break *v,
            AnnuletStep::Failed(e) => return Err(e),
        }
    };
    if let Some(headers) = v.record_to_write() {
        let outcome = save_chain_cache(w, &v.chain.genesis.hash, headers).err();
        v.set_cache_write(outcome);
    }
    Ok(v)
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
    check_registry_leaf(chain, asset, fetch(&registry_leaf_path(asset)))
}

/// Where [`check_registry_leaf`] reads `asset`'s opening.
pub fn registry_leaf_path(asset: u16) -> String {
    format!("/v1/registry/{asset}")
}

/// Step 4 without the fetch (lab #858 WA1): an answer to
/// [`registry_leaf_path`] bound to the verified chain.
pub fn check_registry_leaf(
    chain: &VerifiedChain,
    asset: u16,
    answer: Result<Vec<u8>, String>,
) -> Result<qlab_air::l2::RegistryLeaf, VerifyRefusal> {
    let bytes = answer.map_err(|why| VerifyRefusal::RegistryUnavailable { asset, why })?;
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
