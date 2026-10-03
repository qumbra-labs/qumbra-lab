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

/// Why a verified scan was refused — each a reason the endpoint cannot be
/// believed, never a figure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyRefusal {
    /// No genesis pin: there is no verified scan of an unnamed chain.
    NoPin,
    /// `/genesis.qmb` could not be read.
    GenesisUnavailable { why: String },
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
}

impl std::fmt::Display for VerifyRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use VerifyRefusal::*;
        match self {
            NoPin => write!(f, "no genesis pin: a verified Annulet scan needs the chain named by its genesis hash"),
            GenesisUnavailable { why } => write!(f, "GET {GENESIS_FILE_PATH}: {why}"),
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
    let key = genesis.file.sequencer().map_err(|e| VerifyRefusal::GenesisInvalid { why: e.to_string() })?;
    let mut state = ChainState::new_for(GenesisForm::Annulet, genesis.file.genesis_block_header());
    let mut headers: Vec<BlockHeader> = Vec::new();
    let mut parent = genesis.header_hash;
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
            qlab_devnet::validation::validate_sealed_header_annulet(&state, s, &key)
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
    Ok(VerifiedChain { genesis, headers })
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
    let chain = verify_chain(fetch, genesis, to)?;
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
    Ok(VerifiedAnnulet { report, chain, range: (from, to), bodies_fetched, body_bytes, stated_tip })
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
