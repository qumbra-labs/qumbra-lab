//! **The L2 spend assembly** (lab #720, L2 C2): served witnesses → circuit
//! instance → real prove → the transaction with its encrypted discovery group
//! → `POST /v1/tx`.
//!
//! B6 built this inside `qumbra-faucet` because the faucet needed it first.
//! C2 promotes it here so the wallet and the faucet share one copy.
//!
//! - **Inputs are circuit inputs** ([`L2TxInput`]: `sk`, `d`, and the note's
//!   fields). The wallet derives them from C1's `OwnedL2Note` and its spending
//!   key; the faucet derives them from its dev key.
//! - **The endpoint is a trait** ([`Endpoint`]), so the same assembly runs over
//!   plain HTTP (the faucet, the harness), over the wallet's TLS transport, or
//!   over a fixture.
//! - **The shape follows the served registry leaf.** Shape S opens Cloaked
//!   assets; shape P opens Hybrid assets, and a user's transfer needs only an
//!   empty-freeze opening the wallet can rebuild itself ([`policy_for_transfer`]).
//!   A non-empty freeze tree or a Regulated asset needs the issuer's witnesses
//!   (C3) and is refused by name.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};

use qlab_air::l2::{L2TxInput, L2TxOutput, RegistryLeaf, MODE_CLOAKED, MODE_HYBRID, MODE_REGULATED};
use qlab_air::l2p::{dummy_allow_witness, CanonicalFreezeTree, L2PolicyInput, PolicyWitness, VPublic};
use qlab_air::narrow::MerkleWitness;
use qlab_cbserver::registry::{
    decode_genesis_notes, decode_registry_opening, decode_registry_slot, RegistryOpening, RegistrySlotOpening,
};
use qlab_cbserver::tree::CommitmentTree;
use qlab_devnet::annulet::{L2ShapeTag, L2Surface, VPublicTerm};
use qlab_devnet::body::{TxEntry, TxPublic};
use qlab_devnet::fees::ArityBucket;
use qlab_note::hash::digest_bytes;
use qlab_note::kem::Ek;
use qlab_note::l2note::{GenesisPlaintext, L2Note, L2_PAYLOAD_LEN};
use qlab_note::wire::RecipientBundle;
use rand::Rng;

/// Why a spend could not be assembled or was not admitted — by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpendError {
    /// A served answer was missing or did not decode.
    Served(String),
    /// The node refused the transaction (its named verdict, whole).
    Refused(String),
    /// The asset's policy needs witnesses only its issuer holds (C3).
    NeedsIssuerWitness { asset: u64, why: &'static str },
    /// The inputs' registry openings were computed against different roots.
    RegistryMoved,
    /// The published freeze list does not rebuild the served `freeze_root`:
    /// it is not the issuer's current list (lab #722).
    FreezeListStale { asset: u64 },
    /// This address is on the asset's freeze list (lab #722).
    Frozen { asset: u64 },
    /// The allowlist witness does not fold to the served `allow_root`.
    NotAllowlisted { asset: u64 },
    /// A registry write's fee note holds less than the fee (lab #728).
    FeeExceedsInput { have: u64, fee: u64 },
    /// A4: slot 3's fee note must be asset 0 and worth exactly the fee — it
    /// is spent whole and the 3×2 shapes have no fee change.
    FeeNoteNotExact { value: u64, asset: u64, fee: u64 },
}

impl std::fmt::Display for SpendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpendError::Served(e) => write!(f, "served data: {e}"),
            SpendError::Refused(e) => write!(f, "the node refused the transaction: {e}"),
            SpendError::NeedsIssuerWitness { asset, why } => write!(
                f,
                "asset {asset}: {why} — spending it needs the issuer's witness service (C3), \
                 which does not exist yet"
            ),
            SpendError::RegistryMoved => {
                write!(f, "the registry moved between the two openings; retry")
            }
            SpendError::FreezeListStale { asset } => write!(
                f,
                "asset {asset}: the freeze list does not rebuild the registry's freeze root — fetch the \
                 issuer's current list"
            ),
            SpendError::Frozen { asset } => write!(f, "asset {asset}: this address is frozen by the issuer"),
            SpendError::NotAllowlisted { asset } => {
                write!(f, "asset {asset}: the allowlist witness does not open the registry's allow root")
            }
            SpendError::FeeExceedsInput { have, fee } => {
                write!(f, "the fee note holds {have}, less than the registry-write fee {fee}")
            }
            SpendError::FeeNoteNotExact { value, asset, fee } => write!(
                f,
                "slot 3's fee note is {value} of asset {asset}; it must be exactly {fee} of asset 0 \
                 (spent whole — the 3×2 shapes have no fee change)"
            ),
        }
    }
}

impl std::error::Error for SpendError {}

/// A node's served surfaces, by path. `get` answers only a 200 body.
pub trait Endpoint {
    fn get(&self, path: &str) -> Result<Vec<u8>, String>;
    /// `(status, body)` for any status.
    fn post(&self, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), String>;
}

/// Plain HTTP/1.1 to a socket address (the faucet, the harness).
#[derive(Clone, Copy, Debug)]
pub struct PlainHttp {
    pub addr: SocketAddr,
}

impl PlainHttp {
    fn request(&self, method: &str, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), String> {
        let io = |e: std::io::Error| format!("{method} {path}: {e}");
        let mut s = TcpStream::connect(self.addr).map_err(io)?;
        write!(s, "{method} {path} HTTP/1.1\r\nHost: node\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())
            .map_err(io)?;
        s.write_all(body).map_err(io)?;
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).map_err(io)?;
        let split = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or_else(|| format!("{path}: no header block"))? + 4;
        let status = std::str::from_utf8(raw.get(9..12).unwrap_or_default())
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| format!("{path}: no status"))?;
        Ok((status, raw[split..].to_vec()))
    }
}

impl Endpoint for PlainHttp {
    fn get(&self, path: &str) -> Result<Vec<u8>, String> {
        match self.request("GET", path, &[])? {
            (200, body) => Ok(body),
            (code, body) => Err(format!("{path}: {code} {}", String::from_utf8_lossy(&body))),
        }
    }
    fn post(&self, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), String> {
        self.request("POST", path, body)
    }
}

/// The served surfaces the assembly reads, over any [`Endpoint`].
///
/// [`Served::new`] reads an Annulet node's L2 routes at their own paths;
/// [`Served::v6`] reads a V6 node's derived L2 index (lab #860 R1), the same
/// wire under `/v1/l2/` — leaves, nullifiers, the registry opening. The
/// routes a V6 node does not serve (registry slots, genesis notes, params,
/// detection, `POST /v1/tx`) are refused by name under it, never fetched.
pub struct Served<E: Endpoint> {
    pub endpoint: E,
    /// `""` for an Annulet node, `"/v1/l2"` for a V6 node's index.
    pub prefix: &'static str,
}

/// The V6 index's path prefix (lab #860 R1).
pub const V6_L2_PREFIX: &str = "/v1/l2";

fn served<T>(r: Result<T, String>) -> Result<T, SpendError> {
    r.map_err(SpendError::Served)
}

impl<E: Endpoint> Served<E> {
    pub fn new(endpoint: E) -> Self {
        Self { endpoint, prefix: "" }
    }

    /// A V6 node's derived L2 index, under [`V6_L2_PREFIX`].
    pub fn v6(endpoint: E) -> Self {
        Self { endpoint, prefix: V6_L2_PREFIX }
    }

    /// Refuse, by name, a route a V6 node does not serve.
    fn annulet_only(&self, what: &str) -> Result<(), SpendError> {
        if self.prefix.is_empty() {
            Ok(())
        } else {
            Err(SpendError::Served(format!("{what} is not served by a V6 node's L2 index (lab #860): an Annulet route")))
        }
    }

    /// The whole commitment tree, rebuilt in memory from the served leaves
    /// (nothing is cached: an L1 wallet's `tree-leaves.v1` is never touched).
    pub fn commitment_tree(&self) -> Result<CommitmentTree, SpendError> {
        self.commitment_tree_to(None)
    }

    /// The commitment tree of the first `count` served leaves — the tree a
    /// bundle's surface states (its `c_next`), even when the index has served
    /// more since. Fewer served than `count` is refused by name.
    pub fn commitment_tree_at(&self, count: u64) -> Result<CommitmentTree, SpendError> {
        let tree = self.commitment_tree_to(Some(count))?;
        if tree.len() < count {
            return Err(SpendError::Served(format!("the served tree has {} leaves, fewer than the {count} the anchor states", tree.len())));
        }
        Ok(tree)
    }

    fn commitment_tree_to(&self, count: Option<u64>) -> Result<CommitmentTree, SpendError> {
        let mut tree = CommitmentTree::new();
        loop {
            let body = served(self.endpoint.get(&format!("{}/tree/leaves?from={}", self.prefix_or("/v1"), tree.len())))?;
            let page = served(qlab_node::TreeLeaves::from_bytes(&body).map_err(|e| format!("tree leaves: {e:?}")))?;
            if page.leaves.is_empty() {
                return Ok(tree);
            }
            for leaf in &page.leaves {
                if count.is_some_and(|c| tree.len() >= c) {
                    return Ok(tree);
                }
                tree.append_bytes(leaf);
            }
            if tree.len() >= page.total || count.is_some_and(|c| tree.len() >= c) {
                return Ok(tree);
            }
        }
    }

    /// The route base: the V6 prefix, or `annulet`'s own (`/v1`).
    fn prefix_or(&self, annulet: &'static str) -> &'static str {
        if self.prefix.is_empty() {
            annulet
        } else {
            self.prefix
        }
    }

    /// The registry opening of `asset`, with the root it was computed against.
    pub fn registry(&self, asset: u64) -> Result<RegistryOpening, SpendError> {
        let body = served(self.endpoint.get(&format!("{}/registry/{asset}", self.prefix_or("/v1"))))?;
        served(decode_registry_opening(&body).map_err(|e| format!("registry {asset}: {e:?}")))
    }

    /// The opening of registry slot `asset`, registered or empty, with the
    /// root it was computed against (lab #728 — what a registry write proves
    /// against).
    pub fn registry_slot(&self, asset: u64) -> Result<RegistrySlotOpening, SpendError> {
        self.annulet_only("a registry slot opening")?;
        let body = served(self.endpoint.get(&format!("/v1/registry/slot/{asset}")))?;
        served(decode_registry_slot(&body).map_err(|e| format!("registry slot {asset}: {e:?}")))
    }

    /// The genesis notes, opened, with the served genesis hash.
    pub fn genesis_notes(&self) -> Result<([u8; 32], Vec<L2Note>), SpendError> {
        self.annulet_only("the genesis notes")?;
        let body = served(self.endpoint.get("/v1/genesis/notes"))?;
        let (hash, notes) = served(decode_genesis_notes(&body).map_err(|e| format!("genesis notes: {e:?}")))?;
        let opened = notes
            .iter()
            .map(|n| GenesisPlaintext::open(&n.payload.0).ok_or_else(|| SpendError::Served("a genesis note does not open".into())))
            .collect::<Result<_, _>>()?;
        Ok((hash, opened))
    }

    /// The fee tiers (lab #720's `GET /v1/annulet/params`), with the genesis
    /// hash they come from.
    pub fn params(&self) -> Result<qlab_cbserver::registry::AnnuletParams, SpendError> {
        self.annulet_only("the Annulet fee tiers")?;
        let body = served(self.endpoint.get("/v1/annulet/params"))?;
        served(qlab_cbserver::registry::decode_annulet_params(&body).map_err(|e| format!("params: {e:?}")))
    }

    /// Every nullifier the chain has published (`/v1/nullifiers`, paged).
    pub fn spent_nullifiers(&self) -> Result<std::collections::HashSet<[u8; 32]>, SpendError> {
        let mut spent = std::collections::HashSet::new();
        let mut from = 0u64;
        loop {
            let body = served(self.endpoint.get(&format!("{}/nullifiers?from={from}&to={}", self.prefix_or("/v1"), u64::MAX)))?;
            let page = served(qlab_cbserver::codec::NullifierPage::from_bytes(&body).map_err(|e| format!("nullifiers: {e:?}")))?;
            for b in &page.blocks {
                spent.extend(b.nullifiers.iter().copied());
            }
            match page.blocks.last() {
                Some(last) if last.height < page.to && last.height >= from => from = last.height + 1,
                _ => return Ok(spent),
            }
        }
    }

    /// **The recipient's detection** over `[from, to]`, the way a light wallet
    /// reads it (`/v1/compact` + `/full`), each opened cm checked against the
    /// served one. The wallet's own scan (C1) is the driver; this is the
    /// harness's cross-check.
    pub fn detect(&self, dk: &qlab_note::kem::Dk, from: u64, to: u64) -> Result<Vec<L2Note>, SpendError> {
        self.annulet_only("note detection")?;
        let body = served(self.endpoint.get(&format!("/v1/compact?from={from}&to={to}")))?;
        let blocks = served(qlab_cbserver::codec::decode_compact_response(&body).map_err(|e| format!("compact: {e:?}")))?;
        let mut found = Vec::new();
        for block in &blocks {
            for group in &block.groups {
                let body = served(self.endpoint.get(&format!("/v1/block/{}/tx/{}/full", block.height, group.tx_index)))?;
                let full = served(qlab_cbserver::codec::decode_full_response(&body).map_err(|e| format!("full: {e:?}")))?;
                for (r, bundle) in group.recipients.iter().enumerate() {
                    for d in qlab_cbserver::client::open_served_l2(dk, bundle, &full[r]) {
                        if digest_bytes(&d.note.commitment()) != bundle.entries[d.index].cm {
                            return Err(SpendError::Served("an opened note is not the served cm".into()));
                        }
                        found.push(d.note);
                    }
                }
            }
        }
        Ok(found)
    }

    /// Submit a transaction on the Annulet tx wire.
    pub fn submit(&self, tx: &TxEntry) -> Result<(), SpendError> {
        self.annulet_only("POST /v1/tx")?;
        let wire = qlab_p2p::codec::encode_tx_annulet(tx);
        let (status, body) = served(self.endpoint.post("/v1/tx", &wire))?;
        submit_verdict(status, &body)
    }
}

/// Read `POST /v1/tx`'s answer: `202 accepted` and `200 duplicate` are
/// success; any other status is the node's named refusal, carried whole.
pub fn submit_verdict(status: u16, body: &[u8]) -> Result<(), SpendError> {
    match status {
        202 | 200 => Ok(()),
        _ => Err(SpendError::Refused(String::from_utf8_lossy(body).into_owned())),
    }
}

/// Where an output goes: its `rkm` and the discovery key it is encrypted to.
#[derive(Clone)]
pub struct Recipient {
    pub rkm: [u64; 4],
    pub ek: Ek,
}

/// One output of a spend.
#[derive(Clone)]
pub struct Out {
    pub to: Recipient,
    pub value: u64,
    pub asset: u64,
}

/// An assembled L2 transaction and the output notes it creates.
pub struct Built {
    pub tx: TxEntry,
    pub outputs: [L2Note; 2],
    pub shape: L2ShapeTag,
}

/// What one input's policy needs beyond the served opening (lab #722): the
/// issuer's **published freeze-key list** (Hybrid and Regulated), a
/// Regulated holder's **allowlist witness** (the issuer hands it over), and
/// the issuer secret for a mint or a closed redeem (zero otherwise).
#[derive(Clone, Default)]
pub struct PolicyContext {
    pub freeze_keys: Vec<[u64; 4]>,
    pub allow_witness: Option<PolicyWitness>,
    pub isk: [u64; 4],
}

/// **The policy inputs of one P input**, from the served opening and the
/// published data. A Cloaked leaf opens the empty canonical tree (its path
/// is not checked against a root). A Hybrid or Regulated leaf opens the
/// **canonical** freeze tree rebuilt from the published key list, used only
/// when that root is the served `freeze_root`; a frozen `rkm` is refused by
/// name before any proving. A Regulated leaf also needs the holder's
/// allowlist witness folding to the served `allow_root`.
pub fn policy_input(opening: &RegistryOpening, rkm: &[u64; 4], ctx: &PolicyContext) -> Result<L2PolicyInput, SpendError> {
    let leaf: RegistryLeaf = opening.leaf;
    let tree = match leaf.mode {
        MODE_CLOAKED => CanonicalFreezeTree::empty(),
        MODE_HYBRID | MODE_REGULATED => {
            let tree = CanonicalFreezeTree::from_keys(&ctx.freeze_keys);
            if tree.root != leaf.freeze_root {
                return Err(SpendError::FreezeListStale { asset: leaf.asset });
            }
            tree
        }
        _ => return Err(SpendError::Served(format!("asset {}: unknown registry mode {}", leaf.asset, leaf.mode))),
    };
    let freeze = tree.opening_for(rkm).ok_or(SpendError::Frozen { asset: leaf.asset })?;
    let allow = if leaf.mode == MODE_REGULATED {
        let w = ctx.allow_witness.ok_or(SpendError::NeedsIssuerWitness {
            asset: leaf.asset,
            why: "a Regulated asset needs the holder's allowlist witness, which the issuer hands over",
        })?;
        if w.fold_root(&qlab_air::l2p::cred_of(rkm)) != leaf.allow_root {
            return Err(SpendError::NotAllowlisted { asset: leaf.asset });
        }
        w
    } else {
        dummy_allow_witness()
    };
    Ok(L2PolicyInput { leaf, reg_witness: opening.witness, freeze, allow, isk: ctx.isk })
}

/// A transfer's policy input with an **empty** published freeze list and no
/// issuer secret (C2's case): a Hybrid asset whose freeze tree is not empty
/// is refused as [`SpendError::FreezeListStale`] — pass the issuer's list via
/// [`policy_input`].
pub fn policy_for_transfer(opening: &RegistryOpening, rkm: &[u64; 4]) -> Result<L2PolicyInput, SpendError> {
    policy_input(opening, rkm, &PolicyContext::default())
}

/// The shape a transfer of `leaf`'s asset needs.
pub fn shape_for(leaf: &RegistryLeaf) -> L2ShapeTag {
    if leaf.mode == MODE_CLOAKED {
        L2ShapeTag::S
    } else {
        L2ShapeTag::P
    }
}

fn cm_of(input: &L2TxInput) -> [u64; 4] {
    qlab_air::l2::derive_input_l2(input).2
}

/// The witness of an input's note in `tree` (the tree's current root anchors it).
fn witness_of(tree: &CommitmentTree, input: &L2TxInput) -> Result<MerkleWitness, SpendError> {
    let pos = tree
        .position_of(&cm_of(input))
        .ok_or_else(|| SpendError::Served("an input note is not in the served commitment tree".into()))?;
    Ok(tree.auth_path(pos, tree.len()))
}

fn output_notes(outputs: &[L2TxOutput; 2], nf0: &[u64; 4], cm_out: &[[u64; 4]; 2]) -> [L2Note; 2] {
    core::array::from_fn(|j| {
        let o = &outputs[j];
        let n = L2Note {
            value: o.value,
            asset: o.asset,
            rkm: o.rkm,
            rho: qlab_air::narrow::derive_output_rho(nf0, j),
            rseed: o.rseed,
        };
        assert_eq!(n.commitment(), cm_out[j], "output {j}: the note is the one the proof commits");
        n
    })
}

fn discovery_for<R: rand::CryptoRng>(notes: &[L2Note; 2], outs: &[Out; 2], rng: &mut R) -> Vec<u8> {
    let mut bundles: Vec<RecipientBundle> = Vec::new();
    let mut payloads: Vec<Vec<u8>> = Vec::new();
    for j in 0..2 {
        let out = qlab_note::scan::encrypt_notes_to_recipient(&outs[j].to.ek, &notes[j..=j], rng);
        bundles.push(out.bundle);
        payloads.extend(out.payloads);
    }
    qlab_note::compact::encode_committed_discovery_with_width(&bundles, &payloads, L2_PAYLOAD_LEN)
}

/// A4: a dummy slot-3 fee input (`d3 = 1`) with fresh `sk`/`ρ`.
fn dummy_fee_slot<R: Rng>(rng: &mut R) -> qlab_air::l2::FeeSlot {
    qlab_air::l2::FeeSlot::Dummy {
        input: L2TxInput { sk: random_d4(rng), value: 0, asset: 0, rho: random_d4(rng), rseed: random_d4(rng), d: [0, 0] },
    }
}

/// A4: slot 3 as asked — an exact-`fee` asset-0 note with its witness in
/// `tree` (`d3 = 0`: the rows carry no fee, so two notes of one asset merge),
/// or a fresh dummy (`d3 = 1`: the fee from an asset-0 row, as before A4).
fn fee_slot_for<R: Rng>(
    tree: &CommitmentTree,
    exact: Option<&L2TxInput>,
    fee: u64,
    rng: &mut R,
) -> Result<qlab_air::l2::FeeSlot, SpendError> {
    let Some(note) = exact else { return Ok(dummy_fee_slot(rng)) };
    if note.asset != 0 || note.value != fee {
        return Err(SpendError::FeeNoteNotExact { value: note.value, asset: note.asset, fee });
    }
    Ok(qlab_air::l2::FeeSlot::Exact { input: note.clone(), witness: witness_of(tree, note)? })
}

fn random_d4<R: Rng>(rng: &mut R) -> [u64; 4] {
    [rng.next_u64(), rng.next_u64(), rng.next_u64(), rng.next_u64()]
}

fn l2_outputs<R: Rng>(outs: &[Out; 2], rng: &mut R) -> [L2TxOutput; 2] {
    core::array::from_fn(|j| L2TxOutput {
        value: outs[j].value,
        asset: outs[j].asset,
        rkm: outs[j].to.rkm,
        rho: [0; 4],
        rseed: random_d4(rng),
    })
}

#[allow(clippy::too_many_arguments)]
fn entry(
    proof: &qlab_l2::Proof<qlab_l2::Config>,
    anchor: &[u64; 4],
    nf: &[[u64; 4]; 2],
    nf3: &[u64; 4],
    cm_out: &[[u64; 4]; 2],
    fee: u64,
    surface: L2Surface,
    discovery: Vec<u8>,
) -> TxEntry {
    TxEntry {
        proof: bincode::serialize(proof).expect("a proof serializes"),
        public: TxPublic {
            anchor: digest_bytes(anchor),
            // A4: the two inputs' nullifiers, then slot 3's (the fee input's,
            // or a dummy's fresh one) — the 3×2 shapes publish three.
            nullifiers: nf.iter().chain(std::iter::once(nf3)).map(digest_bytes).collect(),
            commitments: cm_out.iter().map(digest_bytes).collect(),
            bucket: ArityBucket::TwoByTwo,
            fee,
        },
        discovery,
        rider: qlab_devnet::names::RIDER_ABSENT.to_vec(),
        l2: surface.encode(),
    }
}

/// **A shape-S spend** (Cloaked assets): one or two real inputs; with one,
/// the second slot is a dummy (value 0, asset 0, a fresh ρ so its nullifier
/// never repeats). Proves (≈ 7 GB, seconds).
pub fn build_s<E: Endpoint, R: rand::CryptoRng>(
    served: &Served<E>,
    inputs: &[&L2TxInput],
    outs: &[Out; 2],
    fee: u64,
    rng: &mut R,
) -> Result<Built, SpendError> {
    build_s_slot(served, inputs, outs, fee, None, rng)
}

/// **A4's merge on shape S** (`d3 = 0`): two real inputs — two notes of one
/// Cloaked asset, typically — and `fee_note`, an asset-0 note worth exactly
/// `fee`, in slot 3. The rows carry no fee.
pub fn build_s_merge<E: Endpoint, R: rand::CryptoRng>(
    served: &Served<E>,
    inputs: [&L2TxInput; 2],
    outs: &[Out; 2],
    fee: u64,
    fee_note: &L2TxInput,
    rng: &mut R,
) -> Result<Built, SpendError> {
    build_s_slot(served, &inputs, outs, fee, Some(fee_note), rng)
}

fn build_s_slot<E: Endpoint, R: rand::CryptoRng>(
    served: &Served<E>,
    inputs: &[&L2TxInput],
    outs: &[Out; 2],
    fee: u64,
    exact_fee: Option<&L2TxInput>,
    rng: &mut R,
) -> Result<Built, SpendError> {
    assert!(matches!(inputs.len(), 1 | 2), "a 2×2 bucket takes one or two real inputs");
    // A single real input rides #219's dummy slot 1; an exact fee note is
    // only ever planned beside two real inputs (a merge or a two-note pay).
    assert!(exact_fee.is_none() || inputs.len() == 2, "an exact slot-3 fee note is built with two real inputs");
    let tree = served.commitment_tree()?;
    let anchor = tree.root();
    let outputs = l2_outputs(outs, rng);
    // A4: slot 3 — the exact fee note, or a dummy whose sk/ρ are drawn fresh
    // because its nullifier is published.
    let fee_slot = fee_slot_for(&tree, exact_fee, fee, rng)?;
    let inst = if let [a, b] = inputs {
        let regs = [served.registry(a.asset)?, served.registry(b.asset)?];
        if regs[0].root != regs[1].root {
            return Err(SpendError::RegistryMoved);
        }
        qlab_air::l2::build_bucket_l2_with_witnesses(
            qlab_l2::LOG_HEIGHT_S,
            &[(*a).clone(), (*b).clone()],
            &outputs,
            fee,
            &[witness_of(&tree, a)?, witness_of(&tree, b)?],
            anchor,
            &[regs[0].leaf, regs[1].leaf],
            &[regs[0].witness, regs[1].witness],
            regs[0].root,
            &fee_slot,
        )
    } else {
        let real = inputs[0];
        let (reg, reg0) = (served.registry(real.asset)?, served.registry(0)?);
        if reg.root != reg0.root {
            return Err(SpendError::RegistryMoved);
        }
        let dummy = L2TxInput { sk: random_d4(rng), value: 0, asset: 0, rho: random_d4(rng), rseed: random_d4(rng), d: [0, 0] };
        qlab_air::l2::build_bucket_l2_dummy1(
            qlab_l2::LOG_HEIGHT_S,
            real,
            &witness_of(&tree, real)?,
            &dummy,
            &qlab_air::narrow::off_tree_witness(),
            &outputs,
            fee,
            anchor,
            &[reg.leaf, reg0.leaf],
            &[reg.witness, reg0.witness],
            reg.root,
            &fee_slot,
        )
    };
    let (_, proof) = qlab_l2::prove_s(&inst);
    let notes = output_notes(&outputs, &inst.nf[0], &inst.cm_out);
    let discovery = discovery_for(&notes, outs, rng);
    let surface = L2Surface { shape: L2ShapeTag::S, registry_root: digest_bytes(&inst.registry_root), vpublic: None, write: None, exit_rkm: [0; 32] };
    Ok(Built { tx: entry(&proof, &anchor, &inst.nf, &inst.nf3, &inst.cm_out, fee, surface, discovery), outputs: notes, shape: L2ShapeTag::S })
}

/// An assembled registry write (shape R) and its two output notes.
pub struct BuiltR {
    pub tx: TxEntry,
    /// The fee change, to the payer.
    pub output: L2Note,
    /// The seed (A3, lab #731): a 0-value note of the written asset, to the
    /// payer — what an issuer's first mint of the asset rides on.
    pub seed: L2Note,
    /// The registry root the write moves to (header bytes).
    pub new_root: [u8; 32],
}

/// **A shape-R registry write** (lab #728): `new_leaf` replaces registry slot
/// `new_leaf.asset` — a **registration** when the served slot is empty
/// (permissionless; `isk` is not read), an **update** when it holds a leaf
/// (`isk` is the issuer secret behind that leaf's `issuer_key`). One asset-0
/// fee note pays `fee`; the change goes to `change`. The slot's opening and
/// root come from `/v1/registry/slot/{asset}`, the fee note's witness from the
/// served commitment tree. Every write also seeds a 0-value note of the
/// written asset to `change` (A3). Proves (≈ 3.5 GB, under a second on the rig).
pub fn build_r<E: Endpoint, R: rand::CryptoRng>(
    served: &Served<E>,
    fee_input: &L2TxInput,
    change: &Recipient,
    fee: u64,
    new_leaf: RegistryLeaf,
    isk: [u64; 4],
    rng: &mut R,
) -> Result<BuiltR, SpendError> {
    let change_value = fee_input
        .value
        .checked_sub(fee)
        .ok_or(SpendError::FeeExceedsInput { have: fee_input.value, fee })?;
    let tree = served.commitment_tree()?;
    let anchor = tree.root();
    let slot = served.registry_slot(new_leaf.asset)?;
    let write = qlab_air::l2r::RegistryWrite { isk, old_leaf: slot.leaf, new_leaf, opening: slot.witness };
    let out = L2TxOutput { value: change_value, asset: 0, rkm: change.rkm, rho: [0; 4], rseed: random_d4(rng) };
    let seed = qlab_air::l2r::SeedOutput { rkm: change.rkm, rseed: random_d4(rng) };
    let inst = qlab_air::l2r::build_shape_r_with_witnesses(
        qlab_l2::LOG_HEIGHT_R,
        fee_input,
        &witness_of(&tree, fee_input)?,
        anchor,
        &out,
        fee,
        &write,
        &seed,
    );
    if inst.old_root != slot.root {
        return Err(SpendError::RegistryMoved);
    }
    let (_, proof) = qlab_l2::prove_r(&inst);
    // R's output takes the input's nullifier as its ρ (option 4, `ρ′₀ = nf₀`).
    let note = L2Note { value: out.value, asset: 0, rkm: out.rkm, rho: inst.nf, rseed: out.rseed };
    assert_eq!(note.commitment(), inst.cm_out, "the change note is the one the proof commits");
    // The seed's ρ is shape S's output-1 derivation over the nullifier.
    let seed_note = L2Note {
        value: 0,
        asset: new_leaf.asset,
        rkm: seed.rkm,
        rho: qlab_air::narrow::derive_output_rho(&inst.nf, 1),
        rseed: seed.rseed,
    };
    assert_eq!(seed_note.commitment(), inst.cm_seed, "the seed note is the one the proof commits");
    let mut bundles = Vec::new();
    let mut payloads = Vec::new();
    for n in [&note, &seed_note] {
        let enc = qlab_note::scan::encrypt_notes_to_recipient(&change.ek, std::slice::from_ref(n), rng);
        bundles.push(enc.bundle);
        payloads.extend(enc.payloads);
    }
    let discovery = qlab_note::compact::encode_committed_discovery_with_width(&bundles, &payloads, L2_PAYLOAD_LEN);
    let new_root = digest_bytes(&inst.new_root);
    let surface = L2Surface {
        shape: L2ShapeTag::R,
        registry_root: digest_bytes(&inst.old_root),
        vpublic: None,
        write: Some(qlab_devnet::annulet::RegistryWriteSurface {
            new_root,
            leaf_lanes: new_leaf.state()[..15].try_into().expect("15 lanes"),
        }),
        exit_rkm: [0; 32],
    };
    let tx = TxEntry {
        proof: bincode::serialize(&proof).expect("a proof serializes"),
        public: TxPublic {
            anchor: digest_bytes(&anchor),
            nullifiers: vec![digest_bytes(&inst.nf)],
            commitments: vec![digest_bytes(&inst.cm_out), digest_bytes(&inst.cm_seed)],
            bucket: ArityBucket::TwoByTwo,
            fee,
        },
        discovery,
        rider: qlab_devnet::names::RIDER_ABSENT.to_vec(),
        l2: surface.encode(),
    };
    Ok(BuiltR { tx, output: note, seed: seed_note, new_root })
}

/// **A shape-P transfer** (vPublic = 0) of two real inputs — a policy-asset
/// note and an asset-0 fee note, typically — with each input's policy built
/// by [`policy_for_transfer`] from the served opening. Proves (≈ 15 GB).
pub fn build_p<E: Endpoint, R: rand::CryptoRng>(
    served: &Served<E>,
    inputs: [&L2TxInput; 2],
    outs: &[Out; 2],
    fee: u64,
    rng: &mut R,
) -> Result<Built, SpendError> {
    build_p_with(served, inputs, outs, fee, [&PolicyContext::default(), &PolicyContext::default()], [VPublic::NONE; 2], rng)
}

/// **A shape-P spend with issuance** (lab #722): each input's policy from
/// its [`PolicyContext`], and a `vPublic` per row — `VPublic::mint(v)` /
/// `VPublic::redeem(v)` on the row of the asset being issued or burned (the
/// issuer's `isk` in that row's context unless the asset is `redeem_open`).
#[allow(clippy::too_many_arguments)]
pub fn build_p_with<E: Endpoint, R: rand::CryptoRng>(
    served: &Served<E>,
    inputs: [&L2TxInput; 2],
    outs: &[Out; 2],
    fee: u64,
    ctx: [&PolicyContext; 2],
    vp: [VPublic; 2],
    rng: &mut R,
) -> Result<Built, SpendError> {
    build_p_slot(served, inputs, outs, fee, ctx, vp, None, rng)
}

/// **A4's merge on shape P** (`d3 = 0`, vPublic = 0): two real inputs — two
/// notes of one policy asset, typically, each with its own policy context —
/// and `fee_note`, an asset-0 note worth exactly `fee`, in slot 3.
pub fn build_p_merge<E: Endpoint, R: rand::CryptoRng>(
    served: &Served<E>,
    inputs: [&L2TxInput; 2],
    outs: &[Out; 2],
    fee: u64,
    ctx: [&PolicyContext; 2],
    fee_note: &L2TxInput,
    rng: &mut R,
) -> Result<Built, SpendError> {
    build_p_slot(served, inputs, outs, fee, ctx, [VPublic::NONE; 2], Some(fee_note), rng)
}

#[allow(clippy::too_many_arguments)]
fn build_p_slot<E: Endpoint, R: rand::CryptoRng>(
    served: &Served<E>,
    inputs: [&L2TxInput; 2],
    outs: &[Out; 2],
    fee: u64,
    ctx: [&PolicyContext; 2],
    vp: [VPublic; 2],
    exact_fee: Option<&L2TxInput>,
    rng: &mut R,
) -> Result<Built, SpendError> {
    let tree = served.commitment_tree()?;
    let regs = [served.registry(inputs[0].asset)?, served.registry(inputs[1].asset)?];
    if regs[0].root != regs[1].root {
        return Err(SpendError::RegistryMoved);
    }
    let rkm = |i: &L2TxInput| qlab_air::l2p::derive_rkm_l2(i);
    let policy = [policy_input(&regs[0], &rkm(inputs[0]), ctx[0])?, policy_input(&regs[1], &rkm(inputs[1]), ctx[1])?];
    let fee_slot = fee_slot_for(&tree, exact_fee, fee, rng)?;
    prove_p_slot(&tree, inputs, outs, fee, policy, regs[0].root, vp, &fee_slot, rng)
}

/// **The P assembly below the policy check** (lab #722): prove against the
/// given policy inputs and `registry_root` as they are. The wallet never calls
/// this directly — [`build_p_with`] builds the policies from served data and
/// refuses what it cannot open. It exists so a test can hand-forge a spend
/// (a stale leaf, a frozen key) and show that the NODE refuses it.
#[allow(clippy::too_many_arguments)]
pub fn prove_p_with_policies<R: rand::CryptoRng>(
    tree: &CommitmentTree,
    inputs: [&L2TxInput; 2],
    outs: &[Out; 2],
    fee: u64,
    policy: [L2PolicyInput; 2],
    registry_root: [u64; 4],
    vp: [VPublic; 2],
    rng: &mut R,
) -> Result<Built, SpendError> {
    let fee_slot = dummy_fee_slot(rng);
    prove_p_slot(tree, inputs, outs, fee, policy, registry_root, vp, &fee_slot, rng)
}

#[allow(clippy::too_many_arguments)]
fn prove_p_slot<R: rand::CryptoRng>(
    tree: &CommitmentTree,
    inputs: [&L2TxInput; 2],
    outs: &[Out; 2],
    fee: u64,
    policy: [L2PolicyInput; 2],
    registry_root: [u64; 4],
    vp: [VPublic; 2],
    fee_slot: &qlab_air::l2::FeeSlot,
    rng: &mut R,
) -> Result<Built, SpendError> {
    let anchor = tree.root();
    let outputs = l2_outputs(outs, rng);
    let inst = qlab_air::l2p::build_bucket_l2p_with_witnesses(
        qlab_l2::LOG_HEIGHT_P,
        &[inputs[0].clone(), inputs[1].clone()],
        &outputs,
        fee,
        &[witness_of(tree, inputs[0])?, witness_of(tree, inputs[1])?],
        anchor,
        &policy,
        registry_root,
        vp,
        fee_slot,
    );
    let (_, proof) = qlab_l2::prove_p(&inst);
    let notes = output_notes(&outputs, &inst.nf[0], &inst.cm_out);
    let discovery = discovery_for(&notes, outs, rng);
    let term = |k: usize| {
        if vp[k].amount == 0 {
            VPublicTerm::NONE
        } else {
            VPublicTerm { redeem: vp[k].redeem, amount: vp[k].amount, asset: inputs[k].asset as u16 }
        }
    };
    let surface =
        L2Surface { shape: L2ShapeTag::P, registry_root: digest_bytes(&registry_root), vpublic: Some([term(0), term(1)]), write: None, exit_rkm: [0; 32] };
    Ok(Built { tx: entry(&proof, &anchor, &inst.nf, &inst.nf3, &inst.cm_out, fee, surface, discovery), outputs: notes, shape: L2ShapeTag::P })
}

// ---------------------------------------------------------------------------
// Lab #831 W2: the exit — shape P's asset-0 redeem edge (lab #785 F5-4d)
// ---------------------------------------------------------------------------

/// What an exit asks: `value` of asset 0 redeemed on L2 and paid on L1, by
/// the bundle that carries it, as a bridge-coinbase note to `to_rkm`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExitAsk {
    pub value: u64,
    /// The L1 recipient's `rkm` — any address's, the spender's or another's.
    pub to_rkm: [u64; 4],
}

/// Why an exit cannot be assembled — by name, before anything is proved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitError {
    /// Only asset 0 exits: the edge is an asset-0 redeem.
    NotAssetZero { asset: u64 },
    /// An exit of nothing is not an exit (the edge needs `amount ≠ 0`).
    ZeroValue,
    /// The circuit's recipient must be nonzero on an exit.
    ZeroRecipient,
    /// The note cannot pay the fee and the exit from one row.
    AboveNote { note: u64, fee: u64, exit: u64 },
    /// The served registry has no asset-0 leaf to open.
    Spend(SpendError),
}

impl std::fmt::Display for ExitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExitError::NotAssetZero { asset } => {
                write!(f, "only asset 0 exits to L1 (the exit is an asset-0 redeem); this note is asset {asset}")
            }
            ExitError::ZeroValue => write!(f, "an exit of 0 is not an exit"),
            ExitError::ZeroRecipient => write!(f, "the exit recipient's rkm is zero, which the circuit refuses"),
            ExitError::AboveNote { note, fee, exit } => write!(
                f,
                "the asset-0 note holds {note}, less than the exit {exit} plus the fee {fee} it pays from the \
                 same row"
            ),
            ExitError::Spend(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ExitError {}

impl From<SpendError> for ExitError {
    fn from(e: SpendError) -> Self {
        ExitError::Spend(e)
    }
}

/// An exit's circuit instance and its two outputs, before any proof.
pub struct ExitInstance {
    pub inst: qlab_air::l2p::L2PBucketInstance,
    pub outputs: [L2TxOutput; 2],
    pub ask: ExitAsk,
}

/// **The exit's instance** — pure, no endpoint, no prove: the one assembly
/// the wallet proves ([`build_p_exit`]) and the lane hands to a wrapper as a
/// member (`qlab-bench`'s f5box tests). Shape P, one real asset-0 input on
/// row 0 redeemed by `ask.value` to `ask.to_rkm`; row 1 the #219 dummy
/// (`dv`); slot 3 a dummy fee input (`d3 = 1`), so the fee comes from row 0
/// and `change = note − fee − exit` returns to `change_rkm` beside a 0 note.
/// The asset-0 leaf is opened from `reg0`, which must be at `tree`'s state.
pub fn exit_instance<R: Rng>(
    tree: &CommitmentTree,
    reg0: &RegistryOpening,
    input: &L2TxInput,
    ask: ExitAsk,
    change_rkm: [u64; 4],
    fee: u64,
    rng: &mut R,
) -> Result<ExitInstance, ExitError> {
    if input.asset != 0 {
        return Err(ExitError::NotAssetZero { asset: input.asset });
    }
    if ask.value == 0 {
        return Err(ExitError::ZeroValue);
    }
    if ask.to_rkm == [0; 4] {
        return Err(ExitError::ZeroRecipient);
    }
    let change = input
        .value
        .checked_sub(fee)
        .and_then(|v| v.checked_sub(ask.value))
        .ok_or(ExitError::AboveNote { note: input.value, fee, exit: ask.value })?;
    if reg0.leaf.asset != 0 {
        return Err(SpendError::Served(format!("the asset-0 opening is of asset {}", reg0.leaf.asset)).into());
    }
    // #219's second slot: value 0, asset 0, fresh keys so its nullifier
    // never repeats, off the tree (`dv` relaxes its anchor).
    let dummy = L2TxInput { sk: random_d4(rng), value: 0, asset: 0, rho: random_d4(rng), rseed: random_d4(rng), d: [0, 0] };
    let rkm = |i: &L2TxInput| qlab_air::l2p::derive_rkm_l2(i);
    let policy = [policy_for_transfer(reg0, &rkm(input))?, policy_for_transfer(reg0, &rkm(&dummy))?];
    let outputs: [L2TxOutput; 2] = core::array::from_fn(|j| L2TxOutput {
        value: if j == 0 { change } else { 0 },
        asset: 0,
        rkm: change_rkm,
        rho: [0; 4],
        rseed: random_d4(rng),
    });
    let mut inst = qlab_air::l2p::build_bucket_l2p_exit_with_witnesses(
        qlab_l2::LOG_HEIGHT_P,
        &[input.clone(), dummy],
        &outputs,
        fee,
        &[witness_of(tree, input)?, qlab_air::narrow::off_tree_witness()],
        tree.root(),
        &policy,
        reg0.root,
        [VPublic::redeem(ask.value), VPublic::NONE],
        &dummy_fee_slot(rng),
        ask.to_rkm,
    );
    inst.air.dv = true;
    Ok(ExitInstance { inst, outputs, ask })
}

/// The exit's transaction entry from its instance and its proof: the outputs
/// (both to `change_to`) with their discovery, the P surface carrying the
/// redeem term and the recipient (`exit_rkm` = the proof's `PV_XRKM`).
pub fn exit_entry<R: rand::CryptoRng>(
    ei: &ExitInstance,
    proof: &qlab_l2::Proof<qlab_l2::Config>,
    fee: u64,
    change_to: &Recipient,
    rng: &mut R,
) -> Built {
    let inst = &ei.inst;
    let notes = output_notes(&ei.outputs, &inst.nf[0], &inst.cm_out);
    let outs = [Out { to: change_to.clone(), value: notes[0].value, asset: 0 }, Out { to: change_to.clone(), value: 0, asset: 0 }];
    let discovery = discovery_for(&notes, &outs, rng);
    let surface = L2Surface {
        shape: L2ShapeTag::P,
        registry_root: digest_bytes(&inst.registry_root),
        vpublic: Some([VPublicTerm { redeem: true, amount: ei.ask.value, asset: 0 }, VPublicTerm::NONE]),
        write: None,
        exit_rkm: digest_bytes(&ei.ask.to_rkm),
    };
    Built { tx: entry(proof, &inst.anchor, &inst.nf, &inst.nf3, &inst.cm_out, fee, surface, discovery), outputs: notes, shape: L2ShapeTag::P }
}

/// **An exit, proved** (P on the hiding lane: the 32 GiB class — 30.04 GiB
/// peak measured at F5-4d-3). Reads the commitment tree and the asset-0
/// opening from `served`; never submits: an Annulet net refuses an exit by
/// name (`check_l2_no_exit`), and only a V6 bundle carries one.
pub fn build_p_exit<E: Endpoint, R: rand::CryptoRng>(
    served: &Served<E>,
    input: &L2TxInput,
    ask: ExitAsk,
    change_to: &Recipient,
    fee: u64,
    rng: &mut R,
) -> Result<Built, ExitError> {
    let tree = served.commitment_tree()?;
    let reg0 = served.registry(0)?;
    let ei = exit_instance(&tree, &reg0, input, ask, change_to.rkm, fee, rng)?;
    Ok(prove_exit(&ei, fee, change_to, rng))
}

/// Prove an exit instance (the P lane, ≈ 30 GiB) and assemble its entry —
/// [`build_p_exit`]'s last step, for a caller that built the instance
/// against a tree and opening it checked itself (lab #860 R3).
pub fn prove_exit<R: rand::CryptoRng>(ei: &ExitInstance, fee: u64, change_to: &Recipient, rng: &mut R) -> Built {
    let (_, proof) = qlab_l2::prove_p(&ei.inst);
    exit_entry(ei, &proof, fee, change_to, rng)
}

/// The `--out` file's leading bytes: what it is, then its version.
pub const EXIT_ARTIFACT_MAGIC: &[u8; 15] = b"qumbra:l2-exit\0";
/// The version this build writes and the only one it reads.
pub const EXIT_ARTIFACT_VERSION: u8 = 1;

/// Why an exit file is refused — by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactError {
    NotAnExitFile,
    /// The magic, and then the file ends before its header does.
    Truncated,
    Version { found: u8, expected: u8 },
    /// Built against another chain: its genesis is not the one expected.
    OtherChain { file: [u8; 32], expected: [u8; 32] },
    Tx(String),
    /// The transaction decodes but is not one exit: not shape P, no asset-0
    /// redeem, a zero recipient, or more than one exiting row.
    NotAnExit(&'static str),
}

impl std::fmt::Display for ArtifactError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArtifactError::NotAnExitFile => write!(f, "not an L2 exit file (the magic does not match)"),
            ArtifactError::Truncated => write!(f, "the exit file ends inside its header (version byte and genesis hash)"),
            ArtifactError::OtherChain { file, expected } => write!(
                f,
                "the exit file was built on the chain with genesis {}, not this one ({}) — refusing it",
                file.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                expected.iter().map(|b| format!("{b:02x}")).collect::<String>()
            ),
            ArtifactError::Version { found, expected } => write!(
                f,
                "exit file version {found}; this build reads only version {expected} — rebuild the exit with \
                 a matching wallet"
            ),
            ArtifactError::Tx(e) => write!(f, "the exit file's transaction does not decode: {e}"),
            ArtifactError::NotAnExit(why) => write!(f, "the exit file's transaction is not an exit: {why}"),
        }
    }
}

impl std::error::Error for ArtifactError {}

/// The `--out` file: magic ‖ version ‖ the genesis hash of the chain it was
/// built on (32) ‖ the Annulet transaction wire. The genesis binds the file to
/// one chain: a reader names the genesis it expects and refuses any other.
pub fn encode_exit_artifact(genesis_hash: &[u8; 32], tx: &TxEntry) -> Vec<u8> {
    let mut out = EXIT_ARTIFACT_MAGIC.to_vec();
    out.push(EXIT_ARTIFACT_VERSION);
    out.extend_from_slice(genesis_hash);
    out.extend_from_slice(&qlab_p2p::codec::encode_tx_annulet(tx));
    out
}

/// Read an exit file back — the magic, the version (refused by name on a
/// mismatch), the chain (`expected_genesis`, refused by name when it is not
/// the file's), the transaction, and that it is exactly the one exit
/// [`exit_entry`] writes.
pub fn decode_exit_artifact(bytes: &[u8], expected_genesis: &[u8; 32]) -> Result<(TxEntry, L2Surface), ArtifactError> {
    let rest = bytes.strip_prefix(EXIT_ARTIFACT_MAGIC.as_slice()).ok_or(ArtifactError::NotAnExitFile)?;
    let (&version, rest) = rest.split_first().ok_or(ArtifactError::Truncated)?;
    if version != EXIT_ARTIFACT_VERSION {
        return Err(ArtifactError::Version { found: version, expected: EXIT_ARTIFACT_VERSION });
    }
    if rest.len() < 32 {
        return Err(ArtifactError::Truncated);
    }
    let (genesis, wire) = rest.split_at(32);
    let genesis: [u8; 32] = genesis.try_into().expect("32 bytes");
    if &genesis != expected_genesis {
        return Err(ArtifactError::OtherChain { file: genesis, expected: *expected_genesis });
    }
    let tx = qlab_p2p::codec::decode_tx_annulet(wire).map_err(|e| ArtifactError::Tx(format!("{e:?}")))?;
    let surface = match L2Surface::decode(&tx.l2) {
        Ok(Some(s)) => s,
        _ => return Err(ArtifactError::NotAnExit("no L2 surface")),
    };
    let Some(terms) = surface.vpublic.filter(|_| surface.shape == L2ShapeTag::P) else {
        return Err(ArtifactError::NotAnExit("not shape P"));
    };
    // Exactly what `exit_entry` writes: row 0 the asset-0 redeem, row 1 no
    // term, no registry write — `[redeem, redeem]` or `[redeem, mint]` is not
    // "an exit".
    if !(terms[0].redeem && terms[0].asset == 0 && terms[0].amount > 0) {
        return Err(ArtifactError::NotAnExit("row 0 is not an asset-0 redeem"));
    }
    if terms[1] != VPublicTerm::NONE {
        return Err(ArtifactError::NotAnExit("row 1 carries a vPublic term"));
    }
    if surface.write.is_some() {
        return Err(ArtifactError::NotAnExit("it carries a registry write"));
    }
    if surface.exit_rkm == [0; 32] {
        return Err(ArtifactError::NotAnExit("a zero recipient"));
    }
    if tx.public.nullifiers.len() != 3 || tx.public.commitments.len() != 2 {
        return Err(ArtifactError::NotAnExit("not a 3×2 transaction"));
    }
    Ok((tx, surface))
}

fn words(h: &[u8; 32]) -> [u64; 4] {
    core::array::from_fn(|i| u64::from_le_bytes(h[i * 8..i * 8 + 8].try_into().expect("8 bytes")))
}

/// **The P public values a decoded exit declares** — what a wrapper threads
/// as the member and what its proof is verified against: the node's own
/// surface-to-PV mapping (`qumbra-node`'s `L2Verifier`, `pv_vec_p`) over the
/// file's transaction.
pub fn exit_member_pvs(tx: &TxEntry, surface: &L2Surface) -> Vec<u32> {
    let p = &tx.public;
    let terms = surface.vpublic.expect("a decoded exit is shape P");
    qlab_l2::pv_vec_p(
        &words(&p.anchor),
        &words(&p.nullifiers[0]),
        &words(&p.nullifiers[1]),
        &words(&p.commitments[0]),
        &words(&p.commitments[1]),
        p.fee,
        &words(&surface.registry_root),
        &terms.map(|t| VPublic { redeem: t.redeem, amount: t.amount }),
        &terms.map(|t| u64::from(t.asset)),
        &words(&p.nullifiers[2]),
        &words(&surface.exit_rkm),
    )
}

// ---------------------------------------------------------------------------
// Lab #831 W3b: the deposit claim (L1 burn → L2 credit)
// ---------------------------------------------------------------------------

/// Why a claim cannot be assembled — by name, before anything is proved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimError {
    /// The opening does not pay `rkm_burn(l2_id)`.
    NotABurn { l2_id: u64 },
    /// The burn's rebuilt L1 commitment is no leaf of the tree.
    NotInTree,
    /// The burn's leaf is at or past the anchor: the anchor does not cover it.
    AboveAnchor { pos: u64, anchor_count: u64 },
    /// The anchor counts more leaves than the tree holds.
    AnchorPastTree { anchor_count: u64, len: u64 },
    /// The burn is worth no more than the claim fee: the credit would be 0 —
    /// a note nobody can spend, for a wasted prove.
    BelowFee { value: u64, fee: u64 },
}

impl std::fmt::Display for ClaimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClaimError::NotABurn { l2_id } => write!(f, "the note does not pay L2 {l2_id}'s burn address"),
            ClaimError::NotInTree => write!(f, "the burn's commitment is not in the L1 commitment tree"),
            ClaimError::AboveAnchor { pos, anchor_count } => write!(
                f,
                "the burn's leaf {pos} is not under the anchor (which covers {anchor_count} leaves): pick a later anchor"
            ),
            ClaimError::AnchorPastTree { anchor_count, len } => {
                write!(f, "the anchor covers {anchor_count} leaves and the tree holds {len}")
            }
            ClaimError::BelowFee { value, fee } => write!(
                f,
                "the burn holds {value}, no more than the claim fee {fee}: nothing would be credited"
            ),
        }
    }
}

impl std::error::Error for ClaimError {}

/// **A deposit claim's instance** — pure, no endpoint, no prove: the one
/// assembly the wallet proves (`deposit claim`) and the lane hands to a
/// wrapper as a member (`qlab-bench`'s f5box tests). The burn note
/// `note` opens at leaf `pos` of the L1 `tree` under the root that counts
/// `anchor_count` leaves; the claim credits `v − fee` (asset 0, ρ = `cnf`) to
/// `credit`, with the value committed under `r_v`.
///
/// The anchor is the caller's choice and the proof binds it (`PV_A`); a
/// wrapper takes the claim only if it has absorbed that root. With the
/// blinds derived from the wallet and the burn alone
/// (`qlab_wallet::Wallet::claim_blinds`), a claim bound to a root no wrapper
/// absorbs costs a re-prove at another anchor, never a lost deposit.
pub fn claim_instance(
    tree: &CommitmentTree,
    anchor_count: u64,
    note: &qlab_air::claim::BurnNote,
    l2_id: u64,
    r_v: &[u64; 4],
    credit: &qlab_air::claim::ClaimCredit,
    fee: u64,
) -> Result<qlab_air::claim::ClaimInstance, ClaimError> {
    let burn = qlab_air::claim::rkm_burn(l2_id);
    if note.rkm != burn {
        return Err(ClaimError::NotABurn { l2_id });
    }
    if note.value <= fee {
        return Err(ClaimError::BelowFee { value: note.value, fee });
    }
    if anchor_count > tree.len() {
        return Err(ClaimError::AnchorPastTree { anchor_count, len: tree.len() });
    }
    let cm = qlab_air::claim::l1_cm(note.value, &note.rkm, &note.rho, &note.rseed);
    let pos = tree.position_of(&cm).ok_or(ClaimError::NotInTree)?;
    if pos >= anchor_count {
        return Err(ClaimError::AboveAnchor { pos, anchor_count });
    }
    Ok(qlab_air::claim::build_claim_with_witness(
        qlab_l2::claim::LOG_HEIGHT_CLAIM,
        &burn,
        note,
        &tree.auth_path(pos, anchor_count),
        tree.root_at(anchor_count),
        r_v,
        credit,
        fee,
    ))
}

/// **A claim, proved** — the hiding claim lane, ≈ 3.17 GiB / ≈ 10 s
/// measured (l2-architecture §4.1's build update): laptop-class, local only.
pub fn prove_claim(inst: &qlab_air::claim::ClaimInstance) -> qlab_l2::Proof<qlab_l2::Config> {
    qlab_l2::claim::prove_claim(inst).1
}

/// The claim file's leading bytes, and the only version this build writes and reads.
pub const CLAIM_ARTIFACT_MAGIC: &[u8; 16] = b"qumbra:l2-claim\0";
pub const CLAIM_ARTIFACT_VERSION: u8 = 1;

/// A claim file's contents, as read back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimFile {
    pub l2_id: u64,
    /// The claim's public values, `u32` words (the member a wrapper threads).
    pub pvs: Vec<u32>,
    /// The proof, as `bincode` bytes.
    pub proof: Vec<u8>,
    /// The deposit-sum proof's opening for this claim: the burned value and
    /// its commitment blind. **Private to the sequencer** — this is what
    /// reveals the amount.
    pub value: u64,
    pub r_v: [u64; 4],
}

/// Why a claim file is refused — by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimFileError {
    NotAClaimFile,
    Truncated,
    Version { found: u8, expected: u8 },
    OtherChain { file: [u8; 32], expected: [u8; 32] },
    /// The claim was built at another fee tier than the chain serves.
    OtherTier { file: u64, expected: u64 },
    /// The claim's published burn address is not its L2's.
    OtherL2 { l2_id: u64 },
    Malformed(&'static str),
}

impl std::fmt::Display for ClaimFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = |b: &[u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        match self {
            ClaimFileError::NotAClaimFile => write!(f, "not an L2 claim file (the magic does not match)"),
            ClaimFileError::Truncated => write!(f, "the claim file ends early"),
            ClaimFileError::Version { found, expected } => {
                write!(f, "claim file version {found}; this build reads only version {expected}")
            }
            ClaimFileError::OtherChain { file, expected } => write!(
                f,
                "the claim file was built on the chain with genesis {}, not this one ({}) — refusing it",
                hex(file),
                hex(expected)
            ),
            ClaimFileError::OtherTier { file, expected } => write!(
                f,
                "the claim was built at fee tier {file} and this chain's claim tier is {expected}: rebuild it at the \
                 chain's tier"
            ),
            ClaimFileError::OtherL2 { l2_id } => write!(f, "the claim does not publish L2 {l2_id}'s burn address"),
            ClaimFileError::Malformed(why) => write!(f, "the claim file is malformed: {why}"),
        }
    }
}

impl std::error::Error for ClaimFileError {}

fn pv_word(pvs: &[u32], base: usize, limbs: usize) -> u64 {
    (0..limbs).map(|j| u64::from(pvs[base + j] & 0xffff) << (16 * j)).sum()
}

/// The fee a claim's public values state (`PV_FEE`, four 16-bit limbs).
pub fn claim_fee_of(pvs: &[u32]) -> u64 {
    pv_word(pvs, qlab_air::claim::PV_FEE, 4)
}

/// The claim file: magic ‖ version ‖ genesis (32) ‖ l2_id (u64 LE) ‖ PV count
/// (u32 LE) ‖ PVs (u32 LE each) ‖ proof length (u32 LE) ‖ proof ‖ value (u64
/// LE) ‖ r_v (four u64 LE). The genesis binds it to one chain; the PVs carry
/// the fee tier it was built at.
pub fn encode_claim_artifact(
    genesis_hash: &[u8; 32],
    l2_id: u64,
    pvs: &[u32],
    proof: &qlab_l2::Proof<qlab_l2::Config>,
    value: u64,
    r_v: &[u64; 4],
) -> Vec<u8> {
    let proof = bincode::serialize(proof).expect("a proof serializes");
    let mut out = CLAIM_ARTIFACT_MAGIC.to_vec();
    out.push(CLAIM_ARTIFACT_VERSION);
    out.extend_from_slice(genesis_hash);
    out.extend_from_slice(&l2_id.to_le_bytes());
    out.extend_from_slice(&u32::try_from(pvs.len()).expect("a claim's PVs").to_le_bytes());
    for w in pvs {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out.extend_from_slice(&u32::try_from(proof.len()).expect("a proof under 4 GiB").to_le_bytes());
    out.extend_from_slice(&proof);
    out.extend_from_slice(&value.to_le_bytes());
    out.extend_from_slice(&digest_bytes(r_v));
    out
}

/// Read a claim file back, refusing by name: the magic, the version, the
/// chain (`expected_genesis`), the layout, the PV count, that the claim
/// publishes its own L2's burn address, and that it was built at the chain's
/// claim tier (`expected_tier`, the `/v1/l2` value).
///
/// The file's `l2_id` is checked against its own `PV_RKM_BURN`, not against
/// the chain's: the genesis binds the chain's WrapperParams and so its one
/// `l2_id`, which makes [`ClaimFileError::OtherChain`] the check that covers
/// a file of another L2.
pub fn decode_claim_artifact(bytes: &[u8], expected_genesis: &[u8; 32], expected_tier: u64) -> Result<ClaimFile, ClaimFileError> {
    let rest = bytes.strip_prefix(CLAIM_ARTIFACT_MAGIC.as_slice()).ok_or(ClaimFileError::NotAClaimFile)?;
    let mut r = rest;
    let mut take = |n: usize| -> Result<&[u8], ClaimFileError> {
        if r.len() < n {
            return Err(ClaimFileError::Truncated);
        }
        let (h, t) = r.split_at(n);
        r = t;
        Ok(h)
    };
    let version = take(1)?[0];
    if version != CLAIM_ARTIFACT_VERSION {
        return Err(ClaimFileError::Version { found: version, expected: CLAIM_ARTIFACT_VERSION });
    }
    let genesis: [u8; 32] = take(32)?.try_into().expect("32 bytes");
    if &genesis != expected_genesis {
        return Err(ClaimFileError::OtherChain { file: genesis, expected: *expected_genesis });
    }
    let l2_id = u64::from_le_bytes(take(8)?.try_into().expect("8 bytes"));
    let n = u32::from_le_bytes(take(4)?.try_into().expect("4 bytes")) as usize;
    if n != qlab_air::claim::PV_LEN {
        return Err(ClaimFileError::Malformed("not a claim's PV count"));
    }
    let pvs: Vec<u32> = take(4 * n)?.chunks(4).map(|c| u32::from_le_bytes(c.try_into().expect("4 bytes"))).collect();
    let plen = u32::from_le_bytes(take(4)?.try_into().expect("4 bytes")) as usize;
    let proof = take(plen)?.to_vec();
    let value = u64::from_le_bytes(take(8)?.try_into().expect("8 bytes"));
    let r_v = qlab_note::hash::digest_from_bytes(&take(32)?.try_into().expect("32 bytes"));
    if !r.is_empty() {
        return Err(ClaimFileError::Malformed("bytes after r_v"));
    }
    let burn = qlab_air::narrow::pv_chunks(&qlab_air::claim::rkm_burn(l2_id));
    if pvs[qlab_air::claim::PV_RKM_BURN..qlab_air::claim::PV_RKM_BURN + 16] != burn[..] {
        return Err(ClaimFileError::OtherL2 { l2_id });
    }
    if pvs[qlab_air::claim::PV_FEE..qlab_air::claim::PV_FEE + 4].iter().any(|w| *w >= 1 << 16) {
        return Err(ClaimFileError::Malformed("a fee limb is not 16-bit"));
    }
    let fee = claim_fee_of(&pvs);
    if fee != expected_tier {
        return Err(ClaimFileError::OtherTier { file: fee, expected: expected_tier });
    }
    Ok(ClaimFile { l2_id, pvs, proof, value, r_v })
}

#[cfg(test)]
mod tests {

    /// `commitment_tree_at(n)` stops at `n` leaves across pages, even when
    /// more are served, and refuses by name when fewer are.
    #[test]
    fn the_tree_at_a_count_truncates_and_refuses_a_short_serve() {
        struct Leaves(Vec<[u8; 32]>);
        impl Endpoint for Leaves {
            fn get(&self, path: &str) -> Result<Vec<u8>, String> {
                let from: u64 = path.rsplit_once("from=").ok_or("no from")?.1.parse().map_err(|_| "from")?;
                // Two leaves a page, to cross a page boundary.
                let start = (from as usize).min(self.0.len());
                let end = (start + 2).min(self.0.len());
                let page = qlab_node::TreeLeaves { from, total: self.0.len() as u64, leaves: self.0[start..end].to_vec() };
                Ok(page.to_bytes())
            }
            fn post(&self, _: &str, _: &[u8]) -> Result<(u16, Vec<u8>), String> {
                Err("no".into())
            }
        }
        let leaves: Vec<[u8; 32]> = (1..=5u8).map(|k| [k; 32]).collect();
        let v6 = Served::v6(Leaves(leaves.clone()));
        let mut want = CommitmentTree::new();
        for l in &leaves[..3] {
            want.append_bytes(l);
        }
        let got = v6.commitment_tree_at(3).unwrap();
        assert_eq!((got.len(), got.root()), (3, want.root()), "three of five, across a page boundary");
        assert_eq!(v6.commitment_tree().unwrap().len(), 5);
        assert!(matches!(v6.commitment_tree_at(6), Err(SpendError::Served(ref why)) if why.contains("fewer than the 6")));
    }

    /// Lab #860 R3: `Served::v6` reads the index's routes under `/v1/l2`
    /// (leaves, nullifiers, the registry opening), `Served::new` the Annulet
    /// paths unchanged, and under `v6` every Annulet-only route is refused by
    /// name without a fetch.
    #[test]
    fn served_v6_reads_under_the_l2_prefix_and_refuses_annulet_routes() {
        use std::cell::RefCell;
        struct Rec(RefCell<Vec<String>>);
        impl Endpoint for &Rec {
            fn get(&self, path: &str) -> Result<Vec<u8>, String> {
                self.0.borrow_mut().push(path.to_string());
                Err("recorded".into())
            }
            fn post(&self, path: &str, _: &[u8]) -> Result<(u16, Vec<u8>), String> {
                self.0.borrow_mut().push(format!("POST {path}"));
                Err("recorded".into())
            }
        }
        let rec = Rec(RefCell::new(Vec::new()));
        let v6 = Served::v6(&rec);
        let _ = v6.commitment_tree();
        let _ = v6.commitment_tree_at(5);
        let _ = v6.spent_nullifiers();
        let _ = v6.registry(0);
        assert_eq!(
            *rec.0.borrow(),
            ["/v1/l2/tree/leaves?from=0", "/v1/l2/tree/leaves?from=0", &format!("/v1/l2/nullifiers?from=0&to={}", u64::MAX), "/v1/l2/registry/0"]
        );
        rec.0.borrow_mut().clear();
        let named = |e: Option<SpendError>| matches!(e, Some(SpendError::Served(ref why)) if why.contains("not served by a V6 node"));
        assert!(named(v6.registry_slot(1).err()), "registry slot");
        assert!(named(v6.params().err()), "params");
        assert!(named(v6.genesis_notes().err()), "genesis notes");
        let dk = qlab_note::kem::generate_keypair(&mut rand::rng()).dk;
        assert!(named(v6.detect(&dk, 0, 1).err()), "detection");
        let public = qlab_devnet::body::TxPublic {
            anchor: [0; 32],
            nullifiers: vec![],
            commitments: vec![],
            bucket: qlab_devnet::fees::ArityBucket::TwoByTwo,
            fee: 0,
        };
        let tx = TxEntry { proof: vec![], public, discovery: vec![0], rider: vec![], l2: vec![] };
        assert!(named(v6.submit(&tx).err()), "POST /v1/tx");
        assert!(rec.0.borrow().is_empty(), "an Annulet-only route is refused without a fetch");
        let annulet = Served::new(&rec);
        let _ = annulet.commitment_tree();
        let _ = annulet.registry(0);
        assert_eq!(*rec.0.borrow(), ["/v1/tree/leaves?from=0", "/v1/registry/0"], "the Annulet paths do not move");
    }
    use super::*;
    use qlab_air::l2::RegistryWitness;

    fn opening(leaf: RegistryLeaf) -> RegistryOpening {
        let witness = RegistryWitness {
            siblings: [[0; 4]; qlab_air::l2::REGISTRY_DEPTH],
            path_bits: [false; qlab_air::l2::REGISTRY_DEPTH],
        };
        RegistryOpening { height: 0, root: [0; 4], leaf, witness }
    }

    fn hybrid_leaf(asset: u64, frozen: &[[u64; 4]]) -> RegistryLeaf {
        RegistryLeaf {
            asset,
            issuer_key: qlab_air::l2p::issuer_key_of(&[7; 4]),
            mode: MODE_HYBRID,
            freeze_root: CanonicalFreezeTree::from_rkms(frozen).root,
            allow_root: [0; 4],
            flags: 0,
        }
    }

    /// Lab #720/#722: the policy is built from the served leaf plus the
    /// published list — and refused by name when the list is stale, when
    /// the holder is frozen, and for a Regulated asset without a witness.
    #[test]
    fn policy_inputs_are_built_from_the_published_list_and_refused_by_name() {
        let rkm = [9u64; 4];
        let empty = hybrid_leaf(1, &[]);
        let pol = policy_for_transfer(&opening(empty), &rkm).expect("an empty freeze tree needs no list");
        assert_eq!(pol.isk, [0; 4], "a transfer carries no issuer secret");
        assert_eq!(pol.leaf, empty, "the served leaf, as served");
        let frozen = hybrid_leaf(1, &[[1; 4]]);
        assert_eq!(policy_for_transfer(&opening(frozen), &rkm).err(), Some(SpendError::FreezeListStale { asset: 1 }));
        let list = PolicyContext { freeze_keys: vec![qlab_air::l2p::freeze_key_of(&[1; 4])], ..Default::default() };
        assert!(policy_input(&opening(frozen), &rkm, &list).is_ok(), "the published list rebuilds the root");
        assert_eq!(policy_input(&opening(frozen), &[1; 4], &list).err(), Some(SpendError::Frozen { asset: 1 }));
        let allow = qlab_air::l2p::CanonicalAllowTree::from_rkms(&[rkm]);
        let regulated = RegistryLeaf { mode: MODE_REGULATED, allow_root: allow.root, ..hybrid_leaf(2, &[]) };
        assert!(matches!(policy_for_transfer(&opening(regulated), &rkm), Err(SpendError::NeedsIssuerWitness { asset: 2, .. })));
        let with = PolicyContext { allow_witness: allow.witness_for(&qlab_air::l2p::cred_of(&rkm)), ..Default::default() };
        assert!(policy_input(&opening(regulated), &rkm, &with).is_ok());
        assert_eq!(policy_input(&opening(regulated), &[5; 4], &with).err(), Some(SpendError::NotAllowlisted { asset: 2 }));
        assert!(policy_for_transfer(&opening(RegistryLeaf::cloaked(0)), &rkm).is_ok());
        assert_eq!(shape_for(&RegistryLeaf::cloaked(0)), L2ShapeTag::S);
        assert_eq!(shape_for(&empty), L2ShapeTag::P);
    }

    /// Lab #831 W2: an exit is refused by name before any tree is read —
    /// a non-zero asset, a zero exit, a zero recipient, a note that cannot
    /// pay the exit and the fee — and the exit file refuses what is not one.
    #[test]
    fn an_exit_is_refused_by_name_before_anything_is_built() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(831);
        let tree = CommitmentTree::new();
        let reg0 = opening(RegistryLeaf::cloaked(0));
        let note = |value, asset| L2TxInput { sk: [1; 4], value, asset, rho: [2; 4], rseed: [3; 4], d: [0, 0] };
        let to = ExitAsk { value: 50, to_rkm: [7; 4] };
        let mut ex = |input: L2TxInput, ask: ExitAsk| exit_instance(&tree, &reg0, &input, ask, [9; 4], 10, &mut rng).err();
        assert_eq!(ex(note(100, 1), to), Some(ExitError::NotAssetZero { asset: 1 }));
        assert_eq!(ex(note(100, 0), ExitAsk { value: 0, ..to }), Some(ExitError::ZeroValue));
        assert_eq!(ex(note(100, 0), ExitAsk { to_rkm: [0; 4], ..to }), Some(ExitError::ZeroRecipient));
        assert_eq!(ex(note(59, 0), to), Some(ExitError::AboveNote { note: 59, fee: 10, exit: 50 }));
        let g = [0x6f; 32];
        assert_eq!(decode_exit_artifact(b"qumbra:l2-exit", &g).err(), Some(ArtifactError::NotAnExitFile));
        assert_eq!(decode_exit_artifact(b"not an exit file at all", &g).err(), Some(ArtifactError::NotAnExitFile));
        assert_eq!(decode_exit_artifact(EXIT_ARTIFACT_MAGIC, &g).err(), Some(ArtifactError::Truncated), "magic only");
        let mut v1 = EXIT_ARTIFACT_MAGIC.to_vec();
        v1.push(EXIT_ARTIFACT_VERSION);
        v1.extend_from_slice(&[0x6f; 31]);
        assert_eq!(decode_exit_artifact(&v1, &g).err(), Some(ArtifactError::Truncated), "a short genesis");
        let mut v0 = EXIT_ARTIFACT_MAGIC.to_vec();
        v0.push(0);
        assert_eq!(decode_exit_artifact(&v0, &g).err(), Some(ArtifactError::Version { found: 0, expected: EXIT_ARTIFACT_VERSION }));
    }

    /// Lab #831 W3b: a claim is refused by name before anything is proved —
    /// not a burn, below the fee, an anchor past the tree, a burn in no leaf,
    /// a burn above the anchor — and the claim file refuses what it is not.
    #[test]
    fn a_claim_is_refused_by_name_before_anything_is_built() {
        use qlab_air::claim::{l1_cm, rkm_burn, BurnNote, ClaimCredit};
        let credit = ClaimCredit { rkm: [3; 4], rseed: [4; 4] };
        let note = BurnNote { value: 100, rkm: rkm_burn(1), rho: [1; 4], rseed: [2; 4] };
        let mut tree = CommitmentTree::new();
        tree.append([9; 4]);
        let pos = tree.append(l1_cm(note.value, &note.rkm, &note.rho, &note.rseed));
        let claim = |n: &BurnNote, count: u64, fee: u64| claim_instance(&tree, count, n, 1, &[5; 4], &credit, fee).err();
        assert_eq!(claim(&BurnNote { rkm: rkm_burn(2), ..note }, 2, 4), Some(ClaimError::NotABurn { l2_id: 1 }));
        assert_eq!(claim(&note, 2, 101), Some(ClaimError::BelowFee { value: 100, fee: 101 }));
        assert_eq!(claim(&note, 2, 100), Some(ClaimError::BelowFee { value: 100, fee: 100 }), "a zero credit is refused");
        assert_eq!(claim(&note, 3, 4), Some(ClaimError::AnchorPastTree { anchor_count: 3, len: 2 }));
        assert_eq!(claim(&BurnNote { value: 99, ..note }, 2, 4), Some(ClaimError::NotInTree));
        assert_eq!(claim(&note, pos, 4), Some(ClaimError::AboveAnchor { pos, anchor_count: pos }));
        let g = [0x4f; 32];
        assert_eq!(decode_claim_artifact(b"qumbra:l2-claim", &g, 4).err(), Some(ClaimFileError::NotAClaimFile));
        assert_eq!(decode_claim_artifact(CLAIM_ARTIFACT_MAGIC, &g, 4).err(), Some(ClaimFileError::Truncated));
        let mut v2 = CLAIM_ARTIFACT_MAGIC.to_vec();
        v2.push(2);
        assert_eq!(decode_claim_artifact(&v2, &g, 4).err(), Some(ClaimFileError::Version { found: 2, expected: 1 }));
    }

    #[test]
    fn the_submit_verdict_reads_the_nodes_renderings() {
        assert!(submit_verdict(202, b"accepted ab").is_ok());
        assert!(submit_verdict(200, b"duplicate ab").is_ok());
        assert_eq!(submit_verdict(400, b"refused: x"), Err(SpendError::Refused("refused: x".into())));
    }
}
