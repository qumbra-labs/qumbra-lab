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
use qlab_cbserver::registry::{decode_genesis_notes, decode_registry_opening, RegistryOpening};
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
pub struct Served<E: Endpoint> {
    pub endpoint: E,
}

fn served<T>(r: Result<T, String>) -> Result<T, SpendError> {
    r.map_err(SpendError::Served)
}

impl<E: Endpoint> Served<E> {
    pub fn new(endpoint: E) -> Self {
        Self { endpoint }
    }

    /// The whole commitment tree, rebuilt in memory from the served leaves
    /// (nothing is cached: an L1 wallet's `tree-leaves.v1` is never touched).
    pub fn commitment_tree(&self) -> Result<CommitmentTree, SpendError> {
        let mut tree = CommitmentTree::new();
        loop {
            let body = served(self.endpoint.get(&format!("/v1/tree/leaves?from={}", tree.len())))?;
            let page = served(qlab_node::TreeLeaves::from_bytes(&body).map_err(|e| format!("tree leaves: {e:?}")))?;
            if page.leaves.is_empty() {
                return Ok(tree);
            }
            for leaf in &page.leaves {
                tree.append_bytes(leaf);
            }
            if tree.len() >= page.total {
                return Ok(tree);
            }
        }
    }

    /// The registry opening of `asset`, with the root it was computed against.
    pub fn registry(&self, asset: u64) -> Result<RegistryOpening, SpendError> {
        let body = served(self.endpoint.get(&format!("/v1/registry/{asset}")))?;
        served(decode_registry_opening(&body).map_err(|e| format!("registry {asset}: {e:?}")))
    }

    /// The genesis notes, opened, with the served genesis hash.
    pub fn genesis_notes(&self) -> Result<([u8; 32], Vec<L2Note>), SpendError> {
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
        let body = served(self.endpoint.get("/v1/annulet/params"))?;
        served(qlab_cbserver::registry::decode_annulet_params(&body).map_err(|e| format!("params: {e:?}")))
    }

    /// Every nullifier the chain has published (`/v1/nullifiers`, paged).
    pub fn spent_nullifiers(&self) -> Result<std::collections::HashSet<[u8; 32]>, SpendError> {
        let mut spent = std::collections::HashSet::new();
        let mut from = 0u64;
        loop {
            let body = served(self.endpoint.get(&format!("/v1/nullifiers?from={from}&to={}", u64::MAX)))?;
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

fn entry(
    proof: &qlab_l2::Proof<qlab_l2::Config>,
    anchor: &[u64; 4],
    nf: &[[u64; 4]; 2],
    cm_out: &[[u64; 4]; 2],
    fee: u64,
    surface: L2Surface,
    discovery: Vec<u8>,
) -> TxEntry {
    TxEntry {
        proof: bincode::serialize(proof).expect("a proof serializes"),
        public: TxPublic {
            anchor: digest_bytes(anchor),
            nullifiers: nf.iter().map(digest_bytes).collect(),
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
    assert!(matches!(inputs.len(), 1 | 2), "a 2×2 bucket takes one or two real inputs");
    let tree = served.commitment_tree()?;
    let anchor = tree.root();
    let outputs = l2_outputs(outs, rng);
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
        )
    };
    let (_, proof) = qlab_l2::prove_s(&inst);
    let notes = output_notes(&outputs, &inst.nf[0], &inst.cm_out);
    let discovery = discovery_for(&notes, outs, rng);
    let surface = L2Surface { shape: L2ShapeTag::S, registry_root: digest_bytes(&inst.registry_root), vpublic: None };
    Ok(Built { tx: entry(&proof, &anchor, &inst.nf, &inst.cm_out, fee, surface, discovery), outputs: notes, shape: L2ShapeTag::S })
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
    let tree = served.commitment_tree()?;
    let anchor = tree.root();
    let regs = [served.registry(inputs[0].asset)?, served.registry(inputs[1].asset)?];
    if regs[0].root != regs[1].root {
        return Err(SpendError::RegistryMoved);
    }
    let rkm = |i: &L2TxInput| qlab_air::l2p::derive_rkm_l2(i);
    let policy = [policy_input(&regs[0], &rkm(inputs[0]), ctx[0])?, policy_input(&regs[1], &rkm(inputs[1]), ctx[1])?];
    let outputs = l2_outputs(outs, rng);
    let inst = qlab_air::l2p::build_bucket_l2p_with_witnesses(
        qlab_l2::LOG_HEIGHT_P,
        &[inputs[0].clone(), inputs[1].clone()],
        &outputs,
        fee,
        &[witness_of(&tree, inputs[0])?, witness_of(&tree, inputs[1])?],
        anchor,
        &policy,
        regs[0].root,
        vp,
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
        L2Surface { shape: L2ShapeTag::P, registry_root: digest_bytes(&regs[0].root), vpublic: Some([term(0), term(1)]) };
    Ok(Built { tx: entry(&proof, &anchor, &inst.nf, &inst.cm_out, fee, surface, discovery), outputs: notes, shape: L2ShapeTag::P })
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn the_submit_verdict_reads_the_nodes_renderings() {
        assert!(submit_verdict(202, b"accepted ab").is_ok());
        assert!(submit_verdict(200, b"duplicate ab").is_ok());
        assert_eq!(submit_verdict(400, b"refused: x"), Err(SpendError::Refused("refused: x".into())));
    }
}
