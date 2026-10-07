//! The **lying-endpoint fixture** shared by the AD1 and AD2 tests (lab
//! #850): a real `MemChainStore` of sealed Annulet blocks served through
//! `qumbra_node::discovery_server`'s own `respond_*` cores, with one answer
//! mutated per [`Lie`]. Fixture-only — placeholder proofs, nothing proves.
#![allow(dead_code)]

use qlab_devnet::annulet::{
    body_commitment_annulet_for, AnnuletHeaderFields, L2ShapeTag, L2Surface, SequencerKey,
};
use qlab_devnet::body::{BlockBody, TxEntry, TxPublic};
use qlab_devnet::fees::ArityBucket;
use qlab_devnet::forms::{GenesisForm, L2AuthForm};
use qlab_devnet::header::BlockHeader;
use qlab_node::annulet_genesis::{h32, AnnuletGenesisFile, AnnuletParams, GenesisNoteRecord, RegistryLeafRecord};
use qlab_node::{ChainStore, MemChainStore, StoredBlock};
use qlab_note::l2note::{GenesisPlaintext, L2Note};
use qlab_note::scan::encrypt_notes_to_recipient;
use qlab_p2p::compact::WireForm;
use qlab_wallet::address::Address;
use qlab_wallet::seed::{MasterSeed, ENTROPY_LEN};
use qumbra_node::discovery_server::{
    respond, respond_body, respond_full, respond_headers, respond_nullifiers, DiscoveryView,
};
use qumbra_wallet::annulet_verify::{scan_annulet_verified, VerifyRefusal};
use qumbra_wallet::store::WalletDir;
use rand::rngs::StdRng;
use rand::SeedableRng;

pub const AN: WireForm = WireForm::plain(GenesisForm::Annulet);
pub const SEQ_SEED: [u8; 32] = [0xAD; 32];
pub const USDT: u64 = 1;

pub fn wallet_dir(tag: &str, seed: u8) -> WalletDir {
    let dir = std::env::temp_dir().join(format!("qmb_ad1_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut w = WalletDir::create(&dir, MasterSeed::from_entropy([seed; ENTROPY_LEN])).unwrap();
    w.allocate_next().unwrap(); // addresses 0 and 1
    w
}

pub fn note_to(addr: &Address, value: u64, asset: u64, k: u64) -> L2Note {
    L2Note { value, asset, rkm: addr.rkm_lanes(), rho: [k, 1, 2, 3], rseed: [k, 4, 5, 6] }
}

/// One Annulet transaction paying `notes` to `addr`: the committed discovery
/// group a sender builds, its commitments declared, an S surface, a
/// placeholder proof.
pub fn pay_tx(addr: &Address, notes: &[L2Note], nf: u8, rng: &mut StdRng) -> TxEntry {
    let width = GenesisForm::Annulet.discovery_payload_len();
    let out = encrypt_notes_to_recipient(&addr.encapsulation_key().unwrap(), notes, rng);
    let discovery = qlab_note::compact::encode_committed_discovery_with_width(&[out.bundle], &out.payloads, width);
    let public = TxPublic {
        anchor: [0x0A; 32],
        nullifiers: vec![[nf; 32], [nf.wrapping_add(1); 32], [nf.wrapping_add(2); 32]],
        commitments: notes.iter().map(|n| h32(&n.commitment())).collect(),
        bucket: ArityBucket::TwoByTwo,
        fee: 1,
    };
    let surface = L2Surface { shape: L2ShapeTag::S, registry_root: [0; 32], vpublic: None, write: None, exit_rkm: [0; 32] };
    TxEntry { auth: qlab_devnet::annulet::L2_AUTH_ABSENT.to_vec(), proof: vec![0xAB; 64], public, discovery, rider: TxEntry::absent_rider(), l2: surface.encode() }
}

/// The genesis file: asset 0 and USDT-test (asset 1) registered, one USDT
/// genesis note to `holder`.
pub fn genesis(holder: &Address) -> AnnuletGenesisFile {
    genesis_with(holder, Vec::new(), Vec::new())
}

/// [`genesis`] plus `extra` registered leaves and `notes` genesis notes.
pub fn genesis_with(holder: &Address, extra: Vec<qlab_air::l2::RegistryLeaf>, notes: Vec<L2Note>) -> AnnuletGenesisFile {
    let params = AnnuletParams { fee_tier_s: 1, fee_tier_p: 2, fee_tier_r: 2, slot_secs: 10, max_empty_slots: 6 };
    let usdt = RegistryLeafRecord::of(&qlab_air::l2::RegistryLeaf {
        asset: USDT,
        issuer_key: [9, 9, 9, 9],
        mode: qlab_air::l2::MODE_HYBRID,
        freeze_root: qlab_air::l2p::CanonicalFreezeTree::empty().root,
        allow_root: [0; 4],
        flags: 0,
    });
    let g = note_to(holder, 1_000_000, USDT, 10);
    let mut records = vec![GenesisNoteRecord { cm: h32(&g.commitment()), payload: GenesisPlaintext::of(&g).0.to_vec() }];
    records.extend(notes.iter().map(|n| GenesisNoteRecord { cm: h32(&n.commitment()), payload: GenesisPlaintext::of(n).0.to_vec() }));
    let mut leaves = vec![RegistryLeafRecord::asset_zero(), usdt];
    leaves.extend(extra.iter().map(RegistryLeafRecord::of));
    AnnuletGenesisFile::assemble("annulet-ad1", params, SEQ_SEED, leaves, records, 0)
}

/// Lab #896 (extension #68 D2): [`genesis_with`] on the **Candidate A** axis
/// (format 33): the same registry and the same holder note, so `holder` is a
/// version-2 address on a Candidate A net.
pub fn genesis_v2(holder: &Address, notes: Vec<L2Note>) -> AnnuletGenesisFile {
    let v1 = genesis_with(holder, Vec::new(), notes);
    AnnuletGenesisFile::assemble_with_auth(
        "annulet-ad1-v2",
        v1.params,
        SEQ_SEED,
        v1.registry_genesis,
        v1.genesis_notes,
        0,
        L2AuthForm::CandidateA,
    )
}

/// The file's authorization axis (v1 when it does not name one).
pub fn auth_of(file: &AnnuletGenesisFile) -> L2AuthForm {
    file.l2_auth().unwrap_or(L2AuthForm::None)
}

/// The served wire form for `file`'s net: [`AN`] on v1, the Candidate A form
/// on a format-33 net.
pub fn wire_of(file: &AnnuletGenesisFile) -> WireForm {
    match auth_of(file) {
        L2AuthForm::CandidateA => WireForm::ANNULET_AUTH,
        L2AuthForm::None => AN,
    }
}

/// A sealed chain over `bodies` (height 1, 2, …), as a store.
pub fn store(file: &AnnuletGenesisFile, bodies: &[BlockBody]) -> MemChainStore {
    store_with(file, bodies, SEQ_SEED)
}

/// [`store`], sealed under the key of `seed`.
pub fn store_with(file: &AnnuletGenesisFile, bodies: &[BlockBody], seed: [u8; 32]) -> MemChainStore {
    let key = SequencerKey::from_seed(seed);
    let g = file.genesis_block_header();
    let ext = AnnuletHeaderFields { l1_anchor_height: 0, l1_anchor_root: [0; 32], registry_root: file.genesis_header.registry_root };
    let mut chain = MemChainStore::new_for(GenesisForm::Annulet, StoredBlock::annulet_genesis(&g));
    let mut parent = g;
    for (i, body) in bodies.iter().enumerate() {
        let h = BlockHeader::child_of_annulet(&parent, 10 * (i as u64 + 1), ext, body_commitment_annulet_for(body, auth_of(file)));
        chain.put_block(StoredBlock::from_sealed_parts(&key.seal(h), body)).unwrap();
        parent = h;
    }
    chain
}

pub fn view_of(chain: &MemChainStore) -> DiscoveryView {
    let mut v = DiscoveryView::default();
    v.refresh(chain);
    v
}

/// How the endpoint lies — one answer each.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Lie {
    None,
    /// `/genesis.qmb` is another file.
    GenesisBytes,
    /// One byte of height 2's seal flipped.
    BadSeal,
    /// `/v1/registry/1` opens another leaf (under another tree's root).
    RegistryLeaf,
    /// Height 2 grows a transaction paying the wallet: served on every route,
    /// the body under the real header.
    ForgedNote,
    /// Height 2's group in `/v1/compact` (and its payloads) is a note the
    /// block does not carry; the body is the real one.
    ForgedGroup,
    /// The headers stop at height 2 though the node holds 3.
    HeadersShort,
    /// The page skips height 2.
    HeaderGap,
    /// Height 2 onward from another chain (its height 1 differs).
    HeaderFork,
    /// Every header sealed by another key.
    WrongKey,
    /// The body answer for a hit block carries another chain's header.
    BodyHeader,
    /// `/v1/nullifiers` does not answer: the spends cannot be read.
    NoNullifiers,
    /// `/v1/registry/N` answers with another asset's opening.
    RegistryWrongAsset,
    /// `/v1/registry/N`'s path has one sibling flipped.
    RegistryBadPath,
    /// `/v1/registry/N` names an older height, over the tip's own tree.
    RegistryOtherHeight,
}

pub struct Endpoint {
    pub file: AnnuletGenesisFile,
    /// The served wire form, from the file's axis ([`wire_of`]).
    pub wire: WireForm,
    pub view: DiscoveryView,
    /// What `/v1/compact`, `/full` and (for `ForgedNote`) `/body` serve.
    pub served: DiscoveryView,
    pub lie: Lie,
    /// Lab #924: the commitment tree's leaves in order — the genesis notes,
    /// then each honest body's output commitments — for `/v1/tree/leaves`.
    pub leaves: Vec<[u8; 32]>,
}

impl Endpoint {
    pub fn new(file: AnnuletGenesisFile, honest: &[BlockBody], forged: Option<&[BlockBody]>, lie: Lie) -> Self {
        let view = view_of(&store(&file, honest));
        let served = match (lie, forged) {
            (Lie::WrongKey, _) => view_of(&store_with(&file, honest, [0x0E; 32])),
            (_, Some(f)) => view_of(&store(&file, f)),
            (_, None) => view.clone(),
        };
        let leaves = file
            .genesis_notes
            .iter()
            .map(|r| r.cm)
            .chain(honest.iter().flat_map(|b| b.txs.iter().flat_map(|t| t.public.commitments.iter().copied())))
            .collect();
        Endpoint { wire: wire_of(&file), file, view, served, lie, leaves }
    }

    pub fn fetch(&self, path: &str) -> Result<Vec<u8>, String> {
        let (route, query) = path.split_once('?').unwrap_or((path, ""));
        let err = |(code, msg): (u16, String)| format!("{code} {msg}");
        match route {
            "/genesis.qmb" => {
                let mut b = self.file.to_bytes();
                if self.lie == Lie::GenesisBytes {
                    let n = b.len();
                    b[n - 1] ^= 1;
                }
                Ok(b)
            }
            "/v1/headers" => {
                let q = if self.lie == Lie::HeadersShort { "from=1&to=2".to_string() } else { query.to_string() };
                let page = respond_headers(&self.view, self.wire, &q).map_err(err)?;
                match self.lie {
                    Lie::HeaderGap => {
                        let mut units = qlab_p2p::served::decode_headers_page(self.wire, 1, &page).unwrap();
                        units.remove(1);
                        return Ok(qlab_p2p::served::encode_headers_page(self.wire, 1, &units));
                    }
                    Lie::HeaderFork | Lie::WrongKey => {
                        let mut units = qlab_p2p::served::decode_headers_page(self.wire, 1, &page).unwrap();
                        let other = respond_headers(&self.served, self.wire, &q).map_err(err)?;
                        let other = qlab_p2p::served::decode_headers_page(self.wire, 1, &other).unwrap();
                        let keep = if self.lie == Lie::HeaderFork { 1 } else { 0 };
                        units.truncate(keep);
                        units.extend(other.into_iter().skip(keep));
                        return Ok(qlab_p2p::served::encode_headers_page(self.wire, 1, &units));
                    }
                    Lie::BadSeal => {}
                    _ => return Ok(page),
                }
                let mut units = qlab_p2p::served::decode_headers_page(self.wire, 1, &page).unwrap();
                if let Some(qlab_p2p::codec::WireHeader::Sealed(s)) = units.get_mut(1) {
                    s.sig[0] ^= 1;
                }
                Ok(qlab_p2p::served::encode_headers_page(self.wire, 1, &units))
            }
            // Lab #869: what `open_session` reads after the verified scan.
            "/v1/annulet/params" => Ok(qlab_cbserver::registry::encode_annulet_params(&qlab_cbserver::registry::AnnuletParams {
                genesis_hash: self.file.hash(),
                fee_tier_s: self.file.params.fee_tier_s,
                fee_tier_p: self.file.params.fee_tier_p,
                fee_tier_r: self.file.params.fee_tier_r,
            })),
            "/v1/compact" => respond(&self.served, query).map_err(err),
            "/v1/tree/leaves" => {
                let from: u64 = query.strip_prefix("from=").and_then(|f| f.parse().ok()).ok_or("400 from")?;
                Ok(qlab_node::TreeLeaves::page(&self.leaves, from).to_bytes())
            }
            "/v1/nullifiers" if self.lie == Lie::NoNullifiers => Err("503 unavailable: state lag".into()),
            "/v1/nullifiers" => respond_nullifiers(&self.view, query).map_err(err),
            "/v1/registry/root" => {
                let leaves = qlab_node::annulet_genesis::registry_leaves(&self.file.registry_genesis);
                let tree = qlab_cbserver::registry::RegistryTree::from_leaves(&leaves).unwrap();
                Ok(qlab_cbserver::registry::encode_registry_root(self.view.tip_height().unwrap(), &tree.root()))
            }
            p if p.starts_with("/v1/registry/") => {
                let asset: u16 = p.trim_start_matches("/v1/registry/").parse().unwrap();
                let mut leaves = qlab_node::annulet_genesis::registry_leaves(&self.file.registry_genesis);
                if self.lie == Lie::RegistryLeaf {
                    leaves[1].mode = qlab_air::l2::MODE_CLOAKED;
                }
                let tree = qlab_cbserver::registry::RegistryTree::from_leaves(&leaves).unwrap();
                let tip = self.view.tip_height().unwrap();
                let (height, asked) = match self.lie {
                    Lie::RegistryWrongAsset => (tip, 0),
                    Lie::RegistryOtherHeight => (tip - 1, asset),
                    _ => (tip, asset),
                };
                let mut b = qlab_cbserver::registry::encode_registry_opening(&tree, height, asked)
                    .ok_or_else(|| "404".to_string())?;
                if self.lie == Lie::RegistryBadPath {
                    // The first sibling's first byte (after ver ‖ height ‖ root ‖ 15 lanes).
                    b[1 + 8 + 32 + 120] ^= 1;
                }
                Ok(b)
            }
            p if p.ends_with("/full") => {
                let parts: Vec<&str> = p.split('/').collect();
                respond_full(&self.served, (parts[3], parts[5])).map_err(err)
            }
            p if p.ends_with("/body") => {
                let h = p.split('/').nth(3).unwrap();
                if self.lie == Lie::BodyHeader {
                    return respond_body(&self.served, self.wire, h).map_err(err);
                }
                if self.lie != Lie::ForgedNote {
                    return respond_body(&self.view, self.wire, h).map_err(err);
                }
                // The forged body under the real sealed header.
                let real = respond_body(&self.view, self.wire, h).map_err(err)?;
                let height: u64 = h.parse().unwrap();
                let header = qlab_p2p::served::decode_body_answer(self.wire, height, &real).ok().unwrap().header;
                let forged = respond_body(&self.served, self.wire, h).map_err(err)?;
                let mut ann = qlab_p2p::served::decode_body_answer(self.wire, height, &forged).ok().unwrap();
                ann.header = header;
                Ok(qlab_p2p::served::encode_body_answer(self.wire, height, &ann).unwrap())
            }
            other => Err(format!("404 {other}")),
        }
    }
}

/// The honest chain: height 1 pays 5 fee units to address 1, height 2 pays
/// 400 USDT-test to address 0, height 3 pays 7 USDT-test to address 0.
pub fn bodies(w: &WalletDir, rng: &mut StdRng) -> Vec<BlockBody> {
    let (a0, a1) = (w.wallet().address_at_index(0), w.wallet().address_at_index(1));
    vec![
        BlockBody { txs: vec![pay_tx(&a1, &[note_to(&a1, 5, 0, 20)], 0x30, rng)], ..BlockBody::default() },
        BlockBody { txs: vec![pay_tx(&a0, &[note_to(&a0, 400, USDT, 30)], 0x40, rng)], ..BlockBody::default() },
        BlockBody { txs: vec![pay_tx(&a0, &[note_to(&a0, 7, USDT, 40)], 0x50, rng)], ..BlockBody::default() },
    ]
}

pub fn run(w: &WalletDir, ep: &Endpoint, pin: Option<[u8; 32]>) -> Result<qumbra_wallet::annulet_verify::VerifiedAnnulet, VerifyRefusal> {
    let mut rng = StdRng::seed_from_u64(850);
    let mut fetch = |p: &str| ep.fetch(p);
    scan_annulet_verified(w, &mut fetch, 0, u64::MAX, pin, &mut rng)
}
