//! **AD1's done-when** (lab #850): the verified Annulet scan binds every
//! figure to the sealed chain, and a lying endpoint is refused by name in each
//! of five ways — wrong genesis bytes, a bad seal, a forged registry leaf, a
//! forged note, and a forged group in `/v1/compact` that decrypts but is not
//! in the block the header commits to.
//!
//! The "endpoint" is the node's own serving code over a real chain store:
//! `MemChainStore` holding sealed Annulet blocks, `DiscoveryView::refresh`,
//! and `qumbra_node::discovery_server`'s socket-free `respond_*` cores — so the
//! honest answers are exactly what a node serves. Each lie mutates one answer.
//! Fixture-only: the transactions carry placeholder proofs (no route the
//! verifier reads checks a proof), and nothing proves.

use qlab_devnet::annulet::{
    body_commitment_annulet, AnnuletHeaderFields, L2ShapeTag, L2Surface, SequencerKey,
};
use qlab_devnet::body::{BlockBody, TxEntry, TxPublic};
use qlab_devnet::fees::ArityBucket;
use qlab_devnet::forms::GenesisForm;
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
use qumbra_wallet::annulet_verify::{scan_annulet_verified, verify_registry_leaf, VerifyRefusal};
use qumbra_wallet::store::WalletDir;
use rand::rngs::StdRng;
use rand::SeedableRng;

const AN: WireForm = WireForm::plain(GenesisForm::Annulet);
const SEQ_SEED: [u8; 32] = [0xAD; 32];
const USDT: u64 = 1;

fn wallet_dir(tag: &str, seed: u8) -> WalletDir {
    let dir = std::env::temp_dir().join(format!("qmb_ad1_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut w = WalletDir::create(&dir, MasterSeed::from_entropy([seed; ENTROPY_LEN])).unwrap();
    w.allocate_next().unwrap(); // addresses 0 and 1
    w
}

fn note_to(addr: &Address, value: u64, asset: u64, k: u64) -> L2Note {
    L2Note { value, asset, rkm: addr.rkm_lanes(), rho: [k, 1, 2, 3], rseed: [k, 4, 5, 6] }
}

/// One Annulet transaction paying `notes` to `addr`: the committed discovery
/// group a sender builds, its commitments declared, an S surface, a
/// placeholder proof.
fn pay_tx(addr: &Address, notes: &[L2Note], nf: u8, rng: &mut StdRng) -> TxEntry {
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
    TxEntry { proof: vec![0xAB; 64], public, discovery, rider: TxEntry::absent_rider(), l2: surface.encode() }
}

/// The genesis file: asset 0 and USDT-test (asset 1) registered, one USDT
/// genesis note to `holder`.
fn genesis(holder: &Address) -> AnnuletGenesisFile {
    let params = AnnuletParams { fee_tier_s: 1, fee_tier_p: 2, fee_tier_r: 2, slot_secs: 10, max_empty_slots: 6 };
    let usdt = RegistryLeafRecord::of(&qlab_air::l2::RegistryLeaf {
        asset: USDT,
        issuer_key: [9, 9, 9, 9],
        mode: qlab_air::l2::MODE_HYBRID,
        freeze_root: [0; 4],
        allow_root: [0; 4],
        flags: 0,
    });
    let g = note_to(holder, 1_000_000, USDT, 10);
    let notes = vec![GenesisNoteRecord { cm: h32(&g.commitment()), payload: GenesisPlaintext::of(&g).0.to_vec() }];
    AnnuletGenesisFile::assemble("annulet-ad1", params, SEQ_SEED, vec![RegistryLeafRecord::asset_zero(), usdt], notes, 0)
}

/// A sealed chain over `bodies` (height 1, 2, …), as a store.
fn store(file: &AnnuletGenesisFile, bodies: &[BlockBody]) -> MemChainStore {
    let key = SequencerKey::from_seed(SEQ_SEED);
    let g = file.genesis_block_header();
    let ext = AnnuletHeaderFields { l1_anchor_height: 0, l1_anchor_root: [0; 32], registry_root: file.genesis_header.registry_root };
    let mut chain = MemChainStore::new_for(GenesisForm::Annulet, StoredBlock::annulet_genesis(&g));
    let mut parent = g;
    for (i, body) in bodies.iter().enumerate() {
        let h = BlockHeader::child_of_annulet(&parent, 10 * (i as u64 + 1), ext, body_commitment_annulet(body));
        chain.put_block(StoredBlock::from_sealed_parts(&key.seal(h), body)).unwrap();
        parent = h;
    }
    chain
}

fn view_of(chain: &MemChainStore) -> DiscoveryView {
    let mut v = DiscoveryView::default();
    v.refresh(chain);
    v
}

/// How the endpoint lies — one answer each.
#[derive(Clone, Copy, PartialEq)]
enum Lie {
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
}

struct Endpoint {
    file: AnnuletGenesisFile,
    view: DiscoveryView,
    /// What `/v1/compact`, `/full` and (for `ForgedNote`) `/body` serve.
    served: DiscoveryView,
    lie: Lie,
}

impl Endpoint {
    fn new(file: AnnuletGenesisFile, honest: &[BlockBody], forged: Option<&[BlockBody]>, lie: Lie) -> Self {
        let view = view_of(&store(&file, honest));
        let served = forged.map_or_else(|| view.clone(), |f| view_of(&store(&file, f)));
        Endpoint { file, view, served, lie }
    }

    fn fetch(&self, path: &str) -> Result<Vec<u8>, String> {
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
                let page = respond_headers(&self.view, AN, &q).map_err(err)?;
                if self.lie != Lie::BadSeal {
                    return Ok(page);
                }
                let mut units = qlab_p2p::served::decode_headers_page(AN, 1, &page).unwrap();
                if let Some(qlab_p2p::codec::WireHeader::Sealed(s)) = units.get_mut(1) {
                    s.sig[0] ^= 1;
                }
                Ok(qlab_p2p::served::encode_headers_page(AN, 1, &units))
            }
            "/v1/compact" => respond(&self.served, query).map_err(err),
            "/v1/nullifiers" => respond_nullifiers(&self.view, query).map_err(err),
            p if p.starts_with("/v1/registry/") => {
                let asset: u16 = p.trim_start_matches("/v1/registry/").parse().unwrap();
                let mut leaves = qlab_node::annulet_genesis::registry_leaves(&self.file.registry_genesis);
                if self.lie == Lie::RegistryLeaf {
                    leaves[1].mode = qlab_air::l2::MODE_CLOAKED;
                }
                let tree = qlab_cbserver::registry::RegistryTree::from_leaves(&leaves).unwrap();
                qlab_cbserver::registry::encode_registry_opening(&tree, self.view.tip_height().unwrap(), asset)
                    .ok_or_else(|| "404".to_string())
            }
            p if p.ends_with("/full") => {
                let parts: Vec<&str> = p.split('/').collect();
                respond_full(&self.served, (parts[3], parts[5])).map_err(err)
            }
            p if p.ends_with("/body") => {
                let h = p.split('/').nth(3).unwrap();
                if self.lie != Lie::ForgedNote {
                    return respond_body(&self.view, AN, h).map_err(err);
                }
                // The forged body under the real sealed header.
                let real = respond_body(&self.view, AN, h).map_err(err)?;
                let height: u64 = h.parse().unwrap();
                let header = qlab_p2p::served::decode_body_answer(AN, height, &real).ok().unwrap().header;
                let forged = respond_body(&self.served, AN, h).map_err(err)?;
                let mut ann = qlab_p2p::served::decode_body_answer(AN, height, &forged).ok().unwrap();
                ann.header = header;
                Ok(qlab_p2p::served::encode_body_answer(AN, height, &ann).unwrap())
            }
            other => Err(format!("404 {other}")),
        }
    }
}

/// The honest chain: height 1 pays 5 fee units to address 1, height 2 pays
/// 400 USDT-test to address 0, height 3 pays 7 USDT-test to address 0.
fn bodies(w: &WalletDir, rng: &mut StdRng) -> Vec<BlockBody> {
    let (a0, a1) = (w.wallet().address_at_index(0), w.wallet().address_at_index(1));
    vec![
        BlockBody { txs: vec![pay_tx(&a1, &[note_to(&a1, 5, 0, 20)], 0x30, rng)], ..BlockBody::default() },
        BlockBody { txs: vec![pay_tx(&a0, &[note_to(&a0, 400, USDT, 30)], 0x40, rng)], ..BlockBody::default() },
        BlockBody { txs: vec![pay_tx(&a0, &[note_to(&a0, 7, USDT, 40)], 0x50, rng)], ..BlockBody::default() },
    ]
}

fn run(w: &WalletDir, ep: &Endpoint, pin: Option<[u8; 32]>) -> Result<qumbra_wallet::annulet_verify::VerifiedAnnulet, VerifyRefusal> {
    let mut rng = StdRng::seed_from_u64(850);
    let mut fetch = |p: &str| ep.fetch(p);
    scan_annulet_verified(w, &mut fetch, 0, u64::MAX, pin, &mut rng)
}

#[test]
fn an_honest_endpoint_verifies_and_every_figure_is_bound() {
    let w = wallet_dir("honest", 0x51);
    let mut rng = StdRng::seed_from_u64(1);
    let file = genesis(&w.wallet().address_at_index(0));
    let pin = file.hash();
    let ep = Endpoint::new(file, &bodies(&w, &mut rng), None, Lie::None);

    let v = run(&w, &ep, Some(pin)).expect("an honest endpoint verifies");
    assert_eq!(v.chain().tip(), 3, "every sealed header verified");
    assert_eq!(v.range(), (0, 3), "the range ends at the verified tip, not u64::MAX");
    let index = v.report().index.clone().expect("both halves known");
    assert_eq!(index.balances(), vec![(0, 5), (USDT as u16, 1_000_407)]);
    let (bodies, bytes) = v.body_cost();
    assert_eq!(bodies, 3, "one body per block with a hit, and only those");
    eprintln!("AD1 per-hit cost (fixture, 64-B placeholder proof): {bodies} bodies, {bytes} B");

    // The registry leaf binds to the verified header.
    let mut fetch = |p: &str| ep.fetch(p);
    let leaf = verify_registry_leaf(&mut fetch, v.chain(), USDT as u16).expect("the honest opening binds");
    assert_eq!(leaf.mode, qlab_air::l2::MODE_HYBRID);
    let _ = std::fs::remove_dir_all(&w.dir);
}

#[test]
fn no_pin_and_wrong_genesis_bytes_are_refused_by_name() {
    let w = wallet_dir("genesis", 0x52);
    let mut rng = StdRng::seed_from_u64(2);
    let file = genesis(&w.wallet().address_at_index(0));
    let pin = file.hash();
    let ep = Endpoint::new(file, &bodies(&w, &mut rng), None, Lie::GenesisBytes);
    assert_eq!(run(&w, &ep, None).err(), Some(VerifyRefusal::NoPin));
    assert!(matches!(run(&w, &ep, Some(pin)).err(), Some(VerifyRefusal::GenesisMismatch { .. })));
    let _ = std::fs::remove_dir_all(&w.dir);
}

#[test]
fn a_bad_seal_is_refused_by_name() {
    let w = wallet_dir("seal", 0x53);
    let mut rng = StdRng::seed_from_u64(3);
    let file = genesis(&w.wallet().address_at_index(0));
    let pin = file.hash();
    let ep = Endpoint::new(file, &bodies(&w, &mut rng), None, Lie::BadSeal);
    match run(&w, &ep, Some(pin)).err() {
        Some(VerifyRefusal::HeaderInvalid { height: 2, why }) => assert!(why.contains("BadSeal"), "{why}"),
        other => panic!("expected height 2's seal refused, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&w.dir);
}

#[test]
fn a_forged_registry_leaf_is_refused_by_name() {
    let w = wallet_dir("registry", 0x54);
    let mut rng = StdRng::seed_from_u64(4);
    let file = genesis(&w.wallet().address_at_index(0));
    let pin = file.hash();
    let ep = Endpoint::new(file, &bodies(&w, &mut rng), None, Lie::RegistryLeaf);
    let v = run(&w, &ep, Some(pin)).expect("the chain itself is honest");
    let mut fetch = |p: &str| ep.fetch(p);
    assert_eq!(
        verify_registry_leaf(&mut fetch, v.chain(), USDT as u16).err(),
        Some(VerifyRefusal::RegistryRootMismatch { height: 3 })
    );
    let _ = std::fs::remove_dir_all(&w.dir);
}

/// The forged chain: height 2 gains a second transaction paying the wallet
/// 1,000,000 USDT-test.
fn forged_bodies(w: &WalletDir, honest: &[BlockBody], rng: &mut StdRng) -> Vec<BlockBody> {
    let a0 = w.wallet().address_at_index(0);
    let mut f = honest.to_vec();
    f[1].txs.push(pay_tx(&a0, &[note_to(&a0, 1_000_000, USDT, 99)], 0x60, rng));
    f
}

#[test]
fn a_forged_note_is_refused_by_name() {
    let w = wallet_dir("note", 0x55);
    let mut rng = StdRng::seed_from_u64(5);
    let file = genesis(&w.wallet().address_at_index(0));
    let pin = file.hash();
    let honest = bodies(&w, &mut rng);
    let forged = forged_bodies(&w, &honest, &mut rng);
    let ep = Endpoint::new(file, &honest, Some(&forged), Lie::ForgedNote);
    assert_eq!(run(&w, &ep, Some(pin)).err(), Some(VerifyRefusal::BodyCommitmentMismatch { height: 2 }));
    let _ = std::fs::remove_dir_all(&w.dir);
}

#[test]
fn a_forged_compact_group_that_decrypts_is_refused_by_name() {
    let w = wallet_dir("group", 0x56);
    let mut rng = StdRng::seed_from_u64(6);
    let file = genesis(&w.wallet().address_at_index(0));
    let pin = file.hash();
    let honest = bodies(&w, &mut rng);
    // The same height-2 transaction slot, but its group pays a note the block
    // does not carry: it decrypts, and its commitment is in no transaction.
    let a0 = w.wallet().address_at_index(0);
    let mut forged = honest.clone();
    forged[1].txs[0] = pay_tx(&a0, &[note_to(&a0, 1_000_000, USDT, 98)], 0x40, &mut rng);
    let ep = Endpoint::new(file, &honest, Some(&forged), Lie::ForgedGroup);
    match run(&w, &ep, Some(pin)).err() {
        Some(VerifyRefusal::ForgedNote { height: 2, tx_index: 0, why }) => {
            assert!(why.contains("no such commitment"), "{why}")
        }
        other => panic!("expected the forged group refused at height 2, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&w.dir);
}

#[test]
fn the_scanned_tip_is_the_highest_verified_header_not_the_nodes() {
    let w = wallet_dir("tip", 0x57);
    let mut rng = StdRng::seed_from_u64(7);
    let file = genesis(&w.wallet().address_at_index(0));
    let pin = file.hash();
    let ep = Endpoint::new(file, &bodies(&w, &mut rng), None, Lie::HeadersShort);
    let v = run(&w, &ep, Some(pin)).expect("a short header stream is a shorter chain, not a lie");
    assert_eq!(v.chain().tip(), 2);
    assert_eq!(v.range(), (0, 2));
    let index = v.report().index.clone().unwrap();
    assert_eq!(index.balances(), vec![(0, 5), (USDT as u16, 1_000_400)], "height 3's 7 is not counted");
    let _ = std::fs::remove_dir_all(&w.dir);
}

/// The served-chain routes refuse the Annulet genesis by name: it is read
/// from the genesis file, never from a route.
#[test]
fn the_annulet_genesis_is_not_served_as_a_header_or_a_body() {
    let w = wallet_dir("genroute", 0x58);
    let file = genesis(&w.wallet().address_at_index(0));
    let view = view_of(&store(&file, &[]));
    let (code, msg) = respond_headers(&view, AN, "from=0&to=5").unwrap_err();
    assert_eq!(code, 400);
    assert!(msg.contains("genesis.qmb"), "{msg}");
    assert_eq!(respond_body(&view, AN, "0").unwrap_err().0, 400);
    assert_eq!(respond_body(&view, AN, "9").unwrap_err().0, 404);
    let page = respond_headers(&view, AN, "from=1&to=5").unwrap();
    assert!(qlab_p2p::served::decode_headers_page(AN, 1, &page).unwrap().is_empty(), "no height above genesis: an empty page");
    let _ = std::fs::remove_dir_all(&w.dir);
}
