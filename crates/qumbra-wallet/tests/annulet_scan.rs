//! **C1's done-when** (lab #718): a fixture L2 compact stream scans into
//! per-asset balances; the form is verified against the endpoint; and an
//! existing wallet address receives L2 notes (P4, proved end to end).
//!
//! The "endpoint" is an in-process fetch closure serving the real wire
//! encodings (`/v1/genesis/notes`, `/v1/compact`, `/full`, `/v1/nullifiers`)
//! built from `L2Note`s of two assets. No node, no proving.

use std::collections::BTreeMap;

use qlab_cbserver::codec::{
    encode_compact_response, encode_full_response, BlockNullifiers, CompactBlock, NullifierPage,
};
use qlab_cbserver::registry::{encode_genesis_notes, ServedGenesisNote};
use qlab_ledger::assets::OwnedL2Note;
use qlab_note::compact::CompactGroup;
use qlab_note::hash::digest_bytes;
use qlab_note::l2note::{GenesisPlaintext, L2Note};
use qlab_note::scan::encrypt_notes_to_recipient;
use qlab_wallet::address::Address;
use qlab_wallet::seed::{MasterSeed, ENTROPY_LEN};
use qumbra_wallet::annulet::{scan_annulet, verify_annulet, AnnuletRefusal};
use qumbra_wallet::store::WalletDir;
use rand::rngs::StdRng;
use rand::SeedableRng;

const GENESIS: [u8; 32] = [0x6f; 32];

/// One block's worth of served discovery: per tx, per recipient, the bundle
/// and its payloads.
struct FixtureChain {
    genesis: Vec<ServedGenesisNote>,
    blocks: BTreeMap<u64, Vec<Vec<qlab_note::scan::EncryptedOutputs>>>,
    nullifiers: BTreeMap<u64, Vec<[u8; 32]>>,
    tip: u64,
    /// When false, `/v1/genesis/notes` answers as an L1 node does.
    annulet: bool,
}

impl FixtureChain {
    fn fetch(&self, path: &str) -> Result<Vec<u8>, String> {
        let (route, query) = path.split_once('?').unwrap_or((path, ""));
        let q = |k: &str| -> u64 {
            query.split('&').find_map(|kv| kv.strip_prefix(&format!("{k}="))).unwrap().parse().unwrap()
        };
        match route {
            "/v1/genesis/notes" if self.annulet => Ok(encode_genesis_notes(&GENESIS, &self.genesis)),
            "/v1/genesis/notes" => Err("404 not found: an L1 node has no genesis notes".into()),
            "/v1/compact" => {
                // Height 0 is served, groupless (B5): genesis notes are not here.
                let (from, to) = (q("from"), q("to").min(self.tip));
                let blocks: Vec<CompactBlock> = (from..=to)
                    .map(|h| CompactBlock {
                        height: h,
                        groups: self.blocks.get(&h).map_or(Vec::new(), |txs| {
                            txs.iter()
                                .enumerate()
                                .map(|(i, recips)| CompactGroup {
                                    tx_index: i as u64,
                                    recipients: recips.iter().map(|r| r.bundle.clone()).collect(),
                                })
                                .collect()
                        }),
                    })
                    .collect();
                Ok(encode_compact_response(&blocks))
            }
            "/v1/nullifiers" => {
                // The page echoes the request; it carries the blocks the chain holds.
                let (from, to) = (q("from"), q("to"));
                let blocks = (from..=to.min(self.tip))
                    .map(|h| BlockNullifiers { height: h, nullifiers: self.nullifiers.get(&h).cloned().unwrap_or_default() })
                    .collect();
                Ok(NullifierPage { from, to, blocks }.to_bytes())
            }
            full if full.starts_with("/v1/block/") && full.ends_with("/full") => {
                let parts: Vec<&str> = full.split('/').collect();
                let (h, i): (u64, usize) = (parts[3].parse().unwrap(), parts[5].parse().unwrap());
                match self.blocks.get(&h).and_then(|txs| txs.get(i)) {
                    Some(recips) => Ok(encode_full_response(&recips.iter().map(|r| r.payloads.clone()).collect::<Vec<_>>())),
                    None => Err("404".into()),
                }
            }
            other => Err(format!("404 {other}")),
        }
    }
}

fn wallet_dir(tag: &str, seed: u8) -> WalletDir {
    let dir = std::env::temp_dir().join(format!("qmb_c1_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut w = WalletDir::create(&dir, MasterSeed::from_entropy([seed; ENTROPY_LEN])).unwrap();
    w.allocate_next().unwrap(); // addresses 0 and 1
    w
}

/// A note paid to an address the way a SENDER pays one: from the address
/// alone (its `rkm` and `ek`), never from the recipient's keys.
fn note_to(addr: &Address, value: u64, asset: u64, k: u64) -> L2Note {
    L2Note { value, asset, rkm: addr.rkm_lanes(), rho: [k, 1, 2, 3], rseed: [k, 4, 5, 6] }
}

fn pay(addr: &Address, notes: &[L2Note], rng: &mut StdRng) -> qlab_note::scan::EncryptedOutputs {
    encrypt_notes_to_recipient(&addr.encapsulation_key().expect("a valid ek"), notes, rng)
}

fn scan(w: &WalletDir, chain: &FixtureChain, pin: Option<[u8; 32]>) -> Result<qumbra_wallet::annulet::AnnuletReport, AnnuletRefusal> {
    let mut rng = StdRng::seed_from_u64(718);
    let mut fetch = |p: &str| chain.fetch(p);
    scan_annulet(w, &mut fetch, 0, 10, pin, &mut rng)
}

#[test]
fn a_fixture_l2_stream_scans_into_per_asset_balances() {
    let w = wallet_dir("balances", 0x11);
    let stranger = wallet_dir("balances_stranger", 0x22);
    let (a0, a1) = (w.wallet().address_at_index(0), w.wallet().address_at_index(1));
    let s0 = stranger.wallet().address_at_index(0);
    let mut rng = StdRng::seed_from_u64(1);

    // Genesis: the holder's USDT-test (asset 1) to address 0; a stranger's fee note.
    let usdt_genesis = note_to(&a0, 1_000_000, 1, 10);
    let genesis = vec![
        ServedGenesisNote { cm: digest_bytes(&usdt_genesis.commitment()), payload: GenesisPlaintext::of(&usdt_genesis) },
        ServedGenesisNote { cm: digest_bytes(&note_to(&s0, 3, 0, 11).commitment()), payload: GenesisPlaintext::of(&note_to(&s0, 3, 0, 11)) },
    ];
    // Block 1: a fee-unit grant to address 1, with a stranger's change beside it.
    let grant = note_to(&a1, 2, 0, 20);
    // Block 2: USDT-test 400 to address 0 and 600 back… to the stranger, spending the genesis note.
    let usdt_in = note_to(&a0, 400, 1, 30);
    let mut blocks = BTreeMap::new();
    blocks.insert(1, vec![vec![pay(&a1, &[grant], &mut rng), pay(&s0, &[note_to(&s0, 0, 0, 21)], &mut rng)]]);
    blocks.insert(2, vec![vec![pay(&a0, &[usdt_in], &mut rng), pay(&s0, &[note_to(&s0, 600, 1, 31)], &mut rng)]]);
    let spent_genesis = OwnedL2Note::from_genesis(&w.wallet(), 0, genesis[0].cm, usdt_genesis).unwrap().nullifier(&w.wallet());
    let mut nullifiers = BTreeMap::new();
    nullifiers.insert(2, vec![spent_genesis, [0xEE; 32]]);
    let chain = FixtureChain { genesis, blocks, nullifiers, tip: 3, annulet: true };

    let report = scan(&w, &chain, Some(GENESIS)).expect("an Annulet endpoint with the pinned genesis");
    assert_eq!(report.genesis_hash, GENESIS);
    assert_eq!(report.genesis_owned, 1, "the wallet owns exactly its genesis USDT-test");
    assert!(report.refused.is_empty(), "{:?}", report.refused);
    let index = report.index.clone().expect("both halves known: a figure exists");
    assert_eq!(index.balances(), vec![(0, 2), (1, 400)], "per asset, in each asset's own units");
    assert_eq!(index.by_asset[&1].spent.len(), 1, "the genesis USDT-test is spent at height 2");
    assert_eq!(index.by_asset[&1].spent[0].1, 2);
    assert_eq!(index.spendable(0)[0].div_index, 1);
    let text = qumbra_wallet::annulet::render_for_test(&report);
    assert!(text.contains("asset 0 (fee units): 2 spendable"), "{text}");
    assert!(text.contains("asset 1: 400 spendable"), "{text}");
    assert!(text.contains("coinbase: none on a sequencer net"), "{text}");

    // The stranger sees its own notes and none of ours.
    let theirs = scan(&stranger, &chain, None).unwrap().index.unwrap();
    assert_eq!(theirs.balances(), vec![(0, 3), (1, 600)]);
    for d in [&w.dir, &stranger.dir] {
        let _ = std::fs::remove_dir_all(d);
    }
}

/// 🔴 **P4, end to end** (the #718 ruling's addition): a note paid to an
/// EXISTING L1 wallet address — built from the address string alone, as a
/// sender builds it — is detected and opened by that same wallet on an
/// Annulet scan, and its record's spend input re-derives the address.
#[test]
fn a_note_paid_to_an_existing_l1_address_is_found_and_spendable_on_an_annulet_scan() {
    let w = wallet_dir("p4", 0x33);
    let encoded = w.wallet().address_at_index(0).encode();
    let addr = Address::decode(&encoded).expect("the wallet's own L1 address string");
    let mut rng = StdRng::seed_from_u64(4);
    let note = note_to(&addr, 7, 1, 40);
    let mut blocks = BTreeMap::new();
    blocks.insert(1, vec![vec![pay(&addr, &[note], &mut rng)]]);
    let chain = FixtureChain { genesis: Vec::new(), blocks, nullifiers: BTreeMap::new(), tip: 1, annulet: true };

    let report = scan(&w, &chain, None).unwrap();
    let row0 = report.rows.iter().find(|r| r.index == 0).unwrap();
    let outcome = row0.scan.as_ref().expect("the scan started");
    assert_eq!(outcome.notes.len(), 1, "detected and opened at the L2 width");
    assert_eq!(outcome.notes[0].detected.note, note);
    let index = report.index.unwrap();
    let owned = &index.spendable(1)[0];
    let input = owned.spend_input(&w.wallet());
    assert_eq!(qlab_air::l2p::derive_rkm_l2(&input), addr.rkm_lanes(), "the spend key re-derives the address");
    assert_eq!(qlab_air::l2::derive_input_l2(&input).2, note.commitment(), "and the note's commitment");
    let _ = std::fs::remove_dir_all(&w.dir);
}

#[test]
fn the_form_is_verified_an_l1_endpoint_and_a_wrong_pin_are_refused_by_name() {
    let w = wallet_dir("refusals", 0x44);
    let l1 = FixtureChain { genesis: Vec::new(), blocks: BTreeMap::new(), nullifiers: BTreeMap::new(), tip: 1, annulet: false };
    assert!(matches!(scan(&w, &l1, None), Err(AnnuletRefusal::NotAnnulet { .. })));
    let annulet = FixtureChain { annulet: true, ..l1 };
    let wrong = [0x01; 32];
    assert_eq!(
        scan(&w, &annulet, Some(wrong)).err(),
        Some(AnnuletRefusal::GenesisMismatch { pinned: wrong, served: GENESIS })
    );
    let mut fetch = |p: &str| annulet.fetch(p);
    assert_eq!(verify_annulet(&mut fetch, Some(GENESIS)).unwrap().0, GENESIS);
    let _ = std::fs::remove_dir_all(&w.dir);
}

/// Without the nullifier stream there is no figure (lab #314's rule, per asset).
#[test]
fn no_nullifier_stream_no_figure() {
    let w = wallet_dir("unquotable", 0x55);
    let a0 = w.wallet().address_at_index(0);
    let mut rng = StdRng::seed_from_u64(5);
    let mut blocks = BTreeMap::new();
    blocks.insert(1, vec![vec![pay(&a0, &[note_to(&a0, 9, 0, 50)], &mut rng)]]);
    let chain = FixtureChain { genesis: Vec::new(), blocks, nullifiers: BTreeMap::new(), tip: 1, annulet: true };
    let mut rng = StdRng::seed_from_u64(6);
    let mut fetch = |p: &str| if p.starts_with("/v1/nullifiers") { Err("404".into()) } else { chain.fetch(p) };
    let report = scan_annulet(&w, &mut fetch, 0, 10, None, &mut rng).unwrap();
    assert!(report.index.is_none(), "outputs without spends are not a balance");
    assert!(qumbra_wallet::annulet::render_for_test(&report).contains("balance:  UNAVAILABLE"));
    let _ = std::fs::remove_dir_all(&w.dir);
}
