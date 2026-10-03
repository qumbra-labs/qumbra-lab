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

mod common;

use common::*;
use qlab_devnet::body::BlockBody;
use qumbra_wallet::store::WalletDir;
use qumbra_node::discovery_server::{respond_body, respond_headers};
use qumbra_wallet::annulet_verify::{verify_registry_leaf, VerifyRefusal};
use rand::rngs::StdRng;
use rand::SeedableRng;

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
    assert_eq!(v.stated_tip(), Some(3), "the endpoint's own tip, for the freshness line");
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
    assert_eq!(v.stated_tip(), Some(3), "the node says 3: one header behind, which the CLI prints");
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

/// The header-chain refusals (#850 pre-review): a skipped height, a header
/// that does not extend the verified one below it, and a chain sealed by any
/// key but the genesis one — each by name.
#[test]
fn a_gap_a_fork_and_a_foreign_key_are_refused_by_name() {
    let w = wallet_dir("chain", 0x59);
    let mut rng = StdRng::seed_from_u64(9);
    let a0 = w.wallet().address_at_index(0);
    let honest = bodies(&w, &mut rng);
    // Another height 1: a different body, so every header above it differs.
    let mut other = honest.clone();
    other[0].txs.push(pay_tx(&a0, &[note_to(&a0, 1, 0, 77)], 0x70, &mut rng));

    let file = genesis(&a0);
    let pin = file.hash();
    let ep = Endpoint::new(file.clone(), &honest, None, Lie::HeaderGap);
    assert_eq!(run(&w, &ep, Some(pin)).err(), Some(VerifyRefusal::HeaderGap { want: 2, got: 3 }));

    let ep = Endpoint::new(file.clone(), &honest, Some(&other), Lie::HeaderFork);
    assert_eq!(run(&w, &ep, Some(pin)).err(), Some(VerifyRefusal::HeaderFork { height: 2 }));

    let ep = Endpoint::new(file, &honest, None, Lie::WrongKey);
    match run(&w, &ep, Some(pin)).err() {
        Some(VerifyRefusal::HeaderInvalid { height: 1, why }) => assert!(why.contains("BadSeal"), "{why}"),
        other => panic!("expected height 1's foreign seal refused, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&w.dir);
}

/// A body answer whose header is not the verified one at its height is
/// refused before a byte of it is believed.
#[test]
fn a_body_under_another_header_is_refused_by_name() {
    let w = wallet_dir("bodyhdr", 0x5A);
    let mut rng = StdRng::seed_from_u64(10);
    let a0 = w.wallet().address_at_index(0);
    let honest = bodies(&w, &mut rng);
    let mut other = honest.clone();
    other[0].txs.push(pay_tx(&a0, &[note_to(&a0, 1, 0, 78)], 0x71, &mut rng));
    let file = genesis(&a0);
    let pin = file.hash();
    // `served` is the other chain only for the body route; compact and full
    // come from it too, but its height-1 hit is address 1's same note.
    let ep = Endpoint::new(file, &honest, Some(&other), Lie::BodyHeader);
    assert!(
        matches!(run(&w, &ep, Some(pin)).err(), Some(VerifyRefusal::BodyHeaderMismatch { .. })),
        "a body under a header the wallet did not verify"
    );
    let _ = std::fs::remove_dir_all(&w.dir);
}

/// The output side is verified, the spend side is not — and the type says so.
#[test]
fn the_spend_side_is_reported_unverified() {
    let w = wallet_dir("spends", 0x5B);
    let mut rng = StdRng::seed_from_u64(11);
    let file = genesis(&w.wallet().address_at_index(0));
    let pin = file.hash();
    let ep = Endpoint::new(file, &bodies(&w, &mut rng), None, Lie::None);
    let v = run(&w, &ep, Some(pin)).unwrap();
    assert!(!v.spends_verified(), "lab #853: the nullifier list is the endpoint's");
    let _ = std::fs::remove_dir_all(&w.dir);
}

/// Lab #850 AD1b: a genesis file past its bound is refused by name in the
/// verifier itself, whatever transport handed it over.
#[test]
fn an_oversized_genesis_file_is_refused_by_name() {
    use qumbra_wallet::annulet_verify::{verify_genesis, MAX_GENESIS_FILE_BYTES};
    let mut fetch = |_: &str| Ok(vec![0u8; MAX_GENESIS_FILE_BYTES + 1]);
    assert_eq!(
        verify_genesis(&mut fetch, [0; 32]).err(),
        Some(VerifyRefusal::GenesisTooLarge { got: MAX_GENESIS_FILE_BYTES + 1 })
    );
}

// ---------------------------------------------------------------------------
// Lab #852 / WA0: the verified-header record
// ---------------------------------------------------------------------------

use qumbra_wallet::annulet_verify::{chain_cache_path, scan_annulet_verified, ChainCache};

/// Scan `ep` from a recording fetch: the result and every path asked.
fn scan_recorded(
    w: &WalletDir,
    ep: &Endpoint,
) -> (Result<qumbra_wallet::annulet_verify::VerifiedAnnulet, VerifyRefusal>, Vec<String>) {
    let mut paths = Vec::new();
    let mut rng = StdRng::seed_from_u64(852);
    let mut fetch = |p: &str| {
        paths.push(p.to_string());
        ep.fetch(p)
    };
    let r = scan_annulet_verified(w, &mut fetch, 0, u64::MAX, Some(ep.file.hash()), &mut rng);
    (r, paths)
}

fn header_paths(paths: &[String]) -> Vec<&str> {
    paths.iter().filter(|p| p.starts_with("/v1/headers")).map(String::as_str).collect()
}

/// Five bodies; an endpoint over the first `n`.
fn endpoints(w: &WalletDir, seed: u64) -> (Vec<BlockBody>, qlab_node::annulet_genesis::AnnuletGenesisFile) {
    let mut rng = StdRng::seed_from_u64(seed);
    let a0 = w.wallet().address_at_index(0);
    let mut b = bodies(w, &mut rng);
    b.push(BlockBody { txs: vec![pay_tx(&a0, &[note_to(&a0, 1, USDT, 60)], 0x60, &mut rng)], ..BlockBody::default() });
    b.push(BlockBody { txs: vec![pay_tx(&a0, &[note_to(&a0, 2, USDT, 61)], 0x61, &mut rng)], ..BlockBody::default() });
    (b, genesis(&a0))
}

#[test]
fn a_second_scan_resumes_from_the_record_and_fetches_only_new_headers() {
    let w = wallet_dir("cache_resume", 0x71);
    let (b, file) = endpoints(&w, 71);
    let ep3 = Endpoint::new(file.clone(), &b[..3], None, Lie::None);
    let (r, paths) = scan_recorded(&w, &ep3);
    assert_eq!(r.unwrap().cache(), &ChainCache::Unused);
    assert_eq!(header_paths(&paths), vec!["/v1/headers?from=1&to=256"]);
    assert!(chain_cache_path(&w, &file.hash()).exists(), "a verified scan records its headers");

    let ep5 = Endpoint::new(file, &b, None, Lie::None);
    let (r, paths) = scan_recorded(&w, &ep5);
    let v = r.expect("the resumed scan verifies");
    assert_eq!(v.cache(), &ChainCache::Resumed { anchor: 3, recorded: 3 });
    assert_eq!(v.chain().tip(), 5);
    assert_eq!(
        header_paths(&paths),
        vec!["/v1/headers?from=3&to=3", "/v1/headers?from=4&to=259"],
        "the recorded tip re-checked, then only what is new"
    );
    let _ = std::fs::remove_dir_all(&w.dir);
}

#[test]
fn a_forked_endpoint_after_a_recorded_scan_discards_the_record_and_re_verifies() {
    let w = wallet_dir("cache_fork", 0x72);
    let (b, file) = endpoints(&w, 72);
    scan_recorded(&w, &Endpoint::new(file.clone(), &b[..3], None, Lie::None)).0.expect("the honest chain verifies");
    // Another chain from height 3 on: block 3 carries other transactions.
    let mut other = b.clone();
    let a0 = w.wallet().address_at_index(0);
    let mut rng = StdRng::seed_from_u64(7272);
    other[2] = BlockBody { txs: vec![pay_tx(&a0, &[note_to(&a0, 9, USDT, 90)], 0x70, &mut rng)], ..BlockBody::default() };
    let (r, paths) = scan_recorded(&w, &Endpoint::new(file, &other[..4], None, Lie::None));
    let v = r.expect("a fork against the record is re-verified, not a failure");
    assert_eq!(v.cache(), &ChainCache::Discarded(VerifyRefusal::CachedTipForked { height: 3 }));
    assert_eq!(v.chain().tip(), 4);
    assert!(header_paths(&paths).contains(&"/v1/headers?from=1&to=256"), "re-verified from genesis");
    let _ = std::fs::remove_dir_all(&w.dir);
}

#[test]
fn a_tampered_record_is_refused_by_name_and_re_verified() {
    let w = wallet_dir("cache_tamper", 0x73);
    let (b, file) = endpoints(&w, 73);
    let ep = Endpoint::new(file.clone(), &b[..3], None, Lie::None);
    scan_recorded(&w, &ep).0.unwrap();
    let path = chain_cache_path(&w, &file.hash());
    let mut bytes = std::fs::read(&path).unwrap();
    // A byte inside header 1: header 2 no longer links to it. (A flip in the
    // last header would link and meet the tip re-check instead — a fork.)
    bytes[41 + 40] ^= 1;
    std::fs::write(&path, &bytes).unwrap();
    let v = scan_recorded(&w, &ep).0.expect("a bad record is discarded, not fatal");
    assert!(
        matches!(v.cache(), ChainCache::Discarded(VerifyRefusal::ChainCacheInvalid { .. })),
        "{:?}",
        v.cache()
    );
    assert_eq!(v.chain().tip(), 3);
    let _ = std::fs::remove_dir_all(&w.dir);
}

#[test]
fn a_record_of_another_genesis_is_not_this_chains() {
    let w = wallet_dir("cache_genesis", 0x74);
    let (b, file) = endpoints(&w, 74);
    scan_recorded(&w, &Endpoint::new(file.clone(), &b[..3], None, Lie::None)).0.unwrap();
    // Another genesis (another holder's note): its own file name — unused.
    let other = genesis(&w.wallet().address_at_index(1));
    let v = scan_recorded(&w, &Endpoint::new(other.clone(), &b[..3], None, Lie::None)).0.unwrap();
    assert_eq!(v.cache(), &ChainCache::Unused);
    // And a record copied under its name is refused by name.
    std::fs::copy(chain_cache_path(&w, &file.hash()), chain_cache_path(&w, &other.hash())).unwrap();
    let v = scan_recorded(&w, &Endpoint::new(other, &b[..3], None, Lie::None)).0.unwrap();
    match v.cache() {
        ChainCache::Discarded(VerifyRefusal::ChainCacheInvalid { why }) => assert!(why.contains("another genesis"), "{why}"),
        other => panic!("{other:?}"),
    }
    let _ = std::fs::remove_dir_all(&w.dir);
}

#[test]
fn an_endpoint_behind_the_record_is_clamped_never_over_claimed() {
    let w = wallet_dir("cache_behind", 0x75);
    let (b, file) = endpoints(&w, 75);
    scan_recorded(&w, &Endpoint::new(file.clone(), &b, None, Lie::None)).0.unwrap();
    let v = scan_recorded(&w, &Endpoint::new(file.clone(), &b[..3], None, Lie::None)).0.unwrap();
    assert_eq!(v.cache(), &ChainCache::Resumed { anchor: 3, recorded: 5 });
    assert_eq!(v.chain().tip(), 3, "the verified tip is what this endpoint serves");
    assert_eq!(v.range(), (0, 3));
    // The longer record stands for the next endpoint that serves it.
    let len = std::fs::metadata(chain_cache_path(&w, &file.hash())).unwrap().len();
    assert_eq!(len, 41 + 5 * 153);
    let _ = std::fs::remove_dir_all(&w.dir);
}

#[test]
fn a_refused_scan_never_writes_the_record() {
    let w = wallet_dir("cache_refused", 0x76);
    let mut rng = StdRng::seed_from_u64(76);
    let file = genesis(&w.wallet().address_at_index(0));
    let honest = bodies(&w, &mut rng);
    let mut forged = honest.clone();
    let a0 = w.wallet().address_at_index(0);
    forged[1].txs.push(pay_tx(&a0, &[note_to(&a0, 1_000_000, USDT, 99)], 0x60, &mut rng));
    let ep = Endpoint::new(file.clone(), &honest, Some(&forged), Lie::ForgedNote);
    assert!(scan_recorded(&w, &ep).0.is_err());
    assert!(!chain_cache_path(&w, &file.hash()).exists(), "nothing recorded from a refused scan");
    let _ = std::fs::remove_dir_all(&w.dir);
}
