//! **WA1's done-when** (lab #858): the caller-pumped
//! [`AnnuletVerifyDriver`] is the pre-WA1 verified scan, and nothing else.
//!
//! The bar, as ruled on the plan note: over the honest fixture, AD1's five
//! lies (and the other chain/body lies of `tests/annulet_verified.rs`) and
//! WA0's record cases,
//!
//! (a) the pump ([`scan_annulet_verified`]) and the verbatim pre-WA1 text
//!     ([`scan_annulet_verified_reference`]) give a field-by-field equal
//!     [`VerifiedAnnulet`] or an equal [`VerifyRefusal`], over an **identical
//!     fetch sequence**, leaving the same record bytes and the same rng state;
//! (b) a transport failure at every fetch gives the same result as the
//!     reference failing at that same fetch;
//! (c) a hand-stepped driver — stepped more than once per `Need`, supplied
//!     late — asks exactly the reference's paths, an outstanding `Need`
//!     repeating until it is answered and no answered path asked again where
//!     the reference did not ask it again.
//!
//! The multi-key scan's own equality — the plan's (d) — is in
//! `qlab-cbserver` (`multi_driver_is_the_reference_loop`, labelled (e) there
//! after that module's existing (a)–(d)).

mod common;

use common::*;
use qlab_devnet::body::BlockBody;
use qlab_node::annulet_genesis::AnnuletGenesisFile;
use qumbra_wallet::annulet_driver::{AnnuletStep, AnnuletVerifyDriver};
use qumbra_wallet::annulet_reference::scan_annulet_verified_reference;
use qumbra_wallet::annulet_verify::{
    chain_cache_path, encode_chain_cache, read_chain_record, scan_annulet_verified, verify_registry_leaf, VerifiedAnnulet, VerifyRefusal,
};
use qumbra_wallet::store::WalletDir;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Everything a [`VerifiedAnnulet`] says, field by field, as one comparable
/// value (the report types carry `PartialEq` piecewise; the scan outcome and
/// its stats only `Debug`).
fn fields(v: &VerifiedAnnulet) -> String {
    let r = v.report();
    let rows: Vec<String> = r
        .rows
        .iter()
        .map(|row| {
            let scan = match &row.scan {
                Ok(o) => format!("Ok({:?} {:?} {:?} {:?})", o.notes, o.unopened, o.shadowed, o.stats),
                Err(e) => format!("Err({e})"),
            };
            format!("{} {} {scan}", row.index, row.short)
        })
        .collect();
    let headers: Vec<_> = (0..=v.chain().tip()).map(|h| v.chain().header(h)).collect();
    format!(
        "genesis={:?}\nrows={rows:?}\ngenesis_owned={}\nowned={:?}\nspent={:?}\nindex={:?}\nrefused={:?}\n\
         chain.genesis={:?}\nheaders={headers:?}\nrange={:?}\nbody_cost={:?}\nstated_tip={:?}\ncache={:?}\n\
         cache_write={:?}\nspends_verified={}",
        r.genesis_hash,
        r.genesis_owned,
        r.owned,
        r.spent,
        r.index,
        r.refused,
        v.chain().genesis.hash,
        v.range(),
        v.body_cost(),
        v.stated_tip(),
        v.cache(),
        v.cache_write(),
        v.spends_verified(),
    )
}

type Outcome = (Result<String, VerifyRefusal>, Vec<String>, Option<Vec<u8>>, u64);

/// The pre-state a scan starts from: the record bytes at the pin's path (or
/// none), written into a fresh wallet dir of the fixture's seed.
#[derive(Clone)]
struct Pre {
    seed: u8,
    record: Option<Vec<u8>>,
}

fn fresh(tag: &str, pre: &Pre, pin: Option<[u8; 32]>) -> WalletDir {
    let w = wallet_dir(tag, pre.seed);
    if let (Some(b), Some(pin)) = (&pre.record, pin) {
        std::fs::write(chain_cache_path(&w, &pin), b).unwrap();
    }
    w
}

/// One scan of `ep` from `pre`: through the pump (`pump`) or the reference,
/// the `k`-th fetch failing when `fail_at` names it.
fn scan(tag: &str, pre: &Pre, ep: &Endpoint, pin: Option<[u8; 32]>, pump: bool, fail_at: Option<usize>) -> Outcome {
    let w = fresh(&format!("{tag}_{}", if pump { "pump" } else { "ref" }), pre, pin);
    let mut paths = Vec::new();
    let mut fetch = |p: &str| {
        paths.push(p.to_string());
        if Some(paths.len() - 1) == fail_at {
            Err(format!("503 transport down at {p}"))
        } else {
            ep.fetch(p)
        }
    };
    let mut rng = StdRng::seed_from_u64(858);
    let r = if pump {
        scan_annulet_verified(&w, &mut fetch, 0, u64::MAX, pin, &mut rng)
    } else {
        scan_annulet_verified_reference(&w, &mut fetch, 0, u64::MAX, pin, &mut rng)
    };
    let record = pin.and_then(|pin| std::fs::read(chain_cache_path(&w, &pin)).ok());
    let _ = std::fs::remove_dir_all(&w.dir);
    (r.as_ref().map(fields).map_err(Clone::clone), paths, record, rng.next_u64())
}

/// (a) + (b): equal outcomes, honest and failing at each fetch in turn.
fn assert_equivalent(tag: &str, pre: &Pre, ep: &Endpoint, pin: Option<[u8; 32]>) -> Outcome {
    let reference = scan(tag, pre, ep, pin, false, None);
    assert_eq!(scan(tag, pre, ep, pin, true, None), reference, "{tag}: the pump is not the reference");
    for k in 0..reference.1.len() {
        let t = format!("{tag}_fail{k}");
        assert_eq!(
            scan(&t, pre, ep, pin, true, Some(k)),
            scan(&t, pre, ep, pin, false, Some(k)),
            "{tag}: a transport failure at fetch {k} ({})",
            reference.1[k]
        );
    }
    reference
}

/// (c): step by hand, twice per `Need`, and compare with the reference.
fn assert_hand_stepped(tag: &str, pre: &Pre, ep: &Endpoint, pin: [u8; 32], reference: &Outcome) {
    let w = fresh(&format!("{tag}_hand"), pre, Some(pin));
    let mut d = AnnuletVerifyDriver::new(w.wallet(), w.allocated.clone(), pin, 0, u64::MAX, read_chain_record(&w, &pin));
    let mut rng = StdRng::seed_from_u64(858);
    let mut asked: Vec<String> = Vec::new();
    let r = loop {
        match d.step(&mut rng) {
            AnnuletStep::Need(p) => {
                // Suspended: stepping again before the answer asks the same path.
                assert!(matches!(d.step(&mut rng), AnnuletStep::Need(q) if q == p), "{tag}: an outstanding Need repeats");
                asked.push(p.clone());
                d.supply(ep.fetch(&p));
            }
            AnnuletStep::Done(v) => break Ok(*v),
            AnnuletStep::Failed(e) => {
                assert!(matches!(d.step(&mut rng), AnnuletStep::Failed(f) if f == e), "{tag}: Failed is terminal");
                break Err(e);
            }
        }
    };
    assert_eq!(asked, reference.1, "{tag}: the hand-stepped Needs are the reference's fetches");
    // The host writes the record, as the pump does.
    let r = r.map(|mut v| {
        if let Some(h) = v.record_to_write().map(<[_]>::to_vec) {
            std::fs::write(chain_cache_path(&w, &pin), encode_chain_cache(&pin, &h)).unwrap();
            v.set_cache_write(None);
        }
        fields(&v)
    });
    assert_eq!(r, reference.0, "{tag}: the hand-stepped result");
    let record = std::fs::read(chain_cache_path(&w, &pin)).ok();
    assert_eq!(record, reference.2, "{tag}: the record the host writes from record_to_write()");
    let _ = std::fs::remove_dir_all(&w.dir);
}

/// The record a reference scan of `ep` leaves in a fresh dir of `seed`.
fn recorded_by(seed: u8, ep: &Endpoint) -> Vec<u8> {
    let pre = Pre { seed, record: None };
    scan(&format!("prep_{seed:x}"), &pre, ep, Some(ep.file.hash()), false, None).2.expect("a verified scan records")
}

fn five_bodies(w: &WalletDir, seed: u64) -> (Vec<BlockBody>, AnnuletGenesisFile) {
    let mut rng = StdRng::seed_from_u64(seed);
    let a0 = w.wallet().address_at_index(0);
    let mut b = bodies(w, &mut rng);
    b.push(BlockBody { txs: vec![pay_tx(&a0, &[note_to(&a0, 1, USDT, 60)], 0x60, &mut rng)], ..BlockBody::default() });
    b.push(BlockBody { txs: vec![pay_tx(&a0, &[note_to(&a0, 2, USDT, 61)], 0x61, &mut rng)], ..BlockBody::default() });
    (b, genesis(&a0))
}

#[test]
fn the_driver_is_the_reference_over_the_honest_chain_and_every_lie() {
    const SEED: u8 = 0x81;
    let w = wallet_dir("drv_lies", SEED);
    let mut rng = StdRng::seed_from_u64(81);
    let a0 = w.wallet().address_at_index(0);
    let file = genesis(&a0);
    let pin = file.hash();
    let honest = bodies(&w, &mut rng);
    let mut forged_note = honest.clone();
    forged_note[1].txs.push(pay_tx(&a0, &[note_to(&a0, 1_000_000, USDT, 99)], 0x60, &mut rng));
    let mut forged_group = honest.clone();
    forged_group[1].txs[0] = pay_tx(&a0, &[note_to(&a0, 1_000_000, USDT, 98)], 0x40, &mut rng);
    let mut other = honest.clone();
    other[0].txs.push(pay_tx(&a0, &[note_to(&a0, 1, 0, 77)], 0x70, &mut rng));
    let pre = Pre { seed: SEED, record: None };

    type Check = fn(&Result<VerifiedAnnulet, VerifyRefusal>);
    let cases: Vec<(&str, Lie, Option<&[BlockBody]>, Check)> = vec![
        ("honest", Lie::None, None, |r| {
            let v = r.as_ref().expect("an honest endpoint verifies");
            assert_eq!((v.chain().tip(), v.range(), v.stated_tip()), (3, (0, 3), Some(3)));
            assert_eq!(v.report().index.as_ref().unwrap().balances(), vec![(0, 5), (USDT as u16, 1_000_407)]);
            assert_eq!(v.body_cost().0, 3, "one body per block with a hit");
        }),
        ("genesis_bytes", Lie::GenesisBytes, None, |r| {
            assert!(matches!(r.as_ref().err(), Some(VerifyRefusal::GenesisMismatch { .. })), "{:?}", r.as_ref().err())
        }),
        ("bad_seal", Lie::BadSeal, None, |r| match r.as_ref().err() {
            Some(VerifyRefusal::HeaderInvalid { height: 2, why }) => assert!(why.contains("BadSeal"), "{why}"),
            other => panic!("{other:?}"),
        }),
        ("forged_note", Lie::ForgedNote, Some(&forged_note), |r| {
            assert_eq!(r.as_ref().err(), Some(&VerifyRefusal::BodyCommitmentMismatch { height: 2 }))
        }),
        ("forged_group", Lie::ForgedGroup, Some(&forged_group), |r| match r.as_ref().err() {
            Some(VerifyRefusal::ForgedNote { height: 2, tx_index: 0, why }) => assert!(why.contains("no such commitment"), "{why}"),
            other => panic!("{other:?}"),
        }),
        ("headers_short", Lie::HeadersShort, None, |r| {
            let v = r.as_ref().expect("a short header stream is a shorter chain");
            assert_eq!((v.chain().tip(), v.range(), v.stated_tip()), (2, (0, 2), Some(3)));
            assert_eq!(v.report().index.as_ref().unwrap().balances(), vec![(0, 5), (USDT as u16, 1_000_400)]);
        }),
        ("header_gap", Lie::HeaderGap, None, |r| {
            assert_eq!(r.as_ref().err(), Some(&VerifyRefusal::HeaderGap { want: 2, got: 3 }))
        }),
        ("header_fork", Lie::HeaderFork, Some(&other), |r| {
            assert_eq!(r.as_ref().err(), Some(&VerifyRefusal::HeaderFork { height: 2 }))
        }),
        ("wrong_key", Lie::WrongKey, None, |r| match r.as_ref().err() {
            Some(VerifyRefusal::HeaderInvalid { height: 1, why }) => assert!(why.contains("BadSeal"), "{why}"),
            other => panic!("{other:?}"),
        }),
        ("body_header", Lie::BodyHeader, Some(&other), |r| {
            assert!(matches!(r.as_ref().err(), Some(VerifyRefusal::BodyHeaderMismatch { .. })), "{:?}", r.as_ref().err())
        }),
        ("no_nullifiers", Lie::NoNullifiers, None, |r| {
            let v = r.as_ref().expect("the outputs verify; the spends are a named gap");
            assert!(v.report().index.is_none(), "no figure without the spends");
            match &v.report().spent {
                qlab_ledger::vocab::SpentCoverage::Unavailable { why } => assert!(why.contains("503"), "{why}"),
                other => panic!("{other:?}"),
            }
        }),
    ];
    for (n, (tag, lie, forged, check)) in cases.into_iter().enumerate() {
        let ep = Endpoint::new(file.clone(), &honest, forged, lie);
        let reference = assert_equivalent(&format!("drv_{tag}"), &pre, &ep, Some(pin));
        // Each case pinned by value (AD1's own pins), so an equivalence of
        // two equal wrong answers cannot pass.
        let w = fresh(&format!("drv_{tag}_pin{n}"), &pre, Some(pin));
        check(&run(&w, &ep, Some(pin)));
        let _ = std::fs::remove_dir_all(&w.dir);
        assert_hand_stepped(&format!("drv_{tag}"), &pre, &ep, pin, &reference);
    }
    // No pin: refused before any fetch, both ways.
    let ep = Endpoint::new(file.clone(), &honest, None, Lie::None);
    let r = assert_equivalent("drv_nopin", &pre, &ep, None);
    assert_eq!(r.0, Err(VerifyRefusal::NoPin));
    assert!(r.1.is_empty(), "nothing fetched without a pin");

    // The registry leaf: the pure split refuses the forged leaf as the
    // fetching form did.
    let ep = Endpoint::new(file, &honest, None, Lie::RegistryLeaf);
    let mut fetch = |p: &str| ep.fetch(p);
    let mut rng = StdRng::seed_from_u64(1);
    let v = scan_annulet_verified(&w, &mut fetch, 0, u64::MAX, Some(pin), &mut rng).expect("the chain is honest");
    assert_eq!(
        verify_registry_leaf(&mut fetch, v.chain(), USDT as u16).err(),
        Some(VerifyRefusal::RegistryRootMismatch { height: 3 })
    );
    assert_eq!(
        qumbra_wallet::annulet_verify::check_registry_leaf(v.chain(), USDT as u16, ep.fetch("/v1/registry/1")).err(),
        Some(VerifyRefusal::RegistryRootMismatch { height: 3 })
    );
    let _ = std::fs::remove_dir_all(&w.dir);
}

#[test]
fn the_driver_is_the_reference_over_every_record_case() {
    const SEED: u8 = 0x82;
    let w = wallet_dir("drv_rec", SEED);
    let (b, file) = five_bodies(&w, 82);
    let a0 = w.wallet().address_at_index(0);
    let ep3 = Endpoint::new(file.clone(), &b[..3], None, Lie::None);
    let ep5 = Endpoint::new(file.clone(), &b, None, Lie::None);
    let rec3 = recorded_by(SEED, &ep3);
    let rec5 = recorded_by(SEED, &ep5);

    // A fork from height 3 on.
    let mut other = b.clone();
    let mut rng = StdRng::seed_from_u64(8282);
    other[2] = BlockBody { txs: vec![pay_tx(&a0, &[note_to(&a0, 9, USDT, 90)], 0x70, &mut rng)], ..BlockBody::default() };
    let fork = Endpoint::new(file.clone(), &other[..4], None, Lie::None);

    let mut tampered = rec3.clone();
    tampered[41 + 40] ^= 1;
    let mut bad_version = rec3.clone();
    bad_version[0] = 9;
    let honest = b[..3].to_vec();
    let mut forged = honest.clone();
    forged[1].txs.push(pay_tx(&a0, &[note_to(&a0, 1_000_000, USDT, 99)], 0x60, &mut rng));
    let refused = Endpoint::new(file.clone(), &honest, Some(&forged), Lie::ForgedNote);

    // Another genesis, carrying the first one's record under its name.
    let other_genesis = genesis(&w.wallet().address_at_index(1));
    let other_ep = Endpoint::new(other_genesis.clone(), &b[..3], None, Lie::None);
    // `rec3` names the first genesis inside; `fresh` writes it under the
    // other genesis's file name.
    let copied = rec3.clone();

    let cases: Vec<(&str, Option<Vec<u8>>, &Endpoint)> = vec![
        ("unused", None, &ep3),
        ("resume", Some(rec3.clone()), &ep5),
        ("fork", Some(rec3.clone()), &fork),
        ("tamper", Some(tampered), &ep3),
        ("bad_version", Some(bad_version), &ep3),
        ("behind", Some(rec5), &ep3),
        ("refused", Some(rec3.clone()), &refused),
        ("refused_fresh", None, &refused),
        ("other_genesis", Some(copied), &other_ep),
        ("resume_at_tip", Some(rec3), &ep3),
    ];
    for (tag, record, ep) in cases {
        let pre = Pre { seed: SEED, record };
        let pin = ep.file.hash();
        let reference = assert_equivalent(&format!("drv_rec_{tag}"), &pre, ep, Some(pin));
        assert_hand_stepped(&format!("drv_rec_{tag}"), &pre, ep, pin, &reference);
        if tag.starts_with("refused") {
            assert!(reference.0.is_err(), "{tag}");
            assert_eq!(reference.2, pre.record, "{tag}: a refused scan leaves the record as it was");
        } else {
            assert!(reference.0.is_ok(), "{tag}: {:?}", reference.0);
        }
    }
    let _ = std::fs::remove_dir_all(&w.dir);
}

/// The honest fresh scan's Needs repeat no path at all, and the driver does
/// no I/O of its own: a driver built with no record over a dir that holds one
/// ignores the dir.
#[test]
fn the_driver_asks_each_path_once_and_never_reads_the_wallet_dir() {
    const SEED: u8 = 0x83;
    let w = wallet_dir("drv_once", SEED);
    let mut rng = StdRng::seed_from_u64(83);
    let file = genesis(&w.wallet().address_at_index(0));
    let pin = file.hash();
    let ep = Endpoint::new(file, &bodies(&w, &mut rng), None, Lie::None);
    let rec = recorded_by(SEED, &ep);
    std::fs::write(chain_cache_path(&w, &pin), &rec).unwrap();

    let mut d = AnnuletVerifyDriver::new(w.wallet(), w.allocated.clone(), pin, 0, u64::MAX, Ok(None));
    let mut asked = std::collections::HashSet::new();
    let v = loop {
        match d.step(&mut rng) {
            AnnuletStep::Need(p) => {
                assert!(asked.insert(p.clone()), "{p} asked twice");
                d.supply(ep.fetch(&p));
            }
            AnnuletStep::Done(v) => break v,
            AnnuletStep::Failed(e) => panic!("{e}"),
        }
    };
    assert_eq!(v.cache(), &qumbra_wallet::annulet_verify::ChainCache::Unused, "the record came in as Ok(None)");
    assert!(v.record_to_write().is_some(), "a fresh verification is recorded");
    assert_eq!(std::fs::read(chain_cache_path(&w, &pin)).unwrap(), rec, "the driver wrote nothing");
    let _ = std::fs::remove_dir_all(&w.dir);
}

/// `Done` and `Failed` are terminal, and a host's misuse fails by name —
/// for the verified driver and for the scan core inside it.
#[test]
fn misuse_of_either_driver_fails_by_name() {
    use qumbra_wallet::annulet::{AnnuletScanCore, CoreStep};
    const SEED: u8 = 0x84;
    let w = wallet_dir("drv_misuse", SEED);
    let mut rng = StdRng::seed_from_u64(84);
    let file = genesis(&w.wallet().address_at_index(0));
    let pin = file.hash();
    let ep = Endpoint::new(file, &bodies(&w, &mut rng), None, Lie::None);

    // The verified driver: a step after Done.
    let mut d = AnnuletVerifyDriver::new(w.wallet(), w.allocated.clone(), pin, 0, u64::MAX, Ok(None));
    loop {
        match d.step(&mut rng) {
            AnnuletStep::Need(p) => d.supply(ep.fetch(&p)),
            AnnuletStep::Done(_) => break,
            AnnuletStep::Failed(e) => panic!("{e}"),
        }
    }
    let after = VerifyRefusal::DriverMisuse { why: "stepped after the scan completed".into() };
    assert!(matches!(d.step(&mut rng), AnnuletStep::Failed(e) if e == after), "a step after Done");
    assert!(matches!(d.step(&mut rng), AnnuletStep::Failed(e) if e == after), "and it stays failed");
    // An answer with no Need outstanding.
    let mut d = AnnuletVerifyDriver::new(w.wallet(), w.allocated.clone(), pin, 0, u64::MAX, Ok(None));
    d.supply(Ok(Vec::new()));
    let stray = VerifyRefusal::DriverMisuse { why: "a response with no Need outstanding".into() };
    assert!(matches!(d.step(&mut rng), AnnuletStep::Failed(e) if e == stray), "an answer with no Need");

    // The scan core: the same two.
    let core = || AnnuletScanCore::new(w.wallet(), w.allocated.clone(), 0, 3, pin, Vec::new());
    let mut c = core();
    loop {
        match c.step(&mut rng) {
            CoreStep::Need(p) => c.supply(ep.fetch(&p)),
            CoreStep::Done(_) => break,
            CoreStep::Failed(why) => panic!("{why}"),
        }
    }
    assert!(matches!(c.step(&mut rng), CoreStep::Failed(why) if why == "scan core already completed"));
    let mut c = core();
    c.supply(Ok(Vec::new()));
    assert!(matches!(c.step(&mut rng), CoreStep::Failed(why) if why == "scan core received a response without requesting a path"));
    let _ = std::fs::remove_dir_all(&w.dir);
}
