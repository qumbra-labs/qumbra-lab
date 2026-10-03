//! **Lab #869 (a)**: every Annulet write opens its session on the verified
//! scan. `open_session` (and so `send_annulet`, `exit_annulet` and the issuer
//! verbs) refuses with no pin before fetching anything, refuses a lying
//! endpoint by AD1's names before anything is planned or proved, and over an
//! honest endpoint holds exactly the verified figures.
//!
//! Fixture-only, over AD1's lying endpoint (`common`): nothing proves — every
//! refusal lands before a plan, and the honest case stops at the session.

mod common;

use std::cell::Cell;
use std::time::Duration;

use common::*;
use qumbra_wallet::annulet_send::{exit_annulet, open_session, send_annulet, SendRefusal};
use qumbra_wallet::annulet_verify::VerifyRefusal;
use qumbra_wallet::store::WalletDir;
use rand::rngs::StdRng;
use rand::SeedableRng;

/// AD1's fixture endpoint as the spend path's transport, counting reads. It
/// takes no submission: nothing here gets that far.
struct Fixture<'a> {
    ep: &'a Endpoint,
    reads: &'a Cell<usize>,
}

impl qlab_l2spend::Endpoint for Fixture<'_> {
    fn get(&self, path: &str) -> Result<Vec<u8>, String> {
        self.reads.set(self.reads.get() + 1);
        self.ep.fetch(path)
    }
    fn post(&self, path: &str, _body: &[u8]) -> Result<(u16, Vec<u8>), String> {
        panic!("POST {path}: a refused session must never submit")
    }
}

fn session_refusal(w: &WalletDir, ep: &Endpoint, pin: Option<[u8; 32]>) -> Option<SendRefusal> {
    let reads = Cell::new(0);
    let mut rng = StdRng::seed_from_u64(869);
    open_session(w, Fixture { ep, reads: &reads }, u64::MAX, pin, &mut rng).err()
}

#[test]
fn no_pin_is_refused_by_name_before_anything_is_fetched() {
    let w = wallet_dir("as-nopin", 0x69);
    let mut rng = StdRng::seed_from_u64(1);
    let file = genesis(&w.wallet().address_at_index(0));
    let ep = Endpoint::new(file, &bodies(&w, &mut rng), None, Lie::None);
    let reads = Cell::new(0);

    let session = open_session(&w, Fixture { ep: &ep, reads: &reads }, u64::MAX, None, &mut rng);
    assert_eq!(session.err(), Some(SendRefusal::Verify(VerifyRefusal::NoPin)));
    assert_eq!(reads.get(), 0, "no pin: not one read");

    let to = w.wallet().address_at_index(1);
    let mut planned = |_: &_| -> bool { panic!("no plan without a verified session") };
    let send = send_annulet(
        &w,
        Fixture { ep: &ep, reads: &reads },
        USDT as u16,
        1,
        &to,
        u64::MAX,
        None,
        &[],
        Duration::ZERO,
        &mut planned,
        &mut rng,
    );
    assert_eq!(send.err(), Some(SendRefusal::Verify(VerifyRefusal::NoPin)));
    let mut exit_planned = |_: &_| -> bool { panic!("no exit plan without a verified session") };
    let exit = exit_annulet(&w, Fixture { ep: &ep, reads: &reads }, 1, &to, u64::MAX, None, &mut exit_planned, &mut rng);
    assert_eq!(exit.err().map(|e| e.to_string()), Some(SendRefusal::Verify(VerifyRefusal::NoPin).to_string()));
    assert_eq!(reads.get(), 0);
    let _ = std::fs::remove_dir_all(&w.dir);
}

#[test]
fn a_lying_endpoint_is_refused_by_name_before_a_plan() {
    let w = wallet_dir("as-lies", 0x6A);
    let mut rng = StdRng::seed_from_u64(2);
    let a0 = w.wallet().address_at_index(0);
    let file = genesis(&a0);
    let pin = file.hash();
    let honest = bodies(&w, &mut rng);
    let mut forged = honest.clone();
    forged[1].txs.push(pay_tx(&a0, &[note_to(&a0, 1_000_000, USDT, 99)], 0x60, &mut rng));
    let mut other = honest.clone();
    other[0].txs.push(pay_tx(&a0, &[note_to(&a0, 1, 0, 77)], 0x70, &mut rng));

    let cases: Vec<(Lie, Option<&[_]>)> = vec![
        (Lie::GenesisBytes, None),
        (Lie::BadSeal, None),
        (Lie::ForgedNote, Some(&forged)),
        (Lie::HeaderFork, Some(&other)),
        (Lie::WrongKey, None),
        (Lie::BodyHeader, Some(&other)),
    ];
    for (lie, served) in cases {
        let ep = Endpoint::new(file.clone(), &honest, served, lie);
        match session_refusal(&w, &ep, Some(pin)) {
            Some(SendRefusal::Verify(why)) => {
                assert_ne!(why, VerifyRefusal::NoPin, "{lie:?}");
                assert!(SendRefusal::Verify(why.clone()).to_string().starts_with("verified Annulet scan refused: "));
            }
            other => panic!("{lie:?}: expected a verify refusal, got {other:?}"),
        }
        // The send itself: refused before the plan callback is ever asked.
        let reads = Cell::new(0);
        let mut planned = |_: &_| -> bool { panic!("{lie:?}: a lying endpoint reached the plan") };
        let send = send_annulet(
            &w,
            Fixture { ep: &ep, reads: &reads },
            USDT as u16,
            1,
            &w.wallet().address_at_index(1),
            u64::MAX,
            Some(pin),
            &[],
            Duration::ZERO,
            &mut planned,
            &mut rng,
        );
        assert!(matches!(send.err(), Some(SendRefusal::Verify(_))), "{lie:?}");
    }
    let _ = std::fs::remove_dir_all(&w.dir);
}

#[test]
fn an_honest_session_holds_exactly_the_verified_figures() {
    let w = wallet_dir("as-honest", 0x6B);
    let mut rng = StdRng::seed_from_u64(3);
    let file = genesis(&w.wallet().address_at_index(0));
    let pin = file.hash();
    let ep = Endpoint::new(file, &bodies(&w, &mut rng), None, Lie::None);

    let verified = run(&w, &ep, Some(pin)).expect("AD1's honest endpoint verifies");
    let reads = Cell::new(0);
    let session = open_session(&w, Fixture { ep: &ep, reads: &reads }, u64::MAX, Some(pin), &mut rng)
        .expect("the honest endpoint opens a session");
    assert_eq!(session.genesis_hash, pin);
    assert_eq!(session.index.balances(), verified.report().index.as_ref().expect("both halves").balances());
    assert_eq!(session.index.balances(), vec![(0, 5), (USDT as u16, 1_000_407)]);
    assert_eq!((session.tiers.s, session.tiers.p, session.tiers.r), (1, 2, 2));
    // AS-1b: the session carries the verified scan's own flag (lab #853).
    assert_eq!(session.spends_verified, verified.spends_verified());
    assert!(!session.spends_verified);
    let _ = std::fs::remove_dir_all(&w.dir);
}
