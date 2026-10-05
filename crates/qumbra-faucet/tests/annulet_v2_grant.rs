//! **Lab #896 H (QH2): the faucet on the Candidate A devnet.** On
//! [`AnnuletGenesisFile::devnet_v2`] (format 33), across three real nodes
//! running the node's own verifier pick (`L2VerifierV2` + the authorization
//! check), the faucet:
//!
//! 1. reads its stock — the genesis notes paid to the dev key's generation-0
//!    v2 `rkm` — and opens a fresh `auth.v1` at position 0, holding
//!    `auth.lock` (a second faucet on the same directory is refused);
//! 2. grants one stock note to a v2 recipient: the advance is on disk, and the
//!    v2 S with its signed authorization section is admitted, sealed and
//!    applied on every node; the recipient detects it through a follower;
//! 3. restarts on the same journal (stock and cursor carried over), and
//!    refuses by name to start with a **lost** journal once its stock has been
//!    spent, or with a journal that is not its key's.
//!
//! One real v2 S prove.

use qumbra_faucet::annulet::{served, AnnuletError, AnnuletFaucet, Recipient, SpendKey};
use qumbra_faucet::devnet_harness::Net;
use qumbra_node::annulet_genesis::{devnet, AnnuletGenesisBuild, AnnuletGenesisFile};
use qlab_remote_auth::annulet::journal::{generation_root, AuthJournal, JournalError};
use rand::{Rng, SeedableRng};

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("qumbra-faucet-v2-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn the_candidate_a_faucet_signs_its_grants_and_keeps_its_cursor_fail_closed() {
    let g = AnnuletGenesisFile::devnet_v2();
    let net = Net::start(&g, "h-v2");
    let mut rng = rand::rngs::StdRng::seed_from_u64(896);
    let key = SpendKey { sk: devnet::FAUCET_SK, d: devnet::FAUCET_D };
    assert_eq!(key.rkm_v2(&generation_root(&key.auth_secret(), 0)), devnet::rkm_v2(devnet::FAUCET_SK, devnet::FAUCET_D));
    let kem = qlab_note::kem::generate_keypair(&mut rng);
    let start = |at: usize, dir: &std::path::Path| {
        AnnuletFaucet::start_v2(served(net.served[at]), key, kem.ek.clone(), devnet::FEE_TIER_S, dir, g.hash(), g.format_version)
    };

    // 1. Stock, a fresh journal, the lock.
    let dir = tmpdir("journal");
    let mut faucet = start(0, &dir).expect("the Candidate A faucet starts");
    assert_eq!(faucet.stock_left() as u64, devnet::STOCK_NOTES);
    assert_eq!((faucet.auth_next(), faucet.address_version()), (Some(0), 2));
    assert_eq!(AuthJournal::load(&dir).unwrap().expect("written at start").active().next, 0);
    assert!(matches!(start(0, &dir), Err(AnnuletError::Journal(JournalError::Locked))), "one writer");
    net.settle_spends(0, "genesis");
    net.wait_connected();

    // 2. One grant to a v2 recipient.
    let user = SpendKey { sk: [rng.next_u64(), rng.next_u64(), rng.next_u64(), rng.next_u64()], d: [7, 1] };
    let user_kem = qlab_note::kem::generate_keypair(&mut rng);
    let to = Recipient { rkm: user.rkm_v2(&generation_root(&user.auth_secret(), 0)), ek: user_kem.ek.clone() };
    let granted = faucet.grant(&to, &mut rng).expect("the v2 grant is signed and admitted");
    assert_eq!((granted.value, granted.asset, granted.rkm), (devnet::GRANT_VALUE, 0, to.rkm));
    assert_eq!(faucet.auth_next(), Some(1));
    assert_eq!(AuthJournal::load(&dir).unwrap().unwrap().active().next, 1, "the advance is on disk");
    let v = net.settle_spends(3, "the v2 grant");
    let found = served(net.served[2]).detect(&user_kem.dk, 1, v[2].state_tip).expect("the follower serves discovery");
    assert_eq!(found, vec![granted], "the recipient finds exactly its grant");

    // 3. Restart on the same journal: stock and cursor carried over.
    drop(faucet);
    let again = start(2, &dir).expect("restarts on its journal (the lock was released)");
    assert_eq!((again.stock_left() as u64, again.auth_next()), (devnet::STOCK_NOTES - 1, Some(1)));
    drop(again);
    // A lost journal after a grant is refused, never rebuilt from position 0.
    let lost = tmpdir("lost");
    assert!(matches!(start(2, &lost), Err(AnnuletError::JournalLost { spent: 1 })));
    assert!(AuthJournal::load(&lost).unwrap().is_none(), "a refused start writes no journal");
    // A journal of another tree is refused.
    let foreign = tmpdir("foreign");
    AuthJournal::fresh([1, 2, 3, 4]).save(&foreign).unwrap();
    assert!(matches!(start(2, &foreign), Err(AnnuletError::JournalForeign(_))));
    for d in [dir, lost, foreign] {
        let _ = std::fs::remove_dir_all(d);
    }
}
