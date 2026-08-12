//! Stage-7 drill: the EXPIRY SNIPE, end to end across the wallet's whole name
//! layer (lab #367).
//!
//! The one legitimate rebinding in the design (N6) is also its sharpest
//! phishing edge: a name lapses past grace, an adversary re-registers it, and
//! every payer who "knows" the name now resolves the adversary's address. The
//! chain cannot refuse this — it is a valid re-registration — so the wallet's
//! pin-and-alarm rule is the entire defence, and this test walks the full
//! attack: register → pin → lapse → snipe → the payer's wallet REFUSES with
//! the rebind alarm until the new fingerprint is re-confirmed.

use qlab_cbserver::codec::{BlockNames, NamesPage};
use qlab_devnet::names::{
    encode_rider, reopens_at, NameOp, NameRecord, L1_ADDRESS_LEN, NAME_TERM_BLOCKS,
    RECORD_KIND_L1_ADDRESS,
};
use qumbra_wallet::names::{PinVerdict, Pins, Resolution, WalletRegistry};

fn reveal_of(addr: u8) -> Vec<u8> {
    encode_rider(Some(&NameOp::Reveal {
        record: NameRecord {
            kind: RECORD_KIND_L1_ADDRESS,
            name: b"alice".to_vec(),
            // Not a decodable Address on purpose: the drill is about the pin
            // layer, whose fingerprint of an undecodable record is a marker
            // that still never matches a real pin — both sides exercised.
            address: vec![addr; L1_ADDRESS_LEN],
        },
        salt: [addr; 32],
    }))
}

#[test]
fn drill_expiry_snipe_ends_at_the_rebind_alarm_not_at_a_payment() {
    let mut reg = WalletRegistry::default();

    // 1. The honest registration, synced.
    let registered_at = 9_100u64;
    reg.apply_page(&NamesPage {
        from: 0,
        to: registered_at,
        blocks: vec![BlockNames { height: registered_at, riders: vec![reveal_of(0xAA)] }],
    });
    let expiry = registered_at + NAME_TERM_BLOCKS;

    // 2. The payer confirms out of band and pins (first use).
    let mut pins = Pins::default();
    let Resolution::Active(entry) = reg.resolve("alice.qmb", registered_at + 10) else {
        panic!("registered")
    };
    let PinVerdict::FirstUse { fingerprint } = pins.check("alice", &entry.address) else {
        panic!("first use")
    };
    pins.pin("alice", &fingerprint);
    assert_eq!(pins.check("alice", &entry.address), PinVerdict::Match);

    // 3. The name lapses. In grace it still resolves — flagged; past grace it
    //    stops resolving entirely (paying a lapsed claim is refused upstream
    //    of any pin).
    assert!(matches!(reg.resolve("alice", expiry + 1), Resolution::Expiring { .. }));
    assert_eq!(reg.resolve("alice", reopens_at(expiry)), Resolution::Unknown);

    // 4. THE SNIPE: past grace, the adversary re-registers — a perfectly
    //    valid transaction the chain cannot and should not refuse.
    let snipe_h = reopens_at(expiry) + 3;
    reg.apply_page(&NamesPage {
        from: expiry,
        to: snipe_h,
        blocks: vec![BlockNames { height: snipe_h, riders: vec![reveal_of(0xEE)] }],
    });

    // 5. The payer's wallet resolves the name again — and the pin layer
    //    REFUSES with the alarm. Silent rebinding is the entire attack; this
    //    verdict is what makes it loud.
    let Resolution::Active(sniped) = reg.resolve("alice.qmb", snipe_h + 1) else {
        panic!("the snipe is a real registration")
    };
    assert_ne!(sniped.address, entry.address, "the binding moved");
    match pins.check("alice.qmb", &sniped.address) {
        PinVerdict::Rebind { pinned, resolved } => {
            assert_eq!(pinned, fingerprint);
            assert_ne!(pinned, resolved);
        }
        other => panic!("the drill's whole point: expected the rebind alarm, got {other:?}"),
    }

    // 6. Only an explicit re-pin (after out-of-band re-confirmation) unlocks
    //    payment to the new holder — the N6 rule, completed.
    let PinVerdict::Rebind { resolved, .. } = pins.check("alice", &sniped.address) else {
        unreachable!()
    };
    pins.pin("alice", &resolved);
    assert_eq!(pins.check("alice", &sniped.address), PinVerdict::Match);
}
