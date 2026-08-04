//! End-to-end wallet flow (M7 deliverable 4): derive a wallet -> make a
//! diversified address -> (reuse `qlab-note`) encrypt a note to it ->
//! scan/detect/decrypt with the incoming/full viewing keys -> recompute the
//! commitment and confirm it matches `qlab-air`'s `build_bucket` packing ->
//! and close the loop by SPENDING the received note (its nullifier matches).
//!
//! This exercises every crate boundary: `qlab-wallet` keys/addresses,
//! `qlab-note` KEM/AEAD/scan, and `qlab-air`'s circuit packing.

use qlab_air::narrow::{build_bucket, derive_output_rho, TxInput, TxOutput};
use qlab_note::note::Note;
use qlab_note::scan::{encrypt_to_recipient, ScanMode};
use qlab_wallet::address::{Address, Diversifier};
use qlab_wallet::diversifier::DiversifierLedger;
use qlab_wallet::seed::MasterSeed;
use qlab_wallet::Wallet;
use rand::{rngs::StdRng, SeedableRng};

#[test]
fn derive_address_encrypt_scan_recompute_and_spend() {
    // 1. Derive a wallet and its diversified address; round-trip the address
    //    through its bech32m string (as a real sender would receive it).
    let wallet = Wallet::from_seed_lanes([0x0a11_ce, 0xb0b, 0xf00d, 0x1234]);
    let d = Diversifier::from_bytes([5u8; 16]);
    let addr_string = wallet.address(d).encode();
    let addr = Address::decode(&addr_string).expect("address string decodes");

    // The address advertises the wallet's rkm (spendability precondition) and a
    // functional ML-KEM ek.
    assert_eq!(addr.rkm_lanes(), wallet.rkm(d), "address carries the wallet rkm(d)");
    let ek = addr.encapsulation_key().expect("address has a valid ek");

    // 2. Sender builds a note to the address and encrypts it via qlab-note
    //    (REUSED, not reimplemented).
    let note = Note {
        value: 12_345,
        rkm: addr.rkm_lanes(),
        rho: [0x11, 0x22, 0x33, 0x44],
        rseed: [0x55, 0x66, 0x77, 0x88],
    };
    let mut rng = StdRng::seed_from_u64(99);
    let outputs = encrypt_to_recipient(&ek, &[note], &mut rng);

    // 3. Recipient scans with the INCOMING viewing key — both scan modes detect
    //    and decrypt the note exactly.
    for mode in [ScanMode::FullFo, ScanMode::FoSkip] {
        let found = wallet.ivk().scan(&d, &outputs, mode);
        assert_eq!(found.len(), 1, "{mode:?}: exactly one note detected");
        assert_eq!(found[0].note, note, "{mode:?}: decrypted note matches");
    }
    // The FULL viewing key also detects incoming.
    let found = wallet.fvk().scan(&d, &outputs, ScanMode::FullFo);
    assert_eq!(found.len(), 1);
    let received = found[0].note;
    assert_eq!(received, note);

    // A DIFFERENT wallet's ivk detects nothing (wrong key).
    let stranger = Wallet::from_seed_lanes([9, 9, 9, 9]);
    assert!(
        stranger.ivk().scan(&d, &outputs, ScanMode::FullFo).is_empty(),
        "a stranger's ivk must not detect this note"
    );

    // 4. Recompute cm and confirm it matches qlab-air's build_bucket packing,
    //    and spend the received note in the same bucket (nf closure).
    //    Balanced 2x2: input0 = spend(received), input1 balances; output0 = a
    //    fresh note carrying the same rkm (exercises the output cm packing).
    let fee = 100u64;
    let input1_value = 655u64;
    let out0 = Note {
        value: received.value,
        rkm: wallet.rkm(d),
        rho: [0xaa, 0xbb, 0xcc, 0xdd],
        rseed: [0xee, 0xff, 0x01, 0x02],
    };
    let out1_value = received.value + input1_value - out0.value - fee; // = 555
    let outputs_c = [
        TxOutput { value: out0.value, rkm: out0.rkm, rho: out0.rho, rseed: out0.rseed },
        TxOutput { value: out1_value, rkm: [1, 2, 3, 4], rho: [5, 6, 7, 8], rseed: [9, 10, 11, 12] },
    ];
    // input0 is produced by the SPEND capability from the received note, at the
    // SAME diversifier the note was received on (the circuit re-derives rkm(d)).
    let spend0: TxInput = wallet.spend_input(received.value, received.rho, received.rseed, d);
    let stranger_sk = Wallet::from_seed_lanes([2, 4, 6, 8]);
    let input1 = stranger_sk.spend_input(
        input1_value,
        [13, 14, 15, 16],
        [17, 18, 19, 20],
        Diversifier::default(),
    );
    let inputs = [spend0, input1];

    let inst = build_bucket(18, &inputs, &outputs_c, fee);

    // (a) recompute-cm matches qlab-air packing: the output note's commitment
    //     recomputed by the wallet/qlab-note equals the circuit's cm_out[0].
    //
    // 🔴 Issue #215 (i): the seed is DERIVED, so the note the wallet reconstructs
    // takes `rho` from `derive_output_rho(nf_0, index)` — not from the sender's
    // choice, which `build_bucket` overrides. `nf_0` is `PV_NF1`, public, so a
    // wallet needs nothing extra to compute it. This is the wallet-side half of
    // the contract #188 (a) is priced against, and the packing lock it stands
    // for is unaffected: only where `rho` comes from changed.
    let out0 = Note { rho: derive_output_rho(&inst.nf[0], 0), ..out0 };
    assert_eq!(
        out0.commitment(),
        inst.cm_out[0],
        "recomputed output cm must match circuit cm_out (qlab-air packing)"
    );
    // (b) spend closure: the circuit's nullifier for the spent (received) note
    //     equals the one the wallet computes — the note is genuinely spendable.
    assert_eq!(
        inst.nf[0],
        wallet.nullifier(&received.rho),
        "circuit nf[0] must match the wallet's nullifier for the received note"
    );
    // (c) the received note's own commitment equals what the circuit reconstructs
    //     when spending it (rkm from sk == address rkm): full receive->spend loop.
    assert_eq!(
        received.commitment(),
        qlab_note::note::note_commitment(received.value, &wallet.rkm(d), &received.rho, &received.rseed),
        "received note cm is reconstructible from sk-derived rkm(d)"
    );
}

/// Issue #32 end-to-end: ONE wallet, TWO diversified addresses that carry
/// DISTINCT `rkm` (unlinkable), each receiving a note — and BOTH notes spent
/// together in a single balanced 2×2 bucket, each re-deriving `rkm(d)` from its
/// own diversifier. This is the positive unlinkability guarantee: different
/// diversifiers, different on-chain identity, still fully spendable.
#[test]
fn two_diversified_addresses_are_unlinkable_and_both_spend() {
    let wallet = Wallet::from_seed_lanes([0xd1, 0xd2, 0xd3, 0xd4]);
    let d0 = Diversifier::from_bytes([1u8; 16]);
    let d1 = Diversifier::from_bytes([2u8; 16]);

    let addr0 = wallet.address(d0);
    let addr1 = wallet.address(d1);

    // (1) Unlinkability: the two addresses carry DIFFERENT rkm (this is exactly
    //     what M7 could not deliver), though they come from one wallet.
    assert_ne!(
        addr0.rkm_lanes(),
        addr1.rkm_lanes(),
        "two addresses of one wallet must have distinct rkm (issue #32)"
    );

    // (2) A sender pays each address; the recipient scans both with its ivk.
    let mut rng = StdRng::seed_from_u64(2032);
    let recv = |addr: &Address, d: &Diversifier, value: u64, rho, rseed, rng: &mut StdRng| {
        let note = Note { value, rkm: addr.rkm_lanes(), rho, rseed };
        let ek = addr.encapsulation_key().expect("valid ek");
        let outputs = encrypt_to_recipient(&ek, &[note], rng);
        let found = wallet.ivk().scan(d, &outputs, ScanMode::FullFo);
        assert_eq!(found.len(), 1, "note detected at its own diversifier");
        assert_eq!(found[0].note, note);
        note
    };
    let n0 = recv(&addr0, &d0, 1_000, [1, 2, 3, 4], [5, 6, 7, 8], &mut rng);
    let n1 = recv(&addr1, &d1, 2_000, [9, 10, 11, 12], [13, 14, 15, 16], &mut rng);

    // (3) Spend BOTH received notes in one balanced bucket. Each spend witness
    //     carries its OWN diversifier, so the circuit re-derives the matching
    //     rkm(d) for each input.
    let fee = 30u64;
    let out0_v = 1_500u64;
    let out1_v = n0.value + n1.value - out0_v - fee; // = 1_470
    let outputs = [
        TxOutput { value: out0_v, rkm: wallet.rkm(d0), rho: [21; 4], rseed: [22; 4] },
        TxOutput { value: out1_v, rkm: [3, 3, 3, 3], rho: [23; 4], rseed: [24; 4] },
    ];
    let inputs = [
        wallet.spend_input(n0.value, n0.rho, n0.rseed, d0),
        wallet.spend_input(n1.value, n1.rho, n1.rseed, d1),
    ];
    let inst = build_bucket(18, &inputs, &outputs, fee);

    // (4) Both notes are genuinely spendable: each nullifier closes, and each
    //     received note's commitment reconstructs from its own rkm(d).
    assert_eq!(inst.nf[0], wallet.nullifier(&n0.rho), "note 0 spends (nf closes)");
    assert_eq!(inst.nf[1], wallet.nullifier(&n1.rho), "note 1 spends (nf closes)");
    assert_eq!(
        n0.commitment(),
        qlab_note::note::note_commitment(n0.value, &wallet.rkm(d0), &n0.rho, &n0.rseed),
        "note 0 cm reconstructs from rkm(d0)"
    );
    assert_eq!(
        n1.commitment(),
        qlab_note::note::note_commitment(n1.value, &wallet.rkm(d1), &n1.rho, &n1.rseed),
        "note 1 cm reconstructs from rkm(d1)"
    );
}

/// Issue #43 end-to-end: seed phrase → HD wallet → a ROTATED (managed-index)
/// diversified address → encrypt → scan → SPEND — proving a fully seed-derived
/// key yields a genuinely spendable note against `qlab-air`'s `build_bucket`.
/// This is the load-bearing regression lock for the HD layer: if HD derivation
/// or diversifier management drifts, the circuit `nf`/`cm` closure below breaks.
#[test]
fn seed_to_mnemonic_to_rotated_address_encrypt_scan_spend() {
    // 1. A master seed round-trips through its 24-word backup phrase, and the
    //    recovered seed derives the identical wallet (account 0).
    let seed = MasterSeed::from_entropy([0x2a; 32]);
    let phrase = seed.to_mnemonic();
    assert_eq!(phrase.split_whitespace().count(), 24);
    let recovered = MasterSeed::from_mnemonic(&phrase).expect("phrase recovers seed");
    assert_eq!(recovered.entropy(), seed.entropy());

    let wallet = Wallet::from_master_seed(&recovered, 0);
    // A different account of the same seed is an independent wallet.
    let other_account = Wallet::from_master_seed(&recovered, 1);
    assert_ne!(wallet.nk(), other_account.nk(), "accounts are independent");

    // 2. Rotate a fresh managed diversified address from a ledger, then persist
    //    and restore the ledger (the wallet's diversifier bookkeeping).
    let mut ledger = DiversifierLedger::new();
    let (index, addr0) = wallet.next_address(&mut ledger);
    let restored = DiversifierLedger::from_bytes(&ledger.to_bytes()).expect("ledger persists");
    assert_eq!(restored.next_index(), ledger.next_index());
    assert!(restored.is_allocated(index));

    // The rotated address round-trips through its bech32m string (as a sender
    // receives it) and re-derives identically from the index.
    let addr = Address::decode(&addr0.encode()).expect("address decodes");
    let d = wallet.diversifier_at_index(index);
    assert_eq!(addr.rkm_lanes(), wallet.rkm(d), "address carries wallet rkm(d)");
    let ek = addr.encapsulation_key().expect("valid ek");

    // 3. Sender pays the rotated address; recipient scans with its ivk (which
    //    knows the managed diversifier for its own index — div_seed only).
    let note = Note {
        value: 9_999,
        rkm: addr.rkm_lanes(),
        rho: [0xa1, 0xa2, 0xa3, 0xa4],
        rseed: [0xb1, 0xb2, 0xb3, 0xb4],
    };
    let mut rng = StdRng::seed_from_u64(4343);
    let outputs = encrypt_to_recipient(&ek, &[note], &mut rng);
    let scan_d = wallet.ivk().diversifier_at_index(index);
    assert_eq!(scan_d, d, "ivk reproduces the managed diversifier for scanning");
    let found = wallet.ivk().scan(&scan_d, &outputs, ScanMode::FullFo);
    assert_eq!(found.len(), 1, "note detected at the rotated address");
    let received = found[0].note;
    assert_eq!(received, note);

    // 4. SPEND the received note in a balanced 2x2 bucket — the seed-derived key
    //    at the rotated diversifier must produce a valid nullifier and its cm
    //    must reconstruct, byte-for-byte, against build_bucket.
    let fee = 40u64;
    let input1_value = 4_001u64;
    let out0 = Note {
        value: received.value,
        rkm: wallet.rkm(d),
        rho: [0xc1, 0xc2, 0xc3, 0xc4],
        rseed: [0xd1, 0xd2, 0xd3, 0xd4],
    };
    let out1_value = received.value + input1_value - out0.value - fee;
    let outputs_c = [
        TxOutput { value: out0.value, rkm: out0.rkm, rho: out0.rho, rseed: out0.rseed },
        TxOutput { value: out1_value, rkm: [2, 4, 6, 8], rho: [1, 3, 5, 7], rseed: [9, 8, 7, 6] },
    ];
    let spend0 = wallet.spend_input(received.value, received.rho, received.rseed, d);
    let input1 =
        Wallet::from_seed_lanes([3, 5, 7, 9]).spend_input(input1_value, [1; 4], [2; 4], Diversifier::default());
    let inst = build_bucket(18, &[spend0, input1], &outputs_c, fee);

    assert_eq!(
        inst.nf[0],
        wallet.nullifier(&received.rho),
        "circuit nf[0] == seed-derived wallet nullifier (HD key is spendable)"
    );
    // Issue #215 (i): the reconstructed note's seed is derived — see the note on
    // the same assertion in `derive_address_encrypt_scan_recompute_and_spend`.
    let out0 = Note { rho: derive_output_rho(&inst.nf[0], 0), ..out0 };
    assert_eq!(
        out0.commitment(),
        inst.cm_out[0],
        "recomputed output cm == circuit cm_out (packing intact under HD path)"
    );
    assert_eq!(
        received.commitment(),
        qlab_note::note::note_commitment(received.value, &wallet.rkm(d), &received.rho, &received.rseed),
        "received note cm reconstructs from the seed-derived rkm(d)"
    );
}

#[test]
fn amortized_two_output_scan() {
    // Two notes to one address share one ML-KEM ct (the amortization structure)
    // and both are detected via the wallet's viewing key.
    let wallet = Wallet::from_seed_lanes([7, 7, 7, 7]);
    let d = Diversifier::default();
    let addr = wallet.address(d);
    let ek = addr.encapsulation_key().unwrap();
    let n0 = Note { value: 1, rkm: addr.rkm_lanes(), rho: [1; 4], rseed: [2; 4] };
    let n1 = Note { value: 2, rkm: addr.rkm_lanes(), rho: [3; 4], rseed: [4; 4] };
    let mut rng = StdRng::seed_from_u64(7);
    let outputs = encrypt_to_recipient(&ek, &[n0, n1], &mut rng);
    assert_eq!(outputs.bundle.entries.len(), 2);
    assert_eq!(outputs.bundle.ct.len(), 1088, "one shared ML-KEM ciphertext");
    let found = wallet.ivk().scan(&d, &outputs, ScanMode::FullFo);
    assert_eq!(found.len(), 2, "both amortized notes detected");
    assert_eq!(found[0].note, n0);
    assert_eq!(found[1].note, n1);
}
