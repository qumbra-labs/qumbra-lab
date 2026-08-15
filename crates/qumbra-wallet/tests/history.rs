//! 🔴 **The `history` ledger's acceptance**, in the same shape and at the same
//! cost as `spent_subtraction.rs` (lab issue #314's): a real chain, the
//! **deployed** discovery server, real HTTP for every wire the wallet touches,
//! the reference light-client scan, and this wallet's own key hierarchy and
//! nullifier derivation. Cheap enough to run in debug, which is the whole point
//! — the release e2e (`e2e_first_spend.rs`) is two real proves at ~12 GB peak
//! each and cannot be the only place a ledger's arithmetic is pinned.
//!
//! Stubbed: the proofs. `validate_body` never reads one, and every fact this
//! file asserts is decided by `TxPublic::nullifiers`, the committed discovery
//! groups, and the posted fee table — bytes the block commits either way. That
//! is the same deliberate trade `spent_subtraction.rs` records.
//!
//! ## The numbers, so no assertion here is magic
//!
//! The sender is granted one 10 QMB note at height 1. At height 2 it spends it:
//! 1 QMB to a stranger, 0.01 QMB posted fee, 8.99 QMB of change home. Its
//! ledger must therefore be **exactly two events** — a receipt of 10 at height
//! 1 and a send at height 2 whose `inputs 10 − change 8.99 − fee 0.01 = 1 out` —
//! and the summary must close: `in − out − fees == current spendable`
//! (10 − 1 − 0.01 == 8.99).
//!
//! A third wallet, `solo`, is granted 5 QMB at height 1 and spends the whole
//! note at height 3 with nothing coming back. That is the no-change edge: the
//! value that left is exact, and the posted fee cannot be attributed inside it.

use std::sync::{mpsc, Arc, Mutex};

use qlab_cbserver::client::{light_client_scan, Completeness, ScanConfig, ScanOutcome};
use qlab_devnet::body::{BlockBody, TxEntry, TxPublic, TxVerifier};
use qlab_devnet::fees::{posted_fee, ArityBucket};
use qlab_devnet::header::BlockHeader;
use qlab_devnet::params_devnet::GENESIS_DIFFICULTY;
use qlab_node::{coinbase, genesis_block, ChainStore, Hash32, MemNode, NodeState};
use qlab_note::kem::Ek;
use qlab_note::note::Note;
use qlab_note::scan::encrypt_to_recipient;
use qlab_wallet::seed::MasterSeed;
use qlab_wallet::Wallet;
use qumbra_node::discovery_server::{
    AnchorsView, DiscoveryServer, DiscoveryView, LeavesView, SubmitRequest,
};
use qumbra_wallet::history::{self, AddressScan, Event, Outgoing};
use qumbra_wallet::net::HttpNullifierSource;
use qumbra_wallet::sends::{SendLog, SendRecord, SENDS_FILE, SENDS_HEADER};
use qumbra_wallet::spent::{fetch_spent, note_nullifier, SpentSet};
use qumbra_wallet::view::SpentCoverage;
use rand::rngs::StdRng;
use rand::SeedableRng;

const GRANT: u64 = 1_000_000_000; // 10 QMB
const AMOUNT: u64 = 100_000_000; //  1 QMB
const SOLO_GRANT: u64 = 500_000_000; // 5 QMB

/// Fixture blocks carry proofs nothing here reads — see the module docs.
struct AnyTx;
impl TxVerifier for AnyTx {
    fn verify_tx(&self, _: &TxEntry) -> bool {
        true
    }
}

fn mine(node: &mut MemNode, tip: &mut BlockHeader, txs: Vec<TxEntry>) -> u64 {
    let height = tip.height + 1;
    let body = BlockBody { txs, coinbase: coinbase(height), coinbase_rkm: [0xBE, 0xEF, 1, 2] };
    let header = BlockHeader::child_of(tip, height * 75, GENESIS_DIFFICULTY, body.commitment());
    let hash = node.apply_block(header, body, &AnyTx).expect("block applies");
    node.finalize(hash).expect("finalize");
    *tip = header;
    height
}

/// A transaction paying `notes` to `ek` and spending `nullifiers` — the group it
/// commits IS the ML-KEM bundle those notes were encrypted under, so
/// `check_tx_discovery` has something real to bind.
fn payment(
    ek: &Ek,
    notes: &[Note],
    nullifiers: Vec<Hash32>,
    anchor: Hash32,
    rng: &mut StdRng,
) -> TxEntry {
    let enc = encrypt_to_recipient(ek, notes, rng);
    let commitments: Vec<Hash32> = enc.bundle.entries.iter().map(|e| e.cm).collect();
    TxEntry::new(
        b"proof-placeholder".to_vec(),
        TxPublic {
            anchor,
            nullifiers,
            commitments,
            bucket: ArityBucket::TwoByTwo,
            fee: posted_fee(ArityBucket::TwoByTwo),
        },
        &[enc.bundle],
        &enc.payloads,
    )
}

fn refresh(node: &MemNode, discovery: &Arc<Mutex<Arc<DiscoveryView>>>) {
    let mut view = (**discovery.lock().unwrap()).clone();
    view.refresh(node.chain());
    *discovery.lock().unwrap() = Arc::new(view);
}

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("qmb_history_{tag}"));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// One address's scan, in the shape the CLI hands `history::build`.
fn scan_one(url: &str, w: &Wallet, idx: u64, to: u64, rng: &mut StdRng) -> AddressScan {
    let kp = w.diversified_keypair(&w.diversifier_at_index(idx));
    let outcome: Result<ScanOutcome, String> =
        light_client_scan(url, &kp.dk, 0, to, ScanConfig::default(), rng).map_err(|e| e.to_string());
    AddressScan {
        div_index: idx,
        address_short: w.address_at_index(idx).short().encode(),
        outcome,
    }
}

/// 🔴 **The whole ledger, as one story over real sockets.** Grant, spend,
/// history: exactly two events, reconciling to the bessel — and the recipient
/// line in both modes, which is where the derivation boundary is visible in the
/// output itself.
#[test]
fn a_grant_and_a_spend_render_as_two_events_that_reconcile_to_the_bessel() {
    let mut rng = StdRng::from_seed([0x4C; 32]);

    let sender = Wallet::from_master_seed(&MasterSeed::from_entropy([41u8; 32]), 0);
    let recipient = Wallet::from_master_seed(&MasterSeed::from_entropy([42u8; 32]), 0);
    let sender_d = sender.diversifier_at_index(0);
    let recipient_d = recipient.diversifier_at_index(0);
    let sender_kp = sender.diversified_keypair(&sender_d);
    let recipient_kp = recipient.diversified_keypair(&recipient_d);

    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let mut tip = genesis.header();
    let mut node = MemNode::in_memory(genesis);
    let ghash = node.chain().genesis_block_hash();
    assert!(node.finalize(ghash).expect("finalize genesis").is_recorded());
    let anchor = node.commitment_root();

    // ---- height 1: the grant ----------------------------------------------
    let granted = Note {
        value: GRANT,
        rkm: sender.rkm(sender_d),
        rho: [0xA1, 0xA2, 0xA3, 0xA4],
        rseed: [0xB1, 0xB2, 0xB3, 0xB4],
    };
    let grant_height = mine(
        &mut node,
        &mut tip,
        vec![payment(
            &sender_kp.ek,
            std::slice::from_ref(&granted),
            // The grant spends somebody else's notes.
            vec![[0x77; 32], [0x78; 32]],
            anchor,
            &mut rng,
        )],
    );
    assert_eq!(grant_height, 1);

    // ---- height 2: the spend ----------------------------------------------
    let fee = posted_fee(ArityBucket::TwoByTwo);
    let change_value = GRANT - AMOUNT - fee;
    let to_recipient = Note {
        value: AMOUNT,
        rkm: recipient.rkm(recipient_d),
        rho: [0xC1, 0xC2, 0xC3, 0xC4],
        rseed: [0xD1, 0xD2, 0xD3, 0xD4],
    };
    let change = Note {
        value: change_value,
        rkm: sender.rkm(sender_d),
        rho: [0xE1, 0xE2, 0xE3, 0xE4],
        rseed: [0xF1, 0xF2, 0xF3, 0xF4],
    };
    // The nullifier the chain publishes is this wallet's OWN derivation of the
    // granted note — the same `derive_input` call `build_send` makes.
    let spent_nf = note_nullifier(&sender, 0, &granted);
    // The #219 dummy slot's nullifier: a real nullifier of an invented note,
    // belonging to nobody. It is declared on the wire and recorded locally, and
    // it must not make the ledger claim a second input.
    let dummy_nf: Hash32 = [0x99; 32];
    let spend_height = mine(
        &mut node,
        &mut tip,
        vec![
            payment(&recipient_kp.ek, &[to_recipient], vec![spent_nf, dummy_nf], anchor, &mut rng),
            payment(&sender_kp.ek, &[change], vec![[0xAB; 32], [0xAC; 32]], anchor, &mut rng),
        ],
    );
    assert_eq!(spend_height, 2);

    // ---- the deployed serving surface, over a real socket ------------------
    let discovery = Arc::new(Mutex::new(Arc::new(DiscoveryView::default())));
    refresh(&node, &discovery);
    let (submit_chan, _submit_rx) = mpsc::sync_channel::<SubmitRequest>(1);
    let server = DiscoveryServer::start(
        "127.0.0.1:0",
        Arc::clone(&discovery),
        Arc::new(Mutex::new(Arc::new(LeavesView::default()))),
        Arc::new(Mutex::new(Arc::new(AnchorsView::default()))),
        submit_chan,
    )
    .expect("bind the discovery server");
    let url = format!("http://{}", server.addr());

    // ---- the ledger, chain-only -------------------------------------------
    let scans = vec![scan_one(&url, &sender, 0, tip.height, &mut rng)];
    assert_eq!(
        scans[0].outcome.as_ref().unwrap().completeness(),
        Completeness::Complete,
        "🔴 the scan is COMPLETE — which is why an unaccounted ledger would be so convincing"
    );
    let set = fetch_spent(&HttpNullifierSource::new(&url), 0, tip.height)
        .expect("the deployed server serves its nullifier stream");
    assert_eq!(
        set.height_of(&spent_nf),
        Some(spend_height),
        "the chain's own date for this spend, off the same wire the balance uses"
    );
    let coverage = SpentCoverage::Covered { range: set.covered };
    let ledger = history::build(&sender, &scans, Some(&set), &coverage, None, (0, tip.height), Some(qumbra_wallet::ledger_run::posted_fee_2x2()));

    assert!(ledger.gaps.is_empty(), "a fully accounted ledger: {:?}", ledger.gaps);
    assert_eq!(ledger.events.len(), 2, "exactly two: the receipt and the send");

    match &ledger.events[0] {
        Event::Received(r) => {
            assert_eq!(r.height, grant_height);
            assert_eq!(r.value, GRANT);
            assert_eq!(r.div_index, 0);
            assert!(!r.shadowed);
        }
        other => panic!("the first event is the grant receipt, got {other:?}"),
    }
    let send = match &ledger.events[1] {
        Event::Send(s) => s,
        other => panic!("the second event is the send, got {other:?}"),
    };
    assert_eq!(send.height, spend_height);
    assert_eq!(send.inputs.len(), 1, "one input — the dummy slot's nullifier is nobody's note");
    assert_eq!(send.inputs[0].received_height, grant_height);
    assert_eq!(send.inputs_total, u128::from(GRANT));
    assert_eq!(send.change_total, u128::from(change_value));
    assert_eq!(
        send.outgoing,
        Outgoing::Exact { amount: u128::from(AMOUNT), fee },
        "inputs − change − posted fee, to the bessel"
    );
    assert!(send.local.is_none(), "no sends.v1: this is the chain-only mode");

    let totals = ledger.totals.clone().expect("an accounted ledger has totals");
    assert_eq!(totals.total_in, u128::from(GRANT), "the change is NOT income");
    assert_eq!(totals.total_out, u128::from(AMOUNT));
    assert_eq!(totals.fees_paid, u128::from(fee));
    assert_eq!(ledger.current_spendable, Some(u128::from(change_value)));
    assert_eq!(
        totals.total_in - totals.total_out - totals.fees_paid,
        ledger.current_spendable.unwrap(),
        "🔴 in − out − fees == current spendable"
    );

    let chain_only = history::render(&ledger, &url);
    assert!(chain_only.contains("height 1  RECEIVED"), "{chain_only}");
    assert!(chain_only.contains("height 2  SEND"), "{chain_only}");
    assert!(chain_only.contains("recipient: not recorded"), "{chain_only}");
    assert!(
        chain_only.contains("restored from a mnemonic never has one"),
        "the file's own limit travels to the person: {chain_only}"
    );
    assert!(chain_only.contains(&format!("out:       {AMOUNT} bessel")), "{chain_only}");
    assert!(
        chain_only.contains(&format!("current spendable: {change_value} bessel")),
        "{chain_only}"
    );

    // ---- the same ledger with the local record ----------------------------
    // Written through the real file, in a real wallet dir, by the same API
    // `send` calls — not a hand-built struct.
    let dir = tmp("labeled");
    let record = SendRecord {
        txid: [0x5A; 32],
        // Deliberately NOT the mined height — the join is the nullifiers, and
        // this is what a wallet actually knows at submit time.
        submitted_at_tip: spend_height - 1,
        amount: AMOUNT,
        fee,
        recipient_short: recipient.address_at_index(0).short().encode(),
        nullifiers: vec![spent_nf, dummy_nf],
    };
    SendLog::append(&dir, &record).expect("the record appends");
    let log = SendLog::load(&dir).expect("it reads back").expect("it is there");

    let labeled_ledger =
        history::build(&sender, &scans, Some(&set), &coverage, Some(&log), (0, tip.height), Some(qumbra_wallet::ledger_run::posted_fee_2x2()));
    assert_eq!(
        labeled_ledger.totals, ledger.totals,
        "🔴 local memory labels; it never moves a chain figure"
    );
    assert_eq!(labeled_ledger.current_spendable, ledger.current_spendable);
    assert_eq!(labeled_ledger.unmatched_records, 0, "the record joined its event");
    let labeled_send = match &labeled_ledger.events[1] {
        Event::Send(s) => s,
        other => panic!("still a send, got {other:?}"),
    };
    assert_eq!(labeled_send.local.as_ref(), Some(&record));
    assert!(!labeled_send.ambiguous_local);

    let labeled = history::render(&labeled_ledger, &url);
    assert!(
        labeled.contains(&format!(
            "recipient: {} (local record)",
            recipient.address_at_index(0).short().encode()
        )),
        "{labeled}"
    );
    assert!(!labeled.contains("recipient: not recorded"), "{labeled}");
    assert!(labeled.contains("(local record, submitted at node tip 1)"), "{labeled}");

    // ---- 🔴 the coverage-gap refusal, on a genuinely dead endpoint ---------
    // Nothing is listening after this, so the nullifier stream is a real
    // transport refusal rather than a mocked one — and without it the ledger
    // cannot know which notes are gone.
    server.shutdown();
    let gap = fetch_spent(&HttpNullifierSource::new(&url), 0, tip.height)
        .expect_err("a dead endpoint cannot be read");
    let refused = history::build(
        &sender,
        &scans,
        None,
        &SpentCoverage::Unavailable { why: gap.to_string() },
        Some(&log),
        (0, tip.height), Some(qumbra_wallet::ledger_run::posted_fee_2x2()));
    assert!(refused.totals.is_none(), "🔴 no totals over an unaccounted span");
    assert_eq!(refused.current_spendable, None);
    assert!(
        !refused.events.iter().any(|e| matches!(e, Event::Send(_))),
        "no send event can be derived without the chain's nullifiers"
    );
    let text = history::render(&refused, &url);
    assert!(text.contains("total out:         UNAVAILABLE"), "{text}");
    assert!(text.contains("current spendable: UNAVAILABLE"), "{text}");
    assert!(
        text.contains(&format!("spends over heights 0..={}", tip.height)),
        "the heights it could not account for are NAMED: {text}"
    );
    assert!(text.contains("this ledger is NOT complete"), "{text}");
}

/// The no-change edge, over the same real surface: a spend with nothing coming
/// back reports the whole value out and says the posted fee cannot be
/// attributed inside it, rather than guessing which part was which.
#[test]
fn a_spend_with_nothing_coming_back_names_its_fee_as_unattributable() {
    let mut rng = StdRng::from_seed([0x5D; 32]);

    let solo = Wallet::from_master_seed(&MasterSeed::from_entropy([43u8; 32]), 0);
    let stranger = Wallet::from_master_seed(&MasterSeed::from_entropy([44u8; 32]), 0);
    let solo_d = solo.diversifier_at_index(0);
    let solo_kp = solo.diversified_keypair(&solo_d);
    let stranger_kp = stranger.diversified_keypair(&stranger.diversifier_at_index(0));

    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let mut tip = genesis.header();
    let mut node = MemNode::in_memory(genesis);
    let ghash = node.chain().genesis_block_hash();
    assert!(node.finalize(ghash).expect("finalize genesis").is_recorded());
    let anchor = node.commitment_root();

    let granted = Note {
        value: SOLO_GRANT,
        rkm: solo.rkm(solo_d),
        rho: [0x51, 0x52, 0x53, 0x54],
        rseed: [0x61, 0x62, 0x63, 0x64],
    };
    let grant_height = mine(
        &mut node,
        &mut tip,
        vec![payment(&solo_kp.ek, std::slice::from_ref(&granted), vec![[0x11; 32], [0x12; 32]], anchor, &mut rng)],
    );
    mine(&mut node, &mut tip, Vec::new());
    // Everything goes out: one output, to the stranger, and no change home.
    let solo_nf = note_nullifier(&solo, 0, &granted);
    let all_out = Note {
        value: SOLO_GRANT - posted_fee(ArityBucket::TwoByTwo),
        rkm: stranger.rkm(stranger.diversifier_at_index(0)),
        rho: [0x71, 0x72, 0x73, 0x74],
        rseed: [0x81, 0x82, 0x83, 0x84],
    };
    let spend_height = mine(
        &mut node,
        &mut tip,
        vec![payment(&stranger_kp.ek, &[all_out], vec![solo_nf, [0x13; 32]], anchor, &mut rng)],
    );
    assert_eq!((grant_height, spend_height), (1, 3));

    let discovery = Arc::new(Mutex::new(Arc::new(DiscoveryView::default())));
    refresh(&node, &discovery);
    let (submit_chan, _submit_rx) = mpsc::sync_channel::<SubmitRequest>(1);
    let server = DiscoveryServer::start(
        "127.0.0.1:0",
        Arc::clone(&discovery),
        Arc::new(Mutex::new(Arc::new(LeavesView::default()))),
        Arc::new(Mutex::new(Arc::new(AnchorsView::default()))),
        submit_chan,
    )
    .expect("bind the discovery server");
    let url = format!("http://{}", server.addr());

    let scans = vec![scan_one(&url, &solo, 0, tip.height, &mut rng)];
    let set = fetch_spent(&HttpNullifierSource::new(&url), 0, tip.height).expect("the stream reads");
    let ledger = history::build(
        &solo,
        &scans,
        Some(&set),
        &SpentCoverage::Covered { range: set.covered },
        None,
        (0, tip.height), Some(qumbra_wallet::ledger_run::posted_fee_2x2()));

    assert!(ledger.gaps.is_empty(), "{:?}", ledger.gaps);
    assert_eq!(ledger.events.len(), 2);
    let send = match &ledger.events[1] {
        Event::Send(s) => s,
        other => panic!("expected the send, got {other:?}"),
    };
    assert_eq!(send.height, spend_height);
    assert!(send.change.is_empty(), "nothing came back at this height");
    assert_eq!(
        send.outgoing,
        Outgoing::FeeInseparable { amount_and_fee: u128::from(SOLO_GRANT) }
    );

    let totals = ledger.totals.clone().expect("the SUM is exact, so this ledger is accounted");
    assert_eq!(totals.total_in, u128::from(SOLO_GRANT));
    assert_eq!(totals.total_out, u128::from(SOLO_GRANT), "amount + fee together");
    assert_eq!(totals.fees_paid, 0, "no fee is attributed…");
    assert_eq!(totals.fee_inseparable_events, 1, "…and the report says so");
    assert_eq!(ledger.current_spendable, Some(0));

    let text = history::render(&ledger, &url);
    assert!(text.contains("change:    none at this height"), "{text}");
    assert!(text.contains("amount AND fee together"), "{text}");
    assert!(text.contains("cannot be attributed inside it"), "{text}");
    assert!(text.contains("current spendable: 0 bessel"), "{text}");

    server.shutdown();
}

/// The local file's two degradations, on a real wallet dir: an ABSENT
/// `sends.v1` (every wallet today, and every wallet restored from a mnemonic)
/// is an ordinary state, and an UNREADABLE one is refused by name rather than
/// half-believed.
#[test]
fn an_absent_sends_file_degrades_cleanly_and_an_unknown_one_is_refused() {
    let dir = tmp("degrade");

    // Absent: `None`, not an error, and `history` renders chain-only from it.
    assert!(SendLog::load(&dir).expect("an absent file is not a failure").is_none());

    // Unknown version: refused, with the safe fix named. The ledger's own
    // recovery is that it needs nothing from this file at all.
    std::fs::write(dir.join(SENDS_FILE), "qumbra-wallet sends v2\n").unwrap();
    let e = SendLog::load(&dir).expect_err("an unknown header is refused");
    let msg = e.to_string();
    assert!(msg.contains(SENDS_HEADER), "{msg}");
    assert!(msg.contains("no funds are at stake"), "{msg}");

    // Unknown field in an otherwise well-formed record: refused too — a
    // half-read send log would put a confident recipient on the wrong event.
    std::fs::write(
        dir.join(SENDS_FILE),
        format!(
            "{SENDS_HEADER}\nsend txid={} tip=4 amount=5 fee=6 to=qmbs1x nf={} memo=lunch\n",
            "0a".repeat(32),
            "0b".repeat(32)
        ),
    )
    .unwrap();
    let msg = SendLog::load(&dir).expect_err("an unknown field is refused").to_string();
    assert!(msg.contains("unknown field `memo`"), "{msg}");

    // And the same file without the unknown field reads back exactly.
    std::fs::write(
        dir.join(SENDS_FILE),
        format!(
            "{SENDS_HEADER}\nsend txid={} tip=4 amount=5 fee=6 to=qmbs1x nf={}\n",
            "0a".repeat(32),
            "0b".repeat(32)
        ),
    )
    .unwrap();
    let log = SendLog::load(&dir).unwrap().unwrap();
    assert_eq!(log.records.len(), 1);
    assert_eq!(log.records[0].recipient_short, "qmbs1x");
    assert_eq!(log.matching(&[[0x0b; 32]]).len(), 1, "the join is those bytes");

    // A ledger with no events at all still renders, and still says the file is
    // the only reason a recipient could ever appear.
    let w = Wallet::from_master_seed(&MasterSeed::from_entropy([45u8; 32]), 0);
    let empty: Vec<AddressScan> = Vec::new();
    let ledger = history::build(
        &w,
        &empty,
        Some(&SpentSet::from_parts(Some((0, 5)), [])),
        &SpentCoverage::Covered { range: Some((0, 5)) },
        Some(&log),
        (0, 5), Some(qumbra_wallet::ledger_run::posted_fee_2x2()));
    let text = history::render(&ledger, "http://edge");
    assert!(text.contains("no events"), "{text}");
    assert!(text.contains("joined no event in this range"), "the orphan record is stated: {text}");
}
