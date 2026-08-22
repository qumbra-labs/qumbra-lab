//! 🔴 **Lab issue #314's acceptance, end to end and cheap enough to run in
//! debug**: a note this wallet spent stops being spendable, over real sockets,
//! against the deployed serving code.
//!
//! ## What is real here and what is stubbed, and why that split
//!
//! Real: the chain (a `MemNode` with its own block store), the **deployed**
//! discovery server (`qumbra_node::discovery_server::DiscoveryServer`, the same
//! type the binary starts), all three wires the wallet uses over real HTTP
//! (`/v1/compact`, `/v1/block/../full`, `/v1/nullifiers`), the reference
//! light-client scan, and this wallet's own key hierarchy and nullifier
//! derivation.
//!
//! Stubbed: the proofs. `validate_body` never reads one, and the subtraction
//! this test is about is decided entirely by `TxPublic::nullifiers` — bytes the
//! block commits either way. The real-prove path is covered by
//! `e2e_first_spend.rs`, which is release-only at ~12 GB per prove; putting a
//! second and third prove here would buy nothing this file asserts and would
//! make the one test that pins #314's behaviour unrunnable outside the rig lock.
//! That is a deliberate trade and it is the same one `recipient_scan.rs` records.
//!
//! ## The numbers, so the assertions are not magic
//!
//! One 10 QMB note is granted to the sender. It spends 1 QMB with a 0.01 QMB
//! posted fee, so 8.99 QMB comes back as change. The sender's spendable must
//! therefore fall by exactly `spent note − change` = 1.01 QMB, and the
//! recipient's must rise by exactly 1 QMB. Those are the live issue's own
//! proportions (its sender held four 10 QMB grants and over-quoted by exactly
//! one of them).

use std::sync::{mpsc, Arc, Mutex};

use qlab_cbserver::client::{light_client_scan, Completeness, ScanConfig};
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
use qumbra_wallet::net::HttpNullifierSource;
use qumbra_wallet::spent::{fetch_spent, note_nullifier, subtract_spent, SpentRefusal};
use rand::rngs::StdRng;
use rand::SeedableRng;

const GRANT: u64 = 1_000_000_000; // 10 QMB
const AMOUNT: u64 = 100_000_000; //  1 QMB

/// Fixture blocks carry proofs nothing here reads — see the module docs.
struct AnyTx;
impl TxVerifier for AnyTx {
    fn verify_tx(&self, _: &TxEntry) -> bool {
        true
    }
}

fn mine(node: &mut MemNode, tip: &mut BlockHeader, txs: Vec<TxEntry>) -> u64 {
    let height = tip.height + 1;
    let body = BlockBody::from_single_payee(txs, coinbase(height), [0xBE, 0xEF, 1, 2]);
    let header = BlockHeader::child_of(tip, height * 75, GENESIS_DIFFICULTY, body.commitment());
    let hash = node.apply_block(header, body, &AnyTx).expect("block applies");
    node.finalize(hash).expect("finalize");
    *tip = header;
    height
}

/// A transaction paying `notes` to `ek` and spending `nullifiers` — the group it
/// commits IS the ML-KEM bundle those notes were encrypted under, so
/// `check_tx_discovery` has something real to bind (the `recipient_scan.rs`
/// construction).
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

/// 🔴 The whole issue, as one story: the sender's spendable DROPS by exactly
/// `spent note − change` after it spends, and the recipient's RISES by exactly
/// the amount — while a wallet that never spent is untouched by any of it.
#[test]
fn a_spent_note_stops_being_spendable_and_the_recipient_gains() {
    let mut rng = StdRng::from_seed([0x31; 32]);

    let sender = Wallet::from_master_seed(&MasterSeed::from_entropy([21u8; 32]), 0);
    let recipient = Wallet::from_master_seed(&MasterSeed::from_entropy([22u8; 32]), 0);
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

    // ---- the grant: one 10 QMB note to the sender -------------------------
    let granted = Note {
        value: GRANT,
        rkm: sender.rkm(sender_d),
        rho: [0xA1, 0xA2, 0xA3, 0xA4],
        rseed: [0xB1, 0xB2, 0xB3, 0xB4],
    };
    // The grant spends somebody else's notes; those nullifiers are nothing to do
    // with this wallet and must not match anything it holds.
    let grant_height = mine(
        &mut node,
        &mut tip,
        vec![payment(&sender_kp.ek, &[granted.clone()], vec![[0x77; 32], [0x78; 32]], anchor, &mut rng)],
    );

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

    // ---- before the spend: 10 QMB, and the subtraction is a no-op ----------
    let before = light_client_scan(&url, &sender_kp.dk, 0, tip.height, ScanConfig::default(), &mut rng)
        .expect("the scan runs");
    assert_eq!(before.completeness(), Completeness::Complete);
    assert_eq!(before.notes.len(), 1, "the sender detects the grant");
    assert_eq!(before.notes[0].detected.note.value, GRANT);
    assert_eq!(
        before.stats.compact_range_served,
        Some((0, tip.height)),
        "the height range the outputs actually came from"
    );

    let set = fetch_spent(&HttpNullifierSource::new(&url), 0, tip.height)
        .expect("the node serves its nullifier stream");
    assert_eq!(set.covered, Some((0, tip.height)));
    assert!(set.covers_outputs(before.stats.compact_range_served).is_ok());
    assert!(
        set.contains(&[0x77; 32]),
        "the stream carries the chain's nullifiers verbatim, including strangers'"
    );
    let report = subtract_spent(&sender, 0, &before.notes, &set);
    assert_eq!(report.spendable_value(), u128::from(GRANT), "nothing of this wallet's is spent yet");
    assert!(report.spent.is_empty());

    // ---- the spend: 1 QMB out, 0.01 fee, 8.99 change home ------------------
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
    // 🔴 The nullifier the chain publishes is THIS wallet's own derivation of
    // the granted note — the same `derive_input` call `build_send` makes when it
    // really spends. If the balance's derivation ever drifted from the spend's,
    // this is the assertion that would go red.
    let spent_nf = note_nullifier(&sender, 0, &granted);
    let spend_height = mine(
        &mut node,
        &mut tip,
        vec![
            payment(&recipient_kp.ek, &[to_recipient.clone()], vec![spent_nf, [0x99; 32]], anchor, &mut rng),
            payment(&sender_kp.ek, &[change.clone()], vec![[0xAB; 32], [0xAC; 32]], anchor, &mut rng),
        ],
    );
    assert_eq!(spend_height, grant_height + 1);
    refresh(&node, &discovery);

    // ---- after: the sender's spendable DROPS by (spent note − change) ------
    let after = light_client_scan(&url, &sender_kp.dk, 0, tip.height, ScanConfig::default(), &mut rng)
        .expect("the rescan runs");
    assert_eq!(
        after.completeness(),
        Completeness::Complete,
        "🔴 the scan is COMPLETE — which is exactly why an unsubtracted figure was so convincing"
    );
    assert_eq!(after.notes.len(), 2, "the scan alone still sees the grant AND the change");
    assert_eq!(
        after.spendable_value(),
        u128::from(GRANT + change_value),
        "🔴 the pre-#314 number: the spent note still counted, under `complete`"
    );

    let set = fetch_spent(&HttpNullifierSource::new(&url), 0, tip.height)
        .expect("the node serves the spend's nullifiers too");
    set.covers_outputs(after.stats.compact_range_served).expect("covered to the outputs' tip");
    let report = subtract_spent(&sender, 0, &after.notes, &set);

    assert_eq!(report.spent.len(), 1, "exactly the note that was spent");
    assert_eq!(report.spent[0].note.detected.note.rho, granted.rho);
    assert_eq!(report.spent[0].nullifier, spent_nf, "matched on the chain's own bytes");
    assert_eq!(report.spendable_value(), u128::from(change_value), "only the change survives");
    assert_eq!(
        report.spendable_value() + u128::from(GRANT - change_value),
        u128::from(GRANT),
        "the drop is exactly (spent note − change) = amount + fee"
    );
    assert_eq!(u128::from(GRANT) - report.spendable_value(), u128::from(AMOUNT + fee));

    // ---- and the recipient RISES by exactly the amount, subtracting nothing -
    let got = light_client_scan(&url, &recipient_kp.dk, 0, tip.height, ScanConfig::default(), &mut rng)
        .expect("the recipient's scan runs");
    assert_eq!(got.notes.len(), 1);
    let got_report = subtract_spent(&recipient, 0, &got.notes, &set);
    assert_eq!(got_report.spendable_value(), u128::from(AMOUNT));
    assert!(
        got_report.spent.is_empty(),
        "🔴 the negative: a wallet that never spent is unchanged by the new subtraction"
    );

    // ---- honesty: no stream ⇒ no figure, with a reason ---------------------
    // The same shape as a node that predates this route (it answers 404) or one
    // that is simply down. Taken by shutting the server: nothing is listening,
    // so this is a genuine transport refusal and not a mocked one.
    server.shutdown();
    let refusal = fetch_spent(&HttpNullifierSource::new(&url), 0, tip.height)
        .expect_err("a dead endpoint cannot be read");
    assert!(matches!(refusal, SpentRefusal::Endpoint { .. }), "{refusal}");
    assert!(
        refusal.to_string().contains("not quotable"),
        "the refusal says why a balance may not be printed: {refusal}"
    );
}
