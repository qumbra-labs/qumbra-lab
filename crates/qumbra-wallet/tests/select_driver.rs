//! The caller-pumped phase-1 driver's own pins (lab #399) — the #358 test
//! discipline applied to selection: suspension across separately invoked
//! steps, misuse as a fault, transport failure and garbage as NAMED refusals,
//! and the verdict gate that supplying outcomes must not make skippable.
//!
//! The fixture is `select_goldens.rs`'s (each test file carries its own —
//! house pattern): a real chain in a `MemNode`, the deployed `DiscoveryServer`
//! over a real socket, no STARK anywhere, debug-runnable.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{mpsc, Arc, Mutex};

use qlab_cbserver::client::{light_client_scan, ScanConfig, ScanOutcome, Unopened, UnopenedOutput};
use qlab_note::kem::Dk;
use qlab_cbserver::tree::CommitmentTree;
use qlab_devnet::body::{BlockBody, TxEntry, TxPublic, TxVerifier};
use qlab_devnet::fees::{posted_fee, ArityBucket};
use qlab_devnet::forms::GenesisForm;
use qlab_devnet::header::BlockHeader;
use qlab_devnet::params_devnet::GENESIS_DIFFICULTY;
use qlab_node::{anchor_set, coinbase, genesis_block, ChainStore, Hash32, MemNode, NodeState};
use qlab_note::kem::Ek;
use qlab_note::note::Note;
use qlab_note::scan::encrypt_to_recipient;
use qlab_wallet::seed::MasterSeed;
use qlab_wallet::Wallet;
use qumbra_node::discovery_server::{
    AnchorsView, DiscoveryServer, DiscoveryView, LeavesView, SubmitRequest,
};
use qumbra_wallet::bundle::WitnessBundle;
use qumbra_wallet::driver::{SelectDriver, SelectStep};
use qumbra_wallet::spend::SendStep;
use rand::rngs::StdRng;
use rand::SeedableRng;

const GRANT: u64 = 1_000_000_000; // 10 QMB
const AMOUNT: u64 = 100_000_000; //  1 QMB

struct AnyTx;
impl TxVerifier for AnyTx {
    fn verify_tx(&self, _: &TxEntry) -> bool {
        true
    }
}

fn mine(node: &mut MemNode, tip: &mut BlockHeader, txs: Vec<TxEntry>) -> u64 {
    mine_paying(node, tip, txs, [0xBE, 0xEF, 1, 2])
}

fn mine_paying(
    node: &mut MemNode,
    tip: &mut BlockHeader,
    txs: Vec<TxEntry>,
    rkm: [u64; 4],
) -> u64 {
    let height = tip.height + 1;
    let body = BlockBody { txs, coinbase: coinbase(height), coinbase_rkm: rkm };
    let header = BlockHeader::child_of(tip, height * 75, GENESIS_DIFFICULTY, body.commitment());
    let hash = node.apply_block(header, body, &AnyTx).expect("block applies");
    node.finalize(hash).expect("finalize");
    *tip = header;
    height
}

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

/// A minimal one-shot GET, body only — the pump's transport in these tests.
fn get(base: &str, path: &str) -> Result<Vec<u8>, String> {
    let host = base.trim_start_matches("http://");
    let mut s = TcpStream::connect(host).map_err(|e| e.to_string())?;
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes())
        .map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).map_err(|e| e.to_string())?;
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("no header/body split")?;
    Ok(raw[split + 4..].to_vec())
}

struct Fixture {
    url: String,
    wallet: Wallet,
    recipient: qlab_wallet::address::Address,
    dk: Dk,
    to: u64,
    _server: DiscoveryServer,
}

impl Fixture {
    /// A fresh completed scan — `ScanOutcome` is deliberately not `Clone`.
    fn outcomes(&self) -> Vec<(u64, ScanOutcome)> {
        self.outcomes_finding(1)
    }

    /// The same, for a chain that paid this wallet no TRANSACTION at all — a
    /// mining-only wallet's scan is `Complete` with zero notes, which is the
    /// state lab #424 exists for.
    fn outcomes_finding(&self, notes: usize) -> Vec<(u64, ScanOutcome)> {
        let mut rng = StdRng::from_seed([0x77; 32]);
        let outcome =
            light_client_scan(&self.url, &self.dk, 0, self.to, ScanConfig::default(), &mut rng)
                .expect("the fixture scan runs");
        assert_eq!(outcome.notes.len(), notes, "the fixture's transaction outputs");
        vec![(0, outcome)]
    }
}

fn fixture() -> Fixture {
    let mut rng = StdRng::from_seed([0x55; 32]);
    let sender = Wallet::from_master_seed(&MasterSeed::from_entropy([41u8; 32]), 0);
    let recipient = Wallet::from_master_seed(&MasterSeed::from_entropy([42u8; 32]), 0);
    let sender_d = sender.diversifier_at_index(0);
    let sender_kp = sender.diversified_keypair(&sender_d);

    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let mut tip = genesis.header();
    let mut node = MemNode::in_memory(genesis);
    let ghash = node.chain().genesis_block_hash();
    assert!(node.finalize(ghash).expect("finalize genesis").is_recorded());
    let anchor0 = node.commitment_root();

    let granted = Note {
        value: GRANT,
        rkm: sender.rkm(sender_d),
        rho: [0xC1, 0xC2, 0xC3, 0xC4],
        rseed: [0xD1, 0xD2, 0xD3, 0xD4],
    };
    mine(
        &mut node,
        &mut tip,
        vec![payment(&sender_kp.ek, &[granted], vec![[0x71; 32], [0x72; 32]], anchor0, &mut rng)],
    );
    mine(&mut node, &mut tip, vec![]);

    serve(node, tip.height, sender, recipient.address_at_index(0), sender_kp.dk)
}

/// Publish a mined chain over the deployed discovery server — the same three
/// read projections `RunningNode` republishes, including the `/v1/coinbase`
/// facts (lab #415) that `DiscoveryView::refresh` carries.
fn serve(
    node: MemNode,
    to: u64,
    wallet: Wallet,
    recipient: qlab_wallet::address::Address,
    dk: Dk,
) -> Fixture {
    let discovery = Arc::new(Mutex::new(Arc::new(DiscoveryView::default())));
    let leaves_view = Arc::new(Mutex::new(Arc::new(LeavesView::default())));
    let anchors_view = Arc::new(Mutex::new(Arc::new(AnchorsView::default())));
    {
        let mut view = DiscoveryView::default();
        view.refresh(node.chain());
        *discovery.lock().unwrap() = Arc::new(view);
        *leaves_view.lock().unwrap() =
            Arc::new(LeavesView { leaves: node.commitments_ordered().to_vec() });
        *anchors_view.lock().unwrap() = Arc::new(AnchorsView { encoded: anchor_set(&node).to_bytes() });
    }
    let (submit_chan, _rx) = mpsc::sync_channel::<SubmitRequest>(1);
    let server = DiscoveryServer::start(
        "127.0.0.1:0",
        discovery,
        leaves_view,
        anchors_view,
        submit_chan,
    )
    .expect("bind");
    let url = format!("http://{}", server.addr());

    Fixture { url, wallet, recipient, dk, to, _server: server }
}

fn new_driver(f: &Fixture) -> SelectDriver {
    SelectDriver::new(
        f.wallet.clone(),
        f.recipient.clone(),
        AMOUNT,
        None,
        f.outcomes(),
        CommitmentTree::new(),
        f.to,
        GenesisForm::V4,
    )
}

/// The whole point of the inversion: every `Need` can be answered in a
/// separately invoked call, with the driver (and the caller's rng) suspended
/// in between — and the bundle that comes out carries the right facts.
#[test]
fn the_driver_survives_suspension_between_separately_invoked_steps() {
    let f = fixture();
    let mut driver = new_driver(&f);
    let mut rng = StdRng::from_seed([0x66; 32]);

    let mut hops = 0usize;
    let bundle = loop {
        match driver.step(&mut rng) {
            SelectStep::Need { path, .. } => {
                hops += 1;
                assert!(hops < 64, "the pump does not converge");
                // Each response arrives in its own call — the suspension shape.
                driver.supply(get(&f.url, &path));
            }
            SelectStep::Done(bundle) => break bundle,
            SelectStep::Failed(e) => panic!("phase 1 failed: {e}"),
        }
    };
    assert_eq!(bundle.amount(), AMOUNT);
    assert_eq!(bundle.fee(), posted_fee(ArityBucket::TwoByTwo));
    assert_eq!(bundle.change_value(), GRANT - AMOUNT - bundle.fee());
    assert!(bundle.used_dummy());
    assert_eq!(bundle.recipient_short(), f.recipient.short().encode());
    assert!(driver.tree().is_some(), "the caught-up tree is exposed for the caller's cache");
}

/// A response nobody asked for is a fault, not a scan — the driver's own rule,
/// same as the scan driver's.
#[test]
fn an_unrequested_response_is_a_fault() {
    let f = fixture();
    let mut driver = new_driver(&f);
    let mut rng = StdRng::from_seed([0x66; 32]);
    driver.supply(Ok(b"unrequested".to_vec()));
    match driver.step(&mut rng) {
        SelectStep::Failed(e) => assert!(e.contains("without requesting"), "{e}"),
        _ => panic!("an unrequested response must be a fault"),
    }
}

/// A transport failure surfaces as the same named refusal the synchronous
/// flow produces — never a silent stop.
#[test]
fn a_transport_failure_is_the_named_refusal() {
    let f = fixture();
    let mut driver = new_driver(&f);
    let mut rng = StdRng::from_seed([0x66; 32]);
    let SelectStep::Need { path, .. } = driver.step(&mut rng) else {
        panic!("the first step asks for the nullifier stream")
    };
    assert!(path.starts_with("/v1/nullifiers"), "{path}");
    driver.supply(Err("the network is unreachable".into()));
    match driver.step(&mut rng) {
        SelectStep::Failed(e) => {
            assert!(e.contains("GET /v1/nullifiers"), "{e}");
            assert!(
                e.contains("refusing to select inputs this wallet may already have spent"),
                "{e}"
            );
        }
        _ => panic!("a dead endpoint must fail by name"),
    }
}

/// 200-with-garbage is refused as a decode failure by name, not believed.
#[test]
fn garbage_bytes_fail_by_name() {
    let f = fixture();
    let mut driver = new_driver(&f);
    let mut rng = StdRng::from_seed([0x66; 32]);
    let SelectStep::Need { .. } = driver.step(&mut rng) else { panic!("need first") };
    driver.supply(Ok(b"<html>404 not found</html>".to_vec()));
    match driver.step(&mut rng) {
        SelectStep::Failed(e) => assert!(e.contains("did not decode"), "{e}"),
        _ => panic!("garbage must be refused"),
    }
}

/// Handing outcomes to the driver must NOT make the partial-knowledge refusal
/// skippable: an Incomplete scan is refused before a single byte is fetched.
#[test]
fn the_verdict_gate_is_not_skippable() {
    let f = fixture();
    let mut incomplete = f.outcomes();
    incomplete[0].1.unopened.push(UnopenedOutput {
        height: 1,
        tx_index: 0,
        recipient_index: 0,
        output_index: 1,
        cm: [0u8; 32],
        why: Unopened::PayloadMissing,
    });
    let mut driver = SelectDriver::new(
        f.wallet.clone(),
        f.recipient.clone(),
        AMOUNT,
        None,
        incomplete,
        CommitmentTree::new(),
        f.to,
        GenesisForm::V4,
    );
    let mut rng = StdRng::from_seed([0x66; 32]);
    match driver.step(&mut rng) {
        SelectStep::Failed(e) => {
            assert!(e.contains("refusing to build a spend on partial knowledge"), "{e}")
        }
        _ => panic!("an incomplete scan must refuse before any fetch"),
    }
}

/* --- lab #424: selection learns coinbase, and the 404 posture ------------- */

/// What the pump does with `GET /v1/coinbase` — [`Coinbase::NotFound`] is every
/// node older than lab #415, which is most of them.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Coinbase {
    Served,
    NotFound,
}

/// Run a driver to its terminal step, answering every path off the fixture's
/// real socket except a 404'd coinbase route. Returns the outcome, every event
/// the driver narrated, and every path it asked for.
fn pump(
    f: &Fixture,
    driver: &mut SelectDriver,
    coinbase: Coinbase,
) -> (Result<Box<WitnessBundle>, String>, Vec<SendStep>, Vec<String>) {
    let mut rng = StdRng::from_seed([0x66; 32]);
    let (mut events, mut asked) = (Vec::new(), Vec::new());
    let mut hops = 0usize;
    loop {
        let step = driver.step(&mut rng);
        events.extend(driver.take_events());
        match step {
            SelectStep::Need { path, .. } => {
                hops += 1;
                assert!(hops < 512, "the pump does not converge");
                asked.push(path.clone());
                if path.starts_with("/v1/coinbase") && coinbase == Coinbase::NotFound {
                    driver.supply(Err("non-200 response: HTTP 404".into()));
                } else {
                    driver.supply(get(&f.url, &path));
                }
            }
            SelectStep::Done(b) => return (Ok(b), events, asked),
            SelectStep::Failed(e) => return (Err(e), events, asked),
        }
    }
}

/// A **mining-only** wallet's chain: every block 1..=`last` pays this wallet's
/// own `rkm`, nothing ever paid it a transaction, and every block is finalized
/// so a matured coinbase leaf is inside a valid anchor. This is the wallet lab
/// #424 exists for — `scan` called its balance non-zero and `send` refused
/// "no spendable notes" one line below it.
fn mining_fixture(last: u64) -> Fixture {
    let miner = Wallet::from_master_seed(&MasterSeed::from_entropy([0x5B; 32]), 0);
    let stranger = Wallet::from_master_seed(&MasterSeed::from_entropy([0x5C; 32]), 0);
    let d = miner.diversifier_at_index(0);
    let rkm = miner.rkm(d);

    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let mut tip = genesis.header();
    let mut node = MemNode::in_memory(genesis);
    let ghash = node.chain().genesis_block_hash();
    assert!(node.finalize(ghash).expect("finalize genesis").is_recorded());
    for _ in 0..last {
        mine_paying(&mut node, &mut tip, Vec::new(), rkm);
    }
    assert_eq!(tip.height, last);

    let dk = miner.diversified_keypair(&d).dk;
    serve(node, tip.height, miner, stranger.address_at_index(0), dk)
}

/// The height at which block 1's coinbase leaf appears — `qlab_node`'s own
/// schedule, never a copy of 144 here.
fn matures_at() -> u64 {
    qlab_node::coinbase_leaf_appears_at(1)
}

/// This wallet's own nullifier for the coinbase note block `height` minted,
/// derived through the spend path's derivation over the applier's own note.
fn mined_nullifier(f: &Fixture, height: u64) -> [u8; 32] {
    let rkm = f.wallet.rkm(f.wallet.diversifier_at_index(0));
    let body = BlockBody { txs: Vec::new(), coinbase: coinbase(height), coinbase_rkm: rkm };
    let note = qlab_node::coinbase_note(height, &body).expect("that block minted");
    qumbra_wallet::spent::note_nullifier(&f.wallet, 0, &note)
}

/// 🔴 **The headline of lab #424: a mining-only wallet's `send` selects a
/// MATURED coinbase note.** Before this the driver's input set was
/// `ScanOutcome::notes` alone and this wallet — which owns every block on its
/// chain — refused with "no spendable notes".
///
/// The note is not asserted by shape: the bundle's real nullifier is compared
/// against the one derived from `qlab_node::coinbase_note`, the applier's own
/// derivation, so what got selected is provably block 1's coinbase and not
/// something that merely has the right value.
#[test]
fn a_mining_only_wallet_selects_its_matured_coinbase_note() {
    let at = matures_at();
    let f = mining_fixture(at);
    let mut driver = SelectDriver::new(
        f.wallet.clone(),
        f.recipient.clone(),
        AMOUNT,
        None,
        f.outcomes_finding(0),
        CommitmentTree::new(),
        f.to,
        GenesisForm::V4,
    );
    let (outcome, events, asked) = pump(&f, &mut driver, Coinbase::Served);
    let bundle = outcome.unwrap_or_else(|e| panic!("a matured coinbase must be spendable: {e}"));

    assert!(
        asked.iter().any(|p| p.starts_with("/v1/coinbase")),
        "the coinbase stream is part of selection now: {asked:?}"
    );
    // Exactly ONE note is selectable: block 1's. Blocks 2..=at are mined by this
    // same wallet and are all still maturing — real money it owns and cannot
    // spend, which must never reach a witness.
    match events.iter().find(|e| matches!(e, SendStep::Selected { .. })) {
        Some(SendStep::Selected { spendable, mined, .. }) => {
            assert_eq!((*spendable, *mined), (1, 1), "one input, and it is a mined one");
        }
        other => panic!("selection must narrate: {other:?}"),
    }
    assert!(
        !events.iter().any(|e| matches!(e, SendStep::CoinbaseUnavailable { .. })),
        "a served route degrades nothing"
    );
    assert!(
        bundle.real_nullifiers().contains(&mined_nullifier(&f, 1)),
        "the selected input IS block 1's coinbase note"
    );
    assert!(bundle.used_dummy(), "one real note ⇒ the #219 dummy slot");
    assert_eq!(bundle.amount(), AMOUNT);
}

/// 🔴 **Acceptance (d): the maturity boundary, at exactly one block.** At tip
/// `144 + 1 - 1` block 1's leaf does not exist and nothing is selectable; at
/// `144 + 1` it does and the same wallet spends. The threshold is
/// `qlab_node::coinbase_leaf_appears_at`'s, not a copy of it.
///
/// The refusal on the short side is the issue-body's item 3: it distinguishes
/// *you do not have it* from *you have it and it matures at height N*.
#[test]
fn a_maturing_mined_note_is_never_selectable_and_the_refusal_says_when() {
    let at = matures_at();

    // One block short: the leaf has not been appended.
    let early = mining_fixture(at - 1);
    let mut driver = SelectDriver::new(
        early.wallet.clone(),
        early.recipient.clone(),
        AMOUNT,
        None,
        early.outcomes_finding(0),
        CommitmentTree::new(),
        early.to,
        GenesisForm::V4,
    );
    let (outcome, _, _) = pump(&early, &mut driver, Coinbase::Served);
    let why = outcome.err().expect("nothing has matured yet");
    assert!(why.contains("no spendable notes"), "{why}");
    assert!(why.contains("Coinbase WAS visible"), "the refusal is not a bare zero: {why}");
    assert!(
        why.contains(&format!("matures at height {at}")),
        "it says WHEN, which is a miner's second question: {why}"
    );
    assert!(
        !why.contains("TRANSACTIONS ONLY"),
        "coinbase WAS visible here — naming a degradation would be a lie: {why}"
    );

    // …and exactly one block later the same wallet spends the same note.
    let ready = mining_fixture(at);
    let mut driver = SelectDriver::new(
        ready.wallet.clone(),
        ready.recipient.clone(),
        AMOUNT,
        None,
        ready.outcomes_finding(0),
        CommitmentTree::new(),
        ready.to,
        GenesisForm::V4,
    );
    let (outcome, _, _) = pump(&ready, &mut driver, Coinbase::Served);
    let bundle = outcome.unwrap_or_else(|e| panic!("at maturity the leaf exists: {e}"));
    assert!(bundle.real_nullifiers().contains(&mined_nullifier(&ready, 1)));
}

/// 🔴 **Acceptance (b), and the whole of Larry's 2026-08-16 ruling: a 404 on
/// `/v1/coinbase` does NOT refuse the send.** It proceeds on the transaction
/// notes it does have, and says so loudly with the same `TRANSACTIONS ONLY`
/// token the scan's balance line prints.
///
/// The alternative — refusing, symmetric with the nullifier stream — would stop
/// `send` working against every node not yet rolled to lab #415, including for
/// wallets that have never mined. The grounds for not doing that are the safety
/// shape: a missing coinbase source only SHRINKS the input set.
#[test]
fn a_404_on_the_coinbase_route_degrades_loudly_and_the_send_proceeds() {
    let f = fixture();
    let mut driver = new_driver(&f);
    let (outcome, events, asked) = pump(&f, &mut driver, Coinbase::NotFound);

    let bundle = outcome.unwrap_or_else(|e| panic!("a 404 must NOT refuse the send: {e}"));
    assert_eq!(bundle.amount(), AMOUNT, "the transaction note still pays");
    assert!(asked.iter().any(|p| p.starts_with("/v1/coinbase")), "{asked:?}");

    let degraded = events
        .iter()
        .find_map(|e| match e {
            SendStep::CoinbaseUnavailable { why } => Some(why.clone()),
            _ => None,
        })
        .expect("the degradation is VISIBLE on the send path, not silent");
    assert!(degraded.contains("TRANSACTIONS ONLY"), "the shared token: {degraded}");
    assert!(degraded.contains("404"), "carrying the endpoint's own words: {degraded}");
    match events.iter().find(|e| matches!(e, SendStep::Selected { .. })) {
        Some(SendStep::Selected { mined, .. }) => assert_eq!(*mined, 0),
        other => panic!("selection must still narrate: {other:?}"),
    }
    // And the CLI/desktop wording carries it too — a degradation that only one
    // surface prints is a degradation the other surface hides.
    assert!(qumbra_wallet::words::word_for(
        &SendStep::CoinbaseUnavailable { why: degraded }
    )
    .contains("TRANSACTIONS ONLY"));
}

/// 🔴 **Acceptance (c), the guardrail that makes the ruling safe to live
/// with: an insufficient-funds refusal out of the SHRUNK set is
/// distinguishable from a true low balance.** Same wallet, same chain, same
/// impossible amount — the only difference is whether the coinbase route
/// answered, and the two refusals must not read alike, because only one of them
/// is changed by rolling the node.
#[test]
fn insufficient_funds_names_the_coinbase_gap_only_when_coinbase_was_invisible() {
    let f = fixture();
    let unaffordable = GRANT * 100;

    let mut visible = SelectDriver::new(
        f.wallet.clone(),
        f.recipient.clone(),
        unaffordable,
        None,
        f.outcomes(),
        CommitmentTree::new(),
        f.to,
        GenesisForm::V4,
    );
    let (seen, _, _) = pump(&f, &mut visible, Coinbase::Served);
    let seen = seen.err().expect("10 QMB cannot cover 1000");

    let mut blind = SelectDriver::new(
        f.wallet.clone(),
        f.recipient.clone(),
        unaffordable,
        None,
        f.outcomes(),
        CommitmentTree::new(),
        f.to,
        GenesisForm::V4,
    );
    let (unseen, _, _) = pump(&f, &mut blind, Coinbase::NotFound);
    let unseen = unseen.err().expect("still cannot cover it");

    for why in [&seen, &unseen] {
        assert!(why.contains("cannot cover"), "both are value shortfalls: {why}");
    }
    assert!(
        !seen.contains("TRANSACTIONS ONLY"),
        "coinbase WAS visible — this really is all the money there is: {seen}"
    );
    assert!(
        unseen.contains("TRANSACTIONS ONLY"),
        "coinbase was NOT visible — the user must know a seed roll changes the answer: {unseen}"
    );
    assert!(
        unseen.contains("NOT evidence that the balance is too low"),
        "and must know what that means: {unseen}"
    );
}

/// A coinbase stream that ANSWERS but lies about its own range is the same
/// named degradation as an absent one, not a refusal — the position taken on
/// lab #424 before the build. The grounds: every mined note is re-verified
/// downstream (a wrong value derives a `cm` that is in no tree; a note faked
/// into looking mature has no leaf inside the anchor), so a lying server can
/// shrink the input set and no more. Refusing would hand any node that serves a
/// bad page a switch to stop this wallet's sends.
#[test]
fn a_malformed_coinbase_page_degrades_rather_than_refusing() {
    let f = fixture();
    let mut driver = new_driver(&f);
    let mut rng = StdRng::from_seed([0x66; 32]);
    let (mut events, mut hops) = (Vec::new(), 0usize);
    let bundle = loop {
        let step = driver.step(&mut rng);
        events.extend(driver.take_events());
        match step {
            SelectStep::Need { path, .. } => {
                hops += 1;
                assert!(hops < 64, "the pump does not converge");
                if path.starts_with("/v1/coinbase") {
                    // 200 with bytes that are not a CoinbasePage.
                    driver.supply(Ok(b"<html>i am a proxy</html>".to_vec()));
                } else {
                    driver.supply(get(&f.url, &path));
                }
            }
            SelectStep::Done(b) => break b,
            SelectStep::Failed(e) => panic!("a lying coinbase server must not stop a send: {e}"),
        }
    };
    assert_eq!(bundle.amount(), AMOUNT);
    let degraded = events
        .iter()
        .find_map(|e| match e {
            SendStep::CoinbaseUnavailable { why } => Some(why.clone()),
            _ => None,
        })
        .expect("and it is named, quoting the refusal verbatim");
    assert!(degraded.contains("did not decode"), "{degraded}");
    assert!(degraded.contains("TRANSACTIONS ONLY"), "{degraded}");
}
