//! **Lab #785 F5-5d — a wallet scans across an exit-bearing bundle and
//! spends past it.** Phase 1 only (`SelectDriver`: scan → nullifiers →
//! coinbase → **exits** → tree → anchor → witness), split at the STARK the way
//! `coinbase_spend.rs` is; the proven-and-spent exit is F5-6's condition (h).
//!
//! The chain is a V6 `MemNode` on a test bundle rule (the 4c-1 shape:
//! `counter u64 ‖ (rkm 32 ‖ v u64)*`, with `bundle_exits`), finalized by real
//! committee records:
//!
//! - blocks 1–8 empty; block 9 carries the record of checkpoint 8 **and** a
//!   bundle whose exit list pays another key 7 and this wallet 30 QMB — two
//!   exit leaves the fold appends after the block's outputs;
//! - block 10 carries a transaction paying this wallet 10 QMB, anchored under
//!   record 8 — an output whose tree position sits *past* the exit leaves;
//! - blocks 11–16 empty, block 17 carries the record of checkpoint 16, block 18
//!   runs ahead of finality.
//!
//! All wires are real HTTP off the deployed `DiscoveryServer`, its projection
//! refreshed through the node's own rule (`refresh_with_exits` +
//! `MemNode::exits_of`), as `RunningNode` does.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{mpsc, Arc, Mutex};

use qlab_cbserver::client::{light_client_scan, ScanConfig, ScanOutcome};
use qlab_cbserver::codec::NullifierPage;
use qlab_cbserver::tree::CommitmentTree;
use qlab_devnet::body::{
    BlockBody, BundleContext, BundleOutcome, BundleRefusal, BundleVerifier, TxEntry, TxPublic, TxVerifier,
    WrapperSetup,
};
use qlab_devnet::committee::{devnet_committee, Checkpoint, Validator};
use qlab_devnet::fees::{posted_fee, ArityBucket};
use qlab_devnet::finality_record::FinalityRecord;
use qlab_devnet::forms::GenesisForm;
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_node::{anchor_set, genesis_block_v6, ChainStore, MemNode, NodeState, V6Setup};
use qlab_note::kem::{Dk, Ek};
use qlab_note::note::Note;
use qlab_note::scan::encrypt_to_recipient;
use qlab_wallet::seed::MasterSeed;
use qlab_wallet::Wallet;
use qumbra_node::discovery_server::{AnchorsView, DiscoveryServer, DiscoveryView, LeavesView, SubmitRequest};
use qumbra_wallet::driver::{SelectDriver, SelectStep};
use qumbra_wallet::spend::SendStep;
use rand::rngs::StdRng;
use rand::SeedableRng;

const QMB: u64 = 100_000_000;
const EXIT_V: u64 = 30 * QMB;
const TX_V: u64 = 10 * QMB;

struct AnyTx;
impl TxVerifier for AnyTx {
    fn verify_tx(&self, _: &TxEntry) -> bool {
        true
    }
}

/// The 4c-1 test rule: `counter ‖ (rkm ‖ v)*`, threading on the counter, its
/// exits the list — and readable from the bytes alone (`bundle_exits`).
struct ExitRule;
fn exits_of(bundle: &[u8]) -> Result<Vec<(Hash32, u64)>, BundleRefusal> {
    let rest = bundle.get(8..).ok_or(BundleRefusal::Codec("short".into()))?;
    if rest.len() % 40 != 0 {
        return Err(BundleRefusal::Codec("exit list".into()));
    }
    Ok(rest.chunks_exact(40).map(|c| (c[..32].try_into().unwrap(), u64::from_le_bytes(c[32..].try_into().unwrap()))).collect())
}
impl BundleVerifier for ExitRule {
    fn verify_bundle(&self, _: &BlockHeader, bundle: &[u8], ctx: &BundleContext<'_>) -> Result<BundleOutcome, BundleRefusal> {
        self.fold_bundle(ctx.surface, bundle)
    }
    fn fold_bundle(&self, surface: &[u8], bundle: &[u8]) -> Result<BundleOutcome, BundleRefusal> {
        let prev = u64::from_le_bytes(surface.try_into().map_err(|_| BundleRefusal::SurfaceState)?);
        let next = u64::from_le_bytes(bundle.get(..8).ok_or(BundleRefusal::Codec("short".into()))?.try_into().unwrap());
        if next <= prev {
            return Err(BundleRefusal::Wrapper("Thread".into()));
        }
        let exits = exits_of(bundle)?;
        let e_batch = exits.iter().map(|e| e.1).sum();
        Ok(BundleOutcome { surface: next.to_le_bytes().to_vec(), exits, d_batch: 0, e_batch })
    }
    fn bundle_surface(&self, bundle: &[u8]) -> Result<Vec<u8>, BundleRefusal> {
        bundle.get(..8).map(<[u8]>::to_vec).ok_or(BundleRefusal::Codec("short".into()))
    }
    fn bundle_exits(&self, bundle: &[u8]) -> Result<Vec<(Hash32, u64)>, BundleRefusal> {
        exits_of(bundle)
    }
}

fn exit_bundle(counter: u64, exits: &[([u64; 4], u64)]) -> Vec<u8> {
    let mut b = counter.to_le_bytes().to_vec();
    for (rkm, v) in exits {
        b.extend_from_slice(&qlab_note::hash::digest_bytes(rkm));
        b.extend_from_slice(&v.to_le_bytes());
    }
    b
}

fn payment(ek: &Ek, notes: &[Note], nullifiers: Vec<Hash32>, anchor: Hash32, rng: &mut StdRng) -> TxEntry {
    let enc = encrypt_to_recipient(ek, notes, rng);
    let commitments: Vec<Hash32> = enc.bundle.entries.iter().map(|e| e.cm).collect();
    TxEntry::new(
        b"proof-placeholder".to_vec(),
        TxPublic { anchor, nullifiers, commitments, bucket: ArityBucket::TwoByTwo, fee: posted_fee(ArityBucket::TwoByTwo) },
        &[enc.bundle],
        &enc.payloads,
    )
}

/// The record of the checkpoint at `node`'s tip, by 15 of committee₀.
fn record_at_tip(node: &MemNode, validators: &[Validator]) -> Vec<u8> {
    let cp = Checkpoint::new(node.tip_height(), node.tip_hash(), node.tip_hash());
    FinalityRecord { cp, votes: validators[..15].iter().map(|v| v.sign_checkpoint(&cp)).collect() }.encode()
}

fn apply(node: &mut MemNode, txs: Vec<TxEntry>, finality: Vec<u8>, bundle: Vec<u8>) -> Hash32 {
    let parent = node.chain().block(&node.tip_hash()).unwrap().header();
    let height = parent.height + 1;
    let mut body = BlockBody::from_single_payee(txs, qlab_devnet::emission_exact::coinbase_exact(height), [height; 4]);
    body.finality = finality;
    body.bundle = bundle;
    let header = BlockHeader::child_of_for(GenesisForm::V5, &parent, parent.timestamp + 75, 8, body.commitment_v6());
    node.apply_block(header, body, &AnyTx).expect("the block applies")
}

fn get(base: &str, path: &str) -> Result<Vec<u8>, String> {
    let host = base.trim_start_matches("http://");
    let mut s = TcpStream::connect(host).map_err(|e| e.to_string())?;
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes())
        .map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).map_err(|e| e.to_string())?;
    let status_ok = raw.starts_with(b"HTTP/1.1 200");
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or("no header/body split")?;
    if !status_ok {
        return Err(format!("non-200: {}", String::from_utf8_lossy(&raw[..split])));
    }
    Ok(raw[split + 4..].to_vec())
}

struct Fixture {
    url: String,
    wallet: Wallet,
    dk: Dk,
    /// This wallet's exit note, as the node appended it.
    exit_note: Note,
    to: u64,
    _server: DiscoveryServer,
}

impl Fixture {
    fn outcomes(&self) -> Vec<(u64, ScanOutcome)> {
        let mut rng = StdRng::from_seed([0x77; 32]);
        let outcome = light_client_scan(&self.url, &self.dk, 0, self.to, ScanConfig::default(), &mut rng)
            .expect("the fixture scan runs");
        assert_eq!(outcome.notes.len(), 1, "the transaction output past the exit block");
        vec![(0, outcome)]
    }
}

fn fixture() -> Fixture {
    let mut rng = StdRng::from_seed([0x5d; 32]);
    let wallet = Wallet::from_master_seed(&MasterSeed::from_entropy([0x5d; 32]), 0);
    let d0 = wallet.diversifier_at_index(0);
    let kp = wallet.diversified_keypair(&d0);
    let mine = wallet.rkm(d0);
    let (committee, validators) = devnet_committee(qlab_devnet::params_devnet::FROZEN_COMMITTEE_SIZE);
    let setup = V6Setup {
        committee0: committee,
        wrapper: Some(WrapperSetup { rule: Arc::new(ExitRule), genesis_surface: 0u64.to_le_bytes().to_vec() }),
    };
    let mut node = MemNode::in_memory_v6(genesis_block_v6(8, 0), setup);
    for _ in 1..=8 {
        apply(&mut node, vec![], vec![], vec![]);
    }
    let anchor8 = node.commitment_root();
    let record8 = record_at_tip(&node, &validators);
    apply(&mut node, vec![], record8, exit_bundle(5, &[([9, 9, 9, 9], 7 * QMB), (mine, EXIT_V)]));
    let paid = Note { value: TX_V, rkm: mine, rho: [0xC1, 0xC2, 0xC3, 0xC4], rseed: [0xD1, 0xD2, 0xD3, 0xD4] };
    apply(&mut node, vec![payment(&kp.ek, &[paid], vec![[0x71; 32], [0x72; 32]], anchor8, &mut rng)], vec![], vec![]);
    for _ in 11..=16 {
        apply(&mut node, vec![], vec![], vec![]);
    }
    let hash16 = node.tip_hash();
    let record16 = record_at_tip(&node, &validators);
    apply(&mut node, vec![], record16, vec![]);
    apply(&mut node, vec![], vec![], vec![]);
    assert!(node.finalize(hash16).expect("finalize 16").is_recorded());
    assert_eq!(node.tip_height(), 18);

    let exit_note = qlab_node::coinbase::exit_note(9, 1, mine, EXIT_V);
    assert!(
        node.commitments_ordered().contains(&qlab_node::coinbase::exit_note_leaf(9, 1, mine, EXIT_V)),
        "the fold appended this wallet's exit leaf"
    );

    let discovery = Arc::new(Mutex::new(Arc::new(DiscoveryView::default())));
    let leaves_view = Arc::new(Mutex::new(Arc::new(LeavesView::default())));
    let anchors_view = Arc::new(Mutex::new(Arc::new(AnchorsView::default())));
    {
        let mut view = DiscoveryView::default();
        assert!(view.refresh_with_exits(node.chain(), &|b| node.exits_of(b)));
        *discovery.lock().unwrap() = Arc::new(view);
        *leaves_view.lock().unwrap() = Arc::new(LeavesView { leaves: node.commitments_ordered().to_vec() });
        *anchors_view.lock().unwrap() = Arc::new(AnchorsView { encoded: anchor_set(&node).to_bytes() });
    }
    let (submit_chan, _rx) = mpsc::sync_channel::<SubmitRequest>(1);
    let server = DiscoveryServer::start("127.0.0.1:0", discovery, leaves_view, anchors_view, submit_chan).expect("bind");
    Fixture { url: format!("http://{}", server.addr()), wallet, dk: kp.dk, exit_note, to: 18, _server: server }
}

/// Pump phase 1 to its end over the fixture's server; `edit` may rewrite a
/// response by path before it reaches the driver.
fn pump(
    f: &Fixture,
    amount: u64,
    edit: &dyn Fn(&str, Vec<u8>) -> Vec<u8>,
) -> (Result<Box<qumbra_wallet::bundle::WitnessBundle>, String>, Vec<SendStep>, Vec<String>) {
    let other = Wallet::from_master_seed(&MasterSeed::from_entropy([0x99; 32]), 0).address_at_index(0);
    let mut driver = SelectDriver::new(
        f.wallet.clone(),
        other,
        amount,
        None,
        f.outcomes(),
        CommitmentTree::new(),
        f.to,
        GenesisForm::V5,
    );
    let mut rng = StdRng::from_seed([0x66; 32]);
    let (mut events, mut asked) = (Vec::new(), Vec::new());
    for _ in 0..512 {
        let step = driver.step(&mut rng);
        events.extend(driver.take_events());
        match step {
            SelectStep::Need { path, .. } => {
                asked.push(path.clone());
                driver.supply(get(&f.url, &path).map(|b| edit(&path, b)));
            }
            SelectStep::Done(b) => return (Ok(b), events, asked),
            SelectStep::Failed(e) => return (Err(e), events, asked),
        }
    }
    panic!("the pump does not converge");
}

/// 🔒 The F5-5d condition: the wallet finds its exit (no discovery entry, no
/// transaction — only `/v1/exits`), selects it beside the transaction output
/// that sits past the exit leaves, and both are witnessed against the
/// finalized anchor at 16, whose leaf count runs past the exit block.
#[test]
fn a_wallet_scans_across_an_exit_bearing_bundle_and_spends_past_it() {
    let f = fixture();
    // 35 QMB: neither note covers it alone, so both must be selected.
    let (outcome, events, asked) = pump(&f, 35 * QMB, &|_, b| b);
    let bundle = outcome.unwrap_or_else(|e| panic!("phase 1: {e}"));
    assert!(asked.iter().any(|p| p.starts_with("/v1/exits")), "{asked:?}");
    assert_eq!(bundle.amount(), 35 * QMB);
    let exit_nf = qumbra_wallet::spent::note_nullifier(&f.wallet, 0, &f.exit_note);
    assert!(bundle.real_nullifiers().contains(&exit_nf), "the exit note is an input");
    assert_eq!(bundle.real_nullifiers().len(), 2, "beside the transaction output past it");
    match events.iter().find(|e| matches!(e, SendStep::Selected { .. })) {
        Some(SendStep::Selected { spendable, skipped_spent, mined }) => {
            assert_eq!((*spendable, *skipped_spent, *mined), (2, 0, 0));
        }
        other => panic!("selection narrates: {other:?}"),
    }
    assert!(
        !events.iter().any(|e| matches!(e, SendStep::Warning(w) if w.contains("L2 exits"))),
        "the exit stream was visible: no degradation"
    );
    match events.iter().find(|e| matches!(e, SendStep::Tree { .. })) {
        Some(SendStep::Tree { anchor_count, finalized, .. }) => {
            assert_eq!(*finalized, Some(16));
            assert!(*anchor_count >= 3, "the anchor's tree holds both exit leaves and the output: {anchor_count}");
        }
        other => panic!("the tree phase narrates: {other:?}"),
    }
}

/// Condition 4: the exit input carries the nullifier subtraction. With its
/// nullifier on the chain (injected into the served nullifier page), the
/// exit note is not selected and is counted as already spent; and a node that
/// does not serve `/v1/exits` degrades out loud rather than refusing.
#[test]
fn a_spent_exit_is_not_selected_and_a_missing_route_is_named() {
    let f = fixture();
    let exit_nf = qumbra_wallet::spent::note_nullifier(&f.wallet, 0, &f.exit_note);
    let inject = |path: &str, bytes: Vec<u8>| -> Vec<u8> {
        if !path.starts_with("/v1/nullifiers") {
            return bytes;
        }
        let mut page = NullifierPage::from_bytes(&bytes).expect("a nullifier page");
        if let Some(last) = page.blocks.last_mut() {
            last.nullifiers.push(exit_nf);
        }
        page.to_bytes()
    };
    let (outcome, events, _) = pump(&f, 5 * QMB, &inject);
    let bundle = outcome.unwrap_or_else(|e| panic!("the transaction output still pays: {e}"));
    assert!(!bundle.real_nullifiers().contains(&exit_nf), "a spent exit is never an input");
    match events.iter().find(|e| matches!(e, SendStep::Selected { .. })) {
        Some(SendStep::Selected { spendable, skipped_spent, .. }) => assert_eq!((*spendable, *skipped_spent), (1, 1)),
        other => panic!("selection narrates: {other:?}"),
    }

    // A node without the route: the send proceeds on what it can see and says so.
    let (outcome, events, _) = pump(&f, 5 * QMB, &|path, b| if path.starts_with("/v1/exits") { b"<html>404</html>".to_vec() } else { b });
    assert!(outcome.is_ok(), "an unreadable exit stream only shrinks the input set");
    assert!(
        events.iter().any(|e| matches!(e, SendStep::Warning(w) if w.contains("L2 exits were NOT visible"))),
        "and it is named: {events:?}"
    );
}
