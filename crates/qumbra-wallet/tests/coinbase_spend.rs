//! **The first-miner-journey's leg 2: a mining-only wallet spends a matured
//! coinbase note** (lab #424; leg 1 — the route and the scan — closed with lab
//! #415 / PR #425).
//!
//! The wallet here has never received a transaction. Every note it owns was
//! minted by its own `rkm`, which is exactly the wallet `send` could not serve
//! before this change: `SelectDriver` built its input set from
//! `ScanOutcome::notes` — transaction outputs — and a coinbase note is in no
//! discovery group by construction, so the send refused "no spendable notes" one
//! line below a `scan` that called the same coins spendable.
//!
//! ## Two tests, split at the STARK — on purpose
//!
//! Everything through **phase 1** (`spend::select`: scan → nullifiers →
//! coinbase → tree → anchor → witness) is cheap and runs everywhere, because
//! that is where lab #424's change lives and a fixture mistake there should not
//! need a 12 GB run to surface. The **prove + submit + detect** half is one real
//! `qlab_consensus::prove_bucket` and is release-only, behind the rig lock; its
//! home is the CI `verify` lane.
//!
//! What the heavy half adds and the cheap half cannot: that the note phase 1
//! selected survives the **production prove path and the node's own
//! admission** — `NodeRpc::submit_tx` behind `ConsensusVerifier`, the shipping
//! verifier the binary composes — and that a stranger then detects the output.
//!
//! All four wallet-facing wires are real HTTP: `/v1/compact` + `/v1/nullifiers`
//! + **`/v1/coinbase`** off `qlab_node::serve`, and `/v1/tree/leaves`,
//! `/v1/anchors`, `POST /v1/tx` off the deployed
//! `qumbra_node::discovery_server::DiscoveryServer`.
//!
//! ## The chain runs ahead of its finality, deliberately
//!
//! The three unfinalized tail blocks append matured coinbase leaves that are
//! **not** inside any valid anchor, so the count a witness may be built at is
//! strictly below the count the leaf stream served — issue #276's property, and
//! the reason an all-finalized fixture would hide a real defect.

use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex};

use qlab_cbserver::client::{light_client_scan, Completeness, ScanConfig};
use qlab_devnet::body::{BlockBody, TxEntry, TxVerifier};
use qlab_devnet::header::BlockHeader;
use qlab_devnet::params_devnet::GENESIS_DIFFICULTY;
use qlab_node::{
    anchor_set, coinbase, coinbase_leaf_appears_at, genesis_block, ChainStore, MemNodeRpc, NodeRpc,
    NodeState, RpcServerHandle, SubmitOutcome,
};
use qlab_note::compact::decode_committed_discovery;
use qlab_wallet::seed::MasterSeed;
use qlab_wallet::Wallet;
use qumbra_node::discovery_server::{
    AnchorsView, DiscoveryServer, DiscoveryView, LeavesView, SubmitRequest, TxSubmitOutcome,
};
use qumbra_node::verifier::ConsensusVerifier;
use qumbra_wallet::bundle::WitnessBundle;
use qumbra_wallet::coinbase::{fetch_coinbase, match_mined, MinedReport};
use qumbra_wallet::net::{HttpCoinbaseSource, HttpNullifierSource, SubmitClass};
use qumbra_wallet::spend::{preflight, prove, select, submit, SendRequest, SendStep};
use qumbra_wallet::spent::{fetch_spent, note_nullifier};
use qumbra_wallet::store::WalletDir;
use rand::rngs::StdRng;
use rand::SeedableRng;

/// 4 QMB out of the ~32.5 QMB a block's miner share is at this height — amount,
/// posted fee and change all non-trivial.
const AMOUNT: u64 = 400_000_000;

/// How far the chain runs ahead of its finalized head before the wallet spends.
const UNFINALIZED_LAG_BLOCKS: u64 = 3;

/// The two heights that pay this wallet. Both matured before the spend, so the
/// selection has a real choice to make rather than one candidate.
const MINED_HEIGHTS: [u64; 2] = [1, 2];

/// This chain carries exactly one transaction and it is the spend under test;
/// every fixture block is empty.
struct NoTx;
impl TxVerifier for NoTx {
    fn verify_tx(&self, _: &TxEntry) -> bool {
        unreachable!("fixture blocks carry no transactions")
    }
}

fn mine<V: TxVerifier>(
    shared: &Arc<Mutex<MemNodeRpc>>,
    tip: &mut BlockHeader,
    txs: Vec<TxEntry>,
    rkm: [u64; 4],
    verifier: &V,
    finalize: bool,
) -> u64 {
    let height = tip.height + 1;
    let body = BlockBody { txs, coinbase: coinbase(height), coinbase_rkm: rkm };
    let header = BlockHeader::child_of(tip, height * 75, GENESIS_DIFFICULTY, body.commitment());
    let mut g = shared.lock().unwrap();
    let node = g.node_mut();
    let hash = node.apply_block(header, body, verifier).expect("block applies");
    if finalize {
        node.finalize(hash).expect("finalize");
    }
    *tip = header;
    height
}

fn mine_empty(shared: &Arc<Mutex<MemNodeRpc>>, tip: &mut BlockHeader, n: u64, rkm: [u64; 4]) {
    for _ in 0..n {
        mine(shared, tip, Vec::new(), rkm, &NoTx, true);
    }
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("qmb_i424_{tag}"));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A real chain that this wallet — and only this wallet — mined, published over
/// both deployed serving surfaces.
struct Rig {
    shared: Arc<Mutex<MemNodeRpc>>,
    tip: BlockHeader,
    base: String,
    node_url: String,
    submit_rx: mpsc::Receiver<SubmitRequest>,
    discovery_view: Arc<Mutex<Arc<DiscoveryView>>>,
    leaves_view: Arc<Mutex<Arc<LeavesView>>>,
    anchors_view: Arc<Mutex<Arc<AnchorsView>>>,
    miner: Wallet,
    stranger: Wallet,
    wallet_dir: PathBuf,
    /// Every block that is not this wallet's.
    elsewhere: [u64; 4],
    _scan: RpcServerHandle,
    _server: DiscoveryServer,
}

impl Rig {
    /// Republish the three read projections the discovery server serves, exactly
    /// as `RunningNode`'s refresh methods do.
    fn refresh(&self) {
        let g = self.shared.lock().unwrap();
        let node = g.node();
        let mut view = (**self.discovery_view.lock().unwrap()).clone();
        view.refresh(node.chain());
        *self.discovery_view.lock().unwrap() = Arc::new(view);
        *self.leaves_view.lock().unwrap() =
            Arc::new(LeavesView { leaves: node.commitments_ordered().to_vec() });
        *self.anchors_view.lock().unwrap() =
            Arc::new(AnchorsView { encoded: anchor_set(node).to_bytes() });
    }

    /// This wallet's mined notes as the two served streams currently describe
    /// them — the wallet's own view, over real sockets, with the chain's
    /// nullifiers already subtracted.
    fn mined_report(&self) -> MinedReport {
        let chain = fetch_coinbase(
            &HttpCoinbaseSource::new(&self.base),
            0,
            self.tip.height,
            qumbra_wallet::GenesisForm::V4,
        )
            .expect("the node serves /v1/coinbase (lab #415)");
        let spent = fetch_spent(&HttpNullifierSource::new(&self.base), 0, self.tip.height)
            .expect("the node serves /v1/nullifiers");
        match_mined(&self.miner, &[0], &chain, &spent)
    }
}

fn rig(tag: &str) -> Rig {
    // The miner's own wallet, created BEFORE the chain it mined.
    let wallet_dir = tmp(tag);
    let seed = MasterSeed::from_entropy([0x24; 32]);
    let miner = Wallet::from_master_seed(&seed, 0);
    let mine_rkm = miner.rkm(miner.diversifier_at_index(0));
    WalletDir::create(&wallet_dir, seed).expect("the miner's wallet dir exists");

    let stranger = Wallet::from_master_seed(&MasterSeed::from_entropy([0x25; 32]), 0);
    let elsewhere = [0xBE, 0xEF, 0xBE, 0xEF];

    // ---- the devnet: one real node, served over real sockets --------------
    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let mut tip = genesis.header();
    let mut node = qlab_node::MemNode::in_memory(genesis);
    let ghash = node.chain().genesis_block_hash();
    assert!(node.finalize(ghash).expect("finalize genesis").is_recorded());
    let shared = Arc::new(Mutex::new(NodeRpc::new(node)));
    // The scan host: `/v1/compact`, `/v1/nullifiers` AND `/v1/coinbase`.
    let scan_handle = qlab_node::serve(Arc::clone(&shared));
    let base = scan_handle.base_url();

    // Heights 1 and 2 pay THIS wallet; nothing else ever does. Then on to the
    // height at which block 2's coinbase leaf has been appended…
    mine_empty(&shared, &mut tip, MINED_HEIGHTS.len() as u64, mine_rkm);
    let matured_at = coinbase_leaf_appears_at(MINED_HEIGHTS[1]);
    let gap = matured_at - tip.height;
    mine_empty(&shared, &mut tip, gap, elsewhere);
    assert_eq!(tip.height, matured_at);
    // …and now the chain runs AHEAD of its finality.
    for _ in 0..UNFINALIZED_LAG_BLOCKS {
        mine(&shared, &mut tip, Vec::new(), elsewhere, &NoTx, false);
    }

    let discovery_view = Arc::new(Mutex::new(Arc::new(DiscoveryView::default())));
    let leaves_view = Arc::new(Mutex::new(Arc::new(LeavesView::default())));
    let anchors_view = Arc::new(Mutex::new(Arc::new(AnchorsView::default())));
    let (submit_tx_chan, submit_rx) = mpsc::sync_channel::<SubmitRequest>(4);
    let server = DiscoveryServer::start(
        "127.0.0.1:0",
        Arc::clone(&discovery_view),
        Arc::clone(&leaves_view),
        Arc::clone(&anchors_view),
        submit_tx_chan,
    )
    .expect("bind the discovery server");
    let node_url = format!("http://{}", server.addr());

    let rig = Rig {
        shared,
        tip,
        base,
        node_url,
        submit_rx,
        discovery_view,
        leaves_view,
        anchors_view,
        miner,
        stranger,
        wallet_dir,
        elsewhere,
        _scan: scan_handle,
        _server: server,
    };
    rig.refresh();
    rig
}

/// Phase 1 over the rig, with every narrated step — the half lab #424 changed.
fn select_a_spend(rig: &Rig) -> (WitnessBundle, Vec<SendStep>) {
    let stranger_addr = rig.stranger.address_at_index(0);
    let req = SendRequest {
        dir: &rig.wallet_dir,
        url: &rig.base,
        node_url: &rig.node_url,
        recipient: &stranger_addr,
        contact_name: None,
        amount: AMOUNT,
        scan_to: rig.tip.height,
        no_submit: false,
        name_op: None,
        form: qumbra_wallet::GenesisForm::V4,
    };
    let mut steps: Vec<SendStep> = Vec::new();
    let bundle = select(&req, &mut |s| steps.push(s))
        .expect("🔴 lab #424: phase 1 selects a MINED note — this refused before the change");
    (bundle, steps)
}

/// 🔴 **The premise and the fix, without a STARK: a wallet whose scan finds
/// NOTHING selects its matured coinbase notes and reaches a witness bound to a
/// finalized anchor.**
///
/// Every assertion here is about what lab #424 changed, which is why it is not
/// release-gated: a fixture or wiring mistake should surface in a second, not
/// behind a 12 GB prove.
#[test]
fn a_mining_only_wallets_phase_one_selects_coinbase_over_real_sockets() {
    let rig = rig("select_only");

    // The premise, stated rather than assumed. This wallet's TRANSACTION
    // balance is a true zero under `Complete` — every coin it owns is invisible
    // to that half, which is the whole of the issue.
    let mut rng = StdRng::from_seed([0xA4; 32]);
    let miner_dk = rig.miner.diversified_keypair(&rig.miner.diversifier_at_index(0)).dk;
    let scanned =
        light_client_scan(&rig.base, &miner_dk, 0, rig.tip.height, ScanConfig::default(), &mut rng)
            .expect("the scan runs against the live node");
    assert!(
        matches!(scanned.completeness(), Completeness::Complete | Completeness::Shadowed { .. }),
        "{:?}",
        scanned.completeness()
    );
    assert!(scanned.notes.is_empty(), "no transaction ever paid this wallet");

    // …while the coinbase stream says otherwise, and by how much.
    let report = rig.mined_report();
    assert_eq!(report.blocks_mined(), MINED_HEIGHTS.len(), "two blocks paid this wallet");
    assert_eq!(report.spendable.len(), 2, "and both have matured by this tip");
    assert!(report.maturing.is_empty(), "nothing is still maturing at this tip");

    let (bundle, steps) = select_a_spend(&rig);

    match steps.iter().find(|s| matches!(s, SendStep::Selected { .. })) {
        Some(SendStep::Selected { spendable, mined, .. }) => {
            assert_eq!((*spendable, *mined), (2, 2), "both candidate inputs are coinbase notes");
        }
        other => panic!("selection must narrate: {other:?}"),
    }
    assert!(
        !steps.iter().any(|s| matches!(s, SendStep::CoinbaseUnavailable { .. })),
        "a node that serves the route degrades nothing"
    );
    // 🔴 Issue #276's property, which an all-finalized chain would hide: the
    // anchor a witness may be built at trails the served leaf count.
    match steps.iter().find(|s| matches!(s, SendStep::Tree { .. })) {
        Some(SendStep::Tree { held, fetched, anchor_count, .. }) => assert!(
            *anchor_count < held + fetched,
            "the anchor ({anchor_count}) must trail the served leaf count ({})",
            held + fetched
        ),
        other => panic!("the tree phase must narrate: {other:?}"),
    }
    {
        let g = rig.shared.lock().unwrap();
        assert!(
            g.node().is_valid_anchor(&bundle.anchor()),
            "the selected root is a valid anchor by the node's own rule"
        );
    }
    // The input really is a coinbase note: the bundle's real nullifier is one
    // derived from `qlab_node::coinbase_note` — the applier's own derivation —
    // over a block this wallet mined, not something merely of the right value.
    let declared = bundle.real_nullifiers();
    let mined_nfs: Vec<[u8; 32]> = report
        .spendable
        .iter()
        .map(|n| note_nullifier(&rig.miner, n.div_index, &n.note))
        .collect();
    assert!(
        mined_nfs.iter().any(|nf| declared.contains(nf)),
        "🔴 the witness consumes a MINED note"
    );
    assert!(bundle.used_dummy(), "one coinbase note covers it ⇒ the #219 dummy slot");
    assert_eq!(bundle.amount(), AMOUNT);

    let _ = std::fs::remove_dir_all(&rig.wallet_dir);
}

/// 🔴 **Leg 2, end to end: mine → mature → SPEND through the production prove
/// path → a stranger detects it.**
///
/// One real prove (~12 GB peak, ~3 s release) — release only, behind the rig
/// lock, per the bench discipline.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "one real prove (~12 GB peak) — release only, behind the rig lock"
)]
fn a_mining_only_wallet_spends_a_matured_coinbase_note_and_a_stranger_detects_it() {
    let mut rig = rig("coinbase_spend");
    let before = rig.mined_report();
    assert_eq!(before.spendable.len(), 2, "two matured mined notes to choose from");
    let spendable_before = before.spendable_value();

    let (bundle, _) = select_a_spend(&rig);
    let stranger_addr = rig.stranger.address_at_index(0);
    let req = SendRequest {
        dir: &rig.wallet_dir,
        url: &rig.base,
        node_url: &rig.node_url,
        recipient: &stranger_addr,
        contact_name: None,
        amount: AMOUNT,
        scan_to: rig.tip.height,
        no_submit: false,
        name_op: None,
        form: qumbra_wallet::GenesisForm::V4,
    };
    let current = preflight(&req).expect("fresh public chain facts are available");
    let art = prove(&bundle, &current, &mut |_| {})
        .expect("🔴 the production prove path takes a coinbase input");
    assert!(art.used_dummy, "one coinbase note covers it ⇒ the #219 dummy slot");
    assert_eq!(art.change_value, bundle.change_value());

    // What the prover actually declared is a nullifier of a MINED note.
    let mined_nfs: Vec<[u8; 32]> = before
        .spendable
        .iter()
        .map(|n| note_nullifier(&rig.miner, n.div_index, &n.note))
        .collect();
    assert!(
        mined_nfs.iter().any(|nf| art.entry.public.nullifiers.contains(nf)),
        "🔴 the PROOF consumed a mined note"
    );

    // ---- SUBMIT over POST /v1/tx, judged by the shipping verifier ---------
    //
    // The client blocks on the verdict, so the submission runs on its own thread
    // while this one plays the run loop and drains the queue — exactly what
    // `RunningNode::submit_remote_tx` does, through the same checks.
    let wire = art.wire_bytes.clone();
    let submit_url = rig.node_url.clone();
    let client = std::thread::spawn(move || submit(&submit_url, &wire, &mut |_| {}));

    let request = rig.submit_rx.recv().expect("the submission reaches the queue");
    let verdict = {
        let (bundles, payloads) = decode_committed_discovery(&request.tx.discovery)
            .expect("a wallet's own tx re-decodes");
        let mut payloads = payloads.into_iter();
        let discovery = qlab_node::TxDiscovery {
            recipients: bundles
                .into_iter()
                .map(|bundle| {
                    let n = bundle.entries.len();
                    qlab_node::RecipientDiscovery {
                        payloads: payloads.by_ref().take(n).collect(),
                        bundle,
                    }
                })
                .collect(),
        };
        let mut g = rig.shared.lock().unwrap();
        match g.submit_tx(request.tx.clone(), discovery, &ConsensusVerifier) {
            SubmitOutcome::Accepted(txid) => TxSubmitOutcome::Accepted { txid },
            other => panic!("the node must admit a spend of a coinbase note, got {other:?}"),
        }
    };
    request.reply.try_send(verdict).expect("the handler is still waiting");
    let answer = client.join().unwrap().expect("the POST completed");
    assert_eq!(answer.status, 202, "202 Accepted: {}", answer.body);
    assert_eq!(answer.class(), SubmitClass::Accepted);

    // ---- mined under the production verifier ------------------------------
    let elsewhere = rig.elsewhere;
    let send_height = {
        let mut tip = rig.tip;
        let h = mine(
            &rig.shared,
            &mut tip,
            vec![art.entry.clone()],
            elsewhere,
            &ConsensusVerifier,
            true,
        );
        rig.tip = tip;
        h
    };
    rig.refresh();

    // ---- 🔴 the stranger DETECTS it — leg 2 (open → spend), closed --------
    let mut rng = StdRng::from_seed([0xA5; 32]);
    let stranger_dk = rig.stranger.diversified_keypair(&rig.stranger.diversifier_at_index(0)).dk;
    let got = light_client_scan(
        &rig.base,
        &stranger_dk,
        send_height,
        send_height,
        ScanConfig::default(),
        &mut rng,
    )
    .expect("the stranger's scan runs against the live node");
    assert_eq!(got.notes.len(), 1, "the stranger detects exactly the spend's output");
    assert_eq!(got.notes[0].detected.note.value, AMOUNT, "…at the sent amount");

    // ---- and the miner's own mined balance went down by that note ---------
    //
    // Against the chain's own nullifiers, not a local guess: the note that paid
    // for this spend now reports `spent` with the chain's date, and the mined
    // spendable figure drops by exactly its value. Lab #314's rule, holding on
    // the category lab #415 made visible.
    let after = rig.mined_report();
    assert_eq!(after.spent.len(), 1, "the note this spend consumed is REPORTED, not dropped");
    assert_eq!(after.spent[0].spent_height, Some(send_height), "the chain's own date");
    assert_eq!(after.spendable.len(), 1, "the other mined note survives");
    assert_eq!(
        after.spendable_value() + after.spent_value(),
        spendable_before,
        "the mined balance dropped by exactly the consumed note"
    );

    let _ = std::fs::remove_dir_all(&rig.wallet_dir);
}
