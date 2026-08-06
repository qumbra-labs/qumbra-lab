//! The first-spend e2e (issue #276) — C5's lab half, as one test: a local
//! devnet mines to maturity, the faucet funds a wallet with a REAL grant, the
//! wallet detects it by light-client scan over a real socket, syncs its local
//! commitment tree **over `GET /v1/tree/leaves`**, picks its anchor **over
//! `GET /v1/anchors`**, builds and REALLY proves a spend to a stranger, submits
//! it **over `POST /v1/tx`** and gets the typed outcome back — and the
//! recipient's scan detects the spend's output.
//!
//! ## The chain this runs on has a FINALITY CADENCE, and that is the point
//!
//! An earlier version of this test finalized every block, which made the tip
//! root trivially a valid anchor and hid the defect issue #276 found: a valid
//! anchor is a *finalized* root, so on any real chain the count a wallet may
//! build a witness at is **not** the count the leaf stream just served. Here
//! the chain deliberately runs ahead of its finality, and the test asserts that
//! `anchor.count < synced.count` before it proves anything — if that assertion
//! ever reads `==`, this test has stopped covering the thing it exists for.
//!
//! ## What crosses a real socket, and what does not
//!
//! All four wallet-facing wires are real HTTP against the **deployed server
//! code** (`qumbra_node::discovery_server::DiscoveryServer`, the same type the
//! binary starts) over the same codecs: `/v1/compact` for the scan,
//! `/v1/tree/leaves`, `/v1/anchors`, and `POST /v1/tx`.
//!
//! What this test does **not** exercise is `RunningNode`'s own loop wrapper
//! around admission (`submit_remote_tx` + `drain_remote_submits`): standing up
//! a full `RunningNode` with real PoW to reach coinbase maturity would multiply
//! this test's cost to re-cover ground that is already covered node-side by
//! `qumbra_node::run::tests::submit_endpoint_admits_refuses_and_dedups_over_a_real_socket`.
//! Here the test itself drains the submit queue and answers with
//! `NodeRpc::submit_tx` — the same checks, the same typed outcomes.
//!
//! Two real proves (grant + spend), ~12 GB peak each, sequential — release
//! only, behind the rig lock, per the bench discipline.

use std::collections::HashSet;
use std::sync::{mpsc, Arc, Mutex};

use qlab_cbserver::client::{light_client_scan, Completeness, ScanConfig};
use qlab_devnet::body::{BlockBody, TxEntry, TxVerifier};
use qlab_devnet::header::BlockHeader;
use qlab_devnet::params_devnet::GENESIS_DIFFICULTY;
use qlab_faucet::{
    DispenseOutcome, Faucet, FaucetConfig, FaucetLimits, TicketPolicy, TicketSecret,
    DEFAULT_GRANT_BESSEL,
};
use qlab_node::{
    anchor_set, coinbase, genesis_block, ChainStore, CommitmentStore, MemNodeRpc, NodeRpc,
    NodeState, SubmitOutcome,
};
use qlab_note::compact::decode_committed_discovery;
use qlab_wallet::address::Diversifier;
use qlab_wallet::seed::MasterSeed;
use qlab_wallet::Wallet;
use qumbra_faucet::harvest::{harvest_matured, spendable_at_tip};
use qumbra_node::discovery_server::{
    AnchorsView, DiscoveryServer, DiscoveryView, LeavesView, SubmitRequest, TxSubmitOutcome,
};
use qumbra_node::verifier::ConsensusVerifier;
use qumbra_wallet::net::{submit_tx, HttpAnchorSource, HttpLeafSource, SubmitClass};
use qumbra_wallet::send::{build_send, Spendable};
use qumbra_wallet::sync::sync_and_select;
use rand::rngs::StdRng;
use rand::SeedableRng;

/// 4 QMB of the 10 QMB grant — amount + posted fee + change all non-trivial.
const AMOUNT: u64 = 400_000_000;

/// How far the chain is left running ahead of its finalized head before the
/// wallet spends. Every one of these blocks appends the coinbase leaf it
/// matures (issue #102's schedule), so the served leaf count genuinely exceeds
/// the finalized one — which is what makes the anchor selection load-bearing
/// rather than decorative.
const UNFINALIZED_LAG_BLOCKS: u64 = 3;

/// Fixture blocks carry no transactions; grant/spend blocks run the shipping
/// verifier. Same shape as the faucet acceptance rig.
struct NoTx;
impl TxVerifier for NoTx {
    fn verify_tx(&self, _: &TxEntry) -> bool {
        unreachable!("fixture blocks carry no transactions")
    }
}

/// Mine one block carrying `txs`, paying `rkm`. Finalizes it only when asked —
/// see [`UNFINALIZED_LAG_BLOCKS`].
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

/// Republish the three read projections the discovery server serves, exactly as
/// `RunningNode`'s refresh methods do — same derivations, same Arc-swap.
fn refresh(
    shared: &Arc<Mutex<MemNodeRpc>>,
    discovery: &Arc<Mutex<Arc<DiscoveryView>>>,
    leaves: &Arc<Mutex<Arc<LeavesView>>>,
    anchors: &Arc<Mutex<Arc<AnchorsView>>>,
) {
    let g = shared.lock().unwrap();
    let node = g.node();
    let mut view = (**discovery.lock().unwrap()).clone();
    view.refresh(node.chain());
    *discovery.lock().unwrap() = Arc::new(view);
    *leaves.lock().unwrap() =
        Arc::new(LeavesView { leaves: node.commitments_ordered().to_vec() });
    *anchors.lock().unwrap() = Arc::new(AnchorsView { encoded: anchor_set(node).to_bytes() });
}

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("qmb_e2e_{tag}"));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "two real proves (~12 GB peak each) — release only, behind the rig lock"
)]
fn a_first_spend_travels_the_whole_story_and_the_recipient_detects_it() {
    // ---- the devnet: one real node, served over real sockets --------------
    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let mut tip = genesis.header();
    let mut node = qlab_node::MemNode::in_memory(genesis);
    let ghash = node.chain().genesis_block_hash();
    assert!(node.finalize(ghash).expect("finalize genesis").is_recorded());
    let shared = Arc::new(Mutex::new(NodeRpc::new(node)));
    // The scan's compact endpoint (qlab-node's in-process server).
    let scan_handle = qlab_node::serve(Arc::clone(&shared));
    let base = scan_handle.base_url();

    // ---- mine to maturity; the faucet harvests its coinbase ---------------
    let faucet_wallet = Wallet::from_seed_lanes([0x0123_0000_0000_0001; 4]);
    let fd = Diversifier::default();
    let mine_rkm = faucet_wallet.rkm(fd);
    let burn = [0xBE, 0xEF, 0xBE, 0xEF];
    mine_empty(&shared, &mut tip, 2, mine_rkm); // heights 1 and 2 pay the faucet
    let target = spendable_at_tip(2);
    let gap = target - tip.height;
    mine_empty(&shared, &mut tip, gap, burn);

    let mut faucet = Faucet::new(
        faucet_wallet.clone(),
        fd,
        TicketSecret::from_bytes([0x7C; 32]),
        FaucetConfig {
            limits: FaucetLimits { ticket_policy: TicketPolicy::Disabled, ..FaucetLimits::default() },
            ..FaucetConfig::default()
        },
    );
    let mut seen = HashSet::new();
    {
        let g = shared.lock().unwrap();
        let report = harvest_matured(&mut faucet, g.node(), &faucet_wallet, fd, &mut seen);
        assert_eq!(report.funded, 2, "both matured coinbase notes funded in");
    }

    // ---- the faucet funds the sender: a REAL grant, admitted and mined ----
    let sender = Wallet::from_master_seed(&MasterSeed::from_entropy([21u8; 32]), 0);
    let sender_addr = sender.address_at_index(0);
    let recipient_wallet = Wallet::from_master_seed(&MasterSeed::from_entropy([22u8; 32]), 0);
    let recipient_addr = recipient_wallet.address_at_index(0);

    let mut rng = StdRng::from_seed([0xA7; 32]);
    faucet.accept("e2e", sender_addr.clone(), None, 0).expect("open-mode accept");
    let plan = {
        let g = shared.lock().unwrap();
        match faucet.dispense(&*g, &mut rng) {
            DispenseOutcome::Ready { plan, .. } => plan,
            other => panic!("the faucet must dispense: {other:?}"),
        }
    };
    let grant_entry = plan.entry.clone();
    {
        let mut g = shared.lock().unwrap();
        match g.submit_tx(grant_entry.clone(), plan.discovery.clone(), &ConsensusVerifier) {
            SubmitOutcome::Accepted(_) => {}
            other => panic!("the production verifier must admit a real grant: {other:?}"),
        }
    }
    faucet.confirm(*plan);
    // The grant block IS finalized: the note being spent has to be inside the
    // anchor the wallet will build against.
    let grant_height = mine(&shared, &mut tip, vec![grant_entry], burn, &ConsensusVerifier, true);

    // ---- and now the chain runs AHEAD of its finality ---------------------
    // These blocks append matured coinbase leaves and are never finalized, so
    // the served leaf count exceeds the newest anchor's. This is the ordinary
    // state of a live chain, and the state the earlier fixture hid.
    for _ in 0..UNFINALIZED_LAG_BLOCKS {
        mine(&shared, &mut tip, Vec::new(), burn, &NoTx, false);
    }

    // ---- the deployed discovery server, over a real socket ----------------
    let discovery_view = Arc::new(Mutex::new(Arc::new(DiscoveryView::default())));
    let leaves_view = Arc::new(Mutex::new(Arc::new(LeavesView::default())));
    let anchors_view = Arc::new(Mutex::new(Arc::new(AnchorsView::default())));
    refresh(&shared, &discovery_view, &leaves_view, &anchors_view);
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

    // ---- the sender DETECTS its funds: light-client scan, real socket -----
    let sender_dk = sender.diversified_keypair(&sender.diversifier_at_index(0)).dk;
    let found = light_client_scan(&base, &sender_dk, 0, tip.height, ScanConfig::default(), &mut rng)
        .expect("the scan runs against the live node");
    assert!(
        matches!(found.completeness(), Completeness::Complete | Completeness::Shadowed { .. }),
        "a spend is only built on complete knowledge: {:?}",
        found.completeness()
    );
    assert_eq!(found.notes.len(), 1, "the sender detects exactly the grant");
    assert_eq!(found.notes[0].detected.note.value, DEFAULT_GRANT_BESSEL);
    assert_eq!(found.notes[0].at().height, grant_height, "…where it was mined");
    let spendables: Vec<Spendable> = found
        .notes
        .iter()
        .map(|ln| Spendable {
            div_index: 0,
            value: ln.detected.note.value,
            rho: ln.detected.note.rho,
            rseed: ln.detected.note.rseed,
        })
        .collect();

    // ---- SYNC over GET /v1/tree/leaves, ANCHOR over GET /v1/anchors -------
    let wallet_dir = tmp("first_spend");
    let (synced, anchor) = sync_and_select(
        &wallet_dir,
        &HttpLeafSource::new(&node_url),
        &HttpAnchorSource::new(&node_url),
    )
    .expect("the leaf stream syncs and an anchor is selected");

    {
        let g = shared.lock().unwrap();
        assert_eq!(
            synced.count,
            g.node().commitments().tree().len(),
            "the wallet caught up with everything the node served"
        );
    }
    // 🔴 The property this whole issue turned on. If this ever reads `==`, the
    // test has stopped covering the finality cadence and the anchor selection
    // has become a no-op.
    assert!(
        anchor.count < synced.count,
        "the anchor ({}) must be BEHIND the served tip ({}) — a witness is built against a \
         FINALIZED root, and this chain is {UNFINALIZED_LAG_BLOCKS} blocks ahead of its finality",
        anchor.count,
        synced.count
    );
    assert_eq!(anchor.leaves_behind_local, synced.count - anchor.count);
    {
        // The selected anchor is one the node would actually accept.
        let g = shared.lock().unwrap();
        assert!(
            g.node().is_valid_anchor(&anchor.root),
            "the selected root is a valid anchor by the node's own rule"
        );
        let tip_root = qlab_node::main_chain_roots_of(g.node())
            .last()
            .map(|(_, r)| *r)
            .expect("a tip root");
        assert!(
            !g.node().is_valid_anchor(&tip_root),
            "…and the tip root is NOT — which is why building at synced.count would fail"
        );
    }

    // ---- build_send: unchanged, wired — one real prove --------------------
    let art = build_send(
        &sender,
        &spendables,
        &recipient_addr,
        AMOUNT,
        &synced.tree,
        anchor.count,
        &mut rng,
    )
    .expect("the wired path builds and proves");
    assert!(art.used_dummy, "one grant note ⇒ the #219 dummy slot");
    assert_eq!(art.change_value, DEFAULT_GRANT_BESSEL - AMOUNT - art.fee);

    // ---- SUBMIT over POST /v1/tx, on a real socket ------------------------
    // The client blocks on the verdict, so the submission runs on its own
    // thread while this one plays the run loop and drains the queue.
    let wire = art.wire_bytes.clone();
    let submit_url = node_url.clone();
    let client = std::thread::spawn(move || submit_tx(&submit_url, &wire));

    let request = submit_rx.recv().expect("the submission reaches the queue");
    let verdict = {
        // Exactly what `RunningNode::submit_remote_tx` does, via the same
        // `NodeRpc::submit_tx` checks: the discovery artifacts are rebuilt from
        // the COMMITTED bytes, precisely as a server decoding the wire must.
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
        let mut g = shared.lock().unwrap();
        match g.submit_tx(request.tx.clone(), discovery, &ConsensusVerifier) {
            SubmitOutcome::Accepted(txid) => TxSubmitOutcome::Accepted { txid },
            SubmitOutcome::Duplicate => panic!("first submission cannot be a duplicate"),
            other => panic!("the node must admit the wallet's spend, got {other:?}"),
        }
    };
    request.reply.try_send(verdict).expect("the handler is still waiting");

    let answer = client.join().unwrap().expect("the POST completed");
    assert_eq!(answer.status, 202, "202 Accepted: {}", answer.body);
    assert_eq!(answer.class(), SubmitClass::Accepted);
    let txid_hex = answer.txid_hex().expect("accepted carries the statement tx id").to_string();
    assert_eq!(txid_hex.len(), 64, "a full 32-byte id in hex: {txid_hex}");
    assert!(answer.is_in_flight());

    // ---- mined under the production verifier ------------------------------
    let send_height = mine(&shared, &mut tip, vec![art.entry.clone()], burn, &ConsensusVerifier, true);

    // ---- the recipient DETECTS the spend's output — C5, closed ------------
    let recipient_dk =
        recipient_wallet.diversified_keypair(&recipient_wallet.diversifier_at_index(0)).dk;
    let got = light_client_scan(
        &base,
        &recipient_dk,
        send_height,
        send_height,
        ScanConfig::default(),
        &mut rng,
    )
    .expect("the recipient's scan runs against the live node");
    assert_eq!(got.notes.len(), 1, "the recipient detects exactly the spend's output");
    assert_eq!(got.notes[0].detected.note.value, AMOUNT, "…at the sent amount");

    // …and the change came home: the sender's own scan of the spend block.
    let change = light_client_scan(
        &base,
        &sender_dk,
        send_height,
        send_height,
        ScanConfig::default(),
        &mut rng,
    )
    .expect("the sender's rescan runs");
    assert_eq!(change.notes.len(), 1, "the sender detects its change output");
    assert_eq!(change.notes[0].detected.note.value, art.change_value);

    // ---- and a resync picks up the spend block without re-downloading -----
    refresh(&shared, &discovery_view, &leaves_view, &anchors_view);
    let (resynced, _) = sync_and_select(
        &wallet_dir,
        &HttpLeafSource::new(&node_url),
        &HttpAnchorSource::new(&node_url),
    )
    .expect("the second sync verifies too");
    assert!(resynced.count > synced.count, "the spend block's leaves arrived");
    assert_eq!(
        resynced.fetched,
        resynced.count - synced.count,
        "only the new leaves travelled — the cache IS the high-water mark"
    );

    server.shutdown();
}
