//! The first-spend e2e (issue #276) — C5's lab half, as one test: a local
//! devnet mines to maturity, the faucet funds a wallet with a REAL grant, the
//! wallet detects it by light-client scan over a real socket, syncs its local
//! commitment tree **over `GET /v1/tree/leaves`**, picks its anchor **over
//! `GET /v1/anchors`**, builds and REALLY proves a spend to a stranger, submits
//! it **over `POST /v1/tx`** and gets the typed outcome back — and the
//! recipient's scan detects the spend's output.
//!
//! Since lab issue #314 it carries the other end of that sentence too: the
//! sender's **post-spend rescan**, where the spent note stops being spendable.
//! That half is asserted against the nullifiers the real proof actually
//! declared, so the balance's derivation is checked against the spend path's
//! own output and not against a second copy of the formula. The cheap version
//! of the same story — no STARK, debug-runnable — is `spent_subtraction.rs`.
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
//! `qumbra_node::run::tests::the_submit_route_judges_over_a_real_socket_through_the_run_loop`
//! (which is also the one place `/v1/anchors` is exercised off a real
//! `RunningNode`).
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
use qumbra_wallet::history::{self, AddressScan, Event, Outgoing};
use qumbra_wallet::net::{HttpAnchorSource, HttpLeafSource, HttpNullifierSource, SubmitClass};
use qumbra_wallet::spend::{preflight, prove, select, submit, SendRequest};
use qumbra_wallet::sends::SendRecord;
use qumbra_wallet::spent::{fetch_spent, note_nullifier, subtract_spent};
use qumbra_wallet::store::WalletDir;
use qumbra_wallet::sync::sync_and_select;
use qumbra_wallet::view::SpentCoverage;
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
    let sender_seed = MasterSeed::from_entropy([21u8; 32]);
    let sender = Wallet::from_master_seed(&sender_seed, 0);
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

    // ---- select → prove: the serializable host seam, one real prove -------
    WalletDir::create(&wallet_dir, sender_seed).expect("the sender wallet dir exists");
    let req = SendRequest {
        dir: &wallet_dir,
        url: &base,
        node_url: &node_url,
        recipient: &recipient_addr,
        contact_name: None,
        amount: AMOUNT,
        scan_to: tip.height,
        no_submit: false,
    };
    let mut ignore = |_| {};
    let bundle = select(&req, &mut ignore).expect("phase 1 selects and serializes a witness");
    assert_eq!(bundle.anchor(), anchor.root, "the callable phase uses the same finalized anchor");
    let current = preflight(&req).expect("fresh public chain facts are available");
    let art = prove(&bundle, &current, &mut ignore).expect("the host phase proves from the bundle");
    assert!(art.used_dummy, "one grant note ⇒ the #219 dummy slot");
    assert_eq!(art.change_value, DEFAULT_GRANT_BESSEL - AMOUNT - art.fee);

    // ---- SUBMIT over POST /v1/tx, on a real socket ------------------------
    // The client blocks on the verdict, so the submission runs on its own
    // thread while this one plays the run loop and drains the queue.
    let wire = art.wire_bytes.clone();
    let submit_url = node_url.clone();
    let client = std::thread::spawn(move || submit(&submit_url, &wire, &mut |_| {}));

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

    // ---- 🔴 lab issue #314: the spent note stops being spendable ------------
    //
    // The post-spend rescan over the WHOLE range, which is where the defect
    // lived: the scan alone still sees the grant note and the change note and
    // sums both, under `complete`. The subtraction is what makes the number
    // true — and it runs against `/v1/nullifiers` on the same deployed
    // discovery server, over the same real socket as everything else here.
    //
    // The nullifier being matched is not a fixture: `art.entry.public.nullifiers`
    // is what the bundle prover REALLY proved and the node REALLY admitted, so this
    // asserts the balance's derivation against the spend path's own output
    // rather than against a second copy of the formula.
    refresh(&shared, &discovery_view, &leaves_view, &anchors_view);
    let full_rescan =
        light_client_scan(&base, &sender_dk, 0, tip.height, ScanConfig::default(), &mut rng)
            .expect("the sender's full rescan runs");
    assert_eq!(full_rescan.notes.len(), 2, "the grant AND the change are both detected");
    assert_eq!(
        full_rescan.spendable_value(),
        u128::from(DEFAULT_GRANT_BESSEL + art.change_value),
        "the pre-#314 figure: outputs only, spent note included, under `complete`"
    );

    let spent_set = fetch_spent(&HttpNullifierSource::new(&node_url), 0, tip.height)
        .expect("the deployed server serves its nullifier stream");
    spent_set
        .covers_outputs(full_rescan.stats.compact_range_served)
        .expect("the stream covers every height the outputs came from");
    let sender_report = subtract_spent(&sender, 0, &full_rescan.notes, &spent_set);

    let derived = note_nullifier(&sender, 0, &found.notes[0].detected.note);
    assert!(
        art.entry.public.nullifiers.contains(&derived),
        "the balance derives the SAME nullifier the proved spend declared"
    );
    assert_eq!(sender_report.spent.len(), 1, "exactly the note that was spent");
    assert_eq!(sender_report.spent[0].nullifier, derived);
    assert_eq!(
        sender_report.spendable_value(),
        u128::from(art.change_value),
        "the sender's spendable DROPS to the change alone"
    );
    assert_eq!(
        u128::from(DEFAULT_GRANT_BESSEL) - sender_report.spendable_value(),
        u128::from(AMOUNT + art.fee),
        "…i.e. by exactly (spent note − change)"
    );

    // ---- 🔴 the LEDGER over the same real spend ---------------------------
    //
    // `history` renders exactly what happened here, and the arithmetic it
    // reconciles is this transaction's own: the inputs are the note the STARK
    // really proved a spend of, the change is the output the node really
    // admitted, and the fee is read from the posted table rather than from
    // anything this test carries. If the ledger and the spend path ever drifted,
    // this is where it shows — against a real proof rather than a fixture.
    let ledger_scans = vec![AddressScan {
        div_index: 0,
        address_short: sender.address_at_index(0).short().encode(),
        outcome: Ok(full_rescan),
    }];
    let coverage = SpentCoverage::Covered { range: spent_set.covered };
    let ledger =
        history::build(&sender, &ledger_scans, Some(&spent_set), &coverage, None, (0, tip.height));
    assert!(ledger.gaps.is_empty(), "a fully accounted ledger: {:?}", ledger.gaps);
    assert_eq!(ledger.events.len(), 2, "the grant receipt and the send — the change is folded in");
    match &ledger.events[0] {
        Event::Received(r) => {
            assert_eq!((r.height, r.value), (grant_height, DEFAULT_GRANT_BESSEL))
        }
        other => panic!("first event is the grant receipt, got {other:?}"),
    }
    let ledger_send = match &ledger.events[1] {
        Event::Send(s) => s,
        other => panic!("second event is the send, got {other:?}"),
    };
    assert_eq!(ledger_send.height, send_height, "the chain's date is the nullifier's block");
    assert_eq!(ledger_send.inputs_total, u128::from(DEFAULT_GRANT_BESSEL));
    assert_eq!(ledger_send.change_total, u128::from(art.change_value));
    assert_eq!(
        ledger_send.outgoing,
        Outgoing::Exact { amount: u128::from(AMOUNT), fee: art.fee },
        "inputs − change − posted fee == the amount this wallet really sent"
    );
    let totals = ledger.totals.clone().expect("an accounted ledger has totals");
    assert_eq!(
        totals.total_in - totals.total_out - totals.fees_paid,
        ledger.current_spendable.expect("quotable"),
        "in − out − fees == current spendable"
    );
    assert_eq!(ledger.current_spendable, Some(u128::from(art.change_value)));

    let chain_only = history::render(&ledger, &node_url);
    assert!(chain_only.contains("recipient: not recorded"), "{chain_only}");

    // …and with the local record this run really would have written, the one
    // line the chain can never carry is filled in and labeled — and no figure
    // above it moves.
    // The SAME constructor `send` runs — not a copy of it — over the public
    // surface a real STARK proved and a real node admitted.
    let record = SendRecord::declared(
        &art.entry.public,
        anchor.tip_height,
        AMOUNT,
        recipient_addr.short().encode(),
    );
    assert_eq!(record.fee, art.fee, "the record's fee is the DECLARED one");
    assert_eq!(record.nullifiers, art.entry.public.nullifiers);
    assert_eq!(
        qumbra_wallet::sends::hex32(&record.txid),
        txid_hex,
        "🔴 the locally derived statement id IS the one the node answered with"
    );
    let log = qumbra_wallet::sends::SendLog { records: vec![record] };
    let labeled = history::build(
        &sender,
        &ledger_scans,
        Some(&spent_set),
        &coverage,
        Some(&log),
        (0, tip.height),
    );
    assert_eq!(labeled.totals, ledger.totals, "local memory labels; it moves no chain figure");
    assert_eq!(labeled.unmatched_records, 0);
    let labeled_text = history::render(&labeled, &node_url);
    assert!(
        labeled_text
            .contains(&format!("recipient: {} (local record)", recipient_addr.short().encode())),
        "{labeled_text}"
    );

    // The negative, on the same set: the recipient never spent, so nothing of
    // its is subtracted.
    let recipient_full = light_client_scan(
        &base,
        &recipient_dk,
        0,
        tip.height,
        ScanConfig::default(),
        &mut rng,
    )
    .expect("the recipient's full rescan runs");
    let recipient_report = subtract_spent(&recipient_wallet, 0, &recipient_full.notes, &spent_set);
    assert_eq!(
        recipient_report.spendable_value(),
        u128::from(AMOUNT),
        "the recipient's spendable RISES by exactly the amount sent"
    );
    assert!(recipient_report.spent.is_empty(), "and it has spent nothing");

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
