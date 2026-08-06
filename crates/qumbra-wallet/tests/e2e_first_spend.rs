//! The first-spend e2e (issue #276) — C5's lab half, as one test: a local
//! devnet mines to maturity, the faucet funds a wallet with a REAL grant, the
//! wallet detects it by light-client scan over a real socket, syncs its local
//! commitment tree, builds and REALLY proves a spend to a stranger, the node
//! admits it with the typed outcome, it is mined under the production verifier
//! — and the recipient's scan detects the spend's output.
//!
//! ## The two seams this test crosses, and where they stand
//!
//! The wallet half's two served-wire seams are the sibling server issue #275's
//! (`GET /v1/tree/leaves` + `POST /v1/tx` on `qumbra-node`'s discovery
//! server). Until that branch is in this tree, this test crosses them at the
//! nearest in-process equivalent — [`LeafSource`] over the node's own tree,
//! and [`NodeRpc::submit_tx`] with the same typed outcome the endpoint wraps —
//! and the swap to the real HTTP endpoints is a two-function change, called
//! out below at each seam. The scan already runs over a real socket.
//!
//! Two real proves (grant + spend), ~12 GB peak each, sequential — release
//! only, behind the rig lock, per the bench discipline.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use qlab_cbserver::client::{light_client_scan, Completeness, ScanConfig};
use qlab_devnet::body::{BlockBody, TxEntry, TxVerifier};
use qlab_devnet::header::BlockHeader;
use qlab_devnet::params_devnet::GENESIS_DIFFICULTY;
use qlab_faucet::{
    DispenseOutcome, Faucet, FaucetConfig, FaucetLimits, TicketPolicy, TicketSecret,
    DEFAULT_GRANT_BESSEL,
};
use qlab_node::{
    coinbase, genesis_block, ChainStore, CommitmentStore, MemNodeRpc, NodeRpc, NodeState,
    SubmitOutcome,
};
use qlab_note::compact::decode_committed_discovery;
use qlab_note::hash::digest_bytes;
use qlab_wallet::seed::MasterSeed;
use qlab_wallet::address::Diversifier;
use qlab_wallet::Wallet;
use qumbra_faucet::harvest::{harvest_matured, spendable_at_tip};
use qumbra_node::verifier::ConsensusVerifier;
use qumbra_wallet::send::{build_send, Spendable};
use qumbra_wallet::sync::{sync_tree, LeafChunk, LeafSource};
use rand::rngs::StdRng;
use rand::SeedableRng;

/// 4 QMB of the 10 QMB grant — amount + posted fee + change all non-trivial.
const AMOUNT: u64 = 400_000_000;

/// Fixture blocks carry no transactions; grant/spend blocks run the shipping
/// verifier. Same shape as the faucet acceptance rig.
struct NoTx;
impl TxVerifier for NoTx {
    fn verify_tx(&self, _: &TxEntry) -> bool {
        unreachable!("fixture blocks carry no transactions")
    }
}

/// Mine one block carrying `txs`, paying `rkm`, and finalize it — the devnet's
/// clock. Finalizing every block keeps the current tree root a valid anchor.
fn mine<V: TxVerifier>(
    shared: &Arc<Mutex<MemNodeRpc>>,
    tip: &mut BlockHeader,
    txs: Vec<TxEntry>,
    rkm: [u64; 4],
    verifier: &V,
) -> u64 {
    let height = tip.height + 1;
    let body = BlockBody { txs, coinbase: coinbase(height), coinbase_rkm: rkm };
    let header = BlockHeader::child_of(tip, height * 75, GENESIS_DIFFICULTY, body.commitment());
    let mut g = shared.lock().unwrap();
    let node = g.node_mut();
    let hash = node.apply_block(header, body, verifier).expect("block applies");
    node.finalize(hash).expect("finalize");
    *tip = header;
    height
}

fn mine_empty(shared: &Arc<Mutex<MemNodeRpc>>, tip: &mut BlockHeader, n: u64, rkm: [u64; 4]) {
    for _ in 0..n {
        mine(shared, tip, Vec::new(), rkm, &NoTx);
    }
}

/// 🔴 SEAM (B1): the wallet's leaf source. Today: the node's own tree,
/// in-process, chunk-bounded like the real stream. With #275 in the tree this
/// becomes the HTTP client over `GET /v1/tree/leaves?from=N`, and nothing else
/// in this test moves.
struct NodeLeafSource {
    rpc: Arc<Mutex<MemNodeRpc>>,
    chunk: u64,
}

impl LeafSource for NodeLeafSource {
    fn fetch_from(&self, from: u64) -> Result<LeafChunk, String> {
        let g = self.rpc.lock().unwrap();
        let tree = g.node().commitments().tree();
        let len = tree.len();
        let lo = from.min(len);
        let hi = (lo + self.chunk).min(len);
        Ok(LeafChunk {
            leaves: (lo..hi).map(|p| digest_bytes(&tree.leaf(p))).collect(),
            tree_size: len,
            root: digest_bytes(&tree.root()),
        })
    }
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
    // ---- the devnet: one real node, served over a real socket -------------
    let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
    let mut tip = genesis.header();
    let mut node = qlab_node::MemNode::in_memory(genesis);
    let ghash = node.chain().genesis_block_hash();
    assert!(node.finalize(ghash).expect("finalize genesis").is_recorded());
    let shared = Arc::new(Mutex::new(NodeRpc::new(node)));
    let handle = qlab_node::serve(Arc::clone(&shared));
    let base = handle.base_url();

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
    let grant_height = mine(&shared, &mut tip, vec![grant_entry], burn, &ConsensusVerifier);

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

    // ---- the wallet SYNCS its local tree and verifies it ------------------
    // Chunk far below the leaf count so the client genuinely loops.
    let wallet_dir = tmp("first_spend");
    let source = NodeLeafSource { rpc: Arc::clone(&shared), chunk: 16 };
    let synced = sync_tree(&wallet_dir, &source).expect("tree sync verifies against the anchor");
    {
        let g = shared.lock().unwrap();
        assert_eq!(synced.count, g.node().commitments().tree().len(), "caught up");
        assert_eq!(
            digest_bytes(&synced.tree.root_at(synced.count)),
            g.node().commitment_root(),
            "the verified root IS the node's current anchor"
        );
    }

    // ---- build_send: unchanged, wired — one real prove --------------------
    let art = build_send(
        &sender,
        &spendables,
        &recipient_addr,
        AMOUNT,
        &synced.tree,
        synced.count,
        &mut rng,
    )
    .expect("the wired path builds and proves");
    assert!(art.used_dummy, "one grant note ⇒ the #219 dummy slot");
    assert_eq!(art.change_value, DEFAULT_GRANT_BESSEL - AMOUNT - art.fee);

    // ---- 🔴 SEAM (A1): submission. Today: the same typed-outcome API the
    // #275 endpoint wraps (`POST /v1/tx` body = art.wire_bytes; the server
    // decodes and runs exactly these checks). The discovery artifacts travel
    // IN the committed bytes — reconstructed here precisely as a server
    // decoding the wire must.
    let (bundles, payloads) = decode_committed_discovery(&art.entry.discovery)
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
    let txid = {
        let mut g = shared.lock().unwrap();
        match g.submit_tx(art.entry.clone(), discovery, &ConsensusVerifier) {
            SubmitOutcome::Accepted(id) => id,
            other => panic!("the node must admit the wallet's spend, got the typed outcome {other:?}"),
        }
    };
    assert_ne!(txid, [0u8; 32], "a real transaction id came back");

    // ---- mined under the production verifier ------------------------------
    let send_height = mine(&shared, &mut tip, vec![art.entry.clone()], burn, &ConsensusVerifier);

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
}
