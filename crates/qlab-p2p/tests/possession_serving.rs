//! **Issue #198 — serving keys on POSSESSION, not on application.**
//!
//! `#182` made "a body this node holds" and "a body this node has applied" the
//! same predicate, which was true when it landed. `#178` broke the equivalence
//! four hours later: `Node::rewind_to` rebuilds the applied state from the
//! retained ancestor path, so a block the node undid leaves the state machine's
//! block store while its bytes stay in the append-only `blocks.log`.
//!
//! The live T0 net closed the loop on 2026-08-01 (#197): four hosts rewound past
//! height 1058 within 24 s, none had it applied, none would serve its body, all
//! four sat at `slag=1`, and the duty gate refuses to mine while lagging — so the
//! only thing that could clear the lag was a block and the only source of a block
//! was mining.
//!
//! The first test here is the FACT the fix rests on, and it is written so that it
//! states the answer either way: it puts a node in exactly that state and asks
//! what it can still produce.

use std::sync::Arc;

use qlab_devnet::body::{BlockBody, TxEntry, TxVerifier};
use qlab_devnet::committee::{devnet_committee, CommitteeState};
use qlab_devnet::header::BlockHeader;
use qlab_devnet::node::SimConfig;
use qlab_devnet::pow::KeccakPow;
use qlab_node::{genesis_block, read_records, ChainStore as _, LogRecord, MemNode, NodeState as _};
use qlab_p2p::adapter::NodeAdapter;
use qlab_p2p::n1::{BlockIngest, ChainView, IngestOutcome};
use qlab_p2p::peer::PeerId;
use qlab_p2p::transport::{InProcHub, InProcTransport};
use qlab_p2p::P2pNode;

/// The number of nodes in the acceptance net — the live T0 topology (#197).
const NET: usize = 4;

/// Only a tx marked `ok` verifies — the bodies here are coinbase-only, so nothing
/// depends on it.
#[derive(Clone)]
struct MarkerVerifier;
impl TxVerifier for MarkerVerifier {
    fn verify_tx(&self, entry: &TxEntry) -> bool {
        entry.proof == b"ok"
    }
}

type Adapter = NodeAdapter<KeccakPow, MarkerVerifier>;
type Node = P2pNode<InProcTransport, Adapter>;

fn easy_sim() -> SimConfig {
    SimConfig {
        block_time_secs: 2,
        genesis_difficulty: 8,
        mine_nonce_budget: 5_000_000,
        ..SimConfig::default()
    }
}

fn adapter(rkm: u64) -> Adapter {
    let (committee, _v) = devnet_committee(7);
    let mut a = NodeAdapter::new(
        CommitteeState::new(committee, qlab_devnet::params_devnet::BOND_AMOUNT),
        KeccakPow,
        MarkerVerifier,
        easy_sim(),
    );
    a.set_miner_rkm([rkm; 4]);
    a
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "qlab-i198-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::remove_dir_all(&d).ok();
    std::fs::create_dir_all(&d).expect("temp dir");
    d
}

/// Mine one block on `a` and apply it there. Returns it.
fn mine_on(a: &mut Adapter) -> (BlockHeader, BlockBody) {
    let (h, b) = a.mine_block().expect("mine");
    assert_eq!(a.ingest_block(h, b.clone()), IngestOutcome::Accepted);
    (h, b)
}

const SIM_TICK_MS: u64 = 10;

/// `slag` — the applied-state lag the duty gate reads, and the number every one of
/// the four T0 hosts was printing as `slag=1`.
fn slag(node: &Node) -> u64 {
    node.node().state_lag().blocks()
}

fn run(nodes: &mut [&mut Node], rounds: u64, base_ms: u64) -> u64 {
    let mut now = base_ms;
    for _ in 0..rounds {
        now += SIM_TICK_MS;
        for n in nodes.iter_mut() {
            n.tick(now);
        }
    }
    now
}

// ---------------------------------------------------------------------------
// 1. THE FACT
// ---------------------------------------------------------------------------

/// **Is a rewound body still retrievable, in-process?**
///
/// The task book asked for this answer before anything was built and asked that it
/// be reported whichever way it came out. The state is built the way the net built
/// it: apply a block, let a heavier sibling branch take fork choice, let the state
/// machine rewind past the block — then ask the node for that body.
///
/// This test is written against the SHIPPED behaviour on both sides of the fix:
/// the `stored_body` (applied) predicate keeps answering `None`, which is #182's
/// rule unchanged, and the disk log keeps the bytes. What changes with the fix is
/// the third assertion block, which lives in `possession_outlives_application`.
#[test]
fn fact_a_rewound_body_leaves_the_applied_store_and_stays_in_blocks_log() {
    let dir = temp_dir("fact");
    let (committee, _v) = devnet_committee(7);
    let mut loser = NodeAdapter::open(
        &dir,
        CommitteeState::new(committee, qlab_devnet::params_devnet::BOND_AMOUNT),
        KeccakPow,
        MarkerVerifier,
        easy_sim(),
    )
    .expect("open");
    loser.set_miner_rkm([0xB2; 4]);
    let mut winner = adapter(0xA1);

    // The loser mines and APPLIES its own height-1 block. At this instant it both
    // possesses and has applied L1 — the equivalence #182 was written under.
    let (lh1, lb1) = mine_on(&mut loser);
    let l1 = lh1.header_hash();
    assert!(loser.has_stored_body(&l1), "applied ⇒ servable, before the rewind");

    // A competing branch of two takes fork choice, and the state machine rewinds
    // past L1 to genesis and re-applies the winner's two blocks.
    let (wh1, wb1) = mine_on(&mut winner);
    let (wh2, wb2) = mine_on(&mut winner);
    assert_eq!(loser.ingest_block(wh1, wb1), IngestOutcome::Accepted);
    assert_eq!(loser.ingest_block(wh2, wb2), IngestOutcome::Accepted);
    assert_eq!(loser.state().tip_hash(), wh2.header_hash(), "the rewind happened");
    assert_eq!(loser.state_rewinds(), (1, 1), "one rewind, one applied block undone");

    // (a) The applied-block store no longer holds it — this is #182's predicate,
    //     and it is the whole of the defect: the node is now one of the four hosts.
    assert!(!loser.state().chain().contains(&l1), "the rewound block left the applied store");
    assert!(loser.stored_body(&l1).is_none(), "so `stored_body` — 'applied' — declines");

    // (b) The header is still known, on the losing fork. The node is not ignorant
    //     of the block; it is refusing to hand over something it can name.
    assert!(loser.has_header(&l1), "fork choice still knows the header");

    // (c) The bytes ARE on disk. `blocks.log` is append-only and `rewind_to`
    //     writes nothing, so the record the node wrote when it applied L1 is
    //     still there, verbatim — this is the half of the task book's question
    //     that comes out YES.
    let genesis = genesis_block(easy_sim().genesis_difficulty, 0);
    let replayed = MemNode::replay(&dir, genesis).expect("replay");
    assert_eq!(
        replayed.tip_hash(),
        wh2.header_hash(),
        "replay follows the same rewind and lands on the winner"
    );
    assert!(
        !replayed.chain().contains(&l1),
        "and it does NOT resurrect the rewound block into the APPLIED chain"
    );
    // The record itself, read straight off the log: the body survived the rewind.
    let logged = read_records(&dir).expect("read blocks.log");
    let found = logged.iter().find_map(|r| match r {
        LogRecord::Block(b) if b.header().header_hash() == l1 => Some(b),
        _ => None,
    });
    let found = found.expect("blocks.log still carries the rewound block's record");
    assert_eq!(
        found.body().commitment(),
        lb1.commitment(),
        "byte-for-byte the body that was rewound away"
    );

    std::fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------------------
// 2. THE FIX, at the predicate
// ---------------------------------------------------------------------------

/// **Possession outlives application.** Same construction as the fact test; the
/// question is the other one.
///
/// `stored_body` still answers "have I applied this" and still says no — #182's
/// rule is not widened, because four other callers read it as "applied" and one of
/// them (`on_block_announce`'s already-have early return) would drop the very body
/// that closes the gap. `held_body` is the new question and it says yes, with the
/// exact bytes: the served body commits to what the header committed to, so
/// serving from possession cannot re-open #77 from the serving side.
#[test]
fn possession_outlives_application_and_the_applied_predicate_is_unchanged() {
    let mut loser = adapter(0xB2);
    let mut winner = adapter(0xA1);

    let (lh1, lb1) = mine_on(&mut loser);
    let l1 = lh1.header_hash();
    let (wh1, wb1) = mine_on(&mut winner);
    let (wh2, wb2) = mine_on(&mut winner);
    assert_eq!(loser.ingest_block(wh1, wb1), IngestOutcome::Accepted);
    assert_eq!(loser.ingest_block(wh2, wb2), IngestOutcome::Accepted);
    assert_eq!(loser.state_rewinds(), (1, 1), "the rewind happened");

    // The applied predicate: unchanged, still no.
    assert!(!loser.has_stored_body(&l1), "`stored_body` still means APPLIED");
    assert!(loser.stored_body(&l1).is_none());
    // The possession predicate: yes, and byte-exact.
    let held = loser.held_body(&l1).expect("a rewound body is still HELD");
    assert_eq!(held.commitment(), lb1.commitment(), "the exact body the header commits to");
    assert_eq!(held.commitment(), lh1.tx_body_commitment, "…which is #77's binding");
    assert_eq!(loser.state().retained_bodies(), 1, "one block retained, the one undone");

    // And re-applying it drops the archive copy rather than keeping a duplicate:
    // extend the losing branch until it wins again and the block comes back.
    let (lh2, lb2) = {
        let mut ext = adapter(0xB2);
        assert_eq!(ext.ingest_block(lh1, lb1.clone()), IngestOutcome::Accepted);
        let b = ext.mine_block().expect("mine");
        assert_eq!(ext.ingest_block(b.0, b.1.clone()), IngestOutcome::Accepted);
        let c = ext.mine_block().expect("mine");
        assert_eq!(ext.ingest_block(c.0, c.1.clone()), IngestOutcome::Accepted);
        (vec![b.0, c.0], vec![b.1, c.1])
    };
    // The body at fork+1 has to be in hand before `rejoin_main_chain` will rewind,
    // and on `main` there was no way to obtain it — which is the deadlock. Here it
    // is handed over directly; the wire path is the acceptance test below.
    assert_eq!(loser.ingest_block(lh1, lb1), IngestOutcome::Duplicate);
    for (h, b) in lh2.into_iter().zip(lb2) {
        loser.ingest_block(h, b);
    }
    assert_eq!(loser.state().tip_height(), 3, "back on the branch it once abandoned");
    assert!(loser.has_stored_body(&l1), "applied again ⇒ the applied predicate answers");
    assert_eq!(loser.state().retained_bodies(), 2, "and the archive holds the W suffix, not L1");
}

/// **A rewind survives a restart with its possession intact** — the disk half of
/// the fact, turned into the behaviour that depends on it.
///
/// `blocks.log` still carries the rewound record (the fact test reads it back), and
/// `apply_logged_block` re-derives the rewind from it, so a node that restarts is
/// able to serve exactly what it could serve before. Both resume paths are checked
/// because they are different code: `replay` re-folds every record, `open` restores
/// a snapshot and rebuilds the prefix at the chain-store layer.
#[test]
fn possession_survives_open_and_replay() {
    let dir = temp_dir("restart");
    let (committee, _v) = devnet_committee(7);
    let mut loser = NodeAdapter::open(
        &dir,
        CommitteeState::new(committee, qlab_devnet::params_devnet::BOND_AMOUNT),
        KeccakPow,
        MarkerVerifier,
        easy_sim(),
    )
    .expect("open");
    loser.set_miner_rkm([0xB2; 4]);
    let mut winner = adapter(0xA1);

    let (lh1, lb1) = mine_on(&mut loser);
    let l1 = lh1.header_hash();
    let (wh1, wb1) = mine_on(&mut winner);
    let (wh2, wb2) = mine_on(&mut winner);
    loser.ingest_block(wh1, wb1);
    loser.ingest_block(wh2, wb2);
    assert_eq!(loser.state_rewinds(), (1, 1));
    assert!(loser.held_body(&l1).is_some(), "held before the restart");
    loser.save_snapshot().expect("snapshot");
    drop(loser);

    let genesis = genesis_block(easy_sim().genesis_difficulty, 0);
    for (what, node) in [
        ("open", MemNode::open(&dir, genesis.clone()).expect("open")),
        ("replay", MemNode::replay(&dir, genesis).expect("replay")),
    ] {
        assert_eq!(node.tip_hash(), wh2.header_hash(), "{what}: resumed on the winner");
        assert!(!node.chain().contains(&l1), "{what}: and did not resurrect it into state");
        let held = node.held_block(&l1).unwrap_or_else(|| panic!("{what}: still possessed"));
        assert_eq!(held.body().commitment(), lb1.commitment(), "{what}: the exact body");
    }
    std::fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------------------
// 3. THE GATE — it must survive, and its survival is asserted, not assumed
// ---------------------------------------------------------------------------

/// **The duty gate stays.** A node that is lagging AND actively receiving still
/// refuses to mine, for as long as it is lagging.
///
/// This is the assertion the task book asked for by name, and it is the one that
/// says what the fix is *not*. Ethereum's *"an optimistic validator MUST NOT
/// produce a block"* is right and #130 (a) is right to enforce it; a node mining on
/// a view it knows is stale can extend a chain it has not verified, and a halt is
/// recoverable where an invalid chain is not. The net stopping was the SAFE outcome
/// of a bad composition, and #198 does not trade that away — it removes the reason
/// the lag could never clear.
///
/// "And receiving" is the sharp part: the node is being driven, frames are landing,
/// bodies are arriving and being buffered, and the refusal holds through all of it
/// and only lifts on the tick where `slag` reaches zero.
#[test]
fn the_duty_gate_still_refuses_to_mine_while_lagging_and_receiving() {
    let mut factory = adapter(0xF0);
    let chain: Vec<(BlockHeader, BlockBody)> = (0..4).map(|_| mine_on(&mut factory)).collect();

    let hub = InProcHub::new();
    let mut server =
        P2pNode::new(InProcTransport::new(PeerId(1), Arc::clone(&hub)), adapter(0xF0), [1; 32]);
    let mut behind =
        P2pNode::new(InProcTransport::new(PeerId(2), Arc::clone(&hub)), adapter(0xB1), [2; 32]);
    hub.link(PeerId(1), PeerId(2));
    server.add_peer(PeerId(2), None);
    behind.add_peer(PeerId(1), None);

    // The server holds every body; the lagging node holds every HEADER and no body
    // past height 0 — `slag = 4`, the shape three T0 hosts sat in.
    for (h, b) in &chain {
        assert_eq!(server.node_mut().ingest_block(*h, b.clone()), IngestOutcome::Accepted);
        assert_eq!(behind.node_mut().ingest_header(*h), IngestOutcome::Accepted);
    }
    assert_eq!(slag(&behind), 4, "four blocks of applied-state lag");

    // Drive them together. On every tick where the node is still lagging it must
    // refuse, and it must be genuinely receiving while it refuses.
    let mut refused_while_receiving = 0u32;
    let mut cleared_at = None;
    let mut now = 0u64;
    for round in 0..400u32 {
        now += SIM_TICK_MS;
        server.tick(now);
        let frames = behind.tick(now);
        if slag(&behind) > 0 {
            assert!(
                behind.node_mut().mine_block().is_none(),
                "round {round}: lagging by {} and it mined anyway",
                slag(&behind)
            );
            if frames > 0 {
                refused_while_receiving += 1;
            }
        } else if cleared_at.is_none() {
            cleared_at = Some(round);
        }
    }
    assert!(
        refused_while_receiving > 0,
        "the refusal was never exercised on a tick that actually delivered frames"
    );
    assert!(cleared_at.is_some(), "the lag never cleared, so the gate was never the variable");
    // The refusal counter is the operator-visible half and it agrees.
    assert!(
        behind.node().lag_refusals("mine") > 0,
        "`qumbra_state_lag_refusals_total{{duty=mine}}` recorded the refusals"
    );
    // …and once caught up the same node mines. The gate is a lag gate, not a wall.
    assert_eq!(slag(&behind), 0);
    assert!(behind.node_mut().mine_block().is_some(), "caught up ⇒ the duty is allowed");
}
