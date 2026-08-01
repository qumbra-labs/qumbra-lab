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
