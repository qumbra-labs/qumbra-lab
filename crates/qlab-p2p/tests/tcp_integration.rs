//! End-to-end integration over the **real TCP transport** — the same
//! `P2pNode` logic the in-process unit tests exercise, now driven across
//! loopback sockets. Proves the dual-transport claim: identical node code,
//! two transports.
//!
//! TCP reader threads are asynchronous to `tick()`, so these tests spin a
//! poll loop with short sleeps until the expected state is reached (bounded, so
//! a genuine failure still terminates).

use std::time::Duration;

use qlab_devnet::body::{TxEntry, TxPublic};
use qlab_devnet::committee::{devnet_committee, Checkpoint, CommitteeState, Validator, Vote};
use qlab_devnet::fees::ArityBucket;
use qlab_devnet::header::BlockHeader;
use qlab_devnet::params_devnet::BOND_AMOUNT;

use qlab_p2p::codec::tx_id;
use qlab_p2p::n1::{BlockIngest, ChainView, StubNode, TxPool};
use qlab_p2p::sync::SyncPhase;
use qlab_p2p::transport::TcpTransport;
use qlab_p2p::P2pNode;

type TcpP2p = P2pNode<TcpTransport, StubNode>;

fn genesis() -> BlockHeader {
    BlockHeader::genesis(1000, 0)
}

fn stub() -> StubNode {
    let (committee, _v) = devnet_committee(7);
    StubNode::new(genesis(), CommitteeState::new(committee, BOND_AMOUNT))
}

/// A stub node whose main chain already has `n` blocks past genesis.
fn chain_stub(n: u64) -> StubNode {
    let mut node = stub();
    let mut parent = genesis();
    for i in 0..n {
        let child = BlockHeader::child_of(&parent, (i + 1) * 75, 1000, [(i as u8) + 1; 32]);
        node.ingest_header(child);
        parent = child;
    }
    node
}

fn tx(seed: u8) -> TxEntry {
    TxEntry {
        proof: vec![seed; 48],
        public: TxPublic {
            anchor: [seed; 32],
            nullifiers: vec![[seed; 32]],
            commitments: vec![[seed.wrapping_add(3); 32]],
            bucket: ArityBucket::TwoByTwo,
            fee: 1_000_000,
        },
    }
}

/// Drive two nodes until `done` holds or the budget is exhausted.
fn pump(a: &mut TcpP2p, b: &mut TcpP2p, mut done: impl FnMut(&TcpP2p, &TcpP2p) -> bool) -> bool {
    for _ in 0..400 {
        a.tick();
        b.tick();
        if done(a, b) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(3));
    }
    done(a, b)
}

#[test]
fn tcp_handshake_gossip_and_header_first_sync() {
    // Node A: a 12-block chain. Node B: empty. Real sockets.
    let ta = TcpTransport::bind("127.0.0.1:0").unwrap();
    let tb = TcpTransport::bind("127.0.0.1:0").unwrap();
    let addr_a = ta.local_addr().to_string();

    let mut a = P2pNode::new(ta, chain_stub(12), [1u8; 32]);
    let mut b = P2pNode::new(tb, stub(), [2u8; 32]);

    // B dials A and opens the handshake.
    let pid = b.transport().connect(&addr_a).unwrap();
    b.add_peer(pid, Some(addr_a));

    // Handshake completes both ways.
    assert!(
        pump(&mut a, &mut b, |a, b| {
            b.peers().best_height() == Some(12) && a.peers().ready_peers().len() == 1
        }),
        "handshake did not complete over TCP"
    );

    // Header-first sync brings B up to A's tip height 12.
    assert!(
        pump(&mut a, &mut b, |_, b| b.node().tip_height() == 12),
        "B did not sync to height 12 (got {})",
        b.node().tip_height()
    );
    assert_eq!(b.node().chain().tip_hash(), a.node().chain().tip_hash());
    assert_eq!(*b.sync_phase(), SyncPhase::Synced);

    // Transaction gossip A → B over the socket.
    let t = tx(7);
    let id = tx_id(&t);
    a.announce_tx(t);
    assert!(
        pump(&mut a, &mut b, |_, b| b.node().has_tx(&id)),
        "tx did not propagate over TCP"
    );

    a.transport().shutdown();
    b.transport().shutdown();
}

#[test]
fn tcp_checkpoint_gossip_finalizes_peer() {
    // Shared committee so votes verify on both nodes.
    let (committee, validators) = devnet_committee(7); // quorum 5
    let ta = TcpTransport::bind("127.0.0.1:0").unwrap();
    let tb = TcpTransport::bind("127.0.0.1:0").unwrap();
    let addr_a = ta.local_addr().to_string();

    let mut a = P2pNode::new(
        ta,
        StubNode::new(genesis(), CommitteeState::new(committee.clone(), BOND_AMOUNT)),
        [1u8; 32],
    );
    let mut b = P2pNode::new(
        tb,
        StubNode::new(genesis(), CommitteeState::new(committee, BOND_AMOUNT)),
        [2u8; 32],
    );

    let pid = b.transport().connect(&addr_a).unwrap();
    b.add_peer(pid, Some(addr_a));
    assert!(pump(&mut a, &mut b, |a, b| a.peers().ready_peers().len() == 1
        && b.peers().ready_peers().len() == 1));

    let cp = Checkpoint::new(2, [0xAB; 32], [0xAB; 32]);
    let votes: Vec<Vote> =
        validators[..5].iter().map(|v: &Validator| v.sign_checkpoint(&cp)).collect();
    a.announce_checkpoint(cp, votes);

    assert!(
        pump(&mut a, &mut b, |_, b| b.node().finality().finalized_height() == Some(2)),
        "checkpoint did not finalize on peer B over TCP"
    );

    a.transport().shutdown();
    b.transport().shutdown();
}
