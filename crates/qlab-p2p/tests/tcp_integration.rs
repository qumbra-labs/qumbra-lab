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
use qlab_p2p::transport::{TcpTransport, Transport};
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
    TxEntry::with_placeholder_discovery(vec![seed; 48], TxPublic {
            anchor: [seed; 32],
            nullifiers: vec![[seed; 32]],
            commitments: vec![[seed.wrapping_add(3); 32]],
            bucket: ArityBucket::TwoByTwo,
            fee: 1_000_000,
        })
}

/// Drive two nodes until `done` holds or the budget is exhausted.
fn pump(a: &mut TcpP2p, b: &mut TcpP2p, mut done: impl FnMut(&TcpP2p, &TcpP2p) -> bool) -> bool {
    let start = std::time::Instant::now();
    for _ in 0..400 {
        // Real elapsed milliseconds: over a real transport the honest clock is the
        // wall clock, which is also what `qumbra-node` feeds `tick` (issue #91).
        let now_ms = start.elapsed().as_millis() as u64;
        a.tick(now_ms);
        b.tick(now_ms);
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

/// Poll `t` for up to ~1 s, returning every frame of type `want` that arrived.
fn collect(t: &TcpTransport, want: qlab_p2p::MsgType) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for _ in 0..100 {
        for (_, f) in t.poll() {
            if qlab_p2p::Envelope::decode(&f).map(|e| e.msg_type == want).unwrap_or(false) {
                out.push(f);
            }
        }
        if !out.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    out
}

#[test]
fn getaddr_throttling_survives_a_reconnect() {
    // Issue #91, decision 1 — the trap. A rate limit hung on the connection is a
    // rate limit an attacker resets with a TCP handshake, i.e. no rate limit at
    // all. The budget is keyed on the remote HOST, so the second connection —
    // fresh socket, fresh ephemeral port, fresh PeerId — lands on the same
    // already-spent allowance.
    use qlab_p2p::MsgType;

    let ts = TcpTransport::bind("127.0.0.1:0").unwrap();
    let server_addr = ts.local_addr().to_string();
    let mut server = P2pNode::new(ts, stub(), [1u8; 32]);
    // Give the server something worth asking for.
    for i in 0..3u8 {
        let a = format!("198.51.100.{i}:9333");
        server.addrs_mut().add_seed(a.clone());
        server.addrs_mut().on_dial_success(&a, qlab_p2p::PeerId(900 + i as u64));
    }
    assert_eq!(server.addrs().gossipable().len(), 3);

    let getaddr = qlab_p2p::Envelope::new(MsgType::GetAddr, Vec::new()).encode();

    // --- first connection: served ---
    let c1 = TcpTransport::bind("127.0.0.1:0").unwrap();
    let p1 = c1.connect(&server_addr).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    c1.send(p1, &getaddr).unwrap();
    for _ in 0..50 {
        server.tick(0);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(collect(&c1, MsgType::Addr).len(), 1, "the first ask is answered");
    let spent = server.rate_stats();
    let handle_1 = server.peers().all_peers();
    assert_eq!(handle_1.len(), 1);
    c1.shutdown();
    drop(c1);
    std::thread::sleep(Duration::from_millis(150));

    // --- reconnect from the same host: a brand-new socket and PeerId ---
    let c2 = TcpTransport::bind("127.0.0.1:0").unwrap();
    let p2 = c2.connect(&server_addr).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    c2.send(p2, &getaddr).unwrap();
    for _ in 0..50 {
        server.tick(1_000); // 1 s later — far inside the 30 s serve interval
        std::thread::sleep(Duration::from_millis(5));
    }
    let handles_now = server.peers().all_peers();
    assert!(
        handles_now.len() > handle_1.len() || handles_now != handle_1,
        "the reconnect really is a new connection on the server side: {handle_1:?} -> {handles_now:?}"
    );
    assert!(
        collect(&c2, MsgType::Addr).is_empty(),
        "reconnecting must not hand out a fresh allowance"
    );
    assert_eq!(
        server.rate_stats().throttled_getaddr,
        spent.throttled_getaddr + 1,
        "and the refusal is counted, not silently lost"
    );

    // --- past the interval, the same host is served again: a throttle, not a ban ---
    c2.send(p2, &getaddr).unwrap();
    for _ in 0..50 {
        server.tick(qlab_p2p::ratelimit::GETADDR_SERVE_INTERVAL_MS + 1);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(collect(&c2, MsgType::Addr).len(), 1, "the allowance refills; nobody was banned");
    for pid in server.peers().all_peers() {
        assert_eq!(server.peers().get(pid).unwrap().score, 0, "throttling never scores");
    }

    server.transport().shutdown();
    c2.shutdown();
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
