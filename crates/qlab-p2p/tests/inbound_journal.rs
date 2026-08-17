//! **Issue #459's defect, replayed over real sockets.**
//!
//! The finding was measured, not assumed: on 2026-08-17 `66.96.196.8` held
//! established 9444 sessions with node1, node2, node3 and svc0-cbnode, and its
//! log-match count on **every** one of those hosts was `0`. The grep was widened
//! to any dotted quad rather than that one address — 41 matching lines per host,
//! all of them startup banners or outbound `DIAL` lines. An inbound connection
//! produced no record anywhere, so *who connected and when* could only be
//! answered by `ss`, which has no history.
//!
//! The whole file is therefore written as **content greps against the remote
//! address**, the same instrument the finding used, so that the property under
//! test is the one that failed: *an established inbound connection leaves a line
//! that names it*. A refactor that keeps some line but drops the address would
//! fail here, which is the point — the address is what made the census possible.
//!
//! Reader threads are asynchronous to the node loop, so every wait is bounded and
//! a genuine failure still terminates.

use std::time::Duration;

use qlab_devnet::committee::{devnet_committee, CommitteeState};
use qlab_devnet::header::BlockHeader;
use qlab_devnet::params_devnet::BOND_AMOUNT;

use qlab_p2p::n1::StubNode;
use qlab_p2p::transport::{TcpTransport, Transport};
use qlab_p2p::P2pNode;

type TcpP2p = P2pNode<TcpTransport, StubNode>;

fn stub() -> StubNode {
    let (committee, _v) = devnet_committee(7);
    StubNode::new(BlockHeader::genesis(1000, 0), CommitteeState::new(committee, BOND_AMOUNT))
}

fn node(t: TcpTransport, id: u8) -> TcpP2p {
    P2pNode::new(t, stub(), [id; 32])
}

/// Drain `n`'s connection journal until `want` matches one of the lines, or the
/// budget runs out. Returns everything collected, matched or not, so a failure
/// message can show what the node *did* say.
fn journal_until(n: &mut TcpP2p, want: impl Fn(&str) -> bool) -> Vec<String> {
    let start = std::time::Instant::now();
    let mut seen = Vec::new();
    for _ in 0..200 {
        n.tick(start.elapsed().as_millis() as u64);
        seen.extend(n.journal_conn_events());
        if seen.iter().any(|l| want(l)) {
            return seen;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    seen
}

/// Read one `key=value` field out of a journal line.
fn field<'a>(line: &'a str, key: &str) -> &'a str {
    line.split_whitespace()
        .find_map(|kv| kv.strip_prefix(&format!("{key}=")))
        .unwrap_or_else(|| panic!("no {key}= on {line}"))
}

/// 🔴 **The acceptance property: an established inbound connection MUST leave a
/// line, and that line MUST name the peer.**
///
/// This is #459 stated as a test. Before the fix the node's entire record of the
/// session below was empty; the assertion is a content grep for the remote
/// address, exactly the search that returned zero on four live hosts.
#[test]
fn an_established_inbound_connection_leaves_a_line_naming_the_peer() {
    let server = TcpTransport::bind("127.0.0.1:0").unwrap();
    let client = TcpTransport::bind("127.0.0.1:0").unwrap();
    let server_addr = server.local_addr().to_string();

    let mut a = node(server, 1);
    let mut b = node(client, 2);

    let pid = b.transport().connect(&server_addr).unwrap();
    b.add_peer(pid, Some(server_addr));

    let lines = journal_until(&mut a, |l| l.starts_with("ACCEPT "));
    let accept = lines
        .iter()
        .find(|l| l.starts_with("ACCEPT "))
        .unwrap_or_else(|| panic!("an accepted inbound left no line; journal: {lines:?}"));

    assert_eq!(field(accept, "result"), "ok", "{accept}");
    assert_eq!(field(accept, "dir"), "in", "{accept}");

    // The census property: the line carries a real remote endpoint, so grepping
    // for a peer's address finds the session it held. `127.0.0.1:<ephemeral>` is
    // the loopback shape of `66.96.196.8:41022`.
    let addr = field(accept, "addr");
    assert!(addr.starts_with("127.0.0.1:"), "the line must name the peer, got {addr}: {accept}");
    assert_ne!(addr, "unknown", "{accept}");
    // …and it is a *different* endpoint from the listener, i.e. the peer's
    // ephemeral port rather than our own bound one.
    assert_ne!(addr, a.transport().local_addr().to_string(), "{accept}");

    a.transport().shutdown();
    b.transport().shutdown();
}

/// The other half of §1: a session that ends says how long it lasted and why.
///
/// Without the duration the line answers "who" and not "for how long", and #459's
/// open question — *when did this participant first appear* — needs both ends of
/// the interval to be reconstructable from the log ring alone.
#[test]
fn a_closed_inbound_session_leaves_a_close_line_with_duration_and_reason() {
    let server = TcpTransport::bind("127.0.0.1:0").unwrap();
    let client = TcpTransport::bind("127.0.0.1:0").unwrap();
    let server_addr = server.local_addr().to_string();

    let mut a = node(server, 1);
    let mut b = node(client, 2);
    let pid = b.transport().connect(&server_addr).unwrap();
    b.add_peer(pid, Some(server_addr));

    let opened = journal_until(&mut a, |l| l.starts_with("ACCEPT "));
    let accept = opened.iter().find(|l| l.starts_with("ACCEPT ")).expect("accepted");
    let peer_addr = field(accept, "addr").to_string();

    // Hold the session long enough that a duration of zero would be a bug rather
    // than a fast loopback.
    std::thread::sleep(Duration::from_millis(60));
    b.transport().shutdown();

    let lines = journal_until(&mut a, |l| l.starts_with("CLOSE "));
    let close = lines
        .iter()
        .find(|l| l.starts_with("CLOSE "))
        .unwrap_or_else(|| panic!("a closed inbound left no line; journal: {lines:?}"));

    assert_eq!(field(close, "dir"), "in", "{close}");
    assert_eq!(field(close, "addr"), peer_addr, "close names the same peer as accept: {close}");
    let held: u64 = field(close, "ms").parse().expect("a duration parses");
    assert!(held >= 1, "the session was held ~60 ms, the line says {held}: {close}");
    // The peer hung up on us: not our eviction, and not counted as our fault.
    assert_eq!(field(close, "why"), "eof", "{close}");

    a.transport().shutdown();
}

/// §1's *"a capped-out reject is its own, distinct line"*.
///
/// A node at its inbound cap and a node nobody is dialing produced identical logs
/// before this — which is to say, nothing at all — and they want opposite
/// operator responses. On a public 9444 this is the line that separates "we are
/// full" from "we are alone".
#[test]
fn a_capped_out_inbound_connection_is_its_own_distinct_line() {
    let server = TcpTransport::bind("127.0.0.1:0").unwrap();
    server.set_inbound_cap(1);
    let server_addr = server.local_addr().to_string();
    let mut a = node(server, 1);

    let first = TcpTransport::bind("127.0.0.1:0").unwrap();
    first.connect(&server_addr).unwrap();
    let admitted = journal_until(&mut a, |l| l.starts_with("ACCEPT ") && l.contains("result=ok"));
    assert!(
        admitted.iter().any(|l| l.contains("result=ok")),
        "the first connection was admitted: {admitted:?}"
    );

    // The cap is now full. The second connection is refused at accept.
    let second = TcpTransport::bind("127.0.0.1:0").unwrap();
    second.connect(&server_addr).unwrap();
    let lines = journal_until(&mut a, |l| l.contains("result=capped"));
    let capped = lines
        .iter()
        .find(|l| l.contains("result=capped"))
        .unwrap_or_else(|| panic!("a capped-out reject left no line; journal: {lines:?}"));

    // Distinct from an admitted accept, and it says what it was capped *at* —
    // the cap is runtime-tunable, so a line saying only "capped" would not.
    assert!(capped.starts_with("ACCEPT "), "{capped}");
    assert_eq!(field(capped, "cap"), "1", "{capped}");
    assert_eq!(field(capped, "dir"), "in", "{capped}");
    assert!(field(capped, "addr").starts_with("127.0.0.1:"), "{capped}");
    // No peer handle exists for a connection that was never registered, so the
    // line must not claim one.
    assert!(!capped.contains(" peer="), "a refused connection has no handle: {capped}");

    a.transport().shutdown();
    drop(first);
    drop(second);
}

/// **Our own close is attributed to us, not to the peer.**
///
/// `disconnect` has exactly one caller — #289's stalled-socket drop — and that
/// path is deliberately *not* a peer fault. A close line that read `why=eof` for
/// it would put the blame for our own liveness decision on a peer that may be
/// entirely blameless, which is the same misattribution `is_peer_fault` exists to
/// prevent elsewhere in this crate.
#[test]
fn a_connection_we_dropped_is_attributed_to_us() {
    let server = TcpTransport::bind("127.0.0.1:0").unwrap();
    let client = TcpTransport::bind("127.0.0.1:0").unwrap();
    let server_addr = server.local_addr().to_string();

    let mut a = node(server, 1);
    let mut b = node(client, 2);
    let pid = b.transport().connect(&server_addr).unwrap();
    b.add_peer(pid, Some(server_addr));

    let opened = journal_until(&mut a, |l| l.starts_with("ACCEPT "));
    let accept = opened.iter().find(|l| l.starts_with("ACCEPT ")).expect("accepted");
    let handle: u64 = field(accept, "peer").parse().expect("a handle parses");

    a.transport().disconnect(qlab_p2p::peer::PeerId(handle));

    let lines = journal_until(&mut a, |l| l.starts_with("CLOSE "));
    let close = lines.iter().find(|l| l.starts_with("CLOSE ")).expect("our own close is journalled");
    assert_eq!(field(close, "why"), "evicted", "we closed it, so we own it: {close}");
    assert_eq!(field(close, "dir"), "in", "{close}");

    a.transport().shutdown();
    b.transport().shutdown();
}

/// §2: `pin=`/`pout=` split `peers=` by **who opened the connection**, and the
/// two halves sum to it.
///
/// One socket, two nodes, opposite readings — which is the whole point: `peers=1`
/// on both ends of this pair described two different situations and said the same
/// thing about them.
#[test]
fn pin_and_pout_split_the_peer_count_by_who_opened_the_connection() {
    let server = TcpTransport::bind("127.0.0.1:0").unwrap();
    let client = TcpTransport::bind("127.0.0.1:0").unwrap();
    let server_addr = server.local_addr().to_string();

    let mut a = node(server, 1);
    let mut b = node(client, 2);
    let pid = b.transport().connect(&server_addr).unwrap();
    b.add_peer(pid, Some(server_addr));

    // A's peer-table row is created by B's first frame, so pump until both sides
    // have registered each other.
    let start = std::time::Instant::now();
    for _ in 0..200 {
        let now = start.elapsed().as_millis() as u64;
        a.tick(now);
        b.tick(now);
        if a.peers().len() == 1 && b.peers().len() == 1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(3));
    }

    let (a_in, a_out) = a.peer_directions().expect("the TCP transport knows directions");
    let (b_in, b_out) = b.peer_directions().expect("the TCP transport knows directions");
    assert_eq!((a_in, a_out), (1, 0), "A accepted the session");
    assert_eq!((b_in, b_out), (0, 1), "B dialed it");

    // The invariant the TELEMETRY line depends on: the split cannot disagree with
    // the number it splits.
    assert_eq!(a_in + a_out, a.peers().len() as u64);
    assert_eq!(b_in + b_out, b.peers().len() as u64);

    a.transport().shutdown();
    b.transport().shutdown();
}
