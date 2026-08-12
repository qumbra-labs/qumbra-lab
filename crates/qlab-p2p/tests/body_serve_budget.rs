//! **Issue #371 S3 — the body-serving DoS posture, over the real transport.**
//!
//! Serving history is free bandwidth for an attacker: a ~50 B `GetData(Block)`
//! item buys a whole body (~145 KB per transaction at FROZEN v1.0 sizes), and
//! before this baton the serve side had no cost control at all — no item cap on
//! a `GetData` (one 8 MiB frame can name ~250 k items) and no budget on served
//! body bytes. The caps are enumerated in `qlab_p2p::ratelimit`'s body-serving
//! posture table; these tests hold each one to #91's acceptance rule: **an
//! over-limit ask is refused AND an at-limit ask is served** — only testing the
//! refusal would let the limit rot into refusing honest peers unnoticed.
//!
//! Every refusal here must degrade to the pre-#182 header-only answer or to
//! silence — never `NotFound` (scored by the receiver on some paths), never a
//! score (volume is not a protocol fault — #91's law).

use std::time::Duration;

use qlab_devnet::committee::{devnet_committee, CommitteeState};
use qlab_devnet::node::SimConfig;
use qlab_devnet::pow::KeccakPow;
use qlab_p2p::adapter::NodeAdapter;
use qlab_p2p::codec::{encode_inv, InvItem, InvKind};
use qlab_p2p::n1::{BlockIngest, IngestOutcome};
use qlab_p2p::node::MAX_BODIES_PER_GETDATA;
use qlab_p2p::ratelimit::RateLimits;
use qlab_p2p::transport::{TcpTransport, Transport};
use qlab_p2p::{Envelope, Frame, MsgType, P2pNode};

use qlab_devnet::body::{TxEntry, TxVerifier};
use qlab_devnet::header::Hash32;

#[derive(Clone)]
struct MarkerVerifier;
impl TxVerifier for MarkerVerifier {
    fn verify_tx(&self, entry: &TxEntry) -> bool {
        entry.proof == b"ok"
    }
}

type Adapter = NodeAdapter<KeccakPow, MarkerVerifier>;
type Node = P2pNode<TcpTransport, Adapter>;

fn easy_sim() -> SimConfig {
    SimConfig {
        block_time_secs: 2,
        genesis_difficulty: 8,
        mine_nonce_budget: 5_000_000,
        ..SimConfig::default()
    }
}

fn adapter() -> Adapter {
    let (committee, _v) = devnet_committee(7);
    NodeAdapter::new(
        CommitteeState::new(committee, qlab_devnet::params_devnet::BOND_AMOUNT),
        KeccakPow,
        MarkerVerifier,
        easy_sim(),
    )
}

/// A serving node over real TCP with `n` blocks mined and applied — every body
/// in its applied store, the place historical bodies are served from.
fn server_with_chain(n: usize) -> (Node, String, Vec<Hash32>) {
    let mut a = adapter();
    let mut ids = Vec::with_capacity(n);
    for _ in 0..n {
        let (h, b) = a.mine_block().expect("mine");
        assert_eq!(a.ingest_block(h, b), IngestOutcome::Accepted);
        ids.push(h.header_hash());
    }
    let t = TcpTransport::bind("127.0.0.1:0").unwrap();
    let addr = t.local_addr().to_string();
    (P2pNode::new(t, a, [1u8; 32]), addr, ids)
}

/// Drive `server` while collecting every answer frame the raw client receives,
/// classified by type. Bounded, so a genuine failure still terminates.
fn ask_and_collect(
    server: &mut Node,
    client: &TcpTransport,
    ask: &[u8],
    pid: qlab_p2p::PeerId,
    now_ms: u64,
) -> (usize, usize, usize) {
    client.send(pid, ask).unwrap();
    let (mut bodies, mut headers, mut notfound) = (0, 0, 0);
    let mut quiet = 0;
    for _ in 0..200 {
        server.tick(now_ms);
        let mut got = false;
        for (_, f) in client.poll() {
            got = true;
            match Frame::decode(&f).ok().and_then(|fr| fr.msg_type()) {
                Some(MsgType::BlockAnnounce) => bodies += 1,
                Some(MsgType::Header) => headers += 1,
                Some(MsgType::NotFound) => notfound += 1,
                _ => {}
            }
        }
        // Two consecutive quiet polls after something arrived = the answer is
        // complete (single-threaded server; nothing else is in flight).
        quiet = if got { 0 } else { quiet + 1 };
        if (bodies + headers + notfound) > 0 && quiet >= 3 {
            break;
        }
        std::thread::sleep(Duration::from_millis(3));
    }
    (bodies, headers, notfound)
}

fn getdata(ids: &[Hash32]) -> Vec<u8> {
    let items: Vec<InvItem> =
        ids.iter().map(|id| InvItem { kind: InvKind::Block, id: *id }).collect();
    Envelope::new(MsgType::GetData, encode_inv(&items)).encode()
}

/// The server's score of the one raw client, which must stay exactly zero
/// through every refusal in this file.
fn client_score(server: &Node) -> i32 {
    server
        .peers()
        .all_peers()
        .iter()
        .map(|p| server.peers().get(*p).expect("peer").score)
        .sum()
}

/// **At the limit: an honest full-window ask is served whole.** The requester's
/// own cap is `MAX_BODIES_IN_FLIGHT` (16) spread across its peers, so 16 bodies
/// from one peer is the largest honest ask that exists; under default limits it
/// comes back as 16 whole bodies, zero headers, zero throttles.
#[test]
fn an_honest_full_window_ask_is_served_sixteen_whole_bodies() {
    let (mut server, addr, ids) = server_with_chain(20);
    let client = TcpTransport::bind("127.0.0.1:0").unwrap();
    let pid = client.connect(&addr).unwrap();
    std::thread::sleep(Duration::from_millis(50));

    let (bodies, headers, notfound) =
        ask_and_collect(&mut server, &client, &getdata(&ids[..MAX_BODIES_PER_GETDATA]), pid, 0);
    assert_eq!(bodies, MAX_BODIES_PER_GETDATA, "every asked body served whole");
    assert_eq!(headers, 0);
    assert_eq!(notfound, 0);
    let stats = server.rate_stats();
    assert_eq!(stats.throttled_body_serve, 0, "an honest ask is never throttled");
    assert_eq!(stats.getdata_items_dropped, 0);
    assert_eq!(client_score(&server), 0);

    server.transport().shutdown();
    client.shutdown();
}

/// **Past the item cap: ignored, counted, and never `NotFound`.** The tail of an
/// oversized `GetData` gets no answer at all — an answer per item is exactly the
/// amplifier — and the requester is not scored for asking.
#[test]
fn items_past_the_getdata_cap_are_ignored_counted_and_never_notfound() {
    let (mut server, addr, ids) = server_with_chain(20);
    server.set_rate_limits(RateLimits { max_getdata_items: 8, ..RateLimits::default() });
    let client = TcpTransport::bind("127.0.0.1:0").unwrap();
    let pid = client.connect(&addr).unwrap();
    std::thread::sleep(Duration::from_millis(50));

    let (bodies, headers, notfound) =
        ask_and_collect(&mut server, &client, &getdata(&ids[..12]), pid, 0);
    assert_eq!(bodies, 8, "items within the cap are served exactly as before");
    assert_eq!(headers, 0);
    assert_eq!(notfound, 0, "the ignored tail is NOT a welshed inv");
    assert_eq!(server.rate_stats().getdata_items_dropped, 4, "the cap is a counted fact");
    assert_eq!(client_score(&server), 0, "over-asking is volume, not a fault");

    server.transport().shutdown();
    client.shutdown();
}

/// **Past the per-message byte bound: the answer degrades to headers,** so one
/// request can never provoke more body bytes than the asker's own inbound
/// limiter would admit — and at the bound itself, bodies still flow.
#[test]
fn past_the_per_message_byte_bound_the_answer_degrades_to_headers() {
    let (mut server, addr, ids) = server_with_chain(20);
    // Room for a couple of coinbase-sized announces (~200 B each), not sixteen.
    server.set_rate_limits(RateLimits { max_body_bytes_per_getdata: 500, ..RateLimits::default() });
    let client = TcpTransport::bind("127.0.0.1:0").unwrap();
    let pid = client.connect(&addr).unwrap();
    std::thread::sleep(Duration::from_millis(50));

    let (bodies, headers, notfound) =
        ask_and_collect(&mut server, &client, &getdata(&ids[..16]), pid, 0);
    assert!(bodies >= 1, "at the bound: bodies still flow ({bodies})");
    assert!(headers >= 1, "over it: headers, the pre-#182 answer ({headers})");
    assert_eq!(bodies + headers, 16, "every item answered, none dropped, none NotFound");
    assert_eq!(notfound, 0);
    assert_eq!(client_score(&server), 0);

    server.transport().shutdown();
    client.shutdown();
}

/// **A drained per-key budget degrades to headers and REFILLS** — a throttle,
/// not a ban, and a reconnect does not refresh it (the budget is keyed on the
/// host, same trap as `GetAddr`'s).
#[test]
fn a_drained_body_budget_degrades_to_headers_then_refills() {
    let (mut server, addr, ids) = server_with_chain(20);
    // One coinbase announce is ~200 B: a 400 B/s budget serves a body or two,
    // then drains; a second ask inside the same second gets headers only.
    server.set_rate_limits(RateLimits {
        body_serve_byte_burst: 400,
        body_serve_bytes_per_sec: 400,
        ..RateLimits::default()
    });
    let client = TcpTransport::bind("127.0.0.1:0").unwrap();
    let pid = client.connect(&addr).unwrap();
    std::thread::sleep(Duration::from_millis(50));

    let (bodies, headers, _) =
        ask_and_collect(&mut server, &client, &getdata(&ids[..8]), pid, 0);
    assert!(bodies >= 1, "the burst serves something ({bodies})");
    assert!(headers >= 1, "and past it: headers ({headers})");
    assert!(server.rate_stats().throttled_body_serve >= 1, "the throttle is counted");

    // Same ask, same key, budget still drained (same now_ms): headers only.
    let (bodies2, headers2, _) =
        ask_and_collect(&mut server, &client, &getdata(&ids[..8]), pid, 1);
    assert_eq!(bodies2, 0, "drained: nothing served whole");
    assert_eq!(headers2, 8, "but every item still answered honestly");

    // Two seconds later the budget has refilled: served again — nobody was banned.
    let (bodies3, _, _) =
        ask_and_collect(&mut server, &client, &getdata(&ids[..1]), pid, 2_000);
    assert!(bodies3 >= 1, "a throttle refills; a ban would not");
    assert_eq!(client_score(&server), 0, "throttling never scores");
    for p in server.peers().all_peers() {
        assert!(!server.peers().is_banned(p));
    }

    server.transport().shutdown();
    client.shutdown();
}

/// **The drill's mutation switch reproduces the pre-#182 wire through the same
/// code path**: serving disabled ⇒ every `GetData(Block)` answer is a bare
/// header — the exact behaviour the joiner drill's negative control stalls on.
#[test]
fn with_serving_disabled_every_answer_is_a_header() {
    let (mut server, addr, ids) = server_with_chain(20);
    server.set_serve_historical_bodies(false);
    let client = TcpTransport::bind("127.0.0.1:0").unwrap();
    let pid = client.connect(&addr).unwrap();
    std::thread::sleep(Duration::from_millis(50));

    let (bodies, headers, notfound) =
        ask_and_collect(&mut server, &client, &getdata(&ids[..16]), pid, 0);
    assert_eq!(bodies, 0, "nothing served whole — today's deployed answer");
    assert_eq!(headers, 16, "a header per item, exactly as before #182");
    assert_eq!(notfound, 0);
    assert_eq!(client_score(&server), 0);

    server.transport().shutdown();
    client.shutdown();
}
