//! The view against real HTTP servers on real sockets (issue #117).
//!
//! The unit tests in `agree`/`render` decide verdicts from constructed readings.
//! These decide them from **bytes off a socket**, because the seam this tool is
//! most likely to be wrong at is the one where a node's answer becomes a reading:
//! a body that decodes, a body that does not, a server that accepts and then says
//! nothing, and a port with nothing behind it are four different things and only
//! one of them is a node with an opinion.

use std::io::Write;
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use qlab_node::telemetry::LocalCommitment;
use qlab_node::{DurableAgreement, Telemetry};
use qumbra_opview::agree::{Agreement, DurableVerdict, SignedVerdict, Verdict};
use qumbra_opview::poll::{poll_all, Endpoint, PollOptions};
use qumbra_opview::render;

const MAX_LAG: u64 = 16;

/// A live-composition snapshot: head #3 read, and holding the same height head #1
/// reports, under a block identity derived from `dfin_first` (issue #212).
fn telem(fin: u64, fid: u64, signed: Option<(u64, Option<u64>)>) -> Telemetry {
    telem_durable(fin, fid, signed, Some((fin, 0xdd)))
}

fn telem_durable(
    fin: u64,
    fid: u64,
    signed: Option<(u64, Option<u64>)>,
    durable: Option<(u64, u8)>,
) -> Telemetry {
    let base = Telemetry::assemble(fin + 24, Some(fin), 75, 0, 3, 1, MAX_LAG)
        .with_checkpoint(Some(fid), signed.map(|(slot, id)| LocalCommitment { slot, id }))
        .with_tip_difficulty(Some(1_048_576));
    base.with_durable_head(durable.map(|(height, first)| {
        let mut hash = [0xee_u8; 32];
        hash[0] = first;
        (height, hash)
    }))
}

/// The `0x03` body for the same facts: everything the pre-#212 wire carried, with no
/// durable tail, stamped `0x03`. Built by removing the tail the encoder appends and
/// re-stamping, then **asserted** against the strict decoder so the fixture cannot
/// quietly become something else.
fn v3_body(t: &Telemetry) -> Vec<u8> {
    let full = t.to_bytes();
    // The 0x04 tail is `discriminant(1) ‖ height(8) ‖ identity(8)` for a present head.
    let mut old = full[..full.len() - 17].to_vec();
    old[0] = 0x03;
    assert!(
        Telemetry::from_bytes(&old).is_err(),
        "the fixture must not be readable by the STRICT decoder"
    );
    old
}

/// A node stand-in: a real HTTP server answering `GET /v1/telemetry` with `body`.
struct FakeNode {
    addr: SocketAddr,
    server: Arc<tiny_http::Server>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl FakeNode {
    fn serving(body: Vec<u8>) -> FakeNode {
        let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").expect("bind"));
        let addr = server.server_addr().to_ip().expect("ip");
        let worker = Arc::clone(&server);
        let thread = std::thread::spawn(move || {
            for req in worker.incoming_requests() {
                let path = req.url().split('?').next().unwrap_or("").to_string();
                let _ = if path == "/v1/telemetry" {
                    req.respond(tiny_http::Response::from_data(body.clone()))
                } else {
                    req.respond(tiny_http::Response::from_string("nope").with_status_code(404))
                };
            }
        });
        FakeNode { addr, server, thread: Some(thread) }
    }
    fn endpoint(&self, label: &str) -> Endpoint {
        Endpoint::parse(&format!("{label}=http://{}", self.addr)).expect("parse")
    }
}

impl Drop for FakeNode {
    fn drop(&mut self) {
        self.server.unblock();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// A node that accepts the connection and then never answers — the case a plain
/// `TcpStream::connect` + read would sit on for the OS default.
struct BlackHole {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl BlackHole {
    fn start() -> BlackHole {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        listener.set_nonblocking(true).expect("nonblocking");
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            let mut held = Vec::new();
            while !flag.load(Ordering::Relaxed) {
                if let Ok((s, _)) = listener.accept() {
                    held.push(s); // accepted, and deliberately never answered
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        });
        BlackHole { addr, stop, thread: Some(thread) }
    }
    fn endpoint(&self, label: &str) -> Endpoint {
        Endpoint::parse(&format!("{label}=http://{}", self.addr)).expect("parse")
    }
}

impl Drop for BlackHole {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// **Acceptance, over sockets**: four nodes, three of them agreeing at one height
/// and one unreachable ⇒ AGREED, 3/4 answered, and the down node is rendered as
/// unreachable rather than as a dissenter.
#[test]
fn four_nodes_one_down_renders_agreement_over_real_sockets() {
    const H: u64 = 3776;
    const ID: u64 = 0xaaaa_aaaa_aaaa;
    let n0 = FakeNode::serving(telem(H, ID, Some((H, Some(ID)))).to_bytes());
    let n1 = FakeNode::serving(telem(H, ID, Some((H, Some(ID)))).to_bytes());
    let n2 = FakeNode::serving(telem(H, ID, Some((H, Some(ID)))).to_bytes());
    // A port with nothing behind it: bound, then released.
    let dead = TcpListener::bind("127.0.0.1:0").unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);

    let eps = vec![
        n0.endpoint("node0"),
        n1.endpoint("node1"),
        n2.endpoint("node2"),
        Endpoint::parse(&format!("node3=http://{dead_addr}")).unwrap(),
    ];
    let readings = poll_all(&eps, PollOptions { timeout: Duration::from_millis(800) });
    assert_eq!(readings.len(), 4);
    assert_eq!(
        readings.iter().map(|r| r.endpoint.label.clone()).collect::<Vec<_>>(),
        vec!["node0", "node1", "node2", "node3"],
        "readings come back in configured order regardless of who answered first"
    );

    let a = Agreement::of(&readings);
    assert_eq!(a.verdict, Verdict::Agreed);
    assert_eq!(a.signed_verdict, SignedVerdict::Agreed);
    assert_eq!(a.reachable.len(), 3);
    assert_eq!(a.unreachable.len(), 1);
    assert_eq!(a.exit_code(), 0);

    let text = render::view(&readings, &a);
    assert!(text.contains("checkpoint agreement (fid): AGREED — 3/4 nodes answered"), "{text}");
    assert!(text.contains("node3"), "{text}");
    assert!(text.contains("UNREACHABLE"), "{text}");
    assert!(!text.contains("DIVERGED"), "{text}");
    // Every reachable node's fid is rendered, from bytes that crossed a socket.
    assert!(text.matches("aaaaaaaaaaaa").count() >= 3, "{text}");
}

/// **Acceptance, over sockets**: two nodes at the same height with different
/// identities ⇒ 🔴 DIVERGED and exit code 2, decided from the served bytes.
#[test]
fn a_real_split_over_sockets_is_the_stop_condition() {
    const H: u64 = 3776;
    let n0 = FakeNode::serving(telem(H, 0xaaaa_aaaa_aaaa, Some((H, Some(0xaaaa_aaaa_aaaa)))).to_bytes());
    let n1 = FakeNode::serving(telem(H, 0xbbbb_bbbb_bbbb, Some((H, Some(0xbbbb_bbbb_bbbb)))).to_bytes());

    let eps = vec![n0.endpoint("node0"), n1.endpoint("node1")];
    let readings = poll_all(&eps, PollOptions { timeout: Duration::from_millis(800) });
    let a = Agreement::of(&readings);

    assert_eq!(a.verdict, Verdict::Diverged);
    assert_eq!(a.exit_code(), 2);
    let text = render::view(&readings, &a);
    assert!(text.contains("R2 STOP"), "{text}");
    assert!(text.contains(&format!("final={H}")), "{text}");
}

/// A node that accepts and then goes silent is unreachable **within the deadline**
/// — not a hang, and not a disagreement. Without a deadline this read would sit on
/// the OS default and the operator's view, not the node, would be the thing that
/// looked broken.
#[test]
fn a_silent_node_times_out_and_reads_as_unreachable() {
    let hole = BlackHole::start();
    let good = FakeNode::serving(telem(3776, 0xaaaa_aaaa_aaaa, None).to_bytes());

    let eps = vec![good.endpoint("node0"), hole.endpoint("node1")];
    let started = std::time::Instant::now();
    let readings = poll_all(&eps, PollOptions { timeout: Duration::from_millis(400) });
    let elapsed = started.elapsed();

    assert!(readings[0].reading.is_reachable());
    assert!(!readings[1].reading.is_reachable());
    assert!(
        elapsed < Duration::from_secs(3),
        "the deadline bounds the whole poll, took {elapsed:?}"
    );

    let a = Agreement::of(&readings);
    assert_eq!(a.verdict, Verdict::Agreed, "one answer, no conflict");
    assert_eq!(a.unreachable.len(), 1);
    assert!(a.unreachable[0].1.contains("read"), "the reason names the step: {:?}", a.unreachable[0].1);
}

/// **A pre-#121 `0x02` node is unreachable-with-a-reason, not silently parsed.**
///
/// This is the version-byte discipline arriving where it matters: a `0x02`
/// payload carries no committee/supply tail, and best-effort parsing it would
/// render zero aggregates and no attestation — the healthiest-looking possible
/// rendering of a node whose telemetry this build cannot understand.
///
/// 🔴 **Issue #212 pins the boundary of the compat window here.** `0x03` is now
/// readable (see the roll test below) and `0x02` is **not**, so this test is what
/// stops the window from being widened by drift: the readable set is a named list of
/// versions whose layout this build knows, not a `>=` comparison.
#[test]
fn a_node_speaking_the_old_0x02_wire_is_refused_with_a_reason() {
    // A genuine v2 payload: the 0x03 body minus three u64 committee aggregates and
    // the zero-length supply varint, stamped 0x02.
    let live = telem(3776, 0xaaaa_aaaa_aaaa, Some((3776, Some(0xaaaa_aaaa_aaaa))));
    let v3 = v3_body(&live);
    let mut v2 = v3[..v3.len() - 24 - 1].to_vec();
    v2[0] = 0x02;
    assert!(
        Telemetry::from_bytes_compat(&v2).is_err(),
        "the fixture really is outside the readable set"
    );

    let old = FakeNode::serving(v2);
    let eps = vec![old.endpoint("stale-node")];
    let readings = poll_all(&eps, PollOptions { timeout: Duration::from_millis(800) });

    assert!(!readings[0].reading.is_reachable());
    assert_eq!(readings[0].reading.wire_version(), None);
    let a = Agreement::of(&readings);
    assert_eq!(a.verdict, Verdict::Agreed, "one unreadable node is no evidence, not a split");
    assert_eq!(a.exit_code(), 0);
    let text = render::view(&readings, &a);
    assert!(
        text.contains("this build reads wire versions [3, 4]"),
        "the reason names the readable set:\n{text}"
    );
}

/// **Acceptance (#212, over sockets): mid-roll, the rolled host's durable head is
/// read and the un-rolled hosts stay fully readable on every other field.**
///
/// This is the roll problem answered from bytes off a socket, which is the seam that
/// matters — `Reader::version` is an equality check, so before this change an
/// `opview` at `0x04` would have produced four `UNREACHABLE` rows against a net where
/// three hosts were healthy and simply had not been rolled yet, for the whole 23
/// minutes of a one-host-at-a-time roll.
#[test]
fn a_mid_roll_net_is_fully_readable_over_sockets_and_says_which_hosts_predate_the_field() {
    const H: u64 = 2864;
    const FID: u64 = 0x63e4_2f7e_13a7;
    let live = telem_durable(H, FID, None, Some((H, 0x63)));

    let rolled = FakeNode::serving(live.to_bytes());
    let old_a = FakeNode::serving(v3_body(&live));
    let old_b = FakeNode::serving(v3_body(&live));
    let old_c = FakeNode::serving(v3_body(&live));

    let eps = vec![
        rolled.endpoint("node0"),
        old_a.endpoint("node1"),
        old_b.endpoint("node2"),
        old_c.endpoint("node3"),
    ];
    let readings = poll_all(&eps, PollOptions { timeout: Duration::from_millis(800) });

    // 🔴 The property: all four answered and all four decoded.
    assert!(readings.iter().all(|r| r.reading.is_reachable()), "every host readable mid-roll");
    assert_eq!(readings[0].reading.wire_version(), Some(0x04));
    assert!(readings[0].reading.wire_carries_durable_head());
    for r in &readings[1..] {
        assert_eq!(r.reading.wire_version(), Some(0x03));
        assert!(!r.reading.wire_carries_durable_head(), "0x03 predates the field");
        // Everything the old wire DID carry is still read, which is the whole reason
        // the cross-host question stays answerable through the roll.
        let t = r.reading.telemetry().unwrap();
        assert_eq!(t.finalized_height, Some(H));
        assert_eq!(t.fid_field(), "63e42f7e13a7");
        assert_eq!(t.durable_agreement(), DurableAgreement::Unavailable);
    }

    let a = Agreement::of(&readings);
    assert_eq!(a.reachable.len(), 4);
    assert_eq!(a.verdict, Verdict::Agreed, "the fid verdict is still answerable across all four");
    assert_eq!(a.comparable_heights().len(), 1);
    assert_eq!(a.durable_verdict, DurableVerdict::Indeterminate);
    assert_eq!(a.durable_blind.len(), 3);
    assert_eq!(a.exit_code(), 0);

    let text = render::view(&readings, &a);
    assert!(text.contains("checkpoint agreement (fid): AGREED — 4/4 nodes answered"), "{text}");
    assert!(text.contains("node1: wire 0x03 predates the durable head"), "{text}");
    assert!(!text.contains("UNREACHABLE"), "no host may be rendered unreachable mid-roll:\n{text}");
    // The rolled host's durable head renders; the others' are `-`.
    assert!(text.contains("63eeeeeeeeee"), "{text}");
}

/// **Acceptance (#212, over sockets): a durable split is the STOP condition, decided
/// from served bytes, with `fid` agreeing.**
#[test]
fn a_durable_split_over_sockets_is_the_stop_condition_while_fid_agrees() {
    const H: u64 = 2864;
    const FID: u64 = 0x63e4_2f7e_13a7;
    let n0 = FakeNode::serving(telem_durable(H, FID, None, Some((H, 0xa1))).to_bytes());
    let n1 = FakeNode::serving(telem_durable(H, FID, None, Some((H, 0xb2))).to_bytes());

    let eps = vec![n0.endpoint("node0"), n1.endpoint("node1")];
    let readings = poll_all(&eps, PollOptions { timeout: Duration::from_millis(800) });
    let a = Agreement::of(&readings);

    assert_eq!(a.verdict, Verdict::Agreed, "head #1 agrees — that is why this was invisible");
    assert_eq!(a.durable_verdict, DurableVerdict::Diverged);
    assert_eq!(a.exit_code(), 2, "the same STOP code as an fid split");
    let text = render::view(&readings, &a);
    assert!(text.contains("durable finalized head (dfin/dfinbh): 🔴 DIVERGED"), "{text}");
    assert!(text.contains(&format!("dfin={H}")), "{text}");
    assert!(text.contains("a1eeeeeeeeee [node0]"), "{text}");
    assert!(text.contains("b2eeeeeeeeee [node1]"), "{text}");
}

/// A server that answers something else entirely (404 on the route) is also just
/// unreachable — an endpoint pointed at the wrong port is an operator mistake to
/// be told about, not a consensus event.
#[test]
fn a_wrong_endpoint_is_unreachable_not_a_verdict() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    listener.set_nonblocking(true).unwrap();
    let t = std::thread::spawn(move || {
        // Hold the accepted sockets open until the test ends: dropping one the
        // instant the response is written races the client's read and would fail
        // as a connection reset, testing the harness rather than the code.
        let mut held = Vec::new();
        while !flag.load(Ordering::Relaxed) {
            if let Ok((mut s, _)) = listener.accept() {
                let _ = s.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
                let _ = s.flush();
                let _ = s.shutdown(std::net::Shutdown::Write);
                held.push(s);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    });

    let eps = vec![Endpoint::parse(&format!("wrong=http://{addr}")).unwrap()];
    let readings = poll_all(&eps, PollOptions { timeout: Duration::from_millis(500) });
    assert!(!readings[0].reading.is_reachable());
    let a = Agreement::of(&readings);
    assert_eq!(a.exit_code(), 0);
    assert!(a.unreachable[0].1.contains("404"), "{:?}", a.unreachable[0].1);

    stop.store(true, Ordering::Relaxed);
    let _ = t.join();
}
