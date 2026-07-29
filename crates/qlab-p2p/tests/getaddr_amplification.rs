//! Inbound `GetAddr` amplification — the measurement, not an estimate.
//!
//! Issue #91 opens with "≈1000×". That figure is the **worst-case upper bound**
//! (100 addresses × 128 B, the two book caps multiplied together). What a real
//! node actually amplifies depends on how many entries its book has earned the
//! `dialable` flag on (#86, S2), so this file measures the ratio at three book
//! states and reports each with its caliber, rather than quoting the bound.
//!
//! Two calibers are reported, because they answer different questions:
//!
//! - **per-request** — one empty `GetAddr` in, one `Addr` out. This is the ratio
//!   an attacker gets on a single packet, and it is what the ≈1000× bound is. The
//!   fix does not move it, and is not supposed to: one honest request still gets
//!   one honest answer.
//! - **sustained over a window** — R requests inside one serve-limit window. This
//!   is the ratio that decides whether the node is a usable *reflector*, and it is
//!   the number the fix moves. Pre-fix it is flat in R; post-fix it decays as 1/R.
//!
//! Before and after are produced by the **same build**, differing only in
//! [`RateLimits`] (`unlimited()` reproduces the pre-fix `node.rs` behaviour), so
//! the comparison measures one implementation rather than two.

use std::sync::Arc;

use qlab_devnet::committee::{devnet_committee, CommitteeState};
use qlab_devnet::header::BlockHeader;
use qlab_devnet::params_devnet::BOND_AMOUNT;

use qlab_p2p::addrman::{MAX_ADDRS_PER_MSG, MAX_ADDR_LEN};
use qlab_p2p::n1::StubNode;
use qlab_p2p::peer::PeerId;
use qlab_p2p::ratelimit::{RateLimits, GETADDR_SERVE_INTERVAL_MS};
use qlab_p2p::transport::{InProcHub, InProcTransport, Transport};
use qlab_p2p::wire::{Envelope, MsgType, HEADER_LEN};
use qlab_p2p::P2pNode;

fn stub() -> StubNode {
    let (committee, _v) = devnet_committee(7);
    StubNode::new(BlockHeader::genesis(1000, 0), CommitteeState::new(committee, BOND_AMOUNT))
}

/// Realistic T0-shape address: a public IPv4 `host:port` as the four WAN hosts
/// actually carry (`13.212.…:9333`), 17–18 B.
fn wan_addr(i: usize) -> String {
    format!("13.212.{}.{}:9333", i / 256, i % 256)
}

/// A `MAX_ADDR_LEN`-byte address — the worst case the book will admit.
fn max_len_addr(i: usize) -> String {
    let tail = format!("{i:04}:9333");
    let host_len = MAX_ADDR_LEN - tail.len();
    let s = format!("{}{}", "a".repeat(host_len), tail);
    assert_eq!(s.len(), MAX_ADDR_LEN);
    s
}

/// Build a node whose `gossipable()` set is exactly `addrs` (each marked dialable,
/// which is the only way an address may be served — #86 S2).
fn node_with_book(
    hub: &Arc<InProcHub>,
    addrs: &[String],
    limits: RateLimits,
) -> P2pNode<InProcTransport, StubNode> {
    let t = InProcTransport::new(PeerId(1), Arc::clone(hub));
    let mut n = P2pNode::new(t, stub(), [1; 32]);
    n.set_rate_limits(limits);
    // Seeds, not learned entries: the per-netgroup book cap (#91 gap 3) applies to
    // gossip-supplied addresses, and this fixture is about response size, not about
    // how the book was filled.
    n.addrs_mut().set_max_book(addrs.len().max(1) * 2);
    for a in addrs {
        n.addrs_mut().add_seed(a.clone());
    }
    for (i, a) in addrs.iter().enumerate() {
        n.addrs_mut().on_dial_success(a, PeerId(1000 + i as u64));
    }
    assert_eq!(n.addrs().gossipable().len(), addrs.len().min(MAX_ADDRS_PER_MSG));
    n
}

struct Shot {
    bytes_in: usize,
    bytes_out: usize,
    replies: usize,
}

impl Shot {
    fn ratio(&self) -> f64 {
        self.bytes_out as f64 / self.bytes_in as f64
    }
}

/// Send `requests` empty `GetAddr` frames spread `gap_ms` apart and report what
/// the victim put back on the wire.
fn flood(victim_addrs: &[String], requests: usize, gap_ms: u64, limits: RateLimits) -> Shot {
    let hub = InProcHub::new();
    let mut victim = node_with_book(&hub, victim_addrs, limits);
    let attacker = InProcTransport::new(PeerId(2), Arc::clone(&hub));
    hub.link(PeerId(2), PeerId(1));
    hub.link(PeerId(1), PeerId(2));

    let req = Envelope::new(MsgType::GetAddr, Vec::new()).encode();
    assert_eq!(req.len(), HEADER_LEN, "an empty GetAddr is header-only");

    let mut bytes_in = 0;
    let mut bytes_out = 0;
    let mut replies = 0;
    for i in 0..requests {
        attacker.send(PeerId(1), &req).unwrap();
        bytes_in += req.len();
        victim.tick(i as u64 * gap_ms);
        for (_, f) in attacker.poll() {
            bytes_out += f.len();
            if Envelope::decode(&f).map(|e| e.msg_type == MsgType::Addr).unwrap_or(false) {
                replies += 1;
            }
        }
    }
    Shot { bytes_in, bytes_out, replies }
}

#[test]
fn measure_inbound_getaddr_amplification() {
    let t0: Vec<String> = (0..3).map(wan_addr).collect(); // the 4-node net: 3 peers
    let full_wan: Vec<String> = (0..MAX_ADDRS_PER_MSG).map(wan_addr).collect();
    let worst: Vec<String> = (0..MAX_ADDRS_PER_MSG).map(max_len_addr).collect();

    println!("\n=== inbound GetAddr amplification: BEFORE vs AFTER (issue #91) ===");
    println!("caliber — one in-process victim, one attacker peer, one `tick` per request;");
    println!("  request  = empty GetAddr, {HEADER_LEN} B framed, 0 B payload;");
    println!("  response = every byte the victim put on the wire in reply;");
    println!("  BEFORE   = RateLimits::unlimited() (reproduces the pre-fix node.rs:324 path);");
    println!("  AFTER    = RateLimits::default(), serve interval {GETADDR_SERVE_INTERVAL_MS} ms;");
    println!("  book states are the three below; each row is 1 request (per-request caliber).");
    println!();
    println!("{:<32} {:>7} {:>10} {:>10}", "book state (1 request)", "in B", "out B", "ratio");
    for (name, book) in [
        ("T0 4-node net (3 dialable)", &t0),
        ("book full, WAN-shape addrs", &full_wan),
        ("book full, 128 B addrs (bound)", &worst),
    ] {
        let s = flood(book, 1, 0, RateLimits::default());
        println!("{name:<32} {:>7} {:>10} {:>9.1}x", s.bytes_in, s.bytes_out, s.ratio());
    }

    println!("\n--- sustained caliber: R requests inside ONE {GETADDR_SERVE_INTERVAL_MS} ms window,");
    println!("    worst-case book (100 x 128 B). This is the reflector number. ---");
    println!(
        "{:>8}  {:>9} {:>11} {:>10} | {:>9} {:>11} {:>10}",
        "requests", "before B", "before out", "before x", "after B", "after out", "after x"
    );
    for r in [1usize, 10, 100, 1000] {
        let before = flood(&worst, r, 0, RateLimits::unlimited());
        let after = flood(&worst, r, 0, RateLimits::default());
        println!(
            "{r:>8}  {:>9} {:>11} {:>9.1}x | {:>9} {:>11} {:>9.3}x",
            before.bytes_in,
            before.bytes_out,
            before.ratio(),
            after.bytes_in,
            after.bytes_out,
            after.ratio()
        );
    }
    println!();

    // --- the assertions the numbers above are worth ---

    // BEFORE: every request is answered, so the ratio is FLAT in the request rate.
    // That flatness is the defect: it is what makes the node a usable reflector.
    let b1 = flood(&worst, 1, 0, RateLimits::unlimited());
    let b1000 = flood(&worst, 1000, 0, RateLimits::unlimited());
    assert_eq!(b1000.replies, 1000, "pre-fix: every inbound GetAddr is served");
    assert!(
        (b1.ratio() - b1000.ratio()).abs() < 0.01,
        "pre-fix ratio is flat in the request rate: {} vs {}",
        b1.ratio(),
        b1000.ratio()
    );
    assert!(b1.ratio() > 1000.0, "pre-fix worst case is the issue's ~1000x: {}", b1.ratio());

    // AFTER: one reply per window however hard it is asked, so the ratio decays
    // as 1/R and the node stops being worth reflecting off.
    let a1000 = flood(&worst, 1000, 0, RateLimits::default());
    assert_eq!(a1000.replies, 1, "post-fix: one Addr per serve interval, whatever the rate");
    assert!(a1000.ratio() < 1.5, "post-fix sustained ratio is ~1x, got {}", a1000.ratio());

    // And an honest asker is unaffected: on the network's own ask cadence
    // (GETADDR_INTERVAL_MS = 60 s, twice the serve interval) every request is
    // answered. A serve limit that starved honest peers would be a liveness bug.
    let honest = flood(&worst, 10, qlab_p2p::addrman::GETADDR_INTERVAL_MS, RateLimits::default());
    assert_eq!(honest.replies, 10, "an honest peer on its own limit is never refused");
}

#[test]
fn a_request_exactly_on_the_serve_interval_is_answered() {
    // The other half of the acceptance bar: testing only the refusal would let the
    // limit silently become "never serve" without anyone noticing.
    let book: Vec<String> = (0..3).map(wan_addr).collect();
    let just_inside = flood(&book, 2, GETADDR_SERVE_INTERVAL_MS - 1, RateLimits::default());
    assert_eq!(just_inside.replies, 1, "one millisecond short of the interval: refused");

    let exactly_on = flood(&book, 2, GETADDR_SERVE_INTERVAL_MS, RateLimits::default());
    assert_eq!(exactly_on.replies, 2, "exactly on the interval: served");
}
