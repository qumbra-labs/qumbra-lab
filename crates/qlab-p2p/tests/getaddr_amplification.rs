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
//!   an attacker gets on a single packet, and it is what the ≈1000× bound is.
//! - **sustained over a window** — R requests inside one serve-limit window.
//!   This is the ratio that decides whether the node is a usable reflector, and
//!   it is the number the fix moves.

use std::sync::Arc;

use qlab_devnet::committee::{devnet_committee, CommitteeState};
use qlab_devnet::header::BlockHeader;
use qlab_devnet::params_devnet::BOND_AMOUNT;

use qlab_p2p::addrman::{MAX_ADDRS_PER_MSG, MAX_ADDR_LEN};
use qlab_p2p::n1::StubNode;
use qlab_p2p::peer::PeerId;
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
    id: PeerId,
    addrs: &[String],
) -> P2pNode<InProcTransport, StubNode> {
    let t = InProcTransport::new(id, Arc::clone(hub));
    let mut n = P2pNode::new(t, stub(), [1; 32]);
    n.addrs_mut().set_max_book(addrs.len().max(1) * 2);
    n.addrs_mut().learn(addrs.to_vec());
    for (i, a) in addrs.iter().enumerate() {
        n.addrs_mut().on_dial_success(a, PeerId(1000 + i as u64));
    }
    assert_eq!(n.addrs().gossipable().len(), addrs.len().min(MAX_ADDRS_PER_MSG));
    n
}

/// Drive `requests` empty `GetAddr` frames at the victim and return
/// `(bytes_in, bytes_out, addr_replies)`.
fn flood(victim_addrs: &[String], requests: usize) -> (usize, usize, usize) {
    let hub = InProcHub::new();
    let mut victim = node_with_book(&hub, PeerId(1), victim_addrs);
    let attacker = InProcTransport::new(PeerId(2), Arc::clone(&hub));
    hub.link(PeerId(2), PeerId(1));
    hub.link(PeerId(1), PeerId(2));

    let req = Envelope::new(MsgType::GetAddr, Vec::new()).encode();
    assert_eq!(req.len(), HEADER_LEN, "an empty GetAddr is header-only");

    let mut bytes_in = 0;
    for _ in 0..requests {
        attacker.send(PeerId(1), &req).unwrap();
        bytes_in += req.len();
    }
    victim.tick();

    let frames = attacker.poll();
    let bytes_out: usize = frames.iter().map(|(_, f)| f.len()).sum();
    let replies = frames
        .iter()
        .filter(|(_, f)| {
            Envelope::decode(f).map(|e| e.msg_type == MsgType::Addr).unwrap_or(false)
        })
        .count();
    (bytes_in, bytes_out, replies)
}

#[test]
fn measure_inbound_getaddr_amplification() {
    // Three book states, from the net we actually run to the cap-times-cap bound.
    let t0: Vec<String> = (0..3).map(wan_addr).collect(); // 4-node net: 3 peers
    let full_wan: Vec<String> = (0..MAX_ADDRS_PER_MSG).map(wan_addr).collect();
    let worst: Vec<String> = (0..MAX_ADDRS_PER_MSG).map(max_len_addr).collect();

    println!("\n=== inbound GetAddr amplification — PRE-FIX (node.rs:324 serves unconditionally) ===");
    println!("caliber: one in-process victim, one attacker peer, single `tick()` drain;");
    println!("         request = empty GetAddr = {HEADER_LEN} B framed, 0 B payload;");
    println!("         response bytes = every byte the victim put on the wire in reply.");
    println!("{:<34} {:>7} {:>9} {:>10} {:>9}", "book state", "in B", "out B", "replies", "ratio");

    for (name, book) in [
        ("T0 4-node net (3 dialable)", &t0),
        ("book full, WAN-shape addrs", &full_wan),
        ("book full, 128 B addrs (bound)", &worst),
    ] {
        let (bi, bo, replies) = flood(book, 1);
        println!("{name:<34} {bi:>7} {bo:>9} {replies:>10} {:>8.1}x", bo as f64 / bi as f64);
    }

    println!("\n--- sustained: R requests, all inside one 30 s window, worst-case book ---");
    println!("{:<34} {:>7} {:>9} {:>10} {:>9}", "requests", "in B", "out B", "replies", "ratio");
    for r in [1usize, 10, 100, 1000] {
        let (bi, bo, replies) = flood(&worst, r);
        println!("{r:<34} {bi:>7} {bo:>9} {replies:>10} {:>8.1}x", bo as f64 / bi as f64);
    }
    println!();

    // The defect, asserted rather than described: every request is answered, so
    // the sustained ratio does not decay with the request rate.
    let (_, _, replies) = flood(&worst, 1000);
    assert_eq!(replies, 1000, "pre-fix: every inbound GetAddr is served");
}
