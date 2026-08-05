//! **Issue #229 — the P2P serving cache is not an application predicate.**
//!
//! Five instances on the `138e1524…` chain in ~20 hours, each 1 h 25 m – 2 h 09 m,
//! each with the same reading: 12/12 peers `served`, 2,195 asks, `bdrop=0`,
//! `gate=missing`, and the body never applied. Layer (c), ratified 2026-08-05.
//!
//! ## The mechanism this file reproduces
//!
//! `P2pNode::blocks` — the #135 bounded body-serving cache — is a **third ledger of
//! "I have this body"**. It lives in the P2P layer, not in the state machine, and
//! **nothing removes an entry when the block leaves the applied chain**: its only
//! mutation is `insert`, with lowest-height-first eviction at
//! [`MAX_SERVED_BODIES`]. So after a rewind the cache still answers "we hold this",
//! while the state machine does not have it.
//!
//! `on_block_announce`'s "we already hold this body" early return then fires on
//! that stale answer, clears the in-flight ask, sets `body_fetch_progress = true`,
//! and **returns without calling `ingest_block`**. `buffer_body` never runs,
//! `pending_bodies` never receives the body, and `rejoin_main_chain`'s gate reads
//! `Missing` forever — while every peer answers `served`.
//!
//! **#198 reasoned about exactly this deadlock and stopped one ledger short.**
//! `n1.rs`'s `held_body` doc names `on_block_announce`'s early return as a caller
//! that must not be widened to possession, *"that is the same deadlock one seam
//! over, so the two predicates stay apart by construction"* — and the reasoning
//! held for `has_stored_body`. `self.blocks` is a third ledger in the same `if`,
//! and it already answered possession across a rewind, for free.
//!
//! ## What each test is for
//!
//! | test | question |
//! |---|---|
//! | [`the_serving_cache_must_not_strand_a_node_that_rewound_past_a_main_chain_block`] | the defect. **RED on `main`** |
//! | [`the_unfreeze_and_the_ask_clearing_are_one_event`] | the 5/5 recovery coincidence, as the healthy baseline |
//! | [`the_serving_cache_still_serves`] | #135's purpose is not the bug and must survive |
//! | [`an_ordinary_rewind_with_an_uncached_body_was_never_affected`] | the negative criterion: no new rewind trigger |
//!
//! The **eviction deadline** — that the "self-heal" was a `MAX_SERVED_BODIES`
//! counter and not recovery — is deliberately NOT a test here. It is a property of
//! the *defect*, so a test asserting it would be a fossil of the bug that goes red
//! on the fix (the `qlab-bench` n7soak precedent, ruling S5a). It was measured once
//! on the pre-fix tree and the number is recorded in
//! `docs/i229-mechanism-statement.md` §4.

use std::sync::Arc;

use qlab_devnet::body::{BlockBody, TxEntry, TxVerifier};
use qlab_devnet::committee::{devnet_committee, CommitteeState};
use qlab_devnet::header::BlockHeader;
use qlab_devnet::node::SimConfig;
use qlab_devnet::pow::KeccakPow;
use qlab_node::NodeState as _;
use qlab_p2p::adapter::NodeAdapter;
use qlab_p2p::bodywait::{BodyAnswer, RejoinGate};
use qlab_p2p::n1::{BlockIngest, ChainView, IngestOutcome};
use qlab_p2p::peer::PeerId;
use qlab_p2p::transport::{InProcHub, InProcTransport};
use qlab_p2p::P2pNode;

/// Only a tx marked `ok` verifies. Every body here is coinbase-only, so nothing
/// depends on it — same shape as the T0 net, which has never carried a transaction.
#[derive(Clone)]
struct MarkerVerifier;
impl TxVerifier for MarkerVerifier {
    fn verify_tx(&self, entry: &TxEntry) -> bool {
        entry.proof == b"ok"
    }
}

type Adapter = NodeAdapter<KeccakPow, MarkerVerifier>;
type Node = P2pNode<InProcTransport, Adapter>;

const SIM_TICK_MS: u64 = 10;

/// The victim — the host that rewound past a block it had accepted live.
const V: PeerId = PeerId(1);
/// The server — a peer with the body applied, which answers `served` every time.
const S: PeerId = PeerId(2);

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

fn node(id: PeerId, hub: &Arc<InProcHub>, rkm: u64) -> Node {
    P2pNode::new(InProcTransport::new(id, Arc::clone(hub)), adapter(rkm), [id.0 as u8; 32])
}

/// Mine one block on `a` and apply it there.
fn mine_on(a: &mut Adapter) -> (BlockHeader, BlockBody) {
    let (h, b) = a.mine_block().expect("mine");
    assert_eq!(a.ingest_block(h, b.clone()), IngestOutcome::Accepted);
    (h, b)
}

fn pump(v: &mut Node, s: &mut Node, now: &mut u64, rounds: u32) {
    for _ in 0..rounds {
        *now += SIM_TICK_MS;
        v.tick(*now);
        s.tick(*now);
    }
}

fn link(hub: &Arc<InProcHub>, v: &mut Node, s: &mut Node) {
    hub.link(V, S);
    hub.link(S, V);
    v.add_peer(S, None);
    s.add_peer(V, None);
}

/// `slag` — the applied-state lag the duty gate reads.
fn slag(n: &Node) -> u64 {
    n.node().state_lag().blocks()
}

/// The `BODYWAIT` reading for one hash, in the operator's own format.
fn ask_line(n: &Node, hash: &qlab_devnet::header::Hash32, now: u64) -> String {
    match n.body_ask_report(now).into_iter().find(|e| &e.hash == hash) {
        None => "no ask record".to_string(),
        Some(e) => e.to_line(),
    }
}

/// Whether `hash` is outstanding right now — what `breq=` counts, per hash.
fn ask_in_flight(n: &Node, hash: &qlab_devnet::header::Hash32, now: u64) -> bool {
    n.body_ask_report(now).into_iter().any(|e| &e.hash == hash && e.in_flight)
}

/// The state every test here starts from: **V held `L1`'s body in its serving
/// cache, rewound past it onto the `W` branch, and the `L` branch then retook fork
/// choice.** V's applied tip is `W2`; the one block it needs is `L1`, whose body it
/// still carries in its serving cache and no longer has applied — so `bask=1@0`,
/// the ask-set size the live hosts printed.
///
/// **`ServedBodies` has two insert sites and they reach the identical state**:
/// `announce_block` (`node.rs:847`, a node's own block) and `complete_block`
/// (`node.rs:1980`, a body accepted live from a peer, cached only when the header
/// was NEW). This helper uses the first, off-wire, because it is deterministic —
/// the trap must be armed before V can header-sync, and a node that learns a header
/// by sync first gets `Duplicate` on the body and never caches it at all.
/// [`the_same_strand_via_the_peer_accept_insert_site`] covers the second site.
struct Stranded {
    hub: Arc<InProcHub>,
    v: Node,
    s: Node,
    now: u64,
    l1: qlab_devnet::header::Hash32,
    w2: qlab_devnet::header::Hash32,
    l3: qlab_devnet::header::Hash32,
}

fn strand() -> Stranded {
    let hub = InProcHub::new();
    let mut v = node(V, &hub, 0xC0);
    let mut s = node(S, &hub, 0xC1);
    let now = 0u64;

    // ── 1. V produces L1 and announces it, with no peer linked: applied, and its
    //       body cached for serving. This is the state a host is in after accepting
    //       any block at the tip.
    let (lh1, lb1) = v.node_mut().mine_block().expect("V mines L1");
    let l1 = lh1.header_hash();
    v.announce_block(lh1, lb1.txs.clone(), lb1.coinbase, lb1.coinbase_rkm, 7);
    assert!(v.node().has_stored_body(&l1), "V applied L1");
    assert_eq!(v.served_bodies().0, 1, "…and cached its body for serving (#135)");

    // ── 2. The rest of the L branch, and a competing W branch, built off-net so
    //       nothing on the hub can source either one.
    let mut lfac = adapter(0x11);
    assert_eq!(lfac.ingest_block(lh1, lb1.clone()), IngestOutcome::Accepted);
    let (lh2, lb2) = mine_on(&mut lfac);
    let (lh3, lb3) = mine_on(&mut lfac);
    let mut wfac = adapter(0x22);
    let (wh1, wb1) = mine_on(&mut wfac);
    let (wh2, wb2) = mine_on(&mut wfac);
    let (w2, l3) = (wh2.header_hash(), lh3.header_hash());
    assert_ne!(l1, wh1.header_hash(), "a genuine sibling race at height 1");

    // ── 3. The two-block W branch takes fork choice and V rewinds past L1.
    assert_eq!(v.node_mut().ingest_block(wh1, wb1), IngestOutcome::Accepted);
    assert_eq!(v.node_mut().ingest_block(wh2, wb2), IngestOutcome::Accepted);
    assert_eq!(v.node().state_rewinds(), (1, 1), "one rewind, one block undone");
    assert_eq!(v.node().state().tip_hash(), w2, "V's applied tip is now W2");

    // 🔴 THE TRAP STATE, and it is true on both sides of the fix: two ledgers
    //    disagree about whether this node has L1's body.
    assert!(!v.node().has_stored_body(&l1), "L1 left the APPLIED store");
    assert_eq!(v.served_bodies().0, 1, "…and is STILL in the serving cache");

    // ── 4. S holds the whole L branch applied, so it can serve every body and is
    //       taller than V — which is what makes V header-sync from it.
    for (h, b) in [(lh1, lb1), (lh2, lb2), (lh3, lb3)] {
        assert_eq!(s.node_mut().ingest_block(h, b), IngestOutcome::Accepted);
    }

    // ── 5. V learns L2/L3 as HEADERS ONLY, so the L branch retakes fork choice and
    //       V's fork point drops to genesis: the one body it needs is L1.
    //
    //       Done off-wire on purpose. The trap state below is a fact about the
    //       node's two ledgers and must be asserted with no traffic in flight — if
    //       the helper pumped the wire it would already be exercising the fix, and
    //       the assertion would become a fossil of the defect rather than a
    //       description of the starting state.
    for h in [lh2, lh3] {
        assert_eq!(v.node_mut().ingest_header(h), IngestOutcome::Accepted);
    }
    assert_eq!(v.node().chain().tip_hash(), l3, "V's fork choice is on the L branch");
    assert_eq!(v.node().state().tip_hash(), w2, "…while its applied tip is still W2");
    assert_eq!(
        v.node().rejoin_gate_observed(),
        RejoinGate::Missing(1),
        "the rewind is blocked on the body at fork+1, which is L1"
    );
    assert_eq!(slag(&v), 1, "one block of applied-state lag, and the duty gate is engaged");

    // Connected, but not yet pumped: every test here owns its own wire time.
    link(&hub, &mut v, &mut s);

    Stranded { hub, v, s, now, l1, w2, l3 }
}

// ---------------------------------------------------------------------------
// 1. THE DEFECT — red on `main`
// ---------------------------------------------------------------------------

/// **A node whose serving cache holds the body its state machine needs must still
/// apply it when a peer serves it.**
///
/// On `main` this test fails at the recovery assertion, and its failure message is
/// the production reading verbatim: the ask outstanding with `served` against it,
/// re-issued far faster than the 15 s ladder allows, and `gate=missing`.
#[test]
fn the_serving_cache_must_not_strand_a_node_that_rewound_past_a_main_chain_block() {
    let Stranded { hub: _hub, mut v, mut s, mut now, l1, w2, l3 } = strand();

    // Run the net. S has L1 applied, so it serves it on every ask, forever.
    let start = now;
    pump(&mut v, &mut s, &mut now, 400);

    // The peer really did serve it — this is layer (b) being ruled out inside the
    // test, the same way the live reading ruled it out.
    let report = v.body_ask_report(now);
    let served_by_peer = report
        .iter()
        .find(|e| e.hash == l1)
        .map(|e| e.answers.get(&S) == Some(&BodyAnswer::Served))
        .unwrap_or(false);

    // 🔴 The assertion the defect fails.
    assert_eq!(
        v.node().state().tip_hash(),
        l3,
        "V is STRANDED: applied tip {:?} (expected L3), still on the W branch = {}.\n  \
         gate={:?}  slag={}  pend={:?}  cached={:?}\n  \
         L1 ask: {}\n  \
         peer served it: {served_by_peer}\n  \
         asks in {}ms vs the {}ms re-ask ladder — a rate above the ladder means the \
         ask is being CLEARED and re-created, which is the early return firing.",
        v.node().state().tip_hash(),
        v.node().state().tip_hash() == w2,
        v.node().rejoin_gate_observed(),
        slag(&v),
        v.node().pending_bodies(),
        v.served_bodies(),
        ask_line(&v, &l1, now),
        now - start,
        15_000,
    );

    // Recovery is total, not partial.
    assert_eq!(slag(&v), 0, "V caught up, so the duty gate has lifted");
    assert!(v.node().has_stored_body(&l1), "L1 is applied — the body that could not move, moved");
    assert_eq!(v.node().state_rewinds().0, 2, "the second rewind took V back onto the L branch");
    assert!(
        v.node_mut().mine_block().is_some(),
        "and V can mine again — the hashrate a stranding removes is back"
    );
}

/// **The same strand through the other insert site.** [`strand`] fills the cache
/// via `announce_block` because it is deterministic; the live hosts filled it via
/// `complete_block`, which caches a body **only when its header was new**. Both
/// reach one state — two ledgers disagreeing — and the defect does not care which
/// wrote the entry, so this is asserted rather than assumed.
///
/// The order matters and is the reason this is a separate construction: a node that
/// learns a header by **sync** first gets `Duplicate` on the body and never caches
/// it, so only a body that arrives at the tip with a header nobody has seen lands
/// in the cache at all.
#[test]
fn the_same_strand_via_the_peer_accept_insert_site() {
    let hub = InProcHub::new();
    let mut v = node(V, &hub, 0xF0);
    let mut s = node(S, &hub, 0xF1);
    let mut now = 0u64;

    // Handshake FIRST, while both are at genesis and there is nothing to sync, then
    // mine and announce back-to-back with no tick in between. The order is the whole
    // point: if V learns L1's header by sync before its body arrives, `complete_block`
    // gets `Duplicate` and never caches it — so the only way into the cache is a body
    // that arrives at the tip carrying a header nobody has seen.
    link(&hub, &mut v, &mut s);
    pump(&mut v, &mut s, &mut now, 20);
    let (lh1, lb1) = mine_on(s.node_mut());
    let l1 = lh1.header_hash();
    s.announce_block(lh1, lb1.txs.clone(), lb1.coinbase, lb1.coinbase_rkm, 11);
    pump(&mut v, &mut s, &mut now, 10);
    assert!(v.node().has_stored_body(&l1), "V accepted L1 live from a peer");
    assert_eq!(v.served_bodies().0, 1, "…and `complete_block` cached it — the other site");

    // The rest of L, and the W branch, off-net.
    let mut lfac = adapter(0x12);
    assert_eq!(lfac.ingest_block(lh1, lb1.clone()), IngestOutcome::Accepted);
    let (lh2, lb2) = mine_on(&mut lfac);
    let (lh3, lb3) = mine_on(&mut lfac);
    let mut wfac = adapter(0x23);
    let (wh1, wb1) = mine_on(&mut wfac);
    let (wh2, wb2) = mine_on(&mut wfac);

    // V rewinds past L1, S takes the whole L branch, V learns L2/L3 as headers.
    assert_eq!(v.node_mut().ingest_block(wh1, wb1), IngestOutcome::Accepted);
    assert_eq!(v.node_mut().ingest_block(wh2, wb2), IngestOutcome::Accepted);
    assert_eq!(v.node().state_rewinds(), (1, 1));
    assert!(!v.node().has_stored_body(&l1), "L1 left the applied store");
    assert_eq!(v.served_bodies().0, 1, "…and is still in the serving cache");
    for (h, b) in [(lh2, lb2), (lh3, lb3)] {
        assert_eq!(s.node_mut().ingest_block(h, b), IngestOutcome::Accepted);
        assert_eq!(v.node_mut().ingest_header(h), IngestOutcome::Accepted);
    }
    assert_eq!(v.node().rejoin_gate_observed(), RejoinGate::Missing(1));

    pump(&mut v, &mut s, &mut now, 400);
    assert_eq!(
        v.node().chain().tip_hash(),
        lh3.header_hash(),
        "V recovered: {}",
        ask_line(&v, &l1, now)
    );
    assert_eq!(slag(&v), 0);
    assert!(v.node().has_stored_body(&l1));
}

// ---------------------------------------------------------------------------
// 2. THE HEALTHY BASELINE — the 5/5 coincidence, which must survive
// ---------------------------------------------------------------------------

/// **`breq → 0` and the `stip` unfreeze are one event, not two correlated ones.**
///
/// Observed 5/5 across the instances, twice bracketed to 61 s. Under the ratified
/// mechanism that coincidence is structural: the same `on_block_announce` call that
/// applies the body clears the in-flight entry (`node.rs:1867`). A fix that cleared
/// `body_reqs` from some new place would break this silently, so it is asserted
/// per-tick rather than at the end.
#[test]
fn the_unfreeze_and_the_ask_clearing_are_one_event() {
    let Stranded { hub: _hub, mut v, mut s, mut now, l1, .. } = strand();

    let frozen_at = v.node().state().tip_height();
    let mut unfroze_on_tick = None;
    let mut breq_at_unfreeze = None;
    let mut breq_before = v.body_requests();

    for tick in 0..400u32 {
        now += SIM_TICK_MS;
        v.tick(now);
        s.tick(now);
        if v.node().state().tip_height() != frozen_at && unfroze_on_tick.is_none() {
            unfroze_on_tick = Some(tick);
            breq_at_unfreeze = Some((breq_before, v.body_requests()));
            break;
        }
        breq_before = v.body_requests();
    }

    assert!(unfroze_on_tick.is_some(), "V never unfroze from height {frozen_at}");
    let (before, after) = breq_at_unfreeze.expect("sampled");
    assert!(before > 0, "the tick before the unfreeze had the ask outstanding, got breq={before}");
    assert!(
        !ask_in_flight(&v, &l1, now),
        "on the unfreeze tick the L1 ask is gone — cleared by the same call that applied it \
         (breq {before} → {after}); {}",
        ask_line(&v, &l1, now)
    );
}

// ---------------------------------------------------------------------------
// 3. THE CONSTRAINT — #135's cache is not the bug and keeps its job
// ---------------------------------------------------------------------------

/// **The serving cache must keep serving.** Using it as a possession predicate is
/// the defect; caching bodies so a compact-relay peer can reconstruct them is its
/// purpose (#135) and is untouched.
#[test]
fn the_serving_cache_still_serves() {
    let hub = InProcHub::new();
    let mut a = node(V, &hub, 0xD0);
    let mut b = node(S, &hub, 0xD1);
    let mut now = 0u64;
    link(&hub, &mut a, &mut b);
    pump(&mut a, &mut b, &mut now, 20);

    // A mines and announces; the body enters A's cache at the own-block insert site.
    let (h, body) = a.node_mut().mine_block().expect("mine");
    let bh = h.header_hash();
    a.announce_block(h, body.txs.clone(), body.coinbase, body.coinbase_rkm, 3);
    assert!(a.served_bodies().0 >= 1, "the announced body is cached for serving");
    pump(&mut a, &mut b, &mut now, 20);

    // B got it over compact relay, which is what the cache exists to make possible.
    assert!(b.node().has_stored_body(&bh), "the peer reconstructed and applied it");
    assert_eq!(b.node().chain().tip_hash(), bh);
    // And A can still answer for it after it is applied — cache AND applied store.
    assert!(a.node().held_body(&bh).is_some(), "A still possesses the body it announced");
    assert!(a.served_bodies().0 >= 1, "the cache was not emptied by the fix");
}

/// **The negative criterion.** An ordinary rewind whose `fork + 1` body was never
/// cached recovered before this fix and must recover identically after it. The
/// point is that nothing here turns "I hold this in cache" into a rewind trigger:
/// the trigger stays arrival-driven, which is the property the reviewer argued for
/// and the mechanism statement did not challenge.
#[test]
fn an_ordinary_rewind_with_an_uncached_body_was_never_affected() {
    // L1 is never accepted live by V, so its body never enters V's serving cache.
    let mut lfac = adapter(0x11);
    let (lh1, lb1) = mine_on(&mut lfac);
    let (lh2, lb2) = mine_on(&mut lfac);
    let mut wfac = adapter(0x22);
    let (wh1, wb1) = mine_on(&mut wfac);

    let hub = InProcHub::new();
    let mut v = node(V, &hub, 0xE0);
    let mut s = node(S, &hub, 0xE1);
    let mut now = 0u64;
    for (h, b) in [(lh1, lb1.clone()), (lh2, lb2.clone())] {
        assert_eq!(s.node_mut().ingest_block(h, b), IngestOutcome::Accepted);
    }

    // V applies W1 (header-only knowledge of L), so it is off-main at height 1 with
    // an EMPTY serving cache.
    assert_eq!(v.node_mut().ingest_block(wh1, wb1), IngestOutcome::Accepted);
    for h in [lh1, lh2] {
        v.node_mut().ingest_header(h);
    }
    assert_eq!(v.served_bodies().0, 0, "nothing cached — this is the uncached path");
    assert_eq!(v.node().rejoin_gate_observed(), RejoinGate::Missing(1));

    link(&hub, &mut v, &mut s);
    pump(&mut v, &mut s, &mut now, 300);

    assert_eq!(v.node().chain().tip_hash(), lh2.header_hash());
    assert_eq!(slag(&v), 0, "the ordinary path recovers, as it always did");
    assert!(v.node().has_stored_body(&lh1.header_hash()));
}
