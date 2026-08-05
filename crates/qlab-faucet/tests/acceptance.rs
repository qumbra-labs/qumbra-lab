//! The four M11-faucet acceptance items, each as one named test.
//!
//! | acceptance item | test |
//! |---|---|
//! | request → tx → node accepts → requester scans it, **real proof** | [`end_to_end_grant_is_scanned_by_the_requester`] |
//! | the abuse control blocks what it claims | [`the_abuse_control_blocks_what_it_claims`] |
//! | …and does **not** block normal requests | [`the_abuse_control_admits_ordinary_requests`] |
//! | N consecutive grants do not wedge on "no spendable note" | [`consecutive_grants_do_not_wedge_and_the_wedge_is_named`] |
//! | an out-of-window proof is **rejected**, not silently accepted | [`an_aged_out_anchor_is_rejected_by_both_the_faucet_and_the_node`] |
//!
//! ## Two honest notes about the rig
//!
//! **Every grant proof is real** and every grant block is validated by
//! `qumbra_node::verifier::ConsensusVerifier` — the verifier the shipping binary
//! injects by default (M10-T0-4), not a test double. The claim is therefore "the
//! production verifier accepts this", which is the only version of the claim worth
//! making.
//!
//! **The seed block is the exception, and deliberately.** The faucet's real funding
//! is coinbase, and a coinbase note carries no transaction proof at all — but in
//! this prototype a coinbase note never enters the commitment tree
//! (`qlab_node::Node::apply_state` appends only `tx.commitments`), so it has no leaf
//! and cannot be witnessed. Funding is therefore seeded through one block whose
//! transactions carry a stand-in proof and whose outputs are the faucet's notes —
//! exactly the shape `qlab-demo` uses for its pre-existing UTXOs. That block, and
//! only that block, is validated with [`AcceptAll`]. It is reported as a finding,
//! not papered over: see the crate docs.

use std::sync::{Arc, Mutex};

use qlab_cbserver::client::{light_client_scan, DecoyPolicy, ScanConfig};
use qlab_devnet::body::{BlockBody, TxEntry, TxPublic, TxVerifier};
use qlab_devnet::fees::{posted_fee, ArityBucket};
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_devnet::params_devnet::MAX_ANCHOR_AGE_BLOCKS;
use qlab_faucet::{
    AcceptError, ChainView, DispenseOutcome, Faucet, FaucetConfig, FaucetLimits, GrantPlan,
    OwnedNote, Refusal, Ticket, TicketPolicy, TicketSecret, DEFAULT_GRANT_BESSEL,
    PROOF_LEASE_BLOCKS,
};
use qlab_node::{
    genesis_block, ChainStore, MemNode, MemNodeRpc, NodeRpc, NodeState, RejectReason, SubmitOutcome,
};
use qlab_note::hash::digest_bytes;
use qlab_node::rpc::serve;
use qlab_wallet::address::{Address, Diversifier};
use qlab_wallet::Wallet;
use qumbra_node::verifier::ConsensusVerifier;
use rand::rngs::StdRng;
use rand::SeedableRng;

/// **One proof at a time in this binary — the rig is shared and it is small.**
///
/// A single 2×2 grant proof peaks at **11.78 GB** (`peak memory footprint`,
/// `/usr/bin/time -l` on the test binary alone, `--test-threads=1`, release, 1
/// sample). That is not this crate's cost — `qlab-demo`'s e2e measures 11.89 GB max
/// RSS on the same rig for the same prover — but four proving tests at cargo's
/// default parallelism would demand ~48 GB, get OOM-killed (observed: SIGKILL), and
/// worse, would silently raise the whole workspace suite's memory envelope, which
/// the M4 aggregation work measured at 19.75–20.42 GB against a 32 GB budget.
///
/// So proving serialises here **explicitly** rather than by luck. Cargo runs test
/// *binaries* sequentially, so this gate is sufficient: peak stays at one proof.
/// Poisoning is ignored on purpose — a panicking test must not wedge the rest.
fn prover_gate() -> std::sync::MutexGuard<'static, ()> {
    static GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    GATE.lock().unwrap_or_else(|e| e.into_inner())
}

/// Stand-in verifier for the **seed block only** (see the module docs). Never used
/// on a grant.
struct AcceptAll;
impl TxVerifier for AcceptAll {
    fn verify_tx(&self, _: &TxEntry) -> bool {
        true
    }
}

/// The 2×2 posted price (frozen §5).
fn fee() -> u64 {
    posted_fee(ArityBucket::TwoByTwo)
}

// ---------------------------------------------------------------------------
// Rig
// ---------------------------------------------------------------------------

/// A live node behind its wallet-facing RPC, plus the block-mining helpers a
/// faucet test needs.
struct Rig {
    rpc: MemNodeRpc,
    /// Monotonic counter making every seeded note and every seed nullifier unique
    /// across *repeated* seedings. Without it a second seed round reuses the first
    /// round's nullifiers (the node's permanent set rejects the block) and mints a
    /// duplicate `cm` (so the inventory would resolve to an already-spent leaf) —
    /// both of which showed up the first time this test tried to top the faucet up.
    seed_epoch: u64,
}

impl Rig {
    /// A node at a finalized genesis, so the empty commitment root is already a
    /// valid anchor and the faucet is not cold-started into a stall.
    fn new() -> Rig {
        let mut node = MemNode::in_memory(genesis_block(1_000, 0));
        let ghash = node.chain().genesis_block_hash();
        assert!(node.finalize(ghash).expect("finalize genesis").is_recorded(), "genesis finalizes");
        Rig { rpc: NodeRpc::new(node), seed_epoch: 0 }
    }

    fn tip_height(&self) -> u64 {
        self.rpc.node().tip_height()
    }

    /// Mine one block carrying `txs`, validated by `verifier`. Returns its height.
    fn mine<V: TxVerifier>(&mut self, txs: Vec<TxEntry>, verifier: &V) -> u64 {
        let node = self.rpc.node_mut();
        let tip = node.tip_hash();
        let parent = node.chain().block(&tip).expect("tip stored").header();
        let height = parent.height + 1;
        let body = BlockBody { txs, coinbase: 0, coinbase_rkm: [0; 4] };
        let header = BlockHeader::child_of(&parent, height, 1_000, body.commitment());
        node.apply_block(header, body, verifier).expect("block applies");
        height
    }

    /// Finalize the current tip (what turns its commitment root into a valid anchor).
    fn finalize_tip(&mut self) {
        let node = self.rpc.node_mut();
        let tip = node.tip_hash();
        assert!(node.finalize(tip).expect("finalize").is_recorded(), "tip finalizes");
    }

    /// Mine `n` empty blocks — the cheap way to age an anchor out of its window.
    fn mine_empty(&mut self, n: u64) {
        for _ in 0..n {
            self.mine(vec![], &AcceptAll);
        }
    }

    /// Seed `values.len()` notes owned by `wallet` at `d`: one block whose
    /// transactions' outputs are those note commitments, then finalize it, so the
    /// notes are leaves of a *finalized* prefix and can be witnessed.
    ///
    /// Returns the notes, for the caller to register with the faucet.
    fn seed_notes(&mut self, wallet: &Wallet, d: Diversifier, values: &[u64]) -> Vec<OwnedNote> {
        let anchor = self.rpc.newest_anchor().expect("genesis is finalized");
        self.seed_epoch += 1;
        let epoch = self.seed_epoch;
        let notes: Vec<OwnedNote> = values
            .iter()
            .enumerate()
            .map(|(i, &v)| {
                let tag = 0x5EED_0000_0000_0000u64 + epoch * 0x1_0000 + i as u64;
                OwnedNote::new(wallet, v, [tag; 4], [tag ^ 0xFFFF; 4], d)
            })
            .collect();
        // The 2×2 body shape carries two commitments per tx, so K notes need
        // ceil(K/2) seed transactions. Nullifiers are distinct throughout (the body
        // rule rejects an in-block repeat).
        let mut txs = Vec::new();
        for (chunk, pair) in notes.chunks(2).enumerate() {
            let mut commitments: Vec<Hash32> = pair.iter().map(|n| digest_bytes(&n.cm)).collect();
            // Pad an odd tail with a commitment nobody owns, so the shape stays 2×2.
            while commitments.len() < 2 {
                commitments.push([0xEE; 32]);
            }
            let nf = |k: u64| -> Hash32 {
                let mut h = [0xA5u8; 32];
                h[..8].copy_from_slice(&(epoch * 1_000 + k).to_le_bytes());
                h
            };
            txs.push(TxEntry::with_placeholder_discovery(b"seed-stand-in-for-coinbase".to_vec(), TxPublic {
                    anchor,
                    nullifiers: vec![nf(chunk as u64 * 2), nf(chunk as u64 * 2 + 1)],
                    commitments,
                    bucket: ArityBucket::TwoByTwo,
                    fee: fee(),
                }));
        }
        self.mine(txs, &AcceptAll);
        self.finalize_tip();
        notes
    }

    /// Submit a grant through the wallet-facing RPC, checked by the **real**
    /// verifier.
    fn submit(&mut self, plan: &GrantPlan) -> SubmitOutcome {
        self.rpc.submit_tx(plan.entry.clone(), plan.discovery.clone(), &ConsensusVerifier)
    }
}

/// A faucet funded with `values`, plus the rig it is planning against.
fn funded_faucet(values: &[u64], limits: FaucetLimits) -> (Rig, Faucet, Wallet) {
    let wallet = Wallet::from_seed_lanes([0xFA0C_E700_0000_0001; 4]);
    let d = Diversifier::default();
    let mut rig = Rig::new();
    let notes = rig.seed_notes(&wallet, d, values);
    let mut faucet = Faucet::new(
        wallet.clone(),
        d,
        TicketSecret::from_bytes([0x5A; 32]),
        FaucetConfig { limits, ..FaucetConfig::default() },
    );
    for n in notes {
        faucet.fund(n);
    }
    (rig, faucet, wallet)
}

/// A requester wallet and its address.
fn requester(seed: u64) -> (Wallet, Address) {
    let w = Wallet::from_seed_lanes([seed; 4]);
    let a = w.address(Diversifier::default());
    (w, a)
}

/// Fifty coinbase-sized notes' worth of value is irrelevant to the note budget;
/// 50 QMB each is used because that is `coinbase(0)`.
const COINBASE_0: u64 = 50 * 100_000_000;

// ---------------------------------------------------------------------------
// Acceptance 1 — end to end, with a real proof and the production verifier
// ---------------------------------------------------------------------------

#[test]
fn end_to_end_grant_is_scanned_by_the_requester() {
    let _prover = prover_gate();
    let mut rng = StdRng::from_seed([0xA1; 32]);
    let (mut rig, mut faucet, faucet_wallet) = funded_faucet(&[COINBASE_0, COINBASE_0], FaucetLimits::default());
    let (req_wallet, req_addr) = requester(0xB0B0_B0B0_B0B0_B0B0);
    let req_d = Diversifier::default();

    // 1. A request arrives with a valid ticket and is queued.
    let ticket = faucet.issue_ticket(1);
    assert_eq!(faucet.accept("203.0.113.7:44100", req_addr, Some(ticket), 0), Ok(1));
    assert_eq!(faucet.inventory().grants_available(), 1, "two notes buy exactly one grant");

    // 2. The faucet plans, fetches live witnesses, and produces a REAL proof.
    let (plan, request) = match faucet.dispense(&rig.rpc, &mut rng) {
        DispenseOutcome::Ready { plan, request } => (plan, request),
        other => panic!("expected a ready grant, got {other:?}"),
    };
    assert_eq!(plan.grant_value, DEFAULT_GRANT_BESSEL);
    assert_eq!(plan.fee, fee());
    assert_eq!(
        plan.change.value,
        2 * COINBASE_0 - DEFAULT_GRANT_BESSEL - fee(),
        "balance: inputs = grant + change + fee"
    );
    assert_eq!(
        plan.proof_bytes, 148_625,
        "the grant carries the consensus proof wire, byte-for-byte the size \
         qlab-consensus pins"
    );
    assert!(plan.prove_secs > 0.0, "a real proof took real time: {:.2} s", plan.prove_secs);
    assert!(plan.is_submittable(&rig.rpc), "a freshly-planned grant is submittable");
    let _ = request;

    // 3. The node's wallet-facing RPC admits it under the REAL verifier.
    match rig.submit(&plan) {
        SubmitOutcome::Accepted(_) => {}
        other => panic!("the real verifier must accept a real grant, got {other:?}"),
    }
    assert_eq!(rig.rpc.pending_len(), 1);

    // 4. It is mined into a block whose body validation runs the real verifier too.
    let height = rig.mine(vec![plan.entry.clone()], &ConsensusVerifier);
    rig.finalize_tip();
    let grant_cm = plan.entry.public.commitments[0];
    let change_cm = plan.entry.public.commitments[1];
    faucet.confirm(*plan);
    assert_eq!(faucet.stats().confirmed, 1);
    assert_eq!(faucet.stats().granted_bessel, DEFAULT_GRANT_BESSEL);
    assert_eq!(faucet.inventory().len(), 1, "a grant costs exactly one note");

    // 5. The requester scans the live node with the UNMODIFIED reference light
    //    client over a real socket, and finds the grant.
    let shared = Arc::new(Mutex::new(rig.rpc));
    let handle = serve(Arc::clone(&shared));
    let base = handle.base_url();
    let cfg = ScanConfig { mode: qlab_note::scan::ScanMode::FullFo, decoy: DecoyPolicy::Off };

    let req_dk = req_wallet.diversified_keypair(&req_d).dk;
    let mut scan_rng = StdRng::from_seed([1u8; 32]);
    let found = light_client_scan(&base, &req_dk, height, height, cfg, &mut scan_rng)
        .expect("scan runs against the live node");
    assert_eq!(found.notes.len(), 1, "the requester detects exactly the grant");
    let got = &found.notes[0].detected.note;
    assert_eq!(got.value, DEFAULT_GRANT_BESSEL, "the requester scanned the granted value");
    assert_eq!(
        digest_bytes(&got.commitment()),
        grant_cm,
        "cm is byte-identical across proof, wire and note"
    );

    // 6. …and the faucet recovers its own change from the same chain — a faucet
    //    that cannot re-derive its change cannot be restored from its seed.
    let faucet_dk = faucet_wallet.diversified_keypair(&Diversifier::default()).dk;
    let mut scan_rng2 = StdRng::from_seed([2u8; 32]);
    let mine = light_client_scan(&base, &faucet_dk, height, height, cfg, &mut scan_rng2)
        .expect("scan runs");
    assert_eq!(mine.notes.len(), 1, "the faucet detects its own change note");
    assert_eq!(mine.notes[0].detected.note.value, 2 * COINBASE_0 - DEFAULT_GRANT_BESSEL - fee());
    assert_eq!(digest_bytes(&mine.notes[0].detected.note.commitment()), change_cm);

    // 7. A stranger sees nothing.
    let (stranger, _) = requester(0xDEAD_BEEF_DEAD_BEEF);
    let stranger_dk = stranger.diversified_keypair(&req_d).dk;
    let mut scan_rng3 = StdRng::from_seed([3u8; 32]);
    let none =
        light_client_scan(&base, &stranger_dk, height, height, cfg, &mut scan_rng3).expect("scan");
    assert!(none.notes.is_empty(), "a stranger detects nothing");

    handle.shutdown();
}

// ---------------------------------------------------------------------------
// Acceptance 2 — the abuse control blocks what it claims to block
// ---------------------------------------------------------------------------

#[test]
fn the_abuse_control_blocks_what_it_claims() {
    // Claimed: without an operator-issued, unused ticket you get no grant. Every
    // way of not having one is exercised, and each is checked to produce *no grant*
    // rather than merely an error.
    let mut rng = StdRng::from_seed([0xC1; 32]);
    let (rig, mut faucet, _faucet_wallet) = funded_faucet(&[COINBASE_0, COINBASE_0], FaucetLimits::default());
    let (_, addr) = requester(0x1111);

    // (a) no ticket
    assert_eq!(
        faucet.accept("203.0.113.1", addr.clone(), None, 0),
        Err(AcceptError::Refused(Refusal::TicketMissing))
    );
    // (b) a forged MAC
    let mut forged = faucet.issue_ticket(1);
    forged.tag[0] ^= 0x80;
    assert_eq!(
        faucet.accept("198.51.100.1", addr.clone(), Some(forged), 0),
        Err(AcceptError::Refused(Refusal::TicketInvalid))
    );
    // (c) a ticket minted by someone else's secret
    let foreign = Ticket::issue(&TicketSecret::from_bytes([0xFF; 32]), 1);
    assert_eq!(
        faucet.accept("192.0.2.1", addr.clone(), Some(foreign), 0),
        Err(AcceptError::Refused(Refusal::TicketInvalid))
    );

    // Nothing reached the queue, so nothing can be granted — the control stops the
    // *grant*, not merely the HTTP response.
    assert!(faucet.queue().is_empty());
    assert!(matches!(faucet.dispense(&rig.rpc, &mut rng), DispenseOutcome::Idle));
    assert_eq!(faucet.stats().refused, 3);
    assert_eq!(faucet.stats().queued, 0);

    // (d) replay: a valid ticket works exactly once, and the second use is refused
    //     even from a different network.
    let good = faucet.issue_ticket(7);
    assert_eq!(faucet.accept("203.0.113.5", addr.clone(), Some(good), 0), Ok(1));
    assert_eq!(
        faucet.accept("203.0.113.5", addr.clone(), Some(good), 60_000),
        Err(AcceptError::Refused(Refusal::TicketSpent))
    );
    assert_eq!(
        faucet.accept("10.1.2.3", addr.clone(), Some(good), 120_000),
        Err(AcceptError::Refused(Refusal::TicketSpent)),
        "a spent ticket is spent everywhere — the control is not per-network"
    );
    assert_eq!(faucet.queue().len(), 1, "exactly one grant was bought");

    // (e) the honest limit of the control, asserted rather than claimed: an attacker
    //     with unlimited *addresses* and no ticket gets nothing, and the ticket check
    //     runs first so their flood never touches the service budget.
    for i in 0..500u64 {
        let client = format!("203.0.{}.{}", i / 256, i % 256);
        assert!(faucet.accept(&client, addr.clone(), None, i * 1_000).is_err());
    }
    let gs = faucet.gate_stats();
    assert_eq!(gs.global_throttled, 0, "a ticketless flood spends no service budget");
    assert_eq!(gs.subnet_throttled, 0);
    assert_eq!(gs.admitted, 1);
}

// ---------------------------------------------------------------------------
// Acceptance 2b — …and it does not block normal requests
// ---------------------------------------------------------------------------

#[test]
fn the_abuse_control_admits_ordinary_requests() {
    let _prover = prover_gate();
    // Testing only the blocking half is testing nothing. Twenty honest users, each
    // with their own ticket, from twenty networks, arriving one block apart: all
    // twenty are admitted and queued, none throttled.
    let (rig, mut faucet, _faucet_wallet) = funded_faucet(&[COINBASE_0, COINBASE_0], FaucetLimits::default());
    let block_ms = faucet.config().limits.global_refill_window_ms;
    for i in 0..20u64 {
        let (_, addr) = requester(0x2000 + i);
        let t = faucet.issue_ticket(i);
        assert_eq!(
            faucet.accept(&format!("203.0.{i}.9:5000"), addr, Some(t), i * block_ms),
            Ok((i + 1) as usize),
            "honest user {i} must be admitted"
        );
    }
    let gs = faucet.gate_stats();
    assert_eq!(gs.admitted, 20);
    assert_eq!(gs.subnet_throttled + gs.global_throttled, 0, "no honest user throttled");
    assert_eq!(faucet.stats().queued, 20);
    assert_eq!(faucet.stats().refused, 0);

    // And the first of them is actually servable — admission leads to a grant.
    let mut rng = StdRng::from_seed([0xC2; 32]);
    assert!(matches!(
        faucet.dispense(&rig.rpc, &mut rng),
        DispenseOutcome::Ready { .. }
    ));

    // The same twenty users behind ONE network is the accident the subnet filter
    // exists for, and it is honestly a filter and not a defence: the requests are
    // throttled, and the module docs price exactly how many addresses walk around it.
    let (_rig2, mut f2, _w2) = funded_faucet(&[COINBASE_0, COINBASE_0], FaucetLimits::default());
    let (_, addr) = requester(0x3000);
    let burst = f2.config().limits.subnet_burst;
    for i in 0..burst {
        let t = f2.issue_ticket(i);
        assert!(f2.accept("203.0.113.50", addr.clone(), Some(t), 0).is_ok());
    }
    let t = f2.issue_ticket(999);
    assert_eq!(
        f2.accept("203.0.113.51", addr.clone(), Some(t), 0),
        Err(AcceptError::Refused(Refusal::SubnetThrottled)),
        "the same /24 shares one budget"
    );
    assert_eq!(f2.gate_stats().tickets_spent, burst as usize, "the throttle burned no ticket");
}

// ---------------------------------------------------------------------------
// Acceptance 3 — N consecutive grants, and the wedge is named
// ---------------------------------------------------------------------------

#[test]
fn consecutive_grants_do_not_wedge_and_the_wedge_is_named() {
    let _prover = prover_gate();
    // The note-count conservation law, run for real: five seeded notes serve
    // exactly four consecutive grants (count − 1), each a real proof accepted by the
    // real verifier, and the fifth attempt reports a *named* out-of-notes state
    // rather than stalling silently or panicking.
    const SEEDED: usize = 5;
    let mut rng = StdRng::from_seed([0xD1; 32]);
    let (mut rig, mut faucet, faucet_wallet) = funded_faucet(
        &[COINBASE_0; SEEDED],
        FaucetLimits { ticket_policy: TicketPolicy::Disabled, ..FaucetLimits::unlimited() },
    );
    assert_eq!(faucet.inventory().len(), SEEDED);
    assert_eq!(faucet.inventory().grants_available(), SEEDED - 1);

    let mut served = 0usize;
    let mut prove_secs = Vec::new();
    for i in 0..(SEEDED - 1) {
        let (_, addr) = requester(0x4000 + i as u64);
        faucet.accept("203.0.113.10", addr, None, i as u64 * 1_000).expect("open mode admits");
        let (plan, _req) = match faucet.dispense(&rig.rpc, &mut rng) {
            DispenseOutcome::Ready { plan, request } => (plan, request),
            other => panic!("grant {i} should be ready, got {other:?}"),
        };
        prove_secs.push(plan.prove_secs);
        assert!(matches!(rig.submit(&plan), SubmitOutcome::Accepted(_)), "grant {i} admitted");
        rig.mine(vec![plan.entry.clone()], &ConsensusVerifier);
        // Finality is what makes the change note spendable for the NEXT grant —
        // without it the faucet holds notes it cannot witness, which is the failure
        // this test is really watching for.
        rig.finalize_tip();
        faucet.confirm(*plan);
        served += 1;
        assert_eq!(
            faucet.inventory().len(),
            SEEDED - served,
            "after {served} grants the note count is seeded − served"
        );
    }
    assert_eq!(served, SEEDED - 1, "count − 1 grants served without wedging");
    assert_eq!(faucet.stats().confirmed, served as u64);
    assert_eq!(faucet.stats().stalled, 0, "no grant stalled on the way");

    // The change note of the last grant is still there and still anchored — the
    // faucet is not wedged on *value*, only on the note count.
    assert_eq!(faucet.inventory().len(), 1);
    assert!(faucet.inventory().total_value() > DEFAULT_GRANT_BESSEL + fee());

    // The fifth request: named, not silent.
    let (_, addr) = requester(0x4FFF);
    faucet.accept("203.0.113.10", addr, None, 99_000).expect("admitted");
    match faucet.dispense(&rig.rpc, &mut rng) {
        DispenseOutcome::Stalled(reason) => {
            let text = reason.to_string();
            assert!(
                text.contains("out of spendable notes") && text.contains("1 held"),
                "the stall must name the state: {text}"
            );
            assert!(
                text.contains("only coinbase refills"),
                "…and name the only remedy: {text}"
            );
        }
        other => panic!("expected a named stall, got {other:?}"),
    }
    // A stall consumes nothing: the request keeps its place and its attempt budget.
    assert_eq!(faucet.queue().len(), 1);
    assert_eq!(faucet.queue().front().expect("queued").attempts, 0);
    assert_eq!(faucet.stats().stalled, 1);

    // One more note — what a won block would supply — and the same faucet serves
    // again. That is the whole provisioning story: grants come from notes, notes
    // come from coinbase.
    let fresh = rig.seed_notes(&faucet_wallet, Diversifier::default(), &[COINBASE_0]);
    for n in fresh {
        faucet.fund(n);
    }
    assert!(matches!(
        faucet.dispense(&rig.rpc, &mut rng),
        DispenseOutcome::Ready { .. }
    ));

    // Basis for the prove-time figure the report quotes: this many samples, this
    // build, this machine.
    let mean: f64 = prove_secs.iter().sum::<f64>() / prove_secs.len() as f64;
    println!(
        "grant proofs: n={} mean={:.2} s min={:.2} max={:.2} (release, one process)",
        prove_secs.len(),
        mean,
        prove_secs.iter().cloned().fold(f64::MAX, f64::min),
        prove_secs.iter().cloned().fold(0.0, f64::max),
    );
    assert!(mean > 0.0);
}

// ---------------------------------------------------------------------------
// Acceptance 4 — an out-of-window proof is rejected, not silently accepted
// ---------------------------------------------------------------------------

#[test]
fn an_aged_out_anchor_is_rejected_by_both_the_faucet_and_the_node() {
    let _prover = prover_gate();
    let mut rng = StdRng::from_seed([0xE1; 32]);
    let (mut rig, mut faucet, _faucet_wallet) = funded_faucet(
        &[COINBASE_0; 4],
        FaucetLimits { ticket_policy: TicketPolicy::Disabled, ..FaucetLimits::unlimited() },
    );

    // Two requests, two plans, both bound to the anchor that is valid right now.
    for i in 0..2u64 {
        let (_, addr) = requester(0x5000 + i);
        faucet.accept("203.0.113.20", addr, None, i * 1_000).expect("admitted");
    }
    let control = match faucet.dispense(&rig.rpc, &mut rng) {
        DispenseOutcome::Ready { plan, .. } => plan,
        other => panic!("plan A should be ready, got {other:?}"),
    };
    let (aged, aged_request) = match faucet.dispense(&rig.rpc, &mut rng) {
        DispenseOutcome::Ready { plan, request } => (plan, request),
        other => panic!("plan B should be ready, got {other:?}"),
    };
    let anchor = aged.lease.anchor;
    assert_eq!(control.lease.anchor, anchor, "both plans bound the same anchor");

    // Positive control: this plan shape, this anchor, this proof — accepted now.
    // Without it, a later rejection would not distinguish "the anchor aged out" from
    // "the faucet builds bad transactions".
    assert!(control.is_submittable(&rig.rpc));
    assert!(
        matches!(rig.submit(&control), SubmitOutcome::Accepted(_)),
        "the control plan is accepted while its anchor is fresh"
    );
    rig.mine(vec![control.entry.clone()], &ConsensusVerifier);

    // Step 1: past the faucet's SELF-IMPOSED lease but well inside the protocol
    // window. The faucet refuses; the node still would not. That gap is the whole
    // point of the lease — it is conservative on purpose, because /v1/anchors does
    // not publish a root's height and the true deadline is unknowable from the wire.
    rig.mine_empty(PROOF_LEASE_BLOCKS + 1);
    assert!(
        ChainView::is_valid_anchor(&rig.rpc, &anchor),
        "the protocol window is nowhere near expiry yet"
    );
    assert!(
        !aged.is_submittable(&rig.rpc),
        "the faucet's own lease has already run out, so it declines to submit"
    );

    // Step 2: age the anchor past the frozen 24 h window.
    let anchor_height = 1; // the seed block; `Rig::seed_notes` mines and finalizes it
    let target_tip = anchor_height + MAX_ANCHOR_AGE_BLOCKS + 1;
    let to_mine = target_tip.saturating_sub(rig.tip_height());
    rig.mine_empty(to_mine);
    assert!(rig.tip_height() >= target_tip);
    assert!(
        !ChainView::is_valid_anchor(&rig.rpc, &anchor),
        "tip − anchor_height = {} exceeds MAX_ANCHOR_AGE_BLOCKS = {MAX_ANCHOR_AGE_BLOCKS}",
        rig.tip_height() - anchor_height
    );

    // The node REJECTS it, with the specific reason — the property that matters is
    // that this is not a silent acceptance and not a generic failure.
    match rig.submit(&aged) {
        SubmitOutcome::Rejected(RejectReason::AnchorNotValid) => {}
        other => panic!("an out-of-window proof must be rejected as AnchorNotValid, got {other:?}"),
    }
    assert_eq!(rig.rpc.pending_len(), 1, "the aged proof did not enter the pool");

    // And the faucet handles the refusal without losing the notes: the inputs come
    // back, so a re-plan against a fresh anchor is possible.
    let held_before = faucet.inventory().len();
    let plan_value = aged.spent[0].value + aged.spent[1].value;
    assert!(faucet.reject(*aged, aged_request), "the requester gets another attempt");
    assert_eq!(faucet.inventory().len(), held_before + 2, "the spent inputs were restored");
    assert_eq!(faucet.stats().rejected, 1);
    assert!(faucet.inventory().total_value() >= plan_value);
}

// ---------------------------------------------------------------------------
// A cold net: funded but unspendable, and it says so
// ---------------------------------------------------------------------------

#[test]
fn a_faucet_on_an_unfinalized_chain_reports_the_cold_start() {
    // Constraint four's cold start, at the seam that exists: with nothing finalized
    // there is no valid anchor, so a fully-funded faucet cannot pay — and it names
    // that state instead of looking broken.
    let mut rng = StdRng::from_seed([0xF1; 32]);
    let wallet = Wallet::from_seed_lanes([0xC01D; 4]);
    let d = Diversifier::default();

    // A node whose genesis is NOT finalized.
    let node = MemNode::in_memory(genesis_block(1_000, 0));
    let rpc: MemNodeRpc = NodeRpc::new(node);
    assert!(rpc.newest_anchor().is_none(), "nothing finalized ⇒ no valid anchor");

    let mut faucet = Faucet::new(
        wallet.clone(),
        d,
        TicketSecret::from_bytes([1; 32]),
        FaucetConfig {
            limits: FaucetLimits { ticket_policy: TicketPolicy::Disabled, ..FaucetLimits::unlimited() },
            ..FaucetConfig::default()
        },
    );
    for i in 0..4u64 {
        faucet.fund(OwnedNote::new(&wallet, COINBASE_0, [i; 4], [i + 9; 4], d));
    }
    assert!(faucet.inventory().total_value() > 0, "the faucet is funded");

    let (_, addr) = requester(0x6000);
    faucet.accept("203.0.113.30", addr, None, 0).expect("admitted");
    let out = faucet.dispense(&rpc, &mut rng);
    assert!(
        format!("{out:?}").contains("NoValidAnchor"),
        "a funded faucet on an unfinalized chain must name the cold start, got {out:?}"
    );
}

// ---------------------------------------------------------------------------
// A coinbase-funded grant discloses nothing about its coinbase origin
// ---------------------------------------------------------------------------

/// **Replaces `a_coinbase_funded_grant_declares_its_maturity_obligation`, and
/// asserts the opposite property on purpose (issue #102).**
///
/// That test locked in that the faucet *computed* the `spends_coinbase` declaration
/// the maturity gate needed. The declaration is deleted, because computing it
/// honestly was the defect: naming the coinbase notes a transaction spends links the
/// spend to the coinbase, and on a chain with one global shielded pool and no
/// transparent tier that collapses the anonymity set of exactly the first
/// transaction a new user makes. Maturity is structural now, so nothing needs to be
/// said — and this test pins that nothing *is* said.
#[test]
fn a_coinbase_funded_grant_discloses_no_coinbase_origin() {
    let _prover = prover_gate();
    let mut rng = StdRng::from_seed([0x71; 32]);
    let wallet = Wallet::from_seed_lanes([0xFA0C_E700_0000_0001; 4]);
    let d = Diversifier::default();
    let mut rig = Rig::new();

    // Seed two notes and then mark them coinbase-derived, as a mining faucet's own
    // notes would be.
    let plain = rig.seed_notes(&wallet, d, &[COINBASE_0, COINBASE_0]);
    // Real coinbase-note leaves now (issue #101 deleted the placeholder digest):
    // the same commitments `Node::apply_state` would have appended for a block at
    // each height paying this faucet's own rkm.
    let miner_rkm = wallet.rkm(d);
    let cb_at = |h: u64| {
        qlab_node::coinbase_note_leaf(
            h,
            &qlab_devnet::body::BlockBody {
                txs: Vec::new(),
                coinbase: qlab_node::coinbase(h),
                coinbase_rkm: miner_rkm,
            },
        )
        .expect("a minting body has a coinbase leaf")
    };
    let (cb0, cb1) = (cb_at(1), cb_at(2));
    let mut faucet = Faucet::new(
        wallet,
        d,
        TicketSecret::from_bytes([2; 32]),
        FaucetConfig {
            limits: FaucetLimits { ticket_policy: TicketPolicy::Disabled, ..FaucetLimits::unlimited() },
            ..FaucetConfig::default()
        },
    );
    for (n, minted_at) in plain.into_iter().zip([1u64, 2u64]) {
        faucet.fund(OwnedNote { coinbase_minted_at: Some(minted_at), ..n });
    }

    let (_, addr) = requester(0x7000);
    faucet.accept("203.0.113.40", addr, None, 0).expect("admitted");
    let plan = match faucet.dispense(&rig.rpc, &mut rng) {
        DispenseOutcome::Ready { plan, .. } => plan,
        other => panic!("expected a ready grant, got {other:?}"),
    };
    // The faucet knows privately that both inputs are coinbase-derived, and knows the
    // heights — it needs them to decide when to fund, and a holder needs them to tell
    // "immature" from "nonexistent".
    let minted: Vec<u64> =
        plan.spent.iter().map(|n| n.coinbase_minted_at.expect("coinbase-derived")).collect();
    assert_eq!(minted, vec![1, 2]);

    // 🔴 THE CLAIM: none of that reaches the wire. The consensus surface is
    // `anchor ‖ nullifiers ‖ commitments ‖ bucket ‖ fee`, and neither coinbase leaf
    // appears anywhere in it — not as an input (a spend appears only as a nullifier,
    // which is unlinkable by construction), and not as a declaration, because there
    // is no field left to carry one.
    let p = &plan.entry.public;
    for cb in [cb0, cb1] {
        assert!(!p.nullifiers.contains(&cb), "a coinbase leaf must not appear as a nullifier");
        assert!(!p.commitments.contains(&cb), "nor as an output commitment");
        assert_ne!(p.anchor, cb, "nor as the anchor");
    }
    // And nowhere in the bytes a peer actually receives: the serialized proof plus
    // every field of the public surface, concatenated.
    let mut wire = plan.entry.proof.clone();
    wire.extend_from_slice(&p.anchor);
    for h in p.nullifiers.iter().chain(p.commitments.iter()) {
        wire.extend_from_slice(h);
    }
    wire.extend_from_slice(&p.fee.to_le_bytes());
    for cb in [cb0, cb1] {
        assert!(
            !wire.windows(32).any(|w| w == cb),
            "no coinbase-note commitment may appear anywhere on the transaction wire"
        );
    }

    // The change note is an ordinary output with no coinbase origin of its own.
    assert_eq!(plan.change.coinbase_minted_at, None);
}
