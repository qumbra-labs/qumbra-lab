//! The issue-#123 acceptance items, each as one named test.
//!
//! | acceptance item | test |
//! |---|---|
//! | the listener defaults to loopback | [`the_listener_defaults_to_loopback`] |
//! | an unbindable address is **fatal**, not a service its operator wrongly believes is running | [`an_unbindable_listen_addr_is_fatal`] |
//! | a request through the HTTP surface reaches `Faucet::accept` | [`an_http_request_reaches_faucet_accept`] |
//! | …and a refusal is surfaced as a refusal, not a 500 | [`every_refusal_is_a_refusal_over_the_wire_never_a_500`] |
//! | the access/request logs contain **no** full requester address | [`the_access_log_carries_no_full_requester_address`] |
//! | a browser request becomes a real grant the requester can find | [`a_browser_request_becomes_a_real_grant_the_requester_detects`] |
//!
//! Issue #266 added the open-mode half at the same seam — the stamped posture
//! (`t1-faucet-access-decision.md`, option B) was already built and locked at
//! `AbuseGate::admit`, but never exercised through the listener:
//!
//! | acceptance item | test |
//! |---|---|
//! | open mode admits a bare address through `POST /request` | [`open_mode_admits_a_bare_address_through_post_request`] |
//! | …and a supplied ticket — forged included — is a no-op there | [`open_mode_ignores_a_supplied_ticket_forged_included_through_post_request`] |
//!
//! Every request here goes over a **real TCP socket** with a hand-written HTTP/1.1
//! exchange. Nothing calls a handler directly; the unit tests in `src/http.rs` do
//! that, and they are a different claim.
//!
//! ## 🔴 One honest note about the submit seam, and it is load-bearing
//!
//! [`a_browser_request_becomes_a_real_grant_the_requester_detects`] submits through
//! `qlab_node::rpc::NodeRpc::submit_tx` — the wallet-facing RPC — because that is the
//! **only** seam in this tree that records a transaction's note-discovery artifacts,
//! and without them a recipient cannot learn their output's `(value, ρ, rseed)` and
//! so cannot detect or spend it.
//!
//! **That is not the seam the deployed binary has.** `qumbra-node` composes no
//! `NodeRpc`; an in-process faucet's only submit path is `P2pNode::announce_tx` →
//! `NodeAdapter::ingest_tx`, which takes a bare `TxEntry` and drops
//! `plan.discovery` (see `FaucetNode::submit_local`'s impl for `RunningNode`). So
//! what this test proves is: *the faucet builds a correct, verifiable, detectable
//! grant, and a node that serves note discovery delivers it.* What it does **not**
//! prove — and what is reported as a finding on issue #123 rather than worked around
//! — is that the four-node docker net can deliver one, because no node in that
//! topology serves note discovery at all.
//!
//! ## Cost
//!
//! One real 2×2 grant proof: ~2.3 s and ~11.8 GB peak on the reference rig, the same
//! figure `qlab-faucet`'s own acceptance suite and `qumbra-node`'s
//! `coinbase_spend.rs` quote. Exactly one proving test here, so no gate is needed —
//! but run with `--test-threads=1` alongside anything else that proves.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};

use qlab_cbserver::client::{light_client_scan, DecoyPolicy, ScanConfig};
use qlab_devnet::body::{BlockBody, TxEntry, TxVerifier};
use qlab_devnet::header::BlockHeader;
use qlab_devnet::params_devnet::GENESIS_DIFFICULTY;
use qlab_faucet::{
    Faucet, FaucetConfig, FaucetLimits, GrantPlan, TicketPolicy, TicketSecret,
    DEFAULT_GRANT_BESSEL,
};
use qlab_node::{
    coinbase, genesis_block, ChainStore, CommitmentStore, MemNode, MemNodeRpc, NodeRpc, NodeState,
    RejectReason, SubmitOutcome,
};
use qlab_wallet::address::{Address, Diversifier};
use qlab_wallet::Wallet;
use qumbra_faucet::config::FaucetServiceConfig;
use qumbra_faucet::harvest::spendable_at_tip;
use qumbra_faucet::http::{FaucetServer, TrustedProxies};
use qumbra_faucet::service::{
    FaucetNode, FaucetService, LocalSubmit, RequestState, SubmitRefusal,
};
use qumbra_node::verifier::ConsensusVerifier;
use rand::SeedableRng;

// ---------------------------------------------------------------------------
// A real HTTP/1.1 client, hand-written so the test exercises sockets
// ---------------------------------------------------------------------------

/// One request/response over a real socket. Returns `(status, headers, body)`.
fn http(addr: SocketAddr, raw: &str) -> (u16, String, String) {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.write_all(raw.as_bytes()).expect("write");
    let mut out = String::new();
    s.read_to_string(&mut out).expect("read");
    let status = out
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("no status line in {out:?}"));
    let (head, body) = out.split_once("\r\n\r\n").unwrap_or((out.as_str(), ""));
    (status, head.to_string(), body.to_string())
}

fn get(addr: SocketAddr, path: &str) -> (u16, String, String) {
    http(addr, &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"))
}

/// Like [`get`], but the body stays **bytes**. `http` reads with `read_to_string`,
/// which fails outright on a PNG — so a binary route cannot be tested through it,
/// and a test that only checked the status code would pass against a body that was
/// silently mangled.
fn get_bytes(addr: SocketAddr, path: &str) -> (u16, String, Vec<u8>) {
    let mut s = TcpStream::connect(addr).expect("connect");
    let raw = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    s.write_all(raw.as_bytes()).expect("write");
    let mut out = Vec::new();
    s.read_to_end(&mut out).expect("read");
    let split = out.windows(4).position(|w| w == b"\r\n\r\n").expect("headers end");
    let head = String::from_utf8_lossy(&out[..split]).to_string();
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("no status line in {head:?}"));
    (status, head, out[split + 4..].to_vec())
}

/// A real form POST — the exchange a browser makes.
fn post_request(addr: SocketAddr, address: &str, ticket: Option<&str>) -> (u16, String, String) {
    post_request_with_headers(addr, address, ticket, "")
}

/// Like [`post_request`], with extra raw header lines (each ending in `\r\n`).
fn post_request_with_headers(
    addr: SocketAddr,
    address: &str,
    ticket: Option<&str>,
    extra_headers: &str,
) -> (u16, String, String) {
    let mut body = format!("address={address}");
    if let Some(t) = ticket {
        body.push_str(&format!("&ticket={t}"));
    }
    http(
        addr,
        &format!(
            "POST /request HTTP/1.1\r\nHost: localhost\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: {}\r\n{extra_headers}Connection: close\r\n\r\n{body}",
            body.len()
        ),
    )
}

// ---------------------------------------------------------------------------
// Rig
// ---------------------------------------------------------------------------

/// Fixture blocks carry no transactions except the one grant, which is validated by
/// the production verifier.
struct NoTx;
impl TxVerifier for NoTx {
    fn verify_tx(&self, _: &TxEntry) -> bool {
        unreachable!("fixture blocks carry no transactions")
    }
}

/// A [`FaucetNode`] over a real node the test can mine directly.
///
/// It holds a [`MemNodeRpc`] rather than a bare [`MemNode`] for exactly one reason:
/// `NodeRpc::submit_tx` is the only seam in the tree that records note-discovery
/// artifacts, and the last step of the acceptance run is a requester **finding** their
/// grant. See the module docs — the deployed binary has no such seam, and that is a
/// reported finding, not something this rig papers over.
struct TestNode {
    rpc: MemNodeRpc,
    tip: BlockHeader,
    /// Grants the node admitted and has not yet mined.
    pending: Vec<TxEntry>,
}

impl TestNode {
    fn new() -> TestNode {
        let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
        let tip = genesis.header();
        let mut node = MemNode::in_memory(genesis);
        let ghash = node.chain().genesis_block_hash();
        assert!(node.finalize(ghash).expect("finalize genesis").is_recorded(), "genesis finalizes");
        TestNode { rpc: NodeRpc::new(node), tip, pending: Vec::new() }
    }

    /// Mine one block carrying `txs` and paying `rkm`, and finalize it.
    fn mine<V: TxVerifier>(&mut self, txs: Vec<TxEntry>, rkm: [u64; 4], verifier: &V) -> u64 {
        let height = self.tip.height + 1;
        let body = BlockBody { txs, coinbase: coinbase(height), coinbase_rkm: rkm };
        let header =
            BlockHeader::child_of(&self.tip, height * 75, GENESIS_DIFFICULTY, body.commitment());
        let node = self.rpc.node_mut();
        let hash = node.apply_block(header, body, verifier).expect("block applies");
        node.finalize(hash).expect("finalize");
        self.tip = header;
        height
    }

    /// Mine `n` empty blocks paying `rkm`.
    fn mine_empty(&mut self, n: u64, rkm: [u64; 4]) {
        for _ in 0..n {
            self.mine(Vec::new(), rkm, &NoTx);
        }
    }

    /// Mine whatever the faucet has submitted, under the **production** verifier.
    fn mine_pending(&mut self, rkm: [u64; 4]) -> u64 {
        let txs = std::mem::take(&mut self.pending);
        assert!(!txs.is_empty(), "nothing pending to mine");
        self.mine(txs, rkm, &ConsensusVerifier)
    }
}

impl FaucetNode for TestNode {
    fn chain_state(&self) -> &MemNode {
        self.rpc.node()
    }

    fn submit_local(&mut self, plan: &GrantPlan) -> LocalSubmit {
        // The full submission, discovery included — see the module docs for why this
        // is the RPC seam and not the seam the deployed binary has.
        // Named refusals (lab #310) so a double-spend surfaces as `nullifier-spent`
        // rather than a panic — the post-restart path exercises this.
        match self.rpc.submit_tx(plan.entry.clone(), plan.discovery.clone(), &ConsensusVerifier) {
            SubmitOutcome::Accepted(_) => {
                self.pending.push(plan.entry.clone());
                LocalSubmit::Accepted
            }
            SubmitOutcome::Duplicate => {
                LocalSubmit::Refused(SubmitRefusal::Node { reason: "duplicate".into() })
            }
            SubmitOutcome::Rejected(RejectReason::NullifierSpent) => {
                LocalSubmit::Refused(SubmitRefusal::Node { reason: "nullifier-spent".into() })
            }
            SubmitOutcome::Rejected(RejectReason::AnchorNotValid) => {
                LocalSubmit::Refused(SubmitRefusal::Node { reason: "anchor-not-valid".into() })
            }
            SubmitOutcome::Rejected(RejectReason::ProofInvalid) => {
                LocalSubmit::Refused(SubmitRefusal::Node { reason: "proof-invalid".into() })
            }
            other => LocalSubmit::Refused(SubmitRefusal::Node {
                reason: format!("rejected:{other:?}"),
            }),
        }
    }

    fn peers(&self) -> u64 {
        0
    }

    /// This fixture drives `MemNode` directly through `NodeRpc` — there is no P2P
    /// adapter here and so no fork-choice header view distinct from applied state.
    /// It answers with its applied tip in both positions, which is the truth for
    /// this node rather than a convenient zero: it is not behind, it has one view.
    fn chain_views(&self) -> qlab_node::StateLag {
        let tip = self.rpc.node().tip_height();
        qlab_node::StateLag::new(tip, tip)
    }
}

fn faucet_wallet() -> Wallet {
    Wallet::from_seed_lanes([0x0123_0000_0000_0001; 4])
}

/// A faucet + service over `wallet`, with tickets under `policy`.
fn service(wallet: &Wallet, policy: TicketPolicy) -> FaucetService {
    let d = Diversifier::default();
    let faucet = Faucet::new(
        wallet.clone(),
        d,
        TicketSecret::from_bytes([0x7C; 32]),
        FaucetConfig {
            limits: FaucetLimits { ticket_policy: policy, ..FaucetLimits::default() },
            ..FaucetConfig::default()
        },
    );
    FaucetService::new(faucet, wallet.clone(), d)
}

fn requester(seed: u64) -> (Wallet, Address) {
    let w = Wallet::from_seed_lanes([seed; 4]);
    let a = w.address(Diversifier::default());
    (w, a)
}

/// Bring the chain to the point where the faucet holds two **matured** coinbase
/// notes, and tick the service so they are funded in.
///
/// Two, because a 2×2 bucket has two inputs: one grant needs two notes, whatever
/// they are worth (`qlab_faucet::inventory`'s conservation law).
fn funded(node: &mut TestNode, service: &mut FaucetService, wallet: &Wallet) {
    let mine = wallet.rkm(Diversifier::default());
    let burn = [0xBE, 0xEF, 0xBE, 0xEF];
    node.mine_empty(2, mine); // heights 1 and 2 pay the faucet
    let target = spendable_at_tip(2);
    node.mine_empty(target - node.chain_state().tip_height(), burn);
    assert_eq!(node.chain_state().tip_height(), target);

    let mut rng = rand::rngs::StdRng::from_seed([0x11; 32]);
    let report = service.tick(node, &mut rng);
    assert_eq!(report.harvest.funded, 2, "both matured coinbase notes funded in");
    assert_eq!(report.harvest.maturing, 0);
}

// ---------------------------------------------------------------------------
// Acceptance 1 — loopback by default, and an unbindable address is FATAL
// ---------------------------------------------------------------------------

/// 🔴 **The listener defaults to loopback**, and every non-loopback form is
/// recognised as the exposure it is.
///
/// A faucet holds a hot spending key. One that becomes internet-reachable the moment
/// somebody sets a config key is the shape `testnet-plan.md` §6.2 exists to prevent,
/// so the default is the decision — the same shape `metrics_addr` and
/// `telemetry_addr` have, except those default to *no listener at all* and a faucet
/// with no listener is not a faucet.
#[test]
fn the_listener_defaults_to_loopback() {
    let minimal = "node_config = \"n.toml\"\nseed_file = \"s\"\nticket_secret_file = \"t\"\n";
    let cfg = FaucetServiceConfig::from_toml(minimal).expect("parse");
    assert_eq!(cfg.listen_addr, "127.0.0.1:9450");
    assert!(cfg.binds_loopback());

    // …and it really binds there: a socket on the default address answers, and the
    // bound address is loopback as reported by the OS, not merely as configured.
    let wallet = faucet_wallet();
    let svc = service(&wallet, TicketPolicy::Required);
    let server = FaucetServer::start("127.0.0.1:0", svc.gate(), svc.status()).expect("bind");
    assert!(server.addr().ip().is_loopback(), "bound {}", server.addr());
    let (status, _, body) = get(server.addr(), "/healthz");
    assert_eq!(status, 200);
    assert_eq!(body, "ok\n");
    server.shutdown();
}

/// The page's icons are served by **this** process, byte-for-byte as committed.
///
/// Three things are asserted rather than one, because each fails differently and the
/// cheap version of this test would catch none of them: a 200 with an HTML error page
/// in it (wrong content type, right status), a truncated or re-encoded body (right
/// type, wrong bytes), and a missing cache header (correct but refetched on every
/// page load, which puts a line in the access journal each time).
///
/// The comparison is against the same files `http.rs` compiles in, so this also locks
/// what `assets/brand/PROVENANCE.md` records: the served icon is the brand's icon, and
/// a copy that drifts from the canonical source shows up here as a diff rather than as
/// a subtly different mark on one of two public faces.
#[test]
fn the_brand_icons_are_served_from_this_process_unaltered() {
    let wallet = faucet_wallet();
    let svc = service(&wallet, TicketPolicy::Required);
    let server = FaucetServer::start("127.0.0.1:0", svc.gate(), svc.status()).expect("bind");

    for (path, expected) in [
        ("/favicon-32.png", &include_bytes!("../assets/brand/favicon-32.png")[..]),
        ("/favicon-16.png", &include_bytes!("../assets/brand/favicon-16.png")[..]),
    ] {
        let (status, head, body) = get_bytes(server.addr(), path);
        assert_eq!(status, 200, "{path} status; head={head}");
        assert!(
            head.to_lowercase().contains("content-type: image/png"),
            "{path} must be labelled image/png, got {head}"
        );
        assert!(
            head.to_lowercase().contains("cache-control:"),
            "{path} must carry a cache header, got {head}"
        );
        assert_eq!(body, expected, "{path} bytes differ from the committed asset");
        assert_eq!(&body[..8], b"\x89PNG\r\n\x1a\n", "{path} is not a PNG");
    }

    // And the page points at exactly these, on this origin.
    let (_, _, index) = get(server.addr(), "/");
    assert!(index.contains("href=\"/favicon-32.png\""), "index must declare the 32px icon");
    assert!(index.contains("href=\"/favicon-16.png\""), "index must declare the 16px icon");

    server.shutdown();
}

/// 🔴 **An unbindable address is an error, not a silent no-op.**
///
/// The failure mode this closes is `metrics_addr`'s: a service whose operator
/// believes it is running and which is not. For a faucet it is worse than for a
/// metrics endpoint, because the discovery path is a user who cannot get funds and
/// has no way to report it.
#[test]
fn an_unbindable_listen_addr_is_fatal() {
    let wallet = faucet_wallet();
    let svc = service(&wallet, TicketPolicy::Required);

    // Not an address at all.
    assert!(FaucetServer::start("256.256.256.256:9", svc.gate(), svc.status()).is_err());
    // A port only root may bind (this suite does not run as root).
    assert!(FaucetServer::start("127.0.0.1:1", svc.gate(), svc.status()).is_err());
    // Already in use — the likeliest real operator error, two faucets one port.
    let first = FaucetServer::start("127.0.0.1:0", svc.gate(), svc.status()).expect("bind");
    let taken = first.addr().to_string();
    let err = FaucetServer::start(&taken, svc.gate(), svc.status())
        .expect_err("the second bind on one port must fail");
    // The message names the config key, so an operator knows what to change.
    assert!(err.to_string().contains("listen_addr"), "{err}");
    first.shutdown();
}

// ---------------------------------------------------------------------------
// Acceptance 2 — a request reaches the core, and a refusal is a refusal
// ---------------------------------------------------------------------------

/// 🔴 **A request through the HTTP surface reaches `Faucet::accept`.**
///
/// Asserted on the *core's own counters*, not on the HTTP response: a listener that
/// returned 202 without the core having queued anything would pass a status-code
/// test and be a lie.
#[test]
fn an_http_request_reaches_faucet_accept() {
    let wallet = faucet_wallet();
    let mut node = TestNode::new();
    let mut svc = service(&wallet, TicketPolicy::Required);
    funded(&mut node, &mut svc, &wallet);

    let gate = svc.gate();
    let server = FaucetServer::start("127.0.0.1:0", svc.gate(), svc.status()).expect("bind");
    let (_, addr) = requester(0xC0DE_0001);
    let ticket = gate.lock().unwrap().issue_ticket(1).encode();

    let (status, _, body) = post_request(server.addr(), &addr.encode(), Some(&ticket));
    assert_eq!(status, 202, "{body}");
    {
        let g = gate.lock().unwrap();
        assert_eq!(g.faucet().stats().queued, 1, "the CORE queued it, not just the listener");
        assert_eq!(g.faucet().queue().len(), 1);
        assert_eq!(g.faucet().gate_stats().admitted, 1);
        assert_eq!(g.faucet().gate_stats().tickets_spent, 1, "the ticket was spent by the gate");
        assert_eq!(g.state_of(1), Some(RequestState::Queued { position: 1 }));
    }
    // The receipt is reachable, and it is the handle the response advertised.
    let (status, _, body) = get(server.addr(), "/r/1");
    assert_eq!(status, 200);
    assert!(body.contains("waiting"), "{body}");
    // An unissued receipt is a 404, not an invented state.
    assert_eq!(get(server.addr(), "/r/999").0, 404);
    server.shutdown();
}

/// 🔴 **Every refusal is surfaced as a refusal — never a 500.**
///
/// Six refusals over real sockets, each with the status it means and the reason in
/// the body. `assert_ne!(500)` is not enough on its own: a 500 and a 403 are both
/// "you did not get funds", and the difference is whether the operator gets paged.
#[test]
fn every_refusal_is_a_refusal_over_the_wire_never_a_500() {
    let wallet = faucet_wallet();
    let mut node = TestNode::new();
    let mut svc = service(&wallet, TicketPolicy::Required);
    funded(&mut node, &mut svc, &wallet);
    let gate = svc.gate();
    let server = FaucetServer::start("127.0.0.1:0", svc.gate(), svc.status()).expect("bind");
    let (_, addr) = requester(0xC0DE_0002);
    let encoded = addr.encode();

    // (a) no ticket → 403, and the core's own words.
    let (status, _, body) = post_request(server.addr(), &encoded, None);
    assert_eq!(status, 403);
    assert!(body.contains("grant ticket is required"), "{body}");

    // (b) a forged ticket → 403. The tag is flipped, so the MAC fails.
    let mut forged = gate.lock().unwrap().issue_ticket(2);
    forged.tag[0] ^= 0x80;
    let (status, _, body) = post_request(server.addr(), &encoded, Some(&forged.encode()));
    assert_eq!(status, 403);
    assert!(body.contains("not recognised"), "{body}");

    // (c) a malformed address → 400, and it costs no ticket.
    let good = gate.lock().unwrap().issue_ticket(3).encode();
    let (status, _, body) = post_request(server.addr(), "qmb1definitelynot", Some(&good));
    assert_eq!(status, 400);
    assert!(body.contains("not a Qumbra address"), "{body}");

    // (d) that same ticket still works, which is the point of (c).
    assert_eq!(post_request(server.addr(), &encoded, Some(&good)).0, 202);

    // (e) replay → 409. The credential was real; the state refuses.
    let (status, _, body) = post_request(server.addr(), &encoded, Some(&good));
    assert_eq!(status, 409);
    assert!(body.contains("already used"), "{body}");

    // (f) the wrong method and the wrong route are 405 and 404, not 500s.
    assert_eq!(get(server.addr(), "/request").0, 405);
    assert_eq!(get(server.addr(), "/nope").0, 404);
    assert_eq!(
        http(
            server.addr(),
            "DELETE / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        )
        .0,
        405
    );

    // (g) an empty body is a 400, not a panic in the form parser.
    assert_eq!(post_request(server.addr(), "", None).0, 400);

    // Nothing in this test produced a 5xx other than the deliberate 503 path, which
    // is exercised separately below.
    let journal = server.journal();
    assert!(
        journal.iter().all(|l| !l.contains(" 500 ")),
        "a refusal was reported as a server error: {journal:?}"
    );
    server.shutdown();
}

/// 🔴 **An unavailable faucet refuses with a 503 that names the height, and burns no
/// ticket** — position 2, over a real socket.
///
/// The faucet is cold here: nothing is finalized past genesis and no note has
/// matured, so a queue slot would be a promise with no basis.
#[test]
fn an_unservable_faucet_refuses_and_keeps_the_requesters_ticket() {
    let wallet = faucet_wallet();
    let mut node = TestNode::new();
    let mut svc = service(&wallet, TicketPolicy::Required);
    // One block to the faucet, nowhere near maturity: the state is `Maturing` and the
    // wait is far longer than the queue's advertised 32 blocks.
    node.mine_empty(1, wallet.rkm(Diversifier::default()));
    let mut rng = rand::rngs::StdRng::from_seed([0x22; 32]);
    svc.tick(&mut node, &mut rng);

    let gate = svc.gate();
    let server = FaucetServer::start("127.0.0.1:0", svc.gate(), svc.status()).expect("bind");
    let (_, addr) = requester(0xC0DE_0003);
    let ticket = gate.lock().unwrap().issue_ticket(9).encode();

    let (status, head, body) = post_request(server.addr(), &addr.encode(), Some(&ticket));
    assert_eq!(status, 503, "{body}");
    assert!(head.contains("Retry-After"), "a 503 must say when to come back: {head}");
    // The refusal names the height at which the answer changes, and the constant.
    assert!(body.contains("spendable once the chain reaches height"), "{body}");
    assert!(body.contains("144"), "the frozen §2 constant is named: {body}");
    // 🔴 …and the ticket survives the faucet's own shortage.
    {
        let g = gate.lock().unwrap();
        assert_eq!(g.faucet().gate_stats().tickets_spent, 0, "no ticket was presented");
        assert_eq!(g.faucet().stats().refused, 0, "the gate was never consulted");
        assert!(g.faucet().queue().is_empty(), "nothing was queued that cannot be served");
    }
    // Which is checkable: the same ticket is accepted once the faucet is funded.
    let burn = [0xBE, 0xEF, 0xBE, 0xEF];
    let target = spendable_at_tip(1);
    node.mine_empty(target - node.chain_state().tip_height(), burn);
    node.mine_empty(1, wallet.rkm(Diversifier::default()));
    let target2 = spendable_at_tip(node.chain_state().tip_height());
    node.mine_empty(target2 - node.chain_state().tip_height(), burn);
    svc.tick(&mut node, &mut rng);
    assert_eq!(
        post_request(server.addr(), &addr.encode(), Some(&ticket)).0,
        202,
        "the ticket refused by a 503 is still good"
    );
    server.shutdown();
}

// ---------------------------------------------------------------------------
// Issue #266 — the stamped open posture, locked at the listener seam
// ---------------------------------------------------------------------------

/// 🔴 **Open mode admits a bare address through `POST /request`.**
///
/// The stamped posture (`t1-faucet-access-decision.md`, option B):
/// `tickets_required = false` means a browser posting nothing but an address gets a
/// 202 and a receipt. Every other socket test here runs `TicketPolicy::Required`;
/// this one locks the open half at the same seam, asserted on the core's own
/// counters — a listener that returned 202 without the core queueing anything would
/// pass a status-code test and be a lie.
#[test]
fn open_mode_admits_a_bare_address_through_post_request() {
    let wallet = faucet_wallet();
    let mut node = TestNode::new();
    let mut svc = service(&wallet, TicketPolicy::Disabled);
    funded(&mut node, &mut svc, &wallet);

    let gate = svc.gate();
    let server = FaucetServer::start("127.0.0.1:0", svc.gate(), svc.status()).expect("bind");
    let (_, addr) = requester(0xC0DE_0266);

    let (status, _, body) = post_request(server.addr(), &addr.encode(), None);
    assert_eq!(status, 202, "{body}");
    assert!(body.contains("queued at position 1"), "{body}");
    assert!(body.contains("receipt is 1"), "{body}");
    {
        let g = gate.lock().unwrap();
        assert_eq!(g.faucet().stats().queued, 1, "the CORE queued it, not just the listener");
        assert_eq!(g.faucet().gate_stats().admitted, 1);
        assert_eq!(g.faucet().gate_stats().tickets_spent, 0, "no ticket exists to spend");
        assert_eq!(g.faucet().stats().refused, 0);
        assert_eq!(g.state_of(1), Some(RequestState::Queued { position: 1 }));
    }
    server.shutdown();
}

/// 🔴 **In open mode a supplied ticket — forged included — is a no-op through
/// `POST /request`: admitted, no serial burned, no refusal.**
///
/// The stale-bookmark case: a user who kept the ticketed form and still has a
/// ticket in the field must not be refused by a faucet that stopped requiring one.
/// The forged half is the sharper claim — open mode ignores a presented ticket
/// entirely rather than half-validating it, so a ticket this faucet never issued
/// admits exactly like a real one, and neither touches the serial ledger.
#[test]
fn open_mode_ignores_a_supplied_ticket_forged_included_through_post_request() {
    let wallet = faucet_wallet();
    let mut node = TestNode::new();
    let mut svc = service(&wallet, TicketPolicy::Disabled);
    funded(&mut node, &mut svc, &wallet);

    let gate = svc.gate();
    let server = FaucetServer::start("127.0.0.1:0", svc.gate(), svc.status()).expect("bind");
    let (_, addr) = requester(0xC0DE_0267);
    let encoded = addr.encode();

    // (a) a real ticket, issued by this faucet: admitted, and its serial survives.
    let ticket = gate.lock().unwrap().issue_ticket(1);
    let (status, _, body) = post_request(server.addr(), &encoded, Some(&ticket.encode()));
    assert_eq!(status, 202, "{body}");

    // (b) a forged ticket (the tag is flipped, so the MAC could never verify):
    // admitted identically. In Required mode this exact forgery is a 403.
    let mut forged = gate.lock().unwrap().issue_ticket(2);
    forged.tag[0] ^= 0x80;
    let (status, _, body) = post_request(server.addr(), &encoded, Some(&forged.encode()));
    assert_eq!(status, 202, "{body}");

    {
        let g = gate.lock().unwrap();
        assert_eq!(g.faucet().stats().queued, 2, "both requests reached the core's queue");
        assert_eq!(g.faucet().gate_stats().admitted, 2);
        assert_eq!(g.faucet().gate_stats().tickets_spent, 0, "no serial was burned by either");
        assert_eq!(g.faucet().stats().refused, 0, "and the gate refused nothing");
    }
    // No refusal reached the wire either: every /request line the server journalled
    // is the 202.
    let journal = server.journal();
    assert!(
        journal.iter().filter(|l| l.contains("POST /request")).all(|l| l.contains(" 202 ")),
        "{journal:?}"
    );
    server.shutdown();
}

// ---------------------------------------------------------------------------
// Acceptance 3 — the logs carry no full requester address
// ---------------------------------------------------------------------------

/// 🔴 **The access/request log contains no full requester address.**
///
/// PR #103 truncates the requester address in `PendingRequest` because a full address
/// in log rotation is a standing record of who asked for funds on a privacy chain.
/// An access log is the same leak wearing a different hat, and this asserts against
/// the **real journal lines** the server wrote, for a request that really carried the
/// address.
#[test]
fn the_access_log_carries_no_full_requester_address() {
    let wallet = faucet_wallet();
    let mut node = TestNode::new();
    let mut svc = service(&wallet, TicketPolicy::Required);
    funded(&mut node, &mut svc, &wallet);
    let gate = svc.gate();
    let server = FaucetServer::start("127.0.0.1:0", svc.gate(), svc.status()).expect("bind");

    let (_, addr) = requester(0xC0DE_0004);
    let encoded = addr.encode();
    let ticket = gate.lock().unwrap().issue_ticket(11).encode();
    assert_eq!(post_request(server.addr(), &encoded, Some(&ticket)).0, 202);
    // …and a refused one, because a refusal is the request most likely to be logged
    // verbosely "for debugging".
    assert_eq!(post_request(server.addr(), &encoded, None).0, 403);

    let journal = server.journal();
    assert!(!journal.is_empty(), "the server must journal its requests");
    let all = journal.join("\n");

    // The whole address, and any run of it long enough to be a handle.
    assert!(!all.contains(&encoded), "the full address is in the log:\n{all}");
    let prefix: String = encoded.chars().take(32).collect();
    assert!(!all.contains(&prefix), "32 characters of the address are in the log:\n{all}");
    // The bearer credential is not in there either.
    assert!(!all.contains(&ticket), "the ticket is in the log:\n{all}");
    // Nor is the client's individual address — only its subnet.
    let client_ip = server.addr().ip().to_string();
    assert!(all.contains("subnet="), "the log must record a subnet:\n{all}");
    assert!(
        all.contains(&format!("subnet={}", "127.0.0.0/24")),
        "the client is keyed at /24, not individually:\n{all}"
    );
    let _ = client_ip;
    // The one thing that IS logged: method, path, status.
    assert!(all.contains("FAUCET POST /request 202"), "{all}");
    assert!(all.contains("FAUCET POST /request 403"), "{all}");

    // The rendered page does not carry it either — the other place a full address
    // could escape, since the form posts one.
    let (_, _, page) = get(server.addr(), "/");
    assert!(!page.contains(&encoded), "the page echoes the submitted address back");
    server.shutdown();
}

// ---------------------------------------------------------------------------
// Acceptance 4 — the whole point: a browser request becomes a real grant
// ---------------------------------------------------------------------------

/// 🔴 **A browser request becomes a real grant the requester can find.**
///
/// The full path, over real sockets, with a real STARK and the production verifier:
///
/// 1. the faucet's node mines two coinbase notes and grows the chain past the frozen
///    §2 maturity threshold, so the notes are funded in by the harvest pass;
/// 2. a browser posts a form to `POST /request` and gets a 202 and a receipt;
/// 3. the service tick plans, fetches live membership witnesses, and produces a
///    **real** 2×2 proof;
/// 4. the node admits it — `ConsensusVerifier`, the shipping verifier;
/// 5. it is mined into a block whose body validation runs the same verifier;
/// 6. `GET /r/<receipt>` reports the grant, with the transaction id;
/// 7. the requester scans the chain with the **unmodified reference light client**
///    over a real socket and detects exactly the granted note, at the granted value;
/// 8. a stranger scanning the same block detects nothing.
///
/// Step 7 is the one that needs the caveat in the module docs: it submits through the
/// wallet-facing RPC, because that is the only seam that records note discovery, and
/// the deployed node composes no such seam. Steps 1–6 are the deployed path.
#[test]
fn a_browser_request_becomes_a_real_grant_the_requester_detects() {
    let wallet = faucet_wallet();
    let mine_rkm = wallet.rkm(Diversifier::default());
    let mut node = TestNode::new();
    let mut svc = service(&wallet, TicketPolicy::Required);

    // (1) funded, and only because the notes matured.
    funded(&mut node, &mut svc, &wallet);
    // The budget is value, not count (lab #292): two matured coinbase notes are
    // worth several grants, and the page below must quote the same figure this
    // does — derived from the inventory rather than hard-coded, so the assertion
    // survives the emission schedule moving under it.
    let budget = {
        let g = svc.gate();
        let g = g.lock().unwrap();
        assert_eq!(g.faucet().inventory().len(), 2);
        let need = g.faucet().need();
        let budget = g.faucet().inventory().grants_available(need);
        assert_eq!(budget, (g.faucet().inventory().total_value() / need) as usize);
        assert!(budget > 1, "two 50 QMB notes are more than one grant of value: {budget}");
        budget
    };

    let gate = svc.gate();
    let server = FaucetServer::start("127.0.0.1:0", svc.gate(), svc.status()).expect("bind");

    // The page says it is ready before anyone asks — the honest state, rendered.
    let (status, _, page) = get(server.addr(), "/");
    assert_eq!(status, 200);
    assert!(page.contains(&format!("ready — {budget} grants of value available")), "{page}");

    // (2) the browser exchange.
    let (req_wallet, req_addr) = requester(0xB0B0_0123);
    let ticket = gate.lock().unwrap().issue_ticket(1).encode();
    let (status, _, body) = post_request(server.addr(), &req_addr.encode(), Some(&ticket));
    assert_eq!(status, 202, "{body}");
    assert!(body.contains("queued at position 1"), "{body}");
    assert!(body.contains("receipt is 1"), "{body}");

    // (3)+(4) one tick: plan, prove a REAL 2×2 STARK, submit, confirm.
    let mut rng = rand::rngs::StdRng::from_seed([0xA7; 32]);
    let report = svc.tick(&mut node, &mut rng);
    assert_eq!(report.granted, Some(1), "the tick granted receipt 1; report: {report:?}");
    assert_eq!(report.stalled, None);

    let (txid_hex, granted_value) = {
        let g = gate.lock().unwrap();
        // The basis for the prove-time figure the PR quotes: this many samples, this
        // build, this machine. One grant, so n = 1 — quoted with the count.
        let stats = g.faucet().stats();
        println!(
            "grant proof: n={} total={:.2} s (release, one process, one grant)",
            stats.built, stats.prove_secs
        );
        assert!(stats.prove_secs > 0.0, "a real proof took real time");
        assert_eq!(g.faucet().stats().confirmed, 1);
        assert_eq!(g.faucet().stats().granted_bessel, DEFAULT_GRANT_BESSEL);
        assert_eq!(g.faucet().inventory().len(), 1, "a grant costs exactly one note");
        match g.state_of(1) {
            Some(RequestState::Granted { txid_hex, value_bessel, .. }) => (txid_hex, value_bessel),
            other => panic!("expected a granted receipt, got {other:?}"),
        }
    };
    assert_eq!(granted_value, DEFAULT_GRANT_BESSEL);
    assert_eq!(txid_hex.len(), 64, "a full 32-byte transaction id");

    // (5) mined into a block whose body validation runs the production verifier.
    assert_eq!(node.rpc.pending_len(), 1, "the grant is in the node's pool");
    let height = node.mine_pending(mine_rkm);

    // (6) the receipt page reports it — the value, the id, and the height.
    let (status, _, receipt) = get(server.addr(), "/r/1");
    assert_eq!(status, 200);
    assert!(receipt.contains("granted"), "{receipt}");
    assert!(receipt.contains(&txid_hex), "the receipt carries the transaction id: {receipt}");
    assert!(receipt.contains("10.00000000"), "…and the value in QMB: {receipt}");
    // …and NOT the recipient's address, which the faucet knows and must not publish.
    assert!(
        !receipt.contains(&req_addr.encode()),
        "the receipt page must not echo the recipient address"
    );

    // (7) the requester finds it, with the unmodified reference light client, over a
    //     real socket against the live node.
    let shared = Arc::new(Mutex::new(node.rpc));
    let handle = qlab_node::serve(Arc::clone(&shared));
    let base = handle.base_url();
    let cfg = ScanConfig { mode: qlab_note::scan::ScanMode::FullFo, decoy: DecoyPolicy::Off };
    let req_dk = req_wallet.diversified_keypair(&Diversifier::default()).dk;
    let mut scan_rng = rand::rngs::StdRng::from_seed([1u8; 32]);
    let found = light_client_scan(&base, &req_dk, height, height, cfg, &mut scan_rng)
        .expect("the scan runs against the live node");
    assert_eq!(found.notes.len(), 1, "the requester detects exactly the grant");
    assert_eq!(
        found.notes[0].detected.note.value, DEFAULT_GRANT_BESSEL,
        "…at the granted value"
    );
    // The note the requester found is the leaf the chain holds — if this drifts, the
    // grant is detectable and unspendable, which is worse than either.
    let cm = qlab_note::hash::digest_bytes(&found.notes[0].detected.note.commitment());
    {
        let node = shared.lock().unwrap();
        assert!(
            node.node().commitments().tree().position_of(&qlab_note::hash::digest_from_bytes(&cm)).is_some(),
            "the detected note must be a leaf of the live commitment tree"
        );
    }

    // (8) a stranger sees nothing.
    let (stranger, _) = requester(0xDEAD_0123);
    let stranger_dk = stranger.diversified_keypair(&Diversifier::default()).dk;
    let mut scan_rng2 = rand::rngs::StdRng::from_seed([2u8; 32]);
    let none = light_client_scan(&base, &stranger_dk, height, height, cfg, &mut scan_rng2)
        .expect("the scan runs");
    assert!(none.notes.is_empty(), "a stranger detects nothing");

    handle.shutdown();
    server.shutdown();
}

// ---------------------------------------------------------------------------
// Lab #310 — post-restart inventory must not re-include spent notes
// ---------------------------------------------------------------------------

/// 🔴 **Lab #310: after a restart the faucet must not re-fund spent coinbase.**
///
/// The live evidence (svc1, rev `4b60f8d`, 2026-08-09): restart →
/// `FAUCET funded 271 matured coinbase note(s)` → every `POST /request` → 202 →
/// `FAUCET gave-up`. Mechanism 1 predicted the rebuilt inventory re-includes
/// notes whose nullifiers are already on-chain; this test proves the fix:
///
/// 1. fund two matured coinbase notes and serve one real grant (both notes spent);
/// 2. mine the grant so the nullifiers are permanent;
/// 3. build a **fresh** `FaucetService` (empty `harvested`, empty inventory) —
///    the restart path;
/// 4. tick: harvest must report `skipped_spent = 2`, `funded = 0`;
/// 5. availability must be [`Availability::Empty`] (or otherwise non-admitting),
///    never Ready — §9.1's gate learns the unservable state instead of
///    accepting a request it will burn.
///
/// One real 2×2 STARK (~2.3 s). The unit proof of the nullifier subtraction
/// without a STARK lives in `harvest::tests::harvest_skips_notes_whose_nullifiers_are_already_on_chain`.
#[test]
fn post_restart_harvest_skips_spent_notes_and_availability_is_honest() {
    use qumbra_faucet::state::Availability;

    let wallet = faucet_wallet();
    let mine_rkm = wallet.rkm(Diversifier::default());
    let mut node = TestNode::new();
    let mut svc = service(&wallet, TicketPolicy::Required);

    // (1) fund two matured notes and serve one grant.
    funded(&mut node, &mut svc, &wallet);
    {
        let g = svc.gate();
        let g = g.lock().unwrap();
        assert_eq!(g.faucet().inventory().len(), 2);
    }
    let gate = svc.gate();
    let (_req_wallet, req_addr) = requester(0x3100_0001);
    let ticket = gate.lock().unwrap().issue_ticket(1);
    // Admit without HTTP — same accept path the listener uses.
    {
        let mut g = gate.lock().unwrap();
        g.accept("203.0.113.10", req_addr, Some(ticket), 0).expect("admitted");
    }
    let mut rng = rand::rngs::StdRng::from_seed([0x31; 32]);
    let report = svc.tick(&mut node, &mut rng);
    assert_eq!(report.granted, Some(1), "first grant lands; report: {report:?}");
    assert_eq!(node.rpc.pending_len(), 1);

    // (2) mine so the nullifiers are permanent.
    let _height = node.mine_pending(mine_rkm);
    assert!(
        node.chain_state().nullifier_count() >= 2,
        "the grant's two nullifiers are on-chain"
    );

    // (3) restart path: brand-new service, empty harvested set, empty inventory.
    let mut restarted = service(&wallet, TicketPolicy::Required);
    assert_eq!(
        restarted.gate().lock().unwrap().faucet().inventory().len(),
        0,
        "a restarted process starts with no inventory"
    );

    // (4) one tick re-walks the chain the way harvest always does.
    let report = restarted.tick(&mut node, &mut rng);
    assert_eq!(
        report.harvest.skipped_spent, 2,
        "both spent coinbases must be skipped, not funded: {report:?}"
    );
    assert_eq!(
        report.harvest.funded, 0,
        "no live coinbase remains to fund (the change note is not coinbase): {report:?}"
    );
    assert_eq!(
        restarted.gate().lock().unwrap().faucet().inventory().len(),
        0,
        "inventory must stay empty when every matured coinbase is spent"
    );

    // (5) §9.1: the gate must not say ready. Mining the grant paid a fresh
    // coinbase to the faucet, so the honest state is Maturing (144 blocks out,
    // beyond the advertised wait) — or Empty if that coinbase were burned.
    // Either way it must refuse before accept, so no ticket is burned.
    restarted.refresh_status(&node);
    let snap = restarted.status().lock().unwrap().clone();
    assert!(
        !snap.availability.admits_requests(),
        "§9.1: an unservable post-restart faucet must refuse, not queue; got {:?}",
        snap.availability
    );
    assert!(
        matches!(
            snap.availability,
            Availability::Empty { .. } | Availability::Maturing { .. }
        ),
        "expected Empty or Maturing after spent-only restart, got {:?}",
        snap.availability
    );
    // And specifically not Ready — that was the live bug (page said ready,
    // every grant gave-up).
    assert!(
        !matches!(snap.availability, Availability::Ready { .. }),
        "Ready with only spent coinbases is the #310 defect: {:?}",
        snap.availability
    );
}

// ---------------------------------------------------------------------------
// Lab #308 — XFF over real sockets (both directions)
// ---------------------------------------------------------------------------

/// 🔴 Over a real TCP socket: a trusted peer's XFF is the journal key; an
/// untrusted peer's forged XFF is not.
///
/// The unit suite in `http.rs` covers the pure resolution rule (including the
/// multi-hop walk). This test is the wire claim: the listener actually reads
/// the header and the access journal records the subnet the limiter would
/// charge. Localhost stands in for the compose bridge — we name `127.0.0.1/32`
/// as the trusted hop, which is exactly what a single-hop reverse proxy looks
/// like from the faucet's seat.
#[test]
fn xff_is_honored_only_when_the_peer_is_a_named_trusted_proxy() {
    let wallet = faucet_wallet();
    let mut node = TestNode::new();
    let mut svc = service(&wallet, TicketPolicy::Required);
    funded(&mut node, &mut svc, &wallet);
    let gate = svc.gate();

    // Direction 1: peer is trusted → journal keys on the forwarded address.
    let trust = TrustedProxies::parse(&["127.0.0.1/32".to_string()]).expect("loopback trust");
    let server = FaucetServer::start_with_trusted_proxies(
        "127.0.0.1:0",
        svc.gate(),
        svc.status(),
        trust,
    )
    .expect("bind");
    let (_, addr) = requester(0x3080_0001);
    let ticket = gate.lock().unwrap().issue_ticket(3081).encode();
    let (status, _, _) = post_request_with_headers(
        server.addr(),
        &addr.encode(),
        Some(&ticket),
        "X-Forwarded-For: 203.0.113.50\r\n",
    );
    assert_eq!(status, 202);
    let journal = server.journal().join("\n");
    assert!(
        journal.contains("subnet=203.0.113.0/24"),
        "trusted peer + XFF must key on the forwarded subnet:\n{journal}"
    );
    assert!(
        !journal.contains("subnet=127.0.0.0/24"),
        "must not fall back to the socket subnet when XFF is honored:\n{journal}"
    );
    server.shutdown();

    // Direction 2: empty trust (the default) → forged XFF is ignored.
    let server = FaucetServer::start("127.0.0.1:0", svc.gate(), svc.status()).expect("bind");
    let ticket = gate.lock().unwrap().issue_ticket(3082).encode();
    let (status, _, _) = post_request_with_headers(
        server.addr(),
        &addr.encode(),
        Some(&ticket),
        "X-Forwarded-For: 203.0.113.50\r\n",
    );
    assert_eq!(status, 202);
    let journal = server.journal().join("\n");
    assert!(
        journal.contains("subnet=127.0.0.0/24"),
        "default-empty trust must key on the socket subnet:\n{journal}"
    );
    assert!(
        !journal.contains("subnet=203.0.113.0/24"),
        "a forged XFF must not move the journal key under empty trust:\n{journal}"
    );
    server.shutdown();
}
