//! The `/v1/compact` note-discovery endpoint — **the surface a recipient finds
//! its money on** (issue #188 baton 2).
//!
//! ## Why this exists, and why it is the half of the baton that decides the rest
//!
//! Under `discovery-on-the-consensus-wire.md` a transaction's discovery group is
//! in the block body and covered by `tx_body_commitment`. Making `/v1/compact`
//! read it (baton 2, scope item 1) fixes a function that **nothing in the
//! deployed topology constructs**: `qumbra-node` composes no
//! `qlab_node::NodeRpc`, and `telemetry_server`'s own header says so. A correct
//! projection inside a type no binary builds is not a chain that pays anybody.
//!
//! So this is the second half: the deployed binary serves the committed bytes.
//!
//! ## What it is, and what it deliberately is not
//!
//! Exactly one route, `GET /v1/compact?from=&to=`, serving
//! [`qlab_node::compact_response`]'s bytes — the same encoder, over the same
//! projection, that `NodeRpc` serves in-process. Not the wallet-facing RPC:
//!
//! - **`/v1/block/{h}/tx/{i}/full` is not served here, and that is a finding
//!   rather than an omission.** Its bytes are the AEAD payloads, and D2 commits
//!   the compact bundle (`ct ‖ cm ‖ tag ‖ clue_len`) and nothing else — the
//!   ~585 B/note the design priced is `1088/2 + 41`, with no payload in it. The
//!   only place payloads exist is `NodeRpc`'s in-memory side table, and serving
//!   *that* from a deployed node would be option 2a with extra steps: a surface
//!   whose contents no consensus rule obliges anyone to have attached. Reported
//!   on issue #188; it is what baton 4 (spend) has to answer, because detection
//!   is committed and **opening is not**.
//! - **`/v1/tree/frontier` is not served here.** A wallet needs it to build a
//!   membership witness, which is spending. Baton 4.
//! - **`/v1/status`, `/v1/anchors` are not served here.** They are not this
//!   baton's scope and the node already has a versioned health wire
//!   (`/v1/telemetry`).
//!
//! ## Why a snapshot, and why that cannot make a served group wrong
//!
//! Same discipline as [`crate::metrics_server`] and [`crate::telemetry_server`]:
//! the run loop publishes a projection on its own cadence and the server thread
//! serves it, so **a poller can never contend with the consensus loop** on a
//! 2 vCPU host, and no external actor influences the node's timing.
//!
//! The snapshot is [`qlab_node::BlockDiscovery`] per main-chain height, whose
//! `groups[i]` is `StoredTx::discovery` **cloned** — there is no encoder between
//! the block and the served bytes, so a served group cannot differ in content
//! from the committed one. What a snapshot *can* be is **behind**: at most
//! [`crate::run::DISCOVERY_REFRESH`] of chain, and below the finalized head not
//! even that, because no-reorg-past-finality means a finalized height's body is
//! fixed forever. A wallet that reads a stale snapshot sees fewer of its outputs,
//! never a different one, and its next poll sees the rest.
//!
//! It holds discovery bytes, not bodies: ~1.2 KB per transaction against ~136 KB
//! of proof, so this is ~1 % of what the block store already holds rather than a
//! second copy of it.
//!
//! ## Deployment shape — **on by default**, which `/metrics` is not
//!
//! `discovery_addr` defaults to [`DEFAULT_DISCOVERY_ADDR`] when the config does
//! not mention it; `discovery_addr = "off"` is the only way to have no listener.
//! The reasoning, because it is a decision the task book asked to be justified:
//!
//! - **`metrics_addr` is off-by-default because setting it opens a port.** A
//!   loopback default opens nothing an off-host attacker can reach, so the
//!   argument that makes `/metrics` opt-in does not transfer.
//! - **`testnet-plan` §6.2 — a committee-key host "exposes nothing beyond
//!   P2P" — is honoured literally** by a loopback bind. And the bytes are public
//!   chain data either way: every one of them is inside a block body any peer can
//!   already request over `GetData(Block)`. No key material, no mempool, no peer
//!   list, no write.
//! - **An opt-in most operators leave off is option 2a with extra steps.** The
//!   failure mode of an opt-in default is a chain that commits discovery
//!   correctly and hands it to nobody — indistinguishable, from a wallet's side,
//!   from having no discovery at all. That is the absence-reads-as-healthy shape
//!   `t1-discovery-serving-decision.md` §10 refused.
//! - **Cost to expose publicly:** `discovery_addr = "0.0.0.0:9420"` *and* a
//!   source-restricted inbound rule as a standalone `aws_security_group_rule`
//!   (the 2026-07-26 inline-rule incident). Nothing here authenticates.
//!
//! The new failure mode this default buys, stated rather than discovered: **a
//! default-on listener can fail to bind**, and an unbindable address is an error
//! here as everywhere else in this binary. So a port conflict now stops a node
//! that would previously have started, and the error names `"off"`.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use qlab_node::{compact_response, BlockDiscovery};

/// The route this endpoint serves, and the only one.
pub const COMPACT_PATH: &str = "/v1/compact";

/// Where discovery serving binds when the config does not say.
///
/// Loopback on purpose: **serving is the default, exposure is the operator's
/// act.** Port 9420 sits clear of `metrics_addr`'s conventional 9090 and
/// `telemetry_addr`'s 9410.
pub const DEFAULT_DISCOVERY_ADDR: &str = "127.0.0.1:9420";

/// The config value that means "bind nothing".
pub const DISCOVERY_OFF: &str = "off";

/// Content type for the versioned binary wire — `qlab_cbserver::WIRE_VERSION`-led
/// little-endian fields, so it is bytes and labelling it text would invite a
/// reader to treat it as a string.
const CONTENT_TYPE_HEADER: &[u8] = b"Content-Type";
const CONTENT_TYPE_VALUE: &[u8] = b"application/octet-stream";

/// The main chain's committed discovery as of the run loop's last refresh.
///
/// Held behind one `Arc` so a request costs an `Arc` clone under the lock and the
/// bytes are then read with the lock released — a slow reader can never hold the
/// snapshot lock while the run loop wants to replace it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DiscoveryView {
    /// Ascending by height, genesis first, main chain only.
    pub blocks: Vec<BlockDiscovery>,
}

impl DiscoveryView {
    /// Committed discovery bytes held (what the projection actually costs).
    pub fn len_bytes(&self) -> usize {
        self.blocks.iter().map(|b| b.len_bytes()).sum()
    }

    /// Highest indexed height, if any block is indexed at all.
    pub fn tip_height(&self) -> Option<u64> {
        self.blocks.last().map(|b| b.height)
    }

    /// Re-project from a node's main chain, reusing what is already indexed.
    ///
    /// The walk goes tip → genesis and stops at the first height whose recorded
    /// hash matches the chain's, so a steady node pays for the new blocks only. A
    /// reorg is not a special case: the mismatch simply reaches further back and
    /// the replaced suffix is dropped. Nothing here decides what the main chain is
    /// — `chain.tip_hash()` and `header.prev` do, which is the same fork choice
    /// the state machine already committed to.
    pub fn refresh<C: qlab_node::ChainStore>(&mut self, chain: &C) -> bool {
        let tip = chain.tip_hash();
        if self.blocks.last().map(|b| b.hash) == Some(tip) {
            return false;
        }
        let mut fresh: Vec<BlockDiscovery> = Vec::new();
        let mut hash = tip;
        loop {
            let Some(block) = chain.block(&hash) else { break };
            let height = block.header.height;
            if self.blocks.get(height as usize).map(|b| b.hash) == Some(hash) {
                break;
            }
            let prev = block.header.prev;
            fresh.push(BlockDiscovery::of(hash, block));
            if height == 0 {
                break;
            }
            hash = prev;
        }
        let Some(lowest) = fresh.last().map(|b| b.height) else { return false };
        self.blocks.truncate(lowest as usize);
        fresh.reverse();
        self.blocks.extend(fresh);
        true
    }
}

/// A running `/v1/compact` endpoint: bound address + worker thread + the shared
/// projection the run loop refreshes.
pub struct DiscoveryServer {
    addr: SocketAddr,
    server: Arc<tiny_http::Server>,
    thread: Option<JoinHandle<()>>,
    served: Arc<AtomicU64>,
}

impl DiscoveryServer {
    /// Bind `addr` and serve `view` at [`COMPACT_PATH`] until [`Self::shutdown`].
    ///
    /// An unbindable address is an **error**, never a silent no-op: a node whose
    /// operator believes recipients can find their outputs and which serves
    /// nothing is precisely the state this endpoint exists to remove.
    pub fn start(addr: &str, view: Arc<Mutex<Arc<DiscoveryView>>>) -> io::Result<Self> {
        let server = tiny_http::Server::http(addr).map_err(|e| {
            io::Error::other(format!(
                "discovery_addr {addr}: {e} (set discovery_addr = \"{DISCOVERY_OFF}\" to serve nothing)"
            ))
        })?;
        let server = Arc::new(server);
        let bound = server
            .server_addr()
            .to_ip()
            .ok_or_else(|| io::Error::other("discovery listener has no ip address"))?;
        let served = Arc::new(AtomicU64::new(0));

        let worker = Arc::clone(&server);
        let worker_served = Arc::clone(&served);
        let thread = std::thread::spawn(move || {
            for request in worker.incoming_requests() {
                worker_served.fetch_add(1, Ordering::Relaxed);
                // Read-only means read-only: anything that is not a GET is refused
                // before the path is looked at.
                if *request.method() != tiny_http::Method::Get {
                    let _ = request.respond(
                        tiny_http::Response::from_string("method not allowed").with_status_code(405),
                    );
                    continue;
                }
                let url = request.url().to_string();
                let (path, query) = url.split_once('?').unwrap_or((url.as_str(), ""));
                if path != COMPACT_PATH {
                    let _ = request.respond(
                        tiny_http::Response::from_string(format!(
                            "not found: try {COMPACT_PATH}?from=&to="
                        ))
                        .with_status_code(404),
                    );
                    continue;
                }
                // Clone the Arc under the lock, encode with it released.
                let snapshot = match view.lock() {
                    Ok(g) => Arc::clone(&g),
                    Err(p) => Arc::clone(&p.into_inner()),
                };
                let response = respond(&snapshot, query);
                let _ = match response {
                    Ok(bytes) => {
                        let header =
                            tiny_http::Header::from_bytes(CONTENT_TYPE_HEADER, CONTENT_TYPE_VALUE)
                                .expect("static content type parses");
                        request.respond(tiny_http::Response::from_data(bytes).with_header(header))
                    }
                    Err((code, msg)) => request
                        .respond(tiny_http::Response::from_string(msg).with_status_code(code)),
                };
            }
        });

        Ok(DiscoveryServer { addr: bound, server, thread: Some(thread), served })
    }

    /// The bound address (useful when the config asked for port 0).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Requests handled since start (including 404s and 405s).
    pub fn requests_served(&self) -> u64 {
        self.served.load(Ordering::Relaxed)
    }

    /// Stop serving and join the worker.
    pub fn shutdown(mut self) {
        self.server.unblock();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// The socket-free request core: a `from`/`to` query against a projection.
///
/// Mirrors `qlab_node::NodeRpc::route`'s refusals exactly — a missing or
/// unparseable bound is a 400, an inverted range is a 400, and a stored block
/// whose committed discovery does not decode is a **500 rather than an empty
/// group**, because `n = 0` is the meaningful answer "this transaction attaches
/// no discovery" and must never stand in for a broken invariant.
pub fn respond(view: &DiscoveryView, query: &str) -> Result<Vec<u8>, (u16, String)> {
    let from = query_u64(query, "from").ok_or((400, "missing/invalid 'from'".to_string()))?;
    let to = query_u64(query, "to").ok_or((400, "missing/invalid 'to'".to_string()))?;
    if to < from {
        return Err((400, "'to' < 'from'".to_string()));
    }
    compact_response(&view.blocks, from, to)
        .map_err(|e| (500, format!("stored discovery does not decode: {e:?}")))
}

fn query_u64(query: &str, key: &str) -> Option<u64> {
    for kv in query.split('&') {
        if let Some((k, v)) = kv.split_once('=') {
            if k == key {
                return v.parse::<u64>().ok();
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_cbserver::codec::decode_compact_response;
    use qlab_node::{Hash32, StoredBlock, StoredHeader, StoredTx};
    use std::io::{Read, Write};
    use std::net::TcpStream;

    fn get(addr: SocketAddr, path: &str) -> (String, Vec<u8>) {
        let mut s = TcpStream::connect(addr).expect("connect");
        write!(s, "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).expect("read");
        let sep = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("header terminator");
        let head = String::from_utf8_lossy(&raw[..sep]).to_string();
        let status = head.lines().next().unwrap_or_default().to_string();
        (status, raw[sep + 4..].to_vec())
    }

    /// A projected block carrying `groups` verbatim, without building a chain —
    /// the serving core does not care how the bytes got there, only that they are
    /// the block's.
    fn projected(height: u64, hash: u8, groups: Vec<Vec<u8>>) -> BlockDiscovery {
        BlockDiscovery { height, hash: [hash; 32], groups }
    }

    fn a_view() -> DiscoveryView {
        DiscoveryView {
            blocks: vec![
                projected(0, 0, vec![]),
                projected(1, 1, vec![qlab_devnet::body::TxEntry::empty_discovery()]),
                projected(2, 2, vec![]),
            ],
        }
    }

    #[test]
    fn serves_the_compact_wire_over_a_real_socket() {
        let view = Arc::new(Mutex::new(Arc::new(a_view())));
        let srv = DiscoveryServer::start("127.0.0.1:0", Arc::clone(&view)).expect("bind");
        let addr = srv.addr();

        let (status, body) = get(addr, "/v1/compact?from=0&to=2");
        assert!(status.starts_with("HTTP/1.1 200"), "{status}");
        let blocks = decode_compact_response(&body).expect("the served bytes are the ratified wire");
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[1].groups.len(), 1, "height 1's single transaction");
        assert_eq!(blocks[1].groups[0].recipients.len(), 0, "an n = 0 group, served as such");

        // A refreshed projection is what the next read sees.
        let mut later = a_view();
        later.blocks.push(projected(3, 3, vec![]));
        *view.lock().unwrap() = Arc::new(later);
        let (_, body2) = get(addr, "/v1/compact?from=0&to=99");
        assert_eq!(decode_compact_response(&body2).unwrap().len(), 4);

        srv.shutdown();
    }

    /// Nothing else is served, and the refusals are the RPC's refusals — not a
    /// half-implemented wallet API. `/v1/…/full` in particular is a 404 **because
    /// its bytes are not committed**, and a deployed node must not imply it holds
    /// them (see the module docs).
    #[test]
    fn only_v1_compact_is_served_and_writes_are_refused() {
        let view = Arc::new(Mutex::new(Arc::new(a_view())));
        let srv = DiscoveryServer::start("127.0.0.1:0", Arc::clone(&view)).expect("bind");
        let addr = srv.addr();

        for path in [
            "/",
            "/metrics",
            "/v1/telemetry",
            "/v1/status",
            "/v1/anchors",
            "/v1/tree/frontier?at=1",
            "/v1/block/1/tx/0/full",
        ] {
            let (status, _) = get(addr, path);
            assert!(status.starts_with("HTTP/1.1 404"), "{path} => {status}");
        }

        // Bad bounds are 400s, not empty successes.
        for path in ["/v1/compact", "/v1/compact?from=0", "/v1/compact?from=2&to=1"] {
            let (status, _) = get(addr, path);
            assert!(status.starts_with("HTTP/1.1 400"), "{path} => {status}");
        }

        let mut s = TcpStream::connect(addr).expect("connect");
        write!(
            s,
            "POST /v1/compact HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut raw = String::new();
        s.read_to_string(&mut raw).expect("read");
        assert!(raw.starts_with("HTTP/1.1 405"), "{raw}");

        srv.shutdown();
    }

    #[test]
    fn an_unbindable_address_is_an_error_and_the_message_names_the_opt_out() {
        let view = Arc::new(Mutex::new(Arc::new(DiscoveryView::default())));
        let err = match DiscoveryServer::start("256.256.256.256:9", view) {
            Err(e) => e,
            Ok(_) => panic!("that address cannot be bound"),
        };
        assert!(
            err.to_string().contains(DISCOVERY_OFF),
            "a default-on listener that cannot bind must tell the operator how to turn it off: {err}"
        );
    }

    /// 🔴 A corrupt committed group is a 500 and never an empty group. An empty
    /// group is the meaningful `n = 0` answer — "this transaction attaches no
    /// discovery" — and a serving surface that says that about a block it could
    /// not read is the absence-reads-as-healthy shape option 3 exists to remove.
    #[test]
    fn undecodable_committed_bytes_are_a_refusal_not_an_empty_group() {
        let view = DiscoveryView { blocks: vec![projected(0, 0, vec![vec![0x02, 0x00]])] };
        let err = respond(&view, "from=0&to=0").expect_err("must refuse");
        assert_eq!(err.0, 500, "{err:?}");
    }

    // ---- the incremental projection -----------------------------------------

    fn stored(height: u64, prev: Hash32, discovery: Vec<Vec<u8>>) -> StoredBlock {
        StoredBlock {
            header: StoredHeader {
                height,
                prev,
                tx_body_commitment: [0; 32],
                timestamp: height * 75,
                difficulty: 1,
                nonce: height,
            },
            txs: discovery
                .into_iter()
                .map(|d| StoredTx {
                    anchor: [0; 32],
                    nullifiers: vec![],
                    commitments: vec![],
                    bucket_actions: 2,
                    fee: 0,
                    proof: vec![],
                    discovery: d,
                })
                .collect(),
            coinbase: height,
            coinbase_rkm: [1, 2, 3, 4],
        }
    }

    /// The refresh reuses what it has and replaces what the chain replaced. Driven
    /// against a real `MemChainStore` so fork choice, not the test, decides what
    /// the main chain is.
    #[test]
    fn the_projection_extends_a_steady_chain_and_replaces_a_reorged_suffix() {
        use qlab_node::{ChainStore, MemChainStore};

        let genesis = stored(0, [0; 32], vec![]);
        let ghash = genesis.header().header_hash();
        let mut store = MemChainStore::new(genesis);
        let mut view = DiscoveryView::default();
        assert!(view.refresh(&store), "genesis is indexed on the first pass");
        assert_eq!(view.tip_height(), Some(0));
        assert!(!view.refresh(&store), "an unchanged tip is not re-projected");

        // Two blocks with real committed groups.
        let mut prev = ghash;
        for h in 1..=2u64 {
            let b = stored(h, prev, vec![vec![0x00]]);
            prev = b.header().header_hash();
            store.put_block(b).expect("applies");
        }
        assert!(view.refresh(&store));
        assert_eq!(view.tip_height(), Some(2));
        assert_eq!(view.blocks.len(), 3);
        assert_eq!(view.blocks[2].groups, vec![vec![0x00]]);

        // A heavier sibling branch from height 1 takes the tip; the projection's
        // suffix is replaced rather than appended to.
        let old_h2 = view.blocks[2].hash;
        let mut sib_prev = ghash;
        let mut sib_last = ghash;
        for h in 1..=4u64 {
            // A different nonce ⇒ a different header hash ⇒ a genuine sibling.
            let mut b = stored(h, sib_prev, vec![]);
            b.header.nonce = 1_000 + h;
            sib_prev = b.header().header_hash();
            sib_last = sib_prev;
            store.put_block(b).expect("applies");
        }
        assert_eq!(store.tip_hash(), sib_last, "the longer branch is the tip");
        assert!(view.refresh(&store));
        assert_eq!(view.tip_height(), Some(4));
        assert_ne!(view.blocks[2].hash, old_h2, "the reorged height is re-projected");
        assert!(
            view.blocks[2].groups.is_empty(),
            "and carries the winning branch's discovery, not the abandoned one's"
        );
        assert_eq!(view.blocks[0].hash, ghash, "the common prefix is untouched");
    }
}
