//! [`P2pNode`] — the integrator. It owns a [`Transport`], an N1 [`NodeState`]
//! (stubbed), a [`PeerTable`], the gossip dedup cache, and the sync state
//! machine, and drives them all from a single non-blocking [`P2pNode::tick`]:
//! drain the transport, dispatch each frame, emit responses. The same logic runs
//! over the in-process and TCP transports, so tests are deterministic in-process
//! and identical over the socket.

use std::collections::{BTreeSet, HashMap, HashSet};

use qlab_devnet::committee::{Checkpoint, Vote};
use qlab_devnet::body::{BlockBody, TxEntry};
use qlab_devnet::ebbflow::EquivocationEvidence;
use qlab_devnet::header::{BlockHeader, Hash32};

use crate::codec::{
    checkpoint_id, decode_checkpoint_msg, decode_checkpoint_votes, decode_evidence_msg,
    decode_headers, decode_inv, decode_locator, decode_tx, encode_checkpoint_msg,
    encode_checkpoint_votes, encode_evidence_msg, encode_headers, encode_inv, encode_locator,
    encode_tx, evidence_id, tx_id, InvItem, InvKind,
};
use crate::compact::{
    decode_announce, decode_block_txn, decode_get_block_txn, encode_announce, encode_block_txn,
    encode_get_block_txn, reconstruct, short_id, BlockAnnounce, BlockTxn, GetBlockTxn, PrefilledTx,
    Reconstruct,
};
use crate::addrman::AddrManager;
use crate::gossip::{
    SeenCache, PENALTY_INVALID_OBJECT, PENALTY_MALFORMED, PENALTY_WELSHED_INV,
};
use crate::n1::{IngestOutcome, NodeState, VotesOutcome};
use crate::peer::{NodeId, PeerId, PeerTable, VersionMsg};
use crate::ratelimit::{RateKey, RateLimiter, RateLimits, RateStats};
use crate::sync::{build_locator, answer_get_headers, SyncPhase, SyncState, MAX_HEADERS_PER_BATCH};
use crate::transport::{DialCompletion, DialStart, Transport, TransportError};
use crate::wire::{Envelope, MsgType};

/// Service-bits placeholder advertised in the handshake (`[devnet-placeholder]`).
pub const SERVICE_FULL: u64 = 0x01;

/// The `DIAL` journal line for one completed outbound connect — `key=value` like
/// `TELEMETRY`/`ROUND` so the same grep/awk habits work (readers key on the line
/// prefix, e.g. `deploy/docker/soak.sh`'s `grep '^TELEMETRY'`).
///
/// The duration is logged on failures too, quoting the error last: a dial the
/// kernel gave up on after its SYN retry ladder (127 s on the deployed hosts —
/// issue #107's number) and one refused in 3 ms are different operational
/// events, and `result=err` alone cannot tell them apart.
fn dial_line(addr: &str, elapsed_ms: u64, result: &Result<PeerId, TransportError>) -> String {
    match result {
        Ok(_) => format!("DIAL addr={addr} ms={elapsed_ms} result=ok"),
        Err(e) => format!("DIAL addr={addr} ms={elapsed_ms} result=err err=\"{e}\""),
    }
}

/// Entry cap on the body-serving cache (issue #135).
///
/// The cache exists to answer `GetBlockTxn` for announces still in flight — a
/// reconstruction round-trip is seconds, and a re-announce re-drives a failed
/// one — so its horizon is the live relay window, not history. 128 blocks is
/// ~160 minutes at the 75 s target: three orders of magnitude past any round-trip,
/// and a ~5 KB floor on a coinbase-only chain (40 B/entry). Deliberately NOT
/// #130 (a)'s 512: that window must absorb a header-sync run-ahead; this one has
/// no such job, and everything applied is servable from the store regardless.
///
/// `[devnet-placeholder]`, testnet-tunable, NOT frozen.
pub const MAX_SERVED_BODIES: usize = 128;

/// Byte budget for the body-serving cache (issue #135), on the same meter as
/// #130 (a)'s window ([`crate::n1::txs_weight`]).
///
/// Two caps because either alone is wrong — (a)'s reasoning, which transfers even
/// though the numbers do not: a coinbase-only body is tens of bytes, so a byte
/// budget alone would admit ~200k entries; a proof-carrying body is ~145,754 B
/// per tx at FROZEN v1.0 sizes, so the entry cap alone would admit ~19 MB at
/// 1 tx/block and ~187 MB at 10 tx/block — on `t4g.small` hosts whose whole
/// process measured ~262 MiB in the Phase B-lite soak. 8 MiB is ~57 single-tx
/// bodies (~71 min of chain) or ~5 ten-tx bodies (~6 min), all far beyond the
/// relay round-trip the cache serves, and 0.4 % of a 2 GB host.
///
/// `[devnet-placeholder]`, testnet-tunable, NOT frozen.
pub const MAX_SERVED_BODY_BYTES: usize = 8 * 1024 * 1024;

/// **How many block bodies this node will have outstanding at once** (issue
/// #130 (c)) — the in-flight window of the historical-body requester.
///
/// The bound that matters is not bandwidth, it is the pending-body window this
/// feeds: every answered request lands in the adapter's queue, capped at
/// [`crate::adapter::MAX_PENDING_BODIES`] = 512 entries / 32 MiB. 16 is 3 % of
/// that entry cap, so a full in-flight window cannot on its own evict material
/// the state machine still needs — and at the FROZEN v1.0 proof size (~145,754 B
/// per tx, #135's measurement) 16 single-tx bodies are ~2.3 MB, well inside the
/// 8 MiB/s per-peer byte budget the inbound limiter already permits.
///
/// **The catch-up arithmetic, since that is the acceptance criterion.** One
/// request round completes in one round trip (the answer is handled on the next
/// `tick`), so throughput is 16 bodies per round trip against a block rate of one
/// per 75 s. At the Phase B-WAN measured RTT baseline of 68–223 ms that is three
/// orders of magnitude above the block rate; even at issue #107's *worst* observed
/// main-loop period of 131 s it is 16 bodies against ~1.7 new blocks, so `slag`
/// falls. It is the ratio, not the constant, that the criterion needs.
///
/// `[devnet-placeholder]`, testnet-tunable, NOT frozen.
pub const MAX_BODIES_IN_FLIGHT: usize = 16;

/// **How long an unanswered body request is held before it may be re-asked**
/// (issue #130 (c)).
///
/// It is a re-ask interval, not a failure verdict: nothing is scored when it
/// expires (see [`P2pNode::request_missing_bodies`]). 15 s is ~70× the worst
/// measured WAN RTT (223 ms, Phase B-WAN's pre-run baseline), so an expiry means
/// the peer genuinely did not answer rather than that the network was slow; and it
/// caps the cost of a batch lost to the inbound throttle at 15 s of standing still.
///
/// `[devnet-placeholder]`, testnet-tunable, NOT frozen.
pub const BODY_REQUEST_TIMEOUT_MS: u64 = 15_000;

/// **How many whole bodies this node will serve from one `GetData`** (issue
/// #130 (c)).
///
/// `GetData(Block)` used to cost us a header; it can now cost us a body, which is
/// the #91 amplifier shape in miniature (a ~45 B request against a body that is
/// ~145 kB per transaction at FROZEN v1.0 sizes). The response to over-asking is
/// deliberately **not** silence and **not** `NotFound`: items past this cap are
/// answered header-only, exactly as they were before this change. That degrades to
/// the pre-#130 (c) behaviour rather than to a refusal — and `NotFound` would be
/// actively wrong, because the receiving side scores it ([`PENALTY_WELSHED_INV`]).
///
/// Matched to [`MAX_BODIES_IN_FLIGHT`] so an honest requester at its own cap is
/// never truncated by ours.
///
/// `[devnet-placeholder]`, testnet-tunable, NOT frozen.
pub const MAX_BODIES_PER_GETDATA: usize = 16;

/// One cached body: the ordered txs, the coinbase counter and the payout key —
/// all three are needed to rebuild the *exact* body (issue #101) — plus the
/// height it entered under and its metered weight, so eviction needs no rescan.
struct ServedBody {
    height: u64,
    txs: Vec<TxEntry>,
    // Read since issue #130 (c): serving a whole block needs the coinbase counter
    // and payout key as well as the txs, because they are body fields and not tx
    // slots. #135 kept them against exactly this — "a cache entry that cannot
    // rebuild the *exact* body would be a trap for the next serving path" — and
    // the `#[allow(dead_code)]` they carried until now is gone because they are no
    // longer dead.
    coinbase: u64,
    coinbase_rkm: [u64; 4],
    weight: usize,
}

/// The bounded body-serving cache (issue #135) — full block bodies this node can
/// hand to a `GetBlockTxn`, keyed by header hash, with a height index for
/// eviction order.
///
/// **The eviction rule: lowest height first.** `GetBlockTxn` asks follow this
/// node's own `BlockAnnounce` pushes, so the ask distribution concentrates at the
/// tip; the deeper below the tip a body sits, the less likely anyone still wants
/// it over compact relay — and once applied it is servable from the node's block
/// store ([`crate::n1::ChainView::stored_body`]) forever, so evicting it loses
/// nothing. What eviction CAN lose is a never-applied body (a side branch, or a
/// body evicted before its application caught up) older than everything else
/// held — which is precisely the least useful thing this cache holds, and a peer
/// that needs genuinely historical bodies needs #130 (c), not this cache.
///
/// No third height-window cap (½ of (a)'s two-and-a-half): applicability has a
/// hard cliff, so (a)'s window states a real invariant; serviceability only
/// decays, and lowest-first eviction already orders by exactly that decay.
struct ServedBodies {
    by_hash: HashMap<Hash32, ServedBody>,
    /// Eviction order: ascending `(height, hash)` — `first()` is the next victim.
    by_height: BTreeSet<(u64, Hash32)>,
    /// Running metered weight, maintained on insert/evict so the budget is a
    /// subtraction rather than a walk (same discipline as (a)'s `pending_bytes`).
    bytes: usize,
}

impl ServedBodies {
    fn new() -> Self {
        ServedBodies { by_hash: HashMap::new(), by_height: BTreeSet::new(), bytes: 0 }
    }

    fn contains(&self, hash: &Hash32) -> bool {
        self.by_hash.contains_key(hash)
    }

    fn get(&self, hash: &Hash32) -> Option<&ServedBody> {
        self.by_hash.get(hash)
    }

    fn len(&self) -> usize {
        self.by_hash.len()
    }

    /// Cache a body, then evict lowest-height-first until back inside both caps.
    /// The byte budget keeps ≥1 entry ((a)'s guard, same reason): a single body
    /// over the whole budget is one this node just announced — evicting it would
    /// break our own relay, and one body is not a resource-exhaustion surface.
    ///
    /// The freshly-inserted entry gets no special treatment: if it is the lowest
    /// height held while the cache is full, it IS the least useful entry by the
    /// rule, and it goes (its announce was still relayed; a peer that misses the
    /// re-request window recovers via re-announce or, once applied, the store).
    fn insert(&mut self, height: u64, hash: Hash32, txs: Vec<TxEntry>, coinbase: u64, coinbase_rkm: [u64; 4]) {
        let weight = crate::n1::txs_weight(&txs) + 40;
        let entry = ServedBody { height, txs, coinbase, coinbase_rkm, weight };
        if let Some(old) = self.by_hash.insert(hash, entry) {
            // Same hash re-completed (e.g. re-announce after restart): replace,
            // do not double-count.
            self.by_height.remove(&(old.height, hash));
            self.bytes = self.bytes.saturating_sub(old.weight);
        }
        self.by_height.insert((height, hash));
        self.bytes += weight;
        while self.by_hash.len() > MAX_SERVED_BODIES
            || (self.bytes > MAX_SERVED_BODY_BYTES && self.by_hash.len() > 1)
        {
            let Some(&(h, bh)) = self.by_height.iter().next() else { break };
            self.by_height.remove(&(h, bh));
            if let Some(dropped) = self.by_hash.remove(&bh) {
                self.bytes = self.bytes.saturating_sub(dropped.weight);
            }
        }
    }
}

/// A running P2P node: transport + node-state + peers + gossip + sync.
pub struct P2pNode<T: Transport, N: NodeState> {
    transport: T,
    node: N,
    peers: PeerTable,
    node_id: NodeId,
    user_agent: String,
    seen: SeenCache,
    sync: SyncState,
    version_sent: HashSet<PeerId>,
    /// Full block bodies this node can serve (originated or fully reconstructed),
    /// keyed by header hash — backs `GetBlockTxn` answering. **Bounded** (issue
    /// #135): a cache over the hot relay window, no longer the authoritative
    /// serving store — an applied body outlives its eviction via
    /// [`crate::n1::ChainView::stored_body`], the fallback `on_get_block_txn`
    /// takes on a cache miss.
    blocks: ServedBodies,
    /// Announcements awaiting missing transactions (block hash → announce).
    pending_blocks: HashMap<Hash32, BlockAnnounce>,
    /// Finalized checkpoints + their votes, keyed by checkpoint id — so a
    /// `GetData(Checkpoint)` can be re-served (checkpoints, unlike headers/txs,
    /// are not reconstructable from other state).
    checkpoints: HashMap<Hash32, (Checkpoint, Vec<Vote>)>,
    /// Peer discovery: the address book + dial policy (issue #83). Seeds are fed
    /// in by the operator; learned addresses arrive over `Addr`.
    addrs: AddrManager,
    /// Per-peer inbound budgets (issue #91). Keyed on the remote **host**, not the
    /// connection, so dropping and redialling does not hand out a fresh budget.
    limiter: RateLimiter,
    /// **Historical body requests we have outstanding** (issue #130 (c)): block
    /// hash → the `now_ms` the ask was sent at. Bounded by
    /// [`MAX_BODIES_IN_FLIGHT`]; an entry older than [`BODY_REQUEST_TIMEOUT_MS`] is
    /// dropped so the hash may be asked again, of a different peer.
    ///
    /// It is also the list [`Self::on_not_found`] reads: an ask WE originated that a
    /// peer cannot serve is not a welshed inv, and without this set there is no way
    /// to tell those two apart.
    body_reqs: HashMap<Hash32, u64>,
    /// Rotation cursor for spreading body requests across ready peers, so one silent
    /// peer costs a fraction of a batch rather than the whole of it, and so a re-ask
    /// after a timeout lands somewhere new.
    body_rr: usize,
}

impl<T: Transport, N: NodeState> P2pNode<T, N> {
    /// Build a node over `transport` and `node`, advertising `node_id`.
    pub fn new(transport: T, node: N, node_id: NodeId) -> Self {
        P2pNode {
            transport,
            node,
            peers: PeerTable::new(),
            node_id,
            user_agent: format!("qlab-p2p/{}", env!("CARGO_PKG_VERSION")),
            seen: SeenCache::default(),
            sync: SyncState::new(),
            version_sent: HashSet::new(),
            blocks: ServedBodies::new(),
            pending_blocks: HashMap::new(),
            checkpoints: HashMap::new(),
            addrs: AddrManager::new(),
            limiter: RateLimiter::default(),
            body_reqs: HashMap::new(),
            body_rr: 0,
        }
    }

    // --- read-only accessors (tests / callers) ---
    pub fn node(&self) -> &N {
        &self.node
    }
    pub fn node_mut(&mut self) -> &mut N {
        &mut self.node
    }
    pub fn peers(&self) -> &PeerTable {
        &self.peers
    }
    pub fn transport(&self) -> &T {
        &self.transport
    }
    pub fn sync_phase(&self) -> &SyncPhase {
        &self.sync.phase
    }
    /// The address book / dial policy (issue #83).
    pub fn addrs(&self) -> &AddrManager {
        &self.addrs
    }
    /// Serving-cache occupancy `(entries, metered bytes)` (issue #135) —
    /// operator-visible so occupancy is a measurement, not an inference (the
    /// same statement the adapter makes for its pending-body window).
    pub fn served_bodies(&self) -> (usize, usize) {
        (self.blocks.len(), self.blocks.bytes)
    }
    /// Historical body requests outstanding right now (issue #130 (c)).
    ///
    /// Operator-visible for the same reason `slag` is: **a node asking and getting
    /// nothing looks exactly like a node that is not asking**, and that is the
    /// precise state the live net was in on 2026-08-01 — node3 sat at `stip=1` for
    /// thirteen minutes with no line in its log for anything. `slag` falling is the
    /// cure; this is the attempt, and only the two together separate "no peer will
    /// serve me" from "I never asked".
    pub fn body_requests(&self) -> usize {
        self.body_reqs.len()
    }
    pub fn addrs_mut(&mut self) -> &mut AddrManager {
        &mut self.addrs
    }

    // --- peer hardening (issue #91) ---

    /// Throttle counters — what was dropped, and how many rate keys are live.
    /// Read by operators; **never** fed back into scoring (see [`crate::ratelimit`]).
    pub fn rate_stats(&self) -> RateStats {
        self.limiter.stats()
    }

    /// Re-tune the inbound budgets (tests / testnet). Deliberately programmatic
    /// rather than a config-file key: these numbers should move because a
    /// measurement said so.
    pub fn set_rate_limits(&mut self, limits: RateLimits) {
        self.limiter.set_limits(limits);
    }

    /// The rate key a peer's traffic is charged against — the remote host when the
    /// transport knows one, else the handle.
    fn rate_key(&self, pid: PeerId) -> RateKey {
        RateKey::new(self.transport.peer_addr(pid).as_deref(), pid)
    }

    // --- peer discovery (issue #83) ---

    /// One discovery maintenance pass, driven by the caller's monotonic clock in
    /// milliseconds (the binary's run loop; tests pass explicit values). It:
    ///
    /// 1. reconciles the book against the transport's live handles,
    /// 2. **auto-connects** to the addresses the policy picks — seeds first, each
    ///    inside its backoff, never above [`crate::addrman::MAX_OUTBOUND`],
    /// 3. asks ready peers for addresses, rate-limited per peer.
    ///
    /// This is the *only* dial path in the stack: configured seeds and learned
    /// addresses share one cap and one backoff ladder (see [`crate::addrman`]).
    /// Returns how many dials succeeded.
    pub fn maintain(&mut self, now_ms: u64) -> usize {
        let mut connected = self.finish_dials(now_ms);
        let live: HashSet<PeerId> = self.transport.peers().into_iter().collect();
        self.addrs.sync_live(&live);
        for pid in self.peers.all_peers() {
            if !live.contains(&pid) {
                self.addrs.on_disconnect(pid);
                // Issue #172: `PeerTable` is the live connection table and is
                // the source of `peer_count`. The transport drops its handle
                // when the reader observes EOF, so keeping this row would count
                // a dead connection forever and add another stale row after
                // every process restart.
                self.peers.remove(pid);
                // In-process transports may reuse their stable peer handle after
                // an unlink/relink. Let that replacement connection perform a
                // fresh handshake rather than inheriting the old one.
                self.version_sent.remove(&pid);
                if matches!(
                    &self.sync.phase,
                    SyncPhase::AwaitingHeaders { peer, .. } if *peer == pid
                ) {
                    self.sync.phase = SyncPhase::Unknown;
                }
            }
        }

        for addr in self.addrs.next_dials(now_ms) {
            if !self.addrs.on_dial_started(&addr) {
                continue;
            }
            match self.transport.dial(&addr) {
                DialStart::Connected(pid) => {
                    self.addrs.on_dial_success(&addr, pid);
                    self.add_peer(pid, Some(addr));
                    connected += 1;
                }
                DialStart::Pending => {}
                DialStart::Failed(_) => self.addrs.on_dial_failure(&addr, now_ms),
            }
        }

        for pid in self.peers.ready_peers() {
            if self.addrs.may_ask(pid, now_ms) {
                self.send(pid, MsgType::GetAddr, Vec::new());
                self.addrs.mark_asked(pid, now_ms);
            }
        }
        connected
    }

    /// Apply connector-thread results on the main loop. The completion timestamp
    /// supplied by the caller starts failure backoff *after* the wait ended; #107
    /// previously started it before a blocking connect, so a long SYN timeout
    /// silently consumed the whole backoff.
    ///
    /// Every completion is journalled (issue #137). #132 took connects off this
    /// loop, so a connect sitting in the kernel's SYN retry loop no longer shows
    /// up as a stalled node — this line is the only place it shows up at all.
    /// Only real-socket transports ever return completions here (the in-process
    /// hub resolves dials inline), so deterministic sims stay silent.
    fn finish_dials(&mut self, now_ms: u64) -> usize {
        let mut connected = 0;
        for DialCompletion { addr, elapsed_ms, result } in self.transport.poll_dials() {
            println!("{}", dial_line(&addr, elapsed_ms, &result));
            match result {
                Ok(pid) => {
                    self.addrs.on_dial_success(&addr, pid);
                    self.add_peer(pid, Some(addr));
                    connected += 1;
                }
                Err(_) => self.addrs.on_dial_failure(&addr, now_ms),
            }
        }
        connected
    }

    /// Admit addresses learned from a peer (scope 1). A peer's claim about a third
    /// party is a **candidate only** (S6): it is never a scoring input in either
    /// direction, so no peer can use it to get another peer penalised. This is the
    /// same rule [`crate::n1::IngestOutcome::is_peer_fault`] encodes for objects —
    /// a well-formed thing we cannot use is not a misbehaving peer (#70 S5).
    fn on_addr(&mut self, from: PeerId, payload: &[u8]) {
        match crate::peer::decode_addrs(payload) {
            Ok(addrs) => {
                self.addrs.learn(addrs);
            }
            // A frame we cannot decode is this peer's own malformed message —
            // that IS a scoring event, and it is about the sender, not a third party.
            Err(_) => {
                self.peers.penalize(from, PENALTY_MALFORMED);
            }
        }
    }

    // --- outbound framing helpers ---
    fn send(&self, to: PeerId, msg_type: MsgType, payload: Vec<u8>) {
        let frame = Envelope::new(msg_type, payload).encode();
        let _ = self.transport.send(to, &frame); // peer-gone is benign
    }

    /// Announce one inventory item to every ready peer except `except`.
    fn relay_inv(&self, item: InvItem, except: Option<PeerId>) {
        let payload = encode_inv(&[item]);
        for pid in self.peers.ready_peers() {
            if Some(pid) != except {
                self.send(pid, MsgType::Inv, payload.clone());
            }
        }
    }

    fn ensure_version_sent(&mut self, to: PeerId) {
        if self.version_sent.insert(to) {
            let v = VersionMsg {
                node_id: self.node_id,
                services: SERVICE_FULL,
                tip_height: self.node.tip_height(),
                user_agent: self.user_agent.clone(),
            };
            self.send(to, MsgType::Version, v.encode());
        }
    }

    /// Register a peer we dialed and open the handshake.
    pub fn add_peer(&mut self, id: PeerId, addr: Option<String>) {
        self.peers.add(id, addr);
        self.ensure_version_sent(id);
    }

    // --- local origination ---

    /// Ingest a locally-produced transaction and announce it.
    pub fn announce_tx(&mut self, tx: TxEntry) {
        let id = tx_id(&tx);
        if self.node.ingest_tx(tx).should_relay() {
            self.seen.insert(id);
            self.relay_inv(InvItem { kind: InvKind::Tx, id }, None);
        }
    }

    /// Ingest a locally-produced header and announce it.
    pub fn announce_header(&mut self, header: BlockHeader) {
        let id = header.header_hash();
        if self.node.ingest_header(header).should_relay() {
            self.seen.insert(id);
            self.relay_inv(InvItem { kind: InvKind::Block, id }, None);
        }
    }

    /// Ingest this node's own (partial) checkpoint votes and gossip them (M10-T0-5).
    ///
    /// The committee is split across nodes, so a proposer's own set is normally far
    /// below quorum; it MUST still enter the tally and be push-gossiped so the network
    /// can accumulate to a quorum (task-book §2.4 — the old code dropped it on the
    /// floor). If accumulating this node's votes with what it has already heard reaches
    /// quorum, the finalized full set is also announced for re-serving.
    pub fn announce_checkpoint(&mut self, cp: Checkpoint, votes: Vec<Vote>) {
        match self.node.ingest_checkpoint_votes(&cp, &votes) {
            VotesOutcome::Learned { finalized, accumulated } => {
                self.push_checkpoint_votes(&cp, &accumulated, None);
                if finalized {
                    self.store_and_announce_finalized(cp, accumulated, None);
                }
            }
            // Stale / Invalid / Unjudged: nothing to relay from our own announce.
            VotesOutcome::Stale | VotesOutcome::Invalid | VotesOutcome::Unjudged => {}
        }
    }

    /// Push a `CheckpointVotes` (0x0024) set to every ready peer except `except`
    /// (direct-push relay — the accumulated set converges the mesh to a quorum).
    fn push_checkpoint_votes(&self, cp: &Checkpoint, votes: &[Vote], except: Option<PeerId>) {
        let payload = encode_checkpoint_votes(cp, votes);
        for pid in self.peers.ready_peers() {
            if Some(pid) != except {
                self.send(pid, MsgType::CheckpointVotes, payload.clone());
            }
        }
    }

    /// Record a now-finalized checkpoint's full vote set for re-serving and announce
    /// it via the `Checkpoint` inv path (so late joiners can `getdata` the full set).
    fn store_and_announce_finalized(&mut self, cp: Checkpoint, votes: Vec<Vote>, except: Option<PeerId>) {
        let id = checkpoint_id(&cp);
        self.checkpoints.insert(id, (cp, votes));
        self.seen.insert(id);
        self.relay_inv(InvItem { kind: InvKind::Checkpoint, id }, except);
    }

    /// Announce a full block (header + ordered body) via compact relay: store the
    /// body, ingest the header, and push a `BlockAnnounce` to ready peers with a
    /// fresh salt nonce (slot 0 prefilled as the coinbase-position tx).
    pub fn announce_block(
        &mut self,
        header: BlockHeader,
        txs: Vec<TxEntry>,
        coinbase: u64,
        coinbase_rkm: [u64; 4],
        nonce: u64,
    ) {
        let bh = header.header_hash();
        // Ingest first, and do not put on the wire what our own node rejects
        // (issue #77, the own-announce seam): a locally-produced header/body pair
        // that fails the binding is a local bug, and announcing it would make this
        // node the origin of the very object every peer must penalise.
        let outcome = self
            .node
            .ingest_block(header, BlockBody { txs: txs.clone(), coinbase, coinbase_rkm });
        // Issue #134 widens this from `Rejected` to `Rejected | Ignored`. `Ignored` now
        // also covers a body whose anchors this node **could not evaluate**, and
        // announcing one would make this node the origin of an object it never
        // validated — the same failure #77 closed here for `Rejected`. It is reachable
        // for a node's own block: a miner in a finality stall can assemble a body whose
        // anchors its own (stalled) view can no longer judge.
        //
        // `Orphan` deliberately still announces: it is not a refusal, and the orphan
        // sync-kick on the receiving side is how a gap gets closed.
        if matches!(outcome, IngestOutcome::Rejected(_) | IngestOutcome::Ignored(_)) {
            return;
        }
        self.blocks.insert(header.height, bh, txs.clone(), coinbase, coinbase_rkm);
        self.seen.insert(bh);

        let (prefilled, short_ids) = build_announce_parts(&txs, nonce);
        let ann =
            BlockAnnounce { header, nonce, coinbase, coinbase_rkm, short_ids, prefilled };
        let payload = encode_announce(&ann);
        for pid in self.peers.ready_peers() {
            self.send(pid, MsgType::BlockAnnounce, payload.clone());
        }
    }

    // --- the driver ---

    /// Process everything that has arrived since the last call. `now_ms` is the
    /// caller's **monotonic** clock in milliseconds — the same one
    /// [`P2pNode::maintain`] takes, and the reason it is a parameter rather than a
    /// wall-clock read inside is that the in-process sims must stay reproducible
    /// byte-for-byte (the M9-N7 soak property). The binary passes a real monotonic
    /// clock; sims pass a deterministic one.
    ///
    /// Returns the number of frames handled (0 ⇒ quiescent, for test loops) —
    /// including frames dropped by the rate limiter, which *were* handled: they
    /// arrived, were charged, and were discarded.
    pub fn tick(&mut self, now_ms: u64) -> usize {
        self.finish_dials(now_ms);
        let frames = self.transport.poll();
        let n = frames.len();
        for (from, frame) in frames {
            if self.peers.is_banned(from) {
                continue;
            }
            // Rate limiting comes BEFORE anything that costs us: before the peer
            // table row, before decode, before dispatch. A throttled frame is
            // dropped and NOT scored — volume is not a protocol fault, and a peer
            // whose only sin is being fast is not a peer worth banning (#91
            // decision 2). The existing malformed/invalid penalties are untouched.
            let key = self.rate_key(from);
            if !self.limiter.charge_frame(key.clone(), frame.len(), now_ms).allowed() {
                continue;
            }
            if !self.peers.contains(from) {
                // Inbound connection we have not registered yet.
                self.peers.add(from, None);
            }
            match Envelope::decode(&frame) {
                Ok(env) => self.dispatch(from, env, key, now_ms),
                Err(_) => {
                    // Malformed frame at the wire layer → strong penalty.
                    self.peers.penalize(from, PENALTY_MALFORMED);
                }
            }
        }
        self.maybe_start_sync();
        self.request_missing_bodies(now_ms);
        n
    }

    // --- issue #130 (c): the requesting side of historical body transfer -------

    /// **Ask for the bodies this node's state machine is missing.**
    ///
    /// The gap #130 (c) names is that nothing ever asked: `GetBlockTxn` has exactly
    /// one send site, in reply to a fresh `BlockAnnounce`, so a node holding 649
    /// headers and no bodies had no message it could send. This is that message —
    /// and it is deliberately **not a new one**. See [`Self::on_getdata`] for why
    /// `GetData(Block)` is the request and a whole-body `BlockAnnounce` is the
    /// answer; the short version is that a new `MsgType` would be banned on sight by
    /// every node running the current image.
    ///
    /// Four bounds, all named constants:
    ///
    /// 1. [`MAX_BODIES_IN_FLIGHT`] outstanding asks at once;
    /// 2. one ask per hash per [`BODY_REQUEST_TIMEOUT_MS`];
    /// 3. the ask set itself is bounded and shrinking —
    ///    [`crate::n1::ChainView::missing_body_hashes`] returns only main-chain
    ///    blocks at or below the header tip that are neither applied nor already
    ///    held, so **it empties as the state machine advances and the node stops
    ///    asking**. That is the termination argument, and it is the node state's
    ///    guarantee rather than a timer here;
    /// 4. nothing is asked with no ready peer to ask.
    ///
    /// **No reply is not a fault.** A peer that never applied a block genuinely
    /// cannot serve it, and on a mixed-version net it will answer with a header
    /// instead — both are honest. So an expiry here scores nothing; the only scoring
    /// on this path is the one that was already there, in `complete_block`, for a
    /// body that does not match the header's `tx_body_commitment`.
    fn request_missing_bodies(&mut self, now_ms: u64) {
        self.body_reqs
            .retain(|_, sent| now_ms.saturating_sub(*sent) < BODY_REQUEST_TIMEOUT_MS);
        let room = MAX_BODIES_IN_FLIGHT.saturating_sub(self.body_reqs.len());
        if room == 0 {
            return;
        }
        let peers = self.peers.ready_peers();
        if peers.is_empty() {
            return;
        }
        let wanted: Vec<Hash32> = self
            .node
            .missing_body_hashes(MAX_BODIES_IN_FLIGHT)
            .into_iter()
            .filter(|h| !self.body_reqs.contains_key(h))
            .take(room)
            .collect();
        if wanted.is_empty() {
            return;
        }
        // Grouped through a peer-ordered Vec rather than a map: the send order must
        // be a function of the peer list alone, or the in-process sims stop being
        // reproducible byte-for-byte (the M9-N7 property).
        let n = peers.len();
        let mut batches: Vec<Vec<InvItem>> = vec![Vec::new(); n];
        for (i, id) in wanted.iter().enumerate() {
            batches[(self.body_rr + i) % n].push(InvItem { kind: InvKind::Block, id: *id });
            self.body_reqs.insert(*id, now_ms);
        }
        self.body_rr = self.body_rr.wrapping_add(1);
        for (pid, items) in peers.into_iter().zip(batches) {
            if !items.is_empty() {
                self.send(pid, MsgType::GetData, encode_inv(&items));
            }
        }
    }

    /// The body this node can serve for `hash`: the hot relay cache first, then the
    /// applied-block store — the same two sources, in the same order, that
    /// [`Self::on_get_block_txn`] already reads (issue #135). Stated once so the two
    /// serving paths cannot come to disagree about what this node holds.
    fn body_for_serving(&self, hash: &Hash32) -> Option<BlockBody> {
        if let Some(entry) = self.blocks.get(hash) {
            return Some(BlockBody {
                txs: entry.txs.clone(),
                coinbase: entry.coinbase,
                coinbase_rkm: entry.coinbase_rkm,
            });
        }
        self.node.stored_body(hash)
    }

    fn dispatch(&mut self, from: PeerId, env: Envelope, key: RateKey, now_ms: u64) {
        match env.msg_type {
            MsgType::Version => self.on_version(from, &env.payload),
            MsgType::VerAck => self.on_verack(from),
            MsgType::Ping => self.send(from, MsgType::Pong, env.payload),
            MsgType::Pong => {}
            MsgType::GetAddr => {
                // Issue #91's amplifier. A 12 B header-only request used to be
                // answered unconditionally with up to 13,013 B — measured 1084x at
                // the cap, and FLAT in the request rate, which is what made this
                // node a usable reflector rather than merely a chatty one.
                //
                // The fix is to not answer. Amplification is a response-BYTES
                // problem, so the cheapest correct response is no response; a token
                // bucket with room for a burst would still let that burst out, and
                // the burst is itself the amplifier. The allowance is one reply per
                // GETADDR_SERVE_INTERVAL_MS per RATE KEY — a host, not a socket, so
                // an attacker who disconnects and redials comes back to the same
                // spent allowance. Over-rate requests are dropped in silence and
                // NOT scored: asking twice is not misbehaviour.
                if !self.limiter.may_serve_getaddr(key, now_ms) {
                    return;
                }
                // S2: only **dialable** addresses are served — ones we have
                // ourselves connected to, plus our own iff the operator declared
                // us reachable. Handing out merely-connected peers would fill a
                // joiner's book with entries nobody can reach, which is worse than
                // no discovery because it looks like it is working.
                let addrs = self.addrs.gossipable();
                self.send(from, MsgType::Addr, crate::peer::encode_addrs(&addrs));
            }
            MsgType::Addr => self.on_addr(from, &env.payload),
            MsgType::Inv => self.on_inv(from, &env.payload),
            MsgType::GetData => self.on_getdata(from, &env.payload),
            MsgType::NotFound => self.on_not_found(from, &env.payload),
            MsgType::Tx => self.on_tx(from, &env.payload),
            MsgType::Header => self.on_header(from, &env.payload),
            MsgType::Checkpoint => self.on_checkpoint(from, &env.payload),
            MsgType::CheckpointVotes => self.on_checkpoint_votes(from, &env.payload),
            MsgType::Evidence => self.on_evidence(from, &env.payload),
            MsgType::GetHeaders => self.on_get_headers(from, &env.payload),
            MsgType::Headers => self.on_headers(from, &env.payload),
            MsgType::CmpctBlock => self.on_cmpct_block(from, &env.payload),
            MsgType::BlockAnnounce => self.on_block_announce(from, &env.payload),
            MsgType::GetBlockTxn => self.on_get_block_txn(from, &env.payload),
            MsgType::BlockTxn => self.on_block_txn(from, &env.payload),
        }
    }

    // --- handshake ---

    fn on_version(&mut self, from: PeerId, payload: &[u8]) {
        match VersionMsg::decode(payload) {
            Ok(v) => {
                self.peers.on_version(from, &v);
                self.ensure_version_sent(from); // reply with our Version if new
                self.send(from, MsgType::VerAck, vec![]);
            }
            Err(_) => {
                self.peers.penalize(from, PENALTY_MALFORMED);
            }
        }
    }

    fn on_verack(&mut self, from: PeerId) {
        self.peers.on_verack(from);
    }

    // --- inventory gossip ---

    fn on_inv(&mut self, from: PeerId, payload: &[u8]) {
        let items = match decode_inv(payload) {
            Ok(i) => i,
            Err(_) => {
                self.peers.penalize(from, PENALTY_MALFORMED);
                return;
            }
        };
        let mut want = Vec::new();
        for it in items {
            if self.already_have(&it) {
                continue;
            }
            want.push(it);
        }
        if !want.is_empty() {
            self.send(from, MsgType::GetData, encode_inv(&want));
        }
    }

    fn already_have(&self, it: &InvItem) -> bool {
        match it.kind {
            InvKind::Tx => self.node.has_tx(&it.id) || self.seen.contains(&it.id),
            InvKind::Block => self.node.has_header(&it.id) || self.seen.contains(&it.id),
            InvKind::Checkpoint => self.node.has_checkpoint(&it.id) || self.seen.contains(&it.id),
        }
    }

    /// A peer telling us it cannot serve something we asked for.
    ///
    /// **The penalty is now conditional, and it has to be** (issue #130 (c)).
    /// `PENALTY_WELSHED_INV` was written for the only `GetData` this node used to
    /// send: one issued in reply to an `Inv`, i.e. asking a peer for an object it
    /// had *just advertised*. Answering `NotFound` to that is welshing, and 5 points
    /// is right.
    ///
    /// The historical-body requester sends a `GetData` nobody advertised, for a block
    /// a peer may legitimately not hold — a joiner, a node that pruned, a node behind
    /// us. Charging that would be #134's mistake in a new place: **banning honest
    /// peers for not having history**, at 5 points a block over a 649-block catch-up,
    /// which is 20 blocks to a ban. So an item we ourselves put in flight is
    /// exempt, and everything else is charged exactly as before.
    ///
    /// A `NotFound` we cannot decode is still the sender's own malformed frame.
    fn on_not_found(&mut self, from: PeerId, payload: &[u8]) {
        let items = match decode_inv(payload) {
            Ok(i) => i,
            Err(_) => {
                self.peers.penalize(from, PENALTY_MALFORMED);
                return;
            }
        };
        // Charge once per message, not per item, matching the pre-#130 (c) behaviour
        // for a message this node did not originate as a body request.
        if items.iter().any(|it| !self.body_reqs.contains_key(&it.id)) {
            self.peers.penalize(from, PENALTY_WELSHED_INV);
        }
    }

    fn on_getdata(&mut self, from: PeerId, payload: &[u8]) {
        let items = match decode_inv(payload) {
            Ok(i) => i,
            Err(_) => {
                self.peers.penalize(from, PENALTY_MALFORMED);
                return;
            }
        };
        let mut not_found = Vec::new();
        let mut bodies_served = 0usize;
        for it in items {
            match it.kind {
                InvKind::Tx => match self.node.get_tx(&it.id) {
                    Some(tx) => self.send(from, MsgType::Tx, encode_tx(&tx)),
                    None => not_found.push(it),
                },
                // **The door #130 (c) opens, and it needed no new envelope type.**
                //
                // This arm answered with a header and nothing else, which is the
                // "other door is shut" the issue names: a node holding a header and
                // wanting its body had no way to ask for it, because the only
                // body-bearing request in the protocol (`GetBlockTxn`) names
                // transactions by index and a `BlockHeader` carries no transaction
                // count to build those indexes from.
                //
                // So the request is `GetData(Block)` — unchanged, already understood
                // by every deployed node — and the answer is the fullest thing we
                // hold: a `BlockAnnounce` (0x0041) with every transaction prefilled
                // and no short ids, which is the existing announce codec used exactly
                // as its own docs describe ("txs it predicts the peer lacks"). The
                // codec is not forked and no `MsgType` is added.
                //
                // Both mixed-version directions degrade to the status quo, which is
                // why this shape was chosen over the additive type the task book
                // permitted: a NEW node asking an OLD one gets a header back and is
                // not scored; an OLD node asking a NEW one gets a `BlockAnnounce` it
                // has understood since M9. Neither side sees an unknown type — and an
                // unknown type on this net is not ignored, it is `PENALTY_MALFORMED`
                // (100) against a `BAN_THRESHOLD` of −100, i.e. **an instant, one-frame
                // ban**. See the PR body; this is the finding the task book asked for.
                InvKind::Block => match self.node.header(&it.id) {
                    Some(h) => {
                        let body = if bodies_served < MAX_BODIES_PER_GETDATA {
                            self.body_for_serving(&it.id)
                        } else {
                            None
                        };
                        match body {
                            Some(b) => {
                                bodies_served += 1;
                                let ann = whole_block_announce(h, b);
                                self.send(from, MsgType::BlockAnnounce, encode_announce(&ann));
                            }
                            // No body held, or past the per-message cap: the header,
                            // exactly as before. Never `NotFound` — we do have the
                            // object this inv named, and `NotFound` is scored.
                            None => {
                                self.send(from, MsgType::Header, crate::codec::encode_header(&h))
                            }
                        }
                    }
                    None => not_found.push(it),
                },
                InvKind::Checkpoint => match self.checkpoints.get(&it.id) {
                    Some((cp, votes)) => {
                        self.send(from, MsgType::Checkpoint, encode_checkpoint_msg(cp, votes))
                    }
                    None => not_found.push(it),
                },
            }
        }
        if !not_found.is_empty() {
            self.send(from, MsgType::NotFound, encode_inv(&not_found));
        }
    }

    // --- gossip payloads ---

    fn on_tx(&mut self, from: PeerId, payload: &[u8]) {
        let tx = match decode_tx(payload) {
            Ok(t) => t,
            Err(_) => {
                self.peers.penalize(from, PENALTY_MALFORMED);
                return;
            }
        };
        let id = tx_id(&tx);
        let outcome = self.node.ingest_tx(tx);
        // ONE place decides whether the sender is at fault (`is_peer_fault`), so the
        // "an unusable object is not a misbehaving peer" rule cannot drift between
        // the tx, header and block paths (#70 S5; #74 extends it to the halt).
        if outcome.is_peer_fault() {
            self.peers.penalize(from, PENALTY_INVALID_OBJECT);
        }
        if outcome.should_relay() {
            self.seen.insert(id);
            self.relay_inv(InvItem { kind: InvKind::Tx, id }, Some(from));
        }
    }

    fn on_header(&mut self, from: PeerId, payload: &[u8]) {
        let header = match crate::codec::decode_header(payload) {
            Ok(h) => h,
            Err(_) => {
                self.peers.penalize(from, PENALTY_MALFORMED);
                return;
            }
        };
        let id = header.header_hash();
        let outcome = self.node.ingest_header(header);
        if outcome.is_peer_fault() {
            self.peers.penalize(from, PENALTY_INVALID_OBJECT);
        }
        match outcome {
            IngestOutcome::Accepted => {
                self.seen.insert(id);
                self.relay_inv(InvItem { kind: InvKind::Block, id }, Some(from));
            }
            IngestOutcome::Orphan => {
                // Missing ancestors → kick off header-first sync from this peer.
                self.start_sync_with(from);
            }
            // Above our halt height (#74). NOT a misbehaving peer — it is on a
            // different release, exactly as §4 says it may be. No relay, and no sync
            // kick either: syncing toward it would be asking for more of what we
            // have decided not to accept.
            IngestOutcome::Ignored(_) => {}
            IngestOutcome::Rejected(_) | IngestOutcome::Duplicate => {}
        }
    }

    /// Handle a `Checkpoint` (0x0022) object — the finalized-set serving path
    /// (getdata re-serve / late-joiner catch-up). Routed through the same tally as
    /// `CheckpointVotes` so scoring is uniform: a well-formed below-quorum set is NOT
    /// penalised (task-book S5), only a forged/unknown/dup set is.
    fn on_checkpoint(&mut self, from: PeerId, payload: &[u8]) {
        let (cp, votes) = match decode_checkpoint_msg(payload) {
            Ok(cv) => cv,
            Err(_) => {
                self.peers.penalize(from, PENALTY_MALFORMED);
                return;
            }
        };
        self.absorb_votes(from, cp, votes);
    }

    /// Handle a `CheckpointVotes` (0x0024) partial set — the accumulation path
    /// (M10-T0-5). Verifies + accumulates; relays newly-learned votes onward (sender
    /// excluded) so the mesh converges to a quorum.
    fn on_checkpoint_votes(&mut self, from: PeerId, payload: &[u8]) {
        let (cp, votes) = match decode_checkpoint_votes(payload) {
            Ok(cv) => cv,
            Err(_) => {
                self.peers.penalize(from, PENALTY_MALFORMED);
                return;
            }
        };
        self.absorb_votes(from, cp, votes);
    }

    /// Shared body for both checkpoint-vote message types: run equivocation
    /// observation, feed the tally, then relay/score by [`VotesOutcome`].
    fn absorb_votes(&mut self, from: PeerId, cp: Checkpoint, votes: Vec<Vote>) {
        // Equivocation path: a set's votes may reveal a signer that already signed a
        // conflicting checkpoint at this slot. Detect it, tombstone locally, and gossip
        // the evidence BEFORE the tally counts, so a tombstoned vote cannot reach quorum.
        for ev in self.node.observe_votes(&cp, &votes) {
            self.punish_and_gossip_evidence(ev);
        }
        match self.node.ingest_checkpoint_votes(&cp, &votes) {
            VotesOutcome::Learned { finalized, accumulated } => {
                // Relay the accumulated set onward (sender excluded) — direct-push
                // gossip converges the mesh; a well-formed partial is never penalised.
                self.push_checkpoint_votes(&cp, &accumulated, Some(from));
                if finalized {
                    self.store_and_announce_finalized(cp, accumulated, Some(from));
                }
            }
            VotesOutcome::Stale => {} // already known / finalized — no relay, no penalty
            // Issue #164: only Intrinsic failures cost the sender. `Unjudged` is
            // out-of-range only (positional); index-resolves + verify-fail is
            // Invalid. One predicate so scoring cannot drift from classification.
            other => {
                if other.is_peer_fault() {
                    self.peers.penalize(from, PENALTY_INVALID_OBJECT);
                }
            }
        }
    }

    // --- committee: equivocation evidence gossip (M9-N5) ---

    /// Apply verified evidence locally and, if it was valid and not already seen,
    /// gossip it to every ready peer so the whole network tombstones the signer.
    fn punish_and_gossip_evidence(&mut self, ev: EquivocationEvidence) {
        if self.node.apply_evidence(&ev).is_none() {
            return; // did not verify — nothing to relay
        }
        let id = evidence_id(&ev);
        if self.seen.insert(id) {
            let payload = encode_evidence_msg(&ev);
            for pid in self.peers.ready_peers() {
                self.send(pid, MsgType::Evidence, payload.clone());
            }
        }
    }

    /// Gossip locally-held equivocation evidence (e.g. produced off-network).
    pub fn announce_evidence(&mut self, ev: EquivocationEvidence) {
        self.punish_and_gossip_evidence(ev);
    }

    fn on_evidence(&mut self, from: PeerId, payload: &[u8]) {
        let ev = match decode_evidence_msg(payload) {
            Ok(e) => e,
            Err(_) => {
                self.peers.penalize(from, PENALTY_MALFORMED);
                return;
            }
        };
        let id = evidence_id(&ev);
        if !self.seen.insert(id) {
            return; // already handled — dedup re-gossip
        }
        match self.node.apply_evidence(&ev) {
            Some(_signer) => {
                // Valid → relay onward to every ready peer except the sender.
                let payload = encode_evidence_msg(&ev);
                for pid in self.peers.ready_peers() {
                    if pid != from {
                        self.send(pid, MsgType::Evidence, payload.clone());
                    }
                }
            }
            None => {
                // Evidence that does not verify is an invalid object.
                self.peers.penalize(from, PENALTY_INVALID_OBJECT);
            }
        }
    }

    /// This node's Ebb-and-Flow regime (Final vs degraded probabilistic PoW),
    /// observed over the network.
    pub fn finality_status(&self) -> qlab_devnet::ebbflow::FinalityStatus {
        self.node.finality_status()
    }

    // --- header-first sync ---

    fn maybe_start_sync(&mut self) {
        if self.sync.awaiting() {
            return;
        }
        // Issue #106: `None` and `Some(0)` are NOT the same answer, and treating
        // them as one is what let a node with no peers report itself `Synced`.
        // `best_height()` is `None` when no ready peer has claimed a height at all
        // — an empty peer table, or peers still mid-handshake — and the honest
        // phase for that is `Unknown`, not "caught up to 0". A node on a brand-new
        // net whose peers really are at height 0 gets `Some(0)`, compares against
        // its own tip, and reaches `Synced` on evidence.
        match self.peers.best_height() {
            None => self.sync.phase = SyncPhase::Unknown,
            Some(best) if best > self.node.tip_height() => {
                // Sync from the tallest ready peer.
                if let Some(peer) = self.tallest_ready_peer() {
                    self.start_sync_with(peer);
                } else {
                    self.sync.phase = SyncPhase::Behind;
                }
            }
            Some(_) => self.sync.phase = SyncPhase::Synced,
        }
    }

    fn tallest_ready_peer(&self) -> Option<PeerId> {
        self.peers
            .ready_peers()
            .into_iter()
            .filter_map(|p| self.peers.get(p).map(|info| (p, info.tip_height)))
            .max_by_key(|(_, h)| *h)
            .map(|(p, _)| p)
    }

    fn start_sync_with(&mut self, peer: PeerId) {
        if !self.peers.is_ready(peer) {
            return;
        }
        let loc = build_locator(&self.node);
        self.send(peer, MsgType::GetHeaders, encode_locator(&loc));
        self.sync.phase =
            SyncPhase::AwaitingHeaders { peer, from_height: self.node.tip_height() };
    }

    fn on_get_headers(&mut self, from: PeerId, payload: &[u8]) {
        let loc = match decode_locator(payload) {
            Ok(l) => l,
            Err(_) => {
                self.peers.penalize(from, PENALTY_MALFORMED);
                return;
            }
        };
        let batch = answer_get_headers(&self.node, &loc, MAX_HEADERS_PER_BATCH);
        self.send(from, MsgType::Headers, encode_headers(&batch));
    }

    fn on_headers(&mut self, from: PeerId, payload: &[u8]) {
        let batch = match decode_headers(payload) {
            Ok(b) => b,
            Err(_) => {
                self.peers.penalize(from, PENALTY_MALFORMED);
                return;
            }
        };
        let batch_len = batch.len();
        let mut accepted = 0;
        for h in batch {
            let id = h.header_hash();
            match self.node.ingest_header(h) {
                IngestOutcome::Accepted => {
                    accepted += 1;
                    self.seen.insert(id);
                    self.relay_inv(InvItem { kind: InvKind::Block, id }, Some(from));
                }
                IngestOutcome::Duplicate => {}
                // An orphan mid-batch means the batch didn't connect; stop and let
                // the next locator round re-anchor.
                IngestOutcome::Orphan | IngestOutcome::Rejected(_) => break,
                // A halted node stops consuming the batch at the boundary: the
                // rest of it is above our halt height and will never be accepted.
                // Stopping here is what pins a halted node's tip at exactly H even
                // while peers keep serving it taller header batches (#74).
                IngestOutcome::Ignored(_) => break,
            }
        }

        // Advance the state machine. `best` is read once: the same `None`/`Some(0)`
        // conflation fixed in `maybe_start_sync` (issue #106) was here too — a peer
        // that dropped mid-batch left `unwrap_or(0)`, hence `still_behind == false`,
        // hence `Synced` on a node that had just lost its only source of heights.
        let best = self.peers.best_height();
        let still_behind = best.is_some_and(|b| b > self.node.tip_height());
        if batch_len == MAX_HEADERS_PER_BATCH && still_behind && accepted > 0 {
            // Full batch and more to go → request the next one.
            let loc = build_locator(&self.node);
            self.send(from, MsgType::GetHeaders, encode_locator(&loc));
            self.sync.phase =
                SyncPhase::AwaitingHeaders { peer: from, from_height: self.node.tip_height() };
        } else {
            self.sync.phase = match best {
                None => SyncPhase::Unknown,
                Some(_) if still_behind => SyncPhase::Behind,
                Some(_) => SyncPhase::Synced,
            };
        }
    }

    // --- compact-block relay ---

    // (1) §5 compact blocks: relayed opaquely (the stub has no note store), with
    // dedup so each propagates once.
    fn on_cmpct_block(&mut self, from: PeerId, payload: &[u8]) {
        // Validate framing by decoding (inherits §5 reject-* guarantees); a
        // malformed payload penalizes the sender.
        if crate::compact::decode_cmpct_relay(payload).is_err() {
            self.peers.penalize(from, PENALTY_MALFORMED);
            return;
        }
        let id = qlab_devnet::hash::keccak256(payload);
        if self.seen.insert(id) {
            for pid in self.peers.ready_peers() {
                if pid != from {
                    self.send(pid, MsgType::CmpctBlock, payload.to_vec());
                }
            }
        }
    }

    // (2) §7 BIP-152 block relay.
    fn on_block_announce(&mut self, from: PeerId, payload: &[u8]) {
        let ann = match decode_announce(payload) {
            Ok(a) => a,
            Err(_) => {
                self.peers.penalize(from, PENALTY_MALFORMED);
                return;
            }
        };
        let bh = ann.header.header_hash();
        if self.blocks.contains(&bh) || self.node.has_stored_body(&bh) {
            self.body_reqs.remove(&bh); // nothing outstanding: we hold this body
            return; // already have the full body (hot cache or applied store)
        }
        let candidates = self.node.all_txs();
        match reconstruct(&ann, &candidates) {
            Reconstruct::Complete(txs) => self.complete_block(bh, ann, txs, Some(from)),
            Reconstruct::Missing(indexes) => {
                self.pending_blocks.insert(bh, ann);
                self.send(
                    from,
                    MsgType::GetBlockTxn,
                    encode_get_block_txn(&GetBlockTxn { block_hash: bh, indexes }),
                );
            }
        }
        // **The ask is satisfied only if we now hold the body** (issue #130 (c)).
        //
        // Clearing the in-flight entry on *arrival* rather than on *success* was the
        // obvious shape and it is a busy loop: a body this node refuses — a joiner's
        // unjudgeable anchor (#134), a body that loses its own fork — is not applied,
        // so the next `request_missing_bodies` pass re-asks for it on the very next
        // tick, and the peer re-serves it, forever, at the tick rate.
        //
        // Leaving the entry in place makes [`BODY_REQUEST_TIMEOUT_MS`] pace the retry
        // instead: at most one re-ask per block per 15 s, and the rotation still sends
        // that re-ask to a different peer. The cost is that a *bad* answer also delays
        // the retry by up to 15 s, which is the same bound a *missing* answer already
        // pays and is the honest reading of both — we asked, and we still do not have
        // it.
        if self.blocks.contains(&bh) || self.node.has_stored_body(&bh) {
            self.body_reqs.remove(&bh);
        }
    }

    fn on_get_block_txn(&mut self, from: PeerId, payload: &[u8]) {
        let req = match decode_get_block_txn(payload) {
            Ok(r) => r,
            Err(_) => {
                self.peers.penalize(from, PENALTY_MALFORMED);
                return;
            }
        };
        // Hot cache first, then the applied-block store (issue #135): the cache is
        // the relay window, the store is authoritative for everything this node
        // has folded into state — so eviction never makes an applied body
        // unanswerable. A miss on both is a body this node never applied and no
        // longer holds (or never held); it stays silent, as before.
        let txs: Vec<TxEntry> = if let Some(entry) = self.blocks.get(&req.block_hash) {
            req.indexes.iter().filter_map(|&i| entry.txs.get(i as usize).cloned()).collect()
        } else if let Some(body) = self.node.stored_body(&req.block_hash) {
            req.indexes.iter().filter_map(|&i| body.txs.get(i as usize).cloned()).collect()
        } else {
            return; // we don't have that block's body
        };
        self.send(
            from,
            MsgType::BlockTxn,
            encode_block_txn(&BlockTxn { block_hash: req.block_hash, txs }),
        );
    }

    fn on_block_txn(&mut self, from: PeerId, payload: &[u8]) {
        let bt = match decode_block_txn(payload) {
            Ok(b) => b,
            Err(_) => {
                self.peers.penalize(from, PENALTY_MALFORMED);
                return;
            }
        };
        let Some(ann) = self.pending_blocks.remove(&bt.block_hash) else {
            return;
        };
        // Add the supplied txs to our mempool, then re-reconstruct.
        for tx in &bt.txs {
            let _ = self.node.ingest_tx(tx.clone());
        }
        let candidates = self.node.all_txs();
        match reconstruct(&ann, &candidates) {
            Reconstruct::Complete(txs) => self.complete_block(bt.block_hash, ann, txs, Some(from)),
            Reconstruct::Missing(_) => { /* still missing; give up this round */ }
        }
    }

    /// Finish a reconstructed/announced block: store the body, ingest the header,
    /// and re-announce to other peers.
    fn complete_block(
        &mut self,
        bh: Hash32,
        ann: BlockAnnounce,
        txs: Vec<TxEntry>,
        except: Option<PeerId>,
    ) {
        let outcome = self
            .node
            .ingest_block(
                ann.header,
                BlockBody {
                    txs: txs.clone(),
                    coinbase: ann.coinbase,
                    coinbase_rkm: ann.coinbase_rkm,
                },
            );
        // Orphan-triggered sync kick (M10-T0-1, issue #62 item 6 — the N7 finding):
        // an announced block whose parent is unknown was previously dropped, and
        // gap recovery relied solely on the taller-peer handshake. Instead, kick
        // header-first sync toward the announcer to fill the gap — mirroring the
        // orphan path in `on_header`. Do NOT cache or relay an orphan; a re-announce
        // after catch-up re-drives application.
        if outcome == IngestOutcome::Orphan {
            if let Some(peer) = except {
                self.start_sync_with(peer);
            }
            return;
        }
        // Anything we did not accept is neither cached nor re-announced — putting
        // on the wire what our own node refused would make this node the origin of
        // the very object every peer must judge for itself.
        //
        // Whether the ANNOUNCER pays for it is a separate question, and it is asked
        // in exactly one place: `is_peer_fault()` (#74). `Rejected` is a fault;
        // `Ignored` — a block above our halt height — is not, because a peer still
        // mining is on a different release, which `committee-and-governance` §4 says
        // explicitly it may be. Penalising there would ban honest miners inside the
        // upgrade window.
        //
        // This is the compact-reconstruction seam (#77 P2): the announcer controls
        // the prefilled txs and the short-id salt, so "reconstruction succeeded" is
        // no evidence the body is the header's body. That verdict comes from
        // `ingest_block`, and it was being computed and then discarded, so a
        // mismatched body would have been stored and relayed onward.
        if !matches!(outcome, IngestOutcome::Accepted) {
            if outcome.is_peer_fault() {
                if let Some(peer) = except {
                    self.peers.penalize(peer, PENALTY_INVALID_OBJECT);
                }
            }
            return;
        }
        self.blocks.insert(ann.header.height, bh, txs, ann.coinbase, ann.coinbase_rkm);
        self.seen.insert(bh);
        let payload = encode_announce(&ann);
        for pid in self.peers.ready_peers() {
            if Some(pid) != except {
                self.send(pid, MsgType::BlockAnnounce, payload.clone());
            }
        }
    }
}

/// **A whole block, in the announce codec** (issue #130 (c)): every transaction
/// prefilled, no short ids.
///
/// A `BlockAnnounce` already carries the two body fields that are not transaction
/// slots — `coinbase` and `coinbase_rkm` (issue #101) — which is exactly why it,
/// and not `BlockTxn`, is the answer to a historical body request: `BlockTxn`
/// carries transactions only, so a receiver could never rebuild a body whose
/// commitment matches the header, and every served block would be rejected as a
/// binding mismatch.
///
/// The salt `nonce` is 0 and is genuinely unused: it exists to randomise short
/// ids, and there are none. Fixing it rather than inventing one keeps the encoding
/// a pure function of the block, so two nodes serving the same block serve the
/// same bytes.
fn whole_block_announce(header: BlockHeader, body: BlockBody) -> BlockAnnounce {
    let prefilled = body
        .txs
        .into_iter()
        .enumerate()
        .map(|(i, tx)| PrefilledTx { index: i as u32, tx })
        .collect();
    BlockAnnounce {
        header,
        nonce: 0,
        coinbase: body.coinbase,
        coinbase_rkm: body.coinbase_rkm,
        short_ids: Vec::new(),
        prefilled,
    }
}

/// Build the `(prefilled, short_ids)` for a `BlockAnnounce`: slot 0 (the
/// coinbase position) is prefilled; the rest are short ids under `nonce`.
fn build_announce_parts(txs: &[TxEntry], nonce: u64) -> (Vec<PrefilledTx>, Vec<[u8; 6]>) {
    let mut prefilled = Vec::new();
    let mut short_ids = Vec::new();
    for (i, tx) in txs.iter().enumerate() {
        if i == 0 {
            prefilled.push(PrefilledTx { index: 0, tx: tx.clone() });
        } else {
            short_ids.push(short_id(nonce, &tx_id(tx)));
        }
    }
    (prefilled, short_ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::n1::{BlockIngest, ChainView, CheckpointIngest, CommitteeControl, StubNode, TxPool};
    use crate::transport::{InProcHub, InProcTransport, TcpTransport};
    use qlab_devnet::body::TxPublic;
    use qlab_devnet::committee::{devnet_committee, CommitteeState, MemberStatus, Validator};
    use qlab_devnet::ebbflow::{EquivocationEvidence, FinalityStatus};
    use qlab_devnet::epoch::{EpochCommittee, EpochSchedule};
    use qlab_devnet::fees::ArityBucket;
    use qlab_devnet::finality::next_checkpoint_height;
    use qlab_devnet::params_devnet::BOND_AMOUNT;
    use std::sync::Arc;

    /// Verified equivocation evidence: `signer` signed two conflicting checkpoints
    /// at `height` (distinct block hashes ⇒ distinct signing messages).
    fn conflicting_evidence(
        validators: &[Validator],
        signer: usize,
        height: u64,
    ) -> EquivocationEvidence {
        let a = Checkpoint::new(height, [0xA0 + signer as u8; 32], [0xA0; 32]);
        let b = Checkpoint::new(height, [0xB0 + signer as u8; 32], [0xB0; 32]);
        EquivocationEvidence {
            vote_a: validators[signer].sign_checkpoint(&a),
            cp_a: a,
            vote_b: validators[signer].sign_checkpoint(&b),
            cp_b: b,
        }
    }

    type InProcP2p = P2pNode<InProcTransport, StubNode>;

    fn genesis() -> BlockHeader {
        BlockHeader::genesis(1000, 0)
    }

    fn stub() -> StubNode {
        let (committee, _v) = devnet_committee(7);
        StubNode::new(genesis(), CommitteeState::new(committee, BOND_AMOUNT))
    }

    /// The header for a block over `parent` announcing `txs` + `coinbase` — it
    /// commits to exactly that body, which since issue #77 is what makes the
    /// announce ingestable at all.
    fn header_over(parent: &BlockHeader, ts: u64, txs: &[TxEntry], coinbase: u64) -> BlockHeader {
        let body = BlockBody { txs: txs.to_vec(), coinbase, coinbase_rkm: [0; 4] };
        BlockHeader::child_of(parent, ts, 1000, body.commitment())
    }

    fn tx(seed: u8) -> TxEntry {
        TxEntry {
            proof: vec![seed; 32],
            public: TxPublic {
                anchor: [seed; 32],
                nullifiers: vec![[seed; 32]],
                commitments: vec![[seed.wrapping_add(9); 32]],
                bucket: ArityBucket::TwoByTwo,
                fee: 1_000_000,
            },
        }
    }

    /// Milliseconds a simulated round advances the deterministic clock the tests
    /// drive `tick` with (issue #91). A sim clock, not a wall clock: reproducibility
    /// is the point, and a frozen clock would leave the rate limiter's buckets
    /// unable to refill, which models nothing.
    const SIM_TICK_MS: u64 = 10;

    /// Drive a set of nodes to quiescence (no frames moved in a full round).
    fn run(nodes: &mut [InProcP2p]) {
        run_at(nodes, 0)
    }

    /// As [`run`], but starting the deterministic clock at `base_ms` so a caller
    /// that advances a logical clock across rounds keeps it **monotone** — a clock
    /// that jumps backwards would make the rate limiter's refill meaningless.
    fn run_at(nodes: &mut [InProcP2p], base_ms: u64) {
        for round in 0..1000u64 {
            let mut moved = 0;
            for n in nodes.iter_mut() {
                moved += n.tick(base_ms + round * SIM_TICK_MS);
            }
            if moved == 0 {
                break;
            }
        }
    }

    /// A fully-connected mesh of `n` in-process nodes; returns the nodes and hub.
    fn mesh(n: u64) -> (Vec<InProcP2p>, Arc<InProcHub>) {
        let hub = InProcHub::new();
        let mut nodes = Vec::new();
        for i in 0..n {
            let t = InProcTransport::new(PeerId(i + 1), Arc::clone(&hub));
            nodes.push(P2pNode::new(t, stub(), [i as u8 + 1; 32]));
        }
        // Link every pair and introduce peers to each other.
        for i in 0..n {
            for j in 0..n {
                if i != j {
                    hub.link(PeerId(i + 1), PeerId(j + 1));
                }
            }
        }
        for i in 0..n {
            for j in 0..n {
                if i != j {
                    nodes[i as usize].add_peer(PeerId(j + 1), None);
                }
            }
        }
        (nodes, hub)
    }

    /// A fully-connected mesh of `n` nodes that all share one `committee` (so votes
    /// verify on every node even when each node holds only a slice of the signing
    /// keys — the T0 6/5/5/5 topology).
    fn mesh_sharing(
        n: u64,
        committee: &qlab_devnet::committee::Committee,
    ) -> (Vec<InProcP2p>, Arc<InProcHub>) {
        let hub = InProcHub::new();
        let mut nodes = Vec::new();
        for i in 0..n {
            let t = InProcTransport::new(PeerId(i + 1), Arc::clone(&hub));
            let node = StubNode::new(genesis(), CommitteeState::new(committee.clone(), BOND_AMOUNT));
            nodes.push(P2pNode::new(t, node, [i as u8 + 1; 32]));
        }
        for i in 0..n {
            for j in 0..n {
                if i != j {
                    hub.link(PeerId(i + 1), PeerId(j + 1));
                }
            }
        }
        for i in 0..n {
            for j in 0..n {
                if i != j {
                    nodes[i as usize].add_peer(PeerId(j + 1), None);
                }
            }
        }
        (nodes, hub)
    }

    #[test]
    fn handshake_reaches_ready_both_ways() {
        let (mut nodes, _hub) = mesh(2);
        run(&mut nodes);
        assert!(nodes[0].peers().is_ready(PeerId(2)));
        assert!(nodes[1].peers().is_ready(PeerId(1)));
    }

    #[test]
    fn tx_gossip_propagates_across_mesh() {
        let (mut nodes, _hub) = mesh(3);
        run(&mut nodes); // complete handshakes
        let t = tx(42);
        let id = tx_id(&t);
        nodes[0].announce_tx(t);
        run(&mut nodes);
        for n in &nodes {
            assert!(n.node().has_tx(&id), "each node received the tx");
        }
    }

    #[test]
    fn header_gossip_propagates() {
        let (mut nodes, _hub) = mesh(3);
        run(&mut nodes);
        let h = BlockHeader::child_of(&genesis(), 75, 1000, [1; 32]);
        let id = h.header_hash();
        nodes[0].announce_header(h);
        run(&mut nodes);
        for n in &nodes {
            assert!(n.node().has_header(&id));
        }
    }

    #[test]
    fn checkpoint_gossip_propagates_and_finalizes() {
        // All nodes share one committee so votes verify everywhere.
        let (committee, validators) = devnet_committee(7); // quorum 5
        let hub = InProcHub::new();
        let mut nodes: Vec<InProcP2p> = (0..3)
            .map(|i| {
                let t = InProcTransport::new(PeerId(i + 1), Arc::clone(&hub));
                let node = StubNode::new(
                    genesis(),
                    CommitteeState::new(committee.clone(), BOND_AMOUNT),
                );
                P2pNode::new(t, node, [i as u8 + 1; 32])
            })
            .collect();
        for i in 0..3u64 {
            for j in 0..3u64 {
                if i != j {
                    hub.link(PeerId(i + 1), PeerId(j + 1));
                }
            }
        }
        for i in 0..3usize {
            for j in 0..3u64 {
                if i as u64 != j {
                    nodes[i].add_peer(PeerId(j + 1), None);
                }
            }
        }
        run(&mut nodes);

        let cp = Checkpoint::new(2, [0xAB; 32], [0xAB; 32]);
        let votes: Vec<Vote> =
            validators[..5].iter().map(|v: &Validator| v.sign_checkpoint(&cp)).collect();
        nodes[0].announce_checkpoint(cp, votes);
        run(&mut nodes);
        for n in &nodes {
            assert_eq!(n.node().finality().finalized_height(), Some(2));
        }
    }

    // ---- M10-T0-5: distributed vote aggregation (6/5/5/5) ---------------------

    /// ACCEPTANCE #1 — a 4-node net whose 21 committee keys are split 6/5/5/5
    /// finalizes a checkpoint, though NO node holds a quorum (15): each node announces
    /// only its own slice, and the mesh accumulates the partial sets across gossip to
    /// a quorum. (This is the exact gap Phase B-lite found.)
    #[test]
    fn six_five_five_five_reaches_quorum() {
        let (committee, validators) = devnet_committee(21); // quorum 15
        let (mut nodes, _hub) = mesh_sharing(4, &committee);
        run(&mut nodes); // handshakes

        let cp = Checkpoint::new(2, [0xAB; 32], [0xAB; 32]);
        let slices = [0..6usize, 6..11, 11..16, 16..21]; // 6/5/5/5, none ≥ 15
        for (i, sl) in slices.iter().enumerate() {
            let votes: Vec<Vote> =
                validators[sl.clone()].iter().map(|v| v.sign_checkpoint(&cp)).collect();
            assert!(votes.len() < 15, "node {i} holds {} < quorum keys", votes.len());
            nodes[i].announce_checkpoint(cp, votes);
        }
        run(&mut nodes);

        for (i, n) in nodes.iter().enumerate() {
            assert_eq!(
                n.node().finality().finalized_height(),
                Some(2),
                "node {i} must finalize via cross-node accumulation"
            );
        }
    }

    /// ACCEPTANCE #2 — a peer that sends honest below-quorum partial vote sets is
    /// NEVER penalised (task-book S5 / blocker 2). Five partials would have banned it
    /// under the old `Rejected → PENALTY_INVALID_OBJECT` scoring.
    #[test]
    fn partial_sets_do_not_penalise() {
        let (committee, validators) = devnet_committee(21); // quorum 15
        let (mut nodes, _hub) = mesh_sharing(2, &committee);
        run(&mut nodes);

        let cp = Checkpoint::new(2, [0x22; 32], [0x22; 32]);
        // Five distinct honest partial sets (10 votes total, always < quorum 15).
        let slices = [0..2usize, 2..4, 4..6, 6..8, 8..10];
        for sl in slices {
            let votes: Vec<Vote> = validators[sl].iter().map(|v| v.sign_checkpoint(&cp)).collect();
            nodes[0].announce_checkpoint(cp, votes);
            run(&mut nodes);
        }
        // Node 1 saw five honest partials from node 0 and did not score it at all.
        let score = nodes[1].peers().get(PeerId(1)).unwrap().score;
        assert_eq!(score, 0, "honest partial sets must not be penalised");
        assert!(!nodes[1].peers().is_banned(PeerId(1)), "the honest peer is not banned");
        // And nothing wrongly finalized (10 < 15).
        for n in &nodes {
            assert_eq!(n.node().finality().finalized_height(), None);
        }
    }

    /// ACCEPTANCE #3 — late votes for a checkpoint already known are still learnable
    /// (blocker 3 regression lock): a first set {0..5} then a SECOND set {6..10} of
    /// DIFFERENT votes for the SAME checkpoint accumulate to 11 across the mesh. With
    /// a 15-member committee (quorum 11), reaching 11 finalizes — proving the second
    /// set was not dedup-suppressed by the checkpoint-id `seen` cache.
    #[test]
    fn late_votes_for_a_known_checkpoint_are_learnable() {
        let (committee, validators) = devnet_committee(15); // quorum 11
        assert_eq!(committee.quorum_threshold(), 11);
        let (mut nodes, _hub) = mesh_sharing(3, &committee);
        run(&mut nodes);

        let cp = Checkpoint::new(2, [0xCC; 32], [0xCC; 32]);
        let first: Vec<Vote> = validators[0..6].iter().map(|v| v.sign_checkpoint(&cp)).collect();
        let second: Vec<Vote> = validators[6..11].iter().map(|v| v.sign_checkpoint(&cp)).collect();

        nodes[0].announce_checkpoint(cp, first); // {0..5} — 6 < 11, no finality
        run(&mut nodes);
        assert!(nodes.iter().all(|n| n.node().finality().finalized_height().is_none()));

        nodes[1].announce_checkpoint(cp, second); // {6..10} — same cp, different votes
        run(&mut nodes);
        for (i, n) in nodes.iter().enumerate() {
            assert_eq!(
                n.node().finality().finalized_height(),
                Some(2),
                "node {i}: 6 + 5 = 11 distinct votes for the SAME cp reached quorum"
            );
        }
    }

    /// ACCEPTANCE #4 (wire half) — a `CheckpointVotes` frame carrying a forge with
    /// a **resolvable** index is penalised over the wire (issue #164 criterion 3 /
    /// n7soak S2 forged-cp shape: valid member-1 sig claimed as signer 0).
    #[test]
    fn forged_votes_penalised_over_the_wire() {
        let (committee, validators) = devnet_committee(21);
        let (mut nodes, _hub) = mesh_sharing(2, &committee);
        run(&mut nodes);

        let cp = Checkpoint::new(2, [0x22; 32], [0x22; 32]);
        // Soak shape: in-roster signature under the wrong claimed index.
        // Index resolves; verify fails → Invalid → penalise.
        let forged = Vote {
            signer: 0,
            signature: validators[1].sign_checkpoint(&cp).signature,
        };
        let frame =
            Envelope::new(MsgType::CheckpointVotes, encode_checkpoint_votes(&cp, &[forged])).encode();
        // Node 0 (PeerId 1) injects the forged frame to node 1 (PeerId 2).
        nodes[0].transport().send(PeerId(2), &frame).unwrap();
        nodes[1].tick(0);

        let score = nodes[1].peers().get(PeerId(1)).unwrap().score;
        assert!(score < 0, "a forged vote set is penalised: score {score}");
        assert_eq!(nodes[1].node().finality().finalized_height(), None, "forged set moved nothing");
    }

    #[test]
    fn header_first_sync_catches_up_a_behind_node() {
        // Node 0 already has a 30-block chain; node 1 starts at genesis.
        let hub = InProcHub::new();
        let t0 = InProcTransport::new(PeerId(1), Arc::clone(&hub));
        let mut server = P2pNode::new(t0, stub(), [1; 32]);
        let mut parent = genesis();
        for i in 0..30u64 {
            let child = BlockHeader::child_of(&parent, (i + 1) * 75, 1000, [(i as u8) + 1; 32]);
            server.node_mut().ingest_header(child);
            parent = child;
        }
        assert_eq!(server.node().tip_height(), 30);

        let t1 = InProcTransport::new(PeerId(2), Arc::clone(&hub));
        let mut behind = P2pNode::new(t1, stub(), [2; 32]);

        hub.link(PeerId(1), PeerId(2));
        server.add_peer(PeerId(2), None);
        behind.add_peer(PeerId(1), None);

        let mut nodes = vec![server, behind];
        run(&mut nodes);

        assert_eq!(nodes[1].node().tip_height(), 30, "behind node synced to tip");
        assert_eq!(nodes[1].node().chain().tip_hash(), nodes[0].node().chain().tip_hash());
        assert_eq!(*nodes[1].sync_phase(), SyncPhase::Synced);
    }

    /// **Issue #106 — a node that has spoken to nobody never reports `Synced`.**
    ///
    /// The phase this asserts about used to be reachable by a node with an empty
    /// peer table: `best_height().unwrap_or(0) > tip` is false at height 0 with no
    /// peers, so the old `else` arm declared the node caught up on the strength of
    /// nothing at all. Everything downstream that asks "am I at the network's
    /// height?" — the #106 mining gate above all — was reading that answer.
    #[test]
    fn a_node_with_no_peers_never_claims_to_be_synced() {
        let hub = InProcHub::new();
        let t0 = InProcTransport::new(PeerId(1), Arc::clone(&hub));
        let mut lonely = P2pNode::new(t0, stub(), [1; 32]);

        for now in 0..5u64 {
            lonely.tick(now);
            assert_eq!(
                *lonely.sync_phase(),
                SyncPhase::Unknown,
                "no peer has claimed a height, so nothing is known"
            );
        }

        // A peer that connects but has not completed its handshake is not a claim
        // either: the phase only moves once a `Version` has been received.
        lonely.add_peer(PeerId(2), None);
        lonely.tick(6);
        assert_eq!(*lonely.sync_phase(), SyncPhase::Unknown, "mid-handshake claims nothing");
    }

    /// 🔴 **THE MIXED-VERSION FINDING (issue #130 (c)), test-locked.**
    ///
    /// The task book asked what a node does with an envelope type it does not know —
    /// ignore, disconnect, or penalise — because the answer decides whether an
    /// additive `MsgType` can be deployed onto a net running two images.
    ///
    /// **It penalises, and it bans on the FIRST FRAME.** `Envelope::decode` returns
    /// `WireError::UnknownMsgType`, `tick` maps every wire-layer decode failure to
    /// `PENALTY_MALFORMED` (100), and `BAN_THRESHOLD` is −100 — so one frame of an
    /// unallocated type is a permanent ban, with no second chance and no distinction
    /// between "you sent me garbage" and "you are newer than me".
    ///
    /// This test exists so the finding cannot be re-derived wrongly by the next
    /// baton, and so that if anyone later makes unknown types benign, the change
    /// shows up here as a deliberate edit rather than as a silent widening.
    ///
    /// It is why #130 (c) reuses `GetData(Block)` instead of allocating an envelope
    /// type: with three of four T0 hosts on the older image, a new node asking them
    /// for a body would have been banned by each of them on its first request.
    #[test]
    fn an_unknown_envelope_type_bans_the_sender_on_the_very_first_frame() {
        let (mut nodes, _hub) = mesh(2);
        run(&mut nodes);
        assert_eq!(nodes[1].peers().get(PeerId(1)).unwrap().score, 0, "starts clean");

        // A well-formed frame at the current protocol version whose type code is
        // unallocated — exactly what an additive `MsgType` looks like to a node that
        // predates it. Hand-built, because `Envelope::new` cannot express it.
        let unknown_type: u16 = 0x0044;
        assert!(MsgType::from_u16(unknown_type).is_none(), "0x0044 really is unallocated");
        let mut frame = Vec::new();
        frame.extend_from_slice(&crate::wire::MAGIC);
        frame.extend_from_slice(&crate::wire::PROTOCOL_VERSION.to_le_bytes());
        frame.extend_from_slice(&unknown_type.to_le_bytes());
        frame.extend_from_slice(&0u32.to_le_bytes()); // empty body
        assert_eq!(
            Envelope::decode(&frame),
            Err(crate::wire::WireError::UnknownMsgType { got: unknown_type })
        );

        nodes[0].transport().send(PeerId(2), &frame).unwrap();
        nodes[1].tick(0);

        assert_eq!(
            nodes[1].peers().get(PeerId(1)).unwrap().score,
            -crate::gossip::PENALTY_MALFORMED,
            "an unknown type is charged as a malformed frame — the strongest penalty"
        );
        assert!(
            nodes[1].peers().is_banned(PeerId(1)),
            "🔴 ONE frame of an unknown type is a ban: PENALTY_MALFORMED(100) meets \
             BAN_THRESHOLD(-100) exactly, so there is no budget for a version skew"
        );
    }

    /// The complement, and the reason the chosen shape is safe: **every message this
    /// baton puts on the wire is a type that already existed.** A node that predates
    /// #130 (c) decodes all of them.
    #[test]
    fn every_message_the_body_requester_sends_is_a_pre_existing_type() {
        for (mt, code) in [
            (MsgType::GetData, 0x0011u16),      // the request
            (MsgType::BlockAnnounce, 0x0041),   // the answer, whole-body
            (MsgType::Header, 0x0021),          // the answer when we hold no body
            (MsgType::NotFound, 0x0012),        // the answer when we hold nothing
        ] {
            assert_eq!(mt.as_u16(), code);
            assert_eq!(MsgType::from_u16(code), Some(mt), "0x{code:04x} predates this baton");
        }
        // And no code was allocated: the highest assigned type is still BlockTxn.
        assert_eq!(MsgType::BlockTxn.as_u16(), 0x0043);
        assert!(MsgType::from_u16(0x0044).is_none(), "nothing new was added");
    }

    #[test]
    fn compact_block_relay_reconstructs_from_mempool() {
        let (mut nodes, _hub) = mesh(2);
        run(&mut nodes);
        // Both nodes already hold t1, t2 in their mempools; node 0 announces a
        // block over them + a prefilled coinbase.
        let coinbase = tx(0);
        let t1 = tx(1);
        let t2 = tx(2);
        for n in nodes.iter_mut() {
            n.node_mut().ingest_tx(t1.clone());
            n.node_mut().ingest_tx(t2.clone());
        }
        let body_txs = vec![coinbase, t1, t2];
        let header = header_over(&genesis(), 75, &body_txs, 0);
        let bh = header.header_hash();
        nodes[0].announce_block(header, body_txs, 0, [0; 4], 0xABCD);
        run(&mut nodes);
        // Node 1 reconstructed and ingested the header.
        assert!(nodes[1].node().has_header(&bh));
    }

    #[test]
    fn compact_block_relay_fetches_missing_tx() {
        let (mut nodes, _hub) = mesh(2);
        run(&mut nodes);
        let coinbase = tx(0);
        let t1 = tx(1);
        let t2 = tx(2);
        // Only node 0 has t2; node 1 must GetBlockTxn it.
        nodes[0].node_mut().ingest_tx(t1.clone());
        nodes[0].node_mut().ingest_tx(t2.clone());
        nodes[1].node_mut().ingest_tx(t1.clone());
        let body_txs = vec![coinbase, t1, t2.clone()];
        let header = header_over(&genesis(), 75, &body_txs, 0);
        let bh = header.header_hash();
        nodes[0].announce_block(header, body_txs, 0, [0; 4], 0x1234);
        run(&mut nodes);
        assert!(nodes[1].node().has_header(&bh), "header ingested after fetching missing tx");
        assert!(nodes[1].node().has_tx(&tx_id(&t2)), "missing tx fetched into mempool");
    }

    /// M10-T0-1 item 6: a block announced whose parent is unknown must trigger
    /// header-first sync toward the announcer (it was previously dropped).
    #[test]
    fn orphan_block_announce_kicks_header_sync() {
        let (mut nodes, _hub) = mesh(2);
        run(&mut nodes); // handshake both ways to ready
        assert_eq!(*nodes[1].sync_phase(), SyncPhase::Synced);

        // A block two above genesis: its parent (one above genesis) is unknown to
        // node 1, so ingesting it orphans.
        let unknown_parent = BlockHeader::child_of(&genesis(), 75, 1000, [200; 32]);
        let orphan_block = header_over(&unknown_parent, 150, &[tx(0)], 0);
        // Node 0 announces it (prefilled coinbase, no short ids → node 1
        // reconstructs immediately and runs complete_block).
        nodes[0].announce_block(orphan_block, vec![tx(0)], 0, [0; 4], 0xABCD);
        nodes[1].tick(0);

        // Node 1 kicked header-first sync toward the announcer (PeerId 1), rather
        // than silently dropping the orphan.
        assert!(
            matches!(nodes[1].sync_phase(), SyncPhase::AwaitingHeaders { peer, .. } if *peer == PeerId(1)),
            "orphan announce must kick sync toward the announcer, got {:?}",
            nodes[1].sync_phase()
        );
        // And it did not adopt the orphan as a known header.
        assert!(!nodes[1].node().has_header(&orphan_block.header_hash()));
    }

    /// **Issue #77 at the relay seam: the honest header announced with an EMPTY
    /// body.** The announcer controls the prefilled txs and the salt, so
    /// "reconstruction succeeded" is no evidence the body is the header's body.
    /// The receiver must reject it, penalise the announcer (P2), and — the part
    /// that makes it a *propagating* exploit — neither cache nor re-announce it.
    #[test]
    fn announced_body_that_is_not_the_headers_body_is_rejected_and_penalised() {
        let (mut nodes, _hub) = mesh(3);
        run(&mut nodes); // handshake
        // A header committing to a real one-tx body…
        let honest = vec![tx(1)];
        let header = header_over(&genesis(), 75, &honest, 0);
        let bh = header.header_hash();
        // …announced with no transactions at all (fully-prefilled, empty).
        let (prefilled, short_ids) = build_announce_parts(&[], 0xBEEF);
        let ann = BlockAnnounce {
            header,
            nonce: 0xBEEF,
            coinbase: 0,
            coinbase_rkm: [0; 4],
            short_ids,
            prefilled,
        };
        // Node 0 (PeerId 1) pushes it straight at node 1 (PeerId 2).
        nodes[0].send(PeerId(2), MsgType::BlockAnnounce, encode_announce(&ann));
        nodes[1].tick(0);

        assert!(
            nodes[1].peers().get(PeerId(1)).unwrap().score < 0,
            "the announcer of an unbound body is penalised"
        );
        assert!(!nodes[1].node().has_header(&bh), "the header was not adopted");
        assert!(!nodes[1].blocks.contains(&bh), "the body was not cached for serving");
        // …and it was not re-announced onward to node 2.
        nodes[2].tick(0);
        assert!(!nodes[2].node().has_header(&bh), "a rejected block is not relayed");
    }

    /// The own-announce seam (`announce_block`): a locally-produced block whose
    /// body its own node rejects is never put on the wire.
    #[test]
    fn own_announce_of_an_unbound_body_is_not_relayed() {
        let (mut nodes, _hub) = mesh(2);
        run(&mut nodes);
        // Header commits to a one-tx body; we hand announce_block a different one.
        let header = header_over(&genesis(), 75, &[tx(1)], 0);
        let bh = header.header_hash();
        nodes[0].announce_block(header, vec![tx(2)], 0, [0; 4], 0xFEED);
        run(&mut nodes);
        assert!(!nodes[0].blocks.contains(&bh), "not cached locally");
        assert!(!nodes[1].node().has_header(&bh), "never announced to the peer");
    }

    // ── issue #135: the body-serving cache is bounded ────────────────────────

    /// A cache entry: `height` names it, `proof_len` sizes it (the metered weight
    /// is `proof_len + 112 + 40` — one nullifier, one commitment, per [`tx`]'s
    /// shape). The hash is derived from the height so entries stay distinct.
    fn cache_insert(c: &mut ServedBodies, height: u64, proof_len: usize) -> Hash32 {
        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&height.to_le_bytes());
        let entry = TxEntry {
            proof: vec![0xBB; proof_len],
            public: TxPublic {
                anchor: [1; 32],
                nullifiers: vec![[2; 32]],
                commitments: vec![[3; 32]],
                bucket: ArityBucket::TwoByTwo,
                fee: 0,
            },
        };
        c.insert(height, hash, vec![entry], 0, [0; 4]);
        hash
    }

    /// The rule, not just the ceiling: at the entry cap the cache keeps the
    /// HIGHEST heights — and provably by height, not by insertion order, which is
    /// why the heights arrive interleaved (evens ascending, then odds descending).
    #[test]
    fn serving_cache_keeps_the_highest_heights_at_the_entry_cap() {
        let mut c = ServedBodies::new();
        let total = MAX_SERVED_BODIES as u64 + 8;
        let mut hashes = HashMap::new();
        for h in (1..=total).filter(|h| h % 2 == 0) {
            hashes.insert(h, cache_insert(&mut c, h, 0));
        }
        for h in (1..=total).filter(|h| h % 2 == 1).rev() {
            hashes.insert(h, cache_insert(&mut c, h, 0));
        }
        assert_eq!(c.len(), MAX_SERVED_BODIES, "the map stopped growing at the bound");
        for h in 1..=8 {
            assert!(!c.contains(&hashes[&h]), "height {h} is the least useful and was evicted");
        }
        for h in 9..=total {
            assert!(c.contains(&hashes[&h]), "height {h} is within the window and was kept");
        }
    }

    /// The byte budget binds when entries are fat — and keeps at least one body,
    /// because a single body over the whole budget is one this node just announced
    /// and must still be able to serve.
    #[test]
    fn serving_cache_byte_budget_binds_and_keeps_at_least_one_body() {
        let mut c = ServedBodies::new();
        let three_mib = 3 * 1024 * 1024;
        let h1 = cache_insert(&mut c, 1, three_mib);
        let h2 = cache_insert(&mut c, 2, three_mib);
        assert_eq!(c.len(), 2, "6 MiB fits the 8 MiB budget");
        let h3 = cache_insert(&mut c, 3, three_mib);
        assert!(c.bytes <= MAX_SERVED_BODY_BYTES, "the budget holds after eviction");
        assert!(!c.contains(&h1), "lowest height paid for the overflow");
        assert!(c.contains(&h2) && c.contains(&h3));

        let mut solo = ServedBodies::new();
        let big = cache_insert(&mut solo, 1, MAX_SERVED_BODY_BYTES + 1);
        assert!(solo.contains(&big), "a single over-budget body is kept, not thrashed");
        assert_eq!(solo.len(), 1);
    }

    /// A re-completed hash (re-announce after restart) replaces its entry without
    /// double-counting the byte meter — the drift (a) guards against in
    /// `pending_bytes`, guarded here for the same reason.
    #[test]
    fn serving_cache_replaces_a_re_announced_hash_without_double_counting() {
        let mut c = ServedBodies::new();
        let hash = cache_insert(&mut c, 5, 1000);
        let once = c.bytes;
        let again = cache_insert(&mut c, 5, 1000);
        assert_eq!(hash, again);
        assert_eq!(c.len(), 1);
        assert_eq!(c.bytes, once, "replacement, not accumulation");
    }

    /// The bound holds at the announce surface, not just on the struct: a node
    /// that announces an unbounded chain of blocks serves a bounded window of it.
    /// (Pre-#135 this map grew by one body per accepted block, forever.)
    #[test]
    fn announcing_an_unbounded_chain_caches_a_bounded_serving_window() {
        let hub = InProcHub::new();
        let t = InProcTransport::new(PeerId(1), Arc::clone(&hub));
        let mut node = P2pNode::new(t, stub(), [1; 32]);

        let mut parent = genesis();
        let mut hashes = Vec::new();
        for i in 0..(MAX_SERVED_BODIES + 10) {
            let header = header_over(&parent, 75 * (i as u64 + 1), &[], i as u64);
            hashes.push(header.header_hash());
            node.announce_block(header, vec![], i as u64, [0; 4], i as u64);
            parent = header;
        }
        let (entries, bytes) = node.served_bodies();
        assert_eq!(entries, MAX_SERVED_BODIES, "the map stopped growing at the bound");
        assert_eq!(bytes, MAX_SERVED_BODIES * 40, "40 B per empty body on the shared meter");
        for bh in &hashes[..10] {
            assert!(!node.blocks.contains(bh), "the oldest blocks were evicted");
        }
        for bh in &hashes[10..] {
            assert!(node.blocks.contains(bh), "the newest {MAX_SERVED_BODIES} still serve");
        }
    }

    /// A [`StubNode`] with an applied-body store bolted on — the smallest
    /// `NodeState` whose `stored_body` answers, so the store-fallback serving path
    /// is testable at the P2P surface. (The REAL store side — `NodeAdapter` over
    /// the state machine's block store — has its own test in `adapter.rs`.)
    struct StoreStub {
        inner: StubNode,
        bodies: HashMap<Hash32, BlockBody>,
    }

    impl StoreStub {
        fn new() -> Self {
            StoreStub { inner: stub(), bodies: HashMap::new() }
        }
    }

    impl ChainView for StoreStub {
        fn genesis_hash(&self) -> Hash32 {
            self.inner.genesis_hash()
        }
        fn tip_hash(&self) -> Hash32 {
            self.inner.tip_hash()
        }
        fn tip_height(&self) -> u64 {
            self.inner.tip_height()
        }
        fn header(&self, hash: &Hash32) -> Option<BlockHeader> {
            self.inner.header(hash)
        }
        fn main_chain_hash_at(&self, height: u64) -> Option<Hash32> {
            self.inner.main_chain_hash_at(height)
        }
        fn has_header(&self, hash: &Hash32) -> bool {
            self.inner.has_header(hash)
        }
        fn finalized_height(&self) -> Option<u64> {
            self.inner.finalized_height()
        }
        fn stored_body(&self, hash: &Hash32) -> Option<BlockBody> {
            self.bodies.get(hash).cloned()
        }
        fn has_stored_body(&self, hash: &Hash32) -> bool {
            self.bodies.contains_key(hash)
        }
    }

    impl BlockIngest for StoreStub {
        fn ingest_header(&mut self, header: BlockHeader) -> IngestOutcome {
            self.inner.ingest_header(header)
        }
        fn ingest_block(&mut self, header: BlockHeader, body: BlockBody) -> IngestOutcome {
            if qlab_devnet::body::check_body_binding(&header, &body).is_err() {
                return IngestOutcome::Rejected("body does not match header commitment");
            }
            let outcome = self.inner.ingest_header(header);
            // Mirror the adapter's shape: a body for a header we hold is folded in
            // (here: stored immediately — the stub has no lagging state machine).
            if matches!(outcome, IngestOutcome::Accepted | IngestOutcome::Duplicate) {
                self.bodies.insert(header.header_hash(), body);
            }
            outcome
        }
    }

    impl TxPool for StoreStub {
        fn ingest_tx(&mut self, tx: TxEntry) -> IngestOutcome {
            self.inner.ingest_tx(tx)
        }
        fn get_tx(&self, id: &Hash32) -> Option<TxEntry> {
            self.inner.get_tx(id)
        }
        fn has_tx(&self, id: &Hash32) -> bool {
            self.inner.has_tx(id)
        }
        fn all_txs(&self) -> Vec<TxEntry> {
            self.inner.all_txs()
        }
    }

    impl CheckpointIngest for StoreStub {
        fn ingest_checkpoint_votes(&mut self, cp: &Checkpoint, votes: &[Vote]) -> VotesOutcome {
            self.inner.ingest_checkpoint_votes(cp, votes)
        }
        fn has_checkpoint(&self, id: &Hash32) -> bool {
            self.inner.has_checkpoint(id)
        }
    }

    impl CommitteeControl for StoreStub {
        fn observe_votes(&mut self, cp: &Checkpoint, votes: &[Vote]) -> Vec<EquivocationEvidence> {
            self.inner.observe_votes(cp, votes)
        }
        fn apply_evidence(&mut self, ev: &EquivocationEvidence) -> Option<usize> {
            self.inner.apply_evidence(ev)
        }
        fn finality_status(&self) -> FinalityStatus {
            self.inner.finality_status()
        }
        fn is_tombstoned(&self, idx: usize) -> bool {
            self.inner.is_tombstoned(idx)
        }
    }

    /// **The acceptance property: `GetBlockTxn` still answers after eviction.**
    /// A body evicted from the cache but applied to the node's store is served
    /// from the store — the full reconstruct round-trip completes against a node
    /// whose cache no longer holds the block. And the store also gates
    /// re-requests: an announce for a body a node already stores asks for nothing.
    #[test]
    fn get_block_txn_is_answered_from_the_store_after_eviction() {
        let hub = InProcHub::new();
        let ta = InProcTransport::new(PeerId(1), Arc::clone(&hub));
        let tb = InProcTransport::new(PeerId(2), Arc::clone(&hub));
        hub.link(PeerId(1), PeerId(2));
        let mut a: P2pNode<InProcTransport, StoreStub> =
            P2pNode::new(ta, StoreStub::new(), [1; 32]);
        let mut b: P2pNode<InProcTransport, StoreStub> =
            P2pNode::new(tb, StoreStub::new(), [2; 32]);
        a.add_peer(PeerId(2), None);
        b.add_peer(PeerId(1), None);
        for round in 0..20u64 {
            if a.tick(round * SIM_TICK_MS) + b.tick(round * SIM_TICK_MS) == 0 {
                break;
            }
        }

        // A block whose body B cannot fully reconstruct: tx(1) rides prefilled
        // (slot 0), tx(2) hides behind a short id B has never seen.
        let txs = vec![tx(1), tx(2)];
        let header = header_over(&genesis(), 75, &txs, 0);
        let bh = header.header_hash();
        a.announce_block(header, txs.clone(), 0, [0; 4], 0xC0DE);
        assert!(a.blocks.contains(&bh) && a.node().has_stored_body(&bh));

        // Evict it from A's cache FOR REAL — through the eviction rule, by
        // burying it under MAX_SERVED_BODIES higher-height entries.
        for i in 0..MAX_SERVED_BODIES as u64 {
            cache_insert(&mut a.blocks, 100 + i, 0);
        }
        assert!(!a.blocks.contains(&bh), "evicted: the cache alone can no longer answer");
        assert!(a.node().has_stored_body(&bh), "…but the applied store still can");

        b.tick(1_000); // B: announce → tx(2) missing → GetBlockTxn to A
        assert!(b.pending_blocks.contains_key(&bh), "B is waiting on the missing tx");
        a.tick(1_010); // A: cache miss → store hit → BlockTxn
        b.tick(1_020); // B: reconstructs, ingests, stores
        assert!(b.node().has_header(&bh), "the block completed against an evicted cache");
        assert!(b.node().has_stored_body(&bh), "and B folded the body in");

        // Re-request gate: bury B's own cache copy, then re-deliver the announce.
        // B recognises the body from its store and asks for nothing.
        for i in 0..MAX_SERVED_BODIES as u64 {
            cache_insert(&mut b.blocks, 200 + i, 0);
        }
        assert!(!b.blocks.contains(&bh));
        let (prefilled, short_ids) = build_announce_parts(&txs, 0xC0DE);
        let ann = BlockAnnounce {
            header,
            nonce: 0xC0DE,
            coinbase: 0,
            coinbase_rkm: [0; 4],
            short_ids,
            prefilled,
        };
        a.send(PeerId(2), MsgType::BlockAnnounce, encode_announce(&ann));
        b.tick(2_000);
        assert!(
            b.pending_blocks.is_empty(),
            "an announce for a stored body re-requests nothing"
        );
    }

    #[test]
    fn malformed_frame_penalizes_sender() {
        let hub = InProcHub::new();
        let a = InProcTransport::new(PeerId(1), Arc::clone(&hub));
        let t1 = InProcTransport::new(PeerId(2), Arc::clone(&hub));
        hub.link(PeerId(1), PeerId(2));
        let mut node = P2pNode::new(t1, stub(), [2; 32]);
        node.add_peer(PeerId(1), None);
        // Send junk that is not a valid envelope.
        a.send(PeerId(2), &[0xFF; 20]).unwrap();
        node.tick(0);
        assert!(node.peers().get(PeerId(1)).unwrap().score < 0, "sender penalized");
    }

    // ── M9-N5: committee over network ───────────────────────────────────────

    /// Equivocation evidence path: one node holds proof that a member double-signed
    /// a slot; announcing it tombstones that member on EVERY node — the automated
    /// slash executing across the network with no human in the path (committee-gov
    /// §3).
    #[test]
    fn equivocation_evidence_gossip_tombstones_whole_network() {
        // mesh() builds independent-but-deterministic committees → identical keys,
        // so `validators` from a fresh build verify on every node.
        let (_c, validators) = devnet_committee(7);
        let (mut nodes, _hub) = mesh(3);
        run(&mut nodes);

        nodes[0].announce_evidence(conflicting_evidence(&validators, 3, 8));
        run(&mut nodes);

        for (i, n) in nodes.iter().enumerate() {
            assert!(n.node().is_tombstoned(3), "node {i} tombstoned the equivocator");
        }
    }

    /// A node that receives two conflicting checkpoints for the same slot detects
    /// the equivocation itself (no pre-packaged evidence) and gossips it, so the
    /// whole network converges on the tombstone.
    #[test]
    fn conflicting_checkpoints_auto_detected_and_propagated() {
        let (_c, validators) = devnet_committee(7); // quorum 5
        let (mut nodes, _hub) = mesh(3);
        run(&mut nodes);

        // Two checkpoints at height 8 with different block hashes; signer 3 is in
        // both vote sets (it equivocates). Node 1 originates one, node 2 the other;
        // node 0 receives both and detects.
        let cp_a = Checkpoint::new(8, [0xAA; 32], [0xAA; 32]);
        let cp_b = Checkpoint::new(8, [0xBB; 32], [0xBB; 32]);
        let votes_a: Vec<Vote> =
            [0, 1, 2, 3, 4].iter().map(|&s| validators[s].sign_checkpoint(&cp_a)).collect();
        let votes_b: Vec<Vote> =
            [3, 5, 6, 0, 1].iter().map(|&s| validators[s].sign_checkpoint(&cp_b)).collect();
        nodes[1].announce_checkpoint(cp_a, votes_a);
        nodes[2].announce_checkpoint(cp_b, votes_b);
        run(&mut nodes);

        // Signer 3 (in both) is tombstoned everywhere via the auto-detected evidence.
        for (i, n) in nodes.iter().enumerate() {
            assert!(n.node().is_tombstoned(3), "node {i} converged on the tombstone");
        }
    }

    /// NEGATIVE — tombstoned votes MUST NOT count toward quorum, over the network
    /// (frozen §4). With 3 of 7 tombstoned, a checkpoint carrying all 7 votes has
    /// only 4 that count (< quorum 5) and finalizes nowhere.
    #[test]
    fn tombstoned_vote_excluded_from_quorum_over_network() {
        let (_c, validators) = devnet_committee(7); // quorum 5
        let (mut nodes, _hub) = mesh(2);
        run(&mut nodes);

        // Tombstone signers 0,1,2 network-wide via gossiped evidence.
        for s in [0usize, 1, 2] {
            nodes[0].announce_evidence(conflicting_evidence(&validators, s, 90 + s as u64));
        }
        run(&mut nodes);
        for n in &nodes {
            for s in [0, 1, 2] {
                assert!(n.node().is_tombstoned(s));
            }
        }

        // A checkpoint at height 2 signed by ALL 7: the 3 tombstoned are dropped,
        // leaving 4 active < 5. The partial set now gossips (M10-T0-5), but the four
        // active votes can never reach quorum, so nothing finalizes anywhere.
        let cp = Checkpoint::new(2, [0x22; 32], [0x22; 32]);
        let votes: Vec<Vote> = validators.iter().map(|v| v.sign_checkpoint(&cp)).collect();
        nodes[0].announce_checkpoint(cp, votes.clone());
        nodes[1].announce_checkpoint(cp, votes);
        run(&mut nodes);
        for (i, n) in nodes.iter().enumerate() {
            assert_eq!(
                n.node().finality().finalized_height(),
                None,
                "node {i}: tombstoned votes must not reach quorum"
            );
        }
    }

    /// NEGATIVE — a checkpoint that does not strictly advance the finalized height
    /// is rejected over the network; finality stays where it was.
    #[test]
    fn non_advancing_checkpoint_rejected_over_network() {
        let (_c, validators) = devnet_committee(7);
        let (mut nodes, _hub) = mesh(3);
        run(&mut nodes);

        // Finalize height 8 across the network.
        let cp8 = Checkpoint::new(8, [8; 32], [8; 32]);
        let v8: Vec<Vote> = validators[..5].iter().map(|v| v.sign_checkpoint(&cp8)).collect();
        nodes[0].announce_checkpoint(cp8, v8);
        run(&mut nodes);
        for n in &nodes {
            assert_eq!(n.node().finality().finalized_height(), Some(8));
        }
        let counts: Vec<usize> = nodes.iter().map(|n| n.node().finality().count()).collect();

        // A lower checkpoint (height 4) with a valid quorum must NOT advance.
        let cp4 = Checkpoint::new(4, [4; 32], [4; 32]);
        let v4: Vec<Vote> = validators[..5].iter().map(|v| v.sign_checkpoint(&cp4)).collect();
        nodes[0].announce_checkpoint(cp4, v4.clone());
        nodes[1].announce_checkpoint(cp4, v4);
        run(&mut nodes);
        for (i, n) in nodes.iter().enumerate() {
            assert_eq!(n.node().finality().finalized_height(), Some(8), "node {i} unchanged");
            assert_eq!(n.node().finality().count(), counts[i], "no extra checkpoint recorded");
        }
    }

    /// Ebb-and-Flow over the network: with no committee finality the mesh runs in
    /// degraded probabilistic mode; a checkpoint near the tip restores Final on
    /// every node (consensus §4).
    #[test]
    fn finality_degrades_and_recovers_over_network() {
        let (_c, validators) = devnet_committee(7);
        let (mut nodes, _hub) = mesh(3);
        run(&mut nodes);

        // Grow a 20-block chain by gossip; nothing finalized ⇒ degraded everywhere.
        let mut parent = genesis();
        for i in 0..20u64 {
            let child = BlockHeader::child_of(&parent, (i + 1) * 75, 1000, [(i as u8) + 1; 32]);
            nodes[0].announce_header(child);
            parent = child;
        }
        run(&mut nodes);
        for n in &nodes {
            assert_eq!(n.finality_status(), FinalityStatus::Degraded, "no finality ⇒ degraded");
        }

        // Finalize the tip → Final on every node.
        let tip_h = nodes[0].node().tip_height();
        let tip_hash = nodes[0].node().chain().tip_hash();
        let cp = Checkpoint::new(tip_h, tip_hash, tip_hash);
        let votes: Vec<Vote> = validators[..5].iter().map(|v| v.sign_checkpoint(&cp)).collect();
        nodes[0].announce_checkpoint(cp, votes);
        run(&mut nodes);
        for n in &nodes {
            assert_eq!(n.finality_status(), FinalityStatus::Final, "finality resumes cleanly");
        }
    }

    /// Checkpoint cadence over the network: driving finalization on the 8-block
    /// grid (`next_checkpoint_height`) lands finality on the largest slot ≤ tip.
    #[test]
    fn checkpoints_follow_the_8_block_cadence() {
        let (_c, validators) = devnet_committee(7);
        let (mut nodes, _hub) = mesh(2);
        run(&mut nodes);

        let mut parent = genesis();
        for i in 0..20u64 {
            let child = BlockHeader::child_of(&parent, (i + 1) * 75, 1000, [(i as u8) + 1; 32]);
            nodes[0].announce_header(child);
            parent = child;
        }
        run(&mut nodes);

        let cadence = qlab_devnet::params_devnet::CHECKPOINT_CADENCE_BLOCKS; // 8
        let mut finalized: Option<u64> = None;
        while let Some(h) = next_checkpoint_height(finalized, nodes[0].node().tip_height(), cadence) {
            let bh = nodes[0].node().chain().main_chain()[h as usize];
            let cp = Checkpoint::new(h, bh, bh);
            let votes: Vec<Vote> = validators[..5].iter().map(|v| v.sign_checkpoint(&cp)).collect();
            nodes[0].announce_checkpoint(cp, votes);
            run(&mut nodes);
            finalized = Some(h);
        }
        // Tip 20 → slots 8, 16 finalize; 24 is not reached.
        assert_eq!(finalized, Some(16));
        for n in &nodes {
            assert_eq!(n.node().finality().finalized_height(), Some(16));
        }
    }

    /// Epoch membership machinery over the network: the committee advances epochs
    /// as the gossiped chain crosses boundaries (committee-gov §2). Uses a small
    /// epoch so a short chain crosses one.
    #[test]
    fn epoch_advances_with_the_chain_over_network() {
        let (committee, validators) = devnet_committee(7);
        let sched = EpochSchedule::new(8); // small epoch: boundary at height 8
        let hub = InProcHub::new();
        let mut nodes: Vec<InProcP2p> = (0..2)
            .map(|i| {
                let t = InProcTransport::new(PeerId(i + 1), Arc::clone(&hub));
                let ec = EpochCommittee::genesis(
                    sched,
                    CommitteeState::new(committee.clone(), BOND_AMOUNT),
                );
                P2pNode::new(t, StubNode::with_epoch(genesis(), ec), [i as u8 + 1; 32])
            })
            .collect();
        hub.link(PeerId(1), PeerId(2));
        nodes[0].add_peer(PeerId(2), None);
        nodes[1].add_peer(PeerId(1), None);
        run(&mut nodes);

        // Grow the chain to height 10 (crosses the height-8 boundary) via gossip.
        let mut parent = genesis();
        for i in 0..10u64 {
            let child = BlockHeader::child_of(&parent, (i + 1) * 75, 1000, [(i as u8) + 1; 32]);
            nodes[0].announce_header(child);
            parent = child;
        }
        run(&mut nodes);
        for (i, n) in nodes.iter().enumerate() {
            assert_eq!(n.node().committee().current_epoch(), 1, "node {i} sealed epoch 0");
            // No membership change was staged, so the epoch-1 roster is the genesis
            // set intact — all members Active.
            let st = n.node().committee().state();
            for idx in 0..st.size() {
                assert_eq!(st.status(idx), Some(MemberStatus::Active));
            }
        }

        // A checkpoint in epoch 1 still finalizes against the (unchanged) committee.
        let bh = nodes[0].node().chain().main_chain()[8];
        let cp = Checkpoint::new(8, bh, bh);
        let votes: Vec<Vote> = validators[..5].iter().map(|v| v.sign_checkpoint(&cp)).collect();
        nodes[0].announce_checkpoint(cp, votes);
        run(&mut nodes);
        for n in &nodes {
            assert_eq!(n.node().finality().finalized_height(), Some(8));
        }
    }

    // ================= peer discovery (issue #83) =================

    fn addr_of(i: u64) -> String {
        format!("n{i}:9333")
    }

    /// A discovery net: `n` nodes, each **bound** at `n{i}:9333` and declaring that
    /// address reachable, but with NO links and NO peers — everything about who
    /// reaches whom comes from seeds and gossip, as on a real net.
    fn disc_net(n: u64) -> (Vec<InProcP2p>, Arc<InProcHub>) {
        let hub = InProcHub::new();
        let mut nodes = Vec::new();
        for i in 0..n {
            let t = InProcTransport::new(PeerId(i + 1), Arc::clone(&hub));
            hub.bind_addr(&addr_of(i), PeerId(i + 1));
            let mut node = P2pNode::new(t, stub(), [i as u8 + 1; 32]);
            node.addrs_mut().set_self_advertise(Some(addr_of(i)));
            nodes.push(node);
        }
        (nodes, hub)
    }

    /// Alternate maintenance passes with message pumping, stepping the logical
    /// clock past the per-peer `GetAddr` rate limit each round.
    fn run_discovery(nodes: &mut [InProcP2p], rounds: usize) {
        let mut now = 0u64;
        for _ in 0..rounds {
            for n in nodes.iter_mut() {
                n.maintain(now);
            }
            run_at(nodes, now);
            now += crate::addrman::GETADDR_INTERVAL_MS;
        }
    }

    #[test]
    fn seed_only_node_learns_the_mesh_and_connects() {
        // Acceptance item 1. Nodes 1..3 are seeded with each other; node 0 knows
        // ONE address and must discover the rest.
        let (mut nodes, _hub) = disc_net(4);
        for i in 1..4u64 {
            for j in 1..4u64 {
                if i != j {
                    nodes[i as usize].addrs_mut().add_seed(addr_of(j));
                }
            }
        }
        nodes[0].addrs_mut().add_seed(addr_of(1));
        assert_eq!(nodes[0].addrs().known_count(), 1, "one seed, nothing else");

        run_discovery(&mut nodes, 4);

        let known = nodes[0].addrs().known();
        assert!(known.contains(&addr_of(2)), "learned n2 from the seed's book: {known:?}");
        assert!(known.contains(&addr_of(3)), "learned n3 from the seed's book: {known:?}");
        assert_eq!(nodes[0].addrs().dialable_count(), 3, "and dialed all three");
        for j in 1..4u64 {
            assert!(
                nodes[0].peers().is_ready(PeerId(j + 1)),
                "handshake completed with n{j}"
            );
        }
    }

    #[test]
    fn tcp_maintenance_collects_an_async_dial_without_restarting_it() {
        use std::time::{Duration, Instant};

        let server = TcpTransport::bind("127.0.0.1:0").unwrap();
        let target = server.local_addr().to_string();
        let client = TcpTransport::bind("127.0.0.1:0").unwrap();
        let mut node = P2pNode::new(client, stub(), [1; 32]);
        node.addrs_mut().add_seed(target.clone());

        assert_eq!(node.maintain(0), 0, "TCP connect is pending, never completed inline");
        assert!(
            node.addrs().next_dials(0).is_empty(),
            "the pending connector reserves its slot and cannot be started twice"
        );

        let started = Instant::now();
        while node.addrs().outbound_live() == 0 {
            node.tick(started.elapsed().as_millis() as u64);
            assert!(started.elapsed() < Duration::from_secs(1), "loopback dial never completed");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(node.addrs().dialable_count(), 1);
        assert_eq!(node.addrs().entry(&target).unwrap().failures, 0);

        server.shutdown();
        node.transport().shutdown();
    }

    #[test]
    fn dial_line_success_carries_addr_and_duration() {
        // Issue #137: the duration is the number #107 needed — a slow *success*
        // (131 s connect floor) must be as visible as a failure.
        let line = dial_line("10.0.0.7:9400", 131_072, &Ok(PeerId(3)));
        assert_eq!(line, "DIAL addr=10.0.0.7:9400 ms=131072 result=ok");
    }

    #[test]
    fn dial_line_failure_carries_duration_and_error() {
        // Issue #137's failure-side decision: a dial that dies in 3 ms (refused)
        // and one that dies after 127 s (kernel SYN retries exhausted) are
        // different operational events, so failures log the duration too.
        let err = Err(TransportError::Io("connection timed out".to_string()));
        let line = dial_line("10.0.0.7:9400", 127_000, &err);
        assert_eq!(
            line,
            "DIAL addr=10.0.0.7:9400 ms=127000 result=err err=\"transport io: connection timed out\""
        );
    }

    #[test]
    fn a_node_that_is_not_dialable_is_never_gossiped() {
        // Acceptance item 2, both directions. Node 0 is outbound-only: it is not
        // bound to any address and declares none (a home node behind a router).
        let hub = InProcHub::new();
        let t0 = InProcTransport::new(PeerId(1), Arc::clone(&hub));
        let mut n0 = P2pNode::new(t0, stub(), [1; 32]);
        let t1 = InProcTransport::new(PeerId(2), Arc::clone(&hub));
        hub.bind_addr(&addr_of(1), PeerId(2));
        let mut n1 = P2pNode::new(t1, stub(), [2; 32]);
        n1.addrs_mut().set_self_advertise(Some(addr_of(1)));
        // n1 also hears about an address that never answers.
        n1.addrs_mut().learn(vec!["unreachable:9333".to_string()]);

        n0.addrs_mut().add_seed(addr_of(1));
        let mut nodes = vec![n0, n1];
        run_discovery(&mut nodes, 3);

        // Direction 1 — it IS connected, and both sides know it.
        assert!(nodes[0].peers().is_ready(PeerId(2)), "the outbound-only node is connected");
        assert!(
            nodes[1].peers().all_peers().contains(&PeerId(1)),
            "the serving side has it as a live peer"
        );
        // Direction 2 — and it appears in nothing we serve.
        let served = nodes[1].addrs().gossipable();
        assert_eq!(served, vec![addr_of(1)], "only n1's own declared address: {served:?}");
        assert!(
            nodes[1].addrs().known().contains(&"unreachable:9333".to_string()),
            "a never-reached candidate stays known…"
        );
        assert!(
            !served.contains(&"unreachable:9333".to_string()),
            "…but is never handed out (S2)"
        );
        // The outbound-only node learned nothing unreachable from the exchange.
        assert_eq!(nodes[0].addrs().known(), vec![addr_of(1)]);
    }

    #[test]
    fn auto_connect_stops_at_the_outbound_cap() {
        // Scope 5+6: the cap ships WITH auto-connect. Five reachable seeds, cap 2.
        let (mut nodes, _hub) = disc_net(6);
        nodes[0].addrs_mut().set_max_outbound(2);
        for j in 1..6u64 {
            nodes[0].addrs_mut().add_seed(addr_of(j));
        }
        run_discovery(&mut nodes, 3);
        assert_eq!(nodes[0].addrs().outbound_live(), 2, "never above the cap");
        assert_eq!(nodes[0].addrs().dialable_count(), 2, "and only what it dialed");
    }

    /// A bare transport that is not a node — lets a test observe the exact frames
    /// a node emits.
    fn sniffer(hub: &Arc<InProcHub>, id: PeerId, addr: &str) -> InProcTransport {
        let t = InProcTransport::new(id, Arc::clone(hub));
        hub.bind_addr(addr, id);
        t
    }

    fn count_msgs(frames: &[(PeerId, Vec<u8>)], want: MsgType) -> usize {
        frames
            .iter()
            .filter(|(_, f)| Envelope::decode(f).map(|e| e.msg_type == want).unwrap_or(false))
            .count()
    }

    #[test]
    fn getaddr_is_asked_once_per_peer_per_interval() {
        // Scope 2: the book grows without a flood.
        let hub = InProcHub::new();
        let t0 = InProcTransport::new(PeerId(1), Arc::clone(&hub));
        let mut n0 = P2pNode::new(t0, stub(), [1; 32]);
        let sniff = sniffer(&hub, PeerId(2), "sniff:9333");
        n0.addrs_mut().add_seed("sniff:9333".to_string());

        // Dial + handshake: the sniffer answers the Version so n0's peer goes Ready.
        n0.maintain(0);
        let v = VersionMsg { node_id: [2; 32], services: 1, tip_height: 0, user_agent: "s".into() };
        sniff.send(PeerId(1), &Envelope::new(MsgType::Version, v.encode()).encode()).unwrap();
        sniff.send(PeerId(1), &Envelope::new(MsgType::VerAck, vec![]).encode()).unwrap();
        n0.tick(0);
        let _ = sniff.poll();

        n0.maintain(1);
        n0.maintain(2);
        n0.maintain(crate::addrman::GETADDR_INTERVAL_MS - 1);
        assert_eq!(
            count_msgs(&sniff.poll(), MsgType::GetAddr),
            1,
            "three passes inside the interval ask once"
        );
        // The first ask was recorded at t=1 (the pass at t=0 preceded the
        // handshake), so the interval elapses at INTERVAL+1.
        n0.maintain(crate::addrman::GETADDR_INTERVAL_MS + 1);
        assert_eq!(count_msgs(&sniff.poll(), MsgType::GetAddr), 1, "and again after it elapses");
    }

    #[test]
    fn a_malformed_addr_frame_is_scored_but_a_bogus_address_is_not() {
        // S6: a peer's claim about a third party is a candidate at best. If a bad
        // *address* were a scoring event, any peer could get another penalised.
        let hub = InProcHub::new();
        let t0 = InProcTransport::new(PeerId(1), Arc::clone(&hub));
        let mut n0 = P2pNode::new(t0, stub(), [1; 32]);
        let sniff = sniffer(&hub, PeerId(2), "sniff:9333");
        hub.link(PeerId(2), PeerId(1));

        // Well-formed frame carrying unusable addresses → no penalty, nothing learned.
        let payload = crate::peer::encode_addrs(&[
            "not-an-address".to_string(),
            "host:0".to_string(),
            "good:9333".to_string(),
        ]);
        sniff.send(PeerId(1), &Envelope::new(MsgType::Addr, payload).encode()).unwrap();
        n0.tick(0);
        assert_eq!(n0.peers().get(PeerId(2)).unwrap().score, 0, "no score for a third party");
        assert_eq!(n0.addrs().known(), vec!["good:9333".to_string()], "only the usable one");

        // A frame we cannot decode is the *sender's* own malformed message.
        sniff.send(PeerId(1), &Envelope::new(MsgType::Addr, vec![9, 9, 9]).encode()).unwrap();
        n0.tick(0);
        assert_eq!(n0.peers().get(PeerId(2)).unwrap().score, -PENALTY_MALFORMED);
    }

    #[test]
    fn a_message_flood_is_dropped_at_the_limit_and_never_scores_the_peer() {
        // Gap 1 wired end to end: the GetAddr limit covers the amplifier, this is
        // the general one that stops ANY message type being poured in at any rate.
        // Small explicit limits so the test states the bound instead of the
        // default's size.
        let hub = InProcHub::new();
        let t0 = InProcTransport::new(PeerId(1), Arc::clone(&hub));
        let mut n0 = P2pNode::new(t0, stub(), [1; 32]);
        let sniff = sniffer(&hub, PeerId(2), "sniff:9333");
        hub.link(PeerId(2), PeerId(1));
        n0.set_rate_limits(RateLimits {
            msg_burst: 8,
            msg_refill_per_sec: 1,
            ..RateLimits::default()
        });

        let ping = Envelope::new(MsgType::Ping, vec![]).encode();
        // Exactly at the burst: every one is processed (a Ping answers with a Pong).
        for _ in 0..8 {
            sniff.send(PeerId(1), &ping).unwrap();
        }
        n0.tick(0);
        assert_eq!(count_msgs(&sniff.poll(), MsgType::Pong), 8, "at the burst, all served");
        assert_eq!(n0.rate_stats().throttled_frames, 0);

        // Past it: dropped, silently, and with no score.
        for _ in 0..5 {
            sniff.send(PeerId(1), &ping).unwrap();
        }
        n0.tick(0);
        assert_eq!(count_msgs(&sniff.poll(), MsgType::Pong), 0, "over the burst, dropped");
        assert_eq!(n0.rate_stats().throttled_frames, 5, "and counted");
        assert_eq!(
            n0.peers().get(PeerId(2)).unwrap().score,
            0,
            "decision 2: too fast is not wrong — throttling never scores"
        );
        assert!(!n0.peers().is_banned(PeerId(2)));

        // A throttle, not a verdict: one second on, the budget has refilled and the
        // peer is served again without anyone having had to forgive it.
        sniff.send(PeerId(1), &ping).unwrap();
        n0.tick(1_000);
        assert_eq!(count_msgs(&sniff.poll(), MsgType::Pong), 1, "refilled, still a peer");
    }

    #[test]
    fn an_oversized_stream_is_dropped_at_the_byte_budget() {
        // The other half of gap 2, at the node layer: MAX_PAYLOAD bounds one frame,
        // the byte budget bounds the stream. Frame count is left generous so it is
        // unambiguously the BYTE budget doing the work.
        let hub = InProcHub::new();
        let t0 = InProcTransport::new(PeerId(1), Arc::clone(&hub));
        let mut n0 = P2pNode::new(t0, stub(), [1; 32]);
        let sniff = sniffer(&hub, PeerId(2), "sniff:9333");
        hub.link(PeerId(2), PeerId(1));

        let body = vec![7u8; 1_000];
        let frame = Envelope::new(MsgType::Ping, body).encode();
        let frame_len = frame.len() as u64;
        n0.set_rate_limits(RateLimits {
            byte_burst: frame_len * 3,
            byte_refill_per_sec: 1,
            ..RateLimits::default()
        });

        // Exactly at the byte budget: all three accepted.
        for _ in 0..3 {
            sniff.send(PeerId(1), &frame).unwrap();
        }
        n0.tick(0);
        assert_eq!(count_msgs(&sniff.poll(), MsgType::Pong), 3, "exactly at the byte budget");
        assert_eq!(n0.rate_stats().throttled_bytes, 0);

        // The fourth is over it, and it is the byte budget that says so.
        sniff.send(PeerId(1), &frame).unwrap();
        n0.tick(0);
        assert_eq!(count_msgs(&sniff.poll(), MsgType::Pong), 0);
        assert_eq!(n0.rate_stats().throttled_bytes, 1);
        assert_eq!(n0.rate_stats().throttled_frames, 0, "the frame budget was not the binding one");
        assert_eq!(n0.peers().get(PeerId(2)).unwrap().score, 0);
    }

    #[test]
    fn a_gossiped_flood_of_one_netgroup_cannot_eclipse_the_outbound_set() {
        // Issue #91 gap 3, end to end through the path that actually matters: an
        // attacker hands us a big `Addr` message full of addresses it controls, all
        // of them genuinely dialable, and we auto-connect. Without a diversity rule
        // every outbound slot ends up inside the attacker's network — which is the
        // eclipse, and it needs no invalid message anywhere.
        let hub = InProcHub::new();
        let t0 = InProcTransport::new(PeerId(1), Arc::clone(&hub));
        let mut n0 = P2pNode::new(t0, stub(), [1; 32]);

        // Bind reachable endpoints: 60 attacker addresses inside ONE /16, and three
        // honest networks of 3 each.
        let mut handle = 100u64;
        let mut bind = |addr: &str, h: &mut u64| {
            let _t = InProcTransport::new(PeerId(*h), Arc::clone(&hub));
            hub.bind_addr(addr, PeerId(*h));
            *h += 1;
        };
        let attacker: Vec<String> =
            (0..60).map(|i| format!("10.7.{}.{}:9333", i / 256, i % 256)).collect();
        for a in &attacker {
            bind(a, &mut handle);
        }
        let honest: Vec<String> = (0..3)
            .flat_map(|g| (0..3).map(move |i| format!("198.5{g}.100.{i}:9333")))
            .collect();
        for a in &honest {
            bind(a, &mut handle);
        }

        // The attacker peer gossips all 60 of its addresses in one legal `Addr`
        // message (MAX_ADDRS_PER_MSG = 100, so this is well-formed and free).
        let sniff = sniffer(&hub, PeerId(2), "10.7.255.255:9333");
        hub.link(PeerId(2), PeerId(1));
        let mut all = attacker.clone();
        all.extend(honest.clone());
        assert!(all.len() <= crate::addrman::MAX_ADDRS_PER_MSG);
        sniff
            .send(PeerId(1), &Envelope::new(MsgType::Addr, crate::peer::encode_addrs(&all)).encode())
            .unwrap();
        n0.tick(0);

        // Auto-connect under the caps.
        n0.maintain(0);
        let groups = n0.addrs().outbound_groups();

        assert_eq!(
            n0.addrs().outbound_live(),
            crate::addrman::MAX_OUTBOUND,
            "the budget still fills — diversity must not cost liveness: {groups:?}"
        );
        assert!(
            groups.get("v4:10.7").copied().unwrap_or(0) <= crate::addrman::MAX_OUTBOUND_PER_GROUP,
            "60 gossiped addresses from one /16 took {:?} of {} slots",
            groups.get("v4:10.7"),
            crate::addrman::MAX_OUTBOUND
        );
        assert!(
            groups.len() >= 4,
            "the outbound set spans at least 4 networks, so no single one owns it: {groups:?}"
        );
        assert_eq!(
            n0.peers().get(PeerId(2)).unwrap().score,
            0,
            "and the gossiper was not penalised — flooding addresses is not a protocol fault"
        );
    }

    #[test]
    fn a_dropped_peer_is_redialed_after_backoff() {
        // The S9 property, now on the single dial path: a healed partition
        // reconnects with no process restart.
        let (mut nodes, hub) = disc_net(2);
        nodes[0].addrs_mut().add_seed(addr_of(1));
        run_discovery(&mut nodes, 2);
        assert_eq!(nodes[0].addrs().outbound_live(), 1);

        // Partition: the link is cut and the handle goes away.
        hub.unlink(PeerId(1), PeerId(2));
        nodes[0].addrs_mut().on_disconnect(PeerId(2));
        assert_eq!(nodes[0].addrs().outbound_live(), 0);
        assert!(
            nodes[0].addrs().gossipable().contains(&addr_of(1)),
            "a partition is not proof of unreachability"
        );

        // Heal: the next maintenance pass re-dials.
        nodes[0].maintain(crate::addrman::DIAL_BACKOFF_MAX_MS * 2);
        assert_eq!(nodes[0].addrs().outbound_live(), 1, "reconnected without a restart");
    }

    // --- issue #134: the scoring half, over the real gossip path ---------------

    mod i134 {
        //! A joiner must not ban the honest peers that serve it correct history.
        //!
        //! `adapter.rs` locks the *classification* (an anchor this node cannot judge is
        //! `Ignored`, not `Rejected`). This module locks what the classification is
        //! **for**: a real [`PeerTable`] score, moved by the real
        //! `BlockAnnounce` → `complete_block` → `is_peer_fault` → `penalize` path, on a
        //! chain whose every block carries a transaction.

        use std::sync::Arc;

        use qlab_devnet::body::{BlockBody, TxEntry, TxPublic, TxVerifier};
        use qlab_devnet::committee::{devnet_committee, CommitteeState};
        use qlab_devnet::fees::{posted_fee, ArityBucket};
        use qlab_devnet::header::{BlockHeader, Hash32};
        use qlab_devnet::node::SimConfig;
        use qlab_devnet::params_devnet::BOND_AMOUNT;
        use qlab_devnet::pow::KeccakPow;
        use qlab_node::NodeState as _;

        use crate::adapter::NodeAdapter;
        use crate::n1::{IngestOutcome, TxPool};
        use crate::node::P2pNode;
        use crate::peer::{PeerId, BAN_THRESHOLD};
        use crate::transport::{InProcHub, InProcTransport};

        /// A proof is valid iff its bytes are `b"ok"` — the same stand-in `adapter.rs`
        /// and the n7 soak use, so a body's validity here turns on the checks under
        /// test rather than on the prover.
        ///
        /// `strict: false` is how the second test builds a peer that will **serve** a
        /// body this node refuses: a broken or hostile node whose own verifier waves
        /// the proof through. Nothing else about it differs — same genesis, same PoW,
        /// same mined header — so the only variable between the two tests below is the
        /// body, which is the comparison the acceptance bar asks for.
        #[derive(Clone)]
        struct MockVerifier {
            strict: bool,
        }
        impl TxVerifier for MockVerifier {
            fn verify_tx(&self, entry: &TxEntry) -> bool {
                !self.strict || entry.proof == b"ok"
            }
        }

        type Adapter = NodeAdapter<KeccakPow, MockVerifier>;
        type Net = P2pNode<InProcTransport, Adapter>;

        /// Low difficulty so a unit test can mine real PoW headers — the headers must
        /// be genuine, because after #134 a mined header is exactly what buys the
        /// amnesty.
        fn sim() -> SimConfig {
            SimConfig {
                block_time_secs: 2,
                genesis_difficulty: 8,
                mine_nonce_budget: 5_000_000,
                ..SimConfig::default()
            }
        }

        fn adapter(strict: bool) -> Adapter {
            let (committee, _v) = devnet_committee(7);
            NodeAdapter::new(
                CommitteeState::new(committee, BOND_AMOUNT),
                KeccakPow,
                MockVerifier { strict },
                sim(),
            )
        }

        /// A node that can mine transactions: its genesis root is finalized, so a tx
        /// anchored there is admissible. This is what a chain looks like from the first
        /// block that carries a transaction — T1 by construction.
        fn transacting_server(strict: bool) -> (Adapter, Hash32) {
            let mut s = adapter(strict);
            let g = s.chain().genesis_hash();
            s.state_mut().finalize(g).expect("finalize genesis");
            let anchor = s.state().commitment_root();
            (s, anchor)
        }

        fn tx_with(anchor: Hash32, nf: u8, proof: &[u8]) -> TxEntry {
            TxEntry {
                proof: proof.to_vec(),
                public: TxPublic {
                    anchor,
                    nullifiers: vec![[nf; 32]],
                    commitments: vec![[nf.wrapping_add(50); 32]],
                    bucket: ArityBucket::TwoByTwo,
                    fee: posted_fee(ArityBucket::TwoByTwo),
                },
            }
        }

        /// Two linked in-process nodes: `[0]` serves, `[1]` joins. Returns them past
        /// the handshake, so `ready_peers` is non-empty and an announce actually moves.
        fn pair(server: Adapter, joiner: Adapter) -> (Vec<Net>, Arc<InProcHub>) {
            let hub = InProcHub::new();
            let mut nodes = vec![
                P2pNode::new(InProcTransport::new(PeerId(1), Arc::clone(&hub)), server, [1; 32]),
                P2pNode::new(InProcTransport::new(PeerId(2), Arc::clone(&hub)), joiner, [2; 32]),
            ];
            hub.link(PeerId(1), PeerId(2));
            hub.link(PeerId(2), PeerId(1));
            nodes[0].add_peer(PeerId(2), None);
            nodes[1].add_peer(PeerId(1), None);
            drive(&mut nodes, 0);
            (nodes, hub)
        }

        /// Drive both nodes to quiescence from `base_ms` (the local twin of `run_at`,
        /// which is typed to the `StubNode` mesh).
        fn drive(nodes: &mut [Net], base_ms: u64) {
            for round in 0..1000u64 {
                let mut moved = 0;
                for n in nodes.iter_mut() {
                    moved += n.tick(base_ms + round * 10);
                }
                if moved == 0 {
                    break;
                }
            }
        }

        /// Mine one block on `nodes[0]` carrying a single transaction and announce it.
        /// Returns the announced `(header, body)`.
        fn serve_one_transacting_block(
            nodes: &mut [Net],
            anchor: Hash32,
            nf: u8,
            round: u64,
        ) -> (BlockHeader, BlockBody) {
            assert_eq!(
                nodes[0].node_mut().ingest_tx(tx_with(anchor, nf, b"ok")),
                IngestOutcome::Accepted,
                "the server admits the tx it is about to mine"
            );
            let (header, body) = nodes[0].node_mut().mine_block().expect("mine");
            assert_eq!(body.txs.len(), 1, "the served block carries a transaction");
            nodes[0].announce_block(
                header,
                body.txs.clone(),
                body.coinbase,
                body.coinbase_rkm,
                round,
            );
            drive(nodes, (round + 1) * 10_000);
            (header, body)
        }

        /// 🔴 **ACCEPTANCE 1 (#134): a joiner replaying history it cannot anchor does
        /// not penalise the serving peer — and the peer's score is still exactly zero
        /// after more blocks than it used to take to ban it.**
        ///
        /// Six blocks, each carrying one transaction, served over the real
        /// `BlockAnnounce` path. Under the pre-#134 rule each one was
        /// `Rejected("bad body")` ⇒ `is_peer_fault()` ⇒ `PENALTY_INVALID_OBJECT` = 20;
        /// with `BAN_THRESHOLD` = −100 the **fifth** block banned an honest peer, and
        /// at `MAX_OUTBOUND` = 8 the fortieth would have taken the joiner's entire
        /// outbound set — every replacement earning the same ban for the same correct
        /// behaviour.
        ///
        /// The assertion is on the score itself, not on the outcome enum, because the
        /// score is the thing that bans.
        #[test]
        fn a_joiner_does_not_ban_the_peer_serving_it_correct_history() {
            let (server, anchor) = transacting_server(true);

            // The joiner has finalized nothing — the state of every node with an empty
            // data dir, which is every node that has ever joined a running net.
            let joiner = adapter(true);
            assert_eq!(joiner.state().finalized_height(), None);

            let (mut nodes, _hub) = pair(server, joiner);

            const SERVED: u64 = 6;
            for i in 0..SERVED {
                serve_one_transacting_block(&mut nodes, anchor, i as u8 + 1, i);
            }

            // The whole point, in one number.
            let peer = nodes[1].peers().get(PeerId(1)).expect("the serving peer");
            assert_eq!(
                peer.score, 0,
                "{SERVED} correctly-served blocks must cost the honest peer nothing"
            );
            assert!(!nodes[1].peers().is_banned(PeerId(1)), "and it is not banned");
            assert!(
                SERVED as i32 * 20 > -BAN_THRESHOLD,
                "the run is long enough to have banned the peer under the old rule"
            );

            // ...and the joiner is honest about why: it learned the headers, applied no
            // body, and counted every refusal it could not stand behind.
            assert_eq!(nodes[1].node().chain().tip_height(), SERVED, "header-first sync ran");
            assert_eq!(nodes[1].node().state().tip_height(), 0, "no body was applied");
            // `uanchor=` counts **refused bodies**, not blocks served, and since
            // issue #130 (c) those are no longer the same number: the joiner now asks
            // for the bodies it is missing, so a body it cannot judge is re-offered on
            // the requester's ladder (one re-ask per block per `BODY_REQUEST_TIMEOUT_MS`)
            // and refused again each time. The counter's own contract is what it
            // counts — "bodies neither applied nor charged" — and it is stated as a
            // process-lifetime cumulative, so this is the counter doing its job rather
            // than a changed meaning.
            //
            // The bound is asserted rather than the exact value, because the exact
            // value is a function of how long the harness runs its clock for, and
            // pinning it would make this test a timer. What is load-bearing is
            // unchanged and asserted above: **the peer's score is zero.**
            assert!(
                nodes[1].node().ingest_counters().unjudged_anchor >= SERVED,
                "`uanchor=` is what an operator greps for this state: {}",
                nodes[1].node().ingest_counters().unjudged_anchor
            );
        }

        /// 🔴 **ACCEPTANCE 2 (#134) at the same seam: a genuinely invalid body still
        /// costs the sender.** The distinction is not a blanket amnesty on the block
        /// path either.
        ///
        /// 🔴 **ACCEPTANCE 2 (#134) at the same seam: a genuinely invalid body still
        /// costs the sender.** The distinction is not a blanket amnesty on the block
        /// path either.
        ///
        /// The sender runs a **lenient verifier** — a broken or hostile node that waves
        /// its own proofs through — and mines and announces a block whose transaction
        /// carries a proof the receiver refuses. Same genesis, same real PoW, same
        /// announce path as the test above; only the body differs.
        ///
        /// The receiver is a **synced** node rather than the joiner, and the difference
        /// is the whole point of the boundary: it stands at the block's own parent with
        /// a current finalized head, so its verdict on this body is the network's and it
        /// charges for what it finds. `ProofInvalid` is intrinsic, so it would charge
        /// from anywhere — but on the joiner it would never *see* it. `validate_body`
        /// checks each tx's anchor before its proof, so on a node that cannot answer the
        /// anchor question the per-tx checks after it are never reached. That is a
        /// consequence worth naming, and it is exactly why an unjudged body is dropped
        /// rather than buffered: nothing in it has been verified.
        ///
        /// The complement — a genuinely non-final **anchor**, charged from the position
        /// that owns that verdict — is
        /// `adapter::tests::a_genuinely_invalid_body_still_costs_the_sender` case (2).
        #[test]
        fn a_body_with_an_unverifiable_proof_still_costs_the_sender() {
            let (server, anchor) = transacting_server(false);
            // The receiver is synced: same finalized genesis, standing at the same tip.
            let (receiver, _) = transacting_server(true);
            assert_eq!(receiver.state().finalized_height(), Some(0), "its finality is current");
            let (mut nodes, _hub) = pair(server, receiver);

            // The server admits and mines a tx its own (lenient) verifier accepts.
            assert_eq!(
                nodes[0].node_mut().ingest_tx(tx_with(anchor, 1, b"not-a-proof")),
                IngestOutcome::Accepted,
                "the lenient server takes its own bad proof"
            );
            let (header, body) = nodes[0].node_mut().mine_block().expect("mine");
            assert_eq!(body.txs.len(), 1);
            nodes[0].announce_block(header, body.txs.clone(), body.coinbase, body.coinbase_rkm, 1);
            drive(&mut nodes, 50_000);

            assert_eq!(
                nodes[1].peers().get(PeerId(1)).expect("peer").score,
                -crate::gossip::PENALTY_INVALID_OBJECT,
                "an unverifiable proof is the sender's fault and is charged as one"
            );
            assert_eq!(
                nodes[1].node().ingest_counters().unjudged_anchor,
                0,
                "and nothing about it was excused as unjudgeable"
            );
            assert_eq!(nodes[1].node().chain().tip_height(), 0, "nor was the header taken");
        }
    }
}
