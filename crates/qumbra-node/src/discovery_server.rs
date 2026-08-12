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
//! Six routes — the deployed binary's whole wallet-facing surface:
//!
//! - `GET /v1/compact?from=&to=` — [`qlab_node::compact_response`]'s bytes, the
//!   same encoder, over the same projection, that `NodeRpc` serves in-process
//!   (issue #188 baton 2). How a recipient **finds** its money.
//! - `GET /v1/nullifiers?from=&to=` — the per-block nullifier lists
//!   ([`qlab_node::NullifierPage`], lab issue #314). How a wallet learns that
//!   money it found has since been **spent**. The compact wire carries no
//!   nullifier by design (#188 (a) as amended / #32), so before this route a
//!   scan structurally could not know, and a wallet that had spent an hour ago
//!   still quoted its old balance under `verdict: complete`.
//!
//!   **Bulk over a range, never a membership query.** A `?nullifier=<nf>` form
//!   would tell this server which notes are the asker's, which is the exact
//!   linkage the discovery design refuses; the wallet derives its own notes'
//!   nullifiers from keys only it holds and matches locally. What is served is
//!   already public — consensus published every one of these bytes inside a
//!   block body to enforce the double-spend rule — so the bytes add nothing an
//!   `Ivk` could not already fetch over `GetData(Block)`; a per-nullifier probe
//!   would add the *question*, and the question is the leak.
//! - `GET /v1/tree/leaves?from=` — the commitment tree's leaves in authoritative
//!   append order ([`qlab_node::TreeLeaves`], issue #275 / decision brief B1).
//!   How a wallet builds the **witness** to spend: it replays the stream into a
//!   local tree and computes `auth_path` itself, so this server never learns
//!   which positions matter to it. `/v1/tree/frontier` stays unserved on
//!   purpose — a frontier reconstructs the root only, structurally, and a root
//!   is not a witness.
//! - `GET /v1/anchors` — the roots that are valid anchors **right now**
//!   ([`qlab_node::AnchorSet`], issue #276). The other half of the witness
//!   story, and not an optional one: a valid anchor is a *finalized* root,
//!   while the leaf stream's `total` is the live count at the applied tip. A
//!   wallet that built at the count it just synced to would declare an
//!   unfinalized root and be refused `anchor-not-valid` on every net whose
//!   finality runs on a cadence — so without this route the leaf stream serves
//!   a witness source nobody can legally spend against. The wallet matches its
//!   own reconstructed roots against this set locally, so the server still
//!   learns nothing positional (brief B2 stays rejected).
//! - `POST /v1/tx` — body = the canonical tx wire bytes
//!   (`qlab_p2p::codec::encode_tx`, what `build_send` produces). How a
//!   wallet-built transaction gets **in** (issue #275 / decision brief A1). The
//!   checks `NodeRpc::submit_tx` runs — in-tx nullifier repeat, the §4
//!   discovery↔cm binding, then the pool's posted-fee / anchor / double-spend /
//!   duplicate / conflict / real-proof gates — run **before** `announce_tx`,
//!   and every refusal comes back **typed and named** (the faucet's
//!   named-refusal house style; a surface on bare `announce_tx` would be
//!   boolean-blind — brief §2). See [`SubmitRequest`] for how a write crosses
//!   into the consensus loop without a second thread ever holding node state.
//!
//! - `GET /v1/block/{h}/tx/{i}/full` — the **committed AEAD payloads** of one
//!   transaction ([`qlab_node::full_response`], issue #188's serving+open
//!   baton). How a recipient **opens** what it found: `/v1/compact` says *which*
//!   outputs are yours, and these bytes are the only place a transaction
//!   output's `(value, ρ, rseed)` exists.
//!
//!   This route was the lane's named open item until now, and the sentence that
//!   stood here — *"serving the committed payload section to a detached wallet
//!   is … not this issue's"* — was written when it was true that
//!   nothing on a deployed node could answer it. Since the mint (PR #252,
//!   issue #188 (a) as amended) the 120 B payloads are **inside** the committed
//!   region, so every node holds them and serving is a projection like every
//!   other route here: [`respond_full`] copies `PAYLOAD_LEN` bytes at a time out
//!   of the same snapshot `/v1/compact` reads, regrouped by the recipient
//!   boundaries that region itself declares. No second encoding, no side table,
//!   no new index — and `/v1/compact`'s golden vector does not move, because it
//!   still serves the `group_contents` prefix and nothing more.
//!
//!   **The bound, stated because lab issue #309 is what happens when it is
//!   not:** this route has no range and no cursor. One request names one
//!   `(height, tx_index)` and the answer is that transaction's whole payload
//!   section or a named refusal — never a prefix of it — so there is no client
//!   paging loop to build and nothing that could silently truncate. The size is
//!   the block's to decide, not the caller's, and consensus bounds it: the
//!   payload count equals the transaction's declared commitment count
//!   (`check_tx_discovery`), which the FROZEN 2×2 shape puts at 2, i.e. 240 B.
//!
//! Still not the wallet-facing RPC:
//!
//! - **`/v1/status` is not served here.** It is not this surface's scope and
//!   the node already has a versioned health wire (`/v1/telemetry`).
//!   `/v1/anchors` moved out of that sentence in issue #276 for the reason
//!   above — it turned out to be load-bearing for spending, not health.
//! - **`/v1/tree/frontier` is still not served**, for the reason above: a
//!   frontier reconstructs a root, and a root is not a witness.
//!
//! ## The `POST /v1/tx` response wire, pinned
//!
//! Success is `202` with body `accepted <txid-hex>` — the statement tx id
//! ([`qlab_node::rpc::tx_id`]), the same id `NodeRpc::submit_tx` answers.
//! A resubmission of a pending tx is `200` / `duplicate <txid-hex>`, so
//! retry-after-timeout is safe. Refusals are `400` with `refused: <name>`
//! (first token machine-usable, e.g. `refused: wrong-fee expected=1000000
//! got=1`), and `503` with `unavailable: <name>` for states that are the
//! node's, not the transaction's (state lag, queue full, no verdict in time).
//! Nothing here is a 500 unless an internal invariant broke.
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
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use qlab_devnet::body::{BodyError, TxEntry};
use qlab_node::{
    compact_response, full_response, BlockDiscovery, FullRefusal, Hash32, MempoolError, TreeLeaves,
};
use qlab_p2p::adapter::TxSubmitRefusal;

/// The note-discovery route (issue #188 baton 2).
pub const COMPACT_PATH: &str = "/v1/compact";

/// The leaf-stream route (issue #275, decision brief B1) — GET only.
pub const TREE_LEAVES_PATH: &str = "/v1/tree/leaves";

/// The valid-anchor route (issue #276) — GET only, no query.
pub const ANCHORS_PATH: &str = "/v1/anchors";

/// The committed-payload route (issue #188, serving+open) — GET only. Written
/// as a shape because the path carries its two arguments: it is
/// `/v1/block/{height}/tx/{tx_index}/full`, the same URL
/// `qlab_cbserver::client`'s scan has always built and the reference server has
/// always answered. Held here so a 404 body can name it without spelling it a
/// second time.
pub const FULL_PATH_SHAPE: &str = "/v1/block/{h}/tx/{i}/full";

/// The submit route (issue #275, decision brief A1) — POST only.
pub const TX_SUBMIT_PATH: &str = "/v1/tx";

/// The per-block nullifier route (lab issue #314) — GET only, bulk over a
/// range. There is deliberately **no** per-nullifier form of it; see
/// [`qlab_node::NullifierPage`].
pub const NULLIFIERS_PATH: &str = "/v1/nullifiers";

/// The most bytes `POST /v1/tx` will read as a body.
///
/// Basis: the canonical 2×2 transaction wire is the 148,625 B consensus proof
/// (the mint, PR #252) plus the public surface (~200 B) plus the committed
/// discovery group (~2.7 KB with payloads) — ~152 KB total, and the verifier
/// rejects every non-2×2 shape, so no honest submission is larger. 256 KiB
/// covers that with slack and refuses a body an order of magnitude larger
/// before it is read. `[devnet-placeholder]` — moves if the consensus wire
/// does; not a frozen number.
pub const MAX_TX_WIRE_BYTES: usize = 256 * 1024;

/// Submissions the run loop can owe verdicts on at once; a fuller queue answers
/// `503 unavailable: submit-queue-full` without touching the node. Sized to the
/// loop's appetite, not the client's: each verdict costs a real proof verify on
/// the consensus thread, and a deeper queue would only convert refusals into
/// timeouts.
pub const MAX_QUEUED_SUBMITS: usize = 8;

/// Concurrent `POST /v1/tx` handler threads (each owns one socket: body read,
/// queue wait, response). The GET worker never blocks on a submitter — see
/// [`DiscoveryServer::start`] — and past this many in flight the answer is an
/// immediate `503`, not a longer line.
pub const MAX_INFLIGHT_SUBMITS: usize = 8;

/// How long a submit handler waits for the run loop's verdict before answering
/// `503 unavailable: no-verdict-in-time`.
///
/// Basis: a loop pass is normally milliseconds, but issue #107 measured
/// deployed loop periods that never got below 131 s across 53 samples on the
/// t0-wan-2 image — an open defect, not a budget. 60 s deliberately sits under
/// a Cloudflare-proxied edge's ~100 s timeout (the stamped topology fronts this
/// host with that edge) and over any healthy loop's pass; a node exhibiting
/// #107's period answers 503 by name, and because a landed-but-unanswered
/// submission answers `duplicate` on resubmission, timing out is safe to retry.
pub const SUBMIT_VERDICT_TIMEOUT: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// The submit rendezvous (issue #275)
// ---------------------------------------------------------------------------

/// One queued `POST /v1/tx`, handed from the HTTP thread to the run loop.
///
/// **Why a queue and not a lock**: every other route here serves a snapshot so
/// that a poller can never contend with the consensus loop — but a submission
/// IS a consensus write, so it must reach the loop. The honest way to share
/// `&mut` node state is not to: the handler thread parks on `reply` while the
/// loop, on its own iteration cadence, runs the checks and answers
/// ([`crate::run::RunningNode::drain_remote_submits`]). The loop pays exactly
/// one admission (the same cost a peer-delivered tx costs it); the socket
/// thread pays all the waiting.
pub struct SubmitRequest {
    /// The decoded transaction (the HTTP thread already paid the decode).
    pub tx: TxEntry,
    /// Where the verdict goes. Capacity 1; if the handler gave up waiting the
    /// send fails and the loop moves on — the tx's fate is still whatever the
    /// admission decided, discoverable by resubmitting (`duplicate`).
    pub reply: mpsc::SyncSender<TxSubmitOutcome>,
}

/// The run loop's verdict on one submission — what
/// [`crate::run::RunningNode::submit_remote_tx`] answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxSubmitOutcome {
    /// Admitted to this node's pool (re-read confirmed) and relayed to peers.
    /// Carries the **statement** tx id — [`qlab_node::rpc::tx_id`], the same id
    /// `NodeRpc::submit_tx` answers — so the wallet-facing meaning of "the tx
    /// id" does not depend on which surface admitted it.
    Accepted { txid: Hash32 },
    /// Already pending (same statement); no state change. Retry-safe by design.
    Duplicate { txid: Hash32 },
    /// Refused, by name.
    Refused(TxRefusal),
}

/// Why a submission was refused — each variant is one of the checks
/// `NodeRpc::submit_tx` runs, carried whole rather than re-judged here
/// (issue #275's one-validation-path constraint).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxRefusal {
    /// A nullifier repeated within the transaction itself
    /// ([`qlab_node::repeated_nullifier_in_tx`] — since issue #278 also a
    /// `Mempool::admit` gate; this surface still checks it first for the named
    /// 400 below).
    RepeatedNullifier,
    /// The committed discovery group failed the §4 rules — not decodable,
    /// not canonical, or not binding the declared commitments
    /// ([`qlab_devnet::body::check_tx_discovery`]).
    Discovery(BodyError),
    /// The typed admission gate ([`TxSubmitRefusal`]): state lag, or one of
    /// the pool's named refusals (fee, anchor, spent/conflicting nullifier,
    /// proof).
    Submit(TxSubmitRefusal),
    /// The pool re-read after an accepted admission did not find the tx — a
    /// broken internal invariant, never a client fault. Kept expressible so
    /// the re-read is a check and not a comment.
    AdmittedButNotPooled,
}

fn txid_hex(id: &Hash32) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// Render a verdict as `(status, body)` — the response wire pinned in the
/// module docs. The first token is machine-usable; the rest is for a person.
pub fn render_submit_outcome(outcome: &TxSubmitOutcome) -> (u16, String) {
    match outcome {
        TxSubmitOutcome::Accepted { txid } => (202, format!("accepted {}", txid_hex(txid))),
        TxSubmitOutcome::Duplicate { txid } => (200, format!("duplicate {}", txid_hex(txid))),
        TxSubmitOutcome::Refused(r) => render_refusal(r),
    }
}

fn render_refusal(refusal: &TxRefusal) -> (u16, String) {
    match refusal {
        TxRefusal::RepeatedNullifier => {
            (400, "refused: nullifier-repeated-in-tx".to_string())
        }
        TxRefusal::Discovery(BodyError::DiscoveryNotCanonical { .. }) => {
            (400, "refused: discovery-not-canonical".to_string())
        }
        TxRefusal::Discovery(BodyError::DiscoveryDoesNotBind { expected, got, .. }) => (
            400,
            format!("refused: discovery-does-not-bind expected={expected} got={got}"),
        ),
        // `check_tx_discovery` can also surface a malformed group (its decode
        // step); any other BodyError variant cannot reach here, and naming the
        // variant keeps the answer honest if that ever changes.
        TxRefusal::Discovery(other) => (400, format!("refused: discovery {other:?}")),
        TxRefusal::Submit(TxSubmitRefusal::StateLagging) => (
            503,
            "unavailable: state-lag — this node's applied state is behind its chain \
             and it will not judge a submission it could judge wrongly; retry"
                .to_string(),
        ),
        TxRefusal::Submit(TxSubmitRefusal::Pool(e)) => match e {
            MempoolError::WrongFee { expected, got } => {
                (400, format!("refused: wrong-fee expected={expected} got={got}"))
            }
            MempoolError::AnchorNotValid => (400, "refused: anchor-not-valid".to_string()),
            MempoolError::AlreadySpent { .. } => (400, "refused: nullifier-spent".to_string()),
            MempoolError::NullifierConflictInPool { .. } => {
                (400, "refused: nullifier-conflict-in-pool".to_string())
            }
            // Issue #278: the pool now runs both §4 lone-tx rules itself. On
            // THIS surface the pre-checks above answer first with their own
            // tokens (`nullifier-repeated-in-tx`, `discovery-…`), so these two
            // arms are the same verdicts arriving from the pool on any path
            // where a pre-check did not run — same fault, same 400.
            MempoolError::NullifierRepeatedInTx { .. } => {
                (400, "refused: nullifier-repeated-in-tx".to_string())
            }
            MempoolError::DiscoveryInvalid(e) => {
                (400, format!("refused: discovery {e:?}"))
            }
            MempoolError::ProofInvalid => (400, "refused: proof-invalid".to_string()),
            // The loop maps DuplicateTx to `TxSubmitOutcome::Duplicate` before
            // wrapping; reaching here means that mapping broke.
            MempoolError::DuplicateTx => {
                (500, "internal: duplicate escaped its mapping".to_string())
            }
        },
        TxRefusal::AdmittedButNotPooled => (
            500,
            "internal: admitted but not visible in the pool — report this".to_string(),
        ),
    }
}

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

/// The commitment-tree leaves the run loop last projected — what
/// `GET /v1/tree/leaves` serves (issue #275).
///
/// Same snapshot discipline as [`DiscoveryView`]: the run loop publishes on its
/// own cadence ([`crate::run::RunningNode::refresh_leaves`], keyed on the
/// applied tip so an unchanged state costs two comparisons), the server thread
/// serves, and a poller can never contend with the consensus loop. The vector
/// is `Node::commitments_ordered()` **cloned, never re-derived** — the exact
/// append order `apply_state` produced, matured-coinbase-first — so a served
/// page cannot differ in content or order from the tree the node proves
/// against. What a snapshot *can* be is behind, by at most
/// [`crate::run::DISCOVERY_REFRESH`] of chain: a wallet that reads a stale
/// snapshot sees fewer leaves, never different ones, and its next poll sees
/// the rest.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LeavesView {
    /// Every leaf, tree order (position `i` in the tree is `leaves[i]`).
    pub leaves: Vec<Hash32>,
}

/// The valid-anchor set the run loop last projected — what `GET /v1/anchors`
/// serves (issue #276).
///
/// Same snapshot discipline as [`LeavesView`], and **safer than it**: every
/// root here is finalized, and no-reorg-past-finality means a finalized root is
/// fixed forever. So a stale anchor snapshot can only offer *fewer, older*
/// anchors than the node would serve live — never a root that was never an
/// anchor. The one thing staleness can cost is the newest anchor, and a wallet
/// that builds against a slightly older finalized root is submitting a
/// perfectly valid transaction.
///
/// The set is derived by [`qlab_node::anchor_set`] — the same function
/// `NodeRpc::anchors` calls, not a second derivation. That matters more here
/// than usual: `main_chain_counts_of` must track `apply_state`'s append
/// schedule exactly, and its own doc comment records that miscounting "would
/// not fail loudly: it would publish anchors nobody can build a witness
/// against."
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AnchorsView {
    /// Encoded [`qlab_node::AnchorSet`] bytes, ready to serve.
    ///
    /// Held encoded rather than structured because this route has exactly one
    /// answer and no query: the run loop pays the encode once per refresh
    /// instead of once per request, and a poller cannot make the server work.
    pub encoded: Vec<u8>,
}

/// A running discovery-server endpoint: bound address + worker thread + the
/// shared projections the run loop refreshes + the submit queue it drains.
pub struct DiscoveryServer {
    addr: SocketAddr,
    server: Arc<tiny_http::Server>,
    thread: Option<JoinHandle<()>>,
    served: Arc<AtomicU64>,
}

impl DiscoveryServer {
    /// Bind `addr` and serve until [`Self::shutdown`]: `view` at
    /// [`COMPACT_PATH`], `leaves` at [`TREE_LEAVES_PATH`], and submissions into
    /// `submits` at [`TX_SUBMIT_PATH`].
    ///
    /// An unbindable address is an **error**, never a silent no-op: a node whose
    /// operator believes recipients can find their outputs and which serves
    /// nothing is precisely the state this endpoint exists to remove.
    ///
    /// # Threading, because a write route changes the old story
    ///
    /// The GET worker answers every read inline from a snapshot (microseconds)
    /// and never blocks on a submitter. Each `POST /v1/tx` moves to a
    /// short-lived handler thread — the body read and the verdict wait both
    /// block, and a slow or trickling submitter must not be able to hold the
    /// read surface hostage. At most [`MAX_INFLIGHT_SUBMITS`] handlers exist at
    /// once; past that the answer is an immediate 503, not a longer line.
    pub fn start(
        addr: &str,
        view: Arc<Mutex<Arc<DiscoveryView>>>,
        leaves: Arc<Mutex<Arc<LeavesView>>>,
        anchors: Arc<Mutex<Arc<AnchorsView>>>,
        submits: mpsc::SyncSender<SubmitRequest>,
    ) -> io::Result<Self> {
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
        let inflight = Arc::new(AtomicUsize::new(0));
        let thread = std::thread::spawn(move || {
            for request in worker.incoming_requests() {
                worker_served.fetch_add(1, Ordering::Relaxed);
                let url = request.url().to_string();
                let (path, query) = url.split_once('?').unwrap_or((url.as_str(), ""));

                // The one write route, method-gated first (the faucet's 405+Allow
                // shape) and handed off before its body is read — see the method
                // docs for why the GET worker must never block on a submitter.
                if path == TX_SUBMIT_PATH {
                    if *request.method() != tiny_http::Method::Post {
                        let allow = tiny_http::Header::from_bytes(&b"Allow"[..], &b"POST"[..])
                            .expect("static header parses");
                        let _ = request.respond(
                            tiny_http::Response::from_string("method not allowed: POST a canonical tx wire")
                                .with_status_code(405)
                                .with_header(allow),
                        );
                        continue;
                    }
                    spawn_submit_handler(request, submits.clone(), Arc::clone(&inflight));
                    continue;
                }

                // Read-only means read-only: anything else that is not a GET is
                // refused before the path is looked at.
                if *request.method() != tiny_http::Method::Get {
                    let _ = request.respond(
                        tiny_http::Response::from_string("method not allowed").with_status_code(405),
                    );
                    continue;
                }
                let response = match path {
                    COMPACT_PATH => {
                        // Clone the Arc under the lock, encode with it released.
                        let snapshot = match view.lock() {
                            Ok(g) => Arc::clone(&g),
                            Err(p) => Arc::clone(&p.into_inner()),
                        };
                        respond(&snapshot, query)
                    }
                    NULLIFIERS_PATH => {
                        // Same snapshot the compact route reads — the nullifiers
                        // and the discovery groups of one block are projected
                        // together, so a wallet can never be served outputs from
                        // a height whose spends it was not also offered.
                        let snapshot = match view.lock() {
                            Ok(g) => Arc::clone(&g),
                            Err(p) => Arc::clone(&p.into_inner()),
                        };
                        respond_nullifiers(&snapshot, query)
                    }
                    TREE_LEAVES_PATH => {
                        let snapshot = match leaves.lock() {
                            Ok(g) => Arc::clone(&g),
                            Err(p) => Arc::clone(&p.into_inner()),
                        };
                        respond_leaves(&snapshot, query)
                    }
                    ANCHORS_PATH => {
                        let snapshot = match anchors.lock() {
                            Ok(g) => Arc::clone(&g),
                            Err(p) => Arc::clone(&p.into_inner()),
                        };
                        Ok(snapshot.encoded.clone())
                    }
                    // The payload route carries its arguments in the path, so it
                    // is matched on shape rather than by equality. A path that
                    // is not this shape falls through to the 404 below.
                    _ => match full_path_args(path) {
                        Some(args) => {
                            let snapshot = match view.lock() {
                                Ok(g) => Arc::clone(&g),
                                Err(p) => Arc::clone(&p.into_inner()),
                            };
                            respond_full(&snapshot, args)
                        }
                        None => Err((
                            404,
                            format!(
                                "not found: try {COMPACT_PATH}?from=&to=, {NULLIFIERS_PATH}?from=&to=, \
                                 {TREE_LEAVES_PATH}?from=, {ANCHORS_PATH}, {FULL_PATH_SHAPE}, or \
                                 POST {TX_SUBMIT_PATH}"
                            ),
                        )),
                    },
                };
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

/// The socket-free `/v1/nullifiers` core: a `from`/`to` query against the same
/// projection [`respond`] reads (lab issue #314).
///
/// Refusals are `/v1/compact`'s, deliberately: a missing or unparseable bound is
/// a 400 and an inverted range is a 400. **Never an empty success** — an empty
/// page means "this node holds no main-chain height in that range", which is a
/// fact a wallet subtracts against, and it must not also mean "your request was
/// malformed".
///
/// The page arithmetic is [`qlab_node::NullifierPage::of`], the same function
/// the in-process route uses, so the two servers cannot disagree about where a
/// page ends.
pub fn respond_nullifiers(view: &DiscoveryView, query: &str) -> Result<Vec<u8>, (u16, String)> {
    let from = query_u64(query, "from").ok_or((400, "missing/invalid 'from'".to_string()))?;
    let to = query_u64(query, "to").ok_or((400, "missing/invalid 'to'".to_string()))?;
    if to < from {
        return Err((400, "'to' < 'from'".to_string()));
    }
    Ok(qlab_node::nullifier_page(&view.blocks, from, to).to_bytes())
}

/// The socket-free `/v1/tree/leaves` core: a `from` query against the leaves
/// snapshot. Mirrors [`qlab_node::NodeRpc::route`]'s refusals — a missing or
/// unparseable `from` is a 400 — and the page arithmetic is
/// [`TreeLeaves::page`], the same function the in-process route uses, so the
/// two servers cannot disagree about a page boundary.
pub fn respond_leaves(view: &LeavesView, query: &str) -> Result<Vec<u8>, (u16, String)> {
    let from = query_u64(query, "from").ok_or((400, "missing/invalid 'from'".to_string()))?;
    Ok(TreeLeaves::page(&view.leaves, from).to_bytes())
}

/// The two path arguments of `/v1/block/{h}/tx/{i}/full`, **unparsed** — so the
/// shape match and the number parse stay two separate answers (a path that is
/// not this route is a 404; this route with a non-numeric height is a 400).
///
/// `None` for anything that is not this shape.
fn full_path_args(path: &str) -> Option<(&str, &str)> {
    match path.trim_matches('/').split('/').collect::<Vec<_>>().as_slice() {
        ["v1", "block", h, "tx", i, "full"] => Some((h, i)),
        _ => None,
    }
}

/// The socket-free `/v1/block/{h}/tx/{i}/full` core: one transaction's committed
/// AEAD payloads, projected out of the same snapshot `/v1/compact` reads.
///
/// The page arithmetic that `/v1/compact` and `/v1/tree/leaves` need has no
/// analogue here and that is the contract, not an omission: the request names
/// one transaction, so the answer is all of that transaction's payload section
/// or a refusal (see the module docs).
///
/// Refusals, each its own answer because the client turns each into a different
/// sentence for a person:
///
/// - a non-numeric height or index — **400**, before the snapshot is consulted;
/// - a height this node's projection does not hold, or a transaction index past
///   the block's end — **404**, the same honest answer the reference server
///   gives and the one a wallet already renders as `PayloadUnavailable`;
/// - a stored block whose committed region does not decode — **500 rather than
///   an empty payload list**, for the same reason [`respond`] refuses there: an
///   empty list is the meaningful answer *"nothing to open here"*, and it must
///   never stand in for a broken invariant.
pub fn respond_full(
    view: &DiscoveryView,
    (h, i): (&str, &str),
) -> Result<Vec<u8>, (u16, String)> {
    let height = h.parse::<u64>().map_err(|_| (400, format!("invalid height `{h}`")))?;
    let tx_index = i.parse::<u64>().map_err(|_| (400, format!("invalid tx index `{i}`")))?;
    full_response(&view.blocks, height, tx_index).map_err(|e| match e {
        FullRefusal::NoSuchBlock { height } => (
            404,
            format!(
                "no such block: this node's discovery projection holds no main-chain height \
                 {height} (tip {})",
                view.tip_height().map(|t| t.to_string()).unwrap_or_else(|| "none".into())
            ),
        ),
        FullRefusal::NoSuchTx { height, tx_index, n_txs } => (
            404,
            format!("no such transaction: height {height} carries {n_txs} transaction(s), asked for index {tx_index}"),
        ),
        FullRefusal::Undecodable { height, tx_index, err } => (
            500,
            format!("stored discovery does not decode at height {height} tx {tx_index}: {err:?}"),
        ),
    })
}

/// Handle one `POST /v1/tx` on its own bounded thread: read the body, decode,
/// queue for the run loop, wait for the verdict, answer. See
/// [`DiscoveryServer::start`] for why this never runs on the GET worker.
fn spawn_submit_handler(
    request: tiny_http::Request,
    submits: mpsc::SyncSender<SubmitRequest>,
    inflight: Arc<AtomicUsize>,
) {
    // Claim a slot before spawning; the refusal must not cost a thread either.
    if inflight.fetch_add(1, Ordering::AcqRel) >= MAX_INFLIGHT_SUBMITS {
        inflight.fetch_sub(1, Ordering::AcqRel);
        let _ = request.respond(
            tiny_http::Response::from_string(
                "unavailable: submit-busy — too many submissions in flight; retry",
            )
            .with_status_code(503),
        );
        return;
    }
    std::thread::spawn(move || {
        let mut request = request;
        let (code, body) = submit_verdict(&mut request, &submits);
        let _ = request
            .respond(tiny_http::Response::from_string(body).with_status_code(code));
        inflight.fetch_sub(1, Ordering::AcqRel);
    });
}

/// The submit handler's whole decision, as `(status, body)`.
fn submit_verdict(
    request: &mut tiny_http::Request,
    submits: &mpsc::SyncSender<SubmitRequest>,
) -> (u16, String) {
    // 1. The body, bounded BEFORE it is read: a declared oversize is refused on
    //    the header, an undeclared one on the byte that crosses the cap.
    if let Some(len) = request.body_length() {
        if len > MAX_TX_WIRE_BYTES {
            return (413, format!("refused: body-too-large ({len} > {MAX_TX_WIRE_BYTES} bytes)"));
        }
    }
    let mut body = Vec::new();
    {
        use std::io::Read;
        let mut bounded = request.as_reader().take(MAX_TX_WIRE_BYTES as u64 + 1);
        if bounded.read_to_end(&mut body).is_err() {
            return (400, "refused: body-unreadable".to_string());
        }
    }
    if body.len() > MAX_TX_WIRE_BYTES {
        return (413, format!("refused: body-too-large (> {MAX_TX_WIRE_BYTES} bytes)"));
    }

    // 2. Decode — the same canonical wire the P2P layer speaks, same decoder.
    let tx = match qlab_p2p::codec::decode_tx(&body) {
        Ok(tx) => tx,
        Err(e) => return (400, format!("refused: decode {e:?}")),
    };

    // 3. Hand it to the run loop and wait for the verdict.
    let (reply_tx, reply_rx) = mpsc::sync_channel(1);
    match submits.try_send(SubmitRequest { tx, reply: reply_tx }) {
        Ok(()) => {}
        Err(mpsc::TrySendError::Full(_)) => {
            return (503, "unavailable: submit-queue-full — the node is behind on verdicts; retry".to_string());
        }
        Err(mpsc::TrySendError::Disconnected(_)) => {
            return (503, "unavailable: node-shutting-down".to_string());
        }
    }
    match reply_rx.recv_timeout(SUBMIT_VERDICT_TIMEOUT) {
        Ok(outcome) => render_submit_outcome(&outcome),
        Err(mpsc::RecvTimeoutError::Timeout) => (
            503,
            format!(
                "unavailable: no-verdict-in-time — the node loop did not answer within \
                 {}s; if the submission landed, resubmitting answers `duplicate`",
                SUBMIT_VERDICT_TIMEOUT.as_secs()
            ),
        ),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            (503, "unavailable: node-shutting-down".to_string())
        }
    }
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
        BlockDiscovery { height, hash: [hash; 32], groups, nullifiers: vec![] }
    }

    /// The same, spending `nullifiers` (lab issue #314).
    fn projected_spending(
        height: u64,
        hash: u8,
        groups: Vec<Vec<u8>>,
        nullifiers: Vec<Hash32>,
    ) -> BlockDiscovery {
        BlockDiscovery { height, hash: [hash; 32], groups, nullifiers }
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

    /// A server over `view` + `leaves`, with the submit queue's consumer end
    /// handed back so a test can either answer submissions or drop it (a dropped
    /// consumer answers every POST `503 node-shutting-down`, immediately).
    fn serve(
        view: Arc<Mutex<Arc<DiscoveryView>>>,
        leaves: Arc<Mutex<Arc<LeavesView>>>,
    ) -> (DiscoveryServer, mpsc::Receiver<SubmitRequest>) {
        serve_with(view, leaves, no_anchors())
    }

    fn serve_with(
        view: Arc<Mutex<Arc<DiscoveryView>>>,
        leaves: Arc<Mutex<Arc<LeavesView>>>,
        anchors: Arc<Mutex<Arc<AnchorsView>>>,
    ) -> (DiscoveryServer, mpsc::Receiver<SubmitRequest>) {
        let (tx, rx) = mpsc::sync_channel(MAX_QUEUED_SUBMITS);
        let srv =
            DiscoveryServer::start("127.0.0.1:0", view, leaves, anchors, tx).expect("bind");
        (srv, rx)
    }

    fn no_leaves() -> Arc<Mutex<Arc<LeavesView>>> {
        Arc::new(Mutex::new(Arc::new(LeavesView::default())))
    }

    fn no_anchors() -> Arc<Mutex<Arc<AnchorsView>>> {
        Arc::new(Mutex::new(Arc::new(AnchorsView::default())))
    }

    /// A minimal HTTP/1.1 POST crossing a real socket.
    fn post(addr: SocketAddr, path: &str, body: &[u8]) -> (String, String) {
        let mut s = TcpStream::connect(addr).expect("connect");
        write!(
            s,
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        s.write_all(body).unwrap();
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).expect("read");
        let sep = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("header terminator");
        let status = String::from_utf8_lossy(&raw[..sep]).lines().next().unwrap_or_default().to_string();
        let body = String::from_utf8_lossy(&raw[sep + 4..]).to_string();
        (status, body)
    }

    /// `/v1/anchors` serves `AnchorSet`'s own wire, decodable by the same
    /// decoder a wallet uses — the route issue #276 added because without it
    /// the leaf stream is a witness source nobody can legally spend against.
    #[test]
    fn serves_the_anchor_set_over_a_real_socket_and_a_wallet_decodes_it() {
        let set = qlab_node::AnchorSet {
            tip_height: 40,
            finalized_height: Some(33),
            max_age_blocks: 1152,
            roots: vec![[0x11; 32], [0x22; 32]],
        };
        let anchors = Arc::new(Mutex::new(Arc::new(AnchorsView { encoded: set.to_bytes() })));
        let (srv, _submits) =
            serve_with(Arc::new(Mutex::new(Arc::new(a_view()))), no_leaves(), Arc::clone(&anchors));
        let addr = srv.addr();

        let (status, body) = get(addr, "/v1/anchors");
        assert!(status.starts_with("HTTP/1.1 200"), "{status}");
        assert_eq!(
            qlab_node::AnchorSet::from_bytes(&body).expect("the wallet's own decoder reads it"),
            set,
            "served bytes ARE the AnchorSet wire — no second encoding"
        );

        // A refreshed snapshot is what the next read sees (the Arc-swap).
        let grown = qlab_node::AnchorSet {
            tip_height: 41,
            finalized_height: Some(40),
            max_age_blocks: 1152,
            roots: vec![[0x33; 32], [0x11; 32], [0x22; 32]],
        };
        *anchors.lock().unwrap() = Arc::new(AnchorsView { encoded: grown.to_bytes() });
        let (_, body2) = get(addr, "/v1/anchors");
        assert_eq!(qlab_node::AnchorSet::from_bytes(&body2).unwrap(), grown);

        srv.shutdown();
    }

    /// A node with nothing finalized serves an EMPTY anchor set, not a 404 and
    /// not an error: "there is nothing to anchor against yet" is a real state a
    /// young chain is in, and the wallet renders it as its own named refusal.
    #[test]
    fn a_chain_with_nothing_finalized_serves_an_empty_set_not_an_error() {
        let empty = qlab_node::AnchorSet {
            tip_height: 7,
            finalized_height: None,
            max_age_blocks: 1152,
            roots: vec![],
        };
        let (srv, _submits) = serve_with(
            Arc::new(Mutex::new(Arc::new(a_view()))),
            no_leaves(),
            Arc::new(Mutex::new(Arc::new(AnchorsView { encoded: empty.to_bytes() }))),
        );
        let (status, body) = get(srv.addr(), "/v1/anchors");
        assert!(status.starts_with("HTTP/1.1 200"), "{status}");
        let got = qlab_node::AnchorSet::from_bytes(&body).unwrap();
        assert!(got.roots.is_empty());
        assert_eq!(got.finalized_height, None);
        srv.shutdown();
    }

    /// Read-only means read-only on the new route too.
    #[test]
    fn the_anchor_route_refuses_a_non_get() {
        let (srv, _submits) = serve(Arc::new(Mutex::new(Arc::new(a_view()))), no_leaves());
        let (status, _) = post(srv.addr(), "/v1/anchors", b"");
        assert!(status.starts_with("HTTP/1.1 405"), "{status}");
        srv.shutdown();
    }

    #[test]
    fn serves_the_compact_wire_over_a_real_socket() {
        let view = Arc::new(Mutex::new(Arc::new(a_view())));
        let (srv, _submits) = serve(Arc::clone(&view), no_leaves());
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

    /// 🔴 **The route lab issue #314 exists for**, over a real socket: the
    /// per-block nullifier lists, decoded by the wallet's own decoder, off the
    /// SAME snapshot `/v1/compact` reads — so a wallet cannot be offered a
    /// height's outputs without also being offered that height's spends.
    ///
    /// The empty entry is asserted, not incidental: a block that spends nothing
    /// is served and empty, because an omitted height is indistinguishable from
    /// an unserved one and that distinction is the whole coverage story.
    #[test]
    fn serves_the_per_block_nullifier_lists_over_a_real_socket() {
        let view = Arc::new(Mutex::new(Arc::new(DiscoveryView {
            blocks: vec![
                projected(0, 0, vec![]),
                projected_spending(
                    1,
                    1,
                    vec![qlab_devnet::body::TxEntry::empty_discovery()],
                    vec![[0xA1; 32], [0xB2; 32]],
                ),
                projected(2, 2, vec![]),
            ],
        })));
        let (srv, _submits) = serve(Arc::clone(&view), no_leaves());
        let addr = srv.addr();

        let (status, body) = get(addr, "/v1/nullifiers?from=0&to=2");
        assert!(status.starts_with("HTTP/1.1 200"), "{status}");
        let page = qlab_cbserver::codec::NullifierPage::from_bytes(&body)
            .expect("the served bytes are the wallet's wire");
        assert_eq!((page.from, page.to), (0, 2), "the echoes are the request's");
        assert_eq!(page.blocks.len(), 3, "every held height in range, spending or not");
        assert_eq!(page.blocks[1].nullifiers, vec![[0xA1; 32], [0xB2; 32]]);
        assert!(page.blocks[0].nullifiers.is_empty());
        assert!(page.blocks[2].nullifiers.is_empty(), "served and empty, never omitted");

        // A refreshed projection is what the next read sees (the Arc swap), and
        // it is the same swap the compact route rides — one snapshot, one
        // refresh, so the two routes cannot disagree about the main chain.
        let mut later = (**view.lock().unwrap()).clone();
        later.blocks.push(projected_spending(3, 3, vec![], vec![[0xC3; 32]]));
        *view.lock().unwrap() = Arc::new(later);
        let (_, body2) = get(addr, "/v1/nullifiers?from=0&to=99");
        let page2 = qlab_cbserver::codec::NullifierPage::from_bytes(&body2).unwrap();
        assert_eq!(page2.blocks.len(), 4);
        assert_eq!(page2.blocks[3].nullifiers, vec![[0xC3; 32]]);

        srv.shutdown();
    }

    /// Nothing else is served, and the refusals are the RPC's refusals — not a
    /// half-implemented wallet API. `/v1/tree/frontier` in particular stays a
    /// 404 (see the module docs), and the read routes stay GET-only even now
    /// that a write route exists beside them.
    #[test]
    fn only_the_six_routes_are_served_and_methods_are_gated() {
        let view = Arc::new(Mutex::new(Arc::new(a_view())));
        let (srv, _submits) = serve(Arc::clone(&view), no_leaves());
        let addr = srv.addr();

        // `/v1/anchors` is NOT in this list any more: issue #276 made it a
        // served route, because a wallet cannot pick a legal `anchor_count`
        // without it. `/v1/block/{h}/tx/{i}/full` left it too (issue #188's
        // serving+open baton — the payloads are committed, so this node holds
        // them). `/v1/tree/frontier` stays unserved on purpose — a frontier
        // reconstructs a root, and a root is not a witness.
        for path in [
            "/",
            "/metrics",
            "/v1/telemetry",
            "/v1/status",
            "/v1/tree/frontier?at=1",
            // 🔴 There is no per-nullifier membership route and there must never
            // be one — "is nf X spent" tells the server which notes are the
            // asker's. A probe for one is a 404 by shape, so it cannot be
            // answered by accident (lab issue #314).
            "/v1/nullifier?nf=a1a1",
            "/v1/nullifiers/a1a1",
            // Near-misses of the payload route's shape: a 404 by shape, never a
            // 400 (which would claim the route exists and the arguments are bad).
            "/v1/block/1/tx/0",
            "/v1/block/1/tx/0/full/extra",
            "/v1/block/1/full",
        ] {
            let (status, _) = get(addr, path);
            assert!(status.starts_with("HTTP/1.1 404"), "{path} => {status}");
        }

        // Bad bounds are 400s, not empty successes — on every read route that
        // takes an argument, including the payload route's two path arguments.
        for path in [
            "/v1/compact",
            "/v1/compact?from=0",
            "/v1/compact?from=2&to=1",
            // Lab issue #314: the nullifier route's bounds refuse exactly like
            // the compact route's — never an empty success, which a wallet would
            // subtract nothing against and then quote as a balance.
            "/v1/nullifiers",
            "/v1/nullifiers?from=0",
            "/v1/nullifiers?to=3",
            "/v1/nullifiers?from=2&to=1",
            "/v1/tree/leaves",
            "/v1/tree/leaves?from=zzz",
            "/v1/block/zz/tx/0/full",
            "/v1/block/1/tx/zz/full",
        ] {
            let (status, _) = get(addr, path);
            assert!(status.starts_with("HTTP/1.1 400"), "{path} => {status}");
        }

        // A write verb on a read route is a 405, exactly as before #275…
        let (status, _) = post(addr, "/v1/compact", b"");
        assert!(status.starts_with("HTTP/1.1 405"), "{status}");
        let (status, _) = post(addr, "/v1/tree/leaves", b"");
        assert!(status.starts_with("HTTP/1.1 405"), "{status}");
        let (status, _) = post(addr, "/v1/block/1/tx/0/full", b"");
        assert!(status.starts_with("HTTP/1.1 405"), "{status}");
        let (status, _) = post(addr, "/v1/nullifiers", b"");
        assert!(status.starts_with("HTTP/1.1 405"), "{status}");
        // …and a read verb on the write route is a 405 too, not a 404: the
        // route exists and the answer says what it takes.
        let (status, _) = get(addr, "/v1/tx");
        assert!(status.starts_with("HTTP/1.1 405"), "{status}");

        srv.shutdown();
    }

    #[test]
    fn an_unbindable_address_is_an_error_and_the_message_names_the_opt_out() {
        let view = Arc::new(Mutex::new(Arc::new(DiscoveryView::default())));
        let (tx, _rx) = mpsc::sync_channel(1);
        let err = match DiscoveryServer::start("256.256.256.256:9", view, no_leaves(), no_anchors(), tx) {
            Err(e) => e,
            Ok(_) => panic!("that address cannot be bound"),
        };
        assert!(
            err.to_string().contains(DISCOVERY_OFF),
            "a default-on listener that cannot bind must tell the operator how to turn it off: {err}"
        );
    }

    // ---- the leaf stream over the socket (issue #275) ------------------------

    /// The served page is [`qlab_node::TreeLeaves`]'s wire over the snapshot —
    /// decodable by the same versioned decoder the in-process route's consumers
    /// use, refreshed by an `Arc` swap exactly like the compact view.
    #[test]
    fn serves_the_leaf_stream_over_a_real_socket() {
        let leaves = Arc::new(Mutex::new(Arc::new(LeavesView {
            leaves: vec![[0xAA; 32], [0xBB; 32], [0xCC; 32]],
        })));
        let (srv, _submits) = serve(Arc::new(Mutex::new(Arc::new(a_view()))), Arc::clone(&leaves));
        let addr = srv.addr();

        let (status, body) = get(addr, "/v1/tree/leaves?from=1");
        assert!(status.starts_with("HTTP/1.1 200"), "{status}");
        let page = TreeLeaves::from_bytes(&body).expect("the served bytes are the versioned wire");
        assert_eq!(page.from, 1);
        assert_eq!(page.total, 3);
        assert_eq!(page.leaves, vec![[0xBB; 32], [0xCC; 32]]);

        // Beyond the tree: the empty page carrying `total`, never an error.
        let (status, body) = get(addr, "/v1/tree/leaves?from=99");
        assert!(status.starts_with("HTTP/1.1 200"), "{status}");
        let ahead = TreeLeaves::from_bytes(&body).unwrap();
        assert!(ahead.leaves.is_empty());
        assert_eq!(ahead.total, 3);

        // A refreshed snapshot is what the next read sees.
        *leaves.lock().unwrap() = Arc::new(LeavesView { leaves: vec![[0xAA; 32]; 5] });
        let (_, body) = get(addr, "/v1/tree/leaves?from=0");
        assert_eq!(TreeLeaves::from_bytes(&body).unwrap().total, 5);

        srv.shutdown();
    }

    // ---- the submit route's HTTP half (issue #275) ----------------------------
    //
    // The verdicts themselves are the run loop's (`run.rs` tests them against a
    // real node); these tests pin the HTTP plumbing — that a queued submission
    // reaches a consumer decoded and intact, and that every rendered answer and
    // every local refusal carries its name and status.

    fn a_wire_tx(nf: u8) -> Vec<u8> {
        let public = qlab_devnet::body::TxPublic {
            anchor: [0x0F; 32],
            nullifiers: vec![[nf; 32]],
            commitments: vec![[nf.wrapping_add(1); 32]],
            bucket: qlab_devnet::fees::ArityBucket::TwoByTwo,
            fee: qlab_devnet::fees::posted_fee(qlab_devnet::fees::ArityBucket::TwoByTwo),
        };
        let discovery = qlab_devnet::body::placeholder_discovery(&public.commitments);
        let tx = qlab_devnet::body::TxEntry { proof: b"ok".to_vec(), public, discovery, rider: qlab_devnet::body::TxEntry::absent_rider() };
        qlab_p2p::codec::encode_tx(&tx)
    }

    /// A POSTed body reaches the loop-side consumer as the decoded transaction,
    /// and the consumer's verdict comes back rendered: 202 `accepted`, 200
    /// `duplicate`, 400 `refused: <name>` — the response wire the module docs pin.
    #[test]
    fn a_submission_crosses_the_queue_and_the_verdict_comes_back_named() {
        let (srv, submits) = serve(Arc::new(Mutex::new(Arc::new(a_view()))), no_leaves());
        let addr = srv.addr();

        // The loop stand-in: answer each queued submission with a scripted verdict.
        let consumer = std::thread::spawn(move || {
            let verdicts = [
                TxSubmitOutcome::Accepted { txid: [0xA1; 32] },
                TxSubmitOutcome::Duplicate { txid: [0xA1; 32] },
                TxSubmitOutcome::Refused(TxRefusal::Submit(TxSubmitRefusal::Pool(
                    MempoolError::WrongFee { expected: 1_000_000, got: 1 },
                ))),
                TxSubmitOutcome::Refused(TxRefusal::Submit(TxSubmitRefusal::StateLagging)),
            ];
            let mut seen = Vec::new();
            for v in verdicts {
                let req = submits.recv().expect("a queued submission");
                seen.push(req.tx.public.nullifiers[0][0]);
                let _ = req.reply.try_send(v);
            }
            seen
        });

        let (status, body) = post(addr, "/v1/tx", &a_wire_tx(1));
        assert!(status.starts_with("HTTP/1.1 202"), "{status} {body}");
        assert_eq!(body, format!("accepted {}", "a1".repeat(32)));

        let (status, body) = post(addr, "/v1/tx", &a_wire_tx(2));
        assert!(status.starts_with("HTTP/1.1 200"), "{status} {body}");
        assert!(body.starts_with("duplicate "), "{body}");

        let (status, body) = post(addr, "/v1/tx", &a_wire_tx(3));
        assert!(status.starts_with("HTTP/1.1 400"), "{status} {body}");
        assert_eq!(body, "refused: wrong-fee expected=1000000 got=1");

        let (status, body) = post(addr, "/v1/tx", &a_wire_tx(4));
        assert!(status.starts_with("HTTP/1.1 503"), "{status} {body}");
        assert!(body.starts_with("unavailable: state-lag"), "{body}");

        assert_eq!(
            consumer.join().unwrap(),
            vec![1, 2, 3, 4],
            "each verdict answered the submission that asked for it, decoded intact"
        );
        srv.shutdown();
    }

    /// The refusals the HTTP layer owns, each by name: an undecodable body never
    /// reaches the queue, an oversize body is refused on its declared length,
    /// and a server whose loop is gone answers immediately rather than parking
    /// the socket until the timeout.
    #[test]
    fn local_refusals_are_named_and_never_reach_the_queue() {
        let leaves = no_leaves();
        let (srv, submits) = serve(Arc::new(Mutex::new(Arc::new(a_view()))), leaves);
        let addr = srv.addr();

        // Garbage bytes: 400, named, and nothing was queued.
        let (status, body) = post(addr, "/v1/tx", b"not a transaction");
        assert!(status.starts_with("HTTP/1.1 400"), "{status}");
        assert!(body.starts_with("refused: decode"), "{body}");

        // A declared-oversize body: 413 on the header, without reading it.
        let mut s = TcpStream::connect(addr).expect("connect");
        write!(
            s,
            "POST /v1/tx HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            MAX_TX_WIRE_BYTES + 1
        )
        .unwrap();
        let mut raw = String::new();
        s.read_to_string(&mut raw).expect("read");
        assert!(raw.starts_with("HTTP/1.1 413"), "{raw}");
        assert!(raw.contains("body-too-large"), "{raw}");

        assert!(
            matches!(submits.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "neither refusal consumed loop budget"
        );

        // Loop gone (receiver dropped): a well-formed submission answers 503
        // by name, immediately — not after SUBMIT_VERDICT_TIMEOUT.
        drop(submits);
        let before = std::time::Instant::now();
        let (status, body) = post(addr, "/v1/tx", &a_wire_tx(9));
        assert!(status.starts_with("HTTP/1.1 503"), "{status}");
        assert!(body.contains("node-shutting-down"), "{body}");
        assert!(
            before.elapsed() < SUBMIT_VERDICT_TIMEOUT / 2,
            "a dropped consumer must answer promptly, not by timeout"
        );

        srv.shutdown();
    }

    /// A full queue is an immediate `503 submit-queue-full` — the client's
    /// refusal, not a longer line. The queue is filled directly through the
    /// same sender the server holds, so the test does not need nine parked
    /// sockets to prove the bound.
    #[test]
    fn a_full_queue_refuses_by_name_instead_of_queueing_deeper() {
        let view = Arc::new(Mutex::new(Arc::new(a_view())));
        let (tx, _rx) = mpsc::sync_channel(MAX_QUEUED_SUBMITS);
        let srv =
            DiscoveryServer::start("127.0.0.1:0", view, no_leaves(), no_anchors(), tx.clone())
                .expect("bind");
        let addr = srv.addr();

        // Fill the queue with requests nobody answers.
        for _ in 0..MAX_QUEUED_SUBMITS {
            let (reply, _keep) = mpsc::sync_channel(1);
            let entry = qlab_p2p::codec::decode_tx(&a_wire_tx(1)).unwrap();
            tx.try_send(SubmitRequest { tx: entry, reply }).expect("fills");
            std::mem::forget(_keep); // keep the reply channel alive; the queue slot stays owed
        }

        let (status, body) = post(addr, "/v1/tx", &a_wire_tx(2));
        assert!(status.starts_with("HTTP/1.1 503"), "{status}");
        assert!(body.contains("submit-queue-full"), "{body}");

        srv.shutdown();
    }

    // ---- the committed payload route (issue #188, serving+open) --------------

    /// A committed region with real recipient shapes and recognisable payload
    /// bytes: recipient 0 has two outputs, recipient 1 has one.
    fn a_committed_group_with_payloads() -> (Vec<u8>, Vec<Vec<u8>>) {
        use qlab_note::wire::{ClueSlot, CompactEntry, RecipientBundle};
        let entry = |s: u8| CompactEntry { cm: [s; 32], tag: [s ^ 0x5a; 8], clue: ClueSlot::Empty };
        let ct = |b: u8| -> [u8; qlab_note::kem::CT_LEN] { [b; qlab_note::kem::CT_LEN] };
        let recipients = vec![
            RecipientBundle { ct: ct(0x11), entries: vec![entry(1), entry(2)] },
            RecipientBundle { ct: ct(0x22), entries: vec![entry(3)] },
        ];
        let payloads: Vec<Vec<u8>> = (0..3u8)
            .map(|k| (0..qlab_cbserver::codec::PAYLOAD_LEN).map(|i| k.wrapping_add(i as u8)).collect())
            .collect();
        (
            qlab_cbserver::codec::encode_committed_discovery(&recipients, &payloads),
            payloads,
        )
    }

    /// 🔴 **The route this baton exists for.** The served payloads are the
    /// block's own committed bytes, regrouped by the recipient boundaries that
    /// same region declares — decoded by the wire the light client already
    /// speaks, and compared to the committed blob's tail rather than to
    /// anything this test re-encoded.
    #[test]
    fn serves_the_committed_payloads_over_a_real_socket() {
        use qlab_cbserver::codec::{decode_full_response, PAYLOAD_LEN};

        let (committed, payloads) = a_committed_group_with_payloads();
        let view = DiscoveryView {
            blocks: vec![
                projected(0, 0, vec![]),
                projected(1, 1, vec![committed.clone(), TxEntry::empty_discovery()]),
            ],
        };
        let (srv, _submits) = serve(Arc::new(Mutex::new(Arc::new(view))), no_leaves());
        let addr = srv.addr();

        let (status, body) = get(addr, "/v1/block/1/tx/0/full");
        assert!(status.starts_with("HTTP/1.1 200"), "{status}");
        let per_recipient =
            decode_full_response(&body).expect("the served bytes are the ratified /full wire");
        assert_eq!(per_recipient.len(), 2, "one list per committed recipient");
        assert_eq!(per_recipient[0], vec![payloads[0].clone(), payloads[1].clone()]);
        assert_eq!(per_recipient[1], vec![payloads[2].clone()]);

        // Byte identity against the committed region itself: the payload section
        // is its tail, and what was served is a copy of it in order.
        let tail = &committed[committed.len() - 3 * PAYLOAD_LEN..];
        assert_eq!(
            per_recipient.concat().concat(),
            tail.to_vec(),
            "served payloads ARE the committed tail, in order — no re-encoding"
        );

        // An `n = 0` transaction serves an EMPTY payload list, not a 404: "this
        // transaction attaches nothing to open" is a real answer about a real
        // transaction, and it is not the same fact as "no such transaction".
        let (status, body) = get(addr, "/v1/block/1/tx/1/full");
        assert!(status.starts_with("HTTP/1.1 200"), "{status}");
        assert!(decode_full_response(&body).expect("decodes").is_empty());

        srv.shutdown();
    }

    /// Each refusal by name and by status, because the client turns each into a
    /// different sentence: coordinates that do not exist are 404s and carry what
    /// the node does hold, and an undecodable committed region is a **500 rather
    /// than an empty payload list** — the same rule `/v1/compact` follows.
    #[test]
    fn the_payload_route_refuses_by_name_and_never_with_an_empty_list() {
        let (committed, _) = a_committed_group_with_payloads();
        let view = DiscoveryView {
            blocks: vec![projected(0, 0, vec![]), projected(1, 1, vec![committed])],
        };

        // A height the projection does not hold.
        let (code, msg) = respond_full(&view, ("9", "0")).expect_err("must refuse");
        assert_eq!(code, 404, "{msg}");
        assert!(msg.contains("tip 1"), "the refusal says what the node does hold: {msg}");

        // A transaction index past the block's end, with the count it has.
        let (code, msg) = respond_full(&view, ("1", "7")).expect_err("must refuse");
        assert_eq!(code, 404, "{msg}");
        assert!(msg.contains("carries 1 transaction"), "{msg}");

        // Unparseable arguments never reach the snapshot.
        assert_eq!(respond_full(&view, ("x", "0")).expect_err("must refuse").0, 400);
        assert_eq!(respond_full(&view, ("1", "x")).expect_err("must refuse").0, 400);

        // 🔴 A stored block whose committed region does not decode.
        let corrupt = DiscoveryView { blocks: vec![projected(0, 0, vec![vec![0x02, 0x00]])] };
        let (code, msg) = respond_full(&corrupt, ("0", "0")).expect_err("must refuse");
        assert_eq!(code, 500, "{msg}");
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
                    rider: qlab_devnet::names::RIDER_ABSENT.to_vec(),
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
