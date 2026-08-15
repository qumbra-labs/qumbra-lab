//! Node composition + run loop (issue #62 item 1 + 3).
//!
//! [`RunningNode`] composes the N7 stack — the qlab-p2p `NodeAdapter` (real
//! chain / PoW / state machine / mempool / committee over the five N1 traits) and
//! `P2pNode` (gossip / sync / relay) — over the **real TCP transport**
//! (`TcpTransport`) with **on-disk persistence** (the adapter's disk-backed
//! qlab-node stores) and, in the binary, **RandomXPow** (N3). It is generic over
//! the PoW engine `P` so the tests drive it with the deterministic KeccakPow while
//! the binary uses real RandomX (the N7 pattern).
//!
//! ## Frozen 75 s block time + real RandomX (item 3)
//! The run uses the FROZEN 75 s block time (consensus-parameters §2 — NOT the
//! `SIM_BLOCK_TIME_SECS` knob) and real RandomX.
//!
//! ## Wall-clock header timestamps (M10-T0-3 precondition item 0)
//! The binary sets the adapter's mining clock to [`MiningClock::WallClock`] so a
//! mined block's header timestamp is real wall-clock time (clamped non-decreasing
//! against the parent), NOT the constant 75 s counter. LWMA then sees real,
//! variable solvetimes and difficulty retargets to actual block-production pace —
//! the precondition for T0's item-4 difficulty-trace measurement. Header
//! validation tolerates the jitter (non-decreasing rule + LWMA 6T / out-of-sequence
//! clamps). In-process sims/tests keep the deterministic clock (the default).
//!
//! ## Verifier seam
//! The transaction verifier is injected. As of M10-T0-4 (issue #68) the binary's
//! **default is the real M3 verifier** ([`crate::verifier::ConsensusVerifier`] →
//! `qlab_consensus::verify_proof`, frozen `CONSENSUS_CFG`); [`DevnetRehearsalVerifier`]
//! is the clearly-labelled NO-OP stand-in, now an explicit `--rehearsal-verifier`
//! opt-in logged loudly at startup ([`crate::verifier::select_verifier`]). A T0 net
//! mines coinbase-only blocks, so the verifier is never actually exercised on T0 —
//! but the default is now real, closing the named M11 gate early. `RunningNode`
//! stays generic over the injected `V` ([`crate::verifier::NodeVerifier`] dispatches
//! the two at runtime); the tests below drive it with the rehearsal stand-in.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use qlab_devnet::body::{TxEntry, TxVerifier};
use qlab_devnet::committee::CommitteeState;
use qlab_devnet::ebbflow::FinalityStatus;
use qlab_devnet::node::SimConfig;
use qlab_devnet::params_devnet::{
    CHECKPOINT_CADENCE_BLOCKS, CHECKPOINT_SIGN_HYSTERESIS_BLOCKS, DEGRADED_MODE_LAG_BLOCKS,
    EPOCH_LENGTH_BLOCKS,
};
use qlab_devnet::pow::PowEngine;

use qlab_node::metrics::{render as render_metrics, LiveGauges};
use qlab_node::recovery::{Finalizer, FinalizerState};
use qlab_node::round::ObsClock;
use qlab_node::{ChainStore, SupplyBlock, SupplyLedger, Telemetry};

use crate::discovery_server::{
    AnchorsView, DiscoveryServer, DiscoveryView, LeavesView, SubmitRequest, TxRefusal,
    TxSubmitOutcome, MAX_QUEUED_SUBMITS,
};
use crate::looptime::{LoopJournal, LoopPhases};
use crate::metrics_server::MetricsServer;
use crate::telemetry_server::TelemetryServer;

use qlab_p2p::addrman::{valid_addr, AddrManager, DIAL_RETRY_INTERVAL_MS};
use qlab_p2p::adapter::{MiningClock, NodeAdapter};
use qlab_p2p::bodywait::BodyWaitJournal;
use qlab_p2p::node::BODY_REQUEST_TIMEOUT_MS;
use qlab_p2p::n1::{ChainView, CommitteeControl};
use qlab_p2p::sync::SyncPhase;
use qlab_p2p::ticktime::lap;
use qlab_p2p::transport::TcpTransport;
use qlab_p2p::P2pNode;

/// One canonical block's supply-accounting inputs, **including its identity**
/// (lab #299 §4). The identity is what lets the ledger refuse a reorged push instead
/// of absorbing it.
fn supply_block_of(hash: qlab_devnet::header::Hash32, block: &qlab_node::StoredBlock) -> SupplyBlock {
    SupplyBlock {
        height: block.header.height,
        hash,
        prev: block.header.prev,
        coinbase: block.coinbase,
        fees: block.txs.iter().map(|tx| tx.fee).sum(),
        // Lab #367: the burned name-fee portion, from the committed riders —
        // zero on every rider-free (i.e. every pre-boundary) block.
        name_burn: block.body().total_name_burn(),
    }
}

/// Build a [`SupplyLedger`] from the applied main chain — the startup path, and the
/// **reorg-recovery path** (lab #299 §4).
///
/// One function for both, deliberately: a rebuild that differed from the startup
/// build would be a second definition of the ledger, and the whole defect this
/// closes is two views of the same chain disagreeing.
fn rebuild_supply_ledger<C: ChainStore>(
    state_chain: &C,
    main_chain: &[qlab_devnet::header::Hash32],
) -> Result<SupplyLedger, qlab_node::SupplyError> {
    SupplyLedger::from_blocks(
        main_chain.iter().map(|hash| {
            let block = state_chain
                .block(hash)
                .expect("every canonical state-chain hash has its stored body");
            supply_block_of(*hash, block)
        }),
        EPOCH_LENGTH_BLOCKS,
    )
}

/// The `sid=` value when this node's own held keys are committed to *different*
/// checkpoints at the same slot (issue #84), and the type carrying it.
///
/// **Both moved down into `qlab_node::telemetry` by issue #117** so the wire, the
/// `TELEMETRY` log line and any reader share one definition instead of three; they
/// are re-exported here so this module's public surface is unchanged.
pub use qlab_node::telemetry::{LocalCommitment, LOCAL_COMMITMENT_SPLIT};

/// How often [`RunningNode::run_until`] runs a discovery maintenance pass —
/// re-dial, auto-connect, ask for addresses (issue #83; was `REDIAL_INTERVAL`).
const MAINTAIN_INTERVAL: Duration = Duration::from_millis(DIAL_RETRY_INTERVAL_MS);

/// The persisted address book, under the node's data dir (issue #83 scope 7).
const ADDRBOOK_FILE: &str = "peers.dat";

/// **How often the run loop writes a snapshot** (issue #359 S2) — the cadence that
/// makes `snapshot.bin` an invariant instead of an accident.
///
/// Before this, the binary had exactly ONE snapshot write: the graceful-shutdown
/// flush at the bottom of [`RunningNode::run_until_with`]. So a host's snapshot
/// existed if and only if that host had once been stopped *gracefully*, with the
/// loop free to observe the flag and the write free to succeed — which SIGKILL, a
/// wedged loop (#106's 53-minute stall) and a kill during startup replay each
/// defeat. node3 took that branch twice and paid **4.6 hours of from-genesis
/// replay**, then could not catch up at all (#359's Wall 2).
///
/// **300 s, and the trade is staleness against cost.** The loss window is what a
/// SIGKILL costs: at the FROZEN 75 s block time, 300 s is **4 blocks** of replay
/// on the next start — instantaneous next to the 11,751-record replay this exists
/// to prevent. The cost is one `bincode` serialize + `fsync` + rename of the
/// derived state per 4 blocks, i.e. under a percent of the work the node already
/// does per block, and it is paid on the loop, never on the block-application
/// path. Halving it would buy 2 blocks of window for double the writes; doubling
/// it starts trading real replay time for a saving nobody measured.
///
/// **Testnet-tunable, NOT frozen**: no consensus rule reads it, two nodes running
/// different values agree on everything, and `--snapshot-interval-secs` overrides
/// it per host. It is a durability/IO knob in exactly the sense
/// [`METRICS_REFRESH`] and [`TELEMETRY_REFRESH`] are observability knobs.
const SNAPSHOT_INTERVAL: Duration = Duration::from_secs(300);

/// How often the `/metrics` snapshot is re-rendered (issue #87). Chosen under a
/// typical 15 s Prometheus scrape interval so a scrape is never more than one
/// refresh stale, while the node — not the scraper — sets the cost. Rendering is a
/// few dozen string appends over integer state; the run loop pays it, never a
/// request handler. Observability only: it changes nothing but snapshot freshness.
/// #362: how often a halted-unfinalized node re-pushes its stored boundary
/// vote variants. Slow enough to be negligible traffic, fast enough that the
/// island-merge cascade completes within a couple of minutes of connectivity.
const BOUNDARY_REPUSH_INTERVAL: Duration = Duration::from_secs(60);

const METRICS_REFRESH: Duration = Duration::from_secs(5);

/// How often the `/v1/telemetry` snapshot is re-rendered (issue #117).
///
/// Same argument as [`METRICS_REFRESH`], same number: the node — not whoever is
/// polling it — decides how often it pays. Issue #121 adds one 48-byte supply row
/// per epoch: the ledger rebuilds from canonical stored bodies once at startup,
/// then advances only over new heights. At the frozen one-day epoch this remains
/// small daily payload growth rather than a per-block history or a repeated chain
/// scan. The cost is bounded staleness of at most this interval, which against a
/// FROZEN 75 s block time and a
/// [`CHECKPOINT_CADENCE_BLOCKS`]-block checkpoint grid cannot change any answer
/// the operator view gives: a finalized checkpoint is never reverted, so a node's
/// `fid` at a given `finalized_height` reads the same whenever it is read, and a
/// stale sample can only make a node look *behind* — which the view renders as
/// lag, never as disagreement.
pub const TELEMETRY_REFRESH: Duration = Duration::from_secs(5);

/// How often the run loop re-projects the main chain's committed note-discovery
/// for the `/v1/compact` endpoint (issue #188 baton 2).
///
/// Same snapshot discipline, same reason: a wallet polling this must never be able
/// to contend with the consensus loop for node state, so **the node decides how
/// often it pays** and a request costs an `Arc` clone. The refresh itself is
/// incremental — an unchanged tip does no work at all, and a changed one costs the
/// new blocks — so the cadence bounds staleness rather than cost.
///
/// 5 s against a FROZEN 75 s block time means a served range is at most one
/// fifteenth of a block behind, and below the finalized head not even that: no
/// reorg can cross the finalized head, so a finalized height's body — and
/// therefore its committed discovery — is fixed forever. A stale projection can
/// only show a wallet *fewer* of its outputs, never a different one.
pub const DISCOVERY_REFRESH: Duration = Duration::from_secs(5);

/// Unix seconds now (wall clock). Used for the metric surface's `process_start` and
/// `rendered_at` stamps only — never for consensus, which reads header timestamps.
fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

use crate::config::NodeConfig;
use crate::genesis::{GenesisError, GenesisFile};
use crate::release::{HaltMarker, Release, ReleaseError, RELEASE};

/// The NO-OP rehearsal transaction verifier. **NOT the real M3 verifier** — it
/// accepts every tx unconditionally. Since M10-T0-4 (issue #68) it is no longer
/// the default: the binary defaults to [`crate::verifier::ConsensusVerifier`]
/// (`qlab_consensus::verify_proof`, frozen `CONSENSUS_CFG`), and this stand-in is
/// an explicit `--rehearsal-verifier` opt-in that logs a loud warning at startup.
/// A T0 net mines coinbase-only blocks, so no tx proof is ever presented anyway;
/// this remains a convenience for devnet/rehearsal runs that want to skip verify.
#[derive(Clone, Copy, Debug, Default)]
pub struct DevnetRehearsalVerifier;

impl TxVerifier for DevnetRehearsalVerifier {
    fn verify_tx(&self, _entry: &TxEntry) -> bool {
        // NO-OP rehearsal stand-in — see the type doc. Real verification is the
        // default `crate::verifier::ConsensusVerifier`.
        true
    }
}

/// Why starting a node failed.
#[derive(Debug)]
pub enum RunError {
    Config(crate::config::ConfigError),
    Genesis(GenesisError),
    Node(qlab_node::NodeError),
    Io(std::io::Error),
    /// The binary's halt-height release constants are not startable, or this
    /// binary must not resume past the halt this node already performed (#74).
    Release(ReleaseError),
    /// Persisted canonical bodies could not be reduced to a contiguous supply
    /// ledger. Starting without an audit basis would make the public view lie.
    Supply(qlab_node::SupplyError),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::Config(e) => write!(f, "{e}"),
            RunError::Genesis(e) => write!(f, "{e}"),
            RunError::Node(e) => write!(f, "node: {e}"),
            RunError::Io(e) => write!(f, "io: {e}"),
            RunError::Release(e) => write!(f, "release: {e}"),
            RunError::Supply(e) => write!(f, "supply attestation: {e:?}"),
        }
    }
}
impl std::error::Error for RunError {}
impl From<GenesisError> for RunError {
    fn from(e: GenesisError) -> Self {
        RunError::Genesis(e)
    }
}
impl From<qlab_node::NodeError> for RunError {
    fn from(e: qlab_node::NodeError) -> Self {
        RunError::Node(e)
    }
}
impl From<ReleaseError> for RunError {
    fn from(e: ReleaseError) -> Self {
        RunError::Release(e)
    }
}
impl From<qlab_node::SupplyError> for RunError {
    fn from(e: qlab_node::SupplyError) -> Self {
        RunError::Supply(e)
    }
}

/// A read-only pre-flight summary of a node's deployment: the genesis + config +
/// held keys validated exactly as [`RunningNode::start`] would, but WITHOUT
/// binding a socket, opening the data dir, or mining. The deploy dry-run runs this
/// against every staged node to prove the laid-down layout is startable (item 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preflight {
    /// The hex keccak256 of the loaded genesis file.
    pub genesis_hash: String,
    /// Frozen committee size (must be 21 for T0).
    pub committee_size: u32,
    /// Frozen quorum (must be 15 for T0).
    pub quorum: u32,
    /// How many of the 21 committee signing keys this node holds.
    pub keys_held: usize,
    /// The TCP address this node would bind.
    pub listen_addr: String,
    /// How many peers this node would dial.
    pub dial_peers: usize,
    /// Whether this node would produce blocks.
    pub mining: bool,
}

/// Validate a node's `config` against its `genesis` exactly as startup would — the
/// genesis byte-verify + optional hash pin (item 2) and every held key
/// cross-checked against committee₀ — but bind nothing and touch no disk state.
/// Returns an operator/dry-run summary. Errors identically to [`RunningNode::start`]'s
/// pre-listener phase (wrong hash, tampered committee, a key for the wrong index).
pub fn preflight(config: &NodeConfig, genesis: &GenesisFile) -> Result<Preflight, RunError> {
    genesis.verify_startup(config.expected_genesis_hash.as_deref())?;
    let validators = genesis.load_validators(&config.committee_key_paths)?;
    Ok(Preflight {
        genesis_hash: genesis.hash_hex(),
        committee_size: genesis.frozen.committee_size,
        quorum: genesis.frozen.quorum,
        keys_held: validators.len(),
        listen_addr: config.listen_addr.clone(),
        dial_peers: config.dial_peers.len(),
        mining: config.mining,
    })
}

/// A composed, running full node: P2P + real node-state + PoW + committee, over
/// TCP with disk persistence. Generic over the PoW engine `P` (KeccakPow in
/// tests, RandomXPow in the binary) and the injected verifier `V`.
pub struct RunningNode<P: PowEngine, V: TxVerifier + Clone> {
    p2p: P2pNode<TcpTransport, NodeAdapter<P, V>>,
    /// Committee finalizers this node drives (one per held key; may be empty — a
    /// verify-only node). Each pairs a signing key with the persistent never-double-
    /// sign ledger (M10-T0-2), restored from disk on start (M10-T0-5 / S7).
    finalizers: Vec<Finalizer>,
    /// Node data dir — also where each finalizer's ledger is persisted.
    data_dir: std::path::PathBuf,
    /// Whether to produce blocks.
    mining: bool,
    /// Wall-clock spacing between mining attempts (the frozen 75 s in the binary;
    /// tests set it to zero and drive [`Self::try_mine`] directly).
    mine_interval: Duration,
    last_mine: Instant,
    /// #362: last boundary vote re-push, bounded to [`Self::repush_interval`].
    last_boundary_repush: Instant,
    /// #362: spacing between boundary vote re-pushes. Initialised to the
    /// production [`BOUNDARY_REPUSH_INTERVAL`] and only ever moved by
    /// [`Self::set_repush_interval`], the same shape `mine_interval` has: the
    /// binary never touches it, no config key reaches it, and the drill
    /// (issue #369, D2) sets it to zero rather than waiting a minute per push.
    repush_interval: Duration,
    /// Nonce salt for successive `BlockAnnounce`s.
    nonce: u64,
    /// Next checkpoint height to propose (cadence grid; only if we hold keys).
    next_checkpoint: u64,
    /// Next cadence slot the **diagnostics ledger** has not yet opened (issue #87).
    ///
    /// Deliberately separate from `next_checkpoint`: that cursor only moves on a
    /// node that holds committee keys, and a slot nobody here proposed is exactly
    /// the slot most worth having a record of. A verify-only node journals every
    /// round it lived through.
    next_round_slot: u64,
    /// When regime residency was last accumulated, so `Degraded` share is measured
    /// as *seconds spent*, not as a fraction of printed samples (issue #87).
    last_regime_tick: Instant,
    /// The last rendered `/metrics` exposition, shared with the scrape server.
    /// The run loop renders on its own cadence and the server thread serves the
    /// snapshot: a scraper can never contend with the consensus loop for node
    /// state, which matters on a 2 vCPU host.
    metrics_snapshot: Arc<Mutex<String>>,
    /// When the metrics snapshot was last rendered.
    last_metrics_render: Instant,
    /// The scrape server, when `metrics_addr` is configured. `None` = the node
    /// listens on nothing extra, which is the default.
    metrics_server: Option<MetricsServer>,
    /// The last encoded `/v1/telemetry` payload, shared with the read endpoint
    /// (issue #117). Same snapshot discipline as `metrics_snapshot`: the run loop
    /// encodes on its own cadence and the server thread serves the bytes, so a
    /// poller can never contend with the consensus loop for node state.
    telemetry_snapshot: Arc<Mutex<Vec<u8>>>,
    /// When the telemetry snapshot was last encoded.
    last_telemetry_render: Instant,
    /// The `/v1/telemetry` server, when `telemetry_addr` is configured. `None` =
    /// the node listens on nothing extra, which is the default.
    telemetry_server: Option<TelemetryServer>,
    /// The main chain's committed note-discovery, as of the last refresh — what
    /// `/v1/compact` serves (issue #188 baton 2). One `Arc` swap per refresh, so a
    /// reader holds the lock only long enough to clone a pointer.
    discovery_view: Arc<Mutex<Arc<DiscoveryView>>>,
    /// When the projection was last refreshed.
    last_discovery_refresh: Instant,
    /// The discovery server (`/v1/compact` + `/v1/tree/leaves` + `POST /v1/tx`
    /// since issue #275). `None` only when the operator wrote
    /// `discovery_addr = "off"` — **this is the one listener whose default is on**;
    /// see [`crate::discovery_server`] for why it inverts `metrics_addr`'s default.
    discovery_server: Option<DiscoveryServer>,
    /// The commitment-tree leaves as of the last refresh — what
    /// `/v1/tree/leaves` serves (issue #275). Same Arc-swap discipline as
    /// [`Self::discovery_view`].
    leaves_view: Arc<Mutex<Arc<LeavesView>>>,
    /// `(applied tip, leaf count)` the current leaves snapshot was projected at.
    /// The tip hash alone decides identity — the same applied tip means the same
    /// applied chain and therefore the same derived leaves — the count rides
    /// along because it makes the comparison's meaning legible in a debugger.
    leaves_sig: Option<(qlab_devnet::header::Hash32, u64)>,
    /// The valid-anchor set as of the last refresh — what `/v1/anchors` serves
    /// (issue #276), pre-encoded. Same Arc-swap discipline again.
    anchors_view: Arc<Mutex<Arc<AnchorsView>>>,
    /// `(applied tip, finalized height)` the current anchor snapshot was
    /// projected at. Finality is in the key because it is the *only* other
    /// input that moves the set: a block finalizing turns an already-applied
    /// root into an anchor without the tip moving at all, and keying on the tip
    /// alone would serve a stale anchor set across exactly the event a waiting
    /// wallet is waiting for.
    anchors_sig: Option<(qlab_devnet::header::Hash32, Option<u64>)>,
    /// The `POST /v1/tx` rendezvous: the server enqueues, the run loop answers
    /// ([`Self::drain_remote_submits`]). `None` until the discovery endpoint
    /// starts.
    submit_rx: Option<std::sync::mpsc::Receiver<SubmitRequest>>,
    /// Incremental scheduled-issuance accounting. Rebuilt once from the persisted
    /// canonical bodies at startup, then advanced only for new heights.
    supply_ledger: Mutex<SupplyLedger>,
    /// Unix seconds this process started (exported so a restart is a visible fact).
    process_start_secs: u64,
    /// Local listen address (for logs).
    listen_addr: String,
    /// How often [`Self::run_until`] emits a `TELEMETRY` stdout sample line (the
    /// T0-3 Phase B-lite soak monitor reads these via `docker compose logs`).
    sample_interval: Duration,
    /// When the last telemetry sample was emitted.
    last_sample: Instant,
    /// When the last discovery maintenance pass ran.
    last_maintain: Instant,
    /// **The `LOOP` journal** (issue #107 S1) — per-iteration phase timings,
    /// emitted as a slow line on the spot and as a window aggregate on the
    /// telemetry cadence. Observation only; see [`crate::looptime`].
    loop_journal: LoopJournal,
    /// How often [`Self::maintain_snapshot`] may write (issue #359 S2). Defaults
    /// to [`SNAPSHOT_INTERVAL`]; `--snapshot-interval-secs` overrides it.
    snapshot_interval: Duration,
    /// When the snapshot cadence last *fired* — the grid, not the last write: a
    /// tick that finds nothing to do still costs the interval, so a replaying or
    /// unchanged node is checked once per interval rather than every iteration.
    last_snapshot_tick: Instant,
    /// **What this process believes is in `snapshot.bin`** — seeded by one read at
    /// startup, then advanced by this process's own writes.
    ///
    /// Cached rather than re-read because decoding a snapshot is O(state size) and
    /// `TELEMETRY`'s `snap=` is printed every 30 s. The cache is exact under the
    /// one assumption that holds by construction — **this process is the only
    /// writer of this data dir's snapshot** (one node per data dir; the write is a
    /// temp-file rename inside it). If something outside the process deletes the
    /// file, `snap=` says what was last written, not what is on disk.
    durable_snapshot: qlab_node::SnapshotOnDisk,
    /// Process start, the origin of the monotonic millisecond clock the discovery
    /// policy is driven by.
    started: Instant,
    /// This process's release constants (issue #74) — the compile-time [`RELEASE`]
    /// in the binary; tests may drive [`RunningNode::start_with_release`] directly.
    release: Release,
    /// The halt height this release stops at, cached from `release`.
    halt_at: Option<u64>,
    /// Whether the durable halt marker for this halt has been written with
    /// `boundary_finalized = true` yet (it is rewritten once when H finalizes).
    marker_final_written: bool,
    /// **Issue #106: has this node ever been cleared to mine?** Latches `true` the
    /// first time [`Self::mine_gate`] permits a block and never clears.
    ///
    /// The latch is what keeps this a *startup* gate rather than a standing "am I
    /// behind?" check, and that boundary is deliberate:
    ///
    /// - The defect is a **cold** node extending a chain it knows nothing about. A
    ///   node that has already established where the chain is cannot make that
    ///   mistake again in this process's lifetime — it has real history, and #130
    ///   (a)'s `state_lag` gate plus fork choice cover it from there.
    /// - Without the latch, a single peer claiming an absurd height would stop an
    ///   established miner indefinitely (it can never catch up to a chain that does
    ///   not exist). Latching bounds that to *before this node's first block*, where
    ///   refusing is the safe direction anyway.
    mine_gate_latched: bool,
    /// **Issue #229: the `BODYWAIT` journal's rate limiter.** Holds what was last
    /// reported and when, so a stranding that changes nothing does not become a
    /// stream. See [`qlab_p2p::bodywait::BodyWaitJournal`] for the three rules.
    body_wait: BodyWaitJournal,
}

/// Why this node may or may not mine right now (issue #106) — the verdict behind
/// the `TELEMETRY` line's `mready=` field.
///
/// The whole gate is one sentence: **before its first block, a node must either
/// know where the chain is, or know there is no chain to know about.** The three
/// permitting variants are the two halves of that plus the latch; the two refusing
/// variants are the states node0 was in when it mined a genesis fork through a
/// restart on the T0 WAN net.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MineGate {
    /// Not a miner at all (`mining = false`) — the gate has nothing to say.
    NotMining,
    /// PERMITTED: a ready peer claimed a height and this node is not below it.
    Synced,
    /// PERMITTED: there is nobody to ask — no address to dial and no live peer —
    /// so this node *is* the net. The genuinely-first node on a brand-new chain,
    /// which must mine or no net ever starts.
    Alone,
    /// PERMITTED: cleared once already in this process's lifetime (the latch).
    Latched,
    /// REFUSED: no ready peer has claimed a height yet, and there are addresses
    /// left to try. **This is the cold-restart state** — an empty data dir with
    /// seeds configured, before the first handshake lands.
    Unknown,
    /// REFUSED: a peer's chain is taller and this node has not caught up to it.
    Behind,
}

impl MineGate {
    /// Whether this verdict permits mining.
    pub fn permits(&self) -> bool {
        matches!(self, MineGate::Synced | MineGate::Alone | MineGate::Latched)
    }

    /// The `mready=` token for the `TELEMETRY` line. `-` for a non-miner, matching
    /// `final=-` / `age_s=-`: the field is positional and a node with no mining
    /// duty has no readiness to report.
    pub fn field(&self) -> &'static str {
        match self {
            MineGate::NotMining => "-",
            MineGate::Synced => "synced",
            MineGate::Alone => "alone",
            MineGate::Latched => "latched",
            MineGate::Unknown => "unknown",
            MineGate::Behind => "behind",
        }
    }
}

impl<P: PowEngine, V: TxVerifier + Clone> RunningNode<P, V> {
    /// Start a node from a parsed config + loaded genesis file, using PoW engine
    /// `pow` and verifier `verifier`. Verifies the genesis (item 2: a wrong
    /// `expected_genesis_hash` refuses to start), builds the disk-backed adapter,
    /// binds the TCP listener, and dials the configured peers.
    pub fn start(
        config: &NodeConfig,
        genesis: &GenesisFile,
        pow: P,
        verifier: V,
    ) -> Result<Self, RunError> {
        Self::start_with_release(config, genesis, pow, verifier, RELEASE)
    }

    /// [`Self::start`] against an explicit [`Release`] (issue #74).
    ///
    /// This is a **Rust API for tests**, not a runtime override: the binary calls
    /// [`Self::start`], which passes the compile-time [`RELEASE`] constant, and
    /// nothing in the config file, the CLI, or the environment can reach this
    /// parameter (H1). It exists so the halt semantics can be exercised through the
    /// real run path — same seam, same posture, as `set_mining_clock`.
    pub fn start_with_release(
        config: &NodeConfig,
        genesis: &GenesisFile,
        pow: P,
        verifier: V,
        release: Release,
    ) -> Result<Self, RunError> {
        // (0) HALT GATES (issue #74), BEFORE anything else touches state:
        //     (a) the release's own constants must be startable — the cadence-grid
        //         rule (H2) and the revision digest describing this binary (H4);
        //     (b) if this node already halted, this binary must be the release that
        //         is entitled to carry it past that boundary (H4's resume gate).
        release.validate()?;
        let marker = HaltMarker::load(&config.data_dir)?;
        release.check_against_marker(marker.as_ref())?;
        //     (c) #81: the schedule is a property of this release AND of this data
        //         dir. A routine release after an upgrade declares no boundary of its
        //         own, and must still apply the post-halt rule domain recorded on
        //         disk — otherwise it would reject every block the upgraded
        //         population mined above the boundary.
        let rules = release.rule_schedule_on(marker.as_ref())?;
        //     (d) #81: having been *permitted* past the boundary, this binary records
        //         that its revision is now the one in force. Without this the marker
        //         keeps naming the pre-upgrade revision and every later release is
        //         refused forever — the defect #81 was filed for.
        //
        //         This write is FATAL on failure, unlike `maintain_halt_marker`'s
        //         best-effort posture. The asymmetry is deliberate: failing to record
        //         a halt leaves a node that is halted anyway, while failing to record
        //         a transition leaves a marker claiming the OLD revision is in force —
        //         under which a downgrade to the pre-upgrade binary would be silently
        //         ACCEPTED. A gate that quietly weakens on a full disk is worse than
        //         one that refuses to start.
        let marker = match marker {
            Some(m) if release.supersedes(&m) => {
                let advanced = m.superseded_by(&release);
                advanced.write(&config.data_dir)?;
                println!(
                    "HALT marker advanced: boundary height {} passed; revision in force is now \
                     `{}`. Later releases carrying this revision start without declaring the \
                     boundary (issue #81).",
                    advanced.height, advanced.revision_id
                );
                Some(advanced)
            }
            other => other,
        };

        // (1) Byte-verify the genesis file + optional hash pin BEFORE any state.
        genesis.verify_startup(config.expected_genesis_hash.as_deref())?;

        // (2) committee₀ from the baked verifying keys; bond = the frozen
        //     steady-state self-bond in bessel (the epoch ramp is a genesis-recorded
        //     schedule; per-epoch application is a committee follow-up).
        let committee_keys = genesis.committee()?;
        let bond_bessel =
            genesis.frozen.self_bond_qmb_steady.saturating_mul(genesis.frozen.bessel_per_qmb);
        let committee = CommitteeState::new(committee_keys, bond_bessel);

        // (3) This node's signing keys (cross-checked against committee₀), each wrapped
        //     in a Finalizer whose never-double-sign ledger is RESTORED from disk if a
        //     prior run persisted it — so a restarted proposer can never emit the second
        //     half of an equivocation pair (S7). A fresh key starts with an empty ledger.
        let validators = genesis.load_validators(&config.committee_key_paths)?;
        let finalizers: Vec<Finalizer> = validators
            .into_iter()
            .map(|v| {
                let path = finalizer_state_path(&config.data_dir, v.index);
                match std::fs::read(&path).ok().and_then(|b| FinalizerState::from_bytes(&b).ok()) {
                    Some(state) => Finalizer::restore(v, state),
                    None => Finalizer::new(v),
                }
            })
            .collect();

        // (4) Real params: FROZEN 75 s block time (item 3, NOT SIM_BLOCK_TIME_SECS)
        //     + the genesis PoW difficulty; RandomX key schedule from defaults.
        let sim = SimConfig {
            block_time_secs: genesis.frozen.block_time_secs,
            genesis_difficulty: genesis.genesis_difficulty,
            ..SimConfig::default()
        };

        // (5) Disk-backed adapter (restart-safe) + TCP transport + P2P node.
        //     `committee` above is always a fresh all-Active genesis roster, because
        //     that is all the genesis file describes. `open` replays this data dir's
        //     committee-punishment ledger onto it (issue #133); a ledger it cannot
        //     honour is an error here and the node does not start.
        let mut adapter = NodeAdapter::open(&config.data_dir, committee, pow, verifier, sim)?;
        // Issue #133's counter. Printed on EVERY start, zero included: the silence
        // after a restart is what made this class of defect invisible five times over,
        // because a node that restored nothing and a node that had nothing to restore
        // printed the same thing — nothing. Note what this line does NOT claim: it
        // reports what THIS node knows. Two nodes that observed different evidence
        // still disagree about who may sign, and now they disagree durably; agreement
        // needs the evidence on chain, which is a payload change and out of scope.
        {
            let restore = adapter.punishment_restore();
            println!("{}", restore.summary_line());
            if restore.ledger_absent_on_populated_datadir {
                println!(
                    "⚠️  this data dir already holds chain history but carried NO committee-\
                     punishment ledger, so it was written by a binary predating issue #133. \
                     Whether a punishment was ever applied against it is UNKNOWABLE — a \
                     tombstone from before this upgrade is gone, and this node starts with \
                     none. An empty ledger has been written, so later restarts are \
                     unambiguous. If this net has ever seen an equivocation, re-check this \
                     node's committee view against a peer that did not restart."
                );
            }
        }
        // The release's halt/rule schedule, installed once. No runtime path (H1).
        adapter.set_rule_schedule(rules);
        let transport = TcpTransport::bind(&config.listen_addr).map_err(RunError::Io)?;
        let bound = transport.local_addr().to_string();
        let node_id = node_id_from_addr(&bound);
        let mut p2p = P2pNode::new(transport, adapter, node_id);

        // (6) Peer discovery (issue #83). The address book is restored from disk if a
        //     previous run persisted one, the configured `dial_peers` are (re-)applied
        //     as never-evicted SEEDS, and our own address is advertised only if the
        //     operator declared us reachable. Connecting is then the ordinary
        //     maintenance pass — the same single dial path used for the rest of the
        //     process's life, so seeds and learned addresses share one cap and one
        //     backoff ladder (the S9 re-dial behaviour moved there unchanged).
        let mut addrs = match std::fs::read(config.data_dir.join(ADDRBOOK_FILE)) {
            Ok(bytes) => AddrManager::from_bytes(&bytes).unwrap_or_else(|e| {
                eprintln!("address book unreadable ({e}); starting from seeds");
                AddrManager::new()
            }),
            Err(_) => AddrManager::new(),
        };
        for addr in &config.dial_peers {
            addrs.add_seed(addr.clone());
        }
        // Self-filter identities (issue #127). These are independent of
        // `advertise_addr`: the filter must fire when the field is absent, or a
        // peer that gossips our seed-list name back at us admits and dials it.
        // Gossip identity stays operator-declared below — local facts never make
        // us gossipable on their own (outbound-only remains the default).
        for self_addr in local_self_identities(&config.listen_addr, &bound) {
            addrs.note_self_addr(self_addr);
        }
        addrs.set_self_advertise(config.advertise_addr.clone());
        if config.advertise_addr.is_none() {
            println!(
                "no advertise_addr: this node will sync, mine and transact but will \
                 not be gossiped to other peers (expected behind a router)"
            );
        }
        // Where mined coinbase notes are paid (issue #101). Unset is legal and
        // loud, not legal and quiet: the node still mines valid blocks, but to a
        // key nobody holds, so the issuance is burned. Silence here would let a
        // node mine for days before anyone noticed the coins were gone.
        match config.miner_rkm_lanes().map_err(RunError::Config)? {
            Some(rkm) => {
                p2p.node_mut().set_miner_rkm(rkm);
                println!("miner payout: coinbase notes paid to the configured miner_rkm");
            }
            None if config.mining => println!(
                "⚠️  NO miner_rkm CONFIGURED: this node mines valid blocks whose coinbase \
                 notes are paid to a fixed placeholder key that NOBODY can spend. Every \
                 coin this node mines is BURNED. Set `miner_rkm` (64 hex chars, your \
                 wallet's rkm) to keep what you mine."
            ),
            None => {}
        }

        *p2p.addrs_mut() = addrs;
        p2p.maintain(0); // dial the seeds now

        let supply_ledger = {
            let node = p2p.node();
            let state_chain = node.state().chain();
            rebuild_supply_ledger(state_chain, &state_chain.chain().main_chain())?
        };

        Ok(RunningNode {
            p2p,
            finalizers,
            data_dir: config.data_dir.clone(),
            mining: config.mining,
            mine_interval: Duration::from_secs(genesis.frozen.block_time_secs),
            last_mine: Instant::now(),
            last_boundary_repush: Instant::now(),
            repush_interval: BOUNDARY_REPUSH_INTERVAL,
            nonce: 0,
            next_checkpoint: 0, // finalize genesis first, then the cadence grid
            // The ledger's cursor starts at the first cadence slot: genesis is
            // finalized without a round, so there is no round 0 to journal.
            next_round_slot: CHECKPOINT_CADENCE_BLOCKS,
            last_regime_tick: Instant::now(),
            metrics_snapshot: Arc::new(Mutex::new(String::new())),
            last_metrics_render: Instant::now(),
            metrics_server: None,
            telemetry_snapshot: Arc::new(Mutex::new(Vec::new())),
            last_telemetry_render: Instant::now(),
            telemetry_server: None,
            discovery_view: Arc::new(Mutex::new(Arc::new(DiscoveryView::default()))),
            last_discovery_refresh: Instant::now(),
            discovery_server: None,
            leaves_view: Arc::new(Mutex::new(Arc::new(LeavesView::default()))),
            leaves_sig: None,
            anchors_view: Arc::new(Mutex::new(Arc::new(AnchorsView::default()))),
            anchors_sig: None,
            submit_rx: None,
            supply_ledger: Mutex::new(supply_ledger),
            process_start_secs: unix_secs(),
            listen_addr: bound,
            // Sample telemetry roughly every 30 s (well under the 75 s block time,
            // so every block shows up in the trace; the soak monitor also runs
            // `docker compose logs -t` to wall-clock-stamp each line).
            sample_interval: Duration::from_secs(30),
            last_sample: Instant::now(),
            last_maintain: Instant::now(),
            loop_journal: LoopJournal::new(),
            snapshot_interval: SNAPSHOT_INTERVAL,
            last_snapshot_tick: Instant::now(),
            // Issue #359: one read, at the one moment it is free — the node has
            // just opened this data dir. A read error here is reported as
            // `Unreadable` rather than failing the start: a node whose snapshot
            // cannot be read is still a node, and it is about to write a new one.
            durable_snapshot: qlab_node::snapshot_on_disk(&config.data_dir)
                .unwrap_or(qlab_node::SnapshotOnDisk::Unreadable),
            mine_gate_latched: false,
            body_wait: BodyWaitJournal::new(),
            started: Instant::now(),
            release,
            halt_at: release.halt_at(),
            // "The marker for THIS release's halt is already in its final form", so
            // it may only be seeded from a marker that is actually about this halt.
            // Seeding it from any marker at all was unreachable under the height-keyed
            // gate — a binary armed at a SECOND boundary on a resumed data dir was
            // refused outright, so there was never a marker for a different boundary
            // to be confused by. #81 makes the second upgrade possible and therefore
            // makes it live: the node would halt at the new boundary and never write a
            // marker for it, leaving the gate to consult a stale boundary afterwards.
            marker_final_written: marker
                .filter(|m| !m.resumed && Some(m.height) == release.halt_at())
                .is_some_and(|m| m.boundary_finalized),
        })
    }

    /// The bound listen address.
    pub fn listen_addr(&self) -> &str {
        &self.listen_addr
    }

    /// Read-only access to the composed P2P node (tests / status).
    pub fn p2p(&self) -> &P2pNode<TcpTransport, NodeAdapter<P, V>> {
        &self.p2p
    }

    /// Mutable access to the composed P2P node — **this crate's own tests only**.
    ///
    /// `#[cfg(test)]` deliberately: issue #130 (a) needs a node whose header view has
    /// run ahead of its applied bodies, which on a real net is produced by a `Headers`
    /// batch arriving before a body announce and cannot be produced through any of the
    /// public seams. It is not a new capability for any caller outside these tests.
    #[cfg(test)]
    fn p2p_mut(&mut self) -> &mut P2pNode<TcpTransport, NodeAdapter<P, V>> {
        &mut self.p2p
    }

    /// Read-only access to the node's consensus state — the chain store, the
    /// depth-32 commitment tree and the nullifier set.
    ///
    /// Added for the in-process faucet (issue #123): a wallet composed into this
    /// process needs the live tree to cut membership witnesses against, and the
    /// live anchor set to bind a proof to. It is `&`, never `&mut`: a co-resident
    /// wallet **reads** consensus state and writes only by submitting a
    /// transaction ([`Self::submit_local_tx`]), which is the same one-way arrow
    /// `qumbra-opview` has over the telemetry wire.
    pub fn state(&self) -> &qlab_node::MemNode {
        self.p2p.node().state()
    }

    /// Submit a **locally-originated** transaction: admit it to this node's own
    /// mempool and gossip it to peers. Returns whether the node admitted it.
    ///
    /// Added for the in-process faucet (issue #123), and deliberately the *only*
    /// write a co-resident process gets. This is `P2pNode::announce_tx` — the
    /// pre-existing local-origination path a mining node already uses — so it adds
    /// **no network write surface**: nothing new listens, no wire codepoint
    /// changes, and a peer cannot reach it. A faucet running in this process
    /// submits exactly as a wallet on the same host would if the node had a
    /// wallet-facing RPC, which it does not and which this does not add.
    ///
    /// Prefer [`Self::submit_local_tx_named`] when the caller needs the refusal
    /// reason (lab issue #310): the boolean form discards it.
    pub fn submit_local_tx(&mut self, tx: TxEntry) -> bool {
        self.submit_local_tx_named(tx).is_ok()
    }

    /// Submit a **locally-originated** transaction and return the **named**
    /// refusal when the node did not take it (lab issue #310).
    ///
    /// Same admission path as [`Self::submit_local_tx`] / peer `ingest_tx` —
    /// `P2pNode::announce_tx_typed` — only the return shape differs. The reason
    /// tokens match the deployed `POST /v1/tx` surface (`nullifier-spent`,
    /// `anchor-not-valid`, …) so an operator reading either log sees one
    /// vocabulary.
    pub fn submit_local_tx_named(&mut self, tx: TxEntry) -> Result<(), String> {
        use qlab_p2p::adapter::TxSubmitRefusal;
        match self.p2p.announce_tx_typed(tx) {
            Ok(_) => Ok(()),
            Err(TxSubmitRefusal::StateLagging) => Err("state-lagging".into()),
            Err(TxSubmitRefusal::Pool(e)) => Err(mempool_refusal_token(&e).into()),
        }
    }

    /// Tip height reported by the consensus chain view.
    pub fn tip_height(&self) -> u64 {
        self.p2p.node().tip_height()
    }

    /// Finalized height, if any.
    pub fn finalized_height(&self) -> Option<u64> {
        self.p2p.node().finalized_height()
    }

    /// One-line provenance for how this process recovered its durable chain.
    pub fn recovery_report(&self) -> &qlab_node::RecoveryReport {
        self.p2p.node().recovery_report()
    }

    /// Override the mining cadence (tests set 0 to mine every step).
    pub fn set_mine_interval(&mut self, d: Duration) {
        self.mine_interval = d;
    }

    /// Override the #362 boundary vote re-push cadence (tests set 0 to re-push on
    /// every loop pass).
    ///
    /// The production default is [`BOUNDARY_REPUSH_INTERVAL`] — 60 s — and the
    /// binary never calls this: it exists because the island-merge cascade
    /// (issue #369, D2) is a *multi-push* property and a drill that waited a
    /// real minute per push could not be in the suite at all. Deliberately the
    /// same shape as [`Self::set_mine_interval`]: a method on the running node,
    /// not a config key and not a mutable const, so the wire, the config file
    /// and every deployed binary keep exactly one cadence.
    pub fn set_repush_interval(&mut self, d: Duration) {
        self.repush_interval = d;
    }

    /// Select the header-timestamp mining clock (item 0). The binary opts into
    /// [`MiningClock::WallClock`]; the deterministic default is kept by the
    /// in-process tests below.
    pub fn set_mining_clock(&mut self, clock: MiningClock) {
        self.p2p.node_mut().set_mining_clock(clock);
    }

    /// Override the telemetry sampling cadence (tests / faster soaks).
    pub fn set_sample_interval(&mut self, d: Duration) {
        self.sample_interval = d;
    }

    /// Override the snapshot cadence (issue #359 S2) — `--snapshot-interval-secs`
    /// for an operator, `Duration::ZERO` for a test that wants every iteration to
    /// be a cadence tick. Durability only: no consensus rule reads it.
    pub fn set_snapshot_interval(&mut self, d: Duration) {
        self.snapshot_interval = d;
    }

    /// What this process last wrote to (or read from) `snapshot.bin` — issue #359
    /// S3, the value behind `TELEMETRY`'s `snap=`.
    pub fn durable_snapshot(&self) -> qlab_node::SnapshotOnDisk {
        self.durable_snapshot
    }

    /// **The identity of the finalized checkpoint** (issue #84), or `None` when
    /// nothing is finalized. Read from the finality tracker's own head — this is
    /// the checkpoint the quorum was verified against, not a re-derivation.
    pub fn finalized_checkpoint_id(&self) -> Option<u64> {
        self.p2p.node().finality().latest().map(|cp| cp.identity())
    }

    /// Whether the checkpoint behind the operator-facing `final=` is present in
    /// this host's own header chain (issue #85).
    ///
    /// `final=` deliberately remains the committee
    /// [`FinalityTracker`](qlab_devnet::finality::FinalityTracker)'s view: a
    /// behind node must still be able to learn that a quorum formed before it has
    /// downloaded the block. This comparison makes the second view explicit
    /// without weakening that capability:
    ///
    /// - `local` — fork choice holds the exact block hash the tracker finalized;
    /// - `heard` — the tracker verified quorum, but fork choice does not hold it;
    /// - `-` — the tracker has no finalized checkpoint to classify.
    ///
    /// The comparison is by the full block hash, not by height: issue #84 already
    /// established that equal heights do not establish equal checkpoints.
    fn finality_backing_field(&self) -> &'static str {
        let node = self.p2p.node();
        match node.finality().latest() {
            None => "-",
            Some(cp) if node.chain().header(&cp.block_hash).is_some() => "local",
            Some(_) => "heard",
        }
    }

    /// **What this node's own committee keys are committed to** (issue #84).
    ///
    /// Read from the never-double-sign ledgers — the same records that live in
    /// `finalizer-*.state`, which until now could only be inspected by copying
    /// those files off the host and hashing them.
    ///
    /// The slot reported is the highest any held key has committed to, which is
    /// deliberately **not** the finalized height: at a split, the minority still
    /// finalizes the majority's checkpoint, so the two agree on `final` and differ
    /// only here.
    pub fn local_commitment(&self) -> Option<LocalCommitment> {
        let slot = self.finalizers.iter().filter_map(|f| f.last_voted_slot()).max()?;
        let mut id: Option<u64> = None;
        let mut agreed = true;
        for f in &self.finalizers {
            let Some(cp) = f.state().signed_at(slot) else { continue };
            match id {
                None => id = Some(cp.identity()),
                Some(seen) if seen != cp.identity() => agreed = false,
                Some(_) => {}
            }
        }
        Some(LocalCommitment { slot, id: if agreed { id } else { None } })
    }

    /// The canonical live [`Telemetry`] snapshot for this node — **the one place**
    /// the operator surface is assembled (issue #117).
    ///
    /// Both consumers read it: the `TELEMETRY` stdout sample line below, and the
    /// `/v1/telemetry` wire served by [`crate::telemetry_server`] when
    /// `telemetry_addr` is configured. They cannot disagree about what this node
    /// finalized, because there is nothing for them to disagree with.
    ///
    /// Reuses the canonical [`Telemetry::assemble_with_halt`] rule — it never
    /// re-derives the frozen Ebb-and-Flow finality semantics — and stamps in the
    /// two halves [`qlab_node::Node`] cannot see: the network facts (peers, epoch)
    /// and the checkpoint identity (`fid` from the finality tracker's own head,
    /// `sslot`/`sid` from the never-double-sign ledgers).
    ///
    /// Age is chain-time (block timestamps), so that half is deterministic given
    /// the chain; the network half is read live.
    pub fn telemetry(&self) -> Telemetry {
        let node = self.p2p.node();
        let chain = node.chain();
        let state_chain = node.state().chain();
        let supply = {
            let mut ledger = self
                .supply_ledger
                .lock()
                .expect("the supply ledger mutex is not poisoned");
            let main_chain = state_chain.chain().main_chain();
            // 🔴 **Reorg reconciliation (lab #299 §4).** Appending is only correct
            // while the ledger is still summing the canonical branch. Fork choice can
            // move entirely BELOW `next_height`, in which case the loop below runs
            // zero times and the orphaned branch's coinbase would stay in the sum
            // forever — a DIVERGENT manufactured by a reorg, on a surface whose whole
            // job is to make a real supply violation legible.
            //
            // Rebuild rather than rewind: the ledger keeps no per-height measured
            // history, so it cannot recompute the partial row a rewind would land in.
            // The cost is one O(chain) rebuild on a rare event — the same work the
            // startup path already does — against one hash comparison per sample.
            if !ledger.is_in_sync_with(&main_chain) {
                match rebuild_supply_ledger(state_chain, &main_chain) {
                    Ok(rebuilt) => *ledger = rebuilt,
                    // A rebuild cannot fail on a chain the state machine has applied
                    // (contiguous from genesis by construction), but if it ever did,
                    // serving a stale row is worse than serving none: `supply_lag`
                    // then reports the gap and consumers render UNAVAILABLE.
                    Err(e) => eprintln!("SUPPLY rebuild after reorg failed: {e:?}"),
                }
            }
            for height in ledger.next_height()..=state_chain.tip_height() {
                let hash = main_chain
                    .get(height as usize)
                    .expect("every canonical height has a hash");
                let block = state_chain
                    .block(hash)
                    .expect("every canonical state-chain hash has its stored body");
                ledger
                    .push(supply_block_of(*hash, block))
                    .expect("new canonical heights extend the supply ledger contiguously");
            }
            ledger.rows().to_vec()
        };
        // Age is chain-time from the finalized block; 0 when there is no finalized
        // CHECKPOINT to measure from — nothing finalized (S8: no finalized head ⇒
        // no finalized-age, not a genesis-fallback absolute) or the finalized head
        // still genesis (#73: the bootstrap finalization is not a checkpoint round,
        // and its ts=0 placeholder differenced against a WallClock tip printed the
        // wall clock itself on every fresh net).
        let age = match node.finalized_height() {
            None | Some(0) => 0,
            Some(_) => {
                let tip_ts = chain.header(&chain.tip_hash()).map(|h| h.timestamp).unwrap_or(0);
                let base_hash = chain.finalized_hash().unwrap_or_else(|| chain.genesis_block_hash());
                let base_ts = chain.header(&base_hash).map(|h| h.timestamp).unwrap_or(0);
                tip_ts.saturating_sub(base_ts)
            }
        };
        let committee = node.slot_context(node.tip_height());
        Telemetry::assemble_with_halt(
            node.tip_height(),
            node.finalized_height(),
            age,
            node.mempool().len() as u64,
            self.p2p.peers().len() as u64,
            node.committee().current_epoch(),
            DEGRADED_MODE_LAG_BLOCKS,
            self.halt_at,
        )
        .with_committee(
            committee.roster as u64,
            committee.active as u64,
            committee.need as u64,
        )
        .with_supply(supply)
        .with_checkpoint(self.finalized_checkpoint_id(), self.local_commitment())
        .with_tip_difficulty(chain.header(&chain.tip_hash()).map(|h| h.difficulty))
        // Issue #212: head #3, the head that survives a restart. `with_checkpoint`
        // above stamped head #1, which does not. This composition DOES read head #3,
        // so calling the builder is the availability signal even when the answer is
        // `None` — see `Telemetry::with_durable_head`.
        .with_durable_head(node.durable_finalized_head())
    }

    /// A single observability sample line for the soak monitor (M10-T0-3 Phase
    /// B-lite). Reuses the canonical [`Telemetry::assemble`] rule — it never
    /// re-derives the frozen Ebb-and-Flow finality semantics — and adds the tip
    /// block's PoW `difficulty` so the LWMA retarget trace is visible over the
    /// soak (amendment-1 item 4). Age is chain-time (block timestamps), so this
    /// half is deterministic given the chain; the network half (peers/epoch) is
    /// read live. Emitted to stdout, captured via `docker compose logs`.
    pub fn telemetry_sample(&self) -> String {
        let node = self.p2p.node();
        // Issue #117: assembled once, in `telemetry()`, and shared with the
        // `/v1/telemetry` wire — the line and the wire report the same snapshot by
        // construction rather than by two copies of the same arithmetic.
        let t = self.telemetry();
        let regime = match t.finality_status {
            FinalityStatus::Final => "Final",
            FinalityStatus::Degraded => "Degraded",
            FinalityStatus::Halting => "Halting",
            FinalityStatus::Halted => "Halted",
        };
        let final_str = t.finalized_height.map(|h| h.to_string()).unwrap_or_else(|| "-".to_string());
        // `age_s=-` whenever there is no finalized checkpoint to measure from — no
        // finalized head (S8) or a finalized head still at genesis (#73) — so the
        // runbook's stall alarm never mistakes either for a real age. The rule
        // lives on `Telemetry` (the #117 discipline), shared with `qumbra-opview`.
        let age_str = t.age_field();
        // `halt=` is the operator's read of the upgrade schedule: `-` when this
        // release has none, the height when it does. Combined with `regime=`, the
        // soak monitor can tell "paused at the announced boundary" from "stuck".
        let halt_str = self.halt_at.map(|h| h.to_string()).unwrap_or_else(|| "-".to_string());
        // Layer-attributed refusal counts (#74). `hignore` = this release is halted
        // and did not act on a peer's block (RELEASE layer, no fault attributed);
        // `powrej` = a header failed the PoW target, which above an upgrade boundary
        // is the post-halt rule domain biting (HEADER-VALIDATION layer). The drill's
        // "which layer rejected the old branch?" question is answered from these two
        // numbers in the logs, not from a narrative.
        let ic = node.ingest_counters();
        // `dialable/known` is the NAT re-open trigger, condition 3 of Larry's
        // decision: it must fire on a MEASUREMENT, not on someone's memory that the
        // question was deferred. If this ratio collapses toward "only the seeds are
        // dialable", that is the signal to build NAT traversal.
        // Issue #87: `rounds=` / `rfail=` are **appended at the end**, and every
        // pre-existing field keeps its name, position and meaning. The T0 sampler and
        // the sealed evidence pack (PR #93) parse `key=value` pairs, so a consumer
        // that does not know these two simply does not read them. They exist so a
        // consumer watching only this line still sees checkpoint rounds failing —
        // the `ROUND` journal carries the detail, this carries the alarm.
        // Caliper: both are cumulative since PROCESS START, over rounds this node
        // closed; a restart resets them.
        //
        // Issue #105 narrowed WHAT they count, and nothing else — the names, the
        // positions and the arithmetic are untouched. They now cover **live rounds
        // only**: slots within one cadence of this node's own tip when it first
        // learned of them, plus any round that finalized here. A node that resyncs
        // 3,597 blocks crosses ~450 cadence slots the network settled hours before
        // it arrived; those are `backfill`, they are still journalled, and they are
        // counted in `rback=` below instead. Before this, they were `rfail`, and a
        // healthy node read `rounds=1316 rfail=1315` — an alarm at 99.9 % on a node
        // whose `final=` matched its three peers is an alarm nobody will ever read
        // again.
        //
        // `rback=` is appended at the end, under the #87/#84 rule. It exists so the
        // narrowing is not indistinguishable from deleting the counter on the line
        // an operator actually reads: the history a node walked through is a real
        // fact (it is the #104/#106 restart signature), it is just not a failure.
        let rounds_closed = node.rounds().closed_total();
        let rounds_failed = node.rounds().failed_total();
        let rounds_backfill = node.rounds().backfill_total();
        // Issue #84: `fid` / `sslot` / `sid` are **appended at the end**, and every
        // pre-existing field keeps its name, position and meaning (the #87 rule,
        // unchanged). They are the pair the drills need:
        //
        //   `fid` — WHAT this node finalized. `final=3776` agreeing across four
        //     hosts while `fid=` differs is two different checkpoints at one
        //     height: the R2 stop condition, previously undetectable because both
        //     nodes printed the identical `final=`.
        //   `sslot`/`sid` — what this node's own KEYS are committed to, and at
        //     which slot. This is the half that catches a split, because a
        //     minority that signed a different variant still finalizes the
        //     majority's: at slot 3776 all four hosts would print the same `fid`
        //     and one would print a different `sid`.
        //
        // Absence prints `-`, matching `final=`/`age_s=`/`halt=`: the line is
        // positional and a key that comes and goes forces a special case on every
        // parser. A verify-only node holding no committee keys prints
        // `sslot=- sid=-` and is still parsed by the same reader.
        // The three renderings live on `Telemetry` since #117, so the log line and
        // any reader of the wire cannot disagree about what `-` or `split` means.
        // Issue #130 (a): `stip=` / `slag=` are **appended at the end**, under the
        // same rule as #87's and #84's additions — every pre-existing field keeps its
        // name, position and meaning, and `run.rs`'s field-order test passes
        // unmodified.
        //
        // `tip=` has always been FORK CHOICE. `stip=` is the height whose **body** the
        // state machine has applied, and `slag=` is the difference. Until this line
        // carried them, every field on it came from the view that works: the four T0
        // hosts, the 48 h WAN soak, the halt drills and Phase B-lite's late-joiner
        // scenario would all have passed with the state machine arbitrarily far
        // behind, and #130 was found by a faucet page rather than by an instrument.
        //
        // **Both are always printed, zero included.** `final=-`/`age_s=-`/#125's
        // `age_field` refuse to state a figure they cannot stand behind, and these two
        // never have that problem: a node always knows both of its own tip heights, so
        // an omitted field would only force a special case on every parser in
        // `qumbra-ops/`. `slag=0` is the healthy reading and it is a fact.
        let lag = node.state_lag();
        // Issue #134: `uanchor=` is **appended at the end**, under the same rule as
        // #87's, #84's, #105's and #130 (a)'s additions — every pre-existing field
        // keeps its name, position and meaning.
        //
        // It counts block bodies this node **neither applied nor charged anyone for**,
        // because it could not evaluate anchor finality from where it stands. It is the
        // joiner's instrument, and until it existed the state #134 describes had no
        // field on this line at all: a joiner burning its outbound set for serving it
        // correct history looked, from the logs, exactly like "nobody would talk to
        // me". The pair to read it against is `slag=` — `uanchor=` climbing while
        // `slag=` stays pinned is a node being served history it cannot judge, i.e.
        // sync is not progressing and the peers are not at fault.
        //
        // Caliper: cumulative since PROCESS START, over bodies this node was handed; a
        // restart resets it. Zero is printed rather than omitted (the #130 (a) rule) —
        // a node always knows this count, so an omitted field would only force a
        // special case on every parser in `qumbra-ops/`.
        // Issue #106: `mready=` is **appended at the end**, under the same rule as
        // #87's, #84's and #130 (a)'s additions — every pre-existing field keeps its
        // name, position and meaning, and the `PRE_I84_FIELDS` prefix test passes
        // unmodified.
        //
        // It exists because **a node deliberately not mining looks exactly like a
        // node failing to mine**, and the operator surface had no field that could
        // tell them apart. After this change a rolled host that refuses to extend
        // the chain until it has synced is the correct, designed behaviour, and it
        // MUST be legible as such: `mready=unknown` says "I have not heard from any
        // peer yet", `mready=behind` says "I am catching up", and both are answers
        // to the question an operator asks at 12:01 while watching `tip=` sit at 4.
        //
        // Always printed, `-` for a non-miner (`final=-`/`age_s=-`'s precedent):
        // a key that comes and goes forces a special case on every parser in
        // `qumbra-ops/`.
        let mready = self.mine_gate();
        // Issue #162 finding 6: `stipid=` / `schain=` are **appended at the end**,
        // after `mready=`, under the same rule as every addition since #87 — every
        // pre-existing field keeps its name, position and meaning, and the
        // `PRE_I84_FIELDS` prefix test passes unmodified.
        //
        // 🔴 **`stip=` publishes a height and not an identity**, which is #84's
        // sentence one layer down: *"`final=` says how high, never what."* On the
        // 2026-07-31 T0 net, `node0`'s `stip=1` and `node2`'s `stip=1` looked
        // identical and were different blocks — node2's a sibling on a losing
        // branch — and separating them cost an archive dive. `stipid=` is that
        // identity, derived from the block hash at #84's width and printed through
        // #84's helper, so `fid` / `sid` / `stipid` are three readings of one scheme
        // and are comparable by eye.
        //
        // **`schain=` is the half that matters**, and it is a SEPARATE field rather
        // than a distinct `stipid=` rendering. The identity is the thing the archive
        // dive was for; overloading it with a verdict token would put a marker on
        // the one value every cross-host comparison reads, and each of those
        // comparisons would then have to strip it. #84's `sid=split` is not a
        // counter-example: there the identity is genuinely not single-valued, so
        // there is nothing to overload.
        //
        // `schain=main` = the applied tip IS the main-chain block at its height —
        // this node is lagging at worst, and will catch up. `schain=fork` = it is
        // not, so the state machine is on a branch it cannot rewind off and will
        // never catch up. **That distinction is the requirement**: `slag=13` covers
        // both states and they need opposite operator responses. Reading it against
        // `slag=`: `slag=0 schain=main` healthy · `slag=13 schain=main` catching up,
        // wait · `slag=13 schain=fork` **wedged, intervene**.
        //
        // Both always printed (the #130 (a) rule): a node always has an applied tip
        // and always knows whether it is on its own main chain, so an omitted field
        // would only force a special case on every parser in `qumbra-ops/`.
        // `schain=-` is reserved for the one comparison that cannot be made — fork
        // choice holding no block at the applied height — which is unreachable while
        // fork choice is at or above the applied tip.
        let applied = node.applied_tip();
        // Issue #130 (c): `breq=` is **appended at the end**, after `schain=`, under
        // the same rule as every addition since #87 — every pre-existing field keeps
        // its name, position and meaning, and the `PRE_I84_FIELDS` prefix test passes
        // unmodified.
        //
        // It is the count of historical block-body requests this node has
        // outstanding, and it exists because **`slag=` alone cannot distinguish a node
        // whose asks are going unanswered from a node that is not asking at all.**
        // That is not a hypothetical: on 2026-08-01 node3 held `stip=1` for thirteen
        // minutes and matched zero log lines for anything, and the archive could not
        // say from the telemetry whether the requester was broken or absent — it was
        // absent, because before this baton no requester existed. The pair to read is
        // `slag=` / `breq=`: `slag>0 breq=0` is *not asking* (no ready peer, or caught
        // up on the frontier); `slag>0 breq>0` sustained is *asking and not being
        // served*, which is a peer-side or version-skew problem and not this node's.
        //
        // Caliper: an instantaneous level, not a total — how many asks are in flight at
        // the moment the line is printed, capped at
        // `qlab_p2p::MAX_BODIES_IN_FLIGHT` (16). Always printed, zero included (the
        // #130 (a) rule): a node always knows this number.
        let body_reqs = self.p2p.body_requests();
        // Issue #85: `fback=` is appended after every existing field. It says
        // whether the exact checkpoint named by the finality tracker is backed by a
        // block in this host's own header chain (`local`) or is something this host
        // has only learned reached quorum (`heard`). `final=` keeps its existing
        // tracker meaning — learn-ahead is the capability, silent disagreement was
        // the defect. See `finality_backing_field` for the full-hash comparison.
        let finality_backing = self.finality_backing_field();
        // Issue #181: `unk=` is **appended at the end**, under the same rule as
        // every addition since #87 — every pre-existing field keeps its name,
        // position and meaning, and the `PRE_I84_FIELDS` prefix test passes
        // unmodified. This branch was written when `fback=` was the tail at `main`
        // `70706fc` and said so; `prest=` (#133 D3), `uex=` (#200) and `bdrop=`
        // (#130 (b)) have landed since, so `unk=` now follows all three.
        //
        // 🔴 **Why it is on this line and not only in `/metrics`.** #181 makes an
        // unrecognised frame silent, and a silent ignore is how the next
        // version-skew incident becomes invisible. The window where that matters is
        // a rolling upgrade — `OPERATOR.md` §4 rolls one host at a time and the
        // operator watches stdout while each host rejoins — and `/metrics` is
        // **off unless `metrics_addr` is set** (#87's decision, deliberate: a node
        // nobody scrapes listens on nothing extra). A counter that lives only
        // behind an optional endpoint would be absent on precisely the hosts that
        // skew first, which is the same shape as #84's finding: the most
        // informative reading missing from the only instrument the operator has.
        // It is also on `/metrics` (two counters), because a rate is a machine's
        // question — the two are the same numbers, as `dialable=` already is.
        //
        // Two numbers in one field, `dialable={}/{}`'s precedent: they answer one
        // question ("is something newer talking to me?") at two layers, and
        // splitting them would put two fields on the line for one fact.
        //
        // Caliper: cumulative **since process start**, over frames and inventory
        // items this node was handed after the inbound rate limiter; a restart
        // resets both. Always printed, zeroes included (the #130 (a) rule) — a node
        // always knows these counts, and `unk=0/0` is the healthy reading and a
        // fact. Neither number is ever a scoring input; that is the whole of #181.
        let unk = self.p2p.unknown_stats();
        // Issue #133 D3: `prest=` is **appended at the end**, after `breq=`, under the
        // same rule as every addition since #87 — every pre-existing field keeps its
        // name, position and meaning, and the `PRE_I84_FIELDS` prefix test passes
        // unmodified. Touches TELEMETRY.
        //
        // It is the committee-punishment restore report from process start, and it
        // exists because after a restart `qumbra_committee_active` and `ROUND`'s
        // `active=` return to the full roster with no other surface saying so —
        // **byte-identical to a net where nobody was ever punished, and byte-identical
        // to every healthy cold start.** Five other instances of that shape were
        // invisible in exactly this way.
        //
        // Shape is `restored/known` (or `unk`), not a bare count: `0` alone cannot
        // distinguish *nothing to restore* from *could not restore anything*. See
        // [`qlab_p2p::punish::PunishmentRestore::telemetry_field`]. Latched at open;
        // every sample in the process reprints the same value. Always printed, zero
        // included.
        //
        // ⚠️ A host that never observed an equivocation prints `prest=0/0` forever.
        // That is correct for the local ledger (PR #159) and is **not** proof the net
        // is punishment-free: a peer that saw the evidence and this host did not still
        // disagree about who may sign. Agreement needs evidence in blocks (D1).
        let prest = node.punishment_restore().telemetry_field();
        // Issue #200: `uex=` is **appended at the end**, after `prest=`, under the
        // same rule as every addition since #87 — every pre-existing field keeps its
        // name, position and meaning, and the `PRE_I84_FIELDS` prefix test passes
        // unmodified. **Touches TELEMETRY.**
        //
        // It is the unobtainable-body exemption latch: `1` when this node has been
        // lagging with an outstanding, unserved body request for
        // `UNOBTAINABLE_BODY_CADENCES` cadences and may therefore mine on its
        // verified state tip; `0` otherwise. It exists because **a node mining
        // while `slag>0` looks exactly like a broken duty gate**, and an operator
        // needs one field that says "it was the exemption". Always printed, zero
        // included (the #130 (a) rule).
        let uex = u8::from(node.state_tip_mine_ready());
        // Issue #130 (b): `bdrop=` is appended after `uex=`, under the same rule as
        // every addition since #87 — every pre-existing field keeps its name, position
        // and meaning, and the `PRE_I84_FIELDS` prefix test passes unmodified.
        // (Merged after #200 landed on `main`; this branch was written when `fback=`
        // was the tail, so `bdrop=` follows `prest=` and `uex=`, not `fback=`.)
        //
        // 🔴 It is the field #130 asked for by name. `apply_block`'s failure at the
        // body-application funnel was swallowed by an `Err(_) => {}` arm carrying a
        // comment that called the drop expected, and **no counter and no telemetry
        // field existed for it** — so on the one instrument an operator has, a node
        // dropping every body it was handed printed exactly what a healthy node
        // prints. #130 is explicit that this is what made it the worst of the five
        // same-shaped defects that week: *"every other instance was silence; this one
        // was silence with a comment vouching for it."*
        //
        // Caliper: cumulative since PROCESS START over bodies this node's own state
        // machine refused, paired with the CHAIN HEIGHT of the most recent refusal —
        // `bdrop=0@-` when there has been none. See
        // [`qlab_p2p::NodeAdapter::body_refusals`] for why the height is there and why
        // it is a height. The pair to read it against is `stip=`: `bdrop=17@412` next
        // to `stip=413` is a node refusing bodies right now; the same `bdrop=17@412`
        // next to `stip=9000` is a burst that ended long ago. Per-reason attribution
        // is on `/metrics` (`qumbra_body_apply_refused_total`), which is where the
        // question "which of the five, and is `not_extending_tip` still zero" belongs.
        let bdrop = bdrop_field(node.body_refusals());
        // Issue #204: `cpq=` is **appended at the end**, after `uex=`, under the same
        // rule as every addition since #87 — every pre-existing field keeps its name,
        // position and meaning, and the `PRE_I84_FIELDS` prefix test passes
        // unmodified. **Touches TELEMETRY.**
        //
        // It is the count of finalized-checkpoint queries in flight (issue #204's
        // "ask the net what is finalized"), and it exists because of the sentence
        // that issue asked to be kept: **`sslot=` and `final=` are both already on
        // this line and nothing compared them.** The comparison is now made in code
        // every tick — `tip` against `final`, which is the superset, because a
        // keyless node has no `sslot` and was diverging in exactly the same way —
        // and this field is where an operator sees that check firing.
        //
        // The pair to read is `final=` / `cpq=`, exactly as #130 (c) reads
        // `slag=` / `breq=`: `final=` stuck with `cpq=0` is *this node has not
        // noticed*; `final=` stuck with `cpq=1` sustained is *asking and not being
        // served*, which is a peer-side or version-skew problem and not this node's.
        // On 2026-08-01 node1 printed the first reading for hours and there was no
        // field on the line that could have told the two apart.
        //
        // Caliper: an instantaneous level, not a total — how many asks are in flight
        // at the moment the line is printed, capped at
        // `qlab_p2p::node::MAX_CHECKPOINT_QUERIES_IN_FLIGHT` (1). Always printed,
        // zero included (the #130 (a) rule).
        let cpq = self.p2p.checkpoint_queries();
        // Issue #204 (the coordinator's 2026-08-02 correction to #203): `dfin=` and
        // `fdrop=` are **appended at the end**, after `cpq=`, under the same rule as
        // every addition since #87 — every pre-existing field keeps its name,
        // position and meaning, and the `PRE_I84_FIELDS` prefix test passes
        // unmodified. **Touches TELEMETRY.**
        //
        // 🔴 **`final=` is not the head that survives a restart.** `final=` and `fid=`
        // read the `FinalityTracker` (head #1), which is discarded at shutdown and
        // re-derived at `open` from the state machine's chain store (head #3) — and
        // head #3 is what `Snapshot.finalized` is written from, and what
        // `no_reorg_past_finalized_checkpoint_ever` ultimately executes on. Nothing
        // anywhere compared the two. node1 printed `final=1056` on every sample for
        // hours with a durable head of 1048, and no field on this line could say so.
        //
        //   `dfin=` — head #3's height, or `-`. `final=` and `dfin=` disagreeing is
        //     the divergence, on one line, side by side, in the same units.
        //   `fdrop=` — distinct finalize-record refusals since process start. A
        //     TRANSITION count, not an attempt count: `sync_state_finality` retries
        //     every drain, so counting attempts would report the retry rate. `0` on
        //     every healthy node, always; `>0` means read the `FINALIZE refused`
        //     journal lines, which carry the head, the height and the reason.
        //
        // Both always printed, zero and `-` included (the #130 (a) rule).
        //
        // Issue #212: `dfin=` now reads the SNAPSHOT (`t.durable`) rather than
        // calling `durable_finalized_height()` a second time. Same store, same
        // value, and the same reason #117 assembled this line and the wire from one
        // snapshot: two reads of one fact can disagree and there is nothing for them
        // to disagree with if there is only one. `dfin=`'s vocabulary is
        // **unchanged** — a height, or `-`.
        let dfin = t.durable.height_field();
        let fdrop = node.finalize_refused_total();
        // Issue #212: `dfinbh=` is **appended at the end**, after `bask=`, under the
        // same rule as every addition since #87 — every pre-existing field keeps its
        // name, position and meaning, and the `PRE_I84_FIELDS` prefix test passes
        // unmodified. **Touches TELEMETRY.**
        //
        // 🔴 **`dfin=` publishes a height and not an identity**, which is #84's
        // sentence applied to head #3: *"`final=` says how high, never what."* Two
        // hosts both reporting `dfin=2864` may hold different blocks there, and that
        // divergence survives a restart on both of them — which is strictly worse
        // than the `fid` split #84 bought onto this line, because head #1 is
        // discarded at shutdown and head #3 is not.
        //
        // 🔴 **It is a BLOCK HASH prefix and `fid=` is a checkpoint identity.
        // Comparing them is meaningless** — `fid` is
        // `keccak256(height ‖ block_hash ‖ root)` truncated, the digest of the exact
        // bytes the committee's ML-DSA keys signed, and no truncation of a block hash
        // becomes one. Hence `dfinbh` and not `dfid`: every identity field here so
        // far ends in `id`, and a fourth would invite exactly that comparison.
        // `OPERATOR.md` §3 already carries the cost of one such mistake ("two
        // different values are called 'the genesis hash'"). The wire type
        // (`qlab_node::BlockIdentity`) makes the comparison a compile error; this
        // name is the half an operator reads.
        //
        // Caliper: an instantaneous level read from the same snapshot as `dfin=`.
        // Always printed, `-` included (the #130 (a) rule) — `-` when head #3 holds
        // nothing, which on a node reporting a real `final=` is itself the alarm.
        let dfinbh = t.durable.id_field();
        // Issue #229: `bask=` is **appended at the end**, after `fdrop=`, under the
        // same rule as every addition since #87 — every pre-existing field keeps its
        // name, position and meaning, and the `PRE_I84_FIELDS` prefix test passes
        // unmodified. **Touches TELEMETRY.**
        //
        // 🔴 **It is the one thing this line could not say about a stranded node.**
        // Three hosts printed `schain=fork`, a frozen `stip`, `slag=21` and
        // `breq=1–2` for over an hour, and the whole diagnosis turned on a number
        // none of those four fields carries: *how many bodies the requester actually
        // asked for*. `breq=` is the in-flight level, capped at
        // `MAX_BODIES_IN_FLIGHT`; the **ask set** is what `missing_body_hashes`
        // produced, and **an ask set of 15 with 2 in flight and an ask set of 2 are
        // the same `breq=` and different bugs.** The second number is
        // `state_fork_point()`'s answer — where the requester is walking *from* —
        // which no surface anywhere published, so a wrong base was equally
        // invisible.
        //
        // Two numbers in one field, `dialable=`'s and `unk=`'s precedent: they
        // answer one question — *is the requester asking for the right blocks?* —
        // and splitting them would put two fields on the line for one fact.
        //
        // Read it against `breq=` and `slag=`: `bask=15@2680 breq=15` is a
        // requester doing its job and a serving problem; `bask=2@2680 slag=21` is an
        // ask set that cannot close the gap it is looking at; `bask=0@-` is
        // `state_fork_point()` answering `None`, which is the requester walking from
        // the applied tip of a dead branch.
        //
        // Caliper: an instantaneous level computed at print time, the ask set the
        // requester itself would produce on this tick with the same `max`
        // (`qlab_p2p::node::MAX_BODIES_IN_FLIGHT`, 16) — **so it saturates at 16 and
        // is not a gap size**. The fork point is a chain height, or `-` when the
        // walk returns nothing. Always printed, `0@-` included (the #130 (a) rule).
        let bask = node.ask_set_observation(self.p2p.body_requests(), self.mining).telemetry_field();
        // Issue #359 S3: `snap=` is **appended at the end**, after `dfinbh=`, under
        // the same rule as every addition since #87 — every pre-existing field keeps
        // its name, position and meaning, and the `PRE_I84_FIELDS` prefix test passes
        // unmodified (the #106 `mready=` precedent). **Touches TELEMETRY.**
        //
        // 🔴 **It is the field that turns "does this host have a snapshot" from an
        // ssh + `ls` into a read of the instrument the operator already has.** On
        // 2026-08-12 that question decided a day of committee liveness: node3
        // restarted with no `snapshot.bin`, replayed 11,751 records over 4.6 h, and
        // then could not close the gap at all — while node0, restarted three minutes
        // earlier, resumed from a snapshot at height 4,719 and was back in about an
        // hour. Nothing on this line, on `/metrics`, or in `halt-status` could tell
        // the two hosts apart *before* the restart, which is the only moment the
        // answer is worth anything. The OPERATOR §3 standing rule — read snapshot
        // presence before planning a roll — is now readable from telemetry.
        //
        // Three tokens, sharing one vocabulary with `halt-status` so one grep covers
        // both surfaces: **a height** (a restart resumes there and replays only past
        // it), **`none`** (no `snapshot.bin` — node3's shape, a from-genesis replay
        // on the next start), **`bad`** (a snapshot present but undecodable or at a
        // different `FORMAT_VERSION` — the same full replay, a different cause).
        // `none` and `bad` are both the alarm; they are kept apart because "a write
        // never happened" and "a write happened under another format" are different
        // repairs.
        //
        // Caliper: **the applied height in the snapshot this process last wrote or
        // read**, not a fresh disk read — the decode is O(state size) and this line
        // prints every 30 s. Seeded by one read at startup and advanced by this
        // process's own writes (the cadence and the shutdown flush), which is exact
        // while this process is the data dir's only snapshot writer, and it is. Read
        // it against `stip=`: `snap=` far below `stip=` is a node whose next restart
        // replays that difference, and `snap=none` next to any `stip=` at all is the
        // host a roll must not be planned against.
        let snap = self.durable_snapshot.field();
        format!(
            "TELEMETRY tip={} final={} stall={} age_s={} diff={} peers={} mempool={} epoch={} regime={} halt={} hignore={} powrej={} dialable={}/{} rounds={} rfail={} fid={} sslot={} sid={} rback={} stip={} slag={} uanchor={} mready={} stipid={} schain={} breq={} fback={} prest={} uex={} bdrop={} unk={}/{} cpq={} dfin={} fdrop={} bask={} dfinbh={} snap={}",
            t.tip_height, final_str, t.stall_depth, age_str, t.tip_difficulty.unwrap_or(0),
            t.peer_count, t.mempool_size, t.epoch, regime, halt_str,
            ic.halt_ignored, ic.pow_rejected,
            self.p2p.addrs().dialable_count(), self.p2p.addrs().known_count(),
            rounds_closed, rounds_failed,
            t.fid_field(),
            t.sslot_field(),
            t.sid_field(),
            rounds_backfill,
            lag.state_tip,
            lag.blocks(),
            ic.unjudged_anchor,
            mready.field(),
            applied.id_field(),
            applied.chain_field(),
            body_reqs,
            finality_backing,
            prest,
            uex,
            bdrop,
            unk.frames,
            unk.inv_items,
            cpq,
            dfin,
            fdrop,
            bask,
            dfinbh,
            snap,
        )
    }

    // ---- issue #87: round diagnostics + structured metrics -------------------

    /// Select the round-diagnostics clock. The binary opts into
    /// [`ObsClock::WallClock`] alongside [`Self::set_mining_clock`]; tests keep the
    /// deterministic default, which records counts but never invents timings.
    pub fn set_obs_clock(&mut self, clock: ObsClock) {
        self.p2p.node_mut().set_obs_clock(clock);
    }

    /// Bind the `/metrics` scrape endpoint. Returns the bound address.
    ///
    /// Called only when `metrics_addr` is set in the config: a node nobody scrapes
    /// listens on nothing extra. An unbindable address is an **error**, never a
    /// silent no-op — a node that believes it is observable and is not is the exact
    /// failure this issue exists to remove.
    pub fn start_metrics_endpoint(&mut self, addr: &str) -> std::io::Result<std::net::SocketAddr> {
        self.refresh_metrics(); // serve a real snapshot from the first scrape on
        let srv = MetricsServer::start(addr, Arc::clone(&self.metrics_snapshot))?;
        let bound = srv.addr();
        self.metrics_server = Some(srv);
        Ok(bound)
    }

    /// The current exposition text (also what a scrape would receive after the next
    /// refresh). Rendering is a few dozen string appends over integer state.
    pub fn metrics_text(&self) -> String {
        render_metrics(self.p2p.node().metrics(), &self.live_gauges())
    }

    /// Live levels for the exposition, read from node state at render time.
    fn live_gauges(&self) -> LiveGauges {
        // Issue #84. Note the `split` case has no gauge representation and is
        // reported as *absent*: a scrape must not carry a number that is one of two
        // disagreeing values. The `TELEMETRY`/`ROUND` lines say `split` in words,
        // and `qumbra_signed_checkpoint_slot` is still emitted, so the
        // identity-missing-while-slot-present shape is itself the scrape-side
        // signal.
        let commitment = self.local_commitment();
        let node = self.p2p.node();
        let chain = node.chain();
        let tip = node.tip_height();
        let tip_diff = chain.header(&chain.tip_hash()).map(|h| h.difficulty).unwrap_or(0);
        let finalized = node.finalized_height();
        let ctx = node.slot_context(tip);
        let regime = match node.finality_status() {
            FinalityStatus::Final => "final",
            FinalityStatus::Degraded => "degraded",
            FinalityStatus::Halting => "halting",
            FinalityStatus::Halted => "halted",
        };
        // Issue #130 (a): both views, and the buffer between them, read from the
        // adapter's single `state_lag()` rather than re-differenced here.
        let lag = node.state_lag();
        // Issue #162 finding 6: the applied tip's identity and the wedge verdict come
        // from the adapter's one `applied_tip()`, exactly as the heights come from its
        // one `state_lag()` — the log line and the scrape cannot disagree about which
        // block the state machine is on.
        let applied = node.applied_tip();
        let (pending, pending_bytes) = node.pending_bodies();
        LiveGauges {
            tip_height: tip,
            state_tip: lag.state_tip,
            state_lag: lag.blocks(),
            // `bits()` is the one escape hatch on `BlockIdentity` and this gauge is
            // its second live site: Prometheus carries an integer. See #212.
            state_tip_id: applied.identity().bits(),
            state_tip_off_main_chain: applied.off_main_chain(),
            pending_bodies: pending as u64,
            pending_body_bytes: pending_bytes as u64,
            finalized_height: finalized,
            // Same rule as the telemetry wire, read from it rather than re-derived.
            stall_depth: match finalized {
                Some(f) => tip.saturating_sub(f),
                None => tip,
            },
            regime,
            difficulty: tip_diff,
            peers: self.p2p.peers().len() as u64,
            dialable: self.p2p.addrs().dialable_count() as u64,
            known: self.p2p.addrs().known_count() as u64,
            mempool: node.mempool().len() as u64,
            epoch: node.committee().current_epoch(),
            committee_size: ctx.roster as u64,
            committee_active: ctx.active as u64,
            quorum: ctx.need as u64,
            open_rounds: node.rounds().open_len() as u64,
            halt_at: self.halt_at,
            finalized_checkpoint_id: node.finality().latest().map(|cp| cp.identity()),
            signed_checkpoint_id: commitment.and_then(|c| c.id),
            signed_checkpoint_slot: commitment.map(|c| c.slot),
            throttled_frames: {
                let s = self.p2p.rate_stats();
                s.throttled_frames + s.throttled_bytes
            },
            throttled_getaddr: self.p2p.rate_stats().throttled_getaddr,
            // Issue #181, read from the same `unknown_stats()` the `TELEMETRY`
            // line reads, so the log and the scrape cannot come to disagree about
            // how much version skew this node has seen.
            unknown_msg_type: self.p2p.unknown_stats().frames,
            unknown_inv_kind: self.p2p.unknown_stats().inv_items,
            outbound_netgroups: self.p2p.addrs().outbound_groups().len() as u64,
            process_start_secs: self.process_start_secs,
            rendered_at_secs: unix_secs(),
        }
    }

    /// Bind the `/v1/telemetry` read endpoint (issue #117). Returns the bound
    /// address.
    ///
    /// Called only when `telemetry_addr` is set in the config. Like
    /// [`Self::start_metrics_endpoint`], an unbindable address is an **error**, not
    /// a silent no-op: a node whose operator believes it is readable and which is
    /// not is the failure this endpoint exists to remove.
    pub fn start_telemetry_endpoint(&mut self, addr: &str) -> std::io::Result<std::net::SocketAddr> {
        self.refresh_telemetry(); // serve a real snapshot from the first read on
        let srv = TelemetryServer::start(addr, Arc::clone(&self.telemetry_snapshot))?;
        let bound = srv.addr();
        self.telemetry_server = Some(srv);
        Ok(bound)
    }

    /// Re-encode the snapshot the `/v1/telemetry` endpoint serves.
    fn refresh_telemetry(&mut self) {
        let bytes = self.telemetry().to_bytes();
        if let Ok(mut slot) = self.telemetry_snapshot.lock() {
            *slot = bytes;
        }
    }

    /// Bind the `/v1/compact` note-discovery endpoint (issue #188 baton 2).
    /// Returns the bound address.
    ///
    /// Called whenever `config.discovery_bind()` yields an address, which — unlike
    /// every other listener in this binary — is the **default**. An unbindable
    /// address is an error and never a silent no-op, and because this one is on by
    /// default that turns a port conflict into a node that will not start; the
    /// error message names `discovery_addr = "off"`.
    pub fn start_discovery_endpoint(&mut self, addr: &str) -> std::io::Result<std::net::SocketAddr> {
        // Project before binding, so the first read is answered from the chain this
        // process actually opened rather than from an empty view.
        self.refresh_discovery();
        self.refresh_leaves();
        self.refresh_anchors();
        // The submit rendezvous (issue #275): the server holds the sender, this
        // loop drains the receiver once per iteration.
        let (submit_tx, submit_rx) = std::sync::mpsc::sync_channel(MAX_QUEUED_SUBMITS);
        let srv = DiscoveryServer::start(
            addr,
            Arc::clone(&self.discovery_view),
            Arc::clone(&self.leaves_view),
            Arc::clone(&self.anchors_view),
            submit_tx,
        )?;
        let bound = srv.addr();
        self.discovery_server = Some(srv);
        self.submit_rx = Some(submit_rx);
        Ok(bound)
    }

    /// The bound `/v1/compact` address, if serving.
    pub fn discovery_addr(&self) -> Option<std::net::SocketAddr> {
        self.discovery_server.as_ref().map(|s| s.addr())
    }

    /// Re-project the main chain's committed discovery for `/v1/compact`.
    ///
    /// Reads the block store and copies `StoredTx::discovery` verbatim; there is no
    /// encoder between the block and the served bytes, which is what makes a served
    /// group that differs from the committed one unconstructible rather than
    /// unlikely. Incremental: an unchanged tip returns without touching the view.
    pub fn refresh_discovery(&mut self) -> bool {
        let mut next = (**self
            .discovery_view
            .lock()
            .unwrap_or_else(|p| p.into_inner()))
        .clone();
        if !next.refresh(self.p2p.node().state().chain()) {
            return false;
        }
        if let Ok(mut slot) = self.discovery_view.lock() {
            *slot = Arc::new(next);
        }
        true
    }

    /// The projection `/v1/compact` is currently serving (tests / accounting).
    pub fn discovery_view(&self) -> Arc<DiscoveryView> {
        Arc::clone(&self.discovery_view.lock().unwrap_or_else(|p| p.into_inner()))
    }

    /// Re-project the commitment-tree leaves for `/v1/tree/leaves` (issue #275).
    ///
    /// Keyed on the applied tip hash: the leaves are derived deterministically
    /// from the applied chain (`apply_state`'s funnel — and a rewind rebuilds
    /// them with the rest of derived state), so the same applied tip means the
    /// same leaves and an unchanged tip costs two comparisons and no copy. On a
    /// change the whole ordered vector is cloned — 32 B per leaf, once per
    /// applied block at steady state — rather than diffed, because a wrong
    /// incremental splice here would serve a tree the node never had.
    pub fn refresh_leaves(&mut self) -> bool {
        let state = self.p2p.node().state();
        let sig = (state.chain().tip_hash(), state.commitments_ordered().len() as u64);
        if self.leaves_sig == Some(sig) {
            return false;
        }
        let snapshot = Arc::new(LeavesView { leaves: state.commitments_ordered().to_vec() });
        if let Ok(mut slot) = self.leaves_view.lock() {
            *slot = snapshot;
        }
        self.leaves_sig = Some(sig);
        true
    }

    /// The leaves `/v1/tree/leaves` is currently serving (tests / accounting).
    pub fn leaves_view(&self) -> Arc<LeavesView> {
        Arc::clone(&self.leaves_view.lock().unwrap_or_else(|p| p.into_inner()))
    }

    /// Re-project the valid-anchor set for `/v1/anchors` (issue #276).
    ///
    /// Keyed on `(applied tip, finalized height)` — see [`Self::anchors_sig`]
    /// for why finality has to be in the key. The derivation is
    /// [`qlab_node::anchor_set`], the same one `NodeRpc::anchors` uses; this
    /// binary composes no `NodeRpc`, which is exactly why that function stopped
    /// being a method in issue #276.
    ///
    /// Encoded here rather than per request: one answer, no query, so the loop
    /// pays the encode once per change and a poller cannot make the server
    /// work.
    pub fn refresh_anchors(&mut self) -> bool {
        let state = self.p2p.node().state();
        let sig = (state.chain().tip_hash(), state.chain().finalized_height());
        if self.anchors_sig == Some(sig) {
            return false;
        }
        let snapshot = Arc::new(AnchorsView { encoded: qlab_node::anchor_set(state).to_bytes() });
        if let Ok(mut slot) = self.anchors_view.lock() {
            *slot = snapshot;
        }
        self.anchors_sig = Some(sig);
        true
    }

    /// The anchor set `/v1/anchors` is currently serving (tests / accounting).
    pub fn anchors_view(&self) -> Arc<AnchorsView> {
        Arc::clone(&self.anchors_view.lock().unwrap_or_else(|p| p.into_inner()))
    }

    /// Answer every submission the discovery server has queued (issue #275).
    ///
    /// Called once per loop iteration — an empty queue costs one `try_recv`. The
    /// queue is bounded at [`MAX_QUEUED_SUBMITS`], so one pass is bounded work,
    /// and each verdict costs this loop the same admission a peer-delivered tx
    /// costs it (the proof verify dominating). A reply whose handler already
    /// gave up waiting is dropped on the floor by `try_send` — the admission
    /// stands either way, and a resubmission answers `duplicate`.
    pub fn drain_remote_submits(&mut self) {
        loop {
            let req = match self.submit_rx.as_ref().map(|rx| rx.try_recv()) {
                Some(Ok(req)) => req,
                _ => break,
            };
            let outcome = self.submit_remote_tx(req.tx);
            let _ = req.reply.try_send(outcome);
        }
    }

    /// Judge and (on success) announce one remotely-submitted transaction — the
    /// server half of the stamped A1 seam (issue #275).
    ///
    /// The checks are `NodeRpc::submit_tx`'s, in its order, run **before**
    /// `announce_tx` so every refusal is named (a surface on bare `announce_tx`
    /// would be boolean-blind — the faucet's honest limitation, decision brief
    /// §2), and none is a second validation path:
    ///
    /// 1. **In-tx nullifier repeat** — [`qlab_node::repeated_nullifier_in_tx`].
    ///    Since issue #278 `Mempool::admit` runs the same rule on every path
    ///    into the pool; this surface keeps the early call so the refusal is
    ///    its own named token (`nullifier-repeated-in-tx`) rather than the
    ///    flattened pool verdict.
    /// 2. **The §4 discovery↔cm binding** —
    ///    [`qlab_devnet::body::check_tx_discovery`], the same consensus function
    ///    `validate_body` runs per block. `NodeRpc::submit_tx`'s own discovery
    ///    check compares separately-submitted artifacts against the committed
    ///    bytes; over this wire there are no separate artifacts — the group IS
    ///    in the body — so the §4 rules are the whole check, and they are
    ///    strictly what a block embedding this tx will be judged by.
    /// 3. **The typed admission + relay** —
    ///    [`P2pNode::announce_tx_typed`], i.e. `NodeAdapter::submit_tx_typed`
    ///    (the state-lag gate and `Mempool::admit`'s posted-fee / in-tx-repeat /
    ///    anchor / double-spend / duplicate / in-pool-conflict / §4-discovery /
    ///    real-proof gates — exactly what every peer-delivered tx passes),
    ///    relaying exactly when `announce_tx` would.
    /// 4. **The pool re-read** — `submit_local_tx`'s pattern: report what IS in
    ///    the pool, not what the return value promised. Its failure arm is a
    ///    named 500, kept expressible so this stays a check.
    ///
    /// Answers the **statement** tx id ([`qlab_node::rpc::tx_id`]) — the id
    /// `NodeRpc::submit_tx` answers, stable whether the tx is pending or later
    /// embedded — not the mempool's body-commitment id or the gossip wire id.
    pub fn submit_remote_tx(&mut self, tx: TxEntry) -> TxSubmitOutcome {
        let p = &tx.public;
        let txid = qlab_node::rpc::tx_id(
            &p.anchor,
            &p.nullifiers,
            &p.commitments,
            p.bucket.logical_actions(),
            p.fee,
        );
        if qlab_node::repeated_nullifier_in_tx(p).is_some() {
            return TxSubmitOutcome::Refused(TxRefusal::RepeatedNullifier);
        }
        if let Err(e) = qlab_devnet::body::check_tx_discovery(0, &tx) {
            return TxSubmitOutcome::Refused(TxRefusal::Discovery(e));
        }
        use qlab_p2p::adapter::TxSubmitRefusal as R;
        match self.p2p.announce_tx_typed(tx) {
            Ok(pool_id) => {
                if self.p2p.node().mempool().contains(&pool_id) {
                    TxSubmitOutcome::Accepted { txid }
                } else {
                    TxSubmitOutcome::Refused(TxRefusal::AdmittedButNotPooled)
                }
            }
            Err(R::Pool(qlab_node::MempoolError::DuplicateTx)) => {
                TxSubmitOutcome::Duplicate { txid }
            }
            Err(e) => TxSubmitOutcome::Refused(TxRefusal::Submit(e)),
        }
    }

    /// Re-render the snapshot the scrape server serves.
    fn refresh_metrics(&mut self) {
        let text = self.metrics_text();
        if let Ok(mut slot) = self.metrics_snapshot.lock() {
            *slot = text;
        }
    }

    /// Accumulate wall time into the current finality regime.
    ///
    /// This is what makes "`Degraded` 15.9 %" a measured residency rather than a
    /// count of the samples that happened to print while degraded. Called on every
    /// loop pass, so the resolution is the loop's, not the sampler's.
    pub fn accumulate_regime(&mut self) {
        let elapsed = self.last_regime_tick.elapsed();
        self.last_regime_tick = Instant::now();
        let regime = match self.p2p.node().finality_status() {
            FinalityStatus::Final => "final",
            FinalityStatus::Degraded => "degraded",
            FinalityStatus::Halting => "halting",
            FinalityStatus::Halted => "halted",
        };
        self.p2p.node_mut().metrics_mut().observe_regime(regime, elapsed.as_millis() as u64);
    }

    /// **The slot cursor.** Open a diagnostics record for every cadence slot the
    /// chain has reached, whether or not this node proposes or holds a key.
    ///
    /// Without this, a slot that nobody proposed — or whose proposal never reached
    /// us — would leave no trace, and "no trace" is indistinguishable from "nothing
    /// happened". That indistinguishability is the 42 h silence.
    ///
    /// **This is also where a resync used to manufacture 1,315 failed rounds**
    /// (issue #105). The cursor is unchanged and still crosses every slot — the
    /// trace stays — but the ledger now reads `ctx.tip` alongside the roster and
    /// records whether this node reached each slot as a round or as history. On a
    /// resync the tip has already jumped hundreds of blocks by the time this runs,
    /// so all but the slot at the very edge of the jump are `backfill`.
    pub fn note_slots_reached(&mut self) {
        let tip = self.p2p.node().tip_height();
        while self.next_round_slot <= tip {
            // HALT (issue #74, H2): the committee stops checkpointing above H, so
            // there is no round above H to journal either.
            if self.halt_at.is_some_and(|h| self.next_round_slot > h) {
                break;
            }
            let ctx = self.p2p.node().slot_context(self.next_round_slot);
            self.p2p.node_mut().rounds_mut().note_slot_reached(&ctx);
            self.next_round_slot += CHECKPOINT_CADENCE_BLOCKS;
        }
    }

    /// Emit one `ROUND` journal line per round that closed since the last call, and
    /// fold each into the metric aggregates. Returns the lines emitted.
    ///
    /// The journal goes to **stdout, beside the `TELEMETRY` line** — deliberately.
    /// The container log is what is archived and cited as evidence, and (unlike a
    /// scrape target on 7-day retention) it needs no inbound rule to reach. Metrics
    /// answer "how often"; only the journal can answer "who was missing in round
    /// 1,384", and that question is asked after the fact.
    pub fn emit_rounds(&mut self) -> Vec<String> {
        let closed = self.p2p.node_mut().drain_rounds();
        let lines: Vec<String> = closed.iter().map(|r| r.to_line()).collect();
        for line in &lines {
            println!("{line}");
        }
        lines
    }

    /// Emit one `REWIND` journal line per state-machine rewind since the last call
    /// (issue #162), and return the lines emitted.
    ///
    /// Emitted on the message-pump cadence rather than the telemetry cadence, beside
    /// `ROUND`, because a rewind is an **event** and the telemetry line only ever
    /// carries levels. `slag=` returning to zero is what an operator sees; this is the
    /// line that says why it did — which is the whole difference between a wedge
    /// detector that went quiet because the wedge went away and one that went quiet
    /// because it broke.
    pub fn emit_rewinds(&mut self) -> Vec<String> {
        let lines: Vec<String> = self
            .p2p
            .node_mut()
            .drain_rewinds()
            .iter()
            .map(|r| r.to_string())
            .collect();
        for line in &lines {
            println!("{line}");
        }
        lines
    }

    /// Emit one `FINALIZE refused` journal line per finalize record this node
    /// declined to write since the last call (issue #204), and return the lines.
    ///
    /// Beside `REWIND`, on the message-pump cadence, for the same reason: a refusal
    /// is an **event** and the telemetry line only ever carries levels. `fdrop=` is
    /// the alertable count; this is the line that says which head refused, at what
    /// height, for which checkpoint, and why — which is the whole difference between
    /// knowing a divergence happened and being able to act on it.
    pub fn emit_finalize_refusals(&mut self) -> Vec<String> {
        let lines: Vec<String> = self
            .p2p
            .node_mut()
            .drain_finalize_refusals()
            .iter()
            .map(|r| r.to_string())
            .collect();
        for line in &lines {
            println!("{line}");
        }
        lines
    }

    /// **Emit the `BODYWAIT` journal for a node that has stopped applying blocks**
    /// (issue #229), and return the lines emitted.
    ///
    /// Beside `REWIND` and `FINALIZE refused`, on the message-pump cadence, and
    /// for the same reason those are: `TELEMETRY` carries levels, and this is the
    /// surface that can carry per-entry, per-peer detail a field cannot.
    ///
    /// 🔴 **Why here and not `/metrics`.** `metrics_addr` is `Option<String>` with
    /// `#[serde(default)]` — *"Unset = no listener at all, the default and the
    /// right one for any node"* — and every T0 host runs that default. The mining
    /// refusal this line reports is already a counter behind exactly that endpoint
    /// (`refuse_for_lag` is `self.metrics.observe_lag_refusal(duty)` and nothing
    /// else), which is why three hosts stopped mining for forty minutes with no
    /// reachable surface saying so. A new counter there would reproduce the defect
    /// it exists to close.
    ///
    /// **Empty on every healthy node, always** — see
    /// [`qlab_p2p::adapter::NodeAdapter::ask_set_observation`] for the arming
    /// predicate and why it is `stip` frozen rather than `slag` large.
    pub fn emit_body_waits(&mut self) -> Vec<String> {
        let now_ms = self.started.elapsed().as_millis() as u64;
        self.emit_body_waits_at(now_ms)
    }

    /// [`Self::emit_body_waits`] against a caller-supplied monotonic clock — the
    /// seam the tests drive, so a 20-minute threshold is reachable without a
    /// 20-minute test.
    pub fn emit_body_waits_at(&mut self, now_ms: u64) -> Vec<String> {
        let in_flight = self.p2p.body_requests();
        let obs = self.p2p.node().ask_set_observation(in_flight, self.mining);
        let entries = self.p2p.body_ask_report(now_ms);
        let heartbeat = self.p2p.node().unobtainable_threshold_ms();
        let lines =
            self.body_wait.report(&obs, &entries, now_ms, heartbeat, BODY_REQUEST_TIMEOUT_MS);
        for line in &lines {
            println!("{line}");
        }
        lines
    }

    /// Emit a `close=open` line for any round that has been open too long — so a
    /// **stall is visible while it is happening**, not only once it ends.
    ///
    /// Without this the journal is silent for the whole duration of the thing it
    /// exists to explain: a round only closes when a later slot finalizes past it, so
    /// during a stall the detail arrives exactly when it stops being urgent. Reports
    /// repeat when the vote count moves and otherwise stay quiet, so a round stuck at
    /// `have=11/15` says so and then does not spam the log. Sampled on the telemetry
    /// cadence. Returns the lines emitted.
    pub fn emit_overdue_rounds(&mut self) -> Vec<String> {
        let lines = self.p2p.node_mut().rounds_mut().overdue_reports();
        for line in &lines {
            println!("{line}");
        }
        lines
    }

    /// One message-pump step; returns frames handled.
    ///
    /// The binary is the one caller that feeds `tick` a real monotonic clock —
    /// the same source `maintain_peers` uses — so the inbound rate limits
    /// (issue #91) measure real time here while every in-process sim keeps its
    /// deterministic one.
    pub fn step_once(&mut self) -> usize {
        let now_ms = self.started.elapsed().as_millis() as u64;
        self.p2p.tick(now_ms)
    }

    /// Inbound throttle counters (issue #91) — for the metrics surface. These are
    /// reported, never fed back into peer scoring.
    pub fn rate_stats(&self) -> qlab_p2p::ratelimit::RateStats {
        self.p2p.rate_stats()
    }

    /// **Issue #106 — may this node mine right now?** See [`MineGate`].
    ///
    /// The two facts it reads, and why these and not others:
    ///
    /// - the sync phase ([`qlab_p2p::sync::SyncPhase`]), which since #106 can say
    ///   "I have not heard from anyone" instead of folding that into "caught up";
    /// - whether there is **anyone to ask**: no address in the book and no live
    ///   peer. This is the discriminator between *genuinely first* and *rejoining
    ///   and ignorant*, and it is derived from what the operator already wrote —
    ///   `dial_peers` — rather than from a new flag or a wall-clock grace period.
    ///   A node told about a network believes a network exists and will not extend
    ///   the chain until it has found it; a node told about nobody is the net.
    ///
    /// The address book, not the live peer set, is the load-bearing half: node0's
    /// restart had three seeds configured and zero peers *handshaked yet*, which is
    /// precisely the window it forked in. Requiring the peer table to be empty as
    /// well closes the narrower window where an inbound socket is mid-handshake and
    /// is about to tell us the height.
    ///
    /// Not read on purpose: the tip's timestamp. Genesis is stamped `timestamp = 0`
    /// so its hash is reproducible, so "how old is my tip" cannot distinguish a
    /// fresh chain from a three-day-old one at exactly the height where the answer
    /// matters.
    pub fn mine_gate(&self) -> MineGate {
        if !self.mining {
            return MineGate::NotMining;
        }
        if self.p2p.sync_phase().is_synced() {
            return MineGate::Synced;
        }
        if self.p2p.addrs().known_count() == 0 && self.p2p.peers().is_empty() {
            return MineGate::Alone;
        }
        if self.mine_gate_latched {
            return MineGate::Latched;
        }
        match self.p2p.sync_phase() {
            SyncPhase::Unknown => MineGate::Unknown,
            _ => MineGate::Behind,
        }
    }

    /// Attempt to mine + announce the next block over the tip. Returns whether a
    /// block was produced (real RandomX PoW under the key-block seed).
    ///
    /// Issue #106: the readiness gate is here rather than at the call site, so it
    /// covers every caller — the event loop and the tests alike — and so a future
    /// caller cannot reintroduce mine-before-sync by forgetting it.
    pub fn try_mine(&mut self) -> bool {
        let gate = self.mine_gate();
        if !gate.permits() {
            return false;
        }
        // First clearance is worth exactly one line: an operator reading a startup
        // log wants to know *when* this node decided it knew where the chain was,
        // and on the T0 hosts that instant is the difference between a clean join
        // and a genesis fork. Logged before the attempt, because the attempt itself
        // may fail on PoW and this fact is about the decision, not the block.
        if !self.mine_gate_latched {
            self.mine_gate_latched = true;
            println!(
                "MINEGATE ready=1 why={} tip={} best={}",
                gate.field(),
                self.tip_height(),
                self.p2p
                    .peers()
                    .best_height()
                    .map(|h| h.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            );
        }
        match self.p2p.node_mut().mine_block() {
            Some((header, body)) => {
                self.nonce = self.nonce.wrapping_add(1);
                self.p2p.announce_block(header, body.txs, body.coinbase, body.coinbase_rkm, self.nonce);
                self.last_mine = Instant::now();
                true
            }
            None => false,
        }
    }

    /// Propose + announce checkpoints for every cadence slot now reached, signing
    /// through each finalizer's never-double-sign guard (M10-T0-2/S7) and persisting
    /// the finalizer ledgers BEFORE broadcasting (write-ahead, so a crash after the
    /// vote is on the wire can never let a restart equivocate). No-op for a verify-only
    /// node. The (partial) vote set now enters the cross-node tally + gossip (M10-T0-5).
    pub fn try_checkpoint(&mut self) {
        if self.finalizers.is_empty() {
            return;
        }
        let tip = self.tip_height();
        loop {
            // Sign-hysteresis (issue #269): do not commit a key to slot S at
            // `tip == S` — that is the exact tip-race window, and a vote cast there
            // is burned forever if the race resolves the other way (#223; the
            // 2026-08-05 outage was three consecutive slots burned this way).
            // Waived at slot 0 (genesis is hash-pinned — no race exists to wait
            // out, and finalizing it is a bootstrap act) and at the halt boundary
            // (a halted chain never grows past H, so H's checkpoint — which issue
            // #74 requires — must sign at `tip == H`).
            let hysteresis = if self.next_checkpoint == 0
                || self.halt_at == Some(self.next_checkpoint)
            {
                0
            } else {
                CHECKPOINT_SIGN_HYSTERESIS_BLOCKS
            };
            if self.next_checkpoint.saturating_add(hysteresis) > tip {
                break;
            }
            // HALT (issue #74, H2): the committee stops checkpointing ABOVE H. The
            // adapter refuses to sign there in any case (the load-bearing gate); the
            // loop stops advancing too, so a halted node does not spin proposing
            // slots it will never sign.
            if self.halt_at.is_some_and(|h| self.next_checkpoint > h) {
                break;
            }
            let made = self
                .p2p
                .node()
                .make_checkpoint_guarded(self.next_checkpoint, &mut self.finalizers);
            // Issue #87: record that THIS node proposed the slot and how many of its
            // own keys signed. `local=0` on a slot we proposed is itself a finding —
            // it means every held key was refused by the never-double-sign guard.
            //
            // Height 0 is excluded on purpose: finalizing genesis is a bootstrap act,
            // not a checkpoint round. `is_checkpoint_height` says the same thing
            // ("genesis is never a slot"), and a journal that opened with a round
            // nobody ever voted in would put a fictional row at the top of every
            // node's record.
            //
            // Issue #84: the slot's `cpid` is read from the never-double-sign
            // LEDGER, not from `made` — when the guard refused every held key,
            // `local=0` and there is no fresh vote, yet the node is still on record
            // as committed to a variant for this slot, and that commitment is
            // precisely what a split forensic is looking for.
            if self.next_checkpoint > 0 {
                let slot = self.next_checkpoint;
                let ctx = self.p2p.node().slot_context(slot);
                let local = made.as_ref().map(|(_, v)| v.len()).unwrap_or(0);
                let cpid = self
                    .finalizers
                    .iter()
                    .find_map(|f| f.state().signed_at(slot).map(|cp| cp.identity()));
                self.p2p.node_mut().rounds_mut().note_local_proposal(&ctx, local, cpid);
            }
            if let Some((cp, votes)) = made {
                self.persist_finalizers(); // durable BEFORE the vote leaves the node
                self.p2p.announce_checkpoint(cp, votes);
            }
            // Genesis (0) then the cadence grid (8, 16, …).
            self.next_checkpoint = if self.next_checkpoint == 0 {
                CHECKPOINT_CADENCE_BLOCKS
            } else {
                self.next_checkpoint + CHECKPOINT_CADENCE_BLOCKS
            };
        }
    }

    /// Persist every finalizer's ledger to its per-index file, fsync'd. Best-effort:
    /// a write failure is logged (the run continues; the honest persist-before-
    /// broadcast window is documented in `recovery.rs`).
    fn persist_finalizers(&self) {
        for f in &self.finalizers {
            let path = finalizer_state_path(&self.data_dir, f.index());
            if let Err(e) = write_file_durably(&path, &f.state().to_bytes()) {
                eprintln!("persist finalizer {} failed: {e}", f.index());
            }
        }
    }

    /// The finalizers this node drives (test/ops hook — e.g. to assert the restored
    /// never-double-sign guard after a restart).
    pub fn finalizers_mut(&mut self) -> &mut [Finalizer] {
        &mut self.finalizers
    }

    /// One discovery maintenance pass (issue #83): reconnect anything dropped
    /// (the S9 property — a healed partition reconnects with NO process restart),
    /// auto-connect to learned addresses under the outbound cap, and ask peers for
    /// more addresses on the per-peer rate limit. Returns dials made.
    ///
    /// This replaced the old `try_redial`: seeds and learned addresses now share
    /// one dial path, one cap and one backoff ladder, because two dial paths with
    /// different caps is how a node exceeds a limit it believes it is enforcing.
    pub fn maintain_peers(&mut self) -> usize {
        let now_ms = self.started.elapsed().as_millis() as u64;
        self.p2p.maintain(now_ms)
    }

    /// Test/ops hook: clear every dial backoff so the next maintenance pass
    /// attempts immediately (partition-heal without wall-clock waits).
    pub fn force_redial_ready(&mut self) {
        self.p2p.addrs_mut().force_retry_ready();
    }

    /// Persist the address book (dialable entries only) under the data dir, so a
    /// restart does not collapse back to "seeds only" — which is precisely the
    /// state the NAT re-open trigger watches for, and manufacturing it would make
    /// that measurement lie. Best-effort: a write failure is logged, not fatal.
    pub fn save_addr_book(&self) {
        let path = self.data_dir.join(ADDRBOOK_FILE);
        if let Err(e) = write_file_durably(&path, &self.p2p.addrs().to_bytes()) {
            eprintln!("persist address book failed: {e}");
        }
    }

    /// This release's constants (issue #74).
    pub fn release(&self) -> &Release {
        &self.release
    }

    /// The height this node halts at, if its release carries one.
    /// The boundary checkpoint, decoupled from mining (issue #360).
    ///
    /// The run loop's only other route to [`Self::try_checkpoint`] sits inside
    /// `if self.try_mine()` — and a halted node refuses to mine, so on the day
    /// the fleet first reached a live boundary (8,640, 2026-08-12) every armed
    /// node held its keys silent and the "finalized boundary" the halt design
    /// requires (activation doc §5) was structurally unreachable: 21 keys
    /// present, zero proposals, forever. While halted with the boundary not
    /// yet finalized, propose/sign directly. Calling this on the loop cadence
    /// is safe: [`Self::try_checkpoint`] early-returns for keyless nodes, and
    /// repetition is bounded by sign-hysteresis (#269) and the
    /// never-double-sign guard. Once the boundary finalizes, the condition
    /// goes false and this is inert.
    fn maintain_boundary_checkpoint(&mut self) {
        if let Some(h) = self.halt_at() {
            if self.tip_height() >= h && self.finalized_height() < Some(h) {
                self.try_checkpoint();
                // #362: signing alone is not enough. The relay is growth-gated
                // and each restarted process fires its ONE push before its
                // peers have reconnected, so quorum-worth of existing
                // signatures can sit in disconnected islands forever (measured
                // live at the 8,640 halt: 16 of 21 keys signed, no tally ever
                // held 15). Re-push the stored variants on a slow cadence;
                // receiver-side signer-dedup makes repetition harmless, and
                // the halted-unfinalized condition dissolves at finalization.
                if self.last_boundary_repush.elapsed() >= self.repush_interval {
                    let n = self.p2p.repush_slot_votes(h);
                    if n > 0 {
                        println!("REPUSH slot={h} variants={n} why=boundary-unfinalized");
                    }
                    self.last_boundary_repush = Instant::now();
                }
            }
        }
    }

    pub fn halt_at(&self) -> Option<u64> {
        self.halt_at
    }

    /// Whether this node has reached its halt height.
    pub fn is_halted(&self) -> bool {
        self.p2p.node().is_halted_at_tip()
    }

    /// Maintain the durable halt marker (issue #74, H4).
    ///
    /// Written the first time the tip reaches H, and rewritten exactly once more
    /// when H's checkpoint finalizes (`Halting` → `Halted`). This is the record a
    /// later binary's resume gate is checked against — it is written by the binary
    /// that actually halted, which is what makes the gate impossible to dodge by
    /// simply declaring nothing.
    ///
    /// Best-effort on I/O error (logged, run continues): a node that cannot write
    /// its marker is still halted — refusing to halt because the disk is full would
    /// be strictly worse.
    pub fn maintain_halt_marker(&mut self) {
        let Some(h) = self.halt_at else { return };
        if !self.is_halted() {
            return;
        }
        let finalized = self.finalized_height().is_some_and(|f| f >= h);
        // Write once on reaching H, then once more when the boundary finalizes.
        if self.marker_final_written {
            return;
        }
        let marker = HaltMarker::for_release(&self.release, h, finalized);
        match marker.write(&self.data_dir) {
            Ok(()) => {
                if finalized {
                    self.marker_final_written = true;
                    println!(
                        "HALT boundary height {h} is FINALIZED — regime=Halted, revision `{}`. \
                         It is now safe to swap binaries.",
                        marker.revision_id
                    );
                }
            }
            Err(e) => eprintln!("halt marker write failed: {e}"),
        }
    }

    /// Flush the state machine's derived state to an atomic on-disk snapshot.
    pub fn save_snapshot(&self) -> Result<(), RunError> {
        self.p2p.node().save_snapshot().map_err(RunError::Node)
    }

    /// **The snapshot cadence** (issue #359 S2) — the loop's periodic write, and
    /// the reason a host's `snapshot.bin` no longer depends on how its process
    /// died.
    ///
    /// Four conditions, in the order they are cheapest to answer:
    ///
    /// 1. **The cadence has come round** ([`SNAPSHOT_INTERVAL`]). The tick is
    ///    consumed whether or not a write follows, so the checks below cost one
    ///    evaluation per interval and not one per loop iteration.
    /// 2. **Runtime catch-up is included.** `state_lag().blocks()` may be non-zero:
    ///    [`Self::save_snapshot`] serialises the state machine's own applied chain,
    ///    not fork choice's header tip, so the snapshot is a consistent prefix at
    ///    `state_lag().state_tip`. This bounds runtime catch-up loss to one cadence
    ///    interval instead of the whole catch-up, and also covers the #200
    ///    unobtainable-body case where an otherwise healthy node can remain at
    ///    `slag > 0` (`uex=1` is the tell).
    ///
    ///    🔴 **This does not cover `Node::open` replay.** The from-genesis replay
    ///    #359 measured happens inside `qlab_node::Node::open`, before this loop
    ///    and its cadence exist. Persisting progress during that startup replay is
    ///    a separate fix; this rule only makes runtime catch-up prefixes durable.
    /// 3. **The applied height differs from the durable one.** Idempotence: a
    ///    quiet node rewrites nothing, which is what keeps the cadence free on a
    ///    halted or stalled chain. It is `!=` and not `>` deliberately — a rewind
    ///    lowers the applied height, and a snapshot pinned *above* the applied tip
    ///    is precisely issue #225's shape (a snapshot its own log cannot honour,
    ///    which costs a full replay at the next start). An absent or unreadable
    ///    snapshot has no height and therefore always differs, so node3's shape is
    ///    repaired on the first tick after it is synced.
    /// 4. **The write succeeded**, before the cache advances. A failed write leaves
    ///    `snap=` reporting the older snapshot that is still genuinely on disk —
    ///    the atomic temp+rename means a failure never destroys the previous one,
    ///    and issue #145's rule applies here as it does at shutdown: never claim a
    ///    flush that did not happen.
    ///
    /// Not on the hot path: this runs on the loop, between the transport pump and
    /// the idle sleep, like every other maintenance pass here.
    fn maintain_snapshot(&mut self) {
        if self.last_snapshot_tick.elapsed() < self.snapshot_interval {
            return;
        }
        self.last_snapshot_tick = Instant::now();
        // One read supplies the applied prefix this cadence makes durable. The
        // snapshot is consistent even when the same value reports runtime lag:
        // it serialises this state-machine tip, not fork choice's header tip.
        let lag = self.p2p.node().state_lag();
        let applied = lag.state_tip;
        if self.durable_snapshot.height() == Some(applied) {
            return;
        }
        match self.save_snapshot() {
            Ok(()) => {
                self.durable_snapshot = qlab_node::SnapshotOnDisk::At { applied_height: applied };
            }
            // Best-effort, exactly like the halt marker: a node that cannot write
            // its snapshot is still a correct node — the block log is the source of
            // truth and the next start replays it. Loud, because a host silently
            // failing this write is a host quietly returning to node3's shape.
            Err(e) => eprintln!("snapshot cadence write failed: {e}"),
        }
    }

    /// The event loop: pump the transport, mine on the cadence, and propose
    /// checkpoints, until `shutdown` is set. On exit performs the graceful-shutdown
    /// **snapshot flush** (item 1) and address-book write.
    ///
    /// Returns `true` when the snapshot flush succeeded, `false` when it failed
    /// (the failure is already `eprintln!`'d). The binary uses this so it does not
    /// print "snapshot flushed" after a failed write (issue #145).
    pub fn run_until(&mut self, shutdown: &AtomicBool) -> bool {
        self.run_until_with(shutdown, |_| {})
    }

    /// [`Self::run_until`] with a per-iteration hook — the seam a co-resident
    /// process uses to do its own work on this node's loop instead of on a thread
    /// of its own (issue #123, the in-process faucet).
    ///
    /// `on_tick` runs **once per loop iteration, after** the node's own work for
    /// that iteration (transport pump, regime accounting, mining, snapshot
    /// refreshes) and **before** the idle sleep. Consequences worth stating rather
    /// than discovering:
    ///
    /// - It runs on the consensus loop's thread, so whatever it costs, the loop
    ///   pays. A hook that blocks for seconds delays mining and the transport pump
    ///   by that long. The faucet's hook does exactly that once per grant (a
    ///   measured ~2.3 s STARK), which is affordable against a 75 s block time and
    ///   is the reason it is a hook rather than a thread: a second thread would
    ///   need `&mut` node state concurrently with the loop, and the honest way to
    ///   share `&mut` is not to.
    /// - It cannot make the loop exit; only `shutdown` does.
    ///
    /// Returns `true` when the snapshot flush on exit succeeded — same contract as
    /// [`Self::run_until`]. The address book is always attempted (best-effort) after
    /// the snapshot write; it does not affect the return value.
    ///
    /// [`Self::run_until`] is this with a no-op hook, so an ordinary node run is
    /// byte-for-byte the behaviour it was (aside from the returned status).
    pub fn run_until_with<F: FnMut(&mut Self)>(&mut self, shutdown: &AtomicBool, mut on_tick: F) -> bool {
        // An initial sample at startup (height/finality as opened from disk).
        println!("{}", self.telemetry_sample());
        self.last_sample = Instant::now();
        while !shutdown.load(Ordering::Relaxed) {
            let _ = self.one_iteration(&mut on_tick);
        }
        // Any round still open at shutdown stays open: it is genuinely unfinished,
        // and inventing a close for it would put a fabricated verdict in the record.
        // The rounds that DID close are flushed, so nothing already decided is lost.
        self.emit_rounds();
        // Graceful shutdown = snapshot flush + the learned address book.
        // Both sit here so every stop path that sets `shutdown` (SIGINT, and with
        // ctrlc's `termination` feature also SIGTERM/SIGHUP — issue #145) reaches
        // them. Returning the snapshot outcome is what lets main not claim a flush
        // that failed.
        let snapshot_ok = match self.save_snapshot() {
            Ok(()) => {
                // Issue #359: the shutdown flush is still a snapshot write, so the
                // cache it advances is the same one the cadence advances — one
                // record of what is durable, updated wherever it changes.
                self.durable_snapshot = qlab_node::SnapshotOnDisk::At {
                    applied_height: self.p2p.node().state_lag().state_tip,
                };
                true
            }
            Err(e) => {
                eprintln!("snapshot flush on shutdown failed: {e}");
                false
            }
        };
        self.save_addr_book();
        snapshot_ok
    }

    /// **One turn of the event loop, timed phase by phase** (issue #107 S1).
    ///
    /// Split out of [`Self::run_until_with`] so the instrument can be tested
    /// against the loop it instruments rather than against a copy of it: a test
    /// drives one real iteration and reads the real measurement back, with no
    /// stdout capture and no second implementation of the loop body to drift
    /// from this one.
    ///
    /// Returns the iteration's phase record **and the `LOOP` lines it emitted**
    /// — already printed, returned for the same reason [`Self::emit_rounds`]
    /// returns its lines: so a test can assert what the journal said without
    /// capturing stdout or re-deriving it.
    pub fn one_iteration<F: FnMut(&mut Self)>(
        &mut self,
        on_tick: &mut F,
    ) -> (LoopPhases, Vec<String>) {
        // One clock read per statement group. `lap` advances the cursor, so no
        // phase is charged for its neighbour's clock read; see `crate::looptime`.
        let mut phases = LoopPhases::default();
        let mut t = Instant::now();
        let n = self.step_once();
        phases.pump = lap(&mut t);
        phases.tick = self.p2p.last_tick_timings();
        // Issue #87, in the order that keeps the record honest: accumulate the
        // regime residency first (so the seconds land in the regime that was
        // actually in force), then open any newly-reached slot, then emit the
        // rounds that closed while we were away. All three are cheap and none
        // touches consensus.
        self.accumulate_regime();
        self.note_slots_reached();
        self.emit_rounds();
        self.emit_rewinds();
        self.emit_finalize_refusals();
        // Issue #229. On the pump cadence like its two neighbours, and silent
        // on every healthy node — the rate limit is inside the journal, not
        // here, so the emission cadence and the reporting cadence stay two
        // separate decisions.
        self.emit_body_waits();
        phases.journal = lap(&mut t);
        if self.mining && self.last_mine.elapsed() >= self.mine_interval {
            if self.try_mine() {
                self.try_checkpoint();
            }
        }
        phases.mine = lap(&mut t);
        // #360: the call above is the loop's ONLY route to try_checkpoint,
        // and it is unreachable on a halted node. See the method's doc.
        self.maintain_boundary_checkpoint();
        phases.boundary = lap(&mut t);
        if self.metrics_server.is_some() && self.last_metrics_render.elapsed() >= METRICS_REFRESH {
            self.refresh_metrics();
            self.last_metrics_render = Instant::now();
        }
        phases.metrics = lap(&mut t);
        if self.discovery_server.is_some()
            && self.last_discovery_refresh.elapsed() >= DISCOVERY_REFRESH
        {
            self.refresh_discovery();
            self.refresh_leaves();
            self.refresh_anchors();
            self.last_discovery_refresh = Instant::now();
        }
        phases.discovery = lap(&mut t);
        // Every iteration, not on the refresh cadence: a submitter is parked
        // on a socket waiting for this, and an empty queue costs one
        // `try_recv` (issue #275).
        self.drain_remote_submits();
        phases.submit = lap(&mut t);
        if self.telemetry_server.is_some()
            && self.last_telemetry_render.elapsed() >= TELEMETRY_REFRESH
        {
            self.refresh_telemetry();
            self.last_telemetry_render = Instant::now();
        }
        phases.telsrv = lap(&mut t);
        let sampled = self.last_sample.elapsed() >= self.sample_interval;
        if sampled {
            println!("{}", self.telemetry_sample());
            // A stall's open rounds report themselves on the same cadence as the
            // telemetry line they explain.
            self.emit_overdue_rounds();
            self.last_sample = Instant::now();
            // Cheap and idempotent; sampled on the telemetry cadence so it costs
            // nothing on a net that never halts.
            self.maintain_halt_marker();
        }
        phases.sample = lap(&mut t);
        if self.last_maintain.elapsed() >= MAINTAIN_INTERVAL {
            self.maintain_peers(); // re-dial, auto-connect, ask for addresses (#83)
            self.last_maintain = Instant::now();
        }
        phases.maintain = lap(&mut t);
        // Issue #359: the snapshot cadence. Its own interval check lives inside
        // the method, with the three gates it guards, so the loop reads as one
        // line and the rule has one home.
        self.maintain_snapshot();
        phases.snapshot = lap(&mut t);
        // The co-resident hook (#123), last so it observes this iteration's
        // state rather than the previous one's.
        on_tick(self);
        phases.hook = lap(&mut t);
        if n == 0 {
            std::thread::sleep(Duration::from_millis(20));
            phases.sleep = lap(&mut t);
        }
        // Issue #107 S1: the iteration's own record. The slow line is
        // emitted here rather than at the sample, so a loop that is about to
        // spend two minutes in one phase has already said so by the time the
        // gap it causes appears in the log — which is the difference between
        // a journal that explains an incident and one that annotates it
        // afterwards. The window line rides the telemetry cadence, so the
        // aggregate and the `TELEMETRY` line it explains are adjacent.
        let mut lines = Vec::new();
        if let Some(line) = self.loop_journal.note(&phases) {
            lines.push(line);
        }
        if sampled {
            lines.push(self.loop_journal.window_line());
        }
        for line in &lines {
            println!("{line}");
        }
        (phases, lines)
    }

    /// Re-tune the `LOOP kind=slow` threshold (issue #107 S1) — tests and
    /// testnet, programmatic for the same reason the rate limits are: this
    /// number should move because a measurement said so, not because a config
    /// file was edited on one host.
    pub fn set_loop_slow_threshold(&mut self, d: Duration) {
        self.loop_journal.set_threshold(d);
    }
}

/// **`halt-status`'s snapshot section** (issue #359 S3) — the same question
/// `TELEMETRY`'s `snap=` answers, asked of a data dir by a process that is not
/// running the node.
///
/// This is the half of S3 that works when the node is *down*, which is the moment
/// an operator planning a roll actually asks: `halt-status --config` is already
/// how they read this host's release and marker before restarting it, so the
/// snapshot answer belongs on the same output rather than behind an ssh + `ls`.
/// It reads the file directly (a fresh, authoritative read — no cache to be stale,
/// unlike the running node's, and no node to open).
///
/// **The `none` case is the one that must be legible**, because it is node3's
/// shape and the whole cost of this issue: a bare blank line where a height should
/// be would read as "nothing to report" rather than "this host replays the entire
/// chain if you restart it". So the absent and unreadable cases each get the
/// consequence spelled out, and only the present case is a single line.
///
/// Returns the rendered block (always ending in a newline) so it is testable
/// without capturing stdout.
pub fn snapshot_status_report(data_dir: &std::path::Path) -> String {
    let mut out = String::new();
    let state = match qlab_node::snapshot_on_disk(data_dir) {
        Ok(s) => s,
        // A data dir we cannot read at all is not the same as one with no
        // snapshot, and saying "none" here would be a claim this call cannot
        // support.
        Err(e) => {
            out.push_str(&format!("  snapshot:     UNAVAILABLE — cannot read {}: {e}\n", data_dir.display()));
            return out;
        }
    };
    match state {
        qlab_node::SnapshotOnDisk::At { applied_height } => {
            out.push_str(&format!(
                "  snapshot:     height {applied_height} — a restart resumes here and replays \
                 only the records past it\n"
            ));
        }
        qlab_node::SnapshotOnDisk::Absent => {
            out.push_str("  snapshot:     ⚠️  NONE — this data dir has no snapshot.bin.\n");
            out.push_str(
                "      A restart REPLAYS THE WHOLE BLOCK LOG FROM GENESIS (issue #359: 4.6 h for \
                 an\n",
            );
            out.push_str(
                "      11,751-record chain, and the replay cost grows superlinearly with chain \
                 length).\n",
            );
            out.push_str(
                "      On a live chain the node may then be unable to catch up at all. Do not \
                 plan a\n",
            );
            out.push_str(
                "      roll against this host without pricing that outage. A snapshot appears \
                 once the\n",
            );
            out.push_str("      node runs synced for one snapshot interval, or at its next graceful stop.\n");
        }
        qlab_node::SnapshotOnDisk::Unreadable => {
            out.push_str(
                "  snapshot:     ⚠️  UNUSABLE — snapshot.bin is present but does not decode at \
                 this\n",
            );
            out.push_str(&format!(
                "      binary's on-disk format version ({}). It will be IGNORED and rewritten; \
                 the\n",
                qlab_node::FORMAT_VERSION
            ));
            out.push_str(
                "      next restart costs the same from-genesis replay as having none at all.\n",
            );
        }
    }
    out
}

/// Render `bdrop=` from the count/last-height pair (issue #130 (b)):
/// `<total>@<height>`, and `0@-` when this node has refused no body.
///
/// **One token, not two fields**, following `dialable=8/32`: the count and the height
/// are one reading and splitting them would put two appends on a line that has
/// already had two collide in a merge today. `@` rather than `/` because the second
/// number is a position, not a denominator.
///
/// **Always printed, zero included** (the #130 (a) rule) — a node always knows both
/// halves, so an omitted field would only force a special case on every parser. The
/// `-` is the #125/#84 convention for "no value to state", used here for the height
/// alone: `0@-` says *nothing has been refused*, which is different in kind from
/// `0@412`, a state this field cannot reach and a parser should not have to consider.
fn bdrop_field((total, last_height): (u64, Option<u64>)) -> String {
    match last_height {
        Some(h) => format!("{total}@{h}"),
        None => format!("{total}@-"),
    }
}

/// Stable operator-facing token for a mempool refusal (lab issue #310).
///
/// Matches the deployed `POST /v1/tx` vocabulary in `discovery_server.rs` so the
/// faucet log and the wallet-facing surface name the same faults the same way.
fn mempool_refusal_token(e: &qlab_node::MempoolError) -> &'static str {
    use qlab_devnet::body::BodyError;
    use qlab_node::MempoolError;
    match e {
        MempoolError::WrongFee { .. } => "wrong-fee",
        MempoolError::AnchorNotValid => "anchor-not-valid",
        MempoolError::AlreadySpent { .. } => "nullifier-spent",
        MempoolError::NullifierRepeatedInTx { .. } => "nullifier-repeated-in-tx",
        MempoolError::NullifierConflictInPool { .. } => "nullifier-conflict-in-pool",
        MempoolError::DuplicateTx => "duplicate",
        MempoolError::DiscoveryInvalid(BodyError::DiscoveryMalformed { .. }) => {
            "discovery-malformed"
        }
        MempoolError::DiscoveryInvalid(BodyError::DiscoveryNotCanonical { .. }) => {
            "discovery-not-canonical"
        }
        MempoolError::DiscoveryInvalid(_) => "discovery-does-not-bind",
        MempoolError::RiderInvalid(BodyError::RiderMalformed { .. }) => "rider-malformed",
        MempoolError::RiderInvalid(BodyError::RiderBeforeBoundary { .. }) => "rider-before-boundary",
        MempoolError::RiderInvalid(_) => "rider-rule",
        MempoolError::ProofInvalid => "proof-invalid",
    }
}

/// Derive a deterministic 32-byte node id from the bound address, so a node's id
/// is stable across restarts on the same address.
fn node_id_from_addr(addr: &str) -> [u8; 32] {
    qlab_devnet::hash::keccak256(addr.as_bytes())
}

/// Local self-identities for the address-book filter (issue #127).
///
/// A node must recognise its own address **without** `advertise_addr`. The
/// operator-declared advertise is a *gossip* fact; these are *filter* facts the
/// process can know on its own:
///
/// - the bound socket (`transport.local_addr()`), always
/// - the configured `listen_addr` string (may be `0.0.0.0:port`)
/// - the system hostname + listen port (docker compose sets `hostname: nodeN`,
///   and that is exactly the form peers use in `dial_peers` / gossip)
/// - loopback aliases when the bind is unspecified, so a self-dial via
///   `127.0.0.1` is also refused
///
/// Honest remainder: a public address that is not on any local interface and is
/// not the hostname (AWS EIP, 1:1 NAT) is **not** knowable here. Without
/// `advertise_addr` that form can still enter the book as an undialable
/// candidate. Refusing every address we "cannot rule out as self" would refuse
/// discovery for every outbound-only home node — a regression against the NAT
/// decision. The EIP case is therefore a separable remainder, not a reason to
/// take the stricter posture.
fn local_self_identities(listen_addr: &str, bound: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut push = |s: String| {
        if valid_addr(&s) && !out.contains(&s) {
            out.push(s);
        }
    };
    push(bound.to_string());
    push(listen_addr.to_string());

    let port = addr_port(bound).or_else(|| addr_port(listen_addr));
    if let Some(port) = port {
        if let Some(host) = system_hostname() {
            push(format!("{host}:{port}"));
        }
        if host_is_unspecified(listen_addr) || host_is_unspecified(bound) {
            push(format!("127.0.0.1:{port}"));
            push(format!("[::1]:{port}"));
            push(format!("localhost:{port}"));
        }
    }
    out
}

fn addr_port(addr: &str) -> Option<u16> {
    let (_host, port) = addr.rsplit_once(':')?;
    port.parse().ok()
}

fn host_is_unspecified(addr: &str) -> bool {
    let host = match addr.rsplit_once(':') {
        Some((h, _)) => h,
        None => addr,
    };
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    unbracketed == "0.0.0.0"
        || unbracketed == "::"
        || unbracketed == "[::]"
        || unbracketed.eq_ignore_ascii_case("0:0:0:0:0:0:0:0")
}

/// Best-effort system hostname. Docker compose stamps `hostname: nodeN` into
/// `/etc/hostname`; bare processes may only have `$HOSTNAME`. Either is enough
/// for the filter; neither is used for gossip.
fn system_hostname() -> Option<String> {
    if let Ok(s) = std::fs::read_to_string("/etc/hostname") {
        let t = s.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    std::env::var("HOSTNAME")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Path of committee member `index`'s persistent finalizer ledger under `data_dir`.
fn finalizer_state_path(data_dir: &std::path::Path, index: usize) -> std::path::PathBuf {
    data_dir.join(format!("finalizer-{index}.state"))
}

/// Write a file durably (create the parent dir if needed, fsync the file).
fn write_file_durably(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = std::fs::File::create(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis::GenesisFile;
    use qlab_devnet::pow::KeccakPow;
    use qlab_p2p::transport::Transport;
    use std::path::PathBuf;

    /// A test rig: temp data dir + genesis file + all-21 committee key files, and a
    /// config pointing at them. Returns (config, genesis, tempdir).
    fn rig(tag: &str, mining: bool) -> (NodeConfig, GenesisFile, PathBuf) {
        let base = std::env::temp_dir().join(format!("qmb_t01_run_{tag}"));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let genesis = GenesisFile::new_devnet_t0();
        let gpath = base.join("genesis.qmb");
        genesis.write(&gpath).unwrap();
        let keys = genesis.write_committee_key_files(base.join("keys")).unwrap();
        let config = NodeConfig {
            data_dir: base.join("data"),
            listen_addr: "127.0.0.1:0".to_string(),
            dial_peers: vec![],
            advertise_addr: None,
            genesis_file: gpath,
            committee_key_paths: keys, // hold all 21 → this node can finalize
            mining,
            expected_genesis_hash: Some(genesis.hash_hex()),
            metrics_addr: None,
            telemetry_addr: None,
            // Explicitly off in the in-process fixtures: the default is a fixed
            // loopback port and these tests start many nodes in one process, so
            // the second bind would fail. `discovery_default_is_on_*` covers the
            // default itself, from a config FILE, which is where it applies.
            discovery_addr: None,
            miner_rkm: None,
        };
        (config, genesis, base)
    }

    #[test]
    fn starts_mines_checkpoints_and_persists() {
        let (config, genesis, base) = rig("mine", true);
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        node.set_mine_interval(Duration::ZERO);

        // Finalize genesis, then mine three blocks + checkpoint each cadence slot.
        node.try_checkpoint();
        assert_eq!(node.finalized_height(), Some(0), "genesis finalized");
        for _ in 0..3 {
            assert!(node.try_mine(), "KeccakPow mines at genesis difficulty");
            node.try_checkpoint();
        }
        assert_eq!(node.tip_height(), 3);
        let finalized_before = node.finalized_height();
        let fid_before = node.finalized_checkpoint_id();

        // Flush + drop, then re-open the SAME data dir: the tip persists (the disk
        // stores + snapshot are real — restart safety).
        node.save_snapshot().unwrap();
        drop(node);
        let reopened =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        assert_eq!(reopened.tip_height(), 3, "state persisted across restart");
        assert_eq!(
            reopened.finalized_height(),
            finalized_before,
            "the operator-facing finalized head survives the real run path"
        );
        assert_eq!(
            reopened.finalized_checkpoint_id(),
            fid_before,
            "the exact identity survives, not only the checkpoint height"
        );
        assert_eq!(
            reopened.recovery_report().to_string(),
            "RECOVERY restored snapshot at height 3, replayed 0 records, resumed at tip 3"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Issue #269 — sign-hysteresis: a cadence slot is NOT proposed the moment the
    /// tip reaches it (`tip == S` is the exact tip-race window issue #223 burns
    /// votes in — three consecutive slots burned on the live net, 2026-08-05), only
    /// once the chain has grown `CHECKPOINT_SIGN_HYSTERESIS_BLOCKS` past it. Slot 0
    /// stays exempt: genesis is hash-pinned, no race exists to wait out.
    #[test]
    fn checkpoint_slot_waits_for_the_sign_hysteresis() {
        let (config, genesis, base) = rig("hyst", true);
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        node.set_mine_interval(Duration::ZERO);

        node.try_checkpoint();
        assert_eq!(
            node.finalized_height(),
            Some(0),
            "genesis is exempt — a bootstrap act on a hash-pinned block"
        );

        // Mine exactly to the first cadence slot and stop: tip == S.
        for _ in 0..CHECKPOINT_CADENCE_BLOCKS {
            assert!(node.try_mine(), "KeccakPow mines at genesis difficulty");
        }
        assert_eq!(node.tip_height(), CHECKPOINT_CADENCE_BLOCKS);
        node.try_checkpoint();
        assert_eq!(
            node.finalized_height(),
            Some(0),
            "slot S must NOT be signed at tip == S — that is the tip-race window"
        );

        // Grow to one block short of the hysteresis: still no signature.
        for _ in 0..CHECKPOINT_SIGN_HYSTERESIS_BLOCKS - 1 {
            assert!(node.try_mine());
            node.try_checkpoint();
            assert_eq!(
                node.finalized_height(),
                Some(0),
                "still inside the hysteresis window — no key committed"
            );
        }

        // tip == S + hysteresis: the slot block has settled; holding all 21 keys,
        // the checkpoint signs and finalizes in one act.
        assert!(node.try_mine());
        node.try_checkpoint();
        assert_eq!(
            node.finalized_height(),
            Some(CHECKPOINT_CADENCE_BLOCKS),
            "the slot signs once the chain has grown past it"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// ACCEPTANCE #7 — the never-double-sign guard survives a restart through the
    /// real run path: checkpoint slot 8 (persisting each finalizer ledger before
    /// broadcast), restart from the same data dir, and the restored finalizer refuses
    /// a CONFLICTING slot-8 checkpoint. Without persisted state a rebooted proposer
    /// would happily equivocate (the Crosslink-class hazard).
    #[test]
    fn restart_never_equivocates_through_the_run_path() {
        let (config, genesis, base) = rig("noequiv", true);
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        node.set_mine_interval(Duration::ZERO);
        node.try_checkpoint(); // finalize genesis (slot 0)
        for _ in 0..CHECKPOINT_CADENCE_BLOCKS + CHECKPOINT_SIGN_HYSTERESIS_BLOCKS {
            assert!(node.try_mine());
        }
        node.try_checkpoint(); // slot 8, past the #269 hysteresis
        assert_eq!(node.finalized_height(), Some(CHECKPOINT_CADENCE_BLOCKS), "slot 8 finalized");
        let fid_before = node.finalized_checkpoint_id();
        // Ledgers were persisted (write-ahead, before broadcast).
        assert!(config.data_dir.join("finalizer-0.state").exists(), "finalizer 0 ledger on disk");
        node.save_snapshot().unwrap();
        drop(node);

        // Restart: finalizers restore their ledgers from disk, and the finality
        // tracker is reconstructed from the durable state-machine checkpoint. This
        // is recovery, not a fresh quorum event; no votes are replayed to establish it.
        let mut reopened =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        assert_eq!(reopened.finalized_height(), Some(CHECKPOINT_CADENCE_BLOCKS));
        assert_eq!(reopened.finalized_checkpoint_id(), fid_before);
        assert_eq!(
            reopened.finalizers_mut()[0].last_voted_slot(),
            Some(CHECKPOINT_CADENCE_BLOCKS),
            "the finalizer ledger (slot 8) was restored from disk"
        );
        // The restored finalizer already committed to slot 8, so it refuses a
        // CONFLICTING slot-8 checkpoint — the guard survived the restart.
        let conflicting = qlab_devnet::committee::Checkpoint::new(
            CHECKPOINT_CADENCE_BLOCKS,
            [0xEE; 32],
            [0xEE; 32],
        );
        assert!(
            reopened.finalizers_mut()[0].sign(&conflicting).is_err(),
            "restarted finalizer must not equivocate against its persisted slot-8 vote"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// **ACCEPTANCE (issue #133) through the real run path, on the real frozen
    /// committee: a tombstoned member stays tombstoned across a restart.**
    ///
    /// The adapter-level tests in `qlab-p2p` prove the mechanism; this one proves the
    /// *binary* uses it, on the N=21 genesis roster, because that is where the defect
    /// lived: `RunningNode::start` builds `CommitteeState::new(genesis.committee(), …)`
    /// — 21 Active, full bond, zero slashed — on **every** start, and nothing carried a
    /// punishment past it. `reopened` below is a fresh `start` against the same data
    /// dir, exactly as a restarted host is.
    ///
    /// The control is the assertion before the punishment: the freshly-started node
    /// really does hold member 7 Active with a full bond, so what survives afterwards
    /// cannot have come from the fixture.
    #[test]
    fn a_committee_punishment_survives_a_restart_through_the_run_path() {
        use qlab_devnet::committee::{Checkpoint, MemberStatus};
        use qlab_devnet::ebbflow::EquivocationEvidence;
        use qlab_p2p::n1::CommitteeControl;

        let (config, genesis, base) = rig("punish", true);
        let validators = genesis.load_validators(&config.committee_key_paths).unwrap();
        let bond = genesis
            .frozen
            .self_bond_qmb_steady
            .saturating_mul(genesis.frozen.bessel_per_qmb);
        let expect_slash = bond / 10;
        let signer = 7usize;

        // Two conflicting slot-8 checkpoints signed by member 7's real key — the whole
        // adjudication, two signature checks, no human judgement (committee-gov §3).
        let cp_a = Checkpoint::new(CHECKPOINT_CADENCE_BLOCKS, [0xA7; 32], [0xAA; 32]);
        let cp_b = Checkpoint::new(CHECKPOINT_CADENCE_BLOCKS, [0xB7; 32], [0xBB; 32]);
        let ev = EquivocationEvidence {
            vote_a: validators[signer].sign_checkpoint(&cp_a),
            cp_a,
            vote_b: validators[signer].sign_checkpoint(&cp_b),
            cp_b,
        };

        {
            let mut node =
                RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
            // Control: the frozen genesis roster is 21 Active with a full bond.
            let cstate = node.p2p().node().committee().state();
            assert_eq!(cstate.size(), 21);
            assert_eq!(cstate.status(signer), Some(MemberStatus::Active));
            assert_eq!(cstate.bond(signer), Some(bond));
            assert_eq!(cstate.active_count(0), 21);

            assert_eq!(node.p2p_mut().node_mut().apply_evidence(&ev), Some(signer));
            assert!(node.p2p().node().is_tombstoned(signer));
            node.save_snapshot().unwrap();
        }

        // --- the host restarts; only the data dir survived ---

        let reopened =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        let cstate = reopened.p2p().node().committee().state();
        assert_eq!(
            cstate.status(signer),
            Some(MemberStatus::Tombstoned),
            "FROZEN §4's permanent removal must be permanent per CHAIN, not per process"
        );
        assert!(!cstate.is_active(signer, u64::MAX), "never active again, at any height");
        assert_eq!(cstate.bond(signer), Some(bond - expect_slash), "the bond is still slashed");
        assert_eq!(cstate.slashed(signer), Some(expect_slash), "and the slash ledger agrees");
        assert_eq!(
            cstate.active_count(0),
            20,
            "the roster this node will count votes against matches a peer that never restarted"
        );

        // The counter #133 asked for: this restart says what it restored, by name.
        let restore = reopened.p2p().node().punishment_restore();
        assert_eq!(restore.records, 1);
        assert_eq!(restore.tombstoned, vec![signer]);
        assert!(!restore.ledger_absent_on_populated_datadir);
        assert!(restore.summary_line().contains("1 tombstone(s) restored (members 7)"));
        // And the same fact is on the TELEMETRY line operators already read (D3).
        // Shape is restored/known: 1 tombstone re-applied from 1 on-disk record.
        assert_eq!(restore.telemetry_field(), "1/1");
        let line = reopened.telemetry_sample();
        assert!(
            line.contains(" prest=1/1"),
            "TELEMETRY must carry the restore report, not only the startup println: {line}"
        );
        // `prest=` was the last field when #133 D3 landed and is not any more:
        // #200's `uex=` and then #130 (b)'s `bdrop=` appended after it. What #133 was
        // actually pinning is that the restore report reaches the line an operator
        // reads, and the `contains` is that assertion; "and it is last" was true on
        // the day and is not a property `prest=` owns.
        assert!(
            line.contains(" prest=1/1 "),
            "prest remains a mid-line field after #200 and #130 (b): {line}"
        );
        // So the "one field is last" idea is kept rather than deleted — whichever
        // field it is must still be asserted, or a truncated line would pass.
        //
        // ⚠️ This assertion has now been rewritten by three consecutive appends
        // (#200, #130 (b), #181), which is the cost of pinning the tail **by name**
        // on an append-only line: every addition must edit it, and three concurrent
        // batons had to edit the same two lines. It is kept anyway — a truncated
        // line has to fail something — but the name is the newest field, not
        // whichever field happened to be last when the test was written.
        assert!(
            line.contains(" bdrop=0@- "),
            "the body-refusal field is present and mid-line: {line}"
        );
        assert!(
            line.contains(" unk=0/0 "),
            "the version-skew field is present and mid-line: {line}"
        );
        // #204's field is no longer the tail; it is asserted mid-line, by name, so
        // the next append does not have to touch this one.
        assert!(line.contains(" fdrop=0 "), "nothing was refused: {line}");
        // ⚠️ Rewritten a SIXTH time, by #212 — and this one was caught by the
        // workspace suite rather than by inspection, which is the warning the fifth
        // rewrite left. This assertion pins the tail BY NAME on an append-only line,
        // so every append must edit it, and git produced no conflict marker here on
        // any of the six because the incoming branch never touched this hunk. The
        // identical idea 1800 lines below DID conflict, every time, which is what
        // makes this copy the dangerous one.
        //
        // #229's reading is unchanged and is now asserted mid-line: a fresh rig is
        // caught up on its own one-node chain, so the ask set is empty and the fork
        // point is the applied tip — `bask=0@0`, not `0@-`: `state_fork_point()`
        // answers, it just answers "you are on the main chain".
        assert!(line.contains(" bask=0@0 "), "the requester wants nothing: {line}");
        // #212: head #3's identity is the tail now. This rig has finalized nothing on
        // EITHER head — `final=-` beside `dfin=-`/`dfinbh=-` — which is the consistent
        // cold-start reading and not a divergence.
        assert!(line.contains(" final=- "), "nothing finalized on head #1: {line}");
        assert!(line.contains(" dfin=- "), "nor on head #3: {line}");
        assert!(
            line.contains(" dfinbh=- "),
            "and it has no head to name: {line}"
        );
        // #359: this rig snapshotted at height 0 before the restart, so the reopened
        // node reads the height back off disk — and `snap=` is the tail now. (The
        // `ends_with` above became a `contains` for that reason; the discipline it
        // was checking is `telemetry_line_is_extended_at_the_end_and_nowhere_else`'s
        // job, which asserts the whole key order rather than one field's position.)
        assert!(line.ends_with(" snap=0"), "the durable snapshot survived too: {line}");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn telemetry_sample_reports_live_state() {
        // The Phase B-lite soak-monitor surface (M10-T0-3): after finalizing
        // genesis and mining two blocks, a sample line carries the live heights,
        // the derived finality regime, and the tip difficulty (LWMA trace).
        let (config, genesis, base) = rig("telemetry", true);
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        node.set_mine_interval(Duration::ZERO);
        node.try_checkpoint(); // finalize genesis (height 0)
        node.try_mine();
        node.try_checkpoint();
        node.try_mine();
        node.try_checkpoint();

        let line = node.telemetry_sample();
        assert!(line.starts_with("TELEMETRY "), "prefix: {line}");
        assert!(line.contains("tip=2"), "tip height: {line}");
        assert!(line.contains("final=0"), "genesis finalized, cadence 8 not reached: {line}");
        assert!(line.contains("stall=2"), "stall depth tip−final: {line}");
        // tip−final=2 ≤ DEGRADED_MODE_LAG_BLOCKS(16) ⇒ Final (not Degraded).
        assert!(line.contains("regime=Final"), "regime derived from frozen rule: {line}");
        assert!(line.contains("diff="), "difficulty field present: {line}");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// **Issue #130 (a): the `TELEMETRY` line, the `/metrics` scrape and the
    /// `/v1/telemetry` wire report ONE state-vs-fork-choice comparison.**
    ///
    /// Three surfaces need the same verdict, and this repo has ruled derive-don't-
    /// restate three times in one week (#116, #102, #125). #126's `SupplyCoverage`
    /// was already deriving it, so the shared concept is
    /// [`qlab_node::StateLag`] and this test pins the readings together: the log
    /// line's `stip=`, the gauges, and `Telemetry::supply_lag()` (which reads the
    /// applied height off the supply ledger, already on the `0x03` payload) must all
    /// name the same two heights. A fourth independent copy fails here.
    #[test]
    fn the_line_the_scrape_and_the_wire_agree_on_the_state_lag() {
        let (config, genesis, base) = rig("state_lag_agrees", true);
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        node.set_mine_interval(Duration::ZERO);
        node.try_checkpoint();
        assert!(node.try_mine());
        assert!(node.try_mine());

        let lag = node.p2p().node().state_lag();
        assert_eq!(lag.state_tip, 2, "this node applied every body it mined");
        assert_eq!(lag.fork_choice_tip, 2);
        assert!(!lag.is_lagging());

        // The line.
        let line = node.telemetry_sample();
        assert!(line.contains(" tip=2 "), "{line}");
        assert!(line.contains(" stip=2 slag=0"), "{line}");

        // The wire, which derives the applied height from the supply ledger.
        let t = node.telemetry();
        assert_eq!(t.supply_lag(), Some(lag), "the wire's comparison is the same pair");
        assert_eq!(t.supply_coverage(), qlab_node::SupplyCoverage::Complete);

        // The scrape.
        let text = node.metrics_text();
        assert!(text.contains("\nqumbra_tip_height 2\n"), "{text}");
        assert!(text.contains("\nqumbra_state_tip_height 2\n"), "{text}");
        assert!(text.contains("\nqumbra_state_lag_blocks 0\n"), "{text}");
        assert!(text.contains("\nqumbra_pending_bodies 0\n"), "{text}");
        assert!(
            text.contains("qumbra_state_lag_refusals_total{duty=\"mine\"} 0\n"),
            "a healthy node declares the refusal series at zero: {text}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// **Issue #130 (a), end to end through the binary: a node whose state machine is
    /// behind its own chain SAYS SO on the line an operator reads, refuses to mine
    /// while it is, and both stop once its bodies arrive.**
    ///
    /// This is the shape #130 was found in — the faucet's node reported
    /// `regime=Final final=8 fid=b6823616213f`, byte-identical to a healthy peer, with
    /// its state tip pinned at 4 against a fork-choice tip of 14. The same node now
    /// prints `stip=` and `slag=`, and the two `TELEMETRY` lines this test emits are
    /// the ones quoted in the PR.
    #[test]
    fn a_node_behind_its_own_chain_says_so_on_the_telemetry_line_and_refuses_to_mine() {
        use qlab_p2p::n1::{BlockIngest, IngestOutcome};

        // Node A mines a real three-block chain.
        let (config_a, genesis, base_a) = rig("lag_source", true);
        let mut a =
            RunningNode::start(&config_a, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        a.set_mine_interval(Duration::ZERO);
        a.try_checkpoint(); // finalize genesis, so `final=`/`fid=` carry values
        for _ in 0..3 {
            assert!(a.try_mine());
        }
        let chain = a.p2p().node().chain();
        let mined: Vec<_> = (1..=3)
            .map(|h| *chain.header(&chain.main_chain()[h]).expect("mined header"))
            .collect();
        let healthy = a.telemetry_sample();

        // Node B shares the genesis (`new_devnet_t0` is byte-identical across runs) and
        // learns HEADERS only — the state every joiner is in, and the state header-first
        // sync puts any node in the moment a `Headers` batch outruns a body announce.
        let (config_b, _same_genesis, base_b) = rig("lag_joiner", true);
        let mut b =
            RunningNode::start(&config_b, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        b.set_mine_interval(Duration::ZERO);
        b.try_checkpoint();
        for header in &mined {
            assert_eq!(b.p2p_mut().node_mut().ingest_header(*header), IngestOutcome::Accepted);
        }

        let lagging = b.telemetry_sample();
        // 🔴 The finding, as an assertion: before `stip`/`slag`, this line was
        // byte-identical to the healthy node's. Every pre-existing field on it comes
        // from fork choice — the view that works.
        // `stipid=`/`schain=` (issue #162 finding 6) are stripped alongside #130 (a)'s
        // two, because the claim under test is about the line **as it stood before
        // either baton** — and this list growing is itself the point: `stipid=` alone
        // would also have separated these two nodes, one baton later.
        let strip = |line: &str| {
            line.split_whitespace()
                .filter(|kv| {
                    !kv.starts_with("stip=")
                        && !kv.starts_with("slag=")
                        && !kv.starts_with("stipid=")
                        && !kv.starts_with("schain=")
                        // #130 (c)'s append, stripped for the same reason: it is a
                        // field of this family, added after the line the claim is
                        // about, and the list growing is the point.
                        && !kv.starts_with("breq=")
                        // #229's append, and it is the sharpest member of the family
                        // yet: `bask=3@0` against `bask=0@3` separates these two
                        // nodes on the ask set alone, without reading a height.
                        && !kv.starts_with("bask=")
                })
                .collect::<Vec<_>>()
                .join(" ")
        };
        assert_eq!(
            strip(&lagging),
            strip(&healthy),
            "without the two new fields, a node whose state machine is 3 blocks behind \
             its own chain is indistinguishable from a healthy one"
        );
        assert!(lagging.contains(" tip=3 "), "fork choice reached 3: {lagging}");
        assert!(lagging.contains(" stip=0 slag=3"), "and the state machine did not: {lagging}");
        assert!(!b.try_mine(), "a node that cannot record its own block refuses to mine one");
        let text = b.metrics_text();
        assert!(text.contains("\nqumbra_state_lag_blocks 3\n"), "{text}");
        assert!(
            text.contains("qumbra_state_lag_refusals_total{duty=\"mine\"} 1\n"),
            "the refusal is counted: {text}"
        );

        // The bodies arrive. Everything converges and the refusals stop.
        for header in &mined {
            let hash = header.header_hash();
            let stored = a.state().chain().block(&hash).expect("A has the body").clone();
            let body = stored.body();
            assert_eq!(
                b.p2p_mut().node_mut().ingest_block(*header, body),
                IngestOutcome::Duplicate,
                "the header was already held — which is exactly the case that used to \
                 throw the body away"
            );
        }
        let recovered = b.telemetry_sample();
        assert!(recovered.contains(" tip=3 "), "{recovered}");
        assert!(recovered.contains(" stip=3 slag=0"), "caught up: {recovered}");
        assert!(b.try_mine(), "and mining resumes");

        println!("PR-SAMPLE healthy : {healthy}");
        println!("PR-SAMPLE lagging : {lagging}");
        println!("PR-SAMPLE recovered: {recovered}");
        let _ = std::fs::remove_dir_all(&base_a);
        let _ = std::fs::remove_dir_all(&base_b);
    }

    // ---- issue #162 finding 6: the applied tip's IDENTITY, and the wedge -----

    /// [`rig`], plus a distinct miner payout key.
    ///
    /// **This is the ingredient the whole #130 (a) suite lacks and the live net
    /// has.** `mine_chain()` builds one linear chain from one proposer and the
    /// follower starts at state tip 0 on that same chain, so a *sibling at the state
    /// tip's own height* does not exist anywhere in it (QUM-35's §3). Two nodes with
    /// different `miner_rkm` pay their coinbase to different keys, so their coinbase
    /// bodies differ, so their `tx_body_commitment` differs, so their height-1
    /// headers are **genuine siblings** — which is how `node0` and `node2` came to
    /// hold different blocks at `stip=1` on 2026-07-31 with three of them mining at
    /// `tip=0` within three seconds of each other.
    fn rig_paying(tag: &str, rkm_byte: u8) -> (NodeConfig, GenesisFile, PathBuf) {
        let (mut config, genesis, base) = rig(tag, true);
        config.miner_rkm = Some(format!("{rkm_byte:02x}").repeat(32));
        (config, genesis, base)
    }

    /// Start a node on the shared genesis, finalize genesis, and mine `n` blocks of
    /// its own. Returns it at `stip=n slag=0`.
    fn node_mining_its_own(config: &NodeConfig, genesis: &GenesisFile, n: usize) -> RunningNode<KeccakPow, DevnetRehearsalVerifier> {
        let mut node =
            RunningNode::start(config, genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        node.set_mine_interval(Duration::ZERO);
        node.try_checkpoint(); // finalize genesis, so `final=`/`fid=` carry values
        for _ in 0..n {
            assert!(node.try_mine(), "KeccakPow mines at the genesis difficulty");
        }
        node
    }

    /// Every main-chain header of `node` from height 1 to its tip, ascending.
    fn main_chain_headers(
        node: &RunningNode<KeccakPow, DevnetRehearsalVerifier>,
    ) -> Vec<qlab_devnet::header::BlockHeader> {
        let chain = node.p2p().node().chain();
        (1..=chain.tip_height() as usize)
            .map(|h| *chain.header(&chain.main_chain()[h]).expect("main-chain header"))
            .collect()
    }

    /// **ACCEPTANCE #1 — the whole point of the issue, and #84's sentence one layer
    /// down.**
    ///
    /// Two nodes at the *same* `stip=` height having applied *different* blocks must
    /// print different `stipid=`. On the 2026-07-31 T0 net `node0`'s `stip=1` and
    /// `node2`'s `stip=1` looked identical and were different blocks — node2's a
    /// sibling on a losing branch — and that single ambiguity is why diagnosing the
    /// wedge took an archive dive instead of a glance.
    ///
    /// The third node repeats the first exactly, which pins the other half: two
    /// nodes on the same block must be **byte-identical**, or the field cries wolf
    /// on every healthy net and gets ignored (#84's rule, followed here).
    #[test]
    fn nodes_at_one_stip_height_on_different_applied_blocks_print_different_stipid() {
        let (ca, genesis, ba) = rig_paying("stipid_a", 0xa1);
        let (cb, _, bb) = rig_paying("stipid_b", 0xb2);
        let (cc, _, bc) = rig_paying("stipid_c", 0xa1); // A's payout key ⇒ A's block

        let node_a = node_mining_its_own(&ca, &genesis, 1);
        let node_b = node_mining_its_own(&cb, &genesis, 1);
        let node_c = node_mining_its_own(&cc, &genesis, 1);
        let a = node_a.telemetry_sample();
        let b = node_b.telemetry_sample();
        let c = node_c.telemetry_sample();

        // All three agree on the height, which is exactly the problem: `stip=` alone
        // cannot tell the sibling from the shared block.
        for l in [&a, &b, &c] {
            assert_eq!(field(l, "stip"), "1", "{l}");
            assert_eq!(field(l, "slag"), "0", "each applied what it mined: {l}");
        }

        // A and B applied different blocks at height 1 ⇒ different identities.
        assert_ne!(
            field(&a, "stipid"),
            field(&b, "stipid"),
            "two different applied blocks at one height MUST NOT print the same \
             identity\nA: {a}\nB: {b}"
        );
        // A and C applied the same block ⇒ byte-identical identities.
        assert_eq!(
            field(&a, "stipid"),
            field(&c, "stipid"),
            "agreeing nodes MUST be byte-identical\nA: {a}\nC: {c}"
        );

        // Well-formed, and at `fid`/`sid`'s width — the three are one scheme, so an
        // operator can compare them by eye without knowing which is which.
        for l in [&a, &b, &c] {
            let stipid = field(l, "stipid");
            assert_eq!(stipid.len(), field(l, "fid").len(), "same width as fid: {l}");
            assert_eq!(stipid.len(), 12, "{l}");
            assert!(u64::from_str_radix(stipid, 16).is_ok(), "{l}");
            assert!(
                stipid.chars().all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()),
                "{l}"
            );
        }

        // The identity is the block hash's prefix and **not a second scheme**:
        // re-derived here from the raw hash, independently of the rendering path, so
        // a future short-id helper that quietly re-hashes fails this line.
        let applied = node_a.p2p().node().applied_tip();
        let expected: String =
            applied.hash[..6].iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(field(&a, "stipid"), expected, "stipid IS the block hash prefix");
        // …and the scrape carries the same number in decimal (#84's correspondence:
        // `printf '%012x'` of the gauge is the log field).
        let text = node_a.metrics_text();
        assert!(
            text.contains(&format!("\nqumbra_state_tip_id {}\n", applied.identity().bits())),
            "{text}"
        );
        assert_eq!(
            u64::from_str_radix(field(&a, "stipid"), 16).unwrap(),
            applied.identity().bits(),
            "the log field and the gauge are two spellings of one number"
        );

        for base in [ba, bb, bc] {
            let _ = std::fs::remove_dir_all(&base);
        }
    }

    /// **ACCEPTANCE #2 — the detector fires on a wedged node and stays QUIET on a
    /// merely lagging one.**
    ///
    /// Both halves, because a detector that fires on any nonzero `slag=` is worse
    /// than none: it retrains the operator to ignore it. `slag=` covers both states
    /// and they need different responses — a lagging node catches up by applying
    /// forward, a stranded one has to undo an applied block first.
    ///
    /// **Amended by issue #162 (acceptance item 5).** The stranded node now recovers
    /// too, so the tail of this test is inverted: what it pins is that the detector
    /// still SEPARATES the two states while they differ, and that the wedged one goes
    /// quiet because a rewind fixed it — evidenced by the rewind counter and the
    /// `REWIND` journal line, not by the absence of an alarm.
    ///
    /// The wedged node here is the live shape exactly: it mined its own height 1,
    /// lost the fork race, its **chain** reorged onto the winner and its **state**
    /// could not follow.
    #[test]
    fn the_wedge_detector_fires_on_a_stranded_state_machine_and_not_on_a_lagging_one() {
        use qlab_p2p::n1::{BlockIngest, IngestOutcome};

        // The winner: three blocks, all its own.
        let (cw, genesis, bw) = rig_paying("wedge_win", 0xa1);
        let winner = node_mining_its_own(&cw, &genesis, 3);
        let healthy = winner.telemetry_sample();
        let winning = main_chain_headers(&winner);

        // ── The WEDGED node. It mined its own height 1 — a genuine sibling — and
        //    then heard the winner's heavier branch. Fork choice reorgs; the state
        //    machine, which has no rewind, cannot.
        let (cl, _, bl) = rig_paying("wedge_lose", 0xb2);
        let mut loser = node_mining_its_own(&cl, &genesis, 1);
        let own_block_1 = loser.p2p().node().applied_tip().hash;
        assert_ne!(own_block_1, winning[0].header_hash(), "a genuine sibling at height 1");
        for header in &winning {
            loser.p2p_mut().node_mut().ingest_header(*header);
        }
        let wedged = loser.telemetry_sample();

        // ── The LAGGING node. Same headers, but it never mined, so its applied tip
        //    is genesis — which IS the main-chain block at height 0.
        let (cg, _, bg) = rig_paying("wedge_lag", 0xc3);
        let mut lagger = node_mining_its_own(&cg, &genesis, 0);
        for header in &winning {
            assert_eq!(
                lagger.p2p_mut().node_mut().ingest_header(*header),
                IngestOutcome::Accepted
            );
        }
        let lagging = lagger.telemetry_sample();

        // 🔴 THE FINDING. Both are behind their own chain and `slag=` cannot tell
        // them apart; only `schain=` can.
        assert!(field(&wedged, "slag").parse::<u64>().unwrap() > 0, "{wedged}");
        assert!(field(&lagging, "slag").parse::<u64>().unwrap() > 0, "{lagging}");
        assert_eq!(field(&wedged, "schain"), "fork", "the detector FIRES: {wedged}");
        assert_eq!(field(&lagging, "schain"), "main", "and stays QUIET: {lagging}");
        assert_eq!(field(&healthy, "schain"), "main", "and on a healthy node: {healthy}");
        assert_eq!(field(&healthy, "slag"), "0", "{healthy}");

        // The identity is what says *which* block, and it is the losing sibling's.
        let expected: String =
            own_block_1[..6].iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(field(&wedged, "stipid"), expected, "{wedged}");
        assert_ne!(
            field(&wedged, "stipid"),
            field(&healthy, "stipid"),
            "the two nodes' applied tips are different blocks"
        );

        // The scrape carries the same verdict, from the same `applied_tip()`.
        let wedged_metrics = loser.metrics_text();
        assert!(
            wedged_metrics.contains("\nqumbra_state_tip_off_main_chain 1\n"),
            "{wedged_metrics}"
        );
        assert!(
            wedged_metrics.contains(&format!(
                "\nqumbra_state_tip_id {}\n",
                u64::from_str_radix(field(&wedged, "stipid"), 16).unwrap()
            )),
            "printf '%012x' of the gauge is the log field: {wedged_metrics}"
        );
        let lagging_metrics = lagger.metrics_text();
        assert!(
            lagging_metrics.contains("\nqumbra_state_tip_off_main_chain 0\n"),
            "{lagging_metrics}"
        );

        // ── **The half that proves the two states are genuinely different, and —
        //    since issue #162 — that BOTH of them recover.** Every body of the
        //    winning branch is handed to both nodes.
        //
        //    Rewritten by the #162 baton. It used to close by asserting that the
        //    wedged node's state tip had not moved, annotated "fixing it is a
        //    separate baton". That baton is this one, so the assertion is inverted
        //    rather than deleted: the two nodes still reach `slag=0 schain=main` by
        //    **different routes**, and the routes are what this test is for. The
        //    lagging node applies forward and never rewinds; the wedged one rewinds
        //    off its sibling first, and `REWIND` in the journal is what distinguishes
        //    them afterwards, when both lines read identically.
        for header in &winning {
            let hash = header.header_hash();
            let stored = winner.state().chain().block(&hash).expect("the winner has it").clone();
            let body = stored.body();
            lagger.p2p_mut().node_mut().ingest_block(*header, body.clone());
            loser.p2p_mut().node_mut().ingest_block(*header, body);
        }
        let lagger_after = lagger.telemetry_sample();
        assert_eq!(field(&lagger_after, "slag"), "0", "the lagging node catches up: {lagger_after}");
        assert_eq!(field(&lagger_after, "schain"), "main", "{lagger_after}");
        assert_eq!(
            lagger.p2p().node().state_rewinds(),
            (0, 0),
            "and it did NOT rewind — a node that is merely behind must never pay for one"
        );

        let loser_after = loser.telemetry_sample();
        assert_eq!(
            field(&loser_after, "schain"),
            "main",
            "the wedged node rejoined the main chain (#162): {loser_after}"
        );
        assert_eq!(field(&loser_after, "slag"), "0", "and converged: {loser_after}");
        assert_ne!(
            field(&loser_after, "stipid"),
            expected,
            "its applied tip is no longer the losing sibling: {loser_after}"
        );
        assert_eq!(
            field(&loser_after, "stipid"),
            field(&lagger_after, "stipid"),
            "both nodes ended on the same block, by different routes"
        );
        assert_eq!(
            loser.p2p().node().state_rewinds(),
            (1, 1),
            "one rewind, one block undone — the route the lagging node did not take"
        );
        // The event is in the journal, which is where the difference survives after
        // the two telemetry lines have become identical.
        let journal = loser.emit_rewinds();
        assert_eq!(journal.len(), 1, "{journal:?}");
        assert!(journal[0].starts_with("REWIND applied tip "), "{}", journal[0]);
        assert!(journal[0].ends_with("(1 block(s) undone)"), "{}", journal[0]);
        assert!(
            loser.emit_rewinds().is_empty(),
            "drained, so the same event is not journalled twice"
        );
        println!("PR-SAMPLE rewind : {}", journal[0]);
        println!("PR-SAMPLE rejoin : {loser_after}");

        println!("PR-SAMPLE healthy: {healthy}");
        println!("PR-SAMPLE lagging: {lagging}");
        println!("PR-SAMPLE wedged : {wedged}");
        for base in [bw, bl, bg] {
            let _ = std::fs::remove_dir_all(&base);
        }
    }

    // ---- issue #229: the ask set, on the two surfaces an operator has ---------

    /// 🔴 **`bask=` is the ask set, and `breq=` is not.**
    ///
    /// *"An ask set of 15 with 2 in flight and an ask set of 2 are the same `breq`
    /// and different bugs."* The live hosts printed `breq=1–2` for over an hour and
    /// no field on the line could say which of those two it was, because the ask
    /// set — what `missing_body_hashes` actually produced — was never published.
    ///
    /// This node is stranded with **nothing in flight** (it has no peer to ask) and
    /// an ask set of three, which is precisely the pair the old line collapsed: on
    /// `main` it prints `breq=0` and there is no second number.
    #[test]
    fn bask_publishes_the_ask_set_and_the_fork_point_which_breq_cannot() {
        use qlab_p2p::n1::BlockIngest;

        let (cw, genesis, bw) = rig_paying("i229_bask_win", 0xa1);
        let winner = node_mining_its_own(&cw, &genesis, 3);
        let winning = main_chain_headers(&winner);

        let (cl, _, bl) = rig_paying("i229_bask_lose", 0xb2);
        let mut loser = node_mining_its_own(&cl, &genesis, 1);
        for header in &winning {
            loser.p2p_mut().node_mut().ingest_header(*header);
        }

        let healthy = winner.telemetry_sample();
        let stranded = loser.telemetry_sample();
        // A node on its own chain wants nothing and knows where it is.
        assert_eq!(field(&healthy, "bask"), "0@3", "nothing to fetch: {healthy}");
        assert_eq!(field(&healthy, "breq"), "0");
        // The stranded node wants three main-chain bodies and has asked for none.
        assert_eq!(field(&stranded, "schain"), "fork", "{stranded}");
        assert_eq!(field(&stranded, "breq"), "0", "no peer, so nothing in flight");
        assert_eq!(
            field(&stranded, "bask"),
            "3@0",
            "🔴 …and yet it wants three bodies, from a fork point at genesis — the \
             two facts `breq=0` cannot carry: {stranded}"
        );
        // The fork point moves with the strand, so it is a measurement and not a
        // constant: applying the winning branch puts it back on the main chain.
        for header in &winning {
            let hash = header.header_hash();
            let stored = winner.state().chain().block(&hash).expect("winner has it").clone();
            loser.p2p_mut().node_mut().ingest_block(*header, stored.body());
        }
        let rejoined = loser.telemetry_sample();
        assert_eq!(field(&rejoined, "schain"), "main", "{rejoined}");
        assert_eq!(field(&rejoined, "bask"), "0@3", "the gap closed: {rejoined}");
        println!("PR-SAMPLE i229 healthy : {healthy}");
        println!("PR-SAMPLE i229 stranded: {stranded}");
        for base in [bw, bl] {
            let _ = std::fs::remove_dir_all(&base);
        }
    }

    /// 🔴 **The `BODYWAIT` journal on the binary, including the mining refusal —
    /// and silence on a healthy node.**
    ///
    /// The three stranded hosts stopped mining, correctly (`lagging && !exempt ⇒
    /// refuse`), and **nothing said so**: `refuse_for_lag` is a `/metrics` counter
    /// and `metrics_addr` is unset on every T0 host, so the only way to know was to
    /// difference `tip=` across hosts. This asserts the line says it, on stdout,
    /// with no listener configured — and that the refusal *count* is on it too, so
    /// the claim is a measurement rather than a re-derivation of the predicate.
    ///
    /// The clock is supplied rather than slept: the latch threshold is
    /// `UNOBTAINABLE_BODY_CADENCES × CHECKPOINT_CADENCE_BLOCKS × block_time` = 20
    /// minutes at the frozen 75 s target, and a test that waited for it would be a
    /// test nobody runs.
    #[test]
    fn a_stranded_node_journals_what_it_wants_and_that_it_has_stopped_mining() {
        use qlab_p2p::n1::BlockIngest;

        let (cw, genesis, bw) = rig_paying("i229_journal_win", 0xa1);
        let mut winner = node_mining_its_own(&cw, &genesis, 3);
        let winning = main_chain_headers(&winner);

        let (cl, _, bl) = rig_paying("i229_journal_lose", 0xb2);
        let mut loser = node_mining_its_own(&cl, &genesis, 1);
        for header in &winning {
            loser.p2p_mut().node_mut().ingest_header(*header);
        }
        // The refusal the line reports: the duty gate declines, once, for real.
        assert!(!loser.try_mine(), "a node whose applied view is stale must not mine");

        let threshold = loser.p2p().node().unobtainable_threshold_ms();
        // Start the stall clock, then step past the threshold. `observe_body_fetch`
        // is the per-tick hook `P2pNode::tick` calls; driving it directly is what
        // lets a 20-minute constant be tested in microseconds.
        loser.p2p_mut().node_mut().observe_body_fetch(0, 0, false);
        assert!(loser.emit_body_waits_at(0).is_empty(), "not yet — the clock just started");
        loser.p2p_mut().node_mut().observe_body_fetch(threshold + 1, 0, false);
        let lines = loser.emit_body_waits_at(threshold + 1);

        assert!(!lines.is_empty(), "a node stranded past the threshold says so");
        let summary = &lines[0];
        assert!(summary.starts_with("BODYWAIT stip=1 "), "{summary}");
        assert!(summary.contains(" schain=fork "), "{summary}");
        assert!(summary.contains(" sfork=0 ask=3 breq=0 "), "the ask set: {summary}");
        assert!(summary.contains(" gate=missing@1 "), "the rejoin gate: {summary}");
        assert!(
            summary.contains(" mine=refused-lag mrefuse=1 "),
            "🔴 it has stopped mining, and the count is the evidence: {summary}"
        );
        assert!(summary.ends_with(" stuck_s=1200"), "and for how long: {summary}");

        // The rate limit: an unchanged picture inside the floor is silent.
        loser.p2p_mut().node_mut().observe_body_fetch(threshold + 2_000, 0, false);
        assert!(
            loser.emit_body_waits_at(threshold + 2_000).is_empty(),
            "an unchanged stranding does not repeat itself every pass"
        );

        // 🔴 The negative, on the binary: the winner is healthy and mining, and it
        // has been at its tip for longer than the threshold. It emits nothing.
        winner.p2p_mut().node_mut().observe_body_fetch(0, 0, false);
        winner.p2p_mut().node_mut().observe_body_fetch(threshold * 4, 0, false);
        assert!(
            winner.emit_body_waits_at(threshold * 4).is_empty(),
            "a healthy node never emits this line — not even a quiet one"
        );
        assert!(winner.try_mine(), "…and it is still mining");

        println!("PR-SAMPLE i229 journal: {summary}");
        for base in [bw, bl] {
            let _ = std::fs::remove_dir_all(&base);
        }
    }

    #[test]
    fn telemetry_age_is_dash_when_nothing_finalized() {
        // S8: a node that has mined but never finalized prints `final=-` AND `age_s=-`
        // (not a genesis-fallback absolute), so the runbook's stall alarm is honest.
        let (config, genesis, base) = rig("age_dash", true);
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        node.set_mine_interval(Duration::ZERO);
        node.try_mine(); // a block, but no checkpoint ⇒ nothing finalized
        let line = node.telemetry_sample();
        assert!(line.contains("final=-"), "nothing finalized: {line}");
        assert!(line.contains("age_s=-"), "age must be '-' when unfinalized: {line}");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Issue #73 — the boundary S8 left open. A fresh net bootstrap-finalizes
    /// GENESIS (`final=0`), and differencing the WallClock tip against genesis's
    /// `timestamp = 0` placeholder printed the wall clock itself (`age_s=1785352360`
    /// on all four nodes of the #119 run, for the whole start→slot-8 window).
    /// While the finalized head is genesis the line says `age_s=-` and the wire
    /// value is 0; the FIRST non-genesis checkpoint flips it to a real chain-time
    /// age. The transition is the property, not either side alone.
    #[test]
    fn telemetry_age_is_dash_at_genesis_then_real_after_first_checkpoint() {
        let (config, genesis, base) = rig("age_genesis", true);
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        node.set_mine_interval(Duration::ZERO);

        // Bootstrap: finalize genesis, put the tip past it — the live defect's shape.
        node.try_checkpoint();
        assert_eq!(node.finalized_height(), Some(0), "genesis finalized");
        assert!(node.try_mine());
        let line = node.telemetry_sample();
        assert!(line.contains("final=0"), "finalized head is genesis: {line}");
        assert!(line.contains("age_s=-"), "no finalized checkpoint ⇒ no age: {line}");
        assert_eq!(
            node.telemetry().last_finalized_age_secs,
            0,
            "the wire carries 0, never tip_ts − genesis placeholder"
        );

        // Cross the boundary: reach slot 8 plus the #269 sign-hysteresis (the slot
        // is deliberately not signed at tip == slot), finalize it.
        for _ in 1..CHECKPOINT_CADENCE_BLOCKS + CHECKPOINT_SIGN_HYSTERESIS_BLOCKS {
            assert!(node.try_mine());
        }
        node.try_checkpoint();
        assert_eq!(
            node.finalized_height(),
            Some(CHECKPOINT_CADENCE_BLOCKS),
            "the first non-genesis checkpoint finalized"
        );
        assert!(node.try_mine());
        let t = node.telemetry();
        assert!(t.last_finalized_age_secs > 0, "a real chain-time age, both timestamps real");
        let line = node.telemetry_sample();
        assert!(
            line.contains(&format!("age_s={} ", t.last_finalized_age_secs)),
            "the line speaks once a checkpoint exists to measure from: {line}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn run_until_flushes_a_snapshot_on_shutdown() {
        let (config, genesis, base) = rig("shutdown", true);
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        node.set_mine_interval(Duration::ZERO);
        node.try_mine();
        // A pre-set shutdown flag: run_until does the graceful flush and returns.
        // This proves the *exit path* writes both files when the flag is set; the
        // signal→flag arming is covered by `tests/sigterm_shutdown.rs` (issue #145).
        let shutdown = AtomicBool::new(true);
        let ok = node.run_until(&shutdown);
        assert!(ok, "snapshot flush succeeds on a writable data dir");
        // The snapshot file now exists in the data dir (graceful flush ran).
        assert!(config.data_dir.join(qlab_node::SNAPSHOT).exists(), "snapshot flushed");
        // peers.dat is the same post-loop block — every deployment restart was
        // manufacturing a seeds-only book because this write never ran (#145).
        assert!(
            config.data_dir.join(ADDRBOOK_FILE).exists(),
            "peers.dat written on the same graceful-shutdown path as the snapshot"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Issue #145: `run_until` must return `false` when the snapshot flush fails,
    /// **Issue #107 S1 — the instrument measures the loop, not a copy of it.**
    ///
    /// The unit tests in [`crate::looptime`] prove the line formats and the
    /// attribution arithmetic against synthetic phases. This one proves the
    /// wiring: a real iteration of the real loop, with a known cost injected
    /// into a known phase, and the measurement read back off the same code path
    /// the fleet runs. Without it, every phase could be assigned to the wrong
    /// statement and every unit test would still pass.
    #[test]
    fn one_iteration_attributes_an_injected_cost_to_the_phase_that_paid_it() {
        let (config, genesis, base) = rig("loopphase", false);
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        // 120 ms is far above the loop's own floor and far below anything that
        // would make the test slow; the threshold is lowered to match so the
        // journal line is exercised too rather than only the record.
        node.set_loop_slow_threshold(Duration::from_millis(50));
        let mut hook = |_: &mut RunningNode<KeccakPow, DevnetRehearsalVerifier>| {
            std::thread::sleep(Duration::from_millis(120))
        };
        let (phases, lines) = node.one_iteration(&mut hook);

        assert!(
            phases.hook >= Duration::from_millis(100),
            "the hook's 120 ms is charged to the hook phase: {:?}",
            phases.hook
        );
        let (name, d) = phases.worst();
        assert_eq!(name, "hook", "and it is what the attribution names");
        assert_eq!(d, phases.hook, "with the phase's own number");
        // The cost lands in ONE phase: every other phase on a quiet node is
        // sub-millisecond, so a mis-wired `lap` cursor (one that failed to
        // advance, and so charged each phase for its predecessor's work) would
        // show the 120 ms in `snapshot` as well.
        assert!(
            phases.snapshot < Duration::from_millis(50),
            "the phase AFTER the hook is not charged for it: {:?}",
            phases.snapshot
        );
        assert!(
            phases.pump < Duration::from_millis(50),
            "nor the phase before it: {:?}",
            phases.pump
        );
        // And the record is internally consistent: busy covers the injected
        // cost, and the idle back-off is accounted separately from work.
        assert!(phases.busy() >= phases.hook);
        assert_eq!(phases.total(), phases.busy() + phases.sleep);

        // The journal said so too — this is the line an operator greps, taken
        // off the loop rather than off a formatter called with made-up numbers.
        assert_eq!(lines.len(), 1, "one slow line, no window line off-cadence: {lines:?}");
        assert!(lines[0].starts_with("LOOP kind=slow unit=ms "), "{}", lines[0]);
        assert!(lines[0].contains(" phase=hook "), "{}", lines[0]);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// **The window line rides the telemetry cadence** (issue #107 S1): every
    /// `TELEMETRY` line gets a `LOOP kind=window` beside it explaining what the
    /// gap before it was made of, and off-cadence iterations emit neither.
    ///
    /// This is the half that matters for the degraded population in this issue,
    /// which was *steadily* slow rather than spiking — a threshold-only
    /// instrument would have been silent through all 53 samples.
    #[test]
    fn the_window_line_is_emitted_on_the_telemetry_cadence_and_not_otherwise() {
        let (config, genesis, base) = rig("loopwindow", false);
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        let mut noop = |_: &mut RunningNode<KeccakPow, DevnetRehearsalVerifier>| {};

        // Off-cadence: the default 30 s interval has not elapsed, so nothing.
        let (_, quiet) = node.one_iteration(&mut noop);
        assert!(quiet.is_empty(), "a healthy off-cadence iteration is silent: {quiet:?}");

        // On-cadence: every iteration samples.
        node.set_sample_interval(Duration::ZERO);
        let (_, first) = node.one_iteration(&mut noop);
        assert_eq!(first.len(), 1, "the window line, and no slow line: {first:?}");
        let w = &first[0];
        assert!(w.starts_with("LOOP kind=window unit=ms "), "{w}");
        assert!(w.contains(" iters=2 "), "it covers the window since the last one: {w}");
        assert!(w.contains(" slow=0 slowsup=0 "), "nothing was slow: {w}");

        // ...and the next window starts empty rather than carrying the last one.
        let (_, second) = node.one_iteration(&mut noop);
        assert!(second[0].contains(" iters=1 "), "the window reset: {}", second[0]);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The other half of the same wiring claim: a quiet iteration is dominated
    /// by the idle back-off, and the *work* it did is sub-millisecond. This is
    /// the baseline against which "the loop period is 131 s" is a finding at
    /// all — and it is measured here rather than assumed.
    #[test]
    fn a_quiet_iteration_is_idle_rather_than_busy() {
        let (config, genesis, base) = rig("loopquiet", false);
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        let mut noop = |_: &mut RunningNode<KeccakPow, DevnetRehearsalVerifier>| {};
        // The first iteration carries the startup sample; take the second.
        let _ = node.one_iteration(&mut noop);
        let (phases, lines) = node.one_iteration(&mut noop);
        assert!(
            phases.sleep >= Duration::from_millis(15),
            "a quiescent pump ends in the 20 ms back-off: {:?}",
            phases.sleep
        );
        assert!(
            phases.busy() < Duration::from_millis(20),
            "and the work it did is not what the period is made of: {:?}",
            phases.busy()
        );
        assert_eq!(phases.tick.frames, 0, "no peers, no frames");
        assert!(lines.is_empty(), "and it says nothing at all: {lines:?}");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// so main does not print "snapshot flushed" after a failed write.
    #[test]
    fn run_until_returns_false_when_snapshot_flush_fails() {
        let (config, genesis, base) = rig("shutdown_fail", true);
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        node.set_mine_interval(Duration::ZERO);
        node.try_mine();
        // Make the data dir unwritable so the atomic snapshot create (tmp + rename)
        // cannot succeed. The return value is what main keys the status line on.
        let mut perms = std::fs::metadata(&config.data_dir).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&config.data_dir, perms.clone()).unwrap();

        let shutdown = AtomicBool::new(true);
        let ok = node.run_until(&shutdown);
        assert!(!ok, "snapshot flush failure must surface as false to the caller");

        // Restore writability so cleanup can remove the tree.
        perms.set_readonly(false);
        std::fs::set_permissions(&config.data_dir, perms).unwrap();
        let _ = std::fs::remove_dir_all(&base);
    }

    /// **Issue #359 S5 (a) — the invariant.** A node that has run past the cadence
    /// with its applied height advanced has written a snapshot, *with no shutdown
    /// anywhere in the story*.
    ///
    /// The assertion that carries the issue is made **inside the loop**, through
    /// the `run_until_with` hook, before the exit path can run: until this baton
    /// the only write was the post-loop flush, so a test that looked after
    /// `run_until` returned could not tell the cadence from the flush and would
    /// have passed on `main` unchanged. Here the snapshot must already be on disk
    /// while the loop is still running.
    #[test]
    fn a_node_past_the_cadence_has_written_a_snapshot_without_stopping() {
        let (config, genesis, base) = rig("i359_cadence", true);
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        node.set_mine_interval(Duration::ZERO);
        node.set_snapshot_interval(Duration::ZERO); // every iteration is a tick

        // The starting state is node3's: a data dir that has never been stopped.
        assert_eq!(
            node.durable_snapshot(),
            qlab_node::SnapshotOnDisk::Absent,
            "a fresh data dir has no snapshot"
        );
        assert!(!config.data_dir.join(qlab_node::SNAPSHOT).exists());

        let shutdown = AtomicBool::new(false);
        let mut seen: Option<(u64, qlab_node::SnapshotOnDisk, bool)> = None;
        node.run_until_with(&shutdown, |n| {
            seen = Some((
                n.p2p().node().state_lag().state_tip,
                n.durable_snapshot(),
                n.data_dir.join(qlab_node::SNAPSHOT).exists(),
            ));
            shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        let (applied, snap, on_disk) = seen.expect("the per-iteration hook ran");
        assert!(applied > 0, "the loop mined and applied a block this iteration");
        assert!(on_disk, "🔴 the file exists while the loop is still running — not at exit");
        assert_eq!(
            snap,
            qlab_node::SnapshotOnDisk::At { applied_height: applied },
            "and the cadence recorded the height it wrote"
        );
        drop(node);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// **Issue #359 S5 (a), second half — idempotence.** A second tick on an
    /// unchanged chain does not rewrite the snapshot. This is what keeps the
    /// cadence free on a halted or stalled net, where the applied height can sit
    /// still for hours.
    ///
    /// Proven by the file's modification time rather than by its contents: the
    /// snapshot of an unchanged state is byte-identical, so comparing bytes could
    /// not tell "did not write" from "wrote the same thing".
    #[test]
    fn the_cadence_does_not_rewrite_an_unchanged_snapshot() {
        let (config, genesis, base) = rig("i359_idempotent", true);
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        node.set_mine_interval(Duration::ZERO);
        node.set_snapshot_interval(Duration::ZERO);
        assert!(node.try_mine(), "one block, so the height has advanced");

        node.maintain_snapshot();
        let path = config.data_dir.join(qlab_node::SNAPSHOT);
        let first = std::fs::metadata(&path).expect("written").modified().expect("mtime");
        assert_eq!(node.durable_snapshot(), qlab_node::SnapshotOnDisk::At { applied_height: 1 });

        // Enough separation that a rewrite would be visible even on a
        // coarse-grained filesystem timestamp.
        std::thread::sleep(Duration::from_millis(1100));
        node.maintain_snapshot();
        let second = std::fs::metadata(&path).expect("still there").modified().expect("mtime");
        assert_eq!(first, second, "an unchanged applied height rewrites nothing");

        // …and a changed one does write again.
        assert!(node.try_mine());
        node.maintain_snapshot();
        assert_eq!(node.durable_snapshot(), qlab_node::SnapshotOnDisk::At { applied_height: 2 });
        let third = std::fs::metadata(&path).expect("rewritten").modified().expect("mtime");
        assert_ne!(second, third, "an advanced applied height does write");

        drop(node);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// **Issue #359 follow-up S3 — runtime catch-up writes a consistent prefix.**
    ///
    /// B has taken the network's headers to height 3 and applied only the body at
    /// height 1, so `stip=1 slag=2`. A cadence tick must write height 1 while B is
    /// still catching up. Restoring the old `lag.blocks() != 0` gate makes the
    /// file-exists assertion fail, which mutation-checks the exact rule change.
    #[test]
    fn runtime_catch_up_writes_a_snapshot_of_its_applied_prefix() {
        use qlab_p2p::n1::{BlockIngest, IngestOutcome};

        let a_port = free_port();
        let a_addr = format!("127.0.0.1:{a_port}");

        // A is the established net: three blocks, dialable.
        let (mut acfg, agen, abase) = rig("i359_net", true);
        acfg.listen_addr = a_addr.clone();
        acfg.advertise_addr = Some(a_addr.clone());
        let mut a = RunningNode::start(&acfg, &agen, KeccakPow, DevnetRehearsalVerifier).unwrap();
        a.set_mine_interval(Duration::ZERO);
        for _ in 0..3 {
            assert!(a.try_mine());
        }

        // B joins with an empty data dir and syncs headers only.
        let (mut bcfg, bgen, bbase) = rig("i359_joiner", true);
        bcfg.dial_peers = vec![a_addr.clone()];
        let mut b = RunningNode::start(&bcfg, &bgen, KeccakPow, DevnetRehearsalVerifier).unwrap();
        b.set_mine_interval(Duration::ZERO);
        b.set_snapshot_interval(Duration::ZERO); // every call is a cadence tick
        let snap_path = bcfg.data_dir.join(qlab_node::SNAPSHOT);

        // First take only the header chain. Do not tick the cadence before B hears
        // it: at that instant B is legitimately synced with itself and could write
        // a height-0 snapshot, masking the catch-up case this test exists to pin.
        for _ in 0..60 {
            a.step_once();
            b.step_once();
            if b.p2p().sync_phase().is_synced() && b.tip_height() == 3 {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(b.tip_height(), 3, "B took the network's header chain");
        assert_eq!(b.p2p().node().state_lag().blocks(), 3, "no body is applied yet");
        assert_eq!(b.durable_snapshot(), qlab_node::SnapshotOnDisk::Absent);

        // Apply exactly one historical body. B is now actively catching up, with
        // a non-zero applied prefix and a non-zero lag to the known header tip.
        let chain = a.p2p().node().chain();
        let header = *chain.header(&chain.main_chain()[1]).expect("height-1 header");
        let stored =
            a.state().chain().block(&header.header_hash()).expect("A holds the body").clone();
        assert_eq!(
            b.p2p_mut().node_mut().ingest_block(header, stored.body()),
            IngestOutcome::Duplicate,
            "the header was already held"
        );
        let lag = b.p2p().node().state_lag();
        assert_eq!(lag.state_tip, 1, "one historical body is applied");
        assert_eq!(lag.blocks(), 2, "B remains behind the known header tip");

        // The cadence writes that consistent prefix despite the remaining lag.
        b.maintain_snapshot();
        assert!(snap_path.exists(), "🔴 runtime catch-up must write before it is synced");
        assert_eq!(
            b.durable_snapshot(),
            qlab_node::SnapshotOnDisk::At { applied_height: lag.state_tip },
            "the durable height is the state machine's applied prefix"
        );
        assert_eq!(
            qlab_node::snapshot_on_disk(&bcfg.data_dir).unwrap(),
            qlab_node::SnapshotOnDisk::At { applied_height: lag.state_tip },
            "the file on disk carries the same applied prefix"
        );
        let line = b.telemetry_sample();
        assert!(line.contains(" stip=1 slag=2"), "the test exercised catch-up: {line}");
        assert!(line.contains(" snap=1"), "the catch-up prefix is visible: {line}");

        drop(a);
        drop(b);
        let _ = std::fs::remove_dir_all(&abase);
        let _ = std::fs::remove_dir_all(&bbase);
    }

    /// **Issue #359 follow-up S2 — `Node::open` replay remains out of scope.**
    ///
    /// Reopening a snapshotless data dir replays its block log before the run loop
    /// exists. The cadence therefore cannot fire there, and this follow-up does not
    /// claim to persist progress during that startup replay.
    #[test]
    fn node_open_replay_still_writes_no_snapshot_before_the_loop_exists() {
        let (config, genesis, base) = rig("i359_open_replay", true);
        let snap_path = config.data_dir.join(qlab_node::SNAPSHOT);
        {
            let mut node =
                RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
            node.set_mine_interval(Duration::ZERO);
            for _ in 0..3 {
                assert!(node.try_mine());
            }
            assert_eq!(node.tip_height(), 3);
            assert!(!snap_path.exists(), "direct block application is not the cadence");
        }

        let reopened =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        assert_eq!(reopened.tip_height(), 3, "Node::open replayed the block log");
        assert_eq!(reopened.durable_snapshot(), qlab_node::SnapshotOnDisk::Absent);
        assert!(
            !snap_path.exists(),
            "Node::open replay happens before maintain_snapshot can run"
        );

        drop(reopened);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// **Issue #359 S5 (c) — the telemetry field round-trips**, in all three of its
    /// tokens, and the height it reports is the one a restart would resume from.
    ///
    /// The `none` case is asserted first because it is the one that matters: it is
    /// node3's shape, and a field that only ever printed heights would have said
    /// nothing at all about the host this issue is about.
    #[test]
    fn the_snap_field_round_trips_through_the_telemetry_line() {
        let (config, genesis, base) = rig("i359_field", true);
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        node.set_mine_interval(Duration::ZERO);
        node.set_snapshot_interval(Duration::ZERO);

        // (1) none — nothing has ever been written to this data dir.
        assert_eq!(field(&node.telemetry_sample(), "snap"), "none");

        // (2) a height — and it is the applied height, readable back as a number.
        assert!(node.try_mine());
        assert!(node.try_mine());
        node.maintain_snapshot();
        let line = node.telemetry_sample();
        let reported: u64 = field(&line, "snap").parse().expect("a height parses back");
        assert_eq!(reported, 2, "the applied height the snapshot carries: {line}");
        assert_eq!(
            reported,
            qlab_node::snapshot_on_disk(&config.data_dir).unwrap().height().unwrap(),
            "and the line agrees with the file itself"
        );
        // The #84 discipline: an addition may not disturb the fields before it.
        assert!(line.contains(" stip=2 slag=0"), "{line}");
        drop(node);

        // (3) bad — a snapshot present but not decodable at this FORMAT_VERSION.
        // Seeded before startup, because the field is seeded by the startup read.
        std::fs::write(config.data_dir.join(qlab_node::SNAPSHOT), b"not a snapshot").unwrap();
        let node = RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier)
            .expect("an unusable snapshot is a full replay, not a refusal");
        let line = node.telemetry_sample();
        assert_eq!(field(&line, "snap"), "bad", "{line}");
        assert!(line.contains(" stip=2 "), "and the log still replayed the real chain: {line}");

        drop(node);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// **Issue #359 S5 (d) — `halt-status` renders both cases, and the `none` case
    /// is legible.** This is the read an operator makes with the node *down*, which
    /// is the only moment the answer can still change a roll plan.
    ///
    /// The `none` assertions are on the consequence, not on the word: a section
    /// that printed `snapshot: none` and stopped would satisfy a contains-"none"
    /// test while telling the operator nothing about what it costs.
    #[test]
    fn halt_status_renders_the_snapshot_height_and_the_none_case() {
        let (config, genesis, base) = rig("i359_haltstatus", true);

        // (1) none — the data dir exists and has never been snapshotted.
        let report = snapshot_status_report(&config.data_dir);
        assert!(report.contains("NONE"), "{report}");
        assert!(
            report.contains("REPLAYS THE WHOLE BLOCK LOG FROM GENESIS"),
            "the none case states the cost, not just the absence: {report}"
        );
        assert!(!report.contains("height 0"), "an absent snapshot is not height 0: {report}");

        // (2) a height — after a real node writes one.
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        node.set_mine_interval(Duration::ZERO);
        node.set_snapshot_interval(Duration::ZERO);
        assert!(node.try_mine());
        node.maintain_snapshot();
        drop(node);
        let report = snapshot_status_report(&config.data_dir);
        assert!(report.contains("height 1"), "{report}");
        assert!(!report.contains("NONE"), "{report}");

        // (3) unusable — present, undecodable. A different cause, the same cost,
        // and it must not be reported as an absence.
        std::fs::write(config.data_dir.join(qlab_node::SNAPSHOT), b"not a snapshot").unwrap();
        let report = snapshot_status_report(&config.data_dir);
        assert!(report.contains("UNUSABLE"), "{report}");
        assert!(!report.contains("NONE"), "a present-but-broken file is not an absent one: {report}");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn preflight_validates_a_staged_node_without_binding() {
        // The deploy dry-run's per-node assertion: a laid-down config + genesis +
        // key subset validate through the real startup checks, no socket bound.
        let (config, genesis, base) = rig("preflight", true);
        let pf = preflight(&config, &genesis).expect("preflight ok");
        assert_eq!(pf.genesis_hash, genesis.hash_hex());
        assert_eq!(pf.committee_size, 21);
        assert_eq!(pf.quorum, 15);
        assert_eq!(pf.keys_held, 21, "the rig holds all 21 keys");
        assert!(pf.mining);

        // A wrong hash pin fails preflight exactly as startup would (item 2).
        let mut bad = config.clone();
        bad.expected_genesis_hash = Some("00".repeat(32));
        assert!(matches!(
            preflight(&bad, &genesis),
            Err(RunError::Genesis(GenesisError::WrongGenesisHash { .. }))
        ));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn preflight_reports_a_key_subset() {
        // A node holding only a subset of the 21 keys (the ~5-6/node T0 split)
        // preflights fine and reports its subset size.
        let (mut config, genesis, base) = rig("preflight_subset", false);
        config.committee_key_paths.truncate(6); // node0's 6-key slice
        let pf = preflight(&config, &genesis).expect("subset preflight ok");
        assert_eq!(pf.keys_held, 6);
        assert!(!pf.mining);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn refuses_to_start_on_a_wrong_genesis_hash() {
        // item 2 negative through the run path: a mismatched expected hash aborts
        // startup before any listener binds.
        let (mut config, genesis, base) = rig("wronghash", false);
        config.expected_genesis_hash = Some("00".repeat(32));
        let err = RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier);
        assert!(matches!(err, Err(RunError::Genesis(GenesisError::WrongGenesisHash { .. }))));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn randomx_engine_composes_and_mines_over_tcp() {
        // The exact engine the binary uses (RandomXPow, N3) slots into the same
        // RunningNode composition over the real TCP transport + disk stores, and
        // mines a real-PoW block at the genesis difficulty (mirrors the N7 smoke).
        use qlab_devnet::pow::RandomXPow;
        let (config, genesis, base) = rig("randomx", true);
        let mut node =
            RunningNode::start(&config, &genesis, RandomXPow::new(), DevnetRehearsalVerifier)
                .unwrap();
        node.set_mine_interval(Duration::ZERO);
        assert!(node.try_mine(), "RandomX mines at the genesis difficulty");
        assert_eq!(node.tip_height(), 1, "RandomX-mined block accepted");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// ACCEPTANCE (S9) — a configured peer unreachable at boot is reconnected by
    /// periodic re-dial once it comes up, WITHOUT a process restart; and a peer already
    /// connected is never dialed twice. (Partition-heal, the deferred B-lite §4 gate.)
    #[test]
    fn redial_reconnects_a_configured_peer_without_restart() {
        // Reserve a free port, then release it so nothing is listening yet.
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let p = l.local_addr().unwrap().port();
            drop(l);
            p
        };
        let b_addr = format!("127.0.0.1:{port}");

        // Node A boots configured to dial B, but B is DOWN → no connection yet.
        let (mut acfg, agen, abase) = rig("redial_a", false);
        acfg.dial_peers = vec![b_addr.clone()];
        let mut a = RunningNode::start(&acfg, &agen, KeccakPow, DevnetRehearsalVerifier).unwrap();
        assert_eq!(a.p2p().transport().peers().len(), 0, "B is down at boot → no peer");
        pump(&mut [&mut a], 5);
        assert!(
            a.p2p().addrs().entry(&b_addr).unwrap().failures >= 1,
            "the refused startup dial completed before the heal"
        );

        // B comes up on the same address.
        let (mut bcfg, bgen, bbase) = rig("redial_b", false);
        bcfg.listen_addr = b_addr.clone();
        let mut b =
            RunningNode::start(&bcfg, &bgen, KeccakPow, DevnetRehearsalVerifier).unwrap();

        // Re-dial reconnects A to B with no restart.
        a.force_redial_ready();
        a.maintain_peers();
        pump(&mut [&mut a, &mut b], 5);
        assert_eq!(a.p2p().transport().peers().len(), 1, "re-dial reconnected the healed peer");

        // A second re-dial does NOT open a duplicate connection to the live peer.
        a.force_redial_ready();
        a.maintain_peers();
        assert_eq!(a.p2p().transport().peers().len(), 1, "no duplicate dial to a connected peer");

        drop(b);
        let _ = std::fs::remove_dir_all(&abase);
        let _ = std::fs::remove_dir_all(&bbase);
    }

    /// Issue #172 — `peer_count` is the live connection-table size, so a peer
    /// process restart must remove both of the old directed connections from the
    /// survivor before the replacement connections are counted. In a fully
    /// configured N-host mesh every host has one outbound and one inbound
    /// connection to each other host: `2 * (N - 1)` live connections.
    #[test]
    fn peer_process_restart_leaves_both_sides_at_the_live_connection_count() {
        let (a_port, b_port) = (free_port(), free_port());
        let (a_addr, b_addr) =
            (format!("127.0.0.1:{a_port}"), format!("127.0.0.1:{b_port}"));

        let (mut acfg, agen, abase) = rig("peer_restart_a", false);
        acfg.listen_addr = a_addr.clone();
        acfg.dial_peers = vec![b_addr.clone()];
        let mut a =
            RunningNode::start(&acfg, &agen, KeccakPow, DevnetRehearsalVerifier).unwrap();

        let (mut bcfg, bgen, bbase) = rig("peer_restart_b", false);
        bcfg.listen_addr = b_addr.clone();
        bcfg.dial_peers = vec![a_addr];
        let mut b =
            RunningNode::start(&bcfg, &bgen, KeccakPow, DevnetRehearsalVerifier).unwrap();

        // B connected out while A was already listening; make A's initially
        // refused dial retry now that B is up. The two-host instance of
        // `2 * (N - 1)` is two connections on each side.
        pump(&mut [&mut a, &mut b], 5);
        a.force_redial_ready();
        a.maintain_peers();
        pump(&mut [&mut a, &mut b], 5);
        assert_eq!(a.telemetry().peer_count, 2, "A sees both live directions");
        assert_eq!(b.telemetry().peer_count, 2, "B sees both live directions");

        // A is the survivor. Once B's process is gone, both sockets disappear
        // from the transport; maintenance must make the connection table agree.
        drop(b);
        let stopped = std::time::Instant::now();
        while !a.p2p().transport().peers().is_empty() {
            a.step_once();
            assert!(
                stopped.elapsed() < Duration::from_secs(1),
                "survivor did not observe the stopped peer"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        a.maintain_peers();
        assert_eq!(
            a.telemetry().peer_count,
            0,
            "the survivor must not retain either pre-restart connection"
        );

        // Restart B on the same address and restore both directed connections.
        let mut b =
            RunningNode::start(&bcfg, &bgen, KeccakPow, DevnetRehearsalVerifier).unwrap();
        pump(&mut [&mut a, &mut b], 5);
        a.force_redial_ready();
        a.maintain_peers();
        pump(&mut [&mut a, &mut b], 5);

        assert_eq!(
            a.telemetry().peer_count,
            2,
            "the survivor counts only B's replacement connections"
        );
        assert_eq!(b.telemetry().peer_count, 2, "the restarted side also converges");

        drop(a);
        drop(b);
        for base in [abase, bbase] {
            let _ = std::fs::remove_dir_all(&base);
        }
    }

    // ================= peer discovery over real TCP (issue #83) =================

    /// Reserve a free loopback port and release it (the address is then free to
    /// bind by a node we start next).
    fn free_port() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    }

    #[test]
    fn local_self_identities_cover_bound_listen_and_loopback_aliases() {
        // Unspecified bind → loopback forms are also self (a self-dial via 127.0.0.1).
        let ids = local_self_identities("0.0.0.0:9401", "0.0.0.0:9401");
        assert!(ids.contains(&"0.0.0.0:9401".to_string()));
        assert!(ids.contains(&"127.0.0.1:9401".to_string()));
        assert!(ids.contains(&"localhost:9401".to_string()));
        // Concrete bind is itself, not every loopback alias.
        let ids2 = local_self_identities("10.0.0.5:9333", "10.0.0.5:9333");
        assert!(ids2.contains(&"10.0.0.5:9333".to_string()));
        assert!(!ids2.contains(&"127.0.0.1:9333".to_string()));
    }

    /// Issue #127 over the real socket: a node with **no** `advertise_addr` still
    /// refuses to admit the address it is listening on when a peer gossips it back.
    #[test]
    fn node_without_advertise_addr_refuses_its_own_bound_address() {
        let port = free_port();
        let addr = format!("127.0.0.1:{port}");

        let (mut cfg, gen, base) = rig("self_filter", false);
        cfg.listen_addr = addr.clone();
        cfg.advertise_addr = None; // the field is absent — the guard must still fire
        let mut node =
            RunningNode::start(&cfg, &gen, KeccakPow, DevnetRehearsalVerifier).unwrap();

        assert!(node.p2p().addrs().self_advertise().is_none());
        assert!(
            node.p2p().addrs().is_self(&addr),
            "bound address must be a filter identity even without advertise_addr"
        );

        // Simulate a peer gossiping our address back (the ordinary seed→dialable→
        // gossip path that put us in our own book before #127).
        let admitted = node
            .p2p
            .addrs_mut()
            .learn(vec![addr.clone(), "203.0.113.9:9333".into()]);
        assert_eq!(admitted, 1, "self refused; the stranger admitted");
        assert!(
            !node.p2p.addrs().known().contains(&addr),
            "self must not appear in known: {:?}",
            node.p2p.addrs().known()
        );
        assert_eq!(node.p2p.addrs().known_count(), 1);
        assert!(!node.p2p.addrs().next_dials(0).contains(&addr));

        drop(node);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Pump every node's message loop a few times so handshakes/replies land.
    fn pump(nodes: &mut [&mut RunningNode<KeccakPow, DevnetRehearsalVerifier>], rounds: usize) {
        for _ in 0..rounds {
            for n in nodes.iter_mut() {
                n.step_once();
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    /// ACCEPTANCE item 1 over the real socket — a node that knows ONE address ends
    /// up connected to the whole net; and ACCEPTANCE item 2's serving direction:
    /// the joiner has no `advertise_addr` (it is behind a router), so it is never
    /// gossiped and never enters anyone's book.
    #[test]
    fn seed_only_node_learns_the_net_and_an_undialable_one_is_never_gossiped() {
        let (b_port, c_port) = (free_port(), free_port());
        let (b_addr, c_addr) = (format!("127.0.0.1:{b_port}"), format!("127.0.0.1:{c_port}"));

        // C listens and advertises; B listens, advertises, and seeds C.
        let (mut ccfg, cgen, cbase) = rig("disc_c", false);
        ccfg.listen_addr = c_addr.clone();
        ccfg.advertise_addr = Some(c_addr.clone());
        let mut c = RunningNode::start(&ccfg, &cgen, KeccakPow, DevnetRehearsalVerifier).unwrap();

        let (mut bcfg, bgen, bbase) = rig("disc_b", false);
        bcfg.listen_addr = b_addr.clone();
        bcfg.advertise_addr = Some(b_addr.clone());
        bcfg.dial_peers = vec![c_addr.clone()];
        let mut b = RunningNode::start(&bcfg, &bgen, KeccakPow, DevnetRehearsalVerifier).unwrap();

        // A knows only B, and declares no address of its own (outbound-only).
        let (mut acfg, agen, abase) = rig("disc_a", false);
        acfg.dial_peers = vec![b_addr.clone()];
        acfg.advertise_addr = None;
        let mut a = RunningNode::start(&acfg, &agen, KeccakPow, DevnetRehearsalVerifier).unwrap();
        assert_eq!(a.p2p().addrs().known(), vec![b_addr.clone()], "one seed, nothing else");

        pump(&mut [&mut a, &mut b, &mut c], 5);
        a.maintain_peers(); // ask B for addresses
        pump(&mut [&mut a, &mut b, &mut c], 5);
        a.maintain_peers(); // dial what we learned
        pump(&mut [&mut a, &mut b, &mut c], 5);

        assert!(
            a.p2p().addrs().known().contains(&c_addr),
            "A learned C from B: {:?}",
            a.p2p().addrs().known()
        );
        assert_eq!(a.p2p().addrs().dialable_count(), 2, "and connected to both");
        assert_eq!(a.p2p().transport().peers().len(), 2, "two live sockets");

        // The joiner is never gossiped: B's book holds C and nothing of A's, even
        // though A is connected to B right now.
        assert_eq!(b.p2p().addrs().known(), vec![c_addr.clone()], "A is in nobody's book");
        assert!(b.p2p().transport().peers().len() >= 1, "…while A is genuinely connected to B");

        // The re-open trigger is a measurement, and it is in the telemetry line.
        let sample = a.telemetry_sample();
        assert!(sample.contains("dialable=2/2"), "telemetry carries the ratio: {sample}");

        drop(a);
        drop(b);
        drop(c);
        for base in [abase, bbase, cbase] {
            let _ = std::fs::remove_dir_all(&base);
        }
    }

    /// ACCEPTANCE item 4 — learned addresses survive a restart. The restarted node
    /// is configured with NO seeds at all, so everything it knows came off disk.
    #[test]
    fn the_address_book_survives_a_restart() {
        let b_port = free_port();
        let b_addr = format!("127.0.0.1:{b_port}");
        let (mut bcfg, bgen, bbase) = rig("book_b", false);
        bcfg.listen_addr = b_addr.clone();
        bcfg.advertise_addr = Some(b_addr.clone());
        let mut b =
            RunningNode::start(&bcfg, &bgen, KeccakPow, DevnetRehearsalVerifier).unwrap();

        let (mut acfg, agen, abase) = rig("book_a", false);
        acfg.dial_peers = vec![b_addr.clone()];
        let mut a = RunningNode::start(&acfg, &agen, KeccakPow, DevnetRehearsalVerifier).unwrap();
        pump(&mut [&mut a, &mut b], 5);
        assert_eq!(a.p2p().addrs().dialable_count(), 1);
        a.save_addr_book();
        drop(a);

        // Restart with an EMPTY seed list: whatever it knows was restored from disk.
        let mut acfg2 = acfg.clone();
        acfg2.dial_peers = vec![];
        let mut a2 =
            RunningNode::start(&acfg2, &agen, KeccakPow, DevnetRehearsalVerifier).unwrap();
        pump(&mut [&mut a2, &mut b], 5);
        assert_eq!(a2.p2p().addrs().known(), vec![b_addr.clone()], "restored from peers.dat");
        assert_eq!(a2.p2p().addrs().dialable_count(), 1);
        assert_eq!(
            a2.p2p().transport().peers().len(),
            1,
            "and it reconnects from the restored book alone"
        );

        drop(a2);
        drop(b);
        let _ = std::fs::remove_dir_all(&abase);
        let _ = std::fs::remove_dir_all(&bbase);
    }

    /// A corrupt or unknown-version `peers.dat` must not stop a node from starting —
    /// the book is a cache, the seeds are the authority (S4).
    #[test]
    fn a_corrupt_address_book_is_ignored_at_startup() {
        let (config, genesis, base) = rig("book_bad", false);
        std::fs::create_dir_all(&config.data_dir).unwrap();
        std::fs::write(config.data_dir.join(ADDRBOOK_FILE), [0xFF, 0x00, 0x00]).unwrap();
        let node = RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier)
            .expect("an unreadable book is not fatal");
        assert_eq!(node.p2p().addrs().known_count(), 0);
        let _ = std::fs::remove_dir_all(&base);
    }

    // ===== issue #106: a node with an empty data dir must not mine its own chain =====

    /// **ACCEPTANCE — the defect, both halves, over the real socket.**
    ///
    /// This is node0's roll on the T0 WAN net (2026-07-29): a host restarted onto an
    /// empty data dir, with its three peers configured and a network 2,000 blocks
    /// tall, mined its own chain from genesis instead of syncing one. Everything the
    /// old code had to go on is present here — the seed list, the taller peer, an
    /// empty data dir, `mining = true` — and the node now refuses to extend a chain
    /// it has not found yet.
    ///
    /// The four phases are the four states that mattered:
    ///
    /// 1. **before any contact** — `mready=unknown`, and mining now is the fork;
    /// 2. **catching up** — refused at every step, tip never leaves 0 by our own hand;
    /// 3. **synced** — the gate opens, and the block that follows builds on the
    ///    network's chain rather than on genesis;
    /// 4. **eclipsed afterwards** — the peer goes away and mining CONTINUES, because
    ///    the gate is a startup condition and a partition is not proof of anything
    ///    (the same reasoning #86 gave for sticky dialability).
    #[test]
    fn a_cold_node_with_a_taller_peer_does_not_mine_until_it_has_synced() {
        use qlab_p2p::n1::{BlockIngest, IngestOutcome};

        let a_port = free_port();
        let a_addr = format!("127.0.0.1:{a_port}");

        // A is the established net: three blocks, and dialable.
        let (mut acfg, agen, abase) = rig("i106_net", true);
        acfg.listen_addr = a_addr.clone();
        acfg.advertise_addr = Some(a_addr.clone());
        let mut a = RunningNode::start(&acfg, &agen, KeccakPow, DevnetRehearsalVerifier).unwrap();
        a.set_mine_interval(Duration::ZERO);
        for _ in 0..3 {
            assert!(a.try_mine(), "A is genuinely alone and mines the net into being");
        }
        assert_eq!(a.tip_height(), 3);

        // B is the rolled host: empty data dir, mining on, A configured as a seed.
        let (mut bcfg, bgen, bbase) = rig("i106_cold", true);
        bcfg.dial_peers = vec![a_addr.clone()];
        let mut b = RunningNode::start(&bcfg, &bgen, KeccakPow, DevnetRehearsalVerifier).unwrap();
        b.set_mine_interval(Duration::ZERO);

        // ── (1) Nothing known yet. The seed has not answered; `Unknown` is not `Synced`.
        assert_eq!(b.mine_gate(), MineGate::Unknown, "a node that has heard from nobody");
        assert!(!b.try_mine(), "🔴 this call mining a block IS the #106 fork");
        assert_eq!(b.tip_height(), 0, "and no fork block exists");
        assert!(b.telemetry_sample().contains(" mready=unknown "), "{}", b.telemetry_sample());

        // ── (2) Catching up. Refused on every pass until the header chain lands.
        let mut refusals = 0;
        for _ in 0..60 {
            if b.p2p().sync_phase().is_synced() && b.tip_height() == 3 {
                break;
            }
            a.step_once();
            b.step_once();
            assert!(!b.try_mine(), "refused while catching up: gate={:?}", b.mine_gate());
            refusals += 1;
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(refusals > 0, "the catch-up window was exercised");
        assert_eq!(b.tip_height(), 3, "B took the network's chain, not one of its own");
        assert_eq!(b.mine_gate(), MineGate::Synced, "compared against a real claim");

        // The other gate is still shut, and for its own reason: header-first sync
        // gives B the headers, and `GetData(Block)` serves headers only, so B's state
        // machine has applied no body (#130 (a) / #104 — not this issue's business).
        // Two independent gates, two different answers, both correct.
        assert!(!b.try_mine(), "still refused, now for the state lag");
        let line = b.telemetry_sample();
        assert!(line.contains(" stip=0 slag=3"), "{line}");
        assert!(line.contains(" mready=synced "), "the readiness gate is open: {line}");

        // ── (3) The bodies arrive the way a live announce would deliver them.
        let chain = a.p2p().node().chain();
        let mined: Vec<_> =
            (1..=3).map(|h| *chain.header(&chain.main_chain()[h]).expect("header")).collect();
        for header in &mined {
            let hash = header.header_hash();
            let stored = a.state().chain().block(&hash).expect("A holds the body").clone();
            assert_eq!(
                b.p2p_mut().node_mut().ingest_block(*header, stored.body()),
                IngestOutcome::Duplicate,
                "the header was already held"
            );
        }
        assert!(b.try_mine(), "and now it mines: gate={:?}", b.mine_gate());
        assert_eq!(b.tip_height(), 4, "on top of the network's chain, not beside it");

        // ── (4) Eclipse after clearance does not stop an established miner.
        drop(a);
        for _ in 0..5 {
            b.step_once();
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            matches!(b.mine_gate(), MineGate::Latched | MineGate::Synced),
            "gate={:?}",
            b.mine_gate()
        );
        assert!(b.try_mine(), "a node that lost its peers keeps extending its own history");

        drop(b);
        let _ = std::fs::remove_dir_all(&abase);
        let _ = std::fs::remove_dir_all(&bbase);
    }

    /// **ACCEPTANCE — the test that breaks if the fix is too blunt.** Naming it, as
    /// the task book asks: *this* is the one a crude "require a peer before mining"
    /// or "require a header before mining" rule fails, and a net that cannot start
    /// is a worse outcome than the fork this issue is about. The first node on a
    /// brand-new chain has no peers and no history and legitimately must mine.
    ///
    /// It passes for a stated reason and not by luck: with no seed configured and no
    /// live peer there is **nobody to ask**, and a node with nobody to ask is the
    /// net. `deploy/deploy.sh` writes a full mesh into every node's `dial_peers`, so
    /// on the real T0 net no host can reach this branch — see
    /// `a_fresh_net_of_configured_peers_still_starts_from_genesis` for how that one
    /// starts instead.
    #[test]
    fn the_genuinely_first_node_on_a_new_net_does_mine() {
        let (config, genesis, base) = rig("i106_first", true);
        assert!(config.dial_peers.is_empty(), "nobody to ask");
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        node.set_mine_interval(Duration::ZERO);

        assert_eq!(node.p2p().addrs().known_count(), 0);
        assert_eq!(node.mine_gate(), MineGate::Alone);
        assert!(!node.p2p().sync_phase().is_synced(), "…and it does NOT pretend it synced");
        assert!(node.try_mine(), "the net starts");
        assert_eq!(node.tip_height(), 1);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// **ACCEPTANCE — the discriminator AT ITS BOUNDARY.**
    ///
    /// The rule chosen in position 1 is *"is there anybody to ask?"*, and its
    /// boundary is **one address**: zero known addresses permits mining, one known
    /// address forbids it until that address answers. The two nodes here differ in
    /// nothing else — same genesis, same empty data dir, same `mining = true`, same
    /// unreachable network — so the assertion isolates the discriminator itself.
    ///
    /// The failure mode this shape accepts, stated: a node whose seeds are all down
    /// never mines. That is the safe direction (it cannot know whether a chain is
    /// out there), and it is the reason `mready=` exists on the telemetry line —
    /// otherwise a deliberately-idle node is indistinguishable from a broken one.
    #[test]
    fn the_gate_turns_on_one_configured_address_not_on_whether_it_answers() {
        // Reserve a port and release it: an address that is syntactically fine,
        // known to the book, and answers nothing.
        let dead = format!("127.0.0.1:{}", free_port());

        let (zero_cfg, genesis, zbase) = rig("i106_zero", true);
        let mut zero =
            RunningNode::start(&zero_cfg, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        zero.set_mine_interval(Duration::ZERO);

        let (mut one_cfg, _g, obase) = rig("i106_one", true);
        one_cfg.dial_peers = vec![dead];
        let mut one =
            RunningNode::start(&one_cfg, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        one.set_mine_interval(Duration::ZERO);

        // Both have exhausted what they can do about it: neither has a peer.
        for _ in 0..5 {
            zero.step_once();
            one.step_once();
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(zero.p2p().addrs().known_count(), 0);
        assert_eq!(one.p2p().addrs().known_count(), 1);
        assert!(one.p2p().peers().is_empty(), "the seed never answered");

        assert_eq!(zero.mine_gate(), MineGate::Alone);
        assert_eq!(one.mine_gate(), MineGate::Unknown);
        assert!(zero.try_mine(), "no network to be behind");
        assert!(!one.try_mine(), "one address it has not reached is enough to wait");
        assert_eq!(one.tip_height(), 0);
        assert!(one.telemetry_sample().contains(" mready=unknown "), "{}", one.telemetry_sample());

        let _ = std::fs::remove_dir_all(&zbase);
        let _ = std::fs::remove_dir_all(&obase);
    }

    /// **ACCEPTANCE — `deploy/deploy.sh`'s net still starts.** Every node it writes
    /// gets a full mesh in `dial_peers`, so none of them takes the "nobody to ask"
    /// branch; they start because they ask each other, agree that nobody is taller
    /// than genesis, and mine on that evidence. Without the `None`/`Some(0)` split
    /// in `maybe_start_sync` this test would pass for the wrong reason — every node
    /// would have called itself `Synced` before the handshake landed.
    #[test]
    fn a_fresh_net_of_configured_peers_still_starts_from_genesis() {
        let (p_port, q_port) = (free_port(), free_port());
        let (p_addr, q_addr) = (format!("127.0.0.1:{p_port}"), format!("127.0.0.1:{q_port}"));

        let mut nodes = Vec::new();
        for (tag, listen, peer) in
            [("i106_mesh_p", &p_addr, &q_addr), ("i106_mesh_q", &q_addr, &p_addr)]
        {
            let (mut cfg, genesis, base) = rig(tag, true);
            cfg.listen_addr = listen.clone();
            cfg.advertise_addr = Some(listen.clone());
            cfg.dial_peers = vec![peer.clone()];
            let mut n =
                RunningNode::start(&cfg, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
            n.set_mine_interval(Duration::ZERO);
            nodes.push((n, base));
        }

        // Cold, mesh-configured, nobody has answered yet: neither may mine.
        for (n, _) in nodes.iter() {
            assert_eq!(n.mine_gate(), MineGate::Unknown, "a mesh node waits for the mesh");
        }

        for _ in 0..40 {
            if nodes.iter().all(|(n, _)| n.mine_gate() == MineGate::Synced) {
                break;
            }
            for (n, _) in nodes.iter_mut() {
                n.step_once();
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        for (n, _) in nodes.iter_mut() {
            assert_eq!(n.mine_gate(), MineGate::Synced, "genesis is nobody's fork");
            assert_eq!(
                n.p2p().peers().best_height(),
                Some(0),
                "and it opened on a claim that was actually received, not on a default"
            );
            assert!(n.try_mine(), "the net starts");
        }

        for (n, base) in nodes {
            drop(n);
            let _ = std::fs::remove_dir_all(&base);
        }
    }

    #[test]
    fn verify_only_node_starts_without_keys() {
        let (mut config, genesis, base) = rig("verifyonly", false);
        config.committee_key_paths = vec![]; // no signing keys
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        // No keys → checkpoint proposal is a no-op; nothing finalizes locally.
        node.try_checkpoint();
        assert_eq!(node.finalized_height(), None);
        let _ = std::fs::remove_dir_all(&base);
    }

    // ---- issue #74: the halt-height upgrade, through the real run path ---------

    use crate::release::{Release, ReleaseError, DRILL_HALT_HEIGHT as DH, REVISION_V1_0,
                         REVISION_V1_0_1_DRILL};
    use qlab_devnet::halt::HaltPlan;

    fn armed_release() -> Release {
        Release {
            name: "test [armed]",
            plan: HaltPlan::Armed { height: DH },
            revision: Some(REVISION_V1_0),
            resumes_from: None,
        }
    }
    fn resume_release() -> Release {
        Release {
            name: "test [resume]",
            plan: HaltPlan::None,
            revision: Some(REVISION_V1_0_1_DRILL),
            resumes_from: Some(DH),
        }
    }

    /// Mine `n` blocks and checkpoint after each, on a node holding all 21 keys.
    fn mine_and_checkpoint(
        node: &mut RunningNode<KeccakPow, DevnetRehearsalVerifier>,
        n: u64,
    ) -> u64 {
        let mut mined = 0;
        for _ in 0..n {
            if !node.try_mine() {
                break;
            }
            mined += 1;
            node.try_checkpoint();
        }
        mined
    }

    /// H2 through the binary's own run loop: an armed release applies block H, then
    /// stops; the regime walks Halting → Halted; and the durable halt marker lands
    /// on disk with the revision that produced it.
    #[test]
    fn armed_release_halts_at_h_and_writes_a_durable_marker() {
        let (config, genesis, base) = rig("halt_armed", true);
        let mut node = RunningNode::start_with_release(
            &config, &genesis, KeccakPow, DevnetRehearsalVerifier, armed_release(),
        )
        .unwrap();
        node.set_mine_interval(Duration::ZERO);
        assert_eq!(node.halt_at(), Some(DH));

        node.try_checkpoint(); // finalize genesis
        // Mine toward H, but do NOT checkpoint yet — so H is reached unfinalized.
        for _ in 0..DH {
            assert!(node.try_mine(), "mines below the halt height");
        }
        assert_eq!(node.tip_height(), DH, "block H is applied");
        assert!(!node.try_mine(), "…and nothing above it is mined");
        assert!(node.is_halted());

        // Halting: at the boundary, boundary not yet final.
        let line = node.telemetry_sample();
        assert!(line.contains("regime=Halting"), "at H, unfinalized ⇒ Halting: {line}");
        assert!(line.contains(&format!("halt={DH}")), "the schedule is on the wire: {line}");
        // The layer-attribution counters ride the same line (#74 drill evidence).
        assert!(line.contains("hignore="), "release-layer refusals on the wire: {line}");
        assert!(line.contains("powrej="), "header-layer refusals on the wire: {line}");
        node.maintain_halt_marker();
        let m = HaltMarker::load(&config.data_dir).unwrap().expect("marker written on reaching H");
        assert_eq!(m.height, DH);
        assert_eq!(m.revision_id, "v1.0");
        assert!(!m.boundary_finalized, "not final yet");

        // Finalize the boundary ⇒ Halted, and the marker is upgraded once.
        node.try_checkpoint();
        assert_eq!(node.finalized_height(), Some(DH), "the boundary is a FINALIZED boundary");
        let line = node.telemetry_sample();
        assert!(line.contains("regime=Halted"), "H finalized ⇒ Halted: {line}");
        node.maintain_halt_marker();
        let m = HaltMarker::load(&config.data_dir).unwrap().unwrap();
        assert!(m.boundary_finalized, "marker records that the boundary finalized");

        // The committee proposed no slot above H.
        assert!(node.next_checkpoint <= DH + CHECKPOINT_CADENCE_BLOCKS);
        node.save_snapshot().unwrap();
        let _ = std::fs::remove_dir_all(&base);
    }

    /// #359 REHEARSAL, then the standing regression lock for the transplant
    /// path: a snapshotless host is rescued by transplanting a DONOR's
    /// `snapshot.bin` + `blocks.log` while it keeps its OWN finalizer ledgers
    /// and its OWN halt marker. `persist::Snapshot` is pure chain state (no
    /// node identity), so this must work — this test is the proof the
    /// production runbook cites before touching node3.
    ///
    /// Lab #375 adds a second named trigger: a **boundary-tie loser** that stays
    /// halted with `FINALIZE refused ... why=not-held` after its finalized
    /// checkpoint names the sibling of its applied tip. The normal near-tip body
    /// exchange is primary; this transplant remains the fallback for a pre-#375
    /// binary or when no reachable peer can serve the finalized sibling.
    #[test]
    fn a_snapshotless_host_rejoins_by_snapshot_transplant() {
        // --- donor A: halted at DH, finalized, resumed past it, snapshotted.
        let (cfg_a, gen_a, base_a) = rig("i359_donor", true);
        let (a_tip, a_final) = {
            let mut a = RunningNode::start_with_release(
                &cfg_a, &gen_a, KeccakPow, DevnetRehearsalVerifier, armed_release(),
            )
            .unwrap();
            a.set_mine_interval(Duration::ZERO);
            a.try_checkpoint();
            mine_and_checkpoint(&mut a, DH);
            assert!(a.is_halted());
            a.maintain_boundary_checkpoint();
            assert_eq!(a.finalized_height(), Some(DH));
            a.maintain_halt_marker();
            a.save_snapshot().unwrap();
            drop(a);
            let mut a = RunningNode::start_with_release(
                &cfg_a, &gen_a, KeccakPow, DevnetRehearsalVerifier, resume_release(),
            )
            .unwrap();
            a.set_mine_interval(Duration::ZERO);
            assert_eq!(mine_and_checkpoint(&mut a, 2 * CHECKPOINT_CADENCE_BLOCKS), 2 * CHECKPOINT_CADENCE_BLOCKS);
            a.maintain_halt_marker();
            a.save_snapshot().unwrap();
            (a.tip_height(), a.finalized_height())
        };
        assert!(a_tip > DH, "donor mined past the boundary");

        // --- recipient B: its own walk to the halt — its own marker, its own
        // finalizer ledgers, NO snapshot (node3's exact shape).
        let (cfg_b, gen_b, base_b) = rig("i359_recipient", true);
        {
            let mut b = RunningNode::start_with_release(
                &cfg_b, &gen_b, KeccakPow, DevnetRehearsalVerifier, armed_release(),
            )
            .unwrap();
            b.set_mine_interval(Duration::ZERO);
            b.try_checkpoint();
            mine_and_checkpoint(&mut b, DH);
            assert!(b.is_halted());
            b.maintain_boundary_checkpoint();
            b.maintain_halt_marker();
            // Deliberately NO save_snapshot: B is the snapshotless host.
        }
        assert!(!cfg_b.data_dir.join(qlab_node::SNAPSHOT).exists());

        // --- the transplant: donor's two chain files; B keeps everything else.
        std::fs::copy(
            cfg_a.data_dir.join(qlab_node::SNAPSHOT),
            cfg_b.data_dir.join(qlab_node::SNAPSHOT),
        )
        .unwrap();
        std::fs::copy(
            cfg_a.data_dir.join(qlab_node::BLOCK_LOG),
            cfg_b.data_dir.join(qlab_node::BLOCK_LOG),
        )
        .unwrap();

        // --- B opens on the resume release: marker rewritten, state == donor,
        // and its own keys still sign.
        let mut b = RunningNode::start_with_release(
            &cfg_b, &gen_b, KeccakPow, DevnetRehearsalVerifier, resume_release(),
        )
        .unwrap();
        b.set_mine_interval(Duration::ZERO);
        assert_eq!(b.tip_height(), a_tip, "transplanted chain adopted");
        assert_eq!(b.finalized_height(), a_final, "transplanted finality adopted");
        let m = HaltMarker::load(&cfg_b.data_dir).unwrap().expect("marker present");
        assert!(m.resumed, "B's own marker rewritten by the legitimate resume");
        // The committee still works from B's OWN ledgers: one more block, one
        // more checkpoint, finality advances.
        assert_eq!(mine_and_checkpoint(&mut b, CHECKPOINT_CADENCE_BLOCKS), CHECKPOINT_CADENCE_BLOCKS);
        assert!(b.finalized_height() > a_final, "post-transplant signing works");
        let _ = std::fs::remove_dir_all(&base_a);
        let _ = std::fs::remove_dir_all(&base_b);
    }

    /// Issue #360: the loop's only mining-gated route to `try_checkpoint` never
    /// fires on a halted node, so the live boundary halted perfectly and then
    /// could not finalize — 21 keys present, zero proposals, forever. The test
    /// above reaches Halted only because it hand-drives `try_checkpoint`, which
    /// is exactly how the gap stayed invisible. This one reaches the boundary
    /// WITHOUT hand-driven checkpoints and asserts the loop's standalone
    /// maintenance call finalizes it on its own.
    #[test]
    fn a_halted_node_finalizes_the_boundary_without_mining() {
        let (config, genesis, base) = rig("halt_i360", true);
        let mut node = RunningNode::start_with_release(
            &config, &genesis, KeccakPow, DevnetRehearsalVerifier, armed_release(),
        )
        .unwrap();
        node.set_mine_interval(Duration::ZERO);
        node.try_checkpoint(); // finalize genesis, as a live net has
        for _ in 0..DH {
            assert!(node.try_mine(), "mines below the halt height");
        }
        assert!(node.is_halted());
        assert!(node.finalized_height() < Some(DH), "boundary reached, not finalized");
        // The defect: the mining-gated route is closed forever...
        assert!(!node.try_mine(), "a halted node never mines again");
        // ...and the fix is the loop's standalone maintenance call.
        node.maintain_boundary_checkpoint();
        assert_eq!(
            node.finalized_height(),
            Some(DH),
            "the maintenance call finalizes the boundary without mining"
        );
        assert!(node.telemetry_sample().contains("regime=Halted"));
        // Inert afterwards: nothing is proposed above H.
        node.maintain_boundary_checkpoint();
        assert!(node.next_checkpoint <= DH + CHECKPOINT_CADENCE_BLOCKS);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// **DRILL (c) through the run path.** A binary that would resume past the halt
    /// but carries no revision refuses to start on a halted node's data dir — and
    /// the refusal comes from the on-disk marker, so it cannot be dodged.
    #[test]
    fn drill_c_no_revision_refuses_to_resume_a_halted_data_dir() {
        let (config, genesis, base) = rig("halt_norev", true);
        {
            let mut node = RunningNode::start_with_release(
                &config, &genesis, KeccakPow, DevnetRehearsalVerifier, armed_release(),
            )
            .unwrap();
            node.set_mine_interval(Duration::ZERO);
            node.try_checkpoint();
            mine_and_checkpoint(&mut node, DH);
            assert_eq!(node.tip_height(), DH);
            node.maintain_halt_marker();
            node.save_snapshot().unwrap();
        }

        // (c) — resumes past H, carries no revision at all.
        let norev = Release {
            name: "test [resume, no revision]",
            plan: HaltPlan::None,
            revision: None,
            resumes_from: Some(DH),
        };
        let err = RunningNode::start_with_release(
            &config, &genesis, KeccakPow, DevnetRehearsalVerifier, norev,
        );
        assert!(matches!(
            err,
            Err(RunError::Release(ReleaseError::ResumeWithoutRevision { height })) if height == DH
        ));

        // And the subtler dodge: a perfectly valid later release that carries a
        // revision but simply does not DECLARE the boundary. The marker refuses it.
        let undeclared = Release {
            name: "test [some later binary]",
            plan: HaltPlan::None,
            revision: Some(REVISION_V1_0),
            resumes_from: None,
        };
        let err2 = RunningNode::start_with_release(
            &config, &genesis, KeccakPow, DevnetRehearsalVerifier, undeclared,
        );
        assert!(matches!(
            err2,
            Err(RunError::Release(ReleaseError::UndeclaredResume { marked, .. })) if marked == DH
        ));
        let _ = std::fs::remove_dir_all(&base);
    }

    /// **The resume path (scope item 5).** The upgraded binary opens the SAME data
    /// dir at tip H and continues: no re-sync from genesis, no re-mining of H.
    #[test]
    fn the_upgraded_release_resumes_at_h_without_a_resync() {
        let (config, genesis, base) = rig("halt_resume", true);
        let boundary_hash;
        {
            let mut node = RunningNode::start_with_release(
                &config, &genesis, KeccakPow, DevnetRehearsalVerifier, armed_release(),
            )
            .unwrap();
            node.set_mine_interval(Duration::ZERO);
            node.try_checkpoint();
            mine_and_checkpoint(&mut node, DH);
            assert_eq!(node.tip_height(), DH);
            assert_eq!(node.finalized_height(), Some(DH));
            boundary_hash = node.p2p().node().main_chain_hash_at(DH).unwrap();
            node.maintain_halt_marker();
            node.save_snapshot().unwrap();
        }

        // Swap the binary: same data dir, new release.
        let mut up = RunningNode::start_with_release(
            &config, &genesis, KeccakPow, DevnetRehearsalVerifier, resume_release(),
        )
        .expect("the declared resume release starts on a halted data dir");
        up.set_mine_interval(Duration::ZERO);
        assert_eq!(up.tip_height(), DH, "opened AT the boundary — no re-sync from genesis");
        assert_eq!(
            up.p2p().node().main_chain_hash_at(DH),
            Some(boundary_hash),
            "…and block H was not re-mined: it is byte-identical to the pre-halt block"
        );
        assert_eq!(up.halt_at(), None, "the resumed release halts nowhere");

        // It mines past the boundary, under the post-halt rules.
        assert!(up.try_mine(), "the resumed release produces block H+1");
        assert_eq!(up.tip_height(), DH + 1);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Drive a data dir through halt-at-H and the declared upgrade, leaving it running
    /// `resume_release()` past the boundary — i.e. the state a real net is in the day
    /// after an upgrade. Returns the tip and the hash of the first post-boundary block,
    /// so a later binary can be checked for agreeing about it.
    fn halt_then_upgrade(
        config: &NodeConfig,
        genesis: &GenesisFile,
    ) -> (u64, qlab_devnet::header::Hash32) {
        {
            let mut node = RunningNode::start_with_release(
                config, genesis, KeccakPow, DevnetRehearsalVerifier, armed_release(),
            )
            .unwrap();
            node.set_mine_interval(Duration::ZERO);
            node.try_checkpoint();
            mine_and_checkpoint(&mut node, DH);
            assert_eq!(node.finalized_height(), Some(DH), "the boundary is finalized");
            node.maintain_halt_marker();
            node.save_snapshot().unwrap();
        }
        let mut up = RunningNode::start_with_release(
            config, genesis, KeccakPow, DevnetRehearsalVerifier, resume_release(),
        )
        .expect("the declared upgrade starts");
        up.set_mine_interval(Duration::ZERO);
        assert!(up.try_mine(), "mines the first post-boundary block");
        up.try_checkpoint();
        let tip = up.tip_height();
        let first_post = up.p2p().node().main_chain_hash_at(DH + 1).unwrap();
        up.save_snapshot().unwrap();
        (tip, first_post)
    }

    /// **🎯 #81, THE DEFECT AS FILED, through the run path.** A routine release with no
    /// halt of its own and no declaration starts cleanly on a data dir that previously
    /// halted — and it agrees with the upgraded population about the blocks above the
    /// boundary rather than forking from them.
    ///
    /// Under the height-keyed gate this exact release was refused with
    /// `UndeclaredResume { marked: 16 }`, and would have been for the life of the data
    /// dir.
    #[test]
    fn a_routine_later_release_resumes_a_previously_halted_data_dir() {
        let (config, genesis, base) = rig("halt_routine", true);
        let (tip_after_upgrade, first_post_block) = halt_then_upgrade(&config, &genesis);
        assert!(tip_after_upgrade > DH);

        // The marker now names the revision IN FORCE, keeping H as the audit record.
        let m = HaltMarker::load(&config.data_dir).unwrap().expect("marker still on disk");
        assert_eq!(m.height, DH, "the boundary height is preserved as the audit record");
        assert_eq!(m.revision_id, "v1.0.1-drill", "…and the in-force revision advanced");
        assert!(m.resumed, "the data dir has PASSED the boundary");
        assert!(m.boundary_finalized, "the original halt's audit fact survives the rewrite");

        // A routine bug-fix release months later: same revision (it moves no frozen
        // constant), new binary name, halts nowhere, and says NOTHING about height 16.
        let routine = Release {
            name: "test [v1.0.2 — a routine release, no halt of its own]",
            plan: HaltPlan::None,
            revision: Some(REVISION_V1_0_1_DRILL),
            resumes_from: None,
        };
        let mut later = RunningNode::start_with_release(
            &config, &genesis, KeccakPow, DevnetRehearsalVerifier, routine,
        )
        .expect("a routine release must start on a data dir that once halted (#81)");
        later.set_mine_interval(Duration::ZERO);

        // It opened the upgraded chain, not a fresh one, and it did not re-sync.
        assert_eq!(later.tip_height(), tip_after_upgrade, "no re-sync, no replay");
        assert_eq!(
            later.p2p().node().main_chain_hash_at(DH + 1),
            Some(first_post_block),
            "it accepts the upgraded population's post-boundary block — the PoW domain \
             it inherited from the marker is the same one that block was mined under"
        );
        assert_eq!(later.halt_at(), None, "it halts nowhere of its own");
        // And it keeps mining on that chain rather than forking off it.
        assert!(later.try_mine(), "the routine release extends the upgraded chain");
        assert_eq!(later.tip_height(), tip_after_upgrade + 1);

        // Starting it did NOT rewrite the marker — nothing about the data dir changed.
        assert_eq!(HaltMarker::load(&config.data_dir).unwrap(), Some(m));
        let _ = std::fs::remove_dir_all(&base);
    }

    /// **🎯 #81, THE OTHER HALF, through the run path.** The marker is still a gate: an
    /// arbitrary binary is refused on a halted node, and the pre-announcement binary is
    /// refused on the upgraded one. The second refusal is the one a gate keyed on the
    /// bare *frozen* digest would have lost — the drill's upgrade is inert, so `v1.0`
    /// and `v1.0.1-drill` have byte-identical frozen digests.
    #[test]
    fn an_arbitrary_binary_is_still_refused_on_a_halted_and_on_an_upgraded_data_dir() {
        let (config, genesis, base) = rig("halt_arbitrary", true);
        {
            let mut node = RunningNode::start_with_release(
                &config, &genesis, KeccakPow, DevnetRehearsalVerifier, armed_release(),
            )
            .unwrap();
            node.set_mine_interval(Duration::ZERO);
            node.try_checkpoint();
            mine_and_checkpoint(&mut node, DH);
            node.maintain_halt_marker();
            node.save_snapshot().unwrap();
        }
        // (a) HALTED at the boundary: the plain pre-announcement binary is refused,
        //     even though it carries exactly the revision the marker records. A node
        //     paused at an announced boundary is resumed deliberately or not at all.
        let plain = Release {
            name: "test [plain v1.0, pre-announcement]",
            plan: HaltPlan::None,
            revision: Some(REVISION_V1_0),
            resumes_from: None,
        };
        assert!(matches!(
            RunningNode::start_with_release(
                &config, &genesis, KeccakPow, DevnetRehearsalVerifier, plain,
            ),
            Err(RunError::Release(ReleaseError::UndeclaredResume { marked, .. })) if marked == DH
        ));

        // Now perform the upgrade for real.
        {
            let mut up = RunningNode::start_with_release(
                &config, &genesis, KeccakPow, DevnetRehearsalVerifier, resume_release(),
            )
            .unwrap();
            up.set_mine_interval(Duration::ZERO);
            assert!(up.try_mine());
            up.try_checkpoint();
            up.save_snapshot().unwrap();
        }
        assert_eq!(
            REVISION_V1_0.frozen_digest_hex, REVISION_V1_0_1_DRILL.frozen_digest_hex,
            "precondition: this upgrade is INERT, so a frozen-digest key could not \
             tell these two binaries apart"
        );
        // (b) UPGRADED: the same plain binary is a downgrade now, and still refused —
        //     with the two revisions named, so the operator can see which is which.
        let err = RunningNode::start_with_release(
            &config, &genesis, KeccakPow, DevnetRehearsalVerifier, plain,
        );
        match err {
            Err(RunError::Release(
                ref e @ ReleaseError::UndeclaredResume { ref in_force_revision, .. },
            )) => {
                assert_eq!(in_force_revision, "v1.0.1-drill");
                let msg = e.to_string();
                assert!(msg.contains("`v1.0.1-drill`") && msg.contains("`v1.0`"), "{msg}");
            }
            Err(other) => panic!("expected an UndeclaredResume refusal, got {other:?}"),
            Ok(_) => panic!("the pre-announcement binary must NOT start on an upgraded data dir"),
        }
        // …and the refused start left the marker untouched.
        let m = HaltMarker::load(&config.data_dir).unwrap().unwrap();
        assert_eq!(m.revision_id, "v1.0.1-drill");
        assert!(m.resumed);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// **🎯 #81 point 2, through the run path.** A marker written under the pre-#81
    /// height-keyed scheme refuses the node's start with a reason that names the
    /// boundary and the remedy. Critically it does **not** fall through to a fresh
    /// start: the chain on disk is untouched, and the marker is left exactly as found
    /// for an operator to inspect.
    #[test]
    fn a_pre_81_marker_refuses_the_start_and_does_not_fall_through_to_a_fresh_one() {
        let (config, genesis, base) = rig("halt_schema0", true);
        let tip;
        {
            let mut node = RunningNode::start_with_release(
                &config, &genesis, KeccakPow, DevnetRehearsalVerifier, armed_release(),
            )
            .unwrap();
            node.set_mine_interval(Duration::ZERO);
            node.try_checkpoint();
            mine_and_checkpoint(&mut node, DH);
            tip = node.tip_height();
            node.maintain_halt_marker();
            node.save_snapshot().unwrap();
        }
        // Rewrite the marker in the pre-#81 shape: the four original fields, no
        // `schema` and no `resumed`. This is byte-for-byte what #74's binary wrote.
        let on_disk = HaltMarker::load(&config.data_dir).unwrap().unwrap();
        std::fs::write(
            HaltMarker::path(&config.data_dir),
            format!(
                "height = {}\nrevision_id = \"{}\"\nfrozen_digest_hex = \"{}\"\n\
                 boundary_finalized = {}\n",
                on_disk.height,
                on_disk.revision_id,
                on_disk.frozen_digest_hex,
                on_disk.boundary_finalized,
            ),
        )
        .unwrap();
        let raw_before = std::fs::read_to_string(HaltMarker::path(&config.data_dir)).unwrap();

        // Even the correct upgrade binary is refused — the marker cannot say whether
        // this data dir already resumed, so nothing may be inferred from it.
        for release in [armed_release(), resume_release()] {
            let err = RunningNode::start_with_release(
                &config, &genesis, KeccakPow, DevnetRehearsalVerifier, release,
            );
            match err {
                Err(RunError::Release(
                    e @ ReleaseError::UnknownMarkerSchema { found: 0, expected: 1, .. },
                )) => {
                    let msg = e.to_string();
                    assert!(msg.contains(&format!("height {DH}")), "names the boundary: {msg}");
                    assert!(msg.contains(&format!("resumes_from={DH}")), "names a remedy: {msg}");
                }
                Err(other) => panic!("expected a schema refusal, got {other:?}"),
                Ok(_) => panic!("a marker this binary cannot interpret must refuse the start"),
            }
        }
        // The refusal is inert: the marker is untouched and the chain is intact.
        assert_eq!(
            std::fs::read_to_string(HaltMarker::path(&config.data_dir)).unwrap(),
            raw_before,
            "a refused start must not rewrite the evidence it refused on"
        );
        std::fs::remove_file(HaltMarker::path(&config.data_dir)).unwrap();
        let reopened = RunningNode::start_with_release(
            &config, &genesis, KeccakPow, DevnetRehearsalVerifier, resume_release(),
        )
        .expect("with the marker deliberately removed, the upgrade starts");
        assert_eq!(
            reopened.tip_height(),
            tip,
            "…on the SAME chain — the schema refusal never cost the data dir a replay"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A **second** upgrade on the same data dir — the case the height-keyed gate could
    /// not express at all, and the reason #81 exists. Halt at a second boundary under
    /// the already-upgraded revision, resume past it, and confirm the marker tracks the
    /// new boundary and the new revision in force.
    #[test]
    fn a_second_upgrade_advances_the_boundary_and_the_revision_in_force() {
        let (config, genesis, base) = rig("halt_second", true);
        halt_then_upgrade(&config, &genesis);
        const H2: u64 = DH + CHECKPOINT_CADENCE_BLOCKS; // the next boundary on the grid

        // The second armed release: carries the CURRENT in-force revision (it changes
        // no frozen constant yet — the halt is what arms the change) and stops at H2.
        let armed2 = Release {
            name: "test [armed at the second boundary]",
            plan: HaltPlan::Armed { height: H2 },
            revision: Some(REVISION_V1_0_1_DRILL),
            resumes_from: None,
        };
        {
            let mut node = RunningNode::start_with_release(
                &config, &genesis, KeccakPow, DevnetRehearsalVerifier, armed2,
            )
            .expect("it carries the revision in force, so it needs no declaration (#81)");
            node.set_mine_interval(Duration::ZERO);
            assert_eq!(node.halt_at(), Some(H2));
            mine_and_checkpoint(&mut node, H2);
            assert_eq!(node.tip_height(), H2, "halted at the second boundary");
            assert!(node.is_halted());
            node.maintain_halt_marker();
            node.save_snapshot().unwrap();
        }
        let m = HaltMarker::load(&config.data_dir).unwrap().unwrap();
        assert_eq!(m.height, H2, "the marker tracks the SECOND boundary");
        assert!(!m.resumed, "halted at it, not past it");
        assert_eq!(m.revision_id, "v1.0.1-drill");

        // The second upgrade declares H2 — not DH. Under the height-keyed gate this
        // release would have had to declare the historical boundary 16 as well, and
        // there is no field in which to say both.
        let up2 = Release {
            name: "test [the second upgrade]",
            plan: HaltPlan::None,
            revision: Some(REVISION_V1_0),
            resumes_from: Some(H2),
        };
        let mut node = RunningNode::start_with_release(
            &config, &genesis, KeccakPow, DevnetRehearsalVerifier, up2,
        )
        .expect("the second upgrade starts by declaring the SECOND boundary only");
        node.set_mine_interval(Duration::ZERO);
        assert_eq!(node.tip_height(), H2, "opened at the boundary, no replay");
        let m = HaltMarker::load(&config.data_dir).unwrap().unwrap();
        assert_eq!(m.height, H2);
        assert!(m.resumed);
        assert_eq!(m.revision_id, "v1.0", "the second upgrade's revision is now in force");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// **DRILL (d) through the run path.** A cancelled upgrade does not halt at the
    /// cancelled height — the node mines straight through it and writes no marker.
    #[test]
    fn drill_d_cancelled_release_mines_through_the_cancelled_height() {
        let (config, genesis, base) = rig("halt_cancel", true);
        let cancelled = Release {
            name: "test [cancelled]",
            plan: HaltPlan::Cancelled { height: DH, reason: "review stood it down" },
            revision: Some(REVISION_V1_0),
            resumes_from: None,
        };
        let mut node = RunningNode::start_with_release(
            &config, &genesis, KeccakPow, DevnetRehearsalVerifier, cancelled,
        )
        .unwrap();
        node.set_mine_interval(Duration::ZERO);
        assert_eq!(node.halt_at(), None, "a cancelled upgrade stops nowhere");
        node.try_checkpoint();
        let past = DH + 8 + CHECKPOINT_SIGN_HYSTERESIS_BLOCKS; // #269: last slot signs hysteresis-late
        assert_eq!(mine_and_checkpoint(&mut node, past), past, "mined through it");
        assert_eq!(node.tip_height(), past);
        assert!(!node.is_halted());
        assert_eq!(node.finalized_height(), Some(DH + 8), "finality never paused");
        let line = node.telemetry_sample();
        assert!(line.contains("regime=Final"), "never a halt regime: {line}");
        assert!(line.contains("halt=-"), "no halt height on the wire: {line}");
        node.maintain_halt_marker();
        assert_eq!(
            HaltMarker::load(&config.data_dir).unwrap(),
            None,
            "a cancelled upgrade leaves no halt marker — nothing halted"
        );
        // …but the stand-down is still visible to an operator.
        assert!(node.release().banner(None).contains("CANCELLED"));
        let _ = std::fs::remove_dir_all(&base);
    }
    // ---- issue #87: the journal, the caliper, and the scrape endpoint --------

    /// The `TELEMETRY` line's **compatibility contract**: every pre-#87 field keeps
    /// its name, its value and its position, and the two new counters are appended
    /// at the end. The T0 sampler and the sealed evidence pack (PR #93) read this
    /// line; nothing in it may shift under them.
    #[test]
    fn telemetry_line_is_extended_at_the_end_and_nowhere_else() {
        let (config, genesis, base) = rig("telemetry_shape", true);
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        node.set_mine_interval(Duration::ZERO);
        node.try_checkpoint();
        assert!(node.try_mine());

        let line = node.telemetry_sample();
        let keys: Vec<&str> = line
            .split_whitespace()
            .skip(1) // the "TELEMETRY" tag
            .map(|kv| kv.split('=').next().unwrap())
            .collect();
        assert_eq!(
            keys,
            vec![
                // ── the pre-#87 fields, in their original order ──
                "tip", "final", "stall", "age_s", "diff", "peers", "mempool", "epoch", "regime",
                "halt", "hignore", "powrej", "dialable",
                // ── appended by #87, at the end ──
                "rounds", "rfail",
                // ── appended by #84, at the end ──
                "fid", "sslot", "sid",
                // ── appended by #105, at the end ──
                "rback",
                // ── appended by #130 (a), at the end ──
                "stip", "slag",
                // ── appended by #134, at the end ──
                "uanchor",
                // ── appended by #106, at the end ──
                "mready",
                // ── appended by #162 finding 6, at the end ──
                "stipid", "schain",
                // ── appended by #130 (c), at the end ──
                "breq",
                // ── appended by #85, at the end ──
                "fback",
                // ── appended by #133 D3, at the end ──
                "prest",
                // ── appended by #200, at the end ──
                "uex",
                // ── appended by #130 (b), at the end ──
                "bdrop",
                // ── appended by #181, at the end ──
                "unk",
                // ── appended by #204, at the end ──
                "cpq", "dfin", "fdrop",
                // ── appended by #229, at the end ──
                "bask",
                // ── appended by #212, at the end ──
                "dfinbh",
                // ── appended by #359, at the end ──
                "snap",
            ],
            "existing TELEMETRY fields must not move or be renamed: {line}"
        );
        assert!(line.starts_with("TELEMETRY tip="));
        // Genesis finalized as slot 0 without a round, so nothing has closed yet.
        assert!(line.contains(" rounds=0 rfail=0"), "{line}");
        assert!(line.contains(" rback=0"), "nothing was walked past either: {line}");
        // A healthy node states the zero rather than omitting the field (#130 (a)):
        // this node mined its own tip, so its two views agree.
        assert!(line.contains(" stip=1 slag=0"), "both views, and the zero gap: {line}");
        // #106: this rig has no seeds and no peers, so it is the whole net and says
        // which of the gate's permitting reasons applies.
        assert!(line.contains(" mready=alone "), "the readiness verdict: {line}");
        // #162 finding 6: this node mined and applied its own tip, so the applied tip
        // IS the main-chain block at its height.
        assert!(line.contains(" schain=main"), "the wedge verdict: {line}");
        // #130 (c): a node alone on its own chain has nothing outstanding.
        assert!(line.contains(" breq=0 "), "nothing in flight: {line}");
        // #85: this node finalized genesis locally, so the newest append says the
        // tracker checkpoint is backed by its exact block in fork choice.
        // Not `ends_with` any more: later appends landed after this field.
        assert!(line.contains(" fback=local "), "backing verdict present: {line}");
        // #133 D3: a fresh data dir has nothing to restore — and the shape is
        // restored/known, not a bare zero, so "nothing to restore" is distinguishable
        // from "unk". Not `ends_with`: four fields have appended after it.
        assert!(line.contains(" prest=0/0 "), "nothing restored: {line}");
        // #200: a healthy node is not under the unobtainable-body exemption.
        assert!(line.contains(" uex=0 "), "exemption disarmed: {line}");
        // #130 (b): this node applied every body it produced, so nothing has been
        // refused — and it says so with a zero and an explicit "no height", rather
        // than by the field being absent.
        assert!(line.contains(" bdrop=0@- "), "no body refused: {line}");
        // #181: a node that has spoken to nobody has seen no version skew, and it
        // says the zero rather than omitting the field (the #130 (a) rule).
        assert!(line.contains(" unk=0/0 "), "no skew seen: {line}");
        // #204: a node alone on its own chain has nobody to ask and nothing to ask
        // about — the zero is printed, not omitted.
        assert!(line.contains(" cpq=0 "), "no query in flight: {line}");
        // #204: the durable head is the one a restart reads, and on a healthy node it
        // agrees with `final=`. This rig finalized genesis, so both say 0.
        assert!(line.contains(" final=0 "), "the tracker head: {line}");
        assert!(line.contains(" dfin=0 "), "and the DURABLE head agrees: {line}");
        assert!(line.contains(" fdrop=0 "), "nothing was refused: {line}");
        // #229: a node alone on its own chain has an empty ask set and a fork point
        // that IS its applied tip (height 1 here — it mined one block), so the two
        // derived quantities say "there is nothing to fetch and I know exactly where
        // I am". That is the healthy reading and it is a fact, not an absence.
        assert!(line.contains(" bask=0@1 "), "nothing wanted: {line}");
        // #212: head #3's identity. `dfin=0` above says how high the durable head is;
        // this says WHAT it is, which is what a cross-host comparison needs and what
        // `dfin=` alone cannot carry. No longer `ends_with`: #359 appended after it.
        assert!(
            line.contains(&format!(" dfinbh={} ", node.telemetry().durable.id_field())),
            "{line}"
        );
        assert_ne!(field(&line, "dfinbh"), "-", "a finalized durable head has an identity: {line}");
        // #359: this rig has never stopped and never reached a cadence tick, so it is
        // node3's shape and the field says so — and it is the LAST field.
        assert!(line.ends_with(" snap=none"), "no snapshot, said plainly and last: {line}");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// **Acceptance (#212, on a real node): the durable head reaches `/v1/telemetry`,
    /// the wire and the log line come from ONE snapshot, and the identity is the
    /// durable head's own block hash.**
    ///
    /// The unit tests in `qlab_node::telemetry` prove the encoding; what only the
    /// binary can prove is that head #3 is actually *read* here and reaches the served
    /// bytes. That was the whole defect: `dfin=` existed on the log line since
    /// `PR #207` and `qumbra-opview` reads the wire and nothing else.
    #[test]
    fn the_durable_head_reaches_the_telemetry_wire_and_agrees_with_the_log_line() {
        use qlab_node::{ChainStore as _, DurableView};

        let (config, genesis, base) = rig("telemetry_dfinbh", true);
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        node.set_mine_interval(Duration::ZERO);
        node.try_checkpoint();
        assert!(node.try_mine());

        let t = node.telemetry();
        let line = node.telemetry_sample();

        // 🔴 The wire states head #3 — not `Unavailable`, which is what every
        // composition that cannot see it reports and what this one did before #212.
        let DurableView::Head(head) = t.durable else {
            panic!("the binary's composition must state head #3, got {:?}", t.durable);
        };

        // The identity is the durable head's own block hash prefix, taken from the
        // state machine's store rather than from anything this test recomputes.
        let store = node.p2p().node().state().chain();
        assert_eq!(head.height, store.finalized_height().unwrap());
        let expected: String = store.finalized_hash().unwrap()[..6]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(head.identity.field(), expected, "dfinbh IS the durable head's block hash prefix");

        // 🔴 …and it is NOT `fid`. Same width, different space: `fid` is the digest of
        // the bytes the committee signed. If a future edit ever made these equal, the
        // trap this field is named to avoid would be invisible.
        assert_ne!(head.identity.field(), t.fid_field(), "a block hash is not a checkpoint identity");

        // One snapshot, both surfaces (#117's discipline): the line's two fields are
        // the wire's two fields, and there is nothing for them to disagree with.
        assert_eq!(field(&line, "dfin"), t.durable.height_field());
        assert_eq!(field(&line, "dfinbh"), t.durable.id_field());
        assert_eq!(field(&line, "dfin"), field(&line, "final"), "healthy: the two heads agree");

        // And the served bytes round-trip through the reader an operator actually
        // uses, at the bumped version.
        let served = t.to_bytes();
        assert_eq!(served[0], qlab_node::RPC_VERSION);
        let (version, decoded) = qlab_node::Telemetry::from_bytes_compat(&served).unwrap();
        assert_eq!(version, 0x06, "the current wire (lab #367 burned-tail bump)");
        assert_eq!(decoded, t);
        assert_eq!(decoded.durable, t.durable);
        assert_eq!(
            decoded.durable_agreement(),
            qlab_node::DurableAgreement::Agreed,
            "a healthy node's two heads agree, and the WIRE now says so"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// **Issue #181 end-to-end, over a real socket: the frame is ignored, the peer
    /// is not banned, and both operator surfaces say so with the same number.**
    ///
    /// It goes through the TCP transport on purpose. The unit tests in `qlab-p2p`
    /// prove the classification; what only the binary can prove is that a frame an
    /// upgraded host would actually send reaches the counter, and that the counter
    /// reaches `TELEMETRY` and `/metrics` without the two disagreeing — which is
    /// the failure #84 named, one fact rendered twice from two derivations.
    ///
    /// The placement decision it guards is that `unk=` is on the log line at all:
    /// `/metrics` is off unless `metrics_addr` is set, so a scrape-only counter
    /// would be absent on precisely the hosts a rolling upgrade skews first.
    #[test]
    fn an_unknown_envelope_type_over_tcp_is_ignored_and_reported_on_both_surfaces() {
        use std::io::Write;

        let (config, genesis, base) = rig("telemetry_unk", true);
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        assert_eq!(field(&node.telemetry_sample(), "unk"), "0/0", "clean at start");

        // A well-formed frame at our protocol version carrying a type code no build
        // implements — exactly what an additive `MsgType` looks like to a host that
        // predates it. Hand-built, because `Envelope::new` cannot express it.
        let unknown_type: u16 = 0x0044;
        assert!(qlab_p2p::MsgType::from_u16(unknown_type).is_none());
        let mut frame = Vec::new();
        frame.extend_from_slice(&qlab_p2p::MAGIC);
        frame.extend_from_slice(&qlab_p2p::PROTOCOL_VERSION.to_le_bytes());
        frame.extend_from_slice(&unknown_type.to_le_bytes());
        frame.extend_from_slice(&0u32.to_le_bytes());

        let mut sock = std::net::TcpStream::connect(node.listen_addr()).expect("dial the node");
        sock.write_all(&frame).expect("send the newer type");
        sock.flush().unwrap();

        // Pump until the frame lands. The reader thread and the node loop are
        // separate, so a single step can legitimately see nothing yet.
        for _ in 0..200 {
            node.step_once();
            if node.p2p().unknown_stats().frames > 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        assert_eq!(
            field(&node.telemetry_sample(), "unk"),
            "1/0",
            "the frame was ignored, and saying so is the whole point of the field"
        );
        assert!(
            node.metrics_text().contains("\nqumbra_unknown_msg_type_total 1\n"),
            "the log and the scrape carry the same number: {}",
            node.metrics_text()
        );
        assert!(
            node.p2p().peers().iter().all(|p| p.score == 0),
            "🔴 no peer was scored for speaking a type this build does not implement"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// `bdrop=`'s two renderings, pinned as tokens (issue #130 (b)).
    ///
    /// The `-` half is the load-bearing one: `0@-` and a hypothetical `0@0` would be
    /// the same claim to a careless reader and are not the same fact, and genesis is
    /// height 0, so the ambiguity is not academic.
    #[test]
    fn bdrop_renders_the_count_and_the_height_of_the_last_refusal() {
        assert_eq!(bdrop_field((0, None)), "0@-", "nothing refused states no height");
        assert_eq!(bdrop_field((1, Some(0))), "1@0", "…and height 0 is a real height");
        assert_eq!(bdrop_field((17, Some(412))), "17@412");
        // One whitespace-free token, so `soak.sh`'s generic `field()` extractor
        // (`sed -n "s/.* $2=\([^ ]*\).*/\1/p"`) returns the whole value.
        assert!(!bdrop_field((17, Some(412))).contains(' '));
    }

    /// The compatibility contract, stated so that **it survives the next append**.
    ///
    /// `telemetry_line_is_extended_at_the_end_and_nowhere_else` asserts the whole
    /// key vector, so every baton that appends a field must edit it — #87 did, and
    /// #84 did. That makes the "unmodified" half of an acceptance bar impossible to
    /// satisfy honestly, and worse, it means the assertion that pre-existing fields
    /// have not moved is re-typed (and could be re-typed *wrongly*) each time.
    ///
    /// This one pins the pre-#84 prefix as a constant. A future append cannot
    /// require touching it; a rename, a reorder, or a deletion breaks it.
    #[test]
    fn the_pre_i84_telemetry_prefix_is_frozen_against_future_appends() {
        /// Every `TELEMETRY` field that existed before issue #84, in order. This
        /// list is **append-only history, not a wish**: nothing may be added here.
        const PRE_I84_FIELDS: [&str; 15] = [
            "tip", "final", "stall", "age_s", "diff", "peers", "mempool", "epoch", "regime",
            "halt", "hignore", "powrej", "dialable", "rounds", "rfail",
        ];
        let (config, genesis, base) = rig("telemetry_prefix", true);
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        node.set_mine_interval(Duration::ZERO);
        node.try_checkpoint();
        assert!(node.try_mine());

        let line = node.telemetry_sample();
        let keys: Vec<&str> = line
            .split_whitespace()
            .skip(1)
            .map(|kv| kv.split('=').next().unwrap())
            .collect();
        assert!(keys.len() >= PRE_I84_FIELDS.len(), "fields were deleted: {line}");
        assert_eq!(
            &keys[..PRE_I84_FIELDS.len()],
            &PRE_I84_FIELDS,
            "every pre-#84 field keeps its name and its position: {line}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    // ---- issue #84: the finalized checkpoint's identity ----------------------

    /// Read one `key=value` field out of a `TELEMETRY`/`ROUND` line.
    fn field<'a>(line: &'a str, key: &str) -> &'a str {
        line.split_whitespace()
            .find_map(|kv| kv.strip_prefix(&format!("{key}=")))
            .unwrap_or_else(|| panic!("no {key}= in: {line}"))
    }

    // ---- issue #85: tracker finality vs locally-held chain ------------------

    /// **ACCEPTANCE (issue #85): preserve learn-ahead and name its backing.**
    ///
    /// The first node deliberately verifies a frozen-roster quorum for slot 8
    /// while still at genesis and without the checkpoint block. The tracker must
    /// advance — that capability is how a merely-behind node learns it is behind —
    /// while the chain's finalized pointer remains untouched. Its line says
    /// `tip=0 final=8 fback=heard`. A second node finalizes its locally-mined slot-8
    /// block and prints `fback=local`, so the two formerly-ambiguous states differ
    /// on the telemetry line alone.
    #[test]
    fn quorum_ahead_of_local_chain_stays_learned_and_prints_heard() {
        use qlab_devnet::committee::Checkpoint;
        use qlab_p2p::n1::{CheckpointIngest, VotesOutcome};

        let (heard_config, heard_genesis, heard_base) = rig("finality_heard", false);
        let validators = heard_genesis
            .load_validators(&heard_config.committee_key_paths)
            .expect("the rig's 21 committee keys load");
        let mut heard = RunningNode::start(
            &heard_config,
            &heard_genesis,
            KeccakPow,
            DevnetRehearsalVerifier,
        )
        .unwrap();
        assert_eq!(field(&heard.telemetry_sample(), "fback"), "-");

        let slot = CHECKPOINT_CADENCE_BLOCKS;
        let cp = Checkpoint::new(slot, [0x85; 32], [0x58; 32]);
        let votes: Vec<_> = validators.iter().map(|v| v.sign_checkpoint(&cp)).collect();
        let need = heard.p2p().node().slot_context(slot).need;
        assert_eq!(need, 15, "the frozen 21-member roster requires a 15-vote quorum");
        assert!(matches!(
            heard
                .p2p_mut()
                .node_mut()
                .ingest_checkpoint_votes(&cp, &votes[..need]),
            VotesOutcome::Learned { finalized: true, .. }
        ));

        assert_eq!(heard.tip_height(), 0, "the checkpoint block was never supplied");
        assert_eq!(heard.finalized_height(), Some(slot), "the tracker learns ahead");
        assert!(
            heard.p2p().node().chain().header(&cp.block_hash).is_none(),
            "fork choice does not hold the finalized block"
        );
        assert_eq!(
            heard.p2p().node().chain().finalized_height(),
            None,
            "ChainState::set_finalized leaves its pointer untouched for an unknown block"
        );
        let heard_line = heard.telemetry_sample();
        assert_eq!(field(&heard_line, "tip"), "0", "{heard_line}");
        assert_eq!(field(&heard_line, "final"), slot.to_string(), "{heard_line}");
        assert_eq!(field(&heard_line, "fback"), "heard", "{heard_line}");

        let (local_config, local_genesis, local_base) = rig("finality_local", true);
        let mut local = RunningNode::start(
            &local_config,
            &local_genesis,
            KeccakPow,
            DevnetRehearsalVerifier,
        )
        .unwrap();
        local.set_mine_interval(Duration::ZERO);
        local.try_checkpoint(); // bootstrap genesis finality
        for _ in 0..slot + CHECKPOINT_SIGN_HYSTERESIS_BLOCKS {
            assert!(local.try_mine());
        }
        local.try_checkpoint();
        let local_line = local.telemetry_sample();
        assert_eq!(field(&local_line, "final"), field(&heard_line, "final"));
        assert_eq!(field(&local_line, "fback"), "local", "{local_line}");
        assert_ne!(
            field(&heard_line, "fback"),
            field(&local_line, "fback"),
            "heard-only and locally-backed finality must print differently"
        );

        for base in [heard_base, local_base] {
            let _ = std::fs::remove_dir_all(&base);
        }
    }

    /// Mine to the first cadence slot and finalize it, returning the sample line.
    /// `wall` selects the header-timestamp clock: two nodes on different clocks
    /// mine *different blocks* at the same height, which is how a real net's nodes
    /// diverge (timestamps and nonces are the only per-node inputs) and is what
    /// puts two different checkpoints on one height here.
    fn node_finalizing_slot_8(tag: &str, wall: bool) -> (String, PathBuf) {
        let (config, genesis, base) = rig(tag, true);
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        node.set_mine_interval(Duration::ZERO);
        if wall {
            node.set_mining_clock(MiningClock::WallClock);
        }
        node.try_checkpoint(); // genesis (slot 0)
        for _ in 0..CHECKPOINT_CADENCE_BLOCKS + CHECKPOINT_SIGN_HYSTERESIS_BLOCKS {
            assert!(node.try_mine(), "{tag}: mines at the genesis difficulty");
        }
        node.try_checkpoint(); // slot 8, signed once the #269 hysteresis has passed
        assert_eq!(
            node.finalized_height(),
            Some(CHECKPOINT_CADENCE_BLOCKS),
            "{tag}: slot 8 finalized"
        );
        (node.telemetry_sample(), base)
    }

    /// **ACCEPTANCE #1 — the whole point of the issue.**
    ///
    /// Two nodes finalize a checkpoint at the *same height* over *different*
    /// blocks: this is R2, "two different checkpoints finalized at the same
    /// height", the single most serious consensus failure and — before this field
    /// — completely invisible, because both nodes print the identical `final=8`.
    /// The third node repeats the first exactly, so the test also pins the other
    /// half: agreement must be byte-identical, or the field cries wolf on every
    /// healthy net and gets ignored.
    #[test]
    fn nodes_that_finalized_different_checkpoints_at_one_height_print_different_identities() {
        let (a, abase) = node_finalizing_slot_8("id_a", false);
        let (b, bbase) = node_finalizing_slot_8("id_b", true);
        let (c, cbase) = node_finalizing_slot_8("id_c", false);

        // All three agree on the height, which is exactly the problem: `final=`
        // alone cannot tell the fork from the healthy pair.
        for l in [&a, &b, &c] {
            assert_eq!(field(l, "final"), "8", "{l}");
        }

        // A and B finalized different blocks at height 8 ⇒ different identities.
        assert_ne!(
            field(&a, "fid"),
            field(&b, "fid"),
            "two checkpoints at one height MUST NOT print the same identity\nA: {a}\nB: {b}"
        );
        // A and C finalized the same checkpoint ⇒ byte-identical identities.
        assert_eq!(
            field(&a, "fid"),
            field(&c, "fid"),
            "agreeing nodes MUST be byte-identical\nA: {a}\nC: {c}"
        );
        // The identity is well-formed on all three, not merely different.
        for l in [&a, &b, &c] {
            let fid = field(l, "fid");
            assert_eq!(fid.len(), 12, "{l}");
            assert!(u64::from_str_radix(fid, 16).is_ok(), "{l}");
        }

        // The same divergence is visible in what each node's KEYS signed — the
        // slot-3776 half. A and B hold the whole committee here, so each finalized
        // its own variant and `sid == fid`; on the T0 topology (6/5/5/5) a minority
        // finalizes the majority's checkpoint and only `sid` separates them.
        assert_eq!(field(&a, "sslot"), "8");
        assert_eq!(field(&a, "sid"), field(&a, "fid"), "this node signed what it finalized");
        assert_ne!(field(&a, "sid"), field(&b, "sid"), "the two key sets signed different things");

        for base in [abase, bbase, cbase] {
            let _ = std::fs::remove_dir_all(&base);
        }
    }

    /// **ACCEPTANCE #2 — absence is printed, not omitted.** Before anything is
    /// finalized all three fields are present and carry the same `-` sentinel the
    /// line already uses for `final=`/`age_s=`/`halt=`. A field that simply
    /// disappears forces every parser to special-case the cold-start window, and
    /// that special case is the one nobody writes.
    #[test]
    fn identity_fields_are_present_and_well_formed_before_anything_finalizes() {
        let (config, genesis, base) = rig("id_cold", true);
        let node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        assert_eq!(node.finalized_height(), None, "nothing finalized yet");

        let line = node.telemetry_sample();
        assert_eq!(field(&line, "final"), "-", "the precedent this follows: {line}");
        assert_eq!(field(&line, "fid"), "-", "{line}");
        assert_eq!(field(&line, "sslot"), "-", "{line}");
        assert_eq!(field(&line, "sid"), "-", "{line}");
        // Same for the scrape — but there the rule is the opposite and deliberate:
        // no series at all, following `qumbra_finalized_height`. A log line has a
        // position to hold open; a metric series does not, and a placeholder there
        // would be a reading that was never taken.
        let text = node.metrics_text();
        for fam in ["qumbra_finalized_checkpoint_id", "qumbra_signed_checkpoint_id"] {
            assert!(text.contains(&format!("# TYPE {fam} gauge")), "{fam} declared");
            assert!(
                !text.lines().any(|l| l.starts_with(&format!("{fam} "))),
                "{fam} must emit no series before anything is finalized"
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The log field and the scrape are **the same number in two spellings**, on a
    /// live node. If this ever drifts an operator has two instruments that
    /// disagree, which is worse than having one.
    #[test]
    fn the_scrape_and_the_log_line_report_one_identity() {
        let (config, genesis, base) = rig("id_scrape", true);
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        node.set_mine_interval(Duration::ZERO);
        node.try_checkpoint();
        for _ in 0..CHECKPOINT_CADENCE_BLOCKS + CHECKPOINT_SIGN_HYSTERESIS_BLOCKS {
            assert!(node.try_mine());
        }
        node.try_checkpoint();

        let line = node.telemetry_sample();
        let text = node.metrics_text();
        let scraped: u64 = text
            .lines()
            .find_map(|l| l.strip_prefix("qumbra_finalized_checkpoint_id "))
            .expect("the gauge is emitted once something is finalized")
            .parse()
            .unwrap();
        assert_eq!(format!("{scraped:012x}"), field(&line, "fid"), "{line}\n{text}");
        assert!(text.contains(&format!("qumbra_signed_checkpoint_slot {CHECKPOINT_CADENCE_BLOCKS}")));
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The per-slot journal carries the identity too, and it is the *durable* copy:
    /// `TELEMETRY` is sampled on a cadence, so a finality catch-up that jumps
    /// several slots leaves no sample for the slots it skipped. `ROUND` has a line
    /// for every one of them.
    #[test]
    fn the_round_journal_names_what_this_node_signed_for_each_slot() {
        let (config, genesis, base) = rig("id_journal", true);
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        node.set_mine_interval(Duration::ZERO);
        node.try_checkpoint();
        for _ in 0..CHECKPOINT_CADENCE_BLOCKS + CHECKPOINT_SIGN_HYSTERESIS_BLOCKS {
            assert!(node.try_mine());
            node.note_slots_reached();
            node.try_checkpoint();
        }
        let lines = node.emit_rounds();
        let slot8 = lines
            .iter()
            .find(|l| l.starts_with(&format!("ROUND slot={CHECKPOINT_CADENCE_BLOCKS} ")))
            .unwrap_or_else(|| panic!("slot 8 must be journalled; got {lines:?}"));
        let cpid = field(slot8, "cpid");
        assert_eq!(cpid.len(), 12, "{slot8}");
        // …and it is the same checkpoint the sample line reports as finalized.
        assert_eq!(cpid, field(&node.telemetry_sample(), "fid"), "{slot8}");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// **A node whose own key set is split against itself says so.**
    ///
    /// Reachable after a restart on a diverged history: a key whose ledger was
    /// restored refuses to re-sign the new variant while a key with no ledger
    /// signs it, leaving one node holding two commitments for one slot. Printing
    /// either one would produce a line that looks healthy, which is the failure
    /// mode this whole issue is about — so the field says `split` instead, and the
    /// scrape drops the identity while keeping the slot (an identity-missing-but-
    /// slot-present scrape is the machine-side form of the same alarm).
    #[test]
    fn a_node_whose_own_keys_disagree_prints_split_rather_than_picking_one() {
        use qlab_devnet::committee::Checkpoint;

        let (config, genesis, base) = rig("id_split", true);
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        let slot = CHECKPOINT_CADENCE_BLOCKS;
        let x = Checkpoint::new(slot, [0x11; 32], [0x11; 32]);
        let y = Checkpoint::new(slot, [0x22; 32], [0x22; 32]);
        node.finalizers_mut()[0].sign(&x).expect("a fresh ledger signs");
        node.finalizers_mut()[1].sign(&y).expect("a fresh ledger signs");

        let c = node.local_commitment().expect("keys are committed");
        assert_eq!(c.slot, slot);
        assert_eq!(c.id, None, "disagreeing keys have no single identity");

        let line = node.telemetry_sample();
        assert_eq!(field(&line, "sslot"), slot.to_string(), "{line}");
        assert_eq!(field(&line, "sid"), LOCAL_COMMITMENT_SPLIT, "{line}");

        let text = node.metrics_text();
        assert!(
            text.contains(&format!("qumbra_signed_checkpoint_slot {slot}")),
            "the slot is still reported: {text}"
        );
        assert!(
            !text.lines().any(|l| l.starts_with("qumbra_signed_checkpoint_id ")),
            "a scrape must not carry one of two disagreeing values"
        );

        // Agreement is the ordinary case and still prints an identity.
        let (config2, genesis2, base2) = rig("id_agree", true);
        let mut n2 =
            RunningNode::start(&config2, &genesis2, KeccakPow, DevnetRehearsalVerifier).unwrap();
        n2.finalizers_mut()[0].sign(&x).unwrap();
        n2.finalizers_mut()[1].sign(&x).unwrap();
        assert_eq!(n2.local_commitment().unwrap().id, Some(x.identity()));
        assert_eq!(field(&n2.telemetry_sample(), "sid"), x.id_hex());

        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&base2);
    }

    /// The journal on the real run path: a node holding the whole committee closes
    /// its rounds, and each one leaves a `ROUND` line carrying the counts, the roster
    /// context and the timing basis.
    #[test]
    fn closed_rounds_are_journalled_on_the_run_path() {
        let (config, genesis, base) = rig("journal", true);
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        node.set_mine_interval(Duration::ZERO);
        node.try_checkpoint(); // genesis (slot 0) — finalized without a round

        for _ in 0..CHECKPOINT_CADENCE_BLOCKS + CHECKPOINT_SIGN_HYSTERESIS_BLOCKS {
            assert!(node.try_mine());
            node.note_slots_reached();
            node.try_checkpoint();
        }
        assert_eq!(node.finalized_height(), Some(CHECKPOINT_CADENCE_BLOCKS), "slot 8 finalized");

        let lines = node.emit_rounds();
        let slot8 = lines
            .iter()
            .find(|l| l.starts_with(&format!("ROUND slot={CHECKPOINT_CADENCE_BLOCKS} ")))
            .unwrap_or_else(|| panic!("slot 8 must be journalled; got {lines:?}"));
        assert!(slot8.contains("why=finalized"), "{slot8}");
        assert!(slot8.contains("close=finalized"), "{slot8}");
        assert!(slot8.contains("have=21 need=15 active=21 roster=21"), "{slot8}");
        assert!(slot8.contains("absent=-"), "a full committee has no absentees: {slot8}");
        assert!(slot8.contains("local=21"), "this node proposed with all 21 held keys: {slot8}");
        // Deterministic clock in tests ⇒ no timings, and none are invented.
        assert!(slot8.contains("open_ms=- first_ms=- last_ms=-"), "{slot8}");

        // Draining is idempotent: a record is journalled exactly once.
        assert!(node.emit_rounds().is_empty(), "records are emitted once, not twice");
        // …and the same round is now in the aggregates.
        assert!(node
            .metrics_text()
            .contains("qumbra_checkpoint_rounds_total{verdict=\"finalized\"} 1"));
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A node holding a MINORITY of the committee — the T0 6/5/5/5 shape — cannot
    /// finalize alone, and the open round says so **by name**. This is the 42 h
    /// silence, replaced by a record.
    #[test]
    fn a_minority_key_holder_names_the_members_it_never_heard_from() {
        let (mut config, genesis, base) = rig("minority", true);
        config.committee_key_paths.truncate(6); // the T0 node holding 6 of 21
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        node.set_mine_interval(Duration::ZERO);
        node.try_checkpoint();
        assert_eq!(node.finalized_height(), None, "6 < quorum 15: not even genesis finalizes");

        for _ in 0..CHECKPOINT_CADENCE_BLOCKS + CHECKPOINT_SIGN_HYSTERESIS_BLOCKS {
            assert!(node.try_mine());
            node.note_slots_reached();
            node.try_checkpoint();
        }
        assert_eq!(node.finalized_height(), None, "still short of quorum");

        let r = node
            .p2p()
            .node()
            .rounds()
            .open_round(CHECKPOINT_CADENCE_BLOCKS)
            .expect("the slot has a record even though it never finalized");
        assert_eq!((r.have(), r.need, r.active, r.roster), (6, 15, 21, 21));
        assert_eq!(r.absent(), (6..21).collect::<Vec<_>>(), "the fifteen never heard from");
        assert!(r.proposed_locally && r.local_votes == 6);
        assert_eq!(r.rejects.total(), 0, "a shortage, not a stream of junk");

        // And the stall is visible WHILE IT IS HAPPENING: the round never closes on
        // its own (nothing can finalize past it at 11 of 21 keys), so without the
        // overdue report the journal would say nothing for the whole stall. Under the
        // deterministic clock there is no age to judge, so nothing is reported and
        // nothing is invented — the wall-clock behaviour is pinned in
        // `qlab_node::round`'s own test.
        assert!(node.emit_overdue_rounds().is_empty(), "no clock basis ⇒ no age, no report");
        let _ = std::fs::remove_dir_all(&base);
    }

    // ---- issue #105: the alarm counts live rounds, and only live rounds ------

    /// **ACCEPTANCE, on the real run path: the two classes on one node.**
    ///
    /// First half — a tip that moved a long way while the ledger was not looking is
    /// exactly what a `Headers` batch does to a resyncing node, and it is what
    /// produced `rounds=1316 rfail=1315` on a node whose `final=` matched its three
    /// peers. Those slots must reach `rback=`, not `rfail=`, and must still be
    /// journalled.
    ///
    /// Second half — the same node then crosses slots **at the frontier**, one block
    /// at a time, and loses them (it holds no committee keys, so nothing finalizes
    /// and the open-round cap closes them). Those are live rounds that failed and
    /// they must still increment `rfail`. A fix that only silences would leave this
    /// half at zero and be indistinguishable from deleting the counter.
    #[test]
    fn a_catch_up_lands_in_rback_while_a_lost_live_round_still_lands_in_rfail() {
        let (mut config, genesis, base) = rig("i105_catchup", true);
        // Verify-only: no committee keys, so this node never proposes and never
        // finalizes — the position a joiner or a just-restarted node is in.
        config.committee_key_paths.clear();
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        node.set_mine_interval(Duration::ZERO);
        assert_eq!(node.finalized_height(), None, "no keys ⇒ nothing finalizes here");

        // ---- half 1: the tip jumps, THEN the ledger is told ------------------
        const CAUGHT_UP_TO: u64 = 200; // 25 cadence slots crossed in one step
        for _ in 0..CAUGHT_UP_TO {
            assert!(node.try_mine());
        }
        assert_eq!(node.tip_height(), CAUGHT_UP_TO);
        node.note_slots_reached();

        let line = node.telemetry_sample();
        assert_eq!(field(&line, "rounds"), "0", "no round happened at this node: {line}");
        assert_eq!(
            field(&line, "rfail"),
            "0",
            "the history it crossed is not a committee failure: {line}"
        );
        let backfilled: u64 = field(&line, "rback").parse().unwrap();
        assert!(backfilled > 0, "the slots it walked past are counted, as history: {line}");

        // …and every one of them left a trace with a verdict that names what it was.
        let lines = node.emit_rounds();
        assert_eq!(lines.len() as u64, backfilled, "one journal line per closed slot");
        assert!(
            lines.iter().all(|l| l.contains("why=backfill")),
            "a crossed slot says `backfill`, not `silent`: {lines:?}"
        );

        // ---- half 2: slots crossed AT the frontier, and lost ------------------
        // One block at a time with the cursor following it, which is what ordinary
        // operation looks like: the tip is on the slot when the ledger meets it.
        let live_slots = qlab_node::round::MAX_OPEN_ROUNDS as u64 + 2;
        for _ in 0..(live_slots * CHECKPOINT_CADENCE_BLOCKS) {
            assert!(node.try_mine());
            node.note_slots_reached();
        }
        let line = node.telemetry_sample();
        let failed: u64 = field(&line, "rfail").parse().unwrap();
        let closed: u64 = field(&line, "rounds").parse().unwrap();
        let backfilled_now: u64 = field(&line, "rback").parse().unwrap();
        assert!(failed > 0, "a live round this node lost MUST still raise the alarm: {line}");
        assert_eq!(closed, failed, "this node holds no keys, so none of them finalized: {line}");
        assert!(
            backfilled_now > backfilled,
            "the rounds the catch-up left open close as what they were, not as failures: {line}"
        );

        // **The accounting closes.** Every cadence slot the node ever crossed is in
        // exactly one of three places — a live round, history, or still open — and
        // the sum is the slot count. Before #105 the first bucket held all of them.
        let still_open = node.p2p().node().rounds().open_len() as u64;
        let crossed = node.tip_height() / CHECKPOINT_CADENCE_BLOCKS;
        assert_eq!(
            closed + backfilled_now + still_open,
            crossed,
            "slots crossed = {crossed}, accounted = {closed} live + {backfilled_now} history \
             + {still_open} open: {line}"
        );

        let live_lines = node.emit_rounds();
        assert!(
            live_lines.iter().any(|l| l.contains("why=silent")),
            "a live round with no votes is `silent` — that diagnosis is not deleted: {live_lines:?}"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// The scrape carries the same split, with its caliper in the `HELP` text — the
    /// two instruments must not be able to disagree about what `rfail` covers.
    #[test]
    fn the_scrape_declares_the_backfill_verdict_and_states_the_caliper() {
        let (config, genesis, base) = rig("i105_scrape", true);
        let node = RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        let text = node.metrics_text();
        assert!(
            text.contains("qumbra_checkpoint_rounds_total{verdict=\"backfill\"} 0"),
            "the series is pre-declared, so an alert can be written against it: {text}"
        );
        assert!(
            text.contains("EXCLUDES backfill"),
            "the caliper travels with the number, not in a runbook: {text}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// 🔴 **Issue #188 baton 2, scope item 2: the deployed binary serves it.**
    ///
    /// Not "the endpoint returns bytes" — this asserts the composition that did not
    /// exist. Before this the binary bound no discovery listener at all and
    /// composed no `NodeRpc`, so a `/v1/compact` reading committed bytes would have
    /// been a fix inside a type nothing constructs.
    ///
    /// The chain here is coinbase-only (`rig` mines with `KeccakPow`), so every
    /// served block carries zero groups — which is the *correct* answer under D5
    /// and is exactly what the endpoint must say about a T0-shaped net. The
    /// recipient-finds-its-output half needs a transaction and lives in
    /// `tests/discovery_serving.rs`.
    #[test]
    fn discovery_endpoint_serves_the_binarys_own_chain_over_a_real_socket() {
        let (config, genesis, base) = rig("discovery-endpoint", true);
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        node.set_mine_interval(Duration::ZERO);
        for _ in 0..3 {
            assert!(node.try_mine());
        }

        let bound = node.start_discovery_endpoint("127.0.0.1:0").expect("bind ephemeral");
        assert_eq!(node.discovery_addr(), Some(bound));

        let body = {
            use std::io::{Read, Write};
            let mut s = std::net::TcpStream::connect(bound).unwrap();
            write!(
                s,
                "GET /v1/compact?from=0&to=99 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
            let mut raw = Vec::new();
            s.read_to_end(&mut raw).unwrap();
            raw
        };
        let head = String::from_utf8_lossy(&body[..body.windows(4).position(|w| w == b"\r\n\r\n").unwrap()]).to_string();
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        let sep = body.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let blocks = qlab_cbserver::codec::decode_compact_response(&body[sep..])
            .expect("the served bytes are the ratified compact wire");
        assert_eq!(blocks.len(), 4, "genesis + 3 mined blocks");
        assert_eq!(blocks[3].height, node.tip_height());
        assert!(
            blocks.iter().all(|b| b.groups.is_empty()),
            "a coinbase-only chain carries no discovery groups — D5, and the honest answer"
        );

        // The projection follows the chain on the run loop's own cadence: one more
        // block, one more served height, no restart and no request-time chain walk.
        assert!(node.try_mine());
        assert!(node.refresh_discovery(), "a moved tip re-projects");
        assert!(!node.refresh_discovery(), "an unchanged tip does no work");
        assert_eq!(node.discovery_view().tip_height(), Some(node.tip_height()));
        let _ = std::fs::remove_dir_all(&base);
    }

    /// 🔴 **Issue #275 seam 1, the acceptance shape: the deployed binary takes a
    /// wallet's transaction over a real socket, judges it BEFORE announcing, and
    /// answers by name — through the real run loop, not a harness stand-in.**
    ///
    /// One node plays the whole cast: it finalizes its own genesis-era root
    /// (all-21 rig), serves the discovery listener, runs `run_until` on the main
    /// test thread while a client thread submits over TCP. The verifier is the
    /// rehearsal stand-in — the *real*-proof half of the gate is the same
    /// `Mempool::admit` proof arm `tests/coinbase_spend.rs` exercises against
    /// real STARKs, and what this test pins is everything around it: decode,
    /// prechecks, typed verdicts, the queue crossing, the pool re-read, and the
    /// duplicate answer that makes retry safe.
    #[test]
    fn the_submit_route_judges_over_a_real_socket_through_the_run_loop() {
        use qlab_devnet::body::{placeholder_discovery, TxPublic};
        use qlab_devnet::fees::{posted_fee, ArityBucket};

        let (config, genesis, base) = rig("i275-submit", true);
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        node.set_mine_interval(Duration::ZERO);

        // Finalize: mine to the first checkpoint slot; the rig holds all 21 keys.
        node.try_checkpoint();
        for _ in 0..CHECKPOINT_CADENCE_BLOCKS + CHECKPOINT_SIGN_HYSTERESIS_BLOCKS {
            assert!(node.try_mine());
            node.note_slots_reached();
            node.try_checkpoint();
        }
        assert!(node.finalized_height().is_some(), "the all-21 rig finalizes");
        use qlab_node::NodeState as _;
        let anchor = node.state().commitment_root();
        assert!(
            node.state().is_valid_anchor(&anchor),
            "the finalized (still-empty) root is a valid anchor"
        );

        // Idle the miner so the loop's iterations are pump + drain, then serve.
        node.set_mine_interval(Duration::from_secs(3600));
        let addr = node.start_discovery_endpoint("127.0.0.1:0").expect("bind ephemeral");

        let fee = posted_fee(ArityBucket::TwoByTwo);
        let tx_for = |nf: u8, fee: u64, bind: bool| {
            let commitments = vec![[nf.wrapping_add(1); 32]];
            let discovery = if bind {
                placeholder_discovery(&commitments)
            } else {
                // A group binding a DIFFERENT commitment: §4 rule 2 must refuse it.
                placeholder_discovery(&[[0xEE; 32]])
            };
            TxEntry {
                proof: b"rehearsal-accepts-anything".to_vec(),
                public: TxPublic {
                    anchor,
                    nullifiers: vec![[nf; 32]],
                    commitments,
                    bucket: ArityBucket::TwoByTwo,
                    fee,
                },
                discovery,
                rider: TxEntry::absent_rider(),
            }
        };
        let wire_ok = qlab_p2p::codec::encode_tx(&tx_for(1, fee, true));
        let wire_cheap = qlab_p2p::codec::encode_tx(&tx_for(2, 1, true));
        let wire_unbound = qlab_p2p::codec::encode_tx(&tx_for(3, fee, false));

        // The client, on its own thread against the real socket; the node's run
        // loop — the thing that answers — runs on this one.
        let shutdown = Arc::new(AtomicBool::new(false));
        let client_shutdown = Arc::clone(&shutdown);
        let client = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let post = |body: &[u8]| {
                let mut s = std::net::TcpStream::connect(addr).unwrap();
                write!(
                    s,
                    "POST /v1/tx HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .unwrap();
                s.write_all(body).unwrap();
                let mut raw = Vec::new();
                s.read_to_end(&mut raw).unwrap();
                let sep = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
                (
                    String::from_utf8_lossy(&raw[..sep]).lines().next().unwrap().to_string(),
                    String::from_utf8_lossy(&raw[sep + 4..]).to_string(),
                )
            };
            let accepted = post(&wire_ok);
            let duplicate = post(&wire_ok);
            let cheap = post(&wire_cheap);
            let unbound = post(&wire_unbound);
            let leaves = {
                let mut s = std::net::TcpStream::connect(addr).unwrap();
                write!(s, "GET /v1/tree/leaves?from=0 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
                let mut raw = Vec::new();
                s.read_to_end(&mut raw).unwrap();
                let sep = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
                raw[sep + 4..].to_vec()
            };
            // …and the anchor route beside it (issue #276). This is the ONLY
            // place `/v1/anchors` is exercised off a real `RunningNode`: the
            // projection is unit-tested against a mined chain and the route is
            // tested against a hand-built snapshot, and neither would notice if
            // `start_discovery_server` failed to hand the view to the server —
            // the deployed route would then serve an empty set forever.
            let anchors = {
                let mut s = std::net::TcpStream::connect(addr).unwrap();
                write!(s, "GET /v1/anchors HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                    .unwrap();
                let mut raw = Vec::new();
                s.read_to_end(&mut raw).unwrap();
                let sep = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
                raw[sep + 4..].to_vec()
            };
            client_shutdown.store(true, Ordering::Relaxed);
            (accepted, duplicate, cheap, unbound, leaves, anchors)
        });
        node.run_until(&shutdown);
        let (accepted, duplicate, cheap, unbound, leaves, anchors) = client.join().unwrap();

        // 202 + the statement tx id — the id NodeRpc::submit_tx would answer.
        let ok_tx = tx_for(1, fee, true);
        let expected_id = qlab_node::rpc::tx_id(
            &ok_tx.public.anchor,
            &ok_tx.public.nullifiers,
            &ok_tx.public.commitments,
            ok_tx.public.bucket.logical_actions(),
            ok_tx.public.fee,
        );
        let expected_hex: String = expected_id.iter().map(|b| format!("{b:02x}")).collect();
        assert!(accepted.0.starts_with("HTTP/1.1 202"), "{accepted:?}");
        assert_eq!(accepted.1, format!("accepted {expected_hex}"));

        // The same bytes again: 200 duplicate, same id — retry after a timeout
        // is safe by construction.
        assert!(duplicate.0.starts_with("HTTP/1.1 200"), "{duplicate:?}");
        assert_eq!(duplicate.1, format!("duplicate {expected_hex}"));

        // The named refusals, through the whole stack.
        assert!(cheap.0.starts_with("HTTP/1.1 400"), "{cheap:?}");
        assert_eq!(cheap.1, format!("refused: wrong-fee expected={fee} got=1"));
        assert!(unbound.0.starts_with("HTTP/1.1 400"), "{unbound:?}");
        assert!(unbound.1.starts_with("refused: discovery-does-not-bind"), "{unbound:?}");

        // What IS pooled is exactly the accepted transaction.
        assert_eq!(node.p2p().node().mempool().len(), 1, "one admission, one pool entry");

        // And the leaf stream served alongside: the versioned wire, honestly
        // empty — no coinbase has matured on this young chain, so the tree HAS
        // no leaves, and `total = 0` is the true answer (the served-order and
        // root-reconstruction properties are locked in qlab-node's route tests).
        let page = qlab_node::TreeLeaves::from_bytes(&leaves)
            .expect("the served bytes are the versioned leaf wire");
        assert_eq!(page.total, 0);
        assert!(page.leaves.is_empty());

        // And the anchor route, off the SAME live binary (issue #276): the
        // wallet's own decoder reads it, and what it carries is the node's real
        // anchor set — the finalized (still-empty) root this test already
        // asserted `is_valid_anchor` for above. An empty `roots` here would mean
        // the projection never reached the server, which is the one wiring
        // failure both halves' own tests are blind to.
        let served = qlab_node::AnchorSet::from_bytes(&anchors)
            .expect("the served bytes are the AnchorSet wire");
        assert_eq!(
            served,
            qlab_node::anchor_set(node.p2p().node().state()),
            "the route serves anchor_set's own output — one derivation, not a second"
        );
        assert!(
            served.roots.contains(&anchor),
            "the finalized root this test spent its transactions against is served as an anchor"
        );
        assert_eq!(served.finalized_height, node.finalized_height());

        let _ = std::fs::remove_dir_all(&base);
    }

    /// The anchor projection (issue #276), and the property that made the route
    /// necessary: **the newest valid anchor is not the tip root** once the chain
    /// runs ahead of its finality. A wallet building at the leaf count it just
    /// synced to would declare that tip root and be refused `anchor-not-valid`;
    /// this is where it learns which root it may actually use.
    #[test]
    fn the_anchor_snapshot_serves_finalized_roots_and_refreshes_on_finality() {
        let (config, genesis, base) = rig("anchors", true);
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        node.set_mine_interval(Duration::ZERO);

        // Mine PAST coinbase maturity, so leaves actually accrue: from height
        // COINBASE_MATURITY_BLOCKS on, every block appends the coinbase leaf it
        // matures (issue #102's append schedule). Below that the tree is empty
        // at every height, every height shares the empty root, and the tip root
        // is trivially the finalized root — which is exactly the degenerate
        // case that hid this whole problem.
        node.try_checkpoint();
        for _ in 0..qlab_node::COINBASE_MATURITY_BLOCKS + CHECKPOINT_CADENCE_BLOCKS * 2 {
            assert!(node.try_mine());
            node.note_slots_reached();
            node.try_checkpoint();
        }

        assert!(node.refresh_anchors(), "the first projection publishes");
        assert!(!node.refresh_anchors(), "an unchanged (tip, finalized) costs nothing");

        let served = qlab_node::AnchorSet::from_bytes(&node.anchors_view().encoded)
            .expect("the snapshot holds the AnchorSet wire");
        let state = node.p2p().node().state();
        assert_eq!(
            served,
            qlab_node::anchor_set(state),
            "the snapshot IS anchor_set's output — one derivation, not a second one"
        );

        let fin = served.finalized_height.expect("something finalized");
        assert!(served.tip_height > fin, "the chain is ahead of its finality — the real case");
        assert!(!served.roots.is_empty(), "and it has anchors to offer");

        // 🔴 The finding, at the node: the tip root is NOT among the anchors.
        let tip_root = qlab_node::main_chain_roots_of(state)
            .last()
            .map(|(_, r)| *r)
            .expect("a tip root exists");
        assert!(
            !served.roots.contains(&tip_root),
            "the tip root must NOT be a valid anchor while tip {} is ahead of finalized {fin} — \
             this is exactly why a wallet cannot build at the leaf count it just synced to",
            served.tip_height
        );

        // Every served root IS a main-chain root at a finalized height.
        let finalized_roots: Vec<qlab_node::Hash32> = qlab_node::main_chain_roots_of(state)
            .into_iter()
            .filter(|(h, _)| *h <= fin)
            .map(|(_, r)| r)
            .collect();
        for root in &served.roots {
            assert!(finalized_roots.contains(root), "a served anchor is a finalized main-chain root");
        }

        // Finality moving — with or without the tip moving — must republish, or
        // a wallet waiting for its anchor would poll a snapshot that never
        // changes across the one event it is waiting for.
        for _ in 0..CHECKPOINT_CADENCE_BLOCKS {
            assert!(node.try_mine());
            node.note_slots_reached();
            node.try_checkpoint();
        }
        assert!(node.refresh_anchors(), "a moved chain republishes");
        let later = qlab_node::AnchorSet::from_bytes(&node.anchors_view().encoded).unwrap();
        assert!(
            later.finalized_height.unwrap() > fin,
            "finality advanced and the served set followed it"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// The scrape endpoint, end to end over a real socket, serving live node state.
    #[test]
    fn metrics_endpoint_serves_live_state_and_is_off_by_default() {
        let (config, genesis, base) = rig("metrics", true);
        assert!(config.metrics_addr.is_none(), "no listener unless the operator asks");
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        node.set_mine_interval(Duration::ZERO);
        node.try_checkpoint();
        for _ in 0..CHECKPOINT_CADENCE_BLOCKS + CHECKPOINT_SIGN_HYSTERESIS_BLOCKS {
            assert!(node.try_mine());
            node.note_slots_reached();
            node.try_checkpoint();
        }
        node.emit_rounds();
        node.accumulate_regime();

        let bound = node.start_metrics_endpoint("127.0.0.1:0").expect("bind ephemeral");
        let body = {
            use std::io::{Read, Write};
            let mut s = std::net::TcpStream::connect(bound).unwrap();
            write!(s, "GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
            let mut out = String::new();
            s.read_to_string(&mut out).unwrap();
            out
        };
        assert!(body.starts_with("HTTP/1.1 200"), "{body}");
        assert!(body.contains("text/plain; version=0.0.4"));
        // Live levels… (tip carries the #269 hysteresis past the finalized slot)
        let mined = CHECKPOINT_CADENCE_BLOCKS + CHECKPOINT_SIGN_HYSTERESIS_BLOCKS;
        assert!(body.contains(&format!("qumbra_tip_height {mined}")), "{body}");
        assert!(body.contains("qumbra_committee_quorum 15"));
        assert!(body.contains("qumbra_committee_size 21"));
        assert!(body.contains("qumbra_finality_regime{regime=\"final\"} 1"));
        // …and the accumulated, source-side aggregates.
        assert!(body.contains("qumbra_checkpoint_rounds_total{verdict=\"finalized\"} 1"));
        assert!(body.contains(&format!("qumbra_blocks_connected_total {mined}")));
        assert!(body.contains("qumbra_finality_advance_blocks_bucket"));
        assert!(body.contains("qumbra_process_start_time_seconds "));
        let _ = std::fs::remove_dir_all(&base);
    }

    /// **Issues #117/#121, end to end**: the `/v1/telemetry` endpoint over a real
    /// socket, serving a real node's live checkpoint, committee and supply state.
    ///
    /// This is the surface that did not exist before this change: the binary bound
    /// no RPC listener at all, so an operator view had nothing to poll. The test
    /// asserts the endpoint is off unless configured, the bytes decode at `0x03`,
    /// `fid` equals the finality tracker's own identity, the committee aggregates
    /// are read from live state, and the incrementally accumulated scheduled
    /// issuance agrees exactly with the integer audit anchor.
    #[test]
    fn telemetry_endpoint_serves_v3_checkpoint_committee_and_supply() {
        let (config, genesis, base) = rig("telemetry-endpoint", true);
        assert!(config.telemetry_addr.is_none(), "no listener unless the operator asks");
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        node.set_mine_interval(Duration::ZERO);
        node.try_checkpoint();
        for _ in 0..CHECKPOINT_CADENCE_BLOCKS + CHECKPOINT_SIGN_HYSTERESIS_BLOCKS {
            assert!(node.try_mine());
            node.note_slots_reached();
            node.try_checkpoint();
        }
        let fid = node.finalized_checkpoint_id().expect("this rig finalizes");

        let bound = node.start_telemetry_endpoint("127.0.0.1:0").expect("bind ephemeral");
        let raw = {
            use std::io::{Read, Write};
            let mut s = std::net::TcpStream::connect(bound).unwrap();
            write!(s, "GET /v1/telemetry HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
            let mut out = Vec::new();
            s.read_to_end(&mut out).unwrap();
            out
        };
        let sep = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("header terminator");
        assert!(String::from_utf8_lossy(&raw[..sep]).starts_with("HTTP/1.1 200"));
        let served = Telemetry::from_bytes(&raw[sep + 4..]).expect("the versioned wire decodes");

        assert_eq!(served.to_bytes()[0], qlab_node::RPC_VERSION);
        assert_eq!(
            served.tip_height,
            CHECKPOINT_CADENCE_BLOCKS + CHECKPOINT_SIGN_HYSTERESIS_BLOCKS
        );
        assert_eq!(served.finalized_height, node.finalized_height());
        assert_eq!(served.finalized_id, Some(fid), "fid is on the wire, not just in the log line");
        assert_eq!(
            (served.committee_size, served.committee_active, served.committee_quorum),
            (21, 21, 15),
        );
        assert_eq!(served.supply.len(), 1, "all mined blocks remain in epoch 0");
        assert_eq!(
            (served.supply[0].start_height, served.supply[0].end_height),
            (0, CHECKPOINT_CADENCE_BLOCKS + CHECKPOINT_SIGN_HYSTERESIS_BLOCKS)
        );
        assert_eq!(served.supply[0].divergence_bessel(), 0);
        assert!(served.supply[0].measured_coinbase > 0, "the test covers real issuance");
        assert_eq!(served.fid_field(), node.telemetry().fid_field());
        assert_eq!(
            node.telemetry().supply,
            served.supply,
            "a second snapshot appends no duplicate heights"
        );
        // The endpoint and the stdout sample line report the SAME snapshot — they
        // read one `telemetry()`, so they cannot drift.
        let line = node.telemetry_sample();
        assert!(line.contains(&format!("fid={}", served.fid_field())), "{line}");
        assert!(line.contains(&format!("sid={}", served.sid_field())), "{line}");
        assert!(line.contains(&format!("sslot={}", served.sslot_field())), "{line}");

        let _ = std::fs::remove_dir_all(&base);
    }

    /// **The always-on write-volume caliper, derived rather than asserted by hand.**
    /// The round rate is set by the CHECKPOINT CADENCE, not by the block rate — the
    /// number that makes "always on" affordable on a 2 vCPU host.
    #[test]
    fn round_journal_volume_is_set_by_the_cadence_not_the_block_rate() {
        let block_time = GenesisFile::new_devnet_t0().frozen.block_time_secs; // 75 s, FROZEN
        let round_period_secs = CHECKPOINT_CADENCE_BLOCKS * block_time;
        assert_eq!(round_period_secs, 600, "cadence 8 × 75 s = one round per 10 minutes");
        let rounds_per_day = 86_400 / round_period_secs;
        assert_eq!(rounds_per_day, 144);
        // One line per closed round, at the byte budget pinned in
        // `qlab_node::round`'s own test (≤ 400 B for a fully-populated 21-member
        // round). The quoted daily figure follows from those two numbers alone.
        const LINE_BUDGET_BYTES: u64 = 400;
        let bytes_per_day = rounds_per_day * LINE_BUDGET_BYTES;
        assert!(bytes_per_day <= 60_000, "round journal is {bytes_per_day} B/day");
    }

    // ================== issue #369: the committee-to-halt drill ==================
    //
    // 2026-08-12's live boundary (height 8,640) produced three consensus defects in
    // one morning, and every offline drill this repo had was structurally blind to
    // all three: the #74 drills exercise release/marker/validation seams on a SINGLE
    // node, and every committee test — including the M10-T0-2 recovery e2e in
    // `qlab_p2p::adapter` this drill was first pointed at — hand-drives
    // `try_checkpoint` over an in-process, hand-relayed pair of adapters. A drill
    // that hands the committee its own proposals cannot see a committee that never
    // proposes, which is exactly how #360 stayed invisible until a real halt.
    //
    // These three cases run a committee TO a halt and through it, over the real TCP
    // mesh harness the #83/#106 tests already use (`rig` + `free_port` + the real
    // `run_until_with` loop), with the committee keys **split so that no node holds
    // quorum** (stamp S1).
    //
    // **Nothing here calls `try_checkpoint` or `maintain_boundary_checkpoint`**
    // (stamp S2). Every checkpoint in every case below is proposed by the production
    // run loop; `spin` drives that loop and nothing else.

    use qlab_p2p::n1::CheckpointIngest; // `checkpoint_variants_at` — the real tally

    type DrillNode = RunningNode<KeccakPow, DevnetRehearsalVerifier>;

    /// The deployed T0 key split — 6/5/5/5 over the genesis committee's 21 keys.
    ///
    /// **Stamp S1 is this array.** Quorum is 15; the largest share is 6; so no
    /// single node can finalize anything on its own, and every finalization these
    /// cases assert is a real cross-node accumulation over the wire. The 6 is on
    /// index 1 rather than index 0 deliberately: index 0 is D1's miner, and putting
    /// the *small* share on the one host whose mining-gated `try_checkpoint` still
    /// fires makes D1's mutation check strictly harder to pass by accident.
    const KEY_SHARES: [usize; 4] = [5, 6, 5, 5];

    /// Drive `node`'s **real** run loop for exactly `iters` iterations.
    ///
    /// This is the whole point of the drill's driver: it is [`RunningNode::
    /// run_until_with`] — the production event loop, with the production mining
    /// branch, the production `maintain_boundary_checkpoint` call and the production
    /// re-push cadence — stopped by its own `shutdown` flag from the per-iteration
    /// hook. The drill therefore *pumps* the loop (which stamp S2 permits) and never
    /// substitutes for it.
    fn spin(node: &mut DrillNode, iters: usize) {
        let stop = AtomicBool::new(false);
        let mut n = 0usize;
        node.run_until_with(&stop, |_| {
            n += 1;
            if n >= iters {
                stop.store(true, Ordering::Relaxed);
            }
        });
    }

    /// One bounded spin on every node, `rounds` times — the mesh's propagation pump.
    fn spin_all(nodes: &mut [DrillNode], rounds: usize, iters: usize) {
        for _ in 0..rounds {
            for n in nodes.iter_mut() {
                spin(n, iters);
            }
        }
    }

    /// Spin the mesh until `done` holds, or fail with `what` after `rounds` tries.
    fn spin_until(
        nodes: &mut [DrillNode],
        rounds: usize,
        what: &str,
        done: impl Fn(&[DrillNode]) -> bool,
    ) {
        for _ in 0..rounds {
            if done(nodes) {
                return;
            }
            spin_all(nodes, 1, 2);
        }
        assert!(
            done(nodes),
            "{what} — tips {:?}, finalized {:?}",
            nodes.iter().map(|n| n.tip_height()).collect::<Vec<_>>(),
            nodes.iter().map(|n| n.finalized_height()).collect::<Vec<_>>(),
        );
    }

    /// A drill rig for node `i`: [`rig`]'s temp dir + genesis + the 21 key files,
    /// with only this node's SHARE of the keys configured and the mining cadence
    /// parked so the drill — not the wall clock — decides who mines when.
    ///
    /// `peers` is written into `dial_peers`, so an empty slice is a node that starts
    /// **into a not-yet-connected mesh** (D2's staging) and a full slice is the
    /// mesh `deploy/deploy.sh` writes (D1's).
    fn drill_node(
        tag: &str,
        i: usize,
        listen: &str,
        peers: &[String],
        mining: bool,
    ) -> (DrillNode, PathBuf) {
        let (mut cfg, genesis, base) = rig(&format!("{tag}_{i}"), mining);
        let lo: usize = KEY_SHARES[..i].iter().sum();
        cfg.committee_key_paths = cfg.committee_key_paths[lo..lo + KEY_SHARES[i]].to_vec();
        cfg.listen_addr = listen.to_string();
        cfg.advertise_addr = Some(listen.to_string());
        cfg.dial_peers = peers.to_vec();
        let mut node = RunningNode::start_with_release(
            &cfg, &genesis, KeccakPow, DevnetRehearsalVerifier, armed_release(),
        )
        .unwrap();
        // Parked, not zero: the drill opens this gate for exactly one block at a
        // time (see `mine_one`). A live net randomises the mining order; the drill
        // fixes it, because the tip race is D3's subject and racing it in D1/D2
        // would make them nondeterministic rather than realistic.
        node.set_mine_interval(Duration::from_secs(3_600));
        (node, base)
    }

    /// Four loopback addresses and the full mesh each node dials (everyone but
    /// itself) — the shape `deploy/deploy.sh` writes onto the four T0 hosts.
    fn mesh_addrs() -> (Vec<String>, Vec<Vec<String>>) {
        let addrs: Vec<String> =
            (0..4).map(|_| format!("127.0.0.1:{}", free_port())).collect();
        let peers = (0..4)
            .map(|i| {
                addrs
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i)
                    .map(|(_, a)| a.clone())
                    .collect()
            })
            .collect();
        (addrs, peers)
    }

    /// Open node `m`'s mining gate for **one** block and let the mesh catch up.
    /// The checkpoint that block's miner proposes is proposed by the loop's own
    /// mining branch — the drill never calls `try_checkpoint`.
    fn mine_one(nodes: &mut [DrillNode], m: usize, height: u64) {
        nodes[m].set_mine_interval(Duration::ZERO);
        for _ in 0..40 {
            if nodes[m].tip_height() >= height {
                break;
            }
            spin(&mut nodes[m], 1);
        }
        nodes[m].set_mine_interval(Duration::from_secs(3_600));
        assert_eq!(nodes[m].tip_height(), height, "node {m} mined block {height}");
        spin_until(nodes, 60, &format!("block {height} reached the whole mesh"), |ns| {
            ns.iter().all(|n| n.tip_height() == height)
        });
    }

    /// Every node's committed variant at the boundary slot, read from the
    /// never-double-sign LEDGERS (issue #84's `local_commitment`) — the record a
    /// split forensic actually reads.
    fn commitments(nodes: &[DrillNode]) -> Vec<Option<u64>> {
        nodes.iter().map(|n| n.local_commitment().and_then(|c| c.id)).collect()
    }

    /// **DRILL D1 — committee to a halt, finalized by the LOOP path alone.**
    ///
    /// Four nodes over real loopback TCP, committee keys 5/6/5/5 so **no node holds
    /// quorum** (15 of 21). The mesh mines to the drill boundary and stops there;
    /// nothing in this test proposes a checkpoint, and the boundary still finalizes,
    /// unanimously, from `maintain_boundary_checkpoint` plus gossip.
    ///
    /// **The mutation check (stamp S4).** Revert #361 — make
    /// `maintain_boundary_checkpoint` a no-op — and this test fails at the boundary
    /// assertion with `final=8`: the only slot-16 votes that exist are the 5 the
    /// miner of block 16 cast through the still-reachable mining-gated route, and 5
    /// is not 15. That residue is not an artifact of the fixture; it is the live
    /// 8,640 halt in miniature (16 of 21 keys signed, no tally ever holding 15).
    #[test]
    fn d1_a_split_committee_mines_to_a_halt_and_the_loop_finalizes_the_boundary() {
        let (addrs, peers) = mesh_addrs();
        let mut bases = Vec::new();
        let mut nodes: Vec<DrillNode> = Vec::new();
        for i in 0..4 {
            let (n, base) = drill_node("i369_d1", i, &addrs[i], &peers[i], true);
            nodes.push(n);
            bases.push(base);
        }

        // S1, asserted rather than assumed: the quorum is 15 and the largest share
        // is 6, so no single node here can finalize anything by itself.
        let quorum = GenesisFile::new_devnet_t0().frozen.quorum as usize;
        assert_eq!(quorum, 15);
        for (i, share) in KEY_SHARES.iter().enumerate() {
            assert!(*share < quorum, "node {i} holds {share} keys, quorum is {quorum}");
        }
        assert_eq!(KEY_SHARES.iter().sum::<usize>(), 21, "the whole committee is placed");

        // The mesh forms and every node clears the #106 readiness gate on a real
        // claim (best_height 0 received, not defaulted).
        spin_until(&mut nodes, 60, "the mesh handshakes", |ns| {
            ns.iter().all(|n| n.mine_gate() == MineGate::Synced)
        });

        // Mine to the boundary, one block at a time, rotating the miner so every
        // key-holder's mining-gated `try_checkpoint` fires on its own turn — which
        // is how the sub-boundary cadence slots get votes from four separate hosts.
        for h in 1..=DH {
            mine_one(&mut nodes, ((h - 1) % 4) as usize, h);
        }

        // Sub-boundary finality formed ACROSS the split: slot 8 needed 15 keys and
        // no node had more than 6, so this number could only have come off the wire.
        spin_until(&mut nodes, 120, "slot 8 finalized across the split committee", |ns| {
            ns.iter().all(|n| n.finalized_height() >= Some(CHECKPOINT_CADENCE_BLOCKS))
        });

        // Every node is halted at the boundary and no node mines again.
        for (i, n) in nodes.iter_mut().enumerate() {
            assert_eq!(n.tip_height(), DH, "node {i} at the boundary");
            assert!(n.is_halted(), "node {i} halted");
            n.set_mine_interval(Duration::ZERO);
            assert!(!n.try_mine(), "node {i}: a halted node never mines again");
            n.set_mine_interval(Duration::from_secs(3_600));
        }

        // 🔴 THE PROPERTY. Nothing below this line proposes a checkpoint: the loop's
        // own `maintain_boundary_checkpoint` does, and gossip carries the rest.
        spin_until(&mut nodes, 120, "the boundary finalized via the loop path", |ns| {
            ns.iter().all(|n| n.finalized_height() == Some(DH))
        });

        let fid = nodes[0].finalized_checkpoint_id().expect("a finalized boundary");
        for (i, n) in nodes.iter().enumerate() {
            assert_eq!(n.finalized_height(), Some(DH), "node {i} finalized the boundary");
            assert_eq!(n.finalized_checkpoint_id(), Some(fid), "node {i}: fid unanimous");
            assert_eq!(n.finality_backing_field(), "local", "node {i} holds the block it finalized");
            let line = n.telemetry_sample();
            assert!(line.contains("regime=Halted"), "node {i}: {line}");
        }
        // …and the keys that DID commit at the boundary slot are quorum-many and
        // all on the one variant.
        //
        // Not "all 21": the drill measured `have=16 need=15 absent=11..15` — the
        // quorum formed from three hosts' shares and the fourth's
        // `maintain_boundary_checkpoint` then correctly went inert, because the
        // boundary it would have proposed for was already finalized. A drill that
        // demanded 21 would be asserting a race it does not control.
        let on_boundary: usize = nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| {
                n.local_commitment().is_some_and(|c| c.slot == DH && c.id == Some(fid))
            })
            .map(|(i, _)| KEY_SHARES[i])
            .sum();
        assert!(on_boundary >= quorum, "{on_boundary} keys committed to the boundary variant");
        for (i, n) in nodes.iter().enumerate() {
            if let Some(c) = n.local_commitment() {
                if c.slot == DH {
                    assert_eq!(c.id, Some(fid), "node {i} committed to a DIFFERENT variant");
                }
            }
        }

        for (n, base) in nodes.into_iter().zip(bases) {
            drop(n);
            let _ = std::fs::remove_dir_all(&base);
        }
    }

    /// Copy `donor`'s chain files into `dirs` — the transplant path that
    /// `a_snapshotless_host_rejoins_by_snapshot_transplant` already locks
    /// (`persist::Snapshot` is pure chain state, no node identity).
    ///
    /// D2 and D3 need four nodes standing at the boundary **without ever having
    /// been connected to each other**, which is the one state a mesh cannot mine
    /// itself into: propagation is what a mesh does. So the chain is mined once, by
    /// a node that is genuinely alone, and handed to the others the way the #359
    /// runbook hands one to a rescued host.
    fn transplant(donor: &std::path::Path, dirs: &[std::path::PathBuf]) {
        for d in dirs {
            std::fs::create_dir_all(d).unwrap();
            for f in [qlab_node::SNAPSHOT, qlab_node::BLOCK_LOG] {
                std::fs::copy(donor.join(f), d.join(f)).unwrap();
            }
        }
    }

    /// Mine a lone chain to `to` and return its data dir + the temp base. The miner
    /// holds NO committee keys, so nothing it does puts a vote anywhere.
    fn lone_chain(tag: &str, to: u64, rkm: Option<&str>) -> (std::path::PathBuf, PathBuf) {
        let (mut cfg, genesis, base) = rig(tag, true);
        cfg.committee_key_paths = vec![]; // verify-only: mines, never signs
        cfg.miner_rkm = rkm.map(|s| s.to_string());
        assert!(cfg.dial_peers.is_empty(), "genuinely alone (#106's `Alone` branch)");
        let mut n = RunningNode::start_with_release(
            &cfg, &genesis, KeccakPow, DevnetRehearsalVerifier, armed_release(),
        )
        .unwrap();
        n.set_mine_interval(Duration::ZERO);
        for _ in 0..to {
            assert!(n.try_mine(), "the lone miner extends its own chain");
        }
        assert_eq!(n.tip_height(), to);
        n.save_snapshot().unwrap();
        drop(n);
        (cfg.data_dir, base)
    }

    /// Connect a set of already-running, unconnected nodes into a full mesh
    /// **without restarting any of them** — the #83 learn + maintain path.
    fn connect_mesh(nodes: &mut [DrillNode], addrs: &[String]) {
        for (i, n) in nodes.iter_mut().enumerate() {
            let others: Vec<String> = addrs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, a)| a.clone())
                .collect();
            n.p2p.addrs_mut().learn(others);
        }
        // Outbound connects are asynchronous since #132: one `maintain` pass STARTS
        // a dial (`DialStart::Pending`) and a later one finishes it, so the mesh
        // needs several passes plus pumping in between — not one call.
        for _ in 0..60 {
            if nodes.iter().all(|n| n.p2p().addrs().dialable_count() >= 2) {
                break;
            }
            for n in nodes.iter_mut() {
                n.force_redial_ready();
                n.maintain_peers();
            }
            spin_all(nodes, 1, 2);
        }
        // Two outbound edges per node is enough and is what this harness reliably
        // produces: minimum degree 2 on four vertices is a CONNECTED graph, and the
        // vote relay is transitive (a peer whose tally grows pushes onward), so
        // every set reaches every node. Demanding a complete graph would be
        // asserting a property of the dial scheduler, which is not what is on trial
        // here — and the cascade assertion below fails loudly if reachability is in
        // fact short.
        for (i, n) in nodes.iter().enumerate() {
            assert!(
                n.p2p().addrs().dialable_count() >= 2,
                "node {i} reached {} peers — the mesh is not connected",
                n.p2p().addrs().dialable_count(),
            );
        }
    }

    /// **DRILL D2 — vote islands, and the REPUSH cadence that bridges them.**
    ///
    /// The #362 defect, staged as it happened: four halted processes come up one at
    /// a time into a mesh that is not connected yet, each signs the boundary and
    /// fires its ONE growth-gated push into the void, and the result is four stable
    /// islands holding 21 signatures between them with no tally holding 15. The
    /// mesh then connects and **nothing happens** — the relay is growth-gated and
    /// nothing grows. Only the re-push cadence can move it.
    ///
    /// **The mutation check (stamp S4).** Stub `P2pNode::repush_slot_votes` to push
    /// nothing (`return 0`) and this test fails at the cascade assertion: the
    /// islands stay exactly where the first phase left them, which is the whole
    /// finding — the live net sat in that state for hours with 16 of 21 keys signed.
    #[test]
    fn d2_restart_islands_are_bridged_by_the_boundary_repush_cascade() {
        let (donor, donor_base) = lone_chain("i369_d2_donor", DH, None);
        let (addrs, _) = mesh_addrs();

        // Four hosts, each on the boundary chain, each with its own key share, each
        // configured to dial NOBODY — the staggered-restart window, held open.
        let mut bases = Vec::new();
        let mut dirs = Vec::new();
        let mut nodes: Vec<DrillNode> = Vec::new();
        for i in 0..4 {
            let (mut cfg, genesis, base) = rig(&format!("i369_d2_{i}"), true);
            let lo: usize = KEY_SHARES[..i].iter().sum();
            cfg.committee_key_paths = cfg.committee_key_paths[lo..lo + KEY_SHARES[i]].to_vec();
            cfg.listen_addr = addrs[i].clone();
            cfg.advertise_addr = Some(addrs[i].clone());
            transplant(&donor, &[cfg.data_dir.clone()]);
            let mut n = RunningNode::start_with_release(
                &cfg, &genesis, KeccakPow, DevnetRehearsalVerifier, armed_release(),
            )
            .unwrap();
            n.set_mine_interval(Duration::from_secs(3_600));
            assert_eq!(n.tip_height(), DH, "node {i} opened on the transplanted boundary");
            assert!(n.is_halted());
            // Sequenced: this node runs its loop — signs the boundary, pushes to the
            // zero peers it has — before the next one is even started.
            spin(&mut n, 4);
            dirs.push(cfg.data_dir.clone());
            bases.push(base);
            nodes.push(n);
        }

        // Each island holds exactly its own share, and 21 signatures exist in total
        // with no tally anywhere holding 15.
        let quorum = GenesisFile::new_devnet_t0().frozen.quorum as usize;
        for (i, n) in nodes.iter().enumerate() {
            let variants = n.p2p().node().checkpoint_variants_at(DH);
            assert_eq!(variants.len(), 1, "node {i}: one variant, its own");
            assert_eq!(variants[0].1.len(), KEY_SHARES[i], "node {i}: its own share, stranded");
            assert!(variants[0].1.len() < quorum, "node {i} is an island, not a quorum");
            assert_eq!(n.finalized_height(), None, "node {i}: the boundary is unfinalized");
        }

        // The mesh connects — and the islands do NOT merge, because the relay fires
        // on tally GROWTH and nothing here grows. This is #362, reproduced.
        connect_mesh(&mut nodes, &addrs);
        spin_all(&mut nodes, 12, 3);
        for (i, n) in nodes.iter().enumerate() {
            assert_eq!(
                n.p2p().node().checkpoint_variants_at(DH)[0].1.len(),
                KEY_SHARES[i],
                "🔴 node {i}: connectivity alone bridges nothing — the islands are stable",
            );
            assert_eq!(n.finalized_height(), None, "node {i}: still unfinalized after connecting");
        }

        // 🔴 THE PROPERTY. The #362 cadence, and nothing else, puts the stranded
        // signatures back on the wire. (The seam is the drill's only production
        // change — S3; at the shipped 60 s this same cascade takes minutes, which
        // is what the live net measured.)
        for n in nodes.iter_mut() {
            n.set_repush_interval(Duration::ZERO);
        }
        spin_until(&mut nodes, 120, "the re-push cascade finalized the boundary", |ns| {
            ns.iter().all(|n| n.finalized_height() == Some(DH))
        });

        let fid = nodes[0].finalized_checkpoint_id().expect("a finalized boundary");
        for (i, n) in nodes.iter().enumerate() {
            assert_eq!(n.finalized_checkpoint_id(), Some(fid), "node {i}: fid unanimous");
            assert!(n.telemetry_sample().contains("regime=Halted"), "node {i}");
        }
        assert_eq!(commitments(&nodes), vec![Some(fid); 4], "one variant, 21 keys");

        for (n, base) in nodes.into_iter().zip(bases) {
            drop(n);
            let _ = std::fs::remove_dir_all(&base);
        }
        let _ = std::fs::remove_dir_all(&donor_base);
    }

    /// **DRILL D3 — the frozen tip tie at the boundary.**
    ///
    /// Two miners raced height 8,640 on the live net and the halt froze the race in
    /// place: two valid blocks at the boundary, the committee split across them,
    /// and no further block will ever break the tie because the chain is halted.
    /// It resolved only because one host's pre-halt votes happened to be on the
    /// winner. Nothing tested it.
    ///
    /// Deterministic mining cannot race itself (stamp S5), so the second variant is
    /// **built and ingested**: the same parent, the same timestamp and difficulty,
    /// a different payout key — so a different body commitment, a different header
    /// hash, and exactly equal work. Both variants are ingested into every node,
    /// in opposite orders on the two sides, so the split is first-seen fork choice
    /// on a genuine tie rather than an arranged one.
    #[test]
    fn d3_a_boundary_tip_tie_finalizes_on_the_quorum_variant_and_never_on_the_loser() {
        use qlab_node::recovery::SignRefusal;
        use qlab_p2p::n1::BlockIngest;

        // One chain to DH−1, then two different miners each build DH on it.
        let (base_chain, base_chain_tmp) = lone_chain("i369_d3_chain", DH - 1, None);
        let (a_dir, a_tmp) = ("i369_d3_va", "0101010101010101020202020202020203030303030303030404040404040404");
        let (b_dir, b_tmp) = ("i369_d3_vb", "0505050505050505060606060606060607070707070707070808080808080808");

        // Variant builders: each opens on the SAME parent chain and mines DH.
        let variant = |tag: &str, rkm: &str| {
            let (mut cfg, genesis, base) = rig(tag, true);
            cfg.committee_key_paths = vec![];
            cfg.miner_rkm = Some(rkm.to_string());
            transplant(&base_chain, &[cfg.data_dir.clone()]);
            let mut n = RunningNode::start_with_release(
                &cfg, &genesis, KeccakPow, DevnetRehearsalVerifier, armed_release(),
            )
            .unwrap();
            n.set_mine_interval(Duration::ZERO);
            assert_eq!(n.tip_height(), DH - 1, "opened on the shared parent");
            assert!(n.try_mine(), "{tag} mines the boundary block");
            let hash = n.p2p().node().chain().main_chain()[DH as usize];
            let header = *n.p2p().node().chain().header(&hash).expect("header");
            let body = n.state().chain().block(&hash).expect("body").clone().body();
            drop(n);
            (header, body, base)
        };
        let (hdr_a, body_a, va_base) = variant(a_dir, a_tmp);
        let (hdr_b, body_b, vb_base) = variant(b_dir, b_tmp);

        // A genuine tie: same parent, same height, same work, different blocks.
        assert_ne!(hdr_a.header_hash(), hdr_b.header_hash(), "two distinct boundary blocks");
        assert_eq!(hdr_a.prev, hdr_b.prev, "on the same parent");
        assert_eq!(hdr_a.height, hdr_b.height);
        assert_eq!(hdr_a.difficulty, hdr_b.difficulty, "exactly equal work — nothing breaks this tie");

        // Four halted hosts on the shared chain at DH−1, unconnected, split keys.
        let (addrs, _) = mesh_addrs();
        let mut bases = Vec::new();
        let mut nodes: Vec<DrillNode> = Vec::new();
        for i in 0..4 {
            let (mut cfg, genesis, base) = rig(&format!("i369_d3_{i}"), false);
            let lo: usize = KEY_SHARES[..i].iter().sum();
            cfg.committee_key_paths = cfg.committee_key_paths[lo..lo + KEY_SHARES[i]].to_vec();
            cfg.listen_addr = addrs[i].clone();
            cfg.advertise_addr = Some(addrs[i].clone());
            transplant(&base_chain, &[cfg.data_dir.clone()]);
            let n = RunningNode::start_with_release(
                &cfg, &genesis, KeccakPow, DevnetRehearsalVerifier, armed_release(),
            )
            .unwrap();
            assert_eq!(n.tip_height(), DH - 1);
            bases.push(base);
            nodes.push(n);
        }

        // The race, staged by ingestion: nodes 0–2 see A first, node 3 sees B first.
        // Both blocks reach every node, so every node judged a real tie.
        for (i, n) in nodes.iter_mut().enumerate() {
            let first_a = i != 3;
            let order = if first_a {
                [(hdr_a, body_a.clone()), (hdr_b, body_b.clone())]
            } else {
                [(hdr_b, body_b.clone()), (hdr_a, body_a.clone())]
            };
            for (h, b) in order {
                n.p2p_mut().node_mut().ingest_block(h, b);
            }
            let held = n.p2p().node().chain().main_chain()[DH as usize];
            let expect = if first_a { hdr_a.header_hash() } else { hdr_b.header_hash() };
            assert_eq!(held, expect, "node {i}: first-seen holds under equal work");
            assert!(n.is_halted(), "node {i} is halted at the boundary");
        }

        // Connect, and let the loop path do the rest.
        connect_mesh(&mut nodes, &addrs);
        for n in nodes.iter_mut() {
            n.set_repush_interval(Duration::ZERO);
        }
        spin_until(&mut nodes, 200, "the quorum variant finalized", |ns| {
            ns.iter().all(|n| n.finalized_height() == Some(DH))
        });

        // (1) **`variants=2` at the boundary slot** (stamp S5), read from the ROUND
        //     journal rather than from the live tally — deliberately, and this is
        //     the one measurement in the drill that had to move to find a caliper
        //     that works: `VoteTally::on_finalized` drops the slot the instant
        //     quorum lands, so *any* post-hoc tally read is 0 and would have turned
        //     this assertion into a tautology. The round record is the operator's
        //     own instrument (#87's `variants` field, whose documented question is
        //     "is the committee split across conflicting checkpoints?") and it
        //     survives in the retained ring after the journal line is emitted.
        //
        //     `any`, not `all`: a node whose quorum-completing message arrives
        //     before the loser's set finalizes and never sees the second variant.
        //     The 16/5 ledger split in (4) is the assertion that binds.
        let split_seen: Vec<usize> = nodes
            .iter()
            .map(|n| {
                n.p2p()
                    .node()
                    .rounds()
                    .recent()
                    .filter(|r| r.height == DH)
                    .map(|r| r.variants)
                    .max()
                    .unwrap_or(0)
            })
            .collect();
        assert!(
            split_seen.contains(&2),
            "no node journalled a split boundary slot: variants per node {split_seen:?}",
        );

        // (2) The QUORUM variant finalized — A, carrying 16 of 21 keys — and it
        //     finalized on every node including the one that voted against it.
        let cp_a_id = {
            let cp = qlab_devnet::committee::Checkpoint::new(
                DH, hdr_a.header_hash(), hdr_a.header_hash(),
            );
            cp.identity()
        };
        for (i, n) in nodes.iter().enumerate() {
            assert_eq!(n.finalized_checkpoint_id(), Some(cp_a_id), "node {i} finalized variant A");
        }

        // (3) Never-double-sign held per key, asserted as a REFUSAL and not as an
        //     absence: node 3's keys are committed to B and refuse A by name, and
        //     node 0's keys are committed to A and refuse B by name.
        let cp_a = qlab_devnet::committee::Checkpoint::new(
            DH, hdr_a.header_hash(), hdr_a.header_hash(),
        );
        let cp_b = qlab_devnet::committee::Checkpoint::new(
            DH, hdr_b.header_hash(), hdr_b.header_hash(),
        );
        for (i, cp_own, cp_other) in [(0usize, cp_a, cp_b), (3usize, cp_b, cp_a)] {
            for f in nodes[i].finalizers_mut() {
                assert_eq!(f.state().signed_at(DH), Some(&cp_own), "node {i} key {}", f.index());
                let refusal = f.sign(&cp_other);
                assert!(
                    matches!(
                        refusal,
                        Err(SignRefusal::WouldEquivocate { slot, already })
                            if slot == DH && already == cp_own
                    ),
                    "node {i} key {}: the guard must REFUSE the other variant, got {:?}",
                    f.index(),
                    refusal.is_ok(),
                );
            }
        }

        // (4) The loser is unfinalizable — and structurally so, not merely
        //     unfinalized: 16 of the 21 keys are permanently committed to A, which
        //     leaves B a ceiling of 5 against a quorum of 15, forever.
        let quorum = GenesisFile::new_devnet_t0().frozen.quorum as usize;
        let on_b: usize = KEY_SHARES[3];
        assert_eq!(21 - on_b, 16, "16 keys are committed to A");
        assert!(on_b < quorum, "B's ceiling is {on_b} against a quorum of {quorum}");
        assert_eq!(commitments(&nodes), vec![Some(cp_a_id), Some(cp_a_id), Some(cp_a_id), Some(cp_b.identity())],
                   "the minority still finalizes the majority's checkpoint and differs only in its own ledger");

        for (n, base) in nodes.into_iter().zip(bases) {
            drop(n);
            let _ = std::fs::remove_dir_all(&base);
        }
        for base in [base_chain_tmp, va_base, vb_base] {
            let _ = std::fs::remove_dir_all(&base);
        }
    }

    /// **DRILL D3-B — the boundary-tie loser fetches the finalized sibling and
    /// converges while it remains halted (lab #375).**
    ///
    /// D3 above is the shape lock: 16 keys are permanently committed to A, five to
    /// B, and every node finalizes A. This sibling removes A's BODY from node 3
    /// while leaving its validated header in fork choice. At the instant quorum
    /// lands, node 3 is therefore the exact wedge from #375: halted at H, finalized
    /// checkpoint A, applied sibling B, one `not-held` durable-finality refusal.
    ///
    /// The cure uses only the existing near-tip body path. `missing_body_hashes`
    /// names A after finality makes it the main-chain block at H; the normal
    /// `GetData(Block)` request receives a whole `BlockAnnounce`; and the existing
    /// `buffer_body` -> `rejoin_main_chain` -> `Node::rewind_to` ->
    /// `apply_block_gated` funnel applies it. Keeping the peers disconnected, or
    /// making `on_getdata` serve only the header, leaves the first assertion below
    /// permanently wedged: that is the request/serve mutation direction. D3's
    /// 16/5 ledger assertions are the opposite direction — the loser can never
    /// finalize B.
    #[test]
    fn d3_b_boundary_tip_tie_loser_fetches_finalized_sibling_and_reopens_on_it() {
        use qlab_p2p::n1::BlockIngest;

        let (base_chain, base_chain_tmp) = lone_chain("i375_d3b_chain", DH - 1, None);
        let (a_dir, a_tmp) =
            ("i375_d3b_va", "1111111111111111222222222222222233333333333333334444444444444444");
        let (b_dir, b_tmp) =
            ("i375_d3b_vb", "5555555555555555666666666666666677777777777777778888888888888888");

        let variant = |tag: &str, rkm: &str| {
            let (mut cfg, genesis, base) = rig(tag, true);
            cfg.committee_key_paths = vec![];
            cfg.miner_rkm = Some(rkm.to_string());
            transplant(&base_chain, &[cfg.data_dir.clone()]);
            let mut n = RunningNode::start_with_release(
                &cfg, &genesis, KeccakPow, DevnetRehearsalVerifier, armed_release(),
            )
            .unwrap();
            n.set_mine_interval(Duration::ZERO);
            assert!(n.try_mine(), "{tag} mines the boundary block");
            let hash = n.p2p().node().chain().main_chain()[DH as usize];
            let header = *n.p2p().node().chain().header(&hash).expect("header");
            let body = n.state().chain().block(&hash).expect("body").clone().body();
            drop(n);
            (header, body, base)
        };
        let (hdr_a, body_a, va_base) = variant(a_dir, a_tmp);
        let (hdr_b, body_b, vb_base) = variant(b_dir, b_tmp);
        assert_ne!(hdr_a.header_hash(), hdr_b.header_hash());
        assert_eq!(hdr_a.prev, hdr_b.prev);
        assert_eq!(hdr_a.height, DH);
        assert_eq!(hdr_a.difficulty, hdr_b.difficulty, "equal-work siblings");

        let (addrs, _) = mesh_addrs();
        let mut bases = Vec::new();
        let mut nodes: Vec<DrillNode> = Vec::new();
        let mut loser_reopen = None;
        for i in 0..4 {
            let (mut cfg, genesis, base) = rig(&format!("i375_d3b_{i}"), false);
            let lo: usize = KEY_SHARES[..i].iter().sum();
            cfg.committee_key_paths = cfg.committee_key_paths[lo..lo + KEY_SHARES[i]].to_vec();
            cfg.listen_addr = addrs[i].clone();
            cfg.advertise_addr = Some(addrs[i].clone());
            transplant(&base_chain, &[cfg.data_dir.clone()]);
            let mut n = RunningNode::start_with_release(
                &cfg, &genesis, KeccakPow, DevnetRehearsalVerifier, armed_release(),
            )
            .unwrap();

            if i == 3 {
                // B is applied first. A's HEADER is known, so quorum evidence for
                // A can move fork choice, but A's BODY must cross the wire later.
                n.p2p_mut().node_mut().ingest_block(hdr_b, body_b.clone());
                n.p2p_mut().node_mut().ingest_header(hdr_a);
                loser_reopen = Some((cfg.clone(), genesis));
            } else {
                n.p2p_mut().node_mut().ingest_block(hdr_a, body_a.clone());
                n.p2p_mut().node_mut().ingest_block(hdr_b, body_b.clone());
            }
            assert_eq!(n.tip_height(), DH);
            assert!(n.is_halted());
            bases.push(base);
            nodes.push(n);
        }

        connect_mesh(&mut nodes, &addrs);
        for n in nodes.iter_mut() {
            n.set_repush_interval(Duration::ZERO);
        }
        // `spin_until` checks the condition before starting the next mesh round.
        // Node 3's finalizing tick may SEND its body request, but no serving peer
        // gets another tick to answer it before this returns.
        spin_until(&mut nodes, 200, "the quorum variant finalized", |ns| {
            ns.iter().all(|n| n.finalized_height() == Some(DH))
        });

        let a_hash = hdr_a.header_hash();
        let b_hash = hdr_b.header_hash();
        assert_eq!(nodes[3].finalized_checkpoint_id(), Some(
            qlab_devnet::committee::Checkpoint::new(DH, a_hash, a_hash).identity(),
        ));
        assert_eq!(nodes[3].p2p().node().applied_tip().hash, b_hash, "the loser is wedged on B");
        assert!(nodes[3].p2p().body_requests() > 0, "the near-tip requester asks for A");
        assert_eq!(
            nodes[3].p2p().node().finalize_refused_total(),
            1,
            "one not-held transition; the production loop already emitted its journal line",
        );
        assert_eq!(nodes[3].p2p().node().durable_finalized_head(), None);

        // Let the already-sent GetData(Block) traverse the same loop again. A peer
        // serves the whole body; no special admission or validation path exists.
        spin_until(&mut nodes, 120, "the halted loser applied finalized sibling A", |ns| {
            let loser = ns[3].p2p().node();
            loser.applied_tip().hash == a_hash
                && loser.durable_finalized_head() == Some((DH, a_hash))
        });
        let loser = nodes[3].p2p().node();
        assert_eq!(loser.applied_tip().height, DH);
        assert_eq!(loser.applied_tip().hash, a_hash, "state tip == finalized A");
        assert_eq!(loser.applied_tip().main_chain_hash, Some(a_hash), "the two views agree");
        assert_eq!(loser.state_rewinds(), (1, 1), "one sibling rewind, logged once");
        assert_eq!(loser.finalize_refused_total(), 1, "retries do not duplicate the event");
        assert_eq!(nodes[3].p2p().body_requests(), 0, "the bounded request stops on convergence");
        assert!(
            nodes[3]
                .p2p()
                .peers()
                .ready_peers()
                .into_iter()
                .all(|pid| nodes[3].p2p().peers().get(pid).is_some_and(|p| p.score >= 0)),
            "serving the requested sibling never penalizes a peer",
        );
        assert_eq!(nodes[3].tip_height(), DH, "halt still admits nothing above H");
        assert!(nodes[3].is_halted());

        // Persistence leg: the normal apply funnel appended A and the finalize
        // record. A fresh process on the same data dir reopens on A, not B.
        let (loser_cfg, loser_genesis) = loser_reopen.expect("loser config retained");
        for n in nodes {
            drop(n);
        }
        let reopened = RunningNode::start_with_release(
            &loser_cfg,
            &loser_genesis,
            KeccakPow,
            DevnetRehearsalVerifier,
            armed_release(),
        )
        .unwrap();
        assert_eq!(reopened.p2p().node().applied_tip().hash, a_hash, "restart reopens on A");
        assert_eq!(reopened.p2p().node().durable_finalized_head(), Some((DH, a_hash)));
        assert_eq!(reopened.tip_height(), DH, "restart remains halted at H");
        drop(reopened);

        for base in bases {
            let _ = std::fs::remove_dir_all(&base);
        }
        for base in [base_chain_tmp, va_base, vb_base] {
            let _ = std::fs::remove_dir_all(&base);
        }
    }
}
