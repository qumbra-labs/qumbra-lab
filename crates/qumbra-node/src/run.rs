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
    CHECKPOINT_CADENCE_BLOCKS, DEGRADED_MODE_LAG_BLOCKS, EPOCH_LENGTH_BLOCKS,
};
use qlab_devnet::pow::PowEngine;

use qlab_node::metrics::{render as render_metrics, LiveGauges};
use qlab_node::recovery::{Finalizer, FinalizerState};
use qlab_node::round::ObsClock;
use qlab_node::{ChainStore, SupplyBlock, SupplyLedger, Telemetry};

use crate::metrics_server::MetricsServer;
use crate::telemetry_server::TelemetryServer;

use qlab_p2p::addrman::{valid_addr, AddrManager, DIAL_RETRY_INTERVAL_MS};
use qlab_p2p::adapter::{MiningClock, NodeAdapter};
use qlab_p2p::n1::{ChainView, CommitteeControl};
use qlab_p2p::sync::SyncPhase;
use qlab_p2p::transport::TcpTransport;
use qlab_p2p::P2pNode;

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

/// How often the `/metrics` snapshot is re-rendered (issue #87). Chosen under a
/// typical 15 s Prometheus scrape interval so a scrape is never more than one
/// refresh stale, while the node — not the scraper — sets the cost. Rendering is a
/// few dozen string appends over integer state; the run loop pays it, never a
/// request handler. Observability only: it changes nothing but snapshot freshness.
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
        let rules = release.rule_schedule()?;

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
            SupplyLedger::from_blocks(
                state_chain.chain().main_chain().iter().map(|hash| {
                    let block = state_chain
                        .block(hash)
                        .expect("every canonical state-chain hash has its stored body");
                    SupplyBlock {
                        height: block.header.height,
                        coinbase: block.coinbase,
                        fees: block.txs.iter().map(|tx| tx.fee).sum(),
                    }
                }),
                EPOCH_LENGTH_BLOCKS,
            )?
        };

        Ok(RunningNode {
            p2p,
            finalizers,
            data_dir: config.data_dir.clone(),
            mining: config.mining,
            mine_interval: Duration::from_secs(genesis.frozen.block_time_secs),
            last_mine: Instant::now(),
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
            supply_ledger: Mutex::new(supply_ledger),
            process_start_secs: unix_secs(),
            listen_addr: bound,
            // Sample telemetry roughly every 30 s (well under the 75 s block time,
            // so every block shows up in the trace; the soak monitor also runs
            // `docker compose logs -t` to wall-clock-stamp each line).
            sample_interval: Duration::from_secs(30),
            last_sample: Instant::now(),
            last_maintain: Instant::now(),
            mine_gate_latched: false,
            started: Instant::now(),
            release,
            halt_at: release.halt_at(),
            marker_final_written: marker.is_some_and(|m| m.boundary_finalized),
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
    /// Honest limitation: `announce_tx` returns nothing, so the reason for a
    /// refusal is not recoverable here — only whether the transaction is in the
    /// pool afterwards. Callers that need a reason must pre-check what they can
    /// (`GrantPlan::is_submittable` re-checks the anchor) and treat `false` as
    /// "the node did not take it".
    pub fn submit_local_tx(&mut self, tx: TxEntry) -> bool {
        let id = qlab_p2p::codec::tx_id(&tx);
        self.p2p.announce_tx(tx);
        qlab_p2p::n1::TxPool::has_tx(self.p2p.node(), &id)
    }

    /// Tip height reported by the consensus chain view.
    pub fn tip_height(&self) -> u64 {
        self.p2p.node().tip_height()
    }

    /// Finalized height, if any.
    pub fn finalized_height(&self) -> Option<u64> {
        self.p2p.node().finalized_height()
    }

    /// Override the mining cadence (tests set 0 to mine every step).
    pub fn set_mine_interval(&mut self, d: Duration) {
        self.mine_interval = d;
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

    /// **The identity of the finalized checkpoint** (issue #84), or `None` when
    /// nothing is finalized. Read from the finality tracker's own head — this is
    /// the checkpoint the quorum was verified against, not a re-derivation.
    pub fn finalized_checkpoint_id(&self) -> Option<u64> {
        self.p2p.node().finality().latest().map(|cp| cp.identity())
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
            for height in ledger.next_height()..=state_chain.tip_height() {
                let hash = main_chain
                    .get(height as usize)
                    .expect("every canonical height has a hash");
                let block = state_chain
                    .block(hash)
                    .expect("every canonical state-chain hash has its stored body");
                ledger
                    .push(SupplyBlock {
                        height: block.header.height,
                        coinbase: block.coinbase,
                        fees: block.txs.iter().map(|tx| tx.fee).sum(),
                    })
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
                let base_hash = chain.finalized_hash().unwrap_or_else(|| chain.genesis_hash());
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
        format!(
            "TELEMETRY tip={} final={} stall={} age_s={} diff={} peers={} mempool={} epoch={} regime={} halt={} hignore={} powrej={} dialable={}/{} rounds={} rfail={} fid={} sslot={} sid={} rback={} stip={} slag={} uanchor={} mready={}",
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
        let (pending, pending_bytes) = node.pending_bodies();
        LiveGauges {
            tip_height: tip,
            state_tip: lag.state_tip,
            state_lag: lag.blocks(),
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
        while self.next_checkpoint <= tip {
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
            let n = self.step_once();
            // Issue #87, in the order that keeps the record honest: accumulate the
            // regime residency first (so the seconds land in the regime that was
            // actually in force), then open any newly-reached slot, then emit the
            // rounds that closed while we were away. All three are cheap and none
            // touches consensus.
            self.accumulate_regime();
            self.note_slots_reached();
            self.emit_rounds();
            if self.mining && self.last_mine.elapsed() >= self.mine_interval {
                if self.try_mine() {
                    self.try_checkpoint();
                }
            }
            if self.metrics_server.is_some() && self.last_metrics_render.elapsed() >= METRICS_REFRESH {
                self.refresh_metrics();
                self.last_metrics_render = Instant::now();
            }
            if self.telemetry_server.is_some()
                && self.last_telemetry_render.elapsed() >= TELEMETRY_REFRESH
            {
                self.refresh_telemetry();
                self.last_telemetry_render = Instant::now();
            }
            if self.last_sample.elapsed() >= self.sample_interval {
                println!("{}", self.telemetry_sample());
                // A stall's open rounds report themselves on the same cadence as the
                // telemetry line they explain.
                self.emit_overdue_rounds();
                self.last_sample = Instant::now();
                // Cheap and idempotent; sampled on the telemetry cadence so it costs
                // nothing on a net that never halts.
                self.maintain_halt_marker();
            }
            if self.last_maintain.elapsed() >= MAINTAIN_INTERVAL {
                self.maintain_peers(); // re-dial, auto-connect, ask for addresses (#83)
                self.last_maintain = Instant::now();
            }
            // The co-resident hook (#123), last so it observes this iteration's
            // state rather than the previous one's.
            on_tick(self);
            if n == 0 {
                std::thread::sleep(Duration::from_millis(20));
            }
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
            Ok(()) => true,
            Err(e) => {
                eprintln!("snapshot flush on shutdown failed: {e}");
                false
            }
        };
        self.save_addr_book();
        snapshot_ok
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

        // Flush + drop, then re-open the SAME data dir: the tip persists (the disk
        // stores + snapshot are real — restart safety).
        node.save_snapshot().unwrap();
        drop(node);
        let reopened =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        assert_eq!(reopened.tip_height(), 3, "state persisted across restart");
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
        for _ in 0..CHECKPOINT_CADENCE_BLOCKS {
            assert!(node.try_mine());
        }
        node.try_checkpoint(); // slot 8
        assert_eq!(node.finalized_height(), Some(CHECKPOINT_CADENCE_BLOCKS), "slot 8 finalized");
        // Ledgers were persisted (write-ahead, before broadcast).
        assert!(config.data_dir.join("finalizer-0.state").exists(), "finalizer 0 ledger on disk");
        node.save_snapshot().unwrap();
        drop(node);

        // Restart: finalizers restore their ledgers from disk. NOTE: the finality
        // TRACKER is intentionally NOT persisted (S7 — the vote tally / finalized head
        // rebuilds from re-gossip), so a solo reopened node with no peers reports no
        // finalized height until a checkpoint is re-gossiped. What #7 requires is that
        // the never-double-sign LEDGER survives:
        let mut reopened =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
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
        let strip = |line: &str| {
            line.split_whitespace()
                .filter(|kv| !kv.starts_with("stip=") && !kv.starts_with("slag="))
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

        // Cross the boundary: reach slot 8, finalize it, move the tip one past it.
        for _ in 1..CHECKPOINT_CADENCE_BLOCKS {
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
        assert!(b.telemetry_sample().ends_with(" mready=unknown"));

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
        assert!(line.ends_with(" mready=synced"), "the readiness gate is open: {line}");

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
        assert!(one.telemetry_sample().ends_with(" mready=unknown"));

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
        assert_eq!(mine_and_checkpoint(&mut node, DH + 8), DH + 8, "mined through it");
        assert_eq!(node.tip_height(), DH + 8);
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
        assert!(line.ends_with(" mready=alone"), "the readiness verdict, last: {line}");
        let _ = std::fs::remove_dir_all(&base);
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
        for _ in 0..CHECKPOINT_CADENCE_BLOCKS {
            assert!(node.try_mine(), "{tag}: mines at the genesis difficulty");
        }
        node.try_checkpoint(); // slot 8
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
        for _ in 0..CHECKPOINT_CADENCE_BLOCKS {
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
        for _ in 0..CHECKPOINT_CADENCE_BLOCKS {
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

        for _ in 0..CHECKPOINT_CADENCE_BLOCKS {
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

        for _ in 0..CHECKPOINT_CADENCE_BLOCKS {
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

    /// The scrape endpoint, end to end over a real socket, serving live node state.
    #[test]
    fn metrics_endpoint_serves_live_state_and_is_off_by_default() {
        let (config, genesis, base) = rig("metrics", true);
        assert!(config.metrics_addr.is_none(), "no listener unless the operator asks");
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        node.set_mine_interval(Duration::ZERO);
        node.try_checkpoint();
        for _ in 0..CHECKPOINT_CADENCE_BLOCKS {
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
        // Live levels…
        assert!(body.contains(&format!("qumbra_tip_height {CHECKPOINT_CADENCE_BLOCKS}")), "{body}");
        assert!(body.contains("qumbra_committee_quorum 15"));
        assert!(body.contains("qumbra_committee_size 21"));
        assert!(body.contains("qumbra_finality_regime{regime=\"final\"} 1"));
        // …and the accumulated, source-side aggregates.
        assert!(body.contains("qumbra_checkpoint_rounds_total{verdict=\"finalized\"} 1"));
        assert!(body.contains("qumbra_blocks_connected_total 8"));
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
        for _ in 0..CHECKPOINT_CADENCE_BLOCKS {
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
        assert_eq!(served.tip_height, CHECKPOINT_CADENCE_BLOCKS);
        assert_eq!(served.finalized_height, node.finalized_height());
        assert_eq!(served.finalized_id, Some(fid), "fid is on the wire, not just in the log line");
        assert_eq!(
            (served.committee_size, served.committee_active, served.committee_quorum),
            (21, 21, 15),
        );
        assert_eq!(served.supply.len(), 1, "eight mined blocks remain in epoch 0");
        assert_eq!((served.supply[0].start_height, served.supply[0].end_height), (0, 8));
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
}
