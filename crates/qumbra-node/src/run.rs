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
use std::time::{Duration, Instant};

use qlab_devnet::body::{TxEntry, TxVerifier};
use qlab_devnet::committee::CommitteeState;
use qlab_devnet::ebbflow::FinalityStatus;
use qlab_devnet::node::SimConfig;
use qlab_devnet::params_devnet::{CHECKPOINT_CADENCE_BLOCKS, DEGRADED_MODE_LAG_BLOCKS};
use qlab_devnet::pow::PowEngine;

use qlab_node::recovery::{Finalizer, FinalizerState};
use qlab_node::Telemetry;

use qlab_p2p::addrman::{AddrManager, DIAL_RETRY_INTERVAL_MS};
use qlab_p2p::adapter::{MiningClock, NodeAdapter};
use qlab_p2p::n1::ChainView;
use qlab_p2p::transport::TcpTransport;
use qlab_p2p::P2pNode;

/// How often [`RunningNode::run_until`] runs a discovery maintenance pass —
/// re-dial, auto-connect, ask for addresses (issue #83; was `REDIAL_INTERVAL`).
const MAINTAIN_INTERVAL: Duration = Duration::from_millis(DIAL_RETRY_INTERVAL_MS);

/// The persisted address book, under the node's data dir (issue #83 scope 7).
const ADDRBOOK_FILE: &str = "peers.dat";

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
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::Config(e) => write!(f, "{e}"),
            RunError::Genesis(e) => write!(f, "{e}"),
            RunError::Node(e) => write!(f, "node: {e}"),
            RunError::Io(e) => write!(f, "io: {e}"),
            RunError::Release(e) => write!(f, "release: {e}"),
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
        let mut adapter = NodeAdapter::open(&config.data_dir, committee, pow, verifier, sim)?;
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
        addrs.set_self_advertise(config.advertise_addr.clone());
        if config.advertise_addr.is_none() {
            println!(
                "no advertise_addr: this node will sync, mine and transact but will \
                 not be gossiped to other peers (expected behind a router)"
            );
        }
        *p2p.addrs_mut() = addrs;
        p2p.maintain(0); // dial the seeds now

        Ok(RunningNode {
            p2p,
            finalizers,
            data_dir: config.data_dir.clone(),
            mining: config.mining,
            mine_interval: Duration::from_secs(genesis.frozen.block_time_secs),
            last_mine: Instant::now(),
            nonce: 0,
            next_checkpoint: 0, // finalize genesis first, then the cadence grid
            listen_addr: bound,
            // Sample telemetry roughly every 30 s (well under the 75 s block time,
            // so every block shows up in the trace; the soak monitor also runs
            // `docker compose logs -t` to wall-clock-stamp each line).
            sample_interval: Duration::from_secs(30),
            last_sample: Instant::now(),
            last_maintain: Instant::now(),
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

    /// A single observability sample line for the soak monitor (M10-T0-3 Phase
    /// B-lite). Reuses the canonical [`Telemetry::assemble`] rule — it never
    /// re-derives the frozen Ebb-and-Flow finality semantics — and adds the tip
    /// block's PoW `difficulty` so the LWMA retarget trace is visible over the
    /// soak (amendment-1 item 4). Age is chain-time (block timestamps), so this
    /// half is deterministic given the chain; the network half (peers/epoch) is
    /// read live. Emitted to stdout, captured via `docker compose logs`.
    pub fn telemetry_sample(&self) -> String {
        let node = self.p2p.node();
        let chain = node.chain();
        let tip_hash = chain.tip_hash();
        let (tip_ts, tip_diff) = chain
            .header(&tip_hash)
            .map(|h| (h.timestamp, h.difficulty))
            .unwrap_or((0, 0));
        // Age is chain-time from the finalized block; 0 when nothing is finalized
        // (S8: no finalized head ⇒ no finalized-age, not a genesis-fallback absolute).
        let age = if node.finalized_height().is_none() {
            0
        } else {
            let base_hash = chain.finalized_hash().unwrap_or_else(|| chain.genesis_hash());
            let base_ts = chain.header(&base_hash).map(|h| h.timestamp).unwrap_or(0);
            tip_ts.saturating_sub(base_ts)
        };

        let t = Telemetry::assemble_with_halt(
            node.tip_height(),
            node.finalized_height(),
            age,
            node.mempool().len() as u64,
            self.p2p.peers().len() as u64,
            node.committee().current_epoch(),
            DEGRADED_MODE_LAG_BLOCKS,
            self.halt_at,
        );
        let regime = match t.finality_status {
            FinalityStatus::Final => "Final",
            FinalityStatus::Degraded => "Degraded",
            FinalityStatus::Halting => "Halting",
            FinalityStatus::Halted => "Halted",
        };
        let final_str = t.finalized_height.map(|h| h.to_string()).unwrap_or_else(|| "-".to_string());
        // S8: print `age_s=-` (not `age_s=0`) whenever there is no finalized head, so
        // the runbook's stall alarm never mistakes "never finalized" for a real age.
        let age_str = if t.finalized_height.is_none() {
            "-".to_string()
        } else {
            t.last_finalized_age_secs.to_string()
        };
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
        format!(
            "TELEMETRY tip={} final={} stall={} age_s={} diff={} peers={} mempool={} epoch={} regime={} halt={} hignore={} powrej={} dialable={}/{}",
            t.tip_height, final_str, t.stall_depth, age_str, tip_diff,
            t.peer_count, t.mempool_size, t.epoch, regime, halt_str,
            ic.halt_ignored, ic.pow_rejected,
            self.p2p.addrs().dialable_count(), self.p2p.addrs().known_count(),
        )
    }

    /// One message-pump step; returns frames handled.
    pub fn step_once(&mut self) -> usize {
        self.p2p.tick()
    }

    /// Attempt to mine + announce the next block over the tip. Returns whether a
    /// block was produced (real RandomX PoW under the key-block seed).
    pub fn try_mine(&mut self) -> bool {
        match self.p2p.node_mut().mine_block() {
            Some((header, body)) => {
                self.nonce = self.nonce.wrapping_add(1);
                self.p2p.announce_block(header, body.txs, body.coinbase, self.nonce);
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
    /// **snapshot flush** (item 1).
    pub fn run_until(&mut self, shutdown: &AtomicBool) {
        // An initial sample at startup (height/finality as opened from disk).
        println!("{}", self.telemetry_sample());
        self.last_sample = Instant::now();
        while !shutdown.load(Ordering::Relaxed) {
            let n = self.step_once();
            if self.mining && self.last_mine.elapsed() >= self.mine_interval {
                if self.try_mine() {
                    self.try_checkpoint();
                }
            }
            if self.last_sample.elapsed() >= self.sample_interval {
                println!("{}", self.telemetry_sample());
                self.last_sample = Instant::now();
                // Cheap and idempotent; sampled on the telemetry cadence so it costs
                // nothing on a net that never halts.
                self.maintain_halt_marker();
            }
            if self.last_maintain.elapsed() >= MAINTAIN_INTERVAL {
                self.maintain_peers(); // re-dial, auto-connect, ask for addresses (#83)
                self.last_maintain = Instant::now();
            }
            if n == 0 {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        // Graceful shutdown = snapshot flush + the learned address book.
        if let Err(e) = self.save_snapshot() {
            eprintln!("snapshot flush on shutdown failed: {e}");
        }
        self.save_addr_book();
    }
}

/// Derive a deterministic 32-byte node id from the bound address, so a node's id
/// is stable across restarts on the same address.
fn node_id_from_addr(addr: &str) -> [u8; 32] {
    qlab_devnet::hash::keccak256(addr.as_bytes())
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

    #[test]
    fn run_until_flushes_a_snapshot_on_shutdown() {
        let (config, genesis, base) = rig("shutdown", true);
        let mut node =
            RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        node.set_mine_interval(Duration::ZERO);
        node.try_mine();
        // A pre-set shutdown flag: run_until does the graceful flush and returns.
        let shutdown = AtomicBool::new(true);
        node.run_until(&shutdown);
        // The snapshot file now exists in the data dir (graceful flush ran).
        assert!(config.data_dir.join(qlab_node::SNAPSHOT).exists(), "snapshot flushed");
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

        // B comes up on the same address.
        let (mut bcfg, bgen, bbase) = rig("redial_b", false);
        bcfg.listen_addr = b_addr.clone();
        let b = RunningNode::start(&bcfg, &bgen, KeccakPow, DevnetRehearsalVerifier).unwrap();

        // Re-dial reconnects A to B with no restart.
        a.force_redial_ready();
        a.maintain_peers();
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
        let b = RunningNode::start(&bcfg, &bgen, KeccakPow, DevnetRehearsalVerifier).unwrap();

        let (mut acfg, agen, abase) = rig("book_a", false);
        acfg.dial_peers = vec![b_addr.clone()];
        let mut a = RunningNode::start(&acfg, &agen, KeccakPow, DevnetRehearsalVerifier).unwrap();
        a.maintain_peers();
        assert_eq!(a.p2p().addrs().dialable_count(), 1);
        a.save_addr_book();
        drop(a);

        // Restart with an EMPTY seed list: whatever it knows was restored from disk.
        let mut acfg2 = acfg.clone();
        acfg2.dial_peers = vec![];
        let a2 = RunningNode::start(&acfg2, &agen, KeccakPow, DevnetRehearsalVerifier).unwrap();
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
}
