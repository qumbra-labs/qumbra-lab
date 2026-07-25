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

use qlab_node::Telemetry;

use qlab_p2p::adapter::{MiningClock, NodeAdapter};
use qlab_p2p::n1::ChainView;
use qlab_p2p::transport::TcpTransport;
use qlab_p2p::P2pNode;

use crate::config::NodeConfig;
use crate::genesis::{GenesisError, GenesisFile};

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
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::Config(e) => write!(f, "{e}"),
            RunError::Genesis(e) => write!(f, "{e}"),
            RunError::Node(e) => write!(f, "node: {e}"),
            RunError::Io(e) => write!(f, "io: {e}"),
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
    /// Committee signing keys this node holds (may be empty — a verify-only node).
    validators: Vec<qlab_devnet::committee::Validator>,
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
        // (1) Byte-verify the genesis file + optional hash pin BEFORE any state.
        genesis.verify_startup(config.expected_genesis_hash.as_deref())?;

        // (2) committee₀ from the baked verifying keys; bond = the frozen
        //     steady-state self-bond in bessel (the epoch ramp is a genesis-recorded
        //     schedule; per-epoch application is a committee follow-up).
        let committee_keys = genesis.committee()?;
        let bond_bessel =
            genesis.frozen.self_bond_qmb_steady.saturating_mul(genesis.frozen.bessel_per_qmb);
        let committee = CommitteeState::new(committee_keys, bond_bessel);

        // (3) This node's signing keys (cross-checked against committee₀).
        let validators = genesis.load_validators(&config.committee_key_paths)?;

        // (4) Real params: FROZEN 75 s block time (item 3, NOT SIM_BLOCK_TIME_SECS)
        //     + the genesis PoW difficulty; RandomX key schedule from defaults.
        let sim = SimConfig {
            block_time_secs: genesis.frozen.block_time_secs,
            genesis_difficulty: genesis.genesis_difficulty,
            ..SimConfig::default()
        };

        // (5) Disk-backed adapter (restart-safe) + TCP transport + P2P node.
        let adapter = NodeAdapter::open(&config.data_dir, committee, pow, verifier, sim)?;
        let transport = TcpTransport::bind(&config.listen_addr).map_err(RunError::Io)?;
        let bound = transport.local_addr().to_string();
        let node_id = node_id_from_addr(&bound);
        let mut p2p = P2pNode::new(transport, adapter, node_id);

        // (6) Dial configured peers (connect, then register — connect borrows the
        //     transport immutably, add_peer borrows p2p mutably).
        let mut dialed = Vec::new();
        for addr in &config.dial_peers {
            match p2p.transport().connect(addr) {
                Ok(pid) => dialed.push((pid, addr.clone())),
                Err(e) => eprintln!("dial {addr} failed: {e}"),
            }
        }
        for (pid, addr) in dialed {
            p2p.add_peer(pid, Some(addr));
        }

        Ok(RunningNode {
            p2p,
            validators,
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
        let base_hash = chain.finalized_hash().unwrap_or_else(|| chain.genesis_hash());
        let base_ts = chain.header(&base_hash).map(|h| h.timestamp).unwrap_or(0);
        let age = tip_ts.saturating_sub(base_ts);

        let t = Telemetry::assemble(
            node.tip_height(),
            node.finalized_height(),
            age,
            node.mempool().len() as u64,
            self.p2p.peers().len() as u64,
            node.committee().current_epoch(),
            DEGRADED_MODE_LAG_BLOCKS,
        );
        let regime = match t.finality_status {
            FinalityStatus::Final => "Final",
            FinalityStatus::Degraded => "Degraded",
        };
        let final_str = t.finalized_height.map(|h| h.to_string()).unwrap_or_else(|| "-".to_string());
        format!(
            "TELEMETRY tip={} final={} stall={} age_s={} diff={} peers={} mempool={} epoch={} regime={}",
            t.tip_height, final_str, t.stall_depth, t.last_finalized_age_secs, tip_diff,
            t.peer_count, t.mempool_size, t.epoch, regime,
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
    /// with the keys this node holds (no-op for a verify-only node).
    pub fn try_checkpoint(&mut self) {
        if self.validators.is_empty() {
            return;
        }
        let tip = self.tip_height();
        while self.next_checkpoint <= tip {
            if let Some((cp, votes)) =
                self.p2p.node().make_checkpoint(self.next_checkpoint, &self.validators)
            {
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
            }
            if n == 0 {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        // Graceful shutdown = snapshot flush.
        if let Err(e) = self.save_snapshot() {
            eprintln!("snapshot flush on shutdown failed: {e}");
        }
    }
}

/// Derive a deterministic 32-byte node id from the bound address, so a node's id
/// is stable across restarts on the same address.
fn node_id_from_addr(addr: &str) -> [u8; 32] {
    qlab_devnet::hash::keccak256(addr.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis::GenesisFile;
    use qlab_devnet::pow::KeccakPow;
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
}
