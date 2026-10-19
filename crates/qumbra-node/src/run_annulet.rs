//! `run` on an **Annulet** genesis (lab #708, B2b) — the sequencer net.
//!
//! The same [`RunningNode`] and the same loop as the L1; what differs is
//! selected by the form, by name, at each consumer:
//!
//! - **The role** is the sequencer key file's presence in the data dir
//!   ([`SEQUENCER_KEY_FILE`], lab #708 Q6): with it the node is the
//!   **producer** and seals on the genesis slot clock; without it, a
//!   **follower** running the same binary with production off. A key file
//!   whose key is not the genesis `sequencer_key` is refused before anything
//!   opens.
//! - **Committee and checkpoint machinery is off by name**: `run` refuses
//!   committee key paths and `mining = true` on an Annulet genesis; the round
//!   ledger, `try_checkpoint` and the boundary checkpoint have Annulet arms
//!   that return; the committee gauges are absent (see `live_gauges`).
//! - **No halt-height machinery**: the release's halt height does not apply
//!   to the sequencer net (`halt_at` is `None`).
//! - **The slot rule** (genesis `slot_secs` / `max_empty_slots`, Q5): at each
//!   slot the producer seals when its pool is non-empty, and otherwise seals
//!   an empty block once `max_empty_slots` consecutive slots have passed
//!   empty. It seals only when its state is at its header tip — a producer
//!   still applying bodies waits a slot rather than building on a tip it has
//!   not applied.
//!
//! **Finality is operator governance** (final on acceptance), not BFT; the
//! sequencer withholding blocks is a liveness failure only.

use super::*;
use crate::annulet_genesis::{AnnuletGenesisFile, SequencerKeyFile, SEQUENCER_KEY_FILE};
use qlab_devnet::annulet::{SealedHeader, SequencerKey};
use qlab_devnet::committee::Committee;
use qlab_node::NodeState as _;

/// The sequencer-net run state held by [`RunningNode`] (lab #708).
pub(super) struct AnnuletRun {
    /// `Some` exactly when this node is the producer.
    sequencer: Option<SequencerKey>,
    slot: Duration,
    max_empty_slots: u64,
    last_slot: Instant,
    /// Consecutive slots that passed with an empty pool and no block.
    empty_run: u64,
    /// `/v1/genesis/notes`, encoded once from the genesis file (lab #714).
    genesis_notes: Vec<u8>,
    /// `/v1/annulet/params`, encoded once from the genesis file (lab #720).
    params: Vec<u8>,
    /// `/genesis.qmb` (lab #850 AD1): the genesis file's canonical bytes, the
    /// ones whose keccak is the genesis hash — what a verifying wallet hashes
    /// against its pin and reads the sequencer key from.
    genesis_file: Vec<u8>,
}

impl AnnuletRun {
    pub(super) fn new(file: &AnnuletGenesisFile, sequencer: Option<SequencerKey>) -> Self {
        Self {
            sequencer,
            slot: Duration::from_secs(file.params.slot_secs),
            max_empty_slots: file.params.max_empty_slots,
            last_slot: Instant::now(),
            empty_run: 0,
            genesis_file: file.to_bytes(),
            params: qlab_cbserver::registry::encode_annulet_params(&qlab_cbserver::registry::AnnuletParams {
                genesis_hash: file.hash(),
                fee_tier_s: file.params.fee_tier_s,
                fee_tier_p: file.params.fee_tier_p,
                fee_tier_r: file.params.fee_tier_r,
            }),
            genesis_notes: qlab_cbserver::registry::encode_genesis_notes(
                &file.hash(),
                &file
                    .genesis_notes
                    .iter()
                    .map(|n| qlab_cbserver::registry::ServedGenesisNote {
                        cm: n.cm,
                        payload: qlab_note::l2note::GenesisPlaintext(
                            n.payload.as_slice().try_into().expect("a verified genesis has 128-B payloads"),
                        ),
                    })
                    .collect::<Vec<_>>(),
            ),
        }
    }

    /// The startup line naming the role.
    pub(super) fn role_line(&self) -> String {
        match self.sequencer {
            Some(_) => format!(
                "ANNULET role=producer slot_secs={} max_empty_slots={} (sequencer key held; \
                 finality is operator governance: final on acceptance)",
                self.slot.as_secs(),
                self.max_empty_slots
            ),
            None => "ANNULET role=follower (no sequencer key; production off)".to_string(),
        }
    }
}

/// Where an Annulet node's sequencer key comes from (lab #972), decided
/// without reading it, so `check` can ask the same question `run` does.
#[derive(Debug)]
pub(crate) enum SequencerSource<'a> {
    /// No key: the node follows.
    None,
    /// `data_dir/sequencer.key` (devnets; the convention since lab #708).
    File(std::path::PathBuf),
    /// `sequencer_key = "fifo:<path>"`: read once at start, kept in memory.
    Pipe(&'a std::path::Path),
}

/// The most bytes read from the sequencer key pipe. The key file's TOML is
/// about 100 B; anything near this is not a key file.
pub const SEQUENCER_KEY_PIPE_MAX_BYTES: u64 = 4096;

/// [`SequencerSource`] for `config`, or a refusal by name (lab #972): a
/// `sequencer_key` that is not `fifo:<path>`, a pipe path that does not
/// exist or is not a pipe, or the pipe configured while the key file is
/// also on disk.
pub(crate) fn sequencer_source(config: &NodeConfig) -> Result<SequencerSource<'_>, RunError> {
    let file = config.data_dir.join(SEQUENCER_KEY_FILE);
    let file_present = file.try_exists().map_err(RunError::Io)?;
    let Some(pipe) = config.sequencer_key_pipe().map_err(RunError::Config)? else {
        return Ok(if file_present { SequencerSource::File(file) } else { SequencerSource::None });
    };
    if file_present {
        return Err(RunError::SequencerKey(format!(
            "sequencer_key names the pipe {}, but {} is also on disk: remove the file (a production \
             key is never written to the host) or unset sequencer_key",
            pipe.display(),
            file.display()
        )));
    }
    let meta = match std::fs::metadata(pipe) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(RunError::SequencerKey(format!(
                "sequencer_key names the pipe {}, which does not exist, and there is no {}: create the \
                 pipe (mkfifo) before start and write the key into it, or unset sequencer_key to follow",
                pipe.display(),
                file.display()
            )))
        }
        Err(e) => return Err(RunError::Io(e)),
    };
    if !is_pipe(&meta) {
        return Err(RunError::SequencerKey(format!(
            "sequencer_key names {}, which is not a pipe: a key in a regular file belongs at {} \
             (devnets only)",
            pipe.display(),
            file.display()
        )));
    }
    Ok(SequencerSource::Pipe(pipe))
}

#[cfg(unix)]
fn is_pipe(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::FileTypeExt;
    meta.file_type().is_fifo() || meta.file_type().is_socket()
}

#[cfg(not(unix))]
fn is_pipe(_meta: &std::fs::Metadata) -> bool {
    false
}

/// Read the sequencer key from its pipe (lab #972): opening blocks until the
/// operator's writer opens the other end; the read ends at the writer's
/// close. The content is the key file's TOML ([`SequencerKeyFile`]). The
/// buffers that held it are zeroed before return (best effort: the TOML
/// parser's own copies are not reachable from here).
pub(crate) fn read_sequencer_key_pipe(path: &std::path::Path) -> Result<[u8; 32], RunError> {
    use std::io::Read;
    qlab_devnet::jprintln!("STARTUP waiting for the sequencer key on the pipe {} (lab #972)", path.display());
    let mut buf = Vec::with_capacity(SEQUENCER_KEY_PIPE_MAX_BYTES as usize + 1);
    std::fs::File::open(path)
        .and_then(|f| f.take(SEQUENCER_KEY_PIPE_MAX_BYTES + 1).read_to_end(&mut buf))
        .map_err(RunError::Io)?;
    let seed = parse_piped_key(&buf);
    wipe(&mut buf);
    seed
}

fn parse_piped_key(buf: &[u8]) -> Result<[u8; 32], RunError> {
    if buf.iter().all(u8::is_ascii_whitespace) {
        return Err(RunError::SequencerKey(
            "the sequencer key pipe closed without a key: write the key file's TOML into it".into(),
        ));
    }
    if buf.len() as u64 > SEQUENCER_KEY_PIPE_MAX_BYTES {
        return Err(RunError::SequencerKey(format!(
            "more than {SEQUENCER_KEY_PIPE_MAX_BYTES} B arrived on the sequencer key pipe: not a key file"
        )));
    }
    let text = std::str::from_utf8(buf)
        .map_err(|_| RunError::SequencerKey("the sequencer key pipe carried bytes that are not UTF-8 TOML".into()))?;
    let mut file = SequencerKeyFile::from_toml(text)?;
    let seed = file.seed();
    let mut hex = std::mem::take(&mut file.seed_hex).into_bytes();
    wipe(&mut hex);
    Ok(seed?)
}

fn wipe(bytes: &mut [u8]) {
    bytes.fill(0);
    std::hint::black_box(bytes);
}

/// What one producer slot did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlotOutcome {
    /// A block was sealed, applied and relayed.
    Sealed { height: u64, txs: usize, peers: usize },
    /// The pool was empty and the empty-block interval has not elapsed.
    EmptySlot { empty_run: u64 },
    /// The state has not applied the header tip yet; nothing is built on it.
    StateLags { state_tip: u64, header_tip: u64 },
    /// This node is a follower (or not on an Annulet net).
    NotProducer,
}

impl<P: PowEngine, V: TxVerifier + Clone> RunningNode<P, V> {
    /// Phase ① for an **Annulet** genesis (lab #708): verify the file and its
    /// pinned hash, refuse what a sequencer net cannot run under, and select
    /// the role from the sequencer key file. Nothing is opened or bound.
    pub fn prepare_annulet<'a>(
        config: &'a NodeConfig,
        genesis: &'a AnnuletGenesisFile,
        pow: P,
        verifier: V,
    ) -> Result<PreparedNode<'a, P, V>, RunError> {
        genesis.verify(config.expected_genesis_hash.as_deref())?;
        if !config.committee_key_paths.is_empty() {
            return Err(RunError::Annulet(
                "committee_key_paths are set, but a sequencer net has no committee",
            ));
        }
        if config.mining {
            return Err(RunError::Annulet(
                "mining = true, but an Annulet node produces only as the sequencer, selected by the \
                 sequencer key file in the data dir",
            ));
        }
        let pinned = genesis.sequencer()?;
        let sequencer = match sequencer_source(config)? {
            SequencerSource::None => None,
            SequencerSource::File(path) => {
                let text = std::fs::read_to_string(path).map_err(RunError::Io)?;
                let key = SequencerKey::from_seed(SequencerKeyFile::from_toml(&text)?.seed()?);
                if key.verifying_key() != pinned {
                    return Err(RunError::Annulet(
                        "the sequencer key file's key is not the genesis sequencer key",
                    ));
                }
                Some(key)
            }
            SequencerSource::Pipe(path) => {
                let key = SequencerKey::from_seed(read_sequencer_key_pipe(path)?);
                if key.verifying_key() != pinned {
                    return Err(RunError::Annulet(
                        "the key read from the sequencer key pipe is not the genesis sequencer key",
                    ));
                }
                qlab_devnet::jprintln!(
                    "STARTUP sequencer key read from the pipe {}; held in memory only (lab #972)",
                    path.display()
                );
                Some(key)
            }
        };
        Ok(PreparedNode {
            config,
            genesis: PreparedGenesis::Annulet { file: genesis, sequencer },
            pow,
            verifier,
            release: RELEASE,
            marker: None,
            rules: qlab_devnet::halt::RuleSchedule::V1_0,
            committee: CommitteeState::new(Committee::from_keys(Vec::new()), 0),
            finalizers: Vec::new(),
            sim: SimConfig::default(),
        })
    }

    /// [`Self::prepare_annulet`] + open, for callers that bind nothing early.
    pub fn start_annulet(
        config: &NodeConfig,
        genesis: &AnnuletGenesisFile,
        pow: P,
        verifier: V,
    ) -> Result<Self, RunError> {
        Self::prepare_annulet(config, genesis, pow, verifier)?.open()
    }

    /// The `/v1/genesis/notes` body (lab #714): `Some` exactly on an Annulet
    /// node.
    pub fn genesis_notes_body(&self) -> Option<Vec<u8>> {
        self.annulet.as_ref().map(|a| a.genesis_notes.clone())
    }

    /// The `/genesis.qmb` body (lab #850 AD1): `Some` exactly on an Annulet
    /// node.
    pub fn genesis_file_body(&self) -> Option<Vec<u8>> {
        self.annulet.as_ref().map(|a| a.genesis_file.clone())
    }

    /// The `/v1/annulet/params` body (lab #720): `Some` exactly on an
    /// Annulet node.
    pub fn annulet_params_body(&self) -> Option<Vec<u8>> {
        self.annulet.as_ref().map(|a| a.params.clone())
    }

    /// Whether this node is the Annulet producer.
    pub fn is_sequencer(&self) -> bool {
        self.annulet.as_ref().is_some_and(|a| a.sequencer.is_some())
    }

    /// The loop's slot step: run [`Self::seal_slot`] once per `slot_secs` of
    /// wall clock, stamped with the wall-clock time.
    pub(super) fn seal_slot_if_due(&mut self) {
        let due = match &self.annulet {
            Some(a) if a.sequencer.is_some() => a.last_slot.elapsed() >= a.slot,
            Some(_) | None => false,
        };
        if due {
            if let Some(a) = self.annulet.as_mut() {
                a.last_slot = Instant::now();
            }
            let _ = self.seal_slot(unix_secs());
        }
    }

    /// **One producer slot** at `timestamp` (lab #708): seal when the pool is
    /// non-empty, or when `max_empty_slots` consecutive slots have passed
    /// empty; skip while the state lags the header tip. The sealed block goes
    /// through the adapter's own ingest (the follower's path) and is relayed.
    /// Tests drive this directly with deterministic timestamps.
    pub fn seal_slot(&mut self, timestamp: u64) -> SlotOutcome {
        let pool = self.p2p.node().mempool().len();
        let Some(run) = self.annulet.as_mut() else { return SlotOutcome::NotProducer };
        if run.sequencer.is_none() {
            return SlotOutcome::NotProducer;
        }
        let (state_tip, header_tip) = (self.p2p.node().state().tip_height(), self.p2p.node().tip_height());
        if state_tip != header_tip {
            qlab_devnet::jprintln!("SEAL skipped state_tip={state_tip} header_tip={header_tip} (applying bodies first)");
            return SlotOutcome::StateLags { state_tip, header_tip };
        }
        if pool == 0 && run.empty_run + 1 < run.max_empty_slots {
            run.empty_run += 1;
            return SlotOutcome::EmptySlot { empty_run: run.empty_run };
        }
        run.empty_run = 0;
        match self.seal_block_now(timestamp) {
            Ok((sealed, txs, peers)) => SlotOutcome::Sealed { height: sealed.header.height, txs, peers },
            Err(why) => {
                qlab_devnet::jprintln!(WARN, "SEAL failed: {why}");
                SlotOutcome::StateLags { state_tip, header_tip }
            }
        }
    }

    /// Seal, apply and relay one block now, whatever the slot rule says
    /// (the slot rule is [`Self::seal_slot`]'s). Returns the sealed header,
    /// its transaction count and the peers it was announced to.
    pub fn seal_block_now(&mut self, timestamp: u64) -> Result<(SealedHeader, usize, usize), String> {
        let key = self
            .annulet
            .as_ref()
            .and_then(|a| a.sequencer.as_ref())
            .ok_or("this node is not the sequencer")?;
        let (sealed, body) = self.p2p.node_mut().seal_next_block(key, timestamp)?;
        let nonce = u64::from_le_bytes(sealed.id()[..8].try_into().expect("8 bytes"));
        let peers = self.p2p.relay_sealed_block(&sealed, &body, nonce);
        qlab_devnet::jprintln!(
            "SEAL height={} txs={} peers={} id={}",
            sealed.header.height,
            body.txs.len(),
            peers,
            sealed.id()[..4].iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        Ok((sealed, body.txs.len(), peers))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::annulet_genesis::AnnuletGenesisBuild;
    use qlab_devnet::pow::KeccakPow;
    use std::path::PathBuf;

    /// A temp data dir and a config for the fixture Annulet genesis; with
    /// `producer`, the fixture sequencer key file is written into the data
    /// dir first.
    fn annulet_rig(tag: &str, producer: bool) -> (NodeConfig, AnnuletGenesisFile, PathBuf) {
        let base = std::env::temp_dir().join(format!("qmb_annulet_run_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let data = base.join("data");
        std::fs::create_dir_all(&data).unwrap();
        let genesis = AnnuletGenesisFile::fixture();
        if producer {
            let kf = SequencerKeyFile { seed_hex: "5e".repeat(32), note: "fixture sequencer key (test)".into() };
            std::fs::write(data.join(SEQUENCER_KEY_FILE), kf.to_toml()).unwrap();
        }
        let config = NodeConfig {
            data_dir: data,
            listen_addr: "127.0.0.1:0".to_string(),
            dial_peers: vec![],
            advertise_addr: None,
            genesis_file: base.join("genesis.qmb"),
            committee_key_paths: vec![],
            mining: false,
            expected_genesis_hash: Some(genesis.hash_hex()),
            metrics_addr: None,
            telemetry_addr: None,
            discovery_addr: None,
            miner_rkm: None,
            template_serving: false,
            operator_addr: None,
            sequencer_key: None,
        };
        (config, genesis, base)
    }

    fn start(config: &NodeConfig, genesis: &AnnuletGenesisFile) -> RunningNode<KeccakPow, DevnetRehearsalVerifier> {
        RunningNode::start_annulet(config, genesis, KeccakPow, DevnetRehearsalVerifier).expect("starts")
    }

    /// Every finality-facing surface of a running node, read the way its
    /// consumers read it.
    #[derive(Debug)]
    struct FinalitySurfaces {
        tip: u64,
        finalized: Option<u64>,
        age_s: Option<u64>,
        regime: FinalityStatus,
        stall_depth: u64,
        gauge_stall_depth: bool,
        checkpoint_query: Option<u64>,
        committee_series: bool,
        open_rounds: usize,
        names_its_form: bool,
    }

    fn surfaces<P: PowEngine, V: TxVerifier + Clone>(n: &RunningNode<P, V>) -> FinalitySurfaces {
        let t = n.telemetry();
        let metrics = n.metrics_text();
        FinalitySurfaces {
            tip: t.tip_height,
            finalized: t.finalized_height,
            age_s: t.last_finalized_age_secs,
            regime: t.finality_status,
            stall_depth: t.stall_depth,
            gauge_stall_depth: metrics.contains("\nqumbra_stall_depth_blocks 0\n"),
            checkpoint_query: n.p2p().checkpoint_query_trigger(),
            committee_series: metrics.contains("\nqumbra_committee_size "),
            open_rounds: n.p2p().node().rounds().open_len(),
            names_its_form: n.telemetry_sample().ends_with(" form=annulet finality=operator")
                && metrics.contains("\nqumbra_chain_form{form=\"annulet\",finality=\"operator\"} 1\n"),
        }
    }

    /// The finality-facing surfaces a sequencer chain must show: each check
    /// that fails, by name. Empty = the Annulet shape.
    fn annulet_shape_violations(s: &FinalitySurfaces) -> Vec<&'static str> {
        let mut v = Vec::new();
        if s.finalized != Some(s.tip) {
            v.push("finalized_height != tip");
        }
        if s.tip > 0 && s.age_s != Some(0) {
            v.push("age_s not fresh");
        }
        if s.regime != FinalityStatus::Final {
            v.push("regime not final");
        }
        if s.stall_depth != 0 || !s.gauge_stall_depth {
            v.push("stall_depth != 0");
        }
        if s.checkpoint_query.is_some() {
            v.push("checkpoint polling armed");
        }
        if s.committee_series {
            v.push("committee gauges present");
        }
        if s.open_rounds != 0 {
            v.push("checkpoint rounds open");
        }
        if !s.names_its_form {
            v.push("form not named on the text surfaces");
        }
        v
    }

    /// 🔴 **The finality lock** (the lab #708 ruling on the B2a review): a
    /// missing form decision at a finality consumer is invisible to a lexical
    /// lock, so this drives a real Annulet node through ~1,200 sealed blocks —
    /// past the 144-block coinbase-maturity point and the 1,152-block epoch
    /// boundary, both with an empty committee — and asserts every
    /// finality-facing surface at once, at several heights, through the real
    /// loop (`one_iteration`) as well as the producer step.
    ///
    /// **Build-note checklist line: any new consumer of finality must appear
    /// in this test** ([`FinalitySurfaces`] / [`annulet_shape_violations`]).
    #[test]
    fn every_finality_surface_reads_final_at_the_tip_on_an_annulet_chain() {
        let (config, genesis, base) = annulet_rig("i708_lock", true);
        let mut node = start(&config, &genesis);
        assert!(node.is_sequencer());
        let t0 = genesis.genesis_header.timestamp;
        let started = Instant::now();
        for h in 1..=1_200u64 {
            let (sealed, _, _) = node.seal_block_now(t0 + 10 * h).expect("the producer seals");
            assert_eq!(sealed.header.height, h);
            if matches!(h, 1 | 145 | 1_152 | 1_153 | 1_200) {
                node.one_iteration(&mut |_| {});
                let s = surfaces(&node);
                assert_eq!(s.tip, h, "{s:?}");
                assert_eq!(annulet_shape_violations(&s), Vec::<&str>::new(), "height {h}: {s:?}");
            }
        }
        eprintln!("annulet finality lock: 1,200 sealed blocks in {:?}", started.elapsed());
        assert_eq!(node.p2p().node().state().tip_height(), 1_200);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The same assertions against an **L1** chain whose finality lags (blocks
    /// mined, no checkpoint signed): the lock tells the two apart, so it is not
    /// vacuously green.
    #[test]
    fn the_finality_lock_distinguishes_an_l1_chain_whose_finality_lags() {
        use qlab_p2p::n1::BlockIngest;
        let (config, genesis, _base) = super::super::tests::rig("i708_l1_contrast", false);
        let mut node = RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        for _ in 0..20 {
            let (h, body) = node.p2p.node_mut().mine_block().expect("KeccakPow mines at genesis difficulty");
            assert_eq!(node.p2p.node_mut().ingest_block(h, body), qlab_p2p::n1::IngestOutcome::Accepted);
        }
        node.one_iteration(&mut |_| {});
        let v = annulet_shape_violations(&surfaces(&node));
        for want in [
            "finalized_height != tip",
            "regime not final",
            "stall_depth != 0",
            "checkpoint polling armed",
            "committee gauges present",
            "form not named on the text surfaces",
        ] {
            assert!(v.contains(&want), "the L1 contrast must show `{want}`: {v:?}");
        }
    }

    #[test]
    fn a_follower_runs_without_a_key_file_and_produces_nothing() {
        let (config, genesis, base) = annulet_rig("i708_follower", false);
        let mut node = start(&config, &genesis);
        assert!(!node.is_sequencer());
        assert_eq!(node.seal_slot(t_after(&genesis, 1)), SlotOutcome::NotProducer);
        assert!(node.seal_block_now(t_after(&genesis, 1)).is_err());
        node.one_iteration(&mut |_| {});
        assert_eq!(node.tip_height(), 0);
        assert_eq!(annulet_shape_violations(&surfaces(&node)), Vec::<&str>::new());
        let _ = std::fs::remove_dir_all(&base);
    }

    fn t_after(g: &AnnuletGenesisFile, slots: u64) -> u64 {
        g.genesis_header.timestamp + 10 * slots
    }

    /// The slot rule (Q5): an empty pool seals nothing until
    /// `max_empty_slots` slots have passed empty, then an empty block.
    #[test]
    fn the_producer_seals_an_empty_block_every_max_empty_slots() {
        let (config, genesis, base) = annulet_rig("i708_slots", true);
        let mut node = start(&config, &genesis);
        let max = genesis.params.max_empty_slots;
        assert_eq!(max, 6);
        for k in 1..max {
            assert_eq!(node.seal_slot(t_after(&genesis, k)), SlotOutcome::EmptySlot { empty_run: k });
        }
        assert_eq!(node.seal_slot(t_after(&genesis, max)), SlotOutcome::Sealed { height: 1, txs: 0, peers: 0 });
        assert_eq!(node.seal_slot(t_after(&genesis, max + 1)), SlotOutcome::EmptySlot { empty_run: 1 });
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The fixture genesis's sequencer key file (the one `annulet_rig` writes).
    fn fixture_key_toml() -> String {
        SequencerKeyFile { seed_hex: "5e".repeat(32), note: "fixture sequencer key (test)".into() }.to_toml()
    }

    /// A named pipe at `path` (lab #972), made by the system's `mkfifo`.
    #[cfg(unix)]
    fn mkfifo(path: &std::path::Path) {
        let ok = std::process::Command::new("mkfifo").arg(path).status().expect("mkfifo runs").success();
        assert!(ok, "mkfifo {}", path.display());
    }

    /// Open the pipe's write end on a thread (the open blocks until the node
    /// opens the read end), write `bytes`, close.
    #[cfg(unix)]
    fn write_into_pipe(path: PathBuf, bytes: Vec<u8>) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            use std::io::Write;
            let mut w = std::fs::OpenOptions::new().write(true).open(&path).expect("open the pipe's write end");
            w.write_all(&bytes).expect("write the key");
        })
    }

    fn prepare_err(config: &NodeConfig, genesis: &AnnuletGenesisFile) -> Option<String> {
        RunningNode::<KeccakPow, DevnetRehearsalVerifier>::prepare_annulet(config, genesis, KeccakPow, DevnetRehearsalVerifier)
            .err()
            .map(|e| e.to_string())
    }

    /// 🔴 **Lab #972: the producer starts from a key written into its pipe**,
    /// and nothing is written to the data dir. `check`'s preflight on the same
    /// config does not read the pipe (a reader there would consume the key).
    #[cfg(unix)]
    #[test]
    fn a_sequencer_starts_from_the_key_written_into_its_pipe_lab_972() {
        let (mut config, genesis, base) = annulet_rig("i972_pipe", false);
        let pipe = base.join("sequencer.fifo");
        mkfifo(&pipe);
        config.sequencer_key = Some(format!("fifo:{}", pipe.display()));
        let any = crate::annulet_genesis::AnyGenesis::Annulet(Box::new(genesis.clone()));
        assert!(crate::run::preflight_any(&config, &any).is_ok(), "check accepts the pipe without reading it");
        let writer = write_into_pipe(pipe.clone(), fixture_key_toml().into_bytes());
        let node = start(&config, &genesis);
        writer.join().expect("the writer finished");
        assert!(node.is_sequencer(), "the piped key makes the node the producer");
        assert!(!config.data_dir.join(SEQUENCER_KEY_FILE).exists(), "the key never reaches the data dir");
        drop(node);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Lab #972 refusals, each by name: the pipe named but absent (and no key
    /// file either); a regular file where the pipe should be; the pipe and
    /// the key file both present; a value that is not `fifo:<path>`; a pipe
    /// closed empty; a wrong key through the pipe; the key set on a genesis
    /// with no sequencer.
    #[cfg(unix)]
    #[test]
    fn the_sequencer_key_pipe_refusals_lab_972() {
        let (mut config, genesis, base) = annulet_rig("i972_refusals", false);
        let pipe = base.join("sequencer.fifo");
        config.sequencer_key = Some(format!("fifo:{}", pipe.display()));
        // Neither the pipe nor the file.
        assert!(prepare_err(&config, &genesis).is_some_and(|e| e.contains("does not exist") && e.contains("lab #972")));
        // A regular file is not a pipe.
        std::fs::write(&pipe, fixture_key_toml()).unwrap();
        assert!(prepare_err(&config, &genesis).is_some_and(|e| e.contains("not a pipe")));
        std::fs::remove_file(&pipe).unwrap();
        mkfifo(&pipe);
        // The pipe configured while the key file is also on disk.
        std::fs::write(config.data_dir.join(SEQUENCER_KEY_FILE), fixture_key_toml()).unwrap();
        assert!(prepare_err(&config, &genesis).is_some_and(|e| e.contains("also on disk")));
        std::fs::remove_file(config.data_dir.join(SEQUENCER_KEY_FILE)).unwrap();
        // Any value but fifo:<path>.
        for bad in ["file:/x", "fifo:", "/run/annulet/sequencer.fifo"] {
            let mut c = config.clone();
            c.sequencer_key = Some(bad.to_string());
            assert!(prepare_err(&c, &genesis).is_some_and(|e| e.contains("the only accepted form")), "{bad}");
        }
        // The writer closes without writing.
        let writer = write_into_pipe(pipe.clone(), Vec::new());
        assert!(prepare_err(&config, &genesis).is_some_and(|e| e.contains("closed without a key")));
        writer.join().unwrap();
        // A key that is not the genesis sequencer key.
        let wrong = SequencerKeyFile { seed_hex: "5f".repeat(32), note: String::new() }.to_toml();
        let writer = write_into_pipe(pipe.clone(), wrong.into_bytes());
        assert!(prepare_err(&config, &genesis).is_some_and(|e| e.contains("pipe is not the genesis sequencer key")));
        writer.join().unwrap();
        // On an L1 genesis there is no sequencer to read it.
        let l1 = crate::genesis::GenesisFile::new_devnet_t0();
        let any = crate::annulet_genesis::AnyGenesis::L1(Box::new(l1));
        config.expected_genesis_hash = None;
        assert!(crate::run::preflight_any(&config, &any)
            .err()
            .is_some_and(|e| e.to_string().contains("only an Annulet genesis has a sequencer")));
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Lab #972: with `sequencer_key` unset the data-dir file decides, as
    /// before — present: the producer; absent: a follower.
    #[test]
    fn without_sequencer_key_the_data_dir_file_still_decides_the_role_lab_972() {
        let (config, genesis, base) = annulet_rig("i972_file", true);
        assert_eq!(config.sequencer_key, None);
        assert!(start(&config, &genesis).is_sequencer());
        let _ = std::fs::remove_dir_all(&base);
        let (config, genesis, base) = annulet_rig("i972_nofile", false);
        assert!(!start(&config, &genesis).is_sequencer());
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Refusals by name, before anything opens.
    #[test]
    fn run_refuses_what_a_sequencer_net_cannot_run_under() {
        let (mut config, genesis, base) = annulet_rig("i708_refusals", false);
        let refused = |c: &NodeConfig| {
            RunningNode::<KeccakPow, DevnetRehearsalVerifier>::prepare_annulet(c, &genesis, KeccakPow, DevnetRehearsalVerifier)
                .err()
                .map(|e| e.to_string())
        };
        // A key file whose key is not the genesis sequencer key.
        let wrong = SequencerKeyFile { seed_hex: "5f".repeat(32), note: String::new() };
        std::fs::write(config.data_dir.join(SEQUENCER_KEY_FILE), wrong.to_toml()).unwrap();
        assert!(refused(&config).is_some_and(|e| e.contains("not the genesis sequencer key")));
        std::fs::remove_file(config.data_dir.join(SEQUENCER_KEY_FILE)).unwrap();
        // Committee keys, and mining.
        config.committee_key_paths = vec![base.join("k0.toml")];
        assert!(refused(&config).is_some_and(|e| e.contains("no committee")));
        config.committee_key_paths.clear();
        config.mining = true;
        assert!(refused(&config).is_some_and(|e| e.contains("mining = true")));
        config.mining = false;
        // A wrong pinned genesis hash.
        config.expected_genesis_hash = Some("00".repeat(32));
        assert!(refused(&config).is_some());
        let _ = std::fs::remove_dir_all(&base);
    }

    /// 🔴 **The submit route's early discovery check is the form's** (lab #716,
    /// the third L1-only seam on `POST /v1/tx`, found by the B6 journey's
    /// second lane run). One transaction whose group carries two outputs at
    /// the **L2 width** (128-B payloads, a 256-B section): an Annulet node's
    /// `submit_remote_tx` admits it, and an L1 node refuses it at that same
    /// check as a malformed section (expected 240) — so the check is keyed,
    /// and not merely permissive.
    #[test]
    fn the_submit_routes_discovery_check_takes_the_l2_width_on_annulet_and_refuses_it_on_l1() {
        use crate::discovery_server::{TxRefusal, TxSubmitOutcome};
        use qlab_devnet::annulet::{L2ShapeTag, L2Surface};
        use qlab_devnet::body::{BodyError, TxEntry, TxPublic};
        use qlab_devnet::fees::ArityBucket;
        use qlab_note::l2note::{L2Note, L2_PAYLOAD_LEN};
        use rand::SeedableRng;

        let (config, genesis, base) = annulet_rig("i716_submit_width", true);
        let mut node = start(&config, &genesis);
        let mut rng = rand::rngs::StdRng::seed_from_u64(716);
        let wallet = qlab_note::kem::generate_keypair(&mut rng);
        let note = |k: u64| L2Note { value: k, asset: 0, rkm: [k; 4], rho: [k + 1; 4], rseed: [k + 2; 4] };
        let notes = [note(10), note(20)];
        let out = qlab_note::scan::encrypt_notes_to_recipient(&wallet.ek, &notes, &mut rng);
        assert!(out.payloads.iter().all(|p| p.len() == L2_PAYLOAD_LEN));
        let state = node.p2p().node().state();
        let tx = TxEntry {
            auth: qlab_devnet::annulet::L2_AUTH_ABSENT.to_vec(),
            proof: b"ok".to_vec(),
            public: TxPublic {
                anchor: state.commitment_root(),
                nullifiers: vec![[0x71; 32], [0x72; 32], [0x73; 32]],
                commitments: notes.iter().map(|n| qlab_note::hash::digest_bytes(&n.commitment())).collect(),
                bucket: ArityBucket::TwoByTwo,
                fee: genesis.params.fee_tier_s,
            },
            discovery: qlab_note::compact::encode_committed_discovery_with_width(
                std::slice::from_ref(&out.bundle),
                &out.payloads,
                L2_PAYLOAD_LEN,
            ),
            rider: qlab_devnet::names::RIDER_ABSENT.to_vec(),
            l2: L2Surface {
                shape: L2ShapeTag::S,
                registry_root: state.registry_root_bytes().expect("an Annulet state has a registry"),
                vpublic: None,
                write: None,
                exit_rkm: [0; 32],
            }
            .encode(),
        };

        // Annulet: past the discovery check and admitted (rehearsal verifier).
        let annulet = node.submit_remote_tx(tx.clone());
        assert!(matches!(annulet, TxSubmitOutcome::Accepted { .. }), "{annulet:?}");
        let _ = std::fs::remove_dir_all(&base);

        // L1: the same bytes refused AT the discovery check, as a malformed section.
        let (config, genesis, _base) = super::super::tests::rig("i716_submit_width_l1", false);
        let mut l1 = RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
        match l1.submit_remote_tx(tx) {
            TxSubmitOutcome::Refused(TxRefusal::Discovery(BodyError::DiscoveryMalformed { .. })) => {}
            other => panic!("an L1 node must refuse the 128-B section at the discovery check: {other:?}"),
        }
    }

    /// A restarted producer resumes its sealed chain from the data dir
    /// (persist variant 3): same tip, final = tip, and it keeps sealing.
    #[test]
    fn a_restarted_producer_resumes_and_keeps_sealing() {
        let (config, genesis, base) = annulet_rig("i708_restart", true);
        let tip = {
            let mut node = start(&config, &genesis);
            for h in 1..=5 {
                node.seal_block_now(t_after(&genesis, h)).unwrap();
            }
            node.p2p().node().tip_hash()
        };
        let mut node = start(&config, &genesis);
        assert_eq!(node.p2p().node().tip_hash(), tip);
        assert_eq!(node.finalized_height(), Some(5));
        let (sealed, _, _) = node.seal_block_now(t_after(&genesis, 6)).unwrap();
        assert_eq!(sealed.header.prev, tip);
        let _ = std::fs::remove_dir_all(&base);
    }
}
