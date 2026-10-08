//! **The verified Annulet scan, caller-pumped** (lab #858 WA1) — the scan of
//! [`crate::annulet_verify`] for a host with no synchronous network (the
//! browser extension's wasm, the macOS shell through `qumbra-ffi`).
//!
//! The same inversion as [`crate::driver::SelectDriver`] (lab #399): **the
//! driver owns every decision and does no I/O.** A host alternates
//! [`AnnuletVerifyDriver::step`] (`Need` a path / `Done` with the
//! [`VerifiedAnnulet`] / `Failed` by name) with
//! [`AnnuletVerifyDriver::supply`], from any transport, suspending as long as
//! it likes. A transport failure is supplied as `Err(why)` and becomes the
//! same named refusal (or, where the synchronous scan tolerated it, the same
//! tolerated gap) the synchronous scan gives.
//!
//! **One orchestration.** [`crate::annulet_verify::scan_annulet_verified`] is
//! this driver's pump; nothing else sequences the steps. Each step's checks
//! are the shared ones: [`crate::annulet_verify::genesis_from_bytes`], the
//! header [`ChainWalk`], the record's
//! [`crate::annulet_verify::decode_chain_cache`], the scan body
//! [`AnnuletScanCore`] (itself over `MultiScanDriver` and `SpentCatchUp`), and
//! the body binding below.
//!
//! **No filesystem.** The verified-header record (WA0) comes in as bytes
//! ([`crate::annulet_verify::read_chain_record`] — read by the pin, which is
//! the genesis hash the scan will verify) and goes out as
//! [`VerifiedAnnulet::record_to_write`]; the host writes it.

use std::collections::BTreeMap;

use qlab_devnet::annulet::body_commitment_annulet_for;
use qlab_devnet::chain::ChainState;
use qlab_devnet::forms::GenesisForm;
use qlab_devnet::header::BlockHeader;
use qlab_node::annulet_genesis::h32;
use qlab_note::l2note::{GenesisPlaintext, L2Note};
use qlab_p2p::served::decode_body_answer;
use qlab_wallet::Wallet;
use rand::rngs::StdRng;

use crate::annulet::{AnnuletReport, AnnuletScanCore, CoreStep};
use crate::annulet_verify::{
    decode_chain_cache, genesis_from_bytes, header_path, served_header_at, stated_height, ChainCache, ChainWalk,
    VerifiedAnnulet, VerifiedChain, VerifiedGenesis, VerifyRefusal, GENESIS_FILE_PATH, REGISTRY_ROOT_PATH,
};

/// One observation from a caller-pumped [`AnnuletVerifyDriver`]. `Done` and
/// `Failed` are terminal.
pub enum AnnuletStep {
    Need(String),
    Done(Box<VerifiedAnnulet>),
    Failed(VerifyRefusal),
}

/// How the chain phase came to walk: from genesis (the record unused or
/// discarded), or past a resumed record.
enum How {
    Fresh(ChainCache),
    Resumed,
}

enum Phase {
    Genesis,
    Walk { walk: Box<ChainWalk>, how: How },
    /// Re-check the endpoint's header at `anchor` against the record;
    /// `clamped` once the anchor was lowered to the endpoint's stated tip.
    ResumeAt { genesis: VerifiedGenesis, cached: Vec<BlockHeader>, anchor: u64, clamped: bool },
    /// The endpoint serves nothing at the anchor: ask its stated tip.
    ResumeRoot { genesis: VerifiedGenesis, cached: Vec<BlockHeader>, anchor: u64 },
    Scan { core: Box<AnnuletScanCore>, post: Post },
    /// Bind the owned notes from `at` on, one body per block with a hit.
    Bodies { at: usize, report: AnnuletReport, post: Post },
    StatedTip { report: AnnuletReport, post: Post },
    Finished,
}

/// What the steps after the chain carry to the result.
struct Post {
    chain: VerifiedChain,
    cache: ChainCache,
    range: (u64, u64),
    genesis_notes: Vec<([u8; 32], L2Note)>,
    /// Per bound block, each transaction's commitments.
    bound: BTreeMap<u64, Vec<Vec<[u8; 32]>>>,
    bodies_fetched: u64,
    body_bytes: u64,
}

/// **The caller-pumped verified scan.** Construct with the wallet's keys, the
/// pin and the record's bytes; then alternate `step` and `supply`.
pub struct AnnuletVerifyDriver {
    wallet: Wallet,
    allocated: Vec<u64>,
    pin: [u8; 32],
    from: u64,
    to: u64,
    record: Option<Result<Option<Vec<u8>>, String>>,
    recorded_len: usize,
    phase: Phase,
    pending: Option<String>,
    failed: Option<VerifyRefusal>,
    done: Option<Box<VerifiedAnnulet>>,
    /// Lab #896 G: the generations a Candidate A scan owns notes under —
    /// the journal's when the wallet has one ([`Self::with_generations`]),
    /// else the probe set, built only once the genesis says Candidate A.
    generations: Option<Vec<(u32, [u64; 4])>>,
    /// Lab #937: an L2 axis this caller does not serve — refused by name
    /// right after the genesis verifies, before any header is fetched
    /// ([`Self::refusing`]). `None` for the wallet CLI.
    refuse: Option<qlab_devnet::forms::L2AuthForm>,
}

impl AnnuletVerifyDriver {
    /// Lab #937: refuse a net on the axis `form` by name
    /// ([`VerifyRefusal::FormatNotSupported`]) as soon as its genesis is
    /// verified — before any header, body or note is fetched. The kernel
    /// (`qumbra-ffi`) refuses format 34 this way until lab #937 PR D; the
    /// genesis check itself ([`crate::annulet_verify::genesis_from_bytes`])
    /// is unchanged and the wallet CLI never sets this.
    pub fn refusing(mut self, form: qlab_devnet::forms::L2AuthForm) -> Self {
        self.refuse = Some(form);
        self
    }

    /// Lab #896 G: the wallet's known generations (its journal's). Used only
    /// if the pinned genesis is a Candidate A one; a v1 net scans as before.
    pub fn with_generations(mut self, generations: Vec<(u32, [u64; 4])>) -> Self {
        self.generations = Some(generations);
        self
    }

    /// `record` is the verified-header record's bytes for the chain `pin`
    /// names — `Ok(None)` when there is none, `Err(why)` when it could not be
    /// read ([`crate::annulet_verify::read_chain_record`]).
    pub fn new(
        wallet: Wallet,
        allocated: Vec<u64>,
        pin: [u8; 32],
        from: u64,
        to: u64,
        record: Result<Option<Vec<u8>>, String>,
    ) -> Self {
        AnnuletVerifyDriver {
            wallet,
            allocated,
            pin,
            from,
            to,
            record: Some(record),
            recorded_len: 0,
            phase: Phase::Genesis,
            pending: None,
            failed: None,
            generations: None,
            done: None,
            refuse: None,
        }
    }

    /// Advance until the scan needs one path, completes, or is refused.
    pub fn step(&mut self, rng: &mut StdRng) -> AnnuletStep {
        if let Some(e) = &self.failed {
            return AnnuletStep::Failed(e.clone());
        }
        if let Some(v) = self.done.take() {
            return AnnuletStep::Done(v);
        }
        if let Some(path) = &self.pending {
            return AnnuletStep::Need(path.clone());
        }
        loop {
            let need = match std::mem::replace(&mut self.phase, Phase::Finished) {
                Phase::Genesis => {
                    self.phase = Phase::Genesis;
                    GENESIS_FILE_PATH.to_string()
                }
                Phase::Walk { walk, how } => match walk.want() {
                    Some((_, path)) => {
                        self.phase = Phase::Walk { walk, how };
                        path
                    }
                    None => {
                        self.after_chain((*walk).finish(), how);
                        continue;
                    }
                },
                Phase::ResumeAt { genesis, cached, anchor, clamped } => {
                    self.phase = Phase::ResumeAt { genesis, cached, anchor, clamped };
                    header_path(anchor)
                }
                Phase::ResumeRoot { genesis, cached, anchor } => {
                    self.phase = Phase::ResumeRoot { genesis, cached, anchor };
                    REGISTRY_ROOT_PATH.to_string()
                }
                Phase::Scan { mut core, post } => match core.step(rng) {
                    CoreStep::Need(path) => {
                        self.phase = Phase::Scan { core, post };
                        path
                    }
                    CoreStep::Done(report) => {
                        self.phase = Phase::Bodies { at: 0, report, post };
                        continue;
                    }
                    CoreStep::Failed(why) => return self.fail(VerifyRefusal::DriverMisuse { why }),
                },
                Phase::Bodies { at, report, post } => match bind_from(at, &report, &post) {
                    Err(e) => return self.fail(e),
                    Ok(Some((at, height))) => {
                        self.phase = Phase::Bodies { at, report, post };
                        format!("/v1/block/{height}/body")
                    }
                    Ok(None) => {
                        self.phase = Phase::StatedTip { report, post };
                        continue;
                    }
                },
                Phase::StatedTip { report, post } => {
                    self.phase = Phase::StatedTip { report, post };
                    REGISTRY_ROOT_PATH.to_string()
                }
                Phase::Finished => {
                    return self.fail(VerifyRefusal::DriverMisuse { why: "stepped after the scan completed".into() })
                }
            };
            self.pending = Some(need.clone());
            return AnnuletStep::Need(need);
        }
    }

    /// Answer the outstanding `Need` — the bytes, or why the transport could
    /// not get them. An answer with none outstanding fails the driver by name
    /// ([`VerifyRefusal::DriverMisuse`]); one after a refusal changes nothing.
    pub fn supply(&mut self, answer: Result<Vec<u8>, String>) {
        if self.failed.is_some() {
            return;
        }
        if self.pending.take().is_none() {
            self.failed = Some(VerifyRefusal::DriverMisuse { why: "a response with no Need outstanding".into() });
            return;
        }
        let outcome = match std::mem::replace(&mut self.phase, Phase::Finished) {
            Phase::Genesis => answer
                .map_err(|why| VerifyRefusal::GenesisUnavailable { why })
                .and_then(|bytes| genesis_from_bytes(self.pin, &bytes))
                .and_then(|genesis| match self.refuse {
                    Some(form) if genesis.l2_auth == form => {
                        Err(VerifyRefusal::FormatNotSupported { format_version: genesis.file.format_version })
                    }
                    _ => Ok(genesis),
                })
                .and_then(|genesis| self.begin_chain(genesis)),
            Phase::Walk { mut walk, how } => {
                let from = walk.want().expect("a Need was outstanding").0;
                walk.admit(from, answer).map(|()| self.phase = Phase::Walk { walk, how })
            }
            Phase::ResumeAt { genesis, cached, anchor, clamped } => match served_header_at(genesis.wire(), anchor, answer) {
                Err(e) => Err(e),
                Ok(None) if !clamped => {
                    self.phase = Phase::ResumeRoot { genesis, cached, anchor };
                    Ok(())
                }
                Ok(None) => self.resume_refused(genesis, VerifyRefusal::CachedTipForked { height: anchor }),
                Ok(Some(served)) => self.resume_at(genesis, cached, anchor, served),
            },
            Phase::ResumeRoot { genesis, cached, anchor } => {
                // Behind the record: clamp to the endpoint's own stated tip.
                let anchor = stated_height(answer).unwrap_or(0).min(anchor);
                if anchor == 0 {
                    self.after_chain(VerifiedChain { genesis, headers: Vec::new() }, How::Resumed);
                } else {
                    self.phase = Phase::ResumeAt { genesis, cached, anchor, clamped: true };
                }
                Ok(())
            }
            Phase::Scan { mut core, post } => {
                core.supply(answer);
                self.phase = Phase::Scan { core, post };
                Ok(())
            }
            Phase::Bodies { at, report, mut post } => {
                let height = report.owned[at].height;
                bind_body(&mut post, height, answer).map(|()| self.phase = Phase::Bodies { at, report, post })
            }
            Phase::StatedTip { report, post } => {
                // Freshness, not trust: the node's own word on its tip, for
                // the line that says how far behind the verified chain is.
                let stated_tip = stated_height(answer);
                self.finish(report, post, stated_tip);
                Ok(())
            }
            Phase::Finished => Ok(()),
        };
        if let Err(e) = outcome {
            self.failed = Some(e);
        }
    }

    fn fail(&mut self, e: VerifyRefusal) -> AnnuletStep {
        self.failed = Some(e.clone());
        AnnuletStep::Failed(e)
    }

    /// The genesis is verified: load the record and choose the walk.
    fn begin_chain(&mut self, genesis: VerifiedGenesis) -> Result<(), VerifyRefusal> {
        let recorded = match self.record.take().unwrap_or(Ok(None)) {
            Err(why) => Err(why),
            Ok(None) => Ok(None),
            Ok(Some(bytes)) => decode_chain_cache(&bytes, &genesis).map(Some),
        };
        self.recorded_len = recorded.as_ref().ok().and_then(|r| r.as_ref().map(Vec::len)).unwrap_or(0);
        match recorded {
            Ok(None) => self.walk_fresh(genesis, ChainCache::Unused),
            Err(why) => self.walk_fresh(genesis, ChainCache::Discarded(VerifyRefusal::ChainCacheInvalid { why })),
            Ok(Some(cached)) => {
                let anchor = (cached.len() as u64).min(self.to);
                if anchor == 0 {
                    let walk = ChainWalk::from_genesis(genesis, self.to)?;
                    self.phase = Phase::Walk { walk: Box::new(walk), how: How::Resumed };
                } else {
                    self.phase = Phase::ResumeAt { genesis, cached, anchor, clamped: false };
                }
                Ok(())
            }
        }
    }

    fn walk_fresh(&mut self, genesis: VerifiedGenesis, cache: ChainCache) -> Result<(), VerifyRefusal> {
        let walk = ChainWalk::from_genesis(genesis, self.to)?;
        self.phase = Phase::Walk { walk: Box::new(walk), how: How::Fresh(cache) };
        Ok(())
    }

    /// The record was refused at resume: discard it and walk from genesis.
    fn resume_refused(&mut self, genesis: VerifiedGenesis, e: VerifyRefusal) -> Result<(), VerifyRefusal> {
        self.walk_fresh(genesis, ChainCache::Discarded(e))
    }

    /// The endpoint served `served` at the anchor: it must be the recorded
    /// header; then relink the record up to it and admit what is past it.
    fn resume_at(
        &mut self,
        genesis: VerifiedGenesis,
        cached: Vec<BlockHeader>,
        anchor: u64,
        served: BlockHeader,
    ) -> Result<(), VerifyRefusal> {
        if served != cached[anchor as usize - 1] {
            return self.resume_refused(genesis, VerifyRefusal::CachedTipForked { height: anchor });
        }
        let mut headers = cached;
        headers.truncate(anchor as usize);
        let mut state = ChainState::new_for(GenesisForm::Annulet, genesis.file.genesis_block_header());
        for h in &headers {
            if let Err(e) = state.insert_header(*h) {
                return self.resume_refused(genesis, VerifyRefusal::ChainCacheInvalid { why: format!("{e:?}") });
            }
        }
        if anchor as usize == headers.len() && anchor < self.to {
            let walk = ChainWalk::start(genesis, state, headers, self.to)?;
            self.phase = Phase::Walk { walk: Box::new(walk), how: How::Resumed };
        } else {
            self.after_chain(VerifiedChain { genesis, headers }, How::Resumed);
        }
        Ok(())
    }

    /// The chain is verified: name what the record did, clamp the range to
    /// the verified tip, and start the scan body.
    fn after_chain(&mut self, chain: VerifiedChain, how: How) {
        let cache = match how {
            How::Fresh(cache) => cache,
            How::Resumed => {
                let recorded = self.recorded_len as u64;
                ChainCache::Resumed { anchor: recorded.min(self.to).min(chain.tip()), recorded }
            }
        };
        let to = self.to.min(chain.tip());
        let genesis_notes: Vec<([u8; 32], L2Note)> = chain
            .genesis
            .file
            .genesis_notes
            .iter()
            .map(|n| {
                let note = GenesisPlaintext::open(&n.payload).expect("the file's structural check opened every payload");
                (n.cm, note)
            })
            .collect();
        let mut core = AnnuletScanCore::new(
            self.wallet.clone(),
            self.allocated.clone(),
            self.from,
            to,
            chain.genesis.hash,
            genesis_notes.clone(),
        );
        if chain.genesis.l2_auth.has_auth() {
            let generations = match &self.generations {
                Some(g) if !g.is_empty() => g.clone(),
                _ => crate::auth_journal::probe_roots(&self.wallet),
            };
            core = core.with_generations(generations);
        }
        let core = Box::new(core);
        let post = Post {
            chain,
            cache,
            range: (self.from, to),
            genesis_notes,
            bound: BTreeMap::new(),
            bodies_fetched: 0,
            body_bytes: 0,
        };
        self.phase = Phase::Scan { core, post };
    }

    fn finish(&mut self, report: AnnuletReport, post: Post, stated_tip: Option<u64>) {
        let Post { chain, cache, range, bodies_fetched, body_bytes, .. } = post;
        // The record is written only after every check passed — a refused
        // scan never gets here — and only when it would grow or was
        // discarded.
        let grows = chain.headers.len() > self.recorded_len;
        let write_record = matches!(cache, ChainCache::Discarded(_)) || grows;
        let v = VerifiedAnnulet {
            report,
            chain,
            range,
            bodies_fetched,
            body_bytes,
            stated_tip,
            cache,
            write_record,
            cache_write: None,
        };
        self.done = Some(Box::new(v));
    }
}

/// The next owned note from `at` on that needs a body — its index and
/// height — after checking every note before it; `None` when all are bound.
/// The checks are the pre-WA1 loop's, in its order.
fn bind_from(at: usize, report: &AnnuletReport, post: &Post) -> Result<Option<(usize, u64)>, VerifyRefusal> {
    for (i, owned) in report.owned.iter().enumerate().skip(at) {
        let Some(tx_index) = owned.tx_index else {
            if !post.genesis_notes.iter().any(|(cm, _)| *cm == owned.cm) {
                return Err(VerifyRefusal::ForgedGenesisNote { cm: owned.cm });
            }
            continue;
        };
        let height = owned.height;
        let forged = |why: &str| VerifyRefusal::ForgedNote { height, tx_index, why: why.to_string() };
        if h32(&owned.note.commitment()) != owned.cm {
            return Err(forged("the note does not open to the commitment it was served under"));
        }
        // Each block with a hit is fetched and bound once, whichever
        // address's row found it; what is kept is each transaction's
        // commitments.
        if !post.bound.contains_key(&height) {
            post.chain.header(height).ok_or_else(|| forged("above the verified tip"))?;
            return Ok(Some((i, height)));
        }
        let txs = &post.bound[&height];
        let cms = txs.get(tx_index as usize).ok_or_else(|| forged("the block has no such transaction"))?;
        if !cms.contains(&owned.cm) {
            return Err(forged("the transaction carries no such commitment"));
        }
    }
    Ok(None)
}

/// Bind the body served for `height` to its verified header.
fn bind_body(post: &mut Post, height: u64, answer: Result<Vec<u8>, String>) -> Result<(), VerifyRefusal> {
    let header = post.chain.header(height).expect("bind_from asked only under the verified tip");
    let bytes = answer.map_err(|why| VerifyRefusal::BodyUnavailable { height, why })?;
    post.bodies_fetched += 1;
    post.body_bytes += bytes.len() as u64;
    let ann = decode_body_answer(post.chain.genesis.wire(), height, &bytes)
        .map_err(|e| VerifyRefusal::BodyMalformed { height, why: e.to_string() })?;
    if ann.header != header {
        return Err(VerifyRefusal::BodyHeaderMismatch { height });
    }
    let body = qlab_p2p::served::body_of(&ann);
    crate::annulet_verify::check_body_counts(height, &body)?;
    if body_commitment_annulet_for(&body, post.chain.genesis.l2_auth) != header.tx_body_commitment {
        return Err(VerifyRefusal::BodyCommitmentMismatch { height });
    }
    post.bound.insert(height, body.txs.iter().map(|tx| tx.public.commitments.clone()).collect());
    Ok(())
}
