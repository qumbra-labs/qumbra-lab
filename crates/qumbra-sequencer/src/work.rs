//! **The real seams** (lab #847 S4) the posting pass drives: the node over
//! HTTP ([`HttpNode`]), the wall clock ([`SystemClock`]), and the work
//! ([`RealWork`]) — claims selected under the anchors V7 would accept, a
//! claims-only plan, the real prover, assembly, the sequencer's signature, the
//! node's own rule as a self-check, and the landed wrapper recorded in the run
//! state. This is the only [`Work`] the binary has; the pass's tests drive the
//! state machine through their own, and a source lint pins that `run` names
//! this one.

use std::net::SocketAddr;
use std::path::PathBuf;

use qlab_l2spend::Endpoint;
use qlab_node::wrapper_route::WrapperView;
use qlab_wrapper::codec::digest_from_bytes;
use qumbra_node::bundle::WrapperRule;
use qumbra_node::genesis_v6::GenesisFileV6;
use serde_json::Value;

use crate::bundle::{assemble, prove, self_check, sign, Timings};
use crate::chain::{self, Anchor, Http};
use crate::intake::Chain;
use crate::key::SequencerKey;
use crate::members::{plan_claims, Keys, PlanError, K};
use crate::pass::{Clock, Draft, NotDrafted, Node, Work};
use crate::queue::Refusal;
use crate::state::{Built, RunState};
use qlab_wprover::f4::native::{Member, WTag, M_ABS};

/// The node: `/v1/wrapper` on its telemetry listener, `POST /v1/bundle` on
/// its operator listener (loopback, or a tunnel to it).
pub struct HttpNode {
    pub telemetry: SocketAddr,
    pub operator: SocketAddr,
}

impl Node for HttpNode {
    fn wrapper(&self) -> Result<WrapperView, String> {
        let body = qlab_l2spend::PlainHttp { addr: self.telemetry }.get(qlab_node::wrapper_route::WRAPPER_PATH)?;
        qlab_node::wrapper_route::parse(&body)
    }

    fn post(&self, bundle: &[u8]) -> Result<(u16, String), String> {
        let (status, body) = qlab_l2spend::PlainHttp { addr: self.operator }.post("/v1/bundle", bundle)?;
        Ok((status, String::from_utf8_lossy(&body).into_owned()))
    }
}

/// The wall clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
    }
    fn sleep(&self, secs: u64) {
        std::thread::sleep(std::time::Duration::from_secs(secs));
    }
}

/// The work: everything between queued claims and a signed bundle.
pub struct RealWork {
    pub genesis: GenesisFileV6,
    pub chain: Chain,
    pub key: SequencerKey,
    /// The node's discovery listener (`/v1/anchors`, `/v1/tree/leaves`,
    /// `/v1/coinbase`) the plan and the self-check read.
    pub discovery: String,
    pub run: RunState,
    pub state: PathBuf,
}

impl RealWork {
    /// Open the run state at `state` (a new one if absent), refusing one for
    /// another genesis or `l2_id`.
    pub fn open(genesis: GenesisFileV6, key: SequencerKey, discovery: String, state: PathBuf) -> Result<RealWork, String> {
        let chain = Chain::of(&genesis);
        let run = if state.exists() {
            let r = RunState::load(&state)?;
            if r.genesis != chain.genesis || r.l2_id != chain.l2_id {
                return Err(format!("{} belongs to another genesis or l2_id", state.display()));
            }
            r
        } else {
            RunState::new(chain.genesis, chain.l2_id, "")
        };
        Ok(RealWork { genesis, chain, key, discovery, run, state })
    }
}

impl Work for RealWork {
    fn draft(&mut self, w: &WrapperView, candidates: &[([u8; 32], Vec<u8>)]) -> Result<Result<Draft, NotDrafted>, String> {
        if candidates.is_empty() {
            return Ok(Err(NotDrafted::Nothing));
        }
        let (state, prev) = self.run.replay()?;
        // Each candidate read again against this chain; refuse, by name, one
        // that no longer decodes or whose cnf the wrapper state already holds.
        let mut refused = Vec::new();
        let mut claims = Vec::new();
        for (id, bytes) in candidates {
            let Ok(file) = qlab_l2spend::decode_claim_artifact(bytes, &self.chain.genesis, self.chain.claim_fee_tier) else {
                refused.push((*id, Refusal::Unreadable));
                continue;
            };
            let m = Member { tag: WTag::C, pvs: file.pvs.clone(), write: None };
            let (Ok(cnf), Ok(anchor)) = (m.digest_at(qlab_air::claim::PV_CNF), m.digest_at(qlab_air::claim::PV_A)) else {
                refused.push((*id, Refusal::Unreadable));
                continue;
            };
            if state.k.low_leaf_of(&cnf).is_none() {
                refused.push((*id, Refusal::CnfOnChain));
                continue;
            }
            claims.push((*id, anchor, file));
        }
        if !refused.is_empty() {
            return Ok(Err(NotDrafted::Refuse(refused)));
        }
        // The roots V7 accepts in the next block (the node's facts, V7's rule).
        let absorbable: Vec<_> = w.absorbable().iter().map(digest_from_bytes).collect();
        if absorbable.is_empty() {
            return Ok(Err(NotDrafted::Wait("no root is absorbable yet (no finality record covers one)".into())));
        }
        let before: Vec<_> = (0..state.aa.len()).map(|i| state.aa.leaf(i)).collect();
        // Select in arrival order: a claim under a root an earlier wrapper
        // absorbed, or under an absorbable root while this wrapper still has
        // room for it among its M_ABS new roots. Others stay queued.
        let mut roots = Vec::new();
        let mut take = Vec::new();
        for (i, (_, anchor, _)) in claims.iter().enumerate() {
            if take.len() == K {
                break;
            }
            if before.contains(anchor) {
                take.push(i);
            } else if absorbable.contains(anchor) && (roots.contains(anchor) || roots.len() < M_ABS) {
                if !roots.contains(anchor) {
                    roots.push(*anchor);
                }
                take.push(i);
            }
        }
        if take.len() < K {
            return Ok(Err(NotDrafted::Short { have: take.len(), need: K }));
        }
        for r in &absorbable {
            if roots.len() == M_ABS {
                break;
            }
            if !roots.contains(r) {
                roots.push(*r);
            }
        }
        while roots.len() < M_ABS {
            roots.push(absorbable[0]);
        }
        let view = chain::read(&Http { base: self.discovery.clone() })?;
        let mut absorbed: Vec<Anchor> = roots
            .iter()
            .map(|r| view.count_of(r).map(|count| Anchor { count, root: *r }).ok_or("an absorbable root is no prefix of the served leaves"))
            .collect::<Result<_, _>>()?;
        absorbed.sort_by_key(|a| a.count);
        let absorbed: [Anchor; M_ABS] = absorbed.try_into().map_err(|_| "exactly M_ABS roots".to_string())?;
        let items: Vec<[u8; 32]> = take.iter().map(|&i| claims[i].0).collect();
        let mut chosen: Vec<_> = claims.into_iter().enumerate().filter(|(i, _)| take.contains(i)).map(|(_, c)| c).collect();
        let files: Vec<_> = chosen.drain(..).map(|(_, _, f)| f).collect();
        let keys = Keys::from_seed(*self.key.filler_seed);
        let plan = match plan_claims(&state, &prev, absorbed, files, &keys) {
            Ok(p) => p,
            Err(PlanError::Wrapper(e)) => return Err(format!("the native wrapper statement refuses the selected batch: {e}")),
            Err(e) => return Err(format!("plan: {e:?}")),
        };
        let mut timings = Timings::new();
        let mut log = |what: &str| eprintln!("SEQ proving {what}");
        let proofs = prove(&plan, &mut timings, &mut log)?;
        let mut wb = assemble(&plan, self.chain.l2_id, proofs)?;
        sign(&mut wb, &self.key.signer, &self.chain.genesis)?;
        let bytes = wb.encode();
        let rule = WrapperRule::from_genesis(&self.genesis).map_err(|e| format!("{e:?}"))?;
        self_check(&rule, &bytes, &prev, &view).map_err(|r| format!("the node's rule refuses the bundle: {r:?}"))?;
        Ok(Ok(Draft { items, bytes, built: Built::of(&plan).to_json() }))
    }

    fn commit(&mut self, built: &Value) -> Result<(), String> {
        self.run.push_built(Built::from_json(built)?);
        self.run.save(&self.state)
    }
}
