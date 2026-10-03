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
use serde_json::{json, Value};

use crate::bundle::{assemble, manifest, prove, self_check, sign, Timings};
use crate::chain::{self, Anchor, Http};
use crate::intake::Chain;
use crate::key::SequencerKey;
use crate::members::{first_refused, pass_members_ok, plan_claims, spendable, Keys, PlanError, K};
use crate::pass::{Clock, Draft, NotDrafted, Node, Work};
use crate::queue::Refusal;
use crate::state::{owned_json, owned_of, Built, RunState};
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

/// Why a queued claim is not in this wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeftOut {
    /// Its anchor root is neither absorbed nor absorbable at the next block:
    /// no finality record covers it yet (V7). Clears on its own.
    NotAbsorbable,
    /// Its root is absorbable, but this wrapper already takes `M_ABS` new
    /// roots. A later wrapper takes it.
    NoRootRoom,
}

impl LeftOut {
    /// One line naming the claim and the reason.
    pub fn sentence(&self, id: &[u8; 32], anchor: &qlab_wprover::f3::native::Digest) -> String {
        let root = qlab_wrapper::codec::digest_to_bytes(anchor);
        let short = |b: &[u8]| b[..8].iter().map(|x| format!("{x:02x}")).collect::<String>();
        match self {
            LeftOut::NotAbsorbable => format!(
                "claim {}: its anchor root {}… is not absorbable yet — no finality record covers it; wait",
                short(id),
                short(&root)
            ),
            LeftOut::NoRootRoom => format!(
                "claim {}: its anchor root {}… would be a {}th new root; a later wrapper takes it",
                short(id),
                short(&root),
                M_ABS + 1
            ),
        }
    }
}

/// The selection: claims (by index, arrival order) this wrapper takes, the
/// new roots it absorbs for them, and the ones left out with why.
pub struct Selection {
    pub take: Vec<usize>,
    pub roots: Vec<qlab_wprover::f3::native::Digest>,
    pub left: Vec<(usize, LeftOut)>,
}

/// Select in arrival order, at most K: a claim under a root an earlier
/// wrapper absorbed, or under an absorbable root while this wrapper still
/// has room for it among its M_ABS new roots. Others stay queued, named.
pub fn select(
    anchors: &[qlab_wprover::f3::native::Digest],
    before: &[qlab_wprover::f3::native::Digest],
    absorbable: &[qlab_wprover::f3::native::Digest],
) -> Selection {
    let mut roots = Vec::new();
    let mut take = Vec::new();
    let mut left = Vec::new();
    for (i, anchor) in anchors.iter().enumerate() {
        if take.len() == K {
            break;
        }
        if before.contains(anchor) {
            take.push(i);
        } else if !absorbable.contains(anchor) {
            left.push((i, LeftOut::NotAbsorbable));
        } else if roots.contains(anchor) || roots.len() < M_ABS {
            if !roots.contains(anchor) {
                roots.push(*anchor);
            }
            take.push(i);
        } else {
            left.push((i, LeftOut::NoRootRoom));
        }
    }
    Selection { take, roots, left }
}

/// Whether a short wrapper is only waiting on anchors: the claims taken, the
/// claims waiting for a record to cover their root, and one filler per
/// spendable note would fill it — so the pass waits (bounded by its
/// --max-wait) rather than ending short. S6 box run 2: 15 seed claims taken,
/// the user's claim proved against a root no record covered yet, 0 notes.
pub fn only_anchors_lag(taken: usize, waiting: usize, notes: usize) -> bool {
    taken + waiting > 0 && taken + waiting.min(K.saturating_sub(taken)) + notes >= K
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
        let anchors: Vec<_> = claims.iter().map(|(_, a, _)| *a).collect();
        let Selection { take, mut roots, left } = select(&anchors, &before, &absorbable);
        // The rest of the wrapper is fillers, one per spendable sequencer
        // note (S3); a wrapper with no claim is never posted.
        let keys = Keys::from_seed(*self.key.filler_seed);
        let notes = spendable(&state, &keys, &self.run.owned).len();
        if take.is_empty() || take.len() + notes < K {
            let named: Vec<String> = left.iter().map(|(i, why)| why.sentence(&claims[*i].0, &anchors[*i])).collect();
            // Claims only waiting for a record to cover their root would make
            // the wrapper: that is a wait (bounded by the pass's --max-wait),
            // not a short.
            let waiting = left.iter().filter(|(_, why)| *why == LeftOut::NotAbsorbable).count();
            if only_anchors_lag(take.len(), waiting, notes) {
                return Ok(Err(NotDrafted::Wait(format!(
                    "{} claim(s) wait for a finality record to cover their anchor: {}",
                    waiting,
                    named.join("; ")
                ))));
            }
            let mut why = named;
            if take.len() < K {
                why.push(format!("{notes} spendable sequencer note(s) for {} filler slot(s)", K - take.len()));
            }
            return Ok(Err(NotDrafted::Short { have: take.len() + notes.min(K - take.len()), need: K, why }));
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
        let plan = match plan_claims(&state, &prev, absorbed, files.clone(), &self.run.owned, &keys) {
            Ok(p) => p,
            // The statement is native: find the item by elimination and
            // refuse it by name, so the next draft does not pick it again.
            Err(PlanError::Wrapper(e)) => match first_refused(&state, &prev, &absorbed, &files, &keys) {
                Some(i) => return Ok(Err(NotDrafted::Refuse(vec![(items[i], Refusal::Statement)]))),
                None => return Err(format!("the native wrapper statement refuses the batch, and no single item is to blame: {e}")),
            },
            Err(e) => return Err(format!("plan: {e:?}")), // debug-ok: PlanError from plan_claims names counts and roots, no opening
        };
        pass_members_ok(&plan.members)?;
        let mut timings = Timings::new();
        let mut log = |what: &str| eprintln!("SEQ proving {what}");
        let proofs = prove(&plan, &mut timings, &mut log)?;
        let mut wb = assemble(&plan, self.chain.l2_id, proofs)?;
        sign(&mut wb, &self.key.signer, &self.chain.genesis)?;
        let bytes = wb.encode();
        let rule = WrapperRule::from_genesis(&self.genesis).map_err(|e| format!("{e:?}"))?; // debug-ok: a wrapper-rule genesis error, no key material
        self_check(&rule, &bytes, &prev, &view).map_err(|r| format!("the node's rule refuses the bundle: {r:?}"))?; // debug-ok: a BundleRefusal, the node's own reason
        let mut built = Built::of(&plan).to_json();
        built["credited"] = json!(plan.credited.iter().map(owned_json).collect::<Vec<_>>());
        let mut m = manifest(&plan, &wb, &bytes, &self.chain.genesis, self.genesis.wrapper.wrapper_spacing_blocks, &view, &timings);
        m["mode"] = json!("sequencer");
        m["issue"] = json!(847);
        Ok(Ok(Draft { items, bytes, built, manifest: Some(m) }))
    }

    fn commit(&mut self, id: &[u8; 32], built: &Value) -> Result<(), String> {
        if self.run.ids.last() == Some(id) {
            return Ok(()); // a landing replayed after a crash: already recorded
        }
        let b = Built::from_json(built)?;
        // The notes this wrapper made the sequencer (fillers' outputs, the
        // fee note) are spendable from the next wrapper on.
        let credited = match built.get("credited") {
            None => Vec::new(),
            Some(c) => c.as_array().ok_or("built.credited")?.iter().map(owned_of).collect::<Result<_, _>>()?,
        };
        self.run.push_built(*id, b);
        self.run.owned.extend(credited);
        self.run.save(&self.state)
    }

    fn next_number(&mut self) -> Result<u64, String> {
        let n = self.run.next_n;
        self.run.next_n = n.checked_add(1).ok_or("the bundle counter overflows")?;
        self.run.save(&self.state)?;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Selection takes absorbed and absorbable roots in arrival order, at
    /// most M_ABS new roots, and names every claim it leaves out and why.
    #[test]
    fn a_wrapper_short_only_on_anchors_waits() {
        assert!(only_anchors_lag(15, 1, 0), "box run 2: 15 taken + the user's claim waiting");
        assert!(only_anchors_lag(0, 1, 15), "one waiting claim and 15 notes");
        assert!(!only_anchors_lag(15, 0, 0), "nothing waiting: short");
        assert!(!only_anchors_lag(3, 2, 10), "15 of 16 even once both are absorbable: short");
        assert!(!only_anchors_lag(0, 0, 16), "no traffic: never a wrapper of padding");
    }

    #[test]
    fn selection_names_what_it_leaves_out() {
        let r = |k: u64| [k, 0, 0, 0];
        let before = [r(1)];
        let absorbable = [r(2), r(3), r(4), r(5), r(6)];
        // arrival: absorbed, absorbable ×4 new roots, a 5th new root, a root
        // no record covers, and a repeat of an already-taken new root.
        let anchors = [r(1), r(2), r(3), r(4), r(5), r(6), r(9), r(2)];
        let s = select(&anchors, &before, &absorbable);
        assert_eq!(s.take, vec![0, 1, 2, 3, 4, 7]);
        assert_eq!(s.roots, vec![r(2), r(3), r(4), r(5)]);
        assert_eq!(s.left, vec![(5, LeftOut::NoRootRoom), (6, LeftOut::NotAbsorbable)]);
        let line = LeftOut::NotAbsorbable.sentence(&[0xab; 32], &r(9));
        assert!(line.starts_with("claim abababababababab: its anchor root ") && line.contains("no finality record covers it"), "{line}");
        assert!(LeftOut::NoRootRoom.sentence(&[0xab; 32], &r(6)).contains("5th new root"));
    }
}
