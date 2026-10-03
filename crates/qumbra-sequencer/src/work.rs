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
use crate::members::{exit_alone_refused, exit_file, first_refused, pass_members_ok, plan_claims, spendable, ExitFile, Keys, PlanError, K};
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
                "claim {}: its anchor root {}… would exceed the {M_ABS} new roots a wrapper absorbs; a later wrapper takes it",
                short(id),
                short(&root)
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

/// The draft's answer when the selection plus the fillers do not make a
/// wrapper — `None` when they do. A short that is only claims waiting for a
/// finality record to cover their root ([`only_anchors_lag`]) is a
/// [`NotDrafted::Wait`] naming those claims, the tip and CR (the pass polls
/// it under `--max-wait`, ending at exit 3); otherwise a
/// [`NotDrafted::Short`] whose `why` names every claim left out and the
/// fillers' shortfall.
pub fn not_drafted(
    sel: &Selection,
    ids: &[[u8; 32]],
    anchors: &[qlab_wprover::f3::native::Digest],
    exit: bool,
    notes: usize,
    tip: u64,
    cr: Option<u64>,
) -> Option<NotDrafted> {
    // Traffic is the claims taken and the one exit (R3b): a wrapper of one
    // exit and fillers is a wrapper; one of padding alone never is.
    let taken = sel.take.len() + usize::from(exit);
    if taken > 0 && taken + notes >= K {
        return None;
    }
    let line = |(i, why): &(usize, LeftOut)| why.sentence(&ids[*i], &anchors[*i]);
    let waiting: Vec<String> = sel.left.iter().filter(|(_, why)| *why == LeftOut::NotAbsorbable).map(line).collect();
    if only_anchors_lag(taken, waiting.len(), notes) {
        let cr = cr.map_or("none".to_string(), |c| c.to_string());
        return Some(NotDrafted::Wait(format!(
            "{} claim(s) await a finality record covering their anchor (tip {tip}, CR {cr}): {}",
            waiting.len(),
            waiting.join("; ")
        )));
    }
    let mut why: Vec<String> = sel.left.iter().map(line).collect();
    if taken < K {
        let slots = K - taken;
        let advice = if notes < slots { " — `seed` gives the sequencer notes" } else { "" };
        why.push(format!("{notes} spendable sequencer note(s) for {slots} filler slot(s){advice}"));
    }
    Some(NotDrafted::Short { have: taken + notes.min(K - taken), need: K, why })
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
        // that no longer decodes, a claim whose cnf the wrapper state already
        // holds, an exit whose nullifier is already on the L2 (R3b).
        let mut refused = Vec::new();
        let mut claims = Vec::new();
        let mut exits: Vec<([u8; 32], ExitFile)> = Vec::new();
        for (id, bytes) in candidates {
            if bytes.starts_with(qlab_l2spend::EXIT_ARTIFACT_MAGIC) {
                match exit_file(bytes, &self.chain.genesis) {
                    Err(_) => refused.push((*id, Refusal::Unreadable)),
                    Ok(e) if e.nullifiers.iter().any(|nf| state.l2.n.low_leaf_of(&digest_from_bytes(nf)).is_none()) => {
                        refused.push((*id, Refusal::Spent))
                    }
                    Ok(e) => exits.push((*id, e)),
                }
                continue;
            }
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
        let sel = select(&anchors, &before, &absorbable);
        // The rest of the wrapper is fillers, one per spendable sequencer
        // note (S3); a wrapper with no claim is never posted.
        let keys = Keys::from_seed(*self.key.filler_seed);
        let notes = spendable(&state, &keys, &self.run.owned).len();
        let ids: Vec<[u8; 32]> = claims.iter().map(|(id, _, _)| *id).collect();
        // At most one exit a wrapper (R3b), the oldest queued.
        let exit = exits.into_iter().next();
        if let Some(not) = not_drafted(&sel, &ids, &anchors, exit.is_some(), notes, w.tip, w.cr) {
            return Ok(Err(not));
        }
        let Selection { take, mut roots, .. } = sel;
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
        let mut items: Vec<[u8; 32]> = take.iter().map(|&i| claims[i].0).collect();
        let mut chosen: Vec<_> = claims.into_iter().enumerate().filter(|(i, _)| take.contains(i)).map(|(_, c)| c).collect();
        let files: Vec<_> = chosen.drain(..).map(|(_, _, f)| f).collect();
        let (exit_id, exit_file) = match exit {
            Some((id, e)) => (Some(id), Some(e)),
            None => (None, None),
        };
        items.extend(exit_id);
        let plan = match plan_claims(&state, &prev, absorbed, files.clone(), exit_file.clone(), &self.run.owned, &keys) {
            Ok(p) => p,
            // The statement is native: find the item by elimination and
            // refuse it by name, so the next draft does not pick it again —
            // the exit first, on its own (R3b), then the claims by prefix.
            Err(PlanError::Wrapper(e)) => {
                if let (Some(id), Some(x)) = (exit_id, &exit_file) {
                    if exit_alone_refused(&state, &prev, &absorbed, x, &keys) {
                        return Ok(Err(NotDrafted::Refuse(vec![(id, Refusal::Statement)])));
                    }
                }
                match first_refused(&state, &prev, &absorbed, &files, &keys) {
                    Some(i) => return Ok(Err(NotDrafted::Refuse(vec![(items[i], Refusal::Statement)]))),
                    None => return Err(format!("the native wrapper statement refuses the batch, and no single item is to blame: {e}")),
                }
            }
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

    /// The predicate: a short is only anchors lagging when the waiting
    /// claims would fill the wrapper with the ones taken and the fillers.
    #[test]
    fn a_wrapper_short_only_on_anchors_waits() {
        assert!(only_anchors_lag(15, 1, 0), "box run 2: 15 taken + the user's claim waiting");
        assert!(only_anchors_lag(0, 1, 15), "one waiting claim and 15 notes");
        assert!(!only_anchors_lag(15, 0, 0), "nothing waiting: short");
        assert!(!only_anchors_lag(3, 2, 10), "15 of 16 even once both are absorbable: short");
        assert!(!only_anchors_lag(0, 0, 16), "no traffic: never a wrapper of padding");
    }

    /// Selection takes absorbed and absorbable roots in arrival order, at
    /// most M_ABS new roots, and names every claim it leaves out and why.
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
        let root9: String = qlab_wrapper::codec::digest_to_bytes(&r(9))[..8].iter().map(|x| format!("{x:02x}")).collect();
        assert!(line.contains(&format!("its anchor root {root9}…")), "{line}");
        assert!(LeftOut::NoRootRoom.sentence(&[0xab; 32], &r(6)).contains(&format!("exceed the {M_ABS} new roots")));
    }

    /// The draft's answer, variant and text: box run 2's shape (15 claims
    /// taken, the 16th waiting on a record, no notes) is a Wait naming only
    /// the waiting claim with tip and CR; with nothing waiting it is a Short
    /// naming every claim left out and the fillers' shortfall; a full
    /// wrapper is no answer at all.
    #[test]
    fn the_draft_waits_or_names_the_short() {
        let r = |k: u64| [k, 0, 0, 0];
        let ids: Vec<[u8; 32]> = (0..18u8).map(|k| [k; 32]).collect();
        let mut anchors = vec![r(1); 15];
        anchors.push(r(9)); // not absorbable
        anchors.push(r(6)); // absorbable, but no root room
        anchors.push(r(9));
        let sel = Selection {
            take: (0..15).collect(),
            roots: vec![],
            left: vec![(15, LeftOut::NotAbsorbable), (16, LeftOut::NoRootRoom)],
        };
        match not_drafted(&sel, &ids, &anchors, false, 0, 220, Some(212)) {
            Some(NotDrafted::Wait(w)) => {
                assert!(w.starts_with("1 claim(s) await a finality record covering their anchor (tip 220, CR 212): claim 0f0f"), "{w}");
                assert!(!w.contains("exceed"), "only the waiting claims are listed: {w}");
            }
            _ => panic!("box run 2's shape must wait"),
        }
        let sel = Selection { take: (0..3).collect(), roots: vec![], left: vec![(16, LeftOut::NoRootRoom)] };
        match not_drafted(&sel, &ids, &anchors, false, 10, 220, None) {
            Some(NotDrafted::Short { have, need, why }) => {
                assert_eq!((have, need), (13, K));
                assert_eq!(why.len(), 2);
                assert!(why[0].starts_with("claim 1010101010101010") && why[0].contains("exceed"), "{}", why[0]);
                assert_eq!(why[1], format!("10 spendable sequencer note(s) for {} filler slot(s) — `seed` gives the sequencer notes", K - 3));
            }
            _ => panic!("3 claims + 10 notes is short"),
        }
        let full = Selection { take: (0..1).collect(), roots: vec![], left: vec![] };
        assert!(not_drafted(&full, &ids, &anchors, false, 15, 220, None).is_none(), "1 claim + 15 notes is a wrapper");
    }
}
