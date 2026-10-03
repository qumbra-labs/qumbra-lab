//! **One posting pass** (lab #847 S4): the loop `qumbra-sequencer run` drives,
//! as a state machine over three seams — the node ([`Node`]: `/v1/wrapper`
//! and the operator listener), the clock ([`Clock`]), and the work of turning
//! queued items into a signed bundle ([`Work`]: plan, prove, assemble, sign,
//! self-check — and recording a landed wrapper in the run state). The real
//! seams live in [`crate::work`]; the state machine is what this module
//! tests, without proving anything.
//!
//! **No pass plans an R member** (lab #847, the Q4 condition of design
//! `l2-read-path-decision`): a bundle's members are claims, at most one
//! wallet exit P from its exit file (lab #860 R3b), and S3's S fillers —
//! [`crate::members::PASS_MEMBER_TAGS`]. The node's derived
//! L2 index (lab #860) cannot follow a registry write from the wire, so one
//! R member would block every exit until format v2. The real work checks
//! the tags before proving; `lib.rs` holds the sources to it.
//!
//! ## One bundle's life
//!
//! `planned` (its items marked `Planned(n)`, the bytes in `--out`, a pending
//! record `<state>.pending.json` written **before** the POST) → posted (202,
//! or 409 slot-held) → **landed** — only when `/v1/wrapper`'s
//! `last_bundle_id` equals its id. Then, and only then, the wrapper enters
//! the run state, its items become `Landed(height)`, and the pending record
//! goes. The node's answer to a POST:
//!
//! | answer | the pass |
//! |---|---|
//! | 202, 409 | posted; poll for its landing |
//! | 503; 422 `state lagging its chain`, `Spacing {…}`, `Wrapper("Anchor(i)")` | wait one poll, re-post the same bytes (a proved bundle is not thrown away for a wait) |
//! | 422 `Wrapper("Thread(…)")`, `Wrapper("Prev")` | discard: items back to `queued`, re-plan from the run state |
//! | 422 anything else, 400, any other status | fatal, named: the pass stops and the bundle stays in flight for the operator |
//!
//! The 422 kind is read from the operator route's `refused: <reason>` body
//! (the reason a `BundleRefusal`'s Debug form, optionally after `refused
//! before at this tip: `), by its leading token — see [`classify`]. A pass
//! discards at most [`MAX_DISCARDS`] bundles, waiting one poll before each
//! re-draft, then ends at a ceiling.
//!
//! A posted bundle that does not land is re-posted with the same bytes while
//! `/v1/wrapper` still shows its predecessor as the last bundle, at most
//! [`MAX_REPOSTS`] times, then the pass ends with the bundle and its items
//! named (exit 3). If the chain shows another last bundle, it is discarded and
//! its items re-planned.
//!
//! ## Restart
//!
//! A pass starts by reconciling: if a pending record exists and
//! `last_bundle_id` is its id, the bundle landed while no pass was watching
//! (including a crash between the POST and the next write) — it is adopted as
//! landed. If the chain's last bundle is still the pending one's predecessor,
//! the same bytes are re-posted. Otherwise it is discarded. Then any item
//! still `Planned` that no pending record names (a crash between writing the
//! pending record and marking its items is impossible by order, but an older
//! layout or a hand edit is not) goes back to `queued`, by name.
//!
//! Every write is ordered so a crash anywhere replays to a clean end: the
//! pending record (naming the items) is written before any item is marked;
//! landing is commit (skipped if the run state already ends with this bundle)
//! → mark (skipping items already in the target state) → clear the record;
//! discarding is mark → clear. The record is always cleared last.
//!
//! ## Bounds
//!
//! Every wait — spacing, a 503, no absorbable root yet, a landing — polls
//! every `poll_secs` under one deadline per pass (`--max-wait`); `--max-bundles`
//! bounds how many bundles one pass lands. Hitting either ends the pass with
//! [`Outcome::Ceiling`] naming what is left (exit 3) — except landing the
//! `--max-bundles` asked for, which is [`Outcome::Capped`] (exit 0, the items
//! still queued counted). Nothing spins silently.
//!
//! Discards are bounded by `MAX_DISCARDS` per pass. One reached during the
//! startup reconcile counts toward that bound but is not followed by a poll
//! (the chain already moved past it); one reached after a post waits one
//! poll before re-drafting. A discarded bundle's file is not deleted then:
//! landing bundle `m` deletes `bundle-(m − KEEP_BUNDLES).bin` (and its
//! `.json` manifest) and nothing else, so a discarded `bundle-n.bin` goes
//! when the bundle numbered `n + 8` lands, and stays if that number is
//! itself discarded — stray bytes in `--out`, never re-posted, harmless.
//!
//! No log line, record or manifest written here carries a claim's `v`, `r_v`
//! or an opening: items are named by id.

use std::path::{Path, PathBuf};

use qlab_node::wrapper_route::WrapperView;
use serde_json::{json, Value};

use crate::intake::{hex32, parse_hex32};
use crate::queue::{Queue, Refusal, State};
use crate::state::write_atomic;

/// Re-posts of one bundle before the pass gives up on it: twice the 48-block
/// spacing floor, counted in polls (`WRAPPER_SPACING_BLOCKS_V1` × 2).
pub const MAX_REPOSTS: u32 = 2 * 48;

/// Bundles kept in `--out` (the newest by number): a re-post never re-proves.
pub const KEEP_BUNDLES: u64 = 8;

/// Bundles one pass may discard before it ends at a ceiling: a persistent
/// refusal never becomes a prove-post-discard loop.
pub const MAX_DISCARDS: u32 = 3;

/// The longest slice of a node's answer echoed into a message.
pub const MAX_ECHO: usize = 160;

/// A node answer, as it may appear in a message: one line, at most
/// [`MAX_ECHO`] characters.
fn clip(body: &str) -> String {
    let one: String = body.trim().chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    let mut out: String = one.chars().take(MAX_ECHO).collect();
    if one.chars().count() > MAX_ECHO {
        out.push('…');
    }
    out
}

/// What the pass does with a non-2xx answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// Wait one poll and re-post the same bytes; the reason, named.
    Wait(&'static str),
    /// Throw the bundle away and re-plan; the reason, named.
    Discard(&'static str),
    /// Stop the pass.
    Fatal,
}

/// Read a 422 body's refusal kind: the operator route answers `refused:
/// <reason>`, the reason `state lagging its chain` or a `BundleRefusal` in
/// its Debug form, possibly after `refused before at this tip: `. Matched by
/// the leading token, never by a substring anywhere in the body.
pub fn classify(body: &str) -> Answer {
    let Some(r) = body.trim().strip_prefix("refused: ") else { return Answer::Fatal };
    let r = r.strip_prefix("refused before at this tip: ").unwrap_or(r);
    if r == "state lagging its chain" {
        Answer::Wait("the node's state lags its chain")
    } else if r.starts_with("Spacing {") {
        Answer::Wait("the spacing floor")
    } else if r.starts_with("Wrapper(\"Anchor(") {
        Answer::Wait("an absorbed root not yet covered by a finality record (Anchor)")
    } else if r.starts_with("Wrapper(\"Thread(") {
        Answer::Discard("it does not thread from the chain's surface (Thread)")
    } else if r == "Wrapper(\"Prev\")" {
        Answer::Discard("its prev is not the chain's surface (Prev)")
    } else {
        Answer::Fatal
    }
}

/// The node, as the pass sees it.
pub trait Node {
    /// `GET /v1/wrapper`, read strictly.
    fn wrapper(&self) -> Result<WrapperView, String>;
    /// `POST /v1/bundle` on the operator listener: the status and the body.
    fn post(&self, bundle: &[u8]) -> Result<(u16, String), String>;
}

/// Time, in whole seconds.
pub trait Clock {
    fn now(&self) -> u64;
    fn sleep(&self, secs: u64);
}

/// A drafted bundle: its items, its bytes, and the wrapper as built (opaque
/// here; [`Work::commit`] records it once it lands).
pub struct Draft {
    pub items: Vec<[u8; 32]>,
    pub bytes: Vec<u8>,
    pub built: Value,
    /// Written beside the bytes as `bundle-<n>.json` (lab #847 S3: each
    /// member's tag and whether it is a filler, so an auditor can tell
    /// traffic from padding), pruned with them.
    pub manifest: Option<Value>,
}

/// Why a draft is not made now.
pub enum NotDrafted {
    /// Nothing queued to plan.
    Nothing,
    /// Fewer members than a wrapper holds, counting one filler per
    /// spendable sequencer note — or no traffic at all, no claim and no exit
    /// (a wrapper of padding is never posted). `why` names each claim left out and the fillers'
    /// shortfall, one line each.
    Short { have: usize, need: usize, why: Vec<String> },
    /// Items refused at plan time, by id, each with its named reason.
    Refuse(Vec<([u8; 32], Refusal)>),
    /// Not plannable yet for a reason a later poll may clear (no absorbable
    /// root yet), named.
    Wait(String),
}

/// The work between queued items and signed bytes.
pub trait Work {
    /// Draft the next bundle from `candidates` (claim items, arrival order,
    /// with their artifact bytes) against the chain as `w` describes it.
    fn draft(&mut self, w: &WrapperView, candidates: &[([u8; 32], Vec<u8>)]) -> Result<Result<Draft, NotDrafted>, String>;
    /// Record a landed wrapper (its `built` value) in the run state — a
    /// no-op if the run state already ends with bundle `id` (a crash after the
    /// commit and before the pending record was cleared).
    fn commit(&mut self, id: &[u8; 32], built: &Value) -> Result<(), String>;
    /// The next bundle number, persisted before it is returned: monotonic
    /// over the run's life, so `Planned(n)` and `bundle-<n>.bin` are never
    /// reused.
    fn next_number(&mut self) -> Result<u64, String>;
}

/// The pass's settings.
pub struct Pass {
    /// The run state file; the pending record is `<state>.pending.json`.
    pub state: PathBuf,
    /// Where bundle bytes are kept (`bundle-<n>.bin`).
    pub out: PathBuf,
    /// The chain's spacing floor in blocks.
    pub spacing: u64,
    pub max_bundles: u64,
    pub max_wait_secs: u64,
    pub poll_secs: u64,
}

/// How a pass ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Nothing left to plan and nothing in flight.
    Drained { landed: u64 },
    /// The pass landed the `--max-bundles` it was asked for — the requested
    /// outcome, not a ceiling (exit 0); `left` counts the items still queued.
    Capped { landed: u64, left: usize },
    /// A ceiling ended the pass short of its ask (`--max-wait`, re-posts,
    /// discards); the string names what is left.
    Ceiling(String),
    /// Fewer real members than a wrapper holds, with the reasons by name.
    Short { have: usize, need: usize, why: Vec<String> },
}

/// The pending record: the one bundle in flight.
#[derive(Clone, Debug, PartialEq)]
struct Pending {
    n: u64,
    id: [u8; 32],
    /// `last_bundle_id` when it was drafted: its predecessor on chain.
    prev: Option<[u8; 32]>,
    items: Vec<[u8; 32]>,
    reposts: u32,
    /// The work's record of the bundle as built. For the real work it
    /// carries the sequencer's own `credited` openings (filler outputs, the
    /// fee note) — the sequencer's data, the same the run state keeps once
    /// the bundle lands; never a wallet's opening.
    built: Value,
}

impl Pending {
    fn path(state: &Path) -> PathBuf {
        let mut name = state.file_name().unwrap_or_default().to_os_string();
        name.push(".pending.json");
        state.with_file_name(name)
    }

    fn to_json(&self) -> Value {
        json!({
            "n": self.n,
            "id": hex32(&self.id),
            "prev": self.prev.as_ref().map(hex32),
            "items": self.items.iter().map(hex32).collect::<Vec<_>>(),
            "reposts": self.reposts,
            "built": self.built,
        })
    }

    fn from_json(v: &Value) -> Result<Pending, String> {
        let h = |v: &Value, what: &str| v.as_str().and_then(parse_hex32).ok_or(format!("pending record: {what}"));
        Ok(Pending {
            n: v["n"].as_u64().ok_or("pending record: n")?,
            id: h(&v["id"], "id")?,
            prev: if v["prev"].is_null() { None } else { Some(h(&v["prev"], "prev")?) },
            items: v["items"].as_array().ok_or("pending record: items")?.iter().map(|i| h(i, "an item")).collect::<Result<_, _>>()?,
            reposts: v["reposts"].as_u64().and_then(|r| u32::try_from(r).ok()).ok_or("pending record: reposts")?,
            built: v["built"].clone(),
        })
    }

    fn load(state: &Path) -> Result<Option<Pending>, String> {
        let p = Self::path(state);
        match std::fs::read_to_string(&p) {
            Ok(t) => {
                let v: Value = serde_json::from_str(&t).map_err(|e| format!("{}: {e}", p.display()))?;
                Pending::from_json(&v).map(Some).map_err(|e| format!("{}: {e}", p.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("{}: {e}", p.display())),
        }
    }

    fn save(&self, state: &Path) -> Result<(), String> {
        write_atomic(&Self::path(state), serde_json::to_string_pretty(&self.to_json()).expect("json").as_bytes())
    }

    fn clear(state: &Path) -> Result<(), String> {
        match std::fs::remove_file(Self::path(state)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("{}: {e}", Self::path(state).display())),
        }
    }
}

/// The pass's running context.
struct Run<'a> {
    cfg: &'a Pass,
    queue: &'a mut Queue,
    node: &'a dyn Node,
    clock: &'a dyn Clock,
    work: &'a mut dyn Work,
    deadline: u64,
    landed: u64,
    discards: u32,
}

/// What happened to the bundle in flight.
enum Flight {
    Landed,
    Discarded,
}

impl Run<'_> {
    fn bundle_path(&self, n: u64) -> PathBuf {
        self.cfg.out.join(format!("bundle-{n}.bin"))
    }

    fn manifest_path(&self, n: u64) -> PathBuf {
        self.cfg.out.join(format!("bundle-{n}.json"))
    }

    /// One poll, or the ceiling if the deadline has passed.
    fn wait(&self, what: &str) -> Result<(), Outcome> {
        if self.clock.now().saturating_add(self.cfg.poll_secs) > self.deadline {
            return Err(Outcome::Ceiling(format!("--max-wait reached while {what}")));
        }
        // Never silent: every poll says what it waits for.
        eprintln!("SEQ waiting: {what}; next poll in {} s", self.cfg.poll_secs);
        self.clock.sleep(self.cfg.poll_secs);
        Ok(())
    }

    /// Move `items` to `state`, idempotently: an item already there is
    /// skipped (a crash mid-mark replays cleanly), and an item a crashed
    /// discard already put back to `queued` reaches `landed` through
    /// `Planned(n)` — the only path the transition table allows.
    fn mark(&mut self, items: &[[u8; 32]], state: State, n: u64) -> Result<(), String> {
        for id in items {
            let now = self.queue.item(id).map(|i| i.state).ok_or_else(|| format!("no item {}", hex32(id)))?;
            if now == state {
                continue;
            }
            if now == State::Queued && matches!(state, State::Landed(_)) {
                self.queue.set_state(id, State::Planned(n))?;
            }
            self.queue.set_state(id, state)?;
        }
        Ok(())
    }

    /// The chain's last bundle is `p`'s: record it.
    fn land(&mut self, p: &Pending, height: u64) -> Result<(), String> {
        self.work.commit(&p.id, &p.built)?;
        self.mark(&p.items, State::Landed(height), p.n)?;
        Pending::clear(&self.cfg.state)?;
        eprintln!("SEQ landed bundle {} {} at {height} ({} items)", p.n, hex32(&p.id), p.items.len());
        self.landed += 1;
        // Keep the newest KEEP_BUNDLES; older bytes are never re-posted.
        if let Some(old) = p.n.checked_sub(KEEP_BUNDLES) {
            let _ = std::fs::remove_file(self.bundle_path(old));
            let _ = std::fs::remove_file(self.manifest_path(old));
        }
        Ok(())
    }

    fn discard(&mut self, p: &Pending, why: &str) -> Result<(), String> {
        self.mark(&p.items, State::Queued, p.n)?;
        Pending::clear(&self.cfg.state)?;
        self.discards += 1;
        eprintln!("SEQ discarded bundle {} {}: {why} — its {} items are queued again", p.n, hex32(&p.id), p.items.len());
        Ok(())
    }

    /// Drive the bundle in flight to landed or discarded.
    fn fly(&mut self, mut p: Pending) -> Result<Result<Flight, Outcome>, String> {
        let bytes = std::fs::read(self.bundle_path(p.n)).map_err(|e| format!("{}: {e}", self.bundle_path(p.n).display()))?;
        let mut posted = false;
        loop {
            let w = self.node.wrapper()?;
            if w.last_bundle_id == Some(p.id) {
                self.land(&p, w.last_bundle_height.expect("an id comes with its height (checked by the reader)"))?;
                return Ok(Ok(Flight::Landed));
            }
            if w.last_bundle_id != p.prev {
                self.discard(&p, "the chain's last bundle is neither this one nor its predecessor")?;
                return Ok(Ok(Flight::Discarded));
            }
            if posted {
                // Posted, not landed yet: give it a poll before re-posting.
                if let Err(o) = self.wait(&format!("waiting for bundle {} to land", p.n)) {
                    return Ok(Err(o));
                }
                let w = self.node.wrapper()?;
                if w.last_bundle_id == Some(p.id) || w.last_bundle_id != p.prev {
                    continue;
                }
                if p.reposts >= MAX_REPOSTS {
                    let items: Vec<String> = p.items.iter().map(hex32).collect();
                    return Ok(Err(Outcome::Ceiling(format!(
                        "bundle {} {} did not land after {MAX_REPOSTS} re-posts; its items: {}",
                        p.n,
                        hex32(&p.id),
                        items.join(",")
                    ))));
                }
                p.reposts += 1;
                p.save(&self.cfg.state)?;
            }
            let (status, body) = self.node.post(&bytes)?;
            let answer = match status {
                202 | 409 => {
                    posted = true;
                    continue;
                }
                503 => Answer::Wait("the node was busy (503)"),
                422 => classify(&body),
                _ => Answer::Fatal,
            };
            match answer {
                Answer::Wait(why) => {
                    if let Err(o) = self.wait(why) {
                        return Ok(Err(o));
                    }
                }
                Answer::Discard(why) => {
                    self.discard(&p, why)?;
                    return Ok(Ok(Flight::Discarded));
                }
                Answer::Fatal => {
                    return Err(format!(
                        "the node refused bundle {} {} ({status}): {} — the bundle stays in flight",
                        p.n,
                        hex32(&p.id),
                        clip(&body)
                    ))
                }
            }
        }
    }
}

/// Run one pass. The caller holds the queue's lock and the state's lock.
pub fn run(cfg: &Pass, queue: &mut Queue, node: &dyn Node, clock: &dyn Clock, work: &mut dyn Work) -> Result<Outcome, String> {
    std::fs::create_dir_all(&cfg.out).map_err(|e| format!("{}: {e}", cfg.out.display()))?;
    let deadline = clock.now().saturating_add(cfg.max_wait_secs);
    let mut r = Run { cfg, queue, node, clock, work, deadline, landed: 0, discards: 0 };
    // Reconcile what a previous pass left in flight.
    let pending = Pending::load(&cfg.state)?;
    let named: Vec<[u8; 32]> = pending.as_ref().map_or(Vec::new(), |p| p.items.clone());
    let orphans: Vec<[u8; 32]> =
        r.queue.items().filter(|i| matches!(i.state, State::Planned(_)) && !named.contains(&i.id)).map(|i| i.id).collect();
    for id in orphans {
        eprintln!("SEQ item {} was planned in no bundle in flight — queued again", hex32(&id));
        r.queue.set_state(&id, State::Queued)?;
    }
    if let Some(p) = pending {
        eprintln!("SEQ reconciling bundle {} {} left in flight", p.n, hex32(&p.id));
        if let Err(o) = r.fly(p)? {
            return Ok(o);
        }
    }
    loop {
        if r.landed >= cfg.max_bundles {
            let left = r.queue.items().filter(|i| i.state == State::Queued).count();
            return Ok(Outcome::Capped { landed: r.landed, left });
        }
        if r.discards >= MAX_DISCARDS {
            return Ok(Outcome::Ceiling(format!("{MAX_DISCARDS} bundles discarded in one pass")));
        }
        let candidates: Vec<([u8; 32], Vec<u8>)> = r
            .queue
            .items()
            // Claims and exits alike since lab #860 R3b (nothing is held).
            .filter(|i| i.state == State::Queued)
            .map(|i| i.id)
            .collect::<Vec<_>>()
            .into_iter()
            .map(|id| r.queue.artifact(&id).map(|b| (id, b)))
            .collect::<Result<_, _>>()?;
        let w = r.node.wrapper()?;
        // Spacing: the next block must be at least `spacing` past the last bundle.
        if let Some(h) = w.last_bundle_height {
            if w.tip.saturating_add(1) < h.saturating_add(cfg.spacing) && !candidates.is_empty() {
                if let Err(o) = r.wait(&format!("the spacing floor ({} blocks after {h})", cfg.spacing)) {
                    return Ok(o);
                }
                continue;
            }
        }
        let draft = match r.work.draft(&w, &candidates)? {
            Ok(d) => d,
            Err(NotDrafted::Nothing) => return Ok(Outcome::Drained { landed: r.landed }),
            Err(NotDrafted::Short { have, need, why }) => {
                if r.landed > 0 || have == 0 {
                    return Ok(Outcome::Drained { landed: r.landed });
                }
                return Ok(Outcome::Short { have, need, why });
            }
            Err(NotDrafted::Refuse(refused)) => {
                for (id, why) in refused {
                    eprintln!("SEQ refused item {}: {}", hex32(&id), why.sentence());
                    r.queue.set_state(&id, State::Refused(why))?;
                }
                continue;
            }
            Err(NotDrafted::Wait(why)) => {
                if let Err(o) = r.wait(&why) {
                    return Ok(o);
                }
                continue;
            }
        };
        // Order: number (persisted), bytes, the pending record naming the
        // items, and only then the items marked — a crash before the mark
        // leaves a record the next pass reconciles.
        let n = r.work.next_number()?;
        let id = qlab_devnet::hash::keccak256(&draft.bytes);
        write_atomic(&r.bundle_path(n), &draft.bytes)?;
        if let Some(m) = &draft.manifest {
            write_atomic(&r.manifest_path(n), serde_json::to_string_pretty(m).expect("json").as_bytes())?;
        }
        let p = Pending { n, id, prev: w.last_bundle_id, items: draft.items, reposts: 0, built: draft.built };
        p.save(&cfg.state)?;
        r.mark(&p.items, State::Planned(n), n)?;
        eprintln!("SEQ drafted bundle {} {} ({} items, {} bytes)", p.n, hex32(&p.id), p.items.len(), draft.bytes.len());
        match r.fly(p)? {
            Err(o) => return Ok(o),
            Ok(Flight::Discarded) => {
                // Never re-draft at once: what refused it may need a block.
                if let Err(o) = r.wait("re-drafting after a discard") {
                    return Ok(o);
                }
            }
            Ok(Flight::Landed) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intake::{classify, tests::w3c_chain, tests::W3C_CLAIM};
    use crate::queue::Queue;
    use qlab_node::wrapper_route::WrapperView;
    use std::cell::{Cell, RefCell};

    /// A scripted node: `/v1/wrapper` answers from a shared view the test
    /// moves; POST answers from a script, and a 202/409 makes the posted
    /// bundle land `land_after` reads later.
    struct FakeNode {
        view: RefCell<WrapperView>,
        answers: RefCell<Vec<(u16, String)>>,
        posts: Cell<u32>,
        land_after: Cell<Option<u32>>,
        pending_land: RefCell<Option<([u8; 32], u32)>>,
    }

    impl FakeNode {
        fn new(tip: u64) -> Self {
            FakeNode {
                view: RefCell::new(WrapperView { l2_id: 1, tip, cr: Some(tip), last_bundle_height: None, last_bundle_id: None, anchors: Vec::new() }),
                answers: RefCell::new(Vec::new()),
                posts: Cell::new(0),
                land_after: Cell::new(Some(1)),
                pending_land: RefCell::new(None),
            }
        }
    }

    impl Node for FakeNode {
        fn wrapper(&self) -> Result<WrapperView, String> {
            let mut v = self.view.borrow_mut();
            if let Some((id, left)) = *self.pending_land.borrow() {
                if left == 0 {
                    v.tip += 1;
                    v.last_bundle_height = Some(v.tip);
                    v.last_bundle_id = Some(id);
                }
            }
            let mut pl = self.pending_land.borrow_mut();
            if let Some((id, left)) = *pl {
                *pl = if left == 0 { None } else { Some((id, left - 1)) };
            }
            v.tip += 1;
            Ok(v.clone())
        }
        fn post(&self, bundle: &[u8]) -> Result<(u16, String), String> {
            self.posts.set(self.posts.get() + 1);
            let a = {
                let mut q = self.answers.borrow_mut();
                if q.is_empty() { (202, "admitted".into()) } else { q.remove(0) }
            };
            if matches!(a.0, 202 | 409) {
                if let Some(after) = self.land_after.get() {
                    *self.pending_land.borrow_mut() = Some((qlab_devnet::hash::keccak256(bundle), after));
                }
            }
            Ok(a)
        }
    }

    struct FakeClock(Cell<u64>);
    impl Clock for FakeClock {
        fn now(&self) -> u64 {
            self.0.get()
        }
        fn sleep(&self, secs: u64) {
            self.0.set(self.0.get() + secs);
        }
    }

    /// Drafts whatever is queued, `need` at a time: the bytes are the ids.
    struct FakeWork {
        need: usize,
        committed: Vec<Value>,
        refuse: Vec<[u8; 32]>,
        ids: Vec<[u8; 32]>,
        next: u64,
    }

    fn fake(need: usize) -> FakeWork {
        FakeWork { need, committed: Vec::new(), refuse: Vec::new(), ids: Vec::new(), next: 0 }
    }
    impl Work for FakeWork {
        fn draft(&mut self, _w: &WrapperView, c: &[([u8; 32], Vec<u8>)]) -> Result<Result<Draft, NotDrafted>, String> {
            let bad: Vec<_> = c.iter().filter(|(id, _)| self.refuse.contains(id)).map(|(id, _)| (*id, Refusal::CnfOnChain)).collect();
            if !bad.is_empty() {
                return Ok(Err(NotDrafted::Refuse(bad)));
            }
            if c.is_empty() {
                return Ok(Err(NotDrafted::Nothing));
            }
            if c.len() < self.need {
                return Ok(Err(NotDrafted::Short { have: c.len(), need: self.need, why: vec!["fake".into()] }));
            }
            let items: Vec<[u8; 32]> = c.iter().take(self.need).map(|(id, _)| *id).collect();
            let bytes: Vec<u8> = items.iter().flatten().copied().chain(self.committed.len().to_le_bytes()).collect();
            Ok(Ok(Draft { built: json!(items.iter().map(hex32).collect::<Vec<_>>()), manifest: Some(json!({"items": items.len()})), items, bytes }))
        }
        fn commit(&mut self, id: &[u8; 32], built: &Value) -> Result<(), String> {
            if self.ids.last() == Some(id) {
                return Ok(());
            }
            self.ids.push(*id);
            self.committed.push(built.clone());
            Ok(())
        }
        fn next_number(&mut self) -> Result<u64, String> {
            self.next += 1;
            Ok(self.next - 1)
        }
    }

    /// A second queued item: the claim with one byte of r_v flipped (a new
    /// id) under a made-up key — the pass never decodes it; FakeWork drafts
    /// by id.
    fn twin(q: &mut Queue, k: u8) -> [u8; 32] {
        let mut bytes = W3C_CLAIM.to_vec();
        *bytes.last_mut().unwrap() ^= k;
        let mut c = classify(W3C_CLAIM, &w3c_chain()).unwrap();
        c.id = crate::intake::id_of(&bytes);
        c.keys = vec![[k; 32]];
        q.admit(&c, &bytes).unwrap();
        c.id
    }

    fn setup(name: &str) -> (PathBuf, Queue, [u8; 32], Pass) {
        let d = std::env::temp_dir().join(format!("qseq-pass-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let mut q = Queue::open(&d.join("queue")).unwrap();
        let c = classify(W3C_CLAIM, &w3c_chain()).unwrap();
        q.admit(&c, W3C_CLAIM).unwrap();
        let cfg = Pass { state: d.join("state.json"), out: d.join("out"), spacing: 48, max_bundles: 4, max_wait_secs: 3600, poll_secs: 30 };
        (d, q, c.id, cfg)
    }

    /// The happy path: drafted, posted, landed on observation, committed,
    /// the item Landed at the chain's height, the pending record gone; then
    /// nothing left, so the pass drains.
    #[test]
    fn a_bundle_lands_only_when_the_chain_names_it() {
        let (d, mut q, id, cfg) = setup("happy");
        let node = FakeNode::new(100);
        let clock = FakeClock(Cell::new(0));
        let mut work = fake(1);
        let out = run(&cfg, &mut q, &node, &clock, &mut work).unwrap();
        assert_eq!(out, Outcome::Drained { landed: 1 });
        assert_eq!(work.committed.len(), 1);
        assert!(matches!(q.item(&id).unwrap().state, State::Landed(_)));
        assert!(!Pending::path(&cfg.state).exists());
        assert!(cfg.out.join("bundle-0.bin").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// 422 Spacing and 503 are waits — the same bytes re-posted; a 422
    /// naming anything else discards (items back to queued, nothing
    /// committed); a 400 is fatal.
    #[test]
    fn the_post_answer_table() {
        let (d, mut q, _, cfg) = setup("answers");
        let node = FakeNode::new(100);
        node.answers.borrow_mut().extend([(422, "refused: Spacing { since: 3, need: 48 }".to_string()), (503, "busy".into())]);
        let clock = FakeClock(Cell::new(0));
        let mut work = fake(1);
        assert_eq!(run(&cfg, &mut q, &node, &clock, &mut work).unwrap(), Outcome::Drained { landed: 1 });
        assert_eq!(node.posts.get(), 3, "two waits, then admitted");
        assert_eq!(clock.0.get(), 90, "one poll per wait (Spacing, 503), then one landing poll");
        let _ = std::fs::remove_dir_all(&d);

        // Thread discards — items back to queued, a poll before re-drafting —
        // and a persistent one ends the pass after MAX_DISCARDS.
        let (d, mut q, id, cfg) = setup("discard");
        let node = FakeNode::new(100);
        let thread = (422, "refused: Wrapper(\"Thread(\\\"aa\\\")\")".to_string());
        node.answers.borrow_mut().extend(std::iter::repeat_n(thread, MAX_DISCARDS as usize));
        let clock = FakeClock(Cell::new(0));
        let mut work = fake(1);
        let out = run(&cfg, &mut q, &node, &clock, &mut work).unwrap();
        assert_eq!(out, Outcome::Ceiling(format!("{MAX_DISCARDS} bundles discarded in one pass")));
        assert_eq!(q.item(&id).unwrap().state, State::Queued);
        assert!(work.committed.is_empty() && !Pending::path(&cfg.state).exists());
        assert_eq!(clock.0.get(), 30 * u64::from(MAX_DISCARDS), "one poll after each discard");
        let _ = std::fs::remove_dir_all(&d);

        // Anchor is a wait, never a discard: the same bytes go again.
        let (d, mut q, id, cfg) = setup("anchor");
        let node = FakeNode::new(100);
        node.answers.borrow_mut().push((422, "refused: refused before at this tip: Wrapper(\"Anchor(2)\")".into()));
        let mut work = fake(1);
        assert_eq!(run(&cfg, &mut q, &node, &FakeClock(Cell::new(0)), &mut work).unwrap(), Outcome::Drained { landed: 1 });
        assert_eq!((node.posts.get(), work.committed.len()), (2, 1));
        assert!(matches!(q.item(&id).unwrap().state, State::Landed(_)));
        let _ = std::fs::remove_dir_all(&d);

        let (d, mut q, _, cfg) = setup("fatal");
        let node = FakeNode::new(100);
        node.answers.borrow_mut().push((400, format!("refused: Codec(\"bad\")\n{}", "x".repeat(500))));
        let mut work = fake(1);
        let err = run(&cfg, &mut q, &node, &FakeClock(Cell::new(0)), &mut work).unwrap_err();
        assert!(err.contains("(400): refused: Codec") && !err.contains('\n') && err.contains('…'), "{err}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A posted bundle that never lands is re-posted while its predecessor is
    /// still the chain's last, at most MAX_REPOSTS times, then the pass ends
    /// naming it and its items — never a silent spin.
    #[test]
    fn a_bundle_that_never_lands_ends_the_pass_by_name() {
        let (d, mut q, id, cfg) = setup("never");
        let node = FakeNode::new(100);
        node.land_after.set(None);
        let clock = FakeClock(Cell::new(0));
        let mut work = fake(1);
        let cfg = Pass { max_wait_secs: u64::MAX / 2, ..cfg };
        let out = run(&cfg, &mut q, &node, &clock, &mut work).unwrap();
        let Outcome::Ceiling(why) = out else { panic!("{out:?}") };
        assert!(why.contains(&format!("after {MAX_REPOSTS} re-posts")) && why.contains(&hex32(&id)), "{why}");
        assert_eq!(node.posts.get(), MAX_REPOSTS + 1);
        assert_eq!(q.item(&id).unwrap().state, State::Planned(0), "still in flight, recorded for the next pass");
        assert!(Pending::path(&cfg.state).exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Restart: a pending record whose id the chain already names is adopted
    /// as landed — the crash-between-POST-and-write case — without posting.
    #[test]
    fn a_restart_adopts_a_bundle_that_landed_unwatched() {
        let (d, mut q, id, cfg) = setup("adopt");
        std::fs::create_dir_all(&cfg.out).unwrap();
        let bytes = b"bundle zero".to_vec();
        let bid = qlab_devnet::hash::keccak256(&bytes);
        write_atomic(&cfg.out.join("bundle-0.bin"), &bytes).unwrap();
        q.set_state(&id, State::Planned(0)).unwrap();
        Pending { n: 0, id: bid, prev: None, items: vec![id], reposts: 0, built: json!("b0") }.save(&cfg.state).unwrap();
        let node = FakeNode::new(100);
        {
            let mut v = node.view.borrow_mut();
            v.last_bundle_height = Some(90);
            v.last_bundle_id = Some(bid);
        }
        let mut work = fake(1);
        let out = run(&cfg, &mut q, &node, &FakeClock(Cell::new(0)), &mut work).unwrap();
        assert_eq!(out, Outcome::Drained { landed: 1 });
        assert_eq!(node.posts.get(), 0, "adopted, never re-posted");
        assert_eq!(work.committed, vec![json!("b0")]);
        assert_eq!(q.item(&id).unwrap().state, State::Landed(90));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Restart when the chain moved past the pending bundle's predecessor to
    /// some other bundle: discarded, its items queued again.
    #[test]
    fn a_restart_discards_a_bundle_the_chain_moved_past() {
        let (d, mut q, id, cfg) = setup("moved");
        std::fs::create_dir_all(&cfg.out).unwrap();
        write_atomic(&cfg.out.join("bundle-0.bin"), b"zero").unwrap();
        q.set_state(&id, State::Planned(0)).unwrap();
        Pending { n: 0, id: [1; 32], prev: None, items: vec![id], reposts: 0, built: json!("b0") }.save(&cfg.state).unwrap();
        let node = FakeNode::new(100);
        {
            let mut v = node.view.borrow_mut();
            v.last_bundle_height = Some(90);
            v.last_bundle_id = Some([2; 32]);
        }
        let mut work = fake(2);
        let out = run(&cfg, &mut q, &node, &FakeClock(Cell::new(0)), &mut work).unwrap();
        assert_eq!(out, Outcome::Short { have: 1, need: 2, why: vec!["fake".into()] });
        assert_eq!(q.item(&id).unwrap().state, State::Queued);
        assert!(work.committed.is_empty() && !Pending::path(&cfg.state).exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Short is refused by name; a refused item is marked once and the pass
    /// moves on without it; an empty queue drains.
    #[test]
    fn short_refused_and_empty() {
        let (d, mut q, id, cfg) = setup("short");
        let node = FakeNode::new(100);
        let mut work = fake(16);
        assert_eq!(run(&cfg, &mut q, &node, &FakeClock(Cell::new(0)), &mut work).unwrap(), Outcome::Short { have: 1, need: 16, why: vec!["fake".into()] });
        let mut work = FakeWork { refuse: vec![id], ..fake(1) };
        assert_eq!(run(&cfg, &mut q, &node, &FakeClock(Cell::new(0)), &mut work).unwrap(), Outcome::Drained { landed: 0 });
        assert_eq!(q.item(&id).unwrap().state, State::Refused(Refusal::CnfOnChain));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The spacing floor and an un-plannable chain are bounded waits: past
    /// --max-wait the pass ends naming what it waited for.
    #[test]
    fn waits_are_bounded() {
        let (d, mut q, _, cfg) = setup("spacing");
        let node = FakeNode::new(100);
        {
            let mut v = node.view.borrow_mut();
            v.last_bundle_height = Some(100);
            v.last_bundle_id = Some([5; 32]);
        }
        node.view.borrow_mut().tip = 100;
        let mut work = fake(1);
        // Each read advances the tip by one; 300 s of 30 s polls is ten
        // reads — far short of 48 blocks.
        let cfg = Pass { max_wait_secs: 300, ..cfg };
        let out = run(&cfg, &mut q, &node, &FakeClock(Cell::new(0)), &mut work).unwrap();
        let Outcome::Ceiling(why) = out else { panic!("{out:?}") };
        assert!(why.contains("spacing floor"), "{why}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The 422 table, by leading token only.
    #[test]
    fn classify_reads_the_leading_token() {
        assert_eq!(super::classify("refused: state lagging its chain"), Answer::Wait("the node's state lags its chain"));
        assert!(matches!(super::classify("refused: Spacing { since: 1, need: 48 }"), Answer::Wait(_)));
        assert!(matches!(super::classify("refused: Wrapper(\"Anchor(0)\")"), Answer::Wait(_)));
        assert!(matches!(super::classify("refused: refused before at this tip: Wrapper(\"Anchor(3)\")"), Answer::Wait(_)));
        assert!(matches!(super::classify("refused: Wrapper(\"Thread(\\\"d\\\")\")"), Answer::Discard(_)));
        assert!(matches!(super::classify("refused: Wrapper(\"Prev\")"), Answer::Discard(_)));
        for fatal in ["refused: Counters", "refused: Wrapper(\"WProof\")", "Spacing { since: 1 }", "refused: Wrapper(\"Member(0, \\\"Spacing\\\")\")"] {
            assert_eq!(super::classify(fatal), Answer::Fatal, "{fatal}");
        }
    }

    /// Landing the `--max-bundles` asked for is Capped (exit 0), counting
    /// what is still queued — not a ceiling.
    #[test]
    fn the_bundle_cap_is_the_asked_for_outcome() {
        let (d, mut q, id, cfg) = setup("capped");
        let second = twin(&mut q, 1);
        let cfg1 = Pass { max_bundles: 1, ..cfg };
        let mut work = fake(1);
        let out = run(&cfg1, &mut q, &FakeNode::new(100), &FakeClock(Cell::new(0)), &mut work).unwrap();
        assert_eq!(out, Outcome::Capped { landed: 1, left: 1 });
        assert!(matches!(q.item(&id).unwrap().state, State::Landed(_)));
        assert_eq!(q.item(&second).unwrap().state, State::Queued);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Bundle numbers come from the work's persisted counter: a second pass
    /// numbers past the first, never reusing 0.
    #[test]
    fn numbers_continue_across_passes() {
        let (d, mut q, _, cfg) = setup("numbers");
        let node = FakeNode::new(100);
        let mut work = fake(1);
        run(&cfg, &mut q, &node, &FakeClock(Cell::new(0)), &mut work).unwrap();
        let second = twin(&mut q, 1);
        node.view.borrow_mut().tip += 100;
        run(&cfg, &mut q, &node, &FakeClock(Cell::new(0)), &mut work).unwrap();
        assert!(cfg.out.join("bundle-0.bin").exists() && cfg.out.join("bundle-1.bin").exists());
        assert!(cfg.out.join("bundle-0.json").exists() && cfg.out.join("bundle-1.json").exists(), "each manifest beside its bytes");
        assert!(matches!(q.item(&second).unwrap().state, State::Landed(_)));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Crash windows, each restarted to a clean end. (a) An item Planned
    /// that no pending record names goes back to queued.
    #[test]
    fn a_planned_orphan_is_queued_again() {
        let (d, mut q, id, cfg) = setup("orphan");
        q.set_state(&id, State::Planned(7)).unwrap();
        let mut work = fake(2);
        let out = run(&cfg, &mut q, &FakeNode::new(100), &FakeClock(Cell::new(0)), &mut work).unwrap();
        assert_eq!(out, Outcome::Short { have: 1, need: 2, why: vec!["fake".into()] });
        assert_eq!(q.item(&id).unwrap().state, State::Queued);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// (b) A crash after the commit: the restart sees the chain name the
    /// bundle, does not commit it twice, and finishes the marks.
    /// (c) A crash mid-mark: one item already Landed, one still Planned.
    #[test]
    fn a_crash_after_commit_or_mid_mark_replays_once() {
        let (d, mut q, a, cfg) = setup("midmark");
        let b = twin(&mut q, 1);
        std::fs::create_dir_all(&cfg.out).unwrap();
        let bytes = b"bundle zero".to_vec();
        let bid = qlab_devnet::hash::keccak256(&bytes);
        write_atomic(&cfg.out.join("bundle-0.bin"), &bytes).unwrap();
        Pending { n: 0, id: bid, prev: None, items: vec![a, b], reposts: 0, built: json!("b0") }.save(&cfg.state).unwrap();
        q.set_state(&a, State::Planned(0)).unwrap();
        q.set_state(&a, State::Landed(90)).unwrap();
        q.set_state(&b, State::Planned(0)).unwrap();
        let node = FakeNode::new(100);
        {
            let mut v = node.view.borrow_mut();
            v.last_bundle_height = Some(90);
            v.last_bundle_id = Some(bid);
        }
        let mut work = FakeWork { ids: vec![bid], committed: vec![json!("b0")], ..fake(2) };
        let out = run(&cfg, &mut q, &node, &FakeClock(Cell::new(0)), &mut work).unwrap();
        assert_eq!(out, Outcome::Drained { landed: 1 });
        assert_eq!(work.committed.len(), 1, "committed once, not again");
        assert_eq!((q.item(&a).unwrap().state, q.item(&b).unwrap().state), (State::Landed(90), State::Landed(90)));
        assert!(!Pending::path(&cfg.state).exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// (d) A crash mid-discard: one item back to queued, one still planned,
    /// the record still there. If the chain moved on, the discard finishes;
    /// if the chain names the bundle after all, both land — the queued one
    /// through Planned.
    #[test]
    fn a_crash_mid_discard_finishes_either_way() {
        for chain_names_it in [false, true] {
            let (d, mut q, a, cfg) = setup(if chain_names_it { "middiscard-land" } else { "middiscard" });
            let b = twin(&mut q, 1);
            std::fs::create_dir_all(&cfg.out).unwrap();
            let bytes = b"bundle zero".to_vec();
            let bid = qlab_devnet::hash::keccak256(&bytes);
            write_atomic(&cfg.out.join("bundle-0.bin"), &bytes).unwrap();
            Pending { n: 0, id: bid, prev: None, items: vec![a, b], reposts: 0, built: json!("b0") }.save(&cfg.state).unwrap();
            q.set_state(&b, State::Planned(0)).unwrap();
            let node = FakeNode::new(100);
            {
                let mut v = node.view.borrow_mut();
                v.last_bundle_height = Some(90);
                v.last_bundle_id = Some(if chain_names_it { bid } else { [2; 32] });
            }
            let mut work = fake(3);
            run(&cfg, &mut q, &node, &FakeClock(Cell::new(0)), &mut work).unwrap();
            let want = if chain_names_it { State::Landed(90) } else { State::Queued };
            assert_eq!((q.item(&a).unwrap().state, q.item(&b).unwrap().state), (want, want));
            assert!(!Pending::path(&cfg.state).exists());
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    #[test]
    fn the_pending_record_round_trips() {
        let p = Pending { n: 3, id: [9; 32], prev: Some([8; 32]), items: vec![[1; 32], [2; 32]], reposts: 4, built: json!({"x": 1}) };
        assert_eq!(Pending::from_json(&p.to_json()).unwrap(), p);
        let none = Pending { prev: None, ..p };
        assert_eq!(Pending::from_json(&none.to_json()).unwrap(), none);
    }
}
