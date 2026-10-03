//! **One posting pass** (lab #847 S4): the loop `qumbra-sequencer run` drives,
//! as a state machine over three seams — the node ([`Node`]: `/v1/wrapper`
//! and the operator listener), the clock ([`Clock`]), and the work of turning
//! queued items into a signed bundle ([`Work`]: plan, prove, assemble, sign,
//! self-check — and recording a landed wrapper in the run state). The real
//! seams live in [`crate::work`]; the state machine is what this module
//! tests, without proving anything.
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
//! | 422 naming `Spacing`, 503 | wait one poll, re-post the same bytes |
//! | 422 otherwise (`Anchor`, `Thread`, `Prev`, …) | discard: items back to `queued`, re-plan from the run state |
//! | 400 | fatal, named: the bytes alone are wrong, and they are ours |
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
//! the same bytes are re-posted. Otherwise it is discarded.
//!
//! ## Bounds
//!
//! Every wait — spacing, a 503, no absorbable root yet, a landing — polls
//! every `poll_secs` under one deadline per pass (`--max-wait`); `--max-bundles`
//! bounds how many bundles one pass lands. Hitting either ends the pass with
//! [`Outcome::Ceiling`] naming what is left (exit 3). Nothing spins silently.
//!
//! No log line, record or manifest written here carries a claim's `v`, `r_v`
//! or an opening: items are named by id.

use std::path::{Path, PathBuf};

use qlab_node::wrapper_route::WrapperView;
use serde_json::{json, Value};

use crate::intake::{hex32, parse_hex32, Kind};
use crate::queue::{Queue, Refusal, State};
use crate::state::write_atomic;

/// Re-posts of one bundle before the pass gives up on it: twice the 48-block
/// spacing floor, counted in polls (`WRAPPER_SPACING_BLOCKS_V1` × 2).
pub const MAX_REPOSTS: u32 = 2 * 48;

/// Bundles kept in `--out` (the newest): a re-post never re-proves.
pub const KEEP_BUNDLES: u64 = 8;

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
}

/// Why a draft is not made now.
pub enum NotDrafted {
    /// Nothing queued to plan.
    Nothing,
    /// Fewer real members than a wrapper holds (fillers land in S3).
    Short { have: usize, need: usize },
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
    /// Record a landed wrapper (its `built` value) in the run state.
    fn commit(&mut self, built: &Value) -> Result<(), String>;
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
    /// A ceiling was reached; the string names what is left.
    Ceiling(String),
    /// Fewer real members than a wrapper holds.
    Short { have: usize, need: usize },
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

    /// One poll, or the ceiling if the deadline has passed.
    fn wait(&self, what: &str) -> Result<(), Outcome> {
        if self.clock.now() + self.cfg.poll_secs > self.deadline {
            return Err(Outcome::Ceiling(format!("--max-wait reached while {what}")));
        }
        self.clock.sleep(self.cfg.poll_secs);
        Ok(())
    }

    fn mark(&mut self, items: &[[u8; 32]], state: State) -> Result<(), String> {
        for id in items {
            self.queue.set_state(id, state)?;
        }
        Ok(())
    }

    /// The chain's last bundle is `p`'s: record it.
    fn land(&mut self, p: &Pending, height: u64) -> Result<(), String> {
        self.work.commit(&p.built)?;
        self.mark(&p.items, State::Landed(height))?;
        Pending::clear(&self.cfg.state)?;
        eprintln!("SEQ landed bundle {} {} at {height} ({} items)", p.n, hex32(&p.id), p.items.len());
        self.landed += 1;
        // Keep the newest KEEP_BUNDLES; older bytes are never re-posted.
        if p.n >= KEEP_BUNDLES {
            let _ = std::fs::remove_file(self.bundle_path(p.n - KEEP_BUNDLES));
        }
        Ok(())
    }

    fn discard(&mut self, p: &Pending, why: &str) -> Result<(), String> {
        self.mark(&p.items, State::Queued)?;
        Pending::clear(&self.cfg.state)?;
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
            match status {
                202 | 409 => posted = true,
                503 => {
                    if let Err(o) = self.wait("the node was busy (503)") {
                        return Ok(Err(o));
                    }
                }
                422 if body.contains("Spacing") => {
                    if let Err(o) = self.wait("the spacing floor holds the slot (422 Spacing)") {
                        return Ok(Err(o));
                    }
                }
                422 => {
                    self.discard(&p, &format!("the node refused it at this tip ({})", body.trim()))?;
                    return Ok(Ok(Flight::Discarded));
                }
                400 => return Err(format!("the node refused bundle {} as malformed (400): {}", p.n, body.trim())),
                other => {
                    if let Err(o) = self.wait(&format!("an unexpected answer ({other})")) {
                        return Ok(Err(o));
                    }
                }
            }
        }
    }
}

/// Run one pass. The caller holds the queue's lock and the state's lock.
pub fn run(cfg: &Pass, queue: &mut Queue, node: &dyn Node, clock: &dyn Clock, work: &mut dyn Work) -> Result<Outcome, String> {
    std::fs::create_dir_all(&cfg.out).map_err(|e| format!("{}: {e}", cfg.out.display()))?;
    let deadline = clock.now().saturating_add(cfg.max_wait_secs);
    let mut r = Run { cfg, queue, node, clock, work, deadline, landed: 0 };
    // Reconcile what a previous pass left in flight.
    if let Some(p) = Pending::load(&cfg.state)? {
        eprintln!("SEQ reconciling bundle {} {} left in flight", p.n, hex32(&p.id));
        if let Err(o) = r.fly(p)? {
            return Ok(o);
        }
    }
    let mut next_n = 0u64;
    loop {
        if r.landed >= cfg.max_bundles {
            return Ok(Outcome::Ceiling(format!("--max-bundles {} reached", cfg.max_bundles)));
        }
        let candidates: Vec<([u8; 32], Vec<u8>)> = r
            .queue
            .items()
            .filter(|i| i.kind == Kind::Claim && i.state == State::Queued)
            .map(|i| i.id)
            .collect::<Vec<_>>()
            .into_iter()
            .map(|id| r.queue.artifact(&id).map(|b| (id, b)))
            .collect::<Result<_, _>>()?;
        let w = r.node.wrapper()?;
        // Spacing: the next block must be at least `spacing` past the last bundle.
        if let Some(h) = w.last_bundle_height {
            if w.tip + 1 < h + cfg.spacing && !candidates.is_empty() {
                if let Err(o) = r.wait(&format!("the spacing floor ({} blocks after {h})", cfg.spacing)) {
                    return Ok(o);
                }
                continue;
            }
        }
        let draft = match r.work.draft(&w, &candidates)? {
            Ok(d) => d,
            Err(NotDrafted::Nothing) => return Ok(Outcome::Drained { landed: r.landed }),
            Err(NotDrafted::Short { have, need }) => {
                if r.landed > 0 || have == 0 {
                    return Ok(Outcome::Drained { landed: r.landed });
                }
                return Ok(Outcome::Short { have, need });
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
        // A fresh number: past every bundle file this run has kept.
        while r.bundle_path(next_n).exists() {
            next_n += 1;
        }
        let id = qlab_devnet::hash::keccak256(&draft.bytes);
        write_atomic(&r.bundle_path(next_n), &draft.bytes)?;
        r.mark(&draft.items, State::Planned(next_n))?;
        let p = Pending { n: next_n, id, prev: w.last_bundle_id, items: draft.items, reposts: 0, built: draft.built };
        p.save(&cfg.state)?;
        eprintln!("SEQ drafted bundle {} {} ({} items, {} bytes)", p.n, hex32(&p.id), p.items.len(), draft.bytes.len());
        if let Err(o) = r.fly(p)? {
            return Ok(o);
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
                return Ok(Err(NotDrafted::Short { have: c.len(), need: self.need }));
            }
            let items: Vec<[u8; 32]> = c.iter().take(self.need).map(|(id, _)| *id).collect();
            let bytes: Vec<u8> = items.iter().flatten().copied().chain(self.committed.len().to_le_bytes()).collect();
            Ok(Ok(Draft { built: json!(items.iter().map(hex32).collect::<Vec<_>>()), items, bytes }))
        }
        fn commit(&mut self, built: &Value) -> Result<(), String> {
            self.committed.push(built.clone());
            Ok(())
        }
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
        let mut work = FakeWork { need: 1, committed: Vec::new(), refuse: Vec::new() };
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
        node.answers.borrow_mut().extend([(422, "Wrapper(\"Spacing { since: 3, need: 48 }\")".to_string()), (503, "busy".into())]);
        let clock = FakeClock(Cell::new(0));
        let mut work = FakeWork { need: 1, committed: Vec::new(), refuse: Vec::new() };
        assert_eq!(run(&cfg, &mut q, &node, &clock, &mut work).unwrap(), Outcome::Drained { landed: 1 });
        assert_eq!(node.posts.get(), 3, "two waits, then admitted");
        assert_eq!(clock.0.get(), 90, "one poll per wait (Spacing, 503), then one landing poll");
        let _ = std::fs::remove_dir_all(&d);

        let (d, mut q, _, cfg) = setup("discard");
        let node = FakeNode::new(100);
        node.land_after.set(None);
        node.answers.borrow_mut().push((422, "Wrapper(\"Thread\")".into()));
        let mut work = FakeWork { need: 1, committed: Vec::new(), refuse: Vec::new() };
        let cfg1 = Pass { max_wait_secs: 0, ..cfg };
        let out = run(&cfg1, &mut q, &node, &FakeClock(Cell::new(0)), &mut work).unwrap();
        assert!(matches!(out, Outcome::Ceiling(_)), "{out:?}");
        assert!(work.committed.is_empty());
        let _ = std::fs::remove_dir_all(&d);

        let (d, mut q, _, cfg) = setup("fatal");
        let node = FakeNode::new(100);
        node.answers.borrow_mut().push((400, "Codec".into()));
        let mut work = FakeWork { need: 1, committed: Vec::new(), refuse: Vec::new() };
        let err = run(&cfg, &mut q, &node, &FakeClock(Cell::new(0)), &mut work).unwrap_err();
        assert!(err.contains("malformed (400)"), "{err}");
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
        let mut work = FakeWork { need: 1, committed: Vec::new(), refuse: Vec::new() };
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
        let mut work = FakeWork { need: 1, committed: Vec::new(), refuse: Vec::new() };
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
        let mut work = FakeWork { need: 2, committed: Vec::new(), refuse: Vec::new() };
        let out = run(&cfg, &mut q, &node, &FakeClock(Cell::new(0)), &mut work).unwrap();
        assert_eq!(out, Outcome::Short { have: 1, need: 2 });
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
        let mut work = FakeWork { need: 16, committed: Vec::new(), refuse: Vec::new() };
        assert_eq!(run(&cfg, &mut q, &node, &FakeClock(Cell::new(0)), &mut work).unwrap(), Outcome::Short { have: 1, need: 16 });
        let mut work = FakeWork { need: 1, committed: Vec::new(), refuse: vec![id] };
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
        let mut work = FakeWork { need: 1, committed: Vec::new(), refuse: Vec::new() };
        // Each read advances the tip by one; 300 s of 30 s polls is ten
        // reads — far short of 48 blocks.
        let cfg = Pass { max_wait_secs: 300, ..cfg };
        let out = run(&cfg, &mut q, &node, &FakeClock(Cell::new(0)), &mut work).unwrap();
        let Outcome::Ceiling(why) = out else { panic!("{out:?}") };
        assert!(why.contains("spacing floor"), "{why}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_pending_record_round_trips() {
        let p = Pending { n: 3, id: [9; 32], prev: Some([8; 32]), items: vec![[1; 32], [2; 32]], reposts: 4, built: json!({"x": 1}) };
        assert_eq!(Pending::from_json(&p.to_json()).unwrap(), p);
        let none = Pending { prev: None, ..p };
        assert_eq!(Pending::from_json(&none.to_json()).unwrap(), none);
    }
}
