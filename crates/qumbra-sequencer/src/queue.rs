//! **The intake queue** (lab #847 S2): one directory, one format, read and
//! written by the intake listener now and by the posting loop (S4) later.
//!
//! ```text
//! DIR/index           append-only, one record per admitted item, in arrival order:
//!                       "1 <id> <kind> <key>[,<key>…] <check>\n"
//!                     <id>/<key> 64 lower-case hex; <check> the first 16 hex
//!                     digits of Keccak-256 over the record before it
//! DIR/items/<id>.bin  the artifact's bytes (Keccak-256 = <id>)
//! DIR/state/<id>      the item's state, one line: "queued" | "planned <n>" |
//!                     "landed <height>" | "refused <reason>" (a named reason)
//! DIR/index.lock      held while an intake runs (O_EXCL)
//! ```
//!
//! **The index is the commit point and the dedupe set.** An item is admitted
//! when its record is appended and fsynced — after its bytes and its state
//! record are on disk — so a crash before that leaves no record and nothing
//! admitted (an orphan file is ignored, and rewritten by a retry). Nothing is
//! ever removed from it: its keys are every `cnf` and nullifier intake ever
//! admitted, which is what dedupe answers from — never a report from the box
//! (lab #847 S2 ruling). **Opening refuses, by name, an index whose last
//! record is truncated or whose any record is malformed, fails its check, or
//! names an item whose bytes or state are missing or wrong**: a silently
//! shortened index is the one path that would re-admit a key.
//!
//! **Bounds apply to the pending queue only** — items not yet landed, by
//! count and by artifact bytes; the key index is small and unbounded by
//! design. A request refused for a full queue records nothing (no key left
//! behind for a later retry to collide with).
//!
//! **Only the posting loop moves an item past `queued`**; intake writes a
//! state record exactly once, at admission.
//!
//! **No directory fsync** (v0): the files and the index are fsynced, their
//! directory entries are not, so a power loss can lose a just-written file
//! name. Every such loss is caught at the next open — a record whose item or
//! state file is missing refuses to start, by name — never read past.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::intake::{hex32, parse_hex32, Candidate, Kind};
use crate::state::{write_atomic, StateLock};

/// The pending queue's bound on items not yet landed.
pub const MAX_PENDING_ITEMS: usize = 1024;
/// The pending queue's bound on their artifact bytes: 1,024 of the largest
/// artifact the listener accepts.
pub const MAX_PENDING_BYTES: u64 = 1024 * crate::server::MAX_ARTIFACT_BYTES as u64;

const RECORD_VERSION: &str = "1";

/// Why the loop refused an item — a closed catalogue, so a refusal can carry
/// no value from an artifact by construction (lab #847 S4 pre-review). The
/// record stores the code; the status route answers the sentence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The chain's wrapper state already holds the claim's `cnf`.
    CnfOnChain,
    /// The stored artifact no longer decodes against this chain.
    Unreadable,
    /// The native wrapper statement refuses a batch with this item alone in
    /// question.
    Statement,
}

impl Refusal {
    const ALL: [Refusal; 3] = [Refusal::CnfOnChain, Refusal::Unreadable, Refusal::Statement];

    /// The record's code.
    pub fn code(self) -> &'static str {
        match self {
            Refusal::CnfOnChain => "cnf-on-chain",
            Refusal::Unreadable => "unreadable",
            Refusal::Statement => "statement",
        }
    }

    /// The sentence a reader sees.
    pub fn sentence(self) -> &'static str {
        match self {
            Refusal::CnfOnChain => "the chain already holds this claim's cnf",
            Refusal::Unreadable => "the stored artifact no longer decodes against this chain",
            Refusal::Statement => "the native wrapper statement refuses it",
        }
    }

    fn of_code(s: &str) -> Option<Refusal> {
        Self::ALL.into_iter().find(|r| r.code() == s)
    }
}

/// An item's state. Intake writes `Queued` once, at admission; only the
/// posting loop (S4) moves an item past it, along [`State::may_become`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Admitted and waiting for a wrapper.
    Queued,
    /// In the run's bundle `n`, built or posted, not yet seen on chain.
    Planned(u64),
    /// In a bundle the chain applied, at this height (observed through
    /// `/v1/wrapper`'s `last_bundle_id`, never assumed from a POST).
    Landed(u64),
    /// Refused at plan time and never retried — a named reason, no value.
    Refused(Refusal),
}

impl State {
    pub fn name(&self) -> &'static str {
        match self {
            State::Queued => "queued",
            State::Planned(_) => "planned",
            State::Landed(_) => "landed",
            State::Refused(_) => "refused",
        }
    }

    /// The state record's one line.
    fn record(&self) -> String {
        match self {
            State::Queued => "queued\n".into(),
            State::Planned(n) => format!("planned {n}\n"),
            State::Landed(h) => format!("landed {h}\n"),
            State::Refused(r) => format!("refused {}\n", r.code()),
        }
    }

    fn parse(s: &str) -> Option<State> {
        let line = s.strip_suffix('\n').filter(|l| !l.contains('\n'))?;
        let num = |t: &str| t.parse::<u64>().ok().filter(|n| n.to_string() == t);
        match line.split_once(' ') {
            None if line == "queued" => Some(State::Queued),
            Some(("planned", n)) => num(n).map(State::Planned),
            Some(("landed", h)) => num(h).map(State::Landed),
            Some(("refused", code)) => Refusal::of_code(code).map(State::Refused),
            _ => None,
        }
    }

    /// Still owed a wrapper: counted against the pending bounds.
    fn pending(&self) -> bool {
        matches!(self, State::Queued | State::Planned(_))
    }

    /// The loop's transitions — and no others. Queued → Planned (drafted);
    /// Planned → Queued (discarded: Thread/Prev, or the chain moved on);
    /// Planned → Landed (observed on chain); Queued | Planned → Refused.
    /// Landed and Refused are terminal: an item never leaves them.
    pub fn may_become(&self, next: &State) -> bool {
        matches!(
            (self, next),
            (State::Queued, State::Planned(_))
                | (State::Planned(_), State::Queued)
                | (State::Planned(_), State::Landed(_))
                | (State::Queued | State::Planned(_), State::Refused(_))
        )
    }
}

/// Why an item that is `queued` is not being planned, if there is a reason
/// beyond "its turn has not come" — today, every exit (lab #847 Q4: no V6
/// exit can be built until the L2 read path exists).
pub fn held_reason(kind: Kind) -> Option<&'static str> {
    match kind {
        Kind::Exit => Some("no V6 exit can be built until the L2 read path exists (lab #847 Q4)"),
        Kind::Claim => None,
    }
}

/// One admitted item, as the index records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub id: [u8; 32],
    pub kind: Kind,
    pub keys: Vec<[u8; 32]>,
    pub len: u64,
    pub state: State,
}

/// What admitting a candidate would do — decided before its proof is
/// verified, so the cheap answers come first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// The same bytes were admitted before: answer with that id.
    Replay { id: [u8; 32], kind: Kind },
    /// Different bytes collide on a key already admitted.
    Conflict { existing: [u8; 32], key_name: &'static str },
    /// The pending queue is full (by count or by bytes).
    Full,
    /// New: verify it, then [`Queue::admit`].
    Fresh,
}

/// An open queue directory.
pub struct Queue {
    dir: PathBuf,
    order: Vec<[u8; 32]>,
    items: HashMap<[u8; 32], Item>,
    keys: HashMap<[u8; 32], [u8; 32]>,
    pending_items: usize,
    pending_bytes: u64,
}

fn check_of(record: &str) -> String {
    hex32(&qlab_devnet::hash::keccak256(record.as_bytes()))[..16].to_string()
}

impl Queue {
    /// Open (creating it if absent) and read back the whole directory,
    /// refusing by name anything that does not hold together.
    pub fn open(dir: &Path) -> Result<Queue, String> {
        for sub in ["items", "state"] {
            std::fs::create_dir_all(dir.join(sub)).map_err(|e| format!("{}: {e}", dir.join(sub).display()))?;
        }
        Self::read(dir)
    }

    /// Open an existing queue without creating anything — for reading it
    /// (`qumbra-sequencer queue`): a wrong path is refused, never turned into
    /// an empty queue skeleton.
    pub fn open_existing(dir: &Path) -> Result<Queue, String> {
        for sub in ["items", "state"] {
            if !dir.join(sub).is_dir() {
                return Err(format!("{}: not a queue directory (no {sub}/)", dir.display()));
            }
        }
        Self::read(dir)
    }

    fn read(dir: &Path) -> Result<Queue, String> {
        let index = dir.join("index");
        let text = match std::fs::read(&index) {
            Ok(b) => String::from_utf8(b).map_err(|_| format!("{}: not UTF-8 — refusing to start", index.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(format!("{}: {e}", index.display())),
        };
        if !text.is_empty() && !text.ends_with('\n') {
            return Err(format!(
                "{}: the last record is truncated — refusing to start (a shortened index would re-admit a key)",
                index.display()
            ));
        }
        let mut q = Queue { dir: dir.to_path_buf(), order: Vec::new(), items: HashMap::new(), keys: HashMap::new(), pending_items: 0, pending_bytes: 0 };
        for (n, line) in text.lines().enumerate() {
            let at = || format!("{} record {}", index.display(), n + 1);
            let (body, check) = line.rsplit_once(' ').ok_or_else(|| format!("{}: malformed — refusing to start", at()))?;
            if check != check_of(body) {
                return Err(format!("{}: its check does not match — refusing to start", at()));
            }
            let f: Vec<&str> = body.split(' ').collect();
            let [v, id, kind, keys] = f[..] else { return Err(format!("{}: malformed — refusing to start", at())) };
            if v != RECORD_VERSION {
                return Err(format!("{}: record version {v}; this build reads only {RECORD_VERSION} — refusing to start", at()));
            }
            let id = parse_hex32(id).ok_or_else(|| format!("{}: a malformed id — refusing to start", at()))?;
            let kind = Kind::from_name(kind).ok_or_else(|| format!("{}: unknown kind — refusing to start", at()))?;
            let keys = keys
                .split(',')
                .map(|k| parse_hex32(k).ok_or_else(|| format!("{}: a malformed key — refusing to start", at())))
                .collect::<Result<Vec<_>, _>>()?;
            if q.items.contains_key(&id) {
                return Err(format!("{}: item {} admitted twice — refusing to start", at(), hex32(&id)));
            }
            let bytes = std::fs::read(q.item_path(&id)).map_err(|e| format!("{}: its item file: {e} — refusing to start", at()))?;
            if crate::intake::id_of(&bytes) != id {
                return Err(format!("{}: its item file does not hash to its id — refusing to start", at()));
            }
            let state_text = std::fs::read_to_string(q.state_path(&id))
                .map_err(|e| format!("{}: its state record: {e} — refusing to start", at()))?;
            let state = State::parse(&state_text).ok_or_else(|| format!("{}: an unknown state record — refusing to start", at()))?;
            for k in &keys {
                if let Some(other) = q.keys.insert(*k, id) {
                    return Err(format!("{}: a key already held by item {} — refusing to start", at(), hex32(&other)));
                }
            }
            let pending = state.pending();
            let item = Item { id, kind, keys, len: bytes.len() as u64, state };
            if pending {
                q.pending_items += 1;
                q.pending_bytes += item.len;
            }
            q.order.push(id);
            q.items.insert(id, item);
        }
        Ok(q)
    }

    /// Take the directory's run lock (`index.lock`, O_EXCL) — one intake at a
    /// time; held until dropped.
    pub fn lock(dir: &Path) -> Result<StateLock, String> {
        StateLock::take(&dir.join("index")).map_err(|_| {
            format!(
                "another intake holds {} — if none is running (a crash leaves it behind), remove it and start again",
                dir.join("index.lock").display()
            )
        })
    }

    fn item_path(&self, id: &[u8; 32]) -> PathBuf {
        self.dir.join("items").join(format!("{}.bin", hex32(id)))
    }

    fn state_path(&self, id: &[u8; 32]) -> PathBuf {
        self.dir.join("state").join(hex32(id))
    }

    /// What admitting `c` (of `len` bytes) would do.
    pub fn decide(&self, c: &Candidate, len: u64) -> Decision {
        if let Some(item) = self.items.get(&c.id) {
            return Decision::Replay { id: item.id, kind: item.kind };
        }
        if let Some(existing) = c.keys.iter().find_map(|k| self.keys.get(k)) {
            return Decision::Conflict { existing: *existing, key_name: c.kind.key_name() };
        }
        if self.pending_items + 1 > MAX_PENDING_ITEMS || self.pending_bytes + len > MAX_PENDING_BYTES {
            return Decision::Full;
        }
        Decision::Fresh
    }

    /// Admit a verified candidate whose [`Self::decide`] was [`Decision::Fresh`]:
    /// its bytes, then its state record, then — the commit point — its index
    /// record, appended and fsynced.
    pub fn admit(&mut self, c: &Candidate, bytes: &[u8]) -> Result<(), String> {
        if self.decide(c, bytes.len() as u64) != Decision::Fresh {
            return Err("admit: not a fresh candidate".into());
        }
        // The index invariant (one key, one item) holds within an item too:
        // a repeated key would make the next open refuse to start.
        crate::intake::distinct_keys(c.kind, &c.keys)?;
        write_atomic(&self.item_path(&c.id), bytes)?;
        write_atomic(&self.state_path(&c.id), b"queued\n")?;
        let keys: Vec<String> = c.keys.iter().map(hex32).collect();
        let body = format!("{RECORD_VERSION} {} {} {}", hex32(&c.id), c.kind.name(), keys.join(","));
        let record = format!("{body} {}\n", check_of(&body));
        let index = self.dir.join("index");
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&index)
            .map_err(|e| format!("{}: {e}", index.display()))?;
        f.write_all(record.as_bytes()).and_then(|()| f.sync_all()).map_err(|e| format!("{}: {e}", index.display()))?;
        for k in &c.keys {
            self.keys.insert(*k, c.id);
        }
        self.pending_items += 1;
        self.pending_bytes += bytes.len() as u64;
        self.order.push(c.id);
        self.items.insert(c.id, Item { id: c.id, kind: c.kind, keys: c.keys.clone(), len: bytes.len() as u64, state: State::Queued });
        Ok(())
    }

    /// Move an item to `state` — the posting loop's write (S4); intake never
    /// calls it. Only the transitions [`State::may_become`] allows; any other
    /// is refused by name (Landed and Refused never change). The record is
    /// rewritten atomically; the index and the keys never change (a landed or
    /// refused item's keys stay admitted, so a resubmission still replays or
    /// conflicts).
    pub fn set_state(&mut self, id: &[u8; 32], state: State) -> Result<(), String> {
        let path = self.state_path(id);
        let item = self.items.get_mut(id).ok_or_else(|| format!("no item {}", hex32(id)))?;
        if !item.state.may_become(&state) {
            return Err(format!("item {}: {} may not become {}", hex32(id), item.state.name(), state.name()));
        }
        write_atomic(&path, state.record().as_bytes())?;
        match (item.state.pending(), state.pending()) {
            (true, false) => {
                self.pending_items -= 1;
                self.pending_bytes -= item.len;
            }
            (false, true) => {
                self.pending_items += 1;
                self.pending_bytes += item.len;
            }
            _ => {}
        }
        item.state = state;
        Ok(())
    }

    /// An admitted item's artifact bytes, checked against its id.
    pub fn artifact(&self, id: &[u8; 32]) -> Result<Vec<u8>, String> {
        let p = self.item_path(id);
        let b = std::fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        if crate::intake::id_of(&b) != *id {
            return Err(format!("{}: does not hash to its id", p.display()));
        }
        Ok(b)
    }

    /// An item by id.
    pub fn item(&self, id: &[u8; 32]) -> Option<&Item> {
        self.items.get(id)
    }

    /// Every item, in arrival order.
    pub fn items(&self) -> impl Iterator<Item = &Item> {
        self.order.iter().map(|id| &self.items[id])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intake::{classify, tests::w3c_chain, tests::W3C_CLAIM};

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("qseq-queue-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    /// Admit, reopen: the item, its key and its state come back; the same
    /// bytes replay; nothing is lost or re-admitted across the restart.
    #[test]
    fn admit_then_reopen_replays_and_keeps_the_key() {
        let d = dir("reopen");
        let c = classify(W3C_CLAIM, &w3c_chain()).unwrap();
        let mut q = Queue::open(&d).unwrap();
        assert_eq!(q.decide(&c, W3C_CLAIM.len() as u64), Decision::Fresh);
        q.admit(&c, W3C_CLAIM).unwrap();
        assert_eq!(q.decide(&c, W3C_CLAIM.len() as u64), Decision::Replay { id: c.id, kind: Kind::Claim });
        drop(q);
        let q = Queue::open(&d).unwrap();
        let items: Vec<&Item> = q.items().collect();
        assert_eq!((items.len(), items[0].id, items[0].state, items[0].kind), (1, c.id, State::Queued, Kind::Claim));
        assert_eq!(q.decide(&c, W3C_CLAIM.len() as u64), Decision::Replay { id: c.id, kind: Kind::Claim });
        // Different bytes on the same cnf: a conflict naming the held item.
        let mut other = c.clone();
        other.id = [9; 32];
        assert_eq!(q.decide(&other, 1), Decision::Conflict { existing: c.id, key_name: "cnf" });
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A truncated last record, a flipped check, a missing or altered item
    /// file — each refuses to start, by name, rather than read a shorter index.
    #[test]
    fn a_damaged_queue_refuses_to_start() {
        let d = dir("damaged");
        let c = classify(W3C_CLAIM, &w3c_chain()).unwrap();
        Queue::open(&d).unwrap().admit(&c, W3C_CLAIM).unwrap();
        let index = d.join("index");
        let good = std::fs::read_to_string(&index).unwrap();

        std::fs::write(&index, &good[..good.len() - 1]).unwrap();
        assert!(Queue::open(&d).err().unwrap().contains("truncated"));
        std::fs::write(&index, good.replacen(" claim ", " exit ", 1)).unwrap();
        assert!(Queue::open(&d).err().unwrap().contains("check does not match"));
        std::fs::write(&index, &good).unwrap();

        let item = d.join("items").join(format!("{}.bin", hex32(&c.id)));
        std::fs::write(&item, b"not the claim").unwrap();
        assert!(Queue::open(&d).err().unwrap().contains("does not hash to its id"));
        std::fs::remove_file(&item).unwrap();
        assert!(Queue::open(&d).err().unwrap().contains("its item file"));
        std::fs::write(&item, W3C_CLAIM).unwrap();
        std::fs::write(d.join("state").join(hex32(&c.id)), b"landed\n").unwrap();
        assert!(Queue::open(&d).err().unwrap().contains("unknown state record"));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A full queue decides `Full` and records nothing: no key is left for a
    /// later retry to collide with.
    #[test]
    fn a_full_queue_records_nothing() {
        let d = dir("full");
        let c = classify(W3C_CLAIM, &w3c_chain()).unwrap();
        let q = Queue::open(&d).unwrap();
        assert_eq!(q.decide(&c, MAX_PENDING_BYTES + 1), Decision::Full);
        drop(q);
        let q = Queue::open(&d).unwrap();
        assert_eq!(q.items().count(), 0);
        assert_eq!(q.decide(&c, W3C_CLAIM.len() as u64), Decision::Fresh);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// An item whose keys repeat is refused at admit too, and leaves the
    /// queue openable (it would otherwise brick the next start).
    #[test]
    fn repeated_keys_never_reach_the_index() {
        let d = dir("repeat");
        let mut c = classify(W3C_CLAIM, &w3c_chain()).unwrap();
        c.keys = vec![c.keys[0], c.keys[0]];
        let mut q = Queue::open(&d).unwrap();
        assert!(q.admit(&c, W3C_CLAIM).unwrap_err().contains("names one cnf twice"));
        drop(q);
        assert_eq!(Queue::open(&d).unwrap().items().count(), 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Reading a queue never creates one.
    #[test]
    fn listing_a_wrong_path_creates_nothing() {
        let d = dir("nothing");
        assert!(Queue::open_existing(&d).err().unwrap().contains("not a queue directory"));
        assert!(!d.exists());
        Queue::open(&d).unwrap();
        assert_eq!(Queue::open_existing(&d).unwrap().items().count(), 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The loop's state writes survive a reopen; landing frees the pending
    /// bound; a landed item's key still replays; a refusal is a named reason
    /// that survives a reopen; a malformed record is refused.
    #[test]
    fn states_round_trip_and_free_the_pending_bound() {
        let d = dir("states");
        let c = classify(W3C_CLAIM, &w3c_chain()).unwrap();
        let mut q = Queue::open(&d).unwrap();
        q.admit(&c, W3C_CLAIM).unwrap();
        assert_eq!(q.pending_items, 1);
        q.set_state(&c.id, State::Planned(3)).unwrap();
        assert_eq!(q.pending_items, 1, "planned is still owed a wrapper");
        q.set_state(&c.id, State::Landed(268)).unwrap();
        assert_eq!((q.pending_items, q.pending_bytes), (0, 0));
        drop(q);
        let q = Queue::open(&d).unwrap();
        assert_eq!(q.item(&c.id).unwrap().state, State::Landed(268));
        assert_eq!(q.decide(&c, W3C_CLAIM.len() as u64), Decision::Replay { id: c.id, kind: Kind::Claim });
        assert_eq!(q.artifact(&c.id).unwrap(), W3C_CLAIM);
        drop(q);
        let d2 = dir("states-refused");
        let mut q = Queue::open(&d2).unwrap();
        q.admit(&c, W3C_CLAIM).unwrap();
        q.set_state(&c.id, State::Refused(Refusal::Statement)).unwrap();
        assert_eq!((q.pending_items, q.pending_bytes), (0, 0));
        drop(q);
        assert_eq!(Queue::open(&d2).unwrap().item(&c.id).unwrap().state, State::Refused(Refusal::Statement));
        let _ = std::fs::remove_dir_all(&d2);
        for bad in ["planned\n", "planned 03\n", "landed x\n", "refused \n", "refused because\n", "queued", "queued\nqueued\n"] {
            std::fs::write(d.join("state").join(hex32(&c.id)), bad).unwrap();
            assert!(Queue::open(&d).err().unwrap().contains("unknown state record"), "{bad:?}");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The transition table: only the loop's moves are allowed, and the
    /// terminal states never change.
    #[test]
    fn only_the_loops_transitions_are_allowed() {
        let d = dir("transitions");
        let c = classify(W3C_CLAIM, &w3c_chain()).unwrap();
        let mut q = Queue::open(&d).unwrap();
        q.admit(&c, W3C_CLAIM).unwrap();
        let refuse = |q: &mut Queue, s: State| q.set_state(&c.id, s).unwrap_err();
        assert!(refuse(&mut q, State::Landed(1)).contains("queued may not become landed"));
        assert!(refuse(&mut q, State::Queued).contains("queued may not become queued"));
        q.set_state(&c.id, State::Planned(0)).unwrap();
        assert!(refuse(&mut q, State::Planned(1)).contains("planned may not become planned"));
        q.set_state(&c.id, State::Queued).unwrap();
        q.set_state(&c.id, State::Planned(1)).unwrap();
        q.set_state(&c.id, State::Landed(9)).unwrap();
        for s in [State::Queued, State::Planned(2), State::Landed(10), State::Refused(Refusal::Statement)] {
            assert!(refuse(&mut q, s).contains("landed may not become"));
        }
        assert_eq!(q.pending_items, 0, "a refused write never moves the counters");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// One intake per directory; a held lock says what it is and what to do.
    #[test]
    fn the_lock_is_exclusive() {
        let d = dir("lock");
        Queue::open(&d).unwrap();
        let held = Queue::lock(&d).unwrap();
        let err = Queue::lock(&d).err().unwrap();
        assert!(err.contains("another intake holds") && err.contains("index.lock") && err.contains("remove it"), "{err}");
        drop(held);
        assert!(Queue::lock(&d).is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }
}
