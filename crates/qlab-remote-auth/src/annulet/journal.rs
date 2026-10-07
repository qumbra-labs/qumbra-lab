//! Lab #896 seam G: the **authorization journal** `auth.v1` — the wallet's
//! Candidate A leaf state (design `remote-proving-authorization-shape-annulet`
//! §5, §9).
//!
//! One record per generation `g` of this wallet's key: the cursor position
//! `next` (seam A's only persisted cursor state), the generation's
//! authorization-tree root (what its v2 addresses bind, cached so a scan
//! does not rebuild the 2^D tree) and its state:
//!
//! - **`active`** — exactly one; the only generation new addresses come from;
//! - **`sweep`** — after a restore or a migration (§9): its notes may only be
//!   swept to the active generation, and on each net not before that net's
//!   gate height (the tip there plus `MAX_AUTH_VALIDITY_BLOCKS`), by which
//!   every authorization exported before has expired. A gate is a height on
//!   **one** net, recorded with that net's genesis hash: a seed's positions
//!   are shared across nets, its heights are not, so a net with no gate
//!   recorded is refused by name until one is;
//! - **`retired`** — nothing left to spend.
//!
//! **Fail-closed.** A leaf is taken by persisting `next + 1` — written to a
//! temporary file, fsync'd, renamed over `auth.v1` — **before** anything is
//! signed with it. A crash after the write wastes a position and never reuses
//! one. **One writer:** every take holds [`AuthLock`], an OS file lock on
//! `auth.lock`; the OS drops it when the process exits, crash included, so a
//! stale lock cannot outlive its holder.
//!
//! The journal is per key, not per net: one `(sk, g)` cursor serves every net
//! the seed is used on, so no leaf is ever used twice, anywhere.
//!
//! Lives here, beside the cursor it persists and below both `qumbra-wallet`
//! and `qumbra-faucet` (seam H, QH2), so the faucet keeps its own journal
//! under the same rules; `qumbra-wallet` re-exports it as
//! `qumbra_wallet::auth_journal`. This crate is prover-free, so the wallet's
//! wasm/iOS graph stays so.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use crate::Hash32;

/// The journal file in the wallet directory.
pub const AUTH_FILE: &str = "auth.v1";
/// The lock file every take holds.
pub const AUTH_LOCK_FILE: &str = "auth.lock";
const AUTH_HEADER: &str = "qumbra-wallet auth v1";
/// Lab #924 PR 3b: a journal that records how far each generation's landed
/// leaves were checked, per net (`checked <g> <genesis>:<height>` lines).
/// Written only when it has such a line, so a journal without one is the v1
/// text byte for byte; both are read.
const AUTH_HEADER_V2: &str = "qumbra-wallet auth v2";

/// How many generations a wallet with no journal (restored, or new to
/// Candidate A) tries when it scans (§9: "scan generations 0, 1, …"). Each
/// costs one authorization-tree build (≈ 0.32 s natively at D12); a wallet
/// whose highest generation with notes is the last one tried is refused by
/// name ([`JournalError::ProbeExhausted`]) rather than guessed past.
pub const PROBE_GENERATIONS: u32 = 8;

/// Generation `g`'s authorization-tree root for the key whose authorization
/// secret is `auth_secret` (`qlab_wallet::Wallet::auth_secret`): the tree over
/// `auth_master(auth_secret, g)` at `D_AUTH` (design 2b §2), as lanes — what
/// its v2 addresses bind. Takes the secret's bytes, not a wallet, so the
/// faucet (which holds a dev key and no `qlab_wallet::Wallet`) shares it.
pub fn generation_root(auth_secret: &[u8; 32], g: u32) -> [u64; 4] {
    use super::{auth_master, AuthTree, D_AUTH};
    let master = auth_master(auth_secret, g);
    let tree = AuthTree::build(&master, D_AUTH).expect("D_AUTH is a valid depth");
    let root = tree.root();
    // As lanes: four little-endian u64s (`qlab_note::hash::digest_from_bytes`).
    core::array::from_fn(|i| u64::from_le_bytes(root[i * 8..i * 8 + 8].try_into().expect("8 bytes")))
}

/// The probe set: generations `0 .. PROBE_GENERATIONS` with their roots.
pub fn probe_roots(auth_secret: &[u8; 32]) -> Vec<(u32, [u64; 4])> {
    (0..PROBE_GENERATIONS).map(|g| (g, generation_root(auth_secret, g))).collect()
}

/// A sweep gate: on the net with genesis hash `genesis`, nothing of the
/// generation is signed before `not_before_height`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SweepGate {
    pub genesis: [u8; 32],
    pub not_before_height: u64,
}

/// A generation's state (module doc).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GenState {
    Active,
    Sweep { gates: Vec<SweepGate> },
    Retired,
}

/// One generation's record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Generation {
    pub g: u32,
    /// The cursor position: positions `< next` are consumed.
    pub next: u32,
    /// The generation's authorization-tree root, as lanes.
    pub auth_root: [u64; 4],
    pub state: GenState,
}

/// Why the journal could not be read, written or used — by name.
#[derive(Debug)]
pub enum JournalError {
    Io(io::Error),
    /// The file is not a journal this wallet wrote: a bad header, a malformed
    /// record, two active generations, or none.
    Malformed(String),
    /// Another process holds `auth.lock` (a second `qumbra-wallet` on this
    /// wallet). The OS releases it when that process exits.
    Locked,
    /// The generation has no unconsumed leaf: migrate to the next one.
    Exhausted { g: u32 },
    /// No such generation in the journal.
    UnknownGeneration { g: u32 },
    /// A sweep of generation `g` before its gate height on this net.
    SweepNotYet { g: u32, not_before_height: u64, tip: u64 },
    /// A sweep of generation `g` on a net no gate was recorded for.
    SweepNoGate { g: u32 },
    /// Generation `g` is not sweep-only (active or retired).
    NotSweepOnly { g: u32 },
    /// A journal-less scan found notes in the last generation it probed.
    ProbeExhausted { probed: u32 },
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JournalError::Io(e) => write!(f, "{AUTH_FILE}: {e}"),
            JournalError::Malformed(why) => write!(f, "{AUTH_FILE} is malformed: {why}"),
            JournalError::Locked => write!(
                f,
                "another qumbra-wallet process holds this wallet's {AUTH_LOCK_FILE}; wait for it to finish \
                 (the lock is released when that process exits)"
            ),
            JournalError::Exhausted { g } => write!(
                f,
                "generation {g} has no unused authorization left; run `qumbra-wallet migrate` to move its \
                 notes to a new generation"
            ),
            JournalError::UnknownGeneration { g } => write!(f, "generation {g} is not in {AUTH_FILE}"),
            JournalError::SweepNotYet { g, not_before_height, tip } => write!(
                f,
                "generation {g} may be swept on this net from height {not_before_height} (the tip is {tip}): \
                 authorizations exported before the restore or migration must expire first"
            ),
            JournalError::SweepNoGate { g } => write!(
                f,
                "generation {g} has no sweep gate on this net: run `qumbra-wallet migrate` here first, which \
                 records this net's wait"
            ),
            JournalError::NotSweepOnly { g } => write!(f, "generation {g} is not sweep-only"),
            JournalError::ProbeExhausted { probed } => write!(
                f,
                "this wallet has notes in generation {}, the last of the {probed} a restore probes; it cannot \
                 tell which generation is current, so it signs nothing",
                probed - 1
            ),
        }
    }
}

impl std::error::Error for JournalError {}

impl From<io::Error> for JournalError {
    fn from(e: io::Error) -> Self {
        JournalError::Io(e)
    }
}

/// The OS file lock every take holds; dropped (and released) with the value,
/// and by the OS when the process ends however it ends.
#[derive(Debug)]
pub struct AuthLock {
    _file: File,
}

impl AuthLock {
    /// Take the lock, or [`JournalError::Locked`] if another process has it.
    pub fn acquire(dir: &Path) -> Result<AuthLock, JournalError> {
        let file = OpenOptions::new().create(true).truncate(false).write(true).open(dir.join(AUTH_LOCK_FILE))?;
        match file.try_lock() {
            Ok(()) => Ok(AuthLock { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => Err(JournalError::Locked),
            Err(std::fs::TryLockError::Error(e)) => Err(JournalError::Io(e)),
        }
    }
}

/// The journal (module doc).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthJournal {
    gens: Vec<Generation>,
    /// Lab #924 PR 3b: `(generation, genesis) → height` up to which the
    /// generation's landed leaves on that net were matched against its tree
    /// (the open-time `landed_next` check). Absent = 0.
    checked: std::collections::BTreeMap<(u32, Hash32), u64>,
}

impl AuthJournal {
    /// A fresh wallet's journal: generation 0 active at position 0.
    pub fn fresh(auth_root_0: [u64; 4]) -> Self {
        AuthJournal {
            gens: vec![Generation { g: 0, next: 0, auth_root: auth_root_0, state: GenState::Active }],
            checked: Default::default(),
        }
    }

    /// A journal from explicit records (restore). Checked like a loaded one.
    pub fn from_generations(gens: Vec<Generation>) -> Result<Self, JournalError> {
        let j = AuthJournal { gens, checked: Default::default() };
        j.check()?;
        Ok(j)
    }

    pub fn generations(&self) -> &[Generation] {
        &self.gens
    }

    /// The one active generation.
    pub fn active(&self) -> &Generation {
        self.gens.iter().find(|r| r.state == GenState::Active).expect("checked: exactly one active generation")
    }

    pub fn get(&self, g: u32) -> Result<&Generation, JournalError> {
        self.gens.iter().find(|r| r.g == g).ok_or(JournalError::UnknownGeneration { g })
    }

    fn get_mut(&mut self, g: u32) -> Result<&mut Generation, JournalError> {
        self.gens.iter_mut().find(|r| r.g == g).ok_or(JournalError::UnknownGeneration { g })
    }

    /// Record that generation `g`'s cursor now stands at `next` and persist
    /// it — the fail-closed step, run **before** the taken leaf signs
    /// anything. Requires the lock; never moves a cursor backwards.
    pub fn advance(&mut self, _lock: &AuthLock, dir: &Path, g: u32, next: u32) -> Result<(), JournalError> {
        self.advance_mem(g, next)?;
        self.save(dir)
    }

    /// [`Self::advance`] in memory, for a shell that persists the text itself
    /// under its own lock ([`Self::to_text`]; lab #924).
    pub fn advance_mem(&mut self, g: u32, next: u32) -> Result<(), JournalError> {
        let r = self.get_mut(g)?;
        if next < r.next {
            return Err(JournalError::Malformed(format!(
                "generation {g}'s cursor would move back from {} to {next}",
                r.next
            )));
        }
        r.next = next;
        Ok(())
    }

    /// Mark generation `g` retired (nothing left to spend), and persist.
    pub fn retire(&mut self, _lock: &AuthLock, dir: &Path, g: u32) -> Result<(), JournalError> {
        self.retire_mem(g)?;
        self.save(dir)
    }

    /// [`Self::retire`] in memory.
    pub fn retire_mem(&mut self, g: u32) -> Result<(), JournalError> {
        let r = self.get_mut(g)?;
        if r.state == GenState::Active {
            return Err(JournalError::Malformed(format!("generation {g} is active and cannot be retired")));
        }
        r.state = GenState::Retired;
        Ok(())
    }

    /// Open the next generation as the active one, the previous active one
    /// becoming sweep-only with a gate at `gate` (a migration), and persist.
    pub fn open_next(&mut self, _lock: &AuthLock, dir: &Path, auth_root: [u64; 4], gate: SweepGate) -> Result<u32, JournalError> {
        let g = self.open_next_mem(auth_root, gate);
        self.save(dir)?;
        Ok(g)
    }

    /// [`Self::open_next`] in memory.
    pub fn open_next_mem(&mut self, auth_root: [u64; 4], gate: SweepGate) -> u32 {
        let g = self.gens.iter().map(|r| r.g).max().expect("checked: non-empty") + 1;
        for r in &mut self.gens {
            if r.state == GenState::Active {
                r.state = GenState::Sweep { gates: vec![gate] };
            }
        }
        self.gens.push(Generation { g, next: 0, auth_root, state: GenState::Active });
        g
    }

    /// Record a sweep gate for generation `g` on `gate.genesis`'s net —
    /// another net this seed is used on — and persist. A gate already
    /// recorded for that net is kept (the earlier wait is the one that
    /// covers what was exported before it).
    pub fn add_gate(&mut self, _lock: &AuthLock, dir: &Path, g: u32, gate: SweepGate) -> Result<(), JournalError> {
        self.add_gate_mem(g, gate)?;
        self.save(dir)
    }

    /// [`Self::add_gate`] in memory.
    pub fn add_gate_mem(&mut self, g: u32, gate: SweepGate) -> Result<(), JournalError> {
        let r = self.get_mut(g)?;
        let GenState::Sweep { gates } = &mut r.state else { return Err(JournalError::NotSweepOnly { g }) };
        if !gates.iter().any(|x| x.genesis == gate.genesis) {
            gates.push(gate);
        }
        Ok(())
    }

    /// May generation `g` sign a sweep on the net `genesis` at tip `tip`?
    pub fn sweep_allowed(&self, g: u32, genesis: &[u8; 32], tip: u64) -> Result<(), JournalError> {
        let r = self.get(g)?;
        let GenState::Sweep { gates } = &r.state else { return Err(JournalError::NotSweepOnly { g }) };
        let gate = gates.iter().find(|x| &x.genesis == genesis).ok_or(JournalError::SweepNoGate { g })?;
        if tip < gate.not_before_height {
            return Err(JournalError::SweepNotYet { g, not_before_height: gate.not_before_height, tip });
        }
        Ok(())
    }

    /// Load `auth.v1`, or `None` if the wallet has none (a restored or pre-G
    /// wallet: the first Candidate A command migrates, §9).
    pub fn load(dir: &Path) -> Result<Option<Self>, JournalError> {
        let text = match std::fs::read_to_string(dir.join(AUTH_FILE)) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        Self::parse(&text).map(Some)
    }

    /// Write `auth.v1` atomically: a temporary file at mode 0600, fsync,
    /// rename, then fsync the directory so the rename itself is durable.
    pub fn save(&self, dir: &Path) -> Result<(), JournalError> {
        let tmp = dir.join(format!("{AUTH_FILE}.tmp"));
        {
            let mut f = OpenOptions::new().create(true).truncate(true).write(true).open(&tmp)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            f.write_all(self.render().as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, dir.join(AUTH_FILE))?;
        #[cfg(unix)]
        File::open(dir)?.sync_all()?;
        Ok(())
    }

    /// How far generation `g`'s landed leaves on the net `genesis` have been
    /// checked (0: never).
    pub fn checked_to(&self, g: u32, genesis: &Hash32) -> u64 {
        self.checked.get(&(g, *genesis)).copied().unwrap_or(0)
    }

    /// Record that generation `g`'s landed leaves on `genesis` are checked
    /// through `height`. Never moves back (a lower height is kept as is).
    pub fn set_checked_mem(&mut self, g: u32, genesis: &Hash32, height: u64) -> Result<(), JournalError> {
        self.get(g)?;
        let e = self.checked.entry((g, *genesis)).or_insert(0);
        *e = (*e).max(height);
        Ok(())
    }

    /// The `auth.v1` text, exactly as [`Self::save`] writes it — what a shell
    /// that keeps no files (the browser extension) stores under its own lock.
    pub fn to_text(&self) -> String {
        self.render()
    }

    /// Parse `auth.v1` text, checked as [`Self::load`] checks a file.
    pub fn from_text(text: &str) -> Result<Self, JournalError> {
        Self::parse(text)
    }

    fn render(&self) -> String {
        let header = if self.checked.is_empty() { AUTH_HEADER } else { AUTH_HEADER_V2 };
        let mut out = format!("{header}\n");
        for r in &self.gens {
            let root: String = r.auth_root.iter().map(|w| format!("{w:016x}")).collect();
            let state = match &r.state {
                GenState::Active => "active".to_string(),
                GenState::Sweep { gates } => {
                    let g: Vec<String> = gates
                        .iter()
                        .map(|x| format!("{}:{}", x.genesis.iter().map(|b| format!("{b:02x}")).collect::<String>(), x.not_before_height))
                        .collect();
                    format!("sweep {}", g.join(","))
                }
                GenState::Retired => "retired".to_string(),
            };
            out.push_str(&format!("{} {} {root} {state}\n", r.g, r.next));
        }
        for ((g, genesis), h) in &self.checked {
            out.push_str(&format!("checked {g} {}:{h}\n", genesis.iter().map(|b| format!("{b:02x}")).collect::<String>()));
        }
        out
    }

    fn parse(text: &str) -> Result<Self, JournalError> {
        let bad = |why: String| JournalError::Malformed(why);
        let mut lines = text.lines();
        let v2 = match lines.next() {
            Some(AUTH_HEADER) => false,
            Some(AUTH_HEADER_V2) => true,
            _ => return Err(bad(format!("the first line is neither `{AUTH_HEADER}` nor `{AUTH_HEADER_V2}`"))),
        };
        let mut gens = Vec::new();
        let mut checked = std::collections::BTreeMap::new();
        for (i, line) in lines.enumerate() {
            if let Some(rest) = line.strip_prefix("checked ") {
                if !v2 {
                    return Err(bad(format!("record {i}: a `checked` line in a v1 journal")));
                }
                let (g, at) = rest.split_once(' ').ok_or_else(|| bad(format!("record {i}: `checked g genesis:height`")))?;
                let (hash, h) = at.split_once(':').ok_or_else(|| bad(format!("record {i}: `checked g genesis:height`")))?;
                let genesis = hex32(hash).ok_or_else(|| bad(format!("record {i}: the genesis is not 64 hex digits")))?;
                let g: u32 = g.parse().map_err(|_| bad(format!("record {i}: `{g}` is not a generation")))?;
                let h: u64 = h.parse().map_err(|_| bad(format!("record {i}: `{h}` is not a height")))?;
                if checked.insert((g, genesis), h).is_some() {
                    return Err(bad(format!("record {i}: generation {g} checked twice on one net")));
                }
                continue;
            }
            let f: Vec<&str> = line.split(' ').collect();
            let num = |s: &str| s.parse::<u64>().map_err(|_| bad(format!("record {i}: `{s}` is not a number")));
            let (g, next, root, state) = match f.as_slice() {
                [g, n, root, "active"] => (num(g)?, num(n)?, *root, GenState::Active),
                [g, n, root, "sweep", gates] => {
                    let mut out = Vec::new();
                    for gate in gates.split(',') {
                        let (hash, h) = gate.split_once(':').ok_or_else(|| bad(format!("record {i}: a gate is not `genesis:height`")))?;
                        if hash.len() != 64 || !hash.is_ascii() {
                            return Err(bad(format!("record {i}: a gate's genesis is not 64 hex digits")));
                        }
                        let mut genesis = [0u8; 32];
                        for (k, b) in genesis.iter_mut().enumerate() {
                            *b = u8::from_str_radix(&hash[2 * k..2 * k + 2], 16)
                                .map_err(|_| bad(format!("record {i}: a gate's genesis is not hex")))?;
                        }
                        out.push(SweepGate { genesis, not_before_height: num(h)? });
                    }
                    (num(g)?, num(n)?, *root, GenState::Sweep { gates: out })
                }
                [g, n, root, "retired"] => (num(g)?, num(n)?, *root, GenState::Retired),
                _ => return Err(bad(format!("record {i} is not `g next root state`"))),
            };
            if root.len() != 64 || !root.is_ascii() {
                return Err(bad(format!("record {i}: the root is not 64 hex digits")));
            }
            let mut auth_root = [0u64; 4];
            for (k, w) in auth_root.iter_mut().enumerate() {
                *w = u64::from_str_radix(&root[16 * k..16 * k + 16], 16)
                    .map_err(|_| bad(format!("record {i}: the root is not hex")))?;
            }
            let g = u32::try_from(g).map_err(|_| bad(format!("record {i}: generation out of range")))?;
            let next = u32::try_from(next).map_err(|_| bad(format!("record {i}: position out of range")))?;
            gens.push(Generation { g, next, auth_root, state });
        }
        let mut j = Self::from_generations(gens)?;
        if let Some((g, _)) = checked.keys().find(|(g, _)| j.get(*g).is_err()) {
            return Err(bad(format!("a `checked` line names generation {g}, which has no record")));
        }
        if v2 && checked.is_empty() {
            return Err(bad("a v2 journal with no `checked` line (a writer emits v1 then)".into()));
        }
        j.checked = checked;
        Ok(j)
    }

    fn check(&self) -> Result<(), JournalError> {
        let actives = self.gens.iter().filter(|r| r.state == GenState::Active).count();
        if actives != 1 {
            return Err(JournalError::Malformed(format!("{actives} active generations, not exactly one")));
        }
        let mut seen = std::collections::BTreeSet::new();
        for r in &self.gens {
            if !seen.insert(r.g) {
                return Err(JournalError::Malformed(format!("generation {} appears twice", r.g)));
            }
        }
        Ok(())
    }
}

fn hex32(s: &str) -> Option<Hash32> {
    if s.len() != 64 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (k, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * k..2 * k + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lab #924 PR 3b: a journal with no `checked` line is the v1 text byte
    /// for byte; one with lines is v2 and round-trips; the parser refuses a
    /// `checked` line in v1, an unknown generation, a duplicate, and an
    /// empty v2.
    #[test]
    fn the_checked_lines_are_v2_and_v1_stays_byte_identical() {
        let net = [0x33; 32];
        let mut j = AuthJournal::fresh([1, 2, 3, 4]);
        let v1 = j.to_text();
        assert!(v1.starts_with("qumbra-wallet auth v1\n"));
        assert_eq!(AuthJournal::from_text(&v1).unwrap(), j);
        assert_eq!(j.checked_to(0, &net), 0);
        j.set_checked_mem(0, &net, 40).unwrap();
        j.set_checked_mem(0, &net, 30).unwrap();
        assert_eq!(j.checked_to(0, &net), 40, "never moves back");
        assert!(j.set_checked_mem(5, &net, 1).is_err(), "no such generation");
        let v2 = j.to_text();
        assert!(v2.starts_with("qumbra-wallet auth v2\n") && v2.ends_with(&format!("checked 0 {}:40\n", "33".repeat(32))), "{v2}");
        assert_eq!(AuthJournal::from_text(&v2).unwrap(), j);
        let bad = [
            v1.clone() + &format!("checked 0 {}:1\n", "33".repeat(32)),
            v2.replace("checked 0 ", "checked 7 "),
            v2.clone() + &format!("checked 0 {}:9\n", "33".repeat(32)),
            v1.replacen("auth v1", "auth v2", 1),
            v2.replace(":40", ":x"),
        ];
        for text in bad {
            assert!(AuthJournal::from_text(&text).is_err(), "{text}");
        }
    }

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("qumbra-auth-journal-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_journal_round_trips_through_its_file_at_mode_0600() {
        let dir = tmpdir("rt");
        assert!(AuthJournal::load(&dir).unwrap().is_none(), "no file: a restored wallet");
        let mut j = AuthJournal::fresh([1, 2, 3, u64::MAX]);
        let lock = AuthLock::acquire(&dir).unwrap();
        j.advance(&lock, &dir, 0, 7).unwrap();
        let net_a = SweepGate { genesis: [0xA1; 32], not_before_height: 1_200 };
        let g1 = j.open_next(&lock, &dir, [9, 9, 9, 9], net_a).unwrap();
        j.add_gate(&lock, &dir, 0, SweepGate { genesis: [0xB2; 32], not_before_height: 40 }).unwrap();
        assert_eq!(g1, 1);
        let back = AuthJournal::load(&dir).unwrap().unwrap();
        assert_eq!(back, j);
        assert_eq!(back.active().g, 1);
        assert_eq!(
            back.get(0).unwrap().state,
            GenState::Sweep {
                gates: vec![net_a, SweepGate { genesis: [0xB2; 32], not_before_height: 40 }]
            }
        );
        assert_eq!(back.get(0).unwrap().next, 7);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join(AUTH_FILE)).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_cursor_never_moves_back_and_retiring_the_active_one_is_refused() {
        let dir = tmpdir("back");
        let lock = AuthLock::acquire(&dir).unwrap();
        let mut j = AuthJournal::fresh([0; 4]);
        j.advance(&lock, &dir, 0, 5).unwrap();
        assert!(matches!(j.advance(&lock, &dir, 0, 4), Err(JournalError::Malformed(_))));
        assert!(matches!(j.retire(&lock, &dir, 0), Err(JournalError::Malformed(_))));
        assert!(matches!(j.advance(&lock, &dir, 3, 1), Err(JournalError::UnknownGeneration { g: 3 })));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_malformed_journal_is_refused_by_name() {
        for text in [
            "not the header\n",
            "qumbra-wallet auth v1\n0 0 00 active\n",
            "qumbra-wallet auth v1\n",
            &format!("qumbra-wallet auth v1\n0 0 {z} active\n1 0 {z} active\n", z = "0".repeat(64)),
            &format!("qumbra-wallet auth v1\n0 0 {z} retired\n0 1 {z} active\n", z = "0".repeat(64)),
            &format!("qumbra-wallet auth v1\n0 x {z} active\n", z = "0".repeat(64)),
            &format!("qumbra-wallet auth v1\n0 0 {z} active\n1 0 {z} sweep \n", z = "0".repeat(64)),
            &format!("qumbra-wallet auth v1\n0 0 {z} active\n1 0 {z} sweep {w}:5\n", z = "0".repeat(64), w = "é".repeat(32)),
            &format!("qumbra-wallet auth v1\n0 0 {r} active\n", r = "é".repeat(32)),
        ] {
            assert!(matches!(AuthJournal::parse(text), Err(JournalError::Malformed(_))), "{text:?}");
        }
    }

    /// A sweep gate is a height on one net: refused before it, allowed at it,
    /// and refused by name on a net with no gate recorded.
    #[test]
    fn a_sweep_gate_is_per_net() {
        let dir = tmpdir("gate");
        let lock = AuthLock::acquire(&dir).unwrap();
        let mut j = AuthJournal::fresh([0; 4]);
        let (a, b) = ([0xA1; 32], [0xB2; 32]);
        j.open_next(&lock, &dir, [1; 4], SweepGate { genesis: a, not_before_height: 100 }).unwrap();
        assert!(matches!(j.sweep_allowed(0, &a, 99), Err(JournalError::SweepNotYet { g: 0, not_before_height: 100, tip: 99 })));
        assert!(j.sweep_allowed(0, &a, 100).is_ok());
        assert!(matches!(j.sweep_allowed(0, &b, 10_000), Err(JournalError::SweepNoGate { g: 0 })));
        assert!(matches!(j.sweep_allowed(1, &a, 10_000), Err(JournalError::NotSweepOnly { g: 1 })));
        j.add_gate(&lock, &dir, 0, SweepGate { genesis: b, not_before_height: 7 }).unwrap();
        assert!(j.sweep_allowed(0, &b, 7).is_ok());
        // An existing gate is kept: the earlier wait covers what was exported before it.
        j.add_gate(&lock, &dir, 0, SweepGate { genesis: a, not_before_height: 5 }).unwrap();
        assert!(j.sweep_allowed(0, &a, 99).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// One writer: a second lock on the same wallet is refused by name while
    /// the first is held, and taken again once it is dropped.
    #[test]
    fn a_second_writer_is_refused_while_the_lock_is_held() {
        let dir = tmpdir("lock");
        let first = AuthLock::acquire(&dir).unwrap();
        assert!(matches!(AuthLock::acquire(&dir), Err(JournalError::Locked)));
        drop(first);
        assert!(AuthLock::acquire(&dir).is_ok(), "released with its holder");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
