//! Address manager — the **policy** half of peer discovery (issue #83).
//!
//! This module decides *which* addresses this node knows, which of them may be
//! gossiped, and which to dial next. It performs no I/O: the *mechanism* (open a
//! socket) is [`crate::transport::Transport::dial`], driven by
//! [`crate::node::P2pNode::maintain`]. Splitting it this way is deliberate — the
//! whole policy is unit-testable without a socket, and there is exactly **one**
//! dial path in the stack (see "one dialer" below).
//!
//! ## Dialable vs connected (Larry's NAT decision, 2026-07-26)
//!
//! T1 accepts outbound-only participants — a node behind a router syncs, mines
//! and transacts but cannot serve peers. That makes the central distinction here:
//!
//! - **known / candidate** — an address we have heard of. It may be unreachable.
//! - **dialable** — an address we have **successfully connected *to*** at least
//!   once. Only these may be gossiped onward ([`AddrManager::gossipable`]).
//!
//! Gossiping merely-connected addresses would fill every joiner's book with
//! entries nobody can dial, and it would *look* like discovery was working.
//! Reachability of **ourselves** is not inferred — a node cannot learn its own
//! public address without being told, and telling it is a wire change (S1). It is
//! therefore **explicit configuration**: [`AddrManager::set_self_advertise`], set
//! by the operator (the T0 seeds set it; a home node does not).
//!
//! ## One dialer
//!
//! The re-dial state that lived in `qumbra-node`'s run loop (T0-5 / S9:
//! `RedialSlot`, `REDIAL_*`) moved here unchanged in semantics — same backoff
//! ladder, same "skip if the handle is still live" rule — so configured seeds and
//! learned addresses share one path, one backoff and one cap. Two dial paths with
//! different caps is how a node ends up exceeding a limit it believes it is
//! enforcing.
//!
//! ## Caps
//!
//! Every constant here is `[devnet-placeholder]` **testnet-tunable, NOT frozen**.
//! They ship with auto-connect, not after it (S3): auto-connect without a cap is a
//! resource-exhaustion bug that the discovery feature itself would introduce.

use std::collections::{BTreeMap, HashSet};

use crate::peer::PeerId;

/// Maximum simultaneous **outbound** connections we will open ourselves.
pub const MAX_OUTBOUND: usize = 8;
/// Maximum simultaneous **inbound** connections accepted (enforced at accept —
/// see [`crate::transport::TcpTransport::set_inbound_cap`]).
pub const MAX_INBOUND: usize = 32;
/// Maximum entries retained in the address book.
pub const MAX_ADDR_BOOK: usize = 1024;
/// Maximum addresses accepted from, or served in, a single `Addr` message.
pub const MAX_ADDRS_PER_MSG: usize = 100;
/// Minimum gap between two `GetAddr` requests to the *same* peer (rate limit).
pub const GETADDR_INTERVAL_MS: u64 = 60_000;
/// How often the maintenance pass reconsiders dialing (was `REDIAL_INTERVAL`).
pub const DIAL_RETRY_INTERVAL_MS: u64 = 5_000;
/// First backoff after a failed dial; doubles to [`DIAL_BACKOFF_MAX_MS`].
pub const DIAL_BACKOFF_START_MS: u64 = 1_000;
/// Cap on the dial backoff, so a long partition still retries regularly.
pub const DIAL_BACKOFF_MAX_MS: u64 = 30_000;
/// Longest address string accepted (a cheap bound before any parsing).
pub const MAX_ADDR_LEN: usize = 128;

/// Where an address came from. Seeds are **never evicted** (S4): they are the
/// recovery path when everything learned has gone stale.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddrSource {
    /// Configured by the operator (`dial_peers`).
    Seed,
    /// Learned from a peer's `Addr` message. Untrusted (S6): a candidate to try,
    /// never grounds for scoring, preference or ban.
    Learned,
}

/// One address book entry.
#[derive(Clone, Debug)]
pub struct AddrEntry {
    pub addr: String,
    pub source: AddrSource,
    /// True once we have successfully connected **to** this address. Sticky: a
    /// peer that goes down was still demonstrably dialable, and the seed set must
    /// survive a partition.
    pub dialable: bool,
    /// Live transport handle while connected.
    pub connected: Option<PeerId>,
    /// Consecutive failed dials (reset on success).
    pub failures: u32,
    next_retry_ms: u64,
    backoff_ms: u64,
    /// Insertion order, for deterministic eviction.
    seq: u64,
}

impl AddrEntry {
    fn new(addr: String, source: AddrSource, seq: u64) -> Self {
        AddrEntry {
            addr,
            source,
            dialable: false,
            connected: None,
            failures: 0,
            next_retry_ms: 0,
            backoff_ms: DIAL_BACKOFF_START_MS,
            seq,
        }
    }
}

/// The address book + dial policy.
#[derive(Clone, Debug)]
pub struct AddrManager {
    entries: BTreeMap<String, AddrEntry>,
    /// Our own address, iff the operator declared us reachable. `None` ⇒ we are
    /// never gossiped (the outbound-only case, and it is expected).
    self_advertise: Option<String>,
    /// Per-peer last `GetAddr` time, for the ask rate limit.
    last_getaddr: BTreeMap<PeerId, u64>,
    max_outbound: usize,
    max_book: usize,
    seq: u64,
}

impl Default for AddrManager {
    fn default() -> Self {
        AddrManager {
            entries: BTreeMap::new(),
            self_advertise: None,
            last_getaddr: BTreeMap::new(),
            max_outbound: MAX_OUTBOUND,
            max_book: MAX_ADDR_BOOK,
            seq: 0,
        }
    }
}

impl AddrManager {
    pub fn new() -> Self {
        AddrManager::default()
    }

    /// Build with a configured seed set (S4: these are never evicted).
    pub fn with_seeds<I: IntoIterator<Item = String>>(seeds: I) -> Self {
        let mut m = AddrManager::new();
        for s in seeds {
            m.add_seed(s);
        }
        m
    }

    /// Declare our own reachable address (scope 3). Operator-set; unset means
    /// this node is outbound-only and is never gossiped.
    pub fn set_self_advertise(&mut self, addr: Option<String>) {
        self.self_advertise = addr.filter(|a| valid_addr(a));
    }

    pub fn self_advertise(&self) -> Option<&str> {
        self.self_advertise.as_deref()
    }

    /// Override the outbound cap (tests / testnet tuning).
    pub fn set_max_outbound(&mut self, n: usize) {
        self.max_outbound = n;
    }

    /// Override the address-book bound (tests / testnet tuning).
    pub fn set_max_book(&mut self, n: usize) {
        self.max_book = n;
    }

    /// Add a configured seed. Idempotent; upgrades a previously-learned entry to
    /// `Seed` so it can no longer be evicted.
    pub fn add_seed(&mut self, addr: String) {
        if !valid_addr(&addr) {
            return;
        }
        let seq = self.next_seq();
        match self.entries.get_mut(&addr) {
            Some(e) => e.source = AddrSource::Seed,
            None => {
                self.entries.insert(addr.clone(), AddrEntry::new(addr, AddrSource::Seed, seq));
            }
        }
    }

    /// Admit addresses learned from a peer's `Addr` message (scope 1).
    ///
    /// Returns how many were newly admitted. Invalid, duplicate and over-cap
    /// entries are silently dropped: a peer's claim about a third party is a
    /// candidate at best (S6), so a bad one is never a scoring event — it would
    /// let any peer get a third party penalised.
    pub fn learn<I: IntoIterator<Item = String>>(&mut self, addrs: I) -> usize {
        let mut admitted = 0;
        for a in addrs.into_iter().take(MAX_ADDRS_PER_MSG) {
            if !valid_addr(&a) || self.entries.contains_key(&a) {
                continue;
            }
            if self.self_advertise.as_deref() == Some(a.as_str()) {
                continue; // never dial ourselves
            }
            if self.entries.len() >= self.max_book && !self.evict_one() {
                break; // book full of seeds/dialable entries — refuse, never evict those
            }
            let seq = self.next_seq();
            self.entries.insert(a.clone(), AddrEntry::new(a, AddrSource::Learned, seq));
            admitted += 1;
        }
        admitted
    }

    /// Evict the oldest **learned, not-dialable, not-connected** entry. Seeds (S4)
    /// and demonstrably dialable addresses are never evicted — they are the only
    /// things of value in the book. Returns whether something was evicted.
    fn evict_one(&mut self) -> bool {
        let victim = self
            .entries
            .values()
            .filter(|e| {
                e.source == AddrSource::Learned && !e.dialable && e.connected.is_none()
            })
            .min_by_key(|e| e.seq)
            .map(|e| e.addr.clone());
        match victim {
            Some(a) => {
                self.entries.remove(&a);
                true
            }
            None => false,
        }
    }

    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    /// Record a successful dial: the address is now **dialable** and gossipable.
    pub fn on_dial_success(&mut self, addr: &str, pid: PeerId) {
        if let Some(e) = self.entries.get_mut(addr) {
            e.dialable = true;
            e.connected = Some(pid);
            e.failures = 0;
            e.backoff_ms = DIAL_BACKOFF_START_MS;
        }
    }

    /// Record a failed dial: exponential backoff, capped.
    pub fn on_dial_failure(&mut self, addr: &str, now_ms: u64) {
        if let Some(e) = self.entries.get_mut(addr) {
            e.connected = None;
            e.failures = e.failures.saturating_add(1);
            e.backoff_ms = (e.backoff_ms * 2).min(DIAL_BACKOFF_MAX_MS);
            e.next_retry_ms = now_ms + e.backoff_ms;
        }
    }

    /// Forget a dropped connection handle. `dialable` is intentionally sticky —
    /// the address *was* reachable, and a partition must not erase the seed set's
    /// gossipability.
    pub fn on_disconnect(&mut self, pid: PeerId) {
        for e in self.entries.values_mut() {
            if e.connected == Some(pid) {
                e.connected = None;
            }
        }
    }

    /// Reconcile our view of live connections with the transport's (handles that
    /// vanished are no longer connected).
    pub fn sync_live(&mut self, live: &HashSet<PeerId>) {
        for e in self.entries.values_mut() {
            if let Some(p) = e.connected {
                if !live.contains(&p) {
                    e.connected = None;
                }
            }
        }
    }

    /// Addresses to dial now, newest-useful first and **cap-respecting**: at most
    /// `max_outbound - currently_connected` are returned, skipping anything already
    /// connected or still inside its backoff.
    ///
    /// Seeds are tried before learned candidates — when everything else is stale
    /// they are the recovery path (S4) — and among equals the least-failed first.
    pub fn next_dials(&self, now_ms: u64) -> Vec<String> {
        let live = self.outbound_live();
        if live >= self.max_outbound {
            return Vec::new();
        }
        let budget = self.max_outbound - live;
        let mut cands: Vec<&AddrEntry> = self
            .entries
            .values()
            .filter(|e| e.connected.is_none() && now_ms >= e.next_retry_ms)
            .collect();
        cands.sort_by_key(|e| {
            let seed_rank = if e.source == AddrSource::Seed { 0 } else { 1 };
            (seed_rank, e.failures, e.seq)
        });
        cands.into_iter().take(budget).map(|e| e.addr.clone()).collect()
    }

    /// How many outbound connections we currently hold.
    pub fn outbound_live(&self) -> usize {
        self.entries.values().filter(|e| e.connected.is_some()).count()
    }

    /// Whether we may ask `pid` for addresses now (rate limit, scope 2).
    pub fn may_ask(&self, pid: PeerId, now_ms: u64) -> bool {
        match self.last_getaddr.get(&pid) {
            Some(&t) => now_ms.saturating_sub(t) >= GETADDR_INTERVAL_MS,
            None => true,
        }
    }

    /// Record that we asked `pid` for addresses.
    pub fn mark_asked(&mut self, pid: PeerId, now_ms: u64) {
        self.last_getaddr.insert(pid, now_ms);
    }

    /// The addresses we may gossip (S2): **only** ones we have connected to, plus
    /// our own iff the operator declared us reachable. Bounded by
    /// [`MAX_ADDRS_PER_MSG`]; deterministic order.
    pub fn gossipable(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        if let Some(me) = &self.self_advertise {
            out.push(me.clone());
        }
        for e in self.entries.values() {
            if e.dialable && Some(e.addr.as_str()) != self.self_advertise.as_deref() {
                out.push(e.addr.clone());
            }
            if out.len() >= MAX_ADDRS_PER_MSG {
                break;
            }
        }
        out.truncate(MAX_ADDRS_PER_MSG);
        out
    }

    /// Every address known, dialable or not (ops / tests).
    pub fn known(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }

    pub fn known_count(&self) -> usize {
        self.entries.len()
    }

    /// How many known addresses are demonstrably dialable. Together with
    /// [`Self::known_count`] this is the **measured NAT re-open trigger**: if the
    /// ratio collapses toward "only the seeds are dialable", that is the signal to
    /// build NAT traversal.
    pub fn dialable_count(&self) -> usize {
        self.entries.values().filter(|e| e.dialable).count()
    }

    pub fn entry(&self, addr: &str) -> Option<&AddrEntry> {
        self.entries.get(addr)
    }

    /// Test/ops hook: clear every backoff so the next maintenance pass dials
    /// immediately (partition-heal without wall-clock waits).
    pub fn force_retry_ready(&mut self) {
        for e in self.entries.values_mut() {
            e.next_retry_ms = 0;
        }
    }

    // --- persistence (scope 7) ---

    /// Serialize the book: `version(0x01) ‖ n(u32 LE) ‖ [flags(u8) ‖ len(u16 LE) ‖ utf8]*`.
    ///
    /// Only **dialable** entries are persisted: a candidate we never reached is
    /// worth nothing across a restart, and persisting junk is how a book fills
    /// with unreachable entries. Seeds come back from config regardless.
    pub fn to_bytes(&self) -> Vec<u8> {
        let keep: Vec<&AddrEntry> = self.entries.values().filter(|e| e.dialable).collect();
        let mut out = vec![ADDRBOOK_VERSION];
        out.extend_from_slice(&(keep.len() as u32).to_le_bytes());
        for e in keep {
            out.push(if e.source == AddrSource::Seed { 1 } else { 0 });
            let b = e.addr.as_bytes();
            out.extend_from_slice(&(b.len() as u16).to_le_bytes());
            out.extend_from_slice(b);
        }
        out
    }

    /// Restore a persisted book (§0 discipline: reject-unknown version, reject
    /// trailing). Entries are restored as `Learned`/dialable; the configured seed
    /// set is re-applied by the caller, which is the authority on what is a seed.
    pub fn from_bytes(buf: &[u8]) -> Result<AddrManager, AddrBookError> {
        if buf.is_empty() {
            return Err(AddrBookError::Truncated);
        }
        if buf[0] != ADDRBOOK_VERSION {
            return Err(AddrBookError::UnknownVersion(buf[0]));
        }
        if buf.len() < 5 {
            return Err(AddrBookError::Truncated);
        }
        let n = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
        if n > MAX_ADDR_BOOK {
            return Err(AddrBookError::TooMany(n));
        }
        let mut pos = 5usize;
        let mut m = AddrManager::new();
        for _ in 0..n {
            if pos + 3 > buf.len() {
                return Err(AddrBookError::Truncated);
            }
            let is_seed = match buf[pos] {
                0 => false,
                1 => true,
                other => return Err(AddrBookError::BadFlags(other)),
            };
            let len = u16::from_le_bytes([buf[pos + 1], buf[pos + 2]]) as usize;
            pos += 3;
            if pos + len > buf.len() {
                return Err(AddrBookError::Truncated);
            }
            let addr = String::from_utf8(buf[pos..pos + len].to_vec())
                .map_err(|_| AddrBookError::BadUtf8)?;
            pos += len;
            if !valid_addr(&addr) {
                return Err(AddrBookError::BadAddr);
            }
            let seq = m.next_seq();
            let mut e = AddrEntry::new(
                addr.clone(),
                if is_seed { AddrSource::Seed } else { AddrSource::Learned },
                seq,
            );
            e.dialable = true;
            m.entries.insert(addr, e);
        }
        if pos != buf.len() {
            return Err(AddrBookError::Trailing(buf.len() - pos));
        }
        Ok(m)
    }
}

/// Address-book persistence format version (§0: reject-unknown).
pub const ADDRBOOK_VERSION: u8 = 0x01;

/// Why a persisted address book was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddrBookError {
    UnknownVersion(u8),
    Truncated,
    Trailing(usize),
    TooMany(usize),
    BadFlags(u8),
    BadUtf8,
    BadAddr,
}

impl core::fmt::Display for AddrBookError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AddrBookError::UnknownVersion(v) => write!(f, "unknown addrbook version {v:#04x}"),
            AddrBookError::Truncated => write!(f, "addrbook truncated"),
            AddrBookError::Trailing(n) => write!(f, "addrbook has {n} trailing bytes"),
            AddrBookError::TooMany(n) => write!(f, "addrbook declares {n} entries"),
            AddrBookError::BadFlags(b) => write!(f, "addrbook bad flags {b:#04x}"),
            AddrBookError::BadUtf8 => write!(f, "addrbook address is not utf-8"),
            AddrBookError::BadAddr => write!(f, "addrbook address is malformed"),
        }
    }
}
impl std::error::Error for AddrBookError {}

/// Cheap structural validation of a `host:port` address string. Prototype grade,
/// and deliberately conservative: anything we cannot make sense of is not a
/// candidate. It is **not** a reachability claim — that is only earned by a
/// successful dial.
pub fn valid_addr(addr: &str) -> bool {
    if addr.is_empty() || addr.len() > MAX_ADDR_LEN {
        return false;
    }
    if addr.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    // Split off the port at the LAST colon (IPv6 literals carry colons inside
    // brackets: `[::1]:9333`).
    let (host, port) = match addr.rsplit_once(':') {
        Some((h, p)) => (h, p),
        None => return false,
    };
    if host.is_empty() {
        return false;
    }
    match port.parse::<u16>() {
        Ok(p) => p != 0,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> String {
        s.to_string()
    }

    #[test]
    fn validates_addresses() {
        assert!(valid_addr("127.0.0.1:9333"));
        assert!(valid_addr("node.example.org:9333"));
        assert!(valid_addr("[::1]:9333"));
        assert!(!valid_addr("127.0.0.1"), "no port");
        assert!(!valid_addr("127.0.0.1:0"), "port 0");
        assert!(!valid_addr("127.0.0.1:99999"), "port out of range");
        assert!(!valid_addr(":9333"), "no host");
        assert!(!valid_addr("host with space:1"), "whitespace");
        assert!(!valid_addr(""), "empty");
        assert!(!valid_addr(&format!("{}:9333", "x".repeat(MAX_ADDR_LEN))), "over-long");
    }

    #[test]
    fn learned_addresses_are_admitted_once_and_validated() {
        let mut m = AddrManager::new();
        let n = m.learn(vec![a("1.1.1.1:1"), a("1.1.1.1:1"), a("bogus"), a("2.2.2.2:2")]);
        assert_eq!(n, 2, "duplicate and malformed are dropped");
        assert_eq!(m.known_count(), 2);
        assert_eq!(m.dialable_count(), 0, "learning is not a reachability claim");
    }

    #[test]
    fn only_dialable_addresses_are_gossiped() {
        // S2, and acceptance item 2 in the policy layer: a peer we merely know of,
        // and even one that is connected to *us*, is never handed out.
        let mut m = AddrManager::with_seeds(vec![a("seed:1")]);
        m.learn(vec![a("cand:2")]);
        assert!(m.gossipable().is_empty(), "nothing dialed yet ⇒ nothing gossipable");

        m.on_dial_success("cand:2", PeerId(7));
        assert_eq!(m.gossipable(), vec![a("cand:2")]);
        assert!(!m.gossipable().contains(&a("seed:1")), "a seed we never reached is not dialable");

        m.on_dial_success("seed:1", PeerId(8));
        let g = m.gossipable();
        assert!(g.contains(&a("seed:1")) && g.contains(&a("cand:2")));
    }

    #[test]
    fn self_is_gossiped_only_when_declared_reachable() {
        let mut m = AddrManager::new();
        assert!(m.gossipable().is_empty(), "outbound-only node advertises nothing");
        m.set_self_advertise(Some(a("me:9333")));
        assert_eq!(m.gossipable(), vec![a("me:9333")]);
        // A malformed declaration is refused rather than gossiped.
        let mut m2 = AddrManager::new();
        m2.set_self_advertise(Some(a("not-an-addr")));
        assert!(m2.self_advertise().is_none());
    }

    #[test]
    fn never_learns_itself() {
        let mut m = AddrManager::new();
        m.set_self_advertise(Some(a("me:1")));
        assert_eq!(m.learn(vec![a("me:1"), a("other:2")]), 1);
        assert!(!m.known().contains(&a("me:1")));
    }

    #[test]
    fn dial_budget_respects_the_outbound_cap() {
        let mut m = AddrManager::new();
        m.set_max_outbound(2);
        m.learn((0..10).map(|i| format!("h{i}:1")).collect::<Vec<_>>());
        let first = m.next_dials(0);
        assert_eq!(first.len(), 2, "cap bounds a single pass");
        m.on_dial_success(&first[0], PeerId(1));
        m.on_dial_success(&first[1], PeerId(2));
        assert!(m.next_dials(0).is_empty(), "at cap ⇒ no further dials");
        m.on_disconnect(PeerId(1));
        assert_eq!(m.next_dials(0).len(), 1, "a freed slot is refilled");
    }

    #[test]
    fn seeds_are_tried_first_and_never_evicted() {
        let mut m = AddrManager::with_seeds(vec![a("seed:1")]);
        m.set_max_book(3);
        m.learn(vec![a("l1:1"), a("l2:2"), a("l3:3"), a("l4:4")]);
        assert_eq!(m.known_count(), 3);
        assert!(m.known().contains(&a("seed:1")), "S4: the seed survives eviction pressure");
        assert_eq!(m.next_dials(0)[0], a("seed:1"), "seeds are dialed first");
    }

    #[test]
    fn a_full_book_of_dialable_entries_refuses_new_candidates() {
        let mut m = AddrManager::new();
        m.set_max_book(2);
        m.learn(vec![a("d1:1"), a("d2:2")]);
        m.on_dial_success("d1:1", PeerId(1));
        m.on_dial_success("d2:2", PeerId(2));
        assert_eq!(m.learn(vec![a("new:3")]), 0, "dialable entries are never evicted");
        assert_eq!(m.known_count(), 2);
    }

    #[test]
    fn failed_dials_back_off_and_recover() {
        let mut m = AddrManager::with_seeds(vec![a("seed:1")]);
        assert_eq!(m.next_dials(0), vec![a("seed:1")]);
        m.on_dial_failure("seed:1", 0);
        assert!(m.next_dials(0).is_empty(), "inside backoff");
        assert_eq!(m.next_dials(DIAL_BACKOFF_START_MS * 2), vec![a("seed:1")]);
        // Backoff doubles but is capped.
        for i in 0..20 {
            m.on_dial_failure("seed:1", i * 1000);
        }
        let e = m.entry("seed:1").unwrap();
        assert_eq!(e.backoff_ms, DIAL_BACKOFF_MAX_MS);
        assert!(e.failures >= 20);
        // A success clears the ladder.
        m.on_dial_success("seed:1", PeerId(3));
        let e = m.entry("seed:1").unwrap();
        assert_eq!(e.failures, 0);
        assert_eq!(e.backoff_ms, DIAL_BACKOFF_START_MS);
    }

    #[test]
    fn dialable_is_sticky_across_a_drop() {
        let mut m = AddrManager::with_seeds(vec![a("seed:1")]);
        m.on_dial_success("seed:1", PeerId(1));
        m.on_disconnect(PeerId(1));
        assert!(m.entry("seed:1").unwrap().dialable, "it was reachable; a partition is not proof it is not");
        assert_eq!(m.gossipable(), vec![a("seed:1")]);
    }

    #[test]
    fn getaddr_is_rate_limited_per_peer() {
        let mut m = AddrManager::new();
        assert!(m.may_ask(PeerId(1), 0));
        m.mark_asked(PeerId(1), 0);
        assert!(!m.may_ask(PeerId(1), GETADDR_INTERVAL_MS - 1));
        assert!(m.may_ask(PeerId(2), 0), "the limit is per peer");
        assert!(m.may_ask(PeerId(1), GETADDR_INTERVAL_MS));
    }

    #[test]
    fn one_addr_message_cannot_flood_the_book() {
        let mut m = AddrManager::new();
        let many: Vec<String> = (0..MAX_ADDRS_PER_MSG * 3).map(|i| format!("h{i}:1")).collect();
        assert_eq!(m.learn(many), MAX_ADDRS_PER_MSG);
    }

    #[test]
    fn gossip_is_bounded_per_message() {
        let mut m = AddrManager::new();
        m.set_max_book(MAX_ADDRS_PER_MSG * 2);
        for i in 0..MAX_ADDRS_PER_MSG * 2 {
            let addr = format!("h{i}:1");
            m.learn(vec![addr.clone()]);
            m.on_dial_success(&addr, PeerId(i as u64));
        }
        assert_eq!(m.gossipable().len(), MAX_ADDRS_PER_MSG);
    }

    #[test]
    fn persistence_round_trips_dialable_entries_only() {
        let mut m = AddrManager::with_seeds(vec![a("seed:1")]);
        m.learn(vec![a("good:2"), a("never:3")]);
        m.on_dial_success("seed:1", PeerId(1));
        m.on_dial_success("good:2", PeerId(2));

        let back = AddrManager::from_bytes(&m.to_bytes()).unwrap();
        assert_eq!(back.known(), vec![a("good:2"), a("seed:1")]);
        assert_eq!(back.dialable_count(), 2);
        assert!(!back.known().contains(&a("never:3")), "unreached candidates are not worth persisting");
    }

    #[test]
    fn persistence_rejects_unknown_version_and_trailing() {
        let m = AddrManager::with_seeds(vec![a("seed:1")]);
        let bytes = m.to_bytes();
        let mut bad = bytes.clone();
        bad[0] = 0x02;
        assert_eq!(
            AddrManager::from_bytes(&bad).unwrap_err(),
            AddrBookError::UnknownVersion(0x02)
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(AddrManager::from_bytes(&trailing).unwrap_err(), AddrBookError::Trailing(1));
        assert_eq!(AddrManager::from_bytes(&[]).unwrap_err(), AddrBookError::Truncated);
    }

    #[test]
    fn sync_live_drops_vanished_handles() {
        let mut m = AddrManager::with_seeds(vec![a("s1:1"), a("s2:2")]);
        m.on_dial_success("s1:1", PeerId(1));
        m.on_dial_success("s2:2", PeerId(2));
        let live: HashSet<PeerId> = [PeerId(1)].into_iter().collect();
        m.sync_live(&live);
        assert!(m.entry("s1:1").unwrap().connected.is_some());
        assert!(m.entry("s2:2").unwrap().connected.is_none());
        assert_eq!(m.outbound_live(), 1);
    }
}
