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

/// Maximum **outbound connections** this node will hold to any one netgroup
/// (issue #91, gap 3). `[devnet-placeholder]` testnet-tunable, NOT frozen.
///
/// With [`MAX_OUTBOUND`] = 8 this forces at least **4 distinct netgroups** to fill
/// the outbound budget, so an attacker who floods the book with addresses out of
/// one network cannot own every slot — which is the whole eclipse move.
pub const MAX_OUTBOUND_PER_GROUP: usize = 2;

/// Maximum **address-book entries** admitted from any one netgroup (issue #91,
/// gap 3). `[devnet-placeholder]` testnet-tunable, NOT frozen. One eighth of
/// [`MAX_ADDR_BOOK`]: without it a single network can occupy the book and, through
/// ordinary eviction, push out every candidate that came from anywhere else.
pub const MAX_ADDRS_PER_GROUP: usize = MAX_ADDR_BOOK / 8;

/// The diversity bucket an address falls in — the unit an attacker must *buy more
/// of* to widen their footprint (issue #91, decision 3).
///
/// - **IPv4 → `/16`.** `/24` is too fine: a single rented `/16`, or one contiguous
///   cloud allocation, spans 256 of them, so a `/24` rule costs an attacker
///   nothing. `/16` is the coarsest unit that still makes buying diversity cost
///   real address space, and it is the same choice Bitcoin's netgroup makes.
/// - **IPv6 → `/32`**, the routable-allocation analogue. Grouping IPv6 any finer
///   is meaningless when a single end site is routinely handed a `/48` or `/56`.
/// - **ASN — deliberately NOT used.** It is the *right* unit and the wrong trade:
///   it needs an external GeoIP-class dataset, which is a new dependency, needs
///   periodic refreshing, and is stale the moment it is not. At T1 the security it
///   buys over `/16` does not pay for a data-freshness obligation.
/// - **Anything else (a DNS name) → the whole host string.** Honest residual: names
///   can be minted in bulk, so a name-only attacker is not bounded by this rule.
///   Two things blunt it today — an address must have been *successfully dialed by
///   us* before it can be gossiped onward (#86 S2), and the T0 seed set is all
///   literal IPs — but it is a real remainder, recorded rather than papered over.
///
/// Both caps apply to [`AddrSource::Learned`] entries **only**. A configured seed
/// is the operator's own choice, not an attacker's gossip, and exempting seeds is
/// what keeps a same-subnet deployment (the four docker nodes on one bridge
/// network) from throttling itself with an anti-eclipse rule aimed at strangers.
pub fn netgroup(addr: &str) -> String {
    let host = match addr.rsplit_once(':') {
        Some((h, _)) if !h.is_empty() => h,
        _ => addr,
    };
    let unbracketed = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    if let Ok(v4) = unbracketed.parse::<std::net::Ipv4Addr>() {
        let o = v4.octets();
        return format!("v4:{}.{}", o[0], o[1]);
    }
    if let Ok(v6) = unbracketed.parse::<std::net::Ipv6Addr>() {
        let o = v6.octets();
        return format!("v6:{:02x}{:02x}:{:02x}{:02x}", o[0], o[1], o[2], o[3]);
    }
    format!("dns:{}", host.to_ascii_lowercase())
}

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
    /// Anti-eclipse: outbound slots any one netgroup may hold (issue #91).
    max_outbound_per_group: usize,
    /// Anti-eclipse: book entries any one netgroup may occupy (issue #91).
    max_addrs_per_group: usize,
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
            max_outbound_per_group: MAX_OUTBOUND_PER_GROUP,
            max_addrs_per_group: MAX_ADDRS_PER_GROUP,
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

    /// Override the per-netgroup outbound cap (tests / testnet tuning).
    pub fn set_max_outbound_per_group(&mut self, n: usize) {
        self.max_outbound_per_group = n;
    }

    /// Override the per-netgroup book cap (tests / testnet tuning).
    pub fn set_max_addrs_per_group(&mut self, n: usize) {
        self.max_addrs_per_group = n;
    }

    /// How many **learned** entries the book holds in `group`. Seeds are excluded:
    /// the diversity caps constrain what strangers can push into the book, not what
    /// the operator configured.
    pub fn learned_in_group(&self, group: &str) -> usize {
        self.entries
            .values()
            .filter(|e| e.source == AddrSource::Learned && netgroup(&e.addr) == group)
            .count()
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
        // Netgroup occupancy is computed once and updated as we go: recounting per
        // address would make one Addr message O(entries x addresses).
        let mut per_group: BTreeMap<String, usize> = BTreeMap::new();
        for e in self.entries.values() {
            if e.source == AddrSource::Learned {
                *per_group.entry(netgroup(&e.addr)).or_insert(0) += 1;
            }
        }
        let mut admitted = 0;
        for a in addrs.into_iter().take(MAX_ADDRS_PER_MSG) {
            if !valid_addr(&a) || self.entries.contains_key(&a) {
                continue;
            }
            if self.self_advertise.as_deref() == Some(a.as_str()) {
                continue; // never dial ourselves
            }
            // Anti-eclipse (issue #91): one netgroup may not occupy the book. Like
            // an unusable address, an over-quota one is silently dropped and is NOT
            // a scoring event — a peer's claim about a third party never is (S6).
            let group = netgroup(&a);
            if per_group.get(&group).copied().unwrap_or(0) >= self.max_addrs_per_group {
                continue;
            }
            if self.entries.len() >= self.max_book {
                match self.evict_one() {
                    // Keep the running tally honest: the victim vacated its group.
                    Some(gone) => {
                        if let Some(n) = per_group.get_mut(&netgroup(&gone)) {
                            *n = n.saturating_sub(1);
                        }
                    }
                    // Book full of seeds/dialable entries — refuse, never evict those.
                    None => break,
                }
            }
            *per_group.entry(group).or_insert(0) += 1;
            let seq = self.next_seq();
            self.entries.insert(a.clone(), AddrEntry::new(a, AddrSource::Learned, seq));
            admitted += 1;
        }
        admitted
    }

    /// Evict the oldest **learned, not-dialable, not-connected** entry. Seeds (S4)
    /// and demonstrably dialable addresses are never evicted — they are the only
    /// things of value in the book. Returns the evicted address, if any.
    fn evict_one(&mut self) -> Option<String> {
        let victim = self
            .entries
            .values()
            .filter(|e| {
                e.source == AddrSource::Learned && !e.dialable && e.connected.is_none()
            })
            .min_by_key(|e| e.seq)
            .map(|e| e.addr.clone());
        if let Some(a) = &victim {
            self.entries.remove(a);
        }
        victim
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
    ///
    /// **Anti-eclipse (issue #91):** among learned candidates no netgroup may take
    /// more than [`MAX_OUTBOUND_PER_GROUP`] of the budget, counting connections
    /// already held. This is the half that actually stops an eclipse: capping the
    /// *book* alone would still let one network own every outbound slot as long as
    /// its addresses were the ones tried first.
    pub fn next_dials(&self, now_ms: u64) -> Vec<String> {
        let live = self.outbound_live();
        if live >= self.max_outbound {
            return Vec::new();
        }
        let budget = self.max_outbound - live;

        // Netgroups already occupied by live learned connections. Seeds do not
        // count and are not capped — see [`netgroup`] for why.
        let mut per_group: BTreeMap<String, usize> = BTreeMap::new();
        for e in self.entries.values() {
            if e.connected.is_some() && e.source == AddrSource::Learned {
                *per_group.entry(netgroup(&e.addr)).or_insert(0) += 1;
            }
        }

        let mut cands: Vec<&AddrEntry> = self
            .entries
            .values()
            .filter(|e| e.connected.is_none() && now_ms >= e.next_retry_ms)
            .collect();
        cands.sort_by_key(|e| {
            let seed_rank = if e.source == AddrSource::Seed { 0 } else { 1 };
            (seed_rank, e.failures, e.seq)
        });

        let mut out = Vec::new();
        for e in cands {
            if out.len() >= budget {
                break;
            }
            if e.source == AddrSource::Learned {
                let g = netgroup(&e.addr);
                let n = per_group.entry(g).or_insert(0);
                if *n >= self.max_outbound_per_group {
                    continue; // this network already has its share
                }
                *n += 1;
            }
            out.push(e.addr.clone());
        }
        out
    }

    /// Netgroups this node currently holds outbound connections to (ops / tests) —
    /// the measurable form of "am I eclipsed?". A node whose outbound set collapses
    /// to one group is one network's prisoner regardless of how many peers it has.
    pub fn outbound_groups(&self) -> BTreeMap<String, usize> {
        let mut g = BTreeMap::new();
        for e in self.entries.values() {
            if e.connected.is_some() {
                *g.entry(netgroup(&e.addr)).or_insert(0) += 1;
            }
        }
        g
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

    // --- anti-eclipse diversity (issue #91, gap 3) ---

    #[test]
    fn netgroup_buckets_ipv4_by_16_ipv6_by_32_and_names_whole() {
        assert_eq!(netgroup("10.7.0.1:9333"), "v4:10.7");
        assert_eq!(netgroup("10.7.255.254:1"), "v4:10.7", "a whole /16 is one group");
        assert_ne!(netgroup("10.7.0.1:9333"), netgroup("10.8.0.1:9333"));
        // A /24 rule would call these four different networks; a /16 rule does not,
        // which is the point — 256 /24s is one cheap purchase.
        let g: std::collections::BTreeSet<String> =
            (0..4).map(|i| netgroup(&format!("10.7.{i}.1:9333"))).collect();
        assert_eq!(g.len(), 1);

        assert_eq!(netgroup("[2001:db8::1]:9333"), "v6:2001:0db8");
        assert_eq!(netgroup("[2001:db8:ffff::9]:9333"), "v6:2001:0db8", "grouped at /32");
        assert_ne!(netgroup("[2001:db8::1]:9333"), netgroup("[2001:db9::1]:9333"));

        assert_eq!(netgroup("Seed.Example.ORG:9333"), "dns:seed.example.org", "case-folded");
        assert_ne!(netgroup("a.example:1"), netgroup("b.example:1"));
    }

    #[test]
    fn one_netgroup_cannot_fill_the_outbound_budget() {
        // The acceptance item: a large number of addresses from one network must
        // not be able to own the outbound set. 200 addresses, all in 10.7.0.0/16.
        let mut m = AddrManager::new();
        m.set_max_addrs_per_group(1024); // the BOOK cap is not what is under test here
        for chunk in 0..4u8 {
            m.learn((0..50).map(|i| format!("10.7.{chunk}.{i}:9333")).collect::<Vec<_>>());
        }
        assert_eq!(m.known_count(), 200, "all 200 are known…");

        // …and exactly MAX_OUTBOUND_PER_GROUP of them may be dialed.
        let dials = m.next_dials(0);
        assert_eq!(
            dials.len(),
            MAX_OUTBOUND_PER_GROUP,
            "200 addresses in one /16 win {MAX_OUTBOUND_PER_GROUP} of {MAX_OUTBOUND} slots"
        );
        for (i, d) in dials.iter().enumerate() {
            m.on_dial_success(d, PeerId(i as u64 + 1));
        }
        assert!(m.next_dials(0).is_empty(), "the group's share is spent; no third slot");
        assert_eq!(m.outbound_live(), 2, "and 6 of the 8 slots stay free for other networks");

        // A different network is still welcome — this is a diversity rule, not a
        // connection cap wearing a disguise.
        m.learn(vec![a("203.0.113.9:9333")]);
        assert_eq!(m.next_dials(0), vec![a("203.0.113.9:9333")]);
    }

    #[test]
    fn the_outbound_budget_fills_completely_from_distinct_netgroups() {
        // The in-limit half: diversity must not cost liveness. Four networks, plenty
        // of addresses each ⇒ the budget fills, 2 per network.
        let mut m = AddrManager::new();
        m.set_max_addrs_per_group(1024);
        for g in 0..4u8 {
            m.learn((0..10).map(|i| format!("10.{g}.0.{i}:9333")).collect::<Vec<_>>());
        }
        let dials = m.next_dials(0);
        assert_eq!(dials.len(), MAX_OUTBOUND, "every outbound slot is used");
        let mut per: BTreeMap<String, usize> = BTreeMap::new();
        for d in &dials {
            *per.entry(netgroup(d)).or_insert(0) += 1;
        }
        assert_eq!(per.len(), 4, "spread across all four networks");
        assert!(per.values().all(|&n| n == MAX_OUTBOUND_PER_GROUP), "{per:?}");
    }

    #[test]
    fn a_single_netgroup_cannot_occupy_the_address_book() {
        let mut m = AddrManager::new();
        m.set_max_addrs_per_group(5);
        assert_eq!(
            m.learn((0..5).map(|i| format!("198.18.0.{i}:9333")).collect::<Vec<_>>()),
            5,
            "exactly at the per-group cap: all admitted"
        );
        assert_eq!(
            m.learn((5..20).map(|i| format!("198.18.0.{i}:9333")).collect::<Vec<_>>()),
            0,
            "past it: refused, and silently — a third-party address is never a scoring event"
        );
        assert_eq!(m.learned_in_group("v4:198.18"), 5);
        // Refusing one network does not refuse the next.
        assert_eq!(m.learn((0..5).map(|i| format!("198.19.0.{i}:9333")).collect::<Vec<_>>()), 5);
        assert_eq!(m.known_count(), 10);
    }

    #[test]
    fn seeds_are_exempt_from_the_diversity_caps() {
        // The four T0 nodes share a docker bridge network, i.e. one /16. An
        // anti-eclipse rule aimed at what strangers gossip at us must not make an
        // operator's own deployment throttle itself.
        let mut m = AddrManager::new();
        m.set_max_addrs_per_group(1);
        for i in 1..=8u8 {
            m.add_seed(format!("172.20.0.{i}:9333"));
        }
        assert_eq!(m.next_dials(0).len(), MAX_OUTBOUND, "configured seeds fill the budget");
        assert_eq!(m.known_count(), 8, "and none was refused admission to the book");
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
