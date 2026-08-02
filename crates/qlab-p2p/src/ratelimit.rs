//! Per-peer inbound rate limiting — the **throttle**, deliberately not a verdict.
//!
//! Issue #91 gap 1: outside the "how often may *we* ask a peer for addresses"
//! limit ([`crate::addrman::GETADDR_INTERVAL_MS`]), nothing in this crate bounded
//! the rate at which a peer may push work at us. This module is that bound.
//!
//! ## Where the state lives, and why a reconnect does not reset it
//!
//! The obvious place to hang a token bucket is the connection — and it is the
//! wrong one: an attacker drops the socket, redials, and gets a fresh budget, so
//! the limit costs them one TCP handshake per refill. The state here is therefore
//! keyed on [`RateKey`], which is the **remote host with the port stripped**
//! whenever the transport can tell us one. An attacker's ephemeral port and local
//! [`PeerId`] both change across a reconnect; their address does not, so they land
//! back on the same, still-empty bucket.
//!
//! Two consequences are deliberate:
//!
//! - **Several connections from one host share one budget.** That is the point:
//!   otherwise opening the 32 permitted inbound sockets would buy 32× the budget.
//!   The cost is that genuinely distinct nodes behind one NAT, or several nodes on
//!   one loopback host, share a budget too. At T1 scale that is the right trade;
//!   it is called out here so nobody rediscovers it as a bug.
//! - **When the transport has no address, the key falls back to the handle.** The
//!   only such transport is [`crate::transport::InProcTransport`], whose `PeerId`
//!   *is* the node identity and is stable across relink — so the fallback is not a
//!   weaker key in that setting, it is the same key by another name.
//!
//! State is per-process and is not persisted: a restart clears it, which is
//! acceptable because an attacker cannot cheaply cause our restart.
//!
//! ## Tripping the limit is not misbehaviour
//!
//! Nothing in this module scores or bans. That boundary is decision 2 of the
//! issue, and it is drawn at **"is this message wrong?" vs "is it too fast?"**:
//!
//! - [`crate::peer::PeerTable::penalize`] answers the first — a malformed frame or
//!   an object that fails validation is unambiguously the sender's fault, and the
//!   existing 100/20/5 penalties stay exactly as they were.
//! - This module answers the second, and its whole response is **to drop the
//!   frame**. Dropping already caps our cost; there is nothing left for a ban to
//!   protect. Meanwhile an honest peer with a clumsy implementation will trip a
//!   rate limit forever, and banning it would delete a useful peer from a small
//!   network in order to punish a bug.
//!
//! Slot exhaustion — the thing "never disconnect" might otherwise leave open — is
//! already covered by the inbound connection cap enforced at accept
//! ([`crate::addrman::MAX_INBOUND`]). Throttling is counted and readable
//! ([`RateLimiter::stats`]) so an operator can *see* a peer misbehaving, but the
//! decision to act on that stays with the operator.
//!
//! ## Caps
//!
//! Every constant here is `[devnet-placeholder]` **devnet-grade, testnet-tunable,
//! NOT frozen**. See each constant for which real-traffic signal should re-tune it.

use std::collections::HashMap;

use crate::peer::PeerId;

// --------------------------------------------------------------------------
// Constants
// --------------------------------------------------------------------------

/// Burst of inbound **frames** one rate key may spend at once.
///
/// `[devnet-placeholder]` testnet-tunable, NOT frozen. Sized off the burstiest
/// honest inbound stream in this stack: a `GetData` answer storm, where each
/// wanted object comes back as its own frame.
pub const MSG_BURST: u64 = 256;

/// Sustained inbound **frame** rate per rate key.
///
/// `[devnet-placeholder]` testnet-tunable, NOT frozen. protocol-spec §7's design
/// point is 10 TPS network-wide, i.e. ~10 `Tx` frames/s arriving from *all* peers
/// together; 64/s from a single peer is ~6× that. Header-first sync moves 2,000
/// headers per frame and compact relay bundles a block's txs into one `BlockTxn`,
/// so neither is frame-rate bound. Re-tune if real traffic shows honest peers
/// throttled during initial block download.
pub const MSG_REFILL_PER_SEC: u64 = 64;

/// Burst of inbound **bytes** one rate key may spend at once.
///
/// `[devnet-placeholder]` testnet-tunable, NOT frozen. Fixed at exactly
/// 2 × [`crate::wire::MAX_PAYLOAD`] so that a single legal maximum-size frame can
/// never on its own exhaust the budget — a limit that a well-formed message trips
/// by existing would be a liveness bug wearing a security hat.
pub const BYTE_BURST: u64 = 16 * 1024 * 1024;

/// Sustained inbound **byte** rate per rate key.
///
/// `[devnet-placeholder]` testnet-tunable, NOT frozen. **This is the constant most
/// likely to need re-tuning first**, because it is simultaneously the anti-flood
/// bound and the initial-block-download ceiling. Derivation: protocol-spec §7
/// budgets ≈90–115 MB per block at 10 TPS, i.e. ≈1.2–1.5 MB/s steady-state at the
/// frozen 75 s block time; 8 MiB/s is 5–7× that from one peer, and with
/// [`crate::addrman::MAX_OUTBOUND`] = 8 the aggregate ceiling is 64 MiB/s. Re-tune
/// against measured IBD throughput, not against flood tests.
pub const BYTE_REFILL_PER_SEC: u64 = 8 * 1024 * 1024;

/// Minimum gap between two `Addr` responses **we serve** to one rate key.
///
/// `[devnet-placeholder]` testnet-tunable, NOT frozen. Deliberately **half** of
/// [`crate::addrman::GETADDR_INTERVAL_MS`] (the rate at which we ask): a serve
/// limit tighter than the ask limit would have honest peers starving each other,
/// and the 2× headroom absorbs clock skew and scheduling jitter without ever
/// letting the amplifier run free.
pub const GETADDR_SERVE_INTERVAL_MS: u64 = 30_000;

/// Maximum rate keys tracked at once.
///
/// `[devnet-placeholder]` testnet-tunable, NOT frozen. The limiter must not itself
/// become the exhaustion it prevents: without this bound an attacker cycling
/// source addresses grows the map without limit. 4,096 keys ≈ 400 KB. When full,
/// the oldest quarter is dropped in one pass ([`EVICT_FRACTION`]) so the scan
/// amortises to O(1) per admitted key — evicting one-at-a-time would make every
/// packet of an address-cycling flood pay a full-map scan, which is the same DoS
/// by another route.
pub const MAX_RATE_KEYS: usize = 4096;

/// Minimum gap between two finalized-checkpoint **query answers we serve** to one
/// rate key (issue #204).
///
/// The #204 query is a 45 B `GetData` whose answer is a whole finalized checkpoint
/// plus its quorum vote set — at the T0 committee size that is 21 ML-DSA-65
/// signatures, ~3,309 B each, so ~70 KB off one small request. That is #91's
/// amplifier shape exactly (measured 1084x for `GetAddr`), and the query path is
/// the first one that can be driven **without an inv first**, so it needs its own
/// serve budget rather than inheriting the inv path's implicit one.
///
/// 5 s caps the sustained answer rate at ~14 KB/s per key — 0.17 % of the 8 MiB/s
/// the inbound byte budget already permits per key, and still fast enough that a
/// node walking its finalized head up a long catch-up is not the bottleneck (one
/// answer per 5 s against a 75 s block target). Matched to
/// [`crate::node::CHECKPOINT_QUERY_INTERVAL_MS`], the rate at which we ask, so an
/// honest requester is never throttled by an honest server.
///
/// `[devnet-placeholder]` testnet-tunable, NOT frozen.
pub const CHECKPOINT_QUERY_SERVE_INTERVAL_MS: u64 = 5_000;

/// Fraction of the key map dropped when it is full (oldest-first): `1/N`.
pub const EVICT_FRACTION: usize = 4;

// --------------------------------------------------------------------------
// Rate key
// --------------------------------------------------------------------------

/// What a budget is charged against. See the module docs: this is a **host**, not
/// a connection, precisely so that dropping and redialling does not reset it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RateKey {
    /// The remote host, port stripped (`"1.2.3.4"`, `"[::1]"`, `"peer.example"`).
    Host(String),
    /// Fallback for a transport that cannot report an address. The in-process
    /// transport's handle is the node's identity, so this is stable there.
    Handle(PeerId),
}

impl RateKey {
    /// Build the key for a connection: the remote host if the transport knows one,
    /// otherwise the local handle.
    pub fn new(peer_addr: Option<&str>, pid: PeerId) -> RateKey {
        match peer_addr.and_then(host_of) {
            Some(h) => RateKey::Host(h.to_ascii_lowercase()),
            None => RateKey::Handle(pid),
        }
    }
}

/// The host part of a `host:port` string — the port is split at the **last**
/// colon so IPv6 literals (`[::1]:9333`) keep their inner colons. Returns `None`
/// if there is no port to strip, in which case the whole string is already a host.
pub fn host_of(addr: &str) -> Option<&str> {
    match addr.rsplit_once(':') {
        Some((host, _port)) if !host.is_empty() => Some(host),
        Some(_) => None,
        None => Some(addr),
    }
}

// --------------------------------------------------------------------------
// Token bucket
// --------------------------------------------------------------------------

/// A refilling token bucket, integer-exact.
///
/// Tokens are held in **milli-tokens** so that a refill rate slower than one token
/// per millisecond does not round to zero, and `last_ms` advances only by the time
/// actually converted into tokens, so repeated sub-tick polls cannot starve the
/// refill by discarding remainders.
///
/// One primitive, three configurations (see [`RateLimiter`]): a frame budget, a
/// byte budget, and — at `capacity = 1`, `refill = 1 per window` — a minimum
/// serve interval. A second mechanism for the interval case would be a second
/// thing to get wrong.
#[derive(Clone, Debug)]
pub struct TokenBucket {
    capacity_milli: u64,
    /// `refill_tokens` per `refill_window_ms`.
    refill_tokens: u64,
    refill_window_ms: u64,
    tokens_milli: u64,
    last_ms: u64,
}

impl TokenBucket {
    /// A bucket of `capacity` tokens refilling at `refill_tokens per window_ms`,
    /// starting full.
    pub fn new(capacity: u64, refill_tokens: u64, refill_window_ms: u64) -> TokenBucket {
        let capacity_milli = capacity.saturating_mul(1000);
        TokenBucket {
            capacity_milli,
            refill_tokens,
            refill_window_ms: refill_window_ms.max(1),
            tokens_milli: capacity_milli,
            last_ms: 0,
        }
    }

    /// A per-second-refilling bucket (the common case).
    pub fn per_sec(capacity: u64, refill_per_sec: u64) -> TokenBucket {
        TokenBucket::new(capacity, refill_per_sec, 1000)
    }

    /// A bucket holding exactly one token that refills once per `interval_ms` —
    /// i.e. a minimum interval, expressed in the same primitive.
    pub fn every(interval_ms: u64) -> TokenBucket {
        TokenBucket::new(1, 1, interval_ms)
    }

    fn refill(&mut self, now_ms: u64) {
        if self.tokens_milli >= self.capacity_milli {
            self.last_ms = now_ms;
            return;
        }
        let elapsed = now_ms.saturating_sub(self.last_ms);
        if elapsed == 0 || self.refill_tokens == 0 {
            return;
        }
        let added = elapsed
            .saturating_mul(self.refill_tokens)
            .saturating_mul(1000)
            / self.refill_window_ms;
        if added == 0 {
            return; // keep `last_ms` back so the remainder is not discarded
        }
        // Charge back only the time that actually became tokens.
        let used_ms = added.saturating_mul(self.refill_window_ms)
            / self.refill_tokens.saturating_mul(1000).max(1);
        self.last_ms = self.last_ms.saturating_add(used_ms).min(now_ms);
        self.tokens_milli = self.tokens_milli.saturating_add(added).min(self.capacity_milli);
    }

    /// Spend `n` tokens if they are available. Returns whether they were.
    pub fn try_take(&mut self, n: u64, now_ms: u64) -> bool {
        self.refill(now_ms);
        let want = n.saturating_mul(1000);
        if self.tokens_milli >= want {
            self.tokens_milli -= want;
            true
        } else {
            false
        }
    }

    /// Whole tokens currently available (ops / tests).
    pub fn available(&self) -> u64 {
        self.tokens_milli / 1000
    }
}

// --------------------------------------------------------------------------
// Limits + limiter
// --------------------------------------------------------------------------

/// The tunable set. Defaults are the constants above; a testnet operator or a
/// test overrides the struct rather than the constants.
///
/// Deliberately **not** exposed as `qumbra-node` TOML keys: a knob nobody has the
/// traffic data to set is a footgun, and the numbers here should move because a
/// measurement said so, not because an operator guessed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimits {
    pub msg_burst: u64,
    pub msg_refill_per_sec: u64,
    pub byte_burst: u64,
    pub byte_refill_per_sec: u64,
    /// Minimum gap between served `Addr` responses. **`0` disables the serve
    /// limit** — the only supported use is [`RateLimits::unlimited`], which exists
    /// to reproduce pre-fix behaviour through this same code path.
    pub getaddr_serve_interval_ms: u64,
    /// Minimum gap between served finalized-checkpoint query answers (issue #204).
    /// **`0` disables the serve limit**, same contract as
    /// `getaddr_serve_interval_ms`.
    pub cp_query_serve_interval_ms: u64,
    pub max_keys: usize,
}

impl Default for RateLimits {
    fn default() -> Self {
        RateLimits {
            msg_burst: MSG_BURST,
            msg_refill_per_sec: MSG_REFILL_PER_SEC,
            byte_burst: BYTE_BURST,
            byte_refill_per_sec: BYTE_REFILL_PER_SEC,
            getaddr_serve_interval_ms: GETADDR_SERVE_INTERVAL_MS,
            cp_query_serve_interval_ms: CHECKPOINT_QUERY_SERVE_INTERVAL_MS,
            max_keys: MAX_RATE_KEYS,
        }
    }
}

impl RateLimits {
    /// Limits so wide nothing trips them — used to reproduce the **pre-fix**
    /// behaviour through the *same* code path, so a before/after comparison is a
    /// measurement of one implementation rather than of two.
    pub fn unlimited() -> RateLimits {
        RateLimits {
            msg_burst: u64::MAX / 1000,
            msg_refill_per_sec: u64::MAX / 1000,
            byte_burst: u64::MAX / 1000,
            byte_refill_per_sec: u64::MAX / 1000,
            getaddr_serve_interval_ms: 0,
            cp_query_serve_interval_ms: 0,
            max_keys: MAX_RATE_KEYS,
        }
    }
}

/// Why a frame was not processed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Within budget — process it.
    Allow,
    /// Over the frame-rate budget.
    TooManyFrames,
    /// Over the byte-rate budget.
    TooManyBytes,
}

impl Verdict {
    pub fn allowed(self) -> bool {
        self == Verdict::Allow
    }
}

/// Counters an operator can read. Every number is a **process-lifetime total**
/// over frames delivered by the transport to this node.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RateStats {
    /// Frames dropped for exceeding the frame-rate budget.
    pub throttled_frames: u64,
    /// Frames dropped for exceeding the byte-rate budget.
    pub throttled_bytes: u64,
    /// `GetAddr` requests received but not answered (the amplifier, muzzled).
    pub throttled_getaddr: u64,
    /// Finalized-checkpoint queries received but not answered (issue #204).
    pub throttled_cp_query: u64,
    /// Rate keys dropped to keep the map bounded.
    pub evicted_keys: u64,
    /// Rate keys currently tracked.
    pub live_keys: usize,
}

#[derive(Clone, Debug)]
struct Entry {
    msgs: TokenBucket,
    bytes: TokenBucket,
    getaddr: TokenBucket,
    cp_query: TokenBucket,
    last_seen_ms: u64,
}

/// Per-rate-key inbound budgets. Holds no connection state, so it survives the
/// connection it is limiting (which is the whole point).
#[derive(Clone, Debug)]
pub struct RateLimiter {
    limits: RateLimits,
    entries: HashMap<RateKey, Entry>,
    stats: RateStats,
}

impl Default for RateLimiter {
    fn default() -> Self {
        RateLimiter::new(RateLimits::default())
    }
}

impl RateLimiter {
    pub fn new(limits: RateLimits) -> RateLimiter {
        RateLimiter { limits, entries: HashMap::new(), stats: RateStats::default() }
    }

    pub fn limits(&self) -> &RateLimits {
        &self.limits
    }

    /// Replace the limits. Existing buckets are discarded — a re-tune is a policy
    /// change, and carrying stale budgets across it would make the new numbers
    /// mean something other than what they say.
    pub fn set_limits(&mut self, limits: RateLimits) {
        self.limits = limits;
        self.entries.clear();
    }

    /// Counters (ops / tests). `live_keys` is filled in here rather than tracked.
    pub fn stats(&self) -> RateStats {
        RateStats { live_keys: self.entries.len(), ..self.stats }
    }

    fn entry(&mut self, key: RateKey, now_ms: u64) -> &mut Entry {
        if !self.entries.contains_key(&key) && self.entries.len() >= self.limits.max_keys {
            self.evict_oldest();
        }
        let limits = self.limits;
        let e = self.entries.entry(key).or_insert_with(|| Entry {
            msgs: TokenBucket::per_sec(limits.msg_burst, limits.msg_refill_per_sec),
            bytes: TokenBucket::per_sec(limits.byte_burst, limits.byte_refill_per_sec),
            getaddr: match limits.getaddr_serve_interval_ms {
                0 => TokenBucket::per_sec(u64::MAX / 1000, u64::MAX / 1000),
                ms => TokenBucket::every(ms),
            },
            cp_query: match limits.cp_query_serve_interval_ms {
                0 => TokenBucket::per_sec(u64::MAX / 1000, u64::MAX / 1000),
                ms => TokenBucket::every(ms),
            },
            last_seen_ms: now_ms,
        });
        e.last_seen_ms = now_ms;
        e
    }

    /// Drop the oldest `1/EVICT_FRACTION` of the map in one pass — see
    /// [`MAX_RATE_KEYS`] for why this is a batch and not a single eviction.
    fn evict_oldest(&mut self) {
        let drop_n = (self.entries.len() / EVICT_FRACTION).max(1);
        let mut ages: Vec<(u64, RateKey)> =
            self.entries.iter().map(|(k, e)| (e.last_seen_ms, k.clone())).collect();
        ages.sort();
        for (_, k) in ages.into_iter().take(drop_n) {
            self.entries.remove(&k);
            self.stats.evicted_keys += 1;
        }
    }

    /// Charge one inbound frame of `frame_len` bytes against `key`.
    pub fn charge_frame(&mut self, key: RateKey, frame_len: usize, now_ms: u64) -> Verdict {
        let e = self.entry(key, now_ms);
        if !e.msgs.try_take(1, now_ms) {
            self.stats.throttled_frames += 1;
            return Verdict::TooManyFrames;
        }
        if !e.bytes.try_take(frame_len as u64, now_ms) {
            self.stats.throttled_bytes += 1;
            return Verdict::TooManyBytes;
        }
        Verdict::Allow
    }

    /// Whether we may serve an `Addr` response to `key` now. Consumes the
    /// allowance when it returns true.
    pub fn may_serve_getaddr(&mut self, key: RateKey, now_ms: u64) -> bool {
        let e = self.entry(key, now_ms);
        if e.getaddr.try_take(1, now_ms) {
            true
        } else {
            self.stats.throttled_getaddr += 1;
            false
        }
    }

    /// Whether we may answer a finalized-checkpoint query from `key` now (issue
    /// #204). Consumes the allowance when it returns true.
    ///
    /// Over-rate queries are dropped in silence and **not scored**, and — unlike
    /// every other unservable `GetData` item — they are not answered `NotFound`
    /// either: `NotFound` is itself scored by the receiver
    /// ([`crate::gossip::PENALTY_WELSHED_INV`]) on every path that is not its own
    /// outstanding ask, and a throttle is our limit, not the asker's fault. Asking
    /// twice is not misbehaviour (the `GetAddr` rule, unchanged).
    pub fn may_serve_cp_query(&mut self, key: RateKey, now_ms: u64) -> bool {
        let e = self.entry(key, now_ms);
        if e.cp_query.try_take(1, now_ms) {
            true
        } else {
            self.stats.throttled_cp_query += 1;
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_is_split_at_the_last_colon() {
        assert_eq!(host_of("1.2.3.4:9333"), Some("1.2.3.4"));
        assert_eq!(host_of("[::1]:9333"), Some("[::1]"));
        assert_eq!(host_of("peer.example.org:9333"), Some("peer.example.org"));
        assert_eq!(host_of("bare-host"), Some("bare-host"));
        assert_eq!(host_of(":9333"), None, "no host to key on");
    }

    #[test]
    fn the_key_is_the_host_so_a_reconnect_lands_on_the_same_bucket() {
        // The trap this module exists to avoid: a new connection from the same
        // attacker gets a new ephemeral port and a new PeerId, and must NOT get a
        // new budget.
        let first = RateKey::new(Some("203.0.113.7:41022"), PeerId(1));
        let second = RateKey::new(Some("203.0.113.7:58913"), PeerId(99));
        assert_eq!(first, second, "same host, different port and handle → same key");
        assert_ne!(first, RateKey::new(Some("203.0.113.8:41022"), PeerId(1)));
        // Only with no address at all does the handle become the key.
        assert_eq!(RateKey::new(None, PeerId(5)), RateKey::Handle(PeerId(5)));
    }

    #[test]
    fn bucket_spends_its_burst_then_refills_at_the_stated_rate() {
        let mut b = TokenBucket::per_sec(10, 5);
        for i in 0..10 {
            assert!(b.try_take(1, 0), "burst token {i} is available");
        }
        assert!(!b.try_take(1, 0), "burst exhausted");
        // 5/s ⇒ 1 token per 200 ms.
        assert!(!b.try_take(1, 199), "just under one token's worth of time");
        assert!(b.try_take(1, 200), "exactly one token's worth of time");
        assert!(!b.try_take(1, 200), "and only one");
        // Refill is capped at the burst.
        assert!(b.try_take(10, 100_000));
        assert!(!b.try_take(1, 100_000), "never accrues past capacity");
    }

    #[test]
    fn slow_refill_is_not_rounded_away_by_frequent_polls() {
        // 1 token per 30 s polled every millisecond: a naive implementation that
        // advances its clock on every poll would round the refill to zero forever.
        let mut b = TokenBucket::every(30_000);
        assert!(b.try_take(1, 0));
        for t in 1..30_000 {
            assert!(!b.try_take(1, t), "still inside the interval at {t} ms");
        }
        assert!(b.try_take(1, 30_000), "the interval elapsed despite 30k polls");
    }

    #[test]
    fn frames_are_charged_against_both_budgets() {
        let limits = RateLimits { msg_burst: 4, msg_refill_per_sec: 1, ..RateLimits::default() };
        let mut rl = RateLimiter::new(limits);
        let k = RateKey::Handle(PeerId(1));
        for _ in 0..4 {
            assert_eq!(rl.charge_frame(k.clone(), 10, 0), Verdict::Allow);
        }
        assert_eq!(rl.charge_frame(k.clone(), 10, 0), Verdict::TooManyFrames);
        assert_eq!(rl.stats().throttled_frames, 1);

        // A byte-only overrun is reported as such.
        let limits = RateLimits { byte_burst: 100, byte_refill_per_sec: 1, ..RateLimits::default() };
        let mut rl = RateLimiter::new(limits);
        assert_eq!(rl.charge_frame(k.clone(), 100, 0), Verdict::Allow, "exactly at the byte burst");
        assert_eq!(rl.charge_frame(k, 1, 0), Verdict::TooManyBytes);
        assert_eq!(rl.stats().throttled_bytes, 1);
    }

    #[test]
    fn getaddr_allowance_is_one_per_interval_per_key() {
        let mut rl = RateLimiter::default();
        let a = RateKey::Host("1.1.1.1".into());
        let b = RateKey::Host("2.2.2.2".into());
        assert!(rl.may_serve_getaddr(a.clone(), 0));
        assert!(!rl.may_serve_getaddr(a.clone(), GETADDR_SERVE_INTERVAL_MS - 1));
        assert!(rl.may_serve_getaddr(b, 0), "the budget is per key");
        assert!(rl.may_serve_getaddr(a, GETADDR_SERVE_INTERVAL_MS));
        assert_eq!(rl.stats().throttled_getaddr, 1);
    }

    #[test]
    fn the_key_map_is_bounded_and_evicts_the_oldest_in_batches() {
        let limits = RateLimits { max_keys: 8, ..RateLimits::default() };
        let mut rl = RateLimiter::new(limits);
        // Fill exactly to the cap: nothing is evicted at the limit.
        for i in 0..8u64 {
            rl.charge_frame(RateKey::Host(format!("10.0.0.{i}")), 1, i);
        }
        assert_eq!(rl.stats().live_keys, 8, "at the cap, all keys retained");
        assert_eq!(rl.stats().evicted_keys, 0);

        // One more: a batch of the oldest quarter goes.
        rl.charge_frame(RateKey::Host("10.0.0.99".into()), 1, 100);
        assert_eq!(rl.stats().evicted_keys, 2, "8/EVICT_FRACTION = 2 dropped");
        assert_eq!(rl.stats().live_keys, 7);
        // The two oldest (t=0, t=1) are the ones that went.
        let mut rl2 = RateLimiter::new(RateLimits { max_keys: 8, ..RateLimits::default() });
        for i in 0..8u64 {
            rl2.charge_frame(RateKey::Host(format!("10.0.0.{i}")), 1, i);
        }
        rl2.charge_frame(RateKey::Host("10.0.0.99".into()), 1, 100);
        assert!(!rl2.entries.contains_key(&RateKey::Host("10.0.0.0".into())));
        assert!(rl2.entries.contains_key(&RateKey::Host("10.0.0.7".into())));
    }

    #[test]
    fn unlimited_limits_never_trip() {
        let mut rl = RateLimiter::new(RateLimits::unlimited());
        let k = RateKey::Host("1.1.1.1".into());
        for _ in 0..10_000 {
            assert_eq!(rl.charge_frame(k.clone(), 8 * 1024 * 1024, 0), Verdict::Allow);
            assert!(rl.may_serve_getaddr(k.clone(), 0));
        }
        assert_eq!(rl.stats().throttled_frames, 0);
        assert_eq!(rl.stats().throttled_getaddr, 0);
    }
}
