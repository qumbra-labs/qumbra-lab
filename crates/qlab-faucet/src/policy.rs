//! Off-chain anti-abuse — **the most important decision in this crate**, and the
//! one a naive implementation gets silently wrong.
//!
//! ## Why the standard control is unavailable
//!
//! Every ordinary faucet's core control is "this address already claimed". Issue
//! #32 made diversified addresses genuinely unlinkable — `rkm = H(nk ‖ D_R ‖ d)`,
//! proved end-to-end — so **one person can mint unlimited mutually-unlinkable
//! addresses and nothing on-chain can join them**. That is the design working as
//! specified, so the control must be off-chain, and it must not reach for an
//! on-chain identity: doing so would collide with the core decision in
//! `transaction-model-and-anonymity-set`.
//!
//! ## The threat model is queue occupancy, not depletion
//!
//! This is where the naive design fails. Sizing the control against "how much can
//! an attacker drain" gets the wrong answer, because the faucet's service ceiling
//! is **~1 grant per 75 s block** — the note-inflow law in [`crate::inventory`].
//! An attacker does not need to drain anything; they need only hold that 0.8/min,
//! and then honest users are served at zero. So the question the control has to
//! answer is *"what does it cost to occupy the service?"*, and the answer must be
//! in attacker cost, not in mechanism names:
//!
//! | control | cost to occupy ~0.8 grants/min indefinitely |
//! |---|---|
//! | IP address, keyed on the exact address | **≈ 0** against IPv6 — one /64 is 2⁶⁴ keys |
//! | IP, keyed on a /24 | ~100 distinct /24s. A rented /16 contains **256** of them, i.e. 256× the budget |
//! | IP, keyed on the /16 | 1× per rented /16, but every honest user behind that /16 is collateral |
//! | client PoW puzzle | linear in the attacker's cores; to make occupancy cost one core continuously the puzzle must cost ≈75 core-seconds, i.e. the honest user waits a **whole block interval** — and 100 cores still buys 100× |
//! | operator-issued single-use ticket | the operator's signature. **Not rentable at any price**, because the scarce resource is not a resource |
//!
//! ### The decision
//!
//! [`Ticket`] is the **load-bearing** control; the token buckets are a labelled
//! *anti-accident* pre-filter — they stop a retry loop and a single wedged client,
//! and they are honestly documented as stopping nothing that is trying. This is a
//! deliberate refusal to ship a control that looks like rate limiting and is not:
//! the failure mode the task-book warns about is a faucet that "appears to be
//! limiting while anyone can walk around it".
//!
//! Because a fully-open T1 remains Larry's call (`testnet-plan.md` §6's [manual]
//! item — "an open invitation, or a named-participant list first"), tickets are a
//! **toggle** ([`TicketPolicy`]), not a hard-wire. Turning them off is one config
//! field, and the honest consequence — the faucet becomes saturable by ~100
//! addresses — is documented on [`TicketPolicy::Disabled`] rather than discovered.
//!
//! ## Check order is a security property
//!
//! Ticket validity is checked **before** any budget is spent, and the ticket is
//! marked spent only after every other check has passed. Both directions matter:
//!
//! - Spending a global token before validating the ticket would let a ticketless
//!   attacker **burn the service budget for free** — the exact failure the buckets
//!   were supposed to prevent.
//! - Marking the ticket spent before the buckets pass would let an unlucky honest
//!   user lose their one ticket to a throttle.
//!
//! Ticket verification is a single Keccak over public bytes, so putting it first
//! costs one permutation per request — a cheaper floor than any state lookup.
//!
//! ## Every constant here is `[devnet-placeholder]`
//!
//! Testnet-tunable, NOT frozen. The one that is *derived* rather than guessed is
//! [`FaucetLimits::global_refill_window_ms`]: it is the block interval, because the
//! note-inflow law says the sustainable grant rate **is** one per block.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use qlab_devnet::params_devnet::POW_TARGET_BLOCK_TIME_SECS;
use qlab_note::hash::keccak256;
use qlab_p2p::ratelimit::{host_of, TokenBucket};

// --------------------------------------------------------------------------
// Constants
// --------------------------------------------------------------------------

/// Domain separation for the ticket MAC. Versioned so a future scheme cannot be
/// confused with this one.
pub const DS_TICKET: &[u8] = b"qumbra:faucet:ticket:v1";

/// Ticket MAC length in bytes. 16 bytes = 128-bit forgery resistance against an
/// online attacker who gets one guess per request; the faucet is rate-limited
/// below any brute-force rate that could matter.
pub const TICKET_TAG_LEN: usize = 16;

/// Human-facing ticket prefix, so a pasted string is recognisable and a wrong
/// paste fails fast rather than as a MAC mismatch.
pub const TICKET_PREFIX: &str = "qft1";

/// IPv4 prefix length the subnet pre-filter keys on. `[devnet-placeholder]`
/// testnet-tunable, NOT frozen.
///
/// /24 is the compromise the table in the module docs prices: a rented /16 buys
/// 256× the budget, and keying on the /16 instead would make every honest user
/// behind one ISP block share a budget. Neither is a *defence*; see the module
/// docs — this number chooses which accident it prevents, not which attack.
pub const DEFAULT_SUBNET_V4_BITS: u8 = 24;

/// IPv6 prefix length the subnet pre-filter keys on. `[devnet-placeholder]`
/// testnet-tunable, NOT frozen.
///
/// **/64 is a floor, not a preference.** A single host is routinely allocated a
/// whole /64, so keying on the full 128-bit address makes the limit worth exactly
/// nothing (2⁶⁴ free keys). /48 would be stricter still; /64 is the smallest
/// prefix that is not self-defeating.
pub const DEFAULT_SUBNET_V6_BITS: u8 = 64;

/// Requests one subnet may spend at once. `[devnet-placeholder]`.
pub const DEFAULT_SUBNET_BURST: u64 = 2;

/// Refill window for one subnet request: 24 h. `[devnet-placeholder]`. Chosen to
/// match the conventional faucet cadence ("a grant a day"), not derived.
pub const DEFAULT_SUBNET_REFILL_WINDOW_MS: u64 = 24 * 3_600 * 1_000;

/// Requests the service as a whole may spend at once. `[devnet-placeholder]`.
/// Sized to one checkpoint cadence's worth of blocks so a burst of arrivals after
/// a quiet period is served promptly instead of being spread artificially.
pub const DEFAULT_GLOBAL_BURST: u64 = 8;

/// Maximum subnet keys tracked. `[devnet-placeholder]`. The limiter must not become
/// the exhaustion it prevents: an attacker cycling source addresses would otherwise
/// grow this map without bound. Mirrors `qlab_p2p::ratelimit::MAX_RATE_KEYS`'s
/// reasoning, including the batch eviction — evicting one key at a time makes every
/// packet of an address-cycling flood pay a full-map scan, which is the same
/// denial-of-service by another route.
pub const MAX_SUBNET_KEYS: usize = 4096;

/// Fraction of the subnet map dropped (oldest-first) when it is full: `1/N`.
pub const SUBNET_EVICT_FRACTION: usize = 4;

// --------------------------------------------------------------------------
// Tickets
// --------------------------------------------------------------------------

/// The faucet's ticket-issuing secret.
///
/// **Never logged and never rendered.** `Debug` is hand-written to redact, because
/// the single most likely way a secret escapes a Rust service is a struct printed
/// wholesale into a log line by a `#[derive(Debug)]` three layers up.
#[derive(Clone, PartialEq, Eq)]
pub struct TicketSecret([u8; 32]);

impl TicketSecret {
    /// Adopt a 32-byte secret. The caller is responsible for where it came from;
    /// this crate never generates, stores, or prints one.
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }
}

impl std::fmt::Debug for TicketSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TicketSecret(<redacted>)")
    }
}

/// A single-use grant ticket: a serial number and its MAC.
///
/// The MAC is a **Keccak prefix-MAC**, `Keccak256(DS ‖ secret ‖ id)`, truncated to
/// [`TICKET_TAG_LEN`]. Prefix-MAC construction is sound over a sponge — Keccak is
/// not length-extendable, which is the whole reason KMAC can be built this way and
/// the reason the same construction over SHA-256 would be a bug. Reusing
/// `qlab_note::hash::keccak256` also keeps one Keccak in the tree rather than two.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ticket {
    /// Operator-chosen serial. Not secret — the MAC is what authenticates.
    pub id: u64,
    /// Truncated MAC over `id`.
    pub tag: [u8; TICKET_TAG_LEN],
}

impl Ticket {
    /// Issue the ticket for serial `id` (operator-side).
    pub fn issue(secret: &TicketSecret, id: u64) -> Ticket {
        let mut buf = Vec::with_capacity(DS_TICKET.len() + 32 + 8);
        buf.extend_from_slice(DS_TICKET);
        buf.extend_from_slice(&secret.0);
        buf.extend_from_slice(&id.to_le_bytes());
        let mac = keccak256(&buf);
        let mut tag = [0u8; TICKET_TAG_LEN];
        tag.copy_from_slice(&mac[..TICKET_TAG_LEN]);
        Ticket { id, tag }
    }

    /// Whether this ticket's MAC is the one `secret` would issue for its `id`.
    ///
    /// The comparison folds every byte before branching, so it does not leak how
    /// many leading bytes of a forgery were right.
    pub fn verify(&self, secret: &TicketSecret) -> bool {
        let expect = Ticket::issue(secret, self.id);
        let mut diff = 0u8;
        for (a, b) in self.tag.iter().zip(expect.tag.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }

    /// `qft1` + hex(id, 8 B LE) + hex(tag) — the string an operator hands out.
    pub fn encode(&self) -> String {
        let mut s = String::from(TICKET_PREFIX);
        for b in self.id.to_le_bytes() {
            s.push_str(&format!("{b:02x}"));
        }
        for b in self.tag {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// Parse [`Self::encode`]'s form. `None` on a wrong prefix, wrong length, or a
    /// non-hex body — all before any secret is touched, so a malformed paste costs
    /// nothing and reveals nothing.
    pub fn decode(s: &str) -> Option<Ticket> {
        let body = s.strip_prefix(TICKET_PREFIX)?;
        if body.len() != 2 * (8 + TICKET_TAG_LEN) {
            return None;
        }
        let bytes: Option<Vec<u8>> = (0..body.len() / 2)
            .map(|i| u8::from_str_radix(body.get(2 * i..2 * i + 2)?, 16).ok())
            .collect();
        let bytes = bytes?;
        let id = u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes"));
        let mut tag = [0u8; TICKET_TAG_LEN];
        tag.copy_from_slice(&bytes[8..]);
        Some(Ticket { id, tag })
    }
}

/// Whether a ticket is required.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TicketPolicy {
    /// Tickets required — the recommended T1 posture while "how public is public"
    /// is undecided (`testnet-plan.md` §6 [manual]).
    Required,
    /// **Open faucet: no ticket.** The honest consequence, stated so it is not
    /// discovered: with tickets off the only controls left are the token buckets,
    /// which are an anti-accident filter, so the faucet is saturable by roughly a
    /// hundred distinct subnets and the queue becomes first-come-first-served among
    /// whoever can afford the most addresses. Choose this only with a waiting list
    /// or an accepted service-denial risk.
    Disabled,
}

// --------------------------------------------------------------------------
// Subnet keys
// --------------------------------------------------------------------------

/// What a request budget is charged against.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SubnetKey {
    /// An IPv4 prefix, masked to [`FaucetLimits::subnet_v4_bits`].
    V4([u8; 4], u8),
    /// An IPv6 prefix, masked to [`FaucetLimits::subnet_v6_bits`].
    V6([u8; 16], u8),
    /// A client the faucet could not parse as an IP (a hostname, or a test
    /// harness's label). Keyed whole and lower-cased. Deliberately **not** merged
    /// with the IP cases: a reverse-proxy deployment that forwards names instead of
    /// addresses would otherwise silently collapse every client onto one key.
    Opaque(String),
}

/// Derive the subnet key for a client address (`host` or `host:port`).
///
/// **The port is stripped second, not first.** `qlab_p2p::ratelimit::host_of`
/// splits at the last colon, which is correct for a peer address but would eat the
/// final group of a *bracketless* IPv6 literal (`2001:db8::1:2` → `2001:db8::1`) —
/// silently keying two different /64s together. So the whole string is tried as an
/// address first, and only if that fails is a trailing `:port` real. The reuse is
/// still worth having; the trap is worth naming.
pub fn subnet_key(client: &str, v4_bits: u8, v6_bits: u8) -> SubnetKey {
    let raw = client.trim();
    if let Some(k) = parse_ip(raw, v4_bits, v6_bits) {
        return k;
    }
    let host = host_of(raw).unwrap_or(raw);
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    parse_ip(bare, v4_bits, v6_bits)
        .unwrap_or_else(|| SubnetKey::Opaque(bare.to_ascii_lowercase()))
}

/// `s` as a masked IP prefix key, or `None` if it is not an IP literal.
fn parse_ip(s: &str, v4_bits: u8, v6_bits: u8) -> Option<SubnetKey> {
    match s.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => Some(SubnetKey::V4(mask(&a.octets(), v4_bits), v4_bits)),
        Ok(IpAddr::V6(a)) => Some(SubnetKey::V6(mask(&a.octets(), v6_bits), v6_bits)),
        Err(_) => None,
    }
}

/// Zero every bit below `bits` of a big-endian address.
fn mask<const N: usize>(octets: &[u8; N], bits: u8) -> [u8; N] {
    let mut out = *octets;
    let bits = (bits as usize).min(8 * N);
    for (i, byte) in out.iter_mut().enumerate() {
        let keep = bits.saturating_sub(8 * i).min(8);
        *byte &= match keep {
            0 => 0x00,
            8 => 0xFF,
            k => !0u8 << (8 - k),
        };
    }
    out
}

// --------------------------------------------------------------------------
// Limits, refusals, the gate
// --------------------------------------------------------------------------

/// The tunable set. Every field is `[devnet-placeholder]`; see the constants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaucetLimits {
    pub ticket_policy: TicketPolicy,
    pub subnet_v4_bits: u8,
    pub subnet_v6_bits: u8,
    pub subnet_burst: u64,
    pub subnet_refill_window_ms: u64,
    pub global_burst: u64,
    /// Milliseconds per one global request token.
    ///
    /// **Derived, not guessed**: the sustainable grant rate is bounded by coinbase
    /// inflow, one note per won block ([`crate::inventory`]), so this is the frozen
    /// 75 s block interval. A faster refill would advertise a rate the funding
    /// cannot honour, which is how a faucet ends up with a queue that only grows.
    ///
    /// Since issue #292 this is **conservative rather than exact**: the fallback
    /// makes a grant note-count-neutral, so one won note is worth as many grants as
    /// its value covers (≈5 at `coinbase(0)` and a 10 QMB grant) rather than
    /// exactly one. The window was not widened with the fallback — that is a
    /// separate rate decision with its own abuse-control side, and this comment
    /// exists so the next reader knows the headroom is real and unclaimed.
    pub global_refill_window_ms: u64,
    pub max_subnet_keys: usize,
}

impl Default for FaucetLimits {
    fn default() -> Self {
        FaucetLimits {
            ticket_policy: TicketPolicy::Required,
            subnet_v4_bits: DEFAULT_SUBNET_V4_BITS,
            subnet_v6_bits: DEFAULT_SUBNET_V6_BITS,
            subnet_burst: DEFAULT_SUBNET_BURST,
            subnet_refill_window_ms: DEFAULT_SUBNET_REFILL_WINDOW_MS,
            global_burst: DEFAULT_GLOBAL_BURST,
            global_refill_window_ms: POW_TARGET_BLOCK_TIME_SECS * 1_000,
            max_subnet_keys: MAX_SUBNET_KEYS,
        }
    }
}

impl FaucetLimits {
    /// Limits wide enough that nothing trips — used to exercise the *same* code
    /// path with the controls effectively off, so a with/without comparison
    /// measures one implementation rather than two.
    pub fn unlimited() -> FaucetLimits {
        FaucetLimits {
            ticket_policy: TicketPolicy::Disabled,
            subnet_burst: u64::MAX / 1_000,
            subnet_refill_window_ms: 1,
            global_burst: u64::MAX / 1_000,
            global_refill_window_ms: 1,
            ..FaucetLimits::default()
        }
    }
}

/// Why a request was refused. Every variant is a distinct operator/UX action, and
/// none of them says more about the secret than the requester already knew.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// No ticket presented while [`TicketPolicy::Required`].
    TicketMissing,
    /// The ticket's MAC is not one this faucet issued (forged, or from another
    /// faucet). Reported identically to a typo — there is nothing to gain from
    /// distinguishing them.
    TicketInvalid,
    /// A valid ticket that has already been used.
    TicketSpent,
    /// The client's subnet is over its budget.
    SubnetThrottled,
    /// The service as a whole is over its budget — i.e. requests are arriving
    /// faster than the note-inflow law can serve them.
    GlobalThrottled,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Refusal::TicketMissing => "a grant ticket is required",
            Refusal::TicketInvalid => "grant ticket not recognised",
            Refusal::TicketSpent => "grant ticket already used",
            Refusal::SubnetThrottled => "too many requests from your network; try later",
            Refusal::GlobalThrottled => "the faucet is at capacity; try later",
        };
        f.write_str(s)
    }
}

impl std::error::Error for Refusal {}

/// Counters an operator can read. Process-lifetime totals.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GateStats {
    pub admitted: u64,
    pub ticket_missing: u64,
    pub ticket_invalid: u64,
    pub ticket_spent: u64,
    pub subnet_throttled: u64,
    pub global_throttled: u64,
    pub evicted_subnets: u64,
    pub live_subnets: usize,
    pub tickets_spent: usize,
}

#[derive(Clone, Debug)]
struct SubnetEntry {
    bucket: TokenBucket,
    last_seen_ms: u64,
}

/// The off-chain request gate: tickets (load-bearing) over subnet and global token
/// buckets (anti-accident). Holds no chain state and does no I/O, so it is fully
/// deterministic in `now_ms` and testable without a clock.
#[derive(Debug)]
pub struct AbuseGate {
    secret: TicketSecret,
    limits: FaucetLimits,
    spent: HashSet<u64>,
    subnets: HashMap<SubnetKey, SubnetEntry>,
    global: TokenBucket,
    stats: GateStats,
}

impl AbuseGate {
    /// A gate over `secret` with `limits`.
    pub fn new(secret: TicketSecret, limits: FaucetLimits) -> AbuseGate {
        AbuseGate {
            secret,
            limits,
            spent: HashSet::new(),
            subnets: HashMap::new(),
            global: TokenBucket::new(limits.global_burst, 1, limits.global_refill_window_ms),
            stats: GateStats::default(),
        }
    }

    /// The active limits.
    pub fn limits(&self) -> &FaucetLimits {
        &self.limits
    }

    /// Counters. `live_subnets`/`tickets_spent` are filled in here rather than
    /// tracked incrementally.
    pub fn stats(&self) -> GateStats {
        GateStats {
            live_subnets: self.subnets.len(),
            tickets_spent: self.spent.len(),
            ..self.stats
        }
    }

    /// Issue a ticket (operator-side convenience; the same function the CLI would
    /// call). Issuing does **not** register anything — a ticket is a bearer MAC,
    /// and the faucet learns of it when it is presented.
    pub fn issue(&self, id: u64) -> Ticket {
        Ticket::issue(&self.secret, id)
    }

    /// Decide on a request. See the module docs for why the order is
    /// **ticket validity → subnet → global → commit**.
    ///
    /// `client` is the requester's address as the transport saw it (`host` or
    /// `host:port`); `ticket` is the presented ticket, if any.
    pub fn admit(
        &mut self,
        client: &str,
        ticket: Option<Ticket>,
        now_ms: u64,
    ) -> Result<Option<u64>, Refusal> {
        // 1. Ticket validity — stateless, one Keccak, and it must precede every
        //    budget so a ticketless attacker cannot burn the service budget.
        let ticket_id = match (self.limits.ticket_policy, ticket) {
            (TicketPolicy::Required, None) => {
                self.stats.ticket_missing += 1;
                return Err(Refusal::TicketMissing);
            }
            (TicketPolicy::Required, Some(t)) => {
                if !t.verify(&self.secret) {
                    self.stats.ticket_invalid += 1;
                    return Err(Refusal::TicketInvalid);
                }
                if self.spent.contains(&t.id) {
                    self.stats.ticket_spent += 1;
                    return Err(Refusal::TicketSpent);
                }
                Some(t.id)
            }
            // Open mode ignores a presented ticket entirely rather than
            // half-validating it — a control that is off must be off.
            (TicketPolicy::Disabled, _) => None,
        };

        // 2. Subnet budget (anti-accident).
        let key = subnet_key(client, self.limits.subnet_v4_bits, self.limits.subnet_v6_bits);
        if !self.subnet_entry(key, now_ms).bucket.try_take(1, now_ms) {
            self.stats.subnet_throttled += 1;
            return Err(Refusal::SubnetThrottled);
        }

        // 3. Global budget — the note-inflow ceiling, expressed as a rate.
        if !self.global.try_take(1, now_ms) {
            self.stats.global_throttled += 1;
            return Err(Refusal::GlobalThrottled);
        }

        // 4. Commit: burn the ticket only now that nothing else can refuse.
        if let Some(id) = ticket_id {
            self.spent.insert(id);
        }
        self.stats.admitted += 1;
        Ok(ticket_id)
    }

    /// The spent-ticket set is bounded by the number of tickets the **operator**
    /// issued, not by request volume — a forged or unknown id never enters it — so
    /// it needs no eviction and cannot be grown by an attacker.
    pub fn spent_tickets(&self) -> usize {
        self.spent.len()
    }

    fn subnet_entry(&mut self, key: SubnetKey, now_ms: u64) -> &mut SubnetEntry {
        if !self.subnets.contains_key(&key) && self.subnets.len() >= self.limits.max_subnet_keys {
            self.evict_oldest();
        }
        let (burst, window) = (self.limits.subnet_burst, self.limits.subnet_refill_window_ms);
        let e = self.subnets.entry(key).or_insert_with(|| SubnetEntry {
            bucket: TokenBucket::new(burst, 1, window),
            last_seen_ms: now_ms,
        });
        e.last_seen_ms = now_ms;
        e
    }

    /// Drop the oldest `1/SUBNET_EVICT_FRACTION` in one pass — see
    /// [`MAX_SUBNET_KEYS`] for why this is a batch.
    fn evict_oldest(&mut self) {
        let drop_n = (self.subnets.len() / SUBNET_EVICT_FRACTION).max(1);
        let mut ages: Vec<(u64, SubnetKey)> =
            self.subnets.iter().map(|(k, e)| (e.last_seen_ms, k.clone())).collect();
        ages.sort();
        for (_, k) in ages.into_iter().take(drop_n) {
            self.subnets.remove(&k);
            self.stats.evicted_subnets += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 32] = [0x5A; 32];
    const OTHER: [u8; 32] = [0xA5; 32];

    fn gate(limits: FaucetLimits) -> AbuseGate {
        AbuseGate::new(TicketSecret::from_bytes(SECRET), limits)
    }

    // ── the ticket itself ────────────────────────────────────────────────────

    #[test]
    fn a_ticket_verifies_only_under_its_own_secret() {
        let s = TicketSecret::from_bytes(SECRET);
        let other = TicketSecret::from_bytes(OTHER);
        let t = Ticket::issue(&s, 42);
        assert!(t.verify(&s));
        assert!(!t.verify(&other), "another faucet's secret must not validate it");
        // A different serial gets a different tag (the MAC binds the id).
        assert_ne!(Ticket::issue(&s, 42).tag, Ticket::issue(&s, 43).tag);
    }

    #[test]
    fn a_forged_tag_is_rejected_and_encoding_round_trips() {
        let s = TicketSecret::from_bytes(SECRET);
        let t = Ticket::issue(&s, 7);
        let text = t.encode();
        assert!(text.starts_with(TICKET_PREFIX));
        assert_eq!(Ticket::decode(&text), Some(t));

        // Every single-bit tag forgery fails.
        for byte in 0..TICKET_TAG_LEN {
            for bit in 0..8 {
                let mut f = t;
                f.tag[byte] ^= 1 << bit;
                assert!(!f.verify(&s), "forgery at byte {byte} bit {bit} must fail");
            }
        }
        // And so does claiming someone else's serial with this tag.
        let mut swapped = t;
        swapped.id = 8;
        assert!(!swapped.verify(&s));
    }

    #[test]
    fn malformed_ticket_strings_are_rejected_before_any_secret_is_touched() {
        assert_eq!(Ticket::decode(""), None);
        assert_eq!(Ticket::decode("qft2000000"), None, "wrong prefix");
        assert_eq!(Ticket::decode("qft1abcd"), None, "too short");
        let s = TicketSecret::from_bytes(SECRET);
        let good = Ticket::issue(&s, 1).encode();
        assert_eq!(Ticket::decode(&format!("{good}00")), None, "too long");
        let mut nonhex: String = good.clone();
        nonhex.replace_range(6..7, "z");
        assert_eq!(Ticket::decode(&nonhex), None, "non-hex body");
    }

    // ── subnet keying ────────────────────────────────────────────────────────

    #[test]
    fn v4_keys_collapse_to_the_configured_prefix() {
        let k = |s: &str| subnet_key(s, 24, 64);
        assert_eq!(k("203.0.113.7:5000"), k("203.0.113.200"), "same /24, one key");
        assert_ne!(k("203.0.113.7"), k("203.0.114.7"), "different /24, different key");
        // A /16 contains 256 distinct /24 keys — the number the module docs price.
        let distinct: std::collections::HashSet<SubnetKey> =
            (0..256).map(|c| subnet_key(&format!("198.51.{c}.1"), 24, 64)).collect();
        assert_eq!(distinct.len(), 256);
        // Keyed on the /16 instead, that whole range is one key.
        let one: std::collections::HashSet<SubnetKey> =
            (0..256).map(|c| subnet_key(&format!("198.51.{c}.1"), 16, 64)).collect();
        assert_eq!(one.len(), 1);
    }

    #[test]
    fn v6_keys_on_the_prefix_not_the_address() {
        // The trap: a single host owns a whole /64, so keying on 128 bits gives an
        // attacker 2⁶⁴ free budgets. Keyed on /64 the whole allocation is one key.
        let a = subnet_key("[2001:db8:abcd:1234::1]:9333", 24, 64);
        let b = subnet_key("2001:db8:abcd:1234:ffff:ffff:ffff:ffff", 24, 64);
        assert_eq!(a, b, "one /64 is one key");
        let c = subnet_key("2001:db8:abcd:1235::1", 24, 64);
        assert_ne!(a, c, "a different /64 is a different key");
        // Keyed on the full address, the same host would get two budgets.
        assert_ne!(subnet_key("2001:db8::1", 24, 128), subnet_key("2001:db8::2", 24, 128));
    }

    #[test]
    fn a_bracketless_v6_literal_keeps_its_last_group() {
        // The trap named in `subnet_key`'s docs: naive last-colon port stripping
        // would turn `2001:db8:0:1:a:b:c:d` into `…:c` and key two /64s as one.
        let a = subnet_key("2001:db8:0:1:aaaa:bbbb:cccc:dddd", 24, 64);
        let b = subnet_key("2001:db8:0:2:aaaa:bbbb:cccc:dddd", 24, 64);
        assert_ne!(a, b, "two different /64s must not collapse to one key");
        // …and the port is still stripped when there really is one.
        assert_eq!(subnet_key("[2001:db8:0:1::9]:9333", 24, 64), a);
    }

    #[test]
    fn an_unparseable_client_gets_its_own_key_not_a_shared_one() {
        let a = subnet_key("client-a.example:80", 24, 64);
        let b = subnet_key("CLIENT-B.example", 24, 64);
        assert_ne!(a, b);
        assert_eq!(b, subnet_key("client-b.example", 24, 64), "case-insensitive");
    }

    // ── the gate: it blocks what it claims to block ──────────────────────────

    #[test]
    fn the_gate_blocks_what_it_claims_to_block() {
        let mut g = gate(FaucetLimits::default());
        let good = g.issue(1);

        // (a) no ticket
        assert_eq!(g.admit("203.0.113.1", None, 0), Err(Refusal::TicketMissing));
        // (b) forged ticket
        let mut forged = good;
        forged.tag[0] ^= 0x80;
        assert_eq!(g.admit("203.0.113.1", Some(forged), 0), Err(Refusal::TicketInvalid));
        // (c) a ticket from another faucet
        let foreign = Ticket::issue(&TicketSecret::from_bytes(OTHER), 1);
        assert_eq!(g.admit("203.0.113.1", Some(foreign), 0), Err(Refusal::TicketInvalid));
        // (d) replay of a spent ticket
        assert_eq!(g.admit("203.0.113.1", Some(good), 0), Ok(Some(1)));
        assert_eq!(g.admit("203.0.113.9", Some(good), 0), Err(Refusal::TicketSpent));

        // None of the refused requests spent a budget: the ticket check runs first,
        // so a ticketless flood cannot burn the service budget.
        let s = g.stats();
        assert_eq!(s.admitted, 1);
        assert_eq!((s.ticket_missing, s.ticket_invalid, s.ticket_spent), (1, 2, 1));
        assert_eq!((s.subnet_throttled, s.global_throttled), (0, 0));
    }

    #[test]
    fn a_ticketless_flood_cannot_burn_the_global_budget() {
        // The check-order property, stated as an attack: 10,000 ticketless requests
        // must leave the global budget untouched, so a valid ticket still works.
        let mut g = gate(FaucetLimits::default());
        for i in 0..10_000u64 {
            assert!(g.admit(&format!("198.51.100.{}", i % 256), None, i).is_err());
        }
        let t = g.issue(99);
        assert_eq!(g.admit("203.0.113.5", Some(t), 10_000), Ok(Some(99)));
    }

    #[test]
    fn a_throttle_does_not_consume_the_ticket() {
        // An honest user unlucky enough to hit a throttle must not lose their one
        // ticket: the ticket is burned only after every other check passes.
        let limits = FaucetLimits { subnet_burst: 1, ..FaucetLimits::default() };
        let mut g = gate(limits);
        let t1 = g.issue(1);
        let t2 = g.issue(2);
        assert_eq!(g.admit("203.0.113.1", Some(t1), 0), Ok(Some(1)));
        // Second request from the same /24 is throttled — and t2 survives it.
        assert_eq!(g.admit("203.0.113.2", Some(t2), 0), Err(Refusal::SubnetThrottled));
        assert_eq!(g.spent_tickets(), 1, "only the admitted ticket was burned");
        // Same ticket, a different subnet: still valid.
        assert_eq!(g.admit("198.51.100.1", Some(t2), 0), Ok(Some(2)));
    }

    #[test]
    fn the_global_budget_is_the_block_interval() {
        // The derived constant, exercised: after the burst is spent, one further
        // request becomes available per 75 s block and no faster.
        let limits = FaucetLimits::default();
        let block_ms = limits.global_refill_window_ms;
        assert_eq!(block_ms, POW_TARGET_BLOCK_TIME_SECS * 1_000);
        let mut g = gate(FaucetLimits {
            // A wide subnet budget so this test measures only the global bucket.
            subnet_burst: u64::MAX / 1_000,
            ..limits
        });
        for i in 0..limits.global_burst {
            let t = g.issue(i);
            assert_eq!(g.admit("203.0.113.1", Some(t), 0), Ok(Some(i)), "burst token {i}");
        }
        let over = g.issue(1_000);
        assert_eq!(g.admit("203.0.113.1", Some(over), 0), Err(Refusal::GlobalThrottled));
        assert_eq!(
            g.admit("203.0.113.1", Some(over), block_ms - 1),
            Err(Refusal::GlobalThrottled),
            "just under one block"
        );
        assert_eq!(g.admit("203.0.113.1", Some(over), block_ms), Ok(Some(1_000)));
    }

    // ── the gate: it does NOT block normal requests ──────────────────────────

    #[test]
    fn the_gate_admits_ordinary_traffic() {
        // Testing only the blocking half is testing nothing. Twenty distinct
        // honest users, each with their own ticket, arriving one block apart from
        // twenty different networks: every one is served.
        let mut g = gate(FaucetLimits::default());
        let block_ms = g.limits().global_refill_window_ms;
        for i in 0..20u64 {
            let t = g.issue(i);
            let client = format!("203.0.{i}.42:44000");
            assert_eq!(
                g.admit(&client, Some(t), i * block_ms),
                Ok(Some(i)),
                "honest user {i} must be served"
            );
        }
        let s = g.stats();
        assert_eq!(s.admitted, 20);
        assert_eq!(s.subnet_throttled + s.global_throttled, 0, "no honest user throttled");
        assert_eq!(s.ticket_invalid + s.ticket_missing + s.ticket_spent, 0);
    }

    #[test]
    fn a_returning_user_is_served_again_after_the_window() {
        // The same subnet, a fresh ticket, one day later — the ordinary repeat case.
        let mut g = gate(FaucetLimits { subnet_burst: 1, ..FaucetLimits::default() });
        let day = g.limits().subnet_refill_window_ms;
        let t1 = g.issue(1);
        assert_eq!(g.admit("203.0.113.7", Some(t1), 0), Ok(Some(1)));
        let t2 = g.issue(2);
        assert_eq!(g.admit("203.0.113.7", Some(t2), day - 1), Err(Refusal::SubnetThrottled));
        assert_eq!(g.admit("203.0.113.7", Some(t2), day), Ok(Some(2)));
    }

    #[test]
    fn open_mode_admits_without_a_ticket_and_ignores_one() {
        let mut g = gate(FaucetLimits {
            ticket_policy: TicketPolicy::Disabled,
            ..FaucetLimits::default()
        });
        assert_eq!(g.admit("203.0.113.1", None, 0), Ok(None));
        // A presented ticket is ignored, not half-checked — including a forged one.
        let foreign = Ticket::issue(&TicketSecret::from_bytes(OTHER), 5);
        assert_eq!(g.admit("198.51.100.1", Some(foreign), 0), Ok(None));
        assert_eq!(g.spent_tickets(), 0, "open mode burns no serials");
    }

    #[test]
    fn unlimited_limits_never_trip() {
        let mut g = gate(FaucetLimits::unlimited());
        for i in 0..2_000u64 {
            assert!(g.admit("203.0.113.1", None, 0).is_ok(), "request {i}");
        }
        let s = g.stats();
        assert_eq!(s.admitted, 2_000);
        assert_eq!(s.subnet_throttled + s.global_throttled, 0);
    }

    // ── bounds ───────────────────────────────────────────────────────────────

    #[test]
    fn the_subnet_map_is_bounded_and_evicts_in_batches() {
        // An attacker cycling source addresses must not grow the map without bound.
        let mut g = gate(FaucetLimits {
            ticket_policy: TicketPolicy::Disabled,
            max_subnet_keys: 8,
            subnet_burst: u64::MAX / 1_000,
            global_burst: u64::MAX / 1_000,
            ..FaucetLimits::default()
        });
        for i in 0..8u64 {
            g.admit(&format!("10.0.{i}.1"), None, i).unwrap();
        }
        assert_eq!(g.stats().live_subnets, 8);
        assert_eq!(g.stats().evicted_subnets, 0, "at the cap, nothing is dropped");
        g.admit("10.9.9.1", None, 100).unwrap();
        assert_eq!(g.stats().evicted_subnets, 2, "8/4 = 2 dropped in one pass");
        assert_eq!(g.stats().live_subnets, 7);
    }

    #[test]
    fn the_secret_is_never_rendered() {
        // The most likely way a secret escapes is a derived Debug three layers up.
        let s = TicketSecret::from_bytes(SECRET);
        let shown = format!("{s:?}");
        assert_eq!(shown, "TicketSecret(<redacted>)");
        assert!(!shown.contains("5a") && !shown.contains("90"));
        // And through the gate, which owns one.
        let g = gate(FaucetLimits::default());
        let shown = format!("{g:?}");
        assert!(shown.contains("<redacted>"), "gate Debug must not leak the secret");
        assert!(!shown.contains("5a, 5a"));
    }
}
