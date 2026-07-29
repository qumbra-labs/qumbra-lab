# i91 — M11 peer hardening: build note

Per-baton working note (not paired — `CLAUDE.md` working conventions: build notes
are written by a session for a session). The numbers here are reproducible from
the tests named beside them; nothing in this file is a source of truth that the
code does not also carry.

Branch `claude/i91-peer-hardening`, base `248aa78`.

## 0. The "already exists" table, re-verified on `main`

All 11 rows in issue #91 are real. Two drifted:

| row | issue says | actual |
|---|---|---|
| scoring + ban | `peer.rs:26` | threshold `−100` at `peer.rs:26`; the three penalty **values** are at `gossip.rs:16/18/20` |
| our-side `GetAddr` interval | `addrman.rs:54` / `:309` | `addrman.rs:55` / `:310` (each +1) |

Nothing on that list was rebuilt.

## 1. What was actually missing

The issue names three. Verifying the table surfaced a fourth thing sitting on the
same code path, which belongs to gap 2 rather than being a new item:

- **`transport.rs` `TcpShared.inbox` was an unbounded `Vec`.** `MAX_PAYLOAD`
  bounds one frame; nothing bounded the pile. Reader threads push per frame while
  `poll` drains only on the node's tick, so a peer sending faster than we process
  grew it without limit. This *is* gap 2's "no accounting for concurrent or
  cumulative use", in its most literal form.
- **The accept path discarded the peer address** (`Ok((stream, _peer_addr))`), so
  an inbound peer had no identity outliving its socket. That is what decides trap
  1 below, so it had to be fixed first.

## 2. Inbound `GetAddr` amplification — measured

Test: `crates/qlab-p2p/tests/getaddr_amplification.rs`
(`cargo test -p qlab-p2p --test getaddr_amplification -- --nocapture`).

**Caliper.** One in-process victim, one attacker peer, one `tick` per request.
Request = empty `GetAddr` = **12 B framed, 0 B payload**. Response bytes = every
byte the victim put on the wire in reply. BEFORE and AFTER come from the **same
build**, differing only in `RateLimits` — `RateLimits::unlimited()` reproduces the
pre-fix `node.rs:324` path — so this compares one implementation with itself, not
two builds. Book states are as labelled; `gossipable()` size is the only thing
that moves the per-request number.

**Per-request caliper** (1 request; unchanged by the fix, and meant to be — an
honest asker still gets an honest answer):

| book state | in | out | ratio |
|---|---|---|---|
| T0 4-node net (3 dialable) | 12 B | 61 B | **5.1×** |
| book full, WAN-shape addrs (100 × ~18 B) | 12 B | 1,703 B | **141.9×** |
| book full, 128 B addrs (the cap × cap bound) | 12 B | 13,013 B | **1084.4×** |

So the issue's "≈1000×" is right *as an upper bound* and is ~200× above what the
net we actually run would emit today (5.1×). The bound is reached only by a node
whose book holds 100 dialable maximum-length addresses.

**Sustained caliper** — R requests inside one 30 s serve window, worst-case book.
This is the number that says whether the node is a usable *reflector*:

| requests in window | BEFORE | AFTER |
|---|---|---|
| 1 | 1084.4× | 1084.4× |
| 10 | 1084.4× | 108.4× |
| 100 | 1084.4× | 10.8× |
| 1,000 | 1084.4× | **1.084×** |

**The defect was the flatness, not the height.** Pre-fix the ratio does not decay
with the request rate at all, so the reflector is as good at 1,000 req/s as at 1.
Post-fix it decays as 1/R and the node stops being worth pointing at anything.

Honest-asker control, asserted in the same test: at the network's own ask cadence
(`GETADDR_INTERVAL_MS` = 60 s, deliberately twice the serve interval) all 10 of 10
requests are answered.

## 3. The two traps

**Trap 1 — where the rate-limit state lives.** Keyed on `RateKey::Host` (the
remote address with the port stripped), never on the connection. An attacker's
ephemeral port and local `PeerId` both change across a reconnect; their host does
not, so a redial lands back on the same spent bucket. Proven over real sockets:
`getaddr_throttling_survives_a_reconnect` (`tests/tcp_integration.rs`).

Deliberate costs, recorded rather than discovered later:

- several connections from one host share one budget — that is the point, else 32
  inbound sockets buy 32× the budget; the price is that distinct nodes behind one
  NAT, or several on one loopback host, also share;
- when a transport reports no address the key falls back to the handle. The only
  such transport is `InProcTransport`, whose `PeerId` **is** the node identity and
  is stable across relink, so the fallback is the same key by another name;
- state is per-process, not persisted. A restart clears it; an attacker cannot
  cheaply cause our restart.

**Trap 2 — the "clumsy ≠ hostile" line.** Rate limiting **never scores and never
bans**. The line is drawn at *is the message wrong* vs *is it too fast*:
`PeerTable::penalize` answers the first (malformed frame, invalid object — content,
unambiguous; the 100/20/5 penalties are untouched), the limiter answers the second
and its entire response is to drop. Dropping already caps our cost, so a ban
protects nothing further, while an honest peer with a clumsy implementation will
trip a rate limit forever and banning it deletes a useful peer from a small network
to punish a bug. Slot exhaustion — the gap "never disconnect" might leave — is
already covered by the inbound connection cap enforced at accept (`MAX_INBOUND`).
Throttling is counted and exported (`qumbra_throttled_frames_total`,
`qumbra_throttled_getaddr_total`) so an operator can see it and decide.

## 4. Constants introduced, and which ones will move

All `[devnet-placeholder]`, **testnet-tunable, NOT frozen**, annotated in place.
Tuning is programmatic (`RateLimits`), deliberately **not** a `qumbra-node` TOML
key: a knob nobody has traffic data to set is a footgun.

| constant | value | basis |
|---|---|---|
| `MSG_BURST` | 256 frames | a `GetData` answer storm, one frame per object |
| `MSG_REFILL_PER_SEC` | 64 /s | ~6× protocol-spec §7's 10 TPS *network-wide*, from a single peer |
| `BYTE_BURST` | 16 MiB | exactly 2 × `MAX_PAYLOAD`, so one legal max-size frame can never exhaust it alone |
| `BYTE_REFILL_PER_SEC` | 8 MiB/s | §7 budgets ≈90–115 MB/block at 10 TPS ⇒ ≈1.2–1.5 MB/s at the frozen 75 s; 5–7× that per peer |
| `GETADDR_SERVE_INTERVAL_MS` | 30,000 | **half** `GETADDR_INTERVAL_MS`, so honest peers do not starve each other |
| `MAX_RATE_KEYS` | 4,096 | ≈400 KB; the limiter must not become the exhaustion it prevents |
| `MAX_INBOX_BYTES` | 64 MiB | 8 max-size frames, against measured ~262 MiB/node RSS on the 2 GB T0 hosts |
| `MAX_INBOX_BYTES_PER_PEER` | 16 MiB | fairness; one sender must not fill the global budget |
| `MAX_OUTBOUND_PER_GROUP` | 2 | forces ≥4 distinct netgroups to fill `MAX_OUTBOUND` = 8 |
| `MAX_ADDRS_PER_GROUP` | 128 | `MAX_ADDR_BOOK` / 8 |

**Expected to move first: `BYTE_REFILL_PER_SEC`.** It is simultaneously the
anti-flood bound and the initial-block-download ceiling, and only one of those two
roles has been measured. Re-tune it against measured IBD throughput, not against
flood tests. Second: `MSG_REFILL_PER_SEC`, if real IBD turns out to be frame-rate
rather than byte-rate bound.

## 5. Diversity granularity

IPv4 `/16`, IPv6 `/32`, DNS name → whole lowercased host string.

- `/24` **rejected**: one rented `/16`, or a single contiguous cloud allocation,
  spans 256 of them, so the rule would cost an attacker nothing.
- ASN **rejected**: the right unit, the wrong trade at T1 — an external
  GeoIP-class dataset is a new dependency carrying a standing freshness obligation,
  and it is wrong the moment it is not refreshed.
- `/16` is the coarsest unit that still makes buying diversity cost real address
  space; it is also Bitcoin's netgroup choice.

Enforced in **both** places the issue names: address-book admission and outbound
selection. Capping the book alone is not enough — one network could still own
every outbound slot as long as its addresses sorted first.

**Caps apply to `Learned` entries only; seeds are exempt.** A configured seed is
the operator's own choice, not a stranger's gossip. Without the exemption the four
T0 nodes on one docker bridge network (one `/16`) would throttle themselves with a
rule aimed at attackers.

**Honest remainder:** DNS names can be minted in bulk, so a name-only attacker is
not bounded by this rule. Two things blunt it today — an address must have been
*successfully dialed by us* before it is gossiped onward (#86 S2), and the T0 seed
set is all literal IPs — but it is real, and it is recorded rather than papered
over.

## 6. Clock

`P2pNode::tick` now takes the caller's monotonic clock in ms. It is a parameter
and not a wall-clock read inside because the in-process sims must stay
byte-identically reproducible (the M9-N7 property): `qumbra-node` passes a real
monotonic clock, `n7soak` passes a per-node deterministic counter
(`SIM_TICK_MS = 10`), and the p2p unit tests pass an explicit sim clock. A frozen
clock would leave the buckets unable to refill, which models nothing; a wall clock
in the sims would make reproducibility depend on machine speed.
