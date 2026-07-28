# M11 — peer discovery (issue #83)

*中文版：[`m11-peer-discovery-zh.md`](m11-peer-discovery-zh.md)。EN is authoritative on technical detail.*

What a node does with `GetAddr`/`Addr`, how it decides who is dialable, and the
connection caps that had to ship in the same PR. Written from the build; the
task-book is the authority on scope.

## The one-line summary

Before this: `dial_peers` was the whole world — the set of reachable peers was
fixed at deploy time and a node could never learn about anyone else. A node
*served* its address book on request and **discarded** every book it was sent
(`node.rs:248`, `MsgType::Addr => { /* prototype: no auto-connect */ }`).

Now: a node learns addresses from peers, decides which of them are genuinely
dialable, connects to them under a cap, gossips only the dialable ones, and
keeps what it learned across a restart.

## Where the halves live, and why one dialer

| piece | crate | why there |
|---|---|---|
| address book, dialable state, backoff, caps, persistence format | `qlab-p2p::addrman` | pure policy — no sockets, so all of it is unit-testable |
| `Transport::dial` | `qlab-p2p::transport` | mechanism; **both** transports implement it, so the discovery loop is the same code in deterministic in-process tests and over real sockets |
| inbound cap | `qlab-p2p::transport` (accept loop) | it must refuse *at accept*; anywhere higher and the connection is already absorbed |
| the maintenance pass (`maintain`) | `qlab-p2p::node` | reconcile → auto-connect → ask |
| the run-loop cadence, config, persistence I/O | `qumbra-node::run` | it owns the data dir, the clock and the process |

**One dialer, deliberately.** `qumbra-node`'s T0-5/S9 re-dial machinery
(`RedialSlot`, `REDIAL_*`, keyed by *configured* address) is gone; its behaviour
moved into `addrman` unchanged — same backoff ladder, same "skip anything whose
handle is still live" rule — and now covers learned addresses too. Two dial
paths with different backoffs and different caps is how a node ends up exceeding
a limit it believes it is enforcing. The S9 acceptance test was converted, not
deleted: `redial_reconnects_a_configured_peer_without_restart` still passes
through the new path.

## Decisions

### 1. Dialable = "we connected to it". Nothing else counts.

A learned address is a **candidate**. It becomes **dialable** only when we have
successfully opened a connection *to* it, and only dialable addresses are ever
gossiped (S2). A peer that is connected to *us* is not evidence of anything: on a
net that accepts outbound-only participants, most of them cannot be dialed back.

`dialable` is **sticky** across a disconnect. A partition is not proof of
unreachability, and if a partition erased the flag the seed set would stop being
gossipable exactly when the net needs it most.

### 2. Own reachability is **explicit configuration**, not inference

New optional config field: `advertise_addr`.

The alternative — infer it from observed inbound connections — cannot actually
work here. A node sees the *peer's* source address, never its own public one; the
only way to learn that is for the peer to tell it, and that is a change to the
`Addr`/`Version` payloads, which is a wire break and a coordinator decision (S1).
So: an operator who knows the node is reachable says so. The four T0 hosts say so
(`deploy/deploy.sh` and the docker `entrypoint.sh` now write the field).

A node with no `advertise_addr` is **never gossiped and never in anyone's book**,
and says so at startup in the operator's own words. That is the expected state for
a home participant, not a degradation.

### 3. Persistence: **yes**, dialable entries only

`data_dir/peers.dat`, versioned `0x01`, reject-unknown / reject-trailing.

Only dialable entries are written. A candidate we never reached is worth nothing
across a restart, and persisting junk is how a book fills with entries nobody can
use. Seeds come back from config regardless, so the file is a cache and never an
authority — an unreadable one is logged and ignored, never fatal.

The reason to persist at all: without it, every restart collapses the node to
"only the seeds are dialable" — which is precisely the state the NAT re-open
trigger below is watching for. Manufacturing that state would make the
measurement lie.

### 4. The NAT re-open trigger is a number in the telemetry line

Condition 3 of the recorded decision asks for a trigger that fires on a
**measurement**, not on someone's memory that the question was deferred. The
stdout `TELEMETRY` line now carries:

    dialable=<dialable>/<known>

If that ratio collapses toward "only the seeds are dialable" over T1, that is the
signal to build NAT traversal. (The `/v1/telemetry` **wire** is deliberately
untouched — adding a field there is a versioned change that this baton had no
reason to make. If ops wants the ratio over RPC rather than out of the logs, that
is a small follow-up, and it should carry the version bump.)

### 5. `PeerTable::addr_book` / `remember_addr` removed

They recorded every peer that completed a handshake — i.e. exactly the
merely-connected set that S2 forbids serving. Left in place they would have been a
second book, and the day something served from it, S2 would be violated silently.

## Caps — all `[devnet-placeholder]`, testnet-tunable, **NOT frozen**

They ship in the same PR as auto-connect (S3): auto-connect without a cap is a
resource-exhaustion bug that the discovery feature itself introduces.

| constant | value | what it bounds |
|---|---|---|
| `MAX_OUTBOUND` | 8 | simultaneous connections we open |
| `MAX_INBOUND` | 32 | simultaneous connections we accept (**enforced at accept**) |
| `MAX_ADDR_BOOK` | 1024 | entries retained |
| `MAX_ADDRS_PER_MSG` | 100 | addresses accepted from, or served in, one `Addr` |
| `GETADDR_INTERVAL_MS` | 60 000 | minimum gap between asks to the *same* peer |
| `DIAL_RETRY_INTERVAL_MS` | 5 000 | maintenance-pass cadence (was `REDIAL_INTERVAL`) |
| `DIAL_BACKOFF_START_MS` / `_MAX_MS` | 1 000 / 30 000 | per-address failure backoff (moved from S9) |

Eviction never touches a seed (S4) or a dialable entry; a book full of those
refuses new candidates rather than dropping something worth keeping.

## What a learned address may *not* do (S6)

An address from a peer is a candidate to try and nothing else. It is never a
scoring input: if a bogus address were penalisable, any peer could get a third
party punished by naming it. A *frame* we cannot decode is different — that is
the sender's own malformed message, and it is scored. This is the same rule
`IngestOutcome::is_peer_fault` encodes for objects (#70 S5, #74).

## Acceptance evidence

| # | asked for | test |
|---|---|---|
| 1 | seed-only node learns the mesh and connects | `node.rs::seed_only_node_learns_the_mesh_and_connects` (in-process) + `run.rs::seed_only_node_learns_the_net_and_an_undialable_one_is_never_gossiped` (**real TCP**) |
| 2 | an undialable node is never gossiped, both directions | same TCP test (it is connected to B, and B's book stays exactly `[C]`) + `node.rs::a_node_that_is_not_dialable_is_never_gossiped` |
| 3 | caps enforced; an inbound flood refused, not absorbed | `transport.rs::tcp_inbound_cap_refuses_a_flood_rather_than_absorbing_it`, `node.rs::auto_connect_stops_at_the_outbound_cap` |
| 4 | learned addresses survive restart | `run.rs::the_address_book_survives_a_restart` (restarted with an **empty** seed list) + `a_corrupt_address_book_is_ignored_at_startup` |
| 5 | full unfiltered workspace suite | requested on #64 — **not** run by the builder while the rig was held |

## Honest remainders

- **The rate limit is per peer, not global.** Eight peers can each be asked once a
  minute; there is no aggregate cap on inbound `Addr` volume beyond
  `MAX_ADDRS_PER_MSG` per message. Fine at T1 scale, worth revisiting with real
  adversarial load.
- **No address quality/attempt-decay scoring.** Ordering is seeds-first, then
  fewest failures, then insertion order. Bitcoin-style bucketing by network group
  is not here, and neither is eclipse resistance — a topic for peer hardening, the
  other half of the M11 line item.
- **`peers.dat` is written on graceful shutdown**, not periodically. A `SIGKILL`
  loses what was learned since start; the seeds still recover the net.
- **The `/v1/telemetry` wire does not carry the ratio** (see decision 4).
- **`qumbra-deploy/OPERATOR.md` is owed a line** about `advertise_addr` on the four
  T0 hosts — different repo, coordinator/T-ops call.
