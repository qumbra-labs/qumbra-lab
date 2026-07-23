# M9-N2 — P2P core (issue #49): plan + spec-conformance notes

**Crate:** `qlab-p2p` (new; conflict boundary = this crate + its one line in the
workspace members list). Wave 1, parallel; programs against N1 (#48) trait
interfaces, **stubbed** here — integration to the real qlab-consensus/qlab-node
is deferred to N7 (#54).

## Scope (from #49)

1. Versioned message envelope (versioned / reject-unknown per protocol-spec §0)
2. Peer management (handshake, peer table, scoring/ban, addr exchange)
3. Gossip (blocks / txs / checkpoints) — inventory-based, dedup, relay
4. Header-first sync state machine
5. Compact-block relay (protocol-spec §5 framing)
6. Dual transport: in-process simulated (deterministic tests) + real TCP
7. N1 trait stubs

## Wire-conformance discipline (the stop-point rule)

The mandate: **any protocol-spec wire deviation → report, don't improvise**;
**discover a spec gap → stop and report.** Here is the honest mapping of what
the spec binds vs. what it leaves to this layer, so nothing is improvised
silently.

### What the spec binds (MUST match — no deviation)

- **§0 Versioning.** Every version-tagged wire format is **reject-unknown**.
  Our envelope carries an explicit `protocol_version` and `msg_type`; unknown
  values of either are rejected at decode, as are trailing bytes and oversize
  frames. (`wire.rs`.)
- **§5 framing.** The note-discovery / compact-block wire — `version(0x01)` lead
  byte, unsigned **LEB128** varints (≤ 10 B, overflow-guarded), reject
  trailing / unknown-version / non-zero-clue. This is **not re-implemented**:
  compact-block relay reuses `qlab_cbserver::codec` verbatim
  (`write_varint` / `read_varint` / `encode_compact_response` /
  `decode_compact_response` / `WIRE_VERSION`), which is golden-locked to the
  spec's on-record whole-buffer digest `3ee2a5e6…f54017`. Byte-for-byte the
  ratified wire. (`compact.rs`.)

### What the spec explicitly DEFERS (this layer defines a prototype shape)

protocol-spec **§10** ("Deferred to full M8") lists, verbatim, **"P2P message
formats"**. So the envelope layout, handshake, inventory/gossip messages, and
header-sync messages are **not specified anywhere yet** — building them is this
issue's job, not a deviation. Every such message is flagged
**`[devnet-placeholder]`-shape** in code: the *discipline* (§0 versioning, §5
framing) is binding; the *specific bytes* are a lab proposal, to be frozen with
the full-M8 P2P spec section. This mirrors how the devnet header/body preimages
are `[devnet-placeholder]` in §6.

### Reported observation — the two distinct "compact block" objects

The issue says *"compact-block relay (protocol-spec §5 framing)"*. There are, in
the design corpus, **two different objects that both get called "compact
block"**, and they are not the same wire:

1. **§5 "PQ compact blocks"** = the **note-discovery serving wire** (light client
   ↔ compact-block server): per-note `cm(32)‖tag(8)‖clue(1)` entries + amortized
   ML-KEM `ct` bundles, `version(0x01)`-framed. Golden-locked in `qlab-cbserver`.
2. **consensus-and-network §7 "compact-block relay"** = **inter-node block
   propagation** (BIP-152-shape): announce a block as a header + short
   transaction-id list, peers reconstruct the body from their mempools. This is
   the "the real transport is the steady-state gossip stream" mechanism. Its
   wire is **not specified** (it is part of §10's deferred "P2P message
   formats").

This is not a blocking gap — §10 covers it — but it is a genuine terminology
overlap worth surfacing. **Resolution taken (not improvised past the spec):**

- We provide **both**, and keep them cleanly separated:
  - `CompactBlockRelay` — relays the **§5** `CompactBlock` object between peers
    **verbatim** via the reused `qlab_cbserver::codec` (literal "§5 framing").
  - `BlockAnnounce` / `GetBlockTxn` / `BlockTxn` — the **§7** BIP-152-shape
    block-reconstruction round-trip, a `[devnet-placeholder]` P2P format framed
    with the **same** §5-conformant LEB128 varints + `version(0x01)` discipline,
    so the two are wire-consistent even though only #1 is spec-frozen.

If the coordinator wants only one of these two meanings in scope, that is a
one-line trim — flagged rather than assumed.

## Architecture

- `wire.rs` — versioned envelope: `magic ‖ protocol_version(u16 LE) ‖
  msg_type(u16 LE) ‖ payload_len(u32 LE) ‖ payload`. Reject unknown version /
  unknown type / trailing / oversize. Golden-byte-locked.
- `varint.rs` — thin re-export + conformance tests binding our varint use to
  `qlab_cbserver::codec::{read,write}_varint` (single source; no second LEB128).
- `codec.rs` — hand-rolled LE (de)serialization of the devnet consensus objects
  that lack serde: `BlockHeader` (round-trips its 98-B `preimage()` + tag check),
  `Checkpoint`, `Vote` (signer + ML-DSA `.encode()`), `TxEntry`, locators, inv.
- `n1.rs` — the **N1 stub traits** this layer consumes (`ChainView`,
  `BlockIngest`, `TxPool`, `CheckpointIngest`) + `StubNode`, an in-memory impl
  over `qlab_devnet::ChainState` + a body/mempool store for tests.
- `transport.rs` — `Transport` trait (`send` / `poll` / `local_peers`);
  `InProcNet` (shared registry, deterministic) + `TcpTransport` (`std::net`,
  reader thread per connection, no async runtime).
- `peer.rs` — `PeerId`, `PeerTable`, handshake FSM (version negotiation,
  reject-unknown-version), scoring + ban, addr book.
- `gossip.rs` — `inv` / `getdata` inventory gossip with a seen-set dedup, for
  headers / txs / checkpoints; relay on first sight.
- `sync.rs` — header-first sync state machine (`Idle → AwaitingHeaders →
  DownloadingBodies → Synced`), locator build, header-batch validation.
- `compact.rs` — compact-block relay (both objects above).
- `node.rs` — `P2pNode<T, N>` tying it together; `tick()` poll/step driver so
  tests are deterministic on `InProcNet` and identical logic runs over TCP.

## Staged commits

1. scaffold + envelope + varint conformance + N1 stubs
2. dual transport (in-proc + TCP)
3. peer management + handshake
4. gossip (blocks/txs/checkpoints)
5. header-first sync
6. compact-block relay
7. multi-node integration (in-proc + TCP) + docs + full unfiltered suite

## Acceptance

Full **unfiltered** `cargo test --release` across the whole workspace green
(bench discipline #5); staged commits; PR opened, **not merged**.
