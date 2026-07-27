# Issue #77 — binding block bodies to their header (2026-07-26)

Run doc for the `claude/i77-body-binding` baton. Decisions and findings live in PR #79's body;
this file records what a later reader needs on disk: the shape of the fix, the seam map as it
stands after the change, and the honest remainders.

## What changed, in one paragraph

`BlockHeader.tx_body_commitment` was in the header's hash preimage but never checked against the
body a node was handed. `qlab_devnet::body::validate_body` now **takes the header** and checks
`header.tx_body_commitment == body.commitment()` before any other body work, and
`qlab_node::node::apply_state` — the single funnel every state mutation passes through — re-checks
it. Nothing about the wire format or any FROZEN v1.0 constant changed; only what nodes refuse to
accept.

## The seam map after the change

| seam | file | how it is covered |
|---|---|---|
| body validation | `qlab-devnet/src/body.rs` | `validate_body` takes the header; `check_body_binding` runs first |
| p2p full-node ingest | `qlab-p2p/src/adapter.rs` | `validate_body`, own reject reason, penalised by the caller |
| header-only ingest | `qlab-p2p/src/n1.rs` | the **trait default** checks the binding before dropping the body |
| compact reconstruction | `qlab-p2p/src/node.rs` `complete_block` | funnels into `ingest_block`; a reject is penalised, not cached, not relayed |
| own announce | `qlab-p2p/src/node.rs` `announce_block` | a block our own node rejects never goes on the wire |
| state machine | `qlab-node/src/node.rs` `apply_block` | `validate_body(&header, …)` |
| state-mutation funnel | `qlab-node/src/node.rs` `apply_state` | `check_stored_binding` — covers disk-log replay and hand-built `StoredBlock`s |
| snapshot fast path | `qlab-node/src/node.rs` `open` | checked explicitly, because this path skips `apply_state` |
| genesis | — | **exempt at height 0**, see below |

Two guards, two jobs, two error types, deliberately not merged:
`BodyError::CommitmentMismatch` is an adversarial object at an entry point;
`NodeError::BodyCommitmentMismatch` is an internal construction error or a damaged log.

## Cost

`body.commitment()` runs twice on the live path (entry + funnel). Both are O(block bytes) Keccak
over bytes the code then verifies STARK proofs over — orders of magnitude more expensive. On
replay the guard adds one Keccak pass per block over bytes replay has already read off disk and
deserialised. **Deliberately not cached, not deferred, not made path-dependent** (issue #77 P1). If
this ever shows up in a profile it is a measurement question, not a correctness one.

## Honest remainders

1. **🔴 T1 — genesis must commit to its body (finding F1).** The genesis header pins
   `tx_body_commitment = ZERO_HASH` while an empty body commits to `keccak256(coinbase_le)`, so
   genesis does not satisfy the invariant and is the single height-0 exemption in
   `check_stored_binding`.

   *Safe today* because a stronger check covers the same ground: every node pins
   `expected_genesis_hash` and refuses to start against a different genesis (`deploy/README.md`,
   `qumbra-node check`). The binding protects blocks that arrive from the network; genesis never
   does.

   *Deferred, not dismissed*: changing the header changes the genesis hash and therefore the
   network identity (T0 is pinned to `4a75b3b8…c2c3`) — a new-network decision, Larry's alone.

   **When T1's genesis is minted: set the real body commitment and delete the exemption.** The
   requirement is duplicated at the two sites a mint cannot avoid reading —
   `qlab_devnet::header::BlockHeader::genesis` and `qumbra-node`'s `genesis` module — and locked by
   `genesis_header_does_not_bind_its_empty_body` / `genesis_is_exempt_from_the_binding_guard`, which
   fail loudly if the facts change underneath.

2. **The `qlab-devnet` header-only mining lane is unchanged** (`mine_next` / `mine_on` /
   `net.rs:68` take a bare `Hash32`). It has no `BlockBody` and never claimed to compute the value
   it passes — out of scope per the task-book Addendum A4, recorded here so the omission is visible
   rather than accidental.

3. **`is_peer_fault()` convergence.** The `complete_block` fix matches `IngestOutcome::Rejected(_)`
   directly. PR #76 (halt-height, issue #74) introduces `IngestOutcome::Ignored(_)` and routes every
   fault decision through one `is_peer_fault()` predicate. Behaviourally identical today; whichever
   of the two lands second converts this site, so there is never a second rule for the same
   decision.

4. **Issue #80** — "never cache or relay a block you rejected" was fixed here (its own commit) but
   is not a #77 problem: an invalid-proof body was relayed onward by honest nodes too.
