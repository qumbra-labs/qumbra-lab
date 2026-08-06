Implements #275 — the server half of `qumbra-design/t1-wallet-send-seams-decision.md`, **stamped A1+B1 (2026-08-06)**. Four commits: the qlab-node wire + version bump, the qlab-p2p typed seam, the qumbra-node endpoints, the faucet prose fix.

## Premise-check against `main` (`1d7fabb`), per QUM-73 precedent

- Neither `POST /v1/tx` nor `/v1/tree/leaves` exists anywhere on `main` — the only greps are the wallet's own "no submission surface" comments. Task-book rows verified.
- **One task-book row is wrong in the letter**: the stale "plan.discovery is dropped here" block is in **`qumbra-faucet`**`/src/service.rs:81`, not `qlab-faucet/src/service.rs:81-97` as written. Same finding, one crate over; fixed where it actually lives (both the impl block and the trait doc above it, which made the same since-#188-false claim).
- `Node` already maintained the exact projection seam 2 needs: `commitments_ordered`, the snapshot's append-order leaf ledger (matured-coinbase-first per #102, rebuilt on rewind). Serving it adds an accessor, not a second ledger.

## What landed

### Seam 2 — `GET /v1/tree/leaves?from=N` (B1)

- **Wire** (`qlab-node/src/rpc.rs`, `TreeLeaves`): `RPC_VERSION ‖ from(8 LE) ‖ total(8 LE) ‖ n(varint) ‖ leaf(32)×n`. `from` is echoed (a paging client cannot misattribute a response); `total` is the loop condition and the honest answer to `from` beyond the tree — an **empty page carrying `total`**, never an error, because "you are ahead of me" is a meaningful state during a reorg.
- **GOLDEN VECTORS** (stamp rider 1): `golden_bytes_lock_the_leaf_stream_framing` — byte-position asserts + whole-serialization Keccak digest (`d478d958…828e`), `/v1/compact`'s golden shape exactly. Reject-unknown-version / trailing / truncation locked beside it, plus: a payload claiming 2^60 leaves is a `Truncated` refusal, never an allocation.
- **Page bound**: `MAX_TREE_LEAVES = 4096` → a full page is 128 KiB + ≤19 B header, smaller than one tx proof. `[devnet-placeholder]`, deliberately outside the golden (the wire carries `n` explicitly, so the bound can move without touching the framing).
- **Served twice, one implementation** (stamp rider 2): `NodeRpc::route` gains `["v1","tree","leaves"]` so **any full node can serve it**, and `qumbra-node`'s discovery server serves the same `TreeLeaves::page` over an Arc-swapped snapshot (`LeavesView`), refreshed on the existing `DISCOVERY_REFRESH` cadence, keyed on the applied tip hash (same applied tip ⇒ same applied chain ⇒ same derived leaves; an unchanged tip costs two comparisons).
- **The load-bearing test** (`route_serves_the_leaf_stream_in_apply_order_and_it_rebuilds_the_root`): drives a real chain across the 144-block maturity horizon, lands a tx in the exact block that matures a coinbase, and asserts (a) the coinbase leaf precedes the tx's commitments in the stream, (b) served == `commitments_ordered()` byte-for-byte, (c) **a wallet folding the stream into a fresh `CommitmentTree` reproduces the node's root** — the anchor its spend is judged against, i.e. the brief's self-verification property, executed.

### Seam 1 — `POST /v1/tx` (A1)

Body = canonical wire bytes (`qlab_p2p::codec::encode_tx`, what `build_send` produces). The checks run **before** `announce_tx`, refusals typed and named; success is `202` + the **statement** tx id (`qlab_node::rpc::tx_id` — the id `NodeRpc::submit_tx` answers, so "the tx id" means one thing across surfaces).

- **One validation path, not a fork** (the task-book constraint, taken literally):
  - `NodeAdapter::submit_tx_typed` (new) is the exact admission `TxPool::ingest_tx` applies — the #130(a) state-lag gate, then `Mempool::admit` — with the refusal carried whole; **`ingest_tx` is now a mapping over it**, so the HTTP surface and the peer wire cannot run two different rules. `P2pNode::announce_tx_typed` relays exactly when `announce_tx` would (accept ⇒ relay; duplicate/refusal ⇒ no relay).
  - The in-tx nullifier-repeat precheck is extracted from `NodeRpc::submit_tx` into shared `repeated_nullifier_in_tx` (NodeRpc now calls it; behavior unchanged).
  - The discovery check is `qlab_devnet::body::check_tx_discovery` — the §4 consensus function `validate_body` runs per block. **A position taken, stated**: `NodeRpc::submit_tx`'s own discovery check compares *separately-submitted artifacts* against the committed bytes; over this wire there are no separate artifacts (the group is in the body since #188), so the §4 rules — decode, canonical re-encode, binds declared cms — are the whole check, and they are strictly what a block embedding the tx will be judged by.
- **Threading**: submissions cross into the run loop over a bounded rendezvous (`sync_channel(MAX_QUEUED_SUBMITS = 8)`), drained once per loop iteration (`drain_remote_submits`; empty queue = one `try_recv`). Each POST gets a short-lived handler thread (cap `MAX_INFLIGHT_SUBMITS = 8`, body cap `MAX_TX_WIRE_BYTES = 256 KiB` — basis: the 148,625 B consensus proof + surface + committed discovery ≈ 152 KB, and the verifier rejects non-2×2 shapes) so a trickling submitter can never block the GET worker: reads keep serving from snapshots in microseconds. The loop pays exactly one admission per verdict — the same cost a peer-delivered tx already costs it.
- **Success path**: `announce_tx_typed` → **pool re-read** (`submit_local_tx`'s pattern — report what IS pooled; the failure arm is a named 500 kept expressible, not a comment) → `202 accepted <txid>`. Resubmission → `200 duplicate <txid>`, which is what makes timing out safe to retry.
- **Named refusals on the wire** (`refused: <name>` @ 400, `unavailable: <name>` @ 503; faucet's no-refusal-is-a-5xx discipline): `nullifier-repeated-in-tx`, `discovery-not-canonical`, `discovery-does-not-bind expected=N got=M`, `wrong-fee expected=X got=Y`, `anchor-not-valid`, `nullifier-spent`, `nullifier-conflict-in-pool`, `proof-invalid`, `decode …`, `body-too-large` (413), and 503s: `state-lag` (the node declines to judge with a stale tree — #130(a)'s rule, surfaced instead of silently mis-answered), `submit-queue-full`, `submit-busy`, `no-verdict-in-time`, `node-shutting-down`.
- **`SUBMIT_VERDICT_TIMEOUT = 60 s`, basis stated**: a healthy loop pass is milliseconds; #107 measured deployed loop periods never below 131 s (53 samples, t0-wan-2, four hosts) — an open defect, not a budget. 60 s sits under the stamped topology's Cloudflare ~100 s edge timeout; a #107-afflicted host answers `503 no-verdict-in-time` by name, and the duplicate answer makes retry safe.

### `RPC_VERSION 0x04 → 0x05`, compat note

Route bump, zero payload bytes changed. Reader side paid per #242's own mechanism: `READABLE_TELEMETRY_VERSIONS` = `[0x03, 0x04, 0x05]` (an opview built here reads every host of the current fleet; `0x04`'s telemetry layout is `0x05`'s). Strict decoders stay strict — `0x04` now refused by `from_bytes` like every non-current version, locked in the renamed pinned tests (`…at_0x05`, #242's rename precedent). Compact family untouched at `WIRE_VERSION 0x01` (re-asserted). Loopback default preserved; no config change; public exposure remains the T1 deploy's reverse-proxy decision.

### Folded in as preconditions (called out, per the scope rule)

- **`decode_tx` allocation cap** (`qlab-p2p/src/codec.rs`): `Vec::with_capacity(n)` ran on attacker-controlled varint counts *before* the first element read could refuse them — a tiny frame claiming 2^60 nullifiers requests a 2^65-byte allocation (capacity-overflow panic). Reachable from the peer wire **today**; this PR was about to expose the same decoder to HTTP, which is why it is a precondition and not scope creep. Capped by remaining bytes; test locks the refusal. **The same shape exists at `codec.rs`'s other varint-count decodes (`decode_inv`/`decode_headers`/`decode_checkpoint_votes`) — reported on #275 as a finding, deliberately not fixed here.**

## Acceptance evidence (test name per item)

| Item | Test |
|---|---|
| Leaf framing golden (rider 1) | `qlab-node rpc::tests::golden_bytes_lock_the_leaf_stream_framing` |
| Reject unknown/trailing/truncated/count-lie | `rpc::tests::leaf_stream_rejects_bad_version_trailing_truncation_and_count_lies` |
| Page bound + beyond-total = empty page | `rpc::tests::leaf_pages_are_bounded_and_from_beyond_total_is_an_empty_page` |
| Append order (coinbase-first) + root self-verification | `rpc::tests::route_serves_the_leaf_stream_in_apply_order_and_it_rebuilds_the_root` |
| Typed gate ≡ peer wire, refusals carried whole, state-lag arm | `qlab-p2p adapter::tests::submit_tx_typed_is_the_wire_gate_with_the_refusal_carried_whole` |
| decode_tx count-lie refusal | `qlab-p2p codec::tests::tx_decode_refuses_a_count_the_bytes_cannot_hold_without_allocating` |
| 🔴 E2E: socket → run loop → 202/200/400s, pool re-read, statement id | `qumbra-node run::tests::the_submit_route_judges_over_a_real_socket_through_the_run_loop` |
| HTTP plumbing: queue crossing, rendered verdicts | `discovery_server::tests::a_submission_crosses_the_queue_and_the_verdict_comes_back_named` |
| Local refusals (decode/413/shutdown) never reach the loop | `discovery_server::tests::local_refusals_are_named_and_never_reach_the_queue` |
| Queue bound refuses by name | `discovery_server::tests::a_full_queue_refuses_by_name_instead_of_queueing_deeper` |
| Leaves over a real socket + snapshot swap | `discovery_server::tests::serves_the_leaf_stream_over_a_real_socket` |
| Method gates / 404s unchanged elsewhere | `discovery_server::tests::only_the_three_routes_are_served_and_methods_are_gated` |
| Version bump collateral locked | `qlab-node rpc::tests::status_and_anchors_moved_to_0x05_…`, `telemetry::tests::a_current_reader_still_reads_a_0x03_or_0x04_node_…` |
| opview mid-roll readability at 0x05 | `qumbra-opview tests/over_http.rs a_mid_roll_net_is_fully_readable_…` |

**Full unfiltered workspace suite, rig-locked** (`scripts/rig run -- cargo test --release --workspace -- --test-threads=1`, this branch at `<REV>`, MacBook Pro M5 Max 36 GiB, AC): **<TOTAL> passed / 0 failed** — baseline 1237 at `1d7fabb` + <NEW> new tests − 0 removed = <TOTAL>, reconciled below. Negatives verified: `FAILED`, `panicked at`, `^error` all zero in the log.

<RECONCILIATION>

## Constraints, checked

- §6.2 untouched — nothing lands on committee hosts; the routes live behind the loopback-default discovery listener on the keyless binary path. No consensus change, no P2P wire codepoint or payload change, no genesis change, no FROZEN constant touched. Golden compact framing byte-identical (its golden re-asserted in the version-bump test).

## What I did not verify, named

- **The real-STARK arm of the submit path end to end.** The e2e socket test runs `DevnetRehearsalVerifier`; the real `ConsensusVerifier` sits in the identical `Mempool::admit` seam (exercised against real proofs elsewhere in the suite), but **no test in this PR submits a real proof over HTTP**. If something breaks first in production, I'd bet here — specifically a real proof pushing a verdict past the loop-pass budget on a #107-afflicted host.
- **`SUBMIT_VERDICT_TIMEOUT`'s timeout arm.** The disconnect arm is tested; the 60 s expiry arm is not (a test would cost 60 s of wall time or a constant injection I judged not worth the surface). If the timeout fires in anger, the rendered 503 text is asserted nowhere.
- **Leaf-stream behavior across a live reorg** is tested at the projection layer (`DiscoveryView`-style sig change) and argued from `apply_state`/rewind's funnel, but no test reorgs a running node under a paging client.
- The full suite pass reported above is this rig, one run — the coordinator's independent re-run is the bar, as always.

## Findings (reported, not fixed here)

1. **Mempool admits what block validation refuses** — neither `Mempool::admit` nor `ingest_tx` runs `check_tx_discovery` or the in-tx nullifier-repeat check, so a peer can pool a tx whose discovery does not bind (or which repeats a nullifier in-tx); a miner then assembles it and its own `apply_block` → `validate_body` refuses the mined block. Pool poisoning → self-wedging miner, peer-reachable today. The HTTP surface is immune (it runs both checks), which is how it surfaced. Posted on #275.
2. **The varint pre-allocation shape** at the other `codec.rs` decode sites (above).
3. Task-book crate-name drift (`qlab-faucet` → `qumbra-faucet`), recorded above.
