# M9-N7 — integration + soak, T0 readiness evidence (run 1)

Issue [#54](https://github.com/qumbra-labs/qumbra-lab/issues/54). The full node — qlab-p2p
driving the **real** qlab-node state machine (N1) + N4 mempool + N5 committee + N3
PoW — run as an N-node in-process mesh over real P2P messages.

Runner:
```
cargo run --release -p qlab-bench -- n7soak
```

## Environment (bench discipline)

| field | value |
|---|---|
| repo | `claude/m9-n7` @ `8be2cb5` (Tasks A–D) |
| hardware | Apple M5 Max, 36 GiB |
| OS | macOS 26.5.2 (Darwin 25.5.0) |
| power | AC, no thermal throttling observed |
| prover pins | Plonky3 class `=0.6.1` (Cargo.lock) |
| PoW engine | KeccakPow (deterministic soak); RandomXPow composition proven separately |
| verifier seam | marker mock (`proof == b"ok"`); identical `TxVerifier` seam `m6devnet` drives with real `p3_uni_stark::verify` |

**Determinism:** every scenario is driven by KeccakPow + a seeded `SplitMix64`
(no wall-clock, no RNG entropy). Seeds: S1 = 1, S3 = 2, S4 = 3. Run 1 ≡ Run 2
byte-for-byte (see `m9-n7-run2.md`).

## Scenarios

| scenario | nodes | blocks | pass | finalized | detail |
|---|---|---|---|---|---|
| sync-from-genesis under churn | 4 | 7 | ✅ | Some(0) | all 4 nodes on one tip: true; late joiner Synced: true |
| adversarial peers | 2 | 0 | ✅ | Some(0) | bad-tx rejected+penalized; bad-header no-op; bad-block not-applied; subquorum-cp rejected+penalized; forged-evidence rejected+penalized |
| restart / reorg / partition | 5 | 3 | ✅ | Some(0) | genuine-fork; observer-adopted-heavier; finality-safe; restart(open==replay) |
| long-run leak check | 3 | 1000 | ✅ | — | max-mempool across nodes = 0 at every sample (r0..r950 step 50) — txs drain each cycle, no accumulation |

### S1 — sync-from-genesis under churn

A 3-node mesh mines while one node flaps its links (disconnect → reconnect between
blocks), then a **fresh** 4th node joins and header-syncs from genesis to the live
tip. Gate: all four nodes converge on one ChainView tip **and** the late joiner
reaches `SyncPhase::Synced`. Genesis is committee-finalized network-wide (`Some(0)`).

### S2 — adversarial peers (rejected without crash)

An adversary sends five malformed/invalid objects to an honest node:

1. **tx with an invalid proof** → mempool `admit` runs the injected verifier last →
   rejected, sender penalized, not pooled;
2. **header with an unknown parent** → orphan, no crash, tip unmoved;
3. **block whose body carries an invalid-proof tx** → `ingest_block` validates the
   body first → rejected, not applied to state;
4. **sub-quorum checkpoint** (2 of quorum-3 votes) → not finalized, sender penalized;
5. **forged equivocation evidence** (non-conflicting) → not applied, no tombstone,
   sender penalized.

Honest state is byte-identical before/after every injection; the process never
panics.

### S3 — restart / reorg / partition

- **partition → fork:** the mesh splits into two groups; a distinct tx is admitted
  to each group *after* the split, so the branches genuinely diverge. Group A mines
  3 blocks, group B mines 2 → A is the heavier branch.
- **fork-choice on heal:** a fresh observer joins post-heal and header-syncs; it
  adopts the **heavier** branch (ChainState heaviest-chain fork-choice over the
  synced headers).
- **finality safety:** the four partitioned nodes keep genesis finalized and no
  node ever finalizes a higher (conflicting) block — no reorg past finality.
- **restart:** a disk-backed qlab-node applies blocks, snapshots, and is re-opened;
  `open`-state == `replay`-state == pre-snapshot state (tip / commitment root /
  nullifier count) — restart-safe resume.

### S4 — long-run leak check

3-node mesh, 1000 block-rounds with steady tx flow (a fresh tx every 20 rounds).
The max mempool length across all nodes is sampled every 50 rounds: **0 at every
sample** — admitted txs are mined into the next block and evicted via
`on_block_connected`, so the pending pool never accumulates. The chain advances to
height 1000. (The genesis anchor stays inside the ≤ 1,152-block window across the
run, so tx admission holds throughout.)

## Finding (recorded)

qlab-p2p propagates blocks by **announce-flood** (BIP-152), and `complete_block`
drops an orphan block without kicking sync. Consequently a node that misses blocks
(a churn gap, or a partitioned group after heal) does **not** self-heal via
announces — reconciliation runs through the **header-first sync** path, which fires
on a taller-peer handshake (a fresh/late joiner) or an orphan *header*. The soak
therefore models heal/catch-up with a joining node that carries a fresh handshake
(S1 late joiner, S3 observer). This is a property of the current prototype
propagation layer, not a defect in the N7 wiring; a full node would additionally
gossip block inventory or periodic height so long-running peers re-trigger sync.

## Reproduction

Deterministic; re-run `cargo run --release -p qlab-bench -- n7soak`. The scenario
assertions are the pass gate — see `crates/qlab-bench/src/n7soak.rs` `mod tests`
(`s1_sync_under_churn`, `s2_adversarial_rejected`, `s3_restart_reorg_partition`,
`s4_leak_bounded`) plus `two_nodes_handshake_to_ready`,
`single_node_mines_applies_and_reports_new_tip`, `randomx_pow_composes_single_node`.
Reproduced byte-for-byte in `m9-n7-run2.md`.
