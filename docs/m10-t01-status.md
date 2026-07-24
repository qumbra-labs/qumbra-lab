# M10-T0-1 — `qumbra-node` binary + genesis tooling (issue #62)

Makes N7's in-process `FullNode` composition a **real deployable binary**: a
TOML-configured full node over the real TCP transport with RandomXPow (N3) and
on-disk persistence, plus `genesis init` — a versioned genesis file baking the
FROZEN v1.0 constant table + committee₀ + the genesis block, byte-verified by
every node on startup.

## What landed

New crate **`qumbra-node`** (thin — a bin in `qlab-node` would cycle through
`qlab-p2p → qlab-node`, so the issue's "thin new crate" option was taken):

| module | what |
|---|---|
| `config` | TOML `NodeConfig` (data dir, listen addr, dial peers, committee-key paths, mining, genesis file, optional `expected_genesis_hash`). |
| `genesis` | Versioned `GenesisFile` (`[devnet-placeholder]` shape; protocol-spec §9 format is `[full-M8]`, NOT frozen) baking the FROZEN v1.0 `FrozenParams` table + committee₀ (21 ML-DSA-65 verifying keys) + genesis block. `hash = keccak256(bincode)`, printed on init and asserted on startup. Committee **key files** (deterministic seed, honestly-labelled rehearsal). |
| `params_audit` | The params_devnet ⟷ FROZEN v1.0 convergence audit (data + test-locks + markdown; see `docs/m10-t01-params-audit.md`). |
| `run` | `RunningNode<P, V>` composing the N7 stack over `TcpTransport` + disk-backed `NodeAdapter` + PoW; `run_until(flag)` with graceful-shutdown snapshot flush. Generic over the PoW engine (KeccakPow in tests, RandomXPow in the binary — the N7 pattern). |
| `main` | CLI: `genesis init [--out DIR]`, `run --config FILE`, `audit [--out FILE]`. Ctrl-C → snapshot flush. |

**Pinned genesis hash (T0):** `4a75b3b8a80122cbbc35867df17bd14f19054658b511dbc45bcfa67053cfc2c3`
(byte-identical across independent `genesis init` runs; test-locked in
`genesis::tests::genesis_hash_is_pinned`).

In-boundary changes to **`qlab-p2p`** (the only other crate touched):
1. `NodeAdapter::open(dir, …)` + `save_snapshot()` — a disk-backed adapter whose
   state machine resumes restart-safely and, on `open`, **restores the in-memory
   fork-choice header chain from the persisted log** (otherwise a restart started
   with an empty header view).
2. **Orphan-triggered sync kick (item 6):** `P2pNode::complete_block` now kicks
   header-first sync toward the announcer when an announced block's parent is
   unknown (previously dropped — the recorded N7 finding), mirroring `on_header`.
3. **Equivocation-slash convergence (item 5):** `NodeAdapter::apply_evidence` now
   slashes **10 % of the member's bond** (consensus-parameters §4) instead of the
   flat `EQUIVOCATION_SLASH_AMOUNT` placeholder.

## Items 1–6 mapping

1. **binary** ✓ (`run` — TCP + RandomX default + disk + graceful-shutdown flush).
2. **genesis tooling** ✓ (`genesis init`, versioned file, hash printed + asserted;
   wrong-hash refuses to start).
3. **T0 = FROZEN 75 s + real RandomX** ✓ (`SimConfig.block_time_secs = 75`, not the
   sim knob; RandomXPow default). *Annotated sim-only path:* block timestamps
   advance by the frozen 75 s per block (adapter mining clock), so LWMA sees a
   constant solvetime and difficulty holds at genesis — wall-clock timestamps +
   natural PoW pacing are `[full-M8]`.
4. **multi-key finalizers** ✓ (committee₀ = frozen N=21/quorum 15; config lists
   key files per node; loaded keys cross-checked against committee₀).
5. **params convergence audit** ✓ (`docs/m10-t01-params-audit.md`; converged rows
   test-locked; equivocation slash converged at the real path).
6. **orphan-triggered sync kick** ✓ (test `orphan_block_announce_kicks_header_sync`).

## STOP-POINT / boundary notes for the coordinator

- **No wire/constant deviation from FROZEN v1.0.** Every baked value is sourced
  from the single-source code constants (`qlab-consensus` / `qlab-node::emission`
  / `params_devnet`) or pinned as a `[FROZEN §n]` literal, and cross-checked in
  `params_audit::tests`. The genesis-file *format* is `[devnet-placeholder]` per
  the issue (protocol-spec §9 marks it `[full-M8]`) and annotated NOT frozen.
- **params_devnet edits were deliberately NOT made.** The conflict boundary is
  "qlab-node bin/genesis + the qlab-p2p sync-kick"; editing
  `qlab-devnet/params_devnet.rs` is outside it and risks colliding with parallel
  T0-2. So the **genesis file is the frozen source of truth**; the residual
  absolute-scale convergence of `BOND_AMOUNT` / `GENESIS_DIFFICULTY` in
  `params_devnet.rs` is flagged as *debt* in the audit for the qlab-devnet owner.
  The equivocation slash IS converged (at the qlab-p2p `NodeAdapter`, in-boundary).
- **Verifier seam.** The N7 stack is verifier-agnostic; the binary injects a
  clearly-labelled `DevnetRehearsalVerifier` (a T0 net mines coinbase-only blocks,
  so it is never exercised). The real M3 verifier (`qlab_consensus::verify_proof`)
  is the production drop-in at the same `TxVerifier` seam — no composition change.

## Reproduce

```
cargo run --release -p qumbra-node -- genesis init --out ./net     # prints the genesis hash
cargo run --release -p qumbra-node -- audit                         # the convergence table
cargo run --release -p qumbra-node -- run --config node.toml        # a live node (Ctrl-C flushes)
cargo test --release -p qumbra-node                                 # 25 lib tests (incl. RandomX smoke)
```

Acceptance: full unfiltered `cargo test --release --workspace`.
