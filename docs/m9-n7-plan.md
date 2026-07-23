# M9-N7: integration + soak — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Reroute qlab-p2p's `n1.rs` stub node-state onto the real qlab-node
(state machine + N4 mempool), compose PoW+LWMA (N3) + committee-net (N5) + RPC
(N6) into one full node, and deliver an N-node in-process soak harness proving
sync-under-churn, adversarial rejection, restart/reorg/partition resilience, and
a long-run leak check — the T0 readiness evidence pack.

**Architecture:** A new `NodeAdapter` (beside `StubNode` in qlab-p2p) implements
the five N1 traits over *real* components — a qlab-devnet `Node<P>` (chain /
PoW+LWMA / fork-choice / finality), a qlab-node `Node` (commitment tree +
nullifier set + anchors + snapshot restart), the N4 `Mempool` (pending pool,
injected M3 verifier), and the N5 committee machinery (EpochCommittee /
SigningWindow / equivocation). The N1 `BlockIngest` trait gains a
backward-compatible `ingest_block(header, body)` (defaults to `ingest_header`)
so bodies reach real state on both produce and receive paths. A `FullNode`
composition (qlab-bench harness) wraps `P2pNode<InProcTransport, NodeAdapter>`
plus block production and the RPC surface; the soak harness runs N of them over
one `InProcHub`.

**Tech Stack:** Rust 2021, workspace crates qlab-p2p / qlab-node / qlab-devnet /
qlab-pow / qlab-consensus / qlab-bench; Plonky3 `=0.6.1`; deterministic
`SplitMix64`; in-process `InProcHub` transport.

## Global Constraints

- Worktree isolation: ALL edits in `/Users/larry/develop/qumbra/qumbra-lab-n7`
  (branch `claude/m9-n7`). Confirm cwd before every edit batch. Forward this into
  every subagent prompt.
- Additive-only to frozen crates where possible; NO protocol-spec wire/constant
  deviation. Any such deviation → STOP, report to coordinator, do not improvise.
- Frozen constants (params_devnet.rs) are authoritative: block time 75 s,
  committee N=21/quorum 15, epoch 1,152, anchor window 1,152, downtime (100, 33%).
- Two/three tx-id encodings are DELIBERATE — never conflate: `codec::tx_id`
  (p2p, keccak of varint wire incl. proof), `mempool::txid` (body-commitment,
  u8 bucket + proof), `rpc::tx_id` (statement-only, u32 actions, no proof).
- Bench discipline: full unfiltered `cargo test --release --workspace` before PR;
  every recorded number carries git rev / prover pins / hardware / OS / power;
  publishable numbers reproduced twice. Never run two release suites concurrently.
- Staged commits per sub-phase. Open a PR; do NOT merge (coordinator accepts).

---

## File Structure

- `crates/qlab-p2p/src/n1.rs` — MODIFY: add `BlockIngest::ingest_block` (defaulted);
  keep `StubNode` + its tests unchanged (regression guards).
- `crates/qlab-p2p/src/node.rs` — MODIFY: `announce_block` / `complete_block`
  call `ingest_block(header, body)` instead of `ingest_header`.
- `crates/qlab-p2p/src/adapter.rs` — CREATE: `NodeAdapter<P, V>` real-node impl
  of the five N1 traits.
- `crates/qlab-p2p/Cargo.toml` — MODIFY: add `qlab-node`, `qlab-consensus`,
  `qlab-pow` (dev or normal) deps.
- `crates/qlab-node/src/mempool.rs` — MODIFY: add additive read accessors
  (`entries()`, `get(&TxId)`).
- `crates/qlab-node/src/rpc.rs` — MODIFY: rewire pending pool onto `Mempool`.
- `crates/qlab-bench/src/n7soak.rs` — CREATE: `FullNode` + soak scenarios + mode.
- `crates/qlab-bench/src/main.rs` — MODIFY: register `n7soak` mode.
- `crates/qlab-bench/Cargo.toml` — MODIFY: add `qlab-node`, `qlab-p2p`,
  `qlab-pow`, `qlab-devnet` (already present).
- `docs/m9-n7-run1.md`, `docs/m9-n7-run2.md` — CREATE: T0 evidence pack.

---

## Task A: N1 contract extension + `NodeAdapter` (real node-state)

**Files:**
- Modify: `crates/qlab-p2p/src/n1.rs` (add defaulted `ingest_block`)
- Modify: `crates/qlab-p2p/src/node.rs:161-173, 627-643` (call `ingest_block`)
- Create: `crates/qlab-p2p/src/adapter.rs`
- Modify: `crates/qlab-p2p/src/lib.rs` (`pub mod adapter;`)
- Modify: `crates/qlab-p2p/Cargo.toml` (deps)
- Modify: `crates/qlab-node/src/mempool.rs` (additive accessors)

**Interfaces:**
- Consumes: `qlab_p2p::n1::{ChainView, BlockIngest, TxPool, CheckpointIngest,
  CommitteeControl, IngestOutcome}`; `qlab_node::{MemNode, node::genesis_block,
  node::NodeState as NodeStateView}`; `qlab_node::mempool::{Mempool, MempoolError,
  txid as mempool_txid}`; `qlab_devnet::body::{TxEntry, BlockBody, TxVerifier,
  validate_body, BodyError}`; `qlab_devnet::node::Node as ConsensusNode`;
  `qlab_devnet::pow::PowEngine`; `qlab_devnet::committee::{Checkpoint, Vote,
  CommitteeState}`; `qlab_devnet::epoch::EpochCommittee`;
  `qlab_devnet::ebbflow::{SigningWindow, EquivocationEvidence, verify_equivocation,
  finality_status}`; `qlab_devnet::finality::FinalityTracker`;
  `qlab_p2p::codec::tx_id as wire_tx_id`.
- Produces:
  ```rust
  // n1.rs — extension (defaulted, backward-compatible)
  pub trait BlockIngest {
      fn ingest_header(&mut self, header: BlockHeader) -> IngestOutcome;
      fn ingest_block(&mut self, header: BlockHeader, _body: BlockBody) -> IngestOutcome {
          self.ingest_header(header)          // default: header-only nodes ignore the body
      }
  }
  // adapter.rs
  pub struct NodeAdapter<P: PowEngine, V: TxVerifier + Clone> { /* private */ }
  impl<P: PowEngine, V: TxVerifier + Clone> NodeAdapter<P, V> {
      pub fn new(genesis: BlockHeader, committee: CommitteeState, pow: P, verifier: V,
                 sim: qlab_devnet::node::SimConfig) -> Self;
      pub fn with_epoch(genesis: BlockHeader, committee: EpochCommittee, pow: P,
                 verifier: V, sim: qlab_devnet::node::SimConfig) -> Self;
      pub fn consensus(&self) -> &ConsensusNode<P>;      // chain/PoW/finality reads
      pub fn state(&self) -> &qlab_node::MemNode;         // real-state reads
      pub fn mempool(&self) -> &Mempool;
      pub fn committee(&self) -> &EpochCommittee;
      pub fn finality(&self) -> &FinalityTracker;
      pub fn mine_block(&mut self) -> Option<(BlockHeader, BlockBody)>;   // assemble+mine+apply
      pub fn make_checkpoint(&self, validators: &[Validator]) -> Option<(Checkpoint, Vec<Vote>)>;
  }
  // + impl ChainView/BlockIngest/TxPool/CheckpointIngest/CommitteeControl for NodeAdapter
  // mempool.rs — additive read accessors
  impl Mempool {
      pub fn entries(&self) -> Vec<TxEntry>;             // all pending, deterministic order
      pub fn get(&self, id: &TxId) -> Option<&TxEntry>;
  }
  ```

Design notes bound into the impls:
- **ChainView** delegates to `self.consensus.chain()` (fork-choice / main_chain /
  header) exactly as `StubNode`, and `finalized_height()` → `self.finality()`
  (committee source of truth).
- **BlockIngest::ingest_block**: first `validate_body(&body, &self.verifier,
  |r| self.state.is_valid_anchor(r))`; on `Err(_)` → `Rejected("bad body")`
  (adversarial, penalize). Else `self.consensus.submit(header)` → map
  `InsertError` to outcome (Duplicate/Orphan/BadHeight→Rejected, Ok→advance epoch
  + Accepted). On Accepted, best-effort `self.state.apply_block(header, body,
  &self.verifier)` — ignore `NotExtendingTip` (benign reorg lag; qlab-node is
  tip-only by design) but treat a Body error as an internal invariant break
  (should not happen: validate_body already passed). `ingest_header` (no body):
  submit header only (used by pure header sync).
- **TxPool::ingest_tx**: `self.mempool.admit(tx, spends_coinbase=vec![], &self.state,
  &self.verifier)` → Ok→Accepted (record `wire_tx_id(&tx) → txid`), `DuplicateTx`→
  Duplicate, any gate error→`Rejected(reason)`. `get_tx`/`has_tx` resolve
  `wire_tx_id → txid → mempool.get`; `all_txs()` → `mempool.entries()`.
- **CheckpointIngest / CommitteeControl**: copy `StubNode`'s exact logic
  (quorum-active filtering, `try_finalize`, `set_finalized` via
  `self.consensus` chain, downtime jail, `observe_votes`, `apply_evidence`,
  `finality_status`) — the committee machinery is already real (N5).

- [ ] **Step A1: add additive mempool accessors + failing test**

`crates/qlab-node/src/mempool.rs` — add inside `impl Mempool`:
```rust
/// All pending transactions in deterministic (txid) order — for block relay /
/// compact reconstruction (N7). Read-only view; does not mutate the pool.
pub fn entries(&self) -> Vec<TxEntry> {
    self.txs.values().map(|m| m.entry.clone()).collect()
}
/// A pending transaction by its body-commitment id, if present.
pub fn get(&self, id: &TxId) -> Option<&TxEntry> {
    self.txs.get(id).map(|m| &m.entry)
}
```
Add test in mempool.rs `mod tests`:
```rust
#[test]
fn entries_and_get_expose_admitted_txs() {
    // build a node state + one admissible tx via the module's existing helpers
    let (mut mp, state, tx, ver) = admissible_fixture();          // reuse existing test helper
    let id = mp.admit(tx.clone(), vec![], &state, &ver).unwrap();
    assert_eq!(mp.len(), 1);
    assert_eq!(mp.entries().len(), 1);
    assert_eq!(mempool::txid(mp.get(&id).unwrap()), id);
}
```
(If no `admissible_fixture` helper exists, inline the smallest admit fixture the
existing mempool tests already use.)

- [ ] **Step A2: run test to verify it fails**
Run: `cargo test -p qlab-node --lib mempool::tests::entries_and_get -- --nocapture`
Expected: FAIL (no method `entries`) until Step A1 compiles; then PASS.

- [ ] **Step A3: extend the N1 `BlockIngest` trait (defaulted)**
Apply the `ingest_block` default shown in Interfaces to `n1.rs`. Add a test that
`StubNode` inherits the default (body ignored):
```rust
#[test]
fn stubnode_ingest_block_defaults_to_header_only() {
    let mut n = node();
    let g = genesis();
    let h1 = BlockHeader::child_of(&g, 75, 1000, [1; 32]);
    let body = qlab_devnet::body::BlockBody { txs: vec![], coinbase: 0 };
    assert_eq!(n.ingest_block(h1, body), IngestOutcome::Accepted);
    assert_eq!(n.tip_height(), 1);
}
```
Run: `cargo test -p qlab-p2p --lib n1::tests::stubnode_ingest_block` → PASS.
Verify existing n1 + node tests still green: `cargo test -p qlab-p2p`.

- [ ] **Step A4: route bodies in node.rs**
`node.rs` `announce_block` (line ~164): replace `let _ = self.node.ingest_header(header);`
with `let _ = self.node.ingest_block(header, /* body */ txs.clone().into_body());`
— but `BlockBody` needs the coinbase counter. Use a helper: reconstruct
`BlockBody { txs: txs.clone(), coinbase: 0 }` is WRONG (coinbase carries emission).
Instead thread the real body: `announce_block` already has `header` + `txs`; add a
`coinbase: u64` parameter to `announce_block` (the FullNode passes
`template.coinbase_total`). `complete_block` reconstructs body from the announce's
prefilled coinbase-position tx — but coinbase counter is header-derived. **Decision:**
`announce_block(header, txs, coinbase, nonce)`; store `(txs, coinbase)` in
`self.blocks: HashMap<Hash32,(Vec<TxEntry>,u64)>`; `complete_block` calls
`ingest_block(header, BlockBody{txs, coinbase})`. Update `on_get_block_txn`
serving to read `.0`. Update all `announce_block` call sites in node.rs tests.
Run: `cargo test -p qlab-p2p` → all green (adjust test call sites).

- [ ] **Step A5: add qlab-p2p deps + create adapter.rs skeleton**
`Cargo.toml`: add `qlab-node = { path = "../qlab-node" }`,
`qlab-consensus = { path = "../qlab-consensus" }`,
`qlab-pow = { path = "../qlab-pow" }`. Create `adapter.rs` with the struct + `new`
+ `ChainView` impl only. `lib.rs`: `pub mod adapter;`.
Run: `cargo check -p qlab-p2p` → clean.

- [ ] **Step A6: TxPool impl + failing test (invalid proof rejected)**
Write the `TxPool` impl (admit → mempool, wire-id mapping). Test:
```rust
#[test]
fn adapter_txpool_rejects_invalid_proof_and_admits_valid() {
    let mut a = adapter_fixture_with_finalized_anchor();     // genesis + 1 finalized block
    let good = admissible_tx(&a);                            // valid proof under MockOk seam
    assert_eq!(a.ingest_tx(good.clone()), IngestOutcome::Accepted);
    assert!(a.has_tx(&wire_tx_id(&good)));
    let bad = { let mut t = good.clone(); t.proof = vec![0xFF; 8]; t };  // fails verifier
    assert!(matches!(a.ingest_tx(bad), IngestOutcome::Rejected(_)));
}
```
Use a `MockVerifier { accept_if: fn(&TxEntry)->bool }` (accept iff proof matches
a known-good marker) so the test needs no real proving. Run → PASS.

- [ ] **Step A7: BlockIngest (ingest_block) impl + failing tests**
Implement `ingest_block` per design notes. Tests: (a) a valid produced block
applies to state and advances tip; (b) a block whose body carries a
verifier-failing tx → `Rejected` and state unchanged (no crash); (c) an orphan
header → `Orphan`. Run → PASS.

- [ ] **Step A8: CheckpointIngest + CommitteeControl impls + tests**
Port `StubNode`'s logic verbatim (adjusting `self.chain` →
`self.consensus`-owned chain via `set_finalized`, and `self.finality` reads).
Tests: quorum gate; tombstoned-votes-dropped; downtime jail over ingest;
observe_votes conflict detection. Run → PASS.

- [ ] **Step A9: commit Task A**
```bash
git add crates/qlab-p2p crates/qlab-node/src/mempool.rs
git commit -m "M9-N7 A: N1 ingest_block extension + real NodeAdapter (chain/mempool/committee)"
```

---

## Task B: rewire NodeRpc pending pool onto the N4 Mempool

**Files:**
- Modify: `crates/qlab-node/src/rpc.rs:174-286` (+ serving joins that read `pending`)

**Interfaces:**
- Consumes: `crate::mempool::{Mempool, MempoolParams, MempoolError, txid}`;
  existing `TxDiscovery`, `tx_id_of_public`, `SubmitOutcome`, `RejectReason`.
- Produces: `NodeRpc` internals now back the pending set with a `Mempool`; the
  public `submit_tx`, `pending_len`, `pending_txs`, `record_discovery` signatures
  are UNCHANGED. `discovery: HashMap<Hash32 (rpc tx_id), TxDiscovery>` stays.

Design:
- Replace `pending: HashMap<Hash32,TxEntry>` + `pending_nf: HashSet<Hash32>` with
  `mempool: Mempool`. `submit_tx` delegates admission to
  `self.mempool.admit(tx, spends_coinbase, &self.node, verifier)` and maps
  `MempoolError` → `RejectReason` (WrongFee→WrongFee, AnchorNotValid→AnchorNotValid,
  AlreadySpent→NullifierSpent, NullifierConflictInPool→NullifierPending,
  DuplicateTx→Duplicate, ImmatureCoinbase→a NEW `RejectReason::ImmatureCoinbase`,
  ProofInvalid→ProofInvalid). Keep the rpc-layer `DiscoveryMismatch` check BEFORE
  `admit` (mempool has no discovery notion). `discovery` keyed by
  `tx_id_of_public` (statement id) — unchanged; serving joins unchanged.
- `pending_len()` → `self.mempool.len()`; `pending_txs()` → `self.mempool.entries()`.
- The mempool's txid (body-commitment) is the pool key; the rpc discovery map key
  (statement id) is separate — the two-tx-id note honored: NEVER use one where the
  other is meant.

- [ ] **Step B1: failing test — submit path parity + coinbase maturity**
Extend `crates/qlab-node/tests/rpc.rs` (or inline `#[cfg(test)]`):
```rust
#[test]
fn submit_tx_backed_by_mempool_admits_and_rejects() {
    let mut rpc = rpc_with_one_finalized_anchor();
    let (tx, disc) = admissible(&rpc);
    assert!(matches!(rpc.submit_tx(tx.clone(), disc.clone(), &ok_verifier()), SubmitOutcome::Accepted(_)));
    assert_eq!(rpc.pending_len(), 1);
    // duplicate → Duplicate; bad proof → ProofInvalid; wrong fee → WrongFee
    assert!(matches!(rpc.submit_tx(tx, disc, &ok_verifier()), SubmitOutcome::Duplicate));
}
```
Run → FAIL (mempool field absent).

- [ ] **Step B2: implement rewire**
Apply the design. Add `RejectReason::ImmatureCoinbase` if not present (additive
enum variant). Run: `cargo test -p qlab-node` → all green (existing rpc socket +
compact/frontier serving tests must still pass — verify the golden digest
`3ee2a5e6…f54017` test is untouched).

- [ ] **Step B3: commit Task B**
```bash
git add crates/qlab-node/src/rpc.rs crates/qlab-node/tests
git commit -m "M9-N7 B: rewire NodeRpc pending pool onto the N4 Mempool (two-tx-id honored)"
```

---

## Task C: FullNode composition (PoW+LWMA / committee / RPC) in qlab-bench

**Files:**
- Create: `crates/qlab-bench/src/n7soak.rs` (FullNode + helpers; scenarios in Task D)
- Modify: `crates/qlab-bench/Cargo.toml` (add `qlab-node`, `qlab-p2p`, `qlab-pow`)
- Modify: `crates/qlab-bench/src/main.rs` (declare `mod n7soak;`)

**Interfaces:**
- Consumes: `qlab_p2p::{P2pNode, adapter::NodeAdapter, transport::{InProcHub,
  InProcTransport}, peer::PeerId}`; `qlab_devnet::pow::{KeccakPow, RandomXPow}`;
  `qlab_devnet::committee::{devnet_committee, Validator, CommitteeState}`;
  `qlab_consensus` verifier seam; `qlab_node::rpc::NodeRpc`.
- Produces:
  ```rust
  pub struct FullNode { pub p2p: P2pNode<InProcTransport, NodeAdapter<KeccakPow, PoolVerifier>>,
                        pub validators_share: Vec<Validator> /* only committee nodes hold keys */ }
  impl FullNode {
      pub fn new(id: PeerId, node_id: [u8;32], hub: &Arc<InProcHub>, genesis: BlockHeader,
                 committee: CommitteeState, verifier: PoolVerifier) -> Self;
      pub fn tick(&mut self) -> usize;                       // p2p.tick()
      pub fn mine_and_announce(&mut self, nonce: u64) -> bool;// adapter.mine_block → announce_block
      pub fn tip_height(&self) -> u64;
      pub fn finalized_height(&self) -> Option<u64>;
  }
  pub fn run_n7soak(power: &str, only: Option<&str>);        // bench-mode entry
  ```
- `PoolVerifier` = the m6devnet real-`p3_uni_stark::verify` seam for scenarios
  that need a real M3 proof; a `MockOk`/marker verifier for fast churn scenarios.

Design:
- `mine_block` (on the adapter, Task A): `template = mempool.assemble(&state, median)`;
  `bc = template.body.commitment()`; `header = consensus.mine_next(bc)?` (real
  PoW+LWMA+key-seed); `state.apply_block(header, template.body.clone(), verifier)`
  best-effort; `mempool.on_block_connected(height, &body, &state)`; return
  `(header, body)`. FullNode then `p2p.announce_block(header, body.txs,
  body.coinbase, nonce)`.
- Committee nodes hold `Validator` keys and periodically produce checkpoints via
  `adapter.make_checkpoint(&validators)` → `p2p.announce_checkpoint(cp, votes)`.
- KeccakPow default (fast, deterministic); one scenario uses RandomXPow to prove
  N3 composes (single-node, not the N-mesh — RandomXPow is not Clone/Sync).

- [ ] **Step C1: deps + module skeleton + a 2-node handshake test**
Add deps; create `n7soak.rs` with `FullNode::new` + `tick`. Test: two FullNodes
over one hub reach `PeerState::Ready` after a bounded tick loop. Run → PASS.

- [ ] **Step C2: single-node produce→apply→serve test**
`FullNode::mine_and_announce` mines a block over a finalized anchor, applies it,
and the node's RPC `/v1/status` reports the new tip. Run → PASS.

- [ ] **Step C3: RandomXPow composition smoke test (single node)**
One `#[test]` builds a `NodeAdapter<RandomXPow, _>`, mines one block, asserts the
PoW hash satisfies target and LWMA difficulty is the mandated value. Run → PASS.
(Keep it single-block — RandomX light-mode is slow.)

- [ ] **Step C4: commit Task C**
```bash
git add crates/qlab-bench
git commit -m "M9-N7 C: FullNode composition — PoW+LWMA production, committee, RPC over real P2P"
```

---

## Task D: N-node soak harness + scenarios

**Files:**
- Modify: `crates/qlab-bench/src/n7soak.rs` (scenarios + `run_n7soak`)
- Modify: `crates/qlab-bench/src/main.rs` (dispatch `"n7soak"`)

**Interfaces:**
- Consumes: Task C `FullNode`; `qlab_devnet::load::rng::SplitMix64` (deterministic).
- Produces: scenario fns each returning a summary struct printed as Markdown by
  `run_n7soak`; each also asserted by a `#[test]`:
  ```rust
  fn scenario_sync_from_genesis_under_churn(seed: u64) -> SoakResult;   // S1
  fn scenario_adversarial_peers() -> SoakResult;                        // S2
  fn scenario_restart_reorg_partition(seed: u64) -> SoakResult;         // S3
  fn scenario_long_run_leak_check(seed: u64, blocks: u64) -> LeakResult;// S4
  ```

Scenario contracts (each MUST NOT panic; assertions are the pass gate):
- **S1 sync-from-genesis under churn:** N=4 mesh; miner produces blocks while a
  late-joining node (added at height H) header-syncs from genesis; peers join/leave
  (add_peer/ban) per `SplitMix64` schedule. Gate: all live nodes converge to the
  same tip hash and height; late joiner catches up; `SyncPhase::Synced`.
- **S2 adversarial peers:** inject (a) a tx with a bad proof → `Rejected`, sender
  penalized, not relayed; (b) a header with bad height/unknown parent → rejected /
  orphan-triggers-sync, no crash; (c) a block whose body carries a bad-proof tx →
  `Rejected`, penalized; (d) a checkpoint with sub-quorum / forged votes →
  rejected, no false finalization; (e) forged equivocation evidence → not applied,
  penalized. Gate: honest nodes' state unchanged; adversary score ≤ ban threshold;
  zero panics.
- **S3 restart/reorg/partition:** (reorg) partition the mesh into two groups that
  mine competing suffixes above the last finalized height; heal; assert
  heaviest-chain convergence AND no-reorg-past-finality. (restart) snapshot a
  node (`state.save_snapshot` via a temp dir), drop it, `open` a fresh node from
  the dir, assert `open`-state == pre-drop state (tip/root/nullifier count) and it
  re-syncs. (partition) assert degraded→Final transition across heal.
- **S4 long-run leak check:** run `blocks` (default ≥ 2,000) block-rounds on N=3
  with steady tx flow; sample a cheap proxy for retained state each K rounds
  (mempool len bounded, `seen`-cache bounded, peer table stable, adapter map sizes
  bounded); assert monotone-bounded (no unbounded growth). Report the samples.

- [ ] **Step D1: S1 scenario + test** — write `scenario_sync_from_genesis_under_churn`,
  assert convergence. Run: `cargo test -p qlab-bench n7soak::tests::s1` → PASS.
- [ ] **Step D2: S2 scenario + test** — all five adversarial injections; assert
  rejection + no state change + no panic. Run → PASS.
- [ ] **Step D3: S3 scenario + test** — reorg convergence, finality safety,
  snapshot restart equality. Run → PASS.
- [ ] **Step D4: S4 scenario + test** — bounded-growth leak proxy. Run → PASS.
- [ ] **Step D5: `run_n7soak` mode + main.rs dispatch** — print Markdown tables
  (env header via existing `print_env` helper). Run: `cargo run --release -p
  qlab-bench -- n7soak` → prints a report.
- [ ] **Step D6: commit Task D**
```bash
git add crates/qlab-bench
git commit -m "M9-N7 D: N-node soak — churn sync, adversarial rejection, reorg/restart/partition, leak check"
```

---

## Task E: T0 evidence pack + full suite + PR

- [ ] **Step E1: full unfiltered release suite (single suite, no concurrency)**
Run: `cargo test --release --workspace 2>&1 | tee /…/scratchpad/n7-suite-1.txt`
Expected: 0 failed; capture the total. (Rig discipline: no other release suite
running.)
- [ ] **Step E2: reproduce the soak run twice**
`cargo run --release -p qlab-bench -- n7soak > docs/m9-n7-run1.md` then again into a
temp file; diff the deterministic sections; write `docs/m9-n7-run2.md`. Each doc
carries the bench-discipline 5-tuple (git rev, prover pins, hardware, OS, power)
and a Determinism statement.
- [ ] **Step E3: second full suite run (reproduce-twice for the headline count)**
Run the workspace suite again; confirm identical pass count.
- [ ] **Step E4: update CLAUDE.md milestone line** for M9-N7 (DONE, PR #NN,
  headline counts + findings + any residuals) — matching the existing milestone
  entry style.
- [ ] **Step E5: open PR (do NOT merge)**
```bash
git push -u origin claude/m9-n7
gh pr create --title "M9-N7: integration + soak (issue #54)" --body "<summary + evidence + decisions + residuals>"
```
Post the PR URL. Coordinator accepts.

---

## Self-Review (spec coverage)

- reroute n1 stubs → real qlab-node ✓ Task A (NodeAdapter over qlab-node Node +
  N4 Mempool + N5 committee).
- wire rpc pending pool onto N4 mempool (two-tx-id honored) ✓ Task B.
- compose PoW+LWMA (N3) + committee-net (N5) + RPC (N6) into one full node ✓
  Task C (FullNode; KeccakPow mesh + RandomXPow smoke).
- N-node in-process harness over real P2P ✓ Task D (P2pNode + InProcHub).
- sync-from-genesis under churn ✓ S1. adversarial invalid proofs/blocks/
  checkpoints rejected without crash ✓ S2. restart/reorg/partition ✓ S3.
  long-run leak check ✓ S4.
- T0 evidence pack, reproduced twice, per bench discipline ✓ Task E.
- STOP-POINTs: the `ingest_block` contract extension is backward-compatible
  (defaulted) — a design evolution N7 is chartered to do, NOT a wire/constant
  deviation; documented for coordinator. No protocol-spec wire/constant change.
