# M6 — Consensus/Network Devnet — Build Plan

> **For agentic workers / relay sessions:** this is the living plan for the M6
> devnet build. Keep the **Progress table** current at every commit. This build
> spans multiple relay legs; sessions die, uncommitted work is lost work — one
> clean commit per sub-stage, handoff summary at every break, tree clean.

**Goal:** a local multi-node simulation of Qumbra's hybrid consensus — PoW block
production + a small BFT finality committee — that proves out the mechanics the
design docs decided, on real M3 tx proofs, with a measured cadence/finality/
validation-time report.

**Crate:** `crates/qlab-devnet` — a **new, strictly-additive** crate. Zero edits
to `qlab-air` / `qlab-bench` / `qlab-note` / the `m4*` code beyond additive
workspace wiring. No networking beyond localhost. No design-repo writes.

**Worktree / branch:** `../qumbra-lab-m6-devnet` on `claude/m6-devnet`.

**Tech stack:** Rust 2021, workspace-managed. Conservative hash =
`qlab_air::reference::keccak_f` (the same primitive the whole consensus stack
uses — "conservative hash everywhere in consensus", performance-budget §2).
ML-DSA-65 committee votes via a maintained pure-Rust crate (selection is the
棒 2 stop-point, M5 precedent — see below). Real proofs in 棒 5 reuse the
existing M3 builder + verifier; nothing re-implemented.

---

## The contract (binding spec — READ-ONLY source of truth)

Extracted from the design docs. These are decisions, not choices we get to make.
If a design doc and this plan disagree, the doc wins.

**consensus-and-network.md — "Decided here":**
- Hybrid: **permissionless PoW block production + N≈20–50 BFT finality committee**,
  Crosslink-shape on **Ebb-and-Flow**, launched hybrid day one (no migration). (§4)
- CPU-friendly **RandomX-class** PoW — but **exact algorithm is OPEN** (§10). We
  implement PoW **behind a trait** with a **Keccak-based placeholder**; we do NOT
  integrate RandomX and do NOT decide the algorithm in code.
- Committee: transparent self-bonded stake, **ML-DSA-65 votes** (~165 KB/checkpoint
  at N=50), no user delegation at launch. (§5)
- **Anchors reference finalized roots only**; finality lag = minimum anchor age. (§6)
- **60–75 s blocks** (real target); compact-block relay. Sim uses a configurable
  **accelerated** block time — flagged as a sim knob, not a design number. (§7)
- **Posted-price ZIP-317-shape fee table keyed on the arity bucket**; single native
  fee asset; Monero-style weight penalty (backstop, out of devnet scope). (§8)
- Ebb-and-Flow: **committee stall → PoW chain continues in degraded probabilistic
  mode**, finality resumes cleanly on recovery. (§4)

**committee-and-governance.md §2–3:**
- Membership changes **in-protocol at epoch boundaries** — never a fork event;
  "who may sign" = pure function of finalized state at the previous boundary. (§2)
- **Equivocation** (two conflicting signed votes for the same checkpoint slot) →
  automated evidence handling → **permanent tombstone + bond slash**; the pair of
  signatures *is* the proof (two signature checks). (§3)
- **Downtime → jail, NO slash**, re-admission after a timeout. (§3)
- Correlation scaling deferred to the delegation era (out of scope). (§3)

**performance-budget.md §5–6, §9:**
- Sub-ms verification; block validity checking is nearly free. Launch **rung 0**
  with a **reserved aggregate-proof slot in the block header**. (§5)
- **Epoch supply attestation** = a **RESERVED block-header field** at launch,
  *activated with rung 1* — NOT computed at devnet. (§9)
- Tx proofs are prunable at rung 1; verify-then-discard even at rung 0. (§6)

## Honest-constants rule (hard)

Emission schedule, bond/slash amounts, fee-tier values, epoch length, and the PoW
algorithm are **OPEN design questions** — the consensus-parameters appendix does
not exist yet. The devnet uses **PLACEHOLDER constants** confined to one
clearly-banner-marked module, `params_devnet.rs`. Never scatter magic numbers;
never present a placeholder as decided. No tokenomics/emission logic beyond a
placeholder coinbase counter. The supply-attestation field is **RESERVED, not
computed**. Nothing in code decides an open design question.

## Hard lines (never cross)

- No design-repo writes.
- No changes to existing crates beyond additive workspace wiring.
- No networking beyond localhost.
- No tokenomics/emission beyond a placeholder coinbase counter.
- Never enter sibling worktrees (`qumbra-lab-issue21` touches `m4gate.rs` —
  issue #21 is live there; `qumbra-lab-mwhir`). Workspace-file edits are
  additive-only.

---

## ML-DSA crate selection (棒 2 STOP-POINT — decision record)

Follows the **M5 precedent** (PR #28): a maintained pure-Rust impl, FIPS-204
test-vector status recorded here, no hand-rolling. If no crate satisfies, **stop
and report options** — do not hand-roll ML-DSA.

- M5 chose RustCrypto `ml-kem =0.3.2` (FIPS-203-final, ACVP/Wycheproof KATs,
  self-declared **unaudited**; libcrux-ml-kem named as the production alternative).
- The ML-DSA analog to evaluate at 棒 2: RustCrypto `ml-dsa` (FIPS-204). **Status:
  TBD — to be recorded at 棒 2** (crate version, FIPS-204 KAT/ACVP status, audit
  status, production alternative). Not selected yet.

---

## Architecture / file structure (`crates/qlab-devnet/src/`)

Built up stage-by-stage; this is the target layout, not all present at once.

| File | Responsibility | Stage |
|---|---|---|
| `lib.rs` | crate docs + module decls | 棒 0 |
| `params_devnet.rs` | **all** placeholder constants, banner-marked | 棒 0 |
| `hash.rs` | Keccak-256 sponge over `qlab_air::reference::keccak_f` | 棒 0 |
| `header.rs` | `BlockHeader` (PoW fields, tx-body commitment, RESERVED slots) | 棒 0 |
| `pow.rs` | `PowEngine` trait + `KeccakPow` placeholder + difficulty adjust | 棒 0 |
| `chain.rs` | `ChainState`: block store, tip, heaviest-chain fork choice | 棒 0→1 |
| `mining.rs` | mining loop, block validation, accelerated block time | 棒 1 |
| `committee.rs` | genesis committee, ML-DSA-65 checkpoint votes, ⅔-quorum | 棒 2 |
| `finality.rs` | finalized-root tracking, anchors-from-finalized-only API | 棒 2 |
| `ebbflow.rs` | stall→degraded→recover, evidence/tombstone/slash, jail | 棒 3 |
| `net.rs` | multi-node local sim, block gossip, fee-tier table | 棒 4 |
| `fees.rs` | posted-price fee table keyed on arity bucket | 棒 4 |
| (`qlab-bench` mode) | 棒 5 real-proof integration + measured report | 棒 5 |

---

## Staged plan (棒 structure)

### 棒 0 — plan doc + crate skeleton  ← current
Core types: block header (prev, height, PoW fields, tx-body commitment, RESERVED
aggregate-proof slot, RESERVED epoch supply-attestation field), chain state,
placeholder-PoW trait + difficulty adjustment. Plan doc + progress table live.

**Task breakdown (TDD, one clean commit at the end):**
1. Crate skeleton + workspace wiring (additive), `cargo check` green.
2. `hash.rs`: `keccak256` sponge on `reference::keccak_f`; test vs a known vector.
3. `params_devnet.rs`: banner + 棒 0 placeholder constants only.
4. `header.rs`: `BlockHeader`, canonical preimage (RESERVED fields present in the
   preimage as fixed sentinels), `header_hash`; determinism + reserved-presence tests.
5. `pow.rs`: `PowEngine` trait; `KeccakPow`; `target_threshold`/`satisfies_target`
   (monotone in difficulty); `next_difficulty` clamped adjustment; tests.
6. `chain.rs`: `ChainState` skeleton — genesis, insert-by-hash, tip, cumulative
   work; heaviest-chain selection stub (full fork choice lands 棒 1).
7. Full unfiltered `cargo test --release` green; commit.

### 棒 1 — single-node PoW chain
Mining loop, block validation, heaviest-chain fork choice (pre-finality),
configurable accelerated block time for the sim.

### 棒 2 — the finality committee  ⚠ STOP-POINT (ML-DSA crate selection)
Static genesis committee (N≈20 keys from config), ⅔-quorum checkpoints at a
configurable cadence, finalized-root tracking, **anchors-from-finalized-only**
rule exposed as an API. Record ML-DSA crate decision above before coding votes.

### 棒 3 — Ebb-and-Flow semantics
Committee stall → degraded probabilistic mode; clean finality resume on recovery.
Equivocation evidence → automated tombstone + placeholder slash; jail-no-slash
for downtime. **Negative tests:** forged vote rejected; equivocation detected from
evidence; **no reorg past a finalized checkpoint EVER** (the load-bearing safety
test).

### 棒 4 — multi-node local sim
N nodes, block gossip (in-process vs localhost — **decision + justification to be
recorded here at 棒 4**), posted-price fee-tier table keyed on arity bucket.
Scenario tests: partition/rejoin, committee-minority offline, miner-only liveness.

### 棒 5 — real-proof integration + measured report
Block bodies carry REAL M3 tx proofs (pre-generate a small pool once, reuse —
proving is ~1.6 s each). Validation calls the existing verifier (sub-ms/proof).
Measure per-block validation time vs the §7 sub-second budget. Reports:
`docs/m6-devnet-run{1,2}.md` (block cadence, finality latency, validation time,
degraded-mode behavior). Reproduce twice per bench discipline.

---

## Progress table

| 棒 | Description | Status | Commit / notes |
|---|---|---|---|
| 0 | plan doc + crate skeleton | **DONE** | crate `qlab-devnet` (hash/header/pow/chain/params), 18 tests; full unfiltered `cargo test --release` green (air 11 / bench 75 / devnet 18 / note 21 = 125, 0 fail) |
| 1 | single-node PoW chain | not started | — |
| 2 | finality committee (⚠ ML-DSA stop-point) | not started | — |
| 3 | Ebb-and-Flow semantics | not started | — |
| 4 | multi-node local sim | not started | — |
| 5 | real-proof integration + report | not started | — |

## Placeholder-constants inventory

Every placeholder lives in `params_devnet.rs`. Kept current as stages add them.

| Constant | Placeholder value | Real source (open) |
|---|---|---|
| `GENESIS_DIFFICULTY` | `1_000` | launch difficulty — tokenomics/consensus, undecided |
| `SIM_BLOCK_TIME_SECS` | `2` | **not** the real block time; **real = 60–75 s decided** (consensus §7). Sim knob only — devnet does not run at wall-clock scale |
| `DIFFICULTY_WINDOW_BLOCKS` | `16` | retarget window — consensus-parameters appendix |
| `MAX_DIFFICULTY_ADJUST_FACTOR` | `4` | retarget clamp — consensus-parameters appendix |

## Open decisions deferred to design (not decided in code)

- PoW algorithm (RandomX-class vs specify anew) — consensus §10.
- Emission schedule / tail emission — tokenomics doc.
- Bond/slash amounts, fee-tier values, epoch length, block-weight penalty params —
  consensus-parameters appendix.
- ML-DSA crate for votes — recorded at 棒 2 (M5 precedent).
- In-process vs localhost gossip — recorded at 棒 4.
