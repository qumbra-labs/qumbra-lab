# qumbra-lab

Prototype lab for **Qumbra**, a post-quantum privacy-chain design exercise. This file orients Claude Code sessions opened in this repo — read it fully before touching code.

## Ownership — read this first

- **This is Larry's personal project.** It is NOT related to Larry's contract work for pqabelian (Abelian/QDay/USD9-swap, which lives under `~/develop/bidot-blochains/`). Do not frame anything here as "propose to Leo/pqabelian"; Larry is the sole decision-maker.
- Repo is **private** (`lai3d/qumbra-lab`). Keep it that way; new sibling repos also default to `--private`.
- All Qumbra repos live under `~/develop/qumbra/` on disk.

## What Qumbra is, in one paragraph

A 2026 greenfield design for a post-quantum privacy L1: note-based UTXO, one global shielded pool (no transparent tier, no rings), one monolithic STARK per transaction (spend authorization inside the proof — no per-spend signatures), conservative hash (Keccak/SHA-class) everywhere in consensus, ML-KEM note encryption, hybrid PoW + small BFT finality committee. Deliberately NOT Abelian's all-lattice PQRingCT route — the design bets that hash/STARK + NIST standard parts beat lattice ring signatures on every engineering axis.

## Canonical design source

The eight design docs are the **binding spec** for this repo:

- GitHub: [`lai3d/qumbra-design`](https://github.com/lai3d/qumbra-design) (extracted 2026-07 from the bidot-blockchains-design notebook, history preserved)
- Local clone: `~/develop/qumbra/qumbra-design/`

Before touching the AIR, read at minimum: `transaction-model-and-anonymity-set.md` (the circuit's statement) and `performance-budget.md` (targets + the hash-choice framework). `benchmark-survey-2026-07.md` holds the sourced third-party numbers M1 validates against. Docs are EN with `-zh` pairs; EN is authoritative on technical details.

## Design decisions that bind this code

| Decision | Source | Consequence here |
|---|---|---|
| Fixed-shape 2×2-bucket circuit: 2 × depth-32 Merkle membership + 2 × nullifier PRF + 2 × spend-key knowledge + 2 × commitment well-formedness + in-circuit balance ≈ ~90 hash invocations | tx-model doc | `qlab-air` implements exactly this shape; no generality, no zkVM |
| Conservative hash (Keccak/SHA-class) everywhere in consensus; exact pick is **M1's question** | performance-budget §2 | bench matrix = Poseidon2 (calibration baseline only) vs Keccak-f vs SHA-256 vs BLAKE3 raw-AIR |
| Targets: tx ≤ 150 KB, prove ≤ 3 s laptop / ≤ 15 s phone, ~100-bit conjectured security | performance-budget §3–4 | every bench reports against these; the 15 s phone number is the design's riskiest and M2's whole job |
| Raw fixed-shape AIR, no zkVM | performance-budget §4 | the RISC Zero/SP1 7× spread on identical workloads is the zkVM tax we refuse to pay |

If a measurement contradicts a design-doc estimate, the doc gets a correction PR — the design repo has precedent for retracting its own claims (performance-budget §2 retracted tx-model's "layered hedge"). Never silently diverge from the docs.

## Milestones

- **M1** (current): circuit prototype + hash matrix. Deliverable: measured trace dims / proving wall-clock / peak memory / proof size per hash candidate, written back to the design repo (qumbra-design) as `prototype-bench-M1.md` (EN+ZH pair, matching that repo's conventions).
- **M2**: phone-class proving — go/no-go on the 15 s target; fallback ladder already defined in performance-budget §4.
- Out of scope until the docs say otherwise: recursion/aggregation, note encryption, networking, consensus.

## Bench discipline (non-negotiable)

1. Pin exact Plonky3-class revs in `Cargo.lock` before measuring anything; bench numbers against a moving prover are meaningless. First M1 task = select and pin.
2. Every recorded result carries: this repo's git rev, prover crate revs, hardware model, OS, power state (AC/battery, thermal).
3. A number is publishable to the design repo only after being reproduced twice on the same rig.
4. Calibrate the rig against published Poseidon2 numbers (benchmark-survey §2) before trusting any conservative-hash cell.

## Working conventions

- Non-trivial work: `git worktree add ../qumbra-lab-<slug> -b claude/<slug>`, land via PR to `main`, post the full PR URL, clean up the worktree after merge. Trivial single-file fixes may go direct to `main`.
- Layout: `crates/qlab-air` (the fixed-shape AIR), `crates/qlab-bench` (harness). `docs/` is scratch — polished results go to the design repo, not here.
- Rust 2021, workspace-managed. Keep `cargo check` green on every commit.
- Subagents where possible (research, parallel bench runs, doc translation); verify subagent-written files actually exist on disk (`git status` / `wc -l`) before trusting completion reports.
