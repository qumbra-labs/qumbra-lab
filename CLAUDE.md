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

- **M1 — DONE (2026-07-16, PRs #1/#2/#3 + qumbra-design's `prototype-bench-M1.md`)**: proving time is a non-issue (49 ms Keccak, 10–60× margin); proof size is the binding constraint. Keccak = only live conservative candidate (BLAKE3 eliminated by 173 KB zeta floor; SHA-256 has no AIR); narrow-layout geometry floor **172.5 KB** (U-curve @ 164 cols, probe calibrated −0.005%) vs 55 KB Poseidon2 vs ≤150 KB target.
- **M1.6 (a)+(b) — DONE (2026-07-16, `levers` bench mode; runs in `docs/levers-M1.6-run*.md`)**: the ≤150 KB target is REACHED with margin. FRI arity is the dominant lever: arity 8 alone takes the 164-col floor 172.5 → 101.6 KB; blowup 32 / 18 queries alone → 146.8 KB; combined b32/q18/a16 floor = **79.6 KB @ 41 cols** (reproduced twice, ±0.2 KB grind jitter). Higher arity flattens the fold-path term and moves the U-curve minimum narrower (L6 41-col becomes optimal), exactly as predicted. Prove stays ≤ 0.7 s (target 3 s). Levers (c) truncated digest / (d) WHIR are no longer needed for the target — optional future squeeze. → **M1.5b (correct narrow-Keccak AIR implementation) is justified and next**; results to be written up in qumbra-design's prototype-bench doc.
- **M1.5b — DONE (2026-07-17, `qlab-air::narrow` + `narrow` bench mode; runs in `docs/narrow-M15b-run*.md`)**: correct-semantics narrow Keccak-f[1600] at **371 cols × 3072 rows/perm** (vs 2,633-col stock; z-slice pipeline, 128 rows/round, three packed shift registers, 27 free periodic columns + 1 preprocessed RC column; semantics = reference chain, cross-checked vs p3-keccak). **Both targets met: 141.2 KB / 2.0 s prove @ b16/q19/g24/fp16/a16** (exactly 100 bits; 147.7 KB @ q20/g20), reproduced across fresh processes. Findings: the mock's sub-160-col rungs are NOT buildable (2-row window, no lookups — packed-carry floor + rho shift registers); real = mock + 11% entirely from the preprocessed RC column's per-query openings (~740 B/query — in-trace LFSR gadget is the identified next squeeze, ~−15 KB net); realized constraint density = 15× census (prove-time only, harmless at 2 s); b32/a16 = 139.3 KB but RAM-bound on 36 GiB (25 GB LDE). qumbra-design §9 correction owed: "41–82 cols" → 371 cols realizable, margin 6% not 47%.
- **M1.5c — DONE (2026-07-17, runs in `docs/narrow-M15c-run*.md`)**: preprocessed iota-RC column replaced by an in-trace rotating ring (24 registers + 7 exposed bits, first-row pinned, block-boundary rotation via free periodic flag; width 371 → 402, no preprocessed trace at all). **Robust double-pass: 136.9 KB / 2.0 s @ b16/q20/g20/fp16/a16, reproduced identically**; 130.8 KB @ q19/g24 (prove 2.2–3.3 s — the 2^24 grind is in prove time and has high variance); 129.0 KB @ b32/a16 (RAM-bound here). Net −10 to −13 KB vs M1.5b at every config. Conservative-route margin now ~9% at the robust point.
- **M2 — step 0 DONE (2026-07-17, `docs/m2-iphone-plan.md` + `docs/narrow-M2step0-*.md`)**: the 15 s target is safe (low-blowup configs prove in 0.65–1.1 s on the Mac → ~3–9 s phone-projected), but **memory is the real wall**: peak RSS 15.1 GB @ b16 (no iPhone), 7.6 GB @ b8 (marginal even on 12 GB devices), 3.9 GB @ b4 (fits 8 GB-class w/ entitlement) — and every phone-fitting config breaks ≤150 KB (b8 = 172.7 KB, b4 = 238.5 KB; monotone frontier, reproduced twice). **The self-proving-phone vs ≤150 KB collision is M2's actual finding** — resolution options (relax target for self-proved / delegation / WHIR / multi-config) belong to qumbra-design. Build path researched: cargo-dinghy first, hand-rolled bundle + `xcrun devicectl` fallback (entitlement control); `narrow --only <cfg>` filter added for per-launch device runs. Steps 1–2 (device harness + on-device matrix) await the user's iPhone/Xcode setup.
- ~~M2 original framing~~: go/no-go on the 15 s target — answered YES at step 0; fallback ladder in performance-budget §4 is now about *bytes vs RAM*, not seconds.
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
