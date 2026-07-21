# qumbra-lab

Prototype lab for **Qumbra** — the post-quantum privacy-chain design exercise. Canonical spec: [`lai3d/qumbra-design`](https://github.com/lai3d/qumbra-design) (thirteen paired design docs + ROADMAP). This repo answers the design thread's prototype-gated questions with measured code. Not a chain implementation; the lab that decides whether one is worth building. Private, personal.

**Orientation:** read `CLAUDE.md` — it carries the full milestone log (source of truth for lab state) and the bench discipline. One-page status: the design repo's [ROADMAP](https://github.com/lai3d/qumbra-design/blob/main/ROADMAP.md).

**State (2026-07-22):** M1–M5 measured and closed — consensus tx circuit 136.4 KB / 1.6 s at ~100-bit (conjectured, DG25, g22); M4 aggregation rung-1 two-level prototype end-to-end (leaf + interior + merge root + Σfee rider; interior 20.5 GB @ b2/q80 default); M5 note-encryption prototype (`qlab-note`, 585 B/note amortized). In flight: issue #24 (three-binding consolidation), M6 devnet. Experiment branch `claude/mwhir-step0` = WHIR calibration record (not merged by design).

## Layout

```
crates/
  qlab-air/     # the fixed-shape AIR: Merkle path, PRF, commitment, balance
  qlab-bench/   # bench harness: hash matrix × hardware, criterion-based
docs/           # lab notes; polished results go to the design repo, not here
```

## Ground rules

- Rust, Plonky3-class stack; pin exact revs in `Cargo.lock` (bench numbers are meaningless against a moving prover).
- Every bench result records: git rev of this repo, prover crate revs, hardware, OS, power state.
- Numbers land in the design repo only after being reproduced twice on the same rig.
