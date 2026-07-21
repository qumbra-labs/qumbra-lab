# M-WHIR step 0 — run record

> Bench-discipline record for the M-WHIR step-0 baton. **There are no WHIR prover
> measurements** — task 2 (the `mwhir` bench mode) is structurally blocked
> (STOP-POINT B; see `mwhir-step0-plan.md`), so there is no runnable WHIR-over-AIR
> prover to measure. This doc records what IS reproducible: the 0.6.2 regression
> suite, the FRI baseline, and the (deterministic) soundcalc derivation reproduced
> twice. The `run{1,2}` two-reproduction convention applies to prover headline
> numbers; with none produced, this single record stands in and says so plainly.

## Environment (bench-discipline item 2)

| field | value |
|---|---|
| repo rev (branch) | `8298990` — `claude/mwhir-step0` (experiment branch; +docs, uncommitted at record time) |
| stack | Plonky3 **0.6.2** (all p3-* crates; `p3-whir = "=0.6.2"` added) |
| hardware | Apple M5 Max, 36 GiB (Mac17,6) |
| OS | macOS 26.5.2 |
| power | AC, no thermal throttling observed |
| soundcalc rev | `809896fb8d3aba4fd8f657c781601e3ef2b968dd` |

## 1. 0.6.2 regression suite (correctness gate — STOP-POINT A)

`cargo test --release -p qlab-bench` (full unfiltered suite, per CLAUDE.md §Bench
discipline item 5):

```
test result: ok. 68 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 334.04s
```

**68/68 green on 0.6.2** — identical pass count to main's 0.6.1 record (CLAUDE.md,
PR #26). The 0.6.1→0.6.2 upgrade required no consensus-circuit rewrites; the
existing FRI suite is the free regression net and it holds. This is the STOP-POINT
A "does the upgrade drift circuit semantics" check: it does not.

## 2. FRI consensus baseline (for the comparison table)

From PR #26 re-bench (main, 0.6.1), consensus lane **b16/q20/g22/fp16/a16**:

| metric | value |
|---|---|
| proof (fixed-width) | **139,721 B** (≈ 136.4 KB) |
| prove time | ~1.8 s |
| prover peak footprint | ~11.8 GB |
| verify | ~11.8 ms (M3 §10 class) |

Not re-measured on this branch (it would just reproduce main; the regression suite
already exercises the identical prover path green on 0.6.2).

## 3. soundcalc WHIR derivation — reproduced twice (deterministic)

Full inventory in `mwhir-soundcalc.md`; inputs in `mwhir-soundcalc-deg{4,5}.toml`.
Both parameter points at the chosen operating point `q=[40,32,26,23]`, rate 1/16,
folds [4,4,4,4], g22:

| point | field | JBR (proven) total | UDR total | proof-size estimate (expected) |
|---|---|---|---|---|
| (i) degree-4 | KoalaBear⁴ (2^124) | **80** (capped) | 44 | ~1,559 KiB |
| (ii) degree-5 | KoalaBear⁵ (2^155) | **101** | 44 | ~1,564 KiB |

Two independent invocations produced byte-identical results (soundcalc is
deterministic). The ~80-bit degree-4 provable-Johnson cap is **CONFIRMED**.

## 4. Why the pre-registered measurement table is empty for WHIR

Proof bytes / prover peak footprint / prove time / verify time for WHIR at either
point **could not be produced**: Plonky3 0.6.2 exposes WHIR only as a
`MultilinearPcs`, and `p3-uni-stark` consumes only the univariate `Pcs`; no
multilinear-AIR STARK frontend exists in the 0.6.2 tree to prove the qlab-air M3
statement over WHIR (full argument: `mwhir-step0-plan.md` §STOP-POINT B). Building
one is a new proof system, outside step-0 scope and the "minimal local patch"
allowance. The only paper-derivable dimension — proof size — is on record above
(and is adverse: ~1.5 MB estimated for the 618-wide statement). The load-bearing
memory number that branch (d) needs remains unmeasured, as whir-reeval §1.5
anticipated ("exists nowhere and Qumbra must measure it itself").
