# M4 step 1 stage 3 — interior two-child peak-RSS measurement (run 1)

> Measurement per aggregation-rung1 **§7.1** (pre-registered protocol). This
> document reports numbers ONLY. The pass/fail verdict is the coordinator's
> **§7.3** table lookup — not made here.

## Rig / provenance (bench discipline, CLAUDE.md §"Bench discipline")

- **qumbra-lab rev:** `b6f7246` (branch `claude/m4-tree-step2`; stage-2 棒 1+2+3
  complete, m4gate suite 47 passed / 0 failed, distinct two-child SAT, root bound
  to keccak-merge)
- **prover:** Plonky3 0.6.1 (pinned in `Cargo.lock`)
- **hardware:** Apple M5 Max, 36 GiB RAM
- **OS:** macOS 26.5.2
- **power state:** AC (80% battery, not charging); no thermal warning recorded
- **method:** release binary run DIRECTLY under `/usr/bin/time -l` (no `cargo`
  wrapper, no output pipe on the headline runs), one `--only <row>` per process,
  so peak RSS attributes to a single config. Prove ONCE per process; the two
  reproductions are two separate process launches (§7.1.4).
- **contention:** no competing memory tasks — largest non-bench process ~0.36 GB
  (Warp/WhatsApp/WeChat idle) throughout; the b4 compression below is the job's
  own demand, not external pressure.

## What was measured

- **canary** = `single-child` = ONE wide leaf verified in-circuit at **2^18**
  (`build_gate_trace(GateShape::wide())` + `VerifierGateAir::new_with_shape(wide)`).
  §7.1.1: same width-class + blowup as the 2^16 leaf → pins the height-scaling
  slope on-axis.
- **two-child** = TWO DISTINCT wide leaves row-stacked + keccak-merge at **2^19**
  (`build_interior_trace(GateShape::wide())` + `VerifierGateAir::new_interior()`) —
  the interior node, the RSS gate's actual subject.
- lane config = the INTERIOR's own FRI config (independent of the fixed b4/q40
  the child leaves were committed at). `b4/q40/g20/fp16/a16` primary,
  `b2/q80/g20/fp16/a16` backup — both exactly 100 conjectured bits
  (`make_config_with` asserts: 40·2+20 = 80·1+20 = 100).
- child leaves (~11.9 GB / ~0.67 s each at b4/q40) proved SERIALLY and ONCE, then
  dropped — only the recorded `Schedule` + outer PVs survive into the interior
  prove, so the reported peak is the interior's, never a leaf's. Confirmed by the
  numbers: every interior peak exceeds the ~11.9 GB leaf transient.

## Run-1 numbers

`/usr/bin/time -l` fields, verbatim (bytes), plus GB = bytes / 1024³:

| row | height | prove s | **max RSS** | **peak footprint** | swaps | block in/out | sys s |
|---|---|---|---|---|---|---|---|
| single-child/b4/q40 (canary) | 2^18 | 7.26 | 15.22 GB (16,340,025,344) | 16.53 GB (17,745,916,984) | 0 | 0 / 0 | 34.3 |
| two-child/b4/q40 | 2^19 | 166.23 | 16.42 GB (17,631,543,296) | 30.42 GB (32,667,065,744) | 0 | 0 / 0 | 199.7 |
| two-child/b2/q80 | 2^19 | 4.94 | 20.70 GB (22,225,371,136) | 20.53 GB (22,047,014,944) | 0 | 0 / 0 | 15.7 |

- proof size (fixed/bincode): single-child b4 = 0.81 MB; two-child b4 = 0.82 MB;
  two-child b2 = 1.51 MB (q80 → 2× queries → larger).
- **no run had nonzero swap-ins or pageouts** (`swaps 0`, `block input/output
  operations 0`) → none disqualified by §7.1.4's literal disk-swap rule.

## The load-bearing finding: at b4/2^19 max-RSS is a non-reproducible compression artifact; peak footprint is the faithful demand

The `maximum resident set size` metric — the repo's prior convention (the m4gate
leaf reported 11.89 GB there) — **does not survive the two-reproduce bar for the
b4/2^19 row**, while `peak memory footprint` does. Cross-run (this run vs run 2):

| row | metric | run 1 | run 2 | reproduces? |
|---|---|---|---|---|
| single-child/b4 (2^18) | max RSS | 15.22 GB | 15.22 GB | ✅ (±5 MB) |
| two-child/b4 (2^19) | **max RSS** | 16.42 GB | 23.38 GB | ❌ (swings 7 GB) |
| two-child/b4 (2^19) | **peak footprint** | 30.42 GB | 30.42 GB | ✅ (exact, ±1.3 MB) |
| two-child/b2 (2^19) | max RSS | 20.70 GB | 20.70 GB | ✅ (±0.75 MB) |
| two-child/b2 (2^19) | peak footprint | 20.53 GB | 20.53 GB | ✅ (±5.5 MB) |

Mechanism (macOS memory compressor, NOT disk swap):

- The main-trace LDE alone at b4/2^19 = 2^21 LDE rows × ~3,879 wide cols × 4 B ≈
  **32 GB** — the process genuinely demands ~30 GB, which on a 36 GiB rig triggers
  the macOS memory compressor.
- The compressor holds `max RSS` artificially *below* true demand by compressing
  resident-but-cold pages **in RAM** (no disk swap → `swaps 0`, `block I/O 0`).
- How hard it compresses depends on free memory at launch, so `max RSS` is
  non-reproducible (16.42 GB with less free memory + 166 s prove + 199.7 s sys vs
  23.38 GB with more free + 42.7 s prove + 118.6 s sys). The prove time is
  compression noise — exactly §7.1.4's "paged prove time is noise" and
  "paged RSS understates the true footprint," reached via compression rather than
  disk paging.
- `peak memory footprint` (`phys_footprint` — resident + compressed) is the true
  demand and reproduces to ~1 MB: **30.42 GB both runs.**

By contrast the canary (2^18, ~15 GB on 36 GiB, ample headroom) and two-child b2
(2^19, ~20.5 GB, headroom) run with **footprint ≈ max RSS** and low sys time — no
compressor engagement — so both metrics agree and reproduce cleanly.

## §7.1.3 rig wall — discovered empirically, handled as prescribed

§7.1.3 says: if two-child b4 predicts ≥ ~34 GB, do not attempt b4; measure b2/q80
and report b4 as a validated extrapolation. The canary max-RSS slope
(11.89 GB @ 2^16 → 15.22 GB @ 2^18) extrapolated only ~17–20 GB, so b4 was
attempted — but the DIRECT b4 run then revealed the true demand is ~30.42 GB
(footprint), the compressor engaged, and max-RSS became unreliable. This is the
§7.1.3 rig-wall case, just surfaced by direct measurement rather than by the
(misleadingly low, max-RSS-based) extrapolation. Per the protocol's intent, the
**b2/q80 substitute was measured and is clean** (20.70 GB max RSS = 20.53 GB
footprint, reproduced, 4.9 s, no compression).

Height-slope cross-check (§7.1.3 "validated = slope holds across leaf → canary →
two-child-b2"), max RSS, fixed metric, all no-compression points:

- leaf 2^16 b4 = 11.89 GB (aggregation-rung1 PR #18, same rig)
- canary 2^18 b4 = 15.22 GB
- two-child 2^19 **b2** = 20.70 GB (clean)

These three are internally consistent with a large fixed floor (~11 GB) + a
modest height/LDE-linear term; the b4/2^19 footprint 30.42 GB sits where the same
model + the b4/b2 blowup step predicts. (The exact slope arithmetic and its use
for a verdict is the coordinator's, not asserted here.)

## Facts vs the aggregation-rung1 §6/§7.3 envelope (≤ 30 s time, ≤ 32 GB RAM) — NO verdict

Reported for the coordinator's §7.3 table lookup, keyed on two-child b4 peak RSS:

| dimension | two-child b4/2^19 | two-child b2/2^19 (substitute) |
|---|---|---|
| peak footprint (faithful demand, reproduced) | **30.42 GB** | 20.53 GB |
| max RSS (repo convention; b4 = compression artifact) | 16.42–23.38 GB (non-reproducible) | 20.70 GB |
| prove time | 42.7–166 s (compression noise) | 4.7–4.9 s |
| disk swap / pageout | none | none |

- Against **≤ 32 GB**: two-child b4 peak footprint 30.42 GB is *under* 32 GB, but
  close enough to the 36 GiB physical ceiling that the compressor engages — i.e.
  it fits without disk swap but with heavy in-RAM compression. The b2 substitute
  (20.53 GB) has clear headroom.
- Against **≤ 30 s**: b2 clears trivially (4.9 s). b4's 42.7–166 s prove is
  compression noise per §7.1.4, not a clean time — the clean b4 prove (from the
  canary's un-compressed 6–7 s at 2^18, ~2× for the height doubling) would be
  ~13–15 s absent memory pressure.

The two-reproduce discipline (CLAUDE.md §"Bench discipline" #3) selects the
metric that is publishable: **peak footprint** for b4 (30.42 GB, reproduced),
**both metrics** for b2 (20.70 / 20.53 GB, reproduced). The §7.3 verdict is the
coordinator's.
