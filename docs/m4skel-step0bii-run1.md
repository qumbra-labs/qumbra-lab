# qumbra-lab M4 step 0b(ii) increment 1: composite rectangle skeleton

- hardware: Apple M5 Max, 36 GiB RAM
- OS: macOS 26.5.2
- qumbra-lab rev: b01f27c
- prover: Plonky3 0.6.1 (pinned in Cargo.lock)
- power state: AC
- rectangle: 2657 cols x 2^16 = keccak lane (2633, 2233 perms) + ext-mul bank (12, 28800 rows) + ext-add bank (12, 28663 rows); foreign-AIR lane composition via a column-offset LaneBuilder; NO cross-lane routing yet (increment 2)
- projection to beat (layout note): b4 ~463 ms / ~2.91 GB (the measured 0a baseline + 1.5% columns; this rectangle is 24 cols, projection ~462 ms — routing cols come later)

| lane config | rows | prove ms | verify ms | postcard KB | fixed KB |
|---|---|---|---|---|---|
| b4/q40/g20/fp16/a16 | 65536 | 534 | 12.1 | 720.9 | 597.9 |
| b16/q20/g20/fp16/a16 | 65536 | 1583 | 6.9 | 419.3 | 347.6 |

Peak RSS: rerun one config under /usr/bin/time -l with --only <cfg>. Semantics note: bank values are self-consistent random instances (a wrong c fails verification — same discipline as the anchor); the keccak lane runs the stock schedule. Cross-lane routing, FS extraction, and public binding are increment 2.

## Peak RSS (`/usr/bin/time -l` with `--only`, measured once after the record runs)

| lane config | peak RSS |
|---|---|
| b4/q40/g20/fp16/a16 | 3.58 GB |
| b16/q20/g20/fp16/a16 | 12.16 GB |

(The +0.69 GB over the 0a hash-only baseline is the keccak source matrix held alive during trace composition — removable later by fusing the generators.)

## Notes

- Verdict vs the layout projection (b4 ~463 ms / ~2.91 GB): prove 476-561 ms (+3-21% band, thermal jitter included), bytes 597.9 KB fixed (+0.8% over baseline, matching the +24-col arithmetic), RSS +0.69 GB with a named, removable cause. The rectangle behaves.
- Two build lessons captured for increments 2+: (1) a full-width Expr collect inside eval runs per LDE point in the prover's folder and cost +70% prove time before being narrowed to the bank columns; (2) trace buffers must be allocated at full LDE capacity up front — a late reserve() realloc showed up as 3x RSS across bench runs.
- The LaneBuilder (column-offset AirBuilder adapter) evaluates the stock p3-keccak-air unmodified inside the shared rectangle — the composition mechanism the full build needs, now proven.
- Not yet present (increments 2+): cross-lane routing, FS challenge extraction, public binding. Bank values are self-consistent random instances (wrong c fails verification, same discipline as the anchor).
